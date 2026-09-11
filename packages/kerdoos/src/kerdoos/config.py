"""Runtime settings for the Kerdoos WebUI, read from the environment.

Secrets and deployment paths come from env vars, never hardcoded (security
policy): KERDOOS_SESSION_SECRET (the HMAC key for signed session cookies -- NO
default, required for the WebUI), KERDOOS_CONFIG_DB / KERDOOS_STATE_DB (SQLite
paths), KERDOOS_COOKIE_SECURE (set the cookie Secure flag; default on, set
"false" for a plain-http LAN deployment), KERDOOS_WORKERS (process count the
operator has deployed; drives the digest evaluator's workers>1 guard-rail,
ADR 0003 Decision 4 -- default "1"; a non-integer value floors to the
default with a warning, roadmap 6697af90), KERDOOS_DIGEST_EVALUATOR_ENABLED (opt-in
switch for the WebUI's intra-process evaluator lifespan task; default off so
existing deployments/tests see zero behavior change until explicitly enabled).

get_settings() reads them lazily; create_app fails fast if the session secret is
absent (no silent insecure default).

SMTP (ADR 0003 Phase 6b tranche 4): KERDOOS_SMTP_HOST/PORT/FROM/USERNAME/
PASSWORD/USE_TLS configure the digest email adapter (digest.factory.
build_sender). No hardcoded infra defaults -- smtp_host is None unless set,
which is exactly what makes create_app()/cmd_digest fall back to
LogDigestSender (security policy: never bake a mail relay into the code).
smtp_port defaults to 587 (STARTTLS submission), but that default only
matters once an operator has already set KERDOOS_SMTP_HOST.

KERDOOS_SMTP_RETRY_ATTEMPTS / KERDOOS_SMTP_RETRY_BACKOFF_SECONDS (roadmap
f3b644ab): bound a retry on a TRANSIENT send failure (e.g. greylisting)
inside digest.smtp_sender's send() call, never across evaluator ticks --
defaults are low (2 attempts, a short backoff) since the retry budget is
itself capped by digest_reaper_timeout_seconds.

KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS (ADR 0003 Phase 6b fast-follow): the
explicit max-send-timeout bound (default 300s / 5 min) core.evaluator's
reaper sweep uses to reclaim a job_runs row stranded in 'queued'/'running'
(e.g. the process crashed mid-send). Wired into both `kerdoos digest`
(interfaces/cli/main.py's cmd_digest) and the WebUI's intra-process
evaluator lifespan (interfaces/web/app.py). Also the TOTAL send deadline
core.evaluator._run_plan_b passes to asyncio.wait_for -- a non-positive
value would make that wait_for(timeout=<=0) fail every send instantly, so
get_settings() floors it to the default (with a warning) rather than
passing a broken value through (roadmap 58d88fe0).

KERDOOS_SMTP_TIMEOUT_SECONDS (roadmap 58d88fe0): the per-operation socket
timeout smtplib.SMTP() is opened with (digest.smtp_sender). Should stay
strictly below digest_reaper_timeout_seconds -- digest.factory.build_sender
clamps it (with a warning) if it is not, rather than raising, since it runs
inside interfaces/web/app.py's ASGI lifespan where an uncaught exception
would fail the whole WebUI startup, not just the digest path. The TOTAL
send deadline (beyond a single smtplib operation) is enforced separately in
core.evaluator._run_plan_b via asyncio.wait_for(..., timeout=digest_reaper_timeout_seconds).

KERDOOS_BROWSER_MAX_CONCURRENT / KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS
(card ca30b736, ADR 0002 Decision 1/2): the max number of Chromium processes
(browser tier patchright + uc tier seleniumbase, ONE shared gate) alive at
once, and the max seconds a caller waits for that gate before the source
fails as a retryable FetchError instead of blocking forever. Both floor to
their default (with a warning, never a crash at import) on a non-positive or
non-numeric value, same discipline as _safe_workers. Read here and INJECTED
into autolycos.BrowserGate at composition-root time -- autolycos never reads
either env var itself (invariant 2).

KERDOOS_RUN_QUEUE_MAX_RESTARTS (card 65cef071): max times the WebUI's
background run-queue consumer restarts itself after an unexpected crash
before refusing new POST /run enqueues. Same floor-with-warning discipline.

KERDOOS_RUN_NOW_COOLDOWN_SECONDS (card 1af8b18b): min seconds between the
end of one owner's run_now and their next accepted POST /run enqueue.
Bounds how often a single tenant can hammer the shared browser gate
(max_concurrent=1 by default) and degrade the shared egress IP's anti-bot
reputation for every OTHER tenant. 0 explicitly disables the guard. Same
floor-with-warning discipline; keyed per owner_id (invariant 10).
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

logger = logging.getLogger(__name__)

# Fast-follow from the Phase 4a gate (architect MEDIUM finding): a non-empty
# but short secret (e.g. a single character) still passes the HMAC key API,
# but is brute-forceable -- require a real minimum, not just "set".
MIN_SESSION_SECRET_LENGTH = 32

# Sane STARTTLS submission port default -- only applied once KERDOOS_SMTP_HOST
# is set (never used to invent an SMTP relay when SMTP is unconfigured).
DEFAULT_SMTP_PORT = 587

# Reaper max-send-timeout default (ADR 0003 Phase 6b fast-follow) -- must be
# an EXPLICIT bound, not derived from tick_seconds (2*tick would couple an
# unrelated timer to a correctness-affecting staleness window).
DEFAULT_DIGEST_REAPER_TIMEOUT_SECONDS = 300

# SMTP per-operation socket timeout default (roadmap 58d88fe0) -- must stay
# strictly below DEFAULT_DIGEST_REAPER_TIMEOUT_SECONDS.
DEFAULT_SMTP_TIMEOUT_SECONDS = 30

# Bounded retry on a TRANSIENT send failure (roadmap f3b644ab) -- e.g.
# greylisting, a momentarily unavailable relay. Low by design: retries
# happen inside the SAME send() call, budget-capped by
# digest_reaper_timeout_seconds (digest.factory.build_sender).
DEFAULT_SMTP_RETRY_ATTEMPTS = 2
DEFAULT_SMTP_RETRY_BACKOFF_SECONDS = 2.0

# The send_deadline_seconds budget bounds TIME, not the NUMBER of
# attempts -- with backoff=0 and a relay that refuses instantly, an
# unbounded attempt count is a tight reconnect loop (risks the relay
# banning this host). MAX caps attempts; MIN floors backoff so every
# retry cycle costs at least a beat.
MAX_SMTP_RETRY_ATTEMPTS = 5
MIN_SMTP_RETRY_BACKOFF_SECONDS = 1.0

# Single-process default (ADR 0003 Decision 4).
DEFAULT_WORKERS = 1

# ADR 0002 Decision 1/2: at most this many Chromium processes (browser tier
# patchright + uc tier seleniumbase, sharing ONE gate) alive at once.
DEFAULT_BROWSER_MAX_CONCURRENT = 1

# Card ca30b736: max wait for the browser gate before a source is
# reported as a (retryable) FetchError instead of blocking forever. A
# contending fetch's own worst case is roughly one retry cycle at the uc
# tier's UC_PAGE_LOAD_TIMEOUT_SECONDS (45s) plus RECONNECT_TIME/RENDER_WAIT
# (~9s); 120s covers that with headroom while still recovering the process
# in a bounded time if a holder is genuinely stuck.
DEFAULT_BROWSER_ACQUIRE_TIMEOUT_SECONDS = 120

# Card 65cef071: max times the WebUI run-queue consumer restarts itself
# after an unexpected crash (a bug in the queue mechanics, NOT an
# individual owner's run_now failure, already isolated) before the queue
# is marked dead and refuses new enqueues. A handful of restarts survives
# a transient bug without masking a persistently broken consumer forever.
DEFAULT_RUN_QUEUE_MAX_RESTARTS = 5

# Card 1af8b18b: min seconds between one owner's run_now finishing and
# their next accepted manual re-run. 5 minutes is long enough to stop a
# tenant clicking "Verifier maintenant" repeatedly from starving the
# single shared browser gate and burning the shared egress IP's anti-bot
# reputation, short enough not to punish a legitimate re-check after
# fixing a config issue.
DEFAULT_RUN_NOW_COOLDOWN_SECONDS = 300.0


@dataclass(frozen=True, slots=True)
class Settings:
    session_secret: str | None
    config_db: str
    state_db: str
    cookie_secure: bool
    workers: int
    digest_evaluator_enabled: bool
    smtp_host: str | None
    smtp_port: int
    smtp_from: str | None
    smtp_username: str | None
    smtp_password: str | None
    smtp_use_tls: bool
    smtp_timeout_seconds: float
    smtp_retry_attempts: int
    smtp_retry_backoff_seconds: float
    digest_reaper_timeout_seconds: int
    browser_max_concurrent: int
    browser_acquire_timeout_seconds: float
    run_queue_max_restarts: int
    run_now_cooldown_seconds: float

    def require_session_secret(self) -> str:
        if not self.session_secret:
            raise RuntimeError(
                "KERDOOS_SESSION_SECRET is not set: the WebUI refuses to start "
                "without an HMAC key for signed session cookies (no insecure "
                "default)."
            )
        if len(self.session_secret) < MIN_SESSION_SECRET_LENGTH:
            raise RuntimeError(
                f"KERDOOS_SESSION_SECRET is too short ({len(self.session_secret)} "
                f"chars): the WebUI refuses to start with fewer than "
                f"{MIN_SESSION_SECRET_LENGTH} characters (brute-forceable HMAC key)."
            )
        return self.session_secret


_NumT = TypeVar("_NumT", int, float)


def _env_number(
    name: str, default: _NumT, cast: Callable[[str], _NumT],
    is_valid: Callable[[_NumT], bool],
) -> _NumT:
    """Read an env var as a number, falling back to `default` (with a
    warning naming the variable and value) on a cast failure or a failed
    `is_valid` check -- unset is left silently at `default`, not warned."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = cast(raw)
    except ValueError:
        logger.warning(
            "%s=%r is not a valid number: falling back to the default "
            "(%s).", name, raw, default)
        return default
    if not is_valid(value):
        logger.warning(
            "%s=%r failed validation: falling back to the default (%s).",
            name, raw, default)
        return default
    return value


_WORKERS_GRAMMAR = re.compile(r"[0-9]+")


def _safe_workers(raw: str) -> int:
    """Accepts only the Dockerfile shell guard's own KERDOOS_WORKERS
    grammar (plain ASCII digits, positive)."""
    if not _WORKERS_GRAMMAR.fullmatch(raw):
        logger.warning(
            "KERDOOS_WORKERS=%r is not a plain positive integer: "
            "falling back to the default (%d).", raw, DEFAULT_WORKERS,
        )
        return DEFAULT_WORKERS
    value = int(raw)
    if value <= 0:
        logger.warning(
            "KERDOOS_WORKERS=%r must be a positive integer: falling back "
            "to the default (%d).", raw, DEFAULT_WORKERS,
        )
        return DEFAULT_WORKERS
    return value


def get_settings() -> Settings:
    return Settings(
        session_secret=os.environ.get("KERDOOS_SESSION_SECRET"),
        config_db=os.environ.get("KERDOOS_CONFIG_DB", "config.db"),
        state_db=os.environ.get("KERDOOS_STATE_DB", "state.db"),
        cookie_secure=(
            os.environ.get("KERDOOS_COOKIE_SECURE", "true").lower() != "false"),
        workers=_safe_workers(
            os.environ.get("KERDOOS_WORKERS", str(DEFAULT_WORKERS))),
        digest_evaluator_enabled=(
            os.environ.get("KERDOOS_DIGEST_EVALUATOR_ENABLED", "false").lower()
            == "true"),
        smtp_host=os.environ.get("KERDOOS_SMTP_HOST") or None,
        smtp_port=_env_number(
            "KERDOOS_SMTP_PORT", DEFAULT_SMTP_PORT, int,
            lambda v: 0 < v <= 65535),
        smtp_from=os.environ.get("KERDOOS_SMTP_FROM") or None,
        smtp_username=os.environ.get("KERDOOS_SMTP_USERNAME") or None,
        smtp_password=os.environ.get("KERDOOS_SMTP_PASSWORD") or None,
        smtp_use_tls=(
            os.environ.get("KERDOOS_SMTP_USE_TLS", "true").lower() != "false"),
        # is_valid always True: positivity/ordering against reaper_timeout
        # is digest.factory._safe_smtp_timeout's job, not this layer's --
        # only guard the cast here, never re-validate its semantics.
        smtp_timeout_seconds=_env_number(
            "KERDOOS_SMTP_TIMEOUT_SECONDS", float(DEFAULT_SMTP_TIMEOUT_SECONDS),
            float, lambda v: True),
        smtp_retry_attempts=_env_number(
            "KERDOOS_SMTP_RETRY_ATTEMPTS", DEFAULT_SMTP_RETRY_ATTEMPTS, int,
            lambda v: 0 <= v <= MAX_SMTP_RETRY_ATTEMPTS),
        smtp_retry_backoff_seconds=_env_number(
            "KERDOOS_SMTP_RETRY_BACKOFF_SECONDS",
            DEFAULT_SMTP_RETRY_BACKOFF_SECONDS, float,
            lambda v: v >= MIN_SMTP_RETRY_BACKOFF_SECONDS),
        digest_reaper_timeout_seconds=_env_number(
            "KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS",
            DEFAULT_DIGEST_REAPER_TIMEOUT_SECONDS, int, lambda v: v > 0),
        browser_max_concurrent=_env_number(
            "KERDOOS_BROWSER_MAX_CONCURRENT",
            DEFAULT_BROWSER_MAX_CONCURRENT, int, lambda v: v > 0),
        browser_acquire_timeout_seconds=_env_number(
            "KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS",
            float(DEFAULT_BROWSER_ACQUIRE_TIMEOUT_SECONDS), float,
            lambda v: v > 0),
        run_queue_max_restarts=_env_number(
            "KERDOOS_RUN_QUEUE_MAX_RESTARTS",
            DEFAULT_RUN_QUEUE_MAX_RESTARTS, int, lambda v: v >= 0),
        run_now_cooldown_seconds=_env_number(
            "KERDOOS_RUN_NOW_COOLDOWN_SECONDS",
            DEFAULT_RUN_NOW_COOLDOWN_SECONDS, float, lambda v: v >= 0),
    )
