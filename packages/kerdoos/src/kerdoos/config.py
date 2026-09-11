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

# Single-process default (ADR 0003 Decision 4).
DEFAULT_WORKERS = 1


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
    digest_reaper_timeout_seconds: int

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
        digest_reaper_timeout_seconds=_env_number(
            "KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS",
            DEFAULT_DIGEST_REAPER_TIMEOUT_SECONDS, int, lambda v: v > 0),
    )
