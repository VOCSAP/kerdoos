"""Runtime settings for the Kerdoos WebUI, read from the environment.

Secrets and deployment paths come from env vars, never hardcoded (security
policy): KERDOOS_SESSION_SECRET (the HMAC key for signed session cookies -- NO
default, required for the WebUI), KERDOOS_CONFIG_DB / KERDOOS_STATE_DB (SQLite
paths), KERDOOS_COOKIE_SECURE (set the cookie Secure flag; default on, set
"false" for a plain-http LAN deployment), KERDOOS_WORKERS (process count the
operator has deployed; drives the digest evaluator's workers>1 guard-rail,
ADR 0003 Decision 4 -- default "1"), KERDOOS_DIGEST_EVALUATOR_ENABLED (opt-in
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
(e.g. the process crashed mid-send). Only wired into `kerdoos digest`
(interfaces/cli/main.py's cmd_digest, the external-cron trigger) -- the
WebUI's intra-process evaluator (interfaces/web/app.py) always uses
core.evaluator.evaluate_tick's own 300s function default instead of reading
this setting.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

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


def get_settings() -> Settings:
    return Settings(
        session_secret=os.environ.get("KERDOOS_SESSION_SECRET"),
        config_db=os.environ.get("KERDOOS_CONFIG_DB", "config.db"),
        state_db=os.environ.get("KERDOOS_STATE_DB", "state.db"),
        cookie_secure=(
            os.environ.get("KERDOOS_COOKIE_SECURE", "true").lower() != "false"),
        workers=int(os.environ.get("KERDOOS_WORKERS", "1")),
        digest_evaluator_enabled=(
            os.environ.get("KERDOOS_DIGEST_EVALUATOR_ENABLED", "false").lower()
            == "true"),
        smtp_host=os.environ.get("KERDOOS_SMTP_HOST") or None,
        smtp_port=int(os.environ.get("KERDOOS_SMTP_PORT", str(DEFAULT_SMTP_PORT))),
        smtp_from=os.environ.get("KERDOOS_SMTP_FROM") or None,
        smtp_username=os.environ.get("KERDOOS_SMTP_USERNAME") or None,
        smtp_password=os.environ.get("KERDOOS_SMTP_PASSWORD") or None,
        smtp_use_tls=(
            os.environ.get("KERDOOS_SMTP_USE_TLS", "true").lower() != "false"),
        digest_reaper_timeout_seconds=int(os.environ.get(
            "KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS",
            str(DEFAULT_DIGEST_REAPER_TIMEOUT_SECONDS))),
    )
