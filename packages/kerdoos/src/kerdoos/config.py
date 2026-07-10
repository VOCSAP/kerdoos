"""Runtime settings for the Kerdoos WebUI, read from the environment.

Secrets and deployment paths come from env vars, never hardcoded (security
policy): KERDOOS_SESSION_SECRET (the HMAC key for signed session cookies -- NO
default, required for the WebUI), KERDOOS_CONFIG_DB / KERDOOS_STATE_DB (SQLite
paths), KERDOOS_COOKIE_SECURE (set the cookie Secure flag; default on, set
"false" for a plain-http LAN deployment).

get_settings() reads them lazily; create_app fails fast if the session secret is
absent (no silent insecure default).
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Settings:
    session_secret: str | None
    config_db: str
    state_db: str
    cookie_secure: bool

    def require_session_secret(self) -> str:
        if not self.session_secret:
            raise RuntimeError(
                "KERDOOS_SESSION_SECRET is not set: the WebUI refuses to start "
                "without an HMAC key for signed session cookies (no insecure "
                "default)."
            )
        return self.session_secret


def get_settings() -> Settings:
    return Settings(
        session_secret=os.environ.get("KERDOOS_SESSION_SECRET"),
        config_db=os.environ.get("KERDOOS_CONFIG_DB", "config.db"),
        state_db=os.environ.get("KERDOOS_STATE_DB", "state.db"),
        cookie_secure=(
            os.environ.get("KERDOOS_COOKIE_SECURE", "true").lower() != "false"),
    )
