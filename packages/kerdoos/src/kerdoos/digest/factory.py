"""Composition helper: pick the DigestSender adapter from Settings.

Single choke point shared by interfaces/web/app.py and interfaces/cli/main.py
so both composition roots make the exact same SMTP-vs-log decision (ADR 0003
Phase 6b tranche 4) instead of duplicating the branch.
"""

from __future__ import annotations

import logging

from autolycos.safety import DomainPolicy

from kerdoos.config import Settings
from kerdoos.core.evaluator import DigestSender
from kerdoos.digest.sender import LogDigestSender
from kerdoos.digest.smtp_sender import SmtpDigestSender, SmtpSettings
from kerdoos.registry.auth_store import SqliteAuthStore
from kerdoos.registry.ports import ConfigStore

logger = logging.getLogger(__name__)


def build_sender(
    settings: Settings, config_store: ConfigStore, domain_policy: DomainPolicy,
    *, config_db_path: str | None = None,
) -> DigestSender:
    """config_db_path defaults to settings.config_db (correct for
    interfaces/web/app.py, whose config_store is built from that same
    setting), but interfaces/cli/main.py's --config-db flag can diverge from
    the KERDOOS_CONFIG_DB env var -- callers with an explicit config_db path
    of their own MUST pass it here so the email_lookup queries the SAME
    database as config_store, not a different one implied by the env."""
    if not settings.smtp_host:
        logger.warning(
            "KERDOOS_SMTP_HOST is not set: falling back to LogDigestSender "
            "(digest bodies are logged, not emailed)."
        )
        return LogDigestSender()

    if not settings.smtp_from:
        logger.warning(
            "KERDOOS_SMTP_HOST is set but KERDOOS_SMTP_FROM is not: falling "
            "back to LogDigestSender."
        )
        return LogDigestSender()

    # Phase 7a fast-follow (roadmap 58d88fe0): the SMTP socket timeout must
    # stay strictly below the reaper's staleness window, or a wedged send
    # could still outlive what the reaper considers "stale enough to reap" --
    # enforced here (construction time) rather than left as a coincidence of
    # the two defaults.
    if settings.smtp_timeout_seconds >= settings.digest_reaper_timeout_seconds:
        raise ValueError(
            "KERDOOS_SMTP_TIMEOUT_SECONDS "
            f"({settings.smtp_timeout_seconds}) must be strictly less than "
            "KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS "
            f"({settings.digest_reaper_timeout_seconds}), otherwise a wedged "
            "SMTP send could still outlive the reaper's staleness window."
        )

    email_lookup = SqliteAuthStore(config_db_path or settings.config_db).get_email
    smtp_settings = SmtpSettings(
        host=settings.smtp_host,
        port=settings.smtp_port,
        from_addr=settings.smtp_from,
        username=settings.smtp_username,
        password=settings.smtp_password,
        use_tls=settings.smtp_use_tls,
        timeout_seconds=settings.smtp_timeout_seconds,
    )
    return SmtpDigestSender(config_store, domain_policy, email_lookup, smtp_settings)
