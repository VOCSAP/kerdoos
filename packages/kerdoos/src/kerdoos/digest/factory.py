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

    email_lookup = SqliteAuthStore(config_db_path or settings.config_db).get_email
    smtp_timeout_seconds = _safe_smtp_timeout(
        settings.smtp_timeout_seconds, settings.digest_reaper_timeout_seconds)
    smtp_settings = SmtpSettings(
        host=settings.smtp_host,
        port=settings.smtp_port,
        from_addr=settings.smtp_from,
        username=settings.smtp_username,
        password=settings.smtp_password,
        use_tls=settings.smtp_use_tls,
        timeout_seconds=smtp_timeout_seconds,
        retry_attempts=settings.smtp_retry_attempts,
        retry_backoff_seconds=settings.smtp_retry_backoff_seconds,
        # roadmap f3b644ab gate C2 (measured): the evaluator's wait_for
        # deadline starts at SUBMISSION, but send()'s own deadline starts
        # only after config.load() + digest rendering -- strictly LATER
        # than the caller's cutoff if given the exact same value. A
        # margin of one already-clamped smtp timeout absorbs that gap, so
        # send()'s self-imposed budget stays inside the evaluator's own.
        send_deadline_seconds=max(
            0.1, float(settings.digest_reaper_timeout_seconds) - smtp_timeout_seconds),
    )
    return SmtpDigestSender(config_store, domain_policy, email_lookup, smtp_settings)


def _safe_smtp_timeout(smtp_timeout: float, reaper_timeout: int) -> float:
    """roadmap 58d88fe0: the SMTP socket timeout must stay strictly between 0
    and the reaper's staleness window, or a wedged send could outlive what
    the reaper considers "stale enough to reap". A misconfigured value (>=
    reaper_timeout, zero, negative, or NaN -- `0 < t < reaper` rejects all
    four, since any comparison against NaN is False) degrades to a clamped
    safe value with a warning instead of raising: build_sender runs inside
    interfaces/web/app.py's ASGI lifespan, where an uncaught exception fails
    the entire WebUI startup (no /health, no login), not just the digest
    path -- mirrors this module's existing degrade-not-crash policy for a
    missing SMTP host/from.

    reaper_timeout is a caller-guaranteed positive int (config.get_settings's
    _safe_reaper_timeout floors it before it ever reaches here). `reaper / 2`
    is strictly less than `reaper` for every such value -- unlike the
    earlier `reaper - 1` formula, which produced clamped == reaper (not
    strictly less) at reaper_timeout == 1."""
    if 0 < smtp_timeout < reaper_timeout:
        return smtp_timeout
    clamped = max(0.1, float(reaper_timeout) / 2.0)
    logger.warning(
        "KERDOOS_SMTP_TIMEOUT_SECONDS=%r is not a valid value strictly "
        "between 0 and KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS=%s: clamping "
        "the SMTP socket timeout to %ss so a wedged send still unblocks "
        "before the reaper's staleness window.",
        smtp_timeout, reaper_timeout, clamped,
    )
    return clamped
