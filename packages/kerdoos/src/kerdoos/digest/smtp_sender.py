"""SMTP DigestSender adapter (ADR 0003 Phase 6b tranche 4).

Replaces LogDigestSender for deployments where KERDOOS_SMTP_HOST is
configured. Implements the EXACT SAME core.evaluator.DigestSender Protocol
signature (send(job, records, generated_at, tier2_labels) -> None) -- no
Protocol change, so core/evaluator.py needs no edit beyond the S4
concurrency-ceiling semaphore.

Security hardening baked in here (ADR 0003 Phase 6b tranche 4 gate):

S1 (CWE-93 header/CRLF injection): _clean_header strips CR/LF from every
value that reaches an email header (Subject, From, To) or the text/plain
body, regardless of whether it originates from job.name, a scraped error
string, or any other per-record field. Mirrors digest.render._sanitize_error
(interior CR/LF collapsed, not just stripped from the edges).

S2 (owner-scoping at RUN time): send() resolves source URLs via
config_store.load(job.owner_id) -- an owner-scoped read, never a global
sweep -- so a digest can only ever contain the sending job's OWN owner's
products/sources/records. Never touches list_all_enabled_jobs() or any
other owner-unscoped primitive.

Owner-without-email (ADR 0003 Decision 9): if email_lookup(job.owner_id)
returns None, send() logs at INFO and returns False -- it must NOT raise,
since core/evaluator.py's _run_plan_b marks a raised exception as a job-run
"error" (which does not retry until the NEXT window). _run_plan_b persists a
False return as job-run status "skipped_no_email" (not "sent"), so the fact
is observable, and the very next enabled window naturally tries again once
an email is configured -- no special-case evaluator state needed beyond the
status value itself.

S6 (CWE-295, ADR 0003 fast-follow 6b): STARTTLS is negotiated with an
explicit ssl.create_default_context() (check_hostname=True,
verify_mode=CERT_REQUIRED) -- never the bare no-arg starttls(), which would
leave certificate/hostname verification to whatever default smtplib/ssl
happen to apply. Fail-closed is preserved unchanged: if use_tls=True and the
server does not advertise STARTTLS support, smtplib.SMTPNotSupportedError
propagates uncaught -- there is no plaintext fallback path.

S7 (Phase 7a fast-follow, roadmap 58d88fe0): smtplib.SMTP() is opened with
an explicit socket timeout (SmtpSettings.timeout_seconds). A server that
accepts the TCP connection then never responds would otherwise hang the
send indefinitely and wedge the evaluator loop -- core.evaluator's reaper
only reclaims a stranded job_runs row on a LATER tick by wall-clock
comparison, it cannot unblock an in-flight call. digest.factory.build_sender
enforces timeout_seconds < Settings.digest_reaper_timeout_seconds at
construction, so the SMTP call always times out before the reaper's own
staleness window would need to reclaim the same row.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from email.message import EmailMessage

from autolycos.safety import DomainPolicy

from kerdoos.digest.render import render_digest
from kerdoos.digest.templates import render_digest_html
from kerdoos.digest.view import build_digest_view
from kerdoos.persistence.ports import ScrapeRecord
from kerdoos.registry.ports import ConfigStore, DigestJob

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SmtpSettings:
    """SMTP connection parameters. Always sourced from Settings/env
    (kerdoos.config.get_settings) -- never hardcoded infra details."""

    host: str
    port: int
    from_addr: str
    username: str | None = None
    password: str | None = None
    use_tls: bool = True
    timeout_seconds: float = 30.0


def _clean_header(value: str) -> str:
    """Neutralize CR/LF before a value reaches an email header or the
    text/plain body (S1 CWE-93). Interior newlines are collapsed to spaces,
    matching digest.render._sanitize_error's discipline."""
    return value.replace("\r", " ").replace("\n", " ").strip()


class SmtpDigestSender:
    """Renders the digest (HTML + text/plain) and emails it via SMTP."""

    def __init__(
        self,
        config_store: ConfigStore,
        domain_policy: DomainPolicy,
        email_lookup: Callable[[str], str | None],
        smtp_settings: SmtpSettings,
    ) -> None:
        self._config = config_store
        self._domain_policy = domain_policy
        self._email_lookup = email_lookup
        self._smtp = smtp_settings

    def send(
        self,
        job: DigestJob,
        records: list[ScrapeRecord],
        generated_at: str,
        tier2_labels: Mapping[str, str],
    ) -> bool:
        to_addr = self._email_lookup(job.owner_id)
        if not to_addr:
            logger.info(
                "digest for job=%s owner=%s: no email configured, skipping "
                "(will retry on a later window)", job.id, job.owner_id,
            )
            return False

        # S2: owner-scoped read only -- never a global/unscoped registry sweep.
        registry = self._config.load(job.owner_id)
        source_urls: dict[str, str] = {
            source.source_id: source.url
            for _product, source, _site in registry.iter_sources()
        }

        view = build_digest_view(
            job, records, generated_at, dict(tier2_labels), source_urls,
            self._domain_policy,
        )
        html_body = render_digest_html(job.template_id, view)
        text_body = _clean_header_block(
            render_digest(records, generated_at, dict(tier2_labels)))

        message = EmailMessage()
        message["Subject"] = _clean_header(f"Kerdoos digest: {job.name}")
        message["From"] = _clean_header(self._smtp.from_addr)
        message["To"] = _clean_header(to_addr)
        message.set_content(text_body)
        message.add_alternative(html_body, subtype="html")

        with smtplib.SMTP(
            self._smtp.host, self._smtp.port, timeout=self._smtp.timeout_seconds,
        ) as client:
            if self._smtp.use_tls:
                # S6 (CWE-295): explicit context -- check_hostname=True,
                # verify_mode=CERT_REQUIRED. No STARTTLS support on the
                # server -> SMTPNotSupportedError propagates uncaught
                # (fail-closed, never a plaintext fallback).
                client.starttls(context=ssl.create_default_context())
            if self._smtp.username and self._smtp.password:
                client.login(self._smtp.username, self._smtp.password)
            client.send_message(message)
        return True


def _clean_header_block(body: str) -> str:
    """Strip bare CR from the text/plain body (S1) without collapsing the
    intentional newlines between digest lines -- only \\r is neutralized,
    \\n stays as the line separator."""
    return body.replace("\r", "")
