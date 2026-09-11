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

S7 (roadmap 58d88fe0): smtplib.SMTP() is opened with an explicit socket
timeout (SmtpSettings.timeout_seconds). This is a PER-OPERATION timeout
(stdlib smtplib passes it to socket.create_connection, inherited by
starttls' SSL wrap) -- it bounds connect/EHLO/STARTTLS/login/sendmail
INDIVIDUALLY, so a server that accepts the TCP connection then never
responds at all is closed: that read unblocks. It is NOT a total deadline:
a relay that stays alive and answers one line just under the timeout on
every operation can still hold the session for a multiple of
timeout_seconds, longer than the reaper's staleness window. The total-
duration case is closed one layer up, in core.evaluator._run_plan_b, which
wraps the blocking send in asyncio.wait_for(..., timeout=reaper_timeout_seconds)
so the evaluator loop reclaims its send_semaphore slot even if the
underlying thread lingers (Python cannot forcibly kill a thread).

S8 (roadmap f3b644ab): send() retries a TRANSIENT failure a bounded number
of times (SmtpSettings.retry_attempts) inside this SAME call, never across
evaluator ticks -- see _is_retryable_connect_failure/_is_retryable_send_failure
for the exact classification boundary. Safe only because it is narrow:
retryable means either (a) an explicit SMTP 4xx reply (the server itself
said "not delivered, try again"), or (b) a connection-level failure
strictly BEFORE send_message() is ever called. Anything at or after that
point without an explicit 4xx -- a dropped connection, a raw timeout, a
5xx reply, a capability/credential rejection -- is ambiguous or permanent
and propagates unchanged, exactly as before this roadmap item (no retry,
job_runs='error', window consumed). A self-imposed absolute deadline
(SmtpSettings.send_deadline_seconds, computed once at the start of send())
is checked before every attempt and before every backoff sleep, so a
thread that outlives the evaluator's own wait_for budget (roadmap
3c0b1c80's orphan problem) can never start a further attempt after that
budget is spent, even though nothing can kill it from the outside.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
import time
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
    retry_attempts: int = 2
    retry_backoff_seconds: float = 2.0
    send_deadline_seconds: float = float("inf")


def _clean_header(value: str) -> str:
    """Neutralize CR/LF before a value reaches an email header or the
    text/plain body (S1 CWE-93). Interior newlines are collapsed to spaces,
    matching digest.render._sanitize_error's discipline."""
    return value.replace("\r", " ").replace("\n", " ").strip()


class _RetryableSmtpFailure(Exception):
    """Internal-only wrapper: never escapes send(). Carries the ORIGINAL
    smtplib/OSError failure so the caller can re-raise it verbatim once
    retries are exhausted -- core/evaluator.py must keep seeing the real
    exception type and message, not an internal retry-loop detail."""

    def __init__(self, original: BaseException) -> None:
        super().__init__(str(original))
        self.original = original


def _is_retryable_connect_failure(exc: BaseException) -> bool:
    """True only for a network/connection-level failure at connect,
    STARTTLS, or login -- e.g. connection refused, DNS failure, a dropped
    socket. Explicitly NOT a certificate/protocol mismatch (ssl.SSLError,
    including SSLCertVerificationError -- a PERMANENT configuration
    problem no retry can fix) and NOT a capability/credential rejection
    (SMTPNotSupportedError, SMTPAuthenticationError, SMTPHeloError --
    smtplib.SMTPException subclasses OSError in modern Python, so these
    must be excluded explicitly or a bare `isinstance(exc, OSError)` check
    would wrongly net every smtplib protocol exception, not just raw
    connection failures)."""
    if isinstance(exc, ssl.SSLError):
        return False
    if isinstance(exc, (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected)):
        return True
    if isinstance(exc, smtplib.SMTPException):
        return False
    return isinstance(exc, OSError)


def _is_retryable_send_failure(exc: BaseException) -> bool:
    """True ONLY for an explicit SMTP 4xx reply -- the server unambiguously
    said "not delivered, try again". A 5xx reply, or any failure with no
    explicit code at all (a dropped connection, a raw timeout occurring
    during or after send_message()), is either permanent or ambiguous
    about whether the message was transmitted -- never retried."""
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return all(400 <= code < 500 for code, _msg in exc.recipients.values())
    if isinstance(exc, smtplib.SMTPResponseException):
        return 400 <= exc.smtp_code < 500
    return False


def _send_smtp_once(smtp: SmtpSettings, message: EmailMessage) -> None:
    """One full SMTP transaction: connect, optional STARTTLS/login, send.
    Raises _RetryableSmtpFailure for a failure proven safe to retry (see
    the two classifiers above); any other exception propagates as-is."""
    try:
        client = smtplib.SMTP(smtp.host, smtp.port, timeout=smtp.timeout_seconds)
    except Exception as exc:  # noqa: BLE001 -- classified below, not swallowed
        if _is_retryable_connect_failure(exc):
            raise _RetryableSmtpFailure(exc) from exc
        raise
    with client:
        try:
            if smtp.use_tls:
                # S6 (CWE-295): explicit context -- check_hostname=True,
                # verify_mode=CERT_REQUIRED. No STARTTLS support on the
                # server -> SMTPNotSupportedError propagates uncaught
                # (fail-closed, never a plaintext fallback, never retried).
                client.starttls(context=ssl.create_default_context())
            if smtp.username and smtp.password:
                client.login(smtp.username, smtp.password)
        except Exception as exc:  # noqa: BLE001 -- classified below, not swallowed
            if _is_retryable_connect_failure(exc):
                raise _RetryableSmtpFailure(exc) from exc
            raise
        try:
            refused = client.send_message(message)
        except Exception as exc:  # noqa: BLE001 -- classified below, not swallowed
            if _is_retryable_send_failure(exc):
                raise _RetryableSmtpFailure(exc) from exc
            raise
        # C1 (roadmap f3b644ab gate): send_message() can accept SOME
        # recipients and refuse others via a non-empty returned dict,
        # WITHOUT raising -- a retry after that would re-send to whoever
        # already accepted. This adapter sends to exactly ONE recipient
        # (owners.email is a single column, no Cc/Bcc anywhere in this
        # module), so refused must always be empty; a non-empty dict here
        # would mean that invariant broke, and silently returning "sent"
        # would be worse than failing loud.
        assert not refused, (
            f"SmtpDigestSender: send_message() refused some but not all "
            f"recipients ({refused!r}) -- retry-safety assumes exactly one "
            f"recipient, this violates that invariant")


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
        # C1 (roadmap f3b644ab): the retry-safety reasoning below assumes
        # exactly ONE recipient (a partial accept/refuse split is then
        # impossible) -- measured: owners.email is a single TEXT column
        # (registry.auth_store.SqliteAuthStore.get_email), no Cc/Bcc
        # anywhere in this module. Guard the assumption instead of
        # silently trusting it.
        assert "," not in to_addr, (
            f"SmtpDigestSender expects exactly one recipient, got {to_addr!r}")

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

        # S8 (roadmap f3b644ab): the absolute deadline is computed ONCE
        # here, from this call's own configured timeouts -- checked before
        # every attempt and before every backoff, so a thread that outlives
        # the evaluator's wait_for budget can never start a further
        # attempt after that budget is spent (roadmap 3c0b1c80's orphan
        # problem: nothing can kill this thread from the outside).
        deadline = time.monotonic() + self._smtp.send_deadline_seconds
        attempts_left = self._smtp.retry_attempts + 1
        while True:
            attempts_left -= 1
            try:
                _send_smtp_once(self._smtp, message)
                return True
            except _RetryableSmtpFailure as wrapped:
                if attempts_left <= 0:
                    raise wrapped.original from None
                remaining = deadline - time.monotonic()
                if remaining < self._smtp.timeout_seconds:
                    raise wrapped.original from None
                backoff = min(
                    self._smtp.retry_backoff_seconds,
                    remaining - self._smtp.timeout_seconds)
                if backoff > 0:
                    time.sleep(backoff)
                if deadline - time.monotonic() < self._smtp.timeout_seconds:
                    raise wrapped.original from None


def _clean_header_block(body: str) -> str:
    """Strip bare CR from the text/plain body (S1) without collapsing the
    intentional newlines between digest lines -- only \\r is neutralized,
    \\n stays as the line separator."""
    return body.replace("\r", "")
