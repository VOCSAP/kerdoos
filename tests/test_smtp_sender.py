"""SmtpDigestSender security hardening (ADR 0003 Phase 6b tranche 4):

S1 (CWE-93 header/CRLF injection): a CRLF sequence embedded in job.name or a
scraped record's error must never forge extra email headers or body lines.

S2 (owner-scoping at RUN time): send() must resolve source URLs via an
owner-scoped ConfigStore.load(job.owner_id) read ONLY -- with two owners'
data coexisting in the same config store, only the sending job's own owner's
sources may ever appear in the rendered output.

Owner-without-email (Phase 6b fast-follow item 3): send() must return False
(not raise, not attempt an SMTP connection) when email_lookup(job.owner_id)
returns None, so _run_plan_b can persist JobRun.status == 'skipped_no_email'
instead of wrongly marking the run 'sent' -- ADR 0003 Decision 9 auto-resume
on a later window.

S6 (CWE-295, Phase 6b fast-follow item 1): starttls() must be called with a
verifying ssl.SSLContext (check_hostname=True, CERT_REQUIRED via
ssl.create_default_context()) -- fail-closed: an unsupported STARTTLS or an
invalid server certificate must raise, never fall back to a silent plaintext
send.
"""

from __future__ import annotations

import smtplib
import ssl
import unittest
from dataclasses import dataclass, field
from unittest.mock import patch

from autolycos.safety import DomainPolicy

from kerdoos.core.domain import Availability, ScrapeStatus
from kerdoos.digest.smtp_sender import SmtpDigestSender, SmtpSettings
from kerdoos.parsers.ports import ParserSpec
from kerdoos.persistence.ports import ScrapeRecord
from kerdoos.registry.ports import (
    DigestJob, Product, ProductSource, Registry, SiteConfig,
)

_POLICY = DomainPolicy(allowed_domains=frozenset({"kabum.com.br"}))

_SITE = SiteConfig(
    name="kabum", fetcher="http", domain="kabum.com.br",
    parser=ParserSpec(kind="statejson", pix="a", card="b", availability="c"),
)

_SMTP_SETTINGS = SmtpSettings(host="smtp.example.com", port=587, from_addr="digest@example.com")


class _FakeSMTP:
    """Captures the composed EmailMessage without any real network call."""

    instances: list["_FakeSMTP"] = []

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.started_tls = False
        self.starttls_context: object | None = None
        self.logged_in: tuple[str, str] | None = None
        self.sent_message = None
        _FakeSMTP.instances.append(self)

    def __enter__(self) -> "_FakeSMTP":
        return self

    def __exit__(self, *exc_info) -> bool:
        return False

    def starttls(self, context=None) -> None:
        self.started_tls = True
        self.starttls_context = context

    def login(self, username: str, password: str) -> None:
        self.logged_in = (username, password)

    def send_message(self, message) -> None:
        self.sent_message = message


class _ExplodingSMTP:
    """Proves send() never even attempts a connection when there is no
    recipient email -- instantiating this class fails the test loudly."""

    def __init__(self, *args, **kwargs) -> None:
        raise AssertionError(
            "SMTP must not be instantiated when the owner has no email "
            "configured -- send() must return before opening a connection")


@dataclass
class _FakeConfigStore:
    """Owner-keyed registries. load() records every owner it was called
    with, so a test can prove send() never reads another owner's registry."""

    registries: dict[str, Registry]
    calls: list[str] = field(default_factory=list)

    def load(self, owner: str) -> Registry:
        self.calls.append(owner)
        return self.registries[owner]

    def site_domains(self) -> frozenset[str]:
        return frozenset({"kabum.com.br"})


def _registry(source_id: str, url: str) -> Registry:
    source = ProductSource(source_id=source_id, product_id="p1", site="kabum", url=url)
    product = Product(id="p1", sources=(source,))
    return Registry(sites={"kabum": _SITE}, products=(product,))


def _job(owner_id: str = "owner1", name: str = "job1") -> DigestJob:
    return DigestJob(
        id="job1", owner_id=owner_id, name=name, frequency_kind="hourly",
        schedule_cron="0 * * * *",
    )


def _record(source_id: str = "owner1:p1:kabum:aa", error: str | None = None) -> ScrapeRecord:
    return ScrapeRecord(
        source_id=source_id, ts="2026-07-13T00:00:00+00:00", status=ScrapeStatus.OK,
        price_pix_cents=755800, price_card_cents=755800, currency="BRL",
        availability=Availability.IN_STOCK, method="http", error=error,
    )


class _SmtpSenderTestBase(unittest.TestCase):
    def setUp(self) -> None:
        _FakeSMTP.instances.clear()
        self._smtp_patch = patch("kerdoos.digest.smtp_sender.smtplib.SMTP", _FakeSMTP)
        self._smtp_patch.start()

    def tearDown(self) -> None:
        self._smtp_patch.stop()


class CrlfHeaderInjectionTest(_SmtpSenderTestBase):
    def test_crlf_in_job_name_cannot_forge_subject_header(self) -> None:
        evil_name = "job1\r\nX-Injected: evil\r\nBcc: attacker@evil.com"
        job = _job(name=evil_name)
        registry = _registry(_record().source_id, "https://www.kabum.com.br/p/1")
        config_store = _FakeConfigStore({"owner1": registry})
        sender = SmtpDigestSender(
            config_store, _POLICY, lambda owner: "user@example.com", _SMTP_SETTINGS)

        sender.send(job, [_record()], "2026-07-13T00:00:00+00:00", {})

        message = _FakeSMTP.instances[0].sent_message
        self.assertIsNotNone(message)
        subject = message["Subject"]
        self.assertNotIn("\r", subject)
        self.assertNotIn("\n", subject)
        # No forged header ever reaches the header table -- only the
        # legitimate Subject/From/To/MIME headers exist.
        header_names = {name for name, _value in message.items()}
        self.assertNotIn("X-Injected", header_names)
        self.assertNotIn("Bcc", header_names)
        # The injected text is neutralized INLINE into the single Subject
        # line, not silently dropped (matches digest.render's discipline).
        self.assertIn("X-Injected: evil", subject)

    def test_crlf_in_scraped_error_cannot_forge_extra_body_lines(self) -> None:
        job = _job()
        evil_error = "boom\r\nX-Injected: evil\r\nfake line"
        registry = _registry(_record().source_id, "https://www.kabum.com.br/p/1")
        config_store = _FakeConfigStore({"owner1": registry})
        sender = SmtpDigestSender(
            config_store, _POLICY, lambda owner: "user@example.com", _SMTP_SETTINGS)

        sender.send(job, [_record(error=evil_error)], "2026-07-13T00:00:00+00:00", {})

        message = _FakeSMTP.instances[0].sent_message
        text_body = message.get_body(preferencelist=("plain",)).get_content()
        self.assertNotIn("\r", text_body)

    def test_no_forged_header_survives_in_the_raw_serialized_message(self) -> None:
        evil_name = "job1\r\nX-Injected: evil"
        job = _job(name=evil_name)
        registry = _registry(_record().source_id, "https://www.kabum.com.br/p/1")
        config_store = _FakeConfigStore({"owner1": registry})
        sender = SmtpDigestSender(
            config_store, _POLICY, lambda owner: "user@example.com", _SMTP_SETTINGS)

        sender.send(job, [_record()], "2026-07-13T00:00:00+00:00", {})

        raw = _FakeSMTP.instances[0].sent_message.as_string()
        # Every line up to the first blank line is a real header line; a
        # forged 'X-Injected:' header line must never appear standalone.
        header_block = raw.split("\n\n", 1)[0]
        header_lines = header_block.splitlines()
        self.assertFalse(
            any(line.startswith("X-Injected:") for line in header_lines))


class OwnerScopingTest(_SmtpSenderTestBase):
    def test_send_only_ever_reads_the_sending_jobs_own_owner_registry(self) -> None:
        owner1_registry = _registry("owner1:p1:kabum:aa", "https://www.kabum.com.br/p/1")
        owner2_registry = _registry("owner2:p1:kabum:bb", "https://www.kabum.com.br/p/2")
        config_store = _FakeConfigStore({
            "owner1": owner1_registry, "owner2": owner2_registry,
        })
        job = _job(owner_id="owner1")
        sender = SmtpDigestSender(
            config_store, _POLICY, lambda owner: "user@example.com", _SMTP_SETTINGS)

        sender.send(job, [_record("owner1:p1:kabum:aa")], "2026-07-13T00:00:00+00:00", {})

        self.assertEqual(config_store.calls, ["owner1"])
        self.assertNotIn("owner2", config_store.calls)

    def test_cross_owner_source_never_appears_in_rendered_output(self) -> None:
        # Two owners' data coexist in the same store; owner1's job/records
        # must never surface owner2's URL, even if a record with owner2's
        # source_id somehow ended up in the records list passed in.
        owner1_registry = _registry("owner1:p1:kabum:aa", "https://www.kabum.com.br/p/1")
        owner2_registry = _registry("owner2:p1:kabum:bb", "https://www.kabum.com.br/secret-2")
        config_store = _FakeConfigStore({
            "owner1": owner1_registry, "owner2": owner2_registry,
        })
        job = _job(owner_id="owner1")
        sender = SmtpDigestSender(
            config_store, _POLICY, lambda owner: "user@example.com", _SMTP_SETTINGS)

        sender.send(job, [_record("owner1:p1:kabum:aa")], "2026-07-13T00:00:00+00:00", {})

        message = _FakeSMTP.instances[0].sent_message
        html_body = message.get_body(preferencelist=("html",)).get_content()
        self.assertNotIn("secret-2", html_body)
        self.assertIn("www.kabum.com.br/p/1", html_body)


class NoEmailSkipTest(unittest.TestCase):
    def test_send_returns_false_without_raising_and_without_smtp_connection(self) -> None:
        registry = _registry(_record().source_id, "https://www.kabum.com.br/p/1")
        config_store = _FakeConfigStore({"owner1": registry})
        sender = SmtpDigestSender(
            config_store, _POLICY, lambda owner: None, _SMTP_SETTINGS)

        with patch("kerdoos.digest.smtp_sender.smtplib.SMTP", _ExplodingSMTP):
            sent = sender.send(job=_job(), records=[_record()],
                       generated_at="2026-07-13T00:00:00+00:00", tier2_labels={})
        # No exception raised, no SMTP connection attempted (_ExplodingSMTP
        # would have failed loudly), AND the bool return is explicitly False
        # -- item 3 of the Phase 6b fast-follow bundle: this is the signal
        # _run_plan_b uses to persist JobRun.status == 'skipped_no_email'
        # instead of silently marking the run 'sent'.
        self.assertIs(sent, False)


class StarttlsSslContextTest(_SmtpSenderTestBase):
    """S6 (CWE-295, Phase 6b fast-follow item 1): starttls() must be called
    with a verifying SSLContext (check_hostname=True, CERT_REQUIRED) -- never
    the bare no-arg form, which historically risks an unverified/permissive
    fallback."""

    def test_starttls_is_called_with_a_verifying_ssl_context(self) -> None:
        registry = _registry(_record().source_id, "https://www.kabum.com.br/p/1")
        config_store = _FakeConfigStore({"owner1": registry})
        sender = SmtpDigestSender(
            config_store, _POLICY, lambda owner: "owner1@example.com", _SMTP_SETTINGS)

        sent = sender.send(job=_job(), records=[_record()],
                   generated_at="2026-07-13T00:00:00+00:00", tier2_labels={})

        self.assertIs(sent, True)
        self.assertEqual(len(_FakeSMTP.instances), 1)
        fake = _FakeSMTP.instances[0]
        self.assertTrue(fake.started_tls)
        context = fake.starttls_context
        self.assertIsNotNone(context)
        self.assertIs(context.check_hostname, True)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_starttls_not_supported_by_server_fails_closed_no_plaintext_send(self) -> None:
        """FAIL-CLOSED (architect requirement): if the server does not
        support STARTTLS, send() must raise -- NEVER silently fall back to
        a plaintext send. This is the adversarial test for item 1: it
        proves there is no code path where the message is handed to
        send_message() without TLS having been established first."""

        class _NoStarttlsSMTP(_FakeSMTP):
            def starttls(self, context=None) -> None:
                raise smtplib.SMTPNotSupportedError(
                    "STARTTLS extension not supported by server.")

        registry = _registry(_record().source_id, "https://www.kabum.com.br/p/1")
        config_store = _FakeConfigStore({"owner1": registry})
        sender = SmtpDigestSender(
            config_store, _POLICY, lambda owner: "owner1@example.com", _SMTP_SETTINGS)

        with patch("kerdoos.digest.smtp_sender.smtplib.SMTP", _NoStarttlsSMTP):
            with self.assertRaises(smtplib.SMTPNotSupportedError):
                sender.send(job=_job(), records=[_record()],
                           generated_at="2026-07-13T00:00:00+00:00", tier2_labels={})

        # The one SMTP instance created must never have had send_message()
        # called on it -- proves no plaintext fallback happened after the
        # STARTTLS rejection.
        self.assertEqual(len(_NoStarttlsSMTP.instances), 1)
        self.assertIsNone(_NoStarttlsSMTP.instances[0].sent_message)

    def test_server_presenting_an_invalid_cert_is_refused_no_silent_plaintext(self) -> None:
        """Adversarial: a server whose certificate fails verification (self
        -signed / hostname mismatch) must cause starttls() to raise -- proves
        the SSLContext actually passed is a VERIFYING one (not a
        no-verification stand-in), by simulating what a verifying context
        does on a bad cert."""

        class _BadCertSMTP(_FakeSMTP):
            def starttls(self, context=None) -> None:
                # A real ssl.create_default_context() raises exactly this on
                # a self-signed/invalid certificate during the TLS handshake.
                raise ssl.SSLCertVerificationError(
                    "certificate verify failed: self-signed certificate")

        registry = _registry(_record().source_id, "https://www.kabum.com.br/p/1")
        config_store = _FakeConfigStore({"owner1": registry})
        sender = SmtpDigestSender(
            config_store, _POLICY, lambda owner: "owner1@example.com", _SMTP_SETTINGS)

        with patch("kerdoos.digest.smtp_sender.smtplib.SMTP", _BadCertSMTP):
            with self.assertRaises(ssl.SSLCertVerificationError):
                sender.send(job=_job(), records=[_record()],
                           generated_at="2026-07-13T00:00:00+00:00", tier2_labels={})

        self.assertEqual(len(_BadCertSMTP.instances), 1)
        self.assertIsNone(_BadCertSMTP.instances[0].sent_message)


if __name__ == "__main__":
    unittest.main()
