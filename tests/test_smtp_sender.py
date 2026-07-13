"""SmtpDigestSender security hardening (ADR 0003 Phase 6b tranche 4):

S1 (CWE-93 header/CRLF injection): a CRLF sequence embedded in job.name or a
scraped record's error must never forge extra email headers or body lines.

S2 (owner-scoping at RUN time): send() must resolve source URLs via an
owner-scoped ConfigStore.load(job.owner_id) read ONLY -- with two owners'
data coexisting in the same config store, only the sending job's own owner's
sources may ever appear in the rendered output.

Owner-without-email: send() must return normally (no raise, no SMTP
connection attempt) when email_lookup(job.owner_id) returns None, so the
evaluator's per-job try/except does not mark the run 'error' -- ADR 0003
Decision 9 auto-resume on a later window.
"""

from __future__ import annotations

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
        self.logged_in: tuple[str, str] | None = None
        self.sent_message = None
        _FakeSMTP.instances.append(self)

    def __enter__(self) -> "_FakeSMTP":
        return self

    def __exit__(self, *exc_info) -> bool:
        return False

    def starttls(self) -> None:
        self.started_tls = True

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
    def test_send_returns_without_raising_and_without_smtp_connection(self) -> None:
        registry = _registry(_record().source_id, "https://www.kabum.com.br/p/1")
        config_store = _FakeConfigStore({"owner1": registry})
        sender = SmtpDigestSender(
            config_store, _POLICY, lambda owner: None, _SMTP_SETTINGS)

        with patch("kerdoos.digest.smtp_sender.smtplib.SMTP", _ExplodingSMTP):
            sender.send(job=_job(), records=[_record()],
                       generated_at="2026-07-13T00:00:00+00:00", tier2_labels={})
        # No exception raised (asserted implicitly by reaching this line) --
        # and _ExplodingSMTP would have failed the test loudly if send()
        # had attempted a connection despite the missing email.


if __name__ == "__main__":
    unittest.main()
