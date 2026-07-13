"""Digest flat view-model + HTML render (ADR 0003 Phase 6b tranche 4,
security finding S3 CWE-79).

Two invariants under test:
  1. build_digest_view() must only ever produce plain str/None fields (never
     leak a domain/registry object into the Jinja render context).
  2. A disallowed-scheme/off-catalogue href must degrade to href=None rather
     than raising or aborting the whole digest (invariant #8: exactly one
     digest, never silently dropped over a single bad link) -- AND the
     Jinja render must HTML-escape any hostile content injected through a
     scraped field (source_id, error), never emit it raw.
"""

from __future__ import annotations

import dataclasses
import unittest

from autolycos.safety import DomainPolicy

from kerdoos.core.domain import Availability, ScrapeStatus
from kerdoos.digest.templates import render_digest_html
from kerdoos.digest.view import DigestLineView, build_digest_view
from kerdoos.persistence.ports import ScrapeRecord
from kerdoos.registry.ports import DigestJob

_POLICY = DomainPolicy(allowed_domains=frozenset({"kabum.com.br"}))


def _job(name: str = "job1") -> DigestJob:
    return DigestJob(
        id="job1", owner_id="owner1", name=name, frequency_kind="hourly",
        schedule_cron="0 * * * *",
    )


def _record(
    source_id: str = "owner1:p1:kabum:aa", error: str | None = None,
) -> ScrapeRecord:
    return ScrapeRecord(
        source_id=source_id, ts="2026-07-13T00:00:00+00:00", status=ScrapeStatus.OK,
        price_pix_cents=755800, price_card_cents=755800, currency="BRL",
        availability=Availability.IN_STOCK, method="http", error=error,
    )


class FlatViewModelTest(unittest.TestCase):
    def test_view_fields_are_plain_str_or_none_only(self) -> None:
        record = _record()
        view = build_digest_view(
            _job(), [record], "2026-07-13T00:00:00+00:00", {},
            {record.source_id: "https://www.kabum.com.br/p/1"}, _POLICY,
        )
        self.assertIsInstance(view.job_name, str)
        self.assertIsInstance(view.generated_at, str)
        self.assertEqual(len(view.lines), 1)
        line = view.lines[0]
        for field in dataclasses.fields(DigestLineView):
            value = getattr(line, field.name)
            self.assertTrue(
                value is None or isinstance(value, str),
                f"{field.name} is {type(value)!r}, not str/None -- a domain "
                f"object leaked into the flat view-model",
            )
        # No domain/registry type reachable at all -- every attribute access
        # above already proves this, but assert the concrete type too.
        self.assertIsInstance(line, DigestLineView)


class HrefSsrfGuardTest(unittest.TestCase):
    def test_off_catalogue_href_degrades_to_none_not_raise(self) -> None:
        record = _record()
        view = build_digest_view(
            _job(), [record], "2026-07-13T00:00:00+00:00", {},
            {record.source_id: "https://evil.example.com/phish"}, _POLICY,
        )
        self.assertEqual(len(view.lines), 1)
        self.assertIsNone(view.lines[0].href)

    def test_disallowed_scheme_href_degrades_to_none_not_raise(self) -> None:
        record = _record()
        view = build_digest_view(
            _job(), [record], "2026-07-13T00:00:00+00:00", {},
            {record.source_id: "javascript:alert(1)"}, _POLICY,
        )
        self.assertEqual(len(view.lines), 1)
        self.assertIsNone(view.lines[0].href)

    def test_missing_source_url_is_none_href(self) -> None:
        record = _record()
        view = build_digest_view(
            _job(), [record], "2026-07-13T00:00:00+00:00", {}, {}, _POLICY,
        )
        self.assertIsNone(view.lines[0].href)

    def test_allowed_href_is_preserved(self) -> None:
        record = _record()
        url = "https://www.kabum.com.br/produto/1/x"
        view = build_digest_view(
            _job(), [record], "2026-07-13T00:00:00+00:00", {},
            {record.source_id: url}, _POLICY,
        )
        self.assertEqual(view.lines[0].href, url)

    def test_one_bad_href_does_not_drop_other_lines_from_the_digest(self) -> None:
        good = _record("owner1:p1:kabum:aa")
        bad = _record("owner1:p2:kabum:bb")
        view = build_digest_view(
            _job(), [good, bad], "2026-07-13T00:00:00+00:00", {},
            {
                good.source_id: "https://www.kabum.com.br/p/1",
                bad.source_id: "https://evil.example.com/phish",
            },
            _POLICY,
        )
        self.assertEqual(len(view.lines), 2)
        by_source = {line.source_label: line for line in view.lines}
        self.assertIsNotNone(by_source[good.source_id].href)
        self.assertIsNone(by_source[bad.source_id].href)


class JinjaAutoescapeTest(unittest.TestCase):
    def test_hostile_source_label_is_html_escaped_in_render(self) -> None:
        hostile_source_id = '<script>alert(1)</script>'
        record = _record(source_id=hostile_source_id)
        view = build_digest_view(
            _job(), [record], "2026-07-13T00:00:00+00:00", {}, {}, _POLICY,
        )
        html = render_digest_html("default", view)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_hostile_error_field_is_html_escaped_in_render(self) -> None:
        record = _record(error='<img src=x onerror=alert(1)>')
        view = build_digest_view(
            _job(), [record], "2026-07-13T00:00:00+00:00", {}, {}, _POLICY,
        )
        html = render_digest_html("default", view)
        self.assertNotIn("<img src=x onerror=alert(1)>", html)
        self.assertIn("&lt;img", html)

    def test_hostile_job_name_is_html_escaped_in_render(self) -> None:
        job = _job(name='<script>alert(document.cookie)</script>')
        view = build_digest_view(
            job, [], "2026-07-13T00:00:00+00:00", {}, {}, _POLICY,
        )
        html = render_digest_html("default", view)
        self.assertNotIn("<script>alert(document.cookie)</script>", html)
        self.assertIn("&lt;script&gt;", html)


if __name__ == "__main__":
    unittest.main()
