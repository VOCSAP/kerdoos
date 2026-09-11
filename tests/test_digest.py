"""M4: aggregated digest (invariant #8), pt-BR formatting, error sanitization."""

from __future__ import annotations

import unittest

from kerdoos.core.domain import Availability, ScrapeStatus
from kerdoos.digest.render import format_cents, render_digest
from kerdoos.persistence.ports import ScrapeRecord


def _rec(source_id="p:kabum:aa", status=ScrapeStatus.OK, pix=755800, card=755800,
         availability=Availability.IN_STOCK, method="http", error=None,
         ts="2026-07-06T00:00:00+00:00"):
    return ScrapeRecord(
        source_id=source_id, ts=ts, status=status,
        price_pix_cents=pix, price_card_cents=card, currency="BRL",
        availability=availability, method=method, error=error,
    )


class FormatCentsTest(unittest.TestCase):
    def test_pt_br_grouping(self) -> None:
        self.assertEqual(format_cents(755800), "R$ 7.558,00")
        self.assertEqual(format_cents(9990), "R$ 99,90")
        self.assertEqual(format_cents(100000000), "R$ 1.000.000,00")

    def test_absent_is_dash(self) -> None:
        self.assertEqual(format_cents(None), "-")


class DigestAggregationTest(unittest.TestCase):
    def test_single_aggregated_report_for_all_records(self) -> None:
        records = [
            _rec("a:kabum:1", ScrapeStatus.OK),
            _rec("b:kabum:2", ScrapeStatus.UNAVAILABLE, pix=None, card=None,
                 availability=Availability.OUT_OF_STOCK),
            _rec("c:kabum:3", ScrapeStatus.INDETERMINATE, pix=None, card=None,
                 availability=Availability.UNKNOWN, method=None,
                 error="challenged (http 403)"),
        ]
        body = render_digest(records, "2026-07-06T00:00:00+00:00")
        # Invariant #8: ONE body, every source present, with a summary line.
        self.assertEqual(body.count("Kerdoos daily digest"), 1)
        self.assertIn("a:kabum:1", body)
        self.assertIn("b:kabum:2", body)
        self.assertIn("c:kabum:3", body)
        self.assertIn("sources: 3", body)
        self.assertIn("ok=1", body)
        self.assertIn("unavailable=1", body)
        self.assertIn("indeterminate=1", body)

    def test_empty_run_still_renders_one_digest(self) -> None:
        body = render_digest([], "2026-07-06T00:00:00+00:00")
        self.assertIn("sources: 0", body)
        self.assertIn("Kerdoos daily digest", body)


class DigestStalenessTest(unittest.TestCase):
    def test_stale_ok_record_is_not_presented_as_current(self) -> None:
        # An unscraped source's last OK record must read as aged, not fresh.
        stale = _rec(ts="2026-06-06T00:00:00+00:00")
        body = render_digest([stale], "2026-07-06T00:00:00+00:00")
        record_line = next(l for l in body.splitlines() if l.startswith("["))
        self.assertIn("scraped 2026-06-06", record_line)
        self.assertIn("(30d ago)", record_line)
        self.assertNotIn("generated_at: 2026-06-06", body)

    def test_fresh_record_shows_no_misleading_age_suffix(self) -> None:
        fresh = _rec(ts="2026-07-06T00:00:00+00:00")
        body = render_digest([fresh], "2026-07-06T00:00:00+00:00")
        record_line = next(l for l in body.splitlines() if l.startswith("["))
        self.assertIn("scraped 2026-07-06", record_line)
        self.assertNotIn("ago)", record_line)

    def test_future_dated_record_is_flagged_not_read_as_fresh(self) -> None:
        # record.ts after generated_at (clock skew) must not silently clamp
        # to "looks fresh, no suffix at all".
        future = _rec(ts="2026-07-07T00:00:00+00:00")
        body = render_digest([future], "2026-07-06T00:00:00+00:00")
        record_line = next(l for l in body.splitlines() if l.startswith("["))
        self.assertIn("(clock skew)", record_line)

    def test_invalid_timezone_falls_back_to_utc_not_raise(self) -> None:
        from kerdoos.digest.render import _scraped_at_label

        label = _scraped_at_label(
            "2026-07-06T00:00:00+00:00", "2026-07-06T00:00:00+00:00",
            tz_name="not/a-real-zone")
        self.assertIn("UTC", label)


class DigestSanitizationTest(unittest.TestCase):
    def test_error_newlines_stripped(self) -> None:
        # m1: a hostile error must not forge extra digest lines (log injection).
        evil = "boom\nsummary: ok=999\nfake line"
        body = render_digest([_rec(error=evil, status=ScrapeStatus.INDETERMINATE)],
                             "2026-07-06T00:00:00+00:00")
        # The real summary appears once; the forged one is neutralized (inline).
        self.assertEqual(body.count("\nsummary:"), 1)
        for line in body.splitlines():
            if "fake line" in line:
                # forged content stays glued into the single record line
                self.assertIn("boom", line)
                self.assertTrue(line.lstrip().startswith("["))

    def test_error_is_truncated(self) -> None:
        body = render_digest(
            [_rec(error="x" * 500, status=ScrapeStatus.INDETERMINATE)],
            "2026-07-06T00:00:00+00:00")
        record_line = next(l for l in body.splitlines() if l.startswith("["))
        segment = record_line.rsplit("  (", 1)[1]
        self.assertLessEqual(len(segment), 170)
        self.assertIn("...", record_line)


def _member_rec(source_id="p:amazon:1", pix=718010, card=755800,
                member_pix=702905, member_card=739900):
    return ScrapeRecord(
        source_id=source_id, ts="2026-07-06T00:00:00+00:00",
        status=ScrapeStatus.OK, price_pix_cents=pix, price_card_cents=card,
        currency="BRL", availability=Availability.IN_STOCK, method="tls",
        error=None, price_pix_member_cents=member_pix,
        price_card_member_cents=member_card,
    )


class DigestMemberTierTest(unittest.TestCase):
    def test_renders_four_prices_with_label(self) -> None:
        body = render_digest(
            [_member_rec()], "2026-07-06T00:00:00+00:00",
            {"p:amazon:1": "Prime"},
        )
        # Regular tier + labelled member tier, all four prices present.
        self.assertIn("pix=R$ 7.180,10", body)
        self.assertIn("card=R$ 7.558,00", body)
        self.assertIn("Prime:", body)
        self.assertIn("pix=R$ 7.029,05", body)
        self.assertIn("card=R$ 7.399,00", body)

    def test_falls_back_to_member_when_no_label(self) -> None:
        # Member prices present but the source has no tier2 label -> "member:".
        body = render_digest([_member_rec()], "2026-07-06T00:00:00+00:00")
        self.assertIn("member:", body)
        self.assertNotIn("Prime:", body)

    def test_member_segment_omitted_when_member_null(self) -> None:
        body = render_digest(
            [_member_rec(member_pix=None, member_card=None)],
            "2026-07-06T00:00:00+00:00", {"p:amazon:1": "Prime"},
        )
        # No member price -> no second-tier segment at all.
        self.assertNotIn("Prime:", body)
        self.assertNotIn("member:", body)

    def test_partial_member_still_renders_segment(self) -> None:
        # Only member card present (pix member NULL) -> segment shown, pix "-".
        body = render_digest(
            [_member_rec(member_pix=None)], "2026-07-06T00:00:00+00:00",
            {"p:amazon:1": "Prime"},
        )
        self.assertIn("Prime: pix=- card=R$ 7.399,00", body)


if __name__ == "__main__":
    unittest.main()
