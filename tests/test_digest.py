"""M4: aggregated digest (invariant #8), pt-BR formatting, error sanitization."""

from __future__ import annotations

import unittest

from core.domain import Availability, ScrapeStatus
from digest.render import format_cents, render_digest
from persistence.ports import ScrapeRecord


def _rec(source_id="p:kabum:aa", status=ScrapeStatus.OK, pix=755800, card=755800,
         availability=Availability.IN_STOCK, method="http", error=None):
    return ScrapeRecord(
        source_id=source_id, ts="2026-07-06T00:00:00+00:00", status=status,
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
        # Sanitized error is capped well under the raw 500 chars.
        record_line = next(l for l in body.splitlines() if l.startswith("["))
        self.assertLess(len(record_line), 260)
        self.assertIn("...", record_line)


if __name__ == "__main__":
    unittest.main()
