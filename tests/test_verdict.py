"""Three-valued verdict machine + end-to-end orchestration (#3)."""

from __future__ import annotations

import unittest

from autolycos.errors import FetchError
from autolycos.ports import FetchResult
from core.domain import Availability, Extract, ParseError, ScrapeStatus
from core.orchestrator import scrape_one
from core.verdict import compute_verdict


def _extract(pix=755800, card=None, availability=Availability.IN_STOCK) -> Extract:
    return Extract(price_pix_cents=pix, price_card_cents=card,
                   currency="BRL", availability=availability)


def _ok_fetch() -> FetchResult:
    return FetchResult(html="<x/>", status=200, method="http", challenged=False)


class VerdictTest(unittest.TestCase):
    def test_price_in_stock_is_ok(self) -> None:
        self.assertEqual(
            compute_verdict(_ok_fetch(), _extract()), ScrapeStatus.OK)

    def test_price_unknown_availability_is_ok(self) -> None:
        self.assertEqual(
            compute_verdict(_ok_fetch(), _extract(availability=Availability.UNKNOWN)),
            ScrapeStatus.OK)

    def test_price_out_of_stock_is_unavailable(self) -> None:
        self.assertEqual(
            compute_verdict(_ok_fetch(), _extract(availability=Availability.OUT_OF_STOCK)),
            ScrapeStatus.UNAVAILABLE)

    def test_no_fetch_is_indeterminate(self) -> None:
        self.assertEqual(compute_verdict(None, None), ScrapeStatus.INDETERMINATE)

    def test_challenged_is_indeterminate(self) -> None:
        challenged = FetchResult(html="", status=403, method="http", challenged=True)
        self.assertEqual(compute_verdict(challenged, None), ScrapeStatus.INDETERMINATE)

    def test_parse_failure_is_indeterminate(self) -> None:
        self.assertEqual(
            compute_verdict(_ok_fetch(), None, parse_error="boom"),
            ScrapeStatus.INDETERMINATE)


# --- fakes for orchestration ---

class _FakeFetcher:
    def __init__(self, result=None, exc=None):
        self._result = result
        self._exc = exc

    def fetch(self, url):
        if self._exc is not None:
            raise self._exc
        return self._result


class _FakeParser:
    def __init__(self, extract=None, exc=None):
        self._extract = extract
        self._exc = exc

    def extract(self, html):
        if self._exc is not None:
            raise self._exc
        return self._extract


class OrchestratorTest(unittest.TestCase):
    def test_happy_path_records_ok(self) -> None:
        rec = scrape_one(
            _FakeFetcher(result=_ok_fetch()),
            _FakeParser(extract=_extract()),
            "aw3225qf:kabum", "https://www.kabum.com.br/produto/1",
            now="2026-07-06T00:00:00+00:00",
        )
        self.assertEqual(rec.status, ScrapeStatus.OK)
        self.assertEqual(rec.price_pix_cents, 755800)
        self.assertEqual(rec.availability, Availability.IN_STOCK)
        self.assertIsNone(rec.error)
        self.assertEqual(rec.method, "http")

    def test_fetch_error_is_indeterminate_record(self) -> None:
        rec = scrape_one(
            _FakeFetcher(exc=FetchError("network down")),
            _FakeParser(extract=_extract()),
            "s", "https://www.kabum.com.br/x",
        )
        self.assertEqual(rec.status, ScrapeStatus.INDETERMINATE)
        self.assertIsNone(rec.price_pix_cents)
        self.assertIn("fetch:", rec.error)

    def test_parse_error_is_indeterminate_record(self) -> None:
        rec = scrape_one(
            _FakeFetcher(result=_ok_fetch()),
            _FakeParser(exc=ParseError("no price")),
            "s", "https://www.kabum.com.br/x",
        )
        self.assertEqual(rec.status, ScrapeStatus.INDETERMINATE)
        self.assertIn("parse:", rec.error)

    def test_challenge_short_circuits_to_indeterminate(self) -> None:
        challenged = FetchResult(html="", status=429, method="http", challenged=True)
        rec = scrape_one(
            _FakeFetcher(result=challenged),
            _FakeParser(extract=_extract()),
            "s", "https://www.kabum.com.br/x",
        )
        self.assertEqual(rec.status, ScrapeStatus.INDETERMINATE)
        self.assertIn("challenged", rec.error)

    def test_unexpected_fetcher_exception_is_indeterminate(self) -> None:
        # Fail-closed net: an exception the port contract does NOT sanction
        # (RecursionError, ValueError, a future adapter bug...) must degrade to
        # INDETERMINATE, never propagate (invariant #3).
        rec = scrape_one(
            _FakeFetcher(exc=RecursionError("boom")),
            _FakeParser(extract=_extract()),
            "s", "https://www.kabum.com.br/x",
        )
        self.assertEqual(rec.status, ScrapeStatus.INDETERMINATE)
        self.assertIn("unexpected", rec.error)
        self.assertIn("RecursionError", rec.error)

    def test_unexpected_parser_exception_is_indeterminate(self) -> None:
        rec = scrape_one(
            _FakeFetcher(result=_ok_fetch()),
            _FakeParser(exc=ValueError("bad state")),
            "s", "https://www.kabum.com.br/x",
        )
        self.assertEqual(rec.status, ScrapeStatus.INDETERMINATE)
        self.assertIn("unexpected", rec.error)


if __name__ == "__main__":
    unittest.main()
