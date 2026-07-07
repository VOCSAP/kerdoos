"""PichauParser: dual-price extraction from the RSC flight, JSON-LD trap avoided.

The fixture `pichau_cv700b.html` is the captured curl_cffi SSR document, so the
scoping is stressed against the real escaped-JSON flight: the pichau_prices
object with avista/base_price/final_price, plus a JSON-LD Offer whose price is
the CARD price. Effective prices are volatile (invariant #4); these are the exact
values in this capture: pix (a-vista, PIX) 149.99 -> 14999, card (final_price)
176.46 -> 17646, base_price (reference) 241.16 -> 24116 (never read).
"""

from __future__ import annotations

import unittest
from pathlib import Path

from core.domain import Availability, ParseError
from parsers.adapters.pichau import PichauParser
from parsers.ports import ParserSpec

_FIXTURE = Path(__file__).parent / "fixtures" / "pichau_cv700b.html"


def _parser() -> PichauParser:
    return PichauParser(ParserSpec(kind="pichau"))


class PichauRealDumpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.html = _FIXTURE.read_text(encoding="utf-8")

    def test_extracts_flight_prices(self) -> None:
        extract = _parser().extract(self.html)
        self.assertEqual(extract.price_pix_cents, 14999)     # pichau_prices.avista
        self.assertEqual(extract.price_card_cents, 17646)    # .final_price
        self.assertIsNone(extract.price_pix_member_cents)
        self.assertIsNone(extract.price_card_member_cents)
        self.assertEqual(extract.currency, "BRL")

    def test_base_price_reference_is_never_read(self) -> None:
        extract = _parser().extract(self.html)
        for cents in (extract.price_pix_cents, extract.price_card_cents):
            self.assertNotEqual(cents, 24116)   # base_price reference

    def test_jsonld_card_price_is_not_taken_for_pix(self) -> None:
        # The JSON-LD Offer price is 176.46 (the CARD price); pix must be the
        # a-vista 149.99, never the JSON-LD value.
        extract = _parser().extract(self.html)
        self.assertEqual(extract.price_pix_cents, 14999)
        self.assertNotEqual(extract.price_pix_cents, 17646)

    def test_availability_in_stock(self) -> None:
        self.assertEqual(_parser().extract(self.html).availability,
                         Availability.IN_STOCK)


class PichauSyntheticTest(unittest.TestCase):
    def test_escaped_flight_form(self) -> None:
        html = (r'x"pichau_prices\":{\"avista\":149.99,\"avista_discount\":15,'
                r'\"base_price\":241.16,\"final_price\":176.46}'
                r'y\"stock_status\":\"IN_STOCK\"z')
        extract = _parser().extract(html)
        self.assertEqual(extract.price_pix_cents, 14999)
        self.assertEqual(extract.price_card_cents, 17646)
        self.assertEqual(extract.availability, Availability.IN_STOCK)

    def test_plain_flight_form(self) -> None:
        html = ('"pichau_prices":{"avista":99.90,"base_price":150.00,'
                '"final_price":120.00}"stock_status":"OUT_OF_STOCK"')
        extract = _parser().extract(html)
        self.assertEqual(extract.price_pix_cents, 9990)
        self.assertEqual(extract.price_card_cents, 12000)
        self.assertEqual(extract.availability, Availability.OUT_OF_STOCK)

    def test_avista_discount_sibling_is_not_matched(self) -> None:
        # 'avista_discount' must not be read as the avista price.
        html = '"pichau_prices":{"avista_discount":15,"avista":50.00,"final_price":60.00}'
        self.assertEqual(_parser().extract(html).price_pix_cents, 5000)

    def test_related_product_oos_before_anchor_is_ignored(self) -> None:
        # A related product's OUT_OF_STOCK appears BEFORE the pichau_prices
        # anchor. A GLOBAL first-match would return it (false OUT_OF_STOCK); the
        # after-only window from the anchor skips it and reads the main product's
        # IN_STOCK. This is what makes the windowing load-bearing (OLD != NEW).
        html = (
            '"stock_status":"OUT_OF_STOCK"'                       # related, pre-anchor
            '"pichau_prices":{"avista":149.99,"final_price":176.46}'
            '"stock_status":"IN_STOCK"'                            # main, post-anchor
        )
        extract = _parser().extract(html)
        self.assertEqual(extract.price_pix_cents, 14999)
        self.assertEqual(extract.availability, Availability.IN_STOCK)

    def test_fail_closed_when_no_flight(self) -> None:
        with self.assertRaises(ParseError):
            _parser().extract("<html><body>no flight here</body></html>")


if __name__ == "__main__":
    unittest.main()
