"""AmazonParser: 4-price extraction, tier scoping, strike exclusion, fail-closed.

The primary fixture `amazon_b0cvqgsrz9.html` is the REAL captured dump (1.5 MB,
spike/amazon_cffi.html, /dp/B0CVQGSRZ9), so the scoping is stressed against the
true DOM density -- notably the TWO best-offer-string-cc nodes (one per tier)
and the split-span PIX prices. Effective prices are volatile (invariant #4:
read the current price, never a figee reference), so these are the exact values
present in this capture: PIX regular R$7.181,05 (718105) / card regular
R$7.559,00 (755900) / PIX member R$7.029,05 (702905) / card member R$7.399,00
(739900), with a struck MSRP R$7.868,00 (786800) that must NEVER be read.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from kerdoos.core.domain import Availability, ParseError
from kerdoos.parsers.adapters.amazon import AmazonParser
from kerdoos.parsers.ports import ParserSpec

_FIXTURE = Path(__file__).parent / "fixtures" / "amazon_b0cvqgsrz9.html"


def _parser() -> AmazonParser:
    return AmazonParser(ParserSpec(kind="amazon"))


class AmazonFourPriceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.html = _FIXTURE.read_text(encoding="utf-8")

    def test_extracts_all_four_prices(self) -> None:
        extract = _parser().extract(self.html)
        self.assertEqual(extract.price_pix_cents, 718105)
        self.assertEqual(extract.price_card_cents, 755900)
        self.assertEqual(extract.price_pix_member_cents, 702905)
        self.assertEqual(extract.price_card_member_cents, 739900)
        self.assertEqual(extract.currency, "BRL")

    def test_four_slots_are_distinct_and_present(self) -> None:
        # Proof of row-id scoping against real density: the TWO duplicated
        # best-offer-string-cc nodes (regular vs member card) must resolve to
        # DIFFERENT values, and neither PIX slot may be None. If the scoping
        # collapsed, card_regular would equal card_member (or one would be None).
        extract = _parser().extract(self.html)
        slots = (extract.price_pix_cents, extract.price_card_cents,
                 extract.price_pix_member_cents, extract.price_card_member_cents)
        self.assertNotIn(None, slots)
        self.assertEqual(len(set(slots)), 4)
        self.assertNotEqual(extract.price_card_cents,
                            extract.price_card_member_cents)

    def test_struck_msrp_is_never_read(self) -> None:
        # R$7.868,00 (apex-basisprice-value, data-a-strike) must not appear in
        # any of the four slots.
        extract = _parser().extract(self.html)
        for cents in (extract.price_pix_cents, extract.price_card_cents,
                      extract.price_pix_member_cents,
                      extract.price_card_member_cents):
            self.assertNotEqual(cents, 786800)

    def test_card_price_is_full_not_installment(self) -> None:
        # "ou R$ 7.559,00 em ate 12x de R$ 629,99" -> full price, never 629,99.
        extract = _parser().extract(self.html)
        self.assertEqual(extract.price_card_cents, 755900)
        self.assertNotEqual(extract.price_card_cents, 62999)

    def test_availability_in_stock(self) -> None:
        self.assertEqual(_parser().extract(self.html).availability,
                         Availability.IN_STOCK)


class AmazonSingleTierTest(unittest.TestCase):
    """A page exposing only the regular tier -> member slots stay None."""

    _HTML = """
    <div id="apex_desktop_newAccordionRow">
      <span class="apex-pricetopay-value"><span class="a-offscreen">R$1.999,90</span></span>
    </div>
    <div id="reinvent_price_desktop_newAccordionRow">
      <span id="best-offer-string-cc">ou R$ 2.099,00 em ate 10x sem juros</span>
    </div>
    <div id="availability"><span>Em estoque</span></div>
    """

    def test_member_slots_are_none_when_absent(self) -> None:
        extract = _parser().extract(self._HTML)
        self.assertEqual(extract.price_pix_cents, 199990)
        self.assertEqual(extract.price_card_cents, 209900)
        self.assertIsNone(extract.price_pix_member_cents)
        self.assertIsNone(extract.price_card_member_cents)


class AmazonAvailabilityTest(unittest.TestCase):
    def _extract_with_availability(self, availability_html: str):
        html = (
            '<div id="apex_desktop_newAccordionRow">'
            '<span class="apex-pricetopay-value">'
            '<span class="a-offscreen">R$10,00</span></span></div>'
            + availability_html
        )
        return _parser().extract(html).availability

    def test_out_of_stock(self) -> None:
        # "sem estoque" contains the substring "em estoque": OOS must win.
        avail = self._extract_with_availability(
            '<div id="availability"><span>Temporariamente sem estoque</span></div>')
        self.assertEqual(avail, Availability.OUT_OF_STOCK)

    def test_unknown_when_no_availability_block(self) -> None:
        avail = self._extract_with_availability("")
        self.assertEqual(avail, Availability.UNKNOWN)


class AmazonFailClosedTest(unittest.TestCase):
    def test_no_price_anchors_raises_parse_error(self) -> None:
        # Fail-closed: no locatable price -> ParseError (orchestrator degrades to
        # INDETERMINATE), never a silent zero or a false OutOfStock.
        with self.assertRaises(ParseError):
            _parser().extract("<html><body>no prices here</body></html>")


if __name__ == "__main__":
    unittest.main()
