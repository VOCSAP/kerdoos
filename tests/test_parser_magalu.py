"""MagaluParser: __NEXT_DATA__ offers[0] extraction + fail-close on a block.

The resolved fixture `magalu_uc.html` is the SeleniumBase UC render (with
__NEXT_DATA__); `magalu_cffi.html` is the Akamai challenge page (no __NEXT_DATA__)
and proves the SECOND net of invariant #3: a blocked page fails closed to
ParseError (INDETERMINATE), never a false OutOfStock. Effective prices are
volatile (invariant #4); this capture: pix (bestPrice.totalAmount) and card
(price) are both 9433 reais -> 943300 cents.

`magalu_bab5438g3h_camoufox.html` and `magalu_238968700_camoufox.html` are
camoufox-tier renders whose request identifiers (x-forwarded-for, cookie,
rua.trans, ak.rid, ak.cport) were replaced with fixed placeholders. The first
carries distinct pix and card prices, so a swapped or misdirected path cannot
pass. The second is an unavailable item: its offer has no bestPrice, and its
JSON-LD still claims InStock at the list price, which the parser must ignore.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from kerdoos.core.domain import Availability, ParseError
from kerdoos.parsers.adapters.magalu import MagaluParser
from kerdoos.parsers.ports import ParserSpec

_FIXTURES = Path(__file__).parent / "fixtures"


def _parser() -> MagaluParser:
    return MagaluParser(ParserSpec(kind="magalu"))


class MagaluRealDumpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.html = (_FIXTURES / "magalu_uc.html").read_text(encoding="utf-8")

    def test_extracts_offer_prices(self) -> None:
        extract = _parser().extract(self.html)
        self.assertEqual(extract.price_pix_cents, 943300)   # bestPrice.totalAmount
        self.assertEqual(extract.price_card_cents, 943300)  # price
        self.assertEqual(extract.currency, "BRL")

    def test_installment_is_never_read(self) -> None:
        # bestInstallmentPlan.installmentAmount = 943.3 -> 94330 cents must not leak.
        extract = _parser().extract(self.html)
        for cents in (extract.price_pix_cents, extract.price_card_cents):
            self.assertNotEqual(cents, 94330)

    def test_availability_in_stock(self) -> None:
        self.assertEqual(_parser().extract(self.html).availability,
                         Availability.IN_STOCK)


class MagaluCamoufoxInStockDumpTest(unittest.TestCase):
    def setUp(self) -> None:
        html = (_FIXTURES / "magalu_bab5438g3h_camoufox.html").read_text(
            encoding="utf-8")
        self.extract = _parser().extract(html)

    def test_pix_is_best_price_total(self) -> None:
        self.assertEqual(self.extract.price_pix_cents, 807405)

    def test_card_is_offer_price(self) -> None:
        self.assertEqual(self.extract.price_card_cents, 849900)
        self.assertEqual(self.extract.currency, "BRL")

    def test_list_price_and_installment_are_never_read(self) -> None:
        # listPrice 9434 -> 943400, installmentAmount 849.9 -> 84990.
        for cents in (self.extract.price_pix_cents,
                      self.extract.price_card_cents):
            self.assertNotIn(cents, (943400, 84990))

    def test_availability_in_stock(self) -> None:
        self.assertEqual(self.extract.availability, Availability.IN_STOCK)


class MagaluCamoufoxOutOfStockDumpTest(unittest.TestCase):
    def setUp(self) -> None:
        html = (_FIXTURES / "magalu_238968700_camoufox.html").read_text(
            encoding="utf-8")
        self.extract = _parser().extract(html)

    def test_unavailable_item_is_out_of_stock(self) -> None:
        self.assertEqual(self.extract.availability,
                         Availability.OUT_OF_STOCK)

    def test_offer_without_best_price_leaves_pix_empty(self) -> None:
        self.assertIsNone(self.extract.price_pix_cents)
        self.assertEqual(self.extract.price_card_cents, 87900)

    def test_json_ld_list_price_is_never_read(self) -> None:
        self.assertNotEqual(self.extract.price_card_cents, 119900)


class MagaluFailCloseTest(unittest.TestCase):
    def test_akamai_challenge_page_fails_closed(self) -> None:
        # The Akamai challenge page has no __NEXT_DATA__ -> ParseError -> the
        # orchestrator degrades to INDETERMINATE (second net, invariant #3).
        akamai = (_FIXTURES / "magalu_cffi.html").read_text(
            encoding="utf-8", errors="replace")
        with self.assertRaises(ParseError):
            _parser().extract(akamai)

    def test_no_next_data_fails_closed(self) -> None:
        with self.assertRaises(ParseError):
            _parser().extract("<html><body>no next data</body></html>")


class MagaluSyntheticTest(unittest.TestCase):
    _BASE = ('<script id="__NEXT_DATA__" type="application/json">'
             '{{"props":{{"pageProps":{{"data":{{"item":{{'
             '"available":{avail},"offers":[{{"price":{price},'
             '"bestPrice":{{"totalAmount":{pix}}},'
             '"bestInstallmentPlan":{{"installmentAmount":943.3}}}}]}}}}}}}}}}'
             '</script>')

    def _html(self, price, pix, avail="true"):
        return self._BASE.format(price=price, pix=pix, avail=avail)

    def test_integer_reais_to_cents(self) -> None:
        extract = _parser().extract(self._html(9433, 9433))
        self.assertEqual(extract.price_pix_cents, 943300)
        self.assertEqual(extract.price_card_cents, 943300)

    def test_distinct_pix_and_card(self) -> None:
        extract = _parser().extract(self._html(1000, 900))
        self.assertEqual(extract.price_card_cents, 100000)
        self.assertEqual(extract.price_pix_cents, 90000)

    def test_available_false_is_out_of_stock(self) -> None:
        extract = _parser().extract(self._html(1000, 900, avail="false"))
        self.assertEqual(extract.availability, Availability.OUT_OF_STOCK)

    def test_malformed_next_data_fails_closed(self) -> None:
        html = ('<script id="__NEXT_DATA__" type="application/json">'
                '{not valid json}</script>')
        with self.assertRaises(ParseError):
            _parser().extract(html)

    def test_deeply_nested_next_data_fails_closed(self) -> None:
        # A hostile deeply nested payload makes the C json scanner raise
        # RecursionError; it must degrade to ParseError, not crash the run.
        depth = 100_000
        payload = "[" * depth + "]" * depth
        html = ('<script id="__NEXT_DATA__" type="application/json">'
                + payload + "</script>")
        with self.assertRaises(ParseError):
            _parser().extract(html)


if __name__ == "__main__":
    unittest.main()
