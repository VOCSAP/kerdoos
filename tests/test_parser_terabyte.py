"""TerabyteParser: dual-price extraction on the REAL SSR dump, skip-trap ids.

The fixture `terabyte_40561.html` is the captured curl_cffi SSR document (195 KB,
/produto/40561), so the scoping is stressed against the real duplicated ids: the
EMPTY first #valParc (top sticky bar), the hidden '#valVista R$ 000,00' template,
the adjacent 12x installment span, and the struck reference. Effective prices are
volatile (invariant #4); these are the exact values in this capture: pix (a vista
boleto) R$ 749,09 -> 74909, card (12x sem juros) R$ 881,28 -> 88128.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from core.domain import Availability, ParseError
from parsers.adapters.terabyte import TerabyteParser
from parsers.ports import ParserSpec

_FIXTURE = Path(__file__).parent / "fixtures" / "terabyte_40561.html"


def _parser() -> TerabyteParser:
    return TerabyteParser(ParserSpec(kind="terabyte"))


class TerabyteRealDumpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.html = _FIXTURE.read_text(encoding="utf-8")

    def test_extracts_both_prices(self) -> None:
        extract = _parser().extract(self.html)
        self.assertEqual(extract.price_pix_cents, 74909)      # #valVista
        self.assertEqual(extract.price_card_cents, 88128)     # #valParc
        self.assertIsNone(extract.price_pix_member_cents)
        self.assertIsNone(extract.price_card_member_cents)
        self.assertEqual(extract.currency, "BRL")

    def test_traps_are_never_read(self) -> None:
        extract = _parser().extract(self.html)
        # 000,00 hidden template, 12x installment 73,44, struck ref 1.559,99.
        for cents in (extract.price_pix_cents, extract.price_card_cents):
            self.assertNotIn(cents, (0, 7344, 155999))

    def test_availability_in_stock(self) -> None:
        self.assertEqual(_parser().extract(self.html).availability,
                         Availability.IN_STOCK)


class TerabyteSyntheticTest(unittest.TestCase):
    def test_empty_first_valparc_is_skipped(self) -> None:
        # First #valParc empty (top bar), sibling installment span, real value
        # only in the second #valParc -> must read 881,28, never 73,44.
        html = (
            '<span id="valParc" class="valParc"></span>'
            '<span id="Parc">R$ 73,44</span>'
            '<p id="valVista">R$ 749,09</p>'
            '<span id="valParc" class="valParc">R$ 881,28</span>'
        )
        extract = _parser().extract(html)
        self.assertEqual(extract.price_pix_cents, 74909)
        self.assertEqual(extract.price_card_cents, 88128)

    def test_zero_template_is_skipped(self) -> None:
        html = ('<p id="valVista">R$ 000,00</p>'
                '<p id="valVista">R$ 749,09</p>')
        self.assertEqual(_parser().extract(html).price_pix_cents, 74909)

    def test_commented_esgotado_is_not_out_of_stock(self) -> None:
        html = ('<p id="valVista">R$ 10,00</p>'
                '<!-- quando produto estiver esgotado -->'
                '<span title="Produto disponivel no estoque."></span>')
        self.assertEqual(_parser().extract(html).availability,
                         Availability.IN_STOCK)

    def test_real_out_of_stock_marker_wins(self) -> None:
        html = ('<p id="valVista">R$ 10,00</p>'
                '<div class="tarja">Produto esgotado</div>')
        self.assertEqual(_parser().extract(html).availability,
                         Availability.OUT_OF_STOCK)

    def test_cross_sell_oos_outside_window_is_ignored(self) -> None:
        # An OOS marker on a related/cross-sell product FAR from the product
        # block must NOT flip the page to a false OUT_OF_STOCK (invariant #3).
        html = (
            '<p id="valVista">R$ 749,09</p>'
            '<span title="Produto disponivel no estoque."></span>'
            + "<span>filler</span>" * 300   # push the cross-sell out of window
            + '<div class="cross-sell">Outro produto: avise-me, sem estoque</div>'
        )
        self.assertEqual(_parser().extract(html).availability,
                         Availability.IN_STOCK)

    def test_fail_closed_when_no_price(self) -> None:
        with self.assertRaises(ParseError):
            _parser().extract("<html><body>no price here</body></html>")


if __name__ == "__main__":
    unittest.main()
