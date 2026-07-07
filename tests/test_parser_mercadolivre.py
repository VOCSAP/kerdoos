"""MercadoLivreParser: single-price extraction on the REAL rendered dump.

The fixture `mercadolivre_mlb35045987.html` is the captured spike render (1.3 MB,
spike/MercadoLivre_render.html, /p/MLB35045987), so the scoping is stressed
against the true DOM density: the single <meta itemprop="price" content="9433">
under id="price", the SECOND data-testid="price-part" (10x de R$ 943,30
installment) and dozens of recommended-product andes-money-amount spans. The
effective price is volatile (invariant #4), so this is the exact value present
in this capture: R$ 9.433 -> 943300 cents. The 10x installment (943,30 -> 94330)
must NEVER be read.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from core.domain import Availability, ParseError
from parsers.adapters.mercadolivre import MercadoLivreParser
from parsers.ports import ParserSpec

_FIXTURE = Path(__file__).parent / "fixtures" / "mercadolivre_mlb35045987.html"


def _parser() -> MercadoLivreParser:
    return MercadoLivreParser(ParserSpec(kind="mercadolivre"))


class MercadoLivreRealDumpTest(unittest.TestCase):
    def setUp(self) -> None:
        self.html = _FIXTURE.read_text(encoding="utf-8")

    def test_extracts_single_price_into_both_regular_slots(self) -> None:
        # Provisional Option A: the single headline price fills BOTH regular
        # slots; member slots stay None (ML has no membership tier here).
        extract = _parser().extract(self.html)
        self.assertEqual(extract.price_pix_cents, 943300)
        self.assertEqual(extract.price_card_cents, 943300)
        self.assertIsNone(extract.price_pix_member_cents)
        self.assertIsNone(extract.price_card_member_cents)
        self.assertEqual(extract.currency, "BRL")

    def test_installment_price_is_never_read(self) -> None:
        # The 10x de R$ 943,30 per-installment amount (94330) must not leak into
        # any slot -- it has no <meta itemprop="price">, the parser anchors on
        # the product meta only.
        extract = _parser().extract(self.html)
        self.assertNotEqual(extract.price_pix_cents, 94330)
        self.assertNotEqual(extract.price_card_cents, 94330)

    def test_availability_in_stock(self) -> None:
        self.assertEqual(_parser().extract(self.html).availability,
                         Availability.IN_STOCK)


class MercadoLivreSyntheticTest(unittest.TestCase):
    def test_out_of_stock_marker_wins(self) -> None:
        html = (
            '<div id="price"><meta itemprop="price" content="1999">'
            '<span>R$ 1.999</span></div>'
            '<div id="ui-pdp-stock">Ficou sem estoque</div>'
        )
        extract = _parser().extract(html)
        self.assertEqual(extract.price_pix_cents, 199900)
        self.assertEqual(extract.availability, Availability.OUT_OF_STOCK)

    def test_unknown_when_no_stock_signal(self) -> None:
        html = '<div id="price"><meta itemprop="price" content="1500"></div>'
        self.assertEqual(_parser().extract(html).availability,
                         Availability.UNKNOWN)

    def test_decimal_meta_value_is_supported(self) -> None:
        # A meta content with cents (e.g. "1999.90") -> 199990 cents.
        html = ('<div id="price"><meta itemprop="price" content="1999.90">'
                '<div id="buybox_available_quantity"></div></div>')
        extract = _parser().extract(html)
        self.assertEqual(extract.price_pix_cents, 199990)
        self.assertEqual(extract.availability, Availability.IN_STOCK)

    def test_fail_closed_when_no_price(self) -> None:
        # Fail-closed: no locatable price -> ParseError (orchestrator degrades to
        # INDETERMINATE), never a silent zero or a false OutOfStock.
        with self.assertRaises(ParseError):
            _parser().extract("<html><body>no price here</body></html>")

    def test_fail_closed_when_price_block_absent(self) -> None:
        # A stray meta OUTSIDE the id="price" block is not read (must be scoped).
        with self.assertRaises(ParseError):
            _parser().extract(
                '<div id="carousel"><meta itemprop="price" content="42"></div>')

    def test_meta_attribute_order_is_independent(self) -> None:
        # content BEFORE itemprop must still be parsed (nit a).
        html = ('<div id="price">'
                '<meta content="2500" itemprop="price"></div>')
        self.assertEqual(_parser().extract(html).price_pix_cents, 250000)

    def test_oos_marker_outside_stock_window_is_ignored(self) -> None:
        # An OOS phrase far from the stock anchor (a recommended product) must
        # NOT flip availability: OOS is read only within the stock window (nit b).
        html = (
            '<div id="price"><meta itemprop="price" content="1500"></div>'
            '<div id="buybox_available_quantity">Comprar agora</div>'
            + "<span>filler</span>" * 400
            + '<div class="rec">Produto X sem estoque</div>'
        )
        self.assertEqual(_parser().extract(html).availability,
                         Availability.IN_STOCK)


if __name__ == "__main__":
    unittest.main()
