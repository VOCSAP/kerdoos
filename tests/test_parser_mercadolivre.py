"""MercadoLivreParser: single-price extraction on the REAL rendered dump.

The fixture `mercadolivre_mlb35045987.html` is the captured spike render (1.3 MB,
spike/MercadoLivre_render.html, /p/MLB35045987), so the scoping is stressed
against the true DOM density: the single <meta itemprop="price" content="9433">
under id="price", the SECOND data-testid="price-part" (10x de R$ 943,30
installment) and dozens of recommended-product andes-money-amount spans. The
effective price is volatile (invariant #4), so this is the exact value present
in this capture: R$ 9.433 -> 943300 cents. The 10x installment (943,30 -> 94330)
must NEVER be read.

`mercadolivre_mlb35045987_camoufox.html` is a later capture (roadmap 35a14a39)
of the SAME listing where ML dropped the id="price"/meta itemprop="price" block
entirely: the effective price now lives only in a <script
type="application/ld+json"> schema.org/Product node (offers.price). Session/
device identifiers (d2id, csrf token, request/correlation/tracking ids) were
replaced with fixed placeholders before committing; the product data (sku,
price, reviews) is untouched.

`mercadolivre_captcha_wall_camoufox.html` is the captcha wall the camoufox tier
received at HTTP 200 instead of the listing; looks_challenged does not flag it,
so the parser is the only net and must fail closed. Its tracking id was
replaced with a fixed placeholder.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from kerdoos.core.domain import Availability, ParseError
from kerdoos.parsers.adapters.mercadolivre import MercadoLivreParser
from kerdoos.parsers.ports import ParserSpec

_FIXTURE = Path(__file__).parent / "fixtures" / "mercadolivre_mlb35045987.html"
_JSONLD_FIXTURE = (
    Path(__file__).parent / "fixtures"
    / "mercadolivre_mlb35045987_camoufox.html")
_WALL_FIXTURE = (
    Path(__file__).parent / "fixtures"
    / "mercadolivre_captcha_wall_camoufox.html")


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


class MercadoLivreCamoufoxWallTest(unittest.TestCase):
    def test_real_captcha_wall_fails_closed(self) -> None:
        html = _WALL_FIXTURE.read_text(encoding="utf-8")
        with self.assertRaises(ParseError):
            _parser().extract(html)


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


class MercadoLivreJsonLdTest(unittest.TestCase):
    def test_real_camoufox_dump_extracts_jsonld_price(self) -> None:
        # RED before the fix: the old meta-only parser raises ParseError on
        # this dump (measured: "no MercadoLivre price located (meta
        # itemprop=price)") because id="price"/meta itemprop="price" is gone
        # from the current markup. JSON-LD offers.price is now read first.
        html = _JSONLD_FIXTURE.read_text(encoding="utf-8")
        extract = _parser().extract(html)
        self.assertEqual(extract.price_pix_cents, 943400)
        self.assertEqual(extract.price_card_cents, 943400)
        self.assertEqual(extract.currency, "BRL")
        self.assertEqual(extract.availability, Availability.IN_STOCK)

    def test_meta_repli_when_no_jsonld_product(self) -> None:
        # No JSON-LD Product node at all -> falls back to the old meta anchor,
        # never ParseError as long as the meta path can still resolve a price.
        html = ('<div id="price"><meta itemprop="price" content="1999">'
                '</div><div id="buybox_available_quantity"></div>')
        extract = _parser().extract(html)
        self.assertEqual(extract.price_pix_cents, 199900)
        self.assertEqual(extract.availability, Availability.IN_STOCK)

    def test_jsonld_without_offers_price_raises_parse_error(self) -> None:
        # A Product node was found and is unambiguous, but its offers carry no
        # usable price: fail closed, never silently fall back to meta (which
        # could read a stale/unrelated price from elsewhere on the page).
        html = (
            '<script type="application/ld+json">'
            '{"@type":"Product","sku":"MLB1","offers":{"availability":'
            '"https://schema.org/InStock"}}</script>')
        with self.assertRaises(ParseError):
            _parser().extract(html)

    def test_jsonld_multiple_products_without_sku_match_raises_parse_error(
            self) -> None:
        # Two Product nodes, neither sku matching the page's own canonical
        # product id (MLB1): never guess, fail closed.
        html = (
            '<link rel="canonical" href="https://www.mercadolivre.com.br/p/MLB1">'
            '<script type="application/ld+json">'
            '{"@type":"Product","sku":"MLB2","offers":{"price":100,'
            '"priceCurrency":"BRL"}}</script>'
            '<script type="application/ld+json">'
            '{"@type":"Product","sku":"MLB3","offers":{"price":200,'
            '"priceCurrency":"BRL"}}</script>')
        with self.assertRaises(ParseError):
            _parser().extract(html)

    def test_jsonld_multiple_products_matching_sku_is_selected(self) -> None:
        # One of two Product nodes matches the page's own canonical id:
        # that one wins, never the first at random.
        html = (
            '<link rel="canonical" href="https://www.mercadolivre.com.br/p/MLB2">'
            '<script type="application/ld+json">'
            '{"@type":"Product","sku":"MLB2","offers":{"price":100,'
            '"priceCurrency":"BRL","availability":'
            '"https://schema.org/InStock"}}</script>'
            '<script type="application/ld+json">'
            '{"@type":"Product","sku":"MLB3","offers":{"price":200,'
            '"priceCurrency":"BRL"}}</script>')
        extract = _parser().extract(html)
        self.assertEqual(extract.price_pix_cents, 10000)

    def test_jsonld_out_of_stock_maps_to_out_of_stock(self) -> None:
        html = (
            '<script type="application/ld+json">'
            '{"@type":"Product","sku":"MLB1","offers":{"price":9999,'
            '"priceCurrency":"BRL","availability":'
            '"https://schema.org/OutOfStock"}}</script>')
        extract = _parser().extract(html)
        self.assertEqual(extract.availability, Availability.OUT_OF_STOCK)

    def test_jsonld_unrecognized_availability_is_unknown(self) -> None:
        html = (
            '<script type="application/ld+json">'
            '{"@type":"Product","sku":"MLB1","offers":{"price":9999,'
            '"priceCurrency":"BRL","availability":'
            '"https://schema.org/PreOrder"}}</script>')
        extract = _parser().extract(html)
        self.assertEqual(extract.availability, Availability.UNKNOWN)

    def test_jsonld_non_brl_currency_raises_parse_error(self) -> None:
        # offers.priceCurrency is trusted, never copied verbatim: a non-BRL
        # offer must not be funnelled through to_cents as if it were reais.
        html = (
            '<script type="application/ld+json">'
            '{"@type":"Product","sku":"MLB1","offers":{"price":100,'
            '"priceCurrency":"USD"}}</script>')
        with self.assertRaises(ParseError):
            _parser().extract(html)

    def test_jsonld_single_product_sku_mismatch_with_canonical_raises(
            self) -> None:
        # Even with only ONE Product node (no ambiguity to resolve), a sku
        # that disagrees with the page's own canonical id is a stale/unrelated
        # variant, never silently accepted.
        html = (
            '<link rel="canonical" href="https://www.mercadolivre.com.br/p/MLB1">'
            '<script type="application/ld+json">'
            '{"@type":"Product","sku":"MLB2","offers":{"price":4321,'
            '"priceCurrency":"BRL"}}</script>')
        with self.assertRaises(ParseError):
            _parser().extract(html)

    def test_malformed_jsonld_block_is_ignored_not_crashed(self) -> None:
        # A structurally broken JSON-LD block (unquoted key) sits alongside a
        # valid one: the malformed block is skipped, no exception leaks out,
        # and the valid Product is still used.
        html = (
            '<script type="application/ld+json">{not: valid json}</script>'
            '<script type="application/ld+json">'
            '{"@type":"Product","sku":"MLB1","offers":{"price":500,'
            '"priceCurrency":"BRL"}}</script>')
        extract = _parser().extract(html)
        self.assertEqual(extract.price_pix_cents, 50000)


if __name__ == "__main__":
    unittest.main()
