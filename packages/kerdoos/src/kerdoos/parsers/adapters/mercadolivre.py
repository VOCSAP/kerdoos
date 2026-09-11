"""MercadoLivre parser adapter (kind "mercadolivre") -- stdlib only, no bs4.

MercadoLivre (mercadolivre.com.br) product pages are JS SPAs. Two DOM
generations of the same listing have been observed (roadmap 35a14a39):

  * Current: no id="price"/meta itemprop="price" block at all. The effective
    price lives in a <script type="application/ld+json"> schema.org/Product
    node, under offers.price (a bare number, reais) / offers.priceCurrency /
    offers.availability (a schema.org URL, e.g. ".../InStock").
  * Older (still the shape of the committed fixture
    tests/fixtures/mercadolivre_mlb35045987.html): a
    <div id="price"> ... <meta itemprop="price" content="9433"> ... </div>
    block, read DOM-side.

JSON-LD is tried FIRST; the meta anchor is the REPLI (fallback) for any page
that has no JSON-LD Product node at all. Once a JSON-LD Product node has been
unambiguously identified, it is treated as authoritative: a Product with no
usable offers.price raises ParseError rather than silently falling back to a
DOM heuristic that could read a stale or unrelated price.

Multiple Product nodes (rare edge case, not observed in any capture so far):
selected by matching "sku"/"productID" against the page's own canonical
product id (<link rel="canonical" href=".../MLB12345">). No unique match ->
ParseError (never guess the first one). Malformed JSON-LD blocks are silently
skipped (not every <script type="application/ld+json"> on the page is a
Product -- BreadcrumbList/Table nodes are expected and ignored).

Scoping discipline for the meta REPLI path (invariant #4 -- read the CURRENT
effective price):
  * The price is read from the <meta itemprop="price"> node scoped under the
    single id="price" block. The meta content is the clean, unformatted amount
    (reais), so no thousands/decimal parsing ambiguity.
  * The rendered DOM ALSO contains a second data-testid="price-part" node --
    the "10x de R$ 943,30" per-installment amount -- plus dozens of
    andes-money-amount spans from recommended products. Neither carries a
    <meta itemprop="price">, so anchoring on that meta reads the product price
    and never the installment (943,30 -> 94330) nor a recommendation.

Single-price mapping (PROVISIONAL -- Option A): MercadoLivre advertises no
distinct PIX price for this listing (a-vista == the headline price, with
interest-free card installments at the same total). Pending an operator ruling,
the single price fills BOTH the pix and card regular slots. Option B (pix-only,
card None) is a one-line change -- see the TODO in extract().

Availability on the meta REPLI path is DOM-based (there is no schema.org node
to read there): an explicit out-of-stock marker wins; otherwise the presence
of the buy box / stock element marks IN_STOCK; else UNKNOWN. Currency is BRL
(hardcoded there; the page carries no exploitable priceCurrency meta outside
JSON-LD). Prices funnel through the shared normalize.to_cents contract. If no
price can be located by either path the parser fails closed (ParseError -> the
orchestrator degrades the scrape to INDETERMINATE).
"""

from __future__ import annotations

import json
import re
from typing import Any

from kerdoos.core.domain import Availability, Extract, ParseError

from ..normalize import to_cents
from ..ports import ParserSpec

_CURRENCY = "BRL"

# Main price block anchor and the schema.org Offer meta inside it. The two
# lookaheads make the match INDEPENDENT of attribute order (itemprop and content
# may appear in either order inside the same <meta ...> tag).
_PRICE_BLOCK_ID = "price"
_PRICE_META_RE = re.compile(
    r'<meta\b'
    r'(?=[^>]*\bitemprop="price")'
    r'(?=[^>]*\bcontent="([0-9]+(?:\.[0-9]+)?)")'
    r'[^>]*>')
# Window from the price block to its meta: the meta sits a few hundred chars
# after id="price"; bounded so we never bleed into an unrelated later section.
_BLOCK_TO_META_WINDOW = 4000

_TAG_RE = re.compile(r"<[^>]+>")

# JSON-LD (order-independent on the type attribute, mirrors _PRICE_META_RE).
# Non-greedy up to the first closing tag: JSON-LD script content never
# legitimately contains a literal "</script>" (it would be JSON-escaped).
_JSON_LD_BLOCK_RE = re.compile(
    r'<script\b(?=[^>]*\btype="application/ld\+json")[^>]*>(.*?)</script>',
    re.DOTALL)
_CANONICAL_HREF_RE = re.compile(
    r'<link\b(?=[^>]*\brel="canonical")(?=[^>]*\bhref="([^"]*)")[^>]*>')
_CANONICAL_ID_RE = re.compile(r"([^/]+)$")


def _json_ld_products(html: str) -> list[dict[str, Any]]:
    """All @type=="Product" objects found in <script type="application/ld+json">.

    A block that fails to parse (malformed JSON, pathological nesting) is
    skipped, never raised -- most JSON-LD on the page (BreadcrumbList, Table)
    is not a Product and is filtered out the same way.
    """
    products = []
    for match in _JSON_LD_BLOCK_RE.finditer(html):
        try:
            obj = json.loads(match.group(1))
        except (json.JSONDecodeError, RecursionError, ValueError,
                OverflowError):
            continue
        if isinstance(obj, dict) and obj.get("@type") == "Product":
            products.append(obj)
    return products


def _canonical_product_id(html: str) -> str | None:
    """Trailing path segment of <link rel="canonical">, e.g. "MLB35045987"."""
    match = _CANONICAL_HREF_RE.search(html)
    if match is None:
        return None
    id_match = _CANONICAL_ID_RE.search(match.group(1))
    return id_match.group(1) if id_match else None


def _product_sku(product: dict[str, Any]) -> str | None:
    for key in ("sku", "productID"):
        value = product.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _select_product(
    products: list[dict[str, Any]], canonical_id: str | None
) -> dict[str, Any] | None:
    """The single Product, or the one matching the page's own canonical id.

    Never returns an arbitrary pick among several non-matching candidates.
    """
    if len(products) == 1:
        return products[0]
    if not products or canonical_id is None:
        return None
    matches = [p for p in products if _product_sku(p) == canonical_id]
    return matches[0] if len(matches) == 1 else None


def _offers_of(product: dict[str, Any]) -> dict[str, Any] | None:
    offers = product.get("offers")
    if isinstance(offers, dict):
        return offers
    if isinstance(offers, list):
        for entry in offers:
            if isinstance(entry, dict) and "price" in entry:
                return entry
        for entry in offers:
            if isinstance(entry, dict):
                return entry
    return None


def _availability_from_schema_url(value: Any) -> Availability:
    if not isinstance(value, str):
        return Availability.UNKNOWN
    tail = value.rsplit("/", 1)[-1]
    if tail == Availability.IN_STOCK.value:
        return Availability.IN_STOCK
    if tail == Availability.OUT_OF_STOCK.value:
        return Availability.OUT_OF_STOCK
    return Availability.UNKNOWN


def _extract_from_json_ld(html: str) -> Extract | None:
    """None if no JSON-LD Product node is found at all (-> try the meta repli).

    Raises ParseError if a Product WAS unambiguously identified but carries no
    usable price, a non-BRL currency, or a sku/productID that disagrees with
    the page's own canonical id -- that Product is authoritative, never
    silently discarded in favor of a DOM heuristic nor accepted with a value
    that does not belong to the scraped listing.
    """
    products = _json_ld_products(html)
    if not products:
        return None
    canonical_id = _canonical_product_id(html)
    product = _select_product(products, canonical_id)
    if product is None:
        raise ParseError(
            "multiple MercadoLivre JSON-LD Product nodes, none matching the "
            "page's canonical product id")
    sku = _product_sku(product)
    if sku is not None and canonical_id is not None and sku != canonical_id:
        # A single Product node is still validated against the canonical id:
        # "the only candidate" does not mean "the right one" (e.g. a stale
        # variant left over from a related listing).
        raise ParseError(
            "MercadoLivre JSON-LD Product sku/productID does not match the "
            "page's canonical product id")
    offers = _offers_of(product)
    price = to_cents(offers.get("price")) if offers else None
    if price is None:
        raise ParseError(
            "MercadoLivre JSON-LD Product has no usable offers.price")
    currency = offers.get("priceCurrency") if offers else None
    if currency != _CURRENCY:
        raise ParseError(
            f"MercadoLivre JSON-LD Product offers.priceCurrency is not "
            f"{_CURRENCY!r} (got {currency!r})")
    return Extract(
        price_pix_cents=price,
        price_card_cents=price,
        currency=_CURRENCY,
        availability=_availability_from_schema_url(
            offers.get("availability")),
    )


# DOM availability signals (no schema.org node on ML). Availability is scoped to
# a bounded window around the stock/buy-box element so BOTH the out-of-stock and
# in-stock verdicts are read from the SAME region (no false IN_STOCK from a
# stray stock element elsewhere in the page, and no false OOS from a recommended
# product). Out-of-stock markers are checked FIRST inside that window.
_STOCK_ANCHORS = ("buybox_available_quantity", "ui-pdp-stock")
_AVAILABILITY_WINDOW = 2000
_OOS_MARKERS = (
    "sem estoque", "fora de estoque", "indisponivel", "indisponível",
    "esgotad", "produto pausado", "anuncio pausado", "anúncio pausado",
    "currently unavailable", "out of stock",
)


def _scoped_meta_price(html: str) -> int | None:
    """Effective price from <meta itemprop="price"> scoped under id="price"."""
    block_pos = html.find(f'id="{_PRICE_BLOCK_ID}"')
    if block_pos < 0:
        block_pos = html.find(f"id='{_PRICE_BLOCK_ID}'")
    if block_pos < 0:
        return None
    match = _PRICE_META_RE.search(
        html, block_pos, block_pos + _BLOCK_TO_META_WINDOW)
    if match is None:
        return None
    return to_cents(float(match.group(1)))


def _availability(html: str) -> Availability:
    """Three-valued availability from a bounded window around the stock anchor.

    The stock / buy-box element is the availability region. Within one bounded
    window: an explicit out-of-stock marker -> OUT_OF_STOCK; otherwise the
    anchor's presence (a live buy box) -> IN_STOCK. No stock anchor at all
    (nothing to read) -> UNKNOWN, which never downgrades a successful price read.
    """
    anchor_pos = -1
    for anchor in _STOCK_ANCHORS:
        pos = html.find(anchor)
        if pos >= 0:
            anchor_pos = pos if anchor_pos < 0 else min(anchor_pos, pos)
    if anchor_pos < 0:
        return Availability.UNKNOWN
    window = html[anchor_pos:anchor_pos + _AVAILABILITY_WINDOW]
    text = _TAG_RE.sub(" ", window).lower()
    if any(marker in text for marker in _OOS_MARKERS):
        return Availability.OUT_OF_STOCK
    return Availability.IN_STOCK


class MercadoLivreParser:
    """Parser port implementation for mercadolivre.com.br product pages."""

    def __init__(self, spec: ParserSpec) -> None:
        # spec carries no locators for this kind (the DOM anchors are fixed
        # module constants); kept for a uniform factory signature.
        self._spec = spec

    def extract(self, html: str) -> Extract:
        from_json_ld = _extract_from_json_ld(html)
        if from_json_ld is not None:
            return from_json_ld

        price = _scoped_meta_price(html)
        if price is None:
            raise ParseError(
                "no MercadoLivre price located "
                "(JSON-LD offers.price / meta itemprop=price)")

        # PROVISIONAL mapping -- Option A: the single headline price fills BOTH
        # regular slots (ML advertises no distinct PIX price for this listing).
        # TODO(mapping): if the operator picks Option B (pix-only), set
        # price_card_cents=None and keep price_pix_cents=price.
        return Extract(
            price_pix_cents=price,
            price_card_cents=price,
            currency=_CURRENCY,
            availability=_availability(html),
        )
