"""MercadoLivre parser adapter (kind "mercadolivre") -- stdlib only, no bs4.

MercadoLivre (mercadolivre.com.br) product pages are JS SPAs; once rendered, the
effective price is exposed as a schema.org Offer meta inside the main price
block:

    <div id="price"> ... <meta itemprop="price" content="9433"> ... </div>

Scoping discipline (invariant #4 -- read the CURRENT effective price):
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

Availability is DOM-based (there is no schema.org availability node): an
explicit out-of-stock marker wins; otherwise the presence of the buy box /
stock element marks IN_STOCK; else UNKNOWN. Currency is BRL (hardcoded; the page
carries no exploitable priceCurrency meta). Prices funnel through the shared
normalize.to_cents contract. If no price can be located the parser fails closed
(ParseError -> the orchestrator degrades the scrape to INDETERMINATE).
"""

from __future__ import annotations

import re

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
        price = _scoped_meta_price(html)
        if price is None:
            raise ParseError("no MercadoLivre price located (meta itemprop=price)")

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
