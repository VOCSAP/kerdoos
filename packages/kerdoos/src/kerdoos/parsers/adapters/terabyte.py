"""Terabyte parser adapter (kind "terabyte") -- stdlib only, no bs4.

Terabyte (terabyteshop.com.br) SERVER-renders its prices, so the tls tier
(curl_cffi) already returns them in the raw document -- no browser needed. The
product block exposes two prices by stable id:

    <p id="valVista" class="val-prod valVista">R$ 749,09</p>   (pix / a vista, boleto)
    <span id="valParc" class="valParc">R$ 881,28</span>       (card, 12x sem juros)

Scoping discipline (invariant #4 -- read the CURRENT effective price, skip traps):
  * The ids are DUPLICATED (invalid HTML but real): the FIRST #valParc is an
    empty top sticky-bar span (populated by JS), and a hidden template renders
    "#valVista R$ 000,00". We iterate every occurrence of an id and read the
    element's OWN immediate text node ([^<]*), taking the FIRST strictly-positive
    amount. Reading the text node (not a forward window) is what keeps the empty
    #valParc from bleeding into the adjacent 12x installment span (R$ 73,44).
  * The struck reference "De: <del>R$ 1.559,99</del>" lives OUTSIDE the id nodes,
    so anchoring on the ids never reads it.

Availability is DOM-based with no schema.org node: an in-stock page carries a
tooltip "Produto disponivel no estoque", while out-of-stock placeholders live
ONLY inside HTML comments (<!-- quando produto estiver esgotado -->). Comments
are stripped BEFORE the availability scan so a commented "esgotado" never causes
a false OUT_OF_STOCK. Matching uses ASCII-safe substrings because the page
declares UTF-8 but serves invalid bytes for accents (i-acute decodes to U+FFFD).

Prices funnel through the shared normalize.to_cents contract. If neither price
can be located the parser fails closed (ParseError -> INDETERMINATE).
"""

from __future__ import annotations

import re

from kerdoos.core.domain import Availability, Extract, ParseError

from ..normalize import to_cents
from ..ports import ParserSpec

_CURRENCY = "BRL"

_ID_VISTA = "valVista"   # pix / a vista price
_ID_PARC = "valParc"     # card / installment total price

# The element's immediate text node after its opening tag. Capturing [^<]* stops
# at the next tag, so an empty span yields "" and never reaches a sibling.
def _id_text_re(id_value: str) -> re.Pattern[str]:
    return re.compile(r'id="' + re.escape(id_value) + r'"[^>]*>([^<]*)')


_PRICE_RE = re.compile(r"R\$\s*(\d{1,3}(?:\.\d{3})*,\d{2})")
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)

# Availability markers (ASCII-safe; accents may be U+FFFD after decode). OOS is
# checked FIRST, on comment-stripped text.
_OOS_MARKERS = (
    "esgotado", "indisponivel", "indisponível", "produto indisponivel",
    "fora de estoque", "sem estoque", "avise-me", "out of stock",
)
_IN_STOCK_MARKER = "no estoque"   # tooltip "Produto disponivel no estoque"
# Availability is scoped to a window around the product price block (#valVista;
# #valParc as fallback) so an OOS marker on a cross-sell / related product
# elsewhere on the page cannot flip the whole page to a false OUT_OF_STOCK
# (invariant #3). The in-stock tooltip sits just BEFORE #valVista, real OOS
# copy just after it, so the window spans both sides of the anchor.
_AVAIL_BEFORE = 1200
_AVAIL_AFTER = 2500


def _brl_to_reais(amount: str) -> float:
    """"1.559,99" -> 1559.99 (thousands dot dropped, decimal comma -> dot)."""
    return float(amount.replace(".", "").replace(",", "."))


def _first_valid_id_price(html: str, id_value: str) -> int | None:
    """First strictly-positive R$ amount held by an element with this id.

    Iterates every id occurrence (the ids are duplicated) and reads each one's
    own text node, so the empty top-bar span and the '000,00' template are
    skipped and the sibling installment span is never captured.
    """
    for match in _id_text_re(id_value).finditer(html):
        price = _PRICE_RE.search(match.group(1))
        if price is None:
            continue
        cents = to_cents(_brl_to_reais(price.group(1)))
        if cents is not None:   # to_cents rejects 000,00 (<= 0) already
            return cents
    return None


def _availability(html: str) -> Availability:
    """Three-valued availability from a comment-stripped window on the product.

    The scan is BOTH windowed (around the product price block) AND comment-
    stripped: comments are dropped first (out-of-stock placeholders live only
    inside <!-- ... -->), and the window keeps a cross-sell OOS marker elsewhere
    on the page from flipping the verdict. Tags are NOT stripped: the in-stock
    signal is a tooltip in a title="..." ATTRIBUTE. OOS is checked FIRST inside
    the window.
    """
    anchor = html.find(f'id="{_ID_VISTA}"')
    if anchor < 0:
        anchor = html.find(f'id="{_ID_PARC}"')
    if anchor < 0:
        region = html   # no price anchor: fall back to the whole document
    else:
        region = html[max(0, anchor - _AVAIL_BEFORE):anchor + _AVAIL_AFTER]
    text = _COMMENT_RE.sub(" ", region).lower()
    if any(marker in text for marker in _OOS_MARKERS):
        return Availability.OUT_OF_STOCK
    if _IN_STOCK_MARKER in text:
        return Availability.IN_STOCK
    return Availability.UNKNOWN


class TerabyteParser:
    """Parser port implementation for terabyteshop.com.br product pages."""

    def __init__(self, spec: ParserSpec) -> None:
        # spec carries no locators for this kind (the ids are fixed module
        # constants); kept for a uniform factory signature.
        self._spec = spec

    def extract(self, html: str) -> Extract:
        pix = _first_valid_id_price(html, _ID_VISTA)
        card = _first_valid_id_price(html, _ID_PARC)
        if pix is None and card is None:
            raise ParseError("no Terabyte price located (#valVista/#valParc)")
        return Extract(
            price_pix_cents=pix,
            price_card_cents=card,
            currency=_CURRENCY,
            availability=_availability(html),
        )
