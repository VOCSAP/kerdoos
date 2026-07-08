"""Amazon parser adapter (kind "amazon") -- stdlib only, no bs4.

Amazon (amazon.com.br) renders a two-tier "accordion" price block: a regular
public tier and a membership-gated (Prime) tier. Each tier exposes a PIX/a-vista
price and an installment/card price. This adapter reads all four and maps them
onto Extract's regular + member slots.

Scoping discipline (invariant #4 -- read the CURRENT effective price, never the
struck reference):
  * Each price is located by first anchoring on its tier's ROW id, then finding
    the tier-local sub-anchor, then reading the amount after it. The card
    sub-anchor id (best-offer-string-cc) is duplicated once per tier, so the
    row-id scoping is MANDATORY -- never positional.
  * PIX prices are rendered as SPLIT spans (a-price-whole "7.181" + a-price-
    fraction "05"), NOT a concatenated "R$ 7.181,05" string, so they are parsed
    from the whole+fraction pair inside a TIGHT window anchored on
    apex-pricetopay-value. The window is deliberately small so the search never
    reaches the struck MSRP (apex-basisprice-value, data-a-strike="true") that
    sits a few hundred chars further down inside the same accordion row -- a
    generic BRL-string regex would otherwise skip the un-matchable split value
    and latch onto that MSRP.
  * The struck MSRP is never anchored on, so it can never be mistaken for the
    effective price.

Prices funnel through the shared normalize.to_cents sanity contract. If NONE of
the four prices can be located the parser fails closed (ParseError -> the
orchestrator degrades the scrape to INDETERMINATE, never a false OutOfStock).
"""

from __future__ import annotations

import re

from core.domain import Availability, Extract, ParseError

from ..normalize import to_cents
from ..ports import ParserSpec

_CURRENCY = "BRL"

# Tier row-id anchors. "new" = regular public tier; "primeSavingsUpsell" =
# membership-gated tier. PIX rows live under apex_desktop_*, card rows under
# reinvent_price_desktop_*.
_ROW_PIX_REGULAR = "apex_desktop_newAccordionRow"
_ROW_PIX_MEMBER = "apex_desktop_primeSavingsUpsellAccordionRow"
_ROW_CARD_REGULAR = "reinvent_price_desktop_newAccordionRow"
_ROW_CARD_MEMBER = "reinvent_price_desktop_primeSavingsUpsellAccordionRow"

# Tier-local sub-anchors (searched only AFTER the tier's row id).
_PIX_VALUE_CLASS = "apex-pricetopay-value"   # wraps the split-span PIX price
# best-offer-string-cc text is "ou R$ <full> em ate Nx de R$ <installment> sem
# juros". We read the FIRST BRL amount, which is the FULL (a-vista) card price
# -- the per-installment amount always comes AFTER "em ate Nx de". This ordering
# is stable in the observed markup; if Amazon ever reordered it, the regex would
# grab the installment value instead, so the assumption is asserted by the
# real-dump test (regular card 7.559,00, not the 12x 629,99).
_CARD_SPAN_ID = "best-offer-string-cc"

_AVAILABILITY_ID = "availability"

# BRL amount, e.g. "R$7.180,10" or "R$ 7.558,00" (thousands dot, comma cents).
# Used for the card (best-offer) string; PIX uses the split-span regex below.
_PRICE_RE = re.compile(r"R\$\s*(\d{1,3}(?:\.\d{3})*,\d{2})")
# Split-span PIX price: <span class="a-price-whole">7.181<span class="a-price-
# decimal">,</span></span><span class="a-price-fraction">05</span>. Captures the
# integer part (with thousands dots) and the two-digit fraction.
_PIX_SPLIT_RE = re.compile(
    r'a-price-whole"[^>]*>\s*([\d.]+)'
    r'(?:\s*<span[^>]*a-price-decimal[^>]*>[^<]*</span>)?'
    r'\s*</span>\s*<span[^>]*a-price-fraction[^>]*>\s*(\d{2})'
)
_TAG_RE = re.compile(r"<[^>]+>")

# Windows that bound each forward search (chars). Generous but finite so a tier
# never bleeds into an unrelated later section of the ~1.6 MB document.
_ROW_TO_ANCHOR_WINDOW = 8000
_ANCHOR_TO_PRICE_WINDOW = 2000
# PIX value window is deliberately TIGHT: the split-span price sits immediately
# inside apex-pricetopay-value, while the struck MSRP (apex-basisprice-value)
# is ~800+ chars further down in the same accordion row. A small window reads
# the effective price and can never reach the MSRP (invariant #4).
_PIX_VALUE_WINDOW = 500
_AVAILABILITY_WINDOW = 600

# Availability markers. Out-of-stock is checked FIRST: "sem estoque" /
# "fora de estoque" both contain the substring "em estoque", so an in-stock
# check run first would misclassify them.
_OOS_MARKERS = (
    "indisponivel", "indisponível", "fora de estoque", "sem estoque",
    "esgotad", "out of stock", "currently unavailable",
    "nao disponivel", "não disponível",
)
_IN_STOCK_MARKERS = ("em estoque", "in stock")


def _scoped_price(html: str, row_anchor: str, sub_anchor: str) -> int | None:
    """First BRL price under `sub_anchor`, itself scoped under `row_anchor`."""
    row_pos = html.find(row_anchor)
    if row_pos < 0:
        return None
    sub_pos = html.find(sub_anchor, row_pos, row_pos + _ROW_TO_ANCHOR_WINDOW)
    if sub_pos < 0:
        return None
    match = _PRICE_RE.search(html, sub_pos, sub_pos + _ANCHOR_TO_PRICE_WINDOW)
    if match is None:
        return None
    return to_cents(_brl_to_reais(match.group(1)))


def _scoped_pix_price(html: str, row_anchor: str) -> int | None:
    """Effective PIX price for a tier, parsed from its split spans.

    Scoped under `row_anchor` -> apex-pricetopay-value -> the a-price-whole /
    a-price-fraction pair, read within a TIGHT window (`_PIX_VALUE_WINDOW`) that
    never reaches the struck MSRP sitting further down the same accordion row.
    """
    row_pos = html.find(row_anchor)
    if row_pos < 0:
        return None
    sub_pos = html.find(_PIX_VALUE_CLASS, row_pos, row_pos + _ROW_TO_ANCHOR_WINDOW)
    if sub_pos < 0:
        return None
    match = _PIX_SPLIT_RE.search(html, sub_pos, sub_pos + _PIX_VALUE_WINDOW)
    if match is not None:
        whole, fraction = match.group(1), match.group(2)
        return to_cents(_brl_to_reais(f"{whole},{fraction}"))
    # Fallback: some Amazon variants populate the a-offscreen mirror with the
    # full "R$ 1.999,90" string instead of leaving it empty next to the split
    # spans. Bounded to the SAME tight window, so it can never reach the struck
    # MSRP that lives further down the accordion row (invariant #4).
    full = _PRICE_RE.search(html, sub_pos, sub_pos + _PIX_VALUE_WINDOW)
    if full is None:
        return None
    return to_cents(_brl_to_reais(full.group(1)))


def _brl_to_reais(amount: str) -> float:
    """"7.180,10" -> 7180.10 (thousands dot dropped, decimal comma -> dot)."""
    return float(amount.replace(".", "").replace(",", "."))


def _availability(html: str) -> Availability:
    """Map the #availability block text to a three-valued Availability."""
    pos = html.find(f'id="{_AVAILABILITY_ID}"')
    if pos < 0:
        pos = html.find(f"id='{_AVAILABILITY_ID}'")
    if pos < 0:
        return Availability.UNKNOWN
    window = html[pos:pos + _AVAILABILITY_WINDOW]
    text = _TAG_RE.sub(" ", window).lower()
    if any(marker in text for marker in _OOS_MARKERS):
        return Availability.OUT_OF_STOCK
    if any(marker in text for marker in _IN_STOCK_MARKERS):
        return Availability.IN_STOCK
    return Availability.UNKNOWN


class AmazonParser:
    """Parser port implementation for amazon.com.br product pages."""

    def __init__(self, spec: ParserSpec) -> None:
        # spec carries no locators for this kind (the DOM anchors are fixed
        # module constants); kept for a uniform factory signature.
        self._spec = spec

    def extract(self, html: str) -> Extract:
        pix_regular = _scoped_pix_price(html, _ROW_PIX_REGULAR)
        card_regular = _scoped_price(html, _ROW_CARD_REGULAR, _CARD_SPAN_ID)
        pix_member = _scoped_pix_price(html, _ROW_PIX_MEMBER)
        card_member = _scoped_price(html, _ROW_CARD_MEMBER, _CARD_SPAN_ID)

        if (pix_regular is None and card_regular is None
                and pix_member is None and card_member is None):
            raise ParseError("no Amazon price located (all four tiers absent)")

        return Extract(
            price_pix_cents=pix_regular,
            price_card_cents=card_regular,
            currency=_CURRENCY,
            availability=_availability(html),
            price_pix_member_cents=pix_member,
            price_card_member_cents=card_member,
        )
