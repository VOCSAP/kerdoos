"""Pichau parser adapter (kind "pichau") -- stdlib only, no bs4.

Pichau (pichau.com.br) is a Next.js site fronted by Cloudflare. The tls tier
(curl_cffi) returns the server-rendered document, which embeds the product data
in an RSC flight (self.__next_f) as ESCAPED JSON. The effective prices live in a
`pichau_prices` object, e.g. (backslash-quotes are the flight's escaping):

    "pichau_prices":{"avista":149.99,...,"base_price":241.16,"final_price":176.46,...}

Scoping discipline (invariant #4):
  * pix  = pichau_prices.avista (PIX / a-vista price).
  * card = pichau_prices.final_price.
  * base_price is the crossed-out REFERENCE and is never matched.
  * Both keys are read within a bounded window AFTER the `pichau_prices` anchor,
    so an avista/final_price belonging to an unrelated flight block is not read.
  * The JSON-LD (schema.org Offer) is deliberately IGNORED: its `price` is the
    CARD price (final_price), not the a-vista, so trusting it would mislabel pix.

Availability comes from the flight's `stock_status` ("IN_STOCK"/"OUT_OF_STOCK").
Prices funnel through normalize.to_cents. No price -> ParseError (fail-closed).
"""

from __future__ import annotations

import re

from core.domain import Availability, Extract, ParseError

from ..normalize import to_cents
from ..ports import ParserSpec

_CURRENCY = "BRL"
_FLIGHT_ANCHOR = "pichau_prices"
# The pichau_prices object is short; a small window keeps the search inside it.
_FLIGHT_WINDOW = 600


def _flight_number_re(key: str) -> re.Pattern[str]:
    """Match a numeric flight value by key, tolerant to escaped-JSON quoting.

    Between the key and its colon the flight may carry any run of backslash/quote
    characters ("avista":, \\"avista\\":, ...); the character class absorbs them
    so no whole-flight unescaping is needed. The class also anchors the key end
    (a following "_" as in avista_discount is neither backslash, quote nor colon,
    so that sibling key never matches).
    """
    return re.compile(re.escape(key) + r'[\\"]*\s*:\s*(\d+(?:\.\d+)?)')


_AVISTA_RE = _flight_number_re("avista")
_FINAL_PRICE_RE = _flight_number_re("final_price")
_STOCK_STATUS_RE = re.compile(r'stock_status[\\"]*\s*:\s*[\\"]*([A-Z_]+)')
# stock_status sits ~2664 chars AFTER the pichau_prices anchor in the main
# product node. The window is deliberately AFTER-only (no look-back): a related
# product's stock_status further down the flight cannot mislabel the main one
# (invariant #3, never a false OUT_OF_STOCK), and the field NAME
# "quantity_and_stock_status" (which precedes the flight) also stays out.
_STOCK_WINDOW = 3500


def _scoped_flight_price(html: str, price_re: re.Pattern[str]) -> int | None:
    """First `price_re` value inside the pichau_prices window."""
    anchor = html.find(_FLIGHT_ANCHOR)
    if anchor < 0:
        return None
    match = price_re.search(html, anchor, anchor + _FLIGHT_WINDOW)
    if match is None:
        return None
    return to_cents(float(match.group(1)))


def _availability(html: str) -> Availability:
    """Map the main product's flight stock_status to an Availability.

    Scoped to a window AFTER the pichau_prices anchor so a related product's
    stock_status elsewhere in the flight never mislabels the main product.
    """
    anchor = html.find(_FLIGHT_ANCHOR)
    if anchor < 0:
        return Availability.UNKNOWN
    match = _STOCK_STATUS_RE.search(html, anchor, anchor + _STOCK_WINDOW)
    if match is None:
        return Availability.UNKNOWN
    status = match.group(1).upper()
    if status == "IN_STOCK":
        return Availability.IN_STOCK
    if status in ("OUT_OF_STOCK", "OUT_STOCK"):
        return Availability.OUT_OF_STOCK
    return Availability.UNKNOWN


class PichauParser:
    """Parser port implementation for pichau.com.br product pages."""

    def __init__(self, spec: ParserSpec) -> None:
        # spec carries no locators for this kind (the flight keys are fixed
        # module constants); kept for a uniform factory signature.
        self._spec = spec

    def extract(self, html: str) -> Extract:
        pix = _scoped_flight_price(html, _AVISTA_RE)
        card = _scoped_flight_price(html, _FINAL_PRICE_RE)
        if pix is None and card is None:
            raise ParseError("no Pichau price located (pichau_prices flight)")
        return Extract(
            price_pix_cents=pix,
            price_card_cents=card,
            currency=_CURRENCY,
            availability=_availability(html),
        )
