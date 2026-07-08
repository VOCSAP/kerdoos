"""Magalu parser adapter (kind "magalu") -- stdlib only, no bs4.

Magazine Luiza (magazineluiza.com.br) is a Next.js site behind Akamai Bot
Manager; only the uc tier (SeleniumBase undetected Chrome) renders it. Once
rendered, the product data is inlined in __NEXT_DATA__ under
props.pageProps.data.item:

  * offers[0].bestPrice.totalAmount -> pix / a-vista price (paymentMethodId pix)
  * offers[0].price                 -> card price
  * item.available (bool)           -> availability (ITEM level, not offer level)

The 10x installment (offers[0].bestInstallmentPlan.installmentAmount) is NEVER
read. Values are integer reais (9433 -> 943300 cents via to_cents).

Fail-closed: no __NEXT_DATA__ (e.g. an Akamai challenge page served at 200) or a
missing offers path -> ParseError -> INDETERMINATE. This is the SECOND net after
looks_challenged (invariant #3): a blocked page never yields a false OutOfStock.
"""

from __future__ import annotations

import json
from typing import Any

from kerdoos.core.domain import Availability, Extract, ParseError

from ..nextdata import extract_next_data
from ..normalize import to_cents
from ..pathtraverse import PathResolutionError, resolve_path
from ..ports import ParserSpec

_CURRENCY = "BRL"
_PIX_PATH = "props.pageProps.data.item.offers[0].bestPrice.totalAmount"
_CARD_PATH = "props.pageProps.data.item.offers[0].price"
_AVAIL_PATH = "props.pageProps.data.item.available"


def _offer_price(data: Any, path: str) -> int | None:
    """Resolve a numeric offer price to cents, or None on any miss/non-number."""
    try:
        value = resolve_path(data, path)
    except PathResolutionError:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return to_cents(value)


def _availability(data: Any) -> Availability:
    """item.available bool -> three-valued Availability (miss -> UNKNOWN)."""
    try:
        value = resolve_path(data, _AVAIL_PATH)
    except PathResolutionError:
        return Availability.UNKNOWN
    if value is True:
        return Availability.IN_STOCK
    if value is False:
        return Availability.OUT_OF_STOCK
    return Availability.UNKNOWN


class MagaluParser:
    """Parser port implementation for magazineluiza.com.br product pages."""

    def __init__(self, spec: ParserSpec) -> None:
        # spec carries no locators for this kind (the __NEXT_DATA__ paths are
        # fixed module constants); kept for a uniform factory signature.
        self._spec = spec

    def extract(self, html: str) -> Extract:
        raw = extract_next_data(html)
        if raw is None:
            raise ParseError(
                "no __NEXT_DATA__ (Magalu challenge or non-product page)")
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            # Defence in depth (mirrors statejson): a hostile / deeply nested
            # __NEXT_DATA__ can raise RecursionError from the C json scanner, or
            # a ValueError; all degrade to a fail-closed ParseError.
            raise ParseError(f"malformed __NEXT_DATA__: {exc!r}") from exc

        pix = _offer_price(data, _PIX_PATH)
        card = _offer_price(data, _CARD_PATH)
        if pix is None and card is None:
            raise ParseError("no Magalu offer price located (offers[0])")

        return Extract(
            price_pix_cents=pix,
            price_card_cents=card,
            currency=_CURRENCY,
            availability=_availability(data),
        )
