"""statejson Parser adapter.

Extracts price + availability from an embedded state JSON blob. At the MVP this
targets the Next.js `__NEXT_DATA__` script (Kabum); the same family later
subsumes Nuxt/flight state via the same token paths.

Interpretation rules (kept in the adapter, not in ParserSpec / YAML):
  * prices are REAIS (float or int), converted to integer cents via
    round(value * 100). Kabum encodes 73.58 -> R$73,58 and 7558 -> R$7558,00;
    round() absorbs float32 noise and *100 rounding.
  * a resolved price that is <= 0, non-numeric, or out of sane bounds is
    treated as absent (None) -- NULL != 0.
  * availability path resolves to a bool: True -> InStock, False -> OutOfStock;
    anything else, or a missing path, degrades to Availability.UNKNOWN and does
    NOT fail the extraction.
  * if NEITHER price slot resolves -> ParseError (price not found) so the core
    maps to INDETERMINATE (fail-closed).
"""

from __future__ import annotations

import json
from typing import Any

from kerdoos.core.domain import Availability, Extract, ParseError

from ..nextdata import extract_next_data as _extract_next_data
from ..normalize import to_cents as _to_cents
from ..pathtraverse import PathResolutionError, resolve_path
from ..ports import ParserSpec

_DEFAULT_CURRENCY = "BRL"


def _map_availability(value: Any) -> Availability:
    if value is True:
        return Availability.IN_STOCK
    if value is False:
        return Availability.OUT_OF_STOCK
    return Availability.UNKNOWN


class StateJsonParser:
    """Parser port implementation for embedded state JSON."""

    def __init__(self, spec: ParserSpec) -> None:
        self._spec = spec

    def _price_at(self, state: Any, path: str | None) -> int | None:
        if not path:
            return None
        try:
            return _to_cents(resolve_path(state, path))
        except PathResolutionError:
            return None

    def extract(self, html: str) -> Extract:
        raw = _extract_next_data(html)
        if raw is None:
            raise ParseError("no __NEXT_DATA__ state script found")
        try:
            state = json.loads(raw)   # strict json.loads (no relaxed parsing)
        except (json.JSONDecodeError, RecursionError, ValueError,
                OverflowError) as exc:
            # Fail-closed: any structural/parse failure (incl. deeply nested
            # JSON -> RecursionError) becomes a ParseError -> INDETERMINATE.
            raise ParseError(f"invalid state JSON: {exc}") from exc

        pix = self._price_at(state, self._spec.pix)
        card = self._price_at(state, self._spec.card)
        if pix is None and card is None:
            raise ParseError("no price resolved at pix/card paths")

        availability = Availability.UNKNOWN
        if self._spec.availability:
            try:
                availability = _map_availability(
                    resolve_path(state, self._spec.availability))
            except PathResolutionError:
                availability = Availability.UNKNOWN

        return Extract(
            price_pix_cents=pix,
            price_card_cents=card,
            currency=_DEFAULT_CURRENCY,
            availability=availability,
        )
