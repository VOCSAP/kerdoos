"""Shared price normalization -- reais (numeric) -> integer cents.

Hoisted here so every parser adapter applies the SAME sanity contract:
  * bool / non-numeric / non-finite (NaN, +/-inf) -> None
  * value <= 0 -> None (a price is strictly positive; NULL != 0)
  * value*100 overflow (finite-but-enormous float) -> None, never raise
  * result out of [1, MAX_PRICE_CENTS] -> None

statejson (numeric reais from a JSON state) and amazon (reais parsed from a
BRL string) both funnel through `to_cents`, so an out-of-range or malformed
price degrades to absent (None) instead of crashing or leaking a bogus value.
"""

from __future__ import annotations

import math
from typing import Any

MAX_PRICE_CENTS = 100_000_000   # R$1,000,000 upper sanity bound


def to_cents(value: Any) -> int | None:
    """Reais (int/float) -> integer cents, or None if invalid/absent-like."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value):   # reject Infinity / -Infinity / NaN
        return None
    if value <= 0:
        return None
    try:
        cents = round(value * 100)
    except OverflowError:
        # A finite but enormous float (e.g. 1e308) overflows value*100 to inf,
        # and round(inf) raises. Sanity contract: invalid price -> None locally,
        # never escalate to INDETERMINATE via the orchestrator net.
        return None
    if cents <= 0 or cents > MAX_PRICE_CENTS:
        return None
    return cents
