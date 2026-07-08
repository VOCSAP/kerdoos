"""Three-valued verdict machine.

Maps a fetch outcome + parse outcome to {ok, indeterminate, unavailable}. This
is the ONLY place the three-valued status is decided; autolycos returns the raw
HTTP status, never a verdict.

Rules (endorsed by the architect):
  * price present + InStock (or UNKNOWN availability) -> ok
  * price present + OutOfStock (explicit)            -> unavailable
  * price not found / challenge / fetch failure      -> indeterminate

A missing/unknown availability never downgrades a successful price read; only an
EXPLICIT OutOfStock yields `unavailable`.
"""

from __future__ import annotations

from autolycos.ports import FetchResult

from .domain import Availability, Extract, ScrapeStatus


def compute_verdict(
    fetch_result: FetchResult | None,
    extract: Extract | None,
    parse_error: str | None = None,
) -> ScrapeStatus:
    # Transient block or failed fetch -> never a stock verdict.
    if fetch_result is None or fetch_result.challenged:
        return ScrapeStatus.INDETERMINATE
    # Extraction failed (structure unexpected / price node missing) -> fail-closed.
    if extract is None or parse_error is not None:
        return ScrapeStatus.INDETERMINATE
    # Explicit out-of-stock is a legitimate unavailability, even with a price.
    if extract.availability == Availability.OUT_OF_STOCK:
        return ScrapeStatus.UNAVAILABLE
    # A usable price read (availability InStock or UNKNOWN) -> ok.
    if extract.has_price():
        return ScrapeStatus.OK
    return ScrapeStatus.INDETERMINATE
