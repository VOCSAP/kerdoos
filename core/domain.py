"""Domain types for Kerdoos core.

Pure domain: no tool imports (no requests/curl_cffi/playwright/seleniumbase),
no I/O. Parsers/ and persistence/ import these types (adapters -> domain, the
intended hexagonal direction). autolycos/ must NEVER import this module.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class ScrapeStatus(str, enum.Enum):
    """Three-valued verdict for a scrape. Never collapse the three."""

    OK = "ok"
    INDETERMINATE = "indeterminate"
    UNAVAILABLE = "unavailable"


class Availability(str, enum.Enum):
    """Product availability as read from the page.

    UNKNOWN is a first-class value: a missing/unreadable availability field
    degrades to UNKNOWN and the scrape proceeds -- it must never turn a
    successful price read into INDETERMINATE.
    """

    IN_STOCK = "InStock"
    OUT_OF_STOCK = "OutOfStock"
    UNKNOWN = "UNKNOWN"


class ParseError(Exception):
    """Raised by a Parser when the PRICE cannot be located.

    Reserved for a missing/unreadable price node (fail-closed -> INDETERMINATE).
    A missing availability field must NOT raise this -- it degrades to
    Availability.UNKNOWN instead.
    """


@dataclass(frozen=True, slots=True)
class Extract:
    """Result of parsing a page. Up to four nullable prices.

    Two tiers on the same 'member' axis (public vs membership-gated pricing):
      * price_pix_cents / price_card_cents  -- regular public tier.
      * price_pix_member_cents / price_card_member_cents -- membership-gated
        tier (default None; only sites exposing a gated price populate them).

    Prices are integer cents (BRL). A price that is absent must be None, never
    0 (NULL != 0). currency is ISO 4217 (e.g. "BRL").
    """

    price_pix_cents: int | None
    price_card_cents: int | None
    currency: str
    availability: Availability = Availability.UNKNOWN
    price_pix_member_cents: int | None = None
    price_card_member_cents: int | None = None

    def has_price(self) -> bool:
        """True if at least one price slot (any tier) is populated."""
        return (self.price_pix_cents is not None
                or self.price_card_cents is not None
                or self.price_pix_member_cents is not None
                or self.price_card_member_cents is not None)
