"""Parser port and ParserSpec (a pure locator).

ParserSpec carries ONLY locations (paths), never interpretation logic. How a
resolved value maps to a domain value (e.g. bool -> InStock/OutOfStock for
statejson, schema.org URL for jsonld) lives in each adapter, not here and not
in the YAML registry (YAGNI; keeps interpretation out of config).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from kerdoos.core.domain import Extract


@dataclass(frozen=True, slots=True)
class ParserSpec:
    """Locator for a site's price/availability inside a document.

    kind         extraction family (whitelisted: jsonld/statejson/css/regex).
    pix          path to the PIX / a-vista price (nullable slot).
    card         path to the card / base price (nullable slot).
    availability optional path to an availability field; None if the site
                 exposes no distinct availability node -> Availability.UNKNOWN.
    """

    kind: str
    pix: str | None = None
    card: str | None = None
    availability: str | None = None


@runtime_checkable
class Parser(Protocol):
    """Extract price + availability from a document body."""

    def extract(self, html: str) -> Extract:
        ...
