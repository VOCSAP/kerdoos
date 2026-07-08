"""StateStore port + ScrapeRecord DTO.

ScrapeRecord is the full history row (successes AND errors). It imports domain
enums (adapters -> domain). No storage engine leaks through this port, so the
SQLite MVP can migrate to Postgres without touching callers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from kerdoos.core.domain import Availability, ScrapeStatus


@dataclass(frozen=True, slots=True)
class ScrapeRecord:
    """One scrape outcome. Prices are integer cents (BRL), nullable.

    raw_ref is a dormant opaque key at the MVP (schema column, not populated):
    it must never carry a filesystem path (CWE-22).
    """

    source_id: str
    ts: str                       # ISO-8601 UTC
    status: ScrapeStatus
    price_pix_cents: int | None
    price_card_cents: int | None
    currency: str | None
    availability: Availability
    method: str | None
    error: str | None
    # Membership-gated tier (same 'member' axis as Extract); None when the site
    # exposes no gated price. Nullable columns, additive migration (user_version 2).
    price_pix_member_cents: int | None = None
    price_card_member_cents: int | None = None
    raw_ref: str | None = None


@runtime_checkable
class StateStore(Protocol):
    """Persist and read back scrape history."""

    def record(self, scrape: ScrapeRecord) -> None:
        ...

    def history(self, source_id: str, limit: int = 50) -> list[ScrapeRecord]:
        ...
