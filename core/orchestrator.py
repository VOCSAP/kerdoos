"""Scrape orchestration: fetch -> parse -> verdict -> record.

Depends only on ports (Fetcher, Parser, StateStore) and pure error types; no
tool import, no adapter import. Concrete fetchers/parsers/stores are injected by
the interface layer (CLI), keeping the core a library.
"""

from __future__ import annotations

from datetime import datetime, timezone

from autolycos.errors import FetchError
from autolycos.ports import Fetcher
from parsers.ports import Parser
from persistence.ports import ScrapeRecord, StateStore

from .domain import Availability, ParseError, ScrapeStatus
from .verdict import compute_verdict


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def scrape_one(
    fetcher: Fetcher,
    parser: Parser,
    source_id: str,
    url: str,
    *,
    now: str | None = None,
) -> ScrapeRecord:
    """Run one source end-to-end and build its ScrapeRecord (no persistence).

    Fail-closed: any unexpected exception (from the fetcher, the parser, or a
    future adapter) degrades to an INDETERMINATE record instead of propagating
    -- a bad source never crashes the run (invariant #3).
    """
    ts = now or _utcnow_iso()

    try:
        try:
            result = fetcher.fetch(url)
        except FetchError as exc:
            return _indeterminate(source_id, ts, None, f"fetch: {exc}")

        if result.challenged:
            return _indeterminate(
                source_id, ts, result.method,
                f"challenged (http {result.status})")

        extract = None
        parse_error: str | None = None
        try:
            extract = parser.extract(result.html)
        except ParseError as exc:
            parse_error = str(exc)

        status = compute_verdict(result, extract, parse_error)

        if extract is None:
            return _indeterminate(
                source_id, ts, result.method, f"parse: {parse_error}")

        return ScrapeRecord(
            source_id=source_id, ts=ts, status=status,
            price_pix_cents=extract.price_pix_cents,
            price_card_cents=extract.price_card_cents,
            currency=extract.currency, availability=extract.availability,
            method=result.method, error=None,
            price_pix_member_cents=extract.price_pix_member_cents,
            price_card_member_cents=extract.price_card_member_cents,
        )
    except Exception as exc:  # noqa: BLE001 -- generic fail-closed net
        return _indeterminate(
            source_id, ts, None,
            f"unexpected: {type(exc).__name__}: {exc}")


def _indeterminate(
    source_id: str, ts: str, method: str | None, error: str
) -> ScrapeRecord:
    return ScrapeRecord(
        source_id=source_id, ts=ts, status=ScrapeStatus.INDETERMINATE,
        price_pix_cents=None, price_card_cents=None, currency=None,
        availability=Availability.UNKNOWN, method=method, error=error,
    )


def scrape_and_record(
    fetcher: Fetcher,
    parser: Parser,
    store: StateStore,
    source_id: str,
    url: str,
    *,
    now: str | None = None,
) -> ScrapeRecord:
    """scrape_one + persist the record via the StateStore port."""
    record = scrape_one(fetcher, parser, source_id, url, now=now)
    store.record(record)
    return record
