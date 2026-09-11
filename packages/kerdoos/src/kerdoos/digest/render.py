"""Render a single aggregated digest from scrape records.

Invariant #8: exactly ONE digest for the whole run, never a notification per
product. This module produces plain text (the SMTP body is out of scope for the
vertical slice; the CLI prints this to stdout in dry-run).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Mapping
from zoneinfo import ZoneInfo

from kerdoos.core.domain import ScrapeStatus
from kerdoos.persistence.ports import ScrapeRecord


def format_cents(cents: int | None) -> str:
    """Integer cents -> 'R$ 7.558,00' (pt-BR grouping), or '-' when absent."""
    if cents is None:
        return "-"
    reais, cent = divmod(cents, 100)
    grouped = f"{reais:,}".replace(",", ".")   # 7558 -> '7.558'
    return f"R$ {grouped},{cent:02d}"


_MAX_ERROR_LEN = 160


def _sanitize_error(error: str) -> str:
    """Neutralize a scrape-derived error before it enters a digest line.

    The error string can originate from remote content (an exception message
    built from parsed HTML). Stripping CR/LF prevents a hostile message from
    forging extra digest lines (log/report injection), and truncation caps the
    line length. Interior newlines are collapsed to spaces, not just edges.
    """
    flat = error.replace("\r", " ").replace("\n", " ").strip()
    if len(flat) > _MAX_ERROR_LEN:
        flat = flat[:_MAX_ERROR_LEN - 3] + "..."
    return flat


def _parse_ts(ts: str) -> datetime:
    parsed = datetime.fromisoformat(ts)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _scraped_at_label(
    record_ts: str, generated_at: str, *, tz_name: str = "UTC",
) -> str:
    """Human label for WHEN a record's price was actually read, distinct from
    generated_at (the digest's build time) -- card e9ee2b59: a source that
    stopped being scraped must never let its last OK price read as current
    (invariant #4). tz_name is job.timezone when a DigestJob is in scope,
    else explicit UTC (render_digest has no job).
    """
    scraped = _parse_ts(record_ts).astimezone(ZoneInfo(tz_name))
    stamp = scraped.strftime("%Y-%m-%d %H:%M %Z")
    age_days = max(0, (_parse_ts(generated_at) - _parse_ts(record_ts)).days)
    if age_days >= 1:
        return f"scraped {stamp} ({age_days}d ago)"
    return f"scraped {stamp}"


def _price_field(record: ScrapeRecord, label: str | None = None) -> str:
    pix = format_cents(record.price_pix_cents)
    card = format_cents(record.price_card_cents)
    if record.price_pix_cents is None and record.price_card_cents is None:
        regular = "no price"
    else:
        regular = f"pix={pix} card={card}"
    # Second (membership-gated) tier: append a segment only when the site
    # exposed at least one member price. The label is presentation data supplied
    # by the caller (e.g. "Prime"); absent -> fall back to the neutral "member".
    if (record.price_pix_member_cents is None
            and record.price_card_member_cents is None):
        return regular
    member_pix = format_cents(record.price_pix_member_cents)
    member_card = format_cents(record.price_card_member_cents)
    return (f"{regular}  {label or 'member'}: "
            f"pix={member_pix} card={member_card}")


def render_digest(
    records: list[ScrapeRecord],
    generated_at: str,
    tier2_labels: Mapping[str, str] | None = None,
) -> str:
    """Build the aggregated digest body from the run's scrape records.

    tier2_labels maps a record's source_id to the label for its second price
    tier (e.g. "Prime"). It is DATA passed by the caller (the CLI, which holds
    both the Registry and the records); the digest never imports the registry,
    keeping the core->registry boundary clean.
    """
    labels = tier2_labels or {}
    counts = {status: 0 for status in ScrapeStatus}
    lines: list[str] = []
    lines.append("Kerdoos daily digest")
    lines.append(f"generated_at: {generated_at}")
    lines.append(f"sources: {len(records)}")
    lines.append("-" * 60)

    for record in records:
        counts[record.status] = counts.get(record.status, 0) + 1
        detail = _price_field(record, labels.get(record.source_id))
        avail = record.availability.value
        scraped_at = _scraped_at_label(record.ts, generated_at)
        line = (f"[{record.status.value:>13}] {record.source_id}  "
                f"{detail}  availability={avail}  {scraped_at}")
        if record.error:
            line += f"  ({_sanitize_error(record.error)})"
        lines.append(line)

    lines.append("-" * 60)
    summary = "  ".join(
        f"{status.value}={counts.get(status, 0)}" for status in ScrapeStatus
    )
    lines.append(f"summary: {summary}")
    return "\n".join(lines)
