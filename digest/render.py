"""Render a single aggregated digest from scrape records.

Invariant #8: exactly ONE digest for the whole run, never a notification per
product. This module produces plain text (the SMTP body is out of scope for the
vertical slice; the CLI prints this to stdout in dry-run).
"""

from __future__ import annotations

from core.domain import ScrapeStatus
from persistence.ports import ScrapeRecord


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


def _price_field(record: ScrapeRecord) -> str:
    pix = format_cents(record.price_pix_cents)
    card = format_cents(record.price_card_cents)
    if record.price_pix_cents is None and record.price_card_cents is None:
        return "no price"
    return f"pix={pix} card={card}"


def render_digest(records: list[ScrapeRecord], generated_at: str) -> str:
    """Build the aggregated digest body from the run's scrape records."""
    counts = {status: 0 for status in ScrapeStatus}
    lines: list[str] = []
    lines.append("Kerdoos daily digest")
    lines.append(f"generated_at: {generated_at}")
    lines.append(f"sources: {len(records)}")
    lines.append("-" * 60)

    for record in records:
        counts[record.status] = counts.get(record.status, 0) + 1
        detail = _price_field(record)
        avail = record.availability.value
        line = (f"[{record.status.value:>13}] {record.source_id}  "
                f"{detail}  availability={avail}")
        if record.error:
            line += f"  ({_sanitize_error(record.error)})"
        lines.append(line)

    lines.append("-" * 60)
    summary = "  ".join(
        f"{status.value}={counts.get(status, 0)}" for status in ScrapeStatus
    )
    lines.append(f"summary: {summary}")
    return "\n".join(lines)
