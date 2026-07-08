"""SQLite StateStore adapter (MVP).

All SQL is parameterized (spec #2, CWE-89): no value is ever interpolated into a
statement string. Enum values are stored by `.value` and rebuilt on read.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from kerdoos.core.domain import Availability, ScrapeStatus

from .ports import ScrapeRecord

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scrapes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id      TEXT    NOT NULL,
    ts             TEXT    NOT NULL,
    status         TEXT    NOT NULL,
    price_pix_cents  INTEGER,
    price_card_cents INTEGER,
    currency       TEXT,
    availability   TEXT    NOT NULL,
    method         TEXT,
    error          TEXT,
    raw_ref        TEXT,
    price_pix_member_cents  INTEGER,
    price_card_member_cents INTEGER
);
CREATE INDEX IF NOT EXISTS idx_scrapes_source_ts
    ON scrapes (source_id, ts DESC);
"""

# Additive, idempotent migration: existing 2-price databases (user_version < 2)
# gain the two membership-tier columns via ALTER ADD COLUMN. No table recreation,
# so Kabum history is preserved and old rows read back with member prices NULL.
_SCHEMA_VERSION = 2
_MEMBER_COLUMNS = ("price_pix_member_cents", "price_card_member_cents")

_INSERT = """
INSERT INTO scrapes
    (source_id, ts, status, price_pix_cents, price_card_cents,
     currency, availability, method, error, raw_ref,
     price_pix_member_cents, price_card_member_cents)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_SELECT_HISTORY = """
SELECT source_id, ts, status, price_pix_cents, price_card_cents,
       currency, availability, method, error, raw_ref,
       price_pix_member_cents, price_card_member_cents
FROM scrapes
WHERE source_id = ?
ORDER BY ts DESC, id DESC
LIMIT ?
"""


class SqliteStateStore:
    """StateStore backed by a local SQLite file (or :memory: for tests)."""

    def __init__(self, db_path: str | Path = "kerdoos.db") -> None:
        self._path = str(db_path)
        self._conn = sqlite3.connect(self._path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Additive, idempotent upgrade of a pre-existing 2-price database.

        Column names are module constants (never user input), so the ALTER DDL
        carries no injectable value (no CWE-89). Missing member columns are added
        without recreating the table, preserving all existing history; old rows
        then read back with member prices NULL.
        """
        existing = {
            row["name"]
            for row in self._conn.execute("PRAGMA table_info(scrapes)").fetchall()
        }
        for column in _MEMBER_COLUMNS:
            if column not in existing:
                self._conn.execute(
                    f"ALTER TABLE scrapes ADD COLUMN {column} INTEGER")
        self._conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    def record(self, scrape: ScrapeRecord) -> None:
        self._conn.execute(
            _INSERT,
            (
                scrape.source_id,
                scrape.ts,
                scrape.status.value,
                scrape.price_pix_cents,
                scrape.price_card_cents,
                scrape.currency,
                scrape.availability.value,
                scrape.method,
                scrape.error,
                scrape.raw_ref,
                scrape.price_pix_member_cents,
                scrape.price_card_member_cents,
            ),
        )
        self._conn.commit()

    def history(self, source_id: str, limit: int = 50) -> list[ScrapeRecord]:
        rows = self._conn.execute(_SELECT_HISTORY, (source_id, limit)).fetchall()
        return [_row_to_record(row) for row in rows]

    def close(self) -> None:
        self._conn.close()


def _row_to_record(row: sqlite3.Row) -> ScrapeRecord:
    return ScrapeRecord(
        source_id=row["source_id"],
        ts=row["ts"],
        status=ScrapeStatus(row["status"]),
        price_pix_cents=row["price_pix_cents"],
        price_card_cents=row["price_card_cents"],
        currency=row["currency"],
        availability=Availability(row["availability"]),
        method=row["method"],
        error=row["error"],
        price_pix_member_cents=row["price_pix_member_cents"],
        price_card_member_cents=row["price_card_member_cents"],
        raw_ref=row["raw_ref"],
    )
