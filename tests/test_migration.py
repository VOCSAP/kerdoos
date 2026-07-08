"""Additive schema migration: a pre-existing 2-price DB gains member columns.

Simulates a database written by the Kabum slice (no member columns) and checks
that opening it with the current SqliteStateStore adds the two member columns
in place (ALTER, no table recreation), preserving existing history, and that the
migration is idempotent.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from kerdoos.core.domain import Availability, ScrapeStatus
from kerdoos.persistence.ports import ScrapeRecord
from kerdoos.persistence.sqlite_store import SqliteStateStore

# The exact pre-member schema (10 columns), as shipped with the Kabum slice.
_OLD_SCHEMA = """
CREATE TABLE scrapes (
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
    raw_ref        TEXT
);
"""


def _seed_old_db(path: Path) -> None:
    conn = sqlite3.connect(str(path))
    conn.executescript(_OLD_SCHEMA)
    conn.execute(
        "INSERT INTO scrapes (source_id, ts, status, price_pix_cents, "
        "price_card_cents, currency, availability, method, error, raw_ref) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ("legacy:kabum:1", "2026-07-01T00:00:00+00:00", "ok", 100000, 110000,
         "BRL", "InStock", "http", None, None),
    )
    conn.commit()
    conn.close()


def _columns(path: Path) -> set[str]:
    conn = sqlite3.connect(str(path))
    try:
        rows = conn.execute("PRAGMA table_info(scrapes)").fetchall()
    finally:
        conn.close()
    return {row[1] for row in rows}


def _user_version(path: Path) -> int:
    conn = sqlite3.connect(str(path))
    try:
        return conn.execute("PRAGMA user_version").fetchone()[0]
    finally:
        conn.close()


class MigrationTest(unittest.TestCase):
    def test_member_columns_added_to_legacy_db(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kerdoos.db"
            _seed_old_db(path)
            self.assertNotIn("price_pix_member_cents", _columns(path))

            store = SqliteStateStore(path)
            try:
                cols = _columns(path)
                self.assertIn("price_pix_member_cents", cols)
                self.assertIn("price_card_member_cents", cols)
                self.assertIn("owner_id", cols)
                self.assertEqual(_user_version(path), 3)
                # Legacy history survives, backfilled to the bootstrap owner,
                # member prices read back as NULL.
                history = store.history("bootstrap", "legacy:kabum:1")
                self.assertEqual(len(history), 1)
                self.assertEqual(history[0].price_pix_cents, 100000)
                self.assertIsNone(history[0].price_pix_member_cents)
                self.assertIsNone(history[0].price_card_member_cents)
            finally:
                store.close()

    def test_new_member_prices_roundtrip_after_migration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kerdoos.db"
            _seed_old_db(path)
            store = SqliteStateStore(path)
            try:
                store.record("owner1", ScrapeRecord(
                    source_id="amazon:1", ts="2026-07-06T00:00:00+00:00",
                    status=ScrapeStatus.OK, price_pix_cents=718010,
                    price_card_cents=755800, currency="BRL",
                    availability=Availability.IN_STOCK, method="tls", error=None,
                    price_pix_member_cents=702905,
                    price_card_member_cents=739900,
                ))
                row = store.history("owner1", "amazon:1")[0]
                self.assertEqual(row.price_pix_member_cents, 702905)
                self.assertEqual(row.price_card_member_cents, 739900)
            finally:
                store.close()

    def test_migration_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kerdoos.db"
            _seed_old_db(path)
            # Opening twice must not raise (columns already present the 2nd time).
            SqliteStateStore(path).close()
            SqliteStateStore(path).close()
            self.assertIn("price_card_member_cents", _columns(path))


if __name__ == "__main__":
    unittest.main()
