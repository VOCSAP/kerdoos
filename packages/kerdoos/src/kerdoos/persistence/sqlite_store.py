"""SQLite StateStore adapter (ADR 0001 S4 -- multi-tenant).

All SQL is parameterized (spec #2, CWE-89): no value is ever interpolated into a
statement string. Enum values are stored by `.value` and rebuilt on read.

Tenancy (Phase 1): every row carries owner_id and every read/write filters it
INLINE, never as an optional/trailing clause. record()/history()/latest_all()
all require owner; record() fail-closed raises ValueError on a falsy owner
(defense in depth -- see the migration note below on why this substitutes for
a physical NOT NULL on legacy databases).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from kerdoos.core.domain import Availability, ScrapeStatus

from .ports import JobRun, ScrapeRecord

_BUSY_TIMEOUT_MS = 5000

# Fresh databases get owner_id NOT NULL directly (real constraint enforcement).
# Legacy databases (pre owner_id) cannot get a retroactive NOT NULL via ALTER
# TABLE ADD COLUMN without a compile-time-constant default, so they are
# migrated additively (nullable ALTER + backfill) -- see _migrate_owner_id.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS scrapes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id       TEXT    NOT NULL,
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

-- Phase 6a (ADR 0003 T2/Decision 3). No FK to config.db's digest_jobs --
-- state.db and config.db are physically separate SQLite files, so no
-- cross-DB FK is possible; any join is done in-memory at the service layer
-- (6b evaluator concern). (job_id, window_start) PK is the idempotence key:
-- INSERT ... ON CONFLICT DO NOTHING makes a duplicate tick a safe no-op.
CREATE TABLE IF NOT EXISTS job_runs (
    job_id       TEXT NOT NULL,
    owner_id     TEXT NOT NULL,
    window_start TEXT NOT NULL,
    fired_at     TEXT NOT NULL,
    sent_at      TEXT,
    status       TEXT NOT NULL,
    error        TEXT,
    PRIMARY KEY (job_id, window_start)
);
"""
# idx_scrapes_owner_source_ts is created in _migrate(), NOT here: on a legacy
# (pre owner_id) database, this executescript() runs BEFORE the additive ALTER
# TABLE ADD COLUMN owner_id, so an index on that column here would fail with
# "no such column: owner_id" (CREATE TABLE IF NOT EXISTS is a no-op against an
# existing table -- it does not retroactively add the column).

# Additive, idempotent migrations, applied in order to whatever schema version
# an existing database is at. No table recreation, so history is preserved.
_SCHEMA_VERSION = 4
_MEMBER_COLUMNS = ("price_pix_member_cents", "price_card_member_cents")

_INSERT = """
INSERT INTO scrapes
    (owner_id, source_id, ts, status, price_pix_cents, price_card_cents,
     currency, availability, method, error, raw_ref,
     price_pix_member_cents, price_card_member_cents)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_SELECT_HISTORY = """
SELECT source_id, ts, status, price_pix_cents, price_card_cents,
       currency, availability, method, error, raw_ref,
       price_pix_member_cents, price_card_member_cents
FROM scrapes
WHERE owner_id = ? AND source_id = ?
ORDER BY ts DESC, id DESC
LIMIT ?
"""

# Most recent row per source_id for a given owner, via a partitioned window --
# a single query, no N+1 (one SELECT per source would not scale with catalogue
# size).
_SELECT_LATEST_ALL = """
SELECT source_id, ts, status, price_pix_cents, price_card_cents,
       currency, availability, method, error, raw_ref,
       price_pix_member_cents, price_card_member_cents
FROM (
    SELECT *, ROW_NUMBER() OVER (
        PARTITION BY source_id ORDER BY ts DESC, id DESC
    ) AS rn
    FROM scrapes
    WHERE owner_id = ?
)
WHERE rn = 1
ORDER BY source_id
"""


class SqliteStateStore:
    """StateStore backed by a local SQLite file, connection-PER-OPERATION.

    Architect FD3 (ADR 0001 S5.1): no shared self._conn -- each method opens its
    own short-lived WAL connection so concurrent ASGI handlers never hit
    sqlite3.ProgrammingError or a head-of-line lock. `:memory:` is NOT supported
    (each per-op connection would see a separate empty DB); tests use temp files.

    bootstrap_owner_id: backfill target for legacy (pre owner_id) rows found
    in an existing database on open. Irrelevant for fresh databases.
    """

    def __init__(
        self, db_path: str | Path = "kerdoos.db", *,
        bootstrap_owner_id: str = "bootstrap",
    ) -> None:
        self._path = str(db_path)
        self._bootstrap_owner_id = bootstrap_owner_id
        with self._op() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
            self._migrate(conn)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
        return conn

    @contextmanager
    def _op(self) -> Iterator[sqlite3.Connection]:
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """Additive, idempotent upgrade of a pre-existing database.

        Column/index names are module constants (never user input), so the
        ALTER/CREATE INDEX DDL carries no injectable value (no CWE-89).
        """
        existing = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(scrapes)").fetchall()
        }
        for column in _MEMBER_COLUMNS:
            if column not in existing:
                conn.execute(
                    f"ALTER TABLE scrapes ADD COLUMN {column} INTEGER")
        if "owner_id" not in existing:
            # Legacy DB: nullable ALTER (SQLite can't retroactively add a
            # NOT NULL column to a non-empty table without a constant
            # default), then backfill every existing row to the bootstrap
            # owner so pre-Phase-1 history is preserved and stays queryable.
            conn.execute("ALTER TABLE scrapes ADD COLUMN owner_id TEXT")
            conn.execute(
                "UPDATE scrapes SET owner_id = ? WHERE owner_id IS NULL",
                (self._bootstrap_owner_id,),
            )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scrapes_owner_source_ts "
            "ON scrapes (owner_id, source_id, ts DESC)"
        )
        conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    def record(self, owner: str, scrape: ScrapeRecord) -> None:
        if not owner:
            # Fail-closed: legacy DBs can't get a physical NOT NULL via
            # ALTER, so the write path is the enforcement point instead.
            raise ValueError("owner must not be empty")
        with self._op() as conn:
            conn.execute(
                _INSERT,
                (
                    owner,
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

    def history(
        self, owner: str, source_id: str, limit: int = 50
    ) -> list[ScrapeRecord]:
        with self._op() as conn:
            rows = conn.execute(
                _SELECT_HISTORY, (owner, source_id, limit)).fetchall()
        return [_row_to_record(row) for row in rows]

    def latest_all(self, owner: str) -> list[ScrapeRecord]:
        with self._op() as conn:
            rows = conn.execute(_SELECT_LATEST_ALL, (owner,)).fetchall()
        return [_row_to_record(row) for row in rows]

    def record_job_run(self, run: JobRun) -> bool:
        # ON CONFLICT DO NOTHING on the (job_id, window_start) PK -- the
        # idempotence key from ADR 0003 Decision 3. rowcount tells the caller
        # whether THIS call was the one that actually recorded the firing.
        with self._op() as conn:
            cur = conn.execute(
                """
                INSERT INTO job_runs
                    (job_id, owner_id, window_start, fired_at, sent_at,
                     status, error)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id, window_start) DO NOTHING
                """,
                (run.job_id, run.owner_id, run.window_start, run.fired_at,
                 run.sent_at, run.status, run.error),
            )
        return cur.rowcount == 1

    def update_job_run(
        self,
        job_id: str,
        window_start: str,
        *,
        status: str,
        sent_at: str | None = None,
        error: str | None = None,
    ) -> bool:
        # No owner_id filter here BY DESIGN: (job_id, window_start) is the
        # PRIMARY KEY (already globally unique), so there is nothing to scope
        # further -- unlike record_job_run's INSERT (which carries owner_id
        # to persist it), an UPDATE targeting the PK cannot cross tenants.
        with self._op() as conn:
            cur = conn.execute(
                """
                UPDATE job_runs
                SET status = ?, sent_at = ?, error = ?
                WHERE job_id = ? AND window_start = ?
                """,
                (status, sent_at, error, job_id, window_start),
            )
        return cur.rowcount == 1

    def has_active_job_run(self, owner: str, job_id: str) -> bool:
        # Double-scoping IDOR defense (ADR 0003 finding S2): owner_id is
        # filtered INLINE here even though job_id alone would already be a
        # UUID (practically unguessable) -- same discipline as every other
        # StateStore method, never trust a bare job_id at face value.
        with self._op() as conn:
            row = conn.execute(
                """
                SELECT 1 FROM job_runs
                WHERE owner_id = ? AND job_id = ?
                  AND status IN ('queued', 'running')
                LIMIT 1
                """,
                (owner, job_id),
            ).fetchone()
        return row is not None

    def close(self) -> None:
        # No-op: connection-per-operation holds no long-lived connection.
        return None


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
