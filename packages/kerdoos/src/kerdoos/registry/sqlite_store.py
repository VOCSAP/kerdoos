"""SQLite ConfigStore adapter (ADR 0001 S4) -- config.db, physically distinct
from state.db (invariant #7: config and state stay separate, each behind its
own abstraction).

Implements BOTH ConfigStore (read, consumed by AppService.list_config/run_now)
and MutableConfigStore (write, consumed by AppService.add_site/add_product/
add_source/remove_source and the `kerdoos config import` CLI command).

Schema (ADR 0001 S4):
  owners(id, name, email NULLABLE, role, state)                 -- Phase 1: no auth columns used yet
  sites(name PK, fetcher, domain, tier2_label, subresource_domains, parser_*)
                                                                  -- GLOBAL catalogue, no owner_id (Q3)
  products(owner_id, product_key, name, PRIMARY KEY(owner_id, product_key))
  sources(source_id PK, owner_id, product_key, site, url,
          UNIQUE(owner_id, product_key, site, url))
    FK sources.(owner_id, product_key) -> products.(owner_id, product_key)
    FK sources.site -> sites.name

add_site/add_product/add_source are UPSERTs so `kerdoos config import` is
idempotent (re-running it twice never raises nor duplicates rows).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from kerdoos.parsers.ports import ParserSpec
from kerdoos.registry.errors import ConfigError

_BUSY_TIMEOUT_MS = 5000

from .ports import (
    ConfigStore,
    DigestJob,
    MutableConfigStore,
    Product,
    ProductSource,
    Registry,
    SiteConfig,
    dump_job_options,
    parse_job_options,
)

_SCHEMA_VERSION = 4

# owners auth columns added in Phase 3 (ADR 0001 S6). email/role/state already
# existed in Phase 1; password_hash + created_at are added here. On a fresh DB
# they come from this CREATE; on a pre-Phase-3 DB they are added by _migrate()
# (additive ALTER, never dropping existing owners).
_OWNERS_AUTH_COLUMNS = (
    ("password_hash", "TEXT"),   # Argon2id hash, NULL = no password (WebUI SSO/none)
    ("created_at", "TEXT"),      # ISO-8601 UTC, set at owner creation
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS owners (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    email         TEXT,
    role          TEXT NOT NULL DEFAULT 'user',
    state         TEXT NOT NULL DEFAULT 'active',
    password_hash TEXT,
    created_at    TEXT
);

CREATE TABLE IF NOT EXISTS sites (
    name                 TEXT PRIMARY KEY,
    fetcher              TEXT NOT NULL,
    domain               TEXT NOT NULL,
    tier2_label          TEXT,
    subresource_domains  TEXT NOT NULL DEFAULT '[]',
    parser_kind          TEXT NOT NULL,
    parser_pix           TEXT,
    parser_card          TEXT,
    parser_availability  TEXT
);

CREATE TABLE IF NOT EXISTS products (
    owner_id     TEXT NOT NULL,
    product_key  TEXT NOT NULL,
    name         TEXT,
    PRIMARY KEY (owner_id, product_key)
);

CREATE TABLE IF NOT EXISTS sources (
    source_id    TEXT PRIMARY KEY,
    owner_id     TEXT NOT NULL,
    product_key  TEXT NOT NULL,
    site         TEXT NOT NULL,
    url          TEXT NOT NULL,
    UNIQUE (owner_id, product_key, site, url),
    FOREIGN KEY (owner_id, product_key) REFERENCES products (owner_id, product_key),
    FOREIGN KEY (site) REFERENCES sites (name)
);

-- Phase 6a (ADR 0003 S4). UNIQUE(owner_id, name) is safe INLINE here (unlike
-- the owners identity indexes in _migrate()) because this table is BRAND NEW
-- -- there are no pre-existing rows on any DB that could violate it, so the
-- #11162 pre-check-before-CREATE-UNIQUE-INDEX pitfall does not apply.
CREATE TABLE IF NOT EXISTS digest_jobs (
    id             TEXT PRIMARY KEY,
    owner_id       TEXT NOT NULL,
    name           TEXT NOT NULL,
    frequency_kind TEXT NOT NULL,
    schedule_cron  TEXT NOT NULL,
    timezone       TEXT NOT NULL DEFAULT 'UTC',
    template_id    TEXT NOT NULL,
    options        TEXT NOT NULL DEFAULT '{}',
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT,
    UNIQUE (owner_id, name)
);

-- owner_id is carried here too (not just derivable via a join to
-- digest_jobs) so every read/write can filter it INLINE, same discipline as
-- `sources` -- no cross-DB FK exists to state.db's job_runs (ADR 0003 T2),
-- but this table stays entirely inside config.db so the FK to digest_jobs
-- and sources IS safe to declare.
CREATE TABLE IF NOT EXISTS digest_job_sources (
    owner_id   TEXT NOT NULL,
    job_id     TEXT NOT NULL,
    source_id  TEXT NOT NULL,
    PRIMARY KEY (job_id, source_id),
    FOREIGN KEY (job_id)    REFERENCES digest_jobs (id) ON DELETE CASCADE,
    FOREIGN KEY (source_id) REFERENCES sources (source_id) ON DELETE CASCADE
);
"""


def _site_to_row(site: SiteConfig) -> tuple:
    return (
        site.name, site.fetcher, site.domain, site.tier2_label,
        json.dumps(list(site.subresource_domains)),
        site.parser.kind, site.parser.pix, site.parser.card,
        site.parser.availability,
    )


def _row_to_site(row: sqlite3.Row) -> SiteConfig:
    return SiteConfig(
        name=row["name"], fetcher=row["fetcher"], domain=row["domain"],
        tier2_label=row["tier2_label"],
        subresource_domains=tuple(json.loads(row["subresource_domains"])),
        parser=ParserSpec(
            kind=row["parser_kind"], pix=row["parser_pix"],
            card=row["parser_card"], availability=row["parser_availability"],
        ),
    )


def _row_to_job(row: sqlite3.Row, source_ids: tuple[str, ...]) -> DigestJob:
    return DigestJob(
        id=row["id"], owner_id=row["owner_id"], name=row["name"],
        frequency_kind=row["frequency_kind"], schedule_cron=row["schedule_cron"],
        timezone=row["timezone"], template_id=row["template_id"],
        options=parse_job_options(json.loads(row["options"])),
        enabled=bool(row["enabled"]), created_at=row["created_at"],
        source_ids=source_ids,
    )


def _replace_job(job: DigestJob, **changes: object) -> DigestJob:
    return replace(job, **changes)


class SqliteConfigStore:
    """ConfigStore + MutableConfigStore backed by config.db."""

    def __init__(self, db_path: str | Path) -> None:
        # Connection-PER-OPERATION (architect FD3, ADR 0001 S5.1): no shared
        # self._conn. Under concurrent ASGI handlers a single check_same_thread
        # connection would raise sqlite3.ProgrammingError; WAL + busy_timeout
        # let concurrent readers/writers proceed without a head-of-line lock.
        # Schema + migration run ONCE here on a dedicated connection.
        self._path = str(db_path)
        with self._op() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
            self._migrate(conn)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
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
        """Additive, idempotent upgrade of a pre-existing config.db.

        Phase 3 adds owners.password_hash + owners.created_at. Column names are
        module constants (never user input), so the ALTER DDL carries no
        injectable value (no CWE-89). Existing owners/sites/products/sources are
        preserved (ALTER ADD COLUMN only).
        """
        existing = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(owners)").fetchall()
        }
        for column, coltype in _OWNERS_AUTH_COLUMNS:
            if column not in existing:
                conn.execute(
                    f"ALTER TABLE owners ADD COLUMN {column} {coltype}")
        # Hybrid identity (Phase 3): a login identifier (name OR email) must
        # resolve to AT MOST one owner. name is the username (UNIQUE); email is
        # UNIQUE only when present (partial index, so many owners may have no
        # email -- the WebUI-only case, Kleos #11059).
        #
        # PRE-CHECK duplicates BEFORE creating the unique indexes: a legacy
        # config.db populated before the uniqueness rule could hold duplicate
        # names/emails. Without this, CREATE UNIQUE INDEX raises a raw
        # sqlite3.IntegrityError out of __init__ and the DB becomes unopenable.
        # Instead we fail with a NAMED ConfigError that lists the collisions so
        # an operator can fix the data (gate C1).
        self._reject_duplicate_identities(conn)
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_owners_name ON owners(name)")
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_owners_email "
            "ON owners(email) WHERE email IS NOT NULL")
        conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    def _reject_duplicate_identities(self, conn: sqlite3.Connection) -> None:
        dup_names = [
            row["name"] for row in conn.execute(
                "SELECT name FROM owners GROUP BY name HAVING COUNT(*) > 1"
            ).fetchall()
        ]
        dup_emails = [
            row["email"] for row in conn.execute(
                "SELECT email FROM owners WHERE email IS NOT NULL "
                "GROUP BY email HAVING COUNT(*) > 1"
            ).fetchall()
        ]
        if dup_names or dup_emails:
            parts = []
            if dup_names:
                parts.append(f"duplicate owner names: {sorted(dup_names)}")
            if dup_emails:
                parts.append(f"duplicate owner emails: {sorted(dup_emails)}")
            raise ConfigError(
                "cannot enforce owner identity uniqueness -- "
                + "; ".join(parts)
                + ". Resolve the duplicate rows before opening this config.db."
            )

    def close(self) -> None:
        # No-op: connection-per-operation holds no long-lived connection. Kept
        # for API compatibility with existing callers (CLI) that call close().
        return None

    # -- ConfigStore (read) --------------------------------------------

    def load(self, owner: str) -> Registry:
        with self._op() as conn:
            sites = self._load_sites(conn)
            products = self._load_products(conn, owner)
        return Registry(sites=sites, products=products)

    def _load_sites(self, conn: sqlite3.Connection) -> dict[str, SiteConfig]:
        rows = conn.execute("SELECT * FROM sites ORDER BY name").fetchall()
        return {row["name"]: _row_to_site(row) for row in rows}

    def site_domains(self) -> frozenset[str]:
        with self._op() as conn:
            rows = conn.execute(
                "SELECT domain FROM sites WHERE domain != ''"
            ).fetchall()
        return frozenset(row["domain"] for row in rows)

    def _load_products(
        self, conn: sqlite3.Connection, owner: str
    ) -> tuple[Product, ...]:
        # Single grouped query instead of one sources SELECT per product
        # (N+1): all of an owner's sources are fetched at once and grouped
        # in memory by product_key, preserving deterministic ordering.
        product_rows = conn.execute(
            "SELECT product_key, name FROM products WHERE owner_id = ? "
            "ORDER BY product_key",
            (owner,),
        ).fetchall()
        source_rows = conn.execute(
            "SELECT source_id, product_key, site, url FROM sources "
            "WHERE owner_id = ? ORDER BY product_key, source_id",
            (owner,),
        ).fetchall()
        sources_by_product: dict[str, list[ProductSource]] = {}
        for srow in source_rows:
            sources_by_product.setdefault(srow["product_key"], []).append(
                ProductSource(
                    source_id=srow["source_id"], product_id=srow["product_key"],
                    site=srow["site"], url=srow["url"],
                )
            )
        products = [
            Product(
                id=prow["product_key"], name=prow["name"],
                sources=tuple(sources_by_product.get(prow["product_key"], ())),
            )
            for prow in product_rows
        ]
        return tuple(products)

    # -- MutableConfigStore (write, interfaces only) --------------------

    def add_site(self, site: SiteConfig) -> None:
        with self._op() as conn:
            conn.execute(
                """
                INSERT INTO sites (name, fetcher, domain, tier2_label,
                                    subresource_domains, parser_kind, parser_pix,
                                    parser_card, parser_availability)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    fetcher=excluded.fetcher, domain=excluded.domain,
                    tier2_label=excluded.tier2_label,
                    subresource_domains=excluded.subresource_domains,
                    parser_kind=excluded.parser_kind, parser_pix=excluded.parser_pix,
                    parser_card=excluded.parser_card,
                    parser_availability=excluded.parser_availability
                """,
                _site_to_row(site),
            )

    def add_product(self, owner: str, product: Product) -> None:
        with self._op() as conn:
            conn.execute(
                """
                INSERT INTO products (owner_id, product_key, name)
                VALUES (?, ?, ?)
                ON CONFLICT(owner_id, product_key) DO UPDATE SET name=excluded.name
                """,
                (owner, product.id, product.name),
            )

    def add_source(self, owner: str, source: ProductSource) -> None:
        with self._op() as conn:
            conn.execute(
                """
                INSERT INTO sources (source_id, owner_id, product_key, site, url)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(source_id) DO NOTHING
                """,
                (source.source_id, owner, source.product_id, source.site,
                 source.url),
            )

    def remove_source(self, owner: str, source_id: str) -> None:
        # owner-scoped delete: a tenant can never remove another tenant's
        # source, even if it guesses the source_id.
        with self._op() as conn:
            conn.execute(
                "DELETE FROM sources WHERE source_id = ? AND owner_id = ?",
                (source_id, owner),
            )

    def remove_product(self, owner: str, product_key: str) -> None:
        # owner-scoped existence check FIRST (last rampart, invariant
        # multi-tenant): a tenant can never remove another tenant's product,
        # even knowing its exact product_key. Unlike remove_source's silent
        # no-op, an unknown/not-owned product_key raises -- the 4b-web forms
        # need a hard signal to distinguish "already gone" from "not yours".
        with self._op() as conn:
            row = conn.execute(
                "SELECT 1 FROM products WHERE owner_id = ? AND product_key = ?",
                (owner, product_key),
            ).fetchone()
            if row is None:
                raise KeyError(
                    f"unknown product {product_key!r} for owner {owner!r}")
            # Sources reference (owner_id, product_key) via FK -- delete them
            # first (cascade) so PRAGMA foreign_keys=ON does not reject the
            # product delete. Same owner-scoped filter on both deletes.
            conn.execute(
                "DELETE FROM sources WHERE owner_id = ? AND product_key = ?",
                (owner, product_key),
            )
            conn.execute(
                "DELETE FROM products WHERE owner_id = ? AND product_key = ?",
                (owner, product_key),
            )

    # -- digest jobs (Phase 6a, ADR 0003) --------------------------------

    def _link_sources(
        self, conn: sqlite3.Connection, owner: str, job_id: str,
        source_ids: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Link each source_id to job_id via an owner-scoped INSERT...SELECT:
        a source_id is only linked if it actually belongs to owner (double-
        scoping IDOR defense, ADR 0003 finding S2). Not-owned/unknown
        source_ids are silently skipped -- rowcount tells us, without ever
        raising (no oracle: the caller cannot tell 'unknown' from 'someone
        else's source' from the response shape)."""
        linked: list[str] = []
        for source_id in source_ids:
            cur = conn.execute(
                """
                INSERT INTO digest_job_sources (owner_id, job_id, source_id)
                SELECT ?, ?, source_id FROM sources
                WHERE owner_id = ? AND source_id = ?
                ON CONFLICT(job_id, source_id) DO NOTHING
                """,
                (owner, job_id, owner, source_id),
            )
            if cur.rowcount == 1:
                linked.append(source_id)
        return tuple(linked)

    def _load_job_sources(
        self, conn: sqlite3.Connection, owner: str, job_id: str
    ) -> tuple[str, ...]:
        rows = conn.execute(
            "SELECT source_id FROM digest_job_sources "
            "WHERE owner_id = ? AND job_id = ? ORDER BY source_id",
            (owner, job_id),
        ).fetchall()
        return tuple(row["source_id"] for row in rows)

    def create_job(
        self, owner: str, job: DigestJob, source_ids: tuple[str, ...]
    ) -> DigestJob:
        with self._op() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO digest_jobs
                        (id, owner_id, name, frequency_kind, schedule_cron,
                         timezone, template_id, options, enabled, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (job.id, owner, job.name, job.frequency_kind,
                     job.schedule_cron, job.timezone, job.template_id,
                     json.dumps(dump_job_options(job.options)),
                     1 if job.enabled else 0, job.created_at),
                )
            except sqlite3.IntegrityError as exc:
                raise ConfigError(
                    f"digest job name conflict for owner={owner!r} "
                    f"name={job.name!r}: {exc}"
                ) from exc
            linked = self._link_sources(conn, owner, job.id, source_ids)
        return _replace_job(job, owner_id=owner, source_ids=linked)

    def list_jobs(self, owner: str) -> tuple[DigestJob, ...]:
        with self._op() as conn:
            rows = conn.execute(
                "SELECT * FROM digest_jobs WHERE owner_id = ? ORDER BY name",
                (owner,),
            ).fetchall()
            jobs = [
                _row_to_job(row, self._load_job_sources(conn, owner, row["id"]))
                for row in rows
            ]
        return tuple(jobs)

    def list_all_enabled_jobs(self) -> tuple[DigestJob, ...]:
        # Scheduler-internal-only (ADR 0003 Phase 6b evaluator): the ONLY
        # read in this store with no owner_id filter, by design -- the
        # evaluator sweeps every tenant in one tick. See ports.py docstring
        # for the "never expose through AppService/HTTP" constraint.
        with self._op() as conn:
            rows = conn.execute(
                "SELECT * FROM digest_jobs WHERE enabled = 1 "
                "ORDER BY owner_id, name",
            ).fetchall()
            jobs = [
                _row_to_job(
                    row,
                    self._load_job_sources(conn, row["owner_id"], row["id"]),
                )
                for row in rows
            ]
        return tuple(jobs)

    def get_job(self, owner: str, job_id: str) -> DigestJob:
        with self._op() as conn:
            row = conn.execute(
                "SELECT * FROM digest_jobs WHERE owner_id = ? AND id = ?",
                (owner, job_id),
            ).fetchone()
            if row is None:
                raise KeyError(
                    f"unknown digest job {job_id!r} for owner {owner!r}")
            source_ids = self._load_job_sources(conn, owner, job_id)
        return _row_to_job(row, source_ids)

    def update_job(self, owner: str, job_id: str, job: DigestJob) -> DigestJob:
        with self._op() as conn:
            try:
                cur = conn.execute(
                    """
                    UPDATE digest_jobs SET
                        name = ?, frequency_kind = ?, schedule_cron = ?,
                        timezone = ?, template_id = ?, options = ?, enabled = ?
                    WHERE owner_id = ? AND id = ?
                    """,
                    (job.name, job.frequency_kind, job.schedule_cron,
                     job.timezone, job.template_id,
                     json.dumps(dump_job_options(job.options)),
                     1 if job.enabled else 0, owner, job_id),
                )
            except sqlite3.IntegrityError as exc:
                raise ConfigError(
                    f"digest job name conflict for owner={owner!r} "
                    f"name={job.name!r}: {exc}"
                ) from exc
            if cur.rowcount == 0:
                raise KeyError(
                    f"unknown digest job {job_id!r} for owner {owner!r}")
            source_ids = self._load_job_sources(conn, owner, job_id)
        return _replace_job(job, id=job_id, owner_id=owner, source_ids=source_ids)

    def delete_job(self, owner: str, job_id: str) -> None:
        # owner-scoped existence check FIRST, same discipline as
        # remove_product: a tenant can never delete another tenant's job,
        # even knowing its exact job_id.
        with self._op() as conn:
            row = conn.execute(
                "SELECT 1 FROM digest_jobs WHERE owner_id = ? AND id = ?",
                (owner, job_id),
            ).fetchone()
            if row is None:
                raise KeyError(
                    f"unknown digest job {job_id!r} for owner {owner!r}")
            # Explicit owner-scoped cascade delete (defense in depth on top
            # of the FK ON DELETE CASCADE -- same belt-and-braces pattern as
            # remove_product's manual sources delete).
            conn.execute(
                "DELETE FROM digest_job_sources WHERE owner_id = ? AND job_id = ?",
                (owner, job_id),
            )
            conn.execute(
                "DELETE FROM digest_jobs WHERE owner_id = ? AND id = ?",
                (owner, job_id),
            )

    def add_job_source(self, owner: str, job_id: str, source_id: str) -> bool:
        with self._op() as conn:
            row = conn.execute(
                "SELECT 1 FROM digest_jobs WHERE owner_id = ? AND id = ?",
                (owner, job_id),
            ).fetchone()
            if row is None:
                raise KeyError(
                    f"unknown digest job {job_id!r} for owner {owner!r}")
            linked = self._link_sources(conn, owner, job_id, (source_id,))
        return bool(linked)

    def remove_job_source(self, owner: str, job_id: str, source_id: str) -> None:
        # owner-scoped delete, silent no-op if the link is absent (mirrors
        # remove_source's discipline).
        with self._op() as conn:
            conn.execute(
                "DELETE FROM digest_job_sources "
                "WHERE owner_id = ? AND job_id = ? AND source_id = ?",
                (owner, job_id, source_id),
            )

    # -- owner bootstrap (no auth in Phase 1; CLI-only helper) -----------

    def ensure_owner(
        self, owner_id: str, name: str, *, role: str = "user",
        email: str | None = None, password_hash: str | None = None,
        created_at: str | None = None,
    ) -> str:
        """Create/update an owner (CLI-only write path, single-threaded).

        password_hash is an Argon2id digest (or None for a passwordless owner).
        This is the OWNER-table write path; the concurrent verify_* READ path
        lives in SqliteAuthStore (per-op connections), never on this shared
        connection (Phase 3 concurrency invariant, FD3).
        """
        if created_at is None:
            from datetime import datetime, timezone
            created_at = datetime.now(timezone.utc).isoformat()
        try:
            with self._op() as conn:
                conn.execute(
                    """
                    INSERT INTO owners
                        (id, name, email, role, state, password_hash, created_at)
                    VALUES (?, ?, ?, ?, 'active', ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        name=excluded.name, email=excluded.email,
                        role=excluded.role,
                        password_hash=excluded.password_hash
                    """,
                    (owner_id, name, email, role, password_hash, created_at),
                )
        except sqlite3.IntegrityError as exc:
            # A duplicate name/email (unique-index violation) surfaces as a
            # named domain error, not a raw driver exception (gate C2). _op has
            # already closed the connection; no manual rollback needed.
            raise ConfigError(
                f"owner identity conflict for name={name!r} email={email!r}: "
                f"{exc}"
            ) from exc
        return owner_id

    def get_owner_role(self, owner_id: str) -> str | None:
        with self._op() as conn:
            row = conn.execute(
                "SELECT role FROM owners WHERE id = ?", (owner_id,)
            ).fetchone()
        return row["role"] if row else None


# Static conformance check (mypy-time only; documents the ISP split).
_conforms_read: type[ConfigStore] = SqliteConfigStore
_conforms_write: type[MutableConfigStore] = SqliteConfigStore
