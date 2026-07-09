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
from pathlib import Path

from kerdoos.parsers.ports import ParserSpec
from kerdoos.registry.errors import ConfigError

from .ports import ConfigStore, MutableConfigStore, Product, ProductSource, Registry, SiteConfig

_SCHEMA_VERSION = 3

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


class SqliteConfigStore:
    """ConfigStore + MutableConfigStore backed by config.db."""

    def __init__(self, db_path: str | Path) -> None:
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Additive, idempotent upgrade of a pre-existing config.db.

        Phase 3 adds owners.password_hash + owners.created_at. Column names are
        module constants (never user input), so the ALTER DDL carries no
        injectable value (no CWE-89). Existing owners/sites/products/sources are
        preserved (ALTER ADD COLUMN only).
        """
        existing = {
            row["name"]
            for row in self._conn.execute("PRAGMA table_info(owners)").fetchall()
        }
        for column, coltype in _OWNERS_AUTH_COLUMNS:
            if column not in existing:
                self._conn.execute(
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
        self._reject_duplicate_identities()
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_owners_name ON owners(name)")
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_owners_email "
            "ON owners(email) WHERE email IS NOT NULL")
        self._conn.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    def _reject_duplicate_identities(self) -> None:
        dup_names = [
            row["name"] for row in self._conn.execute(
                "SELECT name FROM owners GROUP BY name HAVING COUNT(*) > 1"
            ).fetchall()
        ]
        dup_emails = [
            row["email"] for row in self._conn.execute(
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
        self._conn.close()

    # -- ConfigStore (read) --------------------------------------------

    def load(self, owner: str) -> Registry:
        sites = self._load_sites()
        products = self._load_products(owner)
        return Registry(sites=sites, products=products)

    def _load_sites(self) -> dict[str, SiteConfig]:
        rows = self._conn.execute("SELECT * FROM sites ORDER BY name").fetchall()
        return {row["name"]: _row_to_site(row) for row in rows}

    def site_domains(self) -> frozenset[str]:
        rows = self._conn.execute(
            "SELECT domain FROM sites WHERE domain != ''"
        ).fetchall()
        return frozenset(row["domain"] for row in rows)

    def _load_products(self, owner: str) -> tuple[Product, ...]:
        # Single grouped query instead of one sources SELECT per product
        # (N+1): all of an owner's sources are fetched at once and grouped
        # in memory by product_key, preserving deterministic ordering.
        product_rows = self._conn.execute(
            "SELECT product_key, name FROM products WHERE owner_id = ? "
            "ORDER BY product_key",
            (owner,),
        ).fetchall()
        source_rows = self._conn.execute(
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
        self._conn.execute(
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
        self._conn.commit()

    def add_product(self, owner: str, product: Product) -> None:
        self._conn.execute(
            """
            INSERT INTO products (owner_id, product_key, name)
            VALUES (?, ?, ?)
            ON CONFLICT(owner_id, product_key) DO UPDATE SET name=excluded.name
            """,
            (owner, product.id, product.name),
        )
        self._conn.commit()

    def add_source(self, owner: str, source: ProductSource) -> None:
        self._conn.execute(
            """
            INSERT INTO sources (source_id, owner_id, product_key, site, url)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(source_id) DO NOTHING
            """,
            (source.source_id, owner, source.product_id, source.site, source.url),
        )
        self._conn.commit()

    def remove_source(self, owner: str, source_id: str) -> None:
        # owner-scoped delete: a tenant can never remove another tenant's
        # source, even if it guesses the source_id.
        self._conn.execute(
            "DELETE FROM sources WHERE source_id = ? AND owner_id = ?",
            (source_id, owner),
        )
        self._conn.commit()

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
            self._conn.execute(
                """
                INSERT INTO owners
                    (id, name, email, role, state, password_hash, created_at)
                VALUES (?, ?, ?, ?, 'active', ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name, email=excluded.email, role=excluded.role,
                    password_hash=excluded.password_hash
                """,
                (owner_id, name, email, role, password_hash, created_at),
            )
            self._conn.commit()
        except sqlite3.IntegrityError as exc:
            # A duplicate name/email (unique-index violation) surfaces as a
            # named domain error, not a raw driver exception (gate C2).
            self._conn.rollback()
            raise ConfigError(
                f"owner identity conflict for name={name!r} email={email!r}: "
                f"{exc}"
            ) from exc
        return owner_id

    def get_owner_role(self, owner_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT role FROM owners WHERE id = ?", (owner_id,)
        ).fetchone()
        return row["role"] if row else None


# Static conformance check (mypy-time only; documents the ISP split).
_conforms_read: type[ConfigStore] = SqliteConfigStore
_conforms_write: type[MutableConfigStore] = SqliteConfigStore
