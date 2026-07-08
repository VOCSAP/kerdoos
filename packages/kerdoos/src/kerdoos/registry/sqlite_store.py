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

from .ports import ConfigStore, MutableConfigStore, Product, ProductSource, Registry, SiteConfig

_SCHEMA = """
CREATE TABLE IF NOT EXISTS owners (
    id      TEXT PRIMARY KEY,
    name    TEXT NOT NULL,
    email   TEXT,
    role    TEXT NOT NULL DEFAULT 'user',
    state   TEXT NOT NULL DEFAULT 'active'
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
        self._conn.commit()

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
        email: str | None = None,
    ) -> str:
        self._conn.execute(
            """
            INSERT INTO owners (id, name, email, role, state)
            VALUES (?, ?, ?, ?, 'active')
            ON CONFLICT(id) DO UPDATE SET
                name=excluded.name, email=excluded.email, role=excluded.role
            """,
            (owner_id, name, email, role),
        )
        self._conn.commit()
        return owner_id

    def get_owner_role(self, owner_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT role FROM owners WHERE id = ?", (owner_id,)
        ).fetchone()
        return row["role"] if row else None


# Static conformance check (mypy-time only; documents the ISP split).
_conforms_read: type[ConfigStore] = SqliteConfigStore
_conforms_write: type[MutableConfigStore] = SqliteConfigStore
