"""Kerdoos CLI entry point (MVP).

This is the composition root: the ONLY place that wires concrete adapters
(StaticRouter -> HttpFetcher, factory -> StateJsonParser, SqliteStateStore).
The core stays a library and imports none of these. The `run` command scrapes
every configured source, persists each outcome, and prints the single
aggregated digest to stdout (dry-run: no SMTP send at the MVP).
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from autolycos.router import StaticRouter
from kerdoos.core.domain import Availability, ScrapeStatus
from kerdoos.core.orchestrator import scrape_and_record
from kerdoos.digest.render import render_digest
from kerdoos.parsers.factory import build_parser
from kerdoos.persistence.ports import ScrapeRecord
from kerdoos.persistence.sqlite_store import SqliteStateStore
from kerdoos.registry.domain_policy import DEFAULT_DOMAIN_POLICY
from kerdoos.registry.yaml_store import YamlConfigStore


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_registry(config_dir: Path):
    store = YamlConfigStore(config_dir / "sites.yaml", config_dir / "products.yaml")
    return store.load()


def cmd_run(args: argparse.Namespace) -> int:
    registry = _load_registry(Path(args.config_dir))
    router = StaticRouter(DEFAULT_DOMAIN_POLICY)
    store = SqliteStateStore(args.db)
    generated_at = _now_iso()

    records = []
    # source_id -> second-tier label (e.g. "Prime"); resolved HERE, where both
    # the Registry and the records are in hand, and passed to the digest as data
    # so digest/ never imports the registry.
    tier2_labels: dict[str, str] = {}
    try:
        for _product, source, site in registry.iter_sources():
            if site.tier2_label:
                tier2_labels[source.source_id] = site.tier2_label
            # Per-source guard (invariant #8): a failing source (unknown
            # fetcher/parser tier, store error, ...) must never abort the run
            # nor suppress the aggregated digest.
            try:
                fetcher = router.select(site.fetcher, site.subresource_domains)
                parser = build_parser(site.parser)
                record = scrape_and_record(
                    fetcher, parser, store, source.source_id, source.url,
                    now=generated_at,
                )
            except Exception as exc:  # noqa: BLE001 -- one source must not kill the run
                record = ScrapeRecord(
                    source_id=source.source_id, ts=generated_at,
                    status=ScrapeStatus.INDETERMINATE,
                    price_pix_cents=None, price_card_cents=None, currency=None,
                    availability=Availability.UNKNOWN, method=None,
                    error=f"source failed: {type(exc).__name__}: {exc}",
                )
            records.append(record)
    finally:
        store.close()

    print(render_digest(records, generated_at, tier2_labels))
    return 0


def build_parser_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kerdoos", description="Kerdoos MVP CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="scrape all sources and print the digest")
    run.add_argument("--config-dir", default="config",
                     help="directory holding sites.yaml + products.yaml")
    run.add_argument("--db", default="kerdoos.db",
                     help="SQLite state store path (':memory:' for ephemeral)")
    run.add_argument("--dry-run", action="store_true", default=True,
                     help="render digest to stdout, do not send mail (default)")
    run.set_defaults(func=cmd_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser_cli()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
