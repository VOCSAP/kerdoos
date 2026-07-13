"""Kerdoos CLI entry point.

This is the composition root: the ONLY place that wires concrete adapters
(StaticRouter -> HttpFetcher, build_parser -> adapter parsers,
SqliteConfigStore, SqliteStateStore) and constructs the AppService use-cases
layer (invariant #9: core is a library, CLI stays a thin interface).

Commands:
  run              scrape every configured source for --owner, print the digest
  digest           run ONE digest-jobs evaluation tick across ALL owners, then
                    exit (ADR 0003 Decision 8; for external cron when
                    KERDOOS_WORKERS > 1 -- shares evaluate_tick with the
                    WebUI's intra-process evaluator, never two implementations)
  config import    upsert sites.yaml (+ products.yaml if --owner given) into config.db
  config export    write config.db back out to sites.yaml/products.yaml
  user bootstrap   create a minimal owner row (no auth in Phase 1 -- Phase 3)
"""

from __future__ import annotations

import argparse
import asyncio
import uuid
from pathlib import Path

import yaml
from autolycos.router import StaticRouter

from kerdoos.core.app.services import AppService, Principal, ProductSpec
from kerdoos.core.evaluator import evaluate_tick
from kerdoos.digest.render import render_digest
from kerdoos.digest.sender import LogDigestSender
from kerdoos.parsers.factory import build_parser
from kerdoos.registry.domain_policy import CatalogueDomainPolicy
from kerdoos.registry.ports import SiteConfig
from kerdoos.registry.sqlite_store import SqliteConfigStore
from kerdoos.registry.yaml_store import parse_products_yaml, parse_sites_yaml
from kerdoos.persistence.sqlite_store import SqliteStateStore


def _build_app_service(
    config_db: str, db: str,
) -> tuple[AppService, SqliteConfigStore, SqliteStateStore]:
    config_store = SqliteConfigStore(config_db)
    state_store = SqliteStateStore(db)
    domain_policy = CatalogueDomainPolicy(config_store)
    router = StaticRouter(domain_policy)
    service = AppService(
        config_store, state_store, router, domain_policy, build_parser)
    return service, config_store, state_store


def cmd_run(args: argparse.Namespace) -> int:
    service, config_store, state_store = _build_app_service(args.config_db, args.db)
    try:
        result = service.run_now(args.owner)
    finally:
        config_store.close()
        state_store.close()
    print(render_digest(result.records, result.generated_at, result.tier2_labels))
    return 0


def cmd_digest(args: argparse.Namespace) -> int:
    """Run exactly ONE digest-jobs evaluation tick across ALL owners, then
    exit (ADR 0003 Decision 8). Shares evaluate_tick with the WebUI's
    intra-process evaluator (kerdoos.core.evaluator) -- the CLI is the
    external-cron trigger for KERDOOS_WORKERS > 1 deployments, never a
    second implementation of the tick logic."""
    _service, config_store, state_store = _build_app_service(args.config_db, args.db)
    domain_policy = CatalogueDomainPolicy(config_store)
    router = StaticRouter(domain_policy)
    try:
        summary = asyncio.run(evaluate_tick(
            config_store=config_store, state_store=state_store,
            router=router, parser_factory=build_parser,
            sender=LogDigestSender(),
        ))
    finally:
        config_store.close()
        state_store.close()
    print(
        f"scraped_sources={summary.scraped_sources} "
        f"notified_jobs={summary.notified_jobs} "
        f"skipped_jobs={summary.skipped_jobs} "
        f"errors={summary.errors}"
    )
    return 0


def cmd_config_import(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    service, config_store, state_store = _build_app_service(args.config_db, args.db)
    try:
        sites = parse_sites_yaml(config_dir / "sites.yaml")
        for site in sites.values():
            config_store.add_site(site)
        if args.owner:
            products_path = config_dir / "products.yaml"
            if products_path.exists():
                for product_key, sources in parse_products_yaml(
                    products_path, sites
                ):
                    service.add_product(args.owner, ProductSpec(product_key))
                    for site_name, url in sources:
                        service.add_source(args.owner, product_key, site_name, url)
        print(f"imported {len(sites)} site(s)"
              + (f" for owner {args.owner!r}" if args.owner else ""))
    finally:
        config_store.close()
        state_store.close()
    return 0


def cmd_config_export(args: argparse.Namespace) -> int:
    config_dir = Path(args.config_dir)
    config_dir.mkdir(parents=True, exist_ok=True)
    config_store = SqliteConfigStore(args.config_db)
    try:
        registry = config_store.load(args.owner or "")
        sites_doc = {
            "sites": {
                name: _site_to_yaml(site) for name, site in registry.sites.items()
            }
        }
        (config_dir / "sites.yaml").write_text(
            yaml.safe_dump(sites_doc, sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )
        if args.owner:
            products_doc = {
                "products": [
                    {
                        "id": product.id,
                        "sources": [
                            {"site": source.site, "url": source.url}
                            for source in product.sources
                        ],
                    }
                    for product in registry.products
                ]
            }
            (config_dir / "products.yaml").write_text(
                yaml.safe_dump(products_doc, sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
        print(f"exported {len(registry.sites)} site(s), "
              f"{len(registry.products)} product(s) to {config_dir}")
    finally:
        config_store.close()
    return 0


def _site_to_yaml(site: SiteConfig) -> dict:
    body: dict = {"fetcher": site.fetcher, "domain": site.domain}
    if site.tier2_label:
        body["tier2_label"] = site.tier2_label
    if site.subresource_domains:
        body["subresource_domains"] = list(site.subresource_domains)
    body["parser"] = {
        "kind": site.parser.kind,
        "pix": site.parser.pix,
        "card": site.parser.card,
        "availability": site.parser.availability,
    }
    return body


def cmd_user_bootstrap(args: argparse.Namespace) -> int:
    config_store = SqliteConfigStore(args.config_db)
    try:
        owner_id = uuid.uuid4().hex[:12]
        role = "admin" if args.admin else "user"
        config_store.ensure_owner(owner_id, args.name, role=role)
        print(owner_id)
    finally:
        config_store.close()
    return 0


def _read_password() -> str:
    """Read a password WITHOUT ever accepting it as a CLI arg (plaintext in the
    process table / shell history). From a pipe/stdin when non-interactive
    (scripts, tests); via getpass with confirmation on a TTY.
    """
    import getpass
    import sys

    if sys.stdin is not None and not sys.stdin.isatty():
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("Password: ")
        if password != getpass.getpass("Confirm password: "):
            raise SystemExit("passwords do not match")
    if not password:
        raise SystemExit("password must not be empty")
    return password


def cmd_user_add(args: argparse.Namespace) -> int:
    # Argon2id hashing is imported here (not at module load) so the CLI module
    # stays importable without argon2 for the non-auth commands/tests.
    from kerdoos.registry.auth_store import Argon2Hasher

    config_store = SqliteConfigStore(args.config_db)
    try:
        password = _read_password()
        owner_id = uuid.uuid4().hex[:12]
        role = "admin" if args.admin else "user"
        password_hash = Argon2Hasher().hash(password)
        config_store.ensure_owner(
            owner_id, args.name, role=role, email=args.email,
            password_hash=password_hash)
        print(owner_id)
    finally:
        config_store.close()
    return 0


def build_parser_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kerdoos", description="Kerdoos CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="scrape all sources for --owner, print the digest")
    run.add_argument("--owner", required=True, help="owner id to run for")
    run.add_argument("--config-db", default="config.db",
                     help="SQLite ConfigStore path")
    run.add_argument("--db", default="kerdoos.db",
                     help="SQLite state store path (connection-per-operation; "
                          "':memory:' is a distinct in-memory DB per connection "
                          "and loses all data between operations, use a real "
                          "file path even for ephemeral runs)")
    run.add_argument("--dry-run", action="store_true", default=True,
                     help="render digest to stdout, do not send mail (default)")
    run.set_defaults(func=cmd_run)

    digest = sub.add_parser(
        "digest",
        help="run one digest-jobs evaluation tick across ALL owners, then exit "
             "(ADR 0003 Decision 8 -- for external cron when KERDOOS_WORKERS > 1)")
    digest.add_argument("--config-db", default="config.db",
                        help="SQLite ConfigStore path")
    digest.add_argument("--db", default="kerdoos.db",
                        help="SQLite state store path (connection-per-operation; "
                             "':memory:' is a distinct in-memory DB per connection "
                             "and loses all data between operations, use a real "
                             "file path even for ephemeral runs)")
    digest.set_defaults(func=cmd_digest)

    config = sub.add_parser("config", help="manage config.db")
    config_sub = config.add_subparsers(dest="config_command", required=True)

    imp = config_sub.add_parser("import", help="upsert sites.yaml/products.yaml into config.db")
    imp.add_argument("--config-dir", default="config",
                     help="directory holding sites.yaml + products.yaml")
    imp.add_argument("--config-db", default="config.db")
    imp.add_argument("--db", default="kerdoos.db")
    imp.add_argument("--owner", default=None,
                     help="also import products.yaml sources for this owner")
    imp.set_defaults(func=cmd_config_import)

    exp = config_sub.add_parser("export", help="write config.db back to sites.yaml/products.yaml")
    exp.add_argument("--config-dir", default="config")
    exp.add_argument("--config-db", default="config.db")
    exp.add_argument("--owner", default=None,
                     help="also export this owner's products/sources")
    exp.set_defaults(func=cmd_config_export)

    user = sub.add_parser("user", help="manage owners")
    user_sub = user.add_subparsers(dest="user_command", required=True)

    bootstrap = user_sub.add_parser("bootstrap", help="create a minimal owner row (no auth)")
    bootstrap.add_argument("--name", required=True)
    bootstrap.add_argument("--config-db", default="config.db")
    bootstrap.add_argument("--admin", action="store_true", default=False)
    bootstrap.set_defaults(func=cmd_user_bootstrap)

    add = user_sub.add_parser(
        "add", help="create an owner with a password (prompt/stdin, never an arg)")
    add.add_argument("--name", required=True, help="username / login handle (unique)")
    add.add_argument("--email", default=None, help="optional; omit for WebUI-only")
    add.add_argument("--config-db", default="config.db")
    add.add_argument("--admin", action="store_true", default=False)
    add.set_defaults(func=cmd_user_add)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser_cli()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
