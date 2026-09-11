"""CLI resilience: one failing source never aborts the run nor the digest.

Invariants #3 (three-valued state) + #8 (single aggregated digest). The failing
source is simulated at the scrape level (monkeypatched), so the test is hermetic
(no network): router.select / build_parser run for real but never touch the net.

Phase 1: `run` reads from config.db, not YAML directly (invariant #9 -- the
CLI is a thin AppService wrapper), so this test first goes through
`config import` to seed a fresh config.db, mirroring real CLI usage.
"""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from datetime import datetime, timezone

from autolycos.router import StaticRouter

from kerdoos.core.app.services import (
    AppService, DigestJobSpec, Principal, ProductSpec)
from kerdoos.core.domain import Availability, ScrapeStatus
from kerdoos.interfaces.cli import main as cli
from kerdoos.parsers.factory import build_parser
from kerdoos.parsers.ports import ParserSpec
from kerdoos.persistence.ports import ScrapeRecord
from kerdoos.persistence.sqlite_store import SqliteStateStore
from kerdoos.registry.domain_policy import CatalogueDomainPolicy
from kerdoos.registry.ports import SiteConfig
from kerdoos.registry.sqlite_store import SqliteConfigStore

_SITES = """\
sites:
  kabum:
    fetcher: http
    domain: kabum.com.br
    parser:
      kind: statejson
      pix: props.pageProps.product.prices.priceWithDiscount
      card: props.pageProps.product.prices.price
      availability: props.pageProps.product.available
"""

_PRODUCTS = """\
products:
  - id: aw3225qf
    sources:
      - site: kabum
        url: https://www.kabum.com.br/produto/1/a
      - site: kabum
        url: https://www.kabum.com.br/produto/2/b
"""


def _fake_scrape(fetcher, parser, store, owner, source_id, url, *, now=None):
    if "/1/" in url:
        raise RuntimeError("simulated adapter blowup")
    return ScrapeRecord(
        source_id=source_id, ts=now, status=ScrapeStatus.OK,
        price_pix_cents=755800, price_card_cents=755800, currency="BRL",
        availability=Availability.IN_STOCK, method="http", error=None,
    )


class CliResilienceTest(unittest.TestCase):
    def test_one_failing_source_does_not_kill_run_or_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            config_dir = d / "config"
            config_dir.mkdir()
            (config_dir / "sites.yaml").write_text(_SITES, encoding="utf-8")
            (config_dir / "products.yaml").write_text(_PRODUCTS, encoding="utf-8")
            config_db = d / "config.db"
            state_db = d / "state.db"

            import_args = cli.build_parser_cli().parse_args([
                "config", "import",
                "--config-dir", str(config_dir),
                "--config-db", str(config_db),
                "--db", str(state_db),
                "--owner", "owner1",
            ])
            self.assertEqual(cli.cmd_config_import(import_args), 0)

            run_args = cli.build_parser_cli().parse_args([
                "run", "--owner", "owner1",
                "--config-db", str(config_db), "--db", str(state_db)])

            buf = io.StringIO()
            with mock.patch(
                "kerdoos.core.app.services.scrape_and_record", _fake_scrape
            ):
                with contextlib.redirect_stdout(buf):
                    rc = cli.cmd_run(run_args)

        self.assertEqual(rc, 0)
        out = buf.getvalue()
        # Single aggregated digest covering BOTH sources despite one failing.
        self.assertEqual(out.count("Kerdoos daily digest"), 1)
        self.assertIn("sources: 2", out)
        self.assertIn("simulated adapter blowup", out)   # failed source degraded
        self.assertIn("ok=1", out)                        # good source survived
        self.assertIn("indeterminate=1", out)


_DIGEST_SITE = SiteConfig(
    name="kabum", fetcher="http", domain="kabum.com.br",
    parser=ParserSpec(kind="statejson", pix="a", card="b", availability="c"),
)


class CliDigestTest(unittest.TestCase):
    """`kerdoos digest` (ADR 0003 Decision 8): one evaluate_tick, then exit.

    Seeds a FRESH scrape history so Plan A finds nothing stale to scrape --
    keeps this test hermetic (no network) without monkeypatching the
    scraper, unlike CliResilienceTest above.
    """

    def test_one_tick_notifies_and_prints_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            config_db = d / "config.db"
            state_db = d / "state.db"

            config_store = SqliteConfigStore(config_db)
            state_store = SqliteStateStore(state_db)
            domain_policy = CatalogueDomainPolicy(config_store)
            router = StaticRouter(domain_policy)
            service = AppService(
                config_store, state_store, router, domain_policy, build_parser)
            config_store.add_site(_DIGEST_SITE)
            service.add_product("owner1", ProductSpec("p1"))
            source = service.add_source(
                "owner1", "p1", "kabum", "https://www.kabum.com.br/p/1")
            service.create_job(
                Principal(owner_id="owner1"),
                DigestJobSpec(
                    name="job1", frequency_kind="hourly",
                    source_ids=(source.source_id,)))
            state_store.record("owner1", ScrapeRecord(
                source_id=source.source_id,
                ts=datetime.now(timezone.utc).isoformat(),
                status=ScrapeStatus.OK, price_pix_cents=100,
                price_card_cents=110, currency="BRL",
                availability=Availability.IN_STOCK, method="http", error=None,
            ))
            config_store.close()
            state_store.close()

            digest_args = cli.build_parser_cli().parse_args([
                "digest", "--config-db", str(config_db), "--db", str(state_db)])
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = cli.cmd_digest(digest_args)

        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("scraped_sources=0", out)  # fresh history, no scrape
        self.assertIn("notified_jobs=1", out)
        self.assertIn("skipped_jobs=0", out)
        self.assertIn("errors=0", out)


class CliStateDbDefaultTest(unittest.TestCase):
    """Card 1af8b18b: --db defaults to KERDOOS_STATE_DB when set, so a
    cron-scheduled `kerdoos digest` without --db shares the same state.db
    (and BrowserGate lock directory) as the WebUI. Read at
    build_parser_cli() CALL time (not module import), matching
    config.get_settings()'s own read-at-call discipline -- no reload
    needed, just set/unset the env var before calling build_parser_cli()."""

    def setUp(self) -> None:
        self._saved_state_db = os.environ.pop("KERDOOS_STATE_DB", None)
        self._saved_config_db = os.environ.pop("KERDOOS_CONFIG_DB", None)

    def tearDown(self) -> None:
        for var, saved in (
            ("KERDOOS_STATE_DB", self._saved_state_db),
            ("KERDOOS_CONFIG_DB", self._saved_config_db),
        ):
            if saved is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = saved

    def test_db_defaults_to_state_db_env_var_when_set(self) -> None:
        os.environ["KERDOOS_STATE_DB"] = "/data/state.db"
        parser = cli.build_parser_cli()
        self.assertEqual(
            parser.parse_args(["run", "--owner", "o1"]).db, "/data/state.db")
        self.assertEqual(parser.parse_args(["digest"]).db, "/data/state.db")
        self.assertEqual(
            parser.parse_args(["config", "import"]).db, "/data/state.db")

    def test_db_defaults_to_literal_when_state_db_unset(self) -> None:
        parser = cli.build_parser_cli()
        self.assertEqual(
            parser.parse_args(["run", "--owner", "o1"]).db, "kerdoos.db")

    def test_config_db_defaults_to_config_db_env_var_when_set(self) -> None:
        # Gate 1af8b18b MAJOR: the Dockerfile cron (`kerdoos digest`
        # without --config-db) must resolve to /data/config.db, not the
        # WORKDIR-relative literal -- otherwise it silently finds zero
        # digest jobs.
        os.environ["KERDOOS_CONFIG_DB"] = "/data/config.db"
        parser = cli.build_parser_cli()
        self.assertEqual(
            parser.parse_args(["run", "--owner", "o1"]).config_db,
            "/data/config.db")
        self.assertEqual(
            parser.parse_args(["digest"]).config_db, "/data/config.db")
        self.assertEqual(
            parser.parse_args(["config", "import"]).config_db,
            "/data/config.db")
        self.assertEqual(
            parser.parse_args(["config", "export"]).config_db,
            "/data/config.db")
        self.assertEqual(
            parser.parse_args(["user", "bootstrap", "--name", "a"]).config_db,
            "/data/config.db")
        self.assertEqual(
            parser.parse_args(["user", "add", "--name", "a"]).config_db,
            "/data/config.db")

    def test_config_db_defaults_to_literal_when_unset(self) -> None:
        parser = cli.build_parser_cli()
        self.assertEqual(
            parser.parse_args(["run", "--owner", "o1"]).config_db,
            "config.db")


if __name__ == "__main__":
    unittest.main()
