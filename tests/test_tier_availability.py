"""Deployment-mismatch guard for an unavailable fetcher tier (card 3aeb8a19).

Exercises tier_available/known_tiers detection, the add_source/add_site/
run_now guards, the cross-owner read, and the WebUI/CLI boot-time log.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from autolycos import router as router_mod
from autolycos.ports import FetchResult
from autolycos.router import StaticRouter, tier_available

from kerdoos.core.app.services import AppService, Principal, ProductSpec
from kerdoos.core.domain import Availability, Extract, ScrapeStatus
from kerdoos.interfaces.boot_checks import log_unavailable_fetcher_tiers
from kerdoos.interfaces.cli import main as cli
from kerdoos.parsers.factory import build_parser
from kerdoos.parsers.ports import ParserSpec
from kerdoos.persistence.sqlite_store import SqliteStateStore
from kerdoos.registry.domain_policy import CatalogueDomainPolicy
from kerdoos.registry.errors import ConfigError, FetcherTierUnavailableError
from kerdoos.registry.ports import Product, ProductSource, SiteConfig
from kerdoos.registry.sqlite_store import SqliteConfigStore

_HTTP_SITE = SiteConfig(
    name="kabum", fetcher="http", domain="kabum.com.br",
    parser=ParserSpec(kind="statejson", pix="a", card="b", availability="c"),
)
_UC_SITE = SiteConfig(
    name="magalu", fetcher="uc", domain="magazineluiza.com.br",
    parser=ParserSpec(kind="statejson", pix="a", card="b", availability="c"),
)


@contextmanager
def _tier_forced_missing(tier: str):
    """Point `tier`'s optional module at a name that cannot possibly resolve,
    so tier_available(tier) is False regardless of what is actually installed
    in the dev/CI venv -- the test must not depend on patchright/seleniumbase/
    curl_cffi being absent for real."""
    with mock.patch.dict(
        router_mod._TIER_MODULES,
        {tier: "kerdoos_test_definitely_not_a_real_module_xyz"},
    ):
        yield


@contextmanager
def _tier_forced_available(tier: str):
    """The inverse of _tier_forced_missing -- used to seed a source against a
    tier this dev/CI venv genuinely lacks (curl_cffi/patchright/seleniumbase
    are not installed here), simulating a source added while the tier WAS
    available (e.g. on an `autonomous` image) before a later guard/redeploy
    makes it unavailable."""
    with mock.patch.dict(router_mod._TIER_MODULES, {tier: None}):
        yield


class TierAvailableHelperTest(unittest.TestCase):
    def test_http_is_always_available(self) -> None:
        self.assertTrue(tier_available("http"))

    def test_unknown_tier_name_is_unavailable(self) -> None:
        # F1: fail-closed on ANY unknown name, not just a known tier missing
        # its module -- a typo that reached config.db through a door with no
        # known_tiers() validation of its own (bulk `config import`, a future
        # MCP door) must still be rejected/skipped, not swallowed as "fine".
        self.assertFalse(tier_available("not-a-real-tier"))

    def test_missing_module_is_unavailable(self) -> None:
        with _tier_forced_missing("uc"):
            self.assertFalse(tier_available("uc"))

    def test_does_not_import_the_optional_module(self) -> None:
        # find_spec must LOCATE, never EXECUTE -- a slim image never pays the
        # cost of an unavailable tier's import.
        with mock.patch(
            "autolycos.router.importlib.util.find_spec",
            wraps=router_mod.importlib.util.find_spec,
        ) as spy:
            tier_available("tls")
            spy.assert_called_once_with("curl_cffi")


class _FakeFetcher:
    def fetch(self, url: str) -> FetchResult:
        return FetchResult(html="<html></html>", status=200, method="http")


class _FakeParser:
    def extract(self, html: str) -> Extract:
        return Extract(
            price_pix_cents=100, price_card_cents=110, currency="BRL",
            availability=Availability.IN_STOCK,
        )


def _fake_parser_factory(spec: ParserSpec) -> _FakeParser:
    return _FakeParser()


class _AppServiceTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        d = Path(self._tmp.name)
        self.config = SqliteConfigStore(d / "config.db")
        self.state = SqliteStateStore(d / "state.db")
        self.domain_policy = CatalogueDomainPolicy(self.config)
        self.router = StaticRouter(self.domain_policy)
        self.service = AppService(
            self.config, self.state, self.router, self.domain_policy,
            build_parser)
        self.config.add_site(_HTTP_SITE)
        self.config.add_site(_UC_SITE)

    def tearDown(self) -> None:
        self.config.close()
        self.state.close()
        self._tmp.cleanup()


class AddSourceGuardTest(_AppServiceTestBase):
    def test_unavailable_tier_is_rejected_before_persist(self) -> None:
        self.service.add_product("owner1", ProductSpec("tv55"))
        with _tier_forced_missing("uc"):
            with self.assertRaises(FetcherTierUnavailableError):
                self.service.add_source(
                    "owner1", "tv55", "magalu",
                    "https://www.magazineluiza.com.br/p/1")
        # Rejected BEFORE any row was written.
        self.assertEqual(
            len(self.service.list_config("owner1").products[0].sources), 0)

    def test_available_tier_is_unaffected(self) -> None:
        self.service.add_product("owner1", ProductSpec("aw3225qf"))
        source = self.service.add_source(
            "owner1", "aw3225qf", "kabum",
            "https://www.kabum.com.br/produto/1/a")
        self.assertEqual(source.site, "kabum")


class AddSiteUnknownTierTest(_AppServiceTestBase):
    def test_typo_d_tier_name_is_rejected(self) -> None:
        # A typo ("uC") is a different defect than a genuinely unavailable
        # KNOWN tier -- it would otherwise fall through to select()'s
        # UnknownFetcherError at every scrape, forever (card 3aeb8a19 MAJOR).
        typo_site = SiteConfig(
            name="typo-site", fetcher="uC", domain="example.com.br",
            parser=ParserSpec(kind="statejson", pix="a", card="b",
                              availability="c"),
        )
        with self.assertRaises(ConfigError):
            self.service.add_site(
                Principal(owner_id="root", role="admin"), typo_site)
        self.assertNotIn(
            "typo-site", self.service.list_config("owner1").sites)

    def test_known_tier_is_unaffected(self) -> None:
        new_site = SiteConfig(
            name="terabyte", fetcher="tls", domain="terabyteshop.com.br",
            parser=ParserSpec(kind="dom", pix="a", card="b", availability="c"),
        )
        self.service.add_site(Principal(owner_id="root", role="admin"), new_site)
        self.assertIn("terabyte", self.service.list_config("owner1").sites)


class RunNowSkipTest(_AppServiceTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.service.add_product("owner1", ProductSpec("good"))
        self.service.add_source(
            "owner1", "good", "kabum", "https://www.kabum.com.br/p/1")
        # Add the magalu source WHILE the tier is available, to simulate a
        # pre-existing source from before a redeploy to a slim image (or
        # before this guard shipped) -- run_now's skip is the only rampart
        # left for this case.
        self.service.add_product("owner1", ProductSpec("bad"))
        with _tier_forced_available("uc"):
            self.service.add_source(
                "owner1", "bad", "magalu",
                "https://www.magazineluiza.com.br/p/2")

    def _source_id(self, product_key: str) -> str:
        registry = self.service.list_config("owner1")
        product = next(p for p in registry.products if p.id == product_key)
        return product.sources[0].source_id

    def test_source_with_unavailable_tier_writes_no_record(self) -> None:
        with mock.patch.object(
            self.router, "select", return_value=_FakeFetcher(),
        ), mock.patch.object(
            self.service, "_parser_factory", _fake_parser_factory,
        ), _tier_forced_missing("uc"):
            result = self.service.run_now("owner1")
        source_ids = {r.source_id for r in result.records}
        good_id = self._source_id("good")
        bad_id = self._source_id("bad")
        self.assertIn(good_id, source_ids)
        self.assertNotIn(bad_id, source_ids)
        self.assertEqual(len(result.records), 1)
        self.assertEqual(self.service.get_history("owner1", bad_id), [])

    def test_tier_available_is_rechecked_each_run_not_cached(self) -> None:
        # No delta/diff engine exists in this codebase (nothing compares
        # this run's record to a previous one) -- what this actually
        # protects against is tier_available's result being memoized across
        # run_now calls, which would keep skipping a source forever even
        # after a redeploy makes its tier available again.
        with mock.patch.object(
            self.router, "select", return_value=_FakeFetcher(),
        ), mock.patch.object(
            self.service, "_parser_factory", _fake_parser_factory,
        ), _tier_forced_missing("uc"):
            self.service.run_now("owner1")
        bad_id = self._source_id("bad")
        self.assertEqual(self.service.get_history("owner1", bad_id), [])

        # Tier available again (e.g. redeployed as `autonomous`): the next
        # run_now must re-evaluate tier_available, not reuse a stale result.
        with mock.patch.object(self.router, "select", return_value=_FakeFetcher()), \
             mock.patch.object(self.service, "_parser_factory", _fake_parser_factory), \
             _tier_forced_available("uc"):
            self.service.run_now("owner1")
        history = self.service.get_history("owner1", bad_id)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].status, ScrapeStatus.OK)
        self.assertEqual(history[0].availability, Availability.IN_STOCK)


class ListReferencedFetcherTiersTest(_AppServiceTestBase):
    def test_returns_distinct_tiers_no_owner_identity(self) -> None:
        self.service.add_product("owner1", ProductSpec("p1"))
        self.service.add_source(
            "owner1", "p1", "kabum", "https://www.kabum.com.br/p/1")
        self.service.add_product("owner2", ProductSpec("p2"))
        with _tier_forced_available("uc"):
            self.service.add_source(
                "owner2", "p2", "magalu",
                "https://www.magazineluiza.com.br/p/2")

        tiers = self.config.list_referenced_fetcher_tiers()
        self.assertEqual(tiers, frozenset({"http", "uc"}))
        # Owner-anonymous: no owner id string leaks into the tier names.
        self.assertNotIn("owner1", tiers)
        self.assertNotIn("owner2", tiers)

    def test_a_site_with_zero_sources_is_not_referenced(self) -> None:
        # _UC_SITE is catalogued (add_site in setUp) but nobody has added a
        # source against it yet -- it must not count.
        self.assertEqual(
            self.config.list_referenced_fetcher_tiers(), frozenset())


class BootLogTest(_AppServiceTestBase):
    def test_logs_once_when_a_referenced_tier_is_missing(self) -> None:
        self.service.add_product("owner1", ProductSpec("p1"))
        self.service.add_product("owner2", ProductSpec("p2"))
        self.service.add_source(
            "owner1", "p1", "kabum", "https://www.kabum.com.br/p/1")
        with _tier_forced_available("uc"):
            self.service.add_source(
                "owner2", "p2", "magalu",
                "https://www.magazineluiza.com.br/p/2")

        with _tier_forced_missing("uc"), \
             self.assertLogs("kerdoos.interfaces.boot_checks", level="ERROR") as cm:
            log_unavailable_fetcher_tiers(self.config)
        self.assertEqual(len(cm.output), 1)
        self.assertIn("uc", cm.output[0])

    def test_does_not_raise_and_logs_nothing_when_all_available(self) -> None:
        self.service.add_product("owner1", ProductSpec("p1"))
        self.service.add_source(
            "owner1", "p1", "kabum", "https://www.kabum.com.br/p/1")
        logger = logging.getLogger("kerdoos.interfaces.boot_checks")
        with mock.patch.object(logger, "error") as spy:
            log_unavailable_fetcher_tiers(self.config)  # must not raise
        spy.assert_not_called()


class _BootWiringTestBase(unittest.TestCase):
    """Seeds a real config.db with a magalu (uc) source, THROUGH AppService
    (not log_unavailable_fetcher_tiers directly), so these tests fail if
    create_app()/cmd_run/cmd_digest stop calling the boot check -- unlike
    BootLogTest above, which only proves the helper itself works."""

    def setUp(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="kerdoos-boot-wiring-")
        self.addCleanup(shutil.rmtree, self._dir, ignore_errors=True)
        self.config_db = os.path.join(self._dir, "config.db")
        self.state_db = os.path.join(self._dir, "state.db")
        config = SqliteConfigStore(self.config_db)
        try:
            config.add_site(SiteConfig(
                name="magalu", fetcher="uc",
                parser=ParserSpec(kind="statejson"),
                domain="magazineluiza.com.br"))
            with _tier_forced_available("uc"):
                service = AppService(
                    config, SqliteStateStore(self.state_db), StaticRouter(
                        CatalogueDomainPolicy(config)),
                    CatalogueDomainPolicy(config), build_parser)
                service.add_product("owner1", ProductSpec("tv55"))
                service.add_source(
                    "owner1", "tv55", "magalu",
                    "https://www.magazineluiza.com.br/p/1")
        finally:
            config.close()


class WebAppBootWiringTest(_BootWiringTestBase):
    def test_create_app_logs_the_unavailable_tier(self) -> None:
        from kerdoos.interfaces.web.app import create_app

        env = {
            "KERDOOS_SESSION_SECRET": "test-session-secret-padded-to-32chars",
            "KERDOOS_CONFIG_DB": self.config_db,
            "KERDOOS_STATE_DB": self.state_db,
            "KERDOOS_COOKIE_SECURE": "false",
        }
        with mock.patch.dict(os.environ, env), _tier_forced_missing("uc"), \
             self.assertLogs(
                "kerdoos.interfaces.boot_checks", level="ERROR") as cm:
            create_app()
        self.assertIn("uc", cm.output[0])


class CliBootWiringTest(_BootWiringTestBase):
    def _args(self, *extra: str):
        return cli.build_parser_cli().parse_args([
            *extra, "--config-db", self.config_db, "--db", self.state_db,
        ])

    def test_cmd_run_logs_the_unavailable_tier(self) -> None:
        with _tier_forced_missing("uc"), self.assertLogs(
            "kerdoos.interfaces.boot_checks", level="ERROR") as cm:
            cli.cmd_run(self._args("run", "--owner", "owner1"))
        self.assertIn("uc", cm.output[0])

    def test_cmd_digest_logs_the_unavailable_tier(self) -> None:
        with _tier_forced_missing("uc"), self.assertLogs(
            "kerdoos.interfaces.boot_checks", level="ERROR") as cm:
            cli.cmd_digest(self._args("digest"))
        self.assertIn("uc", cm.output[0])


class ConfigImportTypoTierTest(unittest.TestCase):
    """F1: `kerdoos config import` bypasses AppService.add_site's
    known_tiers() validation entirely -- cmd_config_import (cli/main.py)
    calls config_store.add_site directly, and yaml_store.py only checks the
    `fetcher` field is present, not that it names a real tier. A typo'd
    fetcher lands in config.db this way; tier_available's fail-closed
    default on an unknown name is the ONE check that still catches it,
    regardless of which door it came through."""

    def setUp(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="kerdoos-import-typo-")
        self.addCleanup(shutil.rmtree, self._dir, ignore_errors=True)
        config_dir = Path(self._dir) / "config"
        config_dir.mkdir()
        (config_dir / "sites.yaml").write_text(
            "sites:\n"
            "  typo:\n"
            "    fetcher: uC\n"
            "    domain: example.com.br\n"
            "    parser:\n"
            "      kind: statejson\n"
            "      pix: a\n"
            "      card: b\n"
            "      availability: c\n",
            encoding="utf-8",
        )
        self.config_db = os.path.join(self._dir, "config.db")
        self.state_db = os.path.join(self._dir, "state.db")
        args = cli.build_parser_cli().parse_args([
            "config", "import", "--config-dir", str(config_dir),
            "--config-db", self.config_db, "--db", self.state_db,
            "--owner", "owner1",
        ])
        self.assertEqual(cli.cmd_config_import(args), 0)

    def test_import_lands_the_typo_unvalidated(self) -> None:
        # Proves the bypass is real: cmd_config_import does not reject it.
        config = SqliteConfigStore(self.config_db)
        try:
            self.assertIn("typo", config.load("owner1").sites)
        finally:
            config.close()

    def test_add_source_against_the_typo_is_rejected(self) -> None:
        config = SqliteConfigStore(self.config_db)
        state = SqliteStateStore(self.state_db)
        try:
            domain_policy = CatalogueDomainPolicy(config)
            service = AppService(
                config, state, StaticRouter(domain_policy), domain_policy,
                build_parser)
            service.add_product("owner1", ProductSpec("p1"))
            with self.assertRaises(FetcherTierUnavailableError):
                service.add_source(
                    "owner1", "p1", "typo", "https://example.com.br/p/1")
        finally:
            config.close()
            state.close()

    def test_boot_log_flags_a_pre_existing_bad_row(self) -> None:
        # Simulates a row that reached product_sources through a door with
        # no known_tiers() validation of its own (direct store write, same
        # shape as the config-import bypass above) -- the boot log must
        # still flag it, not just newly-rejected add_source calls.
        config = SqliteConfigStore(self.config_db)
        try:
            config.add_product("owner1", Product(id="p1"))
            config.add_source("owner1", ProductSource(
                source_id="owner1:p1:typo:deadbeef", product_id="p1",
                site="typo", url="https://example.com.br/p/1"))
            with self.assertLogs(
                "kerdoos.interfaces.boot_checks", level="ERROR") as cm:
                log_unavailable_fetcher_tiers(config)
        finally:
            config.close()
        self.assertIn("uC", cm.output[0])


if __name__ == "__main__":
    unittest.main()
