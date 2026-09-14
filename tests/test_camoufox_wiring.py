"""Tier wiring in kerdoos: every tier setting reaches the router each REAL
composition root builds, the boot diagnostic judges the install the router
will launch, and the shipped catalogue names known tiers.
"""

from __future__ import annotations

import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from autolycos.browser_gate import BrowserGate
from autolycos.router import StaticRouter, known_tiers
from autolycos.safety import DomainPolicy

from kerdoos.config import get_settings
from kerdoos.interfaces.boot_checks import log_unavailable_fetcher_tiers
from kerdoos.interfaces.cli import main as cli
from kerdoos.interfaces.routing import build_static_router
from kerdoos.parsers.ports import ParserSpec
from kerdoos.registry.ports import Product, ProductSource, SiteConfig
from kerdoos.registry.sqlite_store import SqliteConfigStore
from kerdoos.registry.yaml_store import parse_sites_yaml

_REPO_ROOT = Path(__file__).resolve().parents[1]

# Every tier setting at a non-default value, and no two alike, so a root that
# drops one or crosses two apart cannot match the shared builder.
_ALL_TIER_ENV = {
    "KERDOOS_UC_LAUNCH_TIMEOUT_SECONDS": "31",
    "KERDOOS_BROWSER_LAUNCH_TIMEOUT_SECONDS": "19",
    "KERDOOS_UC_ORPHAN_SWEEP_DELAY_SECONDS": "6",
    "KERDOOS_BROWSER_FETCH_TIMEOUT_SECONDS": "91",
    "KERDOOS_BROWSER_MAX_ABANDONED_FETCHES": "4",
    "KERDOOS_UC_FETCH_TIMEOUT_SECONDS": "61",
    "KERDOOS_CAMOUFOX_LAUNCH_TIMEOUT_SECONDS": "11",
    "KERDOOS_CAMOUFOX_NAV_TIMEOUT_SECONDS": "22",
    "KERDOOS_CAMOUFOX_FETCH_TIMEOUT_SECONDS": "66",
    "KERDOOS_CAMOUFOX_MAX_ABANDONED_FETCHES": "3",
}


def _builder_router() -> StaticRouter:
    return build_static_router(
        DomainPolicy(frozenset()), BrowserGate(max_concurrent=1),
        get_settings())


class _WiringAssertions(unittest.TestCase):
    def assert_wired_like_the_builder(self, router: StaticRouter) -> None:
        """Compares the settings a root handed its router with those the
        shared builder hands one, under _ALL_TIER_ENV: any tier setting added
        later is covered without touching this test."""
        self.assertIsInstance(router, StaticRouter)
        expected = _builder_router()
        self.assertEqual(router._extra_kwargs, expected._extra_kwargs)
        self.assertEqual(router._readiness_kwargs, expected._readiness_kwargs)


class SharedRouterBuilderTest(unittest.TestCase):
    def test_every_tier_setting_is_forwarded(self) -> None:
        with mock.patch.dict(os.environ, _ALL_TIER_ENV):
            router = _builder_router()
        camoufox = router.select("camoufox")
        self.assertEqual(
            (camoufox._launch_timeout_seconds, camoufox._nav_timeout_seconds,
             camoufox._fetch_timeout_seconds, camoufox._max_abandoned_fetches),
            (11.0, 22.0, 66.0, 3))
        self.assertEqual(router.select("uc")._fetch_timeout_seconds, 61.0)
        self.assertEqual(
            router.select("browser")._fetch_timeout_seconds, 91.0)

    def test_the_test_env_sets_every_setting_the_builder_forwards(self) -> None:
        with mock.patch.dict(os.environ, _ALL_TIER_ENV):
            router = _builder_router()
        forwarded = sum(len(kwargs) for kwargs in router._extra_kwargs.values())
        self.assertEqual(forwarded, len(_ALL_TIER_ENV))


class _TempDbs(_WiringAssertions):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.config_db = str(Path(tmp.name) / "config.db")
        self.state_db = str(Path(tmp.name) / "state.db")


class _Captured(Exception):
    """Stops a composition root right after it hands its router over."""


class CliRunRootTest(_TempDbs):
    def test_app_service_router_is_wired_like_the_builder(self) -> None:
        with mock.patch.dict(os.environ, _ALL_TIER_ENV):
            composition = cli._build_app_service(
                self.config_db, self.state_db, settings=get_settings())
            try:
                self.assertIs(composition.router, composition.service._router)
                self.assert_wired_like_the_builder(composition.router)
            finally:
                composition.close()

    def test_boot_check_receives_the_run_router(self) -> None:
        args = cli.build_parser_cli().parse_args([
            "run", "--owner", "owner1",
            "--config-db", self.config_db, "--db", self.state_db])
        with mock.patch.dict(os.environ, _ALL_TIER_ENV), mock.patch.object(
            cli, "log_unavailable_fetcher_tiers", side_effect=_Captured,
        ) as boot_check:
            with self.assertRaises(_Captured):
                cli.cmd_run(args)
            _, router = boot_check.call_args.args
            self.assert_wired_like_the_builder(router)


class CliDigestRootTest(_TempDbs):
    def test_evaluation_tick_and_boot_check_share_a_router_wired_like_the_builder(
        self,
    ) -> None:
        args = cli.build_parser_cli().parse_args([
            "digest", "--config-db", self.config_db, "--db", self.state_db])
        summary = types.SimpleNamespace(
            scraped_sources=0, notified_jobs=0, skipped_jobs=0, errors=0)
        with mock.patch.dict(os.environ, _ALL_TIER_ENV), mock.patch.object(
            cli, "evaluate_tick", new=mock.AsyncMock(return_value=summary),
        ) as tick, mock.patch.object(
            cli, "log_unavailable_fetcher_tiers",
            wraps=cli.log_unavailable_fetcher_tiers,
        ) as boot_check:
            self.assertEqual(cli.cmd_digest(args), 0)
            tick_router = tick.call_args.kwargs["router"]
            self.assertIs(boot_check.call_args.args[1], tick_router)
            self.assert_wired_like_the_builder(tick_router)

    def test_one_settings_read_serves_the_whole_command(self) -> None:
        args = cli.build_parser_cli().parse_args([
            "digest", "--config-db", self.config_db, "--db", self.state_db])
        summary = types.SimpleNamespace(
            scraped_sources=0, notified_jobs=0, skipped_jobs=0, errors=0)
        with mock.patch.dict(os.environ, _ALL_TIER_ENV), mock.patch.object(
            cli, "evaluate_tick", new=mock.AsyncMock(return_value=summary),
        ), mock.patch.object(
            cli, "get_settings", wraps=cli.get_settings,
        ) as settings_read:
            cli.cmd_digest(args)
        self.assertEqual(settings_read.call_count, 1)


class WebRootTest(_TempDbs):
    def _env(self) -> dict:
        return {
            **_ALL_TIER_ENV,
            "KERDOOS_SESSION_SECRET": "test-session-secret-padded-to-32chars",
            "KERDOOS_CONFIG_DB": self.config_db,
            "KERDOOS_STATE_DB": self.state_db,
            "KERDOOS_COOKIE_SECURE": "false",
        }

    def test_app_service_router_is_wired_like_the_builder(self) -> None:
        from kerdoos.interfaces.web.app import create_app

        with mock.patch.dict(os.environ, self._env()):
            app = create_app()
            self.assert_wired_like_the_builder(app.state.app_service._router)

    def test_boot_check_receives_the_app_router(self) -> None:
        from kerdoos.interfaces.web import app as web_app

        with mock.patch.dict(os.environ, self._env()), mock.patch.object(
            web_app, "log_unavailable_fetcher_tiers",
        ) as boot_check:
            app = web_app.create_app()
        _, router = boot_check.call_args.args
        self.assertIs(router, app.state.app_service._router)


class _StubRouter:
    def __init__(self, available: dict[str, bool]) -> None:
        self._available = available
        self.asked: list[str] = []

    def tier_available(self, fetcher_name: str) -> bool:
        self.asked.append(fetcher_name)
        return self._available[fetcher_name]


class BootCheckJudgesTheRouterTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.config = SqliteConfigStore(str(Path(tmp.name) / "config.db"))
        self.addCleanup(self.config.close)
        self._seed("kabum", "http", "kabum.com.br")
        self._seed("magalu", "camoufox", "magazineluiza.com.br")

    def _seed(self, site: str, fetcher: str, domain: str) -> None:
        self.config.add_site(SiteConfig(
            name=site, fetcher=fetcher, domain=domain,
            parser=ParserSpec(kind="statejson", pix="a", card="b",
                              availability="c")))
        self.config.add_product("owner1", Product(id=f"p-{site}"))
        self.config.add_source("owner1", ProductSource(
            source_id=f"owner1:p-{site}:{site}:x", product_id=f"p-{site}",
            site=site, url=f"https://www.{domain}/p/1"))

    def test_a_tier_the_router_refuses_is_reported(self) -> None:
        # The module-level check would call http always available: only the
        # router can make this line appear.
        router = _StubRouter({"http": False, "camoufox": True})
        with self.assertLogs("kerdoos.interfaces.boot_checks", "ERROR") as cm:
            log_unavailable_fetcher_tiers(self.config, router)
        self.assertIn("http", cm.output[0])
        self.assertNotIn("camoufox", cm.output[0])

    def test_a_tier_the_router_accepts_is_not_reported(self) -> None:
        router = _StubRouter({"http": True, "camoufox": True})
        with mock.patch(
            "kerdoos.interfaces.boot_checks.logger.error") as error:
            log_unavailable_fetcher_tiers(self.config, router)
        error.assert_not_called()
        self.assertEqual(sorted(router.asked), ["camoufox", "http"])


class ShippedCatalogueTest(unittest.TestCase):
    def setUp(self) -> None:
        self.sites = parse_sites_yaml(_REPO_ROOT / "config" / "sites.yaml")

    def test_every_site_names_a_known_tier(self) -> None:
        for name, site in self.sites.items():
            with self.subTest(site=name):
                self.assertIn(site.fetcher, known_tiers())

    def test_magalu_uses_camoufox_and_mercadolivre_uses_browser(self) -> None:
        self.assertEqual(self.sites["magalu"].fetcher, "camoufox")
        self.assertEqual(self.sites["mercadolivre"].fetcher, "browser")


if __name__ == "__main__":
    unittest.main()
