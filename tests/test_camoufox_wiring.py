"""Camoufox tier wiring in kerdoos: KERDOOS_CAMOUFOX_* settings reach the
fetcher each REAL composition root builds, the boot diagnostic judges the
install the router will launch, and the shipped catalogue names known tiers.
"""

from __future__ import annotations

import os
import tempfile
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

_CAMOUFOX_ENV = {
    "KERDOOS_CAMOUFOX_LAUNCH_TIMEOUT_SECONDS": "11",
    "KERDOOS_CAMOUFOX_NAV_TIMEOUT_SECONDS": "22",
    "KERDOOS_CAMOUFOX_FETCH_TIMEOUT_SECONDS": "66",
    "KERDOOS_CAMOUFOX_MAX_ABANDONED_FETCHES": "3",
}
_EXPECTED = (11.0, 22.0, 66.0, 3)


def _camoufox_settings_of(router) -> tuple:  # noqa: ANN001
    fetcher = router.select("camoufox")
    return (fetcher._launch_timeout_seconds, fetcher._nav_timeout_seconds,
            fetcher._fetch_timeout_seconds, fetcher._max_abandoned_fetches)


class _Captured(Exception):
    """Stops a composition root right after it hands its router over."""


class SharedRouterBuilderTest(unittest.TestCase):
    def test_every_tier_setting_is_forwarded(self) -> None:
        env = {**_CAMOUFOX_ENV,
               "KERDOOS_UC_FETCH_TIMEOUT_SECONDS": "60",
               "KERDOOS_BROWSER_FETCH_TIMEOUT_SECONDS": "91"}
        with mock.patch.dict(os.environ, env):
            router = build_static_router(
                DomainPolicy(frozenset()), BrowserGate(max_concurrent=1),
                get_settings())
        self.assertEqual(_camoufox_settings_of(router), _EXPECTED)
        self.assertEqual(router.select("uc")._fetch_timeout_seconds, 60.0)
        self.assertEqual(
            router.select("browser")._fetch_timeout_seconds, 91.0)


class _TempDbs(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.config_db = str(Path(tmp.name) / "config.db")
        self.state_db = str(Path(tmp.name) / "state.db")


class CliRunRootTest(_TempDbs):
    def test_settings_reach_the_camoufox_fetcher(self) -> None:
        with mock.patch.dict(os.environ, _CAMOUFOX_ENV):
            service, config_store, state_store, router = cli._build_app_service(
                self.config_db, self.state_db)
        try:
            self.assertEqual(_camoufox_settings_of(router), _EXPECTED)
            self.assertIs(router, service._router)
        finally:
            config_store.close()
            state_store.close()

    def test_boot_check_receives_the_run_router(self) -> None:
        args = cli.build_parser_cli().parse_args([
            "run", "--owner", "owner1",
            "--config-db", self.config_db, "--db", self.state_db])
        with mock.patch.dict(os.environ, _CAMOUFOX_ENV), mock.patch.object(
            cli, "log_unavailable_fetcher_tiers", side_effect=_Captured,
        ) as boot_check:
            with self.assertRaises(_Captured):
                cli.cmd_run(args)
        _, router = boot_check.call_args.args
        self.assertIsInstance(router, StaticRouter)
        self.assertEqual(_camoufox_settings_of(router), _EXPECTED)


class CliDigestRootTest(_TempDbs):
    def test_tick_router_carries_the_settings(self) -> None:
        args = cli.build_parser_cli().parse_args([
            "digest", "--config-db", self.config_db, "--db", self.state_db])
        with mock.patch.dict(os.environ, _CAMOUFOX_ENV), mock.patch.object(
            cli, "log_unavailable_fetcher_tiers", side_effect=_Captured,
        ) as boot_check:
            with self.assertRaises(_Captured):
                cli.cmd_digest(args)
        _, router = boot_check.call_args.args
        self.assertIsInstance(router, StaticRouter)
        self.assertEqual(_camoufox_settings_of(router), _EXPECTED)


class WebRootTest(_TempDbs):
    def _env(self) -> dict:
        return {
            **_CAMOUFOX_ENV,
            "KERDOOS_SESSION_SECRET": "test-session-secret-padded-to-32chars",
            "KERDOOS_CONFIG_DB": self.config_db,
            "KERDOOS_STATE_DB": self.state_db,
            "KERDOOS_COOKIE_SECURE": "false",
        }

    def test_settings_reach_the_camoufox_fetcher(self) -> None:
        from kerdoos.interfaces.web.app import create_app

        with mock.patch.dict(os.environ, self._env()):
            app = create_app()
        self.assertEqual(
            _camoufox_settings_of(app.state.app_service._router), _EXPECTED)

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


class BootCheckJudgesTheRouterTest(_TempDbs):
    def setUp(self) -> None:
        super().setUp()
        self.config = SqliteConfigStore(self.config_db)
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

    def test_magalu_and_mercadolivre_use_the_camoufox_tier(self) -> None:
        self.assertEqual(self.sites["magalu"].fetcher, "camoufox")
        self.assertEqual(self.sites["mercadolivre"].fetcher, "camoufox")


if __name__ == "__main__":
    unittest.main()
