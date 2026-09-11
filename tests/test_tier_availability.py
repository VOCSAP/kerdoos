"""Deployment-mismatch guard for an unavailable fetcher tier (card 3aeb8a19).

A site's configured fetcher tier (SiteConfig.fetcher) can require an optional
dependency not installed on THIS deployment image (e.g. a `browser`/`uc` site
on a `slim` build). Before this fix, that surfaced only at the first scrape as
a ModuleNotFoundError, caught by services.py's broad per-source except and
replayed forever as ScrapeStatus.INDETERMINATE. This file exercises the three
guards that replace that: autolycos.router.tier_available (detection),
AppService.add_source (reject at write time), AppService.run_now (skip at
scrape time, zero records) -- plus the cross-owner read and the boot-time log
that make the condition operator-visible.
"""

from __future__ import annotations

import logging
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from autolycos import router as router_mod
from autolycos.ports import FetchResult
from autolycos.router import StaticRouter, tier_available

from kerdoos.core.app.services import AppService, ProductSpec
from kerdoos.core.domain import Availability, Extract, ScrapeStatus
from kerdoos.interfaces.boot_checks import log_unavailable_fetcher_tiers
from kerdoos.parsers.factory import build_parser
from kerdoos.parsers.ports import ParserSpec
from kerdoos.persistence.sqlite_store import SqliteStateStore
from kerdoos.registry.domain_policy import CatalogueDomainPolicy
from kerdoos.registry.errors import FetcherTierUnavailableError
from kerdoos.registry.ports import SiteConfig
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

    def test_unknown_tier_name_is_available(self) -> None:
        # Scoped to "tier exists but this image lacks its module" -- an
        # unknown tier name is select()'s UnknownFetcherError concern, not
        # this check's (a config typo must not be swallowed here).
        self.assertTrue(tier_available("not-a-real-tier"))

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

    def test_tier_restored_produces_a_normal_record_no_fabricated_delta(self) -> None:
        # While unavailable: zero records, zero history -- nothing to read as
        # a stock-status transition (invariant #3).
        with mock.patch.object(
            self.router, "select", return_value=_FakeFetcher(),
        ), mock.patch.object(
            self.service, "_parser_factory", _fake_parser_factory,
        ), _tier_forced_missing("uc"):
            self.service.run_now("owner1")
        bad_id = self._source_id("bad")
        self.assertEqual(self.service.get_history("owner1", bad_id), [])

        # Tier available again (e.g. redeployed as `autonomous`): the next
        # real scrape is a normal OK record, not a synthesized transition.
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


if __name__ == "__main__":
    unittest.main()
