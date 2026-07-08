"""AppService tenancy: owner isolation across state + config, admin-only add_site.

Everything in this file exercises the same choke points a WebUI/MCP interface
would eventually go through -- AppService, never the raw stores directly --
so a regression here means a cross-tenant leak at the use-case boundary, not
just at the SQL layer (already covered by test_persistence.py).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from autolycos.router import StaticRouter

from kerdoos.core.app.services import AppService, Principal, ProductSpec
from kerdoos.parsers.factory import build_parser
from kerdoos.parsers.ports import ParserSpec
from kerdoos.persistence.sqlite_store import SqliteStateStore
from kerdoos.registry.domain_policy import CatalogueDomainPolicy
from kerdoos.registry.ports import SiteConfig, make_source_id, validate_product_key
from kerdoos.registry.sqlite_store import SqliteConfigStore
from kerdoos.registry.url_validation import UrlValidationError

_SITE = SiteConfig(
    name="kabum", fetcher="http", domain="kabum.com.br",
    parser=ParserSpec(kind="statejson", pix="a", card="b", availability="c"),
)


class _TenancyTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        d = Path(self._tmp.name)
        self.config = SqliteConfigStore(d / "config.db")
        self.state = SqliteStateStore(d / "state.db")
        # Phase 2a FD1: catalogue-derived, not the static DomainPolicy --
        # this exercises the SAME live-wiring the CLI composition root uses.
        domain_policy = CatalogueDomainPolicy(self.config)
        router = StaticRouter(domain_policy)
        self.service = AppService(
            self.config, self.state, router, domain_policy, build_parser)
        self.config.add_site(_SITE)

    def tearDown(self) -> None:
        self.config.close()
        self.state.close()
        self._tmp.cleanup()


class ConfigTenancyTest(_TenancyTestBase):
    def test_add_product_is_owner_scoped(self) -> None:
        self.service.add_product("owner1", ProductSpec("aw3225qf", name="RTX"))
        registry1 = self.service.list_config("owner1")
        registry2 = self.service.list_config("owner2")
        self.assertEqual(len(registry1.products), 1)
        self.assertEqual(len(registry2.products), 0)

    def test_add_source_owner_scoped_and_source_id_distinct(self) -> None:
        for owner in ("owner1", "owner2"):
            self.service.add_product(owner, ProductSpec("aw3225qf"))
            self.service.add_source(
                owner, "aw3225qf", "kabum",
                "https://www.kabum.com.br/produto/1/a")
        reg1 = self.service.list_config("owner1")
        reg2 = self.service.list_config("owner2")
        id1 = reg1.products[0].sources[0].source_id
        id2 = reg2.products[0].sources[0].source_id
        self.assertNotEqual(id1, id2)

    def test_remove_source_cannot_cross_tenant(self) -> None:
        self.service.add_product("owner1", ProductSpec("aw3225qf"))
        source = self.service.add_source(
            "owner1", "aw3225qf", "kabum",
            "https://www.kabum.com.br/produto/1/a")
        # owner2 cannot remove owner1's source, even knowing its exact id.
        self.service.remove_source("owner2", source.source_id)
        self.assertEqual(
            len(self.service.list_config("owner1").products[0].sources), 1)
        self.service.remove_source("owner1", source.source_id)
        self.assertEqual(
            len(self.service.list_config("owner1").products[0].sources), 0)

    def test_add_source_rejects_unknown_site(self) -> None:
        self.service.add_product("owner1", ProductSpec("aw3225qf"))
        with self.assertRaises(KeyError):
            self.service.add_source(
                "owner1", "aw3225qf", "not-a-site",
                "https://www.kabum.com.br/produto/1/a")

    def test_add_source_rejects_off_allowlist_url(self) -> None:
        self.service.add_product("owner1", ProductSpec("aw3225qf"))
        with self.assertRaises(UrlValidationError):
            self.service.add_source(
                "owner1", "aw3225qf", "kabum", "https://evil.com/x")

    def test_add_source_accepts_new_domain_from_freshly_admin_added_site(
        self,
    ) -> None:
        # Phase 2a FD1: DomainPolicy is derived LIVE from the catalogue
        # (CatalogueDomainPolicy queries ConfigStore.site_domains() on every
        # call), superseding Phase 1's static-allowlist limitation this test
        # used to prove (see git history for the original assertion). An
        # admin-added site's domain must become fetchable in the SAME
        # process, without re-wiring the app -- proving the catalogue is the
        # live source of truth, not a snapshot.
        principal = Principal(owner_id="root", role="admin")
        new_site = SiteConfig(
            name="freshsite", fetcher="http", domain="fresh-domain.com.br",
            parser=ParserSpec(kind="statejson", pix="a", card="b", availability="c"),
        )
        self.service.add_site(principal, new_site)
        self.service.add_product("owner1", ProductSpec("aw3225qf"))
        source = self.service.add_source(
            "owner1", "aw3225qf", "freshsite",
            "https://www.fresh-domain.com.br/produto/1/a")
        self.assertTrue(source.source_id.startswith("owner1:aw3225qf:freshsite:"))

    def test_add_source_still_rejects_domain_outside_catalogue(self) -> None:
        # ip_is_safe / the catalogue itself remain the guard: a domain that
        # was NEVER registered as a site (even post-FD1) is still rejected.
        self.service.add_product("owner1", ProductSpec("aw3225qf"))
        with self.assertRaises(UrlValidationError):
            self.service.add_source(
                "owner1", "aw3225qf", "kabum", "https://never-cataloged.com/x")


class FalsyOwnerRejectionTest(_TenancyTestBase):
    """Mirrors StateStore.record's existing fail-close on a falsy owner."""

    def test_add_product_rejects_empty_owner(self) -> None:
        with self.assertRaises(ValueError):
            self.service.add_product("", ProductSpec("aw3225qf"))

    def test_add_source_rejects_empty_owner(self) -> None:
        with self.assertRaises(ValueError):
            self.service.add_source(
                "", "aw3225qf", "kabum",
                "https://www.kabum.com.br/produto/1/a")


class StateTenancyTest(_TenancyTestBase):
    def test_list_state_and_history_are_owner_scoped(self) -> None:
        from kerdoos.core.domain import Availability, ScrapeStatus
        from kerdoos.persistence.ports import ScrapeRecord

        sid = make_source_id("owner1", "aw3225qf", "kabum", "https://x")
        record = ScrapeRecord(
            source_id=sid, ts="2026-07-08T00:00:00+00:00", status=ScrapeStatus.OK,
            price_pix_cents=100, price_card_cents=110, currency="BRL",
            availability=Availability.IN_STOCK, method="http", error=None,
        )
        self.state.record("owner1", record)
        self.assertEqual(len(self.service.list_state("owner1")), 1)
        self.assertEqual(len(self.service.list_state("owner2")), 0)
        self.assertEqual(len(self.service.get_history("owner1", sid)), 1)
        self.assertEqual(len(self.service.get_history("owner2", sid)), 0)


class AddSiteAdminGuardTest(_TenancyTestBase):
    def test_non_admin_cannot_add_site(self) -> None:
        principal = Principal(owner_id="owner1", role="user")
        new_site = SiteConfig(
            name="terabyte", fetcher="tls", domain="terabyteshop.com.br",
            parser=ParserSpec(kind="dom", pix="a", card="b", availability="c"),
        )
        with self.assertRaises(PermissionError):
            self.service.add_site(principal, new_site)

    def test_admin_can_add_site(self) -> None:
        principal = Principal(owner_id="root", role="admin")
        new_site = SiteConfig(
            name="terabyte", fetcher="tls", domain="terabyteshop.com.br",
            parser=ParserSpec(kind="dom", pix="a", card="b", availability="c"),
        )
        self.service.add_site(principal, new_site)
        self.assertIn("terabyte", self.service.list_config("owner1").sites)


class ProductKeyValidationTest(unittest.TestCase):
    def test_colon_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_product_key("aw:3225qf")

    def test_empty_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_product_key("")


if __name__ == "__main__":
    unittest.main()
