"""URL validation choke point (AppService.add_source) + config import/export.

M2 (url scheme/allowlist rejection) moved here from test_config.py's old
YamlConfigStore-level test, because the validation itself moved to
AppService.add_source (registry.url_validation), the single choke point
shared by every entry point that can add a source (CLI import, future
WebUI/MCP) -- see registry/yaml_store.py's module docstring.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from autolycos.router import StaticRouter
from autolycos.safety import DomainPolicy

from kerdoos.core.app.services import AppService, Principal, ProductSpec
from kerdoos.interfaces.cli import main as cli
from kerdoos.parsers.factory import build_parser
from kerdoos.parsers.ports import ParserSpec
from kerdoos.persistence.sqlite_store import SqliteStateStore
from kerdoos.registry.ports import SiteConfig
from kerdoos.registry.sqlite_store import SqliteConfigStore
from kerdoos.registry.url_validation import UrlValidationError

_DOMAIN_POLICY = DomainPolicy(frozenset({"kabum.com.br"}))
_SITE = SiteConfig(
    name="kabum", fetcher="http", domain="kabum.com.br",
    parser=ParserSpec(kind="statejson", pix="a", card="b", availability="c"),
)

_SITES_YAML = """\
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

_PRODUCTS_YAML = """\
products:
  - id: aw3225qf
    sources:
      - site: kabum
        url: https://www.kabum.com.br/produto/534732/aw3225qf
"""


class UrlValidationChokePointTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        d = Path(self._tmp.name)
        self.config = SqliteConfigStore(d / "config.db")
        self.state = SqliteStateStore(d / "state.db")
        router = StaticRouter(_DOMAIN_POLICY)
        self.service = AppService(
            self.config, self.state, router, _DOMAIN_POLICY, build_parser)
        self.config.add_site(_SITE)
        self.service.add_product("owner1", ProductSpec("aw3225qf"))

    def tearDown(self) -> None:
        self.config.close()
        self.state.close()
        self._tmp.cleanup()

    def test_non_http_scheme_rejected(self) -> None:
        with self.assertRaises(UrlValidationError):
            self.service.add_source("owner1", "aw3225qf", "kabum", "file:///etc/passwd")
        with self.assertRaises(UrlValidationError):
            self.service.add_source("owner1", "aw3225qf", "kabum", "ftp://www.kabum.com.br/x")

    def test_off_allowlist_host_rejected(self) -> None:
        with self.assertRaises(UrlValidationError):
            self.service.add_source("owner1", "aw3225qf", "kabum", "https://evil.com/x")
        with self.assertRaises(UrlValidationError):
            self.service.add_source(
                "owner1", "aw3225qf", "kabum",
                "https://www.kabum.com.br.evil.com/x")

    def test_valid_url_accepted(self) -> None:
        source = self.service.add_source(
            "owner1", "aw3225qf", "kabum",
            "https://www.kabum.com.br/produto/534732/aw3225qf")
        self.assertTrue(source.source_id.startswith("owner1:aw3225qf:kabum:"))


class ConfigImportExportTest(unittest.TestCase):
    def test_import_is_idempotent_and_export_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            config_dir = d / "config"
            config_dir.mkdir()
            (config_dir / "sites.yaml").write_text(_SITES_YAML, encoding="utf-8")
            (config_dir / "products.yaml").write_text(_PRODUCTS_YAML, encoding="utf-8")

            config_db = d / "config.db"
            state_db = d / "state.db"
            args = cli.build_parser_cli().parse_args([
                "config", "import",
                "--config-dir", str(config_dir),
                "--config-db", str(config_db),
                "--db", str(state_db),
                "--owner", "owner1",
            ])
            self.assertEqual(cli.cmd_config_import(args), 0)
            # Re-running must not raise nor duplicate rows (UPSERT semantics).
            self.assertEqual(cli.cmd_config_import(args), 0)

            store = SqliteConfigStore(config_db)
            try:
                registry = store.load("owner1")
                self.assertEqual(len(registry.sites), 1)
                self.assertEqual(len(registry.products), 1)
                self.assertEqual(len(registry.products[0].sources), 1)
            finally:
                store.close()

            export_dir = d / "export"
            export_args = cli.build_parser_cli().parse_args([
                "config", "export",
                "--config-dir", str(export_dir),
                "--config-db", str(config_db),
                "--owner", "owner1",
            ])
            self.assertEqual(cli.cmd_config_export(export_args), 0)
            self.assertTrue((export_dir / "sites.yaml").exists())
            self.assertTrue((export_dir / "products.yaml").exists())

            # Round trip: re-parsing the exported files yields the same shape.
            from kerdoos.registry.yaml_store import parse_products_yaml, parse_sites_yaml
            sites = parse_sites_yaml(export_dir / "sites.yaml")
            products = parse_products_yaml(export_dir / "products.yaml", sites)
            self.assertIn("kabum", sites)
            self.assertEqual(sites["kabum"].domain, "kabum.com.br")
            self.assertEqual(len(products), 1)

    def test_rejected_source_leaves_zero_products_and_reports_all_errors(
        self,
    ) -> None:
        # Card a8d6ee3a: a rejected entry must abort the WHOLE import with
        # zero writes, not leave the product that owns the rejected source
        # committed with no sources.
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            config_dir = d / "config"
            config_dir.mkdir()
            (config_dir / "sites.yaml").write_text(_SITES_YAML, encoding="utf-8")
            products_yaml = (
                "products:\n"
                "  - id: good-one\n"
                "    sources:\n"
                "      - site: kabum\n"
                "        url: https://www.kabum.com.br/produto/1\n"
                "  - id: bad-one\n"
                "    sources:\n"
                '      - site: kabum\n'
                '        url: \'https://www.kabum.com.br/produto/2"x\'\n'
            )
            (config_dir / "products.yaml").write_text(
                products_yaml, encoding="utf-8")

            config_db = d / "config.db"
            state_db = d / "state.db"
            args = cli.build_parser_cli().parse_args([
                "config", "import",
                "--config-dir", str(config_dir),
                "--config-db", str(config_db),
                "--db", str(state_db),
                "--owner", "owner1",
            ])

            import io
            from contextlib import redirect_stderr

            captured = io.StringIO()
            with redirect_stderr(captured):
                exit_code = cli.cmd_config_import(args)

            self.assertEqual(exit_code, 1)
            message = captured.getvalue()
            self.assertIn("bad-one", message)
            self.assertIn("kabum", message)
            self.assertIn("produto/2", message)
            self.assertIn("0 writes", message)

            store = SqliteConfigStore(config_db)
            try:
                registry = store.load("owner1")
                # MEASURED FIX (was: both products persisted, bad-one with
                # zero sources): nothing is written, not even the site or
                # the unrelated valid product.
                self.assertEqual(registry.sites, {})
                self.assertEqual(len(registry.products), 0)
            finally:
                store.close()

    def test_valid_file_imports_everything(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            config_dir = d / "config"
            config_dir.mkdir()
            (config_dir / "sites.yaml").write_text(_SITES_YAML, encoding="utf-8")
            products_yaml = (
                "products:\n"
                "  - id: good-one\n"
                "    sources:\n"
                "      - site: kabum\n"
                "        url: https://www.kabum.com.br/produto/1\n"
                "  - id: good-two\n"
                "    sources:\n"
                "      - site: kabum\n"
                "        url: https://www.kabum.com.br/produto/2\n"
            )
            (config_dir / "products.yaml").write_text(
                products_yaml, encoding="utf-8")

            config_db = d / "config.db"
            state_db = d / "state.db"
            args = cli.build_parser_cli().parse_args([
                "config", "import",
                "--config-dir", str(config_dir),
                "--config-db", str(config_db),
                "--db", str(state_db),
                "--owner", "owner1",
            ])
            self.assertEqual(cli.cmd_config_import(args), 0)

            store = SqliteConfigStore(config_db)
            try:
                registry = store.load("owner1")
                self.assertEqual(set(registry.sites), {"kabum"})
                product_ids = {p.id for p in registry.products}
                self.assertEqual(product_ids, {"good-one", "good-two"})
                sources_by_product = {
                    p.id: [s.url for s in p.sources] for p in registry.products
                }
                self.assertEqual(
                    sources_by_product["good-one"],
                    ["https://www.kabum.com.br/produto/1"])
                self.assertEqual(
                    sources_by_product["good-two"],
                    ["https://www.kabum.com.br/produto/2"])
            finally:
                store.close()

    def test_unknown_fetcher_tier_in_sites_yaml_rejected_with_zero_writes(
        self,
    ) -> None:
        # Card a8d6ee3a: sites.yaml's own fetcher-tier-known check
        # (AppService.add_site's known_tiers() guard) was bypassed
        # entirely by the CLI calling MutableConfigStore.add_site()
        # directly. import_config enforces it, atomically across ALL
        # sites in the file.
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            config_dir = d / "config"
            config_dir.mkdir()
            sites_yaml = _SITES_YAML + (
                "  bogus:\n"
                "    fetcher: not-a-real-tier\n"
                "    domain: bogus.example.com\n"
                "    parser:\n"
                "      kind: statejson\n"
                "      pix: a\n"
                "      card: b\n"
                "      availability: c\n"
            )
            (config_dir / "sites.yaml").write_text(sites_yaml, encoding="utf-8")

            config_db = d / "config.db"
            state_db = d / "state.db"
            args = cli.build_parser_cli().parse_args([
                "config", "import",
                "--config-dir", str(config_dir),
                "--config-db", str(config_db),
                "--db", str(state_db),
            ])

            import io
            from contextlib import redirect_stderr

            captured = io.StringIO()
            with redirect_stderr(captured):
                exit_code = cli.cmd_config_import(args)

            self.assertEqual(exit_code, 1)
            message = captured.getvalue()
            self.assertIn("bogus", message)
            self.assertIn("not-a-real-tier", message)
            self.assertIn("0 writes", message)

            store = SqliteConfigStore(config_db)
            try:
                # Zero sites written, not even the valid "kabum" entry.
                self.assertEqual(store.load("").sites, {})
            finally:
                store.close()

    def test_non_admin_principal_with_sites_is_refused_with_zero_writes(
        self,
    ) -> None:
        # Gate a8d6ee3a C1 (CWE-862): import_config writes the GLOBAL sites
        # catalogue -- a non-admin principal must be refused BEFORE any
        # validation/write, mirroring add_site's own admin-only rampart.
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            self.config = SqliteConfigStore(d / "config.db")
            self.state = SqliteStateStore(d / "state.db")
            router = StaticRouter(_DOMAIN_POLICY)
            service = AppService(
                self.config, self.state, router, _DOMAIN_POLICY, build_parser)
            try:
                with self.assertRaises(PermissionError):
                    service.import_config(
                        Principal(owner_id="tenant1", role="user"),
                        "tenant1", {"kabum": _SITE}, [])
                registry = service.list_config("tenant1")
                self.assertEqual(registry.sites, {})
                self.assertEqual(len(registry.products), 0)
            finally:
                self.config.close()
                self.state.close()

    def test_non_admin_principal_importing_for_another_owner_is_refused_with_zero_writes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            self.config = SqliteConfigStore(d / "config.db")
            self.state = SqliteStateStore(d / "state.db")
            router = StaticRouter(_DOMAIN_POLICY)
            service = AppService(
                self.config, self.state, router, _DOMAIN_POLICY, build_parser)
            try:
                with self.assertRaises(PermissionError):
                    service.import_config(
                        Principal(owner_id="tenant1", role="user"),
                        "tenant2", {}, [("aw3225qf", [])])
                registry = service.list_config("tenant2")
                self.assertEqual(registry.sites, {})
                self.assertEqual(len(registry.products), 0)
            finally:
                self.config.close()
                self.state.close()

    def test_non_admin_principal_importing_for_own_owner_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            self.config = SqliteConfigStore(d / "config.db")
            self.state = SqliteStateStore(d / "state.db")
            router = StaticRouter(_DOMAIN_POLICY)
            service = AppService(
                self.config, self.state, router, _DOMAIN_POLICY, build_parser)
            try:
                summary = service.import_config(
                    Principal(owner_id="tenant1", role="user"),
                    "tenant1", {}, [("aw3225qf", [])])
                self.assertEqual(summary.products, 1)
                registry = service.list_config("tenant1")
                self.assertEqual(len(registry.products), 1)
            finally:
                self.config.close()
                self.state.close()

    def test_write_phase_crash_reports_partial_cleanly(self) -> None:
        # LOW (gate a8d6ee3a): validation passes, but the write phase
        # itself raises (infra error, a race) -- must surface as a clean
        # PARTIAL message via the CLI, never a raw traceback.
        from unittest import mock

        from kerdoos.core.app.services import AppService

        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            config_dir = d / "config"
            config_dir.mkdir()
            (config_dir / "sites.yaml").write_text(_SITES_YAML, encoding="utf-8")
            (config_dir / "products.yaml").write_text(
                _PRODUCTS_YAML, encoding="utf-8")

            config_db = d / "config.db"
            state_db = d / "state.db"
            args = cli.build_parser_cli().parse_args([
                "config", "import",
                "--config-dir", str(config_dir),
                "--config-db", str(config_db),
                "--db", str(state_db),
                "--owner", "owner1",
            ])

            import io
            from contextlib import redirect_stderr

            captured = io.StringIO()
            with mock.patch.object(
                AppService, "add_product",
                side_effect=RuntimeError("disk full"),
            ):
                with redirect_stderr(captured):
                    exit_code = cli.cmd_config_import(args)

            self.assertEqual(exit_code, 1)
            message = captured.getvalue()
            self.assertIn("write phase interrupted", message)
            self.assertIn("PARTIAL", message)
            self.assertIn("disk full", message)


if __name__ == "__main__":
    unittest.main()
