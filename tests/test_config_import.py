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

from kerdoos.core.app.services import AppService, ProductSpec
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


if __name__ == "__main__":
    unittest.main()
