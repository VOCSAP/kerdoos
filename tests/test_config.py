"""Registry YAML parsing: structural validation + N2 (dup triple) + unknown-site.

URL scheme/domain-allowlist validation moved to AppService.add_source (single
choke point, see test_config_import.py) -- parse_sites_yaml/parse_products_yaml
are pure structural parsers now (no ConfigStore, no I/O beyond reading the
file).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from kerdoos.registry.yaml_store import ConfigError, parse_products_yaml, parse_sites_yaml

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


def _products(*urls: str) -> str:
    lines = ["products:", "  - id: aw3225qf", "    sources:"]
    for url in urls:
        lines.append("      - site: kabum")
        lines.append(f"        url: {url}")
    return "\n".join(lines) + "\n"


class ConfigLoadTest(unittest.TestCase):
    def _load(self, products_yaml: str):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "sites.yaml").write_text(_SITES, encoding="utf-8")
            (d / "products.yaml").write_text(products_yaml, encoding="utf-8")
            sites = parse_sites_yaml(d / "sites.yaml")
            products = parse_products_yaml(d / "products.yaml", sites)
            return sites, products

    def test_valid_config_loads(self) -> None:
        sites, products = self._load(_products(
            "https://www.kabum.com.br/produto/534732/aw3225qf"))
        self.assertIn("kabum", sites)
        self.assertEqual(sites["kabum"].domain, "kabum.com.br")
        self.assertEqual(len(products), 1)
        _pid, sources = products[0]
        self.assertEqual(len(sources), 1)

    def test_site_missing_domain_rejected(self) -> None:
        bad_sites = """\
sites:
  kabum:
    fetcher: http
    parser:
      kind: statejson
"""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "sites.yaml").write_text(bad_sites, encoding="utf-8")
            with self.assertRaises(ConfigError):
                parse_sites_yaml(d / "sites.yaml")

    def test_unknown_site_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            self._load(_products("https://www.kabum.com.br/produto/1/a")
                       .replace("site: kabum", "site: nope"))

    def test_two_urls_same_product_site_are_distinct(self) -> None:
        _sites, products = self._load(_products(
            "https://www.kabum.com.br/produto/1/a",
            "https://www.kabum.com.br/produto/2/b",
        ))
        _pid, sources = products[0]
        self.assertEqual(len(sources), 2)
        urls = {url for _site, url in sources}
        self.assertEqual(len(urls), 2)

    def test_identical_triple_rejected_at_load(self) -> None:
        url = "https://www.kabum.com.br/produto/1/a"
        with self.assertRaises(ConfigError):
            self._load(_products(url, url))


if __name__ == "__main__":
    unittest.main()
