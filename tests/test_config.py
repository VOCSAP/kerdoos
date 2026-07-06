"""Registry load-time validation: M2 (url scheme/allowlist) + N2 (dup triple)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from registry.yaml_store import ConfigError, YamlConfigStore

_SITES = """\
sites:
  kabum:
    fetcher: http
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
            store = YamlConfigStore(d / "sites.yaml", d / "products.yaml")
            return store.load()

    def test_valid_config_loads(self) -> None:
        reg = self._load(_products(
            "https://www.kabum.com.br/produto/534732/aw3225qf"))
        sources = [s for _p, s, _c in reg.iter_sources()]
        self.assertEqual(len(sources), 1)

    def test_non_http_scheme_rejected_at_load(self) -> None:
        with self.assertRaises(ConfigError):
            self._load(_products("file:///etc/passwd"))
        with self.assertRaises(ConfigError):
            self._load(_products("ftp://www.kabum.com.br/x"))

    def test_off_allowlist_host_rejected_at_load(self) -> None:
        with self.assertRaises(ConfigError):
            self._load(_products("https://evil.com/x"))
        with self.assertRaises(ConfigError):
            self._load(_products("https://www.kabum.com.br.evil.com/x"))

    def test_two_urls_same_product_site_are_distinct(self) -> None:
        reg = self._load(_products(
            "https://www.kabum.com.br/produto/1/a",
            "https://www.kabum.com.br/produto/2/b",
        ))
        ids = {s.source_id for _p, s, _c in reg.iter_sources()}
        self.assertEqual(len(ids), 2)

    def test_identical_triple_rejected_at_load(self) -> None:
        url = "https://www.kabum.com.br/produto/1/a"
        with self.assertRaises(ConfigError):
            self._load(_products(url, url))


if __name__ == "__main__":
    unittest.main()
