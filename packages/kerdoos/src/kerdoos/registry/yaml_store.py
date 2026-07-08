"""YAML ConfigStore adapter (MVP).

Loads sites.yaml + products.yaml with yaml.safe_load (never full_load: no
arbitrary object construction from config, CWE-502). Shapes:

    # sites.yaml
    sites:
      kabum:
        fetcher: http
        parser: {kind: statejson, pix: ..., card: ..., availability: ...}

    # products.yaml
    products:
      - id: aw3225qf
        sources:
          - {site: kabum, url: https://...}
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from autolycos.safety import ALLOWED_SCHEMES, DomainPolicy
from kerdoos.parsers.ports import ParserSpec

from .domain_policy import DEFAULT_DOMAIN_POLICY
from .ports import Product, ProductSource, Registry, SiteConfig, make_source_id


class ConfigError(ValueError):
    """The configuration is structurally invalid."""


def _validate_url(url: str, ctx: str, domain_policy: DomainPolicy) -> None:
    """Fail-fast at load time: reject a url the fetcher would refuse anyway.

    Enforces the scheme allowlist (http/https) and the injected domain policy
    here, at config load, rather than deferring to the first fetch -- a typo or
    a hostile config entry (file://, gopher://, an off-list host) is caught
    before any network activity. Mirrors autolycos.safety.validate_target's
    checks, the same DomainPolicy contract every Fetcher enforces.
    """
    parts = urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise ConfigError(
            f"{ctx}: url scheme not allowed: {parts.scheme!r} ({url!r})")
    host = parts.hostname
    if not host:
        raise ConfigError(f"{ctx}: url has no host ({url!r})")
    if not domain_policy.domain_allowed(host):
        raise ConfigError(
            f"{ctx}: url host not in allowlist: {host!r} ({url!r})")


def _require(mapping: Any, key: str, ctx: str) -> Any:
    if not isinstance(mapping, dict) or key not in mapping:
        raise ConfigError(f"missing {key!r} in {ctx}")
    return mapping[key]


def _parse_subresource_domains(body: Any, name: str) -> tuple[str, ...]:
    """Optional render-critical sub-resource CDN allowlist for a site.

    A list of host strings (e.g. ['http2.mlstatic.com']); absent -> empty. This
    is NOT the navigation allowlist (autolycos.safety.ALLOWED_DOMAINS): these
    hosts are only ever loaded as browser sub-resources, never navigated to, so
    they are intentionally not validated against the navigation allowlist.
    """
    raw = body.get("subresource_domains") if isinstance(body, dict) else None
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(isinstance(d, str) for d in raw):
        raise ConfigError(
            f"site {name!r}: subresource_domains must be a list of strings")
    return tuple(d for d in raw if d)


def _load_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


class YamlConfigStore:
    """ConfigStore reading two YAML files from a config directory."""

    def __init__(self, sites_path: str | Path, products_path: str | Path,
                 domain_policy: DomainPolicy = DEFAULT_DOMAIN_POLICY) -> None:
        self._sites_path = Path(sites_path)
        self._products_path = Path(products_path)
        self._domain_policy = domain_policy

    def load(self) -> Registry:
        sites = self._load_sites()
        products = self._load_products(sites)
        return Registry(sites=sites, products=products)

    def _load_sites(self) -> dict[str, SiteConfig]:
        doc = _load_yaml(self._sites_path) or {}
        raw_sites = _require(doc, "sites", "sites.yaml")
        if not isinstance(raw_sites, dict):
            raise ConfigError("'sites' must be a mapping")
        sites: dict[str, SiteConfig] = {}
        for name, body in raw_sites.items():
            fetcher = _require(body, "fetcher", f"site {name!r}")
            parser_raw = _require(body, "parser", f"site {name!r}")
            spec = ParserSpec(
                kind=_require(parser_raw, "kind", f"site {name!r} parser"),
                pix=parser_raw.get("pix"),
                card=parser_raw.get("card"),
                availability=parser_raw.get("availability"),
            )
            tier2_label = body.get("tier2_label")
            sites[name] = SiteConfig(
                name=name, fetcher=str(fetcher), parser=spec,
                tier2_label=str(tier2_label) if tier2_label is not None else None,
                subresource_domains=_parse_subresource_domains(body, name),
            )
        return sites

    def _load_products(
        self, sites: dict[str, SiteConfig]
    ) -> tuple[Product, ...]:
        doc = _load_yaml(self._products_path) or {}
        raw_products = _require(doc, "products", "products.yaml")
        if not isinstance(raw_products, list):
            raise ConfigError("'products' must be a list")
        products: list[Product] = []
        # Dedup guard (N2): the (product, site, url) triple is the source
        # identity. Two different urls of the same product/site are distinct
        # sources; an exactly identical triple is a config error, rejected here
        # rather than silently collapsing two entries onto one history key.
        seen_ids: set[str] = set()
        for entry in raw_products:
            pid = str(_require(entry, "id", "product entry"))
            raw_sources = _require(entry, "sources", f"product {pid!r}")
            if not isinstance(raw_sources, list) or not raw_sources:
                raise ConfigError(f"product {pid!r} needs a non-empty sources list")
            sources: list[ProductSource] = []
            for src in raw_sources:
                site = str(_require(src, "site", f"product {pid!r} source"))
                url = str(_require(src, "url", f"product {pid!r} source"))
                if site not in sites:
                    raise ConfigError(
                        f"product {pid!r} references unknown site {site!r}"
                    )
                _validate_url(url, f"product {pid!r} source", self._domain_policy)
                source_id = make_source_id(pid, site, url)
                if source_id in seen_ids:
                    raise ConfigError(
                        f"duplicate source: product {pid!r} site {site!r} "
                        f"url {url!r} already configured"
                    )
                seen_ids.add(source_id)
                sources.append(ProductSource(
                    source_id=source_id,
                    product_id=pid, site=site, url=url,
                ))
            products.append(Product(id=pid, sources=tuple(sources)))
        return tuple(products)
