"""YAML config parser (one-shot import tool, not a runtime ConfigStore).

Loads sites.yaml + products.yaml with yaml.safe_load (never full_load: no
arbitrary object construction from config, CWE-502). Shapes:

    # sites.yaml
    sites:
      kabum:
        fetcher: http
        domain: kabum.com.br
        parser: {kind: statejson, pix: ..., card: ..., availability: ...}

    # products.yaml
    products:
      - id: aw3225qf
        sources:
          - {site: kabum, url: https://...}

Phase 1: this module is no longer consumed at runtime by `kerdoos run` (that
now reads config.db via SqliteConfigStore). It is used ONLY by the one-shot
`kerdoos config import` CLI command as a pure parser -- structural validation
and in-file dedup only. URL scheme/domain-allowlist validation and source_id
construction have moved to AppService.add_source (registry.url_validation +
registry.ports.make_source_id), the single choke point shared by every entry
point that can add a source.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from kerdoos.parsers.ports import ParserSpec

from .errors import ConfigError  # re-exported for backward-compatible imports
from .ports import SiteConfig

__all__ = ["ConfigError", "parse_products_yaml", "parse_sites_yaml"]


def _require(mapping: Any, key: str, ctx: str) -> Any:
    if not isinstance(mapping, dict) or key not in mapping:
        raise ConfigError(f"missing {key!r} in {ctx}")
    return mapping[key]


def _parse_subresource_domains(body: Any, name: str) -> tuple[str, ...]:
    """Optional render-critical sub-resource CDN allowlist for a site.

    A list of host strings (e.g. ['http2.mlstatic.com']); absent -> empty. This
    is NOT the navigation allowlist (DomainPolicy): these hosts are only ever
    loaded as browser sub-resources, never navigated to, so they are
    intentionally not validated against the navigation allowlist.
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


def parse_sites_yaml(path: str | Path) -> dict[str, SiteConfig]:
    """Parse sites.yaml into the SiteConfig catalogue (structural only)."""
    doc = _load_yaml(Path(path)) or {}
    raw_sites = _require(doc, "sites", "sites.yaml")
    if not isinstance(raw_sites, dict):
        raise ConfigError("'sites' must be a mapping")
    sites: dict[str, SiteConfig] = {}
    for name, body in raw_sites.items():
        fetcher = _require(body, "fetcher", f"site {name!r}")
        domain = _require(body, "domain", f"site {name!r}")
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
            domain=str(domain),
            tier2_label=str(tier2_label) if tier2_label is not None else None,
            subresource_domains=_parse_subresource_domains(body, name),
        )
    return sites


def parse_products_yaml(
    path: str | Path, known_sites: dict[str, SiteConfig]
) -> list[tuple[str, list[tuple[str, str]]]]:
    """Parse products.yaml into [(product_key, [(site, url), ...]), ...].

    Structural + in-file dedup guard only (N2: an exactly identical
    (product_key, site, url) triple twice in the SAME file is a config error).
    Does not validate url scheme/domain or construct any source_id -- that is
    AppService.add_source's job, applied uniformly regardless of caller.
    """
    doc = _load_yaml(Path(path)) or {}
    raw_products = _require(doc, "products", "products.yaml")
    if not isinstance(raw_products, list):
        raise ConfigError("'products' must be a list")
    products: list[tuple[str, list[tuple[str, str]]]] = []
    seen_triples: set[tuple[str, str, str]] = set()
    for entry in raw_products:
        pid = str(_require(entry, "id", "product entry"))
        raw_sources = _require(entry, "sources", f"product {pid!r}")
        if not isinstance(raw_sources, list) or not raw_sources:
            raise ConfigError(f"product {pid!r} needs a non-empty sources list")
        sources: list[tuple[str, str]] = []
        for src in raw_sources:
            site = str(_require(src, "site", f"product {pid!r} source"))
            url = str(_require(src, "url", f"product {pid!r} source"))
            if site not in known_sites:
                raise ConfigError(
                    f"product {pid!r} references unknown site {site!r}"
                )
            triple = (pid, site, url)
            if triple in seen_triples:
                raise ConfigError(
                    f"duplicate source: product {pid!r} site {site!r} "
                    f"url {url!r} already configured"
                )
            seen_triples.add(triple)
            sources.append((site, url))
        products.append((pid, sources))
    return products
