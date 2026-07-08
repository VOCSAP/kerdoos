"""ConfigStore port + configuration DTOs.

Config (sites + products) is read-only at runtime and lives behind ConfigStore
so the YAML source can become a DB later without touching the core. A source's
id is DERIVED deterministically (product_id + site) rather than authored, so the
same product/site pair always maps to the same StateStore history key (spec #2).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from kerdoos.parsers.ports import ParserSpec


@dataclass(frozen=True, slots=True)
class SiteConfig:
    name: str
    fetcher: str          # fetcher tier name resolved by the static router
    parser: ParserSpec
    # Optional label for a site's second (membership-gated) price tier, e.g.
    # "Prime" for Amazon. Presentation-only data: the CLI resolves it to a
    # source_id -> label map and passes it to the digest, so digest/ never has
    # to import the registry (keeps the core->registry boundary clean).
    tier2_label: str | None = None
    # Render-critical sub-resource CDN hosts allowed by the browser tier's
    # page.route guard (e.g. http2.mlstatic.com for MercadoLivre). SEPARATE from
    # the navigation allowlist: these are never navigated to, only loaded as
    # sub-resources so a full client-side render can hydrate.
    subresource_domains: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ProductSource:
    source_id: str        # deterministic over (product_id, site, url)
    product_id: str
    site: str
    url: str


@dataclass(frozen=True, slots=True)
class Product:
    id: str
    sources: tuple[ProductSource, ...]


@dataclass(frozen=True, slots=True)
class Registry:
    sites: dict[str, SiteConfig]
    products: tuple[Product, ...]

    def iter_sources(self):
        """Yield (product, source, site_config) for every configured source."""
        for product in self.products:
            for source in product.sources:
                site = self.sites.get(source.site)
                if site is None:
                    raise KeyError(
                        f"source {source.source_id!r} references unknown "
                        f"site {source.site!r}"
                    )
                yield product, source, site


def make_source_id(product_id: str, site: str, url: str) -> str:
    """Deterministic id over the (product_id, site, url) triple.

    The url is folded in as a short stable digest, so two DIFFERENT urls of the
    same product on the same site are distinct sources (no silent collision),
    while the same triple always maps to the same StateStore history key. The
    schema stays single-table (scrapes): the url only feeds this id, it is not
    persisted in a separate sources table.
    """
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
    return f"{product_id}:{site}:{digest}"


@runtime_checkable
class ConfigStore(Protocol):
    def load(self) -> Registry:
        ...
