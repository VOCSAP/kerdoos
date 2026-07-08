"""ConfigStore port + configuration DTOs (ADR 0001 S4 -- multi-tenant).

Config (sites + products/sources) is read via ConfigStore.load(owner); mutation
(add_site/add_product/add_source/remove_source) is a SEPARATE, wider contract
(MutableConfigStore, ISP) reserved for interfaces (CLI/WebUI/MCP) so the core
never accidentally receives write authority. One concrete adapter
(SqliteConfigStore) implements both.

A source's id is DERIVED deterministically (owner + product_key + site + url
digest) rather than authored, so the same (owner, product_key, site, url)
quadruple always maps to the same StateStore history key (spec #2). owner is
folded into the id so two tenants using the same product_key never collide on
the same history key -- it must always come from the resolved Principal/an
explicit trusted param, never from a request body field.

sites is a GLOBAL, admin-only catalogue (no owner_id): a regular tenant can
only add sources that reference an already-admin-approved site, never invent
one (structural SSRF containment, ADR Q3).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from kerdoos.parsers.ports import ParserSpec

OwnerId = str


@dataclass(frozen=True, slots=True)
class SiteConfig:
    name: str
    fetcher: str          # fetcher tier name resolved by the router
    parser: ParserSpec
    # Domain the site's product pages live on (e.g. "kabum.com.br"). Stored
    # data in Phase 1 -- NOT yet wired into DomainPolicy dynamically (that
    # remains the static DEFAULT_DOMAIN_POLICY; dynamic wiring is Phase 2).
    domain: str = ""
    # Optional label for a site's second (membership-gated) price tier, e.g.
    # "Prime" for Amazon. Presentation-only data: the caller resolves it to a
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
    source_id: str        # deterministic over (owner, product_id, site, url)
    product_id: str
    site: str
    url: str


@dataclass(frozen=True, slots=True)
class Product:
    id: str
    name: str | None = None
    sources: tuple[ProductSource, ...] = ()


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


def validate_product_key(product_key: str) -> None:
    """Reject a product_key that could forge/collide a source_id.

    ':' is the field separator inside make_source_id; a product_key carrying
    one could otherwise be crafted to collide across tenants/sources.
    """
    if not product_key:
        raise ValueError("product_key must not be empty")
    if ":" in product_key:
        raise ValueError(f"product_key must not contain ':': {product_key!r}")


def make_source_id(owner: str, product_key: str, site: str, url: str) -> str:
    """Deterministic id over the (owner, product_key, site, url) quadruple.

    owner is folded in FIRST so two different tenants using the identical
    product_key/site/url never collide on the same StateStore history key.
    The url is folded in as a short stable digest, so two DIFFERENT urls of
    the same product/site are distinct sources (no silent collision), while
    the same quadruple always maps to the same id.
    """
    validate_product_key(product_key)
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
    return f"{owner}:{product_key}:{site}:{digest}"


@runtime_checkable
class ConfigStore(Protocol):
    def load(self, owner: OwnerId) -> Registry:
        ...

    def site_domains(self) -> frozenset[str]:
        """Every domain declared by a catalogued site (global, no owner).

        Backs kerdoos.registry.domain_policy.CatalogueDomainPolicy: a
        lightweight read that does not require loading owner-scoped
        products, queried live on every domain_allowed() call so a
        freshly admin-added site becomes fetchable immediately (Phase 2a
        FD1, ADR 0001 S9).
        """
        ...


@runtime_checkable
class MutableConfigStore(ConfigStore, Protocol):
    """Write-side contract, reserved for interfaces (CLI/WebUI/MCP).

    add_site takes no owner: sites are a global admin-only catalogue, not a
    tenant-scoped resource. Callers are expected to authorize the admin role
    check themselves (AppService.add_site does this as a second rampart)
    before calling this method.
    """

    def add_site(self, site: SiteConfig) -> None:
        ...

    def add_product(self, owner: OwnerId, product: Product) -> None:
        ...

    def add_source(self, owner: OwnerId, source: ProductSource) -> None:
        ...

    def remove_source(self, owner: OwnerId, source_id: str) -> None:
        ...
