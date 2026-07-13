"""ConfigStore port + configuration DTOs (ADR 0001 S4 -- multi-tenant).

Config (sites + products/sources) is read via ConfigStore.load(owner); mutation
(add_site/add_product/add_source/remove_source/remove_product) is a SEPARATE, wider contract
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
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable
from zoneinfo import available_timezones

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


# -- Digest jobs (ADR 0003, Phase 6a) ---------------------------------------

# Options are validated by hand against this fixed whitelist (ADR 0003
# Decision 5 Q-d: dataclass + manual validation, no pydantic). The full
# per-template option surface is a 6b render concern; 6a only guarantees no
# unknown/out-of-bounds key ever reaches storage.
_ALLOWED_OPTION_KEYS = frozenset(
    {"show_pix", "show_card", "variation_threshold_pct"})

_VALID_FREQUENCY_KINDS = frozenset({"hourly", "daily", "cron"})


@dataclass(frozen=True, slots=True)
class JobOptions:
    show_pix: bool = True
    show_card: bool = True
    # None = no variation filter. 0-100 inclusive when set.
    variation_threshold_pct: float | None = None


def parse_job_options(raw: dict) -> JobOptions:
    """Validate a raw options dict against the whitelist (fail-closed).

    Unknown keys and out-of-bounds/mistyped values are rejected outright --
    'options' is never passed through unvalidated to storage or the renderer
    (ADR 0003 Decision 5).
    """
    unknown = set(raw) - _ALLOWED_OPTION_KEYS
    if unknown:
        raise ValueError(f"unknown job option keys: {sorted(unknown)}")
    show_pix = raw.get("show_pix", True)
    show_card = raw.get("show_card", True)
    if not isinstance(show_pix, bool):
        raise ValueError("show_pix must be a bool")
    if not isinstance(show_card, bool):
        raise ValueError("show_card must be a bool")
    threshold = raw.get("variation_threshold_pct")
    if threshold is not None:
        if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
            raise ValueError("variation_threshold_pct must be numeric")
        if not (0 <= threshold <= 100):
            raise ValueError("variation_threshold_pct must be within [0, 100]")
        threshold = float(threshold)
    return JobOptions(
        show_pix=show_pix, show_card=show_card,
        variation_threshold_pct=threshold)


def dump_job_options(options: JobOptions) -> dict:
    return {
        "show_pix": options.show_pix,
        "show_card": options.show_card,
        "variation_threshold_pct": options.variation_threshold_pct,
    }


def normalize_schedule(
    frequency_kind: str, *, minute: int = 0, hour: int = 0,
    cron_expr: str | None = None,
) -> str:
    """Normalize a frequency spec into a cron expression (ADR 0003 Decision 2
    option B): the evaluator (6b) gets a single code path regardless of how
    the job was authored. Full cron semantic validation (croniter) is a 6b
    evaluator concern -- 6a only checks shape (5 space-separated fields).
    """
    if frequency_kind == "hourly":
        if not (0 <= minute <= 59):
            raise ValueError("minute must be within [0, 59]")
        return f"{minute} * * * *"
    if frequency_kind == "daily":
        if not (0 <= minute <= 59):
            raise ValueError("minute must be within [0, 59]")
        if not (0 <= hour <= 23):
            raise ValueError("hour must be within [0, 23]")
        return f"{minute} {hour} * * *"
    if frequency_kind == "cron":
        if not cron_expr:
            raise ValueError("cron_expr is required for frequency_kind='cron'")
        if len(cron_expr.split()) != 5:
            raise ValueError(
                f"cron_expr must have exactly 5 space-separated fields: "
                f"{cron_expr!r}")
        return cron_expr
    raise ValueError(f"unknown frequency_kind {frequency_kind!r}")


def validate_timezone(timezone: str) -> None:
    """Reject an unknown/malformed IANA timezone string at authoring time
    (ADR 0003 Phase 6b, architect finding #8).

    A malformed tz must never reach storage: zoneinfo.ZoneInfo(bad_tz) would
    otherwise only fail later, at evaluator tick time (core/scheduler.py),
    where a per-job try/except isolates the crash from other jobs but still
    silently strands that job forever. Checking here, at create_job/update_job
    time, fails closed and gives the caller an actionable error immediately.
    """
    if timezone not in available_timezones():
        raise ValueError(f"unknown IANA timezone {timezone!r}")


@dataclass(frozen=True, slots=True)
class DigestJob:
    id: str                    # opaque uuid (ADR 0003 S4)
    owner_id: str
    name: str
    frequency_kind: str        # 'hourly' | 'daily' | 'cron' -- WebUI round-trip label
    schedule_cron: str         # always a normalized cron expression (Decision 2)
    timezone: str = "UTC"      # IANA
    template_id: str = "default"
    options: JobOptions = field(default_factory=JobOptions)
    enabled: bool = True
    created_at: str | None = None
    # Sources currently linked (read-side convenience; empty on a bare spec
    # before create_job links them). Never trusted for IDOR checks -- the
    # store re-verifies ownership at persist time regardless of this field.
    source_ids: tuple[str, ...] = ()


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

    def list_jobs(self, owner: OwnerId) -> tuple[DigestJob, ...]:
        """Every digest job owned by owner, most-recently-named order."""
        ...

    def get_job(self, owner: OwnerId, job_id: str) -> DigestJob:
        """A single owner-scoped job. Raises KeyError if unknown/not-owned
        (same discipline as remove_product -- no distinguishing oracle
        between 'does not exist' and 'belongs to another owner')."""
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

    def remove_product(self, owner: OwnerId, product_key: str) -> None:
        ...

    def create_job(
        self, owner: OwnerId, job: DigestJob, source_ids: tuple[str, ...]
    ) -> DigestJob:
        """Persist job, then link source_ids -- each RE-VERIFIED to belong to
        owner at persist time (IDOR defense in depth, ADR 0003 finding S2).
        A source_id that is not owned by `owner` is silently dropped from
        the returned job's source_ids, never raised (no oracle leak: the
        caller cannot distinguish 'unknown source' from 'someone else's
        source')."""
        ...

    def update_job(self, owner: OwnerId, job_id: str, job: DigestJob) -> DigestJob:
        """Owner-scoped update of job fields (not its source links -- use
        add_job_source/remove_job_source for those). Raises KeyError if
        job_id is unknown or not owned by owner."""
        ...

    def delete_job(self, owner: OwnerId, job_id: str) -> None:
        """Owner-scoped delete, cascading digest_job_sources. Raises
        KeyError if job_id is unknown or not owned by owner (mirrors
        remove_product)."""
        ...

    def add_job_source(self, owner: OwnerId, job_id: str, source_id: str) -> bool:
        """Link source_id to job_id, both re-verified to belong to owner.
        Raises KeyError if job_id is unknown/not-owned. Returns False
        (silent no-op, no oracle leak) if source_id is unknown/not-owned."""
        ...

    def remove_job_source(
        self, owner: OwnerId, job_id: str, source_id: str
    ) -> None:
        """Owner-scoped unlink. Silent no-op if the link does not exist
        (mirrors remove_source)."""
        ...
