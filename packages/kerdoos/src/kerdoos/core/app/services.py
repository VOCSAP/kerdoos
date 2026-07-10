"""AppService -- core use-cases layer (ADR 0001 S4, invariant #9).

Migrates cmd_run's business logic out of the CLI so interfaces (CLI/WebUI/MCP)
stay thin wrappers over this service. Imports PORTS ONLY (autolycos.ports,
autolycos.safety.DomainPolicy, kerdoos.parsers.ports, kerdoos.persistence.ports,
kerdoos.registry.ports, kerdoos.registry.url_validation) plus same-package
kerdoos.core.* -- never a concrete adapter/router/factory/store
(test_import_contract.py enforces this statically). Concrete collaborators
(SqliteConfigStore, SqliteStateStore, StaticRouter, build_parser,
DEFAULT_DOMAIN_POLICY) are constructed by the composition root (CLI) and
injected here via the constructor.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from autolycos.ports import Router
from autolycos.safety import DomainPolicy

from kerdoos.core.domain import Availability, ScrapeStatus
from kerdoos.core.orchestrator import scrape_and_record
from kerdoos.parsers.ports import Parser, ParserSpec
from kerdoos.persistence.ports import ScrapeRecord, StateStore
from kerdoos.registry.ports import (
    MutableConfigStore,
    Product,
    ProductSource,
    Registry,
    SiteConfig,
    make_source_id,
    validate_product_key,
)
from kerdoos.registry.url_validation import validate_source_url


def _utcnow_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True, slots=True)
class Principal:
    """The resolved caller identity. owner_id NEVER comes from a request
    body/nested spec -- only from an already-authenticated/trusted source.

    role is likewise SERVER-RESOLVED: it is looked up (e.g. via
    ConfigStore.get_owner_role) from the trusted identity, never accepted as
    a client-supplied field on a request body. Phase 1 has no real auth yet
    (CLI callers construct Principal directly), so this is enforced by
    convention here; Phase 3 wires it to real session/bearer resolution."""

    owner_id: str
    role: str = "user"


@dataclass(frozen=True, slots=True)
class ProductSpec:
    product_key: str
    name: str | None = None


@dataclass(frozen=True, slots=True)
class RunResult:
    records: list[ScrapeRecord]
    generated_at: str
    tier2_labels: dict[str, str] = field(default_factory=dict)


class AppService:
    """Tenant-scoped use-cases: config read/write + run_now.

    owner is always an explicit param (never inferred), threaded straight
    into every ConfigStore/StateStore call so the SQL-level owner_id filter
    is applied inline, not bolted on after the fact.
    """

    def __init__(
        self,
        config: MutableConfigStore,
        state: StateStore,
        router: Router,
        domain_policy: DomainPolicy,
        parser_factory: Callable[[ParserSpec], Parser],
        *,
        clock: Callable[[], str] = _utcnow_iso,
    ) -> None:
        self._config = config
        self._state = state
        self._router = router
        self._domain_policy = domain_policy
        self._parser_factory = parser_factory
        self._clock = clock

    # -- read -------------------------------------------------------------

    def list_state(self, owner: str) -> list[ScrapeRecord]:
        return self._state.latest_all(owner)

    def get_history(
        self, owner: str, source_id: str, limit: int = 50
    ) -> list[ScrapeRecord]:
        return self._state.history(owner, source_id, limit)

    def list_config(self, owner: str) -> Registry:
        return self._config.load(owner)

    # -- write --------------------------------------------------------------

    def add_site(self, principal: Principal, spec: SiteConfig) -> SiteConfig:
        # sites are a global admin-only catalogue (Q3): a regular tenant
        # cannot extend the domain allowlist by inventing a site. Checked
        # HERE (not only at the interface layer) as a second rampart.
        if principal.role != "admin":
            raise PermissionError(
                f"principal {principal.owner_id!r} (role={principal.role!r}) "
                "is not allowed to add a site"
            )
        self._config.add_site(spec)
        return spec

    def add_product(self, owner: str, spec: ProductSpec) -> Product:
        if not owner:
            # Fail-closed, mirrors StateStore.record's guard: a falsy owner
            # must never reach the store, tenant or not.
            raise ValueError("owner must not be empty")
        validate_product_key(spec.product_key)
        product = Product(id=spec.product_key, name=spec.name)
        self._config.add_product(owner, product)
        return product

    def add_source(
        self, owner: str, product_key: str, site: str, url: str
    ) -> ProductSource:
        if not owner:
            raise ValueError("owner must not be empty")
        validate_product_key(product_key)
        registry = self._config.load(owner)
        if site not in registry.sites:
            raise KeyError(f"unknown site {site!r}")
        validate_source_url(
            url, ctx=f"add_source(owner={owner!r}, product_key={product_key!r})",
            domain_policy=self._domain_policy,
        )
        source_id = make_source_id(owner, product_key, site, url)
        source = ProductSource(
            source_id=source_id, product_id=product_key, site=site, url=url)
        self._config.add_source(owner, source)
        return source

    def remove_source(self, owner: str, source_id: str) -> None:
        self._config.remove_source(owner, source_id)

    def remove_product(self, owner: str, product_key: str) -> None:
        self._config.remove_product(owner, product_key)

    # -- run ------------------------------------------------------------

    def run_now(self, owner: str) -> RunResult:
        registry = self._config.load(owner)
        generated_at = self._clock()
        records: list[ScrapeRecord] = []
        # source_id -> second-tier label (e.g. "Prime"); resolved here, where
        # both the Registry and the records are in hand, and passed back as
        # data so digest/ never has to import the registry.
        tier2_labels: dict[str, str] = {}
        for _product, source, site in registry.iter_sources():
            if site.tier2_label:
                tier2_labels[source.source_id] = site.tier2_label
            # Per-source guard (invariants #3/#8): a failing source (unknown
            # fetcher/parser tier, store error, ...) must never abort the run
            # nor suppress the aggregated digest.
            try:
                fetcher = self._router.select(site.fetcher, site.subresource_domains)
                parser = self._parser_factory(site.parser)
                record = scrape_and_record(
                    fetcher, parser, self._state, owner,
                    source.source_id, source.url, now=generated_at,
                )
            except Exception as exc:  # noqa: BLE001 -- one source must not kill the run
                record = ScrapeRecord(
                    source_id=source.source_id, ts=generated_at,
                    status=ScrapeStatus.INDETERMINATE,
                    price_pix_cents=None, price_card_cents=None, currency=None,
                    availability=Availability.UNKNOWN, method=None,
                    error=f"source failed: {type(exc).__name__}: {exc}",
                )
            records.append(record)
        return RunResult(
            records=records, generated_at=generated_at, tier2_labels=tier2_labels)
