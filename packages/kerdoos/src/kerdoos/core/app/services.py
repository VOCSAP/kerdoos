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

import uuid
from collections.abc import Callable
from dataclasses import dataclass, field

from autolycos.ports import Router
from autolycos.safety import DomainPolicy

from kerdoos.core.domain import Availability, ScrapeStatus
from kerdoos.core.orchestrator import scrape_and_record
from kerdoos.parsers.ports import Parser, ParserSpec
from kerdoos.persistence.ports import ScrapeRecord, StateStore
from kerdoos.registry.errors import FetcherTierUnavailableError
from kerdoos.registry.ports import (
    DigestJob,
    MutableConfigStore,
    Product,
    ProductSource,
    Registry,
    SiteConfig,
    make_source_id,
    normalize_schedule,
    parse_job_options,
    validate_product_key,
    validate_template_id,
    validate_timezone,
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
class DigestJobSpec:
    """Interface-facing spec for create_job/update_job (ADR 0003 Phase 6a).

    frequency_kind/minute/hour/cron_expr are normalized into DigestJob.
    schedule_cron by normalize_schedule() -- callers never author a cron
    expression directly except in the 'cron' escape hatch. options is a raw
    dict, validated against the whitelist by parse_job_options() before it
    ever reaches DigestJob/storage (ADR 0003 Decision 5, fail-closed)."""

    name: str
    frequency_kind: str        # 'hourly' | 'daily' | 'cron'
    minute: int = 0
    hour: int = 0
    cron_expr: str | None = None
    timezone: str = "UTC"
    template_id: str = "default"
    options: dict = field(default_factory=dict)
    enabled: bool = True
    # create_job-ONLY (ADR 0003 Phase 6b, architect finding #7): source
    # linking at creation goes through this field, but AppService.update_job
    # NEVER reads it -- relinking sources on an existing job is only done via
    # add_job_source/remove_job_source. Passing a changed source_ids to
    # update_job is silently a no-op for linkage (the returned DigestJob's
    # source_ids is still accurate, since the store reloads it fresh from DB
    # regardless of this field's value).
    source_ids: tuple[str, ...] = ()


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
        # Deployment-mismatch guard (card 3aeb8a19): a site's fetcher tier can
        # be unimportable on THIS image (e.g. a browser/uc site on slim). Reject
        # here, at the single choke point every interface (CLI/WebUI/future MCP)
        # goes through, instead of letting it surface only at the first scrape.
        fetcher = registry.sites[site].fetcher
        if not self._router.tier_available(fetcher):
            raise FetcherTierUnavailableError(
                f"site {site!r} needs fetcher tier {fetcher!r}, which is not "
                "available in this deployment"
            )
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

    # -- digest jobs (Phase 6a, ADR 0003) --------------------------------

    def create_job(self, principal: Principal, spec: DigestJobSpec) -> DigestJob:
        # create_job takes Principal (not owner: str) -- mirrors add_site's
        # convention of taking the resolved caller identity, since job_id
        # generation + the create-time cron/options normalization are both
        # authorization-adjacent (ADR 0003 finding S2: owner_id must always
        # come from the resolved Principal, never a request body field).
        if not principal.owner_id:
            raise ValueError("owner must not be empty")
        schedule_cron = normalize_schedule(
            spec.frequency_kind, minute=spec.minute, hour=spec.hour,
            cron_expr=spec.cron_expr,
        )
        # Fail-closed on a malformed IANA tz (finding #8): must never reach
        # storage, since the evaluator (core/scheduler.py) needs a valid
        # zoneinfo.ZoneInfo to compute window_start for this job.
        validate_timezone(spec.timezone)
        validate_template_id(spec.template_id)
        options = parse_job_options(spec.options)
        job = DigestJob(
            id=str(uuid.uuid4()), owner_id=principal.owner_id, name=spec.name,
            frequency_kind=spec.frequency_kind, schedule_cron=schedule_cron,
            timezone=spec.timezone, template_id=spec.template_id,
            options=options, enabled=spec.enabled, created_at=self._clock(),
        )
        # Double-scoping IDOR defense (ADR 0003 finding S2): the store
        # RE-VERIFIES each source_id belongs to principal.owner_id at
        # persist time via an owner-scoped INSERT...SELECT -- this call
        # never trusts spec.source_ids at face value.
        return self._config.create_job(
            principal.owner_id, job, spec.source_ids)

    def list_jobs(self, owner: str) -> tuple[DigestJob, ...]:
        return self._config.list_jobs(owner)

    def get_job(self, owner: str, job_id: str) -> DigestJob:
        return self._config.get_job(owner, job_id)

    def update_job(
        self, owner: str, job_id: str, spec: DigestJobSpec
    ) -> DigestJob:
        # NOTE (finding #7): spec.source_ids is intentionally IGNORED here --
        # see DigestJobSpec.source_ids docstring. Use add_job_source/
        # remove_job_source to change an existing job's linked sources.
        if not owner:
            raise ValueError("owner must not be empty")
        schedule_cron = normalize_schedule(
            spec.frequency_kind, minute=spec.minute, hour=spec.hour,
            cron_expr=spec.cron_expr,
        )
        validate_timezone(spec.timezone)
        validate_template_id(spec.template_id)
        options = parse_job_options(spec.options)
        job = DigestJob(
            id=job_id, owner_id=owner, name=spec.name,
            frequency_kind=spec.frequency_kind, schedule_cron=schedule_cron,
            timezone=spec.timezone, template_id=spec.template_id,
            options=options, enabled=spec.enabled,
        )
        return self._config.update_job(owner, job_id, job)

    def delete_job(self, owner: str, job_id: str) -> None:
        self._config.delete_job(owner, job_id)

    def add_job_source(self, owner: str, job_id: str, source_id: str) -> bool:
        # Re-verified at the store layer regardless of caller intent (same
        # double-scoping defense as create_job).
        return self._config.add_job_source(owner, job_id, source_id)

    def remove_job_source(
        self, owner: str, job_id: str, source_id: str
    ) -> None:
        self._config.remove_job_source(owner, job_id, source_id)

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
            # Deployment-mismatch skip (card 3aeb8a19): a source added before
            # this guard existed (or before a redeploy from autonomous to
            # slim) can still reference an unavailable tier. Skip it -- same
            # treatment as a source absent from the registry (invariant #3) --
            # instead of writing an INDETERMINATE record every cadence
            # forever, which add_source's guard alone cannot retroactively
            # prevent. No record for this source this cycle.
            if not self._router.tier_available(site.fetcher):
                continue
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
