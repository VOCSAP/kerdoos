"""Digest-jobs asyncio evaluator (ADR 0003 Phase 6b, Decisions 3/4/7/8).

One evaluation "tick" sweeps every enabled job across ALL owners
(config_store.list_all_enabled_jobs -- scheduler-internal-only, ADR 0003 S2)
and does two independent things:

  Plan A (scrape dedup, Decision 3): for every source referenced by >=1
  enabled job, the required scrape period is the MIN cron period across all
  referencing jobs (the cadence union). A source is (re)scraped this tick
  only if its last recorded scrape is older than that period. Scrapes run
  SEQUENTIALLY via asyncio.to_thread (never asyncio.gather) -- this alone
  satisfies ADR 0002's max_concurrent=1 without a separate queue/semaphore.

  Plan B (per-job notify, Decision 3/8): for every enabled job, build a
  best-available-latest digest from whatever history already exists (does
  NOT wait on Plan A's fresh scrape -- non-blocking by design) and hand it to
  a DigestSender. Idempotence key is (job_id, window_start), where
  window_start is core.scheduler.compute_window_start's quantized cron
  occurrence -- NEVER the raw tick timestamp (a daily job ticked every 60s
  must resolve to the SAME window_start all day, or the idempotence key is
  defeated). Singleton coalescing: a job with a still-queued/running prior
  firing (StateStore.has_active_job_run) is skipped this tick.

Imports PORTS ONLY (autolycos.ports, kerdoos.parsers.ports,
kerdoos.persistence.ports, kerdoos.registry.ports) plus kerdoos.core.* --
never kerdoos.digest.* (digest/ already imports core/, so the reverse
direction would create a package-level layering inversion; DigestSender is
handed fully-resolved records/labels and is responsible for its own
rendering, same as AppService hands raw ScrapeRecords to its caller).
Third-party: only croniter (stdlib-adjacent estimate of a job's own cron
period), mirroring core/scheduler.py's existing precedent of core/
pragmatically importing a single self-contained tool rather than
manufacturing a bespoke port for it.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol, runtime_checkable

from croniter import croniter

from autolycos.ports import Router

from kerdoos.core.orchestrator import scrape_and_record
from kerdoos.core.scheduler import compute_window_start
from kerdoos.parsers.ports import Parser, ParserSpec
from kerdoos.persistence.ports import JobRun, ScrapeRecord, StateStore
from kerdoos.registry.ports import ConfigStore, DigestJob, Registry

logger = logging.getLogger(__name__)

ParserFactory = Callable[[ParserSpec], Parser]


@dataclass(slots=True)
class EvaluationSummary:
    """Aggregate counters for one evaluate_tick call (CLI/log reporting)."""

    scraped_sources: int = 0
    notified_jobs: int = 0
    skipped_jobs: int = 0
    errors: int = 0


@runtime_checkable
class DigestSender(Protocol):
    """Deliver one job's digest. Concrete adapters live in kerdoos.digest
    (e.g. digest.sender.LogDigestSender -- a tranche-4 placeholder; the real
    SMTP adapter + S1/S3/S5 hardening replace it without touching this
    module). Receives fully-resolved data, never a pre-rendered body here --
    rendering (digest.render.render_digest) is the ADAPTER's job so core/
    never imports kerdoos.digest."""

    def send(
        self,
        job: DigestJob,
        records: list[ScrapeRecord],
        generated_at: str,
        tier2_labels: Mapping[str, str],
    ) -> None:
        ...


def should_start_intra_process_evaluator(workers: int) -> bool:
    """Guard-rail (ADR 0003 Decision 4): the intra-process asyncio evaluator
    must refuse to start when the operator has configured more than one
    worker process -- each would run its own timer and double-fire jobs.
    workers > 1 means the caller must rely on external cron calling
    `kerdoos digest` (one evaluate_tick per invocation, Decision 8) instead.
    """
    return workers <= 1


def _job_period(schedule_cron: str, now: datetime) -> timedelta:
    """Best-effort estimate of a job's own cadence, via two consecutive
    croniter occurrences from `now`. This is a freshness BOUND for Plan A's
    scrape dedup only -- it is NOT the exactly-once idempotence key (that is
    strictly compute_window_start's job, used only in Plan B)."""
    cron = croniter(schedule_cron, now)
    first = cron.get_next(datetime)
    second = cron.get_next(datetime)
    return second - first


def _parse_ts(ts: str) -> datetime:
    parsed = datetime.fromisoformat(ts)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _build_source_index(registry: Registry) -> dict[str, tuple]:
    index: dict[str, tuple] = {}
    for product, source, site in registry.iter_sources():
        index[source.source_id] = (product, source, site)
    return index


async def _run_plan_a(
    *,
    jobs: tuple[DigestJob, ...],
    source_index: dict[str, dict[str, tuple]],
    state_store: StateStore,
    router: Router,
    parser_factory: ParserFactory,
    tick_now: datetime,
    now_iso: str,
    summary: EvaluationSummary,
) -> None:
    required_period: dict[tuple[str, str], timedelta] = {}
    for job in jobs:
        period = _job_period(job.schedule_cron, tick_now)
        for source_id in job.source_ids:
            key = (job.owner_id, source_id)
            current = required_period.get(key)
            if current is None or period < current:
                required_period[key] = period

    for (owner_id, source_id), period in required_period.items():
        index = source_index.get(owner_id)
        entry = index.get(source_id) if index else None
        if entry is None:
            # Dangling job_source link (source removed after the job linked
            # it) -- skip silently, never crash the tick over stale config.
            continue
        try:
            history = state_store.history(owner_id, source_id, limit=1)
            if history and (tick_now - _parse_ts(history[0].ts)) < period:
                continue  # fresh enough, no scrape needed this tick
            _product, source, site = entry
            fetcher = router.select(site.fetcher, site.subresource_domains)
            parser = parser_factory(site.parser)
            await asyncio.to_thread(
                scrape_and_record, fetcher, parser, state_store, owner_id,
                source.source_id, source.url, now=now_iso,
            )
            summary.scraped_sources += 1
        except Exception as exc:  # noqa: BLE001 -- one source must not kill the tick
            logger.warning(
                "evaluator: scrape failed for owner=%s source=%s: %s",
                owner_id, source_id, exc,
            )
            summary.errors += 1


def _collect_job_digest(
    job: DigestJob,
    *,
    source_index: dict[str, tuple],
    state_store: StateStore,
) -> tuple[list[ScrapeRecord], dict[str, str]]:
    records: list[ScrapeRecord] = []
    tier2_labels: dict[str, str] = {}
    for source_id in job.source_ids:
        entry = source_index.get(source_id)
        if entry is not None and entry[2].tier2_label:
            tier2_labels[source_id] = entry[2].tier2_label
        history = state_store.history(job.owner_id, source_id, limit=1)
        if history:
            records.append(history[0])
    return records, tier2_labels


async def _run_plan_b(
    *,
    jobs: tuple[DigestJob, ...],
    source_index: dict[str, dict[str, tuple]],
    state_store: StateStore,
    sender: DigestSender,
    now_iso: str,
    tick_now: datetime,
    summary: EvaluationSummary,
    send_semaphore: asyncio.Semaphore,
) -> None:
    for job in jobs:
        try:
            if state_store.has_active_job_run(job.owner_id, job.id):
                summary.skipped_jobs += 1
                continue
            window_start = compute_window_start(
                job.schedule_cron, job.timezone, tick_now)
            run = JobRun(
                job_id=job.id, owner_id=job.owner_id,
                window_start=window_start, fired_at=now_iso, status="queued",
            )
            if not state_store.record_job_run(run):
                summary.skipped_jobs += 1  # already recorded this window
                continue
            state_store.update_job_run(job.id, window_start, status="running")
            try:
                records, tier2_labels = _collect_job_digest(
                    job,
                    source_index=source_index.get(job.owner_id, {}),
                    state_store=state_store,
                )
                # S4 (ADR 0003 Phase 6b tranche 4): an EXPLICIT ceiling on
                # simultaneously in-flight sender.send calls, on top of the
                # per-job DB singleton above (has_active_job_run). Dispatched
                # via asyncio.to_thread so a real blocking SMTP call cannot
                # stall the event loop while holding the semaphore slot.
                async with send_semaphore:
                    await asyncio.to_thread(
                        sender.send, job, records, now_iso, tier2_labels)
            except Exception as exc:  # noqa: BLE001 -- one job must not kill the tick
                state_store.update_job_run(
                    job.id, window_start, status="error",
                    error=f"{type(exc).__name__}: {exc}"[:500],
                )
                summary.errors += 1
                continue
            state_store.update_job_run(
                job.id, window_start, status="sent", sent_at=now_iso)
            summary.notified_jobs += 1
        except Exception as exc:  # noqa: BLE001 -- one job must not kill the tick
            logger.warning("evaluator: job %s failed: %s", job.id, exc)
            summary.errors += 1


async def evaluate_tick(
    *,
    config_store: ConfigStore,
    state_store: StateStore,
    router: Router,
    parser_factory: ParserFactory,
    sender: DigestSender,
    now: datetime | None = None,
    max_concurrent_sends: int = 1,
    send_semaphore: asyncio.Semaphore | None = None,
) -> EvaluationSummary:
    """Run exactly ONE evaluation tick: Plan A (scrape dedup) then Plan B
    (per-job notify). Shared by the intra-process timer (run_evaluator_loop)
    and the `kerdoos digest` CLI (ADR 0003 Decision 8: two triggers, one
    logic). Never raises -- a total failure to even list jobs is caught and
    reported via EvaluationSummary.errors so a single bad tick can never
    kill the outer loop.

    send_semaphore (S4, ADR 0003 Phase 6b tranche 4): the ceiling on
    simultaneously in-flight sender.send calls. By default a FRESH
    Semaphore(max_concurrent_sends) is built per call -- correct for the
    common case (one evaluate_tick at a time, e.g. `kerdoos digest`).
    run_evaluator_loop builds ONE semaphore and reuses it across every tick
    of its loop. A caller that genuinely drives multiple evaluate_tick
    invocations CONCURRENTLY (e.g. an overlapping intra-process loop tick
    plus an external `kerdoos digest` against the same process) must pass
    the SAME send_semaphore instance to each call for the ceiling to hold
    across them -- an in-process asyncio.Semaphore can only cap concurrency
    among callers that share the object, never across separate processes
    (that boundary is covered by should_start_intra_process_evaluator's
    workers<=1 guard-rail plus the per-job DB-level has_active_job_run
    singleton, which IS cross-process)."""
    tick_now = now if now is not None else datetime.now(timezone.utc)
    if tick_now.tzinfo is None:
        tick_now = tick_now.replace(tzinfo=timezone.utc)
    now_iso = tick_now.isoformat()
    summary = EvaluationSummary()

    try:
        jobs = config_store.list_all_enabled_jobs()
    except Exception as exc:  # noqa: BLE001 -- a listing failure must not kill the loop
        logger.warning("evaluator: failed to list enabled jobs: %s", exc)
        summary.errors += 1
        return summary

    if not jobs:
        return summary

    source_index: dict[str, dict[str, tuple]] = {}
    for owner_id in sorted({job.owner_id for job in jobs}):
        try:
            registry = config_store.load(owner_id)
        except Exception as exc:  # noqa: BLE001 -- one owner must not kill the tick
            logger.warning(
                "evaluator: failed to load registry for owner=%s: %s",
                owner_id, exc,
            )
            summary.errors += 1
            continue
        source_index[owner_id] = _build_source_index(registry)

    await _run_plan_a(
        jobs=jobs, source_index=source_index, state_store=state_store,
        router=router, parser_factory=parser_factory, tick_now=tick_now,
        now_iso=now_iso, summary=summary,
    )
    semaphore = (
        send_semaphore if send_semaphore is not None
        else asyncio.Semaphore(max_concurrent_sends))
    await _run_plan_b(
        jobs=jobs, source_index=source_index, state_store=state_store,
        sender=sender, now_iso=now_iso, tick_now=tick_now, summary=summary,
        send_semaphore=semaphore,
    )
    return summary


async def run_evaluator_loop(
    *,
    config_store: ConfigStore,
    state_store: StateStore,
    router: Router,
    parser_factory: ParserFactory,
    sender: DigestSender,
    tick_seconds: int = 60,
    stop_event: asyncio.Event | None = None,
    max_concurrent_sends: int = 1,
) -> None:
    """Intra-process timer: evaluate_tick every tick_seconds until
    stop_event is set. A crashing tick is caught and logged so it never
    kills the loop (the same per-item resilience discipline as Plan A/B,
    applied one level up).

    Builds ONE send_semaphore (S4) here and reuses it across every tick of
    this loop -- ticks of the SAME loop never overlap (each await blocks the
    next), but sharing one instance is simpler than rebuilding it every
    iteration and matches run_evaluator_loop's role as a single persistent
    evaluator."""
    event = stop_event if stop_event is not None else asyncio.Event()
    send_semaphore = asyncio.Semaphore(max_concurrent_sends)
    while not event.is_set():
        try:
            await evaluate_tick(
                config_store=config_store, state_store=state_store,
                router=router, parser_factory=parser_factory, sender=sender,
                send_semaphore=send_semaphore,
            )
        except Exception:  # noqa: BLE001 -- one crashed tick must not kill the loop
            logger.exception("evaluator: tick failed unexpectedly")
        try:
            await asyncio.wait_for(event.wait(), timeout=tick_seconds)
        except asyncio.TimeoutError:
            pass
