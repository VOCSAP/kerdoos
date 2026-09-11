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
import threading
from collections.abc import Callable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol, runtime_checkable

from croniter import croniter

from autolycos.ports import Router

from kerdoos.core.fetcher_guard import tier_unavailable
from kerdoos.core.orchestrator import scrape_and_record
from kerdoos.core.scheduler import compute_window_start
from kerdoos.parsers.ports import Parser, ParserSpec
from kerdoos.persistence.ports import JobRun, ScrapeRecord, StateStore
from kerdoos.registry.ports import ConfigStore, DigestJob, Registry

logger = logging.getLogger(__name__)

ParserFactory = Callable[[ParserSpec], Parser]

# Live-orphan ceiling multiplier: a small buffer above one orphan per
# worker slot, since a burst of timeouts can retire several pools before
# any of them finish. Not derived more precisely -- just needs to bound
# accumulation over an unboundedly long-lived loop, not be exact.
_LIVE_ORPHANS_PER_WORKER = 3


class _RotatingSendExecutor:
    """A send-only thread pool that swaps itself for a fresh one when a
    send times out, shared by every caller holding this wrapper (never a
    bare ThreadPoolExecutor reference, which a callee could not reseat).
    `can_submit()` refuses a new send once too many retired pools still
    have a live orphan, capped at `max_workers * _LIVE_ORPHANS_PER_WORKER`."""

    def __init__(self, max_workers: int) -> None:
        self._max_workers = max_workers
        self.current = ThreadPoolExecutor(max_workers=max_workers)
        self._retired: list[tuple[ThreadPoolExecutor, Future]] = []
        self._max_live_orphans = max_workers * _LIVE_ORPHANS_PER_WORKER

    def _prune_retired(self) -> None:
        still_live = []
        for pool, orphan_future in self._retired:
            if orphan_future.done():
                pool.shutdown(wait=False)
            else:
                still_live.append((pool, orphan_future))
        self._retired = still_live

    def can_submit(self) -> bool:
        self._prune_retired()
        return len(self._retired) < self._max_live_orphans

    def rotate(self, orphan_future: Future | None = None) -> None:
        stuck = self.current
        self.current = ThreadPoolExecutor(max_workers=self._max_workers)
        if orphan_future is not None:
            self._retired.append((stuck, orphan_future))
            self._prune_retired()
        else:
            stuck.shutdown(wait=False)

    def shutdown(self) -> None:
        self.current.shutdown(wait=False)
        for pool, _orphan_future in self._retired:
            pool.shutdown(wait=False)
        self._retired = []


class _DaemonThreadSendExecutor:
    """evaluate_tick's default (per-call) send executor: one daemon thread
    per send, never a ThreadPoolExecutor -- pool workers are joined at
    interpreter exit regardless of shutdown(wait=False), which would hang
    the short-lived CLI (`kerdoos digest`) on an orphaned send. No pool, so
    no orphan-count ceiling either -- out of scope for a single tick."""

    def __init__(self) -> None:
        self.current = self

    def submit(self, fn, *args) -> Future:
        future: Future = Future()

        def _run() -> None:
            if not future.set_running_or_notify_cancel():
                return
            try:
                result = fn(*args)
            except BaseException as exc:  # noqa: BLE001 -- propagate via the Future, not the thread
                future.set_exception(exc)
            else:
                future.set_result(result)

        threading.Thread(target=_run, daemon=True).start()
        return future

    def can_submit(self) -> bool:
        return True

    def rotate(self, orphan_future: Future | None = None) -> None:
        pass  # no shared pool -- each send already has its own thread

    def shutdown(self) -> None:
        pass  # daemon threads need no teardown, they die with the process


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
    ) -> bool:
        """Returns True if the digest was actually sent, False if it was
        skipped because the owner has no email configured (ADR 0003
        Decision 9) -- never raise for that case, an exception means
        job-run status 'error' instead of 'skipped_no_email'."""
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
            # Skip sources whose tier is not installed here: an INDETERMINATE
            # record would replay a permanent deployment error every cadence
            # (card 3aeb8a19; same guard as AppService.run_now).
            if tier_unavailable(router, site):
                continue
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
    send_executor: _RotatingSendExecutor | _DaemonThreadSendExecutor,
    send_timeout_seconds: int,
) -> None:
    for job in jobs:
        try:
            if state_store.has_active_job_run(job.owner_id, job.id):
                summary.skipped_jobs += 1
                continue
            if not job.source_ids:
                # ADR 0003:144-145: a job with zero linked sources (its
                # last source was removed, cascading the digest_job_sources
                # link) must never send an empty digest. The window IS
                # consumed -- nothing changes for this job before an
                # operator reconfigures it, so a same-window retry would
                # be pointless (unlike the capacity refusal below).
                empty_window_start = compute_window_start(
                    job.schedule_cron, job.timezone, tick_now)
                empty_run = JobRun(
                    job_id=job.id, owner_id=job.owner_id,
                    window_start=empty_window_start, fired_at=now_iso,
                    status="queued",
                )
                if state_store.record_job_run(empty_run):
                    state_store.update_job_run(
                        job.id, empty_window_start, status="skipped_no_sources")
                summary.skipped_jobs += 1
                continue
            if not send_executor.can_submit():
                # Checked BEFORE record_job_run: no send was even
                # attempted, so this must NOT consume the idempotence
                # window the way a timeout may (the mail could already be
                # out by then) -- write no job_runs row, so a later tick
                # of the SAME window can retry once orphans clear.
                logger.error(
                    "evaluator: job %s send refused -- live-orphan ceiling "
                    "reached on this executor", job.name)
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
            cf_future = None
            try:
                records, tier2_labels = _collect_job_digest(
                    job,
                    source_index=source_index.get(job.owner_id, {}),
                    state_store=state_store,
                )
                # Dedicated executor (roadmap 1c67e5b2): an orphaned send
                # thread must not occupy the scrape pool. wait_for bounds
                # the whole send (roadmap 58d88fe0), not just each smtplib
                # op, so a slow-but-alive relay cannot hold the semaphore
                # slot indefinitely. Dispatch happens INSIDE the semaphore:
                # submitting before acquiring it would let two callers'
                # threads run concurrently even under max_concurrent_sends=1.
                async with send_semaphore:
                    cf_future = send_executor.current.submit(
                        sender.send, job, records, now_iso, tier2_labels)
                    sent = await asyncio.wait_for(
                        asyncio.wrap_future(cf_future),
                        timeout=send_timeout_seconds,
                    )
            except asyncio.TimeoutError as exc:
                # The stuck thread cannot be killed and may linger -- swap
                # in a fresh executor so it alone absorbs the damage, never
                # every later send too.
                if cf_future is None or cf_future.cancel():
                    logger.warning(
                        "evaluator: job %s send() future was cancelled "
                        "before it started running (send pool congested, "
                        "no thread orphaned by this timeout)", job.name)
                    send_executor.rotate()
                else:
                    send_executor.rotate(cf_future)
                state_store.update_job_run(
                    job.id, window_start, status="error",
                    error=f"{type(exc).__name__}: {exc}"[:500],
                )
                summary.errors += 1
                continue
            except Exception as exc:  # noqa: BLE001 -- one job must not kill the tick
                state_store.update_job_run(
                    job.id, window_start, status="error",
                    error=f"{type(exc).__name__}: {exc}"[:500],
                )
                summary.errors += 1
                continue
            if sent:
                state_store.update_job_run(
                    job.id, window_start, status="sent", sent_at=now_iso)
                summary.notified_jobs += 1
            else:
                # ADR 0003 Decision 9 / fast-follow observability: the owner
                # has no email configured. Never "sent" -- the auto-resume
                # behavior (retry on a later window) is unchanged, only the
                # persisted status now reflects reality.
                state_store.update_job_run(
                    job.id, window_start, status="skipped_no_email")
                summary.skipped_jobs += 1
        except Exception as exc:  # noqa: BLE001 -- one job must not kill the tick
            logger.warning("evaluator: job %s failed: %s", job.id, exc)
            summary.errors += 1


async def _reap_stale_job_runs(
    *,
    jobs: tuple[DigestJob, ...],
    state_store: StateStore,
    tick_now: datetime,
    reaper_timeout_seconds: int,
) -> None:
    """Reaper/TTL sweep (ADR 0003 Phase 6b fast-follow, architect addendum).
    For every enabled job this tick, reap ITS OWN stale job_runs row (owner
    + job_id scoped, StateStore.reap_stale_job_run) if it has sat in
    'queued'/'running' with fired_at older than reaper_timeout_seconds --
    e.g. the evaluator crashed mid-send on a previous tick. A stranded row
    never gets DELETEd (transitioned to terminal 'error' only), so the
    (job_id, window_start) idempotence key survives and that SAME window can
    never re-fire/double-send; recovery happens at the NEXT window_start.

    Runs synchronously inside evaluate_tick, BEFORE _run_plan_b's
    has_active_job_run check, so a stranded row never permanently blocks
    that job's per-job singleton coalescing. This placement is what makes
    the sweep single-writer-safe without a new lock: evaluate_tick has
    exactly two mutually-exclusive callers system-wide (run_evaluator_loop,
    gated by should_start_intra_process_evaluator's workers<=1 guard-rail,
    versus the CLI's cmd_digest external-cron path for workers>1) -- the
    reaper never runs from a third entry point that could race an in-flight
    send outside that guard."""
    fired_before = (
        tick_now - timedelta(seconds=reaper_timeout_seconds)).isoformat()
    for job in jobs:
        try:
            state_store.reap_stale_job_run(
                job.owner_id, job.id, fired_before=fired_before)
        except Exception as exc:  # noqa: BLE001 -- one job must not kill the tick
            logger.warning(
                "evaluator: reap failed for owner=%s job=%s: %s",
                job.owner_id, job.id, exc,
            )


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
    send_executor: _RotatingSendExecutor | _DaemonThreadSendExecutor | None = None,
    reaper_timeout_seconds: int = 300,
) -> EvaluationSummary:
    """Run exactly ONE evaluation tick: a reaper sweep, then Plan A (scrape
    dedup), then Plan B (per-job notify). Shared by the intra-process timer
    (run_evaluator_loop) and the `kerdoos digest` CLI (ADR 0003 Decision 8:
    two triggers, one logic). Never raises -- a total failure to even list
    jobs is caught and reported via EvaluationSummary.errors so a single bad
    tick can never kill the outer loop.

    reaper_timeout_seconds (ADR 0003 Phase 6b fast-follow): the explicit
    max-send-timeout bound _reap_stale_job_runs uses to decide a job_runs
    row is stranded (fired_at older than this many seconds ago). Default
    300s (5 minutes). A plain function default, not threaded through
    Settings -- mirrors max_concurrent_sends's precedent. Also reused
    (roadmap 58d88fe0) as Plan B's send_timeout_seconds -- the TOTAL
    wall-clock deadline asyncio.wait_for gives a single sender.send call,
    so a job stuck longer than this window releases the send_semaphore
    slot on the same schedule the reaper would consider its row stale.

    send_semaphore (S4, ADR 0003 Phase 6b tranche 4): bounds how many sends
    this evaluator is actively AWAITING at once -- not a hard ceiling on
    threads actually running, since an orphaned send past its own timeout
    keeps its thread alive in the background regardless. By default a FRESH
    Semaphore(max_concurrent_sends) is built per call -- correct for the
    common case (one evaluate_tick at a time, e.g. `kerdoos digest`).
    run_evaluator_loop builds ONE semaphore and reuses it across every tick
    of its loop. A caller that genuinely drives multiple evaluate_tick
    invocations CONCURRENTLY (e.g. an overlapping intra-process loop tick
    plus an external `kerdoos digest` against the same process) must pass
    the SAME send_semaphore instance to each call for this bound to hold
    across them -- an in-process asyncio.Semaphore can only cap concurrency
    among callers that share the object, never across separate processes
    (that boundary is covered by should_start_intra_process_evaluator's
    workers<=1 guard-rail plus the per-job DB-level has_active_job_run
    singleton, which IS cross-process).

    send_executor (roadmap 1c67e5b2): the dedicated pool Plan B's sends run
    on, isolated from Plan A's scrape pool. By default a fresh, per-send
    daemon-thread executor is built and shut down after (roadmap 3c0b1c80 a
    -- never a ThreadPoolExecutor here, or an orphaned send would block
    process exit on the CLI's short-lived `kerdoos digest` path).
    run_evaluator_loop instead passes its own long-lived, self-rotating
    _RotatingSendExecutor, shared across every tick like send_semaphore."""
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

    await _reap_stale_job_runs(
        jobs=jobs, state_store=state_store, tick_now=tick_now,
        reaper_timeout_seconds=reaper_timeout_seconds,
    )

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
    owns_executor = send_executor is None
    executor = (
        send_executor if send_executor is not None
        else _DaemonThreadSendExecutor())
    try:
        await _run_plan_b(
            jobs=jobs, source_index=source_index, state_store=state_store,
            sender=sender, now_iso=now_iso, tick_now=tick_now, summary=summary,
            send_semaphore=semaphore, send_executor=executor,
            send_timeout_seconds=reaper_timeout_seconds,
        )
    finally:
        if owns_executor:
            executor.shutdown()
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
    reaper_timeout_seconds: int = 300,
) -> None:
    """Intra-process timer: evaluate_tick every tick_seconds until
    stop_event is set. A crashing tick is caught and logged so it never
    kills the loop (the same per-item resilience discipline as Plan A/B,
    applied one level up).

    reaper_timeout_seconds is forwarded to every evaluate_tick call as-is
    (see evaluate_tick's docstring). interfaces/web/app.py's lifespan passes
    Settings.digest_reaper_timeout_seconds explicitly (roadmap 58d88fe0);
    callers that omit it fall back to the 300s function default.

    Builds ONE send_semaphore (S4) and ONE send_executor (roadmap 1c67e5b2)
    here and reuses both across every tick of this loop -- ticks of the SAME
    loop never overlap (each await blocks the next), but sharing one
    instance is simpler than rebuilding it every iteration and matches
    run_evaluator_loop's role as a single persistent evaluator. The
    send_executor may internally rotate itself after a stuck send; this
    loop only owns its final shutdown on exit."""
    event = stop_event if stop_event is not None else asyncio.Event()
    send_semaphore = asyncio.Semaphore(max_concurrent_sends)
    send_executor = _RotatingSendExecutor(max_workers=max(max_concurrent_sends, 1))
    try:
        while not event.is_set():
            try:
                await evaluate_tick(
                    config_store=config_store, state_store=state_store,
                    router=router, parser_factory=parser_factory, sender=sender,
                    send_semaphore=send_semaphore, send_executor=send_executor,
                    reaper_timeout_seconds=reaper_timeout_seconds,
                )
            except Exception:  # noqa: BLE001 -- one crashed tick must not kill the loop
                logger.exception("evaluator: tick failed unexpectedly")
            try:
                await asyncio.wait_for(event.wait(), timeout=tick_seconds)
            except asyncio.TimeoutError:
                pass
    finally:
        send_executor.shutdown()
