"""Digest-jobs asyncio evaluator (Phase 6b tranche 2, ADR 0003 Decisions 3/4/8).

Exercises evaluate_tick end-to-end (Plan A scrape-dedup + Plan B per-job
notify) through the real SqliteConfigStore/SqliteStateStore, with a fake
Router/Fetcher/Parser (no real network) and a recording DigestSender double.
A couple of edge cases (dangling job_source link, per-source router failure)
are exercised directly against the private _run_plan_a helper, since they are
either impossible to reproduce through the public API (FK ON DELETE CASCADE
on digest_job_sources) or awkward to trigger end-to-end.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from autolycos import router as router_mod
from autolycos.ports import FetchResult
from autolycos.router import StaticRouter

from kerdoos.core.app.services import AppService, DigestJobSpec, Principal, ProductSpec
from kerdoos.core.domain import Availability, Extract, ScrapeStatus
from kerdoos.core.evaluator import (
    _run_plan_a,
    _EmptyDigestWarningTracker,
    _RotatingSendExecutor,
    EvaluationSummary,
    evaluate_tick,
    should_start_intra_process_evaluator,
)
from kerdoos.core.scheduler import compute_window_start
from kerdoos.parsers.factory import build_parser
from kerdoos.parsers.ports import ParserSpec
from kerdoos.persistence.ports import JobRun, ScrapeRecord
from kerdoos.persistence.sqlite_store import SqliteStateStore
from kerdoos.registry.domain_policy import CatalogueDomainPolicy
from kerdoos.registry.ports import DigestJob, SiteConfig
from kerdoos.registry.sqlite_store import SqliteConfigStore

_SITE = SiteConfig(
    name="kabum", fetcher="http", domain="kabum.com.br",
    parser=ParserSpec(kind="statejson", pix="a", card="b", availability="c"),
)
_BROKEN_SITE = SiteConfig(
    name="brokensite", fetcher="broken", domain="broken.example",
    parser=ParserSpec(kind="statejson", pix="a", card="b", availability="c"),
)


@contextmanager
def _tier_forced_available(tier: str):
    """"broken" is not a real tier (card 3aeb8a19 F1: tier_available is now
    fail-closed on any unknown name), so adding a source against it through
    AppService.add_source's REAL StaticRouter (self.service below) would be
    rejected. This fixture's actual intent is a ROUTING failure INSIDE the
    per-test local _StubRouter used for the scrape itself, not a deployment-
    tier problem -- force "broken" available for the add_source call only."""
    with mock.patch.dict(router_mod._TIER_MODULES, {tier: None}):
        yield


class _FakeFetcher:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def fetch(self, url: str) -> FetchResult:
        self.calls.append(url)
        return FetchResult(html="<html></html>", status=200, method="http",
                           challenged=False)


class _StubRouter:
    """Router.select keyed by fetcher_name. A mapped BaseException instance
    is raised instead of returning a Fetcher, to simulate a per-source
    routing failure. tier_available defaults to always-True (this double
    models routing, not deployment-tier availability) -- pass `unavailable`
    to simulate card 3aeb8a19's guard rejecting specific tiers."""

    def __init__(
        self, mapping: dict[str, object], unavailable: frozenset[str] = frozenset(),
    ) -> None:
        self._mapping = mapping
        self._unavailable = unavailable

    def select(self, fetcher_name: str, subresource_domains=()):
        target = self._mapping[fetcher_name]
        if isinstance(target, BaseException):
            raise target
        return target

    def tier_available(self, fetcher_name: str) -> bool:
        return fetcher_name not in self._unavailable


class _FakeParser:
    def extract(self, html: str) -> Extract:
        return Extract(
            price_pix_cents=100, price_card_cents=110, currency="BRL",
            availability=Availability.IN_STOCK,
        )


def _fake_parser_factory(spec: ParserSpec) -> _FakeParser:
    return _FakeParser()


@dataclass
class _SendCall:
    job: DigestJob
    records: list
    generated_at: str
    tier2_labels: dict


class _RecordingSender:
    """DigestSender double: records every successful send(); raises for any
    job whose name is in fail_for (Plan B per-job error-path tests); returns
    False (owner has no email, ADR 0003 Decision 9) for any job whose name is
    in no_email_for -- item 3 of the Phase 6b fast-follow bundle."""

    def __init__(
        self, fail_for: frozenset[str] = frozenset(),
        no_email_for: frozenset[str] = frozenset(),
    ) -> None:
        self.calls: list[_SendCall] = []
        self._fail_for = fail_for
        self._no_email_for = no_email_for

    def send(self, job, records, generated_at, tier2_labels) -> bool:
        if job.name in self._fail_for:
            raise RuntimeError(f"send failed for job {job.name!r}")
        if job.name in self._no_email_for:
            return False
        self.calls.append(_SendCall(
            job, list(records), generated_at, dict(tier2_labels)))
        return True


class _EvaluatorTestBase(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        d = Path(self._tmp.name)
        self.config = SqliteConfigStore(d / "config.db")
        self.state = SqliteStateStore(d / "state.db")
        domain_policy = CatalogueDomainPolicy(self.config)
        static_router = StaticRouter(domain_policy)
        self.service = AppService(
            self.config, self.state, static_router, domain_policy, build_parser)
        self.config.add_site(_SITE)
        self.config.add_site(_BROKEN_SITE)
        self.fetcher = _FakeFetcher()
        self.router = _StubRouter({"http": self.fetcher})

    def tearDown(self) -> None:
        self.config.close()
        self.state.close()
        self._tmp.cleanup()

    def _add_source(
        self, owner: str, product_key: str, url: str, site: str = "kabum",
    ) -> str:
        self.service.add_product(owner, ProductSpec(product_key))
        source = self.service.add_source(owner, product_key, site, url)
        return source.source_id

    def _seed_history(
        self, owner: str, source_id: str, ts: datetime,
        status: ScrapeStatus = ScrapeStatus.OK,
    ) -> None:
        self.state.record(owner, ScrapeRecord(
            source_id=source_id, ts=ts.isoformat(), status=status,
            price_pix_cents=100, price_card_cents=110, currency="BRL",
            availability=Availability.IN_STOCK, method="http", error=None,
        ))


class PureFunctionTest(unittest.TestCase):
    def test_workers_le_1_allows_intra_process_start(self) -> None:
        self.assertTrue(should_start_intra_process_evaluator(1))
        self.assertTrue(should_start_intra_process_evaluator(0))

    def test_workers_gt_1_refuses_intra_process_start(self) -> None:
        self.assertFalse(should_start_intra_process_evaluator(2))
        self.assertFalse(should_start_intra_process_evaluator(8))


class EmptyTickTest(_EvaluatorTestBase):
    async def test_no_jobs_returns_zero_summary_no_crash(self) -> None:
        summary = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=_RecordingSender(),
        )
        self.assertEqual(summary, EvaluationSummary())


class PlanAScrapeDedupTest(_EvaluatorTestBase):
    async def test_scrapes_source_with_no_prior_history(self) -> None:
        sid = self._add_source("owner1", "p1", "https://www.kabum.com.br/p/1")
        self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly", source_ids=(sid,)))
        summary = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=_RecordingSender(),
        )
        self.assertEqual(summary.scraped_sources, 1)
        self.assertEqual(self.fetcher.calls, ["https://www.kabum.com.br/p/1"])

    async def test_skips_fresh_source_below_its_own_period(self) -> None:
        sid = self._add_source("owner1", "p1", "https://www.kabum.com.br/p/1")
        self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="hourly-job", frequency_kind="daily",
                          source_ids=(sid,)))  # period ~= 1 day
        tick_now = datetime(2026, 7, 13, 10, 7, 0, tzinfo=timezone.utc)
        self._seed_history("owner1", sid, tick_now - _minutes(10))
        summary = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=_RecordingSender(), now=tick_now,
        )
        self.assertEqual(summary.scraped_sources, 0)
        self.assertEqual(self.fetcher.calls, [])

    async def test_cadence_union_across_jobs_uses_the_minimum_period(self) -> None:
        # job A wants this source every 5 minutes, job B only hourly -- Plan
        # A must scrape using the SHORTER (union) period, not job B's alone.
        sid = self._add_source("owner1", "p1", "https://www.kabum.com.br/p/1")
        self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="fast-job", frequency_kind="cron",
                          cron_expr="*/5 * * * *", source_ids=(sid,)))
        self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="slow-job", frequency_kind="cron",
                          cron_expr="0 * * * *", source_ids=(sid,)))
        tick_now = datetime(2026, 7, 13, 10, 7, 0, tzinfo=timezone.utc)
        # 10 minutes stale: stale for the 5-minute union period, fresh for
        # the hourly period alone.
        self._seed_history("owner1", sid, tick_now - _minutes(10))
        summary = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=_RecordingSender(), now=tick_now,
        )
        self.assertEqual(summary.scraped_sources, 1)
        # Dedup: exactly ONE scrape serves both referencing jobs.
        self.assertEqual(len(self.fetcher.calls), 1)

    async def test_per_source_router_failure_does_not_abort_the_tick(self) -> None:
        good_sid = self._add_source(
            "owner1", "p1", "https://www.kabum.com.br/p/1", site="kabum")
        with _tier_forced_available("broken"):
            bad_sid = self._add_source(
                "owner1", "p2", "https://broken.example/p/2", site="brokensite")
        self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly",
                          source_ids=(good_sid, bad_sid)))
        router = _StubRouter({
            "http": self.fetcher,
            "broken": RuntimeError("router blew up"),
        })
        summary = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=router, parser_factory=_fake_parser_factory,
            sender=_RecordingSender(),
        )
        self.assertEqual(summary.scraped_sources, 1)
        self.assertEqual(summary.errors, 1)
        self.assertEqual(self.fetcher.calls, ["https://www.kabum.com.br/p/1"])

    async def test_source_with_unavailable_tier_writes_no_record_across_ticks(
        self,
    ) -> None:
        # Card 3aeb8a19 BLOCKER: _run_plan_a is the PRODUCTION scrape path
        # (WebUI lifespan evaluator + `kerdoos digest` cron) -- it must skip
        # an unavailable tier identically to AppService.run_now, not just log
        # an error and retry forever every tick.
        good_sid = self._add_source(
            "owner1", "p1", "https://www.kabum.com.br/p/1", site="kabum")
        with _tier_forced_available("broken"):
            bad_sid = self._add_source(
                "owner1", "p2", "https://broken.example/p/2", site="brokensite")
        self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly",
                          source_ids=(good_sid, bad_sid)))
        router = _StubRouter(
            {"http": self.fetcher, "broken": RuntimeError("must not be called")},
            unavailable=frozenset({"broken"}),
        )
        for _ in range(2):
            summary = await evaluate_tick(
                config_store=self.config, state_store=self.state,
                router=router, parser_factory=_fake_parser_factory,
                sender=_RecordingSender(),
            )
        self.assertEqual(summary.errors, 0)
        self.assertEqual(self.state.history("owner1", bad_sid, limit=10), [])
        self.assertEqual(self.fetcher.calls, ["https://www.kabum.com.br/p/1"])


class PlanADanglingLinkTest(_EvaluatorTestBase):
    async def test_dangling_job_source_is_skipped_silently(self) -> None:
        # White-box: a source_id present on the job but ABSENT from the
        # owner's source_index (the "config drifted after the job linked
        # it" case) must be skipped without incrementing errors.
        job = DigestJob(
            id="job1", owner_id="owner1", name="job1",
            frequency_kind="hourly", schedule_cron="0 * * * *",
            source_ids=("dangling-source",),
        )
        summary = EvaluationSummary()
        await _run_plan_a(
            jobs=(job,), source_index={"owner1": {}}, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            tick_now=datetime(2026, 7, 13, 10, 0, 0, tzinfo=timezone.utc),
            now_iso="2026-07-13T10:00:00+00:00", summary=summary,
        )
        self.assertEqual(summary.scraped_sources, 0)
        self.assertEqual(summary.errors, 0)


class PlanBNotifyTest(_EvaluatorTestBase):
    async def test_notifies_job_and_marks_job_run_sent(self) -> None:
        sid = self._add_source("owner1", "p1", "https://www.kabum.com.br/p/1")
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly",
                          source_ids=(sid,)))
        tick_now = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        self._seed_history("owner1", sid, tick_now - _minutes(1))
        sender = _RecordingSender()
        summary = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=sender, now=tick_now,
        )
        self.assertEqual(summary.notified_jobs, 1)
        self.assertEqual(len(sender.calls), 1)
        self.assertEqual(sender.calls[0].job.id, job.id)
        self.assertEqual(len(sender.calls[0].records), 1)
        window_start = compute_window_start(job.schedule_cron, job.timezone, tick_now)
        self.assertTrue(self.state.has_active_job_run("owner1", job.id) is False)
        # sent is terminal -- confirmed indirectly via the idempotence tests
        # below (a second tick in the SAME window must be a no-op).
        self.assertIsNotNone(window_start)

    async def test_coalescing_skips_a_still_active_job_run(self) -> None:
        sid = self._add_source("owner1", "p1", "https://www.kabum.com.br/p/1")
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly",
                          source_ids=(sid,)))
        tick_now = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        self._seed_history("owner1", sid, tick_now - _minutes(1))
        window_start = compute_window_start(job.schedule_cron, job.timezone, tick_now)
        self.state.record_job_run(JobRun(
            job_id=job.id, owner_id="owner1", window_start=window_start,
            fired_at=tick_now.isoformat(), status="running",
        ))
        sender = _RecordingSender()
        summary = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=sender, now=tick_now,
        )
        self.assertEqual(summary.skipped_jobs, 1)
        self.assertEqual(summary.notified_jobs, 0)
        self.assertEqual(sender.calls, [])

    async def test_idempotent_across_ticks_within_the_same_window(self) -> None:
        # Two DIFFERENT tick timestamps that fall in the SAME hourly cron
        # window must resolve to the SAME window_start (quantized, never the
        # raw tick) -- the second tick must be a no-op, not a re-send.
        sid = self._add_source("owner1", "p1", "https://www.kabum.com.br/p/1")
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly",
                          source_ids=(sid,)))
        tick1 = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        tick2 = datetime(2026, 7, 13, 10, 55, 0, tzinfo=timezone.utc)
        self._seed_history("owner1", sid, tick1 - _minutes(1))
        sender = _RecordingSender()
        summary1 = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=sender, now=tick1,
        )
        summary2 = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=sender, now=tick2,
        )
        self.assertEqual(summary1.notified_jobs, 1)
        self.assertEqual(summary2.notified_jobs, 0)
        self.assertEqual(summary2.skipped_jobs, 1)
        self.assertEqual(len(sender.calls), 1)

    async def test_sender_error_transitions_job_run_to_error_and_continues(self) -> None:
        sid1 = self._add_source("owner1", "p1", "https://www.kabum.com.br/p/1")
        sid2 = self._add_source("owner1", "p2", "https://www.kabum.com.br/p/2")
        self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="failing-job", frequency_kind="hourly",
                          source_ids=(sid1,)))
        self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="ok-job", frequency_kind="hourly",
                          source_ids=(sid2,)))
        tick_now = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        self._seed_history("owner1", sid1, tick_now - _minutes(1))
        self._seed_history("owner1", sid2, tick_now - _minutes(1))
        sender = _RecordingSender(fail_for=frozenset({"failing-job"}))
        summary = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=sender, now=tick_now,
        )
        self.assertEqual(summary.errors, 1)
        self.assertEqual(summary.notified_jobs, 1)
        self.assertEqual([c.job.name for c in sender.calls], ["ok-job"])

    async def test_owner_without_email_persists_skipped_no_email_not_sent(self) -> None:
        """Phase 6b fast-follow item 3: send() returning False (owner has no
        email, ADR 0003 Decision 9) must NOT be recorded as 'sent' -- it
        must persist the observability-correct 'skipped_no_email' status,
        distinguishable from a real send in job_runs."""
        sid = self._add_source("owner1", "p1", "https://www.kabum.com.br/p/1")
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="no-email-job", frequency_kind="hourly",
                          source_ids=(sid,)))
        tick_now = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        self._seed_history("owner1", sid, tick_now - _minutes(1))
        sender = _RecordingSender(no_email_for=frozenset({"no-email-job"}))

        summary = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=sender, now=tick_now,
        )

        self.assertEqual(summary.notified_jobs, 0)
        self.assertEqual(summary.skipped_jobs, 1)
        self.assertEqual(summary.errors, 0)
        # send() was invoked (returned False) but never RECORDED as a call
        # -- proves the evaluator branched on the bool return, not just
        # "no exception raised".
        self.assertEqual(sender.calls, [])
        window_start = compute_window_start(job.schedule_cron, job.timezone, tick_now)
        with self.state._op() as conn:
            row = conn.execute(
                "SELECT status FROM job_runs WHERE job_id=? AND window_start=?",
                (job.id, window_start),
            ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "skipped_no_email")


class ReaperStaleJobRunEndToEndTest(_EvaluatorTestBase):
    """Phase 6b fast-follow item 2 (RELIABILITY, architect addendum):
    reaper/TTL sweep exercised through the real evaluate_tick entry point,
    proving the full contract -- reap to terminal 'error' (never DELETE),
    at-most-once for the SAME window (no double-send), recovery only at the
    NEXT window_start."""

    async def test_stranded_row_reaped_no_same_window_refire_recovers_next_window(self) -> None:
        sid = self._add_source("owner1", "p1", "https://www.kabum.com.br/p/1")
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly", source_ids=(sid,)))
        tick_now = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        self._seed_history("owner1", sid, tick_now - _minutes(1))
        window_start = compute_window_start(job.schedule_cron, job.timezone, tick_now)
        # Simulate a crash mid-send on a PREVIOUS tick within the SAME
        # window: fired 10 minutes ago -- older than the default 300s/5min
        # reaper bound -- and still stuck in 'running'.
        stranded_fired_at = (tick_now - timedelta(minutes=10)).isoformat()
        self.state.record_job_run(JobRun(
            job_id=job.id, owner_id="owner1", window_start=window_start,
            fired_at=stranded_fired_at, status="running",
        ))
        sender = _RecordingSender()

        summary = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=sender, now=tick_now,
        )

        # Reaped to terminal 'error' -- proven by has_active_job_run
        # flipping to False (a stranded row left un-reaped would block this
        # job's per-job singleton coalescing FOREVER).
        self.assertFalse(self.state.has_active_job_run("owner1", job.id))
        with self.state._op() as conn:
            row = conn.execute(
                "SELECT status FROM job_runs WHERE job_id=? AND window_start=?",
                (job.id, window_start),
            ).fetchone()
        self.assertEqual(row["status"], "error")
        # No send for the SAME window: record_job_run's ON CONFLICT DO
        # NOTHING blocks the re-insert (the PK survives the reap -- UPDATE,
        # never DELETE) -- at-most-once for that window, NOT a re-fire.
        self.assertEqual(sender.calls, [])
        self.assertEqual(summary.notified_jobs, 0)

        # Recovery happens at the NEXT window_start, not a same-window retry.
        next_tick = tick_now + timedelta(hours=1)
        next_window_start = compute_window_start(job.schedule_cron, job.timezone, next_tick)
        self.assertNotEqual(next_window_start, window_start)
        self._seed_history("owner1", sid, next_tick - _minutes(1))

        summary2 = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=sender, now=next_tick,
        )

        self.assertEqual(summary2.notified_jobs, 1)
        self.assertEqual(len(sender.calls), 1)
        self.assertEqual(sender.calls[0].job.id, job.id)

    async def test_fresh_in_flight_row_is_not_reaped_and_still_coalesces(self) -> None:
        """Control case: a row fired WITHIN the timeout bound must be left
        alone by the reaper and still coalesce the tick (has_active_job_run
        stays True) -- proves the timeout threshold itself is what
        distinguishes stranded from legitimately in-flight."""
        sid = self._add_source("owner1", "p1", "https://www.kabum.com.br/p/1")
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly", source_ids=(sid,)))
        tick_now = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        self._seed_history("owner1", sid, tick_now - _minutes(1))
        window_start = compute_window_start(job.schedule_cron, job.timezone, tick_now)
        fresh_fired_at = (tick_now - timedelta(minutes=1)).isoformat()
        self.state.record_job_run(JobRun(
            job_id=job.id, owner_id="owner1", window_start=window_start,
            fired_at=fresh_fired_at, status="running",
        ))
        sender = _RecordingSender()

        summary = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=sender, now=tick_now,
        )

        self.assertTrue(self.state.has_active_job_run("owner1", job.id))
        self.assertEqual(sender.calls, [])
        self.assertEqual(summary.skipped_jobs, 1)
        self.assertEqual(summary.notified_jobs, 0)


class ReapStaleJobRunUnitTest(unittest.TestCase):
    """StateStore.reap_stale_job_run edge cases (Phase 6b fast-follow item
    2), exercised directly against SqliteStateStore -- no evaluator
    involved."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.state = SqliteStateStore(Path(self._tmp.name) / "state.db")

    def tearDown(self) -> None:
        self.state.close()
        self._tmp.cleanup()

    def _status(self, job_id: str, window_start: str) -> str | None:
        with self.state._op() as conn:
            row = conn.execute(
                "SELECT status FROM job_runs WHERE job_id=? AND window_start=?",
                (job_id, window_start),
            ).fetchone()
        return row["status"] if row is not None else None

    def test_missing_row_returns_false_never_raises(self) -> None:
        result = self.state.reap_stale_job_run(
            "owner1", "no-such-job", fired_before="2026-07-13T10:00:00+00:00")
        self.assertFalse(result)

    def test_already_terminal_row_is_a_no_op(self) -> None:
        self.state.record_job_run(JobRun(
            job_id="job1", owner_id="owner1",
            window_start="2026-07-13T10:00:00+00:00",
            fired_at="2026-07-13T09:00:00+00:00", status="sent",
            sent_at="2026-07-13T09:00:05+00:00",
        ))
        result = self.state.reap_stale_job_run(
            "owner1", "job1", fired_before="2026-07-13T23:59:59+00:00")
        self.assertFalse(result)
        self.assertEqual(
            self._status("job1", "2026-07-13T10:00:00+00:00"), "sent")

    def test_owner_scoping_never_cross_reaps(self) -> None:
        """IDOR-safe double-scoping (mirrors has_active_job_run's discipline,
        architect's explicit owner-scope requirement): a stale row under a
        DIFFERENT owner must never be reaped by a call scoped to the wrong
        owner, even with a colliding job_id."""
        self.state.record_job_run(JobRun(
            job_id="shared-job-id", owner_id="victim-owner",
            window_start="2026-07-13T10:00:00+00:00",
            fired_at="2026-07-13T09:00:00+00:00", status="running",
        ))
        result = self.state.reap_stale_job_run(
            "attacker-owner", "shared-job-id",
            fired_before="2026-07-13T23:59:59+00:00")
        self.assertFalse(result)
        self.assertEqual(
            self._status("shared-job-id", "2026-07-13T10:00:00+00:00"),
            "running")

    def test_stale_queued_or_running_row_is_reaped_to_terminal_error(self) -> None:
        self.state.record_job_run(JobRun(
            job_id="job1", owner_id="owner1",
            window_start="2026-07-13T10:00:00+00:00",
            fired_at="2026-07-13T09:50:00+00:00", status="queued",
        ))
        result = self.state.reap_stale_job_run(
            "owner1", "job1", fired_before="2026-07-13T09:55:00+00:00")
        self.assertTrue(result)
        self.assertEqual(
            self._status("job1", "2026-07-13T10:00:00+00:00"), "error")

    def test_fresh_row_not_older_than_bound_is_left_untouched(self) -> None:
        self.state.record_job_run(JobRun(
            job_id="job1", owner_id="owner1",
            window_start="2026-07-13T10:00:00+00:00",
            fired_at="2026-07-13T09:59:00+00:00", status="running",
        ))
        result = self.state.reap_stale_job_run(
            "owner1", "job1", fired_before="2026-07-13T09:55:00+00:00")
        self.assertFalse(result)
        self.assertEqual(
            self._status("job1", "2026-07-13T10:00:00+00:00"), "running")


class _SlowRecordingSender:
    """DigestSender double whose send() blocks briefly on a real thread
    (matching evaluate_tick's asyncio.to_thread dispatch) and tracks the
    peak number of CONCURRENTLY active send() calls -- the S4 acceptance
    signal (ADR 0003 Phase 6b tranche 4, finding S4)."""

    def __init__(self, delay: float = 0.05) -> None:
        self._delay = delay
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.calls: list[str] = []

    def send(self, job, records, generated_at, tier2_labels) -> bool:
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        time.sleep(self._delay)
        with self._lock:
            self.calls.append(job.name)
            self.active -= 1
        return True


class PlanBConcurrencyCeilingTest(unittest.IsolatedAsyncioTestCase):
    """S4: a global concurrent-sends ceiling, on top of the per-job
    singleton (has_active_job_run). Two INDEPENDENT evaluate_tick calls
    (simulating two overlapping ticks/workers) share ONE explicitly
    constructed asyncio.Semaphore via send_semaphore= -- the only way the
    ceiling can hold ACROSS separate evaluate_tick invocations, per
    evaluate_tick's own docstring."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._stores: list[tuple] = []

    def tearDown(self) -> None:
        for config, state in self._stores:
            config.close()
            state.close()
        self._tmp.cleanup()

    def _make_owner_job(self, owner: str, tick_now: datetime) -> tuple:
        d = Path(self._tmp.name) / owner
        d.mkdir()
        config = SqliteConfigStore(d / "config.db")
        state = SqliteStateStore(d / "state.db")
        self._stores.append((config, state))
        domain_policy = CatalogueDomainPolicy(config)
        static_router = StaticRouter(domain_policy)
        service = AppService(config, state, static_router, domain_policy, build_parser)
        config.add_site(_SITE)
        service.add_product(owner, ProductSpec("p1"))
        source = service.add_source(
            owner, "p1", "kabum", f"https://www.kabum.com.br/p/{owner}")
        job = service.create_job(
            Principal(owner_id=owner),
            DigestJobSpec(name=f"job-{owner}", frequency_kind="hourly",
                          source_ids=(source.source_id,)))
        state.record(owner, ScrapeRecord(
            source_id=source.source_id, ts=(tick_now - _minutes(1)).isoformat(),
            status=ScrapeStatus.OK, price_pix_cents=100, price_card_cents=110,
            currency="BRL", availability=Availability.IN_STOCK, method="http",
            error=None,
        ))
        return config, state, job

    async def test_ceiling_of_one_serializes_two_concurrent_ticks(self) -> None:
        tick_now = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        config_a, state_a, _job_a = self._make_owner_job("ownera", tick_now)
        config_b, state_b, _job_b = self._make_owner_job("ownerb", tick_now)
        router = _StubRouter({"http": _FakeFetcher()})
        sender = _SlowRecordingSender(delay=0.05)
        semaphore = asyncio.Semaphore(1)

        summary_a, summary_b = await asyncio.gather(
            evaluate_tick(
                config_store=config_a, state_store=state_a, router=router,
                parser_factory=_fake_parser_factory, sender=sender, now=tick_now,
                max_concurrent_sends=1, send_semaphore=semaphore,
            ),
            evaluate_tick(
                config_store=config_b, state_store=state_b, router=router,
                parser_factory=_fake_parser_factory, sender=sender, now=tick_now,
                max_concurrent_sends=1, send_semaphore=semaphore,
            ),
        )
        self.assertEqual(summary_a.notified_jobs, 1)
        self.assertEqual(summary_b.notified_jobs, 1)
        self.assertEqual(len(sender.calls), 2)
        # The ceiling of 1 must hold ACROSS both evaluate_tick calls: never
        # more than one send() in flight at the same instant.
        self.assertEqual(sender.max_active, 1)

    async def test_higher_ceiling_actually_allows_overlap_control_case(self) -> None:
        # Proves the harness itself detects overlap (i.e. test 1 above is
        # not vacuously passing): with a ceiling >= 2 shared across the
        # same two concurrent ticks, both sends legitimately overlap.
        tick_now = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        config_a, state_a, _job_a = self._make_owner_job("ownera", tick_now)
        config_b, state_b, _job_b = self._make_owner_job("ownerb", tick_now)
        router = _StubRouter({"http": _FakeFetcher()})
        sender = _SlowRecordingSender(delay=0.05)
        semaphore = asyncio.Semaphore(2)

        await asyncio.gather(
            evaluate_tick(
                config_store=config_a, state_store=state_a, router=router,
                parser_factory=_fake_parser_factory, sender=sender, now=tick_now,
                max_concurrent_sends=2, send_semaphore=semaphore,
            ),
            evaluate_tick(
                config_store=config_b, state_store=state_b, router=router,
                parser_factory=_fake_parser_factory, sender=sender, now=tick_now,
                max_concurrent_sends=2, send_semaphore=semaphore,
            ),
        )
        self.assertEqual(len(sender.calls), 2)
        self.assertEqual(sender.max_active, 2)


def _minutes(n: int):
    from datetime import timedelta
    return timedelta(minutes=n)


class _PerJobDelaySender:
    """DigestSender double whose send() delay is keyed by job.name -- lets a
    single evaluate_tick call exercise one job that overruns the total send
    deadline and one that completes well within it, in the SAME tick."""

    def __init__(self, delays: dict[str, float]) -> None:
        self._delays = delays
        self.calls: list[str] = []

    def send(self, job, records, generated_at, tier2_labels) -> bool:
        time.sleep(self._delays.get(job.name, 0.0))
        self.calls.append(job.name)
        return True


class PlanBSendTotalDeadlineTest(unittest.IsolatedAsyncioTestCase):
    """roadmap 58d88fe0: SmtpSettings.timeout_seconds only bounds a SINGLE
    smtplib operation, not the whole send -- a slow-but-alive relay could
    hold the send_semaphore slot far longer than reaper_timeout_seconds
    without a TOTAL deadline. evaluate_tick wraps sender.send in
    asyncio.wait_for(..., timeout=reaper_timeout_seconds) so one stuck job
    cannot block the rest of the SAME tick."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    async def test_one_job_overrunning_the_deadline_does_not_block_the_next(
        self,
    ) -> None:
        tick_now = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        config = SqliteConfigStore(Path(self._tmp.name) / "config.db")
        state = SqliteStateStore(Path(self._tmp.name) / "state.db")
        self.addCleanup(config.close)
        self.addCleanup(state.close)
        domain_policy = CatalogueDomainPolicy(config)
        router = _StubRouter({"http": _FakeFetcher()})
        service = AppService(config, state, router, domain_policy, build_parser)
        config.add_site(_SITE)

        for owner in ("slow-owner", "fast-owner"):
            service.add_product(owner, ProductSpec("p1"))
            source = service.add_source(
                owner, "p1", "kabum", f"https://www.kabum.com.br/p/{owner}")
            service.create_job(
                Principal(owner_id=owner),
                DigestJobSpec(name=f"job-{owner}", frequency_kind="hourly",
                              source_ids=(source.source_id,)))
            state.record(owner, ScrapeRecord(
                source_id=source.source_id, ts=(tick_now - _minutes(1)).isoformat(),
                status=ScrapeStatus.OK, price_pix_cents=100, price_card_cents=110,
                currency="BRL", availability=Availability.IN_STOCK, method="http",
                error=None,
            ))

        sender = _PerJobDelaySender({"job-slow-owner": 5.0, "job-fast-owner": 0.0})

        summary = await evaluate_tick(
            config_store=config, state_store=state, router=router,
            parser_factory=_fake_parser_factory, sender=sender, now=tick_now,
            max_concurrent_sends=1, reaper_timeout_seconds=0.5,
        )

        # Without the total deadline, job-slow-owner's send() would still be
        # blocking the loop when this assertion runs -- job-fast-owner would
        # never have been attempted in the SAME tick.
        self.assertIn("job-fast-owner", sender.calls)
        self.assertEqual(summary.notified_jobs, 1)
        self.assertEqual(summary.errors, 1)


class _HangingThenFastSender:
    """DigestSender double: job "job-slow" blocks FOREVER (a real OS thread
    that cannot be cancelled once orphaned by wait_for's timeout); any other
    job returns immediately."""

    def __init__(self, hang_forever: threading.Event) -> None:
        self._hang_forever = hang_forever
        self.calls: list[str] = []

    def send(self, job, records, generated_at, tier2_labels) -> bool:
        if job.name == "job-slow":
            self._hang_forever.wait()
        self.calls.append(job.name)
        return True


class PlanBDedicatedExecutorTest(unittest.IsolatedAsyncioTestCase):
    """roadmap 1c67e5b2: Plan B's sender.send() must run on its OWN bounded
    executor, never asyncio's shared default one that Plan A's
    to_thread(scrape_and_record) also uses -- otherwise an orphaned send
    thread (wait_for cancels the await, never the underlying OS thread)
    permanently occupies a slot in the shared pool and eventually starves
    the scrape path too."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._never_set = threading.Event()  # the orphaned thread's prison
        # concurrent.futures.thread registers every worker thread it ever
        # starts in a process-wide registry that atexit JOINS on interpreter
        # shutdown, regardless of whether the ThreadPoolExecutor object
        # itself is still referenced. Release the thread at teardown so it
        # cannot hang the whole test process after this test is done with it.
        self.addCleanup(self._never_set.set)

    async def test_a_stuck_send_does_not_starve_a_later_scrape(self) -> None:
        loop = asyncio.get_running_loop()
        # Constrain the DEFAULT executor to a single worker (mirrors the
        # small-vCPU target from the roadmap card: min(32, cpu+4) shrinks to
        # a handful of workers there) so a single orphaned thread is enough
        # to starve it deterministically, without a real multi-hour leak.
        loop.set_default_executor(ThreadPoolExecutor(max_workers=1))

        tick1 = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        tick2 = tick1 + timedelta(hours=2)  # still the same UTC day

        config = SqliteConfigStore(Path(self._tmp.name) / "config.db")
        state = SqliteStateStore(Path(self._tmp.name) / "state.db")
        self.addCleanup(config.close)
        self.addCleanup(state.close)
        domain_policy = CatalogueDomainPolicy(config)
        router = _StubRouter({"http": _FakeFetcher()})
        service = AppService(config, state, router, domain_policy, build_parser)
        config.add_site(_SITE)

        # slow-owner: its OWN source is already fresh (Plan A never needs to
        # scrape it), so the only thing this job contributes is a send()
        # that never returns. Daily frequency keeps BOTH ticks in the same
        # idempotence window, so tick2 never attempts a second hanging send.
        service.add_product("slow-owner", ProductSpec("p1"))
        slow_source = service.add_source(
            "slow-owner", "p1", "kabum", "https://www.kabum.com.br/p/slow")
        service.create_job(
            Principal(owner_id="slow-owner"),
            DigestJobSpec(name="job-slow", frequency_kind="daily",
                          source_ids=(slow_source.source_id,)))
        state.record("slow-owner", ScrapeRecord(
            source_id=slow_source.source_id, ts=(tick1 - _minutes(1)).isoformat(),
            status=ScrapeStatus.OK, price_pix_cents=100, price_card_cents=110,
            currency="BRL", availability=Availability.IN_STOCK, method="http",
            error=None,
        ))

        # scrape-owner: no history seeded, hourly job -- needs a fresh
        # scrape on EVERY tick this test drives. This is what must keep
        # progressing regardless of what happens on the send side.
        service.add_product("scrape-owner", ProductSpec("p1"))
        scrape_source = service.add_source(
            "scrape-owner", "p1", "kabum", "https://www.kabum.com.br/p/scrape")
        service.create_job(
            Principal(owner_id="scrape-owner"),
            DigestJobSpec(name="job-scrape", frequency_kind="hourly",
                          source_ids=(scrape_source.source_id,)))

        sender = _HangingThenFastSender(self._never_set)

        summary1 = await evaluate_tick(
            config_store=config, state_store=state, router=router,
            parser_factory=_fake_parser_factory, sender=sender, now=tick1,
            max_concurrent_sends=1, reaper_timeout_seconds=0.05,
        )
        self.assertEqual(summary1.errors, 1)  # job-slow's send timed out
        self.assertEqual(summary1.scraped_sources, 1)  # job-scrape, tick1

        # The orphaned job-slow thread is now permanently parked in
        # whichever executor Plan B used. If that is the shared default
        # executor (max_workers=1 above), tick2's Plan A scrape -- which
        # also needs the default executor via asyncio.to_thread -- can
        # never get a worker. Bound the assertion itself so a regression
        # fails fast instead of hanging the whole suite.
        summary2 = await asyncio.wait_for(
            evaluate_tick(
                config_store=config, state_store=state, router=router,
                parser_factory=_fake_parser_factory, sender=sender, now=tick2,
                max_concurrent_sends=1, reaper_timeout_seconds=5.0,
            ),
            timeout=5.0,
        )
        self.assertEqual(summary2.scraped_sources, 1)  # job-scrape, tick2
        self.assertEqual(summary2.skipped_jobs, 1)  # job-slow, same window


class SharedSendExecutorRotationTest(unittest.IsolatedAsyncioTestCase):
    """run_evaluator_loop shares ONE send_executor across every tick -- an
    orphaned send from an earlier tick must not permanently occupy that
    executor's only worker and starve every later tick's sends too.
    _run_plan_b rotates the executor on TimeoutError."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._never_set = threading.Event()
        self.addCleanup(self._never_set.set)

    async def test_tick2_job_is_notified_despite_tick1_orphan(self) -> None:
        tick1 = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        tick2 = tick1 + timedelta(hours=1)

        config = SqliteConfigStore(Path(self._tmp.name) / "config.db")
        state = SqliteStateStore(Path(self._tmp.name) / "state.db")
        self.addCleanup(config.close)
        self.addCleanup(state.close)
        domain_policy = CatalogueDomainPolicy(config)
        router = _StubRouter({"http": _FakeFetcher()})
        service = AppService(config, state, router, domain_policy, build_parser)
        config.add_site(_SITE)

        # Only job-slow exists for tick1 -- it alone occupies the shared,
        # single-worker executor and times out.
        service.add_product("slow-owner", ProductSpec("p1"))
        slow_source = service.add_source(
            "slow-owner", "p1", "kabum", "https://www.kabum.com.br/p/slow")
        service.create_job(
            Principal(owner_id="slow-owner"),
            DigestJobSpec(name="job-slow", frequency_kind="daily",
                          source_ids=(slow_source.source_id,)))
        state.record("slow-owner", ScrapeRecord(
            source_id=slow_source.source_id, ts=(tick1 - _minutes(1)).isoformat(),
            status=ScrapeStatus.OK, price_pix_cents=100, price_card_cents=110,
            currency="BRL", availability=Availability.IN_STOCK, method="http",
            error=None,
        ))

        sender = _HangingThenFastSender(self._never_set)
        shared_executor = _RotatingSendExecutor(max_workers=1)

        summary1 = await evaluate_tick(
            config_store=config, state_store=state, router=router,
            parser_factory=_fake_parser_factory, sender=sender, now=tick1,
            max_concurrent_sends=1, reaper_timeout_seconds=0.05,
            send_executor=shared_executor,
        )
        self.assertEqual(summary1.errors, 1)  # job-slow's send timed out

        # job-fast is created only NOW, so it never competed with job-slow
        # for tick1's single worker -- it exists purely to prove tick2 can
        # still notify SOMETHING through the same shared executor instance.
        service.add_product("fast-owner", ProductSpec("p1"))
        fast_source = service.add_source(
            "fast-owner", "p1", "kabum", "https://www.kabum.com.br/p/fast")
        service.create_job(
            Principal(owner_id="fast-owner"),
            DigestJobSpec(name="job-fast", frequency_kind="hourly",
                          source_ids=(fast_source.source_id,)))
        state.record("fast-owner", ScrapeRecord(
            source_id=fast_source.source_id, ts=(tick2 - _minutes(1)).isoformat(),
            status=ScrapeStatus.OK, price_pix_cents=200, price_card_cents=210,
            currency="BRL", availability=Availability.IN_STOCK, method="http",
            error=None,
        ))

        # job-slow is skipped (same idempotence window, daily); if rotation
        # never happened, job-fast would time out too, still stuck behind
        # tick1's orphan -- bound the assertion so a regression fails fast.
        summary2 = await asyncio.wait_for(
            evaluate_tick(
                config_store=config, state_store=state, router=router,
                parser_factory=_fake_parser_factory, sender=sender, now=tick2,
                max_concurrent_sends=1, reaper_timeout_seconds=5.0,
                send_executor=shared_executor,
            ),
            timeout=5.0,
        )
        self.assertEqual(summary2.notified_jobs, 1)
        self.assertIn("job-fast", sender.calls)
        self.assertEqual(summary2.skipped_jobs, 1)  # job-slow, same window


class CliProcessExitTest(unittest.TestCase):
    """roadmap 3c0b1c80 (a): evaluate_tick's default (CLI-style) send
    executor must never block PROCESS EXIT on an orphaned send thread --
    concurrent.futures' atexit hook joins every ThreadPoolExecutor worker
    it ever started, regardless of executor.shutdown(wait=False). Measured
    via a real child process: an in-process test cannot observe this, the
    hang only manifests at actual interpreter shutdown."""

    def test_process_exits_promptly_despite_a_hanging_send(self) -> None:
        probe = Path(__file__).parent / "_cli_exit_probe.py"
        hang_seconds = 20.0
        start = time.monotonic()
        result = subprocess.run(
            [sys.executable, str(probe), "0.3", str(hang_seconds)],
            capture_output=True, text=True, timeout=hang_seconds + 30,
        )
        elapsed = time.monotonic() - start
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ASYNCIO_RUN_RETURNED", result.stdout)
        # If the process were blocked joining the orphaned thread at exit,
        # elapsed would be close to hang_seconds. A fixed, generous bound
        # well below that tolerates process-startup variance (green path
        # measures well under 1s) without becoming a tight race.
        self.assertLess(elapsed, 10.0)


class _AlwaysHangingSender:
    """DigestSender double whose send() blocks FOREVER for every job --
    records which jobs actually got DISPATCHED (send() entered) vs any
    refused before ever reaching the executor."""

    def __init__(self, never_set: threading.Event) -> None:
        self._never_set = never_set
        self.dispatched: list[str] = []

    def send(self, job, records, generated_at, tier2_labels) -> bool:
        self.dispatched.append(job.name)
        self._never_set.wait()
        return True


class LiveOrphanCeilingTest(unittest.IsolatedAsyncioTestCase):
    """_RotatingSendExecutor must refuse a new send once too many retired
    pools still have a live orphaned thread -- an unboundedly long-lived
    loop would otherwise accumulate unbounded concurrent orphans, one
    rotation at a time."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self._never_set = threading.Event()
        self.addCleanup(self._never_set.set)

    def _make_four_jobs(self, config, state, service, tick_now):
        # 4 distinct owners/jobs so no idempotence-window collision needs
        # managing -- the default ceiling for max_workers=1 is 3, so
        # exactly 3 of these must be dispatched (and time out, each
        # rotating the executor) before the 4th is refused outright.
        jobs = []
        for i in range(4):
            owner = f"owner-{i}"
            service.add_product(owner, ProductSpec("p1"))
            source = service.add_source(
                owner, "p1", "kabum", f"https://www.kabum.com.br/p/{i}")
            job = service.create_job(
                Principal(owner_id=owner),
                DigestJobSpec(name=f"job-{i}", frequency_kind="hourly",
                              source_ids=(source.source_id,)))
            jobs.append(job)
            state.record(owner, ScrapeRecord(
                source_id=source.source_id, ts=(tick_now - _minutes(1)).isoformat(),
                status=ScrapeStatus.OK, price_pix_cents=100, price_card_cents=110,
                currency="BRL", availability=Availability.IN_STOCK, method="http",
                error=None,
            ))
        return jobs

    async def test_fourth_send_is_refused_once_the_ceiling_is_reached(
        self,
    ) -> None:
        tick_now = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        config = SqliteConfigStore(Path(self._tmp.name) / "config.db")
        state = SqliteStateStore(Path(self._tmp.name) / "state.db")
        self.addCleanup(config.close)
        self.addCleanup(state.close)
        domain_policy = CatalogueDomainPolicy(config)
        router = _StubRouter({"http": _FakeFetcher()})
        service = AppService(config, state, router, domain_policy, build_parser)
        config.add_site(_SITE)
        self._make_four_jobs(config, state, service, tick_now)

        sender = _AlwaysHangingSender(self._never_set)
        shared_executor = _RotatingSendExecutor(max_workers=1)

        summary = await evaluate_tick(
            config_store=config, state_store=state, router=router,
            parser_factory=_fake_parser_factory, sender=sender, now=tick_now,
            max_concurrent_sends=1, reaper_timeout_seconds=0.05,
            send_executor=shared_executor,
        )

        self.assertEqual(len(sender.dispatched), 3)
        self.assertEqual(summary.errors, 3)  # job-0..2: dispatched, timed out
        self.assertEqual(summary.skipped_jobs, 1)  # job-3: refused outright

    async def test_refused_job_is_retried_in_the_same_window_once_orphans_clear(
        self,
    ) -> None:
        tick_now = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        config = SqliteConfigStore(Path(self._tmp.name) / "config.db")
        state = SqliteStateStore(Path(self._tmp.name) / "state.db")
        self.addCleanup(config.close)
        self.addCleanup(state.close)
        domain_policy = CatalogueDomainPolicy(config)
        router = _StubRouter({"http": _FakeFetcher()})
        service = AppService(config, state, router, domain_policy, build_parser)
        config.add_site(_SITE)
        jobs = self._make_four_jobs(config, state, service, tick_now)
        refused_job = jobs[3]
        refused_window_start = compute_window_start(
            refused_job.schedule_cron, refused_job.timezone, tick_now)

        sender = _AlwaysHangingSender(self._never_set)
        shared_executor = _RotatingSendExecutor(max_workers=1)

        summary1 = await evaluate_tick(
            config_store=config, state_store=state, router=router,
            parser_factory=_fake_parser_factory, sender=sender, now=tick_now,
            max_concurrent_sends=1, reaper_timeout_seconds=0.05,
            send_executor=shared_executor,
        )
        self.assertEqual(summary1.skipped_jobs, 1)  # job-3, refused

        # A capacity refusal must not consume the idempotence window: no
        # job_runs row exists for job-3 at all yet.
        with state._op() as conn:
            row = conn.execute(
                "SELECT status FROM job_runs WHERE job_id=? AND window_start=?",
                (refused_job.id, refused_window_start),
            ).fetchone()
        self.assertIsNone(row)

        # Release the 3 orphaned threads and poll can_submit() until the
        # executor has pruned them -- the background threads need a moment
        # to resume and finish once the Event fires.
        self._never_set.set()
        for _ in range(200):
            if shared_executor.can_submit():
                break
            await asyncio.sleep(0.01)
        else:
            self.fail("orphans never cleared within the poll budget")

        # SAME tick_now -- SAME window -- job-3 gets a fresh attempt and
        # succeeds this time (send() returns immediately, Event is set).
        summary2 = await evaluate_tick(
            config_store=config, state_store=state, router=router,
            parser_factory=_fake_parser_factory, sender=sender, now=tick_now,
            max_concurrent_sends=1, reaper_timeout_seconds=0.05,
            send_executor=shared_executor,
        )
        self.assertEqual(summary2.notified_jobs, 1)
        self.assertEqual(sender.dispatched.count("job-3"), 1)

        with state._op() as conn:
            row = conn.execute(
                "SELECT status FROM job_runs WHERE job_id=? AND window_start=?",
                (refused_job.id, refused_window_start),
            ).fetchone()
        self.assertEqual(row["status"], "sent")


class EmptyJobSourceGhostTest(_EvaluatorTestBase):
    """A job with nothing to report is skipped, never sent an empty digest."""

    async def test_job_with_zero_sources_is_skipped_without_sending(self) -> None:
        sid = self._add_source("owner1", "p1", "https://www.kabum.com.br/p/1")
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly",
                          source_ids=(sid,)))
        self._seed_history(
            "owner1", sid, datetime(2026, 7, 13, 10, 0, 0, tzinfo=timezone.utc))

        self.service.remove_source("owner1", sid)

        tick_now = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        sender = _RecordingSender()
        summary = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=sender, now=tick_now,
        )

        self.assertEqual(sender.calls, [])
        self.assertEqual(summary.notified_jobs, 0)
        self.assertEqual(summary.skipped_jobs, 1)
        # No send was attempted, so exactly-once has nothing to protect:
        # no job_runs row at all, the window stays open for a later tick.
        window_start = compute_window_start(job.schedule_cron, job.timezone, tick_now)
        with self.state._op() as conn:
            row = conn.execute(
                "SELECT status FROM job_runs WHERE job_id=? AND window_start=?",
                (job.id, window_start),
            ).fetchone()
        self.assertIsNone(row)

    async def test_source_relinked_in_the_same_window_is_notified(self) -> None:
        sid = self._add_source("owner1", "p1", "https://www.kabum.com.br/p/1")
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="daily",
                          source_ids=(sid,)))
        self._seed_history(
            "owner1", sid, datetime(2026, 7, 13, 10, 0, 0, tzinfo=timezone.utc))
        self.service.remove_source("owner1", sid)

        tick_now = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)
        sender = _RecordingSender()
        summary1 = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=sender, now=tick_now,
        )
        self.assertEqual(sender.calls, [])
        self.assertEqual(summary1.skipped_jobs, 1)

        new_sid = self._add_source("owner1", "p1", "https://www.kabum.com.br/p/2")
        self.service.add_job_source("owner1", job.id, new_sid)
        self._seed_history("owner1", new_sid, tick_now - _minutes(1))

        # Later tick, SAME day (daily window) -- the fix must not have
        # burned the window on the earlier, sourceless attempt.
        later_tick = tick_now + timedelta(hours=2)
        summary2 = await evaluate_tick(
            config_store=self.config, state_store=self.state,
            router=self.router, parser_factory=_fake_parser_factory,
            sender=sender, now=later_tick,
        )

        self.assertEqual(len(sender.calls), 1)
        self.assertEqual(summary2.notified_jobs, 1)

    async def test_linked_source_with_no_history_is_skipped_without_sending(
        self,
    ) -> None:
        sid = self._add_source("owner1", "p1", "https://www.kabum.com.br/p/1")
        self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly",
                          source_ids=(sid,)))
        # No history seeded, and the fetcher tier is unavailable -- Plan A
        # never scrapes it either, so this state is PERMANENT, not a
        # transient "not scraped yet".
        router = _StubRouter({"http": self.fetcher}, unavailable=frozenset({"http"}))
        sender = _RecordingSender()
        base = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)

        for minute in range(3):
            summary = await evaluate_tick(
                config_store=self.config, state_store=self.state,
                router=router, parser_factory=_fake_parser_factory,
                sender=sender, now=base + timedelta(minutes=minute),
            )
            self.assertEqual(summary.notified_jobs, 0)

        self.assertEqual(sender.calls, [])
        with self.state._op() as conn:
            rows = conn.execute("SELECT * FROM job_runs").fetchall()
        self.assertEqual(rows, [])

    async def test_empty_digest_warning_is_rate_limited_per_window(self) -> None:
        sid = self._add_source("owner1", "p1", "https://www.kabum.com.br/p/1")
        self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly",
                          source_ids=(sid,)))
        router = _StubRouter({"http": self.fetcher}, unavailable=frozenset({"http"}))
        sender = _RecordingSender()
        tracker = _EmptyDigestWarningTracker()
        base = datetime(2026, 7, 13, 10, 5, 0, tzinfo=timezone.utc)

        with self.assertLogs("kerdoos.core.evaluator", level="WARNING") as cm:
            for minute in range(3):  # 3 ticks, SAME hourly window
                await evaluate_tick(
                    config_store=self.config, state_store=self.state,
                    router=router, parser_factory=_fake_parser_factory,
                    sender=sender, now=base + timedelta(minutes=minute),
                    empty_digest_warnings=tracker,
                )
            # A tick in the NEXT hourly window -- a fresh warning is due.
            await evaluate_tick(
                config_store=self.config, state_store=self.state,
                router=router, parser_factory=_fake_parser_factory,
                sender=sender, now=base + timedelta(hours=1),
                empty_digest_warnings=tracker,
            )

        warning_lines = [
            msg for msg in cm.output if "has nothing to report" in msg]
        self.assertEqual(len(warning_lines), 2)


if __name__ == "__main__":
    unittest.main()
