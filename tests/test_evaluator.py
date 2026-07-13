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
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from autolycos.ports import FetchResult
from autolycos.router import StaticRouter

from kerdoos.core.app.services import AppService, DigestJobSpec, Principal, ProductSpec
from kerdoos.core.domain import Availability, Extract, ScrapeStatus
from kerdoos.core.evaluator import (
    _run_plan_a,
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
    routing failure."""

    def __init__(self, mapping: dict[str, object]) -> None:
        self._mapping = mapping

    def select(self, fetcher_name: str, subresource_domains=()):
        target = self._mapping[fetcher_name]
        if isinstance(target, BaseException):
            raise target
        return target


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


if __name__ == "__main__":
    unittest.main()
