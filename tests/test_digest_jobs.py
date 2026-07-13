"""Digest jobs (Phase 6a, ADR 0003): schema + AppService CRUD use-cases.

Everything here exercises AppService (the same choke point a WebUI/MCP
interface would go through), plus a couple of store-level tests for the
IDOR double-scoping-at-persist defense and the job_runs idempotence key,
which are only observable at the SQLite layer.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from autolycos.router import StaticRouter

from kerdoos.core.app.services import (
    AppService,
    DigestJobSpec,
    Principal,
    ProductSpec,
)
from kerdoos.parsers.factory import build_parser
from kerdoos.parsers.ports import ParserSpec
from kerdoos.persistence.ports import JobRun
from kerdoos.persistence.sqlite_store import SqliteStateStore
from kerdoos.registry.domain_policy import CatalogueDomainPolicy
from kerdoos.registry.ports import SiteConfig
from kerdoos.registry.sqlite_store import SqliteConfigStore

_SITE = SiteConfig(
    name="kabum", fetcher="http", domain="kabum.com.br",
    parser=ParserSpec(kind="statejson", pix="a", card="b", availability="c"),
)


class _DigestJobsTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        d = Path(self._tmp.name)
        self.config = SqliteConfigStore(d / "config.db")
        self.state = SqliteStateStore(d / "state.db")
        domain_policy = CatalogueDomainPolicy(self.config)
        router = StaticRouter(domain_policy)
        self.service = AppService(
            self.config, self.state, router, domain_policy, build_parser)
        self.config.add_site(_SITE)

    def tearDown(self) -> None:
        self.config.close()
        self.state.close()
        self._tmp.cleanup()

    def _add_source(self, owner: str, product_key: str, url: str) -> str:
        self.service.add_product(owner, ProductSpec(product_key))
        source = self.service.add_source(owner, product_key, "kabum", url)
        return source.source_id


class CreateJobTest(_DigestJobsTestBase):
    def test_create_job_hourly_normalizes_cron(self) -> None:
        principal = Principal(owner_id="owner1")
        job = self.service.create_job(
            principal, DigestJobSpec(name="daily-check", frequency_kind="hourly",
                                      minute=15))
        self.assertEqual(job.schedule_cron, "15 * * * *")
        self.assertEqual(job.owner_id, "owner1")
        self.assertTrue(job.id)
        self.assertEqual(job.source_ids, ())

    def test_create_job_daily_normalizes_cron(self) -> None:
        principal = Principal(owner_id="owner1")
        job = self.service.create_job(
            principal, DigestJobSpec(
                name="daily", frequency_kind="daily", minute=30, hour=8))
        self.assertEqual(job.schedule_cron, "30 8 * * *")

    def test_create_job_cron_passthrough(self) -> None:
        principal = Principal(owner_id="owner1")
        job = self.service.create_job(
            principal, DigestJobSpec(
                name="custom", frequency_kind="cron",
                cron_expr="*/5 * * * *"))
        self.assertEqual(job.schedule_cron, "*/5 * * * *")

    def test_create_job_links_own_sources(self) -> None:
        principal = Principal(owner_id="owner1")
        sid = self._add_source(
            "owner1", "aw3225qf", "https://www.kabum.com.br/produto/1/a")
        job = self.service.create_job(
            principal, DigestJobSpec(
                name="job1", frequency_kind="hourly", source_ids=(sid,)))
        self.assertEqual(job.source_ids, (sid,))

    def test_create_job_rejects_empty_owner(self) -> None:
        with self.assertRaises(ValueError):
            self.service.create_job(
                Principal(owner_id=""),
                DigestJobSpec(name="job1", frequency_kind="hourly"))

    def test_create_job_rejects_unknown_frequency_kind(self) -> None:
        principal = Principal(owner_id="owner1")
        with self.assertRaises(ValueError):
            self.service.create_job(
                principal, DigestJobSpec(name="job1", frequency_kind="weekly"))

    def test_create_job_rejects_unknown_option_keys(self) -> None:
        principal = Principal(owner_id="owner1")
        with self.assertRaises(ValueError):
            self.service.create_job(
                principal, DigestJobSpec(
                    name="job1", frequency_kind="hourly",
                    options={"not_a_real_option": True}))

    def test_create_job_rejects_duplicate_name_for_same_owner(self) -> None:
        from kerdoos.registry.errors import ConfigError

        principal = Principal(owner_id="owner1")
        self.service.create_job(
            principal, DigestJobSpec(name="dup", frequency_kind="hourly"))
        with self.assertRaises(ConfigError):
            self.service.create_job(
                principal, DigestJobSpec(name="dup", frequency_kind="daily"))

    def test_create_job_same_name_allowed_across_owners(self) -> None:
        self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="dup", frequency_kind="hourly"))
        # Must not raise -- (owner_id, name) uniqueness is per-owner.
        self.service.create_job(
            Principal(owner_id="owner2"),
            DigestJobSpec(name="dup", frequency_kind="hourly"))

    def test_create_job_accepts_known_iana_timezone(self) -> None:
        principal = Principal(owner_id="owner1")
        job = self.service.create_job(
            principal, DigestJobSpec(
                name="job1", frequency_kind="hourly",
                timezone="America/Sao_Paulo"))
        self.assertEqual(job.timezone, "America/Sao_Paulo")

    def test_create_job_rejects_unknown_timezone(self) -> None:
        # Architect finding #8: a malformed tz must never reach storage --
        # the evaluator (core/scheduler.py) needs a valid zoneinfo.ZoneInfo
        # to compute window_start for this job.
        principal = Principal(owner_id="owner1")
        with self.assertRaises(ValueError):
            self.service.create_job(
                principal, DigestJobSpec(
                    name="job1", frequency_kind="hourly",
                    timezone="Not/A_Zone"))

    def test_update_job_rejects_unknown_timezone(self) -> None:
        principal = Principal(owner_id="owner1")
        job = self.service.create_job(
            principal, DigestJobSpec(name="job1", frequency_kind="hourly"))
        with self.assertRaises(ValueError):
            self.service.update_job(
                "owner1", job.id,
                DigestJobSpec(
                    name="job1", frequency_kind="hourly",
                    timezone="Not/A_Zone"))
        # Untouched by the rejected update.
        self.assertEqual(self.service.get_job("owner1", job.id).timezone, "UTC")


class IdorTest(_DigestJobsTestBase):
    """The double-scoping IDOR defense (ADR 0003 finding S2): a source_id
    forged from another owner must never be linked, and the response gives
    no oracle to distinguish 'unknown source' from 'someone else's source'.
    """

    def test_create_job_silently_drops_forged_source_id(self) -> None:
        owner_a_source = self._add_source(
            "ownerA", "aw3225qf", "https://www.kabum.com.br/produto/1/a")
        # ownerB forges ownerA's REAL source_id in their own job spec.
        job = self.service.create_job(
            Principal(owner_id="ownerB"),
            DigestJobSpec(
                name="job1", frequency_kind="hourly",
                source_ids=(owner_a_source,)))
        # No oracle: no exception, no error field -- the forged id is simply
        # absent from the persisted/returned source_ids.
        self.assertEqual(job.source_ids, ())
        reloaded = self.service.get_job("ownerB", job.id)
        self.assertEqual(reloaded.source_ids, ())
        # ownerA's source is untouched -- no cross-tenant link exists at all.
        self.assertEqual(
            self.config.get_job("ownerB", job.id).source_ids, ())

    def test_add_job_source_silently_rejects_forged_source_id(self) -> None:
        owner_a_source = self._add_source(
            "ownerA", "aw3225qf", "https://www.kabum.com.br/produto/1/a")
        job = self.service.create_job(
            Principal(owner_id="ownerB"),
            DigestJobSpec(name="job1", frequency_kind="hourly"))
        linked = self.service.add_job_source(
            "ownerB", job.id, owner_a_source)
        self.assertFalse(linked)
        self.assertEqual(
            self.service.get_job("ownerB", job.id).source_ids, ())

    def test_add_job_source_links_own_source(self) -> None:
        sid = self._add_source(
            "owner1", "aw3225qf", "https://www.kabum.com.br/produto/1/a")
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly"))
        linked = self.service.add_job_source("owner1", job.id, sid)
        self.assertTrue(linked)
        self.assertEqual(
            self.service.get_job("owner1", job.id).source_ids, (sid,))


class CrudOwnerScopeTest(_DigestJobsTestBase):
    def test_list_jobs_is_owner_scoped(self) -> None:
        self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly"))
        self.assertEqual(len(self.service.list_jobs("owner1")), 1)
        self.assertEqual(len(self.service.list_jobs("owner2")), 0)

    def test_get_job_cannot_cross_tenant(self) -> None:
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly"))
        with self.assertRaises(KeyError):
            self.service.get_job("owner2", job.id)
        # owner1 (the real owner) can still read it.
        self.assertEqual(self.service.get_job("owner1", job.id).id, job.id)

    def test_update_job_cannot_cross_tenant(self) -> None:
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly"))
        with self.assertRaises(KeyError):
            self.service.update_job(
                "owner2", job.id,
                DigestJobSpec(name="renamed", frequency_kind="daily"))
        # Untouched by the failed cross-tenant attempt.
        self.assertEqual(self.service.get_job("owner1", job.id).name, "job1")

    def test_update_job_updates_fields_for_real_owner(self) -> None:
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly", minute=0))
        updated = self.service.update_job(
            "owner1", job.id,
            DigestJobSpec(name="job1-renamed", frequency_kind="daily",
                           minute=45, hour=6, enabled=False))
        self.assertEqual(updated.name, "job1-renamed")
        self.assertEqual(updated.schedule_cron, "45 6 * * *")
        self.assertFalse(updated.enabled)

    def test_delete_job_cannot_cross_tenant(self) -> None:
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly"))
        with self.assertRaises(KeyError):
            self.service.delete_job("owner2", job.id)
        self.assertEqual(len(self.service.list_jobs("owner1")), 1)

    def test_delete_job_removes_it_for_real_owner(self) -> None:
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly"))
        self.service.delete_job("owner1", job.id)
        self.assertEqual(len(self.service.list_jobs("owner1")), 0)

    def test_delete_job_cascades_its_source_links(self) -> None:
        sid = self._add_source(
            "owner1", "aw3225qf", "https://www.kabum.com.br/produto/1/a")
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly",
                           source_ids=(sid,)))
        self.service.delete_job("owner1", job.id)
        # sqlite3's context manager only commits/rolls back -- it does NOT
        # close the connection -- so close explicitly to avoid a locked-file
        # handle lingering into tearDown's TemporaryDirectory cleanup
        # (PermissionError on Windows).
        conn = sqlite3.connect(str(Path(self._tmp.name) / "config.db"))
        try:
            rows = conn.execute(
                "SELECT * FROM digest_job_sources WHERE job_id = ?",
                (job.id,),
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(rows, [])

    def test_remove_job_source_cannot_cross_tenant(self) -> None:
        sid = self._add_source(
            "owner1", "aw3225qf", "https://www.kabum.com.br/produto/1/a")
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job1", frequency_kind="hourly",
                           source_ids=(sid,)))
        # owner2 cannot unlink owner1's source, even knowing job_id/source_id.
        self.service.remove_job_source("owner2", job.id, sid)
        self.assertEqual(
            self.service.get_job("owner1", job.id).source_ids, (sid,))
        self.service.remove_job_source("owner1", job.id, sid)
        self.assertEqual(
            self.service.get_job("owner1", job.id).source_ids, ())


class MigrationIdempotenceTest(unittest.TestCase):
    def test_config_migration_creates_new_tables_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.db"
            # First open on a brand-new (zero pre-existing rows) DB.
            SqliteConfigStore(path).close()
            # Second open must not raise (CREATE TABLE IF NOT EXISTS is a
            # true no-op the second time).
            SqliteConfigStore(path).close()
            conn = sqlite3.connect(str(path))
            try:
                tables = {
                    row[0] for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                version = conn.execute("PRAGMA user_version").fetchone()[0]
            finally:
                conn.close()
            self.assertIn("digest_jobs", tables)
            self.assertIn("digest_job_sources", tables)
            self.assertEqual(version, 4)

    def test_state_migration_creates_job_runs_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.db"
            SqliteStateStore(path).close()
            SqliteStateStore(path).close()
            conn = sqlite3.connect(str(path))
            try:
                tables = {
                    row[0] for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                version = conn.execute("PRAGMA user_version").fetchone()[0]
            finally:
                conn.close()
            self.assertIn("job_runs", tables)
            self.assertEqual(version, 4)


class JobRunTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.state = SqliteStateStore(Path(self._tmp.name) / "state.db")

    def tearDown(self) -> None:
        self.state.close()
        self._tmp.cleanup()

    def test_record_job_run_first_call_returns_true(self) -> None:
        run = JobRun(
            job_id="job1", owner_id="owner1", window_start="2026-07-10T00:00:00+00:00",
            fired_at="2026-07-10T00:00:05+00:00", status="sent",
            sent_at="2026-07-10T00:00:06+00:00",
        )
        self.assertTrue(self.state.record_job_run(run))

    def test_record_job_run_duplicate_window_is_idempotent_noop(self) -> None:
        run = JobRun(
            job_id="job1", owner_id="owner1", window_start="2026-07-10T00:00:00+00:00",
            fired_at="2026-07-10T00:00:05+00:00", status="sent",
        )
        self.assertTrue(self.state.record_job_run(run))
        # Same (job_id, window_start) -- retried firing, must NOT raise nor
        # double-record; the idempotence key from ADR 0003 Decision 3.
        duplicate = JobRun(
            job_id="job1", owner_id="owner1", window_start="2026-07-10T00:00:00+00:00",
            fired_at="2026-07-10T00:00:09+00:00", status="error",
            error="retry",
        )
        self.assertFalse(self.state.record_job_run(duplicate))

    def test_record_job_run_distinct_windows_both_recorded(self) -> None:
        run1 = JobRun(
            job_id="job1", owner_id="owner1", window_start="2026-07-10T00:00:00+00:00",
            fired_at="2026-07-10T00:00:05+00:00", status="sent",
        )
        run2 = JobRun(
            job_id="job1", owner_id="owner1", window_start="2026-07-10T01:00:00+00:00",
            fired_at="2026-07-10T01:00:05+00:00", status="sent",
        )
        self.assertTrue(self.state.record_job_run(run1))
        self.assertTrue(self.state.record_job_run(run2))

    # -- Phase 6b lifecycle (architect finding #6) -----------------------

    def test_update_job_run_transitions_existing_row(self) -> None:
        run = JobRun(
            job_id="job1", owner_id="owner1", window_start="2026-07-10T00:00:00+00:00",
            fired_at="2026-07-10T00:00:05+00:00", status="queued",
        )
        self.assertTrue(self.state.record_job_run(run))
        ok = self.state.update_job_run(
            "job1", "2026-07-10T00:00:00+00:00",
            status="running")
        self.assertTrue(ok)
        ok = self.state.update_job_run(
            "job1", "2026-07-10T00:00:00+00:00",
            status="sent", sent_at="2026-07-10T00:00:06+00:00")
        self.assertTrue(ok)

    def test_update_job_run_missing_row_returns_false(self) -> None:
        ok = self.state.update_job_run(
            "no-such-job", "2026-07-10T00:00:00+00:00", status="running")
        self.assertFalse(ok)

    def test_has_active_job_run_true_while_queued_or_running(self) -> None:
        run = JobRun(
            job_id="job1", owner_id="owner1", window_start="2026-07-10T00:00:00+00:00",
            fired_at="2026-07-10T00:00:05+00:00", status="queued",
        )
        self.state.record_job_run(run)
        self.assertTrue(self.state.has_active_job_run("owner1", "job1"))
        self.state.update_job_run(
            "job1", "2026-07-10T00:00:00+00:00", status="running")
        self.assertTrue(self.state.has_active_job_run("owner1", "job1"))

    def test_has_active_job_run_false_once_terminal(self) -> None:
        run = JobRun(
            job_id="job1", owner_id="owner1", window_start="2026-07-10T00:00:00+00:00",
            fired_at="2026-07-10T00:00:05+00:00", status="queued",
        )
        self.state.record_job_run(run)
        self.state.update_job_run(
            "job1", "2026-07-10T00:00:00+00:00",
            status="sent", sent_at="2026-07-10T00:00:06+00:00")
        self.assertFalse(self.state.has_active_job_run("owner1", "job1"))

    def test_has_active_job_run_is_owner_scoped(self) -> None:
        # Double-scoping IDOR defense (finding S2): a job_id shared by
        # coincidence (or forged) across two owners must not leak activity
        # state across the tenant boundary.
        run = JobRun(
            job_id="shared-id", owner_id="ownerA", window_start="2026-07-10T00:00:00+00:00",
            fired_at="2026-07-10T00:00:05+00:00", status="running",
        )
        self.state.record_job_run(run)
        self.assertTrue(self.state.has_active_job_run("ownerA", "shared-id"))
        self.assertFalse(self.state.has_active_job_run("ownerB", "shared-id"))


if __name__ == "__main__":
    unittest.main()
