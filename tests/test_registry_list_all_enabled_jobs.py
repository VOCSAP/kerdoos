"""SqliteConfigStore.list_all_enabled_jobs (ADR 0003 Phase 6b evaluator).

Scheduler-internal-only read: no owner_id filter (sweeps ALL tenants in one
tick), so this is tested directly against the store rather than through
AppService (which never exposes it -- see registry/ports.py docstring).
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from kerdoos.core.app.services import AppService, DigestJobSpec, Principal, ProductSpec
from kerdoos.parsers.factory import build_parser
from kerdoos.persistence.sqlite_store import SqliteStateStore
from kerdoos.registry.domain_policy import CatalogueDomainPolicy
from kerdoos.registry.ports import SiteConfig
from kerdoos.registry.sqlite_store import SqliteConfigStore
from kerdoos.parsers.ports import ParserSpec

from autolycos.router import StaticRouter

_SITE = SiteConfig(
    name="kabum", fetcher="http", domain="kabum.com.br",
    parser=ParserSpec(kind="statejson", pix="a", card="b", availability="c"),
)


class ListAllEnabledJobsTest(unittest.TestCase):
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

    def test_empty_when_no_jobs_exist(self) -> None:
        self.assertEqual(self.config.list_all_enabled_jobs(), ())

    def test_sweeps_jobs_across_multiple_owners(self) -> None:
        self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job-a", frequency_kind="hourly"))
        self.service.create_job(
            Principal(owner_id="owner2"),
            DigestJobSpec(name="job-b", frequency_kind="daily"))
        jobs = self.config.list_all_enabled_jobs()
        self.assertEqual(
            {(j.owner_id, j.name) for j in jobs},
            {("owner1", "job-a"), ("owner2", "job-b")},
        )

    def test_disabled_jobs_are_excluded(self) -> None:
        job = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="job-a", frequency_kind="hourly"))
        self.service.update_job(
            "owner1", job.id,
            DigestJobSpec(name="job-a", frequency_kind="hourly", enabled=False))
        self.assertEqual(self.config.list_all_enabled_jobs(), ())

    def test_only_the_enabled_job_is_returned_among_mixed_jobs(self) -> None:
        self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="enabled-job", frequency_kind="hourly"))
        disabled = self.service.create_job(
            Principal(owner_id="owner1"),
            DigestJobSpec(name="disabled-job", frequency_kind="hourly"))
        self.service.update_job(
            "owner1", disabled.id,
            DigestJobSpec(
                name="disabled-job", frequency_kind="hourly", enabled=False))
        jobs = self.config.list_all_enabled_jobs()
        self.assertEqual([j.name for j in jobs], ["enabled-job"])


if __name__ == "__main__":
    unittest.main()
