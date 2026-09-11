"""Subprocess probe for roadmap 3c0b1c80 (a): reproduces `kerdoos digest`'s
process-exit behavior under a send that hangs well past its own timeout.

Not collected by pytest (no test_/_test naming) -- invoked as a CHILD
PROCESS by test_evaluator.py::CliProcessExitTest, which measures REAL
process termination time. An in-process asyncio test cannot observe this:
concurrent.futures' atexit hook only manifests at actual interpreter
shutdown, invisible from inside the same process that started it.

argv: <send_timeout_seconds> <hang_seconds>
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from autolycos.router import StaticRouter

from kerdoos.core.app.services import AppService, DigestJobSpec, Principal, ProductSpec
from kerdoos.core.domain import Availability, ScrapeStatus
from kerdoos.core.evaluator import evaluate_tick
from kerdoos.parsers.factory import build_parser
from kerdoos.parsers.ports import ParserSpec
from kerdoos.persistence.ports import ScrapeRecord
from kerdoos.persistence.sqlite_store import SqliteStateStore
from kerdoos.registry.domain_policy import CatalogueDomainPolicy
from kerdoos.registry.ports import SiteConfig
from kerdoos.registry.sqlite_store import SqliteConfigStore


class _HangingSender:
    def __init__(self, hang_seconds: float) -> None:
        self._hang_seconds = hang_seconds

    def send(self, job, records, generated_at, tier2_labels) -> bool:
        time.sleep(self._hang_seconds)
        return True


def main() -> None:
    send_timeout_seconds = float(sys.argv[1])
    hang_seconds = float(sys.argv[2])

    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        config = SqliteConfigStore(d / "config.db")
        state = SqliteStateStore(d / "state.db")
        domain_policy = CatalogueDomainPolicy(config)
        router = StaticRouter(domain_policy)
        service = AppService(config, state, router, domain_policy, build_parser)
        site = SiteConfig(
            name="kabum", fetcher="http", domain="kabum.com.br",
            parser=ParserSpec(kind="statejson", pix="a", card="b", availability="c"),
        )
        config.add_site(site)
        service.add_product("owner", ProductSpec("p1"))
        source = service.add_source(
            "owner", "p1", "kabum", "https://www.kabum.com.br/p/x")
        service.create_job(
            Principal(owner_id="owner"),
            DigestJobSpec(name="job", frequency_kind="hourly",
                          source_ids=(source.source_id,)))
        # Fresh history so Plan A skips scraping -- no real network needed.
        state.record("owner", ScrapeRecord(
            source_id=source.source_id, ts=datetime.now(timezone.utc).isoformat(),
            status=ScrapeStatus.OK, price_pix_cents=100, price_card_cents=110,
            currency="BRL", availability=Availability.IN_STOCK, method="http",
            error=None,
        ))

        asyncio.run(evaluate_tick(
            config_store=config, state_store=state, router=router,
            parser_factory=build_parser, sender=_HangingSender(hang_seconds),
            max_concurrent_sends=1, reaper_timeout_seconds=send_timeout_seconds,
        ))
        config.close()
        state.close()

    print("ASYNCIO_RUN_RETURNED", flush=True)


if __name__ == "__main__":
    main()
