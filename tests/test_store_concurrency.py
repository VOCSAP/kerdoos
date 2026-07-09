"""FD3 (ADR 0001 S5.1): SqliteConfigStore + SqliteStateStore are
connection-per-operation and safe under concurrent OS threads.

BITES if either store is ever re-routed onto a single shared
check_same_thread=True connection: cross-thread use of such a connection raises
sqlite3.ProgrammingError, which this test would surface. Temp FILE dbs (not
:memory:) per the architect's option (a).
"""

from __future__ import annotations

import os
import shutil
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from kerdoos.core.domain import Availability, ScrapeStatus
from kerdoos.persistence.ports import ScrapeRecord
from kerdoos.persistence.sqlite_store import SqliteStateStore
from kerdoos.registry.ports import ParserSpec, Product, ProductSource, SiteConfig
from kerdoos.registry.sqlite_store import SqliteConfigStore

_SITE = SiteConfig(
    name="kabum", fetcher="http", domain="kabum.com.br",
    parser=ParserSpec(kind="statejson", pix="a", card="b", availability="c"))


def _record(source_id: str) -> ScrapeRecord:
    return ScrapeRecord(
        source_id=source_id, ts="2026-07-09T00:00:00+00:00",
        status=ScrapeStatus.OK, price_pix_cents=100, price_card_cents=100,
        currency="BRL", availability=Availability.IN_STOCK, method="http",
        error=None)


class StoreConcurrencyTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="kerdoos-conc-")
        self.addCleanup(shutil.rmtree, self._dir, ignore_errors=True)
        self.config = SqliteConfigStore(os.path.join(self._dir, "config.db"))
        self.addCleanup(self.config.close)
        self.state = SqliteStateStore(os.path.join(self._dir, "state.db"))
        self.addCleanup(self.state.close)
        self.config.add_site(_SITE)
        self.config.add_product("owner1", Product(id="aw3225qf", name="Mon"))

    def test_concurrent_store_access_no_programming_error(self) -> None:
        errors: list[Exception] = []
        lock = threading.Lock()

        def _hammer(n: int) -> None:
            try:
                for i in range(15):
                    sid = f"owner1:aw3225qf:kabum:{n}-{i}"
                    # config store: read + write mix
                    self.config.load("owner1")
                    self.config.site_domains()
                    self.config.add_source(
                        "owner1",
                        ProductSource(source_id=sid, product_id="aw3225qf",
                                      site="kabum",
                                      url=f"https://kabum.com.br/p/{n}-{i}"))
                    # state store: read + write mix
                    self.state.record("owner1", _record(sid))
                    self.state.history("owner1", sid, 5)
                    self.state.latest_all("owner1")
            except Exception as exc:  # noqa: BLE001 -- capture for assertion
                with lock:
                    errors.append(exc)

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(_hammer, n) for n in range(8)]
            for f in futures:
                f.result(timeout=30)

        self.assertEqual(errors, [])
        # All owner1 sources persisted (8 threads x 15 distinct source ids).
        registry = self.config.load("owner1")
        total_sources = sum(len(p.sources) for p in registry.products)
        self.assertEqual(total_sources, 8 * 15)


if __name__ == "__main__":
    unittest.main()
