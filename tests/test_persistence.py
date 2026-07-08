"""SQLite StateStore round-trip + deterministic source id (#2)."""

from __future__ import annotations

import unittest

from kerdoos.core.domain import Availability, ScrapeStatus
from kerdoos.persistence.ports import ScrapeRecord
from kerdoos.persistence.sqlite_store import SqliteStateStore
from kerdoos.registry.ports import make_source_id


def _record(source_id: str, ts: str, pix: int | None) -> ScrapeRecord:
    return ScrapeRecord(
        source_id=source_id, ts=ts, status=ScrapeStatus.OK,
        price_pix_cents=pix, price_card_cents=None, currency="BRL",
        availability=Availability.IN_STOCK, method="http", error=None,
    )


_URL = "https://www.kabum.com.br/produto/534732/x"
_URL2 = "https://www.kabum.com.br/produto/999999/y"


class SourceIdTest(unittest.TestCase):
    def test_source_id_is_deterministic(self) -> None:
        # Same (product, site, url) triple -> same id, always.
        self.assertEqual(make_source_id("aw3225qf", "kabum", _URL),
                         make_source_id("aw3225qf", "kabum", _URL))
        self.assertTrue(
            make_source_id("aw3225qf", "kabum", _URL).startswith("aw3225qf:kabum:"))

    def test_url_is_part_of_identity(self) -> None:
        # N2: two DIFFERENT urls of the same product/site are distinct sources.
        a = make_source_id("aw3225qf", "kabum", _URL)
        b = make_source_id("aw3225qf", "kabum", _URL2)
        self.assertNotEqual(a, b)


class SqliteStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.store = SqliteStateStore(":memory:")

    def tearDown(self) -> None:
        self.store.close()

    def test_record_and_history_roundtrip(self) -> None:
        sid = make_source_id("aw3225qf", "kabum", _URL)
        self.store.record(_record(sid, "2026-07-06T00:00:00+00:00", 755800))
        self.store.record(_record(sid, "2026-07-06T01:00:00+00:00", 749900))
        history = self.store.history(sid)
        self.assertEqual(len(history), 2)
        # Most recent first.
        self.assertEqual(history[0].price_pix_cents, 749900)
        self.assertEqual(history[0].status, ScrapeStatus.OK)
        self.assertEqual(history[0].availability, Availability.IN_STOCK)

    def test_history_isolated_by_source(self) -> None:
        self.store.record(_record("a:kabum", "2026-07-06T00:00:00+00:00", 100))
        self.store.record(_record("b:kabum", "2026-07-06T00:00:00+00:00", 200))
        self.assertEqual(len(self.store.history("a:kabum")), 1)
        self.assertEqual(self.store.history("a:kabum")[0].price_pix_cents, 100)

    def test_sql_injection_in_source_id_is_inert(self) -> None:
        # Parameterized SQL: a hostile source_id is stored/read as literal text.
        evil = "x'; DROP TABLE scrapes;--"
        self.store.record(_record(evil, "2026-07-06T00:00:00+00:00", 1))
        history = self.store.history(evil)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].source_id, evil)


if __name__ == "__main__":
    unittest.main()
