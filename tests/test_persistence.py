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


_OWNER = "owner1"


class SourceIdTest(unittest.TestCase):
    def test_source_id_is_deterministic(self) -> None:
        # Same (owner, product, site, url) quadruple -> same id, always.
        self.assertEqual(make_source_id(_OWNER, "aw3225qf", "kabum", _URL),
                         make_source_id(_OWNER, "aw3225qf", "kabum", _URL))
        self.assertTrue(
            make_source_id(_OWNER, "aw3225qf", "kabum", _URL)
            .startswith(f"{_OWNER}:aw3225qf:kabum:"))

    def test_url_is_part_of_identity(self) -> None:
        # N2: two DIFFERENT urls of the same product/site are distinct sources.
        a = make_source_id(_OWNER, "aw3225qf", "kabum", _URL)
        b = make_source_id(_OWNER, "aw3225qf", "kabum", _URL2)
        self.assertNotEqual(a, b)

    def test_owner_is_part_of_identity(self) -> None:
        # Two tenants with the SAME product_key/site/url get distinct ids
        # (tenancy isolation, not just a display prefix).
        a = make_source_id("owner1", "aw3225qf", "kabum", _URL)
        b = make_source_id("owner2", "aw3225qf", "kabum", _URL)
        self.assertNotEqual(a, b)

    def test_product_key_rejects_colon(self) -> None:
        with self.assertRaises(ValueError):
            make_source_id(_OWNER, "aw:3225qf", "kabum", _URL)


class SqliteStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.store = SqliteStateStore(":memory:")

    def tearDown(self) -> None:
        self.store.close()

    def test_record_and_history_roundtrip(self) -> None:
        sid = make_source_id(_OWNER, "aw3225qf", "kabum", _URL)
        self.store.record(_OWNER, _record(sid, "2026-07-06T00:00:00+00:00", 755800))
        self.store.record(_OWNER, _record(sid, "2026-07-06T01:00:00+00:00", 749900))
        history = self.store.history(_OWNER, sid)
        self.assertEqual(len(history), 2)
        # Most recent first.
        self.assertEqual(history[0].price_pix_cents, 749900)
        self.assertEqual(history[0].status, ScrapeStatus.OK)
        self.assertEqual(history[0].availability, Availability.IN_STOCK)

    def test_history_isolated_by_source(self) -> None:
        self.store.record(_OWNER, _record("a:kabum", "2026-07-06T00:00:00+00:00", 100))
        self.store.record(_OWNER, _record("b:kabum", "2026-07-06T00:00:00+00:00", 200))
        self.assertEqual(len(self.store.history(_OWNER, "a:kabum")), 1)
        self.assertEqual(
            self.store.history(_OWNER, "a:kabum")[0].price_pix_cents, 100)

    def test_history_isolated_by_owner(self) -> None:
        # Same source_id, two owners: tenancy isolation on the read path too.
        self.store.record("owner1", _record("shared:kabum", "2026-07-06T00:00:00+00:00", 100))
        self.store.record("owner2", _record("shared:kabum", "2026-07-06T00:00:00+00:00", 200))
        self.assertEqual(len(self.store.history("owner1", "shared:kabum")), 1)
        self.assertEqual(
            self.store.history("owner1", "shared:kabum")[0].price_pix_cents, 100)
        self.assertEqual(
            self.store.history("owner2", "shared:kabum")[0].price_pix_cents, 200)

    def test_record_rejects_empty_owner(self) -> None:
        with self.assertRaises(ValueError):
            self.store.record("", _record("x:kabum", "2026-07-06T00:00:00+00:00", 1))

    def test_latest_all_returns_one_row_per_source(self) -> None:
        self.store.record(_OWNER, _record("a:kabum", "2026-07-06T00:00:00+00:00", 100))
        self.store.record(_OWNER, _record("a:kabum", "2026-07-06T01:00:00+00:00", 150))
        self.store.record(_OWNER, _record("b:kabum", "2026-07-06T00:30:00+00:00", 200))
        latest = self.store.latest_all(_OWNER)
        by_source = {row.source_id: row for row in latest}
        self.assertEqual(len(latest), 2)
        self.assertEqual(by_source["a:kabum"].price_pix_cents, 150)
        self.assertEqual(by_source["b:kabum"].price_pix_cents, 200)

    def test_sql_injection_in_source_id_is_inert(self) -> None:
        # Parameterized SQL: a hostile source_id is stored/read as literal text.
        evil = "x'; DROP TABLE scrapes;--"
        self.store.record(_OWNER, _record(evil, "2026-07-06T00:00:00+00:00", 1))
        history = self.store.history(_OWNER, evil)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].source_id, evil)


if __name__ == "__main__":
    unittest.main()
