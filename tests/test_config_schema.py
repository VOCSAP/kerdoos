"""config.db opened at the pre-ADR-0006 sources schema (source_id alone as
primary key) is refused with a named ConfigError and left untouched."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from kerdoos.registry.errors import ConfigError
from kerdoos.registry.sqlite_store import SqliteConfigStore

_PRE_0006_SOURCES = """
CREATE TABLE sources (
    source_id    TEXT PRIMARY KEY,
    owner_id     TEXT NOT NULL,
    product_key  TEXT NOT NULL,
    site         TEXT NOT NULL,
    url          TEXT NOT NULL,
    UNIQUE (owner_id, product_key, site, url)
);
INSERT INTO sources VALUES
    ('owner1:aw3225qf:kabum:7c5fc8d1bcd7', 'owner1', 'aw3225qf', 'kabum',
     'https://www.kabum.com.br/produto/1/a');
"""


def _snapshot(path: Path) -> tuple[list, list]:
    conn = sqlite3.connect(str(path))
    try:
        schema = conn.execute(
            "SELECT type, name, sql FROM sqlite_master ORDER BY name").fetchall()
        rows = conn.execute("SELECT * FROM sources").fetchall()
    finally:
        conn.close()
    return schema, rows


class Pre0006ConfigDbTest(unittest.TestCase):
    def test_old_sources_schema_is_refused_and_left_intact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.db"
            conn = sqlite3.connect(str(path))
            conn.executescript(_PRE_0006_SOURCES)
            conn.close()
            before = _snapshot(path)

            with self.assertRaisesRegex(ConfigError, "predates schema 5"):
                SqliteConfigStore(path)

            self.assertEqual(_snapshot(path), before)

    def test_schema_5_database_reopens_without_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.db"
            SqliteConfigStore(path).close()
            SqliteConfigStore(path).close()


if __name__ == "__main__":
    unittest.main()
