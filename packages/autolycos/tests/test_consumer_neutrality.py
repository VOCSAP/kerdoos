"""autolycos names none of its consumers: no KERDOOS string, no kerdoos import."""

from __future__ import annotations

import ast
import pathlib
import unittest

_SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "autolycos"
_CONSUMER_TOKEN = "KERDOOS"
_CONSUMER_PACKAGE = "kerdoos"


def consumer_references(source: str) -> list[str]:
    findings = [
        f"line {number}: {line.strip()}"
        for number, line in enumerate(source.splitlines(), start=1)
        if _CONSUMER_TOKEN in line
    ]
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            modules = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules = [node.module]
        else:
            continue
        findings.extend(
            f"line {node.lineno}: imports {module}" for module in modules
            if module.split(".")[0] == _CONSUMER_PACKAGE)
    return findings


class ConsumerNeutralityTest(unittest.TestCase):
    def test_scanner_finds_each_kind_of_reference(self) -> None:
        sample = "\n".join([
            "import os",
            "import kerdoos.core",
            "from kerdoos.config import get_settings",
            "NAME = 'KERDOOS_BROWSER_MAX_CONCURRENT'",
        ])
        self.assertEqual(len(consumer_references(sample)), 3,
                         consumer_references(sample))

    def test_scanner_accepts_a_neutral_module(self) -> None:
        sample = "\n".join([
            "from autolycos.errors import FetchError",
            "LIMIT = 'max_concurrent'",
        ])
        self.assertEqual(consumer_references(sample), [])

    def test_no_source_file_references_a_consumer(self) -> None:
        files = sorted(_SRC.rglob("*.py"))
        self.assertTrue(files, f"no source file found under {_SRC}")
        offending = {}
        for path in files:
            findings = consumer_references(path.read_text(encoding="utf-8"))
            if findings:
                offending[str(path.relative_to(_SRC))] = findings
        self.assertEqual(offending, {})


if __name__ == "__main__":
    unittest.main()
