"""kerdoos looks budget terms up only by names autolycos declares."""

from __future__ import annotations

import ast
import pathlib
import typing
import unittest

from autolycos.tiers import TermName

CONFIG = (pathlib.Path(__file__).resolve().parents[1] / "packages" / "kerdoos"
          / "src" / "kerdoos" / "config.py")


def term_keys(source: str) -> list[str]:
    """Every literal key read as terms[<str>]."""
    return [
        node.slice.value for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Name) and node.value.id == "terms"
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
    ]


class TermNameContractTest(unittest.TestCase):
    def test_reader_finds_a_literal_key(self) -> None:
        sample = "\n".join([
            "terms = {}",
            "seconds = terms['bogus_seconds'].seconds",
        ])
        self.assertEqual(term_keys(sample), ["bogus_seconds"])

    def test_config_reads_only_declared_term_names(self) -> None:
        keys = term_keys(CONFIG.read_text(encoding="utf-8"))
        self.assertTrue(keys, "config.py reads no budget term by name")
        self.assertEqual(
            sorted(set(keys) - set(typing.get_args(TermName))), [],
            "config.py looks up term names autolycos does not declare")


if __name__ == "__main__":
    unittest.main()
