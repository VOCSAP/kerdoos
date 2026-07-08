"""Parser factory: whitelist gating + amazon adapter wiring (spec HIGH-1)."""

from __future__ import annotations

import unittest

from kerdoos.parsers.adapters.amazon import AmazonParser
from kerdoos.parsers.adapters.statejson import StateJsonParser
from kerdoos.parsers.factory import (KIND_WHITELIST, UnknownParserKindError,
                             build_parser)
from kerdoos.parsers.ports import ParserSpec


class FactoryTest(unittest.TestCase):
    def test_amazon_kind_builds_amazon_parser(self) -> None:
        parser = build_parser(ParserSpec(kind="amazon"))
        self.assertIsInstance(parser, AmazonParser)

    def test_statejson_kind_still_wired(self) -> None:
        spec = ParserSpec(kind="statejson", pix="a", card="b", availability="c")
        self.assertIsInstance(build_parser(spec), StateJsonParser)

    def test_amazon_in_whitelist(self) -> None:
        self.assertIn("amazon", KIND_WHITELIST)

    def test_unknown_kind_rejected(self) -> None:
        with self.assertRaises(UnknownParserKindError):
            build_parser(ParserSpec(kind="../../evil"))


if __name__ == "__main__":
    unittest.main()
