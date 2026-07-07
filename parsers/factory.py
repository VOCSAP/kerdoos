"""Parser factory -- kind whitelist + adapter wiring (spec HIGH-1).

The kind is validated against a closed whitelist before any adapter is built,
so an untrusted/typo'd kind from the registry can never select an arbitrary
code path.
"""

from __future__ import annotations

from .adapters.amazon import AmazonParser
from .adapters.statejson import StateJsonParser
from .ports import Parser, ParserSpec

KIND_WHITELIST: frozenset[str] = frozenset(
    {"jsonld", "statejson", "css", "regex", "amazon"})


class UnknownParserKindError(ValueError):
    """The parser kind is not in the whitelist."""


def build_parser(spec: ParserSpec) -> Parser:
    if spec.kind not in KIND_WHITELIST:
        raise UnknownParserKindError(
            f"parser kind {spec.kind!r} not in whitelist {sorted(KIND_WHITELIST)}"
        )
    if spec.kind == "statejson":
        return StateJsonParser(spec)
    if spec.kind == "amazon":
        return AmazonParser(spec)
    raise NotImplementedError(
        f"parser kind {spec.kind!r} is whitelisted but not wired at the MVP"
    )
