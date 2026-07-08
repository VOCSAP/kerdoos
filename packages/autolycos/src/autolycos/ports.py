"""Autolycos ports -- the Fetcher contract and its result DTO.

FetchResult lives HERE (not in core/) because autolycos must stay extractible
without importing core. It carries the raw HTTP status as an int; the
three-valued verdict is computed in core/verdict.py, never here.

No tool imports in this module (Protocol + dataclass only). Concrete tools
(requests, curl_cffi, ...) live in autolycos/adapters/.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True, slots=True)
class FetchResult:
    """Outcome of a fetch attempt.

    status is the raw HTTP status code (int), NOT a verdict. `challenged` marks
    a detected anti-bot / rate-limit response (403/429/503 or a challenge
    marker); the core maps it to INDETERMINATE.
    """

    html: str
    status: int
    method: str
    challenged: bool = False


@runtime_checkable
class Fetcher(Protocol):
    """Resolve access to a URL and return its HTML."""

    def fetch(self, url: str) -> FetchResult:
        ...


@runtime_checkable
class Router(Protocol):
    """Resolve a fetcher tier name to a concrete Fetcher.

    Mirrors StaticRouter.select's signature exactly, so core/app/services.py
    can type-hint against this Protocol without importing the concrete
    router module (test_import_contract.py forbids core/ from importing any
    `router`-suffixed module).
    """

    def select(
        self, fetcher_name: str, subresource_domains: Iterable[str] = ()
    ) -> Fetcher:
        ...
