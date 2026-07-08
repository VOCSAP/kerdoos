"""Autolycos ports -- the Fetcher contract and its result DTO.

FetchResult lives HERE (not in core/) because autolycos must stay extractible
without importing core. It carries the raw HTTP status as an int; the
three-valued verdict is computed in core/verdict.py, never here.

No tool imports in this module (Protocol + dataclass only). Concrete tools
(requests, curl_cffi, ...) live in autolycos/adapters/.
"""

from __future__ import annotations

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
