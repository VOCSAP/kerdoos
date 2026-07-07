"""core.retry.fetch_with_retry: same-tier retry driven by the abstract signal.

The loop keys ONLY on FetchResult.challenged (never a tool exception), so a fake
Fetcher fully exercises it. `sleep` is injected as a recorder so the backoff is
asserted without real delay. The orchestrator-level "persistent challenge ->
INDETERMINATE" mapping is covered too (with the sleep neutralised).
"""

from __future__ import annotations

import unittest

from autolycos.errors import FetchError
from autolycos.ports import FetchResult
from core import retry
from core.domain import ScrapeStatus
from core.orchestrator import scrape_one


class _ScriptedFetcher:
    """Returns a scripted sequence of FetchResults / raises, one per call."""

    def __init__(self, script: list) -> None:
        self._script = list(script)
        self.calls = 0

    def fetch(self, url: str) -> FetchResult:
        self.calls += 1
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _ok(status: int = 200) -> FetchResult:
    return FetchResult(html="<html>" + "x" * 5000, status=status,
                       method="fake", challenged=False)


def _challenged(status: int = 503) -> FetchResult:
    return FetchResult(html="blocked", status=status, method="fake",
                       challenged=True)


class FetchWithRetryTest(unittest.TestCase):
    def test_challenged_then_ok_retries_and_returns_ok(self) -> None:
        slept: list[float] = []
        fetcher = _ScriptedFetcher([_challenged(503), _ok()])
        result = retry.fetch_with_retry(
            fetcher, "https://x/", sleep=slept.append)
        self.assertFalse(result.challenged)
        self.assertEqual(result.status, 200)
        self.assertEqual(fetcher.calls, 2)
        self.assertEqual(slept, [1.0])   # one backoff before the retry

    def test_first_attempt_ok_does_not_sleep(self) -> None:
        slept: list[float] = []
        fetcher = _ScriptedFetcher([_ok()])
        retry.fetch_with_retry(fetcher, "https://x/", sleep=slept.append)
        self.assertEqual(fetcher.calls, 1)
        self.assertEqual(slept, [])

    def test_persistent_challenge_exhausts_retries(self) -> None:
        slept: list[float] = []
        fetcher = _ScriptedFetcher([_challenged() for _ in range(10)])
        result = retry.fetch_with_retry(
            fetcher, "https://x/", retries=3, backoff_base=1.0,
            sleep=slept.append)
        self.assertTrue(result.challenged)
        self.assertEqual(fetcher.calls, 4)          # 1 + 3 retries
        self.assertEqual(slept, [1.0, 2.0, 4.0])    # exponential backoff

    def test_fetch_error_is_not_retried(self) -> None:
        # A hard FetchError propagates (it is NOT the abstract challenged
        # signal); the caller/orchestrator degrades it.
        fetcher = _ScriptedFetcher([FetchError("boom"), _ok()])
        with self.assertRaises(FetchError):
            retry.fetch_with_retry(fetcher, "https://x/", sleep=lambda _: None)
        self.assertEqual(fetcher.calls, 1)


class OrchestratorRetryTest(unittest.TestCase):
    def test_persistent_challenge_maps_to_indeterminate(self) -> None:
        # Through scrape_one, a persistently challenged fetch retries (sleep
        # neutralised) and lands as INDETERMINATE -- never a false OutOfStock.
        fetcher = _ScriptedFetcher([_challenged() for _ in range(10)])
        record = scrape_one(
            fetcher, parser=object(), source_id="c:ml:1",
            url="https://x/", now="2026-07-07T00:00:00+00:00",
            sleep=lambda _: None)
        self.assertEqual(record.status, ScrapeStatus.INDETERMINATE)
        self.assertEqual(fetcher.calls, 4)   # retried before degrading


if __name__ == "__main__":
    unittest.main()
