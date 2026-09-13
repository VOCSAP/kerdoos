"""Same-tier retry with backoff (invariant #5).

A generic loop above any Fetcher: it re-attempts a fetch while the ABSTRACT
FetchResult.challenged signal is set (anti-bot / rate-limit / transient block),
backing off between tries up to a bounded number of attempts. It keys ONLY on
the tool-agnostic FetchResult, never on a tool-specific exception, so the SAME
loop is reused by every tier (http/tls/browser/uc/camoufox).

Two concerns are deliberately kept OUT of this loop:
  * Inter-tier ESCALATION (http < tls < browser < uc < camoufox, invariant #6) is the
    post-MVP dynamic router's job, not retry. This is retry-SAME-tier only.
  * A browser adapter WAITING for render (networkidle / a selector to appear)
    is request COMPLETION handled inside the adapter, not a retry.

A hard FetchError is NOT retried here: it propagates to the orchestrator's
fail-closed net (which degrades to INDETERMINATE). Retry is driven exclusively
by the `challenged` signal on a returned FetchResult.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from autolycos.ports import FetchResult, Fetcher

# Total attempts = 1 initial + up to DEFAULT_RETRIES re-tries.
DEFAULT_RETRIES = 3
# Exponential backoff: sleep = backoff_base * 2**attempt (attempt 0-based).
DEFAULT_BACKOFF_BASE = 1.0


def fetch_with_retry(
    fetcher: Fetcher,
    url: str,
    *,
    retries: int = DEFAULT_RETRIES,
    backoff_base: float = DEFAULT_BACKOFF_BASE,
    sleep: Callable[[float], None] = time.sleep,
) -> FetchResult:
    """Fetch `url`, re-trying the SAME fetcher while the result is challenged.

    Returns the first non-challenged FetchResult, or -- if every attempt stays
    challenged -- the last (still challenged) result, which the verdict machine
    maps to INDETERMINATE. `sleep` is injectable so tests never block.
    """
    result = fetcher.fetch(url)
    attempt = 0
    while result.challenged and attempt < retries:
        sleep(backoff_base * (2 ** attempt))
        attempt += 1
        result = fetcher.fetch(url)
    return result
