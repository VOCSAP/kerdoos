"""Shared anti-bot challenge heuristic (pure module, no tool imports).

Hoisted so EVERY fetcher tier (http/tls/browser/uc) derives
FetchResult.challenged from the SAME markers. The core retry loop keys on that
abstract signal, so it must be consistent across tiers -- a marker known to one
tier but not another would make retry behave differently per tool.

A response is treated as challenged when it is a hard block status, carries a
known challenge/interstitial marker, or is implausibly short for a real page.
"""

from __future__ import annotations

# Substrings (lowercased) that betray an anti-bot / interstitial response.
# The last three are MercadoLivre's JS "account verification" micro-landing
# (a client-side gate that redirects to /gz/account-verification and renders a
# noscript "enable JavaScript" shell): specific enough not to false-positive on
# a real product page.
CHALLENGE_MARKERS: tuple[str, ...] = (
    "captcha", "challenge-platform", "cf-chl", "just a moment",
    "attention required", "px-captcha", "datadome", "_incapsula_",
    "account-verification", "micro-landing-container", "micro-landing-title",
)

# Below this length a 200 body is almost certainly a block/stub, not a page.
_MIN_PLAUSIBLE_BYTES = 1500


def looks_challenged(status: int, text: str) -> bool:
    """True if the response looks like an anti-bot block / interstitial."""
    if status in (403, 429, 503):
        return True
    low = text.lower()
    if any(marker in low for marker in CHALLENGE_MARKERS):
        return True
    return len(text) < _MIN_PLAUSIBLE_BYTES
