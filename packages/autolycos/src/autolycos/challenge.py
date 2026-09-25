"""Shared anti-bot challenge heuristic (pure module, no tool imports).

Hoisted so EVERY fetcher tier (http/tls/browser/uc/camoufox) derives
FetchResult.challenged from the SAME markers. The core retry loop keys on that
abstract signal, so it must be consistent across tiers -- a marker known to one
tier but not another would make retry behave differently per tool.

A response is treated as challenged when it is a hard block status, carries a
known challenge/interstitial marker, or is implausibly short for a real page.
"""

from __future__ import annotations

# Substrings (lowercased) specific to an ACTIVE anti-bot interstitial. Each must
# be absent from healthy pages: bare "captcha" and "challenge-platform" are
# deliberately NOT here -- they match Google reCAPTCHA v3 (grecaptcha-badge,
# recaptcha/api.js) and Cloudflare's PASSIVE telemetry script
# (/cdn-cgi/challenge-platform/.../scripts/) that legitimate pages embed, which
# would falsely flag them and drive a healthy fetch to INDETERMINATE.
#   * Cloudflare active challenge : "just a moment" (title), "cf-chl-" (challenge
#     element class), "_cf_chl_opt" (challenge JS options), "attention required".
#   * Vendor challenges           : "px-captcha" (PerimeterX), "datadome",
#     "_incapsula_" (Imperva).
#   * Akamai Bot Manager          : "scf-akamai" and "sec-if-cpt" are the real
#     challenge DOM (Magalu: sec-if-cpt-container / scf-akamai-logo /
#     behavioral-content), served at HTTP 200. "sec-cpt" is kept as a generic
#     Akamai hint but does NOT match Magalu's DOM (pending security-auditor call).
#   * Amazon Robot Check          : "validatecaptcha" (the /errors/validateCaptcha
#     form action of the anti-bot wall Amazon serves at HTTP 200; specific enough
#     not to hit a healthy /dp page, and restores retry on that soft block).
#   * MercadoLivre JS gate        : "account-verification" redirect + the
#     "micro-landing" shell that renders before hydration.
CHALLENGE_MARKERS: tuple[str, ...] = (
    "just a moment", "cf-chl-", "_cf_chl_opt", "attention required",
    "px-captcha", "datadome", "_incapsula_", "sec-cpt", "scf-akamai",
    "sec-if-cpt", "validatecaptcha",
    "captcha-wall-index", "account-verification", "micro-landing-container",
    "micro-landing-title",
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


# Chrome's OWN "can't reach this page" interstitial (a failed navigation --
# ERR_CONNECTION_REFUSED, DNS_PROBE_*, a timeout) is a distinct signal from
# CHALLENGE_MARKERS above: those are content a SITE serves, this is Chrome
# never reaching the site at all. Card 1bddf3fa: SeleniumBase UC's
# uc_open_with_reconnect does not raise on this failure -- it silently lands
# on the interstitial, which is large enough (~188KB) and generic enough to
# slip past looks_challenged unnoticed. Judged by CONTENT only (never size):
# a genuine large page and a large error page cannot be told apart by length.
# Hoisted here (not uc.py-local) so a Chrome-based tier other than uc can
# reuse the same predicate without duplicating it.
_CHROME_ERROR_PAGE_MARKER = '"errorCode":"ERR_'


def looks_like_chrome_error_page(current_url: str | None, text: str) -> bool:
    """True if Chrome served its OWN internal error page instead of
    anything the target actually returned."""
    if current_url is not None and current_url.startswith("chrome-error://"):
        return True
    return _CHROME_ERROR_PAGE_MARKER in text
