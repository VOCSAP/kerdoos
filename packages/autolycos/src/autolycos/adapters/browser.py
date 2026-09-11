"""Browser Fetcher adapter (patchright/Chromium, MVP tier `browser`).

Escalation tier for SPA sites whose price is injected by client-side JS
(MercadoLivre today; the SAME adapter is reused by Terabyte/Pichau, only the DOM
parser differs). A headless Chromium renders the page so the DOM the parser sees
matches what a real browser produces.

Undetected launch (Phase 2b): the browser is LAUNCHED by patchright -- a
drop-in fork of playwright whose deep launch-time patches make Chromium
undetected at startup (Kleos #11050) -- NOT vanilla playwright. On top of the
launch patches, playwright-stealth's Stealth().apply_stealth_sync(page) injects
JS-level evasion into each page before navigation. patchright exposes the same
sync_api surface as playwright, so the egress-proxy wiring below is unchanged.

Anti-SSRF posture (spec HIGH-2 / M1, CWE-918), fail-closed:
  * validate_target runs FIRST, before Playwright is even imported and before
    any navigation, so a non-allowlisted / rebinding / private target is refused
    even when the optional dependency is absent (the guard raises first). This
    enforces the navigation-domain allowlist on the PRIMARY target (the proxy
    below does not: it is the network-layer IP guard, not the domain guard).
  * anti-rebind (ADR 0001 S9): Chromium is launched behind a loopback
    egress-proxy (PinningProxy) via proxy_config; Chromium NEVER resolves the
    target itself -- it CONNECTs through the proxy, which resolves once, rejects
    any non-global IP (ip_is_safe) and dials the PINNED IP. This closes the DNS
    rebind TOCTOU at the network layer for BOTH the primary navigation AND every
    sub-resource, replacing the fragile --host-resolver-rules launch flag. TLS
    stays end-to-end (the proxy tunnels ciphertext; SNI/cert/Host verification
    stay bound to the hostname). Egress-weakening launch flags are scrubbed
    (strip_dangerous_browser_args).
  * sub-resource fan-out is gated: page.route("**/*") aborts any request whose
    host is not in the domain allowlist (a rendered page pulls many hosts; only
    the target sites' domains may load). The proxy's IP pin backstops every host
    that page.route does permit.
  * the rendered HTML is size-capped (anti-OOM, CWE-400).

Playwright is imported lazily INSIDE fetch(), so this module -- and the whole
test suite -- imports fine without Playwright installed; the browser tier is
only ever exercised when the static router selects it. Waiting for the render to
settle (networkidle) is request COMPLETION, NOT retry (retry lives in the core).
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

from ..browser_gate import BrowserGate, default_browser_gate
from ..challenge import looks_challenged
from ..egress_proxy import PinningProxy, strip_dangerous_browser_args
from ..errors import FetchError
from ..ports import FetchResult
from ..safety import DomainPolicy, validate_target

MAX_HTML_BYTES = 5 * 1024 * 1024   # 5 MiB cap (largest recon dump ~1.5 MiB)
NAV_TIMEOUT_MS = 30_000
_WAIT_UNTIL = "networkidle"
# Roadmap b3213f3c: bounds the Chromium LAUNCH itself (pw.chromium.launch),
# which patchright otherwise bounds at its own 180s internal default --
# longer than KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS's default 120s, so a
# stuck launch would hold the shared BrowserGate past every other caller's
# own wait deadline. Kept below NAV_TIMEOUT_MS.
BROWSER_LAUNCH_TIMEOUT_SECONDS = 20.0


def _normalize_domains(domains: Iterable[str]) -> frozenset[str]:
    return frozenset(d.lower().rstrip(".") for d in domains if d)


def _load_playwright():  # type: ignore[no-untyped-def]
    """Lazy handle on patchright's sync_playwright (optional dependency).

    patchright is a drop-in playwright fork (same sync_api), so the symbol name
    is preserved. Imported on demand so the module -- and the whole test suite
    -- loads on a base interpreter without patchright. Called only AFTER the
    SSRF guard has validated the target, so a hostile URL is refused even when
    the dependency is missing (the guard raises before we get here).
    """
    from patchright.sync_api import sync_playwright

    return sync_playwright


def _load_stealth():  # type: ignore[no-untyped-def]
    """Lazy handle on playwright-stealth's Stealth class (optional dependency).

    Imported on demand (same rationale as _load_playwright) so the module loads
    without playwright-stealth installed.
    """
    from playwright_stealth import Stealth

    return Stealth


def _load_timeout_error():  # type: ignore[no-untyped-def]
    """Lazy handle on patchright's TimeoutError (same rationale as
    _load_playwright): imported on demand so this module loads without
    patchright installed.
    """
    from patchright.sync_api import TimeoutError as PlaywrightTimeoutError

    return PlaywrightTimeoutError


class BrowserFetcher:
    """Fetcher port implementation backed by Playwright (headless Chromium).

    `subresource_domains` is a per-site allowlist of RENDER-critical CDN hosts
    (e.g. MercadoLivre's http2.mlstatic.com bundle) that the page.route guard may
    load IN ADDITION to the navigation allowlist. It is deliberately SEPARATE
    from the injected DomainPolicy: we never NAVIGATE to these hosts
    (validate_target still governs the primary target + IP pin, gated by the
    caller's DomainPolicy only); they are permitted only as sub-resources so a
    full client-side render can hydrate.
    """

    method_name = "browser"

    def __init__(self, domain_policy: DomainPolicy,
                 subresource_domains: Iterable[str] = (),
                 gate: BrowserGate | None = None,
                 launch_timeout_seconds: float = BROWSER_LAUNCH_TIMEOUT_SECONDS,
                 ) -> None:
        self._domain_policy = domain_policy
        self._subresource_domains = _normalize_domains(subresource_domains)
        self._gate = gate if gate is not None else default_browser_gate()
        self._launch_timeout_seconds = launch_timeout_seconds

    def _subresource_allowed(self, host: str) -> bool:
        """Suffix-match a request host against the render-CDN allowlist."""
        return any(host == d or host.endswith("." + d)
                   for d in self._subresource_domains)

    def fetch(self, url: str) -> FetchResult:
        # SSRF guard runs FIRST, before importing/using Playwright, so a
        # non-allowlisted or rebinding target is refused even if the optional
        # dependency is absent (fail-closed, CWE-918). This also enforces the
        # navigation-domain allowlist on the primary target before we launch.
        validate_target(url, self._domain_policy)
        sync_playwright = _load_playwright()
        stealth = _load_stealth()()
        timeout_error = _load_timeout_error()

        # Loopback IP-pinning egress-proxy: Chromium routes every connection
        # (primary + sub-resources) through it and never resolves the target
        # itself, closing the DNS-rebind TOCTOU at the network layer (ADR S9).
        # Gate acquired around the whole launch-to-close cycle (card ca30b736:
        # ADR 0002 Decision 1's single-Chromium OOM-coherence guarantee).
        with self._gate.acquire(), PinningProxy() as proxy, sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(
                    headless=True,
                    proxy={"server": proxy.url},
                    # No caller args; scrub egress-weakening flags defensively.
                    args=strip_dangerous_browser_args([]),
                    timeout=self._launch_timeout_seconds * 1000,
                )
            except timeout_error as exc:
                raise FetchError(
                    f"browser launch exceeded {self._launch_timeout_seconds}s "
                    "timeout") from exc
            try:
                page = browser.new_page()
                # JS-level stealth on top of patchright's launch patches, applied
                # to the page BEFORE any routing/navigation.
                stealth.apply_stealth_sync(page)

                def _guard(route) -> None:  # type: ignore[no-untyped-def]
                    # Allow a request iff its host is a navigation domain OR a
                    # declared render-critical sub-resource CDN; abort the rest.
                    # Fail-closed: an empty/unparseable host is aborted. Controls
                    # the browser's SSRF fan-out surface.
                    host = (urlsplit(route.request.url).hostname or "").lower().rstrip(".")
                    if host and (self._domain_policy.domain_allowed(host)
                                 or self._subresource_allowed(host)):
                        route.continue_()
                    else:
                        route.abort()

                page.route("**/*", _guard)
                response = page.goto(
                    url, wait_until=_WAIT_UNTIL, timeout=NAV_TIMEOUT_MS)
                if response is None:
                    raise FetchError("no response from navigation")
                status = response.status
                html = page.content()
                if len(html.encode("utf-8", errors="ignore")) > MAX_HTML_BYTES:
                    raise FetchError(
                        f"rendered page exceeds {MAX_HTML_BYTES} bytes cap")
                return FetchResult(
                    html=html,
                    status=status,
                    method=self.method_name,
                    challenged=looks_challenged(status, html),
                )
            finally:
                browser.close()
