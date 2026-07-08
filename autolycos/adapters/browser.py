"""Browser Fetcher adapter (Playwright/Chromium, MVP tier `browser`).

Escalation tier for SPA sites whose price is injected by client-side JS
(MercadoLivre today; the SAME adapter is reused by Terabyte/Pichau, only the DOM
parser differs). A headless Chromium renders the page so the DOM the parser sees
matches what a real browser produces.

Anti-SSRF posture (spec HIGH-2 / M1, CWE-918), fail-closed:
  * validate_target runs FIRST, before Playwright is even imported and before
    any navigation, so a non-allowlisted / rebinding / private target is refused
    even when the optional dependency is absent (the guard raises first).
  * anti-rebind on the PRIMARY target: Chromium is launched with
    --host-resolver-rules="MAP <host> <validated-ip>", pinning the navigation to
    the exact IP safety resolved (the browser's own resolver is bypassed for
    that host), analogous to CURLOPT_RESOLVE in the tls tier. SNI, certificate
    verification and the Host header stay bound to the hostname.
  * sub-resource fan-out is gated: page.route("**/*") aborts any request whose
    host is not in the domain allowlist (a rendered page pulls many hosts; only
    the target sites' domains may load). The network egress policy backstops the
    non-pinned sub-resource hosts.
  * the rendered HTML is size-capped (anti-OOM, CWE-400).

Playwright is imported lazily INSIDE fetch(), so this module -- and the whole
test suite -- imports fine without Playwright installed; the browser tier is
only ever exercised when the static router selects it. Waiting for the render to
settle (networkidle) is request COMPLETION, NOT retry (retry lives in the core).
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

from ..challenge import looks_challenged
from ..errors import FetchError
from ..ports import FetchResult
from ..safety import DomainPolicy, ValidatedTarget, validate_target

MAX_HTML_BYTES = 5 * 1024 * 1024   # 5 MiB cap (largest recon dump ~1.5 MiB)
NAV_TIMEOUT_MS = 30_000
_WAIT_UNTIL = "networkidle"


def _normalize_domains(domains: Iterable[str]) -> frozenset[str]:
    return frozenset(d.lower().rstrip(".") for d in domains if d)


def _host_resolver_rules(target: ValidatedTarget) -> str:
    """Chromium --host-resolver-rules pinning the target host to the validated IP.

    Format is "MAP <host> <address>"; an IPv6 literal must be bracketed
    ("[2001:db8::1]") or the colons are mis-parsed and the pin is silently
    dropped -- which would re-open the DNS-rebind window for the primary
    navigation. Only the primary host is pinned here; sub-resource hosts are
    governed by the page.route domain allowlist plus the network egress policy.
    """
    addr = f"[{target.ip}]" if ":" in target.ip else target.ip
    return f"MAP {target.host} {addr}"


def _load_playwright():  # type: ignore[no-untyped-def]
    """Lazy handle on Playwright (optional dependency).

    Imported on demand so the module -- and the whole test suite -- loads on a
    base interpreter without Playwright. Called only AFTER the SSRF guard has
    validated the target, so a hostile URL is refused even when the dependency
    is missing (the guard raises before we get here).
    """
    from playwright.sync_api import sync_playwright

    return sync_playwright


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
                 subresource_domains: Iterable[str] = ()) -> None:
        self._domain_policy = domain_policy
        self._subresource_domains = _normalize_domains(subresource_domains)

    def _subresource_allowed(self, host: str) -> bool:
        """Suffix-match a request host against the render-CDN allowlist."""
        return any(host == d or host.endswith("." + d)
                   for d in self._subresource_domains)

    def fetch(self, url: str) -> FetchResult:
        # SSRF guard runs FIRST, before importing/using Playwright, so a
        # non-allowlisted or rebinding target is refused even if the optional
        # dependency is absent (fail-closed, CWE-918).
        target = validate_target(url, self._domain_policy)
        sync_playwright = _load_playwright()

        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                # Pin the primary navigation host to the validated IP.
                args=[f"--host-resolver-rules={_host_resolver_rules(target)}"],
            )
            try:
                page = browser.new_page()

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
