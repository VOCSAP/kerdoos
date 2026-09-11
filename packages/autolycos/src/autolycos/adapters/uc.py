"""UC Fetcher adapter (SeleniumBase undetected Chrome, MVP tier `uc`).

Top escalation tier for sites behind Akamai Bot Manager (Magazine Luiza): plain
requests get 403, curl_cffi and Playwright receive the Akamai challenge; only a
real undetected Chrome (SeleniumBase UC, headless) resolves the JS challenge.
This adapter is the ONLY reason the uc tier exists.

Anti-SSRF posture (spec HIGH-2 / M1, CWE-918), fail-closed:
  * validate_target runs FIRST, before SeleniumBase is imported and before Chrome
    launches, so a non-allowlisted / rebinding / private target is refused even
    when the optional dependency is absent (the guard raises first).
  * Pin + sub-resource allowlist = OPTION A, entirely at the DNS layer via one
    Chromium --host-resolver-rules argument (NO application-level request
    interception, unlike the browser tier's page.route: intercepting requests is
    detectable and would defeat the Akamai bypass). The composite rule
    (see _host_resolver_rules) blocks EVERYTHING by default (MAP * ~NOTFOUND),
    EXCLUDEs the navigation host and each declared render-critical CDN so they
    resolve normally, and pins the navigation host to the validated IP. Chrome's
    own resolver is thus constrained to the allowlist, closing the fan-out.
  * the rendered HTML is size-capped (anti-OOM, CWE-400).

Sequencing decision (Phase 2a, 2026-07-08): unlike the browser tier -- which
Phase 2a moved onto the loopback egress-proxy CONNECT (autolycos.egress_proxy)
-- the uc tier DELIBERATELY KEEPS its --host-resolver-rules pin here. ADR 0001
S9 says the egress-proxy applies to "browser AND uc", so this is an ASSUMED,
architect-acknowledged deviation: we do NOT replace a working Akamai bypass
(gate D passed for Magalu) with a CONNECT proxy we cannot yet validate against
real Akamai. Routing uc Chrome through the proxy is probably safe (a network
CONNECT proxy is not application-level page.route interception, and tunnelling
ciphertext preserves Chrome's own TLS fingerprint), but "probably" is not
enough to touch a functioning anti-bot path -- a silent regression would be
invisible to green unit tests (recon-B discipline). Wiring uc onto the
egress-proxy is deferred to Phase 7, E2E-gated against live Akamai (Magalu).

Fallback C (documented, NOT coded): if the composite host-resolver rule proves
too brittle in E2E (Akamai edge cases, CDP quirks), fall back to a MAP-only pin
of the navigation host and rely on the LXC network egress allowlist (the 6 site
domains + declared CDNs) as the PRIMARY sub-resource control. That is an infra
decision, deferred to the fast-follow, and is intentionally not implemented here.

SeleniumBase is imported lazily INSIDE fetch(), so this module -- and the whole
test suite -- imports fine without it; the uc tier is only ever exercised when
the static router selects it. Status is read from CDP when available, else falls
back to 200 (the core retry loop consumes the abstract `challenged` signal, which
is computed from the rendered page_source, not from the status).
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable

from ..browser_gate import BrowserGate, default_browser_gate
from ..challenge import looks_challenged
from ..errors import FetchError
from ..ports import FetchResult
from ..safety import DomainPolicy, ValidatedTarget, validate_target

MAX_HTML_BYTES = 5 * 1024 * 1024   # 5 MiB cap (largest recon dump ~1.5 MiB)
# Reconnect window (s) SeleniumBase UC uses to let the Akamai JS challenge settle.
RECONNECT_TIME = 6.0
RENDER_WAIT = 3.0
_STATUS_FALLBACK = 200


def _normalize_domains(domains: Iterable[str]) -> list[str]:
    # Sorted + de-duplicated for a deterministic rule string (testability).
    return sorted({d.lower().rstrip(".") for d in domains if d})


def _host_resolver_rules(
    target: ValidatedTarget, subresource_domains: Iterable[str]
) -> str:
    """Option A Chromium --host-resolver-rules value (deny-by-default allowlist).

    Composition (ORDER IS LOAD-BEARING, per Chromium host_mapping_rules.cc):
      MAP <nav host> <ip>    -- pin the navigation host to the validated IP FIRST
      MAP * ~NOTFOUND        -- block every other host by default
      EXCLUDE <each cdn>     -- let each declared render-critical CDN resolve

    Chromium's RewriteHost evaluates rules and an EXCLUDE match returns "no
    rewrite" and STOPS. So the nav MUST be pinned by the FIRST rule and must NOT
    be EXCLUDEd (an EXCLUDE <nav> after a wildcard MAP would cancel the rewrite
    and the pin would be silently dead -- reopening the DNS-rebind TOCTOU). The
    CDNs are EXCLUDEd from the wildcard ~NOTFOUND so they resolve normally; every
    other host falls through to MAP * -> ~NOTFOUND (blocked). An IPv6 literal is
    bracketed.
    """
    addr = f"[{target.ip}]" if ":" in target.ip else target.ip
    rules = [f"MAP {target.host} {addr}", "MAP * ~NOTFOUND"]
    rules += [f"EXCLUDE {d}" for d in _normalize_domains(subresource_domains)]
    return ", ".join(rules)


_MS_PLAYWRIGHT_CACHE = "~/.cache/ms-playwright"
_CHROMIUM_DIR_RE = re.compile(r"^chromium-(\d+)$")


def _find_patchright_chromium() -> str | None:
    """SeleniumBase's browser detection only searches PATH and fixed system
    paths, never patchright's private cache. Returns None when patchright's
    Chromium is absent (slim image, dev hosts).
    """
    base = os.path.expanduser(_MS_PLAYWRIGHT_CACHE)
    try:
        entries = os.listdir(base)
    except OSError:
        return None
    best: tuple[int, str] | None = None
    for name in entries:
        # Only a strict digits-only match is ever turned into a path: this
        # candidate is later shelled out by SeleniumBase (detect_b_ver.py
        # Popen(shell=True)), so a directory name is untrusted input here.
        match = _CHROMIUM_DIR_RE.fullmatch(name)
        if match is None:
            continue
        candidate = os.path.join(base, name, "chrome-linux64", "chrome")
        if not os.path.isfile(candidate):
            continue
        revision = int(match.group(1))
        if best is None or revision > best[0]:
            best = (revision, candidate)
    return best[1] if best else None


def _load_seleniumbase():  # type: ignore[no-untyped-def]
    """Lazy handle on SeleniumBase's Driver (optional dependency).

    Imported on demand so the module -- and the whole test suite -- loads on a
    base interpreter without SeleniumBase. Called only AFTER the SSRF guard has
    validated the target, so a hostile URL is refused even when the dependency
    is missing (the guard raises before we get here).
    """
    from seleniumbase import Driver

    return Driver


def _read_status(driver) -> int:  # type: ignore[no-untyped-def]
    """Best-effort HTTP status via CDP; 200 fallback when CDP is unavailable."""
    getter = getattr(driver, "get_http_status", None)
    if getter is None:
        return _STATUS_FALLBACK
    try:
        status = getter()
    except Exception:  # noqa: BLE001 -- CDP is best-effort; never fail the fetch
        return _STATUS_FALLBACK
    return int(status) if status else _STATUS_FALLBACK


class UcFetcher:
    """Fetcher port implementation backed by SeleniumBase undetected Chrome."""

    method_name = "uc"

    def __init__(self, domain_policy: DomainPolicy,
                 subresource_domains: Iterable[str] = (),
                 gate: BrowserGate | None = None) -> None:
        self._domain_policy = domain_policy
        self._subresource_domains = tuple(subresource_domains)
        self._gate = gate if gate is not None else default_browser_gate()

    def fetch(self, url: str) -> FetchResult:
        # SSRF guard runs FIRST, before importing/using SeleniumBase, so a
        # non-allowlisted or rebinding target is refused even if the optional
        # dependency is absent (fail-closed, CWE-918).
        target = validate_target(url, self._domain_policy)
        rule = _host_resolver_rules(target, self._subresource_domains)

        driver_cls = _load_seleniumbase()
        driver_kwargs = {
            "uc": True,
            "headless": True,
            # A list, not a bare string: SeleniumBase splits a string
            # chromium_arg on commas (browser_launcher.py get_local_driver),
            # which truncates this rule's internal commas (Chromium's own
            # syntax for composing MAP/EXCLUDE sub-rules in one flag value)
            # into bogus standalone switches, silently dropping the
            # deny-by-default MAP * ~NOTFOUND (roadmap dde2d243).
            "chromium_arg": [f"--host-resolver-rules={rule}"],
        }
        binary_location = _find_patchright_chromium()
        if binary_location is not None:
            driver_kwargs["binary_location"] = binary_location
        # Gate acquired around the whole launch-to-quit cycle (card ca30b736:
        # ADR 0002 Decision 1's single-Chromium OOM-coherence guarantee --
        # the SAME gate as the browser tier, since uc reuses its Chromium).
        with self._gate.acquire():
            driver = driver_cls(**driver_kwargs)
            try:
                # UC open + reconnect lets the Akamai JS challenge auto-resolve.
                driver.uc_open_with_reconnect(url, reconnect_time=RECONNECT_TIME)
                driver.sleep(RENDER_WAIT)
                html = driver.get_page_source()
                if len(html.encode("utf-8", errors="ignore")) > MAX_HTML_BYTES:
                    raise FetchError(
                        f"rendered page exceeds {MAX_HTML_BYTES} bytes cap")
                status = _read_status(driver)
                return FetchResult(
                    html=html,
                    status=status,
                    method=self.method_name,
                    # challenged is derived from the RENDERED DOM (Akamai
                    # serves its challenge at 200), not the status
                    # (invariant #3 + retry).
                    challenged=looks_challenged(status, html),
                )
            finally:
                driver.quit()
