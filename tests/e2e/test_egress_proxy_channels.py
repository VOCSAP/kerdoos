"""Image-level proof for the egress-proxy's page.route-invisible channels.

ADR 0004 D4/C1 (roadmap 5806b7d7). page.route only sees requests Playwright's
routing API is told about; it does NOT see service worker fetches,
WebSocket frames, or popup/new-page navigation by default. The PRIMARY
control is meant to be the PinningProxy's CONNECT-authority domain check
(autolycos.egress_proxy.PinningProxy), which every one of Chromium's
outbound connections is supposed to pass through regardless of which
in-page API triggered it. This file measures whether that is actually true
for four channels (WebSocket, a dedicated Worker's own fetch, a Service
Worker, and window.open), IN A REAL BROWSER, rather than asserting it from
reading the wiring code.

Reuses the REAL PinningProxy and the SAME context.route("**/*")/
service_workers="block" wiring as
autolycos.adapters.browser.BrowserFetcher._run -- this file does not import
from, patch, or modify egress_proxy.py or browser.py's own test doubles; it
drives the production PinningProxy class directly. domain_allowed is a
deny-all recorder (the worst case: the forbidden target is absent from
every DomainPolicy, exactly like a real attacker-controlled host would be),
so ANY successful reach of the target is a genuine bypass finding, not a
policy gap.

The hostile page is injected via page.set_content() -- never page.goto() to
a network URL -- so loading the harness page itself never needs to pass
validate_target/ip_is_safe (which would refuse it outright, being local
content) and never touches the proxy. Only the four channels' OWN egress
attempts, triggered from inside that page, are what gets measured.

The page reports each channel's outcome by mutating a DOM attribute, read
back via page.content() -- NOT via page.evaluate()/expose_function(),
which patchright's anti-detection CDP patches isolate from the page's real
JS globals even when the page's own script demonstrably ran (measured:
Kleos #17088 -- a plain `window.__x = 42` in the page is invisible to
page.evaluate() under patchright while the same script executes correctly
under vanilla playwright; a DOM mutation like `document.title = ...` IS
visible via page.content()/page.title(), a different CDP domain).

Not part of the default `pytest` run: launches a real Chromium and must run
inside the `autonomous` image (patchright + its Chromium installed). Opt-in
via KERDOOS_RUN_EGRESS_PROBE=1.
"""

from __future__ import annotations

import os
import re
import sys
import threading
from urllib.parse import urlsplit

import pytest

from autolycos.egress_proxy import PinningProxy, strip_dangerous_browser_args

# Symbolic forbidden target: link-local / cloud-metadata range, never
# reachable from a legitimate DomainPolicy and never resolvable to a global
# IP even if it were a hostname (ip_is_safe rejects it independently --
# this harness targets the DOMAIN-layer check, not the IP-layer one, which
# already has its own mutation-tested coverage per the roadmap card). A
# DISTINCT host per channel (same /24, all link-local/cloud-metadata-like)
# so the proxy's CONNECT log and the route-guard events can be attributed
# to exactly one channel -- four channels sharing one target would make
# "the proxy saw 169.254.169.254 once" ambiguous as to WHICH channel that
# CONNECT came from.
CHANNELS = ("websocket", "worker_fetch", "service_worker", "popup")
TARGET_HOSTS: dict[str, str] = {
    "websocket": "169.254.169.254",
    "worker_fetch": "169.254.169.253",
    "service_worker": "169.254.169.252",
    "popup": "169.254.169.251",
}
CHANNEL_TIMEOUT_MS = 4_000
SETTLE_SECONDS = 6.0

_HOSTILE_PAGE = f"""<!doctype html>
<meta charset="utf-8">
<div id="results">
  <span data-channel="websocket"></span>
  <span data-channel="worker_fetch"></span>
  <span data-channel="service_worker"></span>
  <span data-channel="popup"></span>
</div>
<script>
const TARGETS = {TARGET_HOSTS!r};
const TIMEOUT_MS = {CHANNEL_TIMEOUT_MS};

// DOM mutation, not a JS global: page.evaluate()/expose_function() are
// isolated from the page's real world under patchright (measured), but a
// DOM attribute mutated by the page's own script IS visible via
// page.content() (a different CDP domain -- DOM, not Runtime).
function report(channel, outcome) {{
  const el = document.querySelector('[data-channel="' + channel + '"]');
  if (el && el.textContent === "") el.textContent = outcome;
}}

// 1. WebSocket: a separate network stack from the Fetch/XHR surface
// page.route intercepts.
try {{
  const ws = new WebSocket("wss://" + TARGETS.websocket + "/canary");
  const t = setTimeout(function () {{
    report("websocket", "timeout");
    try {{ ws.close(); }} catch (e) {{}}
  }}, TIMEOUT_MS);
  ws.onopen = function () {{ clearTimeout(t); report("websocket", "open"); }};
  ws.onerror = function () {{ clearTimeout(t); report("websocket", "error_event"); }};
  ws.onclose = function (e) {{ clearTimeout(t); report("websocket", "closed_code_" + e.code); }};
}} catch (e) {{ report("websocket", "js_exception:" + e.message); }}

// 2. Dedicated Worker performing its OWN fetch: a separate execution
// context from the page.
try {{
  const workerSrc = "self.onmessage = async function () {{" +
    "try {{ const r = await fetch('https://" + TARGETS.worker_fetch + "/canary', {{mode: 'no-cors'}}); " +
    "self.postMessage('fetched_status_' + r.status); }} " +
    "catch (e) {{ self.postMessage('fetch_error:' + e.message); }} }};";
  const blob = new Blob([workerSrc], {{type: "application/javascript"}});
  const worker = new Worker(URL.createObjectURL(blob));
  const t2 = setTimeout(function () {{
    report("worker_fetch", "timeout");
    try {{ worker.terminate(); }} catch (e) {{}}
  }}, TIMEOUT_MS);
  worker.onmessage = function (e) {{
    clearTimeout(t2); report("worker_fetch", e.data);
    try {{ worker.terminate(); }} catch (er) {{}}
  }};
  worker.onerror = function (e) {{ clearTimeout(t2); report("worker_fetch", "worker_error:" + e.message); }};
  worker.postMessage("go");
}} catch (e) {{ report("worker_fetch", "js_exception:" + e.message); }}

// 3. Service Worker: registration itself can be refused for reasons that
// have NOTHING to do with egress control (opaque origin from
// page.set_content(), the "blob:" script scheme, disallowed by the SW spec
// for service workers specifically, unlike plain Workers above) -- the raw
// rejection message is kept so the harness can tell these two apart rather
// than mislabel a spec-mandated refusal as an egress block.
(async function () {{
  try {{
    if (!("serviceWorker" in navigator)) {{ report("service_worker", "unsupported_in_this_context"); return; }}
    const swSrc = "self.addEventListener('activate', function (e) {{ " +
      "e.waitUntil(fetch('https://" + TARGETS.service_worker + "/canary', {{mode:'no-cors'}})" +
      ".then(function (r) {{ self.__outcome = 'fetched_status_' + r.status; }})" +
      ".catch(function (err) {{ self.__outcome = 'fetch_error:' + err.message; }})); }});";
    const blob = new Blob([swSrc], {{type: "application/javascript"}});
    const url = URL.createObjectURL(blob);
    await navigator.serviceWorker.register(url);
    report("service_worker", "registered_pending_activation");
  }} catch (e) {{ report("service_worker", "register_rejected:" + e.message); }}
}})();

// 4. window.open: bound to the CONTEXT (not the page) precisely so
// context.route("**/*", ...) also covers it -- measure whether that guard
// (or the proxy behind it) actually intercepts it.
try {{
  const popup = window.open("https://" + TARGETS.popup + "/canary", "_blank");
  setTimeout(function () {{
    if (popup === null) {{ report("popup", "blocked_by_popup_blocker"); return; }}
    try {{ report("popup", "handle_state_closed_" + popup.closed); }}
    catch (e) {{ report("popup", "opaque_handle:" + e.message); }}
  }}, TIMEOUT_MS);
}} catch (e) {{ report("popup", "js_exception:" + e.message); }}
</script>
"""

_RESULT_RE = re.compile(r'data-channel="([a-z_]+)">([^<]*)</span>')


class _DomainAllowedRecorder:
    """Deny-all domain_allowed predicate that records every host the PROXY
    checked, in call order. This is the PRIMARY evidence that a channel's
    egress reached the CONNECT-authority check (ADR 0004 D4/C1) before any
    resolution -- independent of whether the JS side ever got a response
    (169.254.169.254 is not a listening host in this environment either
    way, so the JS-side outcome alone cannot distinguish "correctly
    blocked" from "bypassed the proxy and failed for an unrelated reason").
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.calls: list[str] = []

    def __call__(self, host: str) -> bool:
        with self._lock:
            self.calls.append(host)
        return False

    def saw(self, host: str) -> bool:
        with self._lock:
            return host in self.calls


def _extract_results(html: str) -> dict[str, str]:
    return {channel: outcome for channel, outcome in _RESULT_RE.findall(html)}


def run_probe() -> dict[str, str]:
    """Launch one real, patchright-driven Chromium behind an instrumented
    PinningProxy, drive the four channels from a page.set_content() page,
    and return a verdict per channel: "bloque", "PASSE" (bypass finding),
    or "non_concluant" (with the reason inlined)."""
    from patchright.sync_api import sync_playwright
    from playwright_stealth import Stealth

    recorder = _DomainAllowedRecorder()
    events_lock = threading.Lock()
    # host -> list of (source, failed) tuples: "route" (context.route's own
    # guard aborted it, never reached the proxy) or "cdp" (Playwright's
    # context-level network events / page-level websocket event).
    network_events: dict[str, list[tuple[str, bool]]] = {h: [] for h in TARGET_HOSTS.values()}

    def _record_event(source: str, url: str, *, failed: bool) -> None:
        host = urlsplit(url).hostname or ""
        with events_lock:
            if host in network_events:
                network_events[host].append((source, failed))

    with PinningProxy(domain_allowed=recorder) as proxy, sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            proxy={"server": proxy.url},
            args=strip_dangerous_browser_args([]),
            timeout=20_000,
        )
        try:
            # Same wiring as BrowserFetcher._run: service_workers="block"
            # on the context, context.route("**/*") bound to the context
            # (covers popups too). domain_allowed is the deny-all recorder
            # above, not BrowserFetcher._host_allowed -- this probe does not
            # need a real DomainPolicy, it only needs to know whether the
            # CONNECT authority for each target host is ever asked about.
            context = browser.new_context(service_workers="block")

            def _guard(route) -> None:  # noqa: ANN001
                host = urlsplit(route.request.url).hostname or ""
                if host in TARGET_HOSTS.values():
                    _record_event("route", route.request.url, failed=True)
                    route.abort()
                else:
                    route.continue_()

            context.route("**/*", _guard)
            context.on("request", lambda req: _record_event("cdp", req.url, failed=False))
            context.on("requestfailed", lambda req: _record_event("cdp", req.url, failed=True))
            popup_urls: list[str] = []
            context.on("page", lambda popup: popup_urls.append(popup.url))

            page = context.new_page()
            page.on("websocket", lambda ws: _record_event("cdp", ws.url, failed=False))
            Stealth().apply_stealth_sync(page)
            page.set_content(_HOSTILE_PAGE)
            page.wait_for_timeout(SETTLE_SECONDS * 1000)
            js_results = _extract_results(page.content())
            # Diagnostic only (not part of the verdict logic): if a popup
            # Page object was created but its url stayed "about:blank",
            # Chromium's popup-blocker (script-initiated window.open with no
            # user gesture) most likely intercepted it BEFORE any
            # navigation was even attempted -- explains a non-null popup
            # handle with zero route/CDP/proxy events for its target host.
            print(f"[diag] popup Page objects observed, final url(s): {popup_urls}",
                  file=sys.stderr)
        finally:
            browser.close()

    verdicts: dict[str, str] = {}
    for channel in CHANNELS:
        js_outcome = js_results.get(channel, "no_report")
        host = TARGET_HOSTS[channel]
        proxy_saw_host = recorder.saw(host)
        with events_lock:
            events_for_host = list(network_events[host])
        route_saw_host = any(source == "route" for source, _ in events_for_host)
        cdp_saw_host = any(source == "cdp" for source, _ in events_for_host)
        any_signal_saw_host = bool(events_for_host)
        all_events_failed = bool(events_for_host) and all(failed for _, failed in events_for_host)

        if channel == "service_worker" and js_outcome.startswith("register_rejected"):
            verdicts[channel] = (
                "non_concluant (enregistrement refuse avant tout acces "
                f"reseau, raison sans rapport avec l'egress: {js_outcome})"
            )
        elif channel == "service_worker" and js_outcome == "unsupported_in_this_context":
            # Control experiment (not part of this run): "serviceWorker" in
            # navigator is false on a data:/opaque-origin page REGARDLESS of
            # service_workers="block" vs the context default -- so this
            # harness's loading mechanism removes the channel before the
            # egress control under test ever gets exercised. Reporting this
            # as "bloque" would credit a control that was never actually
            # tried; a same-origin https:// page would be needed to test it
            # for real, which this harness's page.set_content()/data:
            # loading strategy structurally cannot provide.
            verdicts[channel] = (
                "non_concluant (navigator.serviceWorker absent sur l'origine "
                "opaque de ce harnais, MEME sans service_workers=\"block\" -- "
                "controle non exerce, pas prouve ; necessite une page "
                f"same-origin https:// hors de la portee de ce harnais ; js={js_outcome})"
            )
        elif "fetched_status_2" in js_outcome or js_outcome == "open":
            # The target actually answered -- in this environment that can
            # only happen if the connection escaped the proxy entirely.
            verdicts[channel] = f"PASSE -- cible atteinte (js={js_outcome})"
        elif proxy_saw_host:
            verdicts[channel] = (
                "bloque (autorite CONNECT du proxy interrogee et refusee ; "
                f"route_vu={route_saw_host}, cdp_vu={cdp_saw_host}, js={js_outcome})"
            )
        elif any_signal_saw_host and all_events_failed:
            verdicts[channel] = (
                "bloque (garde context.route/CDP, jamais atteint le proxy ; "
                f"route_vu={route_saw_host}, cdp_vu={cdp_saw_host}, js={js_outcome})"
            )
        else:
            verdicts[channel] = (
                f"non_concluant (ni le proxy ni context.route/CDP n'ont vu "
                f"de tentative pour {host} ; js={js_outcome})"
            )
    return verdicts


def _print_markdown(verdicts: dict[str, str]) -> None:
    print("| canal | verdict |")
    print("|---|---|")
    for channel, verdict in verdicts.items():
        print(f"| {channel} | {verdict} |")


@pytest.mark.skipif(
    os.environ.get("KERDOOS_RUN_EGRESS_PROBE") != "1",
    reason=(
        "launches a real Chromium behind the egress-proxy; opt-in only "
        "(KERDOOS_RUN_EGRESS_PROBE=1), run inside the autonomous image"
    ),
)
def test_egress_proxy_channels_image_probe() -> None:
    verdicts = run_probe()
    _print_markdown(verdicts)
    bypassed = [channel for channel, verdict in verdicts.items()
                if verdict.startswith("PASSE")]
    assert not bypassed, f"egress-proxy bypass found on channel(s): {bypassed}"


if __name__ == "__main__":
    _verdicts = run_probe()
    _print_markdown(_verdicts)
    _bypassed = [c for c, v in _verdicts.items() if v.startswith("PASSE")]
    sys.exit(1 if _bypassed else 0)
