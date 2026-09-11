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

import os
import threading
import uuid
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
# Roadmap d8b7b8fd: bounds the WHOLE launch-to-close cycle, not just the
# launch. Measured: a real Chromium frozen (SIGSTOP) right after a
# successful launch() blocks browser.new_page() indefinitely (45s
# observation, no return, no exception, no internal recovery) -- none of
# new_page/apply_stealth_sync/page.content/browser.close accept a timeout
# of their own, unlike chromium.launch. Default comfortably above
# BROWSER_LAUNCH_TIMEOUT_SECONDS + NAV_TIMEOUT_MS so a launch or navigation
# timeout that fires normally is never preempted by this outer one.
BROWSER_FETCH_TIMEOUT_SECONDS = 90.0
# An unknown Chromium switch (ignored by Chrome itself), unique per fetch,
# so a timed-out fetch's cleanup can target ONLY this fetch's own process
# tree (browser + its patchright Node driver parent + descendants) instead
# of a concurrent, unrelated fetch's.
_LAUNCH_ID_ARG_PREFIX = "--kerdoos-launch-id="
# Best-effort hard ceiling on watchdog threads abandoned by a timed-out
# fetch and not yet naturally exited (roadmap d8b7b8fd, modelled on
# 3c0b1c80's orphan-accumulation concern): each one is daemon and harmless
# on its own, but nothing bounds how many could pile up if the same freeze
# recurs across many fetches before any of them notices its process was
# killed and unblocks -- refuse new fetches past this ceiling rather than
# grow it without limit.
MAX_ABANDONED_FETCH_THREADS = 5

_abandoned_fetch_threads_lock = threading.Lock()
_abandoned_fetch_thread_count = 0


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


def _is_patchright_launch_timeout(exc: BaseException) -> bool:
    """True iff `exc` is patchright's own TimeoutError. Only imports
    patchright at the point an exception actually needs classifying (unlike
    a module-level or fetch()-entry import), and tolerates patchright being
    absent OR broken (a caller with a fake `_load_playwright` never needs
    the real package, and a corrupted patchright install must not mask the
    ORIGINAL exception `exc` behind an unrelated import failure -- caught
    broadly, not just ImportError, so any failure to even ask the question
    degrades to "not a recognized timeout, re-raise `exc` as-is").
    """
    try:
        from patchright.sync_api import TimeoutError as PlaywrightTimeoutError
    except Exception:  # noqa: BLE001 -- any import failure, not just missing
        return False
    return isinstance(exc, PlaywrightTimeoutError)


def _process_matches_launch(proc, marker: str) -> bool:  # type: ignore[no-untyped-def]
    try:
        cmdline = proc.cmdline()
    except Exception:  # noqa: BLE001 -- psutil.Error / race with process exit
        return False
    return any(marker in arg for arg in cmdline)


def _launch_process_tree(marker: str) -> list:  # type: ignore[no-untyped-def]
    """The OS process tree belonging to the fetch tagged with `marker`: the
    Chromium process whose cmdline carries it, its parent when that parent
    is patchright's own Node driver process (cmdline contains
    "patchright"), and all of their descendants (zygote/renderer/gpu/
    utility children, which do not carry the marker in their own argv).
    """
    import psutil

    try:
        candidates = psutil.Process(os.getpid()).children(recursive=True)
    except psutil.Error:
        return []

    roots = [p for p in candidates if _process_matches_launch(p, marker)]
    for proc in list(roots):
        try:
            parent = proc.parent()
        except psutil.Error:
            continue
        if parent is None:
            continue
        try:
            parent_cmdline = " ".join(parent.cmdline())
        except psutil.Error:
            continue
        if "patchright" in parent_cmdline:
            roots.append(parent)

    tree: dict[int, object] = {}
    for root in roots:
        tree[root.pid] = root
        try:
            for descendant in root.children(recursive=True):
                tree[descendant.pid] = descendant
        except psutil.Error:
            continue
    return list(tree.values())


def _kill_launch_processes(marker: str) -> None:
    """Best-effort: kill only the process tree of the fetch tagged with
    `marker`, so a fetch abandoned at the deadline never leaves a live (or
    stopped/frozen) Chromium behind without also hitting a concurrent,
    unrelated fetch's own process. SIGKILL works on a stopped process
    without needing SIGCONT first (measured). psutil is optional (declared
    under the `browser` extra); any error here is swallowed -- this is
    cleanup, not correctness.
    """
    for proc in _launch_process_tree(marker):
        try:
            proc.kill()
        except Exception:  # noqa: BLE001 -- psutil.Error, already exited, etc.
            pass


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
                 fetch_timeout_seconds: float = BROWSER_FETCH_TIMEOUT_SECONDS,
                 ) -> None:
        self._domain_policy = domain_policy
        self._subresource_domains = _normalize_domains(subresource_domains)
        self._gate = gate if gate is not None else default_browser_gate()
        self._launch_timeout_seconds = launch_timeout_seconds
        self._fetch_timeout_seconds = fetch_timeout_seconds

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

        global _abandoned_fetch_thread_count
        with _abandoned_fetch_threads_lock:
            abandoned_now = _abandoned_fetch_thread_count
        if abandoned_now >= MAX_ABANDONED_FETCH_THREADS:
            raise FetchError(
                f"browser tier refused: {abandoned_now} abandoned fetch(es) "
                f"not yet resolved (ceiling {MAX_ABANDONED_FETCH_THREADS})")

        sync_playwright = _load_playwright()
        stealth_cls = _load_stealth()

        # Unique per fetch: lets a timed-out fetch's cleanup target ONLY its
        # own process tree (roadmap d8b7b8fd, same technique as uc.py).
        marker = f"{_LAUNCH_ID_ARG_PREFIX}{uuid.uuid4().hex}"
        launch_args = [*strip_dangerous_browser_args([]), marker]

        holder: dict = {}
        claim_lock = threading.Lock()
        claimed = {"value": False}

        def _claim() -> bool:
            with claim_lock:
                if claimed["value"]:
                    return False
                claimed["value"] = True
                return True

        def _run() -> None:
            # Owns the ENTIRE launch-to-close cycle on this ONE thread, start
            # to finish: patchright's sync API is not thread-safe for a
            # cross-thread call (measured -- a call from a different thread
            # than the one that opened `with sync_playwright()` raises
            # immediately, regardless of Chromium's state), so no step here
            # can be delegated to yet another thread or bounded individually
            # from outside once started.
            global _abandoned_fetch_thread_count
            try:
                # Loopback IP-pinning egress-proxy: Chromium routes every
                # connection through it and never resolves the target itself,
                # closing the DNS-rebind TOCTOU at the network layer (ADR S9).
                with PinningProxy() as proxy, sync_playwright() as pw:
                    try:
                        browser = pw.chromium.launch(
                            headless=True,
                            proxy={"server": proxy.url},
                            args=launch_args,
                            timeout=self._launch_timeout_seconds * 1000,
                        )
                    except Exception as exc:  # noqa: BLE001 -- narrowed just below
                        if _is_patchright_launch_timeout(exc):
                            raise FetchError(
                                f"browser launch exceeded "
                                f"{self._launch_timeout_seconds}s timeout"
                            ) from exc
                        raise
                    try:
                        stealth = stealth_cls()
                        page = browser.new_page()
                        # JS-level stealth on top of patchright's launch
                        # patches, applied BEFORE any routing/navigation.
                        stealth.apply_stealth_sync(page)

                        def _guard(route) -> None:  # type: ignore[no-untyped-def]
                            # Allow a request iff its host is a navigation
                            # domain OR a declared render-critical
                            # sub-resource CDN; abort the rest. Fail-closed:
                            # an empty/unparseable host is aborted.
                            host = (urlsplit(route.request.url).hostname
                                    or "").lower().rstrip(".")
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
                                f"rendered page exceeds {MAX_HTML_BYTES} "
                                "bytes cap")
                        outcome = ("result", FetchResult(
                            html=html,
                            status=status,
                            method=self.method_name,
                            challenged=looks_challenged(status, html),
                        ))
                    finally:
                        browser.close()
            except BaseException as exc:  # noqa: BLE001 -- relayed or discarded
                outcome = ("error", exc)

            if _claim():
                kind, value = outcome
                holder[kind] = value
            else:
                # The deadline already fired and the main thread moved on:
                # this fetch's result is unreachable either way, so kill its
                # process tree (idempotent if the main thread's own kill
                # already ran) and stop counting it as abandoned.
                _kill_launch_processes(marker)
                with _abandoned_fetch_threads_lock:
                    _abandoned_fetch_thread_count -= 1

        # Gate acquired around the whole launch-to-close cycle (card
        # ca30b736: ADR 0002 Decision 1's single-Chromium OOM-coherence
        # guarantee), released only AFTER the kill below completes -- never
        # while a Chromium from THIS fetch could still be alive, or
        # KERDOOS_BROWSER_MAX_CONCURRENT's memory bound would be a lie.
        with self._gate.acquire():
            run_thread = threading.Thread(target=_run, daemon=True)
            run_thread.start()
            run_thread.join(timeout=self._fetch_timeout_seconds)
            if run_thread.is_alive() and _claim():
                with _abandoned_fetch_threads_lock:
                    _abandoned_fetch_thread_count += 1
                _kill_launch_processes(marker)
                raise FetchError(
                    f"browser fetch exceeded {self._fetch_timeout_seconds}s "
                    "total timeout")
            # Either the thread had already finished by the deadline, or it
            # won the claim race right as the deadline fired -- either way
            # it is about to return (or already has), so this join is
            # bounded.
            run_thread.join()
            if "error" in holder:
                raise holder["error"]
            return holder["result"]
