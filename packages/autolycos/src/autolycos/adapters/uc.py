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

import logging
import os
import re
import threading
import time
import uuid
from collections.abc import Iterable
from urllib.parse import quote

from ..browser_gate import BrowserGate, default_browser_gate
from ..challenge import looks_challenged, looks_like_chrome_error_page
from ..errors import FetchError
from ..ports import FetchResult
from ..safety import DomainPolicy, ValidatedTarget, validate_target

logger = logging.getLogger(__name__)

MAX_HTML_BYTES = 5 * 1024 * 1024   # 5 MiB cap (largest recon dump ~1.5 MiB)
# Reconnect window (s) SeleniumBase UC uses to let the Akamai JS challenge settle.
RECONNECT_TIME = 6.0
RENDER_WAIT = 3.0
_STATUS_FALLBACK = 200
# Card ca30b736: bounds the WebDriver navigation itself, so a frozen Chrome
# raises instead of holding the browser gate forever. Generous vs.
# RECONNECT_TIME + RENDER_WAIT (~9s) to tolerate a slow Akamai challenge.
UC_PAGE_LOAD_TIMEOUT_SECONDS = 45.0
# Roadmap c06082a5: SeleniumBase's uc_open_with_reconnect interpolates the
# url, unescaped, into a JS string literal (currently double-quoted)
# executed via execute_script -- ' is deliberately EXCLUDED from `safe`
# (encoded to %27) against a future seleniumbase change that interpolates
# between single quotes instead.
_JS_SAFE_URL_CHARS = ":/?#[]@!$&()*+,;=%"
# Roadmap 65cef071: bounds the Chrome LAUNCH itself (driver_cls(**kwargs)),
# unlike UC_PAGE_LOAD_TIMEOUT_SECONDS above which only takes effect once the
# launch has already returned. Without this, a hung launch (patchright cache
# corruption, an Xvfb issue, OOM) holds the browser gate forever, and with
# max_concurrent=1 that takes down the browser AND uc tiers process-wide.
# Default measured against 3 real Driver() constructions in the built
# autonomous image (0.33s-0.81s cold start included), generously multiplied
# to tolerate real-world load while staying well under
# UC_PAGE_LOAD_TIMEOUT_SECONDS and the browser gate's own acquire timeout.
UC_LAUNCH_TIMEOUT_SECONDS = 30.0
# Roadmap 6521bbce: a launch whose driver_cls(**kwargs) call never returns
# at all can still spawn a process AFTER the deadline's own one-shot kill
# already ran. A second sweep, run before releasing the browser gate,
# catches it -- see _launch_with_deadline. Public (no leading underscore,
# like UC_LAUNCH_TIMEOUT_SECONDS): kerdoos.config imports it as the single
# source of truth for KERDOOS_UC_ORPHAN_SWEEP_DELAY_SECONDS's own default.
ORPHAN_SWEEP_DELAY_SECONDS = 5.0
# Roadmap f0c236da, MEASURED (autonomous image, real Driver, SIGSTOP on
# Chrome after navigation): get_page_source(), current_url and quit() all
# hang past 60s with no client-side timeout -- a per-command timeout on
# Selenium's RemoteConnection (client_config.timeout, MEASURED against the
# same SIGSTOP scenario) does NOT bound them either, so this is a total
# deadline on the whole navigate-to-quit cycle, not a per-command one.
# Default budget: UC_PAGE_LOAD_TIMEOUT_SECONDS (45) + RECONNECT_TIME (6) +
# RENDER_WAIT (3) already sums to 54s under a normal navigation, and a
# MEASURED real cycle (data: URL) put get_page_source/current_url/quit at
# well under 1s combined -- comfortable margin above that floor.
UC_FETCH_TIMEOUT_SECONDS = 90.0
# Roadmap d8b7b8fd, MEASURED (browser tier, same mechanism): a bare kill()
# only SENDS SIGKILL and returns immediately -- an instrumented gate saw
# the targeted processes still genuinely running for ~0.5s after kill()
# returned, a window in which a caller releasing the gate right after
# could hand the slot to a new launch while this one's Chromium is still
# alive. _kill_identities waits (bounded) for confirmed death instead.
_KILL_WAIT_SECONDS = 5.0


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


# Roadmap 65cef071: an unknown Chrome switch (ignored by Chrome itself)
# injected into chromium_arg, unique per launch, so cleanup can identify
# THIS launch's OWN process tree by cmdline substring instead of by mere
# process-tree novelty, which also matches a concurrent, unrelated
# browser/uc launch's own Chrome.
_LAUNCH_ID_ARG_PREFIX = "--kerdoos-launch-id="
# SeleniumBase's own driver process sits between this Python process and the
# marked Chrome process; the marker itself lives only in Chrome's argv.
_LAUNCH_PARENT_NAMES = frozenset({"chromedriver", "uc_driver"})


def _process_matches_launch(proc, marker: str) -> bool:  # type: ignore[no-untyped-def]
    try:
        cmdline = proc.cmdline()
    except Exception:  # noqa: BLE001 -- psutil.Error / race with process exit
        return False
    return any(marker in arg for arg in cmdline)


def _snapshot_descendant_pids() -> frozenset[int]:
    """PIDs of this process's live descendants right now. Taken before a
    launch's own thread starts, this is the baseline `_launch_process_tree`
    diffs against to find a later-spawned uc_driver sibling -- PID
    membership only, never a process creation timestamp."""
    import psutil

    try:
        me = psutil.Process(os.getpid())
        return frozenset(p.pid for p in me.children(recursive=True))
    except psutil.Error:
        return frozenset()


def _launch_process_tree(  # type: ignore[no-untyped-def]
    marker: str, pids_before: frozenset[int] | None = None,
) -> list:
    """The OS process tree belonging to the launch tagged with `marker`:
    any live process whose cmdline carries it, that process's
    chromedriver/uc_driver parent if any, and all of their descendants.

    `pids_before`, a PID snapshot taken before this launch started, also
    matches a live uc_driver/chromedriver descendant NOT in that snapshot
    (it never carries the marker itself in undetected mode). Only pass it
    while this launch still holds the browser gate exclusively -- see
    UcFetcher._launch_with_deadline.
    """
    import psutil

    try:
        me = psutil.Process(os.getpid())
        candidates = me.children(recursive=True)
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
            parent_name = parent.name().lower()
        except psutil.Error:
            continue
        if parent_name in _LAUNCH_PARENT_NAMES:
            roots.append(parent)

    if pids_before is not None:
        known_pids = {r.pid for r in roots}
        for proc in candidates:
            if proc.pid in known_pids or proc.pid in pids_before:
                continue
            try:
                if proc.name().lower() in _LAUNCH_PARENT_NAMES:
                    roots.append(proc)
            except psutil.Error:
                continue

    tree: dict[int, object] = {}
    for root in roots:
        tree[root.pid] = root
        try:
            for descendant in root.children(recursive=True):
                tree[descendant.pid] = descendant
        except psutil.Error:
            continue
    return list(tree.values())


def _capture_identities(procs) -> list[tuple[int, float]]:  # type: ignore[no-untyped-def]
    """(pid, create_time) pairs for a live process list, so a caller can
    act on this EXACT set later without re-scanning by name."""
    import psutil

    identities = []
    for proc in procs:
        try:
            identities.append((proc.pid, proc.create_time()))
        except psutil.Error:
            continue
    return identities


def _kill_identities(identities: list[tuple[int, float]]) -> None:
    """Best-effort kill + reap for an already-identified (pid, create_time)
    set. Re-verifies identity against a FRESH psutil.Process immediately
    before acting, so a pid recycled since capture is skipped rather than
    signalled. uc_driver is routinely already a zombie by the time this
    runs; we are its direct parent, so os.waitpid(pid, WNOHANG) reaps it.

    Roadmap d8b7b8fd, MEASURED (browser tier, same mechanism): kill() only
    SENDS SIGKILL and returns immediately, before the kernel finishes
    tearing the process down -- psutil.wait_procs waits (bounded by
    _KILL_WAIT_SECONDS) for confirmed death, so a caller releasing the
    browser gate right after this call never does so on a false negative.
    """
    import psutil

    killed: list = []
    for pid, created in identities:
        try:
            proc = psutil.Process(pid)
            if proc.create_time() != created:
                continue  # pid recycled since capture; not our process
        except psutil.Error:
            continue
        try:
            proc.kill()
        except Exception:  # noqa: BLE001 -- psutil.Error, already exited, etc.
            pass
        else:
            killed.append(proc)
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass  # not our own direct child (a grandchild), or already reaped
        except Exception:  # noqa: BLE001 -- best-effort, never raise from cleanup
            pass
    if not killed:
        return
    _gone, alive = psutil.wait_procs(killed, timeout=_KILL_WAIT_SECONDS)
    if alive:
        logger.warning(
            "uc tier: %d process(es) survived SIGKILL + %.1fs wait: %s",
            len(alive), _KILL_WAIT_SECONDS, [p.pid for p in alive])


def _kill_launch_processes(
    marker: str, pids_before: frozenset[int] | None = None,
) -> None:
    """Best-effort: kill only the process tree of the launch tagged with
    `marker` (roadmap 65cef071), never a concurrent, unrelated launch's
    own process. psutil is optional (the `uc` extra); any error here is
    swallowed -- this is cleanup, not correctness."""
    _kill_identities(
        _capture_identities(_launch_process_tree(marker, pids_before)))


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


def _current_url(driver) -> str | None:  # type: ignore[no-untyped-def]
    """Best-effort; None if unavailable (mirrors _read_status)."""
    try:
        return driver.current_url
    except Exception:  # noqa: BLE001 -- best-effort, never fail the fetch on this alone
        return None


class UcFetcher:
    """Fetcher port implementation backed by SeleniumBase undetected Chrome."""

    method_name = "uc"

    def __init__(self, domain_policy: DomainPolicy,
                 subresource_domains: Iterable[str] = (),
                 gate: BrowserGate | None = None,
                 launch_timeout_seconds: float = UC_LAUNCH_TIMEOUT_SECONDS,
                 orphan_sweep_delay_seconds: float = ORPHAN_SWEEP_DELAY_SECONDS,
                 fetch_timeout_seconds: float = UC_FETCH_TIMEOUT_SECONDS,
                 ) -> None:
        self._domain_policy = domain_policy
        self._subresource_domains = tuple(subresource_domains)
        self._gate = gate if gate is not None else default_browser_gate()
        self._launch_timeout_seconds = launch_timeout_seconds
        self._orphan_sweep_delay_seconds = orphan_sweep_delay_seconds
        self._fetch_timeout_seconds = fetch_timeout_seconds

    def _launch_with_deadline(self, driver_cls, driver_kwargs):  # type: ignore[no-untyped-def]
        """Runs driver_cls(**driver_kwargs) (the Chrome launch itself) under
        self._launch_timeout_seconds. A native launch cannot be cancelled
        from Python once started, so a hang is bounded by abandoning the
        thread (daemon) and killing the process tree it spawned instead.

        A unique --kerdoos-launch-id marker is injected into chromium_arg so
        cleanup targets only THIS launch's own process tree (roadmap
        65cef071). An atomic claim decides which side -- this method's
        timeout, or the thread's own completion -- resolves the launch;
        whichever side loses cleans up (quit the Driver, kill the marked
        process tree) instead of leaking it.
        """
        launch_id = uuid.uuid4().hex
        marker = f"{_LAUNCH_ID_ARG_PREFIX}{launch_id}"
        driver_kwargs = dict(driver_kwargs)
        driver_kwargs["chromium_arg"] = [
            *driver_kwargs.get("chromium_arg", []), marker,
        ]
        # Roadmap 6521bbce: baseline _launch_process_tree diffs against to
        # find THIS launch's own uc_driver sibling (it never carries the
        # marker itself, and is never Chrome's parent, in undetected mode).
        pids_before = _snapshot_descendant_pids()
        # Only sound when no other launch can be creating processes at the
        # same time -- see the sweep below, which relies on this being
        # true for its whole duration, not just at this instant.
        single_flight = self._gate.max_concurrent == 1

        holder: dict = {}
        claim_lock = threading.Lock()
        claimed = {"value": False}
        # Populated by the deadline branch below, still under the gate.
        # A construction call that loses the claim AFTER that point runs
        # asynchronously with NO guarantee the gate is still held -- it may
        # act on this already-identified set, never a fresh PID diff (a
        # different launch could by then own the gate and its own uc_driver).
        frozen_siblings: list[tuple[int, float]] = []
        sweep_done = threading.Event()

        def _claim() -> bool:
            with claim_lock:
                if claimed["value"]:
                    return False
                claimed["value"] = True
                return True

        def _cleanup_after_losing_the_claim() -> None:
            sweep_done.wait(self._orphan_sweep_delay_seconds + 5.0)
            _kill_launch_processes(marker)  # marker match: safe at any time
            _kill_identities(frozen_siblings)

        def _construct() -> None:
            try:
                driver = driver_cls(**driver_kwargs)
            except BaseException as exc:  # noqa: BLE001 -- relayed to the caller
                if _claim():
                    holder["error"] = exc
                else:
                    _cleanup_after_losing_the_claim()
                return
            if _claim():
                holder["driver"] = driver
            else:
                try:
                    driver.quit()
                except Exception:  # noqa: BLE001 -- best-effort, caller is gone
                    pass
                _cleanup_after_losing_the_claim()

        launch_thread = threading.Thread(target=_construct, daemon=True)
        launch_thread.start()
        launch_thread.join(timeout=self._launch_timeout_seconds)
        if launch_thread.is_alive() and _claim():
            sibling_pids = pids_before if single_flight else None
            _kill_launch_processes(marker, sibling_pids)
            # The construction call may still be running (a launch that
            # never returns, roadmap 6521bbce) and spawn a process AFTER
            # this pass. A second pass catches it -- but ONLY while this
            # launch still holds the browser gate (single_flight): once
            # released, a different launch may be running, and a fresh
            # by-name/by-PID scan could then hit ITS process instead of
            # ours. The caller's `with self._gate.acquire():` still wraps
            # this whole method, so blocking here simply delays the
            # release rather than racing it.
            if single_flight:
                time.sleep(self._orphan_sweep_delay_seconds)
                frozen_siblings.extend(_capture_identities(
                    _launch_process_tree(marker, sibling_pids)))
                _kill_identities(frozen_siblings)
            sweep_done.set()
            raise FetchError(
                f"uc launch exceeded {self._launch_timeout_seconds}s timeout")
        sweep_done.set()
        # Either the thread had already finished by the deadline, or it won
        # the claim race right as the deadline fired -- either way it is
        # about to return (or already has), so this join is bounded.
        launch_thread.join()
        if "error" in holder:
            raise holder["error"]
        driver = holder["driver"]
        # Roadmap f0c236da: lets _run_after_launch_with_deadline clean up
        # THIS launch's own Chrome/renderers by marker, without threading a
        # new parameter through every _launch_with_deadline call site (many
        # tests call it directly with a bare driver_cls/driver_kwargs pair).
        try:
            driver._kerdoos_launch_marker = marker  # noqa: SLF001
        except Exception:  # noqa: BLE001 -- best-effort, never fail the launch
            pass
        return driver

    def _run_after_launch_with_deadline(  # type: ignore[no-untyped-def]
        self, driver, safe_url: str,
    ) -> FetchResult:
        """Runs navigation through get_page_source/status/quit under
        self._fetch_timeout_seconds. MEASURED (roadmap f0c236da): none of
        SeleniumBase's post-navigation calls, nor a client-side Selenium
        command timeout, are bounded when Chrome freezes -- so this is a
        total deadline on an owner thread, mirroring
        _launch_with_deadline. On timeout, driver.quit() is NEVER retried
        (it would hang identically); cleanup kills only THIS launch's own
        process tree, by marker (Chrome/renderers) and by
        driver.service.process.pid (uc_driver's EXACT pid, not a
        name/time heuristic), under the gate.
        """
        marker = getattr(driver, "_kerdoos_launch_marker", None)
        holder: dict = {}
        done = threading.Event()

        def _run() -> None:
            try:
                # Bounds the navigation itself (card ca30b736): without
                # this, a frozen Chrome holds the gate forever regardless
                # of any acquisition-side deadline.
                driver.set_page_load_timeout(UC_PAGE_LOAD_TIMEOUT_SECONDS)
                # UC open + reconnect lets the Akamai JS challenge auto-resolve.
                driver.uc_open_with_reconnect(
                    safe_url, reconnect_time=RECONNECT_TIME)
                driver.sleep(RENDER_WAIT)
                html = driver.get_page_source()
                if len(html.encode("utf-8", errors="ignore")) > MAX_HTML_BYTES:
                    raise FetchError(
                        f"rendered page exceeds {MAX_HTML_BYTES} bytes cap")
                status = _read_status(driver)
                # Card 1bddf3fa: uc_open_with_reconnect does not raise when
                # Chrome fails to reach the target -- it silently lands on
                # Chrome's OWN internal error interstitial, which
                # get_page_source() then returns as if it were the site's
                # response. Folded into `challenged` (not a raised
                # FetchError): retry.py's same-tier retry+backoff loop
                # (invariant 5) is driven exclusively by that signal on a
                # RETURNED FetchResult, a raised FetchError skips retry
                # entirely and degrades straight to INDETERMINATE.
                holder["result"] = FetchResult(
                    html=html,
                    status=status,
                    method=self.method_name,
                    # challenged is derived from the RENDERED DOM (Akamai
                    # serves its challenge at 200), not the status
                    # (invariant #3 + retry).
                    challenged=(
                        looks_challenged(status, html)
                        or looks_like_chrome_error_page(
                            _current_url(driver), html)
                    ),
                )
            except BaseException as exc:  # noqa: BLE001 -- relayed to the caller
                holder["error"] = exc
            finally:
                done.set()
                try:
                    driver.quit()
                except Exception:  # noqa: BLE001 -- best-effort cleanup
                    pass

        worker = threading.Thread(target=_run, daemon=True)
        worker.start()
        worker.join(timeout=self._fetch_timeout_seconds)
        if not done.is_set():
            self._kill_after_fetch_timeout(driver, marker)
            raise FetchError(
                f"uc post-navigation exceeded "
                f"{self._fetch_timeout_seconds}s timeout")
        if "error" in holder:
            raise holder["error"]
        return holder["result"]

    def _kill_after_fetch_timeout(self, driver, marker) -> None:  # type: ignore[no-untyped-def]
        """Best-effort cleanup for a fetch that exceeded its deadline:
        driver.quit() is never retried here (it would hang identically on
        the same frozen Chrome) -- kill by marker (Chrome/renderers) plus
        uc_driver's own service process, read directly from the Popen
        SeleniumBase already holds (no name/time heuristic needed)."""
        if marker is not None:
            _kill_launch_processes(marker)
        try:
            service_pid = driver.service.process.pid
        except Exception:  # noqa: BLE001 -- best-effort, service may be gone
            return
        import psutil

        try:
            service_proc = psutil.Process(service_pid)
        except psutil.Error:
            return
        _kill_identities(_capture_identities([service_proc]))

    def fetch(self, url: str) -> FetchResult:
        # SSRF guard runs FIRST, before importing/using SeleniumBase, so a
        # non-allowlisted or rebinding target is refused even if the optional
        # dependency is absent (fail-closed, CWE-918).
        target = validate_target(url, self._domain_policy)
        rule = _host_resolver_rules(target, self._subresource_domains)
        safe_url = quote(url, safe=_JS_SAFE_URL_CHARS)

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
            driver = self._launch_with_deadline(driver_cls, driver_kwargs)
            return self._run_after_launch_with_deadline(driver, safe_url)
