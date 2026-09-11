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
import threading
import uuid
from collections.abc import Iterable
from urllib.parse import quote

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


# Roadmap 65cef071 re-gate, finding C1: an unknown Chrome switch (ignored by
# Chrome itself) injected into chromium_arg, unique per launch, so cleanup
# can identify THIS launch's OWN process tree by cmdline substring instead of
# by mere process-tree novelty -- "every new child of the current process"
# also matches a concurrent, unrelated browser/uc launch's own Chrome.
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


def _launch_process_tree(marker: str) -> list:  # type: ignore[no-untyped-def]
    """The OS process tree belonging to the launch tagged with `marker`: any
    live process whose cmdline carries it, that process's parent when the
    parent is itself named chromedriver/uc_driver, and all of their
    descendants (renderer/GPU child processes, which do not carry the
    marker in their own argv).
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
            parent_name = parent.name().lower()
        except psutil.Error:
            continue
        if parent_name in _LAUNCH_PARENT_NAMES:
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
    """Best-effort: kill only the process tree of the launch tagged with
    `marker`, so a launch abandoned at the deadline never leaves a zombie
    behind (roadmap 65cef071) without also hitting a concurrent, unrelated
    launch's own process (re-gate finding C1). psutil is optional (declared
    under the `uc` extra); any error here is swallowed -- this is cleanup,
    not correctness.
    """
    for proc in _launch_process_tree(marker):
        try:
            proc.kill()
        except Exception:  # noqa: BLE001 -- psutil.Error, already exited, etc.
            pass


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
                 gate: BrowserGate | None = None,
                 launch_timeout_seconds: float = UC_LAUNCH_TIMEOUT_SECONDS,
                 ) -> None:
        self._domain_policy = domain_policy
        self._subresource_domains = tuple(subresource_domains)
        self._gate = gate if gate is not None else default_browser_gate()
        self._launch_timeout_seconds = launch_timeout_seconds

    def _launch_with_deadline(self, driver_cls, driver_kwargs):  # type: ignore[no-untyped-def]
        """Runs driver_cls(**driver_kwargs) (the Chrome launch itself) under
        self._launch_timeout_seconds. A native launch cannot be cancelled
        from Python once started, so a hang is bounded by abandoning the
        thread (daemon, never joined again after abandonment) and killing
        the process tree it spawned, rather than by cancelling the call
        itself.

        A unique --kerdoos-launch-id marker is injected into chromium_arg so
        cleanup can target THIS launch's own process tree instead of every
        new child of the current process, which also hits a concurrent,
        unrelated launch (roadmap 65cef071 re-gate, finding C1).

        Which side -- this method's timeout, or the thread's own completion
        -- gets to resolve the launch is decided by a single atomic claim.
        Whichever side loses it is the one that happened AFTER the other has
        already committed to its outcome: if the thread loses, it means the
        launch finished (successfully or not) only after this method had
        already given up and moved on, so the caller will never see that
        Driver -- the thread quits it and kills its process tree
        itself before returning (re-gate finding C2, a leak in the previous
        single-snapshot-at-the-deadline implementation). If this method
        loses (the launch finished right as the deadline fired), it defers
        to the thread's own result instead of raising a spurious timeout.
        """
        launch_id = uuid.uuid4().hex
        marker = f"{_LAUNCH_ID_ARG_PREFIX}{launch_id}"
        driver_kwargs = dict(driver_kwargs)
        driver_kwargs["chromium_arg"] = [
            *driver_kwargs.get("chromium_arg", []), marker,
        ]

        holder: dict = {}
        claim_lock = threading.Lock()
        claimed = {"value": False}

        def _claim() -> bool:
            with claim_lock:
                if claimed["value"]:
                    return False
                claimed["value"] = True
                return True

        def _construct() -> None:
            try:
                driver = driver_cls(**driver_kwargs)
            except BaseException as exc:  # noqa: BLE001 -- relayed to the caller
                if _claim():
                    holder["error"] = exc
                else:
                    _kill_launch_processes(marker)
                return
            if _claim():
                holder["driver"] = driver
            else:
                try:
                    driver.quit()
                except Exception:  # noqa: BLE001 -- best-effort, caller is gone
                    pass
                _kill_launch_processes(marker)

        launch_thread = threading.Thread(target=_construct, daemon=True)
        launch_thread.start()
        launch_thread.join(timeout=self._launch_timeout_seconds)
        if launch_thread.is_alive() and _claim():
            _kill_launch_processes(marker)
            raise FetchError(
                f"uc launch exceeded {self._launch_timeout_seconds}s timeout")
        # Either the thread had already finished by the deadline, or it won
        # the claim race right as the deadline fired -- either way it is
        # about to return (or already has), so this join is bounded.
        launch_thread.join()
        if "error" in holder:
            raise holder["error"]
        return holder["driver"]

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
            try:
                # Bounds the navigation itself (card ca30b736): without
                # this, a frozen Chrome holds the gate forever regardless of
                # any acquisition-side deadline.
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
