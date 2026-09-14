"""Camoufox Fetcher adapter (Firefox anti-detection, tier `camoufox`).

Akamai blocks the Linux Chromium tiers inside a container; Camoufox passes.
SSRF: validate_target first, then every connection goes through a per-fetch
PinningProxy that checks the CONNECT authority against the allowlist before
any resolution. There is no in-browser request interception: it was measured
inert and harmful on this Camoufox/Playwright pairing.
Nothing is downloaded at run time: the binary path, the Firefox version and
the excluded default addons are always passed explicitly, because the package
otherwise fetches a browser or an addon it finds missing.
The camoufox package, playwright and psutil are only imported inside
functions, so this module loads without the `camoufox` extra.
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import json
import logging
import os
import threading
import time
import uuid
import warnings
from collections.abc import Iterable, Mapping
from types import MappingProxyType
from urllib.parse import urlsplit

from ..browser_gate import BrowserGate, default_browser_gate
from ..challenge import looks_challenged
from ..egress_proxy import PinningProxy
from ..errors import FetchError
from ..ports import FetchResult
from ..safety import DomainPolicy, validate_target
from .browser import _is_hostname_shaped

logger = logging.getLogger(__name__)

MAX_HTML_BYTES = 5 * 1024 * 1024
# Measured through this adapter in a container: launch 0.4-1.8s over 19
# launches; goto plus the Akamai interstitial wait 2.1-15.6s on Magalu. The
# fetch budget covers both plus teardown, which includes PinningProxy.stop's
# own join of up to 5s. Past the deadline a frozen fetch still holds the
# gate for LATE_SWEEP_SECONDS and up to two KILL_WAIT_SECONDS, which keeps
# the whole hold under the composition root's 120s gate acquire timeout.
CAMOUFOX_LAUNCH_TIMEOUT_SECONDS = 20.0
CAMOUFOX_NAV_TIMEOUT_SECONDS = 45.0
CAMOUFOX_FETCH_TIMEOUT_SECONDS = 90.0
_WAIT_UNTIL = "load"
_SETTLE_POLL_MS = 250
KILL_WAIT_SECONDS = 5.0
LATE_SWEEP_SECONDS = 5.0
MAX_ABANDONED_FETCH_THREADS = 5

# Defaults for the autonomous image layout, not facts about the host running
# this code: CamoufoxFetcher and camoufox_ready take both as parameters.
CAMOUFOX_EXECUTABLE_PATH = "/opt/camoufox/camoufox-bin"
CAMOUFOX_BROWSER_VERSION = "152.0.4-beta.30"

# One LeakWarning per launch otherwise, which i_know_what_im_doing does not
# silence. geoip is off ON PURPOSE: turning it on downloads a database at
# launch, the runtime fetch this tier exists to avoid, and the proxy is ours,
# pinned to an address already verified, not an anonymising one. Set once at
# import rather than around each launch: warnings filters are process-global,
# so a per-launch catch_warnings would race between concurrent fetches.
# Matched by message on RuntimeWarning instead of importing the class, which
# lives in the package's PRIVATE _warnings module.
warnings.filterwarnings(
    "ignore", message="When using a proxy", category=RuntimeWarning)

_LAUNCH_ID_ARG_PREFIX = "--kerdoos-launch-id="
# By name, and checked against the package's own enum before every launch:
# an addon added upstream would otherwise be downloaded on first launch.
_EXCLUDED_DEFAULT_ADDONS = ("UBO",)
_DRIVER_CMDLINE_TOKEN = "playwright"
_BROWSER_CMDLINE_TOKEN = "camoufox"

FROZEN_FIREFOX_PREFS: Mapping[str, bool | int | str] = MappingProxyType({
    # Firefox otherwise connects to loopback addresses directly, bypassing
    # the proxy for exactly the address class it must refuse.
    "network.proxy.allow_hijacking_localhost": True,
    "network.proxy.no_proxies_on": "",
    "network.proxy.failover_direct": False,
    "network.trr.mode": 5,
    "network.dns.disablePrefetch": True,
    "network.dns.disablePrefetchFromHTTPS": True,
    "network.prefetch-next": False,
    "network.predictor.enabled": False,
    "network.predictor.enable-prefetch": False,
    "network.http.speculative-parallel-limit": 0,
    "browser.urlbar.speculativeConnect.enabled": False,
    "browser.places.speculativeConnect.enabled": False,
    "media.peerconnection.enabled": False,
    "network.http.http3.enable": False,
    "dom.serviceWorkers.enabled": False,
    "dom.push.enabled": False,
    "dom.push.connection.enabled": False,
    "network.captive-portal-service.enabled": False,
    "network.connectivity-service.enabled": False,
    "captivedetect.canonicalURL": "",
    "browser.safebrowsing.malware.enabled": False,
    "browser.safebrowsing.phishing.enabled": False,
    "browser.safebrowsing.blockedURIs.enabled": False,
    "browser.safebrowsing.downloads.enabled": False,
    "browser.safebrowsing.downloads.remote.enabled": False,
    "browser.safebrowsing.provider.google.updateURL": "",
    "browser.safebrowsing.provider.google.gethashURL": "",
    "browser.safebrowsing.provider.google4.updateURL": "",
    "browser.safebrowsing.provider.google4.gethashURL": "",
    "browser.safebrowsing.provider.mozilla.updateURL": "",
    "browser.safebrowsing.provider.mozilla.gethashURL": "",
    "app.update.auto": False,
    "app.update.checkInstallTime": False,
    "extensions.update.enabled": False,
    "extensions.update.autoUpdateDefault": False,
    "extensions.getAddons.cache.enabled": False,
    "extensions.systemAddon.update.enabled": False,
    "extensions.blocklist.enabled": False,
    "media.gmp-manager.url": "",
    "media.gmp-gmpopenh264.enabled": False,
    "media.gmp-widevinecdm.enabled": False,
    "browser.region.update.enabled": False,
    "browser.region.network.url": "",
    "toolkit.telemetry.enabled": False,
    "toolkit.telemetry.unified": False,
    "toolkit.telemetry.archive.enabled": False,
    "toolkit.telemetry.server": "",
    "toolkit.telemetry.newProfilePing.enabled": False,
    "toolkit.telemetry.shutdownPingSender.enabled": False,
    "toolkit.telemetry.firstShutdownPing.enabled": False,
    "toolkit.telemetry.updatePing.enabled": False,
    "toolkit.telemetry.bhrPing.enabled": False,
    "datareporting.healthreport.uploadEnabled": False,
    "datareporting.policy.dataSubmissionEnabled": False,
    "app.normandy.enabled": False,
    "app.normandy.api_url": "",
    "app.shield.optoutstudies.enabled": False,
    "breakpad.reportURL": "",
    "browser.tabs.crashReporting.sendReport": False,
    "browser.newtabpage.activity-stream.feeds.telemetry": False,
    "browser.newtabpage.activity-stream.telemetry": False,
    "geo.enabled": False,
    "geo.provider.network.url": "",
    "services.settings.server": "",
    # Held today only by camoufox.cfg defaults, which another build may change
    # (that cfg even enables the remote debugger).
    "network.webtransport.enabled": False,
    "devtools.debugger.remote-enabled": False,
    "browser.safebrowsing.passwords.enabled": False,
    "app.update.enabled": False,
    "app.update.service.enabled": False,
    "media.gmp-manager.updateEnabled": False,
    "dom.push.serverURL": "",
    # The allowlisted proxy refuses every CA responder anyway, so online
    # revocation is dropped explicitly; stapling sends no request of its own.
    "security.OCSP.enabled": 0,
    "security.ssl.enable_ocsp_stapling": True,
})

_abandoned_lock = threading.Lock()
_abandoned_fetch_thread_count = 0

_reported_problems: set[str] = set()
_reported_problems_lock = threading.Lock()


class _NotReady(Exception):
    """The Camoufox install cannot be launched without a download."""


def merged_firefox_prefs(
    caller_prefs: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """The caller's prefs with FROZEN_FIREFOX_PREFS on top. A caller
    `security.sandbox.*` pref is dropped: the content sandbox is never
    lowered from here."""
    merged = {
        key: value for key, value in (caller_prefs or {}).items()
        if not key.startswith("security.sandbox.")
    }
    merged.update(FROZEN_FIREFOX_PREFS)
    return merged


def _build_key(build: str) -> tuple[int, ...]:
    # Same ordering as camoufox.pkgman.Version, so this floor check agrees
    # with the one the package applies before deciding to download. That
    # ordering is private to the package; re-check it on any camoufox
    # version bump.
    parts = [int(x) if x.isdigit() else ord(x[0]) - 1024
             for x in build.split(".")]
    return tuple(parts + [0] * (5 - build.count(".")))


def _semver(version: str) -> tuple[int, ...]:
    parts = [int(p) if p.isdigit() else 0 for p in version.split(".")]
    return tuple(parts + [0] * (3 - len(parts)))


def _installed_version(executable_path: str) -> tuple[str, str]:
    """(version, build) from the version.json shipped beside the binary."""
    path = os.path.join(os.path.dirname(executable_path), "version.json")
    with open(path, "rb") as fh:
        data = json.load(fh)
    return str(data["version"]), str(data["build"])


def _package_browser_floor() -> str:
    """Lowest browser build the installed package accepts with the installed
    playwright. Runs camoufox/__version__.py on its own: importing the
    package pulls playwright in, too heavy for a check the scrape loop runs
    once per source.

    That file path and CONSTRAINTS.MIN_VERSION /
    PLAYWRIGHT_BROWSER_FLOORS are the package's private layout, held stable
    only by the exact camoufox pin: any version bump must re-check them."""
    spec = importlib.util.find_spec("camoufox")
    if spec is None or not spec.submodule_search_locations:
        raise LookupError("camoufox package not found")
    version_file = os.path.join(
        next(iter(spec.submodule_search_locations)), "__version__.py")
    module_spec = importlib.util.spec_from_file_location(
        "_autolycos_camoufox_constraints", version_file)
    if module_spec is None or module_spec.loader is None:
        raise LookupError(f"cannot load {version_file}")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    constraints = module.CONSTRAINTS
    floor = str(constraints.MIN_VERSION)
    playwright = _semver(importlib.metadata.version("playwright"))
    for required, build in constraints.PLAYWRIGHT_BROWSER_FLOORS:
        if playwright >= tuple(required) and _build_key(floor) < _build_key(build):
            floor = str(build)
    return floor


def _module_installed(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _ready_firefox_major(executable_path: str, expected_version: str) -> int:
    """The Firefox major version to pass as ff_version, or _NotReady."""
    for module in ("camoufox", "playwright", "psutil"):
        if not _module_installed(module):
            raise _NotReady(f"python module {module!r} is not installed")
    if not (os.path.isfile(executable_path)
            and os.access(executable_path, os.X_OK)):
        raise _NotReady(f"no executable Camoufox binary at {executable_path!r}")
    try:
        version, build = _installed_version(executable_path)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise _NotReady(
            f"unreadable version.json beside {executable_path!r}: {exc}"
        ) from exc
    installed = f"{version}-{build}"
    if installed != expected_version:
        raise _NotReady(
            f"installed Camoufox build {installed!r} differs from the "
            f"expected {expected_version!r}")
    major = version.split(".", 1)[0]
    if not major.isdigit():
        raise _NotReady(f"unparseable Firefox version {version!r}")
    try:
        floor = _package_browser_floor()
        below_floor = _build_key(build) < _build_key(floor)
    except Exception as exc:  # noqa: BLE001 -- failing to answer is a refusal
        raise _NotReady(f"cannot determine the browser build floor: {exc}") from exc
    if below_floor:
        raise _NotReady(
            f"installed Camoufox build {build!r} is below the floor {floor!r} "
            "required by the installed playwright")
    return int(major)


def camoufox_ready(executable_path: str = CAMOUFOX_EXECUTABLE_PATH,
                   expected_version: str = CAMOUFOX_BROWSER_VERSION) -> bool:
    """True iff a launch needs no download: package, playwright and psutil
    installed, an executable binary at `executable_path` whose version.json
    matches `expected_version` and satisfies the package's build floor.
    Each distinct reason for a refusal is logged once."""
    try:
        _ready_firefox_major(executable_path, expected_version)
    except _NotReady as exc:
        problem = str(exc)
        with _reported_problems_lock:
            first = problem not in _reported_problems
            _reported_problems.add(problem)
        if first:
            logger.warning("camoufox tier unavailable: %s", problem)
        return False
    return True


def _load_camoufox():  # type: ignore[no-untyped-def]
    from camoufox import DefaultAddons
    from camoufox.sync_api import Camoufox

    return Camoufox, DefaultAddons


def _is_playwright_timeout(exc: BaseException) -> bool:
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    except Exception:  # noqa: BLE001 -- a broken install must not mask `exc`
        return False
    return isinstance(exc, PlaywrightTimeoutError)


def _is_playwright_error(exc: BaseException) -> bool:
    try:
        from playwright.sync_api import Error as PlaywrightError
    except Exception:  # noqa: BLE001 -- a broken install must not mask `exc`
        return False
    return isinstance(exc, PlaywrightError)


def _cmdline_carries(proc, token: str) -> bool:  # type: ignore[no-untyped-def]
    try:
        return any(token in arg for arg in proc.cmdline())
    except Exception:  # noqa: BLE001 -- psutil.Error / race with process exit
        return False


def _snapshot_descendant_pids() -> frozenset[int] | None:
    try:
        import psutil

        me = psutil.Process(os.getpid())
        return frozenset(p.pid for p in me.children(recursive=True))
    except Exception:  # noqa: BLE001 -- no baseline, no attribution by novelty
        return None


def _launch_process_tree(  # type: ignore[no-untyped-def]
    marker: str, pids_before: frozenset[int] | None,
) -> list:
    """This launch's processes: the Firefox carrying `marker`, its playwright
    driver parent, and, when `pids_before` is given, any driver or Camoufox
    process born since that snapshot (the only way to reach a launch killed
    before Firefox existed). Pass `pids_before` only while this fetch holds a
    single-flight gate. Descendants of all of them are included."""
    import psutil

    try:
        candidates = psutil.Process(os.getpid()).children(recursive=True)
    except psutil.Error:
        return []
    roots = [p for p in candidates if _cmdline_carries(p, marker)]
    for proc in list(roots):
        try:
            parent = proc.parent()
        except psutil.Error:
            continue
        if parent is not None and _cmdline_carries(parent, _DRIVER_CMDLINE_TOKEN):
            roots.append(parent)
    if pids_before is not None:
        known = {p.pid for p in roots}
        roots.extend(
            p for p in candidates
            if p.pid not in pids_before and p.pid not in known
            and (_cmdline_carries(p, _DRIVER_CMDLINE_TOKEN)
                 or _cmdline_carries(p, _BROWSER_CMDLINE_TOKEN)))
    tree: dict[int, object] = {}
    for root in roots:
        tree[root.pid] = root
        try:
            for descendant in root.children(recursive=True):
                tree[descendant.pid] = descendant
        except psutil.Error:
            continue
    return list(tree.values())


def _kill_processes(procs) -> bool:  # type: ignore[no-untyped-def]
    """SIGKILL an already-identified set and wait for confirmed death. True
    iff none survives the wait."""
    import psutil

    if not procs:
        return True
    for proc in procs:
        try:
            proc.kill()
        except psutil.Error:
            pass
    _gone, alive = psutil.wait_procs(procs, timeout=KILL_WAIT_SECONDS)
    if alive:
        logger.warning(
            "camoufox tier: %d process(es) survived SIGKILL + %.1fs wait: %s",
            len(alive), KILL_WAIT_SECONDS, [p.pid for p in alive])
    return not alive


def _kill_launch(marker: str, pids_before: frozenset[int] | None) -> bool:
    try:
        import psutil  # noqa: F401
    except Exception:  # noqa: BLE001 -- the caller's FetchError must survive
        logger.warning(
            "camoufox tier: psutil is unavailable, cannot kill the process "
            "tree of launch %s", marker)
        return False
    return _kill_processes(_launch_process_tree(marker, pids_before))


_DEFAULT_PORTS: Mapping[str, int] = MappingProxyType({"http": 80, "https": 443})


def _effective_port(parts) -> int | None:  # type: ignore[no-untyped-def]
    """The URL's port, its scheme's default when absent, None when invalid."""
    try:
        port = parts.port
    except ValueError:
        return None
    return port if port is not None else _DEFAULT_PORTS.get(parts.scheme)


class CamoufoxFetcher:
    """Fetcher port implementation backed by Camoufox (headless Firefox).

    `subresource_domains` extends the proxy's allowlist past the navigation
    target, exactly like BrowserFetcher: validate_target
    still gates the primary URL on the DomainPolicy alone.
    """

    method_name = "camoufox"

    def __init__(self, domain_policy: DomainPolicy,
                 subresource_domains: Iterable[str] = (),
                 gate: BrowserGate | None = None,
                 launch_timeout_seconds: float = CAMOUFOX_LAUNCH_TIMEOUT_SECONDS,
                 nav_timeout_seconds: float = CAMOUFOX_NAV_TIMEOUT_SECONDS,
                 fetch_timeout_seconds: float = CAMOUFOX_FETCH_TIMEOUT_SECONDS,
                 max_abandoned_fetches: int = MAX_ABANDONED_FETCH_THREADS,
                 executable_path: str = CAMOUFOX_EXECUTABLE_PATH,
                 expected_version: str = CAMOUFOX_BROWSER_VERSION,
                 late_sweep_seconds: float = LATE_SWEEP_SECONDS,
                 ) -> None:
        self._domain_policy = domain_policy
        self._subresource_domains = frozenset(
            d.lower().rstrip(".") for d in subresource_domains if d)
        self._gate = gate if gate is not None else default_browser_gate()
        self._launch_timeout_seconds = launch_timeout_seconds
        self._nav_timeout_seconds = nav_timeout_seconds
        self._fetch_timeout_seconds = fetch_timeout_seconds
        self._max_abandoned_fetches = max_abandoned_fetches
        self._executable_path = executable_path
        self._expected_version = expected_version
        self._late_sweep_seconds = late_sweep_seconds

    def _host_allowed(self, host: str) -> bool:
        """The proxy's CONNECT domain check for this fetch. Fail-closed on an
        empty or malformed host."""
        host = host.lower().rstrip(".")
        return _is_hostname_shaped(host) and (
            self._domain_policy.domain_allowed(host)
            or any(host == d or host.endswith("." + d)
                   for d in self._subresource_domains))

    # Serialised and measured inside the page: a DOM over the cap never
    # crosses the Playwright pipe into this process.
    _CAPPED_HTML_JS = (
        "cap => { const h = document.documentElement.outerHTML;"
        " return h.length > cap ? null : h; }")

    # page.evaluate has no timeout and waits for the page's main thread, which
    # a busy page holds. wait_for_function's timeout is enforced by the driver
    # even then, and a primitive result comes back without another round trip
    # to the page. The predicate is always truthy: -1 stands for over the cap.
    # documentURI travels in the same read, ahead of the first newline (a URL
    # never holds one): Firefox leaves page.url on the attempted address of
    # its own error page, and only documentURI names that page.
    _BOUNDED_READ_JS = (
        "cap => { const h = (" + _CAPPED_HTML_JS + ")(cap);"
        " return h === null ? -1"
        " : document.documentURI + String.fromCharCode(10) + h; }")

    @classmethod
    def _read_document(cls, page, deadline: float | None = None) -> tuple[str, str]:  # type: ignore[no-untyped-def]
        """(documentURI, rendered DOM). With a `deadline` (time.monotonic()),
        a read still unanswered at it raises the Playwright TimeoutError;
        without one the read is unbounded."""
        if deadline is None:
            timeout_ms = 0.0
        else:
            # Playwright reads a timeout of 0 as no timeout at all.
            timeout_ms = max((deadline - time.monotonic()) * 1000, 1.0)
        value = page.wait_for_function(
            cls._BOUNDED_READ_JS, arg=MAX_HTML_BYTES,
            timeout=timeout_ms).json_value()
        if not isinstance(value, str):
            raise FetchError(
                f"rendered page exceeds {MAX_HTML_BYTES} characters cap")
        document_uri, _, html = value.partition("\n")
        return document_uri, html

    @classmethod
    def _read_capped(cls, page, deadline: float | None = None) -> str:  # type: ignore[no-untyped-def]
        return cls._read_document(page, deadline)[1]

    @classmethod
    def _settled_content(cls, page, status: int, deadline: float) -> tuple[str, str]:  # type: ignore[no-untyped-def]
        """(documentURI, DOM) once settled. Akamai answers the first
        navigation with a 200 JS interstitial that replaces itself with the
        real page after the load event has already fired. Polls until it is
        gone, and starts no poll once less than one interval of budget is
        left; any non-200 answer is returned as is. Every read is bounded by
        `deadline`: a first read past it raises FetchError, a poll read past
        it returns the interstitial already read."""
        try:
            document = cls._read_document(page, deadline)
        except Exception as exc:  # noqa: BLE001 -- narrowed just below
            if _is_playwright_timeout(exc):
                raise FetchError(
                    "rendered page could not be read within the navigation "
                    "budget") from exc
            raise
        interval = _SETTLE_POLL_MS / 1000
        while (status == 200 and looks_challenged(status, document[1])
               and deadline - time.monotonic() >= interval):
            page.wait_for_timeout(_SETTLE_POLL_MS)
            try:
                document = cls._read_document(page, deadline)
            except FetchError:
                raise
            except Exception:  # noqa: BLE001 -- mid-navigation or past the deadline
                continue
        return document

    @staticmethod
    def _check_final_document(final_url: str, requested_url: str,
                              document_uri: str | None = None) -> None:
        """A Firefox error page, or a script navigation to another allowed
        host or to another port, would otherwise be returned as the
        requested site's answer. The port may only change to the default of
        the final scheme, so http may still upgrade to https."""
        requested = urlsplit(requested_url)
        requested_host = (requested.hostname or "").rstrip(".")
        requested_port = _effective_port(requested)
        for url in (final_url or "", document_uri):
            if url is None:
                continue
            final = urlsplit(url)
            final_host = (final.hostname or "").rstrip(".")
            if final.scheme not in _DEFAULT_PORTS or final_host != requested_host:
                raise FetchError(
                    f"final document is {final.scheme}://{final_host}, not "
                    f"the requested host {requested_host}")
            final_port = _effective_port(final)
            if final_port not in (requested_port, _DEFAULT_PORTS[final.scheme]):
                raise FetchError(
                    f"final document is on port {final_port}, not the "
                    f"requested port {requested_port}")

    def _render(self, browser, url: str) -> FetchResult:  # type: ignore[no-untyped-def]
        context = browser.new_context(service_workers="block")
        try:
            # No context.route / route_web_socket guard: measured inert on this
            # Camoufox/Playwright pairing (handler never invoked) and harmful (a
            # page opening many channels timed out with it, returned without
            # it). Egress rests on the proxy's CONNECT check and the frozen prefs.
            page = context.new_page()
            # A script navigation after goto commits a document with its own
            # status; goto's response only describes the first one.
            document_statuses: list[int] = []

            def _record_document_status(nav_response) -> None:  # type: ignore[no-untyped-def]
                if (nav_response.request.is_navigation_request()
                        and nav_response.frame.parent_frame is None):
                    document_statuses.append(nav_response.status)

            page.on("response", _record_document_status)
            nav_deadline = time.monotonic() + self._nav_timeout_seconds
            response = page.goto(
                url, wait_until=_WAIT_UNTIL,
                timeout=self._nav_timeout_seconds * 1000)
            if response is None:
                raise FetchError("no response from navigation")
            document_uri, html = self._settled_content(
                page, response.status, nav_deadline)
            status = document_statuses[-1] if document_statuses else response.status
            self._check_final_document(page.url, url, document_uri)
            if len(html.encode("utf-8", errors="ignore")) > MAX_HTML_BYTES:
                raise FetchError(
                    f"rendered page exceeds {MAX_HTML_BYTES} bytes cap")
            return FetchResult(
                html=html, status=status, method=self.method_name,
                challenged=looks_challenged(status, html))
        finally:
            context.close()

    def _drive(self, camoufox_cls, launch_kwargs: dict, url: str) -> FetchResult:  # type: ignore[no-untyped-def]
        launched = False
        try:
            with PinningProxy(domain_allowed=self._host_allowed) as proxy:
                kwargs = {**launch_kwargs, "proxy": {"server": proxy.url}}
                with camoufox_cls(**kwargs) as browser:
                    launched = True
                    return self._render(browser, url)
        except Exception as exc:  # noqa: BLE001 -- narrowed just below
            if _is_playwright_timeout(exc):
                stage = "navigation" if launched else "launch"
                raise FetchError(f"camoufox {stage} timed out: {exc}") from exc
            if _is_playwright_error(exc):
                raise FetchError(f"camoufox browser error: {exc}") from exc
            raise

    def _kill_after_deadline(self, marker: str,
                             pids_before: frozenset[int] | None,
                             run_thread: threading.Thread) -> None:
        # The set is frozen at the deadline and killed before the owner
        # thread is given its short grace; the second pass only reaches what
        # that thread spawned after the freeze, and still runs under the gate.
        try:
            import psutil  # noqa: F401
        except Exception:  # noqa: BLE001 -- the caller's FetchError must survive
            logger.warning(
                "camoufox tier: psutil is unavailable, cannot kill the process "
                "tree of launch %s", marker)
            return
        _kill_processes(_launch_process_tree(marker, pids_before))
        run_thread.join(timeout=self._late_sweep_seconds)
        _kill_processes(_launch_process_tree(marker, pids_before))

    def fetch(self, url: str) -> FetchResult:
        validate_target(url, self._domain_policy)

        global _abandoned_fetch_thread_count
        with _abandoned_lock:
            abandoned_now = _abandoned_fetch_thread_count
        if abandoned_now >= self._max_abandoned_fetches:
            logger.error(
                "camoufox tier: refusing new fetch, %d abandoned fetch "
                "thread(s) at or above ceiling %d", abandoned_now,
                self._max_abandoned_fetches)
            raise FetchError(
                f"camoufox tier refused: {abandoned_now} abandoned fetch "
                f"thread(s) still alive (ceiling {self._max_abandoned_fetches})")

        try:
            firefox_major = _ready_firefox_major(
                self._executable_path, self._expected_version)
        except _NotReady as exc:
            raise FetchError(f"camoufox tier unavailable: {exc}") from exc

        camoufox_cls, default_addons = _load_camoufox()
        upstream_addons = {addon.name for addon in default_addons}
        unexcluded = sorted(upstream_addons - set(_EXCLUDED_DEFAULT_ADDONS))
        if unexcluded:
            raise FetchError(
                f"camoufox declares default addon(s) {unexcluded} that this "
                "adapter does not exclude by name; refusing a launch that "
                "would download them")

        marker = f"{_LAUNCH_ID_ARG_PREFIX}{uuid.uuid4().hex}"
        launch_kwargs = {
            "headless": True,
            "executable_path": self._executable_path,
            "ff_version": firefox_major,
            "i_know_what_im_doing": True,
            "geoip": False,
            "exclude_addons": [default_addons[name]
                               for name in _EXCLUDED_DEFAULT_ADDONS
                               if name in upstream_addons],
            "firefox_user_prefs": merged_firefox_prefs(),
            "args": [marker],
            "timeout": self._launch_timeout_seconds * 1000,
        }

        # Same cycle ownership as BrowserFetcher: the sync API is not
        # thread-safe, so one thread runs launch to close under a total
        # deadline. Three deliberate differences: the abandoned counter rises
        # at the deadline and falls when the thread exits, so clean kills never
        # pin the ceiling; attribution by PID novelty under a single-flight
        # gate reaches a launch killed before Firefox existed; a second pass
        # after the grace catches what the thread spawned after the freeze.
        holder: dict = {}
        state = {"claimed": False, "finished": False, "abandoned": False}
        claim_lock = threading.Lock()

        def _claim() -> bool:
            with claim_lock:
                if state["claimed"]:
                    return False
                state["claimed"] = True
                return True

        def _run() -> None:
            global _abandoned_fetch_thread_count
            try:
                outcome = ("result", self._drive(camoufox_cls, launch_kwargs, url))
            except BaseException as exc:  # noqa: BLE001 -- relayed or discarded
                outcome = ("error", exc)
            with _abandoned_lock:
                state["finished"] = True
                if state["abandoned"]:
                    _abandoned_fetch_thread_count -= 1
            if _claim():
                holder[outcome[0]] = outcome[1]
            else:
                _kill_launch(marker, None)

        with self._gate.acquire():
            single_flight = self._gate.max_concurrent == 1
            pids_before = _snapshot_descendant_pids() if single_flight else None
            run_thread = threading.Thread(
                target=_run, name="camoufox-fetch", daemon=True)
            run_thread.start()
            run_thread.join(timeout=self._fetch_timeout_seconds)
            if run_thread.is_alive() and _claim():
                with _abandoned_lock:
                    if not state["finished"]:
                        state["abandoned"] = True
                        _abandoned_fetch_thread_count += 1
                self._kill_after_deadline(marker, pids_before, run_thread)
                raise FetchError(
                    f"camoufox fetch exceeded {self._fetch_timeout_seconds}s "
                    "total timeout")
            run_thread.join()
        if "error" in holder:
            raise holder["error"]
        return holder["result"]
