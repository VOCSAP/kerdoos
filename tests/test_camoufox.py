"""CamoufoxFetcher: install readiness, frozen prefs, launch wiring, liveness.

Camoufox is absent from the test venv. The launch is driven through a fake
Camoufox class injected in place of the lazy loader, and every kill is proven
against real child processes, never against a mock of psutil.
"""

from __future__ import annotations

import enum
import json
import os
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from autolycos import router as router_mod
from autolycos import safety
from autolycos.adapters import camoufox as cfx
from autolycos.browser_gate import BrowserGate
from autolycos.challenge import looks_challenged
from autolycos.errors import FetchError, SSRFError
from autolycos.router import StaticRouter, known_tiers, tier_available
from autolycos.safety import DomainPolicy

_POLICY = DomainPolicy(frozenset({"magazineluiza.com.br"}))
_URL = "https://www.magazineluiza.com.br/p/bab5438g3h/"
_REPO_ROOT = Path(__file__).resolve().parents[1]
_PAGE = "<html>" + "x" * 5000 + "</html>"
_INTERSTITIAL = ("<html><div class='sec-if-cpt-container'>"
                 + "y" * 2000 + "</div></html>")


def _addrinfo(ip: str, port: int = 443):
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
             (ip, port))]


def _write_install(root: Path, version: str = "152.0.4",
                   build: str = "beta.30") -> str:
    exe = root / "camoufox-bin"
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    exe.chmod(0o755)
    (root / "version.json").write_text(
        json.dumps({"version": version, "build": build}), encoding="utf-8")
    return str(exe)


class _Addons(enum.Enum):
    UBO = "https://addons.example/ubo.xpi"


class _AddonsWithNewcomer(enum.Enum):
    UBO = "https://addons.example/ubo.xpi"
    NEWCOMER = "https://addons.example/newcomer.xpi"


class _Response:
    def __init__(self, status: int) -> None:
        self.status = status


class _Page:
    """`contents` is served one read at a time, its last item repeating; an
    exception item is raised instead of returned."""

    def __init__(self, contents: list, status: int | None) -> None:
        self._contents = list(contents)
        self._status = status
        self.goto_args: tuple | None = None
        self.waits: list[float] = []

    def goto(self, url, wait_until, timeout):  # noqa: ANN001, ANN201
        self.goto_args = (url, wait_until, timeout)
        return None if self._status is None else _Response(self._status)

    def wait_for_timeout(self, ms: float) -> None:
        self.waits.append(ms)
        time.sleep(ms / 1000)

    def content(self) -> str:
        item = self._contents.pop(0) if len(self._contents) > 1 else self._contents[0]
        if isinstance(item, BaseException):
            raise item
        return item


class _Context:
    def __init__(self, page: _Page, kwargs: dict) -> None:
        self.page = page
        self.kwargs = kwargs
        self.route_args: tuple | None = None
        self.ws_route_args: tuple | None = None
        self.closed = False

    def route(self, pattern, handler) -> None:  # noqa: ANN001
        self.route_args = (pattern, handler)

    def route_web_socket(self, pattern, handler) -> None:  # noqa: ANN001
        self.ws_route_args = (pattern, handler)

    def new_page(self) -> _Page:
        return self.page

    def close(self) -> None:
        self.closed = True


class _Browser:
    def __init__(self, contents: list | None = None,
                 status: int | None = 200) -> None:
        self._contents = contents if contents is not None else [_PAGE]
        self._status = status
        self.contexts: list[_Context] = []

    def new_context(self, **kwargs) -> _Context:  # noqa: ANN003
        context = _Context(_Page(self._contents, self._status), kwargs)
        self.contexts.append(context)
        return context


class _FakeCamoufox:
    """Stands in for camoufox.sync_api.Camoufox: records each call's kwargs
    and yields `enter(kwargs)` as the launched browser."""

    def __init__(self, enter) -> None:  # noqa: ANN001
        self._enter = enter
        self.calls: list[dict] = []

    def __call__(self, **kwargs):  # noqa: ANN003, ANN204
        self.calls.append(kwargs)
        enter = self._enter

        class _Manager:
            def __enter__(self):  # noqa: ANN204
                return enter(kwargs)

            def __exit__(self, *exc) -> bool:  # noqa: ANN002
                return False

        return _Manager()


class _FakeRoute:
    def __init__(self, url: str) -> None:
        self.request = mock.Mock(url=url)
        self.action: str | None = None

    def continue_(self) -> None:
        self.action = "continue"

    def abort(self) -> None:
        self.action = "abort"


def _marker(kwargs: dict) -> str:
    return next(a for a in kwargs["args"]
                if a.startswith(cfx._LAUNCH_ID_ARG_PREFIX))


def _sleeper(*argv: str) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)", *argv])


class _CounterIsolation(unittest.TestCase):
    def setUp(self) -> None:
        with cfx._abandoned_lock:
            saved = cfx._abandoned_fetch_thread_count
            cfx._abandoned_fetch_thread_count = 0

        def _restore() -> None:
            with cfx._abandoned_lock:
                cfx._abandoned_fetch_thread_count = saved

        self.addCleanup(_restore)
        with cfx._reported_problems_lock:
            cfx._reported_problems.clear()


class ImportWithoutExtraTest(unittest.TestCase):
    def test_router_and_adapter_work_with_the_extra_blocked(self) -> None:
        script = textwrap.dedent("""
            import sys
            for name in ("camoufox", "playwright", "psutil"):
                sys.modules[name] = None
            from autolycos.errors import SSRFError
            from autolycos.router import StaticRouter, tier_available
            from autolycos.safety import DomainPolicy
            router = StaticRouter(DomainPolicy(frozenset({"example.com"})))
            fetcher = router.select("camoufox")
            assert type(fetcher).__name__ == "CamoufoxFetcher", fetcher
            assert tier_available("camoufox") is False
            assert router.tier_available("camoufox") is False
            try:
                fetcher.fetch("https://not-allowlisted.invalid/")
            except SSRFError:
                print("SSRF-FIRST")
        """)
        proc = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True,
            timeout=60, cwd=str(_REPO_ROOT))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("SSRF-FIRST", proc.stdout)


class FrozenPrefsTest(unittest.TestCase):
    _REQUIRED = {
        "network.proxy.allow_hijacking_localhost": True,
        "network.proxy.no_proxies_on": "",
        "network.proxy.failover_direct": False,
        "network.trr.mode": 5,
        "network.dns.disablePrefetch": True,
        "network.prefetch-next": False,
        "network.predictor.enabled": False,
        "network.http.speculative-parallel-limit": 0,
        "media.peerconnection.enabled": False,
        "network.http.http3.enable": False,
        "dom.serviceWorkers.enabled": False,
        "dom.push.enabled": False,
        "network.captive-portal-service.enabled": False,
        "network.connectivity-service.enabled": False,
        "browser.safebrowsing.malware.enabled": False,
        "app.update.auto": False,
        "extensions.update.enabled": False,
        "toolkit.telemetry.enabled": False,
        "datareporting.healthreport.uploadEnabled": False,
        "geo.enabled": False,
        "services.settings.server": "",
        "security.OCSP.enabled": 0,
        "security.ssl.enable_ocsp_stapling": True,
    }

    def test_every_required_pref_wins_over_a_contrary_caller_value(self) -> None:
        contrary = {name: "caller-override" for name in self._REQUIRED}
        merged = cfx.merged_firefox_prefs(contrary)
        for name, expected in self._REQUIRED.items():
            with self.subTest(pref=name):
                self.assertEqual(merged.get(name), expected)

    def test_unrelated_caller_pref_is_kept(self) -> None:
        merged = cfx.merged_firefox_prefs({"intl.accept_languages": "pt-BR"})
        self.assertEqual(merged["intl.accept_languages"], "pt-BR")

    def test_caller_cannot_lower_the_content_sandbox(self) -> None:
        merged = cfx.merged_firefox_prefs({
            "security.sandbox.content.level": 0,
            "security.sandbox.warn_unprivileged_namespaces": False,
        })
        self.assertEqual(
            [k for k in merged if k.startswith("security.sandbox.")], [])

    def test_frozen_list_itself_never_touches_the_sandbox(self) -> None:
        self.assertEqual(
            [k for k in cfx.FROZEN_FIREFOX_PREFS
             if k.startswith("security.sandbox.")], [])

    def test_frozen_list_is_read_only(self) -> None:
        with self.assertRaises(TypeError):
            cfx.FROZEN_FIREFOX_PREFS["network.trr.mode"] = 0  # type: ignore[index]


class ReadinessTest(_CounterIsolation):
    def setUp(self) -> None:
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        patcher = mock.patch.object(cfx, "_module_installed", return_value=True)
        self.module_installed = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(
            cfx, "_package_browser_floor", return_value="beta.30")
        self.floor = patcher.start()
        self.addCleanup(patcher.stop)

    def test_matching_install_is_ready(self) -> None:
        exe = _write_install(self.root)
        self.assertTrue(cfx.camoufox_ready(exe, "152.0.4-beta.30"))
        self.assertEqual(cfx._ready_firefox_major(exe, "152.0.4-beta.30"), 152)

    def test_each_missing_module_is_unavailable(self) -> None:
        exe = _write_install(self.root)
        for missing in ("camoufox", "playwright", "psutil"):
            with self.subTest(module=missing):
                self.module_installed.side_effect = (
                    lambda name, absent=missing: name != absent)
                self.assertFalse(cfx.camoufox_ready(exe, "152.0.4-beta.30"))

    def test_absent_binary_is_unavailable(self) -> None:
        self.assertFalse(cfx.camoufox_ready(
            str(self.root / "camoufox-bin"), "152.0.4-beta.30"))

    @unittest.skipIf(os.name == "nt", "no execute bit on Windows")
    def test_non_executable_binary_is_unavailable(self) -> None:
        exe = _write_install(self.root)
        os.chmod(exe, 0o644)
        self.assertFalse(cfx.camoufox_ready(exe, "152.0.4-beta.30"))

    def test_binary_without_version_json_is_unavailable(self) -> None:
        exe = self.root / "camoufox-bin"
        exe.write_text("", encoding="utf-8")
        exe.chmod(0o755)
        self.assertFalse(cfx.camoufox_ready(str(exe), "152.0.4-beta.30"))

    def test_unreadable_version_json_is_unavailable(self) -> None:
        exe = _write_install(self.root)
        version_json = self.root / "version.json"
        for body in ("", "{not json", json.dumps({"version": "152.0.4"}),
                     json.dumps(["152.0.4", "beta.30"])):
            with self.subTest(body=body):
                version_json.write_text(body, encoding="utf-8")
                self.assertFalse(cfx.camoufox_ready(exe, "152.0.4-beta.30"))

    def test_version_mismatch_is_unavailable_and_names_both_values(self) -> None:
        exe = _write_install(self.root, build="beta.31")
        with self.assertLogs("autolycos.adapters.camoufox", "WARNING") as cm:
            self.assertFalse(cfx.camoufox_ready(exe, "152.0.4-beta.30"))
        self.assertIn("152.0.4-beta.31", cm.output[0])
        self.assertIn("152.0.4-beta.30", cm.output[0])

    def test_build_below_the_package_floor_is_unavailable(self) -> None:
        exe = _write_install(self.root, build="beta.29")
        self.assertFalse(cfx.camoufox_ready(exe, "152.0.4-beta.29"))

    def test_undeterminable_floor_is_unavailable(self) -> None:
        exe = _write_install(self.root)
        self.floor.side_effect = LookupError("no CONSTRAINTS")
        self.assertFalse(cfx.camoufox_ready(exe, "152.0.4-beta.30"))

    def test_same_refusal_is_logged_once(self) -> None:
        exe = str(self.root / "camoufox-bin")
        with self.assertLogs("autolycos.adapters.camoufox", "WARNING") as cm:
            cfx.camoufox_ready(exe, "152.0.4-beta.30")
            cfx.camoufox_ready(exe, "152.0.4-beta.30")
        self.assertEqual(len(cm.output), 1)


class BuildOrderTest(unittest.TestCase):
    def test_orders_like_the_package(self) -> None:
        key = cfx._build_key
        self.assertLess(key("beta.29"), key("beta.30"))
        self.assertLess(key("beta.9"), key("beta.10"))
        self.assertLess(key("alpha.40"), key("beta.1"))
        self.assertLess(key("beta.30"), key("1"))


class PackageFloorTest(unittest.TestCase):
    """The floor comes from the package's own CONSTRAINTS, read without
    importing the package: its __init__ here raises if executed."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        pkg = Path(tmp.name) / "camoufox"
        pkg.mkdir()
        (pkg / "__init__.py").write_text(
            "raise RuntimeError('package imported')\n", encoding="utf-8")
        (pkg / "__version__.py").write_text(textwrap.dedent("""
            class CONSTRAINTS:
                MIN_VERSION = 'alpha.1'
                MAX_VERSION = '1'
                PLAYWRIGHT_BROWSER_FLOORS = (((1, 61), 'beta.30'),)
        """), encoding="utf-8")
        sys.path.insert(0, tmp.name)
        self.addCleanup(sys.path.remove, tmp.name)
        self.addCleanup(sys.modules.pop, "camoufox", None)

    def _floor(self, playwright_version: str) -> str:
        with mock.patch.object(cfx.importlib.metadata, "version",
                               return_value=playwright_version):
            return cfx._package_browser_floor()

    def test_recent_playwright_raises_the_floor(self) -> None:
        self.assertEqual(self._floor("1.61.0"), "beta.30")

    def test_older_playwright_keeps_the_minimum(self) -> None:
        self.assertEqual(self._floor("1.60.2"), "alpha.1")

    def test_package_is_never_imported(self) -> None:
        self._floor("1.62.0")
        self.assertNotIn("camoufox", sys.modules)


class RouterRegistryTest(unittest.TestCase):
    def test_camoufox_is_a_known_tier(self) -> None:
        self.assertIn("camoufox", known_tiers())

    def test_missing_package_is_unavailable_without_readiness_check(self) -> None:
        with mock.patch.dict(router_mod._TIER_MODULES,
                             {"camoufox": "autolycos_test_absent_module_xyz"}), \
             mock.patch.object(cfx, "camoufox_ready") as ready:
            self.assertFalse(tier_available("camoufox"))
        ready.assert_not_called()

    def test_importable_package_still_needs_a_ready_install(self) -> None:
        with mock.patch.dict(router_mod._TIER_MODULES, {"camoufox": "json"}):
            with mock.patch.object(cfx, "camoufox_ready", return_value=False):
                self.assertFalse(tier_available("camoufox"))
            with mock.patch.object(cfx, "camoufox_ready", return_value=True):
                self.assertTrue(tier_available("camoufox"))

    def test_router_judges_the_install_it_will_launch(self) -> None:
        router = StaticRouter(
            _POLICY, camoufox_executable_path="/srv/cfx/camoufox-bin",
            camoufox_expected_version="152.0.4-beta.30")
        with mock.patch.dict(router_mod._TIER_MODULES, {"camoufox": "json"}), \
             mock.patch.object(cfx, "camoufox_ready", return_value=True) as ready:
            self.assertTrue(router.tier_available("camoufox"))
        ready.assert_called_once_with(
            executable_path="/srv/cfx/camoufox-bin",
            expected_version="152.0.4-beta.30")

    def test_select_threads_gate_and_settings(self) -> None:
        gate = BrowserGate(max_concurrent=1)
        router = StaticRouter(
            _POLICY, browser_gate=gate, camoufox_launch_timeout_seconds=11.0,
            camoufox_nav_timeout_seconds=22.0,
            camoufox_fetch_timeout_seconds=66.0,
            camoufox_max_abandoned_fetches=3,
            camoufox_executable_path="/srv/cfx/camoufox-bin",
            camoufox_expected_version="152.0.4-beta.30")
        fetcher = router.select("camoufox", ["mlcdn.com.br"])
        self.assertIsInstance(fetcher, cfx.CamoufoxFetcher)
        self.assertIs(fetcher._gate, gate)
        self.assertEqual(
            (fetcher._launch_timeout_seconds, fetcher._nav_timeout_seconds,
             fetcher._fetch_timeout_seconds, fetcher._max_abandoned_fetches,
             fetcher._executable_path, fetcher._expected_version),
            (11.0, 22.0, 66.0, 3, "/srv/cfx/camoufox-bin", "152.0.4-beta.30"))
        self.assertTrue(fetcher._host_allowed("static.mlcdn.com.br"))


class _WiringBase(_CounterIsolation):
    def setUp(self) -> None:
        super().setUp()
        for patcher in (
            mock.patch.object(safety.socket, "getaddrinfo",
                              return_value=_addrinfo("104.18.0.1")),
            mock.patch.object(cfx, "_ready_firefox_major", return_value=152),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _fetch(self, fake: _FakeCamoufox, addons=_Addons,  # noqa: ANN001
               subresource_domains=(), **fetcher_kwargs):  # noqa: ANN001, ANN003
        fetcher_kwargs.setdefault("gate", BrowserGate(max_concurrent=1))
        fetcher = cfx.CamoufoxFetcher(
            _POLICY, subresource_domains,
            executable_path="/opt/camoufox/camoufox-bin", **fetcher_kwargs)
        with mock.patch.object(cfx, "_load_camoufox",
                               return_value=(fake, addons)):
            return fetcher, fetcher.fetch(_URL)


class LaunchWiringTest(_WiringBase):
    def test_launch_is_pinned_and_download_free(self) -> None:
        fake = _FakeCamoufox(lambda kwargs: _Browser())
        self._fetch(fake, launch_timeout_seconds=7.0)
        (kwargs,) = fake.calls
        self.assertEqual(kwargs["executable_path"], "/opt/camoufox/camoufox-bin")
        self.assertIs(kwargs["headless"], True)
        self.assertIs(kwargs["geoip"], False)
        self.assertEqual(kwargs["ff_version"], 152)
        self.assertEqual(kwargs["exclude_addons"], [_Addons.UBO])
        self.assertEqual(kwargs["firefox_user_prefs"], cfx.merged_firefox_prefs())
        self.assertNotIn("browser", kwargs)
        self.assertEqual(kwargs["timeout"], 7000)
        self.assertEqual(len(kwargs["args"]), 1)
        self.assertTrue(kwargs["args"][0].startswith(cfx._LAUNCH_ID_ARG_PREFIX))
        self.assertTrue(kwargs["proxy"]["server"].startswith("http://127.0.0.1:"))

    def test_upstream_addon_outside_the_named_list_refuses_the_launch(self) -> None:
        fake = _FakeCamoufox(lambda kwargs: _Browser())
        with self.assertRaises(FetchError) as ctx:
            self._fetch(fake, addons=_AddonsWithNewcomer)
        self.assertIn("NEWCOMER", str(ctx.exception))
        self.assertEqual(fake.calls, [])

    def test_unready_install_refuses_before_loading_the_package(self) -> None:
        loader = mock.Mock()
        with mock.patch.object(
            cfx, "_ready_firefox_major",
            side_effect=cfx._NotReady("build 'beta.31' differs from 'beta.30'"),
        ), mock.patch.object(cfx, "_load_camoufox", loader):
            with self.assertRaises(FetchError) as ctx:
                cfx.CamoufoxFetcher(_POLICY).fetch(_URL)
        self.assertIn("beta.31", str(ctx.exception))
        loader.assert_not_called()

    def test_ssrf_guard_runs_before_readiness_and_loading(self) -> None:
        loader = mock.Mock()
        with mock.patch.object(cfx, "_ready_firefox_major") as ready, \
             mock.patch.object(cfx, "_load_camoufox", loader):
            with self.assertRaises(SSRFError):
                cfx.CamoufoxFetcher(_POLICY).fetch("https://evil.example/")
        ready.assert_not_called()
        loader.assert_not_called()

    def test_proxy_uses_the_same_predicate_as_the_route_guard(self) -> None:
        fake = _FakeCamoufox(lambda kwargs: _Browser())
        with mock.patch.object(cfx, "PinningProxy",
                               wraps=cfx.PinningProxy) as proxy_cls:
            fetcher, _ = self._fetch(fake)
        _, kwargs = proxy_cls.call_args
        self.assertEqual(kwargs["domain_allowed"], fetcher._host_allowed)

    def test_launch_timeout_becomes_a_fetch_error_and_frees_the_gate(self) -> None:
        class _LaunchTimeout(Exception):
            pass

        def _enter(kwargs):  # noqa: ANN001, ANN202
            raise _LaunchTimeout("Timeout 7000ms exceeded")

        gate = BrowserGate(max_concurrent=1)
        with mock.patch.object(
            cfx, "_is_playwright_timeout",
            side_effect=lambda exc: isinstance(exc, _LaunchTimeout),
        ):
            with self.assertRaises(FetchError) as ctx:
                self._fetch(_FakeCamoufox(_enter), gate=gate)
        self.assertIn("launch", str(ctx.exception))
        self.assertTrue(gate._semaphore.acquire(timeout=1.0))
        gate._semaphore.release()

    def test_other_launch_error_propagates_unchanged(self) -> None:
        original = RuntimeError("corrupted profile")

        def _enter(kwargs):  # noqa: ANN001, ANN202
            raise original

        with self.assertRaises(RuntimeError) as ctx:
            self._fetch(_FakeCamoufox(_enter))
        self.assertIs(ctx.exception, original)


class ContextGuardTest(_WiringBase):
    def test_one_blocked_service_worker_context_per_fetch_closed_after(self) -> None:
        browser = _Browser()
        fake = _FakeCamoufox(lambda kwargs: browser)
        self._fetch(fake)
        self._fetch(fake)
        self.assertEqual(len(browser.contexts), 2)
        for context in browser.contexts:
            self.assertEqual(context.kwargs, {"service_workers": "block"})
            self.assertTrue(context.closed)

    def test_route_guard_on_the_context_follows_the_allowlist(self) -> None:
        browser = _Browser()
        self._fetch(_FakeCamoufox(lambda kwargs: browser),
                    subresource_domains=["mlcdn.com.br"])
        pattern, guard = browser.contexts[0].route_args
        self.assertEqual(pattern, "**/*")
        cases = {
            "https://www.magazineluiza.com.br/app.js": "continue",
            "https://a-static.mlcdn.com.br/img.jpg": "continue",
            "https://evil.example/beacon": "abort",
            "https://localhost/x": "abort",
        }
        for url, expected in cases.items():
            route = _FakeRoute(url)
            guard(route)
            self.assertEqual(route.action, expected, url)

    def test_every_websocket_is_closed(self) -> None:
        browser = _Browser()
        self._fetch(_FakeCamoufox(lambda kwargs: browser))
        pattern, handler = browser.contexts[0].ws_route_args
        self.assertEqual(pattern, "**/*")
        ws = mock.Mock()
        handler(ws)
        ws.close.assert_called_once_with()


class ResultTest(_WiringBase):
    def test_result_carries_status_method_and_navigation_bounds(self) -> None:
        browser = _Browser()
        _, result = self._fetch(
            _FakeCamoufox(lambda kwargs: browser), nav_timeout_seconds=9.0)
        self.assertEqual(result.method, "camoufox")
        self.assertEqual(result.status, 200)
        self.assertFalse(result.challenged)
        self.assertEqual(result.html, _PAGE)
        self.assertEqual(browser.contexts[0].page.goto_args,
                         (_URL, cfx._WAIT_UNTIL, 9000))

    def test_blocked_status_is_challenged_and_not_waited_on(self) -> None:
        browser = _Browser(["blocked"], 503)
        _, result = self._fetch(_FakeCamoufox(lambda kwargs: browser))
        self.assertTrue(result.challenged)
        self.assertEqual(browser.contexts[0].page.waits, [])

    def test_oversized_page_is_a_fetch_error(self) -> None:
        huge = "x" * (cfx.MAX_HTML_BYTES + 1)
        with self.assertRaises(FetchError):
            self._fetch(_FakeCamoufox(lambda kwargs: _Browser([huge])))

    def test_missing_response_is_a_fetch_error(self) -> None:
        with self.assertRaises(FetchError):
            self._fetch(_FakeCamoufox(lambda kwargs: _Browser(status=None)))


class InterstitialSettleTest(_WiringBase):
    def test_interstitial_is_waited_out_until_the_real_page(self) -> None:
        self.assertTrue(looks_challenged(200, _INTERSTITIAL))
        browser = _Browser([_INTERSTITIAL, _INTERSTITIAL, _PAGE])
        _, result = self._fetch(_FakeCamoufox(lambda kwargs: browser))
        self.assertFalse(result.challenged)
        self.assertEqual(result.html, _PAGE)
        self.assertEqual(len(browser.contexts[0].page.waits), 2)

    def test_read_during_the_replacing_navigation_is_retried(self) -> None:
        browser = _Browser(
            [_INTERSTITIAL, RuntimeError("page is navigating"), _PAGE])
        _, result = self._fetch(_FakeCamoufox(lambda kwargs: browser))
        self.assertEqual(result.html, _PAGE)

    def test_persistent_interstitial_stops_at_the_navigation_budget(self) -> None:
        browser = _Browser([_INTERSTITIAL])
        t0 = time.monotonic()
        _, result = self._fetch(_FakeCamoufox(lambda kwargs: browser),
                                nav_timeout_seconds=0.6)
        elapsed = time.monotonic() - t0
        self.assertTrue(result.challenged)
        self.assertGreaterEqual(elapsed, 0.6)
        self.assertLess(elapsed, 0.6 + 3.0)


class _FrozenBrowser:
    """new_context() spawns the given real processes, then blocks until
    `release` is set, like a Firefox stopped right after its launch."""

    def __init__(self, spawn, release: threading.Event) -> None:  # noqa: ANN001
        self._spawn = spawn
        self._release = release

    def new_context(self, **kwargs):  # noqa: ANN003, ANN201
        self._spawn()
        self._release.wait(timeout=30)
        raise RuntimeError("browser connection closed")


class LivenessTest(_WiringBase):
    def setUp(self) -> None:
        super().setUp()
        self.release = threading.Event()
        self.addCleanup(self.release.set)
        self.spawned: list[subprocess.Popen] = []

        def _reap() -> None:
            for proc in self.spawned:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)

        self.addCleanup(_reap)

    def _frozen(self, *argv_builders) -> _FakeCamoufox:  # noqa: ANN002
        def _enter(kwargs):  # noqa: ANN001, ANN202
            marker = _marker(kwargs)

            def _spawn() -> None:
                for build_argv in argv_builders:
                    self.spawned.append(_sleeper(*build_argv(marker)))

            return _FrozenBrowser(_spawn, self.release)

        return _FakeCamoufox(_enter)

    def _fetch_frozen(self, fake: _FakeCamoufox, gate: BrowserGate) -> float:
        t0 = time.monotonic()
        with self.assertRaises(FetchError):
            self._fetch(fake, gate=gate, fetch_timeout_seconds=0.5,
                        late_sweep_seconds=0.2)
        return time.monotonic() - t0

    def test_frozen_fetch_fails_at_the_deadline_with_its_process_dead(self) -> None:
        fake = self._frozen(lambda marker: (marker,))
        elapsed = self._fetch_frozen(fake, BrowserGate(max_concurrent=1))
        self.assertLess(elapsed, 5.0)
        self.assertIsNotNone(self.spawned[0].poll(),
                             "marked process still alive when fetch returned")

    def test_gate_is_released_only_after_the_kill_returned(self) -> None:
        events: list[str] = []
        test_thread = threading.current_thread()

        class _TracingGate(BrowserGate):
            def _release(self, fd):  # noqa: ANN001, ANN202
                events.append("release")
                super()._release(fd)

        real_kill = cfx._kill_processes

        def _traced_kill(procs):  # noqa: ANN001, ANN202
            done = real_kill(procs)
            if threading.current_thread() is test_thread:
                events.append("killed")
            return done

        fake = self._frozen(lambda marker: (marker,))
        with mock.patch.object(cfx, "_kill_processes", side_effect=_traced_kill):
            self._fetch_frozen(fake, _TracingGate(max_concurrent=1))
        self.assertIn("killed", events)
        self.assertEqual(events[-1], "release", events)
        self.assertIsNotNone(self.spawned[0].poll())

    def test_abandoned_thread_counts_until_it_exits(self) -> None:
        fake = self._frozen(lambda marker: (marker,))
        self._fetch_frozen(fake, BrowserGate(max_concurrent=1))
        self.assertEqual(cfx._abandoned_fetch_thread_count, 1)
        self.release.set()
        deadline = time.monotonic() + 5.0
        while cfx._abandoned_fetch_thread_count and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(cfx._abandoned_fetch_thread_count, 0)

    def test_completed_fetch_counts_nothing(self) -> None:
        self._fetch(_FakeCamoufox(lambda kwargs: _Browser()))
        self.assertEqual(cfx._abandoned_fetch_thread_count, 0)

    def test_ceiling_refuses_with_an_error_log_without_loading(self) -> None:
        loader = mock.Mock()
        with cfx._abandoned_lock:
            cfx._abandoned_fetch_thread_count = 2
        fetcher = cfx.CamoufoxFetcher(_POLICY, max_abandoned_fetches=2)
        with mock.patch.object(cfx, "_load_camoufox", loader), \
             self.assertLogs("autolycos.adapters.camoufox", "ERROR") as cm:
            with self.assertRaises(FetchError):
                fetcher.fetch(_URL)
        self.assertIn("refusing new fetch", cm.output[0])
        loader.assert_not_called()

    def test_driver_born_during_the_fetch_is_killed_single_flight(self) -> None:
        fake = self._frozen(lambda marker: ("playwright-driver-stand-in",))
        self._fetch_frozen(fake, BrowserGate(max_concurrent=1))
        self.assertIsNotNone(self.spawned[0].poll(),
                             "unmarked driver process survived the deadline")

    def test_unmarked_process_is_spared_when_the_gate_is_shared(self) -> None:
        fake = self._frozen(
            lambda marker: (marker,),
            lambda marker: ("playwright-driver-stand-in",))
        self._fetch_frozen(fake, BrowserGate(max_concurrent=2))
        self.assertIsNotNone(self.spawned[0].poll())
        self.assertIsNone(self.spawned[1].poll(),
                          "a process without this launch's marker was killed "
                          "while another launch could own it")

    def test_other_launch_marker_is_never_killed(self) -> None:
        other = _sleeper(f"{cfx._LAUNCH_ID_ARG_PREFIX}deadbeef")
        self.spawned.append(other)
        fake = self._frozen(lambda marker: (marker,))
        self._fetch_frozen(fake, BrowserGate(max_concurrent=1))
        self.assertIsNone(other.poll(), "another launch's process was killed")

    def test_process_spawned_after_the_freeze_is_caught_by_the_second_pass(
            self) -> None:
        first_kill_done = threading.Event()
        real_kill = cfx._kill_processes
        test_thread = threading.current_thread()

        def _traced_kill(procs):  # noqa: ANN001, ANN202
            done = real_kill(procs)
            # Abandoned threads of earlier tests may still run their own
            # backstop kill while this patch is active.
            if threading.current_thread() is test_thread:
                first_kill_done.set()
            return done

        spawned = self.spawned

        class _LateSpawner:
            def new_context(self, **kwargs):  # noqa: ANN003, ANN201
                first_kill_done.wait(timeout=10)
                spawned.append(_sleeper("playwright-late-driver"))
                raise RuntimeError("browser connection closed")

        fake = _FakeCamoufox(lambda kwargs: _LateSpawner())
        with mock.patch.object(cfx, "_kill_processes", side_effect=_traced_kill):
            with self.assertRaises(FetchError):
                self._fetch(fake, gate=BrowserGate(max_concurrent=1),
                            fetch_timeout_seconds=0.5, late_sweep_seconds=5.0)
        self.assertTrue(spawned, "the late process was never spawned")
        self.assertIsNotNone(spawned[0].poll(),
                             "process spawned after the freeze survived")

    def test_missing_psutil_keeps_the_deadline_fetch_error(self) -> None:
        fake = self._frozen()
        with mock.patch.dict(sys.modules, {"psutil": None}):
            self._fetch_frozen(fake, BrowserGate(max_concurrent=1))


if __name__ == "__main__":
    unittest.main()
