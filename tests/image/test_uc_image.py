"""UcFetcher: real-Chromium acceptance tests, gated on the autonomous image
(KERDOOS_REQUIRE_IMAGE_TESTS).

These four classes launch a real patchright Chromium via SeleniumBase and
must run inside the autonomous Docker image (or hard-fail loudly if that
image lacks a real Chromium, per KERDOOS_REQUIRE_IMAGE_TESTS=1 -- a silent
skip must never read as a pass).
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import threading
import time
import unittest
from unittest import mock

from autolycos.adapters import uc
from autolycos.browser_gate import BrowserGate
from autolycos.errors import FetchError
from autolycos.safety import DomainPolicy, ValidatedTarget

_HAS_SELENIUMBASE = importlib.util.find_spec("seleniumbase") is not None


def _real_chromium_available() -> bool:
    if not _HAS_SELENIUMBASE:
        return False
    from autolycos.adapters.uc import _find_patchright_chromium
    return _find_patchright_chromium() is not None


_HAS_REAL_CHROMIUM = _real_chromium_available()

_NEUTRAL_POLICY = DomainPolicy(frozenset({"example.com"}))


class _FakeDriver:
    def __init__(self, page_source: str, *, current_url: str | None = None,
                 **kwargs) -> None:  # noqa: ANN003
        self.kwargs = kwargs
        self._page = page_source
        self.current_url = current_url
        self.opened: tuple | None = None
        self.slept: float | None = None
        self.quit_called = False
        self.page_load_timeout: float | None = None

    def set_page_load_timeout(self, seconds):  # noqa: ANN001
        self.page_load_timeout = seconds

    def uc_open_with_reconnect(self, url, reconnect_time):  # noqa: ANN001
        self.opened = (url, reconnect_time)

    def sleep(self, seconds):  # noqa: ANN001
        self.slept = seconds

    def get_page_source(self) -> str:
        return self._page

    def quit(self) -> None:
        self.quit_called = True


class UcPinExecutionTest(unittest.TestCase):
    """Roadmap dde2d243 acceptance test: rerunnable, real Chrome launch,
    neutral targets ONLY (never Magalu -- IP reputation + cadence). Judges by
    navigation exception / fetch() outcome, never by html_len or a substring
    search in /proc/<pid>/cmdline (both are documented measurement traps for
    this exact bug class: Chrome's error page can be large, and cmdline
    substring search does not reveal whether a rule was truncated).

    Drives the REAL UcFetcher.fetch() call to capture the ACTUAL
    driver_kwargs it builds (via the same Driver-substitution the other
    UcFetcherWiringTest cases use), then launches a real Chrome with those
    EXACT captured kwargs -- so a future regression to a flat-string
    chromium_arg in uc.py itself changes what gets launched here too,
    unlike a test that only reconstructs its own hardcoded kwarg shape.
    """

    def setUp(self) -> None:
        if _HAS_REAL_CHROMIUM:
            return
        if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
            self.fail(
                "KERDOOS_REQUIRE_IMAGE_TESTS=1 but no real patchright "
                "Chromium was found -- run inside the autonomous image")
        self.skipTest(
            "needs a real patchright Chromium (autonomous image), not just "
            "SeleniumBase")

    def _capture_real_kwargs(self, url: str, subresource_domains) -> dict:
        holder: dict = {}

        def _factory(**kwargs):
            holder["kwargs"] = kwargs
            return _FakeDriver("<html></html>", **kwargs)

        with mock.patch.object(uc, "_load_seleniumbase",
                               return_value=_factory):
            uc.UcFetcher(_NEUTRAL_POLICY, subresource_domains).fetch(url)
        return holder["kwargs"]

    def test_bogus_pin_makes_navigation_fail(self) -> None:
        # A bogus, non-routable IP fails validate_target's ip_is_safe guard
        # (by design -- fail-closed), so it can never reach UcFetcher.fetch()
        # for real. This directly exercises the rule builder + Driver launch
        # the way UcFetcherWiringTest does, with a REAL Chrome instead of a
        # fake, to prove the pin itself is honored end-to-end.
        target = ValidatedTarget(url="https://example.com/", scheme="https",
                                 host="example.com", port=443, ip="192.0.2.1")
        rule = uc._host_resolver_rules(target, [])
        from autolycos.adapters.uc import _find_patchright_chromium
        from seleniumbase import Driver

        binary = _find_patchright_chromium()
        driver = Driver(uc=True, headless=True, binary_location=binary,
                        chromium_arg=[f"--host-resolver-rules={rule}"])
        try:
            with self.assertRaises(Exception) as ctx:
                driver.get("https://example.com/")
            self.assertIn("ERR_CONNECTION_REFUSED", str(ctx.exception))
        finally:
            driver.quit()

    def test_deny_by_default_blocks_unlisted_host_but_allows_excluded_cdn(
            self) -> None:
        # www.iana.org, not the bare "iana.org" -- the latter 301-redirects
        # to the former, and a redirect target not itself EXCLUDEd would be
        # blocked, giving a false negative unrelated to this bug.
        real_kwargs = self._capture_real_kwargs(
            "https://example.com/", ["www.iana.org"])
        from seleniumbase import Driver

        driver = Driver(**real_kwargs)
        try:
            driver.get("https://example.com/")
            driver.sleep(2)
            # mode: "no-cors" resolves on ANY successful connection (opaque
            # response) regardless of CORS headers, and throws ONLY on a
            # real network/DNS-level failure -- unlike a default-mode
            # fetch(), whose "Failed to fetch" is ambiguous between a CORS
            # rejection and an actual connection failure.
            unlisted = driver.execute_script(
                "return fetch('https://example.org/', {mode: 'no-cors'})"
                ".then(r => 'RESOLVED:' + r.type)"
                ".catch(e => 'THREW:' + e.message)")
            self.assertTrue(unlisted.startswith("THREW"), unlisted)
            excluded = driver.execute_script(
                "return fetch('https://www.iana.org/', {mode: 'no-cors'})"
                ".then(r => 'RESOLVED:' + r.type)"
                ".catch(e => 'THREW:' + e.message)")
            self.assertTrue(excluded.startswith("RESOLVED"), excluded)
        finally:
            driver.quit()

    def _fetch_no_cors(self, driver, url: str) -> str:
        return driver.execute_script(
            "return fetch(arguments[0], {mode: 'no-cors'})"
            ".then(r => 'RESOLVED:' + r.type)"
            ".catch(e => 'THREW:' + e.message)", url)

    def test_deny_by_default_blocks_literal_ip_targets(self) -> None:
        # Card c06082a5 (URL-to-JS injection in uc_open_with_reconnect):
        # severity depends on whether MAP * ~NOTFOUND -- proven above for
        # DNS names -- ALSO covers literal IPs reached directly from injected
        # page JS, never resolved by name. Both the security and debugger
        # tracks currently ASSUME it does; this measures it. Reported target
        # by target: one passing target does not imply the others do.
        real_kwargs = self._capture_real_kwargs("https://example.com/", [])
        from seleniumbase import Driver

        driver = Driver(**real_kwargs)
        try:
            driver.get("https://example.com/")
            driver.sleep(2)
            targets = {
                "cloud-metadata (169.254.169.254)": "http://169.254.169.254/",
                "private-range (10.0.0.1)": "http://10.0.0.1/",
                "loopback-v4 (127.0.0.1:8000)": "http://127.0.0.1:8000/",
                "loopback-v6 ([::1])": "http://[::1]/",
            }
            for label, url in targets.items():
                with self.subTest(target=label):
                    result = self._fetch_no_cors(driver, url)
                    self.assertTrue(
                        result.startswith("THREW"),
                        f"{label} was NOT blocked: {result}")
        finally:
            driver.quit()

    def test_redirect_to_unlisted_host_is_blocked(self) -> None:
        # EXCLUDE "iana.org" (bare) only. iana.org 301-redirects to
        # www.iana.org, which is NOT excluded -- the redirect TARGET must be
        # re-checked against the deny-by-default, not just the initial host.
        real_kwargs = self._capture_real_kwargs(
            "https://example.com/", ["iana.org"])
        from seleniumbase import Driver

        driver = Driver(**real_kwargs)
        try:
            driver.get("https://example.com/")
            driver.sleep(2)
            result = self._fetch_no_cors(driver, "https://iana.org/")
            self.assertTrue(result.startswith("THREW"), result)
        finally:
            driver.quit()


class UcErrorPageDetectionTest(unittest.TestCase):
    """Card 1bddf3fa acceptance test: real Chrome, neutral pinned target
    ONLY (192.0.2.1, TEST-NET-1, never routable -- same discipline as
    UcPinExecutionTest above). uc_open_with_reconnect (unlike plain
    Selenium .get(), used by UcPinExecutionTest) does NOT raise on a
    connection failure -- it lands on Chrome's own interstitial and
    returns normally, which is exactly the bug this card closes."""

    def setUp(self) -> None:
        if _HAS_REAL_CHROMIUM:
            return
        if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
            self.fail(
                "KERDOOS_REQUIRE_IMAGE_TESTS=1 but no real patchright "
                "Chromium was found -- run inside the autonomous image")
        self.skipTest(
            "needs a real patchright Chromium (autonomous image), not just "
            "SeleniumBase")

    def test_real_chrome_error_page_is_detected_by_content(self) -> None:
        target = ValidatedTarget(url="https://example.com/", scheme="https",
                                 host="example.com", port=443, ip="192.0.2.1")
        rule = uc._host_resolver_rules(target, [])
        from autolycos.adapters.uc import _find_patchright_chromium
        from seleniumbase import Driver

        binary = _find_patchright_chromium()
        driver = Driver(uc=True, headless=True, binary_location=binary,
                        chromium_arg=[f"--host-resolver-rules={rule}"])
        try:
            # The SAME navigation call UcFetcher.fetch() makes -- unlike
            # plain .get() (UcPinExecutionTest above), this does not raise.
            driver.uc_open_with_reconnect(
                "https://example.com/", reconnect_time=uc.RECONNECT_TIME)
            driver.sleep(uc.RENDER_WAIT)
            html = driver.get_page_source()
            current_url = driver.current_url
        finally:
            driver.quit()
        self.assertTrue(
            uc.looks_like_chrome_error_page(current_url, html),
            f"expected a Chrome error page, current_url={current_url!r}, "
            f"html[:200]={html[:200]!r}")


class UcOrphanCleanupImageTest(unittest.TestCase):
    """Card 6521bbce acceptance test: a REAL Driver() construction, a real
    (artificially tiny) launch timeout, real Chrome + uc_driver processes.
    No live target needed -- it is the LAUNCH itself that must time out,
    not navigation, so this runs cleanly under --network none."""

    def setUp(self) -> None:
        if _HAS_REAL_CHROMIUM:
            return
        if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
            self.fail(
                "KERDOOS_REQUIRE_IMAGE_TESTS=1 but no real patchright "
                "Chromium was found -- run inside the autonomous image")
        self.skipTest(
            "needs a real patchright Chromium (autonomous image), not just "
            "SeleniumBase")

    def test_real_timeout_leaves_no_uc_driver_or_chrome_but_spares_foreign(
            self) -> None:
        import psutil
        from autolycos.adapters.uc import _find_patchright_chromium
        from seleniumbase import Driver

        me = psutil.Process(os.getpid())
        before_pids = {p.pid for p in me.children(recursive=True)}

        foreign = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            binary = _find_patchright_chromium()
            fetcher = uc.UcFetcher(
                _NEUTRAL_POLICY, launch_timeout_seconds=0.01,
                orphan_sweep_delay_seconds=1.0)
            with self.assertRaises(FetchError):
                fetcher._launch_with_deadline(
                    Driver,
                    {"uc": True, "headless": True, "binary_location": binary})

            # Real Driver() construction takes ~0.3-0.8s (cold start) --
            # well past the 0.01s deadline above, so this genuinely
            # exercises both cleanup paths (the deadline's own pass, and
            # the construction's own late-completion cleanup once it
            # actually returns), plus the delayed sweep. Construction
            # timing varies with system load (shared with every other
            # image test in this run) -- poll instead of a fixed sleep.
            def _survivors() -> list:
                found = []
                for p in me.children(recursive=True):
                    if p.pid in before_pids or p.pid == foreign.pid:
                        continue
                    try:
                        if not p.is_running():
                            continue
                        name = p.name().lower()
                    except psutil.Error:
                        continue
                    if name in ("chrome", "uc_driver", "chromedriver"):
                        found.append((p.pid, name))
                return found

            deadline = time.monotonic() + 30.0
            survivors = _survivors()
            while survivors and time.monotonic() < deadline:
                time.sleep(0.5)
                survivors = _survivors()
            self.assertEqual(survivors, [], f"processes leaked: {survivors}")
            self.assertIsNone(
                foreign.poll(), "an unrelated foreign process was killed")
        finally:
            if foreign.poll() is None:
                foreign.kill()


_UC_DRIVER_NAMES = ("uc_driver", "chromedriver")


def _local_http_server():
    """A loopback http:// target. seleniumbase's uc_open_with_reconnect
    only runs its reconnect (terminate + restart the uc_driver service)
    for http/https URLs, so a data: URL cannot reach the topology the
    post-respawn test is about."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 -- http.server's own name
            body = b"<html><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:  # noqa: ANN002
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}/"


def _load_seleniumbase_driver():
    from seleniumbase import Driver

    return Driver


def _is_live_uc_process(proc) -> bool:  # type: ignore[no-untyped-def]
    import psutil

    try:
        if not proc.is_running():
            return False
        return proc.name().lower() in ("chrome", "uc_driver", "chromedriver")
    except psutil.Error:
        return False


class UcPostNavigationFreezeImageTest(unittest.TestCase):
    """Card f0c236da acceptance test: a REAL Driver(uc=True), SIGSTOP on
    Chrome after navigation -- fetch()'s post-navigation phase must return
    a FetchError within the configured deadline, with zero survivors of
    this launch once the browser gate is released, and the NEXT fetch's own
    Chrome must survive this one's cleanup. POSIX only (signal.SIGSTOP).

    Scope, since the two cases have DIFFERENT process topologies:
    test_frozen_chrome... uses a data: URL, which seleniumbase's
    uc_open_with_reconnect short-circuits (it only reconnects for http/https
    targets), so the live uc_driver there is still the launch-time one.
    test_frozen_chrome_after_the_reconnect... drives the http path, where
    reconnect() has replaced that uc_driver with a younger process.
    """

    def setUp(self) -> None:
        if os.name != "posix":
            self.skipTest("needs SIGSTOP (POSIX)")
        if _HAS_REAL_CHROMIUM:
            return
        if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
            self.fail(
                "KERDOOS_REQUIRE_IMAGE_TESTS=1 but no real patchright "
                "Chromium was found -- run inside the autonomous image")
        self.skipTest(
            "needs a real patchright Chromium (autonomous image), not just "
            "SeleniumBase")

    def test_frozen_chrome_after_navigation_yields_a_bounded_fetch_error(
            self) -> None:
        import signal

        import psutil

        from autolycos.adapters.uc import _find_patchright_chromium

        gate = BrowserGate(max_concurrent=1)
        fetcher = uc.UcFetcher(
            _NEUTRAL_POLICY, gate=gate, fetch_timeout_seconds=3.0)
        binary = _find_patchright_chromium()
        driver_cls = _load_seleniumbase_driver()

        gate_released_survivors: list = []

        def _freeze_soon_after_navigation() -> None:
            # A data: URL navigates near-instantly (MEASURED ~0.03s); a
            # short, generous wait covers it before SIGSTOP.
            time.sleep(1.0)
            me = psutil.Process(os.getpid())
            for p in me.children(recursive=True):
                try:
                    if p.name().lower() == "chrome":
                        p.send_signal(signal.SIGSTOP)
                except psutil.Error:
                    pass

        freezer = threading.Thread(
            target=_freeze_soon_after_navigation, daemon=True)
        with gate.acquire():
            driver = fetcher._launch_with_deadline(
                driver_cls, {"uc": True, "headless": True,
                             "binary_location": binary})
            freezer.start()
            t0 = time.monotonic()
            with self.assertRaises(FetchError):
                fetcher._run_after_launch_with_deadline(
                    driver, "data:text/html,<html><body>ok</body></html>")
            elapsed = time.monotonic() - t0
            self.assertLess(elapsed, 3.0 + 15.0)
            me = psutil.Process(os.getpid())
            gate_released_survivors.extend(
                p.pid for p in me.children(recursive=True)
                if _is_live_uc_process(p))
        self.assertEqual(
            gate_released_survivors, [],
            "process(es) of the frozen launch still alive at gate release")

        # The NEXT fetch's own uc_driver/Chrome must survive.
        next_fetcher = uc.UcFetcher(
            _NEUTRAL_POLICY, gate=gate, fetch_timeout_seconds=30.0)
        with gate.acquire():
            next_driver = next_fetcher._launch_with_deadline(
                driver_cls, {"uc": True, "headless": True,
                             "binary_location": binary})
            try:
                result = next_fetcher._run_after_launch_with_deadline(
                    next_driver,
                    "data:text/html,<html><body>next</body></html>")
                self.assertIn("next", result.html)
            except FetchError:
                self.fail("the next fetch was itself killed/timed out")

    def test_frozen_chrome_after_the_reconnect_respawn_leaves_no_survivor(
            self) -> None:
        import signal

        import psutil

        from autolycos.adapters.uc import _find_patchright_chromium

        server, url = _local_http_server()
        self.addCleanup(server.shutdown)
        gate = BrowserGate(max_concurrent=1)
        fetcher = uc.UcFetcher(
            _NEUTRAL_POLICY, gate=gate, fetch_timeout_seconds=12.0,
            orphan_sweep_delay_seconds=1.0)
        binary = _find_patchright_chromium()
        driver_cls = _load_seleniumbase_driver()

        respawned: list[int] = []
        survivors: list[int] = []

        with gate.acquire():
            driver = fetcher._launch_with_deadline(
                driver_cls, {"uc": True, "headless": True,
                             "binary_location": binary})
            known = {pid for pid, _ in getattr(
                driver, "_autolycos_launch_siblings", ())}
            # The SPARING direction of _names_a_driver is unit-tested; this
            # is its other direction, on a real driver process. Without it,
            # an upstream rename of the uc_driver binary would silently
            # turn the service-pid kill into a no-op and nothing would go
            # red -- the survivor assertions below are covered by the late
            # sweep on their own.
            self.assertTrue(
                uc._names_a_driver(
                    psutil.Process(driver.service.process.pid)),
                "the real service process is not recognised as a driver: "
                "_kill_service_process would spare it")

            def _freeze_once_the_driver_has_been_respawned() -> None:
                # Waiting for the YOUNGER uc_driver rather than sleeping a
                # fixed delay is what makes this test about the topology
                # instead of about a timing coincidence.
                deadline = time.monotonic() + 30.0
                me = psutil.Process(os.getpid())
                while time.monotonic() < deadline and not respawned:
                    for proc in me.children(recursive=True):
                        try:
                            if (proc.name().lower() in _UC_DRIVER_NAMES
                                    and proc.pid not in known
                                    and proc.status() != psutil.STATUS_ZOMBIE):
                                respawned.append(proc.pid)
                        except psutil.Error:
                            continue
                    time.sleep(0.1)
                for proc in me.children(recursive=True):
                    try:
                        if proc.name().lower() == "chrome":
                            proc.send_signal(signal.SIGSTOP)
                    except psutil.Error:
                        pass

            threading.Thread(
                target=_freeze_once_the_driver_has_been_respawned,
                daemon=True).start()
            # Either the deadline fires (FetchError) or the severed session
            # surfaces as a Selenium error first; which one depends on where
            # in the cycle the freeze lands, and neither may return a page.
            with self.assertRaises(Exception):
                fetcher._run_after_launch_with_deadline(driver, url)
            me = psutil.Process(os.getpid())
            survivors.extend(p.pid for p in me.children(recursive=True)
                             if _is_live_uc_process(p))
        self.assertTrue(
            respawned,
            "no younger uc_driver appeared: reconnect() did not run, so this "
            "test did not exercise the post-respawn topology it is about")
        self.assertEqual(
            survivors, [],
            "process(es) of the frozen launch still alive at gate release")

    def test_a_deadline_inside_the_reconnect_window_leaves_no_late_spawn(
            self) -> None:
        import signal

        import psutil

        from autolycos.adapters.uc import _find_patchright_chromium

        server, url = _local_http_server()
        self.addCleanup(server.shutdown)
        gate = BrowserGate(max_concurrent=1)
        # Deadline well inside RECONNECT_TIME: the abandoned worker is
        # asleep in reconnect() when the cleanup runs, and wakes up LATER
        # to call service.start(). MEASURED: without the late sweep that
        # uc_driver was still alive 8s past gate release -- born after the
        # kill, so no kill that runs before the sleep can reach it.
        fetcher = uc.UcFetcher(
            _NEUTRAL_POLICY, gate=gate, fetch_timeout_seconds=2.0)
        binary = _find_patchright_chromium()
        driver_cls = _load_seleniumbase_driver()

        survivors: list[int] = []
        late_survivors: list[int] = []

        def _freeze_during_the_reconnect_window() -> None:
            time.sleep(1.0)
            me = psutil.Process(os.getpid())
            for proc in me.children(recursive=True):
                try:
                    if proc.name().lower() == "chrome":
                        proc.send_signal(signal.SIGSTOP)
                except psutil.Error:
                    pass

        with gate.acquire():
            driver = fetcher._launch_with_deadline(
                driver_cls, {"uc": True, "headless": True,
                             "binary_location": binary})
            threading.Thread(
                target=_freeze_during_the_reconnect_window, daemon=True).start()
            with self.assertRaises(FetchError):
                fetcher._run_after_launch_with_deadline(driver, url)
            me = psutil.Process(os.getpid())
            survivors.extend(p.pid for p in me.children(recursive=True)
                             if _is_live_uc_process(p))
        self.assertEqual(
            survivors, [],
            "process(es) of the frozen launch still alive at gate release")
        # The worker's wake-up is bounded by RECONNECT_TIME; sampling past
        # it proves the sweep outlived the spawn rather than merely
        # preceding it.
        time.sleep(uc.RECONNECT_TIME + 2.0)
        late_survivors.extend(
            p.pid for p in psutil.Process(os.getpid()).children(recursive=True)
            if _is_live_uc_process(p))
        self.assertEqual(
            late_survivors, [],
            "the abandoned worker spawned a uc_driver after gate release")

    @staticmethod
    def _wait_until(predicate, timeout: float = 20.0,
                     interval: float = 0.2) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(interval)
        return predicate()


if __name__ == "__main__":
    unittest.main()
