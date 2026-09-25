"""BrowserFetcher: real-Chromium liveness proofs, gated on the autonomous
image (KERDOOS_REQUIRE_IMAGE_TESTS).

These classes launch a real patchright Chromium and must run inside the
autonomous Docker image (or hard-fail loudly if that image lacks patchright,
per KERDOOS_REQUIRE_IMAGE_TESTS=1 -- a silent skip must never read as a pass).
"""

from __future__ import annotations

import importlib.util
import os
import socket
import time
import unittest
from pathlib import Path
from unittest import mock

from autolycos import safety
from autolycos.adapters import browser
from autolycos.browser_gate import BrowserGate
from autolycos.errors import FetchError
from autolycos.safety import DomainPolicy

_HAS_PATCHRIGHT = importlib.util.find_spec("patchright") is not None
_HAS_POSIX_SHELL = os.name == "posix" and Path("/bin/sh").exists()
_NEUTRAL_POLICY = DomainPolicy(frozenset({"example.com"}))


def _addrinfo(ip: str, port: int = 443):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]


class RealBrowserLaunchTimeoutTest(unittest.TestCase):
    """Roadmap b3213f3c acceptance test: drives the REAL UcFetcher-style
    integration -- patchright's own BrowserType.launch, through the REAL
    fetch() call, with executable_path swapped for a script that genuinely
    hangs (never a nonexistent path, which fails instantly and proves
    nothing). Neutral target only (example.com), never a real site. POSIX
    only (needs /bin/sh); runs for real inside the autonomous image.
    """

    def setUp(self) -> None:
        if _HAS_PATCHRIGHT and _HAS_POSIX_SHELL:
            return
        if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
            self.fail(
                "KERDOOS_REQUIRE_IMAGE_TESTS=1 but patchright or a POSIX "
                "shell is unavailable -- run inside the autonomous image")
        self.skipTest(
            "needs patchright and a POSIX shell (autonomous image), not "
            "just patchright")

    def test_hung_launch_raises_fetch_error_releases_gate_no_leftover_process(
            self) -> None:
        import psutil
        from patchright.sync_api import BrowserType

        script_path = Path("/tmp/kerdoos-test-hang-browser-launch.sh")
        script_path.write_text("#!/bin/sh\nsleep 60\n", encoding="utf-8")
        script_path.chmod(0o755)
        self.addCleanup(script_path.unlink, missing_ok=True)

        original_launch = BrowserType.launch

        def _patched_launch(self_bt, **kwargs):  # noqa: ANN001, ANN003
            kwargs["executable_path"] = str(script_path)
            return original_launch(self_bt, **kwargs)

        gate = BrowserGate(max_concurrent=1)
        before = {p.pid for p in psutil.Process().children(recursive=True)}
        with mock.patch.object(BrowserType, "launch", _patched_launch), \
             mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            fetcher = browser.BrowserFetcher(
                _NEUTRAL_POLICY, gate=gate, launch_timeout_seconds=2.0)
            t0 = time.monotonic()
            with self.assertRaises(FetchError):
                fetcher.fetch("https://example.com/")
            elapsed = time.monotonic() - t0
        # Bounded by the 2s deadline, not the script's 60s sleep.
        self.assertLess(elapsed, 10.0)

        acquired_promptly = gate._semaphore.acquire(timeout=1.0)
        self.assertTrue(acquired_promptly, "gate slot was not released")
        gate._semaphore.release()

        time.sleep(1.0)
        leftover = [p for p in psutil.Process().children(recursive=True)
                    if p.pid not in before and p.is_running()]
        self.assertEqual(leftover, [], f"lingering process(es): {leftover}")


class RealBrowserFreezeTest(unittest.TestCase):
    """Roadmap d8b7b8fd acceptance test: a REAL Chromium (patchright's own
    bundled binary, not an executable_path substitute), frozen with SIGSTOP
    right after a successful launch(), must still make fetch() raise
    FetchError within fetch_timeout_seconds, release the gate only after
    cleanup, and leave zero survivors -- the exact scenario measured
    (45s observation, no return, no exception) before this fix existed.
    POSIX only (SIGSTOP); runs for real inside the autonomous image.
    """

    def setUp(self) -> None:
        if _HAS_PATCHRIGHT and _HAS_POSIX_SHELL:
            return
        if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
            self.fail(
                "KERDOOS_REQUIRE_IMAGE_TESTS=1 but patchright or a POSIX "
                "shell is unavailable -- run inside the autonomous image")
        self.skipTest(
            "needs patchright and a POSIX shell (autonomous image), not "
            "just patchright")

    def test_frozen_chromium_raises_fetch_error_releases_gate_no_leftover(
            self) -> None:
        import signal

        import psutil
        from patchright.sync_api import BrowserType

        original_launch = BrowserType.launch
        before = {p.pid for p in psutil.Process().children(recursive=True)}

        def _patched_launch(self_bt, **kwargs):  # noqa: ANN001, ANN003
            result = original_launch(self_bt, **kwargs)
            # Freeze the newly-launched browser's own top-level OS process
            # (not a zygote/renderer/gpu child) right after launch() itself
            # succeeds, so every call the adapter makes AFTER this point
            # hangs -- exactly what was measured against a real Chromium.
            candidates = [p for p in psutil.Process().children(recursive=True)
                          if p.pid not in before]
            for p in candidates:
                try:
                    cmdline = " ".join(p.cmdline())
                    name = (p.name() or "").lower()
                except psutil.Error:
                    continue
                if "--type=" in cmdline:
                    continue
                if "chrome" in name or "headless" in cmdline:
                    os.kill(p.pid, signal.SIGSTOP)
                    break
            return result

        gate = BrowserGate(max_concurrent=1)
        with mock.patch.object(BrowserType, "launch", _patched_launch), \
             mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            fetcher = browser.BrowserFetcher(
                _NEUTRAL_POLICY, gate=gate, fetch_timeout_seconds=5.0)
            t0 = time.monotonic()
            with self.assertRaises(FetchError):
                fetcher.fetch("https://example.com/")
            elapsed = time.monotonic() - t0
        # Bounded by the 5s deadline, not an indefinite hang.
        self.assertLess(elapsed, 20.0)

        acquired_promptly = gate._semaphore.acquire(timeout=1.0)
        self.assertTrue(acquired_promptly, "gate slot was not released")
        gate._semaphore.release()

        time.sleep(1.0)
        leftover = [p for p in psutil.Process().children(recursive=True)
                    if p.pid not in before and p.is_running()]
        self.assertEqual(leftover, [], f"lingering process(es): {leftover}")


class _NoopStealth:
    def apply_stealth_sync(self, page) -> None:  # noqa: ANN001
        pass


class _InterceptingContext:
    def __init__(self, context, handler, page_wrapper=None) -> None:  # noqa: ANN001
        self._context = context
        self._handler = handler
        self._page_wrapper = page_wrapper or (lambda page: page)

    def route(self, pattern, handler) -> None:  # noqa: ANN001
        self._context.route(pattern, handler)
        self._context.route(pattern, self._handler)

    def route_web_socket(self, pattern, handler) -> None:  # noqa: ANN001
        self._context.route_web_socket(pattern, handler)

    def new_page(self):  # noqa: ANN201
        return self._page_wrapper(self._context.new_page())

    def close(self) -> None:
        self._context.close()


class _InterceptingBrowser:
    def __init__(self, browser_obj, handler, page_wrapper=None) -> None:  # noqa: ANN001
        self._browser_obj = browser_obj
        self._handler = handler
        self._page_wrapper = page_wrapper

    def new_context(self, **kwargs):  # noqa: ANN003, ANN201
        return _InterceptingContext(
            self._browser_obj.new_context(**kwargs), self._handler,
            self._page_wrapper)

    def close(self) -> None:
        self._browser_obj.close()


class _BusyAfterNavigationPage:
    def __init__(self, page, duration_ms: int) -> None:  # noqa: ANN001
        self._page = page
        self._duration_ms = duration_ms

    def __getattr__(self, name):  # noqa: ANN204
        return getattr(self._page, name)

    def goto(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
        response = self._page.goto(*args, **kwargs)
        self._page.evaluate(
            "duration => { setTimeout(() => { const end = Date.now() + duration; "
            "while (Date.now() < end) {} }, 0); }",
            self._duration_ms)
        return response


class BrowserFinalDocumentImageTest(unittest.TestCase):
    def setUp(self) -> None:
        if _HAS_PATCHRIGHT and _HAS_POSIX_SHELL:
            return
        if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
            self.fail(
                "KERDOOS_REQUIRE_IMAGE_TESTS=1 but patchright or a POSIX "
                "shell is unavailable -- run inside the autonomous image")
        self.skipTest(
            "needs patchright and a POSIX shell (autonomous image), not "
            "just patchright")

    def _fetch(self, path: str, handler, *, page_wrapper=None,
               fetch_timeout_seconds: float = 10.0):
        from patchright.sync_api import BrowserType

        original_launch = BrowserType.launch

        def _patched_launch(browser_type, **kwargs):  # noqa: ANN001, ANN003
            return _InterceptingBrowser(
                original_launch(browser_type, **kwargs), handler, page_wrapper)

        with mock.patch.object(BrowserType, "launch", _patched_launch), \
             mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")), \
             mock.patch.object(browser, "_load_stealth", return_value=_NoopStealth):
            return browser.BrowserFetcher(
                _NEUTRAL_POLICY, fetch_timeout_seconds=fetch_timeout_seconds
            ).fetch(f"https://example.com/{path}")

    def test_script_navigation_to_chromium_error_document_is_refused(self) -> None:
        def _route(route) -> None:
            if route.request.url == "https://example.com/start":
                route.fulfill(
                    status=200, content_type="text/html",
                    body=("<html><body>start<script>"
                          "setTimeout(() => { location.href = "
                          "'https://example.com:9/gone'; }, 0);"
                          "</script></body></html>"))
            else:
                route.abort("connectionrefused")

        with self.assertRaisesRegex(
                FetchError, r"chrome-error://chromewebdata"):
            self._fetch("start", _route)

    def test_busy_main_thread_fails_before_outer_fetch_timeout(self) -> None:
        def _route(route) -> None:
            route.fulfill(
                status=200, content_type="text/html",
                body="<html><body>ready</body></html>")

        t0 = time.monotonic()
        with mock.patch.object(browser, "NAV_TIMEOUT_MS", 1_000):
            with self.assertRaisesRegex(
                    FetchError, r"rendered document read exceeded"):
                self._fetch(
                    "busy", _route,
                    page_wrapper=lambda page: _BusyAfterNavigationPage(
                        page, 6_000),
                    fetch_timeout_seconds=5.0)
        elapsed = time.monotonic() - t0
        self.assertLess(
            elapsed, 3.0,
            f"bounded document read took {elapsed:.1f}s instead of its 1s budget")

    def test_https_to_http_script_navigation_is_refused(self) -> None:
        def _route(route) -> None:
            if route.request.url == "https://example.com/downgrade":
                route.fulfill(
                    status=200, content_type="text/html",
                    body=("<html><body>start<script>"
                          "setTimeout(() => { location.href = "
                          "'http://example.com/final'; }, 0);"
                          "</script></body></html>"))
            else:
                route.fulfill(
                    status=200, content_type="text/html",
                    body="<html><body>plain text</body></html>")

        with self.assertRaisesRegex(FetchError, r"fell back to http"):
            self._fetch("downgrade", _route)

    def test_script_navigated_main_document_status_is_reported(self) -> None:
        def _route(route) -> None:
            if route.request.url == "https://example.com/status":
                route.fulfill(
                    status=200, content_type="text/html",
                    body=("<html><body>start<script>"
                          "setTimeout(() => { location.href = '/missing'; }, 0);"
                          "</script></body></html>"))
            else:
                route.fulfill(
                    status=404, content_type="text/html",
                    body="<html><body>gone</body></html>")

        result = self._fetch("status", _route)
        self.assertEqual(result.status, 404)
        self.assertIn("gone", result.html)


if __name__ == "__main__":
    unittest.main()
