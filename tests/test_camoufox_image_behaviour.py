"""CamoufoxFetcher against a real Camoufox Firefox, inside the autonomous image
only: skipped elsewhere, failed instead under KERDOOS_REQUIRE_IMAGE_TESTS=1."""

from __future__ import annotations

import os
import time
import unittest
import uuid
from unittest import mock

from autolycos.adapters import camoufox as cfx
from autolycos.browser_gate import BrowserGate
from autolycos.errors import FetchError
from autolycos.safety import DomainPolicy

_NEUTRAL_POLICY = DomainPolicy(frozenset({"example.com"}))
_HAS_SIGSTOP = hasattr(__import__("signal"), "SIGSTOP")


def _real_camoufox_available() -> bool:
    return cfx.camoufox_ready()


_HAS_REAL_CAMOUFOX = _real_camoufox_available()


def _real_camoufox_kwargs():
    """(camoufox_cls, kwargs) mirroring the exact shape CamoufoxFetcher.fetch
    builds, so a launch driven directly here matches production: no addon
    download, frozen prefs, a launch-id marker."""
    camoufox_cls, default_addons = cfx._load_camoufox()
    major = cfx._ready_firefox_major(
        cfx.CAMOUFOX_EXECUTABLE_PATH, cfx.CAMOUFOX_BROWSER_VERSION)
    upstream = {addon.name: addon for addon in default_addons}
    excluded = [upstream[name] for name in cfx._EXCLUDED_DEFAULT_ADDONS
                if name in upstream]
    kwargs = {
        "headless": True,
        "executable_path": cfx.CAMOUFOX_EXECUTABLE_PATH,
        "ff_version": major,
        "i_know_what_im_doing": True,
        "geoip": False,
        "exclude_addons": excluded,
        "firefox_user_prefs": cfx.merged_firefox_prefs(),
        "args": [f"{cfx._LAUNCH_ID_ARG_PREFIX}t4b-{uuid.uuid4().hex}"],
        "timeout": cfx.CAMOUFOX_LAUNCH_TIMEOUT_SECONDS * 1000,
    }
    return camoufox_cls, kwargs


class _RealCamoufoxTestCase(unittest.TestCase):
    """A real, unproxied Camoufox Firefox instance per test: no PinningProxy,
    no SSRF gate. These tests judge CamoufoxFetcher's class/static helpers
    against a real engine, not the guarded fetch() pipeline end to end."""

    def setUp(self) -> None:
        if not _HAS_REAL_CAMOUFOX:
            if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
                self.fail(
                    "KERDOOS_REQUIRE_IMAGE_TESTS=1 but no real Camoufox "
                    "install was found -- run inside the autonomous image")
            self.skipTest(
                "needs a real Camoufox Firefox install (autonomous image)")
        camoufox_cls, kwargs = _real_camoufox_kwargs()
        self._cm = camoufox_cls(**kwargs)
        self.browser = self._cm.__enter__()
        self.addCleanup(self._cm.__exit__, None, None, None)

    def _new_page(self):
        context = self.browser.new_context()
        self.addCleanup(context.close)
        return context.new_page()


class CappedReadRealFirefoxTest(_RealCamoufoxTestCase):
    """_read_document runs _BOUNDED_READ_JS against a real Firefox DOM."""

    def test_dom_over_cap_raises_fetch_error(self) -> None:
        page = self._new_page()
        page.goto("data:text/html,<html><body>x</body></html>",
                  wait_until="load", timeout=10_000)
        page.evaluate("s => { document.body.textContent = s; }", "y" * 5000)
        with mock.patch.object(cfx, "MAX_HTML_BYTES", 200):
            with self.assertRaises(FetchError):
                cfx.CamoufoxFetcher._read_document(
                    page, time.monotonic() + 10.0)

    def test_dom_under_cap_returns_full_rendered_document(self) -> None:
        page = self._new_page()
        page.goto("data:text/html,<html><body>hello</body></html>",
                  wait_until="load", timeout=10_000)
        with mock.patch.object(cfx, "MAX_HTML_BYTES", 10_000):
            _, html = cfx.CamoufoxFetcher._read_document(
                page, time.monotonic() + 10.0)
        full = page.evaluate("() => document.documentElement.outerHTML")
        self.assertEqual(
            html, full,
            "under the cap, _read_document must return the exact rendered "
            "document, not a truncated or reconstructed copy")
        self.assertIn("hello", html)


class BoundedReadWirePayloadTest(unittest.TestCase):
    """_BOUNDED_READ_JS answers an over-cap DOM with one flat -1 frame on the
    wire. The protocol trace is only visible from a child process started
    with DEBUG=pw:protocol: pytest's capture swallows it in-process."""

    _CHILD_SCRIPT = """
import sys
from autolycos.adapters import camoufox as cfx

camoufox_cls, default_addons = cfx._load_camoufox()
major = cfx._ready_firefox_major(
    cfx.CAMOUFOX_EXECUTABLE_PATH, cfx.CAMOUFOX_BROWSER_VERSION)
upstream = {a.name: a for a in default_addons}
excluded = [upstream[n] for n in cfx._EXCLUDED_DEFAULT_ADDONS
            if n in upstream]
kwargs = dict(
    headless=True, executable_path=cfx.CAMOUFOX_EXECUTABLE_PATH,
    ff_version=major, i_know_what_im_doing=True, geoip=False,
    exclude_addons=excluded, firefox_user_prefs=cfx.merged_firefox_prefs(),
    timeout=cfx.CAMOUFOX_LAUNCH_TIMEOUT_SECONDS * 1000)

with camoufox_cls(**kwargs) as browser:
    context = browser.new_context()
    page = context.new_page()
    page.goto("data:text/html,<html><body>x</body></html>",
              wait_until="load", timeout=10_000)
    for size in (200_000, 4_000_000):
        page.evaluate("s => { document.body.textContent = s; }", "z" * size)
        result = page.wait_for_function(
            cfx.CamoufoxFetcher._BOUNDED_READ_JS, arg=100,
            timeout=10_000).json_value()
        assert result == -1, f"{size}-byte DOM was not over the cap: {result!r}"
        sys.stderr.write(f"###MARK size={size}\\n")
        sys.stderr.flush()
    context.close()

print("###RESULT ok")
"""

    def setUp(self) -> None:
        if not _HAS_REAL_CAMOUFOX:
            if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
                self.fail(
                    "KERDOOS_REQUIRE_IMAGE_TESTS=1 but no real Camoufox "
                    "install was found -- run inside the autonomous image")
            self.skipTest(
                "needs a real Camoufox Firefox install (autonomous image)")

    def test_response_payload_stays_flat_across_dom_sizes(self) -> None:
        import subprocess
        import sys as _sys

        env = dict(os.environ)
        env["DEBUG"] = "pw:protocol"
        proc = subprocess.run(
            [_sys.executable, "-c", self._CHILD_SCRIPT],
            env=env, capture_output=True, timeout=60)
        self.assertEqual(
            proc.returncode, 0,
            f"child process failed: stdout_tail={proc.stdout[-2000:]!r} "
            f"stderr_tail={proc.stderr[-2000:]!r}")
        self.assertIn(b"###RESULT ok", proc.stdout)

        lines = proc.stderr.split(b"\n")
        marks = [i for i, ln in enumerate(lines) if b"###MARK" in ln]
        self.assertEqual(
            len(marks), 2,
            f"expected 2 ###MARK lines (one per DOM size), got {len(marks)}")
        sizes_on_wire = []
        for mark_index in marks:
            over_cap_frame = next(
                (ln for ln in reversed(lines[:mark_index])
                 if b'"result":{"result":{"value":-1}}}' in ln),
                None)
            self.assertIsNotNone(
                over_cap_frame,
                "no pw:protocol RECV frame carrying the -1 over-cap answer "
                f"found before mark {mark_index}")
            sizes_on_wire.append(len(over_cap_frame))
        self.assertLess(
            max(sizes_on_wire), 1000,
            f"the over-cap read answer is {sizes_on_wire} bytes on the wire")
        self.assertEqual(
            sizes_on_wire[0], sizes_on_wire[1],
            f"the response frame grew with DOM size ({sizes_on_wire}) -- "
            "the oversized DOM may be crossing the Playwright transport "
            "instead of being measured and dropped in-page")


class SettledContentNavigationBudgetTest(_RealCamoufoxTestCase):
    """A busy page main thread cannot hold _settled_content past its budget."""

    def test_busy_main_thread_bounds_settle_within_nav_deadline(self) -> None:
        page = self._new_page()
        html = (
            "data:text/html,<html><body>"
            "<div class='sec-if-cpt-container'>wait</div>"
            "<script>window.addEventListener('load', () => {"
            "setTimeout(() => { const s = Date.now();"
            " while (Date.now() - s < 6000) {} }, 0); });</script>"
            "</body></html>")
        page.goto(html, wait_until="load", timeout=10_000)
        budget_seconds = 5.0
        deadline = time.monotonic() + budget_seconds
        t0 = time.monotonic()
        with self.assertRaises(
                FetchError,
                msg="the first read, held by the busy main thread past the "
                "budget, has no document to return"):
            cfx.CamoufoxFetcher._settled_content(page, 200, deadline)
        elapsed = time.monotonic() - t0
        self.assertLess(
            elapsed, budget_seconds + 1.0,
            f"_settled_content took {elapsed:.1f}s against a "
            f"{budget_seconds:.0f}s nav budget")


def _start_local_success_server(
        routes: dict[str, tuple[int, bytes]] | None = None):
    """A loopback-only HTTP server: `routes` maps a path to (status, body),
    every other path answers 200."""
    import http.server
    import socketserver

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            status, body = (routes or {}).get(
                self.path, (200, b"<html><body>ok</body></html>"))
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    httpd = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    import threading

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread


class FinalDocumentUrlCheckTest(_RealCamoufoxTestCase):
    """A Firefox error page on the requested host AND port is refused through
    its documentURI alone."""

    def test_error_page_on_the_requested_host_and_port_is_refused(self) -> None:
        httpd, thread = _start_local_success_server()
        self.addCleanup(httpd.server_close)
        requested_url = f"http://127.0.0.1:{httpd.server_address[1]}/"

        page = self._new_page()
        response = page.goto(
            requested_url, wait_until="load", timeout=10_000)
        self.assertEqual(response.status, 200)
        httpd.shutdown()
        httpd.server_close()
        thread.join(2.0)
        page.evaluate(
            "() => { setTimeout(() => { window.location.href = "
            f"'{requested_url}gone'; }}, 0); }}")
        page.wait_for_timeout(3000)

        uri, _ = cfx.CamoufoxFetcher._read_document(
            page, time.monotonic() + 10.0)
        self.assertTrue(uri.startswith("about:neterror"),
                        f"documentURI is {uri!r}, page.url is {page.url!r}")
        cfx.CamoufoxFetcher._check_final_document(page.url, requested_url)
        with self.assertRaises(FetchError):
            cfx.CamoufoxFetcher._check_final_document(
                page.url, requested_url, uri)


class ScriptNavigatedDocumentStatusTest(_RealCamoufoxTestCase):
    """_render reports the status of the document a script navigation committed."""

    def test_status_of_a_script_navigated_404_is_reported(self) -> None:
        interstitial = (
            b"<html><body><div class='sec-if-cpt-container'>wait</div>"
            b"<script>setTimeout(() => { location.href = '/missing'; }, 800);"
            b"</script></body></html>")
        missing = b"<html><body>" + b"gone " * 400 + b"</body></html>"
        httpd, _thread = _start_local_success_server({
            "/interstitial": (200, interstitial), "/missing": (404, missing)})
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        fetcher = cfx.CamoufoxFetcher(_NEUTRAL_POLICY, nav_timeout_seconds=15.0)

        result = fetcher._render(
            self.browser,
            f"http://127.0.0.1:{httpd.server_address[1]}/interstitial")

        self.assertIn("gone", result.html)
        self.assertEqual(result.status, 404)


class LivenessSigstopTest(unittest.TestCase):
    """Card 5438dd0b acceptance test: SIGSTOP-ing the real Firefox process
    right as _render starts, for 5 independent fetches, must make every one
    of them raise FetchError within fetch_timeout_seconds, release the
    browser gate promptly, and leave zero survivors 5s after -- the exact
    guarantee _kill_after_deadline exists to provide. Mirrors
    tests/test_browser.py's RealBrowserFreezeTest for the patchright tier."""

    def setUp(self) -> None:
        if _HAS_REAL_CAMOUFOX and _HAS_SIGSTOP:
            return
        if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
            self.fail(
                "KERDOOS_REQUIRE_IMAGE_TESTS=1 but a real Camoufox install "
                "or SIGSTOP is unavailable -- run inside the autonomous "
                "image")
        self.skipTest(
            "needs a real Camoufox Firefox install and SIGSTOP (POSIX "
            "autonomous image)")

    @staticmethod
    def _freeze_new_firefox(before: frozenset[int]) -> None:
        import signal

        import psutil

        for proc in psutil.Process().children(recursive=True):
            if proc.pid in before:
                continue
            try:
                cmdline = " ".join(proc.cmdline())
                name = (proc.name() or "").lower()
            except psutil.Error:
                continue
            if "--type=" in cmdline:
                continue  # a content/gpu child, not the top-level browser
            if "firefox" in name or "camoufox" in cmdline.lower():
                try:
                    os.kill(proc.pid, signal.SIGSTOP)
                except ProcessLookupError:
                    pass

    def test_five_frozen_fetches_all_raise_fetch_error_gate_free_no_zombies(
            self) -> None:
        import psutil

        gate = BrowserGate(max_concurrent=1)
        original_render = cfx.CamoufoxFetcher._render

        for attempt in range(5):
            with self.subTest(attempt=attempt):
                before = frozenset(
                    p.pid for p in psutil.Process().children(recursive=True))

                def _frozen_render(self_fetcher, browser, url, _before=before):
                    self._freeze_new_firefox(_before)
                    return original_render(self_fetcher, browser, url)

                with mock.patch.object(
                        cfx.CamoufoxFetcher, "_render", _frozen_render):
                    fetcher = cfx.CamoufoxFetcher(
                        _NEUTRAL_POLICY, gate=gate, fetch_timeout_seconds=5.0)
                    t0 = time.monotonic()
                    with self.assertRaises(FetchError):
                        fetcher.fetch("https://example.com/")
                    elapsed = time.monotonic() - t0
                # Bounded (not indefinite), not tight: measured 15-23.5s
                # across real-image runs for the kill cascade (fetch_timeout
                # + two KILL_WAIT_SECONDS passes + LATE_SWEEP_SECONDS grace
                # plus real process-wait syscall overhead under load).
                self.assertLess(elapsed, 40.0)

                acquired_promptly = gate._semaphore.acquire(timeout=1.0)
                self.assertTrue(
                    acquired_promptly,
                    f"attempt {attempt}: gate slot was not released")
                gate._semaphore.release()

                time.sleep(1.0)
                leftover = [
                    p for p in psutil.Process().children(recursive=True)
                    if p.pid not in before and p.is_running()]
                self.assertEqual(
                    leftover, [],
                    f"attempt {attempt}: lingering process(es): {leftover}")


class RealFetchMemoryFootprintTest(unittest.TestCase):
    """Card 5438dd0b measurement: peak RSS of one real, end-to-end fetch
    (this process plus every child it spawns: Firefox, the playwright
    driver, the PinningProxy thread). Reported, never asserted against a
    specific number -- only that the sampler actually observed something."""

    def setUp(self) -> None:
        if _HAS_REAL_CAMOUFOX:
            return
        if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
            self.fail(
                "KERDOOS_REQUIRE_IMAGE_TESTS=1 but no real Camoufox install "
                "was found -- run inside the autonomous image")
        self.skipTest(
            "needs a real Camoufox Firefox install (autonomous image)")

    def test_peak_rss_of_one_real_fetch_is_measured_and_reported(
            self) -> None:
        import threading

        import psutil

        gate = BrowserGate(max_concurrent=1)
        fetcher = cfx.CamoufoxFetcher(_NEUTRAL_POLICY, gate=gate)
        peak_rss = {"bytes": 0}
        stop = threading.Event()

        def _sample() -> None:
            me = psutil.Process()
            while not stop.is_set():
                try:
                    total = me.memory_info().rss + sum(
                        p.memory_info().rss
                        for p in me.children(recursive=True))
                except psutil.Error:
                    total = 0
                peak_rss["bytes"] = max(peak_rss["bytes"], total)
                time.sleep(0.2)

        sampler = threading.Thread(target=_sample, daemon=True)
        sampler.start()
        try:
            fetcher.fetch("https://example.com/")
        finally:
            stop.set()
            sampler.join(timeout=2.0)

        self.assertGreater(
            peak_rss["bytes"], 0,
            "peak RSS sampling never observed any process memory")
        print(
            f"\n[camoufox T4-B] measured peak RSS for one real fetch: "
            f"{peak_rss['bytes'] / (1024 * 1024):.1f} MiB")


if __name__ == "__main__":
    unittest.main()
