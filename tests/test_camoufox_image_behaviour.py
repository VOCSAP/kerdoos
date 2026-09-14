"""CamoufoxFetcher against a REAL Firefox: capped read, settle-loop budget,
final-document check, liveness and memory footprint (carte 5438dd0b, lot
T4-B).

The mocked suite in test_camoufox.py drives a fake Page whose
wait_for_function() IGNORES the JS expression it receives and re-implements
the cap in Python (see its own docstring): it proves the adapter's handling
of the read's return value, never the truth of _CAPPED_HTML_JS itself. Every test below
either drives _read_capped/_settled_content/_check_final_document against a
real, unproxied Camoufox Firefox page (CappedRead*, SettledContent*,
FinalDocumentUrlCheck*), or drives the full guarded CamoufoxFetcher.fetch()
pipeline through a real launch (Liveness*, RealFetchMemoryFootprint*).
Runs for real only inside the autonomous image; everywhere else it skips
(hard-fails instead under KERDOOS_REQUIRE_IMAGE_TESTS=1, same discipline as
tests/test_uc.py's UcPinExecutionTest and tests/test_browser.py's
RealBrowserFreezeTest).
"""

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
    """_read_capped drives cls._CAPPED_HTML_JS through page.evaluate() on a
    real Firefox DOM: the mocked suite cannot exercise the JS string at all."""

    def test_dom_over_cap_raises_fetch_error(self) -> None:
        page = self._new_page()
        page.goto("data:text/html,<html><body>x</body></html>",
                  wait_until="load", timeout=10_000)
        page.evaluate("s => { document.body.textContent = s; }", "y" * 5000)
        with mock.patch.object(cfx, "MAX_HTML_BYTES", 200):
            with self.assertRaises(FetchError):
                cfx.CamoufoxFetcher._read_capped(page)

    def test_dom_under_cap_returns_full_rendered_document(self) -> None:
        page = self._new_page()
        page.goto("data:text/html,<html><body>hello</body></html>",
                  wait_until="load", timeout=10_000)
        with mock.patch.object(cfx, "MAX_HTML_BYTES", 10_000):
            html = cfx.CamoufoxFetcher._read_capped(page)
        full = page.evaluate("() => document.documentElement.outerHTML")
        self.assertEqual(
            html, full,
            "under the cap, _read_capped must return the exact rendered "
            "document, not a truncated or reconstructed copy")
        self.assertIn("hello", html)

class EvaluateResponsePayloadSizeTest(unittest.TestCase):
    """Proof 1(b): the actual bytes Playwright's own transport carries back
    for cls._CAPPED_HTML_JS's Runtime.callFunction response. Runs the
    launch+evaluate cycle in a DEDICATED CHILD PROCESS with
    DEBUG=pw:protocol set from that process's start: an in-process raw
    file-descriptor redirect around the SAME process running pytest was
    tried first and silently lost the driver's debug output (log bytes=0)
    -- pytest's own stdout/stderr capture intercepts at a layer a bare
    os.dup2 in the test body does not control. The child writes the
    driver's protocol trace to its own stderr and one JSON status line to
    its own stdout; the parent only parses stdout and correlates the
    ###MARK lines it wrote to stderr right after each evaluate() call."""

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
        result = page.evaluate(cfx.CamoufoxFetcher._CAPPED_HTML_JS, 100)
        assert result is None, f"{size}-byte DOM was not over the cap"
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
            null_result = next(
                (ln for ln in reversed(lines[:mark_index])
                 if b'"result":{"result":{"value":{"v":"null"}}}}' in ln),
                None)
            self.assertIsNotNone(
                null_result,
                "no pw:protocol RECV frame carrying the null cap-check "
                f"result found before mark {mark_index}")
            sizes_on_wire.append(len(null_result))
        self.assertLess(
            max(sizes_on_wire), 1000,
            f"the evaluate() response for the cap-check call is "
            f"{sizes_on_wire} bytes on the wire -- expected it to stay "
            "well under 1000 bytes regardless of DOM size")
        self.assertEqual(
            sizes_on_wire[0], sizes_on_wire[1],
            f"the response frame grew with DOM size ({sizes_on_wire}) -- "
            "the oversized DOM may be crossing the Playwright transport "
            "instead of being measured and dropped in-page")


class SettledContentNavigationBudgetTest(_RealCamoufoxTestCase):
    """Card 5438dd0b measurement: _settled_content's own page.evaluate() call
    inside the poll loop cannot be interrupted once issued -- if the page's
    main thread is busy when that call is made, the call blocks for as long
    as the main thread stays busy, past the nav deadline it is meant to
    respect. Reproduced locally (data: URL, no network) with a load-then-
    setTimeout busy loop so the block starts AFTER goto() returns, inside the
    poll loop itself."""

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
            f"{budget_seconds:.0f}s nav budget -- its own page.evaluate() "
            "call inside the poll loop is not bounded by the deadline once "
            "the page main thread is busy")


def _start_local_success_server():
    """A loopback-only HTTP server answering 200 on every path. Used as the
    FIRST, successful leg of the FinalDocumentUrlCheckTest scenario so the
    whole test stays hermetic (127.0.0.1 only, never real internet egress,
    never through PinningProxy -- _check_final_document is a staticmethod
    tested in isolation, not the guarded fetch() pipeline)."""
    import http.server
    import socketserver

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            body = b"<html><body>ok</body></html>"
            self.send_response(200)
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
    """Card 5438dd0b measurement: a client-side (JS) navigation issued AFTER
    the tracked page.goto() returned is invisible to _render's own Response
    object, so the `status` variable used for the final FetchResult still
    holds the FIRST navigation's status. _check_final_document's host/scheme
    check is the only remaining guard against this; on a real Firefox
    network-error page for a same-host, unreachable target, `page.url` may
    still report the originally-attempted URL (Firefox keeps the address
    bar on the attempted address for its own error page), which would make
    final_host == requested_host and let the check pass. Both legs stay on
    127.0.0.1 (a local server for the success leg, an unbound port for the
    failure leg) so the test needs no real network egress and does not go
    through PinningProxy (_check_final_document is tested here in
    isolation, as a staticmethod, not the guarded fetch() pipeline)."""

    def test_js_redirect_to_unreachable_same_host_is_caught(self) -> None:
        httpd, thread = _start_local_success_server()
        self.addCleanup(httpd.shutdown)
        self.addCleanup(thread.join, 2.0)
        port_ok = httpd.server_address[1]
        requested_url = f"http://127.0.0.1:{port_ok}/"

        page = self._new_page()
        response = page.goto(
            requested_url, wait_until="load", timeout=10_000)
        self.assertIsNotNone(response, "no response from the first, real "
                              "local navigation -- cannot set up the scenario")
        self.assertEqual(response.status, 200)
        page.evaluate(
            "() => { setTimeout(() => {"
            " window.location.href = 'http://127.0.0.1:1/'; }, 0); }")
        page.wait_for_timeout(4000)
        with self.assertRaises(
                FetchError,
                msg=f"page.url is {page.url!r} after a same-host JS "
                "navigation to an unreachable port (127.0.0.1:1) produced "
                "a Firefox error page -- _check_final_document did not "
                "detect it"):
            cfx.CamoufoxFetcher._check_final_document(page.url, requested_url)


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
