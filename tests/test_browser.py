"""BrowserFetcher: pure helpers + fail-closed SSRF guard + wiring via a fake.

Playwright is absent from the base interpreter. What can be exercised WITHOUT it:
the challenge heuristic and the guarantee that the SSRF guard rejects a hostile
target BEFORE Playwright is imported. The navigation wiring (egress-proxy launch
config, route guard, goto, FetchResult) is driven with a FAKE sync_playwright
injected in place of the real one, so the adapter logic is covered without a real
browser (real E2E is a blocking-before-prod fast-follow). The egress-proxy's own
CONNECT/pin behavior is covered in test_ssrf.py.
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
from autolycos.challenge import looks_challenged
from autolycos.errors import FetchError, SSRFError
from autolycos.router import StaticRouter
from autolycos.safety import DomainPolicy

_POLICY = DomainPolicy(frozenset({
    "kabum.com.br", "amazon.com.br", "mercadolivre.com.br",
    "terabyteshop.com.br", "pichau.com.br", "magazineluiza.com.br",
}))


def _addrinfo(ip: str, port: int = 443):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]


class LooksChallengedTest(unittest.TestCase):
    # Heuristic hoisted to autolycos.challenge; the browser tier uses the same
    # shared function so the retry loop keys on a consistent challenged signal.
    def test_block_status_codes(self) -> None:
        for status in (403, 429, 503):
            self.assertTrue(looks_challenged(status, "x" * 5000))

    def test_challenge_markers(self) -> None:
        self.assertTrue(
            looks_challenged(200, "<html>Just a moment...</html>"))

    def test_ml_interstitial_is_challenged(self) -> None:
        # The MercadoLivre JS account-verification micro-landing must be flagged
        # (so a gated non-render degrades to INDETERMINATE, not a false parse).
        shell = ('<div class="micro-landing-container">'
                 '<h1 class="micro-landing-title">x</h1></div>' + "y" * 5000)
        self.assertTrue(looks_challenged(200, shell))
        self.assertTrue(
            looks_challenged(200, "go=/gz/account-verification " + "z" * 5000))

    def test_short_body_is_suspicious(self) -> None:
        self.assertTrue(looks_challenged(200, "tiny"))

    def test_healthy_page_not_challenged(self) -> None:
        self.assertFalse(looks_challenged(200, "<html>" + "x" * 5000))


class BrowserFetcherContractTest(unittest.TestCase):
    def test_method_name(self) -> None:
        self.assertEqual(browser.BrowserFetcher.method_name, "browser")

    def test_ssrf_refused_before_playwright_import(self) -> None:
        # A non-allowlisted target must be rejected by the guard first, so this
        # holds even though Playwright is not installed (no ImportError leaks).
        with self.assertRaises(SSRFError):
            browser.BrowserFetcher(_POLICY).fetch("https://evil.com/x")

    def test_rebind_to_private_ip_refused(self) -> None:
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("10.1.2.3")):
            with self.assertRaises(SSRFError):
                browser.BrowserFetcher(_POLICY).fetch(
                    "https://mercadolivre.com.br/p/X")


# ----- navigation wiring, driven with a FAKE Playwright (no real browser) -----

class _FakeResponse:
    def __init__(self, status: int) -> None:
        self.status = status


class _FakePage:
    def __init__(self, content: str, status: int) -> None:
        self._content = content
        self._status = status
        self.route_pattern: str | None = None
        self.route_handler = None
        self.goto_args: tuple | None = None

    def route(self, pattern, handler):  # noqa: ANN001
        self.route_pattern = pattern
        self.route_handler = handler

    def goto(self, url, wait_until, timeout):  # noqa: ANN001
        self.goto_args = (url, wait_until, timeout)
        return _FakeResponse(self._status)

    def content(self) -> str:
        return self._content


class _FakeBrowser:
    def __init__(self, page: _FakePage) -> None:
        self._page = page
        self.closed = False

    def new_page(self) -> _FakePage:
        return self._page

    def close(self) -> None:
        self.closed = True


class _FakeChromium:
    def __init__(self, browser_obj: _FakeBrowser | None,
                 error: BaseException | None = None) -> None:
        self._browser = browser_obj
        self._error = error
        self.launch_kwargs: dict | None = None

    def launch(self, **kwargs):  # noqa: ANN003
        self.launch_kwargs = kwargs
        if self._error is not None:
            raise self._error
        return self._browser


class _FakePW:
    def __init__(self, chromium: _FakeChromium) -> None:
        self.chromium = chromium

    def __enter__(self) -> "_FakePW":
        return self

    def __exit__(self, *exc) -> bool:  # noqa: ANN002
        return False


class _FakeRoute:
    def __init__(self, url: str) -> None:
        self.request = mock.Mock(url=url)
        self.action: str | None = None

    def continue_(self) -> None:
        self.action = "continue"

    def abort(self) -> None:
        self.action = "abort"


class _FakeStealth:
    """Stand-in for playwright_stealth.Stealth (Phase 2b): records the pages it
    was applied to so the wiring test can assert JS stealth was applied."""

    applied: list = []

    def apply_stealth_sync(self, page) -> None:  # noqa: ANN001
        _FakeStealth.applied.append(page)


class BrowserFetcherWiringTest(unittest.TestCase):
    def _run(self, page: _FakePage, subresource_domains=()) -> tuple:
        chromium = _FakeChromium(_FakeBrowser(page))
        fake_sync_playwright = lambda: _FakePW(chromium)  # noqa: E731
        _FakeStealth.applied = []
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(browser, "_load_playwright",
                                   return_value=fake_sync_playwright), \
                 mock.patch.object(browser, "_load_stealth",
                                   return_value=_FakeStealth):
                result = browser.BrowserFetcher(
                    _POLICY, subresource_domains).fetch(
                    "https://mercadolivre.com.br/p/MLB1")
        return result, chromium, page

    def test_routes_through_egress_proxy_and_builds_result(self) -> None:
        page = _FakePage("<html>" + "x" * 5000, 200)
        result, chromium, page = self._run(page)
        # Chromium launched behind the loopback egress-proxy (no host-resolver
        # pin flag; the proxy does the pinning at the network layer).
        proxy_server = chromium.launch_kwargs["proxy"]["server"]
        self.assertTrue(proxy_server.startswith("http://127.0.0.1:"))
        # No egress-weakening launch flags survive the scrub.
        self.assertEqual(chromium.launch_kwargs["args"], [])
        # No host-resolver pin re-introduced by the patchright swap.
        self.assertNotIn("proxy_bypass", chromium.launch_kwargs)
        for a in chromium.launch_kwargs["args"]:
            self.assertNotIn("--host-resolver-rules", a)
        # Phase 2b: JS stealth was applied to the rendered page.
        self.assertIn(page, _FakeStealth.applied)
        # Navigation waited for the render to settle.
        self.assertEqual(page.goto_args[1], "networkidle")
        # Result carries the rendered HTML and the browser method.
        self.assertEqual(result.method, "browser")
        self.assertEqual(result.status, 200)
        self.assertFalse(result.challenged)
        self.assertIn("xxxxx", result.html)

    def test_route_guard_allows_allowlisted_aborts_others(self) -> None:
        page = _FakePage("<html>" + "x" * 5000, 200)
        _, _, page = self._run(page)
        self.assertEqual(page.route_pattern, "**/*")
        allowed = _FakeRoute("https://www.mercadolivre.com.br/x.js")
        blocked = _FakeRoute("https://evil.com/track.js")
        page.route_handler(allowed)
        page.route_handler(blocked)
        self.assertEqual(allowed.action, "continue")
        self.assertEqual(blocked.action, "abort")

    def test_challenged_status_marks_result(self) -> None:
        page = _FakePage("blocked", 503)
        result, _, _ = self._run(page)
        self.assertTrue(result.challenged)


class SubResourceGateTest(unittest.TestCase):
    """The page.route guard admits declared render CDNs, aborts everything else."""

    def _guarded_page(self, subresource_domains) -> _FakePage:
        page = _FakePage("<html>" + "x" * 5000, 200)
        chromium = _FakeChromium(_FakeBrowser(page))
        fake_sync_playwright = lambda: _FakePW(chromium)  # noqa: E731
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(browser, "_load_playwright",
                                   return_value=fake_sync_playwright), \
                 mock.patch.object(browser, "_load_stealth",
                                   return_value=_FakeStealth):
                browser.BrowserFetcher(_POLICY, subresource_domains).fetch(
                    "https://mercadolivre.com.br/p/MLB1")
        return page

    def test_declared_render_cdn_is_allowed_others_aborted(self) -> None:
        page = self._guarded_page(["http2.mlstatic.com"])
        cases = {
            "https://www.mercadolivre.com.br/x.js": "continue",  # nav domain
            "https://http2.mlstatic.com/app.js": "continue",     # declared CDN
            "https://mlstatic-3p.com/track.js": "abort",         # undeclared CDN
            "https://evil.com/x.js": "abort",                    # off-allowlist
        }
        for url, expected in cases.items():
            route = _FakeRoute(url)
            page.route_handler(route)
            self.assertEqual(route.action, expected, url)

    def test_without_declaration_render_cdn_is_aborted(self) -> None:
        # Default (no subresource_domains): mlstatic is aborted -> proves the
        # allowlist is what unblocks ML, not a hard-coded exception.
        page = self._guarded_page(())
        route = _FakeRoute("https://http2.mlstatic.com/app.js")
        page.route_handler(route)
        self.assertEqual(route.action, "abort")

    def test_empty_host_is_aborted(self) -> None:
        page = self._guarded_page(["http2.mlstatic.com"])
        route = _FakeRoute("about:blank")   # no hostname
        page.route_handler(route)
        self.assertEqual(route.action, "abort")

    def test_navigation_to_render_cdn_still_refused(self) -> None:
        # A declared SUB-RESOURCE host is never a valid NAVIGATION target:
        # validate_target rejects it (not in ALLOWED_DOMAINS) before Playwright.
        with self.assertRaises(SSRFError):
            browser.BrowserFetcher(_POLICY, ["http2.mlstatic.com"]).fetch(
                "https://http2.mlstatic.com/x")


class GateWiringTest(unittest.TestCase):
    """Card ca30b736: fetch() must acquire the browser gate around the
    launch-to-close cycle, whether an explicit gate is injected or the
    module-level default is used."""

    def _fetch_with_spy_gate(self, gate) -> None:
        page = _FakePage("<html>" + "x" * 5000, 200)
        chromium = _FakeChromium(_FakeBrowser(page))
        fake_sync_playwright = lambda: _FakePW(chromium)  # noqa: E731
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(browser, "_load_playwright",
                                   return_value=fake_sync_playwright), \
                 mock.patch.object(browser, "_load_stealth",
                                   return_value=_FakeStealth):
                browser.BrowserFetcher(_POLICY, gate=gate).fetch(
                    "https://mercadolivre.com.br/p/MLB1")

    def test_fetch_acquires_the_injected_gate_exactly_once(self) -> None:
        gate = mock.MagicMock()
        self._fetch_with_spy_gate(gate)
        gate.acquire.assert_called_once()
        # The hold object's context-manager protocol was used (entered AND
        # exited), not just gate.acquire() called and ignored.
        hold = gate.acquire.return_value
        hold.__enter__.assert_called_once()
        hold.__exit__.assert_called_once()

    def test_fetch_uses_the_default_gate_when_none_injected(self) -> None:
        with mock.patch(
            "autolycos.adapters.browser.default_browser_gate"
        ) as default_gate_fn:
            spy_gate = mock.MagicMock()
            default_gate_fn.return_value = spy_gate
            self._fetch_with_spy_gate(None)
        spy_gate.acquire.assert_called_once()


_HAS_PATCHRIGHT = importlib.util.find_spec("patchright") is not None


@unittest.skipUnless(
    _HAS_PATCHRIGHT, "patchright not installed (autolycos[browser] extra)")
class BrowserLaunchTimeoutWiringTest(unittest.TestCase):
    """Roadmap b3213f3c: a launch that raises patchright's REAL TimeoutError
    (not a look-alike local class -- the except clause must match the actual
    type) is converted to a retryable FetchError, and the browser gate --
    acquired around the whole launch-to-close cycle -- is released
    regardless.
    """

    def _fetch_with_failing_launch(self, gate, launch_timeout_seconds=None):
        from patchright.sync_api import TimeoutError as RealTimeoutError

        chromium = _FakeChromium(
            browser_obj=None, error=RealTimeoutError("boom"))
        fake_sync_playwright = lambda: _FakePW(chromium)  # noqa: E731
        kwargs = {}
        if launch_timeout_seconds is not None:
            kwargs["launch_timeout_seconds"] = launch_timeout_seconds
        raised = None
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(browser, "_load_playwright",
                                   return_value=fake_sync_playwright), \
                 mock.patch.object(browser, "_load_stealth",
                                   return_value=_FakeStealth):
                fetcher = browser.BrowserFetcher(_POLICY, gate=gate, **kwargs)
                try:
                    fetcher.fetch("https://mercadolivre.com.br/p/MLB1")
                except FetchError as exc:
                    raised = exc
        return chromium, raised

    def test_launch_timeout_becomes_a_fetch_error(self) -> None:
        gate = BrowserGate(max_concurrent=1)
        _, raised = self._fetch_with_failing_launch(gate)
        self.assertIsInstance(raised, FetchError)

    def test_launch_timeout_seconds_is_passed_in_milliseconds(self) -> None:
        gate = BrowserGate(max_concurrent=1)
        chromium, raised = self._fetch_with_failing_launch(
            gate, launch_timeout_seconds=7.0)
        self.assertIsInstance(raised, FetchError)
        self.assertEqual(chromium.launch_kwargs["timeout"], 7000)

    def test_gate_is_released_after_a_failed_launch(self) -> None:
        gate = BrowserGate(max_concurrent=1)
        self._fetch_with_failing_launch(gate)
        acquired_promptly = gate._semaphore.acquire(timeout=1.0)
        self.assertTrue(acquired_promptly, "gate slot was not released")
        gate._semaphore.release()


_HAS_POSIX_SHELL = os.name == "posix" and Path("/bin/sh").exists()
_NEUTRAL_POLICY = DomainPolicy(frozenset({"example.com"}))


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


class StaticRouterBrowserLaunchTimeoutTest(unittest.TestCase):
    """Roadmap b3213f3c: KERDOOS_BROWSER_LAUNCH_TIMEOUT_SECONDS is injected
    by the kerdoos composition root through StaticRouter/_make_browser --
    never read by autolycos itself (invariant 2).
    """

    def test_injected_value_reaches_the_built_browser_fetcher(self) -> None:
        router = StaticRouter(_POLICY, browser_launch_timeout_seconds=42.0)
        fetcher = router.select("browser")
        self.assertIsInstance(fetcher, browser.BrowserFetcher)
        self.assertEqual(fetcher._launch_timeout_seconds, 42.0)

    def test_no_value_injected_keeps_the_tier_s_own_default(self) -> None:
        router = StaticRouter(_POLICY)
        fetcher = router.select("browser")
        self.assertEqual(
            fetcher._launch_timeout_seconds,
            browser.BROWSER_LAUNCH_TIMEOUT_SECONDS)

    def test_other_tiers_call_shape_is_unaffected(self) -> None:
        router = StaticRouter(_POLICY, browser_launch_timeout_seconds=5.0)
        http_fetcher = router.select("http")
        self.assertEqual(http_fetcher.method_name, "http")


if __name__ == "__main__":
    unittest.main()
