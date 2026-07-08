"""BrowserFetcher: pure helpers + fail-closed SSRF guard + wiring via a fake.

Playwright is absent from the base interpreter. What can be exercised WITHOUT it:
the --host-resolver-rules builder, the challenge heuristic, and the guarantee
that the SSRF guard rejects a hostile target BEFORE Playwright is imported. The
navigation wiring (launch args, route guard, goto, FetchResult) is driven with a
FAKE sync_playwright injected in place of the real one, so the adapter logic is
covered without a real browser (real E2E is a blocking-before-prod fast-follow).
"""

from __future__ import annotations

import socket
import unittest
from unittest import mock

from autolycos import safety
from autolycos.adapters import browser
from autolycos.challenge import looks_challenged
from autolycos.errors import SSRFError
from autolycos.safety import DomainPolicy, ValidatedTarget

_POLICY = DomainPolicy(frozenset({
    "kabum.com.br", "amazon.com.br", "mercadolivre.com.br",
    "terabyteshop.com.br", "pichau.com.br", "magazineluiza.com.br",
}))


def _addrinfo(ip: str, port: int = 443):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]


class HostResolverRulesTest(unittest.TestCase):
    def test_ipv4_map_rule(self) -> None:
        target = ValidatedTarget(
            url="https://mercadolivre.com.br/p/X", scheme="https",
            host="mercadolivre.com.br", port=443, ip="104.18.0.1")
        self.assertEqual(browser._host_resolver_rules(target),
                         "MAP mercadolivre.com.br 104.18.0.1")

    def test_ipv6_address_is_bracketed(self) -> None:
        # Chromium's host-resolver-rules mis-parses a bare IPv6 literal; it must
        # be bracketed or the pin is silently dropped (rebind window re-opens).
        target = ValidatedTarget(
            url="https://mercadolivre.com.br/p/X", scheme="https",
            host="mercadolivre.com.br", port=443, ip="2606:4700::6812:1")
        self.assertEqual(browser._host_resolver_rules(target),
                         "MAP mercadolivre.com.br [2606:4700::6812:1]")


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
    def __init__(self, browser_obj: _FakeBrowser) -> None:
        self._browser = browser_obj
        self.launch_kwargs: dict | None = None

    def launch(self, **kwargs):  # noqa: ANN003
        self.launch_kwargs = kwargs
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


class BrowserFetcherWiringTest(unittest.TestCase):
    def _run(self, page: _FakePage, subresource_domains=()) -> tuple:
        chromium = _FakeChromium(_FakeBrowser(page))
        fake_sync_playwright = lambda: _FakePW(chromium)  # noqa: E731
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(browser, "_load_playwright",
                                   return_value=fake_sync_playwright):
                result = browser.BrowserFetcher(
                    _POLICY, subresource_domains).fetch(
                    "https://mercadolivre.com.br/p/MLB1")
        return result, chromium, page

    def test_pins_validated_ip_and_builds_result(self) -> None:
        page = _FakePage("<html>" + "x" * 5000, 200)
        result, chromium, page = self._run(page)
        # Chromium launched with the host-resolver-rules pin on the validated IP.
        self.assertEqual(
            chromium.launch_kwargs["args"],
            ["--host-resolver-rules=MAP mercadolivre.com.br 104.18.0.1"])
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
                                   return_value=fake_sync_playwright):
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


if __name__ == "__main__":
    unittest.main()
