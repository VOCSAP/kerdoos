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
import subprocess
import sys
import threading
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


def _marker_from_kwargs(kwargs: dict) -> str:
    # Mirrors how a real Chrome process receives the fetch-id: as a literal
    # entry of the args list _run() injects, which a fake factory must
    # thread into its own spawned process's argv the same way patchright
    # threads it into Chrome's argv.
    return next(
        arg for arg in kwargs["args"]
        if arg.startswith(browser._LAUNCH_ID_ARG_PREFIX))


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

    def test_host_allowed_covers_navigation_domain_and_subresource_cdn(
            self) -> None:
        # This predicate is what the egress-proxy's domain check (ADR 0004
        # D4/C1) now runs on every CONNECT authority -- it must accept the
        # SAME hosts the context-level route guard always accepted,
        # including declared render-critical sub-resource CDNs, or a
        # legitimate render would start failing at the network layer.
        fetcher = browser.BrowserFetcher(
            _POLICY, subresource_domains=("http2.mlstatic.com",))
        self.assertTrue(fetcher._host_allowed("mercadolivre.com.br"))
        self.assertTrue(fetcher._host_allowed("www.mercadolivre.com.br"))
        self.assertTrue(fetcher._host_allowed("http2.mlstatic.com"))
        self.assertFalse(fetcher._host_allowed("evil.com"))
        self.assertFalse(fetcher._host_allowed(""))

    def test_host_allowed_rejects_strings_that_are_not_host_names(self) -> None:
        # Every string below ENDS IN ".mercadolivre.com.br", so a bare suffix
        # test accepts them all. The allowlist must not depend on an upstream
        # canonicalizer to be the thing that rejects them.
        fetcher = browser.BrowserFetcher(_POLICY)
        for host in ("evil.com#.mercadolivre.com.br",
                     "evil.com/.mercadolivre.com.br",
                     "evil.com\\.mercadolivre.com.br",
                     "evil.com?.mercadolivre.com.br",
                     "evil.com@.mercadolivre.com.br",
                     "evil.com\x00.mercadolivre.com.br",
                     "evil.com\t.mercadolivre.com.br",
                     "evil.com .mercadolivre.com.br",
                     "evil.com..mercadolivre.com.br"):
            with self.subTest(host=host):
                self.assertFalse(fetcher._host_allowed(host))
        # The plain name and its root-dot spelling stay allowed: the form
        # check must not cost a legitimate render.
        self.assertTrue(fetcher._host_allowed("mercadolivre.com.br"))
        self.assertTrue(fetcher._host_allowed("mercadolivre.com.br."))


class BrowserWebRtcPolicyTest(unittest.TestCase):
    def test_security_policy_replaces_conflicting_site_arguments(self) -> None:
        args = browser._browser_launch_args([
            "--autolycos-launch-id=test",
            "--webrtc-ip-handling-policy=default",
            "--force-webrtc-ip-handling-policy=default",
            "--webrtc-ip-handling-policy",
            "--FORCE-WEBRTC-IP-HANDLING-POLICY",
        ])
        policy_args = [
            arg for arg in args
            if arg.lower().startswith((
                "--webrtc-ip-handling-policy",
                "--force-webrtc-ip-handling-policy",
            ))
        ]
        self.assertEqual(policy_args, [browser._WEBRTC_IP_HANDLING_POLICY])


class FinalDocumentContractTest(unittest.TestCase):
    def test_rejects_multibyte_document_above_the_byte_cap(self) -> None:
        page = _FakePage(
            "é" * (browser.MAX_HTML_BYTES // len("é".encode()) + 1), 200)
        with self.assertRaisesRegex(FetchError, "bytes cap"):
            browser.BrowserFetcher._read_document(page, time.monotonic() + 1)

    def test_rejects_final_document_on_an_unrequested_port(self) -> None:
        with self.assertRaisesRegex(FetchError, "port 8443"):
            browser.BrowserFetcher._check_final_document(
                "https://mercadolivre.com.br:8443/p/MLB1",
                "https://mercadolivre.com.br/p/MLB1")

    def test_rejects_different_allowed_final_host(self) -> None:
        with self.assertRaisesRegex(FetchError, "not the requested host"):
            browser.BrowserFetcher._check_final_document(
                "https://www.mercadolivre.com.br/p/MLB1",
                "https://mercadolivre.com.br/p/MLB1")

    def test_rejects_https_to_http_final_document(self) -> None:
        with self.assertRaisesRegex(FetchError, "fell back to http"):
            browser.BrowserFetcher._check_final_document(
                "http://mercadolivre.com.br/p/MLB1",
                "https://mercadolivre.com.br/p/MLB1")

    def test_rejects_final_document_with_userinfo(self) -> None:
        with self.assertRaisesRegex(FetchError, "userinfo"):
            browser.BrowserFetcher._check_final_document(
                "https://user@mercadolivre.com.br/p/MLB1",
                "https://mercadolivre.com.br/p/MLB1")

    def test_rejects_non_http_final_document_schemes(self) -> None:
        for final_url in ("about:blank", "data:text/html,ready",
                          "chrome-error://chromewebdata/"):
            with self.subTest(final_url=final_url):
                with self.assertRaises(FetchError):
                    browser.BrowserFetcher._check_final_document(
                        final_url, "https://mercadolivre.com.br/p/MLB1")

    def test_rejects_invalid_document_uri_when_page_url_is_allowed(self) -> None:
        with self.assertRaisesRegex(FetchError, "chrome-error://chromewebdata"):
            browser.BrowserFetcher._check_final_document(
                "https://mercadolivre.com.br/p/MLB1",
                "https://mercadolivre.com.br/p/MLB1",
                "chrome-error://chromewebdata/")


# ----- navigation wiring, driven with a FAKE Playwright (no real browser) -----

class _FakeResponse:
    def __init__(self, status: int) -> None:
        self.status = status


class _FakeJSHandle:
    def __init__(self, value: str) -> None:
        self._value = value

    def json_value(self) -> str:
        return self._value


class _FakePage:
    def __init__(self, content: str, status: int,
                 document_uri: str | None = None) -> None:
        self._content = content
        self._status = status
        self._document_uri = document_uri
        # Set by _FakeContext.route(): the guard is attached to the
        # CONTEXT now (ADR 0004 D4/C3), but mirrored here so every existing
        # test reading page.route_pattern/route_handler keeps working --
        # it is the SAME callable either way.
        self.route_pattern: str | None = None
        self.route_handler = None
        self.goto_args: tuple | None = None
        self.url = ""
        self._event_handlers: dict[str, object] = {}

    def goto(self, url, wait_until, timeout):  # noqa: ANN001
        self.goto_args = (url, wait_until, timeout)
        self.url = url
        return _FakeResponse(self._status)

    def on(self, event: str, handler) -> None:  # noqa: ANN001
        self._event_handlers[event] = handler

    def wait_for_function(self, expression, arg, timeout):  # noqa: ANN001
        return _FakeJSHandle(
            f"{self._document_uri or self.url}\n{self._content}")

    def content(self) -> str:
        return self._content


class _FakeContext:
    def __init__(self, page: _FakePage, **kwargs) -> None:  # noqa: ANN003
        self._page = page
        self.kwargs = kwargs
        self.route_pattern: str | None = None
        self.route_handler = None
        self.ws_route_pattern: str | None = None
        self.ws_route_handler = None

    def route(self, pattern, handler):  # noqa: ANN001
        self.route_pattern = pattern
        self.route_handler = handler
        self._page.route_pattern = pattern
        self._page.route_handler = handler

    def route_web_socket(self, pattern, handler):  # noqa: ANN001
        self.ws_route_pattern = pattern
        self.ws_route_handler = handler

    def new_page(self) -> _FakePage:
        return self._page

    def close(self) -> None:
        pass


class _FakeBrowser:
    def __init__(self, page: _FakePage) -> None:
        self._page = page
        self.closed = False
        self.context_kwargs: dict | None = None
        self.context: _FakeContext | None = None

    def new_context(self, **kwargs):  # noqa: ANN003
        self.context_kwargs = kwargs
        self.context = _FakeContext(self._page, **kwargs)
        return self.context

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
        self.assertEqual(len(chromium.launch_kwargs["args"]), 2)
        self.assertTrue(
            chromium.launch_kwargs["args"][0].startswith(
                browser._LAUNCH_ID_ARG_PREFIX))
        self.assertEqual(
            chromium.launch_kwargs["args"][1],
            browser._WEBRTC_IP_HANDLING_POLICY)
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

    def test_rejects_document_uri_that_differs_from_page_url(self) -> None:
        page = _FakePage(
            "<html>" + "x" * 5000, 200,
            document_uri="chrome-error://chromewebdata/")
        with self.assertRaisesRegex(FetchError, "chrome-error://chromewebdata"):
            self._run(page)

    def test_proxy_config_subtracts_the_implicit_loopback_bypass(self) -> None:
        # Without this, Chromium sends localhost / 127.0.0.1/8 / [::1] /
        # 169.254/16 / [FE80::]/10 DIRECTLY, emitting no CONNECT, so neither
        # the domain guard nor ip_is_safe nor the pin is ever consulted for
        # the address class they exist to refuse.
        page = _FakePage("<html>" + "x" * 5000, 200)
        _, chromium, _ = self._run(page)
        self.assertEqual(chromium.launch_kwargs["proxy"]["bypass"],
                         "<-loopback>")
        # It must travel in the proxy dict, because the equivalent launch
        # flag does NOT survive: carrying it in args would silently reopen
        # the hole. This asserts the scrub really would eat it.
        self.assertEqual(
            browser.strip_dangerous_browser_args(
                ["--proxy-bypass-list=<-loopback>"]), [])
        for a in chromium.launch_kwargs["args"]:
            self.assertNotIn("--proxy-bypass-list", a)

    def test_websocket_route_is_not_installed(self) -> None:
        page = _FakePage("<html>" + "x" * 5000, 200)
        _, chromium, _ = self._run(page)
        context = chromium._browser.context
        self.assertIsNone(context.ws_route_pattern)
        self.assertIsNone(context.ws_route_handler)

    def test_context_created_with_service_workers_blocked(self) -> None:
        # ADR 0004 D4/C3: a service worker must not be able to make ANY
        # request, through any channel.
        page = _FakePage("<html>" + "x" * 5000, 200)
        chromium = _FakeChromium(_FakeBrowser(page))
        fake_sync_playwright = lambda: _FakePW(chromium)  # noqa: E731
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(browser, "_load_playwright",
                                   return_value=fake_sync_playwright), \
                 mock.patch.object(browser, "_load_stealth",
                                   return_value=_FakeStealth):
                browser.BrowserFetcher(_POLICY).fetch(
                    "https://mercadolivre.com.br/p/MLB1")
        self.assertEqual(
            chromium._browser.context_kwargs, {"service_workers": "block"})

    def test_proxy_constructed_with_the_host_allowed_predicate(self) -> None:
        # ADR 0004 D4/C1: the proxy's domain check must be the SAME
        # predicate as the context-level route guard, not a second,
        # independently-maintained copy.
        page = _FakePage("<html>" + "x" * 5000, 200)
        chromium = _FakeChromium(_FakeBrowser(page))
        fake_sync_playwright = lambda: _FakePW(chromium)  # noqa: E731
        fetcher = browser.BrowserFetcher(_POLICY)
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(browser, "_load_playwright",
                                   return_value=fake_sync_playwright), \
                 mock.patch.object(browser, "_load_stealth",
                                   return_value=_FakeStealth), \
                 mock.patch.object(browser, "PinningProxy",
                                   wraps=browser.PinningProxy) as proxy_cls:
                fetcher.fetch("https://mercadolivre.com.br/p/MLB1")
        _, kwargs = proxy_cls.call_args
        # Bound methods are not cached: two separate accesses of
        # fetcher._host_allowed yield distinct objects that still compare
        # equal (same __self__, same __func__) -- assertIs would be too
        # strict here for a correct wiring.
        self.assertEqual(kwargs["domain_allowed"], fetcher._host_allowed)

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


class BrowserLaunchGenericExceptionTest(unittest.TestCase):
    """Roadmap 1d72b1e5 NIT (f): a launch failure that is NOT a patchright
    timeout must propagate as the SAME exception object (type, cause,
    traceback untouched), and the gate must still be released -- proven
    WITHOUT patchright needing to be installed at all, since the contract
    under test is "anything _is_patchright_launch_timeout doesn't recognize
    is re-raised unchanged", not patchright's own behavior.
    """

    def test_arbitrary_exception_propagates_unchanged_and_releases_gate(
            self) -> None:
        gate = BrowserGate(max_concurrent=1)
        original = RuntimeError("boom -- launch corrupted profile dir")
        chromium = _FakeChromium(browser_obj=None, error=original)
        fake_sync_playwright = lambda: _FakePW(chromium)  # noqa: E731
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(browser, "_load_playwright",
                                   return_value=fake_sync_playwright), \
                 mock.patch.object(browser, "_load_stealth",
                                   return_value=_FakeStealth):
                fetcher = browser.BrowserFetcher(_POLICY, gate=gate)
                with self.assertRaises(RuntimeError) as ctx:
                    fetcher.fetch("https://mercadolivre.com.br/p/MLB1")
        self.assertIs(ctx.exception, original)

        acquired_promptly = gate._semaphore.acquire(timeout=1.0)
        self.assertTrue(acquired_promptly, "gate slot was not released")
        gate._semaphore.release()


class _HangingBrowser:
    """A launched Chromium standing in: new_page() never returns (mirrors
    the roadmap d8b7b8fd measurement -- a real frozen Chromium blocks
    new_page() indefinitely), after spawning a REAL child process tagged
    with the fetch's own marker so the kill mechanism is proven against a
    genuine OS process, not asserted from reading psutil's API alone.
    """

    def __init__(self, marker: str, spawned: list) -> None:
        self._marker = marker
        self._spawned = spawned
        self.closed = False

    def new_context(self, **kwargs):  # noqa: ANN003, ANN201
        return self

    def route(self, pattern, handler) -> None:  # noqa: ANN001
        pass

    def route_web_socket(self, pattern, handler) -> None:  # noqa: ANN001
        pass

    def new_page(self):  # noqa: ANN201
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)", self._marker])
        self._spawned.append(proc)
        threading.Event().wait()  # never set: blocks this thread forever

    def close(self) -> None:
        self.closed = True


class _NeverReturningBrowser:
    """A launched Chromium standing in: new_page() blocks forever WITHOUT
    spawning any real OS process -- used only where the process side of
    the kill is irrelevant to what is being tested (e.g. psutil itself
    being unavailable, roadmap d8b7b8fd).
    """

    def new_context(self, **kwargs):  # noqa: ANN003, ANN201
        return self

    def route(self, pattern, handler) -> None:  # noqa: ANN001
        pass

    def route_web_socket(self, pattern, handler) -> None:  # noqa: ANN001
        pass

    def new_page(self):  # noqa: ANN201
        threading.Event().wait()  # never set: blocks this thread forever

    def close(self) -> None:
        pass


class _HangingThenUnblockedBrowser:
    """Simulates a real frozen Chromium's pipe read: new_page() blocks until
    `unblock_event` is set (standing in for the OS finally reporting the
    killed process, well after the deadline already fired and the gate was
    already released), then raises -- letting _run()'s OWN abandonment
    cleanup branch run LATE, exactly the "passe différée" scenario measured
    on the sibling uc-tier card 6521bbce.
    """

    def __init__(self, marker: str, spawned: list,
                 unblock_event: threading.Event) -> None:
        self._marker = marker
        self._spawned = spawned
        self._unblock_event = unblock_event

    def new_context(self, **kwargs):  # noqa: ANN003, ANN201
        return self

    def route(self, pattern, handler) -> None:  # noqa: ANN001
        pass

    def route_web_socket(self, pattern, handler) -> None:  # noqa: ANN001
        pass

    def new_page(self):  # noqa: ANN201
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)", self._marker])
        self._spawned.append(proc)
        self._unblock_event.wait(timeout=10)
        raise RuntimeError("connection reset (simulated post-kill unblock)")

    def close(self) -> None:
        pass


class BrowserFetchDeferredCleanupTest(unittest.TestCase):
    """Roadmap d8b7b8fd, lesson measured on sibling card 6521bbce: a
    deferred cleanup pass (the abandoned thread's OWN kill, running long
    after the deadline already fired and the gate was already released)
    must stay scoped to its OWN marker and never touch a DIFFERENT,
    concurrent-or-later fetch's live process, even with max_concurrent=1.
    """

    def test_late_cleanup_from_a_previous_fetch_spares_the_next_fetch(
            self) -> None:
        gate = BrowserGate(max_concurrent=1)
        unblock_event = threading.Event()
        prev_spawned: list = []

        chromium_prev = _FakeChromium(browser_obj=None)

        def _launch_prev(**kwargs):  # noqa: ANN003
            chromium_prev.launch_kwargs = kwargs
            marker = _marker_from_kwargs(kwargs)
            return _HangingThenUnblockedBrowser(
                marker, prev_spawned, unblock_event)

        chromium_prev.launch = _launch_prev
        fake_pw_prev = lambda: _FakePW(chromium_prev)  # noqa: E731

        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(browser, "_load_playwright",
                                   return_value=fake_pw_prev), \
                 mock.patch.object(browser, "_load_stealth",
                                   return_value=_FakeStealth):
                fetcher_prev = browser.BrowserFetcher(
                    _POLICY, gate=gate, fetch_timeout_seconds=0.2)
                with self.assertRaises(FetchError):
                    fetcher_prev.fetch("https://mercadolivre.com.br/p/prev")
        # Deadline already fired, gate already released -- prev's own
        # process was already killed by the MAIN thread's timeout branch.
        prev_spawned[0].wait(timeout=5)
        self.assertIsNotNone(
            prev_spawned[0].poll(), "prev's own process was not killed")

        # A NEXT fetch starts and succeeds normally, on the SAME gate slot
        # prev's release just freed -- its own process must stay alive
        # throughout the deferred cleanup that follows.
        next_spawned: list = []
        next_page = _FakePage("<html>ok</html>", 200)
        chromium_next = _FakeChromium(browser_obj=None)

        def _launch_next(**kwargs):  # noqa: ANN003
            chromium_next.launch_kwargs = kwargs
            marker = _marker_from_kwargs(kwargs)
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)", marker])
            next_spawned.append(proc)
            return _FakeBrowser(next_page)

        chromium_next.launch = _launch_next
        fake_pw_next = lambda: _FakePW(chromium_next)  # noqa: E731

        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(browser, "_load_playwright",
                                   return_value=fake_pw_next), \
                 mock.patch.object(browser, "_load_stealth",
                                   return_value=_FakeStealth):
                fetcher_next = browser.BrowserFetcher(_POLICY, gate=gate)
                fetcher_next.fetch("https://mercadolivre.com.br/p/next")

        try:
            # NOW let prev's abandoned thread finally "notice" the kill
            # (simulated) and run its own late, deferred cleanup pass --
            # well after the next fetch's own process already exists.
            unblock_event.set()
            time.sleep(0.5)
            self.assertIsNone(
                next_spawned[0].poll(),
                "the next fetch's live process was killed by a deferred, "
                "differently-marked cleanup pass")
        finally:
            for proc in prev_spawned + next_spawned:
                if proc.poll() is None:
                    proc.kill()


class BrowserFetchFreezeWiringTest(unittest.TestCase):
    """Roadmap d8b7b8fd: a step AFTER the launch (new_page, in this fake --
    the real measurement froze a genuine Chromium the same way) that never
    returns must still raise FetchError within fetch_timeout_seconds,
    release the gate only after cleanup, and kill ONLY its own process
    tree, never a concurrent unrelated fetch's.
    """

    def setUp(self) -> None:
        # The abandoned-fetch counter is a module-level global (roadmap
        # d8b7b8fd): isolate each test from whatever an earlier one left
        # behind.
        with browser._abandoned_fetch_threads_lock:
            self._saved_abandoned_count = browser._abandoned_fetch_thread_count
            browser._abandoned_fetch_thread_count = 0

    def tearDown(self) -> None:
        with browser._abandoned_fetch_threads_lock:
            browser._abandoned_fetch_thread_count = self._saved_abandoned_count

    def _hanging_chromium(self, spawned: list) -> _FakeChromium:
        chromium = _FakeChromium(browser_obj=None)

        def _launch(**kwargs):  # noqa: ANN003
            chromium.launch_kwargs = kwargs
            marker = _marker_from_kwargs(kwargs)
            return _HangingBrowser(marker, spawned)

        chromium.launch = _launch  # noqa: SLF001 -- test-only override
        return chromium

    def _fetch_with_frozen_step(self, gate, spawned: list,
                                 fetch_timeout_seconds: float = 0.3):
        chromium = self._hanging_chromium(spawned)
        fake_sync_playwright = lambda: _FakePW(chromium)  # noqa: E731
        raised = None
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(browser, "_load_playwright",
                                   return_value=fake_sync_playwright), \
                 mock.patch.object(browser, "_load_stealth",
                                   return_value=_FakeStealth):
                fetcher = browser.BrowserFetcher(
                    _POLICY, gate=gate,
                    fetch_timeout_seconds=fetch_timeout_seconds)
                try:
                    fetcher.fetch("https://mercadolivre.com.br/p/MLB1")
                except FetchError as exc:
                    raised = exc
        return chromium, raised

    def test_frozen_step_becomes_a_fetch_error_within_the_deadline(
            self) -> None:
        gate = BrowserGate(max_concurrent=1)
        spawned: list = []
        t0 = time.monotonic()
        _, raised = self._fetch_with_frozen_step(gate, spawned)
        elapsed = time.monotonic() - t0
        self.assertIsInstance(raised, FetchError)
        self.assertLess(elapsed, 5.0)  # bounded by the 0.3s deadline
        spawned[0].wait(timeout=5)

    def test_gate_released_after_a_frozen_fetch(self) -> None:
        gate = BrowserGate(max_concurrent=1)
        spawned: list = []
        self._fetch_with_frozen_step(gate, spawned)
        acquired_promptly = gate._semaphore.acquire(timeout=1.0)
        self.assertTrue(acquired_promptly, "gate slot was not released")
        gate._semaphore.release()
        spawned[0].wait(timeout=5)

    def test_no_zombie_process_survives_a_frozen_fetch(self) -> None:
        gate = BrowserGate(max_concurrent=1)
        spawned: list = []
        self._fetch_with_frozen_step(gate, spawned)
        proc = spawned[0]
        proc.wait(timeout=5)
        self.assertIsNotNone(
            proc.poll(), "the spawned child process was not killed")

    def test_process_confirmed_dead_before_fetch_even_returns(self) -> None:
        """A bare kill() sends SIGKILL and returns immediately, before the
        kernel finishes tearing the process down -- measured, an
        instrumented gate saw the targeted processes still genuinely
        running ~0.5s after kill() returned (roadmap d8b7b8fd).
        _kill_launch_processes must WAIT for the actual death before
        fetch() ever raises, so THIS check (no extra wait of its own,
        unlike the sibling test above) proves the confirmation already
        happened inside fetch()."""
        gate = BrowserGate(max_concurrent=1)
        spawned: list = []
        self._fetch_with_frozen_step(gate, spawned)
        self.assertIsNotNone(
            spawned[0].poll(),
            "the process was not yet confirmed dead when fetch() returned")

    def test_frozen_fetch_kills_only_its_own_process_tree(self) -> None:
        gate = BrowserGate(max_concurrent=2)
        own_spawned: list = []
        other_spawned: list = []
        other_marker_holder: dict = {}

        def _other_launch() -> None:
            time.sleep(0.1)  # starts inside the frozen fetch's window
            marker = f"{browser._LAUNCH_ID_ARG_PREFIX}deadbeef"
            other_marker_holder["marker"] = marker
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)", marker])
            other_spawned.append(proc)

        other_thread = threading.Thread(target=_other_launch, daemon=True)
        other_thread.start()
        try:
            self._fetch_with_frozen_step(gate, own_spawned)
            other_thread.join(timeout=5)
            self.assertFalse(other_thread.is_alive())
            own_spawned[0].wait(timeout=5)
            self.assertIsNotNone(
                own_spawned[0].poll(),
                "the frozen fetch's own process was not killed")
            self.assertIsNone(
                other_spawned[0].poll(),
                "an unrelated concurrent process was killed")
        finally:
            for proc in own_spawned + other_spawned:
                if proc.poll() is None:
                    proc.kill()

    def test_ceiling_refuses_new_fetches_without_launching(self) -> None:
        gate = BrowserGate(max_concurrent=1)
        with mock.patch.object(
            browser, "_abandoned_fetch_thread_count",
            browser.MAX_ABANDONED_FETCH_THREADS,
        ):
            with mock.patch.object(safety.socket, "getaddrinfo",
                                   return_value=_addrinfo("104.18.0.1")):
                with mock.patch.object(browser, "_load_playwright") as load_pw:
                    with self.assertRaises(FetchError):
                        browser.BrowserFetcher(_POLICY, gate=gate).fetch(
                            "https://mercadolivre.com.br/p/MLB1")
                    load_pw.assert_not_called()

    def test_ceiling_refusal_logs_at_error_level(self) -> None:
        gate = BrowserGate(max_concurrent=1)
        with mock.patch.object(
            browser, "_abandoned_fetch_thread_count",
            browser.MAX_ABANDONED_FETCH_THREADS,
        ):
            with mock.patch.object(safety.socket, "getaddrinfo",
                                   return_value=_addrinfo("104.18.0.1")):
                with mock.patch.object(browser, "_load_playwright"):
                    with self.assertLogs(
                        "autolycos.adapters.browser", level="ERROR"
                    ) as cm:
                        with self.assertRaises(FetchError):
                            browser.BrowserFetcher(_POLICY, gate=gate).fetch(
                                "https://mercadolivre.com.br/p/MLB1")
                    self.assertTrue(
                        any("refusing new fetch" in msg for msg in cm.output),
                        cm.output)

    def test_five_confirmed_kills_never_trip_the_ceiling_sixth_accepted(
            self) -> None:
        """Incrementing the ceiling counter must be tied to whether the
        kill could actually be confirmed, not to the deadline firing by
        itself (roadmap d8b7b8fd): 5 real freezes, each genuinely
        SIGKILLed and confirmed dead, must never count against the
        ceiling at all, so a 6th fetch is accepted normally."""
        gate = BrowserGate(max_concurrent=1)
        for _ in range(5):
            spawned: list = []
            _, raised = self._fetch_with_frozen_step(
                gate, spawned, fetch_timeout_seconds=0.2)
            self.assertIsInstance(raised, FetchError)
            spawned[0].wait(timeout=5)

        with browser._abandoned_fetch_threads_lock:
            count = browser._abandoned_fetch_thread_count
        self.assertEqual(
            count, 0,
            "a fetch whose process tree was confirmed dead must never "
            "count against the abandoned-fetch ceiling")

        page = _FakePage("<html>ok</html>", 200)
        chromium = _FakeChromium(browser_obj=_FakeBrowser(page))
        fake_sync_playwright = lambda: _FakePW(chromium)  # noqa: E731
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(browser, "_load_playwright",
                                   return_value=fake_sync_playwright), \
                 mock.patch.object(browser, "_load_stealth",
                                   return_value=_FakeStealth):
                result = browser.BrowserFetcher(_POLICY, gate=gate).fetch(
                    "https://mercadolivre.com.br/p/MLB1")
        self.assertEqual(result.method, "browser")

    def test_unconfirmed_kill_does_count_against_the_ceiling(self) -> None:
        """The ceiling must still protect against a GENUINE leak: if
        psutil.wait_procs reports a survivor (the kill could not be
        confirmed), the fetch counts against MAX_ABANDONED_FETCH_THREADS."""
        gate = BrowserGate(max_concurrent=1)
        spawned: list = []
        survivor = mock.MagicMock()
        survivor.pid = 999_999
        survivor.name.return_value = "chrome-headless"
        with mock.patch("psutil.wait_procs", return_value=([], [survivor])):
            self._fetch_with_frozen_step(
                gate, spawned, fetch_timeout_seconds=0.2)
        with browser._abandoned_fetch_threads_lock:
            count = browser._abandoned_fetch_thread_count
        self.assertEqual(
            count, 1,
            "a kill that could not be confirmed must still count against "
            "the ceiling")
        spawned[0].kill()


class BrowserFetchPsutilAbsentTest(unittest.TestCase):
    """Roadmap d8b7b8fd: psutil is declared under the `browser` extra,
    but a broken/partial install must still degrade to a clean
    FetchError -- never an uncaught ModuleNotFoundError escaping fetch()'s
    timeout branch, and the ceiling must treat "cannot even check" as an
    unconfirmed (dangerous) kill.
    """

    def setUp(self) -> None:
        with browser._abandoned_fetch_threads_lock:
            self._saved_abandoned_count = browser._abandoned_fetch_thread_count
            browser._abandoned_fetch_thread_count = 0

    def tearDown(self) -> None:
        with browser._abandoned_fetch_threads_lock:
            browser._abandoned_fetch_thread_count = self._saved_abandoned_count

    def test_missing_psutil_raises_fetch_error_not_module_not_found_error(
            self) -> None:
        gate = BrowserGate(max_concurrent=1)
        chromium = _FakeChromium(browser_obj=None)

        def _launch(**kwargs):  # noqa: ANN003
            chromium.launch_kwargs = kwargs
            return _NeverReturningBrowser()

        chromium.launch = _launch  # noqa: SLF001 -- test-only override
        fake_sync_playwright = lambda: _FakePW(chromium)  # noqa: E731

        # sys.modules[name] = None forces a bare `import psutil` inside the
        # code under test to raise ImportError.
        with mock.patch.dict(sys.modules, {"psutil": None}):
            with mock.patch.object(safety.socket, "getaddrinfo",
                                   return_value=_addrinfo("104.18.0.1")):
                with mock.patch.object(browser, "_load_playwright",
                                       return_value=fake_sync_playwright), \
                     mock.patch.object(browser, "_load_stealth",
                                       return_value=_FakeStealth):
                    fetcher = browser.BrowserFetcher(
                        _POLICY, gate=gate, fetch_timeout_seconds=0.2)
                    with self.assertRaises(FetchError):
                        fetcher.fetch("https://mercadolivre.com.br/p/MLB1")

        with browser._abandoned_fetch_threads_lock:
            count = browser._abandoned_fetch_thread_count
        self.assertEqual(
            count, 1,
            "psutil being unavailable must count as an unconfirmed "
            "(dangerous) kill, not a silent no-op")


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


class StaticRouterBrowserFetchTimeoutTest(unittest.TestCase):
    """Roadmap d8b7b8fd: KERDOOS_BROWSER_FETCH_TIMEOUT_SECONDS is injected
    by the kerdoos composition root through StaticRouter/_make_browser --
    never read by autolycos itself (invariant 2).
    """

    def test_injected_value_reaches_the_built_browser_fetcher(self) -> None:
        router = StaticRouter(_POLICY, browser_fetch_timeout_seconds=42.0)
        fetcher = router.select("browser")
        self.assertEqual(fetcher._fetch_timeout_seconds, 42.0)

    def test_no_value_injected_keeps_the_tier_s_own_default(self) -> None:
        router = StaticRouter(_POLICY)
        fetcher = router.select("browser")
        self.assertEqual(
            fetcher._fetch_timeout_seconds,
            browser.BROWSER_FETCH_TIMEOUT_SECONDS)

    def test_both_browser_overrides_apply_together(self) -> None:
        router = StaticRouter(
            _POLICY, browser_launch_timeout_seconds=7.0,
            browser_fetch_timeout_seconds=42.0)
        fetcher = router.select("browser")
        self.assertEqual(fetcher._launch_timeout_seconds, 7.0)
        self.assertEqual(fetcher._fetch_timeout_seconds, 42.0)


class StaticRouterBrowserMaxAbandonedFetchesTest(unittest.TestCase):
    """Roadmap d8b7b8fd F3: KERDOOS_BROWSER_MAX_ABANDONED_FETCHES is
    injected by the kerdoos composition root through
    StaticRouter/_make_browser -- never read by autolycos itself
    (invariant 2)."""

    def test_injected_value_reaches_the_built_browser_fetcher(self) -> None:
        router = StaticRouter(_POLICY, browser_max_abandoned_fetches=9)
        fetcher = router.select("browser")
        self.assertEqual(fetcher._max_abandoned_fetches, 9)

    def test_no_value_injected_keeps_the_tier_s_own_default(self) -> None:
        router = StaticRouter(_POLICY)
        fetcher = router.select("browser")
        self.assertEqual(
            fetcher._max_abandoned_fetches,
            browser.MAX_ABANDONED_FETCH_THREADS)


if __name__ == "__main__":
    unittest.main()
