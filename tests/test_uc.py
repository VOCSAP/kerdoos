"""UcFetcher: pure host-resolver builder + fail-closed SSRF + wiring via a fake.

SeleniumBase is absent from the base interpreter. What can be exercised WITHOUT
it: the Option A --host-resolver-rules builder, and the guarantee that the SSRF
guard rejects a hostile target BEFORE SeleniumBase is imported. The open/render
wiring is driven with a FAKE Driver injected in place of the real one, so the
adapter logic (deny-by-default rule, page_source challenged, driver quit) is
covered without a real browser. Real UC E2E is a blocking-before-prod fast-follow.
"""

from __future__ import annotations

import importlib.util
import os
import socket
import unittest
from pathlib import Path
from unittest import mock

from autolycos import safety
from autolycos.adapters import uc
from autolycos.errors import SSRFError
from autolycos.safety import DomainPolicy, ValidatedTarget

_POLICY = DomainPolicy(frozenset({
    "kabum.com.br", "amazon.com.br", "mercadolivre.com.br",
    "terabyteshop.com.br", "pichau.com.br", "magazineluiza.com.br",
}))
_FIXTURES = Path(__file__).parent / "fixtures"
_MAGALU_URL = ("https://www.magazineluiza.com.br/monitor-gamer-alienware-32-4k-"
               "qd-oled-aw3225qf/p/bab5438g3h/in/mnpc/")


def _addrinfo(ip: str, port: int = 443):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]


def _target(ip: str) -> ValidatedTarget:
    return ValidatedTarget(url="https://www.magazineluiza.com.br/x",
                           scheme="https", host="www.magazineluiza.com.br",
                           port=443, ip=ip)


class HostResolverRulesTest(unittest.TestCase):
    # NB: these assertions check the RULE STRING only. They do NOT prove
    # Chromium's runtime rule evaluation -- a wrong order once produced a valid
    # string yet a dead pin (nav matched MAP * then EXCLUDE nav -> no rewrite).
    # The pin-is-honored guarantee is an E2E fast-follow (the connection must hit
    # the pinned IP). The ORDER asserted here (MAP nav FIRST, no EXCLUDE nav) is
    # the load-bearing fix.
    def test_option_a_pins_nav_first_then_deny_then_cdn_excludes(self) -> None:
        rule = uc._host_resolver_rules(_target("104.18.0.1"), ["mlcdn.com.br"])
        self.assertEqual(
            rule,
            "MAP www.magazineluiza.com.br 104.18.0.1, MAP * ~NOTFOUND, "
            "EXCLUDE mlcdn.com.br")

    def test_no_subresources_still_denies_and_pins(self) -> None:
        rule = uc._host_resolver_rules(_target("203.0.113.9"), [])
        self.assertEqual(
            rule,
            "MAP www.magazineluiza.com.br 203.0.113.9, MAP * ~NOTFOUND")

    def test_nav_is_never_excluded(self) -> None:
        # An EXCLUDE for the nav host would cancel the pin (the MAJOR that was
        # fixed); it must never appear in the rule.
        rule = uc._host_resolver_rules(_target("104.18.0.1"), ["mlcdn.com.br"])
        self.assertNotIn("EXCLUDE www.magazineluiza.com.br", rule)

    def test_pin_precedes_wildcard(self) -> None:
        rule = uc._host_resolver_rules(_target("104.18.0.1"), [])
        self.assertLess(rule.index("MAP www.magazineluiza.com.br 104.18.0.1"),
                        rule.index("MAP * ~NOTFOUND"))

    def test_multiple_cdns_are_sorted_deterministic(self) -> None:
        rule = uc._host_resolver_rules(
            _target("104.18.0.1"), ["b.cdn.com", "a.cdn.com", "b.cdn.com"])
        self.assertTrue(rule.endswith("EXCLUDE a.cdn.com, EXCLUDE b.cdn.com"))

    def test_ipv6_pin_is_bracketed_and_first(self) -> None:
        rule = uc._host_resolver_rules(_target("2606:4700::6812:1"), [])
        self.assertTrue(rule.startswith(
            "MAP www.magazineluiza.com.br [2606:4700::6812:1]"))


class FindPatchrightChromiumTest(unittest.TestCase):
    def test_returns_none_when_cache_dir_absent(self) -> None:
        with mock.patch.object(uc.os, "listdir", side_effect=OSError):
            self.assertIsNone(uc._find_patchright_chromium())

    def test_returns_none_when_no_dir_matches_chromium_pattern(self) -> None:
        with mock.patch.object(uc.os, "listdir",
                               return_value=["other", "chromium", "chromium-"]):
            self.assertIsNone(uc._find_patchright_chromium())

    def test_ignores_dir_name_with_shell_metacharacters(self) -> None:
        # SeleniumBase shells this candidate out downstream (detect_b_ver.py
        # Popen(shell=True)); a name that fails the strict digits-only match
        # must never reach the returned path (CWE-78).
        with mock.patch.object(uc.os, "listdir",
                               return_value=["chromium-0;touch pwned"]):
            with mock.patch.object(uc.os.path, "isfile", return_value=True):
                self.assertIsNone(uc._find_patchright_chromium())

    def test_picks_highest_revision_numerically_not_lexicographically(self) -> None:
        # Lexicographic sort would rank "chromium-1000" BEFORE "chromium-999".
        with mock.patch.object(uc.os, "listdir",
                               return_value=["chromium-999", "chromium-1000"]):
            with mock.patch.object(uc.os.path, "isfile", return_value=True):
                path = uc._find_patchright_chromium()
        self.assertIn("chromium-1000", path)

    def test_skips_dir_missing_the_expected_chrome_binary(self) -> None:
        def _isfile(path: str) -> bool:
            return "chromium-1000" not in path  # higher revision incomplete

        with mock.patch.object(uc.os, "listdir",
                               return_value=["chromium-999", "chromium-1000"]):
            with mock.patch.object(uc.os.path, "isfile", side_effect=_isfile):
                path = uc._find_patchright_chromium()
        self.assertIn("chromium-999", path)


class UcFetcherContractTest(unittest.TestCase):
    def test_method_name(self) -> None:
        self.assertEqual(uc.UcFetcher.method_name, "uc")

    def test_ssrf_refused_before_seleniumbase_import(self) -> None:
        # Refused by the guard first, so it holds even without SeleniumBase.
        with self.assertRaises(SSRFError):
            uc.UcFetcher(_POLICY).fetch("https://evil.com/x")

    def test_rebind_to_private_ip_refused(self) -> None:
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("10.1.2.3")):
            with self.assertRaises(SSRFError):
                uc.UcFetcher(_POLICY).fetch(_MAGALU_URL)

    def test_injection_shaped_url_rejected_before_driver_construction(
            self) -> None:
        # Roadmap c06082a5 L2: ties rempart 1 to the actual sink. The domain
        # is allowlisted (unlike evil.com above), so only the RFC 3986
        # character check can be what rejects this -- and the exploding
        # factory proves seleniumbase.Driver is never even constructed, not
        # merely that fetch() eventually raises.
        def _exploding_factory(**kwargs):  # noqa: ANN003
            raise AssertionError(
                "Driver() must never be constructed for a rejected URL")

        with mock.patch.object(uc, "_load_seleniumbase",
                               return_value=_exploding_factory):
            with self.assertRaises(SSRFError):
                uc.UcFetcher(_POLICY).fetch(
                    'https://www.magazineluiza.com.br/p/x");alert(1)//')


class _FakeDriver:
    def __init__(self, page_source: str, **kwargs) -> None:  # noqa: ANN003
        self.kwargs = kwargs
        self._page = page_source
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


class UcFetcherWiringTest(unittest.TestCase):
    def _run(self, page_source: str, subresource_domains=("mlcdn.com.br",)):
        holder: dict = {}

        def _factory(**kwargs):  # the fake Driver class
            drv = _FakeDriver(page_source, **kwargs)
            holder["driver"] = drv
            return drv

        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(uc, "_load_seleniumbase",
                                   return_value=_factory):
                result = uc.UcFetcher(
                    _POLICY, subresource_domains).fetch(_MAGALU_URL)
        return result, holder["driver"]

    def test_apostrophe_percent_encoded_before_reaching_the_js_sink(
            self) -> None:
        # Roadmap c06082a5 L3, rempart (2): a literal apostrophe is valid
        # RFC 3986 (rempart 1 accepts it, see RfcOutOfBandCharacterTest), but
        # uc.py must still neutralise it for the JS sink -- a future
        # seleniumbase version interpolating between '...' would otherwise
        # be reachable through a perfectly legal URL.
        url_with_apostrophe = _MAGALU_URL + "?ref=o'brien"
        holder: dict = {}

        def _factory(**kwargs):
            drv = _FakeDriver("<html></html>", **kwargs)
            holder["driver"] = drv
            return drv

        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(uc, "_load_seleniumbase",
                                   return_value=_factory):
                uc.UcFetcher(_POLICY).fetch(url_with_apostrophe)

        opened_url = holder["driver"].opened[0]
        self.assertNotIn("'", opened_url)
        self.assertIn("%27", opened_url)
        self.assertIn("o%27brien", opened_url)

    def test_binary_location_passed_to_driver_when_patchright_chromium_found(
            self) -> None:
        chrome_path = "/root/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome"
        with mock.patch.object(uc, "_find_patchright_chromium",
                               return_value=chrome_path):
            _, driver = self._run("<html>ok</html>")
        self.assertEqual(driver.kwargs["binary_location"], chrome_path)

    def test_binary_location_omitted_when_no_patchright_chromium(self) -> None:
        with mock.patch.object(uc, "_find_patchright_chromium",
                               return_value=None):
            _, driver = self._run("<html>ok</html>")
        self.assertNotIn("binary_location", driver.kwargs)

    def test_pins_and_builds_result_from_page_source(self) -> None:
        page = "<html>" + "x" * 5000 + "</html>"
        result, driver = self._run(page)
        chromium_arg = driver.kwargs["chromium_arg"]
        # A list, not a bare string: seleniumbase splits a STRING chromium_arg
        # on commas (browser_launcher.py), which would truncate this rule's
        # internal commas into bogus standalone switches and silently drop
        # the deny-by-default MAP * ~NOTFOUND (roadmap dde2d243).
        self.assertIsInstance(chromium_arg, list)
        self.assertEqual(len(chromium_arg), 1)
        arg = chromium_arg[0]
        self.assertIn(
            "--host-resolver-rules=MAP www.magazineluiza.com.br 104.18.0.1", arg)
        self.assertIn("MAP * ~NOTFOUND", arg)
        self.assertIn("EXCLUDE mlcdn.com.br", arg)
        self.assertNotIn("EXCLUDE www.magazineluiza.com.br", arg)
        self.assertTrue(driver.kwargs["uc"])
        self.assertEqual(result.method, "uc")
        self.assertEqual(result.status, 200)      # CDP absent -> 200 fallback
        self.assertFalse(result.challenged)
        self.assertIn("xxxxx", result.html)
        self.assertTrue(driver.quit_called)       # closed in finally
        self.assertEqual(driver.opened[0], _MAGALU_URL)

    def test_page_load_timeout_is_set_before_navigation(self) -> None:
        # Card ca30b736: a frozen Chrome must not hold the browser gate
        # forever -- set_page_load_timeout is what bounds the navigation.
        _, driver = self._run("<html>ok</html>")
        self.assertEqual(driver.page_load_timeout, uc.UC_PAGE_LOAD_TIMEOUT_SECONDS)

    def test_akamai_challenge_page_marks_challenged(self) -> None:
        akamai = (_FIXTURES / "magalu_cffi.html").read_text(
            encoding="utf-8", errors="replace")
        result, driver = self._run(akamai)
        self.assertTrue(result.challenged)        # scf-akamai / sec-if-cpt hit
        self.assertTrue(driver.quit_called)

    def test_driver_quit_even_on_error(self) -> None:
        # If page source is oversize, FetchError propagates but quit still runs.
        big = "y" * (uc.MAX_HTML_BYTES + 10)
        holder: dict = {}

        def _factory(**kwargs):
            drv = _FakeDriver(big, **kwargs)
            holder["driver"] = drv
            return drv

        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(uc, "_load_seleniumbase",
                                   return_value=_factory):
                with self.assertRaises(Exception):
                    uc.UcFetcher(_POLICY).fetch(_MAGALU_URL)
        self.assertTrue(holder["driver"].quit_called)


_HAS_SELENIUMBASE = importlib.util.find_spec("seleniumbase") is not None


@unittest.skipUnless(
    _HAS_SELENIUMBASE, "SeleniumBase not installed (autolycos[uc] extra)")
class ChromiumArgSurvivesSeleniumBaseParsingTest(unittest.TestCase):
    """Roadmap dde2d243: seleniumbase splits a STRING chromium_arg on commas
    (browser_launcher.py get_local_driver/_set_chrome_options), truncating a
    host-resolver-rules value's internal commas into bogus standalone
    switches and silently dropping the deny-by-default MAP * ~NOTFOUND. Drives
    the real kwarg through SeleniumBase's own option-construction function
    (no Chrome launch) to prove the FULL rule survives as one argument -- a
    test that only froze the list shape at the UcFetcher call site would not
    have caught this regression class.
    """

    def _build_chrome_options(self, chromium_arg):
        from seleniumbase import config as sb_config
        from seleniumbase.core import browser_launcher
        from seleniumbase.fixtures import constants

        sb_config._ext_dirs = []
        return browser_launcher._set_chrome_options(
            browser_name=constants.Browser.GOOGLE_CHROME,
            downloads_path=None, headless=True, locale_code=None,
            proxy_string=None, proxy_auth=None, proxy_user=None,
            proxy_pass=None, proxy_scheme=None, proxy_bypass_list=None,
            proxy_pac_url=None, multi_proxy=None, user_agent=None,
            recorder_ext=False, disable_cookies=False, disable_js=False,
            disable_csp=False, enable_ws=False, enable_sync=False,
            use_auto_ext=False, undetectable=True, uc_cdp_events=False,
            uc_subprocess=False, log_cdp_events=False, no_sandbox=True,
            disable_gpu=False, headless1=False, headless2=False,
            incognito=False, guest_mode=False, dark_mode=False,
            devtools=False, remote_debug=False, enable_3d_apis=False,
            swiftshader=False, ad_block_on=False, host_resolver_rules=None,
            block_images=False, do_not_track=False, chromium_arg=chromium_arg,
            user_data_dir=None, extension_zip=None, extension_dir=None,
            disable_features=None, binary_location=None, driver_version=None,
            page_load_strategy=None, external_pdf=False, servername=None,
            mobile_emulator=False, device_width=None, device_height=None,
            device_pixel_ratio=None,
        )

    def test_list_shape_keeps_the_full_rule_as_one_argument(self) -> None:
        rule = uc._host_resolver_rules(
            _target("104.18.0.1"), ["mlcdn.com.br"])
        options = self._build_chrome_options([f"--host-resolver-rules={rule}"])
        matching = [a for a in options.arguments if "host-resolver-rules" in a]
        self.assertEqual(matching, [f"--host-resolver-rules={rule}"])
        # No bogus standalone switches from a comma-split.
        self.assertFalse(any(a.startswith("--MAP") for a in options.arguments))
        self.assertFalse(
            any(a.startswith("--EXCLUDE") for a in options.arguments))

    def test_flat_string_shape_truncates_into_bogus_switches(self) -> None:
        # RED reference: proves this test actually catches the regression
        # class, not just the CURRENT UcFetcher call site.
        rule = uc._host_resolver_rules(
            _target("104.18.0.1"), ["mlcdn.com.br"])
        options = self._build_chrome_options(f"--host-resolver-rules={rule}")
        self.assertIn(
            "--host-resolver-rules=MAP www.magazineluiza.com.br 104.18.0.1",
            options.arguments)
        # The deny-by-default and the CDN exclude are LOST as real switches.
        self.assertIn("--MAP * ~NOTFOUND", options.arguments)
        self.assertIn("--EXCLUDE mlcdn.com.br", options.arguments)


def _real_chromium_available() -> bool:
    if not _HAS_SELENIUMBASE:
        return False
    from autolycos.adapters.uc import _find_patchright_chromium
    return _find_patchright_chromium() is not None


_HAS_REAL_CHROMIUM = _real_chromium_available()


_NEUTRAL_POLICY = DomainPolicy(frozenset({"example.com"}))


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


class GateWiringTest(unittest.TestCase):
    """Card ca30b736: fetch() must acquire the browser gate around the
    launch-to-quit cycle -- the SAME gate type as the browser tier, since uc
    reuses its Chromium."""

    def _fetch_with_gate(self, gate) -> None:
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(
                uc, "_load_seleniumbase",
                return_value=lambda **kw: _FakeDriver("<html>ok</html>", **kw),
            ):
                uc.UcFetcher(_POLICY, gate=gate).fetch(_MAGALU_URL)

    def test_fetch_acquires_the_injected_gate_exactly_once(self) -> None:
        gate = mock.MagicMock()
        self._fetch_with_gate(gate)
        gate.acquire.assert_called_once()
        hold = gate.acquire.return_value
        hold.__enter__.assert_called_once()
        hold.__exit__.assert_called_once()

    def test_fetch_uses_the_default_gate_when_none_injected(self) -> None:
        with mock.patch(
            "autolycos.adapters.uc.default_browser_gate"
        ) as default_gate_fn:
            spy_gate = mock.MagicMock()
            default_gate_fn.return_value = spy_gate
            self._fetch_with_gate(None)
        spy_gate.acquire.assert_called_once()


if __name__ == "__main__":
    unittest.main()
