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
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from autolycos import safety
from autolycos.adapters import uc
from autolycos.browser_gate import BrowserGate
from autolycos.errors import FetchError, SSRFError
from autolycos.router import StaticRouter
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


def _marker_from_kwargs(kwargs: dict) -> str:
    # Mirrors how a real Chrome process receives the launch-id: as a literal
    # entry of the chromium_arg list _launch_with_deadline injects, which a
    # fake factory must thread into its own spawned process's argv the same
    # way SeleniumBase threads it into Chrome's argv.
    return next(
        arg for arg in kwargs["chromium_arg"]
        if arg.startswith(uc._LAUNCH_ID_ARG_PREFIX))


def _fake_uc_driver_binary() -> str:
    """A REAL executable psutil reports .name() == 'uc_driver' for --
    /bin/sleep copied under that name (POSIX only). Mirrors the reviewer's
    probe_orph2.py technique: only a real process proves attribution
    against psutil's actual process table, not a mock of it."""
    path = os.path.join(tempfile.gettempdir(), "uc_driver")
    if not os.path.exists(path):
        shutil.copy("/bin/sleep", path)
        os.chmod(path, 0o755)
    return path


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


class UcFetcherWiringTest(unittest.TestCase):
    def _run(self, page_source: str, subresource_domains=("mlcdn.com.br",),
             current_url: str | None = None):
        holder: dict = {}

        def _factory(**kwargs):  # the fake Driver class
            drv = _FakeDriver(page_source, current_url=current_url, **kwargs)
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
        # host-resolver-rules + the per-launch --kerdoos-launch-id marker
        # _launch_with_deadline appends (roadmap 65cef071).
        self.assertEqual(len(chromium_arg), 2)
        arg = chromium_arg[0]
        self.assertIn(
            "--host-resolver-rules=MAP www.magazineluiza.com.br 104.18.0.1", arg)
        self.assertIn("MAP * ~NOTFOUND", arg)
        self.assertIn("EXCLUDE mlcdn.com.br", arg)
        self.assertNotIn("EXCLUDE www.magazineluiza.com.br", arg)
        self.assertTrue(chromium_arg[1].startswith(uc._LAUNCH_ID_ARG_PREFIX))
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

    def test_chrome_error_page_marks_challenged_not_a_plain_200(self) -> None:
        # Card 1bddf3fa: uc_open_with_reconnect does not raise on a failed
        # navigation -- it silently lands on Chrome's own interstitial,
        # large enough (~188KB) and generic enough to slip past
        # looks_challenged on its own. No browser needed: the fake driver
        # returns the same shape a real Chrome connection failure produces.
        error_page = (
            '<html><body><script>window.errorData = '
            '{"errorCode":"ERR_CONNECTION_REFUSED"};</script>'
            + "x" * 200000 + "</body></html>")
        result, driver = self._run(
            error_page, current_url="chrome-error://chromewebdata/")
        self.assertTrue(result.challenged)
        self.assertTrue(driver.quit_called)

    def test_chrome_error_page_detected_from_dom_marker_alone(self) -> None:
        # current_url is best-effort (CDP/driver state can be unavailable,
        # mirrors _read_status) -- the DOM errorCode marker alone must
        # still be enough.
        error_page = (
            '{"errorCode":"ERR_NAME_NOT_RESOLVED"}' + "x" * 200000)
        result, _ = self._run(error_page, current_url=None)
        self.assertTrue(result.challenged)

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


class UcLaunchDeadlineTest(unittest.TestCase):
    """Roadmap 65cef071: bounds the Chrome LAUNCH itself, not just navigation
    (UC_PAGE_LOAD_TIMEOUT_SECONDS only takes effect after the launch already
    returned). Uses a REAL BrowserGate (not a mock) so a second acquire
    actually exercises the semaphore, and a REAL spawned child process so
    the kill mechanism is proven against a genuine OS process, not asserted
    from reading psutil's API alone.
    """

    def _hanging_factory(self, sleep_seconds: float, spawned: list) -> object:
        def _factory(**kwargs):  # noqa: ANN003
            # The spawned process carries the launch-id marker in its own
            # argv, exactly as a real Chrome process would receive it via
            # chromium_arg -- required for the marker-targeted kill (C1) to
            # find it at all.
            marker = _marker_from_kwargs(kwargs)
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)", marker])
            spawned.append(proc)
            time.sleep(sleep_seconds)
            return _FakeDriver("<html></html>", **kwargs)

        return _factory

    @staticmethod
    def _wait_until(predicate, timeout: float = 5.0, interval: float = 0.05) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(interval)
        return predicate()

    def test_hung_launch_raises_fetch_error_within_the_deadline(self) -> None:
        gate = BrowserGate(max_concurrent=1)
        spawned: list = []
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(
                uc, "_load_seleniumbase",
                return_value=self._hanging_factory(2.0, spawned),
            ):
                fetcher = uc.UcFetcher(
                    _POLICY, gate=gate, launch_timeout_seconds=0.3,
                    orphan_sweep_delay_seconds=0.1)
                t0 = time.monotonic()
                with self.assertRaises(FetchError):
                    fetcher.fetch(_MAGALU_URL)
                elapsed = time.monotonic() - t0
        # Bounded by the deadline + sweep delay, not the factory's 2.0s hang.
        self.assertLess(elapsed, 1.5)
        spawned[0].wait(timeout=5)

    def test_gate_released_after_a_timed_out_launch(self) -> None:
        gate = BrowserGate(max_concurrent=1)
        spawned: list = []
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(
                uc, "_load_seleniumbase",
                return_value=self._hanging_factory(2.0, spawned),
            ):
                fetcher = uc.UcFetcher(
                    _POLICY, gate=gate, launch_timeout_seconds=0.3,
                    orphan_sweep_delay_seconds=0.1)
                with self.assertRaises(FetchError):
                    fetcher.fetch(_MAGALU_URL)
            # A second acquire on the SAME gate must succeed promptly --
            # proves the slot was released, not held by the abandoned thread.
            acquired_promptly = gate._semaphore.acquire(timeout=1.0)
            self.assertTrue(acquired_promptly, "gate slot was not released")
            gate._semaphore.release()
        spawned[0].wait(timeout=5)

    def test_no_zombie_process_survives_a_timed_out_launch(self) -> None:
        gate = BrowserGate(max_concurrent=1)
        spawned: list = []
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(
                uc, "_load_seleniumbase",
                return_value=self._hanging_factory(2.0, spawned),
            ):
                fetcher = uc.UcFetcher(
                    _POLICY, gate=gate, launch_timeout_seconds=0.3,
                    orphan_sweep_delay_seconds=0.1)
                with self.assertRaises(FetchError):
                    fetcher.fetch(_MAGALU_URL)
        proc = spawned[0]
        proc.wait(timeout=5)
        self.assertIsNotNone(
            proc.poll(), "the spawned child process was not killed")

    def test_timed_out_launch_kills_only_its_own_process_tree(self) -> None:
        """Roadmap 65cef071: killing every new child of the current process
        would hit a concurrent, unrelated launch's own Chrome/chromedriver
        too as soon as max_concurrent >= 2. Two REAL _launch_with_deadline
        calls run concurrently on the SAME gate: only the one that times out
        may lose its process, the other one's must survive.
        """
        gate = BrowserGate(max_concurrent=2)
        own_spawned: list = []
        other_spawned: list = []
        other_result: dict = {}

        def _other_factory(**kwargs):  # noqa: ANN003
            marker = _marker_from_kwargs(kwargs)
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)", marker])
            other_spawned.append(proc)
            return _FakeDriver("<html></html>", **kwargs)

        def _other_launch() -> None:
            time.sleep(0.2)  # starts inside the timed-out launch's window
            other_fetcher = uc.UcFetcher(
                _POLICY, gate=gate, launch_timeout_seconds=5.0)
            other_result["driver"] = other_fetcher._launch_with_deadline(
                _other_factory, {})

        other_thread = threading.Thread(target=_other_launch, daemon=True)
        other_thread.start()
        try:
            fetcher = uc.UcFetcher(
                _POLICY, gate=gate,
                launch_timeout_seconds=0.6)
            with self.assertRaises(FetchError):
                fetcher._launch_with_deadline(
                    self._hanging_factory(3.0, own_spawned), {})
            other_thread.join(timeout=5)
            self.assertFalse(other_thread.is_alive(),
                              "the concurrent launch never completed")
            self.assertIn("driver", other_result)
            self.assertTrue(
                self._wait_until(lambda: own_spawned
                                  and own_spawned[0].poll() is not None),
                "the timed-out launch's own process was not killed")
            self.assertIsNone(
                other_spawned[0].poll(),
                "an unrelated concurrent launch's process was killed")
        finally:
            for proc in own_spawned + other_spawned:
                if proc.poll() is None:
                    proc.kill()

    def test_launch_finishing_after_the_deadline_is_quit_and_cleaned_up(
            self) -> None:
        """Roadmap 65cef071: a launch whose factory returns its Driver AFTER
        the deadline (a slow launch under load, chromedriver up before
        Chrome) must still be quit() and have its process tree cleaned up,
        instead of leaking both the Driver's process tree and the gate slot
        already vacated.
        """
        gate = BrowserGate(max_concurrent=1)
        late_spawned: list = []
        driver_holder: dict = {}

        def _late_factory(**kwargs):  # noqa: ANN003
            time.sleep(0.8)  # returns AFTER the 0.3s deadline below
            marker = _marker_from_kwargs(kwargs)
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)", marker])
            late_spawned.append(proc)
            drv = _FakeDriver("<html></html>", **kwargs)
            driver_holder["driver"] = drv
            return drv

        try:
            fetcher = uc.UcFetcher(
                _POLICY, gate=gate, launch_timeout_seconds=0.3,
                orphan_sweep_delay_seconds=0.1)
            with self.assertRaises(FetchError):
                fetcher._launch_with_deadline(_late_factory, {})
            self.assertTrue(
                self._wait_until(
                    lambda: driver_holder.get("driver") is not None
                    and driver_holder["driver"].quit_called),
                "the Driver returned after the deadline was never quit()")
            self.assertTrue(
                self._wait_until(lambda: late_spawned
                                  and late_spawned[0].poll() is not None),
                "the process spawned after the deadline was never cleaned up")
        finally:
            for proc in late_spawned:
                if proc.poll() is None:
                    proc.kill()

    def test_process_spawned_after_the_deadline_is_caught_by_delayed_sweep(
            self) -> None:
        """Roadmap 6521bbce: a launch whose factory call never returns at
        all can still spawn a process AFTER the deadline's own one-shot
        kill already ran -- a second, later pass (run before the browser
        gate is released, see _launch_with_deadline) must catch it. The
        factory spawns its marked child shortly after the 0.3s deadline
        (so the FIRST pass alone finds nothing).
        """
        gate = BrowserGate(max_concurrent=1)
        late_spawned: list = []

        def _never_returns_factory(**kwargs):  # noqa: ANN003
            time.sleep(0.4)  # after the 0.3s deadline's first kill pass
            marker = _marker_from_kwargs(kwargs)
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)", marker])
            late_spawned.append(proc)
            time.sleep(60)  # the construction call itself never returns

        fetcher = uc.UcFetcher(
            _POLICY, gate=gate, launch_timeout_seconds=0.3,
            orphan_sweep_delay_seconds=1.5)
        try:
            with self.assertRaises(FetchError):
                fetcher._launch_with_deadline(_never_returns_factory, {})
            self.assertTrue(
                self._wait_until(lambda: late_spawned
                                  and late_spawned[0].poll() is not None),
                "the process spawned after the first kill pass was not "
                "caught by the delayed sweep")
        finally:
            for proc in late_spawned:
                if proc.poll() is None:
                    proc.kill()


class UcDriverSiblingDiscoveryTest(unittest.TestCase):
    """Roadmap 6521bbce: in undetected mode SeleniumBase launches Chrome
    DIRECTLY from Python and runs uc_driver as Chrome's SIBLING, not its
    parent -- the marker-walk in _launch_process_tree never finds it, since
    uc_driver's own argv never carries the marker. Exercises the PID-set-diff
    matching against a REAL uc_driver-named process (a copy of /bin/sleep --
    the reviewer's probe_orph2.py technique, since a fake psutil.Process
    mock proves nothing about the real process table). POSIX only.
    """

    def setUp(self) -> None:
        if os.name != "posix" or not os.path.exists("/bin/sleep"):
            self.skipTest("needs /bin/sleep (POSIX)")
        self._spawned: list = []

    def tearDown(self) -> None:
        for proc in self._spawned:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)

    def _spawn_fake_uc_driver(self) -> subprocess.Popen:
        proc = subprocess.Popen([_fake_uc_driver_binary(), "60"])
        self._spawned.append(proc)
        return proc

    @staticmethod
    def _wait_until_visible(pid: int, timeout: float = 5.0) -> None:
        import psutil

        deadline = time.monotonic() + timeout
        me = psutil.Process(os.getpid())
        while time.monotonic() < deadline:
            if pid in {p.pid for p in me.children(recursive=True)}:
                return
            time.sleep(0.02)

    def test_sibling_spawned_after_the_baseline_snapshot_is_attributed(
            self) -> None:
        marker = "--kerdoos-launch-id=abc123"
        pids_before = uc._snapshot_descendant_pids()
        proc = self._spawn_fake_uc_driver()
        self._wait_until_visible(proc.pid)
        tree = uc._launch_process_tree(marker, pids_before)
        self.assertIn(proc.pid, {p.pid for p in tree})

    def test_sibling_present_before_the_baseline_snapshot_is_not_attributed(
            self) -> None:
        marker = "--kerdoos-launch-id=abc123"
        proc = self._spawn_fake_uc_driver()
        self._wait_until_visible(proc.pid)
        pids_before = uc._snapshot_descendant_pids()  # already includes proc
        tree = uc._launch_process_tree(marker, pids_before)
        self.assertNotIn(proc.pid, {p.pid for p in tree})

    def test_without_pids_before_the_sibling_is_never_attributed(
            self) -> None:
        # max_concurrent > 1: the caller passes pids_before=None, so a real
        # uc_driver sibling stays out of reach regardless of spawn timing --
        # documented limitation above KERDOOS_BROWSER_MAX_CONCURRENT=1.
        marker = "--kerdoos-launch-id=abc123"
        uc._snapshot_descendant_pids()  # mirrors the caller's own baseline
        proc = self._spawn_fake_uc_driver()
        self._wait_until_visible(proc.pid)
        tree = uc._launch_process_tree(marker, pids_before=None)
        self.assertNotIn(proc.pid, {p.pid for p in tree})

    def test_attribution_does_not_read_create_time(self) -> None:
        # Roadmap 6521bbce gate finding: psutil.create_time() truncates to
        # whole seconds (/proc/stat btime), making any timestamp-based
        # decision unreliable. Proof of independence: force EVERY psutil
        # Process's create_time() to a wrong, constant value (not an error --
        # psutil.children() itself uses create_time for its own pid-recycle
        # bookkeeping, so raising there would break unrelated plumbing, not
        # just prove anything about OUR decision) and confirm attribution is
        # unaffected -- it is driven by PID-set membership alone.
        import psutil

        marker = "--kerdoos-launch-id=abc123"
        pids_before = uc._snapshot_descendant_pids()
        proc = self._spawn_fake_uc_driver()
        self._wait_until_visible(proc.pid)
        with mock.patch.object(psutil.Process, "create_time",
                                lambda self: 0.0):
            tree = uc._launch_process_tree(marker, pids_before)
        self.assertIn(proc.pid, {p.pid for p in tree})


class UcOrphanSweepExclusiveGateTest(unittest.TestCase):
    """Card 6521bbce, reviewer NO-GO (R1, probe_orph2.py): with
    max_concurrent=1, a launch that never spawns anything and never
    returns must NEVER, through its own delayed sweep, kill a DIFFERENT,
    later, real launch's own uc_driver. The fix keeps the browser gate
    held through the sweep, so no other launch can be running while it
    scans -- this is what the timed sleep below is measuring. POSIX only.
    """

    def setUp(self) -> None:
        if os.name != "posix" or not os.path.exists("/bin/sleep"):
            self.skipTest("needs /bin/sleep (POSIX)")

    @staticmethod
    def _hanging_forever(**kwargs) -> None:  # noqa: ANN003, ARG004
        time.sleep(60)  # never spawns anything, never returns

    def test_next_launch_uc_driver_survives_the_previous_delayed_sweep(
            self) -> None:
        gate = BrowserGate(max_concurrent=1)
        later_spawned: list = []
        sweep_delay = 0.6

        def _real_uc_driver_factory(**kwargs):  # noqa: ANN003
            proc = subprocess.Popen([_fake_uc_driver_binary(), "60"])
            later_spawned.append(proc)
            return _FakeDriver("<html></html>", **kwargs)

        fetcher_a = uc.UcFetcher(
            _NEUTRAL_POLICY, gate=gate, launch_timeout_seconds=0.2,
            orphan_sweep_delay_seconds=sweep_delay)
        with self.assertRaises(FetchError):
            with gate.acquire():
                fetcher_a._launch_with_deadline(self._hanging_forever, {})

        fetcher_b = uc.UcFetcher(
            _NEUTRAL_POLICY, gate=gate, launch_timeout_seconds=5.0)
        try:
            with gate.acquire():
                fetcher_b._launch_with_deadline(_real_uc_driver_factory, {})
            # Past A's own sweep window: if attribution were unsound, A's
            # delayed sweep would have fired by now and could have hit B.
            time.sleep(sweep_delay + 0.3)
            self.assertIsNone(
                later_spawned[0].poll(),
                "the NEXT launch's real uc_driver was killed by the "
                "PREVIOUS launch's delayed sweep")
        finally:
            if later_spawned and later_spawned[0].poll() is None:
                later_spawned[0].kill()


class UcLateClaimLoserTest(unittest.TestCase):
    """Card 6521bbce, re-gate NO-GO (R1b/R1c, reviewer probe_orph3.py): A's
    construction thread can lose the claim race LONG after the deadline
    branch already released the browser gate (a late successful return, or
    a late exception) -- that branch must never re-diff by PID against its
    own stale pre-launch snapshot, because a DIFFERENT, later launch (B)
    may already hold the gate and have spawned its own live uc_driver.
    POSIX only.
    """

    def setUp(self) -> None:
        if os.name != "posix" or not os.path.exists("/bin/sleep"):
            self.skipTest("needs /bin/sleep (POSIX)")

    def _run_scenario(self, late_raises: bool) -> None:
        gate = BrowserGate(max_concurrent=1)

        def _a_factory(**kwargs):  # noqa: ANN003
            time.sleep(2.5)  # returns/raises long AFTER A's deadline+sweep
            if late_raises:
                raise RuntimeError("late launch failure")
            return _FakeDriver("<html></html>", **kwargs)

        fetcher_a = uc.UcFetcher(
            _NEUTRAL_POLICY, gate=gate, launch_timeout_seconds=0.3,
            orphan_sweep_delay_seconds=0.5)
        with self.assertRaises(FetchError):
            with gate.acquire():
                fetcher_a._launch_with_deadline(_a_factory, {})

        b_spawned: list = []

        def _b_factory(**kwargs):  # noqa: ANN003
            b_spawned.append(subprocess.Popen([_fake_uc_driver_binary(), "60"]))
            return _FakeDriver("<html></html>", **kwargs)

        fetcher_b = uc.UcFetcher(
            _NEUTRAL_POLICY, gate=gate, launch_timeout_seconds=5.0,
            orphan_sweep_delay_seconds=0.5)
        try:
            with gate.acquire():
                fetcher_b._launch_with_deadline(_b_factory, {})
            # A's construction thread returns/raises at ~2.5s -- past that,
            # if the fix were unsound it would have killed B's live process.
            time.sleep(3.0)
            self.assertIsNone(
                b_spawned[0].poll(),
                "the NEXT launch's real uc_driver was killed by A's "
                "late (post-gate-release) claim-loser cleanup")
        finally:
            if b_spawned and b_spawned[0].poll() is None:
                b_spawned[0].kill()

    def test_next_launch_survives_a_late_successful_return(self) -> None:
        self._run_scenario(late_raises=False)

    def test_next_launch_survives_a_late_exception(self) -> None:
        self._run_scenario(late_raises=True)


class UcOrphanSweepAttributionTest(unittest.TestCase):
    """Card 6521bbce acceptance test, reviewer NO-GO: must bite on the
    attribution mechanism itself, not on driver.quit() -- the factory
    below never returns, so quit() is provably never invoked; the only
    thing that can clean up its sibling is the snapshot-diff mechanism
    under test. POSIX only.
    """

    def setUp(self) -> None:
        if os.name != "posix" or not os.path.exists("/bin/sleep"):
            self.skipTest("needs /bin/sleep (POSIX)")

    def test_sibling_spawned_by_a_launch_that_never_returns_is_cleaned_up(
            self) -> None:
        gate = BrowserGate(max_concurrent=1)
        spawned: list = []

        def _never_returns_with_sibling(**kwargs):  # noqa: ANN003
            proc = subprocess.Popen([_fake_uc_driver_binary(), "60"])
            spawned.append(proc)
            time.sleep(60)  # construct() never returns -> quit() never runs

        fetcher = uc.UcFetcher(
            _NEUTRAL_POLICY, gate=gate, launch_timeout_seconds=0.2,
            orphan_sweep_delay_seconds=0.5)
        try:
            with self.assertRaises(FetchError):
                with gate.acquire():
                    fetcher._launch_with_deadline(
                        _never_returns_with_sibling, {})
            self.assertTrue(spawned, "the sibling was never spawned")
            self.assertIsNotNone(
                spawned[0].poll(),
                "the sibling uc_driver was not cleaned up -- quit() was "
                "never callable here, since the factory never returned")
        finally:
            for proc in spawned:
                if proc.poll() is None:
                    proc.kill()


class _HangingPostNavDriver:
    """A fake driver whose get_page_source() never returns -- simulates a
    Chrome frozen after navigation (roadmap f0c236da, MEASURED: neither
    get_page_source/current_url/quit nor a client-side Selenium command
    timeout are bounded on their own)."""

    class _FakeServiceProcess:
        def __init__(self, pid: int) -> None:
            self.pid = pid

    class _FakeService:
        def __init__(self, pid: int) -> None:
            self.process = _HangingPostNavDriver._FakeServiceProcess(pid)

    def __init__(self, marker: str | None, service_pid: int) -> None:
        self._kerdoos_launch_marker = marker
        self.service = self._FakeService(service_pid)
        self.quit_called = 0

    def set_page_load_timeout(self, seconds):  # noqa: ANN001
        pass

    def uc_open_with_reconnect(self, url, reconnect_time):  # noqa: ANN001
        pass

    def sleep(self, seconds):  # noqa: ANN001
        pass

    def get_page_source(self) -> str:
        time.sleep(60)  # never returns
        return "<html></html>"

    def quit(self) -> None:
        self.quit_called += 1


class UcPostNavigationDeadlineTest(unittest.TestCase):
    """Roadmap f0c236da: _run_after_launch_with_deadline bounds the whole
    navigate-to-quit cycle, since neither the individual calls nor a
    client-side Selenium command timeout are bounded on their own
    (MEASURED via probe_postnav.py / probe_remedy_a.py in the image)."""

    def test_timeout_raises_fetch_error_without_recalling_quit(self) -> None:
        # A real, disposable process for the cleanup path to kill -- NEVER
        # os.getpid() (the test runner itself): _kill_after_fetch_timeout
        # really does act on the pid it is given.
        dummy = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            fetcher = uc.UcFetcher(_NEUTRAL_POLICY, fetch_timeout_seconds=0.3)
            driver = _HangingPostNavDriver(marker=None, service_pid=dummy.pid)
            with self.assertRaises(FetchError):
                fetcher._run_after_launch_with_deadline(
                    driver, "https://example.com/")
            # The worker thread is still stuck inside get_page_source() (its
            # own `finally: driver.quit()` cannot run until that returns) --
            # proves the timeout path itself never calls quit() a second time.
            self.assertEqual(driver.quit_called, 0)
        finally:
            if dummy.poll() is None:
                dummy.kill()

    def test_timeout_kills_marker_matched_chrome_and_the_exact_service_pid(
            self) -> None:
        marker = "--kerdoos-launch-id=abc123"
        chrome_proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)", marker])
        service_proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"])
        unrelated = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            driver = _HangingPostNavDriver(
                marker=marker, service_pid=service_proc.pid)
            fetcher = uc.UcFetcher(_NEUTRAL_POLICY, fetch_timeout_seconds=0.2)
            with self.assertRaises(FetchError):
                fetcher._run_after_launch_with_deadline(
                    driver, "https://example.com/")
            self.assertTrue(
                self._wait_until(lambda: chrome_proc.poll() is not None),
                "marker-matched Chrome process survived")
            self.assertTrue(
                self._wait_until(lambda: service_proc.poll() is not None),
                "driver.service.process.pid was not killed")
            self.assertIsNone(
                unrelated.poll(), "an unrelated process was killed")
        finally:
            for proc in (chrome_proc, service_proc, unrelated):
                if proc.poll() is None:
                    proc.kill()

    @staticmethod
    def _wait_until(predicate, timeout: float = 5.0,
                     interval: float = 0.05) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(interval)
        return predicate()


class UcPostNavigationFreezeImageTest(unittest.TestCase):
    """Card f0c236da acceptance test: a REAL Driver(uc=True), SIGSTOP on
    Chrome after navigation (the probe_postnav.py scenario) -- fetch()'s
    post-navigation phase must return a FetchError within the configured
    deadline, with zero survivors of this launch once the browser gate is
    released, and the NEXT fetch's own Chrome must survive this one's
    cleanup. POSIX only (signal.SIGSTOP)."""

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

    @staticmethod
    def _wait_until(predicate, timeout: float = 20.0,
                     interval: float = 0.2) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(interval)
        return predicate()


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


class StaticRouterUcFetchTimeoutTest(unittest.TestCase):
    """Roadmap f0c236da: KERDOOS_UC_FETCH_TIMEOUT_SECONDS is injected by the
    kerdoos composition root through StaticRouter/_make_uc -- never read by
    autolycos itself (invariant 2)."""

    def test_injected_value_reaches_the_built_uc_fetcher(self) -> None:
        router = StaticRouter(_POLICY, uc_fetch_timeout_seconds=42.0)
        fetcher = router.select("uc")
        self.assertIsInstance(fetcher, uc.UcFetcher)
        self.assertEqual(fetcher._fetch_timeout_seconds, 42.0)

    def test_no_value_injected_keeps_the_tier_s_own_default(self) -> None:
        router = StaticRouter(_POLICY)
        fetcher = router.select("uc")
        self.assertEqual(
            fetcher._fetch_timeout_seconds, uc.UC_FETCH_TIMEOUT_SECONDS)

    def test_other_tiers_call_shape_is_unaffected(self) -> None:
        router = StaticRouter(_POLICY, uc_fetch_timeout_seconds=3.0)
        http_fetcher = router.select("http")
        self.assertEqual(http_fetcher.method_name, "http")


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


class StaticRouterUcLaunchTimeoutTest(unittest.TestCase):
    """Roadmap 65cef071: KERDOOS_UC_LAUNCH_TIMEOUT_SECONDS is injected by
    the kerdoos composition root through StaticRouter/_make_uc -- never read
    by autolycos itself (invariant 2).
    """

    def test_injected_value_reaches_the_built_uc_fetcher(self) -> None:
        router = StaticRouter(_POLICY, uc_launch_timeout_seconds=99.0)
        fetcher = router.select("uc")
        self.assertIsInstance(fetcher, uc.UcFetcher)
        self.assertEqual(fetcher._launch_timeout_seconds, 99.0)

    def test_no_value_injected_keeps_the_tier_s_own_default(self) -> None:
        router = StaticRouter(_POLICY)
        fetcher = router.select("uc")
        self.assertEqual(
            fetcher._launch_timeout_seconds, uc.UC_LAUNCH_TIMEOUT_SECONDS)

    def test_other_tiers_call_shape_is_unaffected(self) -> None:
        # http/tls/browser's factories don't declare launch_timeout_seconds;
        # injecting it must not break their construction.
        router = StaticRouter(_POLICY, uc_launch_timeout_seconds=5.0)
        http_fetcher = router.select("http")
        self.assertEqual(http_fetcher.method_name, "http")


class StaticRouterUcOrphanSweepDelayTest(unittest.TestCase):
    """Roadmap 6521bbce: KERDOOS_UC_ORPHAN_SWEEP_DELAY_SECONDS is injected
    by the kerdoos composition root through StaticRouter/_make_uc -- never
    read by autolycos itself (invariant 2).
    """

    def test_injected_value_reaches_the_built_uc_fetcher(self) -> None:
        router = StaticRouter(_POLICY, uc_orphan_sweep_delay_seconds=42.0)
        fetcher = router.select("uc")
        self.assertIsInstance(fetcher, uc.UcFetcher)
        self.assertEqual(fetcher._orphan_sweep_delay_seconds, 42.0)

    def test_no_value_injected_keeps_the_tier_s_own_default(self) -> None:
        router = StaticRouter(_POLICY)
        fetcher = router.select("uc")
        self.assertEqual(
            fetcher._orphan_sweep_delay_seconds, uc.ORPHAN_SWEEP_DELAY_SECONDS)

    def test_other_tiers_call_shape_is_unaffected(self) -> None:
        router = StaticRouter(_POLICY, uc_orphan_sweep_delay_seconds=3.0)
        http_fetcher = router.select("http")
        self.assertEqual(http_fetcher.method_name, "http")


if __name__ == "__main__":
    unittest.main()
