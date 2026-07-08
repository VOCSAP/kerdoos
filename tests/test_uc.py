"""UcFetcher: pure host-resolver builder + fail-closed SSRF + wiring via a fake.

SeleniumBase is absent from the base interpreter. What can be exercised WITHOUT
it: the Option A --host-resolver-rules builder, and the guarantee that the SSRF
guard rejects a hostile target BEFORE SeleniumBase is imported. The open/render
wiring is driven with a FAKE Driver injected in place of the real one, so the
adapter logic (deny-by-default rule, page_source challenged, driver quit) is
covered without a real browser. Real UC E2E is a blocking-before-prod fast-follow.
"""

from __future__ import annotations

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


class _FakeDriver:
    def __init__(self, page_source: str, **kwargs) -> None:  # noqa: ANN003
        self.kwargs = kwargs
        self._page = page_source
        self.opened: tuple | None = None
        self.slept: float | None = None
        self.quit_called = False

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

    def test_pins_and_builds_result_from_page_source(self) -> None:
        page = "<html>" + "x" * 5000 + "</html>"
        result, driver = self._run(page)
        arg = driver.kwargs["chromium_arg"]
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


if __name__ == "__main__":
    unittest.main()
