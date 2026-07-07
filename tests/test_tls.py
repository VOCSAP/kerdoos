"""TlsFetcher: pure helpers + fail-closed SSRF guard (curl_cffi-independent).

The curl_cffi dependency is optional and absent from the base test interpreter.
These tests cover what can be exercised WITHOUT it: the CURLOPT_RESOLVE entry
builder, the challenge heuristic, and the guarantee that the SSRF guard rejects
a hostile target BEFORE curl_cffi is ever imported. A network round-trip test is
gated behind skipUnless(curl_cffi installed).
"""

from __future__ import annotations

import importlib.util
import socket
import unittest
from unittest import mock

from autolycos import safety
from autolycos.adapters import tls
from autolycos.errors import SSRFError
from autolycos.safety import ValidatedTarget

_HAS_CURL = importlib.util.find_spec("curl_cffi") is not None


def _addrinfo(ip: str, port: int = 443):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]


class ResolveEntryTest(unittest.TestCase):
    def test_builds_host_port_ip_triple(self) -> None:
        target = ValidatedTarget(
            url="https://amazon.com.br/dp/X", scheme="https",
            host="amazon.com.br", port=443, ip="104.18.0.1",
        )
        self.assertEqual(tls._resolve_entry(target), "amazon.com.br:443:104.18.0.1")

    def test_preserves_non_default_port(self) -> None:
        target = ValidatedTarget(
            url="https://amazon.com.br:8443/x", scheme="https",
            host="amazon.com.br", port=8443, ip="203.0.113.9",
        )
        self.assertEqual(tls._resolve_entry(target),
                         "amazon.com.br:8443:203.0.113.9")

    def test_ipv6_address_is_bracketed(self) -> None:
        # libcurl RESOLVE requires an IPv6 literal to be bracketed, else the
        # colons are mis-parsed and the pin is silently dropped.
        target = ValidatedTarget(
            url="https://amazon.com.br/dp/X", scheme="https",
            host="amazon.com.br", port=443, ip="2606:4700::6812:1",
        )
        self.assertEqual(tls._resolve_entry(target),
                         "amazon.com.br:443:[2606:4700::6812:1]")


class LooksChallengedTest(unittest.TestCase):
    def test_block_status_codes(self) -> None:
        for status in (403, 429, 503):
            self.assertTrue(tls._looks_challenged(status, "x" * 5000))

    def test_challenge_markers(self) -> None:
        self.assertTrue(tls._looks_challenged(200, "<html>Just a moment...</html>"))
        self.assertTrue(tls._looks_challenged(200, "px-captcha " + "x" * 5000))

    def test_short_body_is_suspicious(self) -> None:
        self.assertTrue(tls._looks_challenged(200, "tiny"))

    def test_healthy_page_not_challenged(self) -> None:
        self.assertFalse(tls._looks_challenged(200, "<html>" + "x" * 5000))


class TlsFetcherContractTest(unittest.TestCase):
    def test_method_name(self) -> None:
        self.assertEqual(tls.TlsFetcher.method_name, "tls")

    def test_ssrf_refused_before_curl_import(self) -> None:
        # A non-allowlisted target must be rejected by the guard first, so this
        # holds even though curl_cffi is not installed (no ImportError leaks).
        with self.assertRaises(SSRFError):
            tls.TlsFetcher().fetch("https://evil.com/x")

    def test_rebind_to_private_ip_refused(self) -> None:
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("10.1.2.3")):
            with self.assertRaises(SSRFError):
                tls.TlsFetcher().fetch("https://amazon.com.br/dp/X")


@unittest.skipUnless(_HAS_CURL, "curl_cffi not installed")
class TlsFetcherNetworkTest(unittest.TestCase):
    def test_pins_validated_ip_via_resolve(self) -> None:
        # With curl_cffi present, a validated global target reaches cffi.get with
        # the CURLOPT_RESOLVE pin built from the validated IP.
        from curl_cffi import CurlOpt

        captured: dict = {}

        class _Resp:
            status_code = 200
            headers: dict = {}
            encoding = "utf-8"

            def iter_content(self, chunk_size):
                yield b"<html>" + b"x" * 5000

            def close(self):
                pass

        def _fake_get(url, **kwargs):
            captured.update(kwargs)
            return _Resp()

        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch("curl_cffi.requests.get", _fake_get):
                result = tls.TlsFetcher().fetch("https://amazon.com.br/dp/X")

        self.assertEqual(result.method, "tls")
        self.assertEqual(captured["curl_options"][CurlOpt.RESOLVE],
                         ["amazon.com.br:443:104.18.0.1"])
        self.assertFalse(captured["allow_redirects"])


if __name__ == "__main__":
    unittest.main()
