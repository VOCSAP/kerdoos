"""HIGH-2 / M1: shared anti-SSRF guard + IP pinning (CWE-918).

The guard now lives in autolycos.safety (single choke point). These tests target
it there, plus the DNS-rebind pinning wired in autolycos.adapters.http.
"""

from __future__ import annotations

import socket
import unittest
from unittest import mock

from autolycos import safety
from autolycos.adapters import http
from autolycos.errors import FetchError, SSRFError

_POLICY = safety.DomainPolicy(frozenset({
    "kabum.com.br", "amazon.com.br", "mercadolivre.com.br",
    "terabyteshop.com.br", "pichau.com.br", "magazineluiza.com.br",
}))


class DomainAllowlistTest(unittest.TestCase):
    def test_exact_and_subdomain_allowed(self) -> None:
        self.assertTrue(_POLICY.domain_allowed("kabum.com.br"))
        self.assertTrue(_POLICY.domain_allowed("www.kabum.com.br"))
        self.assertTrue(_POLICY.domain_allowed("KABUM.COM.BR"))

    def test_suffix_spoof_rejected(self) -> None:
        self.assertFalse(_POLICY.domain_allowed("kabum.com.br.evil.com"))
        self.assertFalse(_POLICY.domain_allowed("evilkabum.com.br"))
        self.assertFalse(_POLICY.domain_allowed("evil.com"))


class IpGuardTest(unittest.TestCase):
    def test_private_and_local_blocked(self) -> None:
        for addr in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
                     "169.254.1.1", "::1", "0.0.0.0"):
            self.assertFalse(safety.ip_is_safe(addr), addr)

    def test_global_allowed(self) -> None:
        self.assertTrue(safety.ip_is_safe("8.8.8.8"))
        self.assertTrue(safety.ip_is_safe("104.18.0.1"))

    def test_ipv4_mapped_link_local_blocked(self) -> None:
        # CWE-918 / issue #11054: an IPv4-mapped IPv6 literal embedding the
        # cloud metadata address must be judged on the EMBEDDED IPv4, not on
        # IPv6Address.is_global (which was True for the mapped form, letting
        # the metadata endpoint slip through the allowlist).
        self.assertFalse(safety.ip_is_safe("::ffff:169.254.169.254"))
        self.assertFalse(safety.ip_is_safe("::ffff:127.0.0.1"))
        self.assertFalse(safety.ip_is_safe("::ffff:10.0.0.1"))

    def test_ipv4_mapped_global_allowed(self) -> None:
        # A mapped GLOBAL address must still be judged safe (no over-blocking).
        self.assertTrue(safety.ip_is_safe("::ffff:104.18.0.1"))


def _addrinfo(ip: str, port: int = 443):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]


class ValidateTargetTest(unittest.TestCase):
    def test_non_http_scheme_rejected(self) -> None:
        with self.assertRaises(SSRFError):
            safety.validate_target("ftp://kabum.com.br/x", _POLICY)
        with self.assertRaises(SSRFError):
            safety.validate_target("file:///etc/passwd", _POLICY)

    def test_non_allowlisted_domain_rejected(self) -> None:
        with self.assertRaises(SSRFError):
            safety.validate_target("https://evil.com/x", _POLICY)

    def test_raw_ip_host_rejected_by_allowlist(self) -> None:
        with self.assertRaises(SSRFError):
            safety.validate_target(
                "http://169.254.169.254/latest/meta-data", _POLICY)

    def test_allowlisted_domain_resolving_private_ip_rejected(self) -> None:
        # DNS-rebind style: allowlisted host that resolves to a private IP.
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("10.1.2.3")):
            with self.assertRaises(SSRFError):
                safety.validate_target(
                    "https://kabum.com.br/produto/1", _POLICY)

    def test_allowlisted_domain_resolving_global_ip_ok(self) -> None:
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            target = safety.validate_target(
                "https://kabum.com.br/produto/1", _POLICY)
        self.assertEqual(target.host, "kabum.com.br")
        self.assertEqual(target.ip, "104.18.0.1")   # pinned validated IP
        self.assertEqual(target.scheme, "https")
        self.assertEqual(target.port, 443)

    def test_dns_failure_is_fetch_error(self) -> None:
        with mock.patch.object(safety.socket, "getaddrinfo",
                               side_effect=socket.gaierror("nope")):
            with self.assertRaises(FetchError):
                safety.validate_target(
                    "https://kabum.com.br/produto/1", _POLICY)


class PinIpTest(unittest.TestCase):
    """The connection must use the validated IP, never a later re-resolution."""

    def test_validated_ip_survives_rebind(self) -> None:
        # 1st resolution (validation) -> global IP, pinned.
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            target = safety.validate_target(
                "https://kabum.com.br/produto/1", _POLICY)
        self.assertEqual(target.ip, "104.18.0.1")

        # Simulate a rebind: the underlying resolver now returns a PRIVATE IP.
        # Inside the pin context the host must still resolve to the pinned
        # global IP -- the rebind answer is never consulted.
        with mock.patch.object(socket, "getaddrinfo",
                               return_value=_addrinfo("10.9.9.9")) as rebind:
            with http._pinned_getaddrinfo(target.host, target.ip):
                resolved = socket.getaddrinfo(target.host, target.port)
            ips = {info[4][0] for info in resolved}
        self.assertEqual(ips, {"104.18.0.1"})   # pinned, not the rebind 10.9.9.9
        rebind.assert_not_called()              # synthetic answer, no re-resolve

    def test_pin_leaves_other_hosts_untouched(self) -> None:
        sentinel = _addrinfo("203.0.113.7", port=443)
        with mock.patch.object(socket, "getaddrinfo",
                               return_value=sentinel) as other:
            with http._pinned_getaddrinfo("kabum.com.br", "104.18.0.1"):
                out = socket.getaddrinfo("amazon.com.br", 443)
        self.assertEqual(out, sentinel)
        other.assert_called_once()

    def test_getaddrinfo_restored_after_context(self) -> None:
        original = socket.getaddrinfo
        with http._pinned_getaddrinfo("kabum.com.br", "104.18.0.1"):
            self.assertIsNot(socket.getaddrinfo, original)
        self.assertIs(socket.getaddrinfo, original)


if __name__ == "__main__":
    unittest.main()
