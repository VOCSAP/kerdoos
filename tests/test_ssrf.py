"""HIGH-2 / M1: shared anti-SSRF guard + IP pinning (CWE-918).

The guard now lives in autolycos.safety (single choke point). These tests target
it there, plus the connection-level IP pin wired in autolycos.adapters.http
(ADR 0001 S9.1 Option A).
"""

from __future__ import annotations

import importlib.util
import socket
import unittest
from unittest import mock

import requests

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


class IpGuardNonRoutableMatrixTest(unittest.TestCase):
    """Phase 2a item 1 (ADR 0001 S9): a biting matrix over EVERY non-routable
    range ip_is_safe must reject, including the gaps explicitly called out at
    the P0 gate (CGNAT native+mapped, 0.0.0.0/8 mapped, ULA, v6 link-local).

    Empirically confirmed (2026-07-08, probe script) that the CURRENT
    ip_is_safe already rejects all cases below -- no implementation gap was
    found; this class exists to lock the coverage in as a regression guard
    (Kleos #11082).
    """

    def test_loopback_blocked(self) -> None:
        self.assertFalse(safety.ip_is_safe("127.0.0.1"))
        self.assertFalse(safety.ip_is_safe("::1"))

    def test_link_local_v4_blocked_including_metadata(self) -> None:
        self.assertFalse(safety.ip_is_safe("169.254.1.1"))
        self.assertFalse(safety.ip_is_safe("169.254.169.254"))  # cloud metadata

    def test_link_local_v6_blocked(self) -> None:
        # fe80::/10
        self.assertFalse(safety.ip_is_safe("fe80::1"))

    def test_unique_local_v6_blocked(self) -> None:
        # fc00::/7 (ULA)
        self.assertFalse(safety.ip_is_safe("fc00::1"))
        self.assertFalse(safety.ip_is_safe("fd12:3456:789a::1"))

    def test_zero_network_v4_blocked_native_and_mapped(self) -> None:
        # 0.0.0.0/8
        self.assertFalse(safety.ip_is_safe("0.0.0.0"))
        self.assertFalse(safety.ip_is_safe("0.1.2.3"))
        self.assertFalse(safety.ip_is_safe("::ffff:0.0.0.0"))

    def test_cgnat_blocked_native_and_mapped(self) -> None:
        # 100.64.0.0/10 (Carrier-Grade NAT, RFC 6598)
        self.assertFalse(safety.ip_is_safe("100.64.0.1"))
        self.assertFalse(safety.ip_is_safe("100.127.255.254"))  # range edge
        self.assertFalse(safety.ip_is_safe("::ffff:100.64.0.1"))

    def test_multicast_blocked(self) -> None:
        self.assertFalse(safety.ip_is_safe("224.0.0.1"))
        self.assertFalse(safety.ip_is_safe("ff02::1"))

    def test_broadcast_blocked(self) -> None:
        self.assertFalse(safety.ip_is_safe("255.255.255.255"))

    def test_public_controls_still_allowed(self) -> None:
        # Sanity: the matrix above must not accidentally over-block globals.
        self.assertTrue(safety.ip_is_safe("8.8.8.8"))
        self.assertTrue(safety.ip_is_safe("2001:4860:4860::8888"))


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


class RfcOutOfBandCharacterTest(unittest.TestCase):
    """Roadmap c06082a5: SeleniumBase's uc_open_with_reconnect interpolates
    the URL, unescaped, into a JS string handed to execute_script. A stored
    source URL carrying one of these characters must never reach that call --
    check_scheme_and_domain is the single shared choke point (also used by
    kerdoos.registry.url_validation.validate_source_url and
    kerdoos.digest.view._safe_href). One test per forbidden character class:
    a future regression in the allowlist regex for a single character must
    not hide behind an unrelated character's coverage.
    """

    _BASE = "https://www.kabum.com.br/produto/1"

    def test_double_quote_rejected(self) -> None:
        with self.assertRaises(SSRFError):
            safety.check_scheme_and_domain(self._BASE + '");alert(1)//', _POLICY)

    def test_backslash_rejected(self) -> None:
        with self.assertRaises(SSRFError):
            safety.check_scheme_and_domain(self._BASE + "\\x", _POLICY)

    def test_angle_bracket_open_rejected(self) -> None:
        with self.assertRaises(SSRFError):
            safety.check_scheme_and_domain(self._BASE + "<script>", _POLICY)

    def test_angle_bracket_close_rejected(self) -> None:
        with self.assertRaises(SSRFError):
            safety.check_scheme_and_domain(self._BASE + ">x", _POLICY)

    def test_backtick_rejected(self) -> None:
        with self.assertRaises(SSRFError):
            safety.check_scheme_and_domain(self._BASE + "`x`", _POLICY)

    def test_space_rejected(self) -> None:
        with self.assertRaises(SSRFError):
            safety.check_scheme_and_domain(self._BASE + " x", _POLICY)

    def test_control_character_rejected(self) -> None:
        with self.assertRaises(SSRFError):
            safety.check_scheme_and_domain(self._BASE + "\nx", _POLICY)
        with self.assertRaises(SSRFError):
            safety.check_scheme_and_domain(self._BASE + "\x00x", _POLICY)

    def test_trailing_newline_only_rejected(self) -> None:
        # Locks fullmatch specifically: re.match (or re.search) would accept
        # this because everything BEFORE the newline matches the allowlist --
        # only fullmatch's requirement that the WHOLE string match catches a
        # trailing character with nothing after it.
        with self.assertRaises(SSRFError):
            safety.check_scheme_and_domain(self._BASE + "\n", _POLICY)

    def test_trailing_space_rejected(self) -> None:
        with self.assertRaises(SSRFError):
            safety.check_scheme_and_domain(self._BASE + " ", _POLICY)

    def test_trailing_tab_rejected(self) -> None:
        with self.assertRaises(SSRFError):
            safety.check_scheme_and_domain(self._BASE + "\t", _POLICY)

    def test_non_ascii_byte_rejected(self) -> None:
        # RFC 3986 requires percent-encoding for non-ASCII; a raw byte is
        # outside the allowed repertoire regardless of intent.
        with self.assertRaises(SSRFError):
            safety.check_scheme_and_domain(self._BASE + "-café", _POLICY)

    def test_percent_encoded_quote_and_literal_apostrophe_accepted(self) -> None:
        # Rempart 1 must not OVER-reject: %22 is a valid percent-escape (not
        # a literal quote byte), and a literal apostrophe is a valid RFC 3986
        # sub-delim. Both must pass check_scheme_and_domain -- rempart 2
        # (uc.py's own call-site encoding) is what additionally neutralises
        # the apostrophe for the JS sink specifically, not this predicate.
        safety.check_scheme_and_domain(self._BASE + "%22x", _POLICY)
        safety.check_scheme_and_domain(self._BASE + "'x", _POLICY)

    def test_real_stored_product_urls_still_accepted(self) -> None:
        # Every one of these is a REAL captured product URL from this repo's
        # test fixtures (never a synthetic example) -- a regression here
        # would break the fetch-time gate for every currently-working site.
        real_urls = [
            "https://www.kabum.com.br/produto/534732/monitor-gamer-alienware-32-4k-qd-oled-aw3225qf",
            "https://www.amazon.com.br/Monitor-Gamer-Alienware-QD-OLED-AW3225QF/dp/B0CVQGSRZ9",
            "https://www.mercadolivre.com.br/monitor-gamer-alienware-32-4k-qd-oled-aw3225qf/p/MLB35045987",
            "https://www.terabyteshop.com.br/produto/40561/water-cooler-deepcool-lq240-wh-argb-240mm-com-display-intel-amd-branco-r-lq240-whdsmc-g-1",
            "https://www.pichau.com.br/gabinete-gamer-mancer-cv700b-mini-tower-lateral-de-vidro-com-2-fans-preto-mcr-cv700b-bk-2f",
            "https://www.magazineluiza.com.br/monitor-gamer-alienware-32-4k-qd-oled-aw3225qf/p/bab5438g3h/in/mnpc/",
        ]
        for url in real_urls:
            with self.subTest(url=url):
                scheme, host = safety.check_scheme_and_domain(url, _POLICY)
                self.assertEqual(scheme, "https")
                self.assertTrue(host)


class PinIpTest(unittest.TestCase):
    """The connection must use the validated IP, never a later re-resolution.

    Phase 2a item 3 (ADR 0001 S9.1, Option A): the previous global
    socket.getaddrinfo monkeypatch (_pinned_getaddrinfo, serialized under a
    process-wide lock) is replaced by a connection-level urllib3 pin
    (_PinnedHTTPAdapter.build_connection_pool_key_attributes). The new
    mechanism structurally never calls getaddrinfo for the pinned host on the
    request path at all -- the validated IP is placed directly into the
    urllib3 connection-pool key, so there is nothing for a DNS rebind to
    intercept.
    """

    def test_pool_key_pinned_to_validated_ip(self) -> None:
        # 1st resolution (validation) -> global IP, pinned.
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            target = safety.validate_target(
                "https://kabum.com.br/produto/1", _POLICY)
        self.assertEqual(target.ip, "104.18.0.1")

        adapter = http._PinnedHTTPAdapter(target.host, target.ip)
        req = requests.models.PreparedRequest()
        req.prepare(method="GET", url="https://kabum.com.br/produto/1",
                    headers={"Host": target.host})

        # A rebind at this point (a later getaddrinfo call returning a
        # PRIVATE ip) must have NO effect: the pool key is built directly
        # from target.ip, no resolver is consulted on this path.
        with mock.patch.object(socket, "getaddrinfo",
                               return_value=_addrinfo("10.9.9.9")) as rebind:
            host_params, pool_kwargs = adapter.build_connection_pool_key_attributes(
                req, verify=True)
        rebind.assert_not_called()
        self.assertEqual(host_params["host"], "104.18.0.1")   # pinned, not rebind
        self.assertEqual(pool_kwargs["server_hostname"], "kabum.com.br")
        self.assertEqual(pool_kwargs["assert_hostname"], "kabum.com.br")

    def test_each_adapter_owns_a_private_pool_manager(self) -> None:
        # No shared/mutable state between adapter instances -- concurrency
        # safety comes from this, not from a lock (see http.py docstring).
        a = http._PinnedHTTPAdapter("kabum.com.br", "104.18.0.1")
        b = http._PinnedHTTPAdapter("amazon.com.br", "104.18.0.2")
        self.assertIsNot(a.poolmanager, b.poolmanager)

    def test_pin_api_present_on_installed_requests(self) -> None:
        # The pin depends on this override point (requests >=2.32.0). Its
        # presence is the premise of the whole http-tier SSRF pin.
        self.assertTrue(hasattr(
            http.HTTPAdapter, "build_connection_pool_key_attributes"))

    def test_constructor_fails_fast_when_pin_api_absent(self) -> None:
        # Gate C1: if the installed requests is too old (override point gone),
        # constructing the fetcher must FAIL LOUDLY instead of silently losing
        # the IP pin at request time. Simulate the skew by swapping HTTPAdapter
        # for a class lacking the method.
        class _OldHTTPAdapter:
            pass

        with mock.patch.object(http, "HTTPAdapter", _OldHTTPAdapter):
            with self.assertRaises(RuntimeError):
                http.HttpFetcher(_POLICY)


class HttpConcurrencyTest(unittest.TestCase):
    """Phase 2a item 3 acceptance: concurrent http-tier fetches must not
    serialize on each other (no global lock / shared session or adapter).
    HttpFetcher is synchronous-only in this codebase (no asyncio fetch path
    exists to also exercise, per ADR 0001 S9.1's "threadpool ET async"
    wording -- only the threadpool half applies here), so this validates the
    concurrency property via a ThreadPoolExecutor and by patching
    requests.Session.get at the CLASS level (autospec, so the mock receives
    `self`): this exercises the real production fetch() path (no session
    override), proving each call builds its OWN Session/adapter rather than
    sharing self._session -- the exact design that made the old shared
    session + global DNS-patch lock necessary.
    """

    def test_concurrent_fetches_use_independent_sessions_same_host(self) -> None:
        import threading
        from concurrent.futures import ThreadPoolExecutor

        barrier = threading.Barrier(2, timeout=5)
        session_ids: list[int] = []
        ids_lock = threading.Lock()

        def _fake_get(self, url, headers=None, timeout=None,
                       allow_redirects=None, stream=None):
            with ids_lock:
                session_ids.append(id(self))
            # Rendezvous: both threads must be inside a GET simultaneously --
            # if fetch() serialized on shared state before reaching here
            # (as the old global-lock design did), this would deadlock and
            # the barrier.wait() timeout would fail the test.
            barrier.wait()
            resp = mock.MagicMock(status_code=200, is_redirect=False)
            resp.headers = {"Content-Type": "text/html"}
            resp.encoding = "utf-8"
            resp.iter_content.return_value = iter([b"<html></html>"])
            return resp

        fetcher = http.HttpFetcher(_POLICY)  # production path: no session override
        with mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            with mock.patch.object(requests.Session, "get", _fake_get):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [
                        pool.submit(fetcher.fetch, "https://kabum.com.br/a"),
                        pool.submit(fetcher.fetch, "https://kabum.com.br/b"),
                    ]
                    for f in futures:
                        f.result(timeout=5)

        # Both GETs were in flight at once (barrier didn't time out) AND each
        # used a DIFFERENT Session instance -- fetch() shares no mutable
        # session/adapter state across concurrent calls, even to the SAME
        # host (the scenario a shared self._session.mount() would have raced
        # on).
        self.assertEqual(len(session_ids), 2)
        self.assertNotEqual(session_ids[0], session_ids[1])


class RedirectRevalidationTest(unittest.TestCase):
    """Phase 2a item 4 (ADR 0001 S9): a 3xx redirect must be re-validated on
    the NEW target, http.py and tls.py already loop back to validate_target at
    the top of each hop (structurally present before Phase 2a) -- these tests
    lock that behavior in as a regression guard rather than a new fix.
    """

    def test_http_redirect_to_internal_ip_blocked(self) -> None:
        # First hop (kabum.com.br) resolves to a safe global IP and returns a
        # 302 pointing at a DIFFERENT allowlisted host (amazon.com.br) that
        # resolves to a private IP -- the redirect hop must be rejected before
        # ever following it, not silently connected to.
        redirect_resp = mock.MagicMock(status_code=302, is_redirect=True)
        redirect_resp.headers = {"Location": "https://amazon.com.br/internal"}
        session = mock.MagicMock()
        session.get.return_value = redirect_resp

        mapping = {"kabum.com.br": "104.18.0.1", "amazon.com.br": "10.1.2.3"}

        def _resolver(host, port, *args, **kwargs):
            return _addrinfo(mapping[host], port)

        fetcher = http.HttpFetcher(_POLICY, session=session)
        with mock.patch.object(safety.socket, "getaddrinfo", side_effect=_resolver):
            with self.assertRaises(SSRFError):
                fetcher.fetch("https://kabum.com.br/produto/1")
        # Only the first (safe) hop's GET was ever issued; the redirect target
        # was rejected by validate_target before a second request could fire.
        session.get.assert_called_once()

    @unittest.skipUnless(
        importlib.util.find_spec("curl_cffi") is not None, "curl_cffi not installed")
    def test_tls_redirect_to_internal_ip_blocked(self) -> None:
        from autolycos.adapters import tls

        class _RedirectResp:
            status_code = 302
            headers = {"Location": "https://kabum.com.br/internal"}

            def iter_content(self, chunk_size):
                return iter(())

            def close(self):
                pass

        def _fake_get(url, **kwargs):
            return _RedirectResp()

        mapping = {"amazon.com.br": "104.18.0.1", "kabum.com.br": "10.1.2.3"}

        def _resolver(host, port, *args, **kwargs):
            return _addrinfo(mapping[host], port)

        with mock.patch.object(safety.socket, "getaddrinfo", side_effect=_resolver):
            with mock.patch("curl_cffi.requests.get", _fake_get):
                with self.assertRaises(SSRFError):
                    tls.TlsFetcher(_POLICY).fetch("https://amazon.com.br/dp/X")


class _EchoUpstream:
    """A tiny loopback TCP server that echoes back whatever it receives.

    Stands in for the real remote origin so the egress-proxy's CONNECT tunnel
    (dial + bidirectional splice) can be exercised end-to-end over real
    loopback sockets, without any network access.
    """

    def __init__(self) -> None:
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(4)
        self.host, self.port = self._srv.getsockname()[:2]
        self._thread = None

    def start(self) -> None:
        import threading

        def _run() -> None:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            with conn:
                while True:
                    try:
                        data = conn.recv(4096)
                    except OSError:
                        break
                    if not data:
                        break
                    conn.sendall(data)

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        try:
            self._srv.close()
        except OSError:
            pass


_REAL_GETADDRINFO = socket.getaddrinfo


def _host_aware_resolver(target_host: str, target_ip: str):
    """A getaddrinfo side_effect that maps ONE hostname to a fixed IP and
    delegates everything else (notably 127.0.0.1 for the test's own client
    socket to the proxy) to the real resolver -- patching getaddrinfo globally
    would otherwise misroute the client's connection to the proxy.
    """
    def _resolver(host, port, *args, **kwargs):  # type: ignore[no-untyped-def]
        if host == target_host:
            return _addrinfo(target_ip, port)
        return _REAL_GETADDRINFO(host, port, *args, **kwargs)
    return _resolver


class EgressProxyTest(unittest.TestCase):
    """Phase 2a item 2 (ADR 0001 S9): loopback IP-pinning CONNECT proxy."""

    def test_strip_dangerous_browser_args(self) -> None:
        from autolycos.egress_proxy import strip_dangerous_browser_args
        args = [
            "--headless",
            "--host-resolver-rules=MAP x 1.2.3.4",
            "--proxy-server=http://evil:8080",
            "--ignore-certificate-errors",
            "--window-size=800,600",
        ]
        self.assertEqual(
            strip_dangerous_browser_args(args),
            ["--headless", "--window-size=800,600"])

    def test_binds_loopback_only(self) -> None:
        from autolycos.egress_proxy import PinningProxy
        with PinningProxy() as proxy:
            self.assertEqual(proxy.bound_host, "127.0.0.1")
            self.assertTrue(proxy.url.startswith("http://127.0.0.1:"))

    def test_connect_pins_validated_ip_and_tunnels(self) -> None:
        from autolycos.egress_proxy import PinningProxy

        upstream = _EchoUpstream()
        upstream.start()
        self.addCleanup(upstream.stop)

        dialed: list[tuple[str, int]] = []

        def _dialer(ip: str, port: int) -> socket.socket:
            dialed.append((ip, port))
            # Ignore the (restricted 443) port; dial the fake echo server.
            return socket.create_connection((upstream.host, upstream.port),
                                            timeout=5)

        proxy = PinningProxy(dialer=_dialer)
        proxy.start()
        self.addCleanup(proxy.stop)

        # A rebind at connect time would resolve to a private IP; the proxy must
        # dial the IP it PINNED at resolve (104.18.0.1), never re-resolve.
        with mock.patch.object(safety.socket, "getaddrinfo",
                               side_effect=_host_aware_resolver(
                                   "kabum.com.br", "104.18.0.1")):
            client = socket.create_connection(
                (proxy.bound_host, proxy.bound_port), timeout=5)
            client.settimeout(5)
            client.sendall(b"CONNECT kabum.com.br:443 HTTP/1.1\r\n"
                           b"Host: kabum.com.br:443\r\n\r\n")
            resp = client.recv(1024)
            self.assertIn(b"200", resp)
            client.sendall(b"ping-through-tunnel")
            echoed = client.recv(1024)
            client.close()

        self.assertEqual(echoed, b"ping-through-tunnel")
        self.assertEqual(dialed, [("104.18.0.1", 443)])   # pinned IP, not rebind

    def test_connect_rejects_disallowed_port(self) -> None:
        from autolycos.egress_proxy import PinningProxy

        dialed: list[tuple[str, int]] = []
        proxy = PinningProxy(dialer=lambda ip, p: dialed.append((ip, p)))  # type: ignore[arg-type,return-value]
        proxy.start()
        self.addCleanup(proxy.stop)

        client = socket.create_connection(
            (proxy.bound_host, proxy.bound_port), timeout=5)
        client.settimeout(5)
        client.sendall(b"CONNECT kabum.com.br:22 HTTP/1.1\r\n\r\n")
        resp = client.recv(1024)
        client.close()
        self.assertIn(b"403", resp)
        self.assertEqual(dialed, [])   # never resolved nor dialed

    def test_connect_rejects_internal_resolving_host(self) -> None:
        from autolycos.egress_proxy import PinningProxy

        dialed: list[tuple[str, int]] = []
        proxy = PinningProxy(dialer=lambda ip, p: dialed.append((ip, p)))  # type: ignore[arg-type,return-value]
        proxy.start()
        self.addCleanup(proxy.stop)

        with mock.patch.object(safety.socket, "getaddrinfo",
                               side_effect=_host_aware_resolver(
                                   "kabum.com.br", "10.1.2.3")):
            client = socket.create_connection(
                (proxy.bound_host, proxy.bound_port), timeout=5)
            client.settimeout(5)
            client.sendall(b"CONNECT kabum.com.br:443 HTTP/1.1\r\n\r\n")
            resp = client.recv(1024)
            client.close()
        self.assertIn(b"403", resp)
        self.assertEqual(dialed, [])   # blocked before dialing

    def test_non_connect_method_rejected(self) -> None:
        from autolycos.egress_proxy import PinningProxy

        proxy = PinningProxy()
        proxy.start()
        self.addCleanup(proxy.stop)

        client = socket.create_connection(
            (proxy.bound_host, proxy.bound_port), timeout=5)
        client.settimeout(5)
        client.sendall(b"GET http://kabum.com.br/ HTTP/1.1\r\n\r\n")
        resp = client.recv(1024)
        client.close()
        self.assertIn(b"400", resp)

    def test_non_loopback_client_helper(self) -> None:
        # The accept loop rejects any non-loopback peer; the bind already blocks
        # remote clients, this asserts the explicit guard's predicate.
        from autolycos.egress_proxy import _is_loopback
        self.assertTrue(_is_loopback("127.0.0.1"))
        self.assertTrue(_is_loopback("::1"))
        self.assertFalse(_is_loopback("10.1.2.3"))
        self.assertFalse(_is_loopback("8.8.8.8"))
        self.assertFalse(_is_loopback("not-an-ip"))


class EgressProxyDomainAllowlistTest(unittest.TestCase):
    """ADR 0004 Decision 4 condition C1: the proxy becomes the primary
    domain-allowlist control, checked BEFORE any resolution."""

    def test_connect_to_disallowed_domain_refused_without_resolving(self) -> None:
        from autolycos.egress_proxy import PinningProxy

        dialed: list[tuple[str, int]] = []
        resolved: list[str] = []

        def _tracking_resolver(host, port, *args, **kwargs):  # type: ignore[no-untyped-def]
            # Only track resolution of the TARGET host: the test's own
            # client socket also resolves 127.0.0.1 to reach the proxy
            # itself, which must not be mistaken for a resolution of the
            # refused target (same pitfall as _host_aware_resolver above).
            if host == "evil.example":
                resolved.append(host)
            return _REAL_GETADDRINFO(host, port, *args, **kwargs)

        proxy = PinningProxy(
            dialer=lambda ip, p: dialed.append((ip, p)),  # type: ignore[arg-type,return-value]
            domain_allowed=lambda host: host == "kabum.com.br")
        proxy.start()
        self.addCleanup(proxy.stop)

        with mock.patch.object(safety.socket, "getaddrinfo",
                               side_effect=_tracking_resolver):
            client = socket.create_connection(
                (proxy.bound_host, proxy.bound_port), timeout=5)
            client.settimeout(5)
            client.sendall(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
            resp = client.recv(1024)
            client.close()

        self.assertIn(b"403", resp)
        self.assertEqual(resolved, [])   # zero resolution attempts
        self.assertEqual(dialed, [])     # zero dial attempts

    def test_connect_to_allowed_domain_still_reaches_resolution(self) -> None:
        from autolycos.egress_proxy import PinningProxy

        upstream = _EchoUpstream()
        upstream.start()
        self.addCleanup(upstream.stop)

        dialed: list[tuple[str, int]] = []

        def _dialer(ip: str, port: int) -> socket.socket:
            dialed.append((ip, port))
            return socket.create_connection((upstream.host, upstream.port),
                                            timeout=5)

        proxy = PinningProxy(
            dialer=_dialer, domain_allowed=lambda host: host == "kabum.com.br")
        proxy.start()
        self.addCleanup(proxy.stop)

        with mock.patch.object(safety.socket, "getaddrinfo",
                               side_effect=_host_aware_resolver(
                                   "kabum.com.br", "104.18.0.1")):
            client = socket.create_connection(
                (proxy.bound_host, proxy.bound_port), timeout=5)
            client.settimeout(5)
            client.sendall(b"CONNECT kabum.com.br:443 HTTP/1.1\r\n\r\n")
            resp = client.recv(1024)
            client.close()

        self.assertIn(b"200", resp)
        self.assertEqual(dialed, [("104.18.0.1", 443)])

    def test_no_predicate_injected_preserves_ip_and_port_only_behavior(self) -> None:
        # Backward compat: a caller that does not pass domain_allowed (the
        # default) keeps the pre-C1 behavior -- any domain that resolves
        # safely is accepted, only IP/port are checked.
        from autolycos.egress_proxy import PinningProxy

        upstream = _EchoUpstream()
        upstream.start()
        self.addCleanup(upstream.stop)
        dialed: list[tuple[str, int]] = []

        def _dialer(ip: str, port: int) -> socket.socket:
            dialed.append((ip, port))
            return socket.create_connection((upstream.host, upstream.port),
                                            timeout=5)

        proxy = PinningProxy(dialer=_dialer)
        proxy.start()
        self.addCleanup(proxy.stop)

        with mock.patch.object(safety.socket, "getaddrinfo",
                               side_effect=_host_aware_resolver(
                                   "kabum.com.br", "104.18.0.1")):
            client = socket.create_connection(
                (proxy.bound_host, proxy.bound_port), timeout=5)
            client.settimeout(5)
            client.sendall(b"CONNECT kabum.com.br:443 HTTP/1.1\r\n\r\n")
            resp = client.recv(1024)
            client.close()

        self.assertIn(b"200", resp)
        self.assertEqual(dialed, [("104.18.0.1", 443)])

    def test_allowlisted_domain_rebinding_to_private_ip_still_refused(self) -> None:
        # ADR 0004 revision R1: the domain check must not SHORT-CIRCUIT the
        # IP-layer guard. An attacker who controls DNS for an allowlisted
        # host (or a compromised CDN record) points it at a private address;
        # ip_is_safe is the only thing left standing, so it must still run
        # and still refuse.
        from autolycos.egress_proxy import PinningProxy

        dialed: list[tuple[str, int]] = []

        proxy = PinningProxy(
            dialer=lambda ip, p: dialed.append((ip, p)),  # type: ignore[arg-type,return-value]
            domain_allowed=lambda host: host == "kabum.com.br")
        proxy.start()
        self.addCleanup(proxy.stop)

        with mock.patch.object(safety.socket, "getaddrinfo",
                               side_effect=_host_aware_resolver(
                                   "kabum.com.br", "169.254.169.254")):
            client = socket.create_connection(
                (proxy.bound_host, proxy.bound_port), timeout=5)
            client.settimeout(5)
            client.sendall(b"CONNECT kabum.com.br:443 HTTP/1.1\r\n\r\n")
            resp = client.recv(1024)
            client.close()

        self.assertIn(b"403", resp)
        self.assertEqual(dialed, [])

    def test_ip_literal_authority_refused_before_resolution(self) -> None:
        # An IP literal is never a name in the allowlist, so the domain check
        # refuses it first -- including the IPv6 literal form, whose brackets
        # the authority parser strips before the predicate sees it.
        from autolycos.egress_proxy import PinningProxy

        for authority in (b"127.0.0.1:443", b"169.254.169.254:443",
                          b"[::1]:443"):
            with self.subTest(authority=authority):
                dialed: list[tuple[str, int]] = []
                seen: list[str] = []

                proxy = PinningProxy(
                    dialer=lambda ip, p: dialed.append((ip, p)),  # type: ignore[arg-type,return-value]
                    domain_allowed=lambda host: (seen.append(host)
                                                 or host == "kabum.com.br"))
                proxy.start()
                self.addCleanup(proxy.stop)

                client = socket.create_connection(
                    (proxy.bound_host, proxy.bound_port), timeout=5)
                client.settimeout(5)
                client.sendall(b"CONNECT " + authority + b" HTTP/1.1\r\n\r\n")
                resp = client.recv(1024)
                client.close()

                self.assertIn(b"403", resp)
                self.assertEqual(dialed, [])
                self.assertEqual(len(seen), 1)
                self.assertNotIn("[", seen[0])


if __name__ == "__main__":
    unittest.main()
