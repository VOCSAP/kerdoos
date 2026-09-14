"""Camoufox tier (card 5438dd0b) T4 image security proofs.

Ports the ad-hoc probe campaigns run against the autonomous image (Kleos
#17455/#17456) into a versioned suite. Every proof drives a REAL Camoufox
Firefox process inside the autonomous image, gated by
KERDOOS_REQUIRE_IMAGE_TESTS=1 on the model of tests/test_uc.py's
UcPinExecutionTest -- a skip must never silently read as a pass, and a
builder-side-only assertion (a flag is present in launch kwargs) must never
substitute for a runtime one: that exact gap silently broke the uc tier's
--host-resolver-rules pin in production.

Probes reuse CamoufoxFetcher's own real fetch() pipeline (validate_target,
the addon-exclusion guard, the marker/gate/deadline machinery, PinningProxy,
FROZEN_FIREFOX_PREFS) via a subclass that only swaps _render -- never a
hand-rolled second launch path that would duplicate, and could silently
diverge from, the code under test.

An inline <script> tag injected via page.set_content() never executes on
this Camoufox/Firefox build (MEASURED: page.evaluate("() => window.__x")
reads back None after such a tag ran "() => { window.__x = true }"), unlike
the documented Playwright contract. Every probe below drives its JS through
page.evaluate() directly instead, never through an embedded <script> tag.

Every test that concludes on a zero-hit measurement carries a positive
control (Kleos lesson: a zero only means something if the instrument could
have registered a non-zero result).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from urllib.request import urlopen

import pytest

from autolycos.adapters import camoufox
from autolycos.egress_proxy import PinningProxy
from autolycos.errors import FetchError
from autolycos.ports import FetchResult
from autolycos.safety import DomainPolicy

_HAS_REAL_CAMOUFOX = camoufox.camoufox_ready()
_STRACE = shutil.which("strace")
_NEUTRAL_POLICY = DomainPolicy(frozenset({"example.com"}))


class _ImageGatedCase(unittest.TestCase):
    def setUp(self) -> None:
        if _HAS_REAL_CAMOUFOX:
            return
        if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
            self.fail(
                "KERDOOS_REQUIRE_IMAGE_TESTS=1 but camoufox_ready() is "
                "False -- run inside the autonomous image")
        self.skipTest("needs a real Camoufox install (autonomous image)")


class _RecordingPinningProxy(PinningProxy):
    dials: list[tuple[str, int]]

    def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
        super().__init__(*args, **kwargs)
        self.dials = []
        self._dials_lock = threading.Lock()
        real_dialer = self._dialer

        def _recording_dial(ip: str, port: int) -> socket.socket:
            with self._dials_lock:
                self.dials.append((ip, port))
            return real_dialer(ip, port)

        self._dialer = _recording_dial


class _ProbeCamoufoxFetcher(camoufox.CamoufoxFetcher):
    def __init__(self, *args, probe, **kwargs) -> None:  # noqa: ANN002, ANN003
        super().__init__(*args, **kwargs)
        self._probe = probe

    def _render(self, browser, url: str) -> FetchResult:  # type: ignore[no-untyped-def]
        context = browser.new_context(service_workers="block")
        try:
            page = context.new_page()
            self._probe(page)
            return FetchResult(html="<probe/>", status=200,
                                method=self.method_name, challenged=False)
        finally:
            context.close()


def _run_probe(domain_policy, probe, *, url="https://example.com/",
                proxy_cls=_RecordingPinningProxy,
                neutralize_validate_target=False,
                subresource_domains=(), out=None, **fetcher_kwargs):
    """`out`, when given, is populated with the constructed PinningProxy
    even if fetch() raises -- a `proxy = _run_probe(...)` assignment never
    completes on the raising path (the exception fires before the return
    value would be bound), so a caller expecting fetch() to raise must
    read the proxy back through `out["proxy"]` instead."""
    holder: dict = {}

    def _capturing_probe(page) -> None:  # noqa: ANN001
        probe(page)

    fetcher = _ProbeCamoufoxFetcher(
        domain_policy, subresource_domains, probe=_capturing_probe,
        nav_timeout_seconds=fetcher_kwargs.pop("nav_timeout_seconds", 10),
        fetch_timeout_seconds=fetcher_kwargs.pop("fetch_timeout_seconds", 25),
        **fetcher_kwargs)

    orig_proxy_cls = camoufox.PinningProxy

    class _CapturingProxy(proxy_cls):
        def __init__(self, *a, **k):  # noqa: ANN002, ANN003
            super().__init__(*a, **k)
            holder["proxy"] = self

    camoufox.PinningProxy = _CapturingProxy
    if neutralize_validate_target:
        orig_validate = camoufox.validate_target
        camoufox.validate_target = lambda *_a, **_k: None
    try:
        fetcher.fetch(url)
    finally:
        camoufox.PinningProxy = orig_proxy_cls
        if neutralize_validate_target:
            camoufox.validate_target = orig_validate
        if out is not None and "proxy" in holder:
            out["proxy"] = holder["proxy"]
    return holder["proxy"]


class CamoufoxPinnedConnectTest(_ImageGatedCase):
    """192.0.2.1 (TEST-NET-1) is deliberately non-global -- MEASURED
    (ipaddress.IPv4Address("192.0.2.1").is_global is False in CPython, and
    autolycos.safety.ip_is_safe agrees): resolve_and_pin's own ip_is_safe
    check refuses it BEFORE any dial, for an otherwise fully allowlisted
    domain. The proof is therefore two-sided, not "the pin gets dialed":
    the domain-level CONNECT authorization is granted (no "domain not in
    allowlist" refusal, distinct from CamoufoxAntiRebindingTest's targets
    which use a NON-allowlisted-by-IP host), and the dial log stays
    EMPTY -- zero connections anywhere, not just away from the pin."""

    def test_domain_accepted_but_zero_dial_to_a_non_global_pin(self) -> None:
        real_getaddrinfo = socket.getaddrinfo

        def _fake_getaddrinfo(host, *args, **kwargs):  # noqa: ANN001, ANN002
            if host == "example.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                          ("192.0.2.1", 443))]
            return real_getaddrinfo(host, *args, **kwargs)

        result: dict = {}

        def _probe(page) -> None:  # noqa: ANN001
            # The JS catches its own rejection into a plain string, so
            # this never raises in Python regardless of outcome -- the
            # dial record on the proxy is what this proof actually rests
            # on, not a Python-level exception.
            result["outcome"] = page.evaluate(
                "() => fetch('https://example.com/', {mode: 'no-cors'})"
                ".then(() => 'RESOLVED').catch(e => 'THREW:' + e.message)")

        import unittest.mock as mock
        # validate_target neutralized: it resolves the SAME primary host
        # via the same (mocked) getaddrinfo and would reject a non-global
        # pin before the proxy ever runs, hiding whether the PROXY's own
        # domain-then-IP layering (not validate_target's early gate) is
        # what is doing the refusing here.
        with mock.patch.object(socket, "getaddrinfo", side_effect=_fake_getaddrinfo):
            with self.assertNoLogs("autolycos.egress_proxy", level="WARNING"):
                proxy = _run_probe(
                    _NEUTRAL_POLICY, _probe,
                    neutralize_validate_target=True,
                    nav_timeout_seconds=4, fetch_timeout_seconds=8)
        self.assertTrue(
            result["outcome"].startswith("THREW"),
            f"fetch to the non-routable pin unexpectedly succeeded: "
            f"{result['outcome']}")
        self.assertEqual(
            proxy.dials, [],
            f"the proxy dialed {proxy.dials} despite the pin resolving to "
            "a non-global address")


def _run_traced(script: str, timeout: float) -> tuple[str, str]:
    # A TemporaryDirectory context manager (stdlib-owned cleanup) rather
    # than a hand-authored delete, on purpose.
    with tempfile.TemporaryDirectory(prefix="kerdoos-strace-") as tmp_dir:
        script_path = Path(tmp_dir) / "probe.py"
        log_path = Path(tmp_dir) / "trace.log"
        script_path.write_text(script, encoding="utf-8")
        proc = subprocess.run(
            [_STRACE, "-f", "-qq", "-e", "trace=network",
             "-o", str(log_path), sys.executable, str(script_path)],
            capture_output=True, text=True, timeout=timeout)
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        return proc.stdout + proc.stderr, log_text


_CONNECT_IP_RE = re.compile(
    r'connect\(\d+,\s*\{sa_family=AF_INET6?,[^}]*'
    r'(?:sin6?_addr(?:2)?="?|inet_pton\(AF_INET6?,\s*")([0-9a-fA-F:.]+)"?')
_SENDTO_PORT53_RE = re.compile(r'send(?:to|msg|mmsg)\(.*sin_port=htons\(53\)')


def _non_loopback_connect_ips(log_text: str) -> set[str]:
    ips: set[str] = set()
    for match in _CONNECT_IP_RE.finditer(log_text):
        raw = match.group(1)
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if not addr.is_loopback:
            ips.add(raw)
    return ips


@unittest.skipUnless(_STRACE, "strace not installed in this image -- run the "
                      "TEST container (never the shipped one) with strace "
                      "installed and CAP_SYS_PTRACE to exercise this proof")
class CamoufoxStraceNetworkAuditTest(_ImageGatedCase):
    def setUp(self) -> None:
        super().setUp()
        if _STRACE is None:
            self.skipTest("strace not installed")

    def test_pinned_target_never_leaves_the_loopback_proxy(self) -> None:
        # 192.0.2.1 (TEST-NET-1) is non-global -- MEASURED: ip_is_safe
        # refuses it inside resolve_and_pin before any dial (same finding
        # as CamoufoxPinnedConnectTest), so the strace-visible claim here
        # is zero non-loopback connect() syscalls anywhere in the tree,
        # not a successful dial to the pin.
        script = (
            "import socket\n"
            "_real = socket.getaddrinfo\n"
            "def _fake(host, *a, **k):\n"
            "    if host == 'example.com':\n"
            "        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 443))]\n"
            "    return _real(host, *a, **k)\n"
            "socket.getaddrinfo = _fake\n"
            "from autolycos.adapters import camoufox as cfx\n"
            "from autolycos.safety import DomainPolicy\n"
            "from autolycos.errors import FetchError\n"
            "cfx.validate_target = lambda *a, **k: None\n"
            "fetcher = cfx.CamoufoxFetcher(DomainPolicy(frozenset({'example.com'})),\n"
            "                          nav_timeout_seconds=5, fetch_timeout_seconds=12)\n"
            "try:\n"
            "    fetcher.fetch('https://example.com/')\n"
            "    print('RESULT:ok')\n"
            "except FetchError as exc:\n"
            "    print('RESULT:FetchError:' + str(exc))\n"
            "except Exception as exc:\n"
            "    print('RESULT:other:' + type(exc).__name__ + ':' + str(exc))\n"
        )
        stdout, log_text = _run_traced(script, timeout=60.0)
        self.assertIn("RESULT:FetchError", stdout, stdout)
        destinations = _non_loopback_connect_ips(log_text)
        self.assertEqual(
            destinations, set(),
            f"a non-loopback connect() was observed: {destinations}, "
            "expected zero (the pin is refused before any dial)")

    def test_disallowed_host_produces_zero_network_syscalls(self) -> None:
        script = (
            "from autolycos.adapters.camoufox import CamoufoxFetcher\n"
            "from autolycos.safety import DomainPolicy\n"
            "from autolycos.errors import SSRFError\n"
            "fetcher = CamoufoxFetcher(DomainPolicy(frozenset({'example.com'})))\n"
            "try:\n"
            "    fetcher.fetch('https://evil.example.org/')\n"
            "    print('RESULT:ok')\n"
            "except SSRFError as exc:\n"
            "    print('RESULT:SSRFError:' + str(exc))\n"
            "except Exception as exc:\n"
            "    print('RESULT:other:' + type(exc).__name__ + ':' + str(exc))\n"
        )
        stdout, log_text = _run_traced(script, timeout=20.0)
        self.assertIn("RESULT:SSRFError", stdout, stdout)
        network_lines = [
            line for line in log_text.splitlines()
            if line.strip() and not line.startswith("+++")
        ]
        self.assertEqual(
            network_lines, [],
            f"expected zero network syscalls, saw: {network_lines}")
        self.assertIsNone(
            _SENDTO_PORT53_RE.search(log_text),
            "a DNS-shaped sendto/sendmsg to port 53 was observed")

    def test_proxy_killed_mid_fetch_never_falls_back_to_direct(self) -> None:
        script = (
            "import threading, time\n"
            "from autolycos.adapters import camoufox as cfx\n"
            "from autolycos.egress_proxy import PinningProxy\n"
            "from autolycos.safety import DomainPolicy\n"
            "from autolycos.errors import FetchError\n"
            "class _KillingProxy(PinningProxy):\n"
            "    def _splice(self, a, b):\n"
            "        self.stop()\n"
            "        def _sever():\n"
            "            time.sleep(0.05)\n"
            "            for sock in (a, b):\n"
            "                try:\n"
            "                    sock.close()\n"
            "                except OSError:\n"
            "                    pass\n"
            "        threading.Thread(target=_sever, daemon=True).start()\n"
            "        return super()._splice(a, b)\n"
            "cfx.PinningProxy = _KillingProxy\n"
            "fetcher = cfx.CamoufoxFetcher(DomainPolicy(frozenset({'example.com'})),\n"
            "                              nav_timeout_seconds=8, fetch_timeout_seconds=15)\n"
            "try:\n"
            "    fetcher.fetch('https://example.com/')\n"
            "    print('RESULT:ok')\n"
            "except FetchError as exc:\n"
            "    print('RESULT:FetchError:' + str(exc))\n"
            "except Exception as exc:\n"
            "    print('RESULT:other:' + type(exc).__name__ + ':' + str(exc))\n"
        )
        stdout, log_text = _run_traced(script, timeout=40.0)
        self.assertIn("RESULT:FetchError", stdout, stdout)
        destinations = _non_loopback_connect_ips(log_text)
        self.assertEqual(
            destinations, set(),
            f"a direct (non-proxied) connection was attempted after the "
            f"proxy died: {destinations}")


class CamoufoxAntiRebindingTest(_ImageGatedCase):
    _REBIND_POLICY = DomainPolicy(frozenset({"rebind.example.com"}))

    def _assert_rebind_refused(self, malicious_ip: str) -> None:
        import unittest.mock as mock
        real_getaddrinfo = socket.getaddrinfo

        def _fake_getaddrinfo(host, *args, **kwargs):  # noqa: ANN001, ANN002
            if host == "rebind.example.com":
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                          (malicious_ip, 443))]
            return real_getaddrinfo(host, *args, **kwargs)

        result: dict = {}

        def _probe(page) -> None:  # noqa: ANN001
            # https:// on purpose: PinningProxy._handle only parses the
            # CONNECT method (egress_proxy.py), the path a real fetch
            # takes. A plain http:// proxied GET never reaches the
            # domain/IP checks at all and gets the proxy's generic 400,
            # which no-cors turns into a false-positive "resolved:opaque".
            outcome = page.evaluate(
                "() => fetch('https://rebind.example.com/', {mode: 'no-cors'})"
                ".then(r => 'RESOLVED:' + r.type)"
                ".catch(e => 'THREW:' + e.message)")
            result["outcome"] = outcome

        with mock.patch.object(socket, "getaddrinfo", side_effect=_fake_getaddrinfo):
            proxy = _run_probe(
                self._REBIND_POLICY, _probe, url="https://example.com/",
                neutralize_validate_target=True,
                nav_timeout_seconds=8, fetch_timeout_seconds=15)
        self.assertTrue(
            result["outcome"].startswith("THREW"),
            f"rebind to {malicious_ip} was NOT refused: {result['outcome']}")
        self.assertEqual(
            proxy.dials, [],
            f"the proxy dialed {proxy.dials} despite the target resolving "
            f"to the non-global {malicious_ip}")

    def test_rebind_to_loopback_is_refused(self) -> None:
        self._assert_rebind_refused("127.0.0.1")

    def test_rebind_to_private_range_is_refused(self) -> None:
        self._assert_rebind_refused("10.0.0.5")

    def test_rebind_to_link_local_metadata_is_refused(self) -> None:
        self._assert_rebind_refused("169.254.169.254")


class _HitCounter:
    def __init__(self) -> None:
        self.count = 0
        self._lock = threading.Lock()

    def inc(self) -> None:
        with self._lock:
            self.count += 1


class _Listener:
    def __init__(self, family: int, kind: int, host: str, port: int,
                 counter: _HitCounter) -> None:
        self._srv = socket.socket(family, kind)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((host, port))
        self._counter = counter
        self._stop = threading.Event()
        self._is_stream = kind == socket.SOCK_STREAM
        if self._is_stream:
            self._srv.listen(128)
        self._srv.settimeout(0.2)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                if self._is_stream:
                    conn, _ = self._srv.accept()
                    self._counter.inc()
                    try:
                        conn.sendall(
                            b"HTTP/1.1 204 No Content\r\n"
                            b"Content-Length: 0\r\n\r\n")
                    except OSError:
                        pass
                    conn.close()
                else:
                    self._srv.recvfrom(65536)
                    self._counter.inc()
            except socket.timeout:
                continue
            except OSError:
                return

    def stop(self) -> None:
        self._stop.set()
        self._srv.close()
        self._thread.join(timeout=2.0)

    def probe_from_python(self) -> None:
        addr = self._srv.getsockname()
        if self._is_stream:
            with socket.socket(self._srv.family, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect(addr[:2] if self._srv.family == socket.AF_INET6
                          else addr)
                s.sendall(b"GET / HTTP/1.1\r\n\r\n")
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(b"probe", addr)


# Driven via page.evaluate() directly (see module docstring): a <script>
# tag embedded in page.set_content()'s HTML never runs on this build.
_HOSTILE_PROBE_JS = """
async () => {
  const t80 = 'http://127.0.0.1:80/';
  const t443 = 'https://127.0.0.1:443/';
  const t8765 = 'http://127.0.0.1:8765/';
  const t8766 = 'http://127.0.0.1:8766/';
  const t8765v6 = 'http://[::1]:8765/';
  const attempts = [];
  try {
    attempts.push(new Promise(r => {
      const i = new Image(); i.onerror = i.onload = () => r();
      i.src = t80 + '?c=img'; setTimeout(r, 1500);
    }));
    attempts.push(fetch(t443, {mode: 'no-cors'}).catch(() => {}));
    attempts.push(Promise.resolve().then(() =>
      navigator.sendBeacon(t8765, 'x')));
    attempts.push(new Promise(r => {
      try {
        const ws = new WebSocket('ws://127.0.0.1:8766/');
        ws.onerror = ws.onclose = () => r();
        setTimeout(r, 1500);
      } catch (e) { r(); }
    }));
    attempts.push(new Promise(r => {
      try {
        const es = new EventSource(t8765v6);
        es.onerror = () => { es.close(); r(); };
        setTimeout(() => { es.close(); r(); }, 1500);
      } catch (e) { r(); }
    }));
    attempts.push(new Promise(r => {
      const f = document.createElement('iframe');
      f.src = t80 + '?c=iframe';
      f.onload = f.onerror = () => r();
      document.body.appendChild(f);
      setTimeout(r, 1500);
    }));
    ['preconnect', 'dns-prefetch', 'prefetch', 'preload'].forEach(rel => {
      const l = document.createElement('link');
      l.rel = rel; l.href = t443;
      if (rel === 'preload') l.as = 'fetch';
      document.head.appendChild(l);
    });
    attempts.push(new Promise(r => {
      const tgt = document.createElement('iframe');
      tgt.name = 'formtgt'; tgt.style.display = 'none';
      document.body.appendChild(tgt);
      const form = document.createElement('form');
      form.action = t8766; form.method = 'POST'; form.target = 'formtgt';
      document.body.appendChild(form);
      try { form.submit(); } catch (e) {}
      setTimeout(r, 1000);
    }));
    attempts.push(new Promise(r => {
      try {
        const w = window.open(t80 + '?c=open');
        setTimeout(() => { try { w && w.close(); } catch (e) {} r(); }, 1000);
      } catch (e) { r(); }
    }));
    await Promise.race([
      Promise.allSettled(attempts),
      new Promise(r => setTimeout(r, 4000)),
    ]);
    await new Promise(r => setTimeout(r, 1500));
  } catch (e) {}
  return 'done';
}
"""


class CamoufoxLoopbackChannelsTest(_ImageGatedCase):
    def test_zero_hits_with_a_positive_control(self) -> None:
        counter = _HitCounter()
        listeners = [
            _Listener(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1", 80, counter),
            _Listener(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1", 443, counter),
            _Listener(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1", 8765, counter),
            _Listener(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1", 8766, counter),
            _Listener(socket.AF_INET6, socket.SOCK_STREAM, "::1", 8765, counter),
            _Listener(socket.AF_INET, socket.SOCK_DGRAM, "127.0.0.1", 8767, counter),
        ]
        try:
            def _probe(page) -> None:  # noqa: ANN001
                page.set_content("<html><body></body></html>")
                page.evaluate(_HOSTILE_PROBE_JS)

            _run_probe(_NEUTRAL_POLICY, _probe, nav_timeout_seconds=8,
                       fetch_timeout_seconds=30)

            self.assertEqual(
                counter.count, 0,
                "a hostile page reached a real loopback listener")

            for listener in listeners:
                listener.probe_from_python()
            deadline = time.monotonic() + 5.0
            while counter.count < len(listeners) and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertEqual(
                counter.count, len(listeners),
                "positive control failed -- some listeners never "
                "registered a hit even from a direct Python connection, "
                "so the zero above is not trustworthy")
        finally:
            for listener in listeners:
                listener.stop()


class CamoufoxDisabledBrowserApisTest(_ImageGatedCase):
    def test_rtc_webtransport_serviceworker_are_undefined(self) -> None:
        result: dict = {}

        def _probe(page) -> None:  # noqa: ANN001
            result["types"] = page.evaluate(
                "() => ({rtc: typeof RTCPeerConnection, "
                "webTransport: typeof WebTransport, "
                "serviceWorker: typeof navigator.serviceWorker})")

        _run_probe(_NEUTRAL_POLICY, _probe, nav_timeout_seconds=8,
                   fetch_timeout_seconds=20)
        self.assertEqual(result["types"], {
            "rtc": "undefined",
            "webTransport": "undefined",
            "serviceWorker": "undefined",
        })


class CamoufoxAllowedVsDisallowedChannelTest(_ImageGatedCase):
    _POLICY = DomainPolicy(frozenset({"example.com"}))

    def test_websocket_worker_and_open_dial_only_the_allowed_host(self) -> None:
        result: dict = {}

        def _probe(page) -> None:  # noqa: ANN001
            page.set_content("<html><body></body></html>")
            result["outcomes"] = page.evaluate(
                "async () => {"
                "  const out = {};"
                "  out.ws_allowed = await new Promise(r => {"
                "    try {"
                "      const ws = new WebSocket('wss://example.com/');"
                "      ws.onerror = ws.onclose = () => r('closed');"
                "      setTimeout(() => r('timeout'), 3000);"
                "    } catch (e) { r('threw:' + e.message); }"
                "  });"
                "  out.worker_disallowed = await new Promise(r => {"
                "    try {"
                "      const src = ["
                "        'fetch(\\'http://127.0.0.1:9999/\\').then(',"
                "        '()=>postMessage(\\'resolved\\')).catch(',"
                "        'e=>postMessage(\\'threw:\\'+e.message))',"
                "      ].join('');"
                "      const blob = new Blob([src],"
                "        {type: 'application/javascript'});"
                "      const w = new Worker(URL.createObjectURL(blob));"
                "      w.onmessage = ev => { w.terminate(); r(ev.data); };"
                "      setTimeout(() => { w.terminate(); r('timeout'); }, 3000);"
                "    } catch (e) { r('threw:' + e.message); }"
                "  });"
                "  return out;"
                "}")

        proxy = _run_probe(self._POLICY, _probe, nav_timeout_seconds=8,
                            fetch_timeout_seconds=20)
        outcomes = result["outcomes"]
        allowed_dials = [d for d in proxy.dials if d[0] != "127.0.0.1"]
        self.assertTrue(
            allowed_dials,
            f"no dial was ever attempted for the allowed host, only "
            f"{proxy.dials}")
        self.assertNotIn(
            "resolved", outcomes["worker_disallowed"],
            "a Worker reached a disallowed loopback target")
        self.assertNotIn(("127.0.0.1", 9999), proxy.dials)


def _network_is_reachable() -> bool:
    try:
        with socket.create_connection(("1.1.1.1", 53), timeout=1.5):
            return True
    except OSError:
        return False


class CamoufoxNoNetworkZeroDownloadTest(_ImageGatedCase):
    def test_empty_home_creates_no_addon_directory(self) -> None:
        # A test cannot drop its OWN container's network from inside
        # itself -- KERDOOS_IMAGE_NETWORK_NONE=1 is the caller's explicit
        # promise that this process was launched under --network none
        # (see AGENTS.md). Present: hard-fail if that promise is false
        # (auto-detection alone cannot tell an accidental absence from a
        # deliberate one). Absent: skip explicitly, never silently infer
        # network state from a reachability probe.
        if os.environ.get("KERDOOS_IMAGE_NETWORK_NONE") != "1":
            self.skipTest(
                "KERDOOS_IMAGE_NETWORK_NONE=1 not set -- rerun the image "
                "with --network none and this env var (see AGENTS.md) to "
                "exercise this proof")
        self.assertFalse(
            _network_is_reachable(),
            "KERDOOS_IMAGE_NETWORK_NONE=1 was set but the network is "
            "reachable -- the container was not actually started with "
            "--network none")
        old_home = os.environ.get("HOME")
        # TemporaryDirectory (stdlib-owned cleanup) rather than a
        # hand-authored delete of the empty-HOME probe directory.
        with tempfile.TemporaryDirectory(prefix="kerdoos-empty-home-") as tmp_home:
            os.environ["HOME"] = tmp_home
            try:
                fetcher = camoufox.CamoufoxFetcher(
                    _NEUTRAL_POLICY, launch_timeout_seconds=5,
                    nav_timeout_seconds=5, fetch_timeout_seconds=10)
                with self.assertRaises(Exception):
                    fetcher.fetch("https://example.com/")
                created = os.listdir(tmp_home)
                self.assertEqual(
                    created, [],
                    f"a directory was created under an empty HOME with no "
                    f"network: {created}")
            finally:
                if old_home is not None:
                    os.environ["HOME"] = old_home
                else:
                    os.environ.pop("HOME", None)


class CamoufoxProcessHardeningTest(_ImageGatedCase):
    def setUp(self) -> None:
        super().setUp()
        if os.name != "posix":
            self.skipTest("needs /proc (POSIX)")

    @staticmethod
    def _read_status_field(pid: int, field: str):
        try:
            text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8",
                                                          errors="replace")
        except OSError:
            return None
        for line in text.splitlines():
            if line.startswith(field + ":"):
                return line.split(":", 1)[1].strip()
        return None

    @pytest.mark.xfail(
        strict=True,
        reason="card 371ecc59: autonomous runs the browser as root, which "
        "disables Firefox's own content sandbox entirely -- MEASURED "
        "2026-09-14 on kerdoos-t4:6835df6, zero -contentproc process "
        "carries an active Seccomp filter. Remove this xfail the day "
        "371ecc59 lands (this test flips to a real pass, strict=True "
        "turns an unexpected pass into a failure so it cannot go unnoticed)")
    def test_content_process_sandbox_is_active(self) -> None:
        """uid=0 for the autonomous image is a KNOWN, separately tracked
        gap (card 371ecc59, non-root hardening covering /data + compose +
        this sandbox together) -- not re-asserted here. Firefox's content
        sandbox (seccomp-bpf) applies to its `-contentproc` CHILDREN, not
        the parent browser process -- an earlier version of this test
        measured Seccomp on the parent by name match alone and always
        read 0, which proved nothing about the sandbox itself."""
        import psutil

        pids_before = camoufox._snapshot_descendant_pids()
        seen: dict = {}

        def _probe(page) -> None:  # noqa: ANN001
            page.evaluate("() => 1")
            me = psutil.Process(os.getpid())
            candidates: list = []
            deadline = time.monotonic() + 8.0
            while not candidates and time.monotonic() < deadline:
                for p in me.children(recursive=True):
                    if p.pid in pids_before:
                        continue
                    try:
                        cmdline = p.cmdline()
                    except psutil.Error:
                        continue
                    if any("-contentproc" in arg for arg in cmdline):
                        candidates.append(p.pid)
                time.sleep(0.2)
            seen["candidates"] = candidates

        _run_probe(_NEUTRAL_POLICY, _probe, nav_timeout_seconds=8,
                   fetch_timeout_seconds=20)

        candidates = seen.get("candidates", [])
        self.assertTrue(
            candidates,
            "no Firefox content process (-contentproc argv) was found "
            "while the browser was open")
        found_seccomp = False
        for pid in candidates:
            seccomp_line = self._read_status_field(pid, "Seccomp")
            if seccomp_line and seccomp_line.strip() not in ("", "0"):
                found_seccomp = True
        self.assertTrue(
            found_seccomp,
            "no Firefox -contentproc process had an active Seccomp "
            "filter (content sandbox)")


class CamoufoxBinaryProvenanceTest(_ImageGatedCase):
    def setUp(self) -> None:
        super().setUp()
        if not _network_is_reachable():
            self.skipTest(
                "no network reachable from the test harness -- this proof "
                "needs real egress to github.com, separate from the "
                "browser's own SSRF-pinned proxy")

    @staticmethod
    def _sha256_of_zip_member(data: bytes, member_name: str) -> str:
        import hashlib
        import io
        import zipfile

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            with zf.open(member_name) as fh:
                digest = hashlib.sha256()
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    digest.update(chunk)
                return digest.hexdigest()

    def test_installed_binary_matches_a_fresh_download_and_github_digest(
            self) -> None:
        import hashlib

        version = camoufox.CAMOUFOX_BROWSER_VERSION
        asset_name = f"camoufox-{version}-lin.x86_64.zip"
        asset_url = (
            "https://github.com/daijro/camoufox/releases/download/"
            f"v{version}/{asset_name}")

        with urlopen(asset_url, timeout=90) as resp:
            zip_bytes = resp.read()
        fresh_sha256 = self._sha256_of_zip_member(zip_bytes, "camoufox-bin")

        installed_digest = hashlib.sha256()
        with open(camoufox.CAMOUFOX_EXECUTABLE_PATH, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                installed_digest.update(chunk)
        installed_sha256 = installed_digest.hexdigest()

        self.assertEqual(
            fresh_sha256, installed_sha256,
            "the binary installed in the image does not match an "
            "independently re-downloaded and re-extracted copy of the "
            f"same pinned asset ({asset_url})")

        api_url = (
            "https://api.github.com/repos/daijro/camoufox/releases/tags/"
            f"v{version}")
        try:
            with urlopen(api_url, timeout=30) as resp:
                release = json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 -- best-effort cross-check
            self.skipTest(f"GitHub release API unreachable: {exc}")
        asset = next(
            (a for a in release.get("assets", [])
             if a.get("name") == asset_name), None)
        self.assertIsNotNone(
            asset, f"GitHub release v{version} has no asset {asset_name}")
        digest = asset.get("digest")
        zip_sha256 = hashlib.sha256(zip_bytes).hexdigest()
        if digest:
            self.assertEqual(
                digest, f"sha256:{zip_sha256}",
                "GitHub's published asset digest does not match the "
                "downloaded zip's own sha256")
        else:
            self.skipTest(
                "GitHub did not publish a digest for this asset (TOFU, "
                "matches the Dockerfile's own documented trust model)")
