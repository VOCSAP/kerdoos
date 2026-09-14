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
    """dials proves a target was DIALED; heads proves a target was
    CONSULTED at all, whether or not a dial followed -- a domain-refused
    or IP-refused request never reaches the dialer, so `dials` alone
    cannot distinguish "the proxy refused this" from "the proxy was never
    asked" (gate finding B4)."""

    dials: list[tuple[str, int]]
    heads: list[str]

    def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
        super().__init__(*args, **kwargs)
        self.dials = []
        self.heads = []
        self._dials_lock = threading.Lock()
        self._heads_lock = threading.Lock()
        real_dialer = self._dialer

        def _recording_dial(ip: str, port: int) -> socket.socket:
            with self._dials_lock:
                self.dials.append((ip, port))
            return real_dialer(ip, port)

        self._dialer = _recording_dial

    def _read_head(self, sock: socket.socket) -> tuple[bytes, bytes]:  # type: ignore[override]
        head, leftover = super()._read_head(sock)
        if head:
            request_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            method_and_authority = " ".join(request_line.split()[:2])
            with self._heads_lock:
                self.heads.append(method_and_authority)
        return head, leftover


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
            proxy.heads, ["CONNECT example.com:443"],
            f"expected the CONNECT to actually reach the proxy (proving "
            f"the domain check passed), got {proxy.heads}")
        self.assertEqual(
            proxy.dials, [],
            f"the proxy dialed {proxy.dials} despite the pin resolving to "
            "a non-global address")


class _NoTrafficDialPinningProxy(_RecordingPinningProxy):
    """Records dials and heads like its parent, but the dial itself
    returns one end of a local socketpair -- no byte ever reaches the
    real target -- so the positive path (domain allowed, resolved,
    pinned, dialed) can be proven with a real Firefox fetch without
    actually contacting a live IP."""

    def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
        super().__init__(*args, **kwargs)
        self._pairs: list[tuple[socket.socket, socket.socket]] = []

        def _no_traffic_dial(ip: str, port: int) -> socket.socket:
            with self._dials_lock:
                self.dials.append((ip, port))
            a, b = socket.socketpair()
            self._pairs.append((a, b))
            return a

        self._dialer = _no_traffic_dial


class CamoufoxPositivePinPathTest(_ImageGatedCase):
    """Gate finding F6: proofs 1 and 3 both stop at ip_is_safe refusing a
    non-global pin -- neither exercises the path where the domain IS
    allowed, resolution succeeds, and a dial actually happens. Proves
    "resolve once and pin" concretely: getaddrinfo answers 104.18.0.1 on
    its FIRST call and 127.0.0.1 (a rebind) on any later call, and the
    real dial is still to the FIRST answer -- a re-resolution bug would
    show up as a dial to 127.0.0.1 instead."""

    def test_domain_allowed_resolves_pins_and_dials_the_first_answer(
            self) -> None:
        real_getaddrinfo = socket.getaddrinfo
        call_count = {"n": 0}

        def _fake_getaddrinfo(host, *args, **kwargs):  # noqa: ANN001, ANN002
            if host == "example.com":
                call_count["n"] += 1
                ip = "104.18.0.1" if call_count["n"] == 1 else "127.0.0.1"
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]
            return real_getaddrinfo(host, *args, **kwargs)

        def _probe(page) -> None:  # noqa: ANN001
            # Bounded independently of the proxy/browser's own timeouts:
            # the socketpair end is never read, so an unbounded fetch
            # would hang until Firefox's own navigation ceiling instead.
            page.evaluate(
                "() => { const c = new AbortController();"
                " setTimeout(() => c.abort(), 3000);"
                " return fetch('https://example.com/', "
                "{mode: 'no-cors', signal: c.signal})"
                ".then(() => 'ok').catch(e => 'threw:' + e.message); }")

        import unittest.mock as mock
        # validate_target neutralized: otherwise ITS OWN resolution
        # consumes the mock's first (104.18.0.1) answer before the proxy
        # ever resolves anything, leaving the proxy to see the rebind
        # answer on what would then be ITS first call -- confounding the
        # very "resolve once" property this test measures.
        with mock.patch.object(socket, "getaddrinfo", side_effect=_fake_getaddrinfo):
            proxy = _run_probe(
                _NEUTRAL_POLICY, _probe,
                proxy_cls=_NoTrafficDialPinningProxy,
                neutralize_validate_target=True,
                nav_timeout_seconds=8, fetch_timeout_seconds=15)
        self.assertEqual(
            proxy.heads, ["CONNECT example.com:443"],
            f"expected exactly one CONNECT for the allowed domain, got "
            f"{proxy.heads}")
        self.assertEqual(
            proxy.dials, [("104.18.0.1", 443)],
            f"expected a single dial to the FIRST resolved IP, got "
            f"{proxy.dials} -- a dial to 127.0.0.1 would mean the proxy "
            "re-resolved instead of pinning its first answer")


def _run_traced(script: str, timeout: float) -> tuple[str, str]:
    # A TemporaryDirectory context manager (stdlib-owned cleanup) rather
    # than a hand-authored delete, on purpose.
    with tempfile.TemporaryDirectory(prefix="kerdoos-strace-") as tmp_dir:
        script_path = Path(tmp_dir) / "probe.py"
        log_path = Path(tmp_dir) / "trace.log"
        script_path.write_text(script, encoding="utf-8")
        proc = subprocess.run(
            [_STRACE, "-f", "-qq", "-e",
             "trace=execve,clone,clone3,fork,vfork,network",
             "-o", str(log_path), sys.executable, str(script_path)],
            capture_output=True, text=True, timeout=timeout)
        log_text = log_path.read_text(encoding="utf-8", errors="replace")
        return proc.stdout + proc.stderr, log_text


# strace 6.13 (MEASURED, gate finding): IPv4 is sin_addr=inet_addr("x"),
# never the bare quoted form the previous regex assumed -- that bug made
# the destination set silently empty for ANY IPv4 connection. Scans
# connect/sendto/sendmsg/sendmmsg uniformly (a UDP resolver often issues
# sendmmsg with no separate connect()) rather than connect() alone.
_EGRESS_SYSCALL_RE = re.compile(r'\b(?:connect|sendto|sendmsg|sendmmsg)\(')
# IPv6 form MEASURED via diag_ipv6.py on this same strace 6.13: the real
# line is `inet_pton(AF_INET6, "x", &sin6_addr)`, with NO "sin6_addr="
# prefix before the call -- the earlier assumed form never matched either.
_ADDR_RE = re.compile(
    r'sin_addr=inet_addr\("([0-9.]+)"\)'
    r'|inet_pton\(AF_INET6,\s*"([0-9a-fA-F:]+)"')
# Not anchored to sendto/sendmsg/sendmmsg alone: glibc's stub resolver can
# issue connect() on a UDP socket then plain send() (no destination
# argument on that line at all), so port 53 evidence often sits on the
# connect() line instead.
_PORT53_RE = re.compile(r'sin_port=htons\(53\)')
# MEASURED (re-gate 3, diag_test1_repro.py): glibc's getaddrinfo runs RFC
# 6724 source-address selection, which queries the kernel's routing table
# over an AF_NETLINK socket (RTM_GETROUTE) for each DNS candidate -- that
# sendmsg() carries the candidate address as NESTED ATTRIBUTE PAYLOAD, not
# as the socket's own destination, and never sends a single byte over the
# network. Without this exclusion, this pure local IPC was being counted
# as real egress to whatever IP the OS happened to consider routing to.
_AF_NETLINK_RE = re.compile(r'\bAF_NETLINK\b')


def _non_loopback_egress_ips(log_text: str) -> set[str]:
    ips: set[str] = set()
    for line in log_text.splitlines():
        if not _EGRESS_SYSCALL_RE.search(line) or _AF_NETLINK_RE.search(line):
            continue
        for match in _ADDR_RE.finditer(line):
            raw = match.group(1) or match.group(2)
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if not addr.is_loopback:
                ips.add(raw)
    return ips


# MEASURED (diag_baseline_strace.py, this gate-fix pass): a genuine
# connect() to example.com's real resolved IP shows up on the traced
# python3 PID itself, not on camoufox-bin -- because PinningProxy runs
# IN-PROCESS (a thread of the SAME python process, not inside Firefox) and
# its _dialer legitimately dials the resolved target on every accepted
# CONNECT. That dial is the intended mechanism, not a leak; the actual
# "did Firefox fall back to a direct connection" question can only be
# answered by attributing egress to Firefox's OWN process tree.
_EXECVE_RE = re.compile(r'^(\d+)\s+execve\("([^"]+)"', re.MULTILINE)
# strace -f attributes syscalls by TID, and CLONE_THREAD children (e.g.
# Firefox's own Socket Thread, which does the actual network I/O) get a
# TID distinct from the PID that execve'd camoufox-bin, even though
# ps/getpid() would call it "the same process" (gate finding, re-gate 2).
# MEASURED (diag_kill.py under -e trace=clone,clone3,fork,vfork): each
# spawn syscall ends the line with "= <child pid/tid>", the same shape for
# clone(), the (unsupported here) clone3() attempt, fork() and vfork().
_SPAWN_RE = re.compile(
    r'^(\d+)\s+(?:clone3?|v?fork)\(.*=\s*(\d+)\s*$', re.MULTILINE)


def _firefox_pids(log_text: str) -> set[str]:
    return {
        m.group(1) for m in _EXECVE_RE.finditer(log_text)
        if m.group(2) == "/opt/camoufox/camoufox-bin"
    }


def _firefox_process_tree_ids(log_text: str) -> set[str]:
    """Every PID/TID descending from a camoufox-bin execve, transitively
    through clone/clone3/fork/vfork -- covers Firefox's own threads (the
    Socket Thread among them), not just the PIDs that themselves execve'd
    the binary."""
    seeds = _firefox_pids(log_text)
    if not seeds:
        return set()
    children: dict[str, list[str]] = {}
    for m in _SPAWN_RE.finditer(log_text):
        children.setdefault(m.group(1), []).append(m.group(2))
    tree = set(seeds)
    frontier = list(seeds)
    while frontier:
        pid = frontier.pop()
        for child in children.get(pid, []):
            if child not in tree:
                tree.add(child)
                frontier.append(child)
    return tree


def _has_any_egress_for_pids(log_text: str, pids: set[str]) -> bool:
    for line in log_text.splitlines():
        pid_match = re.match(r'^(\d+)\s', line)
        if pid_match and pid_match.group(1) in pids \
                and _EGRESS_SYSCALL_RE.search(line) \
                and not _AF_NETLINK_RE.search(line):
            return True
    return False


def _non_loopback_egress_ips_for_pids(log_text: str, pids: set[str]) -> set[str]:
    ips: set[str] = set()
    for line in log_text.splitlines():
        pid_match = re.match(r'^(\d+)\s', line)
        if not pid_match or pid_match.group(1) not in pids:
            continue
        if not _EGRESS_SYSCALL_RE.search(line) or _AF_NETLINK_RE.search(line):
            continue
        for match in _ADDR_RE.finditer(line):
            raw = match.group(1) or match.group(2)
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if not addr.is_loopback:
                ips.add(raw)
    return ips


# Positive control for every strace-based proof below: deliberate,
# clearly-artificial connect()s the traced child always makes, so a test
# can tell "the instrument saw nothing" from "there was nothing to see" --
# TEST-NET-3 (IPv4) and 2001:db8::/32 (IPv6 documentation range), distinct
# from the 192.0.2.1 (TEST-NET-1) pin used elsewhere so none are confused
# in the parsed destination set. Both address families are controlled for
# separately: the IPv4 and IPv6 extraction paths in _ADDR_RE are two
# independent regex alternatives that can (and did) break independently.
_STRACE_CONTROL_IP = "203.0.113.77"
_STRACE_CONTROL_IPV6 = "2001:db8::77"
_STRACE_POSITIVE_CONTROL = (
    "import socket as _ctrl_socket\n"
    "_ctrl = _ctrl_socket.socket(_ctrl_socket.AF_INET, _ctrl_socket.SOCK_STREAM)\n"
    "_ctrl.settimeout(0.2)\n"
    "try:\n"
    f"    _ctrl.connect(('{_STRACE_CONTROL_IP}', 443))\n"
    "except OSError:\n"
    "    pass\n"
    "finally:\n"
    "    _ctrl.close()\n"
    "_ctrl6 = _ctrl_socket.socket(_ctrl_socket.AF_INET6, _ctrl_socket.SOCK_STREAM)\n"
    "_ctrl6.settimeout(0.2)\n"
    "try:\n"
    f"    _ctrl6.connect(('{_STRACE_CONTROL_IPV6}', 443))\n"
    "except OSError:\n"
    "    pass\n"
    "finally:\n"
    "    _ctrl6.close()\n"
)


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
        script = _STRACE_POSITIVE_CONTROL + (
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
        all_ips = _non_loopback_egress_ips(log_text)
        self.assertIn(
            _STRACE_CONTROL_IP, all_ips,
            "positive control failed -- the instrument never saw the "
            "deliberate IPv4 connect() to the control address, so a zero "
            "elsewhere is not trustworthy")
        self.assertIn(
            _STRACE_CONTROL_IPV6, all_ips,
            "positive control failed -- the instrument never saw the "
            "deliberate IPv6 connect() to the control address")
        destinations = all_ips - {_STRACE_CONTROL_IP, _STRACE_CONTROL_IPV6}
        self.assertEqual(
            destinations, set(),
            f"a non-loopback egress was observed beyond the positive "
            f"control: {destinations}, expected zero (the pin is refused "
            "before any dial)")

    def test_disallowed_host_produces_zero_network_syscalls(self) -> None:
        script = _STRACE_POSITIVE_CONTROL + (
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
        all_ips = _non_loopback_egress_ips(log_text)
        self.assertIn(
            _STRACE_CONTROL_IP, all_ips,
            "positive control failed -- the instrument never saw the "
            "deliberate IPv4 connect() to the control address")
        self.assertIn(
            _STRACE_CONTROL_IPV6, all_ips,
            "positive control failed -- the instrument never saw the "
            "deliberate IPv6 connect() to the control address")
        destinations = all_ips - {_STRACE_CONTROL_IP, _STRACE_CONTROL_IPV6}
        self.assertEqual(
            destinations, set(),
            f"expected zero egress beyond the positive control, saw: "
            f"{destinations}")
        self.assertIsNone(
            _PORT53_RE.search(
                log_text.replace(_STRACE_CONTROL_IP, "")),
            "a DNS-shaped port-53 reference was observed")

    def test_proxy_killed_mid_fetch_never_falls_back_to_direct(self) -> None:
        script = _STRACE_POSITIVE_CONTROL + (
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
            # strace -f measurably slows Firefox's own syscalls; timeouts
            # here are wider than a plain (untraced) fetch needs so a
            # strace-slowed but otherwise NORMAL page load never races the
            # outer abandonment ceiling instead of the deliberate kill.
            "fetcher = cfx.CamoufoxFetcher(DomainPolicy(frozenset({'example.com'})),\n"
            "                              nav_timeout_seconds=25, fetch_timeout_seconds=40)\n"
            "try:\n"
            "    fetcher.fetch('https://example.com/')\n"
            "    print('RESULT:ok')\n"
            "except FetchError as exc:\n"
            "    print('RESULT:FetchError:' + str(exc))\n"
            "except Exception as exc:\n"
            "    print('RESULT:other:' + type(exc).__name__ + ':' + str(exc))\n"
        )
        stdout, log_text = _run_traced(script, timeout=90.0)
        self.assertIn("RESULT:FetchError", stdout, stdout)
        self.assertNotIn(
            "exceeded", stdout,
            f"the fetch hit its own outer abandonment ceiling instead of "
            f"the deliberate kill -- inconclusive, not a pass: {stdout}")
        # PinningProxy runs IN-PROCESS (a thread of this same traced
        # python, not inside Firefox) and legitimately dials example.com's
        # real resolved IP for every accepted CONNECT -- MEASURED that
        # this shows up attributed to the python PID itself, which is the
        # intended mechanism, not a leak. "Never falls back to direct"
        # is a claim about FIREFOX'S OWN process tree, so egress is
        # attributed by execve path, not scanned across the whole trace.
        all_ips = _non_loopback_egress_ips(log_text)
        self.assertIn(
            _STRACE_CONTROL_IP, all_ips,
            "positive control failed -- the instrument never saw the "
            "deliberate IPv4 connect() to the control address")
        self.assertIn(
            _STRACE_CONTROL_IPV6, all_ips,
            "positive control failed -- the instrument never saw the "
            "deliberate IPv6 connect() to the control address")
        # execve alone only names the PID that ran camoufox-bin, missing
        # its OWN cloned threads (Firefox's Socket Thread, which does the
        # real network I/O, gets a distinct TID via CLONE_THREAD) -- the
        # transitive clone/fork tree is what "Firefox's own process tree"
        # actually means.
        firefox_pids = _firefox_process_tree_ids(log_text)
        self.assertTrue(
            firefox_pids,
            "no camoufox-bin process was ever launched (execve not "
            "observed) -- cannot attribute egress to Firefox at all")
        # Positive control for the ATTRIBUTED set itself: Firefox is
        # configured to use the loopback proxy for everything, so it MUST
        # make at least one connect() attributed to this exact PID/TID
        # set (to the proxy's own loopback port) -- if none shows up, the
        # attribution mechanism is blind, not the fetch actually silent.
        self.assertTrue(
            _has_any_egress_for_pids(log_text, firefox_pids),
            "no network syscall at all was attributed to Firefox's own "
            "process tree -- the PID/TID attribution is not capturing "
            "real Firefox activity, so the zero below proves nothing")
        firefox_egress = _non_loopback_egress_ips_for_pids(log_text, firefox_pids)
        self.assertEqual(
            firefox_egress, set(),
            f"the Firefox process itself made a non-loopback connection "
            f"after the proxy died: {firefox_egress}")


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
        # dials==[] alone cannot distinguish "the proxy refused this" from
        # "the proxy was never even asked" (e.g. a direct DNS failure
        # bypassing the proxy entirely) -- heads proves the CONNECT for
        # this exact authority actually reached _handle.
        self.assertTrue(
            any("CONNECT rebind.example.com:443" in h for h in proxy.heads),
            f"the proxy never received a CONNECT for rebind.example.com, "
            f"heads were {proxy.heads} -- 'refused' cannot be told from "
            f"'never consulted'")
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
# tag embedded in page.set_content()'s HTML never runs on this build. All
# targets are https:// since PinningProxy._handle only parses CONNECT --
# a plain http:// proxied GET bypasses the domain/IP checks entirely.
# Attempts are reported via console.log, captured by a page-level
# listener attached in Python BEFORE this runs (MEASURED: form.submit()
# to a same-tick-created named iframe target, and window.open(), can
# still navigate the TOP-level context on this build, destroying the
# execution context page.evaluate() needs to return its value -- a
# page-level console listener survives that, a JS return value does not).
# No UDP stimulus: RTCPeerConnection/WebTransport are undefined on this
# build, so no JS API can open a raw UDP channel at all -- the UDP
# listener below was REMOVED rather than kept as a permanently-untested
# zero (gate finding F7).
_HOSTILE_PROBE_JS = """
async () => {
  const t80 = 'https://127.0.0.1:80/';
  const t443 = 'https://127.0.0.1:443/';
  const t8765 = 'https://127.0.0.1:8765/';
  const t8766 = 'https://127.0.0.1:8766/';
  const t8765v6 = 'https://[::1]:8765/';
  const attempts = [];
  const channels = [
    ['img', () => new Promise(r => {
      const i = new Image(); i.onerror = i.onload = () => r();
      i.src = t80 + '?c=img'; setTimeout(r, 1500);
    })],
    ['fetch', () => fetch(t443, {mode: 'no-cors'}).catch(() => {})],
    ['sendBeacon', () => Promise.resolve().then(() =>
      navigator.sendBeacon(t8765, 'x'))],
    ['websocket', () => new Promise(r => {
      const ws = new WebSocket('wss://127.0.0.1:8766/');
      ws.onerror = ws.onclose = () => r();
      setTimeout(r, 1500);
    })],
    ['eventsource', () => new Promise(r => {
      const es = new EventSource(t8765v6);
      es.onerror = () => { es.close(); r(); };
      setTimeout(() => { es.close(); r(); }, 1500);
    })],
    ['iframe', () => new Promise(r => {
      const f = document.createElement('iframe');
      f.src = t80 + '?c=iframe';
      f.onload = f.onerror = () => r();
      document.body.appendChild(f);
      setTimeout(r, 1500);
    })],
    ['link-hints', () => {
      ['preconnect', 'dns-prefetch', 'prefetch', 'preload'].forEach(rel => {
        const l = document.createElement('link');
        l.rel = rel; l.href = t443;
        if (rel === 'preload') l.as = 'fetch';
        document.head.appendChild(l);
      });
      return Promise.resolve();
    }],
    ['form', () => new Promise(r => {
      const tgt = document.createElement('iframe');
      tgt.name = 'formtgt'; tgt.style.display = 'none';
      document.body.appendChild(tgt);
      const form = document.createElement('form');
      form.action = t8766; form.method = 'POST'; form.target = 'formtgt';
      document.body.appendChild(form);
      form.submit();
      setTimeout(r, 1000);
    })],
    ['window-open', () => new Promise(r => {
      const w = window.open(t80 + '?c=open', '_blank', 'noopener,noreferrer');
      setTimeout(() => { try { w && w.close(); } catch (e) {} r(); }, 1000);
    })],
    ['a-ping', () => new Promise(r => {
      const a = document.createElement('a');
      a.href = t8765; a.ping = t8766; a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      setTimeout(r, 1000);
    })],
    ['fetch-keepalive', () =>
      fetch(t443, {mode: 'no-cors', keepalive: true}).catch(() => {})],
    ['css-url', () => new Promise(r => {
      const style = document.createElement('style');
      style.textContent = '.kerdoos-probe { background: url(' +
        t8765 + '?c=css); }';
      document.head.appendChild(style);
      const div = document.createElement('div');
      div.className = 'kerdoos-probe';
      document.body.appendChild(div);
      setTimeout(r, 1000);
    })],
  ];
  for (const [name, start] of channels) {
    try {
      console.log('KERDOOS_ATTEMPT:' + name);
      attempts.push(start());
    } catch (e) {
      console.log('KERDOOS_ATTEMPT:' + name + ':ctor-threw:' + e.message);
    }
  }
  await Promise.race([
    Promise.allSettled(attempts),
    new Promise(r => setTimeout(r, 4000)),
  ]);
  await new Promise(r => setTimeout(r, 1500));
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
            # No UDP listener (gate finding F7): RTCPeerConnection and
            # WebTransport are both undefined on this build, so no JS API
            # exists that could ever drive a stimulus toward one -- kept
            # would have been a permanently-untested zero.
        ]
        seen: dict = {"attempted": []}
        try:
            def _probe(page) -> None:  # noqa: ANN001
                page.on("console", lambda msg: seen["attempted"].append(
                    msg.text[len("KERDOOS_ATTEMPT:"):])
                    if msg.text.startswith("KERDOOS_ATTEMPT:") else None)
                page.set_content("<html><body></body></html>")
                try:
                    page.evaluate(_HOSTILE_PROBE_JS)
                except Exception as exc:  # noqa: BLE001 -- e.g. a stray
                    # navigation destroying the execution context; the
                    # console listener already captured every attempt
                    # logged before that point, independent of whether
                    # evaluate() itself survived to return.
                    seen["evaluate_error"] = str(exc)

            proxy = _run_probe(_NEUTRAL_POLICY, _probe, nav_timeout_seconds=8,
                               fetch_timeout_seconds=30)

            _EXPECTED_CHANNELS = {
                "img", "fetch", "sendBeacon", "websocket", "eventsource",
                "iframe", "link-hints", "form", "window-open", "a-ping",
                "fetch-keepalive", "css-url",
            }
            attempted = {name.split(":ctor-threw:")[0]
                         for name in seen["attempted"]}
            self.assertEqual(
                attempted, _EXPECTED_CHANNELS,
                f"the hostile page did not actually attempt every "
                f"channel, only {attempted} (evaluate_error="
                f"{seen.get('evaluate_error')!r}) -- a zero-hit "
                "measurement means nothing for a channel that never fired")

            # heads proves the CONNECTs actually reached the proxy (and
            # were refused there), not that the browser silently never
            # tried -- zero hits on the listener alone does not carry
            # that distinction on its own.
            _EXPECTED_HEADS = {
                "CONNECT 127.0.0.1:80", "CONNECT 127.0.0.1:443",
                "CONNECT 127.0.0.1:8765", "CONNECT 127.0.0.1:8766",
                "CONNECT [::1]:8765",
            }
            missing_heads = _EXPECTED_HEADS - set(proxy.heads)
            self.assertFalse(
                missing_heads,
                f"expected CONNECTs never reached the proxy: "
                f"{missing_heads}, got heads={proxy.heads}")

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


# Driven SEQUENTIALLY, one target at a time (gate finding F7): running
# these alongside the 12-channel hostile page above MEASURABLY starved
# them of a connection within the test's time budget (Firefox's own
# per-destination connection-pool limits), which read as "never reached
# the proxy" for a reason unrelated to any security control -- confirmed
# by the SAME fetches succeeding in isolation (diag_isolated_localhost_
# via_runprobe.py). A dedicated, uncontended probe is what actually
# measures the refusal.
_SPECIAL_TARGETS_PROBE_JS = """
async () => {
  const targets = [
    ['localhost-fetch', 'https://localhost:8765/'],
    ['x-localhost-fetch', 'https://x.localhost:8766/'],
    ['zero-addr-fetch', 'https://0.0.0.0/'],
    ['v4-mapped-fetch', 'https://[::ffff:127.0.0.1]:8765/'],
    ['private-ip-fetch', 'https://10.0.0.5/'],
    ['metadata-ip-fetch', 'https://169.254.169.254/'],
  ];
  for (const [name, url] of targets) {
    console.log('KERDOOS_ATTEMPT:' + name);
    await Promise.race([
      fetch(url, {mode: 'no-cors'}).catch(() => {}),
      new Promise(r => setTimeout(r, 2500)),
    ]);
  }
  return 'done';
}
"""


class CamoufoxSpecialAddressTargetsTest(_ImageGatedCase):
    """ADR T4-1 (localhost/x.localhost) and T4-10 (private/metadata IPs,
    0.0.0.0, an IPv4-mapped IPv6 loopback literal) as channel DESTINATIONS
    -- distinct from CamoufoxAntiRebindingTest (a hostname that RESOLVES
    to a bad IP) and CamoufoxLoopbackChannelsTest's plain 127.0.0.1/[::1]
    targets. localhost/x.localhost are hostname-shaped and reach the
    domain check; the four literal IPs are refused earlier, by
    _is_hostname_shaped, before any domain/IP-safety check runs."""

    def test_special_address_targets_are_refused(self) -> None:
        counter = _HitCounter()
        listeners = [
            _Listener(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1", 8765, counter),
            _Listener(socket.AF_INET, socket.SOCK_STREAM, "127.0.0.1", 8766, counter),
        ]
        seen: dict = {"attempted": []}
        try:
            def _probe(page) -> None:  # noqa: ANN001
                page.on("console", lambda msg: seen["attempted"].append(
                    msg.text[len("KERDOOS_ATTEMPT:"):])
                    if msg.text.startswith("KERDOOS_ATTEMPT:") else None)
                page.set_content("<html><body></body></html>")
                page.evaluate(_SPECIAL_TARGETS_PROBE_JS)

            proxy = _run_probe(_NEUTRAL_POLICY, _probe, nav_timeout_seconds=20,
                               fetch_timeout_seconds=30)

            _EXPECTED_TARGETS = {
                "localhost-fetch", "x-localhost-fetch", "zero-addr-fetch",
                "v4-mapped-fetch", "private-ip-fetch", "metadata-ip-fetch",
            }
            self.assertEqual(
                set(seen["attempted"]), _EXPECTED_TARGETS,
                f"not every special-address target was actually "
                f"attempted, only {seen['attempted']}")

            _EXPECTED_HEADS = {
                "CONNECT localhost:8765", "CONNECT x.localhost:8766",
                # Firefox canonicalizes the IPv4-mapped literal to pure
                # hex (127.0.0.1 = 0x7f000001) before issuing the CONNECT
                # -- MEASURED, not the dotted form the URL was written in.
                "CONNECT 0.0.0.0:443", "CONNECT [::ffff:7f00:1]:8765",
                "CONNECT 10.0.0.5:443", "CONNECT 169.254.169.254:443",
            }
            missing_heads = _EXPECTED_HEADS - set(proxy.heads)
            self.assertFalse(
                missing_heads,
                f"expected CONNECTs never reached the proxy: "
                f"{missing_heads}, got heads={proxy.heads}")

            self.assertEqual(
                counter.count, 0,
                "a special-address target reached a real loopback listener")

            for listener in listeners:
                listener.probe_from_python()
            deadline = time.monotonic() + 5.0
            while counter.count < len(listeners) and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertEqual(
                counter.count, len(listeners),
                "positive control failed -- some listeners never "
                "registered a hit even from a direct Python connection")
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
    """Gate finding B4: the previous version used a literal IP
    (127.0.0.1:9999, refused by _is_hostname_shaped before any dial --
    dials can NEVER contain a literal-IP authority regardless of allow or
    deny), a default-mode fetch() inside the Worker (CORS rejection and a
    proxy refusal are indistinguishable as a plain "threw"), and no
    listener behind the disallowed target (its own zero is not
    attributable to the proxy). Fixed: a real hostname outside the
    policy, no-cors throughout, and the domain-refused WARNING plus
    proxy.heads prove the proxy was actually consulted and refused it,
    rather than merely never being reached."""

    _POLICY = DomainPolicy(frozenset({"example.com"}))

    def test_worker_and_websocket_reach_the_proxy_only_for_the_allowed_host(
            self) -> None:
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
                "        'fetch(\\'https://disallowed.example.net/\\', '"
                "        + '{mode: \\'no-cors\\'}).then(',"
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

        with self.assertLogs("autolycos.egress_proxy", level="WARNING") as logs:
            proxy = _run_probe(self._POLICY, _probe, nav_timeout_seconds=8,
                                fetch_timeout_seconds=20)
        outcomes = result["outcomes"]

        self.assertTrue(
            any("CONNECT example.com:443" in h for h in proxy.heads),
            f"the proxy never received the allowed WebSocket's CONNECT, "
            f"heads were {proxy.heads}")
        allowed_dials = [d for d in proxy.dials]
        self.assertTrue(
            allowed_dials,
            f"no dial was ever attempted for the allowed host, only "
            f"{proxy.dials}")

        self.assertTrue(
            any("disallowed.example.net" in r.getMessage()
                for r in logs.records),
            "the proxy never logged a domain refusal for the Worker's "
            "target -- 'refused' cannot be told from 'never consulted'")
        self.assertNotIn(
            "resolved", outcomes["worker_disallowed"],
            f"a Worker reached the disallowed host: {outcomes}")


def _network_is_reachable() -> bool:
    try:
        with socket.create_connection(("1.1.1.1", 53), timeout=1.5):
            return True
    except OSError:
        return False


class CamoufoxNoNetworkZeroDownloadTest(_ImageGatedCase):
    """Gate finding B2: the previous version set os.environ["HOME"] on the
    ALREADY-RUNNING test process -- too late, the camoufox package's own
    pkgman module freezes its install directory from $HOME at IMPORT time
    (possibly already imported by an earlier test in the same process),
    and validate_target resolves the primary host and raises before any
    launch is even attempted under a real --network none (swallowed by a
    bare assertRaises(Exception), measured 1 passed in 0.23s with zero
    real exec). Fixed: HOME is set on a FRESH subprocess's environment
    before the interpreter starts, validate_target is neutralized the
    same way the in-process probes do it, and the proof requires a
    page.evaluate() result as evidence Firefox actually ran."""

    def test_launch_needs_zero_network_download(self) -> None:
        # A test cannot drop its OWN container's network from inside
        # itself -- KERDOOS_IMAGE_NETWORK_NONE=1 is the caller's explicit
        # promise that this process was launched under --network none
        # (see AGENTS.md). Present: hard-fail if that promise is false.
        # Absent: skip explicitly, never infer network state from a probe.
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

        script = (
            "import requests\n"
            "def _spy_get(*a, **k):\n"
            "    raise AssertionError('requests.get called: ' + str(a))\n"
            "requests.get = _spy_get\n"
            "from autolycos.adapters import camoufox as cfx\n"
            "from autolycos.safety import DomainPolicy\n"
            "from autolycos.errors import FetchError\n"
            "cfx.validate_target = lambda *a, **k: None\n"
            "class _ProbeFetcher(cfx.CamoufoxFetcher):\n"
            "    def _render(self, browser, url):\n"
            "        context = browser.new_context()\n"
            "        page = context.new_page()\n"
            "        result = page.evaluate('() => 1 + 1')\n"
            "        context.close()\n"
            "        raise FetchError('PROBE_OK:' + str(result))\n"
            "fetcher = _ProbeFetcher(DomainPolicy(frozenset({'example.com'})),\n"
            "                        launch_timeout_seconds=8,\n"
            "                        nav_timeout_seconds=8, fetch_timeout_seconds=15)\n"
            "try:\n"
            "    fetcher.fetch('https://example.com/')\n"
            "    print('RESULT:unexpectedly_returned_normally')\n"
            "except FetchError as exc:\n"
            "    print('RESULT:' + str(exc))\n"
            "except Exception as exc:\n"
            "    print('RESULT:other:' + type(exc).__name__ + ':' + str(exc))\n"
        )
        with tempfile.TemporaryDirectory(prefix="kerdoos-empty-home-") as tmp_home:
            with tempfile.TemporaryDirectory(prefix="kerdoos-net-none-script-") as tmp_dir:
                script_path = Path(tmp_dir) / "probe.py"
                script_path.write_text(script, encoding="utf-8")
                env = os.environ.copy()
                env["HOME"] = tmp_home
                proc = subprocess.run(
                    [sys.executable, str(script_path)],
                    capture_output=True, text=True, timeout=30, env=env)
                stdout = proc.stdout + proc.stderr
            self.assertIn(
                "RESULT:PROBE_OK:2", stdout,
                f"Firefox did not actually launch and evaluate JS under "
                f"--network none: {stdout}")
            # camoufox's own adapter docstring documents that a launch
            # ALWAYS writes ~/.camoufox and ~/.cache/camoufox/fontconfig
            # regardless of network -- routine profile/cache setup, not a
            # download. The requests.get spy above (raises loudly if
            # invoked) is what actually proves zero network download; a
            # populated HOME after a successful launch under --network
            # none is expected, not a red flag.
            self.assertNotIn(
                "RESULT:other:AssertionError", stdout,
                f"requests.get was called during a launch under "
                f"--network none: {stdout}")


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

    def test_content_process_sandbox_is_active(self) -> None:
        """Gate finding B3: the previous version read /proc AFTER
        _run_probe returned, when the browser (and its -contentproc
        children) was already torn down -- guaranteed to read None/dead
        PIDs regardless of reality. MEASURED live, with a page still open
        (security-auditor, --runxfail): a -contentproc child carries MORE
        Seccomp filters than this Python process's own baseline (the
        Docker-imposed default filter both share), even running as root
        -- so this must be read from INSIDE the probe callback, before
        the context closes, and compared to a baseline, not to a bare
        nonzero Seccomp field (which Docker's own default filter would
        satisfy for any process, sandboxed or not)."""
        import psutil

        pids_before = camoufox._snapshot_descendant_pids()
        baseline_raw = self._read_status_field(os.getpid(), "Seccomp_filters")
        baseline = int(baseline_raw) if baseline_raw else 0
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
                    # -contentproc alone is not enough (re-gate finding):
                    # Firefox also launches "socket", "rdd", "forkserver"
                    # -contentproc processes with their OWN unrelated
                    # seccomp filter counts, which can mask a disabled
                    # CONTENT (web page) sandbox behind an any() match.
                    # MEASURED (diag_contentproc_argv.py): the actual web
                    # content process is the one whose LAST argv is "tab".
                    if cmdline and cmdline[-1] == "tab":
                        candidates.append(p.pid)
                time.sleep(0.2)
            # Read Seccomp_filters HERE, while the page (and its content
            # process) is still alive -- the parent test method's own
            # context has not closed yet at this point.
            seen["candidates"] = candidates
            seen["readings"] = [
                (pid, self._read_status_field(pid, "Seccomp_filters"))
                for pid in candidates
            ]

        _run_probe(_NEUTRAL_POLICY, _probe, nav_timeout_seconds=8,
                   fetch_timeout_seconds=20)

        candidates = seen.get("candidates", [])
        self.assertTrue(
            candidates,
            "no Firefox 'tab' content process was found while the "
            "browser was open")
        readings = seen.get("readings", [])
        found_sandboxed = any(
            filters is not None and int(filters) > baseline
            for _pid, filters in readings)
        self.assertTrue(
            found_sandboxed,
            f"no -contentproc process carried more Seccomp filters than "
            f"this test process's own baseline ({baseline}): {readings}")

    @pytest.mark.xfail(
        strict=True,
        reason="card 371ecc59: autonomous runs the browser as root -- "
        "MEASURED 2026-09-14 on kerdoos-t4:6835df6. Remove this xfail the "
        "day 371ecc59 lands (strict=True turns an unexpected pass into a "
        "failure so it cannot go unnoticed)")
    def test_content_process_runs_non_root(self) -> None:
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
            seen["readings"] = [
                (pid, self._read_status_field(pid, "Uid"))
                for pid in candidates
            ]

        _run_probe(_NEUTRAL_POLICY, _probe, nav_timeout_seconds=8,
                   fetch_timeout_seconds=20)

        readings = seen.get("readings", [])
        self.assertTrue(readings, "no Firefox content process was found")
        found_nonroot = any(
            uid_line and uid_line.split()[0] != "0"
            for _pid, uid_line in readings)
        self.assertTrue(
            found_nonroot,
            f"every content process ran as uid 0: {readings}")


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


class DockerfileDefaultTargetTest(unittest.TestCase):
    """Gate finding F5: appending a new stage at the end of the file makes
    it the implicit default for a flagless `docker build .` (buildx picks
    the LAST stage when none is named) -- runs on the host, needs no real
    Camoufox, so it is not gated by _ImageGatedCase."""

    _DOCKER = shutil.which("docker")

    def setUp(self) -> None:
        if self._DOCKER is None:
            self.skipTest("docker CLI not available")

    def test_default_target_is_not_the_strace_test_stage(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        proc = subprocess.run(
            [self._DOCKER, "buildx", "build", "--call=targets", str(repo_root)],
            capture_output=True, text=True, timeout=60)
        output = proc.stdout + proc.stderr
        default_line = next(
            (line for line in output.splitlines() if "(default)" in line),
            None)
        self.assertIsNotNone(
            default_line, f"no stage was annotated (default): {output}")
        self.assertNotIn(
            "autonomous-test", default_line,
            f"a flagless docker build would use the strace-enabled "
            f"TEST-only stage: {default_line}")
