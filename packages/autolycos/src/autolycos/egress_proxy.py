"""Loopback IP-pinning forward-proxy for locally-launched Chromium tiers.

ADR 0001 S9 (SSRF/egress). The browser tier's page.route sees URLs, not IPs,
so it cannot stop DNS rebinding: Chromium resolves the target host itself at
connect time, and an attacker can answer "public" to our up-front validation
and "169.254.169.254" to the browser. The old defence was a fragile launch
flag (--host-resolver-rules MAP <host> <ip>) whose rule ordering was
load-bearing and which caused real Magalu breakage (Kleos #11001, #10996).

This proxy is the real control. Chromium is pointed at it (launch proxy
config), so it never resolves the target itself: it asks us to CONNECT
host:port. We check the CONNECT authority's DOMAIN against the fetch's own
allowlist FIRST, before any resolution (ADR 0004 Decision 4 condition C1) --
this proxy is the ONLY point ALL of the browser's egress traffic passes
through (navigation, sub-resources, service workers, WebSockets, popups),
unlike a page-level route guard, which only sees requests Playwright's
page-routing API is told about. Once the domain passes, we run the IP-layer
egress rule (safety.resolve_and_pin: resolve once, reject any non-global IP
via ip_is_safe, pin one IP), dial the PINNED IP ourselves, and splice raw
bytes. TLS stays end-to-end (we tunnel ciphertext; Chromium verifies the
cert/SNI against the real host -- no MITM, so a stealth-mode browser's own
TLS fingerprint is preserved).

Hardening contract (gate, ADR 0001 S9; domain check added ADR 0004 D4/C1):
  * binds loopback-only (127.0.0.1) on an ephemeral port;
  * rejects any non-loopback client (defence in depth on top of the bind);
  * an optional per-instance domain_allowed predicate refuses a CONNECT
    authority outside the fetch's allowlist BEFORE any resolution;
  * restricts CONNECT target ports to 80/443 (no CONNECT to arbitrary ports);
  * resolve-once + pin closes the DNS-rebind TOCTOU at the network layer;
  * strip_dangerous_browser_args scrubs proxy/resolver/TLS-weakening launch
    flags (a caller must not be able to re-route or downgrade egress).

Synchronous by design (stdlib sockets + threads): the browser/uc fetchers are
synchronous (Playwright sync API, SeleniumBase), so each fetch spins up its
own ephemeral proxy as a context manager -- no shared state, no event-loop
bridge, and concurrent fetches each get an independent proxy on its own port.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
from collections.abc import Callable, Iterable

from .errors import FetchError, SSRFError
from .safety import resolve_and_pin

logger = logging.getLogger(__name__)

_CONNECT_OK = b"HTTP/1.1 200 Connection established\r\n\r\n"
_BLOCKED = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 11\r\n\r\nURL blocked"
_BAD = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request"

_ALLOWED_CONNECT_PORTS = frozenset({80, 443})
_MAX_HEADER_BYTES = 64 * 1024
_CONNECT_TIMEOUT = 30
_CHUNK = 64 * 1024

# Chromium launch flags that would re-route or weaken egress; scrubbed before
# launch so a caller cannot bypass the pinning proxy or disable TLS checks.
_DANGEROUS_BROWSER_ARGS = (
    "--proxy-server", "--proxy-pac-url", "--proxy-bypass-list",
    "--host-resolver-rules", "--ignore-certificate-errors",
    "--allow-insecure-localhost",
)

# Upstream dialer: (ip, port) -> connected socket. Injectable for tests.
Dialer = Callable[[str, int], socket.socket]

# Domain-allowlist predicate: normalized host -> allowed. None (the
# constructor default) means no domain check at this layer -- callers that
# do not pass one keep the pre-C1 behavior (IP/port checks only), which
# existing non-browser callers of PinningProxy may still rely on.
DomainAllowed = Callable[[str], bool]


def strip_dangerous_browser_args(args: Iterable[str]) -> list[str]:
    """Drop any egress-weakening Chromium launch flag (prefix match)."""
    return [a for a in args
            if not any(str(a).startswith(bad) for bad in _DANGEROUS_BROWSER_ARGS)]


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class PinningProxy:
    """Loopback HTTP CONNECT forward-proxy that dials only pinned, safe IPs.

    `domain_allowed`, when given, is consulted on the CONNECT authority
    BEFORE any resolution (ADR 0004 D4/C1) -- a non-allowlisted host is
    refused with zero DNS lookups and zero upstream connection attempts.
    One instance is created per fetch (the caller's allowlist is fixed for
    that fetch's lifetime), so this is a constructor argument, not a
    per-request parameter.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0, *,
                 dialer: Dialer | None = None,
                 domain_allowed: DomainAllowed | None = None) -> None:
        self._host = host
        self._port = port
        self._dialer = dialer or self._default_dial
        self._domain_allowed = domain_allowed
        self._srv: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopping = threading.Event()
        self.bound_host: str | None = None
        self.bound_port: int | None = None

    @staticmethod
    def _default_dial(ip: str, port: int) -> socket.socket:
        return socket.create_connection((ip, port), timeout=_CONNECT_TIMEOUT)

    @property
    def url(self) -> str | None:
        if self.bound_port is None:
            return None
        return f"http://{self.bound_host}:{self.bound_port}"

    def start(self) -> str:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self._host, self._port))   # loopback-only bind
        srv.listen(128)
        self._srv = srv
        self.bound_host, self.bound_port = srv.getsockname()[:2]
        self._thread = threading.Thread(
            target=self._serve, name="egress-proxy", daemon=True)
        self._thread.start()
        assert self.url is not None
        return self.url

    def stop(self) -> None:
        self._stopping.set()
        if self._srv is not None:
            try:
                self._srv.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> "PinningProxy":
        self.start()
        return self

    def __exit__(self, *exc: object) -> bool:
        self.stop()
        return False

    # ---------------------------------------------------------------- serving
    def _serve(self) -> None:
        assert self._srv is not None
        while not self._stopping.is_set():
            try:
                client, addr = self._srv.accept()
            except OSError:
                break  # server socket closed by stop()
            # Reject non-loopback clients outright (defence in depth: the bind
            # already prevents remote clients, this makes the guarantee explicit).
            if not _is_loopback(addr[0]):
                self._safe_close(client)
                continue
            threading.Thread(
                target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        try:
            client.settimeout(_CONNECT_TIMEOUT)
            head, leftover = self._read_head(client)
            if not head:
                return
            request_line = head.split(b"\r\n", 1)[0]
            parts = request_line.split()
            if len(parts) < 3 or parts[0].upper() != b"CONNECT":
                self._reply(client, _BAD)
                return
            host, port = self._parse_authority(parts[1])
            if host is None or port is None:
                self._reply(client, _BAD)
                return
            domain = host.lower().rstrip(".")
            if self._domain_allowed is not None and not self._domain_allowed(domain):
                # Refused on the DOMAIN alone: no resolution, no dial, no IP
                # check even attempted (ADR 0004 D4/C1) -- this authorization
                # decision must not depend on what the name happens to
                # resolve to right now.
                logger.warning(
                    "egress-proxy: CONNECT %s:%d refused, domain not in "
                    "this fetch's allowlist", domain, port)
                self._reply(client, _BLOCKED)
                return
            if port not in _ALLOWED_CONNECT_PORTS:
                self._reply(client, _BLOCKED)
                return
            try:
                pin = resolve_and_pin(host, port)
            except (SSRFError, FetchError):
                self._reply(client, _BLOCKED)
                return
            try:
                upstream = self._dialer(pin.ip, port)   # dial the PINNED ip
            except OSError:
                self._reply(client, _BLOCKED)
                return
            try:
                client.sendall(_CONNECT_OK)
                if leftover:
                    upstream.sendall(leftover)
                self._splice(client, upstream)
            finally:
                self._safe_close(upstream)
        except (OSError, socket.timeout):
            pass
        finally:
            self._safe_close(client)

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def _parse_authority(raw: bytes) -> tuple[str | None, int | None]:
        target = raw.decode("latin-1", "replace")
        host, _, port_s = target.rpartition(":")
        if not host or not port_s.isdigit():
            return None, None
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]   # unwrap an IPv6 literal for resolution
        return host, int(port_s)

    @staticmethod
    def _read_head(sock: socket.socket) -> tuple[bytes, bytes]:
        """Read up to end-of-headers (CRLFCRLF). Returns (head, leftover).

        For CONNECT the client waits for our 200 before sending tunnel bytes,
        so `leftover` is normally empty; any residual is forwarded to upstream.
        """
        buf = b""
        while b"\r\n\r\n" not in buf:
            if len(buf) > _MAX_HEADER_BYTES:
                return b"", b""
            chunk = sock.recv(_CHUNK)
            if not chunk:
                break
            buf += chunk
        head, _, leftover = buf.partition(b"\r\n\r\n")
        return head, leftover

    def _splice(self, a: socket.socket, b: socket.socket) -> None:
        def pipe(src: socket.socket, dst: socket.socket) -> None:
            try:
                while True:
                    data = src.recv(_CHUNK)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t1 = threading.Thread(target=pipe, args=(a, b), daemon=True)
        t2 = threading.Thread(target=pipe, args=(b, a), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def _reply(self, sock: socket.socket, payload: bytes) -> None:
        try:
            sock.sendall(payload)
        except OSError:
            pass

    @staticmethod
    def _safe_close(sock: socket.socket) -> None:
        try:
            sock.close()
        except OSError:
            pass
