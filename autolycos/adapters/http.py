"""HTTP Fetcher adapter (plain requests, MVP tier `http`).

Security posture (spec HIGH-2 / M1, anti-SSRF, CWE-918):
  * the anti-SSRF guard lives in autolycos.safety (single choke point, shared by
    every future fetcher tier).
  * IP pinning: safety.validate_target resolves the hostname ONCE and returns
    the validated IP; the connection is pinned to that exact IP via a custom
    HTTPAdapter, so the tool never re-resolves. This closes the TOCTOU window
    (DNS-rebind) between our validation lookup and requests' own resolution. The
    URL keeps the hostname, so TLS SNI, certificate verification and the Host
    header all stay bound to the hostname.
  * redirects are NOT auto-followed; each hop is re-validated and re-pinned.
  * the response body is size-capped while streaming (anti-OOM, CWE-400).
"""

from __future__ import annotations

import contextlib
import socket
import threading
from typing import Iterator
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter

from ..challenge import looks_challenged
from ..errors import FetchError
from ..ports import FetchResult
from ..safety import validate_target

MAX_HTML_BYTES = 5 * 1024 * 1024   # 5 MiB cap (largest recon dump ~1.5 MiB)
MAX_REDIRECTS = 5
TIMEOUT = 25
_CHUNK = 64 * 1024

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8",
}

# Serialize the scoped resolver swap (defensive; the MVP is single-threaded).
_dns_lock = threading.Lock()


@contextlib.contextmanager
def _pinned_getaddrinfo(hostname: str, ip: str) -> Iterator[None]:
    """Within this context, resolving `hostname` yields ONLY the pinned `ip`.

    The pinned answer is synthesized directly (no re-resolution), so a rebinding
    resolver cannot substitute a different address. Other hosts resolve normally.
    """
    original = socket.getaddrinfo
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET

    def patched(host, port, *args, **kwargs):  # type: ignore[no-untyped-def]
        if host == hostname:
            return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                     (ip, port))]
        return original(host, port, *args, **kwargs)

    with _dns_lock:
        socket.getaddrinfo = patched  # type: ignore[assignment]
        try:
            yield
        finally:
            socket.getaddrinfo = original  # type: ignore[assignment]


class _PinnedHTTPAdapter(HTTPAdapter):
    """HTTPAdapter that pins DNS for one hostname to a validated IP during send."""

    def __init__(self, hostname: str, ip: str, **kwargs) -> None:
        self._hostname = hostname
        self._ip = ip
        super().__init__(**kwargs)

    def send(self, request, **kwargs):  # type: ignore[no-untyped-def]
        with _pinned_getaddrinfo(self._hostname, self._ip):
            return super().send(request, **kwargs)


def _read_capped(resp: requests.Response) -> str:
    total = 0
    chunks: list[bytes] = []
    for chunk in resp.iter_content(_CHUNK):
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_HTML_BYTES:
            raise FetchError(f"response exceeds {MAX_HTML_BYTES} bytes cap")
        chunks.append(chunk)
    encoding = resp.encoding or "utf-8"
    return b"".join(chunks).decode(encoding, errors="replace")


class HttpFetcher:
    """Fetcher port implementation backed by `requests` (no TLS impersonation)."""

    method_name = "http"

    def __init__(self, session: requests.Session | None = None) -> None:
        self._session = session or requests.Session()

    def fetch(self, url: str) -> FetchResult:
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            target = validate_target(current)  # resolves once, pins target.ip
            adapter = _PinnedHTTPAdapter(target.host, target.ip)
            self._session.mount(f"{target.scheme}://{target.host}", adapter)

            resp = self._session.get(
                current, headers=_HEADERS, timeout=TIMEOUT,
                allow_redirects=False, stream=True,
            )
            if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                resp.close()
                if not location:
                    raise FetchError("redirect without Location header")
                current = urljoin(current, location)
                continue  # re-validated + re-pinned at loop top before following
            try:
                text = _read_capped(resp)
            finally:
                resp.close()
            return FetchResult(
                html=text,
                status=resp.status_code,
                method=self.method_name,
                challenged=looks_challenged(resp.status_code, text),
            )
        raise FetchError(f"too many redirects (> {MAX_REDIRECTS})")
