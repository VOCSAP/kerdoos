"""HTTP Fetcher adapter (plain requests, MVP tier `http`).

Security posture (spec HIGH-2 / M1, anti-SSRF, CWE-918):
  * the anti-SSRF guard lives in autolycos.safety (single choke point, shared by
    every future fetcher tier).
  * IP pinning (ADR 0001 S9.1, Option A): safety.validate_target resolves the
    hostname ONCE and returns the validated IP; _PinnedHTTPAdapter pins the
    urllib3 connection pool to that exact IP at the CONNECTION level (via
    HTTPAdapter.build_connection_pool_key_attributes, requests' own documented
    extension point for this use case), so the tool never re-resolves. This
    closes the TOCTOU window (DNS-rebind) between our validation lookup and
    requests' own resolution. `server_hostname`/`assert_hostname` are pinned
    to the hostname (not the IP), so TLS SNI, certificate verification and the
    Host header all stay bound to the hostname -- only the TCP destination is
    the validated IP.
    This replaces a prior design (global `socket.getaddrinfo` monkeypatch
    under a shared lock) that serialized every http-tier fetch process-wide
    (head-of-line blocking). Each `_PinnedHTTPAdapter` instance owns its own
    private `urllib3.PoolManager` (via HTTPAdapter.__init__ -> init_poolmanager)
    and is used for exactly one request, so there is no shared mutable state
    and no lock: concurrent fetches to different targets never serialize on
    each other.
  * redirects are NOT auto-followed; each hop is re-validated and re-pinned.
  * the response body is size-capped while streaming (anti-OOM, CWE-400).
"""

from __future__ import annotations

from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from requests.models import PreparedRequest

from ..challenge import looks_challenged
from ..errors import FetchError
from ..ports import FetchResult
from ..safety import DomainPolicy, validate_target

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


class _PinnedHTTPAdapter(HTTPAdapter):
    """HTTPAdapter that pins the connection pool for one hostname to a
    validated IP, at the urllib3 connection-pool-key level (no DNS
    monkeypatch, no shared lock -- see module docstring).

    A fresh instance (with its own private urllib3.PoolManager) is created
    PER REQUEST by HttpFetcher.fetch, so this is trivially concurrency-safe:
    nothing is shared or mutated between requests, even to the same host.
    """

    def __init__(self, hostname: str, ip: str, **kwargs) -> None:
        self._hostname = hostname
        self._ip = ip
        super().__init__(**kwargs)

    def build_connection_pool_key_attributes(
        self, request: PreparedRequest, verify, cert=None,
    ):  # type: ignore[no-untyped-def]
        host_params, pool_kwargs = super().build_connection_pool_key_attributes(
            request, verify, cert,
        )
        # Pin the pool (and therefore the TCP connection) to the validated IP...
        host_params["host"] = self._ip
        # ...while keeping TLS SNI + certificate hostname verification bound
        # to the real hostname, exactly as if we had connected to it directly.
        pool_kwargs["server_hostname"] = self._hostname
        pool_kwargs["assert_hostname"] = self._hostname
        return host_params, pool_kwargs


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
    """Fetcher port implementation backed by `requests` (no TLS impersonation).

    Concurrency (ADR 0001 S9.1): fetch() builds a fresh requests.Session (and
    therefore a fresh, private urllib3.PoolManager) PER HOP, unless a session
    was explicitly injected via the constructor (test-only override -- a
    shared session is not thread-safe by design and is never used in
    production). This is the "session PAR REQUÊTE" requirement: nothing on
    self is mutated by fetch(), so concurrent fetch() calls -- even to the
    same host -- never race on a shared adapter map or connection pool.
    """

    method_name = "http"

    def __init__(self, domain_policy: DomainPolicy,
                 session: requests.Session | None = None) -> None:
        # Fail FAST (at construction, not silently at request time) if the
        # requests version is too old to carry the IP pin: _PinnedHTTPAdapter
        # overrides build_connection_pool_key_attributes, added in requests
        # 2.32.0. On an older requests the parent never calls the override and
        # the SSRF IP pin would silently vanish (CWE-918). pyproject pins
        # requests>=2.34; this guard catches any environment/dependency skew.
        if not hasattr(HTTPAdapter, "build_connection_pool_key_attributes"):
            raise RuntimeError(
                "requests is too old for the SSRF IP pin: "
                "HTTPAdapter.build_connection_pool_key_attributes (requests "
                ">=2.32.0) is missing. Install requests>=2.34 (see "
                "autolycos/pyproject.toml)."
            )
        self._domain_policy = domain_policy
        # Test-only override; production callers leave this None so fetch()
        # builds an unshared session per hop (see class docstring).
        self._session_override = session

    def fetch(self, url: str) -> FetchResult:
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            # resolves once, pins target.ip
            target = validate_target(current, self._domain_policy)
            session = self._session_override or requests.Session()
            adapter = _PinnedHTTPAdapter(target.host, target.ip)
            session.mount(f"{target.scheme}://{target.host}", adapter)

            resp = session.get(
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
