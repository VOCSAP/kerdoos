"""TLS Fetcher adapter (curl_cffi impersonation, MVP tier `tls`).

Escalation tier above `http`: curl_cffi replays a real Chrome TLS/JA3 + HTTP2
fingerprint to pass fingerprint-based gates (e.g. Akamai) that plain requests
trips. Same anti-SSRF posture as HttpFetcher (spec HIGH-2 / M1, CWE-918):

  * every hop goes through autolycos.safety.validate_target BEFORE connecting
    (single choke point; scheme + domain allowlist + resolved-IP safety).
  * IP pinning closes the DNS-rebind TOCTOU window. libcurl uses its OWN
    resolver, so the socket.getaddrinfo monkeypatch used by HttpFetcher does
    NOT apply here; we pin via CURLOPT_RESOLVE ("HOST:PORT:ADDRESS"), which
    forces libcurl to use the validated IP while keeping the hostname for SNI,
    certificate verification and the Host header.
  * redirects are NOT auto-followed; each hop is re-validated and re-pinned.
  * no TLS downgrade: HTTPS targets keep verification on (curl_cffi verifies by
    default; we never disable it).
  * the response body is size-capped while streaming (anti-OOM, CWE-400).

curl_cffi is imported lazily INSIDE fetch(), so this module (and the whole test
suite) imports fine on a base interpreter without curl_cffi installed. The tls
tier is only ever exercised when the static router selects it.
"""

from __future__ import annotations

from urllib.parse import urljoin

from ..challenge import looks_challenged
from ..errors import FetchError
from ..ports import FetchResult
from ..safety import ValidatedTarget, validate_target

MAX_HTML_BYTES = 5 * 1024 * 1024   # 5 MiB cap (largest recon dump ~1.7 MiB)
MAX_REDIRECTS = 5
TIMEOUT = 30
_CHUNK = 64 * 1024
_IMPERSONATE = "chrome"

# Only a language hint; the UA and fingerprint headers come from impersonation
# and must not be overridden (that would defeat the whole point of this tier).
_HEADERS = {"Accept-Language": "pt-BR,pt;q=0.9,en;q=0.8"}


def _resolve_entry(target: ValidatedTarget) -> str:
    """CURLOPT_RESOLVE entry pinning target.host:port to the validated IP.

    Format is libcurl's "HOST:PORT:ADDRESS"; the hostname is preserved so SNI,
    certificate validation and the Host header all stay bound to the hostname
    while the actual connection goes to the pre-validated address.

    An IPv6 literal must be bracketed ("[2001:db8::1]"), otherwise libcurl
    mis-parses the colons and the RESOLVE pin is silently ignored -- which would
    quietly re-open the DNS-rebind TOCTOU window for IPv6 targets.
    """
    addr = f"[{target.ip}]" if ":" in target.ip else target.ip
    return f"{target.host}:{target.port}:{addr}"


def _load_curl():  # type: ignore[no-untyped-def]
    """Lazy handle on curl_cffi (optional dependency).

    Imported on demand so the module -- and the whole test suite -- loads on a
    base interpreter without curl_cffi. Called only AFTER the SSRF guard has
    validated the target, so a hostile URL is refused even when the dependency
    is missing (the guard raises before we get here).
    """
    from curl_cffi import CurlOpt
    from curl_cffi import requests as cffi

    return cffi, CurlOpt


def _read_capped(resp) -> str:  # type: ignore[no-untyped-def]
    total = 0
    chunks: list[bytes] = []
    for chunk in resp.iter_content(chunk_size=_CHUNK):
        if not chunk:
            continue
        total += len(chunk)
        if total > MAX_HTML_BYTES:
            raise FetchError(f"response exceeds {MAX_HTML_BYTES} bytes cap")
        chunks.append(chunk)
    encoding = resp.encoding or "utf-8"
    return b"".join(chunks).decode(encoding, errors="replace")


class TlsFetcher:
    """Fetcher port implementation backed by curl_cffi (Chrome impersonation)."""

    method_name = "tls"

    def fetch(self, url: str) -> FetchResult:
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            # SSRF guard runs FIRST, before importing/using curl_cffi, so a
            # non-allowlisted or rebinding target is refused even if the optional
            # dependency is absent (fail-closed, CWE-918).
            target = validate_target(current)  # resolves once, pins target.ip
            cffi, CurlOpt = _load_curl()
            resp = cffi.get(
                current,
                impersonate=_IMPERSONATE,
                headers=_HEADERS,
                timeout=TIMEOUT,
                allow_redirects=False,
                stream=True,
                # Pin libcurl's resolver to the validated IP for this hop.
                curl_options={CurlOpt.RESOLVE: [_resolve_entry(target)]},
            )
            status = resp.status_code
            if status in (301, 302, 303, 307, 308):
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
                status=status,
                method=self.method_name,
                challenged=looks_challenged(status, text),
            )
        raise FetchError(f"too many redirects (> {MAX_REDIRECTS})")
