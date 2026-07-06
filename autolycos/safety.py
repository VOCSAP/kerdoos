"""Shared anti-SSRF guard (spec HIGH-2 / M1, CWE-918).

Single choke point for target validation, imported by every Fetcher adapter
(http today; tls/browser/uc must use it too). Validating here -- rather than in
each adapter -- guarantees a new tool cannot forget the guard.

`validate_target` resolves the hostname EXACTLY ONCE and returns the validated
IP to pin the connection on, so the caller can close the TOCTOU window between
this DNS lookup and the tool's own resolution (DNS-rebind).
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from .errors import FetchError, SSRFError

# Registrable domains of the 6 target sites. A host is allowed iff it equals one
# of these or is a subdomain (leading-dot match prevents suffix spoofing).
ALLOWED_DOMAINS: frozenset[str] = frozenset({
    "kabum.com.br",
    "amazon.com.br",
    "mercadolivre.com.br",
    "terabyteshop.com.br",
    "pichau.com.br",
    "magazineluiza.com.br",
})

ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

_DEFAULT_PORT = {"http": 80, "https": 443}


@dataclass(frozen=True, slots=True)
class ValidatedTarget:
    """A target that passed every SSRF check, with the IP to pin the socket on."""

    url: str
    scheme: str
    host: str
    port: int
    ip: str


def domain_allowed(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in ALLOWED_DOMAINS)


def ip_is_safe(addr: str) -> bool:
    """True only for globally routable addresses (fail-closed on anything else)."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
        return False
    return ip.is_global


def validate_target(url: str) -> ValidatedTarget:
    """Validate scheme + domain + resolved IPs. Resolve once and pin an IP.

    Raises SSRFError when the target is refused (scheme/domain/IP), FetchError
    when DNS resolution itself fails.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFError(f"scheme not allowed: {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise SSRFError("missing host")
    if not domain_allowed(host):
        raise SSRFError(f"domain not in allowlist: {host!r}")
    port = parts.port or _DEFAULT_PORT[scheme]
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise FetchError(f"DNS resolution failed for {host!r}: {exc}") from exc
    addrs = [info[4][0] for info in infos]
    if not addrs:
        raise SSRFError(f"no addresses resolved for {host!r}")
    # Fail-closed: reject if ANY resolved address is unsafe (a host that mixes
    # public and private answers is refused outright).
    for addr in addrs:
        if not ip_is_safe(addr):
            raise SSRFError(f"resolved address blocked for {host!r}: {addr}")
    return ValidatedTarget(url=url, scheme=scheme, host=host,
                           port=port, ip=addrs[0])
