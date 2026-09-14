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
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

from .errors import FetchError, SSRFError

ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

# RFC 3986 unreserved + reserved (gen-delims + sub-delims) + the percent
# escape marker. An allowlist, not a denylist of "known-bad" characters
# (quote, backslash, angle brackets, backtick, space, control bytes): closes
# the injection at the shared choke point (check_scheme_and_domain, roadmap
# c06082a5) against any byte outside RFC 3986, known or not yet enumerated.
_RFC3986_SAFE_RE = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*$")

_DEFAULT_PORT = {"http": 80, "https": 443}


@dataclass(frozen=True, slots=True)
class ValidatedTarget:
    """A target that passed every SSRF check, with the IP to pin the socket on."""

    url: str
    scheme: str
    host: str
    port: int
    ip: str


@dataclass(frozen=True, slots=True)
class PinnedAddress:
    """A resolved-and-validated host:port with the exact IP to dial.

    Returned by resolve_and_pin (the egress-proxy CONNECT path): the caller
    MUST dial `.ip`, never re-resolve `.host`, so the DNS-rebind TOCTOU window
    stays closed at the network layer (ADR 0001 S9, invariant #2).
    """

    host: str
    port: int
    ip: str


@dataclass(frozen=True, slots=True)
class DomainPolicy:
    """Caller-injected navigation-domain allowlist.

    autolycos is a generic anti-bot toolkit: it must not hardcode which
    domains are legitimate to navigate to. The caller constructs
    this from its own site catalogue and passes it into every Fetcher and
    into `validate_target`. A host is allowed iff it equals one of
    `allowed_domains` or is a subdomain (leading-dot match prevents suffix
    spoofing, e.g. "evilkabum.com.br" or "kabum.com.br.evil.com").
    """

    allowed_domains: frozenset[str]

    def domain_allowed(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(host == d or host.endswith("." + d)
                   for d in self.allowed_domains)


def ip_is_safe(addr: str) -> bool:
    """True only for globally routable addresses (fail-closed on anything else)."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    # IPv4-mapped IPv6 (::ffff:a.b.c.d) must be judged on the embedded IPv4:
    # IPv6Address.is_private/is_global do NOT reflect the mapped address's
    # own range, so e.g. "::ffff:169.254.169.254" (cloud metadata) would
    # otherwise slip through as "global" (CWE-918, issue #11054).
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
        return False
    return ip.is_global


def check_scheme_and_domain(url: str, domain_policy: DomainPolicy) -> tuple[str, str]:
    """Validate scheme + host allowlist only (no DNS, no IP check).

    Shared choke-point predicate (FD2): the ONE place that decides whether a
    url's scheme/host are structurally acceptable. Used by both
    validate_target (fetch-time gate, below) and
    the consumer's write-path URL validator (config-mutation
    gate) so the two independent SSRF gates can never drift apart on this
    check (ADR 0001 SSRF requirement #4: one predicate, no allowlist drift).

    Returns (scheme, host) on success. Raises SSRFError on any rejection.
    """
    if not _RFC3986_SAFE_RE.fullmatch(url):
        raise SSRFError("url contains a character outside RFC 3986")
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFError(f"scheme not allowed: {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise SSRFError("missing host")
    if not domain_policy.domain_allowed(host):
        raise SSRFError(f"domain not in allowlist: {host!r}")
    return scheme, host


def _resolve_and_check(host: str, port: int) -> str:
    """Resolve `host` ONCE and return the first IP to pin. Fail-closed.

    Shared resolution+pin primitive: resolves exactly once, rejects the host
    outright if ANY resolved address is unsafe (a host that mixes public and
    private answers is refused), and returns the first address to dial.
    Raises SSRFError on an unsafe/empty answer, FetchError on DNS failure.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise FetchError(f"DNS resolution failed for {host!r}: {exc}") from exc
    addrs = [info[4][0] for info in infos]
    if not addrs:
        raise SSRFError(f"no addresses resolved for {host!r}")
    for addr in addrs:
        if not ip_is_safe(addr):
            raise SSRFError(f"resolved address blocked for {host!r}: {addr}")
    return addrs[0]


def validate_target(url: str, domain_policy: DomainPolicy) -> ValidatedTarget:
    """Validate scheme + domain + resolved IPs. Resolve once and pin an IP.

    Raises SSRFError when the target is refused (scheme/domain/IP), FetchError
    when DNS resolution itself fails.
    """
    scheme, host = check_scheme_and_domain(url, domain_policy)
    parts = urlsplit(url)
    port = parts.port or _DEFAULT_PORT[scheme]
    ip = _resolve_and_check(host, port)
    return ValidatedTarget(url=url, scheme=scheme, host=host, port=port, ip=ip)


def resolve_and_pin(host: str, port: int) -> PinnedAddress:
    """Resolve `host` once and pin a safe IP for the egress-proxy CONNECT path.

    Unlike validate_target this takes an already-parsed host:port (a proxy
    CONNECT gives "host:port", not a URL) and does NOT apply the domain
    allowlist itself: PinningProxy (ADR 0004 D4/C1) checks the CONNECT
    authority's domain BEFORE ever calling this function, so a
    non-allowlisted host is refused with zero resolution and never reaches
    here at all. This function stays IP-layer-only by design (ip_is_safe +
    pin), a second, independent line of defense against a host that IS
    allowlisted but resolves to a non-global address (DNS rebind). Raises
    SSRFError / FetchError like validate_target.
    """
    ip = _resolve_and_check(host, port)
    return PinnedAddress(host=host, port=port, ip=ip)
