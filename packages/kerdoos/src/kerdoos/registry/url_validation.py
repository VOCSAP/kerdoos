"""Shared source-url validation (SSRF choke point for config mutation).

Single function used by AppService.add_source AND the one-shot YAML import
path, so a hostile/typo'd url is rejected the same way regardless of entry
point (ADR 0001 S4: "the url validation moves from YAML-load-time to
add_source"). Mirrors autolycos.safety.validate_target's checks -- the same
DomainPolicy contract every Fetcher enforces -- but this is the config-mutation
gate, not the fetch-time gate; both must independently reject an off-policy
target (defense in depth, no single point of bypass).
"""

from __future__ import annotations

from urllib.parse import urlsplit

from autolycos.safety import ALLOWED_SCHEMES, DomainPolicy


class UrlValidationError(ValueError):
    """The candidate source url is structurally invalid or off-policy."""


def validate_source_url(url: str, ctx: str, domain_policy: DomainPolicy) -> None:
    parts = urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise UrlValidationError(
            f"{ctx}: url scheme not allowed: {parts.scheme!r} ({url!r})")
    host = parts.hostname
    if not host:
        raise UrlValidationError(f"{ctx}: url has no host ({url!r})")
    if not domain_policy.domain_allowed(host):
        raise UrlValidationError(
            f"{ctx}: url host not in allowlist: {host!r} ({url!r})")
