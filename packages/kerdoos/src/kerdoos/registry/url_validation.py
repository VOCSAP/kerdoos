"""Shared source-url validation (SSRF choke point for config mutation).

Single function used by AppService.add_source AND the one-shot YAML import
path, so a hostile/typo'd url is rejected the same way regardless of entry
point (ADR 0001 S4: "the url validation moves from YAML-load-time to
add_source"). Delegates scheme/host checks to
autolycos.safety.check_scheme_and_domain -- the SAME predicate
autolycos.safety.validate_target uses at fetch time (ADR 0001 SSRF
requirement #4: one shared predicate, no allowlist drift) -- but this
remains the config-mutation gate, not the fetch-time gate; both must
independently reject an off-policy target (defense in depth, no single
point of bypass).
"""

from __future__ import annotations

from autolycos.errors import SSRFError
from autolycos.safety import DomainPolicy, check_scheme_and_domain


class UrlValidationError(ValueError):
    """The candidate source url is structurally invalid or off-policy."""


def validate_source_url(url: str, ctx: str, domain_policy: DomainPolicy) -> None:
    try:
        check_scheme_and_domain(url, domain_policy)
    except SSRFError as exc:
        raise UrlValidationError(f"{ctx}: {exc} ({url!r})") from exc
