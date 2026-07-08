"""Kerdoos's canonical navigation-domain allowlist.

autolycos is a generic anti-bot toolkit (extractible package): it exposes
`autolycos.safety.DomainPolicy` but does not know which domains are
legitimate to navigate to -- that is Kerdoos's business, derived from the
configured site catalogue. This module is the single place kerdoos
constructs its DomainPolicy and hands it to every caller
(registry.url_validation.validate_source_url, StaticRouter, and --
transitively -- every Fetcher adapter).

Phase 2a (FD1, ADR 0001 S9): CatalogueDomainPolicy replaces the static
DEFAULT_DOMAIN_POLICY at the CLI composition root. It duck-types
autolycos.safety.DomainPolicy's domain_allowed(host) contract but queries
the live site catalogue (ConfigStore.site_domains()) on every call instead
of a snapshot resolved once at wiring time -- so a site an admin adds
mid-process becomes fetchable immediately, without re-wiring the app. This
is domain-string matching ONLY: ip_is_safe remains the separate, hard guard
that still blocks a cataloged domain resolving to a private/internal IP
(unaffected by this class, enforced later in autolycos.safety.validate_target).

DEFAULT_DOMAIN_POLICY (the static 6-domain allowlist) is kept as a
lightweight, still-tested primitive used directly by unit-level tests that
don't need a ConfigStore; it is no longer the CLI's wired default.
"""

from __future__ import annotations

from dataclasses import dataclass

from autolycos.safety import DomainPolicy
from kerdoos.registry.ports import ConfigStore

ALLOWED_DOMAINS: frozenset[str] = frozenset({
    "kabum.com.br",
    "amazon.com.br",
    "mercadolivre.com.br",
    "terabyteshop.com.br",
    "pichau.com.br",
    "magazineluiza.com.br",
})

DEFAULT_DOMAIN_POLICY = DomainPolicy(ALLOWED_DOMAINS)


@dataclass(frozen=True, slots=True)
class CatalogueDomainPolicy:
    """DomainPolicy derived live from the admin site catalogue.

    Not a frozen snapshot: domain_allowed(host) re-queries
    config_store.site_domains() on every call, so it always reflects the
    catalogue as of the call, including sites added earlier in the same
    process (Phase 2a FD1).
    """

    config_store: ConfigStore

    def domain_allowed(self, host: str) -> bool:
        return DomainPolicy(self.config_store.site_domains()).domain_allowed(host)
