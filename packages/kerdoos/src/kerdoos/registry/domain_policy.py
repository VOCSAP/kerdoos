"""Kerdoos's canonical navigation-domain allowlist.

autolycos is a generic anti-bot toolkit (extractible package): it exposes
`autolycos.safety.DomainPolicy` but does not know which domains are
legitimate to navigate to -- that is Kerdoos's business, derived from the
configured site catalogue. This module is the single place kerdoos
constructs its DomainPolicy and hands it to every caller
(registry.url_validation.validate_source_url, StaticRouter, and --
transitively -- every Fetcher adapter), so the 6 registrable domains are
declared exactly once.

Behavior is unchanged from the MVP: same 6 domains, now injected instead of
hardcoded inside autolycos (ADR 0001 section 7).
"""

from __future__ import annotations

from autolycos.safety import DomainPolicy

ALLOWED_DOMAINS: frozenset[str] = frozenset({
    "kabum.com.br",
    "amazon.com.br",
    "mercadolivre.com.br",
    "terabyteshop.com.br",
    "pichau.com.br",
    "magazineluiza.com.br",
})

DEFAULT_DOMAIN_POLICY = DomainPolicy(ALLOWED_DOMAINS)
