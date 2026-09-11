"""Static Fetcher router (MVP).

Mode A policy: the site config names a fetcher tier (`sites.<site>.fetcher`)
and the router returns the matching adapter instance. No protector detection at
the MVP -- that is the post-MVP dynamic router (detect.py), added without
touching this contract.

All four tiers (`http`, `tls`, `browser`, `uc`) are wired. The `tls`, `browser`
and `uc` factories import their optional dependency (curl_cffi, Playwright,
SeleniumBase) lazily, so it is only pulled in when a site actually selects that
tier.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Callable, Iterable

from .adapters.http import HttpFetcher
from .browser_gate import BrowserGate, default_browser_gate
from .ports import Fetcher
from .safety import DomainPolicy


def _make_http(domain_policy: DomainPolicy,
                subresource_domains: Iterable[str],
                browser_gate: BrowserGate) -> Fetcher:
    return HttpFetcher(domain_policy)


def _make_tls(domain_policy: DomainPolicy,
              subresource_domains: Iterable[str],
              browser_gate: BrowserGate) -> Fetcher:
    # Deferred import: curl_cffi is optional and only needed for the tls tier.
    from .adapters.tls import TlsFetcher

    return TlsFetcher(domain_policy)


def _make_browser(domain_policy: DomainPolicy,
                   subresource_domains: Iterable[str],
                   browser_gate: BrowserGate) -> Fetcher:
    # Deferred import: Playwright is optional and only needed for the browser
    # tier (SPA sites whose price is injected by client-side JS). The per-site
    # render-CDN sub-resource allowlist flows in here.
    from .adapters.browser import BrowserFetcher

    return BrowserFetcher(domain_policy, subresource_domains, browser_gate)


def _make_uc(domain_policy: DomainPolicy,
             subresource_domains: Iterable[str],
             browser_gate: BrowserGate) -> Fetcher:
    # Deferred import: SeleniumBase is optional and only needed for the uc tier
    # (sites behind Akamai Bot Manager; Magalu). The per-site render-CDN
    # sub-resource allowlist feeds the DNS-level host-resolver rule.
    from .adapters.uc import UcFetcher

    return UcFetcher(domain_policy, subresource_domains, browser_gate)


# Lazy factories so importing the router does not construct every tool. Each
# accepts the injected DomainPolicy, the per-site sub-resource domains (the
# browser and uc tiers use the latter), and the shared BrowserGate (only
# browser/uc take it -- http/tls never launch a browser, and ignore it, so
# _FACTORIES stays one homogeneous callable shape).
_FACTORIES: dict[
    str, Callable[[DomainPolicy, Iterable[str], BrowserGate], Fetcher]
] = {
    "http": _make_http,
    "tls": _make_tls,
    "browser": _make_browser,
    "uc": _make_uc,
}

# Optional dependency each tier's factory imports lazily (mirrors _FACTORIES
# above -- keep the two in sync). None means always available (stdlib/requests
# baseline, no optional import).
_TIER_MODULES: dict[str, str | None] = {
    "http": None,
    "tls": "curl_cffi",
    "browser": "patchright",
    "uc": "seleniumbase",
}


def tier_available(fetcher_name: str) -> bool:
    """True if fetcher_name's optional dependency is importable in this
    deployment. Uses importlib.util.find_spec, which locates a module WITHOUT
    importing it -- a slim image still never pays the cost of an unavailable
    tier's import (same rationale as the deferred imports in _make_tls/
    _make_browser/_make_uc above).

    An UNKNOWN tier name (not in _TIER_MODULES, e.g. a config typo landed in
    config.db via `kerdoos config import`, which does not go through
    AppService.add_site's known_tiers() validation) is fail-closed -- reported
    as UNAVAILABLE, not available (card 3aeb8a19 F1). This is deliberately
    stricter than "tier-name validation only at add_site": add_source and
    run_now/_run_plan_a call tier_available too, so a row that reached
    config.db some other way (bulk import, a future MCP door, a pre-existing
    row) is still rejected/skipped, not just newly-typed ones."""
    if fetcher_name not in _TIER_MODULES:
        return False
    module = _TIER_MODULES[fetcher_name]
    if module is None:
        return True
    return importlib.util.find_spec(module) is not None


def known_tiers() -> frozenset[str]:
    """Every fetcher tier name select() can ever resolve, regardless of
    whether its optional dependency is installed (mirrors _FACTORIES)."""
    return frozenset(_TIER_MODULES)


class UnknownFetcherError(KeyError):
    """The site config references a fetcher tier with no adapter wired."""


class StaticRouter:
    """Resolve a fetcher tier name to a Fetcher, caching instances."""

    def __init__(
        self, domain_policy: DomainPolicy,
        browser_gate: BrowserGate | None = None,
    ) -> None:
        self._domain_policy = domain_policy
        # Defaults to the SAME module-level singleton as a directly-
        # constructed BrowserFetcher/UcFetcher (card ca30b736) -- two
        # StaticRouters built without an explicit gate still share one door.
        self._browser_gate = (
            browser_gate if browser_gate is not None else default_browser_gate())
        self._cache: dict[tuple[str, frozenset[str]], Fetcher] = {}

    def select(
        self, fetcher_name: str, subresource_domains: Iterable[str] = ()
    ) -> Fetcher:
        if fetcher_name not in _FACTORIES:
            raise UnknownFetcherError(
                f"no fetcher adapter for tier {fetcher_name!r} "
                f"(wired: {sorted(_FACTORIES)})"
            )
        # Cache key folds in the sub-resource allowlist so two sites on the same
        # tier with different render CDNs get distinct instances.
        key = (fetcher_name, frozenset(subresource_domains))
        if key not in self._cache:
            self._cache[key] = _FACTORIES[fetcher_name](
                self._domain_policy, subresource_domains, self._browser_gate)
        return self._cache[key]

    def tier_available(self, fetcher_name: str) -> bool:
        return tier_available(fetcher_name)

    def known_tiers(self) -> frozenset[str]:
        return known_tiers()
