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

from collections.abc import Iterable

from .adapters.http import HttpFetcher
from .ports import Fetcher
from .safety import DomainPolicy


def _make_http(domain_policy: DomainPolicy,
                subresource_domains: Iterable[str]) -> Fetcher:
    return HttpFetcher(domain_policy)


def _make_tls(domain_policy: DomainPolicy,
              subresource_domains: Iterable[str]) -> Fetcher:
    # Deferred import: curl_cffi is optional and only needed for the tls tier.
    from .adapters.tls import TlsFetcher

    return TlsFetcher(domain_policy)


def _make_browser(domain_policy: DomainPolicy,
                   subresource_domains: Iterable[str]) -> Fetcher:
    # Deferred import: Playwright is optional and only needed for the browser
    # tier (SPA sites whose price is injected by client-side JS). The per-site
    # render-CDN sub-resource allowlist flows in here.
    from .adapters.browser import BrowserFetcher

    return BrowserFetcher(domain_policy, subresource_domains)


def _make_uc(domain_policy: DomainPolicy,
             subresource_domains: Iterable[str]) -> Fetcher:
    # Deferred import: SeleniumBase is optional and only needed for the uc tier
    # (sites behind Akamai Bot Manager; Magalu). The per-site render-CDN
    # sub-resource allowlist feeds the DNS-level host-resolver rule.
    from .adapters.uc import UcFetcher

    return UcFetcher(domain_policy, subresource_domains)


# Lazy factories so importing the router does not construct every tool. Each
# accepts the injected DomainPolicy plus the per-site sub-resource domains
# (the browser and uc tiers use the latter).
_FACTORIES: dict[str, callable] = {
    "http": _make_http,
    "tls": _make_tls,
    "browser": _make_browser,
    "uc": _make_uc,
}


class UnknownFetcherError(KeyError):
    """The site config references a fetcher tier with no adapter wired."""


class StaticRouter:
    """Resolve a fetcher tier name to a Fetcher, caching instances."""

    def __init__(self, domain_policy: DomainPolicy) -> None:
        self._domain_policy = domain_policy
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
                self._domain_policy, subresource_domains)
        return self._cache[key]
