"""Static Fetcher router (MVP).

Mode A policy: the site config names a fetcher tier (`sites.<site>.fetcher`)
and the router returns the matching adapter instance. No protector detection at
the MVP -- that is the post-MVP dynamic router (detect.py), added without
touching this contract.

The `http`, `tls` and `browser` tiers are wired; the `uc` tier raises until its
adapter lands. The `tls` and `browser` factories import their optional
dependency (curl_cffi, Playwright) lazily, so it is only pulled in when a site
actually selects that tier.
"""

from __future__ import annotations

from collections.abc import Iterable

from .adapters.http import HttpFetcher
from .ports import Fetcher


def _make_http(subresource_domains: Iterable[str]) -> Fetcher:
    return HttpFetcher()


def _make_tls(subresource_domains: Iterable[str]) -> Fetcher:
    # Deferred import: curl_cffi is optional and only needed for the tls tier.
    from .adapters.tls import TlsFetcher

    return TlsFetcher()


def _make_browser(subresource_domains: Iterable[str]) -> Fetcher:
    # Deferred import: Playwright is optional and only needed for the browser
    # tier (SPA sites whose price is injected by client-side JS). The per-site
    # render-CDN sub-resource allowlist flows in here.
    from .adapters.browser import BrowserFetcher

    return BrowserFetcher(subresource_domains)


# Lazy factories so importing the router does not construct every tool. Each
# accepts the per-site sub-resource domains; only the browser tier uses them.
_FACTORIES: dict[str, callable] = {
    "http": _make_http,
    "tls": _make_tls,
    "browser": _make_browser,
}


class UnknownFetcherError(KeyError):
    """The site config references a fetcher tier with no adapter wired."""


class StaticRouter:
    """Resolve a fetcher tier name to a Fetcher, caching instances."""

    def __init__(self) -> None:
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
            self._cache[key] = _FACTORIES[fetcher_name](subresource_domains)
        return self._cache[key]
