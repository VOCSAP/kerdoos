"""Static Fetcher router (MVP).

Mode A policy: the site config names a fetcher tier (`sites.<site>.fetcher`)
and the router returns the matching adapter instance. No protector detection at
the MVP -- that is the post-MVP dynamic router (detect.py), added without
touching this contract.

The `http` and `tls` tiers are wired; other tiers (browser/uc) raise until
their adapters land. The `tls` factory imports curl_cffi lazily, so the optional
dependency is only pulled in when a site actually selects that tier.
"""

from __future__ import annotations

from .adapters.http import HttpFetcher
from .ports import Fetcher


def _make_tls() -> Fetcher:
    # Deferred import: curl_cffi is optional and only needed for the tls tier.
    from .adapters.tls import TlsFetcher

    return TlsFetcher()


# Lazy factories so importing the router does not construct every tool.
_FACTORIES: dict[str, callable] = {
    "http": HttpFetcher,
    "tls": _make_tls,
}


class UnknownFetcherError(KeyError):
    """The site config references a fetcher tier with no adapter wired."""


class StaticRouter:
    """Resolve a fetcher tier name to a Fetcher, caching instances."""

    def __init__(self) -> None:
        self._cache: dict[str, Fetcher] = {}

    def select(self, fetcher_name: str) -> Fetcher:
        if fetcher_name not in _FACTORIES:
            raise UnknownFetcherError(
                f"no fetcher adapter for tier {fetcher_name!r} "
                f"(wired: {sorted(_FACTORIES)})"
            )
        if fetcher_name not in self._cache:
            self._cache[fetcher_name] = _FACTORIES[fetcher_name]()
        return self._cache[fetcher_name]
