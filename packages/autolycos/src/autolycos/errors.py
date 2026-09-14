"""Autolycos fetch errors. Pure module (no tool imports, no core import)."""

from __future__ import annotations


class FetchError(Exception):
    """A fetch attempt failed hard (network, oversize, protocol)."""


class SSRFError(FetchError):
    """A fetch was refused by the anti-SSRF guard (blocked target)."""


class UnknownFetcherError(KeyError):
    """The site config references a fetcher tier with no adapter wired."""
