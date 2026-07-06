"""Kerdoos parsers -- Parser port + concrete extraction adapters.

Adapters import core.domain types (Extract, Availability, ParseError): the
intended hexagonal direction adapters -> domain. This package may use stdlib
HTML parsing; it must not leak into core/.
"""
