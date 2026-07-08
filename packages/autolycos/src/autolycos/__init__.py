"""Autolycos -- anti-bot subsystem (Fetcher port + adapters + router).

Extractibility invariant: this package MUST NEVER import core/. Its only
outward dependency is the Fetcher port it exposes; the core depends on that
port, never the reverse.
"""
