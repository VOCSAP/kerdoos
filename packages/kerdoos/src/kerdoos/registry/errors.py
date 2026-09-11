"""Registry domain errors (shared, tool-free).

ConfigError is the registry's domain-level configuration error. It lives here
(not in yaml_store) so both the YAML loader and the SQLite store can raise it
without importing each other; yaml_store re-exports it for backward-compatible
imports.
"""

from __future__ import annotations


class ConfigError(ValueError):
    """Invalid or inconsistent configuration/registry state."""


class FetcherTierUnavailableError(ConfigError):
    """A source references a site whose fetcher tier's optional dependency is
    not importable in this deployment (e.g. a `browser`/`uc` site added on a
    `slim` image, card 3aeb8a19). A ValueError/ConfigError subclass so the
    existing `except (ValueError, KeyError)` domain-error handling at the
    WebUI/CLI boundary catches it without any route change."""


class ConfigImportError(ConfigError):
    """A bulk import batch (AppService.import_config, card a8d6ee3a) failed
    validation. Carries every rejected entry's message, not just the first
    -- the caller reports them all and writes nothing."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__(f"{len(errors)} error(s): " + "; ".join(errors))
