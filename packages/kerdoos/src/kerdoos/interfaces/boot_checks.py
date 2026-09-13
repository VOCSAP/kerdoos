"""Boot-time fetcher-tier availability check (card 3aeb8a19).

Shared by web.app.create_app() and the CLI entry points so a deployment
mismatch (a site's configured fetcher tier not runnable on this image,
e.g. a `browser`/`uc`/`camoufox` site on a `slim` build) is diagnosed
identically regardless of interface, instead of two divergent
implementations.
"""

from __future__ import annotations

import logging

from autolycos.ports import Router

from kerdoos.registry.ports import ConfigStore

logger = logging.getLogger(__name__)


def log_unavailable_fetcher_tiers(config_store: ConfigStore, router: Router) -> None:
    """Log ONE error listing every fetcher tier referenced by a configured
    product source (across all owners) that `router` cannot run.

    Judged by the router the composition root will scrape with, not by the
    module-level check: only the router knows the install it launches, so
    this diagnostic and the per-source guard in AppService cannot disagree.

    A single tenant's misconfigured source must not prevent the whole
    multi-tenant app/CLI command from starting (blast radius): a failure
    reading config_store is logged, not raised. The per-source guards in
    AppService.add_source/run_now are what actually stop the scrape loop;
    this is the operator-visible diagnostic.
    """
    try:
        referenced = config_store.list_referenced_fetcher_tiers()
        missing = sorted(
            tier for tier in referenced if not router.tier_available(tier))
    except Exception:  # noqa: BLE001 -- a boot-time diagnostic must not crash boot
        logger.exception("fetcher tier availability check failed at boot")
        return
    if missing:
        logger.error(
            "fetcher tier(s) %s are referenced by a configured source but "
            "unknown or not runnable in this deployment image -- those "
            "sources will be skipped at every scrape until the deployment "
            "is fixed",
            missing,
        )
