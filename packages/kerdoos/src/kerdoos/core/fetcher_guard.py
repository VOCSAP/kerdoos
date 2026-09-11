"""Deployment-mismatch guard shared by every per-source scrape loop.

AppService.run_now and evaluator._run_plan_a both call router.select() once
per configured source (card 3aeb8a19). Both must skip identically when the
site's fetcher tier is not importable on this deployment image, via this ONE
function, so a future third scrape loop cannot forget the check by
duplicating it ad hoc.
"""

from __future__ import annotations

from autolycos.ports import Router

from kerdoos.registry.ports import SiteConfig


def tier_unavailable(router: Router, site: SiteConfig) -> bool:
    return not router.tier_available(site.fetcher)
