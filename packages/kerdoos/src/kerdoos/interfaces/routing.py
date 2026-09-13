"""StaticRouter construction shared by every composition root.

The WebUI and each CLI command build their router here, so a tier setting
added to Settings reaches all of them or none of them.
"""

from __future__ import annotations

from autolycos.browser_gate import BrowserGate
from autolycos.router import StaticRouter
from autolycos.safety import DomainPolicy

from kerdoos.config import Settings


def build_static_router(
    domain_policy: DomainPolicy, browser_gate: BrowserGate, settings: Settings,
) -> StaticRouter:
    return StaticRouter(
        domain_policy, browser_gate=browser_gate,
        uc_launch_timeout_seconds=settings.uc_launch_timeout_seconds,
        browser_launch_timeout_seconds=settings.browser_launch_timeout_seconds,
        uc_orphan_sweep_delay_seconds=settings.uc_orphan_sweep_delay_seconds,
        browser_fetch_timeout_seconds=settings.browser_fetch_timeout_seconds,
        browser_max_abandoned_fetches=settings.browser_max_abandoned_fetches,
        uc_fetch_timeout_seconds=settings.uc_fetch_timeout_seconds,
        camoufox_launch_timeout_seconds=settings.camoufox_launch_timeout_seconds,
        camoufox_nav_timeout_seconds=settings.camoufox_nav_timeout_seconds,
        camoufox_fetch_timeout_seconds=settings.camoufox_fetch_timeout_seconds,
        camoufox_max_abandoned_fetches=settings.camoufox_max_abandoned_fetches,
    )
