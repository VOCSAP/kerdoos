"""Public contract of the browser-backed tiers: their defaults, the budget
checks a consumer runs on its own settings, and the install probes an image
build runs. Tool-free: the adapters import their tools lazily."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from .adapters import browser as _browser
from .adapters import camoufox as _camoufox
from .adapters import uc as _uc
from .adapters.camoufox import (
    CAMOUFOX_BROWSER_VERSION,
    CAMOUFOX_EXECUTABLE_PATH,
    camoufox_ready,
)

__all__ = [
    "BROWSER", "CAMOUFOX", "CAMOUFOX_BROWSER_VERSION",
    "CAMOUFOX_EXECUTABLE_PATH", "UC", "BrowserBudget", "BudgetCondition",
    "BudgetWarning", "CamoufoxBudget", "UcBudget", "camoufox_ready",
    "chromium_executable",
]

BudgetCondition = Literal["navigation", "gate"]


@dataclass(frozen=True, slots=True)
class BudgetWarning:
    """`navigation`: the fetch deadline can fire before the timeout it wraps.
    `gate`: a stuck fetch can hold the shared browser gate at or past the
    acquire timeout other callers wait with."""

    condition: BudgetCondition
    message: str


@dataclass(frozen=True, slots=True)
class BrowserBudget:
    launch_timeout_seconds: float
    nav_timeout_ms: int
    fetch_timeout_seconds: float
    max_abandoned_fetches: int

    def check(self, *, fetch_timeout_seconds: float,
              launch_timeout_seconds: float,
              acquire_timeout_seconds: float) -> list[BudgetWarning]:
        warnings: list[BudgetWarning] = []
        nav_seconds = self.nav_timeout_ms / 1000
        min_expected = launch_timeout_seconds + nav_seconds
        if fetch_timeout_seconds <= min_expected:
            warnings.append(BudgetWarning("navigation", (
                "KERDOOS_BROWSER_FETCH_TIMEOUT_SECONDS=%s is not above the "
                "browser tier's own launch (%.1fs) + navigation (%.1fs) budget "
                "(%.1fs) -- a fetch could be abandoned before the launch or "
                "navigation timeout it wraps ever gets a chance to fire.") % (
                    fetch_timeout_seconds, launch_timeout_seconds,
                    nav_seconds, min_expected)))
        if fetch_timeout_seconds >= acquire_timeout_seconds:
            warnings.append(BudgetWarning("gate", (
                "KERDOOS_BROWSER_FETCH_TIMEOUT_SECONDS=%s is not below "
                "KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS=%s -- another caller "
                "waiting for the browser gate could time out its own wait "
                "before this fetch ever abandons its stuck launch and frees "
                "the gate.") % (
                    fetch_timeout_seconds, acquire_timeout_seconds)))
        return warnings


@dataclass(frozen=True, slots=True)
class UcBudget:
    launch_timeout_seconds: float
    orphan_sweep_delay_seconds: float
    fetch_timeout_seconds: float
    page_load_timeout_seconds: float
    reconnect_time: float
    render_wait: float
    post_nav_kill_passes: int
    kill_wait_seconds: float

    def check(self, *, fetch_timeout_seconds: float,
              orphan_sweep_delay_seconds: float,
              acquire_timeout_seconds: float) -> list[BudgetWarning]:
        """`orphan_sweep_delay_seconds` is the delay the tier will actually
        sleep, after any clamping the caller applies."""
        warnings: list[BudgetWarning] = []
        min_expected = (self.page_load_timeout_seconds + self.reconnect_time
                        + self.render_wait)
        if fetch_timeout_seconds <= min_expected:
            warnings.append(BudgetWarning("navigation", (
                "KERDOOS_UC_FETCH_TIMEOUT_SECONDS=%s is not above the uc tier's "
                "own page-load (%.1fs) + reconnect (%.1fs) + render (%.1fs) "
                "budget (%.1fs) -- a fetch could be abandoned before the "
                "navigation timeout it wraps ever gets a chance to fire.") % (
                    fetch_timeout_seconds, self.page_load_timeout_seconds,
                    self.reconnect_time, self.render_wait, min_expected)))
        cleanup_seconds = (self.post_nav_kill_passes * self.kill_wait_seconds
                           + orphan_sweep_delay_seconds)
        held = fetch_timeout_seconds + cleanup_seconds
        if held >= acquire_timeout_seconds:
            warnings.append(BudgetWarning("gate", (
                "KERDOOS_UC_FETCH_TIMEOUT_SECONDS=%s plus the post-navigation "
                "cleanup it triggers (%.1fs: %d confirmed-death waits of %.1fs "
                "plus the late sweep's %ss ceiling) would hold the browser gate "
                "for %.1fs, at or past KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS="
                "%s -- another caller waiting for that gate could time out its "
                "own wait before this one ever frees it.") % (
                    fetch_timeout_seconds, cleanup_seconds,
                    self.post_nav_kill_passes, self.kill_wait_seconds,
                    orphan_sweep_delay_seconds, held,
                    acquire_timeout_seconds)))
        return warnings


@dataclass(frozen=True, slots=True)
class CamoufoxBudget:
    launch_timeout_seconds: float
    nav_timeout_seconds: float
    fetch_timeout_seconds: float
    max_abandoned_fetches: int
    kill_wait_seconds: float
    late_sweep_seconds: float

    def check(self, *, fetch_timeout_seconds: float,
              launch_timeout_seconds: float, nav_timeout_seconds: float,
              acquire_timeout_seconds: float) -> list[BudgetWarning]:
        """Past its deadline a frozen fetch keeps the gate through two
        confirmed-death waits and the late sweep's grace."""
        warnings: list[BudgetWarning] = []
        min_expected = launch_timeout_seconds + nav_timeout_seconds
        if fetch_timeout_seconds <= min_expected:
            warnings.append(BudgetWarning("navigation", (
                "KERDOOS_CAMOUFOX_FETCH_TIMEOUT_SECONDS=%s is not above the "
                "camoufox tier's launch (%.1fs) + navigation (%.1fs) budget "
                "(%.1fs) -- a fetch could be abandoned before the timeout it "
                "wraps ever gets a chance to fire.") % (
                    fetch_timeout_seconds, launch_timeout_seconds,
                    nav_timeout_seconds, min_expected)))
        cleanup_seconds = 2 * self.kill_wait_seconds + self.late_sweep_seconds
        held = fetch_timeout_seconds + cleanup_seconds
        if held >= acquire_timeout_seconds:
            warnings.append(BudgetWarning("gate", (
                "KERDOOS_CAMOUFOX_FETCH_TIMEOUT_SECONDS=%s plus the cleanup it "
                "triggers (%.1fs: two confirmed-death waits of %.1fs plus the "
                "late sweep's %.1fs grace) would hold the browser gate for "
                "%.1fs, at or past KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS=%s "
                "-- another caller waiting for that gate could time out its "
                "own wait before this one ever frees it.") % (
                    fetch_timeout_seconds, cleanup_seconds,
                    self.kill_wait_seconds, self.late_sweep_seconds, held,
                    acquire_timeout_seconds)))
        return warnings


BROWSER = BrowserBudget(
    launch_timeout_seconds=_browser.BROWSER_LAUNCH_TIMEOUT_SECONDS,
    nav_timeout_ms=_browser.NAV_TIMEOUT_MS,
    fetch_timeout_seconds=_browser.BROWSER_FETCH_TIMEOUT_SECONDS,
    max_abandoned_fetches=_browser.MAX_ABANDONED_FETCH_THREADS,
)

UC = UcBudget(
    launch_timeout_seconds=_uc.UC_LAUNCH_TIMEOUT_SECONDS,
    orphan_sweep_delay_seconds=_uc.ORPHAN_SWEEP_DELAY_SECONDS,
    fetch_timeout_seconds=_uc.UC_FETCH_TIMEOUT_SECONDS,
    page_load_timeout_seconds=_uc.UC_PAGE_LOAD_TIMEOUT_SECONDS,
    reconnect_time=_uc.RECONNECT_TIME,
    render_wait=_uc.RENDER_WAIT,
    post_nav_kill_passes=_uc.POST_NAV_KILL_PASSES,
    kill_wait_seconds=_uc.KILL_WAIT_SECONDS,
)

CAMOUFOX = CamoufoxBudget(
    launch_timeout_seconds=_camoufox.CAMOUFOX_LAUNCH_TIMEOUT_SECONDS,
    nav_timeout_seconds=_camoufox.CAMOUFOX_NAV_TIMEOUT_SECONDS,
    fetch_timeout_seconds=_camoufox.CAMOUFOX_FETCH_TIMEOUT_SECONDS,
    max_abandoned_fetches=_camoufox.MAX_ABANDONED_FETCH_THREADS,
    kill_wait_seconds=_camoufox.KILL_WAIT_SECONDS,
    late_sweep_seconds=_camoufox.LATE_SWEEP_SECONDS,
)


def chromium_executable() -> str | None:
    """The newest Chromium patchright installed for the uc tier, or None."""
    return _uc._find_patchright_chromium()
