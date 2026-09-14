"""Public contract of the browser-backed tiers: their defaults, the budget
checks a consumer runs on its own settings, and the install probes an image
build runs. Tool-free: the adapters import their tools lazily.

A check reports what is out of order as data; wording it, and naming the
consumer's own settings, is left to the consumer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Literal

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
    "BudgetTerm", "BudgetWarning", "CamoufoxBudget", "GateWarning",
    "NavigationWarning", "UcBudget", "camoufox_ready", "chromium_executable",
]

BudgetCondition = Literal["navigation", "gate"]


@dataclass(frozen=True, slots=True)
class BudgetTerm:
    """One summand of a budget: `count` times `seconds`. `name` is the budget
    field or check argument the value comes from."""

    name: str
    seconds: float
    count: int = 1


@dataclass(frozen=True, slots=True)
class NavigationWarning:
    """fetch_timeout_seconds <= floor_seconds, the sum of `terms`: the fetch
    deadline can fire before the timeouts it wraps."""

    condition: ClassVar[Literal["navigation"]] = "navigation"
    fetch_timeout_seconds: float
    floor_seconds: float
    terms: tuple[BudgetTerm, ...]


@dataclass(frozen=True, slots=True)
class GateWarning:
    """held_seconds = fetch_timeout_seconds + cleanup_seconds (the sum of
    `cleanup_terms`) >= acquire_timeout_seconds: a stuck fetch can hold the
    shared browser gate as long as other callers wait for it."""

    condition: ClassVar[Literal["gate"]] = "gate"
    fetch_timeout_seconds: float
    acquire_timeout_seconds: float
    cleanup_seconds: float
    held_seconds: float
    cleanup_terms: tuple[BudgetTerm, ...]


BudgetWarning = NavigationWarning | GateWarning


def _check(fetch_timeout_seconds: float, acquire_timeout_seconds: float,
           floor_terms: tuple[BudgetTerm, ...],
           cleanup_terms: tuple[BudgetTerm, ...]) -> list[BudgetWarning]:
    warnings: list[BudgetWarning] = []
    floor_seconds = sum(term.count * term.seconds for term in floor_terms)
    if fetch_timeout_seconds <= floor_seconds:
        warnings.append(NavigationWarning(
            fetch_timeout_seconds=fetch_timeout_seconds,
            floor_seconds=floor_seconds, terms=floor_terms))
    cleanup_seconds = sum(term.count * term.seconds for term in cleanup_terms)
    held_seconds = fetch_timeout_seconds + cleanup_seconds
    if held_seconds >= acquire_timeout_seconds:
        warnings.append(GateWarning(
            fetch_timeout_seconds=fetch_timeout_seconds,
            acquire_timeout_seconds=acquire_timeout_seconds,
            cleanup_seconds=cleanup_seconds, held_seconds=held_seconds,
            cleanup_terms=cleanup_terms))
    return warnings


@dataclass(frozen=True, slots=True)
class BrowserBudget:
    launch_timeout_seconds: float
    nav_timeout_ms: int
    fetch_timeout_seconds: float
    max_abandoned_fetches: int

    def check(self, *, fetch_timeout_seconds: float,
              launch_timeout_seconds: float,
              acquire_timeout_seconds: float) -> list[BudgetWarning]:
        """Past its deadline the browser tier releases the gate with no
        cleanup of its own."""
        return _check(
            fetch_timeout_seconds, acquire_timeout_seconds,
            floor_terms=(
                BudgetTerm("launch_timeout_seconds", launch_timeout_seconds),
                BudgetTerm("nav_timeout_seconds", self.nav_timeout_ms / 1000)),
            cleanup_terms=())


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
        return _check(
            fetch_timeout_seconds, acquire_timeout_seconds,
            floor_terms=(
                BudgetTerm("page_load_timeout_seconds",
                           self.page_load_timeout_seconds),
                BudgetTerm("reconnect_time", self.reconnect_time),
                BudgetTerm("render_wait", self.render_wait)),
            cleanup_terms=(
                BudgetTerm("kill_wait_seconds", self.kill_wait_seconds,
                           count=self.post_nav_kill_passes),
                BudgetTerm("orphan_sweep_delay_seconds",
                           orphan_sweep_delay_seconds)))


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
        return _check(
            fetch_timeout_seconds, acquire_timeout_seconds,
            floor_terms=(
                BudgetTerm("launch_timeout_seconds", launch_timeout_seconds),
                BudgetTerm("nav_timeout_seconds", nav_timeout_seconds)),
            cleanup_terms=(
                BudgetTerm("kill_wait_seconds", self.kill_wait_seconds,
                           count=2),
                BudgetTerm("late_sweep_seconds", self.late_sweep_seconds)))


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
