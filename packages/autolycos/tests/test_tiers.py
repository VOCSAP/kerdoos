"""autolycos.tiers: tier defaults and the budget checks consumers rely on."""

from __future__ import annotations

import dataclasses
import subprocess
import sys
import unittest
from unittest import mock

from autolycos import tiers
from autolycos.adapters import browser, camoufox, uc

_TOOLS = ("playwright", "patchright", "playwright_stealth", "camoufox",
          "seleniumbase", "curl_cffi", "psutil")

_BROWSER = tiers.BrowserBudget(
    launch_timeout_seconds=1.0, nav_timeout_ms=30_000,
    fetch_timeout_seconds=1.0, max_abandoned_fetches=1)
_UC = tiers.UcBudget(
    launch_timeout_seconds=1.0, orphan_sweep_delay_seconds=1.0,
    fetch_timeout_seconds=1.0, page_load_timeout_seconds=40.0,
    reconnect_time=5.0, render_wait=2.0, post_nav_kill_passes=2,
    kill_wait_seconds=4.0)
_CAMOUFOX = tiers.CamoufoxBudget(
    launch_timeout_seconds=1.0, nav_timeout_seconds=1.0,
    fetch_timeout_seconds=1.0, max_abandoned_fetches=1,
    kill_wait_seconds=4.0, late_sweep_seconds=3.0)


def _conditions(warnings: list[tiers.BudgetWarning]) -> list[str]:
    return [warning.condition for warning in warnings]


class DefaultsTest(unittest.TestCase):
    def test_browser_defaults_are_the_adapter_constants(self) -> None:
        self.assertEqual(
            dataclasses.astuple(tiers.BROWSER),
            (browser.BROWSER_LAUNCH_TIMEOUT_SECONDS, browser.NAV_TIMEOUT_MS,
             browser.BROWSER_FETCH_TIMEOUT_SECONDS,
             browser.MAX_ABANDONED_FETCH_THREADS))

    def test_uc_defaults_are_the_adapter_constants(self) -> None:
        self.assertEqual(
            dataclasses.astuple(tiers.UC),
            (uc.UC_LAUNCH_TIMEOUT_SECONDS, uc.ORPHAN_SWEEP_DELAY_SECONDS,
             uc.UC_FETCH_TIMEOUT_SECONDS, uc.UC_PAGE_LOAD_TIMEOUT_SECONDS,
             uc.RECONNECT_TIME, uc.RENDER_WAIT, uc.POST_NAV_KILL_PASSES,
             uc.KILL_WAIT_SECONDS))

    def test_camoufox_defaults_are_the_adapter_constants(self) -> None:
        self.assertEqual(
            dataclasses.astuple(tiers.CAMOUFOX),
            (camoufox.CAMOUFOX_LAUNCH_TIMEOUT_SECONDS,
             camoufox.CAMOUFOX_NAV_TIMEOUT_SECONDS,
             camoufox.CAMOUFOX_FETCH_TIMEOUT_SECONDS,
             camoufox.MAX_ABANDONED_FETCH_THREADS,
             camoufox.KILL_WAIT_SECONDS, camoufox.LATE_SWEEP_SECONDS))

    def test_budgets_are_frozen(self) -> None:
        for budget in (tiers.BROWSER, tiers.UC, tiers.CAMOUFOX):
            with self.subTest(budget=type(budget).__name__):
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    budget.fetch_timeout_seconds = 0.0  # type: ignore[misc]

    def test_default_budgets_raise_no_warning(self) -> None:
        acquire = 120.0
        self.assertEqual(tiers.BROWSER.check(
            fetch_timeout_seconds=tiers.BROWSER.fetch_timeout_seconds,
            launch_timeout_seconds=tiers.BROWSER.launch_timeout_seconds,
            acquire_timeout_seconds=acquire), [])
        self.assertEqual(tiers.UC.check(
            fetch_timeout_seconds=tiers.UC.fetch_timeout_seconds,
            orphan_sweep_delay_seconds=tiers.UC.orphan_sweep_delay_seconds,
            acquire_timeout_seconds=acquire), [])
        self.assertEqual(tiers.CAMOUFOX.check(
            fetch_timeout_seconds=tiers.CAMOUFOX.fetch_timeout_seconds,
            launch_timeout_seconds=tiers.CAMOUFOX.launch_timeout_seconds,
            nav_timeout_seconds=tiers.CAMOUFOX.nav_timeout_seconds,
            acquire_timeout_seconds=acquire), [])


class BrowserBudgetCheckTest(unittest.TestCase):
    def _check(self, fetch: float, launch: float = 40.0,
               acquire: float = 1000.0) -> list[tiers.BudgetWarning]:
        return _BROWSER.check(fetch_timeout_seconds=fetch,
                              launch_timeout_seconds=launch,
                              acquire_timeout_seconds=acquire)

    def test_navigation_floor_is_launch_plus_navigation_inclusive(self) -> None:
        self.assertEqual(_conditions(self._check(70.0)), ["navigation"])
        self.assertEqual(self._check(70.5), [])

    def test_gate_warns_from_the_acquire_timeout_inclusive(self) -> None:
        self.assertEqual(_conditions(self._check(90.0, acquire=90.0)), ["gate"])
        self.assertEqual(self._check(89.5, acquire=90.0), [])

    def test_both_conditions_are_reported_in_one_call(self) -> None:
        self.assertEqual(_conditions(self._check(50.0, acquire=50.0)),
                         ["navigation", "gate"])

    def test_messages(self) -> None:
        (navigation,) = self._check(50.0)
        self.assertEqual(
            navigation.message,
            "KERDOOS_BROWSER_FETCH_TIMEOUT_SECONDS=50.0 is not above the "
            "browser tier's own launch (40.0s) + navigation (30.0s) budget "
            "(70.0s) -- a fetch could be abandoned before the launch or "
            "navigation timeout it wraps ever gets a chance to fire.")
        (gate,) = self._check(90.0, launch=20.0, acquire=60.0)
        self.assertEqual(
            gate.message,
            "KERDOOS_BROWSER_FETCH_TIMEOUT_SECONDS=90.0 is not below "
            "KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS=60.0 -- another caller "
            "waiting for the browser gate could time out its own wait "
            "before this fetch ever abandons its stuck launch and frees "
            "the gate.")


class UcBudgetCheckTest(unittest.TestCase):
    def _check(self, fetch: float, sweep: float = 6.0,
               acquire: float = 1000.0) -> list[tiers.BudgetWarning]:
        return _UC.check(fetch_timeout_seconds=fetch,
                         orphan_sweep_delay_seconds=sweep,
                         acquire_timeout_seconds=acquire)

    def test_navigation_floor_is_page_load_plus_reconnect_plus_render(
            self) -> None:
        self.assertEqual(_conditions(self._check(47.0)), ["navigation"])
        self.assertEqual(self._check(47.5), [])

    def test_gate_counts_kill_passes_and_the_given_sweep_delay(self) -> None:
        self.assertEqual(
            _conditions(self._check(86.0, sweep=6.0, acquire=100.0)), ["gate"])
        self.assertEqual(self._check(85.5, sweep=6.0, acquire=100.0), [])
        self.assertEqual(
            _conditions(self._check(85.5, sweep=6.5, acquire=100.0)), ["gate"])

    def test_messages(self) -> None:
        (navigation,) = self._check(20.0)
        self.assertEqual(
            navigation.message,
            "KERDOOS_UC_FETCH_TIMEOUT_SECONDS=20.0 is not above the uc tier's "
            "own page-load (40.0s) + reconnect (5.0s) + render (2.0s) "
            "budget (47.0s) -- a fetch could be abandoned before the "
            "navigation timeout it wraps ever gets a chance to fire.")
        (gate,) = self._check(86.0, sweep=6.0, acquire=100.0)
        self.assertEqual(
            gate.message,
            "KERDOOS_UC_FETCH_TIMEOUT_SECONDS=86.0 plus the post-navigation "
            "cleanup it triggers (14.0s: 2 confirmed-death waits of 4.0s "
            "plus the late sweep's 6.0s ceiling) would hold the browser gate "
            "for 100.0s, at or past KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS="
            "100.0 -- another caller waiting for that gate could time out its "
            "own wait before this one ever frees it.")


class CamoufoxBudgetCheckTest(unittest.TestCase):
    def _check(self, fetch: float, launch: float = 30.0, nav: float = 40.0,
               acquire: float = 1000.0) -> list[tiers.BudgetWarning]:
        return _CAMOUFOX.check(fetch_timeout_seconds=fetch,
                               launch_timeout_seconds=launch,
                               nav_timeout_seconds=nav,
                               acquire_timeout_seconds=acquire)

    def test_navigation_floor_uses_the_given_launch_and_navigation(
            self) -> None:
        self.assertEqual(_conditions(self._check(70.0)), ["navigation"])
        self.assertEqual(self._check(70.5), [])
        self.assertEqual(self._check(35.0, launch=10.0, nav=20.0), [])

    def test_gate_counts_two_kill_waits_and_the_late_sweep(self) -> None:
        self.assertEqual(
            _conditions(self._check(89.0, acquire=100.0)), ["gate"])
        self.assertEqual(self._check(88.5, acquire=100.0), [])

    def test_messages(self) -> None:
        (navigation,) = self._check(70.0)
        self.assertEqual(
            navigation.message,
            "KERDOOS_CAMOUFOX_FETCH_TIMEOUT_SECONDS=70.0 is not above the "
            "camoufox tier's launch (30.0s) + navigation (40.0s) budget "
            "(70.0s) -- a fetch could be abandoned before the timeout it "
            "wraps ever gets a chance to fire.")
        (gate,) = self._check(89.0, acquire=100.0)
        self.assertEqual(
            gate.message,
            "KERDOOS_CAMOUFOX_FETCH_TIMEOUT_SECONDS=89.0 plus the cleanup it "
            "triggers (11.0s: two confirmed-death waits of 4.0s plus the "
            "late sweep's 3.0s grace) would hold the browser gate for "
            "100.0s, at or past KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS=100.0 "
            "-- another caller waiting for that gate could time out its own "
            "wait before this one ever frees it.")


class ReExportTest(unittest.TestCase):
    def test_chromium_executable_is_the_uc_tier_resolver(self) -> None:
        with mock.patch.object(uc, "_find_patchright_chromium",
                               return_value="/cache/chromium-1/chrome"):
            self.assertEqual(tiers.chromium_executable(),
                             "/cache/chromium-1/chrome")
        with mock.patch.object(uc, "_find_patchright_chromium",
                               return_value=None):
            self.assertIsNone(tiers.chromium_executable())

    def test_camoufox_install_contract(self) -> None:
        self.assertIs(tiers.camoufox_ready, camoufox.camoufox_ready)
        self.assertEqual(tiers.CAMOUFOX_BROWSER_VERSION,
                         camoufox.CAMOUFOX_BROWSER_VERSION)
        self.assertEqual(tiers.CAMOUFOX_EXECUTABLE_PATH,
                         camoufox.CAMOUFOX_EXECUTABLE_PATH)


class ToolFreeImportTest(unittest.TestCase):
    """Imports run in a child where every tool package is made unimportable."""

    @staticmethod
    def _run_with_tools_blocked(statement: str) -> subprocess.CompletedProcess:
        script = "\n".join([
            "import sys",
            f"for name in {_TOOLS!r}:",
            "    sys.modules[name] = None",
            statement,
        ])
        return subprocess.run([sys.executable, "-c", script],
                              capture_output=True, text=True, timeout=120)

    def test_tiers_imports_without_any_tool(self) -> None:
        proc = self._run_with_tools_blocked("import autolycos.tiers")
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_a_blocked_tool_really_fails_to_import(self) -> None:
        for tool in _TOOLS:
            with self.subTest(tool=tool):
                proc = self._run_with_tools_blocked(f"import {tool}")
                self.assertNotEqual(proc.returncode, 0, proc.stdout)


if __name__ == "__main__":
    unittest.main()
