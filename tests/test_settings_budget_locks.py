"""Each tier budget condition warns once per process, independently of the
other condition of the same tier."""

from __future__ import annotations

import os
import unittest

import kerdoos.config as kerdoos_config
from kerdoos.config import get_settings

_LATCHES = (
    "_browser_fetch_timeout_below_launch_warned",
    "_browser_fetch_timeout_above_acquire_warned",
    "_uc_fetch_timeout_below_navigation_warned",
    "_uc_fetch_timeout_above_acquire_warned",
    "_camoufox_fetch_timeout_below_navigation_warned",
    "_camoufox_fetch_timeout_above_acquire_warned",
)

# Both conditions of the named tier fire together under these settings.
_TIERS = {
    "browser": ("KERDOOS_BROWSER_FETCH_TIMEOUT_SECONDS=", {
        "KERDOOS_BROWSER_LAUNCH_TIMEOUT_SECONDS": "40",
        "KERDOOS_BROWSER_FETCH_TIMEOUT_SECONDS": "50",
        "KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS": "50",
    }),
    "uc": ("KERDOOS_UC_FETCH_TIMEOUT_SECONDS=", {
        "KERDOOS_UC_FETCH_TIMEOUT_SECONDS": "20",
        "KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS": "40",
    }),
    "camoufox": ("KERDOOS_CAMOUFOX_FETCH_TIMEOUT_SECONDS=", {
        "KERDOOS_CAMOUFOX_LAUNCH_TIMEOUT_SECONDS": "30",
        "KERDOOS_CAMOUFOX_NAV_TIMEOUT_SECONDS": "40",
        "KERDOOS_CAMOUFOX_FETCH_TIMEOUT_SECONDS": "70",
        "KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS": "80",
    }),
}


class BudgetWarningLatchTest(unittest.TestCase):
    def setUp(self) -> None:
        names = {name for _, env in _TIERS.values() for name in env}
        names.add("KERDOOS_UC_ORPHAN_SWEEP_DELAY_SECONDS")
        self._saved_env = {name: os.environ.pop(name, None) for name in names}
        self._saved_latches = {
            name: getattr(kerdoos_config, name) for name in _LATCHES}
        for name in _LATCHES:
            setattr(kerdoos_config, name, False)

    def tearDown(self) -> None:
        for name, value in self._saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        for name, value in self._saved_latches.items():
            setattr(kerdoos_config, name, value)

    def test_both_conditions_warn_once_each_across_repeated_reads(self) -> None:
        for tier, (prefix, env) in _TIERS.items():
            with self.subTest(tier=tier):
                for name in _LATCHES:
                    setattr(kerdoos_config, name, False)
                os.environ.update(env)
                try:
                    with self.assertLogs("kerdoos.config", "WARNING") as cm:
                        get_settings()
                        get_settings()
                        get_settings()
                finally:
                    for name in env:
                        os.environ.pop(name, None)
                records = [record for record in cm.records
                           if record.getMessage().startswith(prefix)]
                self.assertEqual(len(records), 2,
                                 [record.getMessage() for record in records])
                self.assertEqual(len({record.msg for record in records}), 2,
                                 "both conditions logged the same template")
                for record in records:
                    self.assertTrue(
                        record.msg.startswith(prefix) and record.args,
                        f"pre-formatted log record: msg={record.msg!r}")


if __name__ == "__main__":
    unittest.main()
