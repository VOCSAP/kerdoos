"""compute_window_start quantization (ADR 0003 Phase 6b, architect finding
#5): the core exactly-once scheduling primitive."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from kerdoos.core.scheduler import compute_window_start


class ComputeWindowStartTest(unittest.TestCase):
    def test_inclusive_on_exact_cron_boundary(self) -> None:
        # Daily job at 09:00 America/Sao_Paulo (UTC-3, no DST since 2019) --
        # now landing EXACTLY on the boundary must return THAT occurrence,
        # not the previous day's (the off-by-one the epsilon fix targets).
        now = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)  # 09:00 local
        window = compute_window_start("0 9 * * *", "America/Sao_Paulo", now)
        self.assertEqual(window, "2026-07-13T12:00:00+00:00")

    def test_one_second_after_boundary_same_window(self) -> None:
        now = datetime(2026, 7, 13, 12, 0, 1, tzinfo=timezone.utc)
        window = compute_window_start("0 9 * * *", "America/Sao_Paulo", now)
        self.assertEqual(window, "2026-07-13T12:00:00+00:00")

    def test_one_second_before_boundary_previous_window(self) -> None:
        now = datetime(2026, 7, 13, 11, 59, 59, tzinfo=timezone.utc)
        window = compute_window_start("0 9 * * *", "America/Sao_Paulo", now)
        self.assertEqual(window, "2026-07-12T12:00:00+00:00")

    def test_daily_job_stable_window_across_90_minutes_of_60s_ticks(self) -> None:
        # The regression this tranche exists to prevent: a daily job ticked
        # every 60s must NOT re-fire on every tick -- window_start must stay
        # constant for every tick within the same day's occurrence window.
        base = datetime(2026, 7, 13, 12, 0, 0, tzinfo=timezone.utc)  # 09:00 local
        windows = {
            compute_window_start("0 9 * * *", "America/Sao_Paulo", base + timedelta(seconds=60 * i))
            for i in range(90)
        }
        self.assertEqual(windows, {"2026-07-13T12:00:00+00:00"})

    def test_hourly_job_utc(self) -> None:
        now = datetime(2026, 7, 13, 14, 37, 0, tzinfo=timezone.utc)
        window = compute_window_start("0 * * * *", "UTC", now)
        self.assertEqual(window, "2026-07-13T14:00:00+00:00")

    def test_naive_now_treated_as_utc(self) -> None:
        now = datetime(2026, 7, 13, 14, 37, 0)  # naive
        window = compute_window_start("0 * * * *", "UTC", now)
        self.assertEqual(window, "2026-07-13T14:00:00+00:00")

    def test_dst_transition_uses_job_local_wall_clock(self) -> None:
        # America/New_York observes DST: on 2026-03-08 clocks spring forward
        # 02:00 -> 03:00 EST->EDT (offset UTC-5 -> UTC-4). A daily job at
        # 09:00 local must resolve to 09:00 EDT (13:00 UTC) the day AFTER the
        # transition, not naive UTC arithmetic carried over from EST
        # (which would incorrectly compute 14:00 UTC).
        before_transition = datetime(2026, 3, 7, 14, 0, 0, tzinfo=timezone.utc)  # 09:00 EST
        after_transition = datetime(2026, 3, 9, 13, 0, 0, tzinfo=timezone.utc)   # 09:00 EDT
        self.assertEqual(
            compute_window_start("0 9 * * *", "America/New_York", before_transition),
            "2026-03-07T14:00:00+00:00",
        )
        self.assertEqual(
            compute_window_start("0 9 * * *", "America/New_York", after_transition),
            "2026-03-09T13:00:00+00:00",
        )


if __name__ == "__main__":
    unittest.main()
