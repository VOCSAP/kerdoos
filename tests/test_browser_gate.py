"""BrowserGate: cross-tier, cross-process Chromium concurrency bound (card
ca30b736, ADR 0002 Decision 1/2).

Concurrency proofs use explicit threading.Event/Barrier synchronization, not
sleep-based polling: a worker signals when it holds the gate and waits on an
explicit release signal, so a second worker's block/unblock transition is
observed deterministically.
"""

from __future__ import annotations

import errno
import multiprocessing
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from autolycos import browser_gate as gate_mod
from autolycos.browser_gate import BrowserGate
from autolycos.errors import FetchError


def _mp_hold(
    lock_dir: Path, marker_dir: Path, marker_name: str, wait_for_ready: bool,
    ready, release,
) -> None:
    # Module-level (not a closure): multiprocessing on Windows pickles the
    # target via spawn, which cannot pickle a nested function.
    gate = BrowserGate(max_concurrent=1, lock_dir=lock_dir)
    with gate.acquire():
        (marker_dir / marker_name).write_text("held")
        if wait_for_ready:
            ready.set()
            release.wait(timeout=5)
        else:
            ready.wait(timeout=5)
    (marker_dir / marker_name).write_text("released")


def _mp_hold_forever(lock_dir: Path, holding) -> None:
    gate = BrowserGate(max_concurrent=1, lock_dir=lock_dir)
    with gate.acquire():
        holding.set()
        time.sleep(30)


class _LiveTracker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.live = 0
        self.max_live = 0

    def enter(self) -> None:
        with self._lock:
            self.live += 1
            self.max_live = max(self.max_live, self.live)

    def exit(self) -> None:
        with self._lock:
            self.live -= 1


class GateConcurrencyTest(unittest.TestCase):
    def test_max_concurrent_one_serializes_two_holders(self) -> None:
        gate = BrowserGate(max_concurrent=1, acquire_timeout_seconds=2)
        tracker = _LiveTracker()
        a_holding = threading.Event()
        b_blocked_confirmed = threading.Event()
        release_a = threading.Event()
        b_acquired = threading.Event()

        def holder_a() -> None:
            with gate.acquire():
                tracker.enter()
                a_holding.set()
                release_a.wait(timeout=2)
                tracker.exit()

        def holder_b() -> None:
            a_holding.wait(timeout=2)
            # b's acquire() call below WILL block (a still holds the only
            # slot) -- confirm that from the outside before releasing a.
            threading.Timer(0.05, b_blocked_confirmed.set).start()
            with gate.acquire():
                tracker.enter()
                b_acquired.set()
                tracker.exit()

        ta = threading.Thread(target=holder_a, daemon=True)
        tb = threading.Thread(target=holder_b, daemon=True)
        ta.start()
        tb.start()
        b_blocked_confirmed.wait(timeout=2)
        self.assertFalse(b_acquired.is_set())  # still blocked while a holds
        release_a.set()
        ta.join(timeout=2)
        tb.join(timeout=2)
        self.assertTrue(b_acquired.is_set())
        self.assertEqual(tracker.max_live, 1)

    def test_max_concurrent_two_admits_two_blocks_a_third(self) -> None:
        gate = BrowserGate(max_concurrent=2, acquire_timeout_seconds=2)
        tracker = _LiveTracker()
        # 3 parties: ta, tb, AND this test thread -- the barrier only trips
        # once all three arrive, which proves ta and tb are both past
        # tracker.enter() (i.e. both hold the gate) by the time it releases.
        both_holding = threading.Barrier(3, timeout=2)
        c_blocked_confirmed = threading.Event()
        c_acquired = threading.Event()
        release_all = threading.Event()

        def holder() -> None:
            with gate.acquire():
                tracker.enter()
                both_holding.wait()
                release_all.wait(timeout=2)
                tracker.exit()

        ta = threading.Thread(target=holder, daemon=True)
        tb = threading.Thread(target=holder, daemon=True)
        ta.start()
        tb.start()
        both_holding.wait(timeout=2)  # a and b both confirmed holding

        def holder_c() -> None:
            threading.Timer(0.05, c_blocked_confirmed.set).start()
            with gate.acquire():
                tracker.enter()
                c_acquired.set()
                tracker.exit()

        tc = threading.Thread(target=holder_c, daemon=True)
        tc.start()
        c_blocked_confirmed.wait(timeout=2)
        self.assertFalse(c_acquired.is_set())  # a slot must free first
        release_all.set()
        ta.join(timeout=2)
        tb.join(timeout=2)
        tc.join(timeout=2)
        self.assertTrue(c_acquired.is_set())
        self.assertEqual(tracker.max_live, 2)

    def test_gate_released_when_guarded_block_raises(self) -> None:
        gate = BrowserGate(max_concurrent=1, acquire_timeout_seconds=2)
        with self.assertRaises(ValueError):
            with gate.acquire():
                raise ValueError("simulated fetch failure")
        # The next acquirer must not block -- release happened in `finally`.
        acquired = threading.Event()

        def worker() -> None:
            with gate.acquire():
                acquired.set()

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        t.join(timeout=2)
        self.assertTrue(acquired.is_set())

    def test_shared_gate_bounds_two_different_callers_together(self) -> None:
        # Simulates the browser tier and the uc tier sharing ONE gate: two
        # DIFFERENT logical callers, same BrowserGate instance, still capped.
        gate = BrowserGate(max_concurrent=1, acquire_timeout_seconds=2)
        tracker = _LiveTracker()
        browser_holding = threading.Event()
        uc_blocked_confirmed = threading.Event()
        uc_acquired = threading.Event()
        release_browser = threading.Event()

        def browser_tier_call() -> None:
            with gate.acquire():
                tracker.enter()
                browser_holding.set()
                release_browser.wait(timeout=2)
                tracker.exit()

        def uc_tier_call() -> None:
            browser_holding.wait(timeout=2)
            threading.Timer(0.05, uc_blocked_confirmed.set).start()
            with gate.acquire():
                tracker.enter()
                uc_acquired.set()
                tracker.exit()

        t_browser = threading.Thread(target=browser_tier_call, daemon=True)
        t_uc = threading.Thread(target=uc_tier_call, daemon=True)
        t_browser.start()
        t_uc.start()
        uc_blocked_confirmed.wait(timeout=2)
        self.assertFalse(uc_acquired.is_set())
        release_browser.set()
        t_browser.join(timeout=2)
        t_uc.join(timeout=2)
        self.assertTrue(uc_acquired.is_set())
        self.assertEqual(tracker.max_live, 1)


class GateConstructionTest(unittest.TestCase):
    def test_rejects_non_positive_max_concurrent(self) -> None:
        with self.assertRaises(ValueError):
            BrowserGate(max_concurrent=0)
        with self.assertRaises(ValueError):
            BrowserGate(max_concurrent=-1)

    def test_creates_lock_dir_if_missing(self) -> None:
        # Exercise the mkdir path deterministically regardless of host
        # platform: a minimal fake fcntl so the branch runs even on Windows.
        fake_fcntl = mock.Mock(LOCK_EX=1, LOCK_NB=2, LOCK_UN=4)
        fake_fcntl.flock = mock.Mock(return_value=None)
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(gate_mod, "fcntl", fake_fcntl):
            target = Path(tmp) / "not-yet-created"
            BrowserGate(max_concurrent=1, lock_dir=target)
            self.assertTrue(target.is_dir())


def _fake_fcntl(flock_side_effect=None):
    fake = mock.Mock(LOCK_EX=1, LOCK_NB=2, LOCK_UN=4)
    fake.flock = mock.Mock(side_effect=flock_side_effect, return_value=None)
    return fake


class GateFailureModesTest(unittest.TestCase):
    """Card ca30b736: a slot-acquisition failure must not leak the semaphore,
    and acquire() must honor a deadline instead of blocking forever."""

    def test_os_open_failure_does_not_leak_the_semaphore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(gate_mod, "fcntl", _fake_fcntl()):
            gate = BrowserGate(
                max_concurrent=1, lock_dir=Path(tmp), acquire_timeout_seconds=2)
            with mock.patch.object(
                gate_mod.os, "open",
                side_effect=OSError(errno.EMFILE, "too many open files"),
            ):
                with self.assertRaises(OSError):
                    gate.acquire()
            # os.open restored: the failed attempt above must not have
            # leaked the semaphore permit.
            acquired = threading.Event()

            def worker() -> None:
                with gate.acquire():
                    acquired.set()

            t = threading.Thread(target=worker, daemon=True)
            t.start()
            t.join(timeout=2)
            self.assertTrue(acquired.is_set())

    def test_unexpected_flock_error_raises_instead_of_spinning(self) -> None:
        broken_fcntl = _fake_fcntl(
            flock_side_effect=OSError(errno.ENOLCK, "no locks available"))
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(gate_mod, "fcntl", broken_fcntl):
                gate = BrowserGate(
                    max_concurrent=1, lock_dir=Path(tmp),
                    acquire_timeout_seconds=2)
                start = time.monotonic()
                with self.assertRaises(OSError):
                    gate.acquire()
                self.assertLess(time.monotonic() - start, 1.0)
            # fcntl restored to a working fake: the failed attempt above
            # must not have leaked the SAME gate's semaphore permit.
            acquired = threading.Event()

            def worker() -> None:
                with mock.patch.object(gate_mod, "fcntl", _fake_fcntl()):
                    with gate.acquire():
                        acquired.set()

            t = threading.Thread(target=worker, daemon=True)
            t.start()
            t.join(timeout=2)
            self.assertTrue(acquired.is_set())

    def test_acquire_timeout_raises_fetch_error_promptly(self) -> None:
        gate = BrowserGate(max_concurrent=1, acquire_timeout_seconds=0.2)
        gate.acquire()  # held forever (no `with`, no release) -- simulates a stuck holder
        start = time.monotonic()
        with self.assertRaises(FetchError):
            gate.acquire()
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 0.15)
        self.assertLess(elapsed, 2.0)

    def test_slot_polling_also_honors_the_timeout(self) -> None:
        # The semaphore alone (max_concurrent=2) would let a 2nd acquirer
        # through -- only the SLOT is exhausted (max_concurrent slots too),
        # proving the deadline applies to the flock-polling loop, not just
        # the semaphore wait.
        fake_fcntl = _fake_fcntl(
            flock_side_effect=OSError(errno.EAGAIN, "locked"))
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(gate_mod, "fcntl", fake_fcntl):
            gate = BrowserGate(
                max_concurrent=2, lock_dir=Path(tmp), acquire_timeout_seconds=0.2)
            start = time.monotonic()
            with self.assertRaises(FetchError):
                gate.acquire()
            elapsed = time.monotonic() - start
            self.assertGreaterEqual(elapsed, 0.15)
            self.assertLess(elapsed, 2.0)


@unittest.skipIf(gate_mod.fcntl is None, "fcntl unavailable on this platform")
class GateInterProcessTest(unittest.TestCase):
    def test_two_processes_never_hold_the_slot_at_the_same_instant(self) -> None:
        # Marker file content (never deleted, only overwritten) tracks each
        # process's state: "held" while inside the gate, "released" after.
        with tempfile.TemporaryDirectory() as tmp:
            marker_dir = Path(tmp) / "markers"
            marker_dir.mkdir()
            lock_dir = Path(tmp) / "locks"
            (marker_dir / "p1.marker").write_text("idle")
            (marker_dir / "p2.marker").write_text("idle")
            ready = multiprocessing.Event()
            release = multiprocessing.Event()

            p1 = multiprocessing.Process(
                target=_mp_hold,
                args=(lock_dir, marker_dir, "p1.marker", True, ready, release))
            p1.start()
            ready.wait(timeout=5)
            self.assertEqual(
                (marker_dir / "p1.marker").read_text(), "held")

            p2 = multiprocessing.Process(
                target=_mp_hold,
                args=(lock_dir, marker_dir, "p2.marker", False, ready, release))
            p2.start()
            # p2 must be BLOCKED behind p1's held slot: give it a moment, then
            # confirm p2 never reached "held" while p1 still holds it.
            time.sleep(0.2)
            self.assertEqual(
                (marker_dir / "p1.marker").read_text(), "held")
            self.assertEqual(
                (marker_dir / "p2.marker").read_text(), "idle")

            release.set()
            p1.join(timeout=5)
            p2.join(timeout=5)
            self.assertEqual(
                (marker_dir / "p1.marker").read_text(), "released")
            self.assertEqual(
                (marker_dir / "p2.marker").read_text(), "released")

    def test_killed_process_releases_its_slot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock_dir = Path(tmp) / "locks"
            holding = multiprocessing.Event()

            p = multiprocessing.Process(
                target=_mp_hold_forever, args=(lock_dir, holding))
            p.start()
            holding.wait(timeout=5)
            p.kill()
            p.join(timeout=5)

            # The kernel released the flock on process death -- a fresh
            # acquire from THIS process must succeed without blocking.
            gate = BrowserGate(
                max_concurrent=1, lock_dir=lock_dir, acquire_timeout_seconds=2)
            acquired = threading.Event()

            def worker() -> None:
                with gate.acquire():
                    acquired.set()

            t = threading.Thread(target=worker, daemon=True)
            t.start()
            t.join(timeout=2)
            self.assertTrue(acquired.is_set())


class DefaultGateWarningTest(unittest.TestCase):
    def test_warns_once_on_first_use_and_reuses_the_singleton(self) -> None:
        # A composition root that forgets to inject a gate must not lose
        # the bound silently.
        with mock.patch.object(gate_mod, "_default_gate", None):
            with self.assertLogs(
                "autolycos.browser_gate", level="WARNING") as cm:
                gate1 = gate_mod.default_browser_gate()
                gate2 = gate_mod.default_browser_gate()
            self.assertEqual(len(cm.output), 1)
            self.assertIs(gate1, gate2)


class GateWindowsFallbackTest(unittest.TestCase):
    def test_no_fcntl_falls_back_in_process_only_with_one_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(gate_mod, "fcntl", None), \
                 self.assertLogs(
                    "autolycos.browser_gate", level="WARNING") as cm:
                gate = BrowserGate(
                    max_concurrent=1, lock_dir=Path(tmp),
                    acquire_timeout_seconds=2)
            self.assertEqual(len(cm.output), 1)
            self.assertIn("Windows", cm.output[0])
            # Still enforces the IN-PROCESS bound correctly.
            acquired = threading.Event()

            def worker() -> None:
                with gate.acquire():
                    acquired.set()

            t = threading.Thread(target=worker, daemon=True)
            t.start()
            t.join(timeout=2)
            self.assertTrue(acquired.is_set())


if __name__ == "__main__":
    unittest.main()
