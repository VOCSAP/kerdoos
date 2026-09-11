"""RunQueue: background run_now with per-owner coalescing (card ca30b736
tranche 2). Unit-level tests drive run_forever directly with a fake
AppService double; no real scrape, no real HTTP.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from kerdoos.core.run_queue import RunQueue, RunState, RunStatus


class _FakeService:
    """Records calls; run_now blocks on a per-owner threading.Event until
    released, so a test can observe the 'running' state deterministically
    before letting it complete."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self._release: dict[str, threading.Event] = {}
        self._entered: dict[str, threading.Event] = {}
        self.raise_for: set[str] = set()

    def gate(self, owner_id: str) -> None:
        self._release[owner_id] = threading.Event()
        self._entered[owner_id] = threading.Event()

    def release(self, owner_id: str) -> None:
        self._release[owner_id].set()

    def wait_entered(self, owner_id: str, timeout: float = 2) -> bool:
        return self._entered[owner_id].wait(timeout=timeout)

    def run_now(self, owner_id: str):  # noqa: ANN001 -- test double
        self.calls.append(owner_id)
        if owner_id in self._entered:
            self._entered[owner_id].set()
        if owner_id in self._release:
            self._release[owner_id].wait(timeout=2)
        if owner_id in self.raise_for:
            raise RuntimeError(f"simulated failure for {owner_id}")


class RunQueueTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.service = _FakeService()
        self.queue = RunQueue(self.service)
        self.stop = asyncio.Event()
        self.consumer = asyncio.create_task(self.queue.run_forever(self.stop))

    async def asyncTearDown(self) -> None:
        self.stop.set()
        self.consumer.cancel()
        try:
            await self.consumer
        except asyncio.CancelledError:
            pass

    async def test_enqueue_runs_and_marks_done(self) -> None:
        self.assertTrue(await self.queue.enqueue("owner1"))
        for _ in range(200):
            status = self.queue.status_for("owner1")
            if status is not None and status.state == RunState.DONE:
                break
            await asyncio.sleep(0.01)
        status = self.queue.status_for("owner1")
        self.assertEqual(status.state, RunState.DONE)
        self.assertIsNotNone(status.finished_at)
        self.assertEqual(self.service.calls, ["owner1"])

    async def test_second_enqueue_while_running_is_coalesced(self) -> None:
        self.service.gate("owner1")
        self.assertTrue(await self.queue.enqueue("owner1"))
        await asyncio.get_event_loop().run_in_executor(
            None, self.service.wait_entered, "owner1")
        self.assertEqual(
            self.queue.status_for("owner1").state, RunState.RUNNING)
        self.assertFalse(await self.queue.enqueue("owner1"))  # coalesced
        self.service.release("owner1")
        for _ in range(200):
            if self.queue.status_for("owner1").state == RunState.DONE:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(self.service.calls, ["owner1"])  # exactly once

    async def test_owner_error_recorded_next_owner_still_runs(self) -> None:
        self.service.raise_for.add("bad-owner")
        await self.queue.enqueue("bad-owner")
        for _ in range(200):
            status = self.queue.status_for("bad-owner")
            if status is not None and status.state == RunState.ERROR:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(status.state, RunState.ERROR)
        self.assertIn("simulated failure", status.error)

        await self.queue.enqueue("good-owner")
        for _ in range(200):
            status = self.queue.status_for("good-owner")
            if status is not None and status.state == RunState.DONE:
                break
            await asyncio.sleep(0.01)
        self.assertEqual(status.state, RunState.DONE)

    async def test_unknown_owner_status_is_none(self) -> None:
        self.assertIsNone(self.queue.status_for("never-run"))

    async def test_queued_state_visible_before_consumer_picks_it_up(self) -> None:
        # Stop the consumer so the item stays QUEUED, observably.
        self.stop.set()
        self.consumer.cancel()
        try:
            await self.consumer
        except asyncio.CancelledError:
            pass
        await self.queue.enqueue("owner1")
        self.assertEqual(
            self.queue.status_for("owner1").state, RunState.QUEUED)


class RunSupervisedTest(unittest.IsolatedAsyncioTestCase):
    """run_supervised (card 65cef071) restarts run_forever after an
    unexpected crash, up to max_consumer_restarts."""

    async def test_restart_after_crash_processes_next_enqueue(self) -> None:
        service = _FakeService()
        queue = RunQueue(service, max_consumer_restarts=2)
        stop = asyncio.Event()
        real_run_forever = RunQueue.run_forever
        calls = {"n": 0}

        async def _flaky_run_forever(self: RunQueue, stop_event: asyncio.Event) -> None:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("simulated consumer crash")
            await real_run_forever(self, stop_event)

        with mock.patch.object(RunQueue, "run_forever", _flaky_run_forever):
            supervised = asyncio.create_task(queue.run_supervised(stop))
            self.assertTrue(await queue.enqueue("owner1"))
            status = None
            for _ in range(300):
                status = queue.status_for("owner1")
                if status is not None and status.state == RunState.DONE:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(status.state, RunState.DONE)
            self.assertFalse(queue.is_dead)
            stop.set()
            supervised.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await supervised

    async def test_restart_cap_exceeded_marks_dead_and_refuses_enqueue(self) -> None:
        service = _FakeService()
        queue = RunQueue(service, max_consumer_restarts=1)
        stop = asyncio.Event()
        queue._queued_or_running.add("stuck-owner")
        queue._status["stuck-owner"] = RunStatus(state=RunState.RUNNING)

        async def _always_crash(self: RunQueue, stop_event: asyncio.Event) -> None:
            raise RuntimeError("simulated persistent crash")

        with mock.patch.object(RunQueue, "run_forever", _always_crash):
            await queue.run_supervised(stop)  # returns once dead, no task needed

        self.assertTrue(queue.is_dead)
        self.assertEqual(
            queue.status_for("stuck-owner").state, RunState.ERROR)

        enqueued = await queue.enqueue("new-owner")
        self.assertFalse(enqueued)
        status = queue.status_for("new-owner")
        self.assertEqual(status.state, RunState.ERROR)
        self.assertIn("restart budget", status.error)

    async def test_restart_counter_resets_after_a_successful_run(self) -> None:
        # Two crashes separated by a successful run are unrelated
        # incidents, not one persistently broken consumer -- the budget
        # must not accumulate across them.
        service = _FakeService()
        queue = RunQueue(service, max_consumer_restarts=1)
        queue._restarts = 1  # simulate: one crash already recovered from
        stop = asyncio.Event()
        consumer = asyncio.create_task(queue.run_forever(stop))
        try:
            self.assertTrue(await queue.enqueue("owner1"))
            status = None
            for _ in range(300):
                status = queue.status_for("owner1")
                if status is not None and status.state == RunState.DONE:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(status.state, RunState.DONE)
            self.assertEqual(queue._restarts, 0)
        finally:
            stop.set()
            consumer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await consumer

        async def _crash_once(self: RunQueue, stop_event: asyncio.Event) -> None:
            raise RuntimeError("simulated consumer crash")

        fresh_stop = asyncio.Event()
        with mock.patch.object(RunQueue, "run_forever", _crash_once):
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(
                    queue.run_supervised(fresh_stop), timeout=0.2)
        self.assertEqual(queue._restarts, 1)
        self.assertFalse(queue.is_dead)

    async def test_queued_owners_flip_to_error_when_queue_dies(self) -> None:
        service = _FakeService()
        queue = RunQueue(service, max_consumer_restarts=0)
        stop = asyncio.Event()
        queue._queued_or_running.add("queued-owner")
        queue._status["queued-owner"] = RunStatus(state=RunState.QUEUED)

        async def _always_crash(self: RunQueue, stop_event: asyncio.Event) -> None:
            raise RuntimeError("simulated persistent crash")

        with mock.patch.object(RunQueue, "run_forever", _always_crash):
            await queue.run_supervised(stop)

        self.assertTrue(queue.is_dead)
        self.assertEqual(
            queue.status_for("queued-owner").state, RunState.ERROR)
        self.assertNotIn("queued-owner", queue._queued_or_running)

    async def test_non_fatal_crash_keeps_queued_owner_in_flight(self) -> None:
        # A QUEUED owner's item is still physically in the asyncio.Queue
        # after a non-fatal crash -- dropping it from _queued_or_running
        # would let a re-enqueue add a duplicate, processed twice in a row.
        service = _FakeService()
        queue = RunQueue(service, max_consumer_restarts=5)
        stop = asyncio.Event()
        queue._queued_or_running.add("running-owner")
        queue._status["running-owner"] = RunStatus(state=RunState.RUNNING)
        queue._queued_or_running.add("queued-owner")
        queue._status["queued-owner"] = RunStatus(state=RunState.QUEUED)

        async def _crash_once(self: RunQueue, stop_event: asyncio.Event) -> None:
            raise RuntimeError("simulated consumer crash")

        with mock.patch.object(RunQueue, "run_forever", _crash_once):
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(queue.run_supervised(stop), timeout=0.2)

        self.assertNotIn("running-owner", queue._queued_or_running)
        self.assertIn("queued-owner", queue._queued_or_running)
        self.assertEqual(
            queue.status_for("queued-owner").state, RunState.QUEUED)
        self.assertEqual(
            queue.status_for("running-owner").state, RunState.ERROR)


class CooldownTest(unittest.IsolatedAsyncioTestCase):
    """Card 1af8b18b: cooldown_seconds bounds how often ONE owner may
    re-enqueue after their last successful run_now."""

    async def test_second_enqueue_within_cooldown_is_refused(self) -> None:
        service = _FakeService()
        queue = RunQueue(service, cooldown_seconds=300)
        finished = datetime.now(timezone.utc).isoformat()
        queue._status["owner1"] = RunStatus(
            state=RunState.DONE, finished_at=finished)
        queue._done_monotonic["owner1"] = time.monotonic()

        self.assertFalse(await queue.enqueue("owner1"))

        remaining = queue.cooldown_remaining_seconds("owner1")
        self.assertIsNotNone(remaining)
        self.assertGreater(remaining, 0)
        self.assertLessEqual(remaining, 300)
        # The refusal must not touch the DONE status -- overwriting
        # finished_at would break the cooldown window's own computation
        # on the next attempt.
        status = queue.status_for("owner1")
        self.assertEqual(status.state, RunState.DONE)
        self.assertEqual(status.finished_at, finished)

    async def test_enqueue_accepted_after_cooldown_elapses(self) -> None:
        service = _FakeService()
        queue = RunQueue(service, cooldown_seconds=1)
        old = (datetime.now(timezone.utc) - timedelta(seconds=2)).isoformat()
        queue._status["owner1"] = RunStatus(
            state=RunState.DONE, finished_at=old)
        queue._done_monotonic["owner1"] = time.monotonic() - 2

        self.assertIsNone(queue.cooldown_remaining_seconds("owner1"))
        self.assertTrue(await queue.enqueue("owner1"))

    async def test_cooldown_disabled_by_default(self) -> None:
        service = _FakeService()
        queue = RunQueue(service)  # cooldown_seconds=0 default
        finished = datetime.now(timezone.utc).isoformat()
        queue._status["owner1"] = RunStatus(
            state=RunState.DONE, finished_at=finished)
        queue._done_monotonic["owner1"] = time.monotonic()

        self.assertIsNone(queue.cooldown_remaining_seconds("owner1"))
        self.assertTrue(await queue.enqueue("owner1"))

    async def test_non_done_status_never_cooldown_refused(self) -> None:
        service = _FakeService()
        queue = RunQueue(service, cooldown_seconds=300)
        for state in (RunState.QUEUED, RunState.RUNNING, RunState.ERROR):
            with self.subTest(state=state):
                queue._status["owner-x"] = RunStatus(state=state)
                self.assertIsNone(
                    queue.cooldown_remaining_seconds("owner-x"))

    async def test_cooldown_isolated_per_owner(self) -> None:
        service = _FakeService()
        queue = RunQueue(service, cooldown_seconds=300)
        finished = datetime.now(timezone.utc).isoformat()
        queue._status["owner-a"] = RunStatus(
            state=RunState.DONE, finished_at=finished)
        queue._done_monotonic["owner-a"] = time.monotonic()

        self.assertFalse(await queue.enqueue("owner-a"))
        self.assertTrue(await queue.enqueue("owner-b"))
        self.assertIsNone(queue.cooldown_remaining_seconds("owner-b"))

    async def test_ntp_wall_clock_jump_does_not_affect_cooldown(self) -> None:
        # NIT (gate 1af8b18b): elapsed time must come from time.monotonic(),
        # not the wall clock -- a backward NTP step on finished_at (wall
        # clock, display-only) must not fool the cooldown into expiring
        # early or never.
        service = _FakeService()
        queue = RunQueue(service, cooldown_seconds=300)
        # finished_at claims a run 10 minutes ago (would normally have
        # elapsed the cooldown), but the monotonic clock says it JUST
        # finished -- monotonic must win.
        stale_wall_clock = (
            datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        queue._status["owner1"] = RunStatus(
            state=RunState.DONE, finished_at=stale_wall_clock)
        queue._done_monotonic["owner1"] = time.monotonic()

        self.assertIsNotNone(queue.cooldown_remaining_seconds("owner1"))
        self.assertFalse(await queue.enqueue("owner1"))


class BacklogWarningTest(unittest.IsolatedAsyncioTestCase):
    """roadmap 3c557a9c item 6: queued_count / backlog_warning_active and
    the debounced WARNING log."""

    async def asyncSetUp(self) -> None:
        self.service = _FakeService()
        self.queue = RunQueue(self.service, backlog_warn_threshold=2)
        self.stop = asyncio.Event()
        self.consumer = asyncio.create_task(self.queue.run_forever(self.stop))

    async def asyncTearDown(self) -> None:
        self.stop.set()
        self.consumer.cancel()
        try:
            await self.consumer
        except asyncio.CancelledError:
            pass

    async def _block_consumer_on(self, owner_id: str) -> None:
        """Enqueue owner_id and wait until the single consumer has picked
        it up and entered run_now -- the consumer processes ONE owner at a
        time, so every owner enqueued AFTER this one stays QUEUED (not
        RUNNING) until this one is released, which is exactly what lets a
        backlog of several QUEUED owners build up behind it."""
        self.service.gate(owner_id)
        self.assertTrue(await self.queue.enqueue(owner_id))
        await asyncio.get_event_loop().run_in_executor(
            None, self.service.wait_entered, owner_id)

    async def _release_and_wait_drained(self, *owner_ids: str) -> None:
        for owner_id in owner_ids:
            self.service.release(owner_id)
        for _ in range(200):
            if self.queue.queued_count == 0:
                break
            await asyncio.sleep(0.01)

    async def test_queued_count_coalesces_same_owner(self) -> None:
        await self._block_consumer_on("owner1")
        self.assertFalse(await self.queue.enqueue("owner1"))  # coalesced
        self.assertEqual(self.queue.queued_count, 1)
        await self._release_and_wait_drained("owner1")

    async def test_queued_count_decrements_after_done(self) -> None:
        await self._block_consumer_on("owner1")
        self.assertEqual(self.queue.queued_count, 1)
        await self._release_and_wait_drained("owner1")
        self.assertEqual(self.queue.queued_count, 0)

    async def test_queued_count_decrements_after_error(self) -> None:
        self.service.raise_for.add("bad-owner")
        await self._block_consumer_on("bad-owner")
        self.assertEqual(self.queue.queued_count, 1)
        await self._release_and_wait_drained("bad-owner")
        self.assertEqual(self.queue.queued_count, 0)

    async def test_backlog_warning_active_once_threshold_reached(self) -> None:
        self.assertFalse(self.queue.backlog_warning_active)
        # owner1 blocks the consumer; owner2 stays QUEUED behind it -- both
        # still count toward queued_count.
        await self._block_consumer_on("owner1")
        self.assertFalse(self.queue.backlog_warning_active)  # depth 1 < 2
        self.assertTrue(await self.queue.enqueue("owner2"))
        self.assertTrue(self.queue.backlog_warning_active)  # depth 2 >= 2
        await self._release_and_wait_drained("owner1")

    async def test_backlog_warning_log_fires_once_then_rearms(self) -> None:
        with self.assertLogs(
            "kerdoos.core.run_queue", level="WARNING",
        ) as first_crossing:
            await self._block_consumer_on("owner1")
            self.assertTrue(await self.queue.enqueue("owner2"))
            # Depth 3, still >= threshold -- must NOT log a second time.
            self.assertTrue(await self.queue.enqueue("owner3"))
        self.assertEqual(
            sum(1 for msg in first_crossing.output if "backlog depth" in msg),
            1, first_crossing.output)

        # owner2/owner3 were never gated -- they run to completion on
        # their own as soon as the consumer reaches them, only owner1
        # needs an explicit release.
        await self._release_and_wait_drained("owner1")
        self.assertFalse(self.queue.backlog_warning_active)

        with self.assertLogs(
            "kerdoos.core.run_queue", level="WARNING",
        ) as second_crossing:
            await self._block_consumer_on("owner4")
            self.assertTrue(await self.queue.enqueue("owner5"))
        self.assertEqual(
            sum(1 for msg in second_crossing.output if "backlog depth" in msg),
            1, second_crossing.output)
        await self._release_and_wait_drained("owner4")


class BacklogWarningDisabledTest(unittest.IsolatedAsyncioTestCase):
    async def test_zero_threshold_disables_warning(self) -> None:
        service = _FakeService()
        queue = RunQueue(service, backlog_warn_threshold=0)
        stop = asyncio.Event()
        consumer = asyncio.create_task(queue.run_forever(stop))
        try:
            service.gate("owner1")
            self.assertTrue(await queue.enqueue("owner1"))
            await asyncio.get_event_loop().run_in_executor(
                None, service.wait_entered, "owner1")
            self.assertFalse(queue.backlog_warning_active)
            service.release("owner1")
        finally:
            stop.set()
            consumer.cancel()
            try:
                await consumer
            except asyncio.CancelledError:
                pass


if __name__ == "__main__":
    unittest.main()
