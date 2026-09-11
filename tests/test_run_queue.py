"""RunQueue: background run_now with per-owner coalescing (card ca30b736
tranche 2). Unit-level tests drive run_forever directly with a fake
AppService double; no real scrape, no real HTTP.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
import unittest
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


if __name__ == "__main__":
    unittest.main()
