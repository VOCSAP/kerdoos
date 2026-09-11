"""Background run_now queue (card ca30b736): POST /run enqueues and returns
immediately (invariant 9) instead of blocking on a scrape. ONE consumer,
started in the WebUI lifespan alongside core.evaluator's run_evaluator_loop.
Single-process in-memory state (same workers=1 assumption as the digest
evaluator, ADR 0003 Decision 4): a restart forgets in-flight status, not the
already-written ScrapeRecords. RunState is a run-JOB lifecycle axis
(queued/running/done/error), orthogonal to ScrapeStatus -- not a 4th value
on that enum (invariant 3 untouched).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from kerdoos.core.app.services import AppService

logger = logging.getLogger(__name__)

_POLL_TIMEOUT_SECONDS = 0.5


class RunState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class RunStatus:
    state: RunState
    finished_at: str | None = None
    error: str | None = None


class RunQueue:
    """In-memory, single-process run_now queue with per-owner coalescing."""

    def __init__(self, service: AppService) -> None:
        self._service = service
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._queued_or_running: set[str] = set()
        self._status: dict[str, RunStatus] = {}
        self._lock = asyncio.Lock()

    async def enqueue(self, owner_id: str) -> bool:
        """Enqueue owner_id unless a run for it is already queued or
        running. Returns True iff this call actually enqueued it (False =
        silently coalesced into the existing one)."""
        async with self._lock:
            if owner_id in self._queued_or_running:
                return False
            self._queued_or_running.add(owner_id)
            self._status[owner_id] = RunStatus(state=RunState.QUEUED)
        await self._queue.put(owner_id)
        return True

    def status_for(self, owner_id: str) -> RunStatus | None:
        return self._status.get(owner_id)

    def handle_consumer_crash(self, task: asyncio.Task) -> None:
        """asyncio.Task.add_done_callback target for run_forever. Each
        owner's own exception is already isolated inside the loop, so this
        only fires on a genuinely unexpected crash -- log it and clear the
        in-flight set, or every coalesced owner would stay stuck 'running'
        forever against a consumer that no longer exists."""
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            logger.error("run_queue consumer crashed: %s", exc, exc_info=exc)
            self._queued_or_running.clear()

    async def run_forever(self, stop_event: asyncio.Event) -> None:
        """Consumer loop. Polls with a short timeout (rather than blocking
        forever on queue.get()) so it can observe stop_event and exit
        promptly on shutdown, instead of leaving lifespan teardown to rely
        purely on task cancellation."""
        while not stop_event.is_set():
            try:
                owner_id = await asyncio.wait_for(
                    self._queue.get(), timeout=_POLL_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                continue
            async with self._lock:
                self._status[owner_id] = RunStatus(state=RunState.RUNNING)
            try:
                await asyncio.to_thread(self._service.run_now, owner_id)
            except Exception as exc:  # noqa: BLE001 -- one owner must not kill the consumer
                logger.warning(
                    "run_now failed for owner=%s: %s", owner_id, exc)
                async with self._lock:
                    self._status[owner_id] = RunStatus(
                        state=RunState.ERROR, error=str(exc))
            else:
                finished_at = datetime.now(timezone.utc).isoformat()
                async with self._lock:
                    self._status[owner_id] = RunStatus(
                        state=RunState.DONE, finished_at=finished_at)
            finally:
                async with self._lock:
                    self._queued_or_running.discard(owner_id)
                self._queue.task_done()
