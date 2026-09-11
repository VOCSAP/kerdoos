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
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from kerdoos.core.app.services import AppService

logger = logging.getLogger(__name__)

_POLL_TIMEOUT_SECONDS = 0.5
# Fixed (not operator-configurable, unlike the restart CAP): bounds a
# persistently crashing consumer to a slow retry instead of a CPU hot loop.
_RESTART_BACKOFF_SECONDS = 0.5


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

    def __init__(
        self, service: AppService, max_consumer_restarts: int = 5,
        cooldown_seconds: float = 0, backlog_warn_threshold: int = 0,
    ) -> None:
        self._service = service
        self._max_consumer_restarts = max_consumer_restarts
        self._cooldown_seconds = cooldown_seconds
        self._backlog_warn_threshold = backlog_warn_threshold
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._queued_or_running: set[str] = set()
        self._status: dict[str, RunStatus] = {}
        # Debounce state for the backlog WARNING log (roadmap 3c557a9c item
        # 6): fires once when depth reaches the threshold, re-arms only
        # once depth has dropped back below it -- never a burst of one log
        # line per enqueue while the backlog stays high.
        self._backlog_warned = False
        # Cooldown elapsed time is measured on time.monotonic(), never
        # wall-clock: an NTP step (forward or back) must not shrink or
        # widen the window. finished_at (wall-clock ISO) stays purely for
        # display -- RunStatus keeps it, this dict is the cooldown source
        # of truth.
        self._done_monotonic: dict[str, float] = {}
        self._lock = asyncio.Lock()
        self._dead = False
        self._dead_reason: str | None = None
        # Crashes separated by a successfully processed item are unrelated
        # incidents, not a persistently broken consumer -- reset in
        # run_forever's success branch so the budget covers consecutive
        # failures, not the process's whole lifetime.
        self._restarts = 0

    @property
    def is_dead(self) -> bool:
        return self._dead

    @property
    def queued_count(self) -> int:
        """Number of DISTINCT owners currently queued or running. A plain
        read (no lock), same discipline as is_dead/status_for: the GIL
        makes this single set.__len__() call atomic regardless of which
        thread calls it (a sync route handler runs on a thread-pool
        worker, not the event loop), so there is no torn read to observe."""
        return len(self._queued_or_running)

    @property
    def backlog_warning_active(self) -> bool:
        """True once queued_count has reached the configured warning
        threshold (roadmap 3c557a9c item 6). threshold<=0 disables it."""
        if self._backlog_warn_threshold <= 0:
            return False
        return self.queued_count >= self._backlog_warn_threshold

    def _check_backlog_warning_locked(self) -> None:
        """Debounced WARNING log -- caller must already hold self._lock,
        so the depth read matches the mutation that just happened."""
        if self._backlog_warn_threshold <= 0:
            return
        depth = len(self._queued_or_running)
        if depth >= self._backlog_warn_threshold and not self._backlog_warned:
            self._backlog_warned = True
            logger.warning(
                "run_queue: backlog depth %d reached the warning "
                "threshold %d", depth, self._backlog_warn_threshold)
        elif depth < self._backlog_warn_threshold and self._backlog_warned:
            self._backlog_warned = False

    def cooldown_remaining_seconds(self, owner_id: str) -> float | None:
        """Seconds left before owner_id may enqueue again, or None if not
        in cooldown (disabled, never run, or last run isn't DONE -- a
        QUEUED/RUNNING/ERROR status never blocks a re-enqueue on this
        basis, only a recent successful one)."""
        if self._cooldown_seconds <= 0:
            return None
        status = self._status.get(owner_id)
        if status is None or status.state is not RunState.DONE:
            return None
        done_at = self._done_monotonic.get(owner_id)
        if done_at is None:
            return None
        remaining = self._cooldown_seconds - (time.monotonic() - done_at)
        return remaining if remaining > 0 else None

    async def enqueue(self, owner_id: str) -> bool:
        """Enqueue owner_id unless a run for it is already queued or
        running, or the owner is in its post-run cooldown (card 1af8b18b --
        bounds how often one tenant can hammer the shared browser gate and
        the shared egress IP's anti-bot reputation). Returns True iff this
        call actually enqueued it (False = silently coalesced into the
        existing one, refused by cooldown, OR refused because the consumer
        exhausted its restart budget -- status_for(owner_id) plus
        cooldown_remaining_seconds(owner_id) distinguish the three: ERROR
        for a dead-queue refusal, a non-None cooldown_remaining_seconds for
        a cooldown refusal (status stays DONE, untouched), QUEUED/RUNNING
        for a coalesce)."""
        if self._dead:
            async with self._lock:
                self._status[owner_id] = RunStatus(
                    state=RunState.ERROR, error=self._dead_reason)
            return False
        if self.cooldown_remaining_seconds(owner_id) is not None:
            # Deliberately does not touch self._status: overwriting it
            # would lose finished_at, breaking the cooldown window's own
            # computation on the NEXT refused attempt.
            return False
        async with self._lock:
            if owner_id in self._queued_or_running:
                return False
            self._queued_or_running.add(owner_id)
            self._status[owner_id] = RunStatus(state=RunState.QUEUED)
            self._check_backlog_warning_locked()
        await self._queue.put(owner_id)
        return True

    def status_for(self, owner_id: str) -> RunStatus | None:
        return self._status.get(owner_id)

    async def run_supervised(self, stop_event: asyncio.Event) -> None:
        """Top-level coroutine the composition root starts: restarts
        run_forever after an unexpected crash (a bug in the queue mechanics
        itself -- an individual owner's run_now failure is already isolated
        inside run_forever and never reaches here) up to
        max_consumer_restarts, logging each one. Beyond the cap, marks the
        queue dead instead of restarting forever."""
        while True:
            try:
                await self.run_forever(stop_event)
                return  # clean shutdown (stop_event set), not a crash
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 -- supervisor: isolate any crash
                self._restarts += 1
                logger.error(
                    "run_queue consumer crashed (restart %d/%d): %s",
                    self._restarts, self._max_consumer_restarts, exc,
                    exc_info=exc)
                dying = self._restarts > self._max_consumer_restarts
                async with self._lock:
                    for owner_id, status in list(self._status.items()):
                        # Only the RUNNING owner's item was lost (already
                        # popped from _queue by the crashed run_forever).
                        # A QUEUED owner's item is still physically sitting
                        # in _queue -- discarding it from
                        # _queued_or_running here would let a re-enqueue
                        # add a second copy, processed twice back-to-back
                        # once the consumer restarts.
                        if status.state is RunState.RUNNING or (
                            dying and status.state is RunState.QUEUED
                        ):
                            self._status[owner_id] = RunStatus(
                                state=RunState.ERROR,
                                error="run_queue consumer crashed")
                            self._queued_or_running.discard(owner_id)
                    self._check_backlog_warning_locked()
                if stop_event.is_set():
                    return
                if dying:
                    self._dead = True
                    self._dead_reason = (
                        f"run_queue consumer crashed {self._restarts} "
                        "times, exceeding the restart budget")
                    return
                await asyncio.sleep(_RESTART_BACKOFF_SECONDS)

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
                    self._done_monotonic[owner_id] = time.monotonic()
                    self._restarts = 0
            finally:
                async with self._lock:
                    self._queued_or_running.discard(owner_id)
                    self._check_backlog_warning_locked()
                self._queue.task_done()
