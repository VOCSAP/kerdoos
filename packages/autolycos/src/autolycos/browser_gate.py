"""Cross-tier, cross-process browser concurrency gate (card ca30b736).

Bounds the number of Chromium processes alive at once -- the patchright
`browser` tier AND the seleniumbase `uc` tier, which reuses the SAME
Chromium binary -- to KERDOOS_BROWSER_MAX_CONCURRENT. This is the OOM
coherence guarantee ADR 0002 Decision 1 picked the intra-process scheduler
FOR, that no code previously enforced. Lives in autolycos, never core
(invariant 1), and never reads the environment itself (invariant 2): the
composition root reads KERDOOS_BROWSER_MAX_CONCURRENT and injects the value
(plus a lock directory) when it builds the router/fetchers.

Two layers, both bounded by the SAME max_concurrent, both acquired around a
fetch's launch-to-close cycle:

  * in-process: a threading.BoundedSemaphore, always active. Bounds every
    caller in THIS process (the sync WebUI route's threadpool thread, the
    evaluator's asyncio.to_thread worker, a future MCP call) without any of
    them having to remember to take it themselves -- the fetcher's fetch()
    does, once (card 3aeb8a19's lesson: a guard duplicated per call site
    eventually misses one).
  * inter-process (Option A, best-effort): N `browser-slot-<i>.lock` files
    in a shared directory (KERDOOS_STATE_DB's directory in production, so
    every process sharing that volume shares the gate), each guarded by a
    non-blocking fcntl.flock retried in a poll loop. The kernel releases a
    flock automatically when the holding process dies -- no orphaned-lock
    cleanup, unlike a DB-backed counter. Windows (dev) has no fcntl: this
    layer no-ops with one explicit warning, degrading to the in-process-only
    bound -- never promising more than the code holds.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from pathlib import Path
from types import TracebackType

logger = logging.getLogger(__name__)

try:
    import fcntl
except ImportError:  # Windows (dev) -- no advisory file locking.
    fcntl = None  # type: ignore[assignment]

_POLL_INTERVAL_SECONDS = 0.05


class BrowserGate:
    """Acquire around a Chromium launch-to-close cycle, release in `finally`
    (use as `with gate.acquire(): ...`)."""

    def __init__(
        self, max_concurrent: int = 1,
        lock_dir: str | os.PathLike | None = None,
    ) -> None:
        if max_concurrent < 1:
            raise ValueError(
                f"max_concurrent must be >= 1, got {max_concurrent!r}")
        self._semaphore = threading.BoundedSemaphore(max_concurrent)
        self._max_concurrent = max_concurrent
        self._slot_paths: tuple[Path, ...] | None = None
        if lock_dir is None:
            return
        if fcntl is None:
            logger.warning(
                "KERDOOS_BROWSER_MAX_CONCURRENT is only enforced WITHIN this "
                "process on this platform (fcntl is unavailable, e.g. "
                "Windows) -- separate processes launching Chromium are NOT "
                "bounded against each other."
            )
            return
        lock_path = Path(lock_dir)
        lock_path.mkdir(parents=True, exist_ok=True)
        self._slot_paths = tuple(
            lock_path / f"browser-slot-{i}.lock" for i in range(max_concurrent))

    def acquire(self) -> "_BrowserGateHold":
        self._semaphore.acquire()
        fd = self._acquire_slot() if self._slot_paths else None
        return _BrowserGateHold(self, fd)

    def _acquire_slot(self) -> int:
        assert self._slot_paths is not None
        assert fcntl is not None
        while True:
            for path in self._slot_paths:
                fd = os.open(str(path), os.O_CREAT | os.O_RDWR)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    os.close(fd)
                    continue
                return fd
            time.sleep(_POLL_INTERVAL_SECONDS)

    def _release(self, fd: int | None) -> None:
        if fd is not None:
            assert fcntl is not None
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        self._semaphore.release()


class _BrowserGateHold:
    def __init__(self, gate: BrowserGate, fd: int | None) -> None:
        self._gate = gate
        self._fd = fd

    def __enter__(self) -> "_BrowserGateHold":
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None,
        exc: BaseException | None, tb: TracebackType | None,
    ) -> None:
        self._gate._release(self._fd)


_default_gate: BrowserGate | None = None


def default_browser_gate() -> BrowserGate:
    """Lazy in-process-only singleton (max_concurrent=1, no lock_dir): the
    fallback for any Fetcher constructed without an explicit gate, so it is
    never possible to build one that is not bounded AT ALL."""
    global _default_gate
    if _default_gate is None:
        _default_gate = BrowserGate(max_concurrent=1)
    return _default_gate
