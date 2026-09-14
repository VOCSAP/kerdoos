"""Cross-tier, cross-process browser concurrency gate (card ca30b736).

Bounds how many browsers run at once -- `browser` and `uc` (Chromium) and
`camoufox` (Firefox) share ONE gate. In-process via threading.BoundedSemaphore; cross-process, when
lock_dir is given, via N `browser-slot-<i>.lock` files (fcntl.flock,
POSIX-only, Windows falls back in-process-only). Never reads the
environment (invariant 2): all parameters are injected by the caller.
"""

from __future__ import annotations

import errno
import logging
import os
import threading
import time
from pathlib import Path
from types import TracebackType

from .errors import FetchError

logger = logging.getLogger(__name__)

try:
    import fcntl
except ImportError:  # Windows (dev) -- no advisory file locking.
    fcntl = None  # type: ignore[assignment]

_POLL_INTERVAL_SECONDS = 0.05
# O_NOFOLLOW is POSIX-only (CWE-59 symlink guard); Windows never reaches
# this code path for real (fcntl is None there), but a 0 no-op keeps the
# constant safe to reference under test mocking on any platform.
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


class BrowserGate:
    """Acquire around a Chromium launch-to-close cycle, release in `finally`
    (use as `with gate.acquire(): ...`)."""

    def __init__(
        self, max_concurrent: int = 1,
        lock_dir: str | os.PathLike | None = None,
        acquire_timeout_seconds: float | None = None,
    ) -> None:
        if max_concurrent < 1:
            raise ValueError(
                f"max_concurrent must be >= 1, got {max_concurrent!r}")
        self._semaphore = threading.BoundedSemaphore(max_concurrent)
        self._max_concurrent = max_concurrent
        self._acquire_timeout_seconds = acquire_timeout_seconds
        self._slot_paths: tuple[Path, ...] | None = None
        if lock_dir is None:
            return
        if fcntl is None:
            logger.warning(
                "BrowserGate(max_concurrent=%d) is only enforced WITHIN this "
                "process on this platform (fcntl is unavailable, e.g. "
                "Windows) -- separate processes launching Chromium are NOT "
                "bounded against each other.", max_concurrent)
            return
        lock_path = Path(lock_dir)
        lock_path.mkdir(parents=True, exist_ok=True)
        self._slot_paths = tuple(
            lock_path / f"browser-slot-{i}.lock" for i in range(max_concurrent))

    @property
    def max_concurrent(self) -> int:
        return self._max_concurrent

    def acquire(self) -> "_BrowserGateHold":
        timeout = self._acquire_timeout_seconds
        if not self._semaphore.acquire(timeout=timeout):
            raise FetchError(
                f"browser gate: no slot freed within {timeout}s "
                f"(max_concurrent={self._max_concurrent})")
        try:
            fd = self._acquire_slot(timeout) if self._slot_paths else None
        except BaseException:
            # A slot-side failure (EMFILE, ENOLCK, a timeout) must not leak
            # the semaphore permit -- without this, ONE bad acquisition
            # blocks every future browser/uc fetch in this process forever.
            self._semaphore.release()
            raise
        return _BrowserGateHold(self, fd)

    def _acquire_slot(self, timeout: float | None) -> int:
        assert self._slot_paths is not None
        assert fcntl is not None
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            for path in self._slot_paths:
                fd = os.open(
                    str(path), os.O_CREAT | os.O_RDWR | _O_NOFOLLOW, 0o600)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    os.close(fd)
                    if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        continue  # held by someone else -- try the next slot
                    raise  # unexpected (e.g. ENOLCK on a network FS): do not spin
                return fd
            if deadline is not None and time.monotonic() >= deadline:
                raise FetchError(
                    f"browser gate: no lock slot freed within {timeout}s "
                    f"(max_concurrent={self._max_concurrent})")
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
    """Lazy in-process-only singleton (max_concurrent=1, no lock_dir, no
    acquire timeout): the fallback for any Fetcher constructed without an
    explicit gate. Logs ONE warning on first use, so a composition root that
    forgets to inject a real gate (e.g. a future MCP door) does not lose the
    bound silently."""
    global _default_gate
    if _default_gate is None:
        logger.warning(
            "browser_gate: no gate was injected -- falling back to the "
            "default in-process-only, max_concurrent=1 gate. If this is a "
            "production composition root, it forgot to inject one."
        )
        _default_gate = BrowserGate(max_concurrent=1)
    return _default_gate
