"""BrowserFetcher: real-Chromium liveness proofs, gated on the autonomous
image (KERDOOS_REQUIRE_IMAGE_TESTS).

These classes launch a real patchright Chromium and must run inside the
autonomous Docker image (or hard-fail loudly if that image lacks patchright,
per KERDOOS_REQUIRE_IMAGE_TESTS=1 -- a silent skip must never read as a pass).
"""

from __future__ import annotations

import importlib.util
import os
import socket
import time
import unittest
from pathlib import Path
from unittest import mock

from autolycos import safety
from autolycos.adapters import browser
from autolycos.browser_gate import BrowserGate
from autolycos.errors import FetchError
from autolycos.safety import DomainPolicy

_HAS_PATCHRIGHT = importlib.util.find_spec("patchright") is not None
_HAS_POSIX_SHELL = os.name == "posix" and Path("/bin/sh").exists()
_NEUTRAL_POLICY = DomainPolicy(frozenset({"example.com"}))


def _addrinfo(ip: str, port: int = 443):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))]


class RealBrowserLaunchTimeoutTest(unittest.TestCase):
    """Roadmap b3213f3c acceptance test: drives the REAL UcFetcher-style
    integration -- patchright's own BrowserType.launch, through the REAL
    fetch() call, with executable_path swapped for a script that genuinely
    hangs (never a nonexistent path, which fails instantly and proves
    nothing). Neutral target only (example.com), never a real site. POSIX
    only (needs /bin/sh); runs for real inside the autonomous image.
    """

    def setUp(self) -> None:
        if _HAS_PATCHRIGHT and _HAS_POSIX_SHELL:
            return
        if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
            self.fail(
                "KERDOOS_REQUIRE_IMAGE_TESTS=1 but patchright or a POSIX "
                "shell is unavailable -- run inside the autonomous image")
        self.skipTest(
            "needs patchright and a POSIX shell (autonomous image), not "
            "just patchright")

    def test_hung_launch_raises_fetch_error_releases_gate_no_leftover_process(
            self) -> None:
        import psutil
        from patchright.sync_api import BrowserType

        script_path = Path("/tmp/kerdoos-test-hang-browser-launch.sh")
        script_path.write_text("#!/bin/sh\nsleep 60\n", encoding="utf-8")
        script_path.chmod(0o755)
        self.addCleanup(script_path.unlink, missing_ok=True)

        original_launch = BrowserType.launch

        def _patched_launch(self_bt, **kwargs):  # noqa: ANN001, ANN003
            kwargs["executable_path"] = str(script_path)
            return original_launch(self_bt, **kwargs)

        gate = BrowserGate(max_concurrent=1)
        before = {p.pid for p in psutil.Process().children(recursive=True)}
        with mock.patch.object(BrowserType, "launch", _patched_launch), \
             mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            fetcher = browser.BrowserFetcher(
                _NEUTRAL_POLICY, gate=gate, launch_timeout_seconds=2.0)
            t0 = time.monotonic()
            with self.assertRaises(FetchError):
                fetcher.fetch("https://example.com/")
            elapsed = time.monotonic() - t0
        # Bounded by the 2s deadline, not the script's 60s sleep.
        self.assertLess(elapsed, 10.0)

        acquired_promptly = gate._semaphore.acquire(timeout=1.0)
        self.assertTrue(acquired_promptly, "gate slot was not released")
        gate._semaphore.release()

        time.sleep(1.0)
        leftover = [p for p in psutil.Process().children(recursive=True)
                    if p.pid not in before and p.is_running()]
        self.assertEqual(leftover, [], f"lingering process(es): {leftover}")


class RealBrowserFreezeTest(unittest.TestCase):
    """Roadmap d8b7b8fd acceptance test: a REAL Chromium (patchright's own
    bundled binary, not an executable_path substitute), frozen with SIGSTOP
    right after a successful launch(), must still make fetch() raise
    FetchError within fetch_timeout_seconds, release the gate only after
    cleanup, and leave zero survivors -- the exact scenario measured
    (45s observation, no return, no exception) before this fix existed.
    POSIX only (SIGSTOP); runs for real inside the autonomous image.
    """

    def setUp(self) -> None:
        if _HAS_PATCHRIGHT and _HAS_POSIX_SHELL:
            return
        if os.environ.get("KERDOOS_REQUIRE_IMAGE_TESTS") == "1":
            self.fail(
                "KERDOOS_REQUIRE_IMAGE_TESTS=1 but patchright or a POSIX "
                "shell is unavailable -- run inside the autonomous image")
        self.skipTest(
            "needs patchright and a POSIX shell (autonomous image), not "
            "just patchright")

    def test_frozen_chromium_raises_fetch_error_releases_gate_no_leftover(
            self) -> None:
        import signal

        import psutil
        from patchright.sync_api import BrowserType

        original_launch = BrowserType.launch
        before = {p.pid for p in psutil.Process().children(recursive=True)}

        def _patched_launch(self_bt, **kwargs):  # noqa: ANN001, ANN003
            result = original_launch(self_bt, **kwargs)
            # Freeze the newly-launched browser's own top-level OS process
            # (not a zygote/renderer/gpu child) right after launch() itself
            # succeeds, so every call the adapter makes AFTER this point
            # hangs -- exactly what was measured against a real Chromium.
            candidates = [p for p in psutil.Process().children(recursive=True)
                          if p.pid not in before]
            for p in candidates:
                try:
                    cmdline = " ".join(p.cmdline())
                    name = (p.name() or "").lower()
                except psutil.Error:
                    continue
                if "--type=" in cmdline:
                    continue
                if "chrome" in name or "headless" in cmdline:
                    os.kill(p.pid, signal.SIGSTOP)
                    break
            return result

        gate = BrowserGate(max_concurrent=1)
        with mock.patch.object(BrowserType, "launch", _patched_launch), \
             mock.patch.object(safety.socket, "getaddrinfo",
                               return_value=_addrinfo("104.18.0.1")):
            fetcher = browser.BrowserFetcher(
                _NEUTRAL_POLICY, gate=gate, fetch_timeout_seconds=5.0)
            t0 = time.monotonic()
            with self.assertRaises(FetchError):
                fetcher.fetch("https://example.com/")
            elapsed = time.monotonic() - t0
        # Bounded by the 5s deadline, not an indefinite hang.
        self.assertLess(elapsed, 20.0)

        acquired_promptly = gate._semaphore.acquire(timeout=1.0)
        self.assertTrue(acquired_promptly, "gate slot was not released")
        gate._semaphore.release()

        time.sleep(1.0)
        leftover = [p for p in psutil.Process().children(recursive=True)
                    if p.pid not in before and p.is_running()]
        self.assertEqual(leftover, [], f"lingering process(es): {leftover}")


if __name__ == "__main__":
    unittest.main()
