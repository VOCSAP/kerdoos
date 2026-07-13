"""create_app() factory: /health -> 200, no module-level app instance.

Phase 0 structural check only (ADR 0001 §7/§10): the factory pattern lets
each test build an isolated app (rule FastAPI "create_app() factory").

Since Phase 4a, create_app() is a real composition root (wires AuthService +
AppService from Settings/env) and fails fast without KERDOOS_SESSION_SECRET
-- these tests supply a temp config/state DB pair and a session secret so the
Phase 0 structural checks keep exercising the real factory, not a stub.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from kerdoos.interfaces.web.app import create_app


class HealthTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="kerdoos-web-health-")
        self.addCleanup(shutil.rmtree, self._dir, ignore_errors=True)
        patcher = mock.patch.dict(os.environ, {
            "KERDOOS_SESSION_SECRET": "test-session-secret-padded-to-32chars",
            "KERDOOS_CONFIG_DB": os.path.join(self._dir, "config.db"),
            "KERDOOS_STATE_DB": os.path.join(self._dir, "state.db"),
            "KERDOOS_COOKIE_SECURE": "false",
        })
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_health_returns_200(self) -> None:
        client = TestClient(create_app())
        resp = client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok"})

    def test_two_apps_are_independent_instances(self) -> None:
        # Guards against a future regression to a module-level `app = FastAPI()`
        # singleton (rule FastAPI: two create_app() calls must not share state).
        app_a = create_app()
        app_b = create_app()
        self.assertIsNot(app_a, app_b)


class DigestEvaluatorLifespanTest(unittest.TestCase):
    """ADR 0003 Decision 4/8: the intra-process evaluator lifespan task is
    opt-in (KERDOOS_DIGEST_EVALUATOR_ENABLED, default off) and refuses to
    start when KERDOOS_WORKERS > 1 (each worker process would double-fire
    jobs). These tests use `with TestClient(...) as client:` explicitly --
    unlike HealthTest above -- since the ASGI lifespan only runs inside that
    context manager (pytest.md rule)."""

    def setUp(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="kerdoos-web-lifespan-")
        self.addCleanup(shutil.rmtree, self._dir, ignore_errors=True)
        self._base_env = {
            "KERDOOS_SESSION_SECRET": "test-session-secret-padded-to-32chars",
            "KERDOOS_CONFIG_DB": os.path.join(self._dir, "config.db"),
            "KERDOOS_STATE_DB": os.path.join(self._dir, "state.db"),
            "KERDOOS_COOKIE_SECURE": "false",
        }

    def _patch_env(self, **overrides: str) -> None:
        patcher = mock.patch.dict(os.environ, {**self._base_env, **overrides})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_default_off_starts_and_stops_cleanly(self) -> None:
        self._patch_env()  # KERDOOS_DIGEST_EVALUATOR_ENABLED unset -> False
        with TestClient(create_app()) as client:
            resp = client.get("/health")
            self.assertEqual(resp.status_code, 200)

    def test_enabled_with_workers_1_starts_and_stops_cleanly(self) -> None:
        self._patch_env(
            KERDOOS_DIGEST_EVALUATOR_ENABLED="true", KERDOOS_WORKERS="1")
        with TestClient(create_app()) as client:
            resp = client.get("/health")
            self.assertEqual(resp.status_code, 200)

    def test_enabled_with_workers_gt_1_refuses_and_warns(self) -> None:
        self._patch_env(
            KERDOOS_DIGEST_EVALUATOR_ENABLED="true", KERDOOS_WORKERS="2")
        with self.assertLogs(
            "kerdoos.interfaces.web.app", level="WARNING") as cm:
            with TestClient(create_app()) as client:
                resp = client.get("/health")
                self.assertEqual(resp.status_code, 200)
        self.assertTrue(
            any("refusing to start" in msg for msg in cm.output),
            cm.output,
        )


if __name__ == "__main__":
    unittest.main()
