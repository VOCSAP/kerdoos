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
            "KERDOOS_SESSION_SECRET": "test-session-secret",
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


if __name__ == "__main__":
    unittest.main()
