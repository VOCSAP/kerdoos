"""create_app() factory: /health -> 200, no module-level app instance.

Phase 0 structural check only (ADR 0001 §7/§10): the factory pattern lets
each test build an isolated app (rule FastAPI "create_app() factory").
"""

from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from kerdoos.interfaces.web.app import create_app


class HealthTest(unittest.TestCase):
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
