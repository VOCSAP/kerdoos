"""Phase 4a WebUI auth wiring: signed session cookie, router-level auth
dependencies, and the create_app() composition root (ADR 0001 S4/S6).

Uses a real TestClient(create_app()) against a temp config.db seeded via
SqliteConfigStore.ensure_owner + a real Argon2id hash (same pattern as
tests/test_auth.py). KERDOOS_COOKIE_SECURE=false because Starlette's
TestClient talks http://testserver (a Secure cookie set by response.set_cookie
would not round-trip over http, cf. rule "Secure configurable for a plain-http
LAN deployment").
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from kerdoos.interfaces.web.app import create_app
from kerdoos.registry.auth_store import Argon2Hasher
from kerdoos.registry.sqlite_store import SqliteConfigStore


class _WebAuthTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="kerdoos-web-auth-")
        self.addCleanup(shutil.rmtree, self._dir, ignore_errors=True)
        self.config_db = os.path.join(self._dir, "config.db")
        self.state_db = os.path.join(self._dir, "state.db")
        env = {
            "KERDOOS_SESSION_SECRET": "test-session-secret",
            "KERDOOS_CONFIG_DB": self.config_db,
            "KERDOOS_STATE_DB": self.state_db,
            "KERDOOS_COOKIE_SECURE": "false",
        }
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)

        self._hasher = Argon2Hasher()
        config_store = SqliteConfigStore(self.config_db)
        config_store.close()

        self.client = TestClient(create_app())

    def _add_owner(self, owner_id, name, password, *, role="user"):
        config_store = SqliteConfigStore(self.config_db)
        try:
            config_store.ensure_owner(
                owner_id, name, role=role,
                password_hash=self._hasher.hash(password))
        finally:
            config_store.close()

    def _set_state(self, owner_id: str, state: str) -> None:
        import sqlite3

        conn = sqlite3.connect(self.config_db)
        try:
            conn.execute("UPDATE owners SET state = ? WHERE id = ?",
                         (state, owner_id))
            conn.commit()
        finally:
            conn.close()

    def _login(self, identifier: str, password: str):
        return self.client.post(
            "/login", json={"identifier": identifier, "password": password})


class MissingSecretTest(unittest.TestCase):
    def test_create_app_raises_without_session_secret(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("KERDOOS_SESSION_SECRET", None)
            with self.assertRaises(RuntimeError):
                create_app()


class LoginTest(_WebAuthTestBase):
    def test_valid_login_sets_cookie_and_protected_route_resolves(self) -> None:
        self._add_owner("o1", "alice", "s3cret")
        resp = self._login("alice", "s3cret")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("kerdoos_session", resp.cookies)

        me = self.client.get("/me")
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json(), {"owner_id": "o1", "role": "user"})

    def test_three_failure_branches_return_identical_401(self) -> None:
        self._add_owner("o1", "alice", "s3cret")
        # Owner with no password (passwordless / WebUI-disabled account).
        self._add_owner("o2", "nopass", "irrelevant")
        config_store = SqliteConfigStore(self.config_db)
        try:
            config_store.ensure_owner("o2", "nopass", password_hash=None)
        finally:
            config_store.close()

        unknown = self._login("ghost", "whatever")
        wrong_pw = self._login("alice", "wrong")
        no_pw = self._login("nopass", "whatever")

        for resp in (unknown, wrong_pw, no_pw):
            self.assertEqual(resp.status_code, 401)
            self.assertEqual(resp.json(), {"detail": "invalid credentials"})
        self.assertEqual(
            {r.json()["detail"] for r in (unknown, wrong_pw, no_pw)},
            {"invalid credentials"},
        )


class ProtectedRouteTest(_WebAuthTestBase):
    def test_protected_route_without_cookie_is_401(self) -> None:
        resp = self.client.get("/me")
        self.assertEqual(resp.status_code, 401)

    def test_tampered_cookie_is_rejected(self) -> None:
        self._add_owner("o1", "alice", "s3cret")
        self._login("alice", "s3cret")
        self.client.cookies.set("kerdoos_session", "not-a-real-session.badhmac")
        resp = self.client.get("/me")
        self.assertEqual(resp.status_code, 401)

    def test_disabled_owner_session_rejected(self) -> None:
        self._add_owner("o1", "alice", "s3cret")
        self._login("alice", "s3cret")
        self.assertEqual(self.client.get("/me").status_code, 200)
        self._set_state("o1", "disabled")
        self.assertEqual(self.client.get("/me").status_code, 401)


class AdminRouteTest(_WebAuthTestBase):
    def test_admin_route_forbidden_for_user_role(self) -> None:
        self._add_owner("o1", "alice", "s3cret", role="user")
        self._login("alice", "s3cret")
        resp = self.client.get("/admin/whoami")
        self.assertEqual(resp.status_code, 403)

    def test_admin_route_ok_for_admin_role(self) -> None:
        self._add_owner("o1", "root", "s3cret", role="admin")
        self._login("root", "s3cret")
        resp = self.client.get("/admin/whoami")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"owner_id": "o1", "role": "admin"})


class LogoutTest(_WebAuthTestBase):
    def test_logout_clears_cookie_and_revokes_session(self) -> None:
        self._add_owner("o1", "alice", "s3cret")
        self._login("alice", "s3cret")
        self.assertEqual(self.client.get("/me").status_code, 200)

        resp = self.client.post("/logout")
        self.assertEqual(resp.status_code, 200)

        self.assertEqual(self.client.get("/me").status_code, 401)

    def test_logout_without_session_still_succeeds(self) -> None:
        resp = self.client.post("/logout")
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
