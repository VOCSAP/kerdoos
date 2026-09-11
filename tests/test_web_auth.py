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
            "KERDOOS_SESSION_SECRET": "test-session-secret-padded-to-32chars",
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

    def test_create_app_raises_on_short_session_secret(self) -> None:
        # Fast-follow from the Phase 4a gate (architect MEDIUM): a non-empty
        # but short secret is brute-forceable and must be rejected too, not
        # just an absent one.
        with mock.patch.dict(os.environ, {"KERDOOS_SESSION_SECRET": "x"}):
            with self.assertRaises(RuntimeError):
                create_app()

    def test_create_app_accepts_32_char_session_secret(self) -> None:
        secret = "a" * 32
        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "KERDOOS_SESSION_SECRET": secret,
                "KERDOOS_CONFIG_DB": os.path.join(tmp, "config.db"),
                "KERDOOS_STATE_DB": os.path.join(tmp, "state.db"),
                "KERDOOS_COOKIE_SECURE": "false",
            }
            with mock.patch.dict(os.environ, env):
                create_app()  # must not raise (boundary: 32 is accepted)


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

    def test_logout_revokes_session_server_side_not_just_client_cookie(
        self,
    ) -> None:
        # Fast-follow from the Phase 4a gate (reviewer LOW): the previous test
        # only checks the CLIENT's post-logout state (cookie cleared by the
        # response), which conflates "client dropped its cookie" with "server
        # revoked the session". Capture the still-validly-signed cookie value
        # BEFORE logout and replay it AFTER logout: its HMAC signature is
        # still correct (SessionCookie.read() would accept it), so a 401 here
        # can only come from AuthService.verify_session finding the session
        # gone server-side -- proving real revocation, not a signature check.
        self._add_owner("o1", "alice", "s3cret")
        self._login("alice", "s3cret")
        self.assertEqual(self.client.get("/me").status_code, 200)
        captured_cookie = self.client.cookies.get("kerdoos_session")
        self.assertIsNotNone(captured_cookie)

        resp = self.client.post("/logout")
        self.assertEqual(resp.status_code, 200)

        self.client.cookies.set("kerdoos_session", captured_cookie)
        replayed = self.client.get("/me")
        self.assertEqual(replayed.status_code, 401)

    def test_logout_without_session_still_succeeds(self) -> None:
        resp = self.client.post("/logout")
        self.assertEqual(resp.status_code, 200)


class LoginRateLimitWebTest(_WebAuthTestBase):
    """roadmap f1048ab8: /login and /auth/login rate-limit, over HTTP."""

    def setUp(self) -> None:
        os.environ["KERDOOS_LOGIN_RATE_LIMIT_MAX_ATTEMPTS"] = "2"
        os.environ["KERDOOS_LOGIN_RATE_LIMIT_WINDOW_SECONDS"] = "60"
        self.addCleanup(
            os.environ.pop, "KERDOOS_LOGIN_RATE_LIMIT_MAX_ATTEMPTS", None)
        self.addCleanup(
            os.environ.pop, "KERDOOS_LOGIN_RATE_LIMIT_WINDOW_SECONDS", None)
        super().setUp()
        self._add_owner("o1", "alice", "s3cret")

    def _html_login(self, identifier: str, password: str):
        return self.client.post(
            "/auth/login",
            data={"identifier": identifier, "password": password})

    def test_json_login_two_failures_then_429_with_retry_after(self) -> None:
        self._login("alice", "wrong")
        self._login("alice", "wrong")
        resp = self._login("alice", "s3cret")  # correct, but now blocked
        self.assertEqual(resp.status_code, 429)
        self.assertIn("Retry-After", resp.headers)

    def test_html_login_two_failures_then_429(self) -> None:
        self._html_login("alice", "wrong")
        self._html_login("alice", "wrong")
        resp = self._html_login("alice", "s3cret")
        self.assertEqual(resp.status_code, 429)
        self.assertIn("Retry-After", resp.headers)

    def test_existing_and_nonexistent_identifier_identical_responses(
        self,
    ) -> None:
        for identifier in ("alice", "ghost-user"):
            self._login(identifier, "wrong")
            self._login(identifier, "wrong")
        resp_existing = self._login("alice", "wrong")
        resp_nonexistent = self._login("ghost-user", "wrong")
        self.assertEqual(
            resp_existing.status_code, resp_nonexistent.status_code)
        self.assertEqual(resp_existing.json(), resp_nonexistent.json())
        self.assertIn("Retry-After", resp_existing.headers)
        self.assertIn("Retry-After", resp_nonexistent.headers)

    def test_success_resets_the_counter(self) -> None:
        self._login("alice", "wrong")
        ok = self._login("alice", "s3cret")
        self.assertEqual(ok.status_code, 200)
        # A single fresh failure right after must not be blocked yet.
        resp = self._login("alice", "wrong")
        self.assertEqual(resp.status_code, 401)


if __name__ == "__main__":
    unittest.main()
