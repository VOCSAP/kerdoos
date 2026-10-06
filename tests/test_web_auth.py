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
        self.assertEqual(me.json(), {"role": "user"})

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
        self.assertEqual(resp.json(), {"role": "admin"})


class OwnerIdNeverSerializedTest(_WebAuthTestBase):
    """Invariant 10: owner_id is derived from the authenticated Principal and
    never serialized to the client, not even the caller's own."""

    _OWNER_ID = "owner-7f3a9c"

    def _assert_no_owner_identity(self, resp, expected_role: str) -> None:
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"role": expected_role})
        self.assertNotIn(self._OWNER_ID, resp.text)

    def test_me_response_carries_the_role_but_no_owner_identity(self) -> None:
        self._add_owner(self._OWNER_ID, "alice", "s3cret")
        self._login("alice", "s3cret")
        self._assert_no_owner_identity(self.client.get("/me"), "user")

    def test_admin_whoami_response_carries_no_owner_identity(self) -> None:
        self._add_owner(self._OWNER_ID, "root", "s3cret", role="admin")
        self._login("root", "s3cret")
        self._assert_no_owner_identity(
            self.client.get("/admin/whoami"), "admin")


class OwnerIdNeverRenderedInHtmlTest(_WebAuthTestBase):
    """Invariant 10 on the HTML surface, for accounts without sources."""

    _OWNER_ID = "owner-7f3a9c"
    _HTML = {"Accept": "text/html"}

    def _html_login(self, identifier: str, password: str) -> None:
        resp = self.client.post(
            "/auth/login",
            data={"identifier": identifier, "password": password},
            headers=self._HTML)
        self.assertEqual(resp.status_code, 200)

    def _assert_pages_omit_owner_id(self, paths) -> None:
        for path in paths:
            with self.subTest(path=path):
                resp = self.client.get(path, headers=self._HTML)
                self.assertEqual(resp.status_code, 200)
                self.assertIn("text/html", resp.headers["content-type"])
                self.assertNotIn(self._OWNER_ID, resp.text)

    def test_user_pages_never_render_owner_id(self) -> None:
        self._add_owner(self._OWNER_ID, "alice", "s3cret")
        self._html_login("alice", "s3cret")
        self._assert_pages_omit_owner_id(
            ("/", "/products", "/profile", "/notifications"))

    def test_admin_pages_never_render_owner_id(self) -> None:
        self._add_owner(self._OWNER_ID, "root", "s3cret", role="admin")
        self._html_login("root", "s3cret")
        self._assert_pages_omit_owner_id(("/", "/profile", "/admin"))


class _CapturingSMTP:
    sent: list = []

    def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
        pass

    def __enter__(self) -> "_CapturingSMTP":
        return self

    def __exit__(self, *exc_info) -> bool:
        return False

    def starttls(self, context=None) -> None:
        pass

    def send_message(self, message) -> None:
        _CapturingSMTP.sent.append(message)


class OwnerIdNeverExposedWithSourcesTest(_WebAuthTestBase):
    """Invariant 10 (ADR 0006) for an account seeded through the real
    add_source with one source, one scrape and one job: source ids reach
    links, forms, URLs and the digest, so none of them may carry owner_id."""

    _OWNER_ID = "3f9c2a7b1d4e"
    _HTML = {"Accept": "text/html"}
    _URL = "https://www.kabum.com.br/produto/534732/aw3225qf"

    def setUp(self) -> None:
        super().setUp()
        from autolycos.router import StaticRouter

        from kerdoos.core.app.services import (
            AppService, DigestJobSpec, Principal, ProductSpec,
        )
        from kerdoos.core.domain import Availability, ScrapeStatus
        from kerdoos.parsers.factory import build_parser
        from kerdoos.parsers.ports import ParserSpec
        from kerdoos.persistence.ports import ScrapeRecord
        from kerdoos.persistence.sqlite_store import SqliteStateStore
        from kerdoos.registry.domain_policy import CatalogueDomainPolicy
        from kerdoos.registry.ports import SiteConfig

        self._add_owner(self._OWNER_ID, "alice", "s3cret")
        self.config = SqliteConfigStore(self.config_db)
        self.state = SqliteStateStore(self.state_db)
        self.addCleanup(self.state.close)
        self.domain_policy = CatalogueDomainPolicy(self.config)
        service = AppService(
            self.config, self.state, StaticRouter(self.domain_policy),
            self.domain_policy, build_parser)
        self.config.add_site(SiteConfig(
            name="kabum", fetcher="http", domain="kabum.com.br",
            parser=ParserSpec(kind="statejson", pix="a", card="b",
                              availability="c")))
        service.add_product(self._OWNER_ID, ProductSpec("aw3225qf", name="RTX"))
        self.source = service.add_source(
            self._OWNER_ID, "aw3225qf", "kabum", self._URL)
        self.record = ScrapeRecord(
            source_id=self.source.source_id, ts="2026-07-13T00:00:00+00:00",
            status=ScrapeStatus.OK, price_pix_cents=755800,
            price_card_cents=755800, currency="BRL",
            availability=Availability.IN_STOCK, method="http", error=None)
        self.state.record(self._OWNER_ID, self.record)
        self.job = service.create_job(
            Principal(owner_id=self._OWNER_ID, role="user"),
            DigestJobSpec(name="daily", frequency_kind="daily",
                          source_ids=(self.source.source_id,)))

        resp = self.client.post(
            "/auth/login", data={"identifier": "alice", "password": "s3cret"},
            headers=self._HTML)
        self.assertEqual(resp.status_code, 200)

    def _assert_omits_owner_id(self, resp) -> None:
        self.assertNotIn(self._OWNER_ID, resp.text)
        for name, value in resp.headers.items():
            self.assertNotIn(self._OWNER_ID, value, f"header {name}")

    def test_pages_with_sources_never_carry_owner_id(self) -> None:
        paths = (
            "/", "/products", "/notifications",
            f"/history/{self.source.source_id}",
            f"/notifications/{self.job.id}/preview",
        )
        for path in paths:
            with self.subTest(path=path):
                self.assertNotIn(self._OWNER_ID, path)
                resp = self.client.get(
                    path, headers=self._HTML, follow_redirects=False)
                self.assertEqual(resp.status_code, 200)
                self._assert_omits_owner_id(resp)

    def test_preview_labels_the_source_with_product_and_site(self) -> None:
        resp = self.client.get(
            f"/notifications/{self.job.id}/preview", headers=self._HTML)
        self.assertIn("RTX -- kabum", resp.text)

    def test_digest_email_never_carries_owner_id(self) -> None:
        from kerdoos.digest.smtp_sender import SmtpDigestSender, SmtpSettings

        _CapturingSMTP.sent.clear()
        sender = SmtpDigestSender(
            self.config, self.domain_policy, lambda owner: "alice@example.com",
            SmtpSettings(host="smtp.example.com", port=587,
                         from_addr="digest@example.com"))
        with mock.patch("kerdoos.digest.smtp_sender.smtplib.SMTP",
                        _CapturingSMTP):
            self.assertTrue(sender.send(
                self.job, [self.record], "2026-07-13T00:00:00+00:00", {}))

        message = _CapturingSMTP.sent[0]
        html = message.get_body(preferencelist=("html",)).get_content()
        text = message.get_body(preferencelist=("plain",)).get_content()
        for body in (html, text):
            self.assertIn("RTX -- kabum", body)
            self.assertNotIn(self._OWNER_ID, body)
        self.assertNotIn(self._OWNER_ID, message.as_string())

    def test_unknown_and_owner_prefixed_history_ids_are_404(self) -> None:
        for sid in ("aw3225qf:kabum:000000000000",
                    f"{self._OWNER_ID}:{self.source.source_id}"):
            with self.subTest(sid=sid):
                resp = self.client.get(f"/history/{sid}", headers=self._HTML)
                self.assertEqual(resp.status_code, 404)
                self.assertNotIn(sid, resp.text)
                self.assertNotIn(self._OWNER_ID, resp.text)


class TemplatesNeverNameOwnerIdTest(unittest.TestCase):
    def test_no_template_references_owner_id(self) -> None:
        from pathlib import Path

        import kerdoos.digest
        import kerdoos.interfaces.web

        roots = [Path(kerdoos.interfaces.web.__file__).parent / "templates",
                 Path(kerdoos.digest.__file__).parent / "templates"]
        templates = [p for root in roots for p in root.rglob("*.html")]
        self.assertTrue(templates)
        for template in templates:
            with self.subTest(template=template.name):
                self.assertNotIn(
                    "owner_id", template.read_text(encoding="utf-8"))


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
