"""Phase 4b WebUI vertical: HTML views, CSRF, and authz surfaces.

Same harness as tests/test_web_auth.py (real TestClient(create_app()) over a
temp config.db seeded via SqliteConfigStore.ensure_owner + a real Argon2id
hash). These tests drive the SERVER-RENDERED surface (login form, dashboard,
products, admin) and the stateless CSRF guard.

The profile screen's set_email / list_tokens integration is fully exercised
(ProfileIntegrationTest) now that phase4b-profile-core is merged: email
set/taken/invalid, token create/list/revoke, revoke-all self-logout, and CSRF on
the profile POSTs. No profile test is skipped.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import unittest
from unittest import mock

from fastapi.testclient import TestClient

from kerdoos.interfaces.web.app import create_app
from kerdoos.registry.auth_store import Argon2Hasher
from kerdoos.registry.sqlite_store import SqliteConfigStore

_CSRF_META = re.compile(r'name="csrf-token" content="([0-9a-f]+)"')
_HTML = {"accept": "text/html"}


class _WebUITestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.mkdtemp(prefix="kerdoos-web-ui-")
        self.addCleanup(shutil.rmtree, self._dir, ignore_errors=True)
        self.config_db = os.path.join(self._dir, "config.db")
        self.state_db = os.path.join(self._dir, "state.db")
        patcher = mock.patch.dict(os.environ, {
            "KERDOOS_SESSION_SECRET": "test-session-secret-padded-to-32chars",
            "KERDOOS_CONFIG_DB": self.config_db,
            "KERDOOS_STATE_DB": self.state_db,
            "KERDOOS_COOKIE_SECURE": "false",
        })
        patcher.start()
        self.addCleanup(patcher.stop)

        self._hasher = Argon2Hasher()
        SqliteConfigStore(self.config_db).close()  # run migrations
        self.client = TestClient(create_app())

    def _add_owner(self, owner_id, name, password, *, role="user", email=None):
        store = SqliteConfigStore(self.config_db)
        try:
            store.ensure_owner(owner_id, name, role=role, email=email,
                               password_hash=self._hasher.hash(password))
        finally:
            store.close()

    def _owner_email(self, owner_id):
        import sqlite3
        conn = sqlite3.connect(self.config_db)
        try:
            row = conn.execute(
                "SELECT email FROM owners WHERE id = ?", (owner_id,)).fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def _login(self, identifier, password):
        """HTML login flow -> stores the session cookie on the client."""
        return self._login_on(self.client, identifier, password)

    def _login_on(self, client, identifier, password):
        return client.post(
            "/auth/login",
            data={"identifier": identifier, "password": password})

    def _csrf(self):
        """Read this session's CSRF token from a rendered page's <meta>."""
        return self._csrf_on(self.client)

    def _csrf_on(self, client):
        page = client.get("/")
        match = _CSRF_META.search(page.text)
        assert match, "no csrf-token meta on the dashboard"
        return match.group(1)

    def _fresh_client(self):
        """A second app instance over the SAME config/state DB (distinct session
        jar), to exercise cross-session / cross-tenant flows."""
        return TestClient(create_app())

    def _add_site(self, name="terabyte", domain="terabyteshop.com.br"):
        store = SqliteConfigStore(self.config_db)
        try:
            from kerdoos.parsers.ports import ParserSpec
            from kerdoos.registry.ports import SiteConfig
            store.add_site(SiteConfig(
                name=name, fetcher="http",
                parser=ParserSpec(kind="jsonld"), domain=domain))
        finally:
            store.close()


class LoginHtmlTest(_WebUITestBase):
    def test_login_form_is_public_html(self):
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Se connecter", resp.text)

    def test_valid_login_lands_on_dashboard(self):
        self._add_owner("o1", "alice", "s3cret")
        resp = self._login("alice", "s3cret")  # follows the 303 to /
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Tableau de veille", resp.text)
        self.assertIn("kerdoos_session", self.client.cookies)

    def test_invalid_login_rerenders_form_401(self):
        self._add_owner("o1", "alice", "s3cret")
        resp = self.client.post(
            "/auth/login", data={"identifier": "alice", "password": "nope"})
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Identifiants invalides", resp.text)

    def test_dashboard_requires_session_html_401(self):
        resp = self.client.get("/", headers=_HTML)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("Session expir", resp.text)


class DashboardTest(_WebUITestBase):
    def test_empty_watchlist_shows_empty_state(self):
        self._add_owner("o1", "alice", "s3cret")
        self._login("alice", "s3cret")
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Aucun produit surveillé", resp.text)


class ProductsCsrfTest(_WebUITestBase):
    def setUp(self):
        super().setUp()
        self._add_owner("o1", "alice", "s3cret")
        self._login("alice", "s3cret")
        self._add_site()

    def test_add_product_with_csrf_then_visible(self):
        token = self._csrf()
        resp = self.client.post(
            "/products",
            data={"product_key": "rtx-4070", "name": "RTX 4070",
                  "csrf_token": token})
        self.assertEqual(resp.status_code, 200)  # 303 -> GET /products
        self.assertIn("RTX 4070", resp.text)

    def test_add_product_without_csrf_is_403(self):
        resp = self.client.post(
            "/products", data={"product_key": "rtx-4070", "name": "x"})
        self.assertEqual(resp.status_code, 403)

    def test_add_product_with_wrong_csrf_is_403(self):
        resp = self.client.post(
            "/products",
            data={"product_key": "rtx-4070", "csrf_token": "deadbeef"})
        self.assertEqual(resp.status_code, 403)

    def test_delete_via_header_csrf_removes_product(self):
        token = self._csrf()
        self.client.post(
            "/products", data={"product_key": "rtx-4070", "csrf_token": token})
        resp = self.client.delete(
            "/products/rtx-4070", headers={"X-CSRF-Token": token})
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(resp.headers.get("HX-Redirect"), "/products")
        # Assert the product CARD is gone (its key also appears in a form
        # placeholder, so match the unambiguous row/card id marker instead).
        self.assertNotIn('id="product-rtx-4070"', self.client.get("/products").text)

    def test_remove_unknown_product_is_generic_404(self):
        token = self._csrf()
        resp = self.client.delete(
            "/products/ghost-not-owned", headers={"X-CSRF-Token": token})
        # KeyError (unknown OR another tenant's) -> generic 404, no leak.
        self.assertEqual(resp.status_code, 404)

    def test_add_source_unknown_site_shows_form_error(self):
        token = self._csrf()
        self.client.post(
            "/products", data={"product_key": "rtx-4070", "csrf_token": token})
        resp = self.client.post(
            "/sources",
            data={"product_key": "rtx-4070", "site": "ghost",
                  "url": "https://terabyteshop.com.br/x", "csrf_token": token})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Source refusée", resp.text)

    def test_add_source_unavailable_tier_is_400_not_500(self):
        # Card 3aeb8a19: a site needing a fetcher tier this deployment lacks
        # must be rejected as a domain error (4xx), not crash to a 500.
        # Forced missing rather than relied-upon-absent: this must stay red
        # for the right reason even in a full (autonomous) venv.
        from unittest import mock

        from autolycos import router as router_mod
        from kerdoos.parsers.ports import ParserSpec
        from kerdoos.registry.ports import SiteConfig
        store = SqliteConfigStore(self.config_db)
        try:
            store.add_site(SiteConfig(
                name="magalu", fetcher="uc",
                parser=ParserSpec(kind="statejson"),
                domain="magazineluiza.com.br"))
        finally:
            store.close()
        token = self._csrf()
        self.client.post(
            "/products", data={"product_key": "tv55", "csrf_token": token})
        with mock.patch.dict(
            router_mod._TIER_MODULES,
            {"uc": "kerdoos_test_definitely_not_a_real_module_xyz"},
        ):
            resp = self.client.post(
                "/sources",
                data={"product_key": "tv55", "site": "magalu",
                      "url": "https://www.magazineluiza.com.br/p/1",
                      "csrf_token": token})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Source refusée", resp.text)


class XssEscapingTest(_WebUITestBase):
    def test_product_name_is_html_escaped(self):
        self._add_owner("o1", "alice", "s3cret")
        self._login("alice", "s3cret")
        token = self._csrf()
        self.client.post(
            "/products",
            data={"product_key": "xss-1",
                  "name": "<script>alert(1)</script>", "csrf_token": token})
        page = self.client.get("/products")
        self.assertNotIn("<script>alert(1)</script>", page.text)
        self.assertIn("&lt;script&gt;", page.text)


class AdminTest(_WebUITestBase):
    def test_admin_page_forbidden_for_user_html(self):
        self._add_owner("o1", "alice", "s3cret", role="user")
        self._login("alice", "s3cret")
        resp = self.client.get("/admin", headers=_HTML)
        self.assertEqual(resp.status_code, 403)
        self.assertIn("administrateurs", resp.text)

    def test_admin_add_site_ok_for_admin(self):
        self._add_owner("o1", "root", "s3cret", role="admin")
        self._login("root", "s3cret")
        self.assertEqual(self.client.get("/admin").status_code, 200)
        token = self._csrf()
        resp = self.client.post(
            "/admin/sites",
            data={"name": "pichau", "fetcher": "tls", "domain": "pichau.com.br",
                  "parser_kind": "css", "csrf_token": token})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("pichau", resp.text)

    def test_admin_add_site_without_csrf_is_403(self):
        self._add_owner("o1", "root", "s3cret", role="admin")
        self._login("root", "s3cret")
        resp = self.client.post(
            "/admin/sites",
            data={"name": "pichau", "fetcher": "tls", "domain": "pichau.com.br",
                  "parser_kind": "css"})
        self.assertEqual(resp.status_code, 403)


class ProfileTest(_WebUITestBase):
    def setUp(self):
        super().setUp()
        self._add_owner("o1", "alice", "s3cret")
        self._login("alice", "s3cret")

    def test_profile_renders(self):
        resp = self.client.get("/profile")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Profil", resp.text)

    def test_create_token_reveals_plaintext_once(self):
        token = self._csrf()
        resp = self.client.post(
            "/profile/tokens", data={"csrf_token": token})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Jeton créé", resp.text)

    def test_revoke_all_logs_out_to_login(self):
        # revoke_all cuts sessions too -> the caller is logged out and lands on
        # the public login page (a /profile redirect would 401).
        token = self._csrf()
        resp = self.client.post(
            "/profile/tokens/revoke-all", data={"csrf_token": token})
        self.assertEqual(resp.status_code, 200)  # 303 -> GET /login
        self.assertIn("Se connecter", resp.text)


class JsonApiUntouchedTest(_WebUITestBase):
    """The Phase 4a JSON contract must survive the HTML additions."""

    def test_json_login_still_returns_json(self):
        self._add_owner("o1", "alice", "s3cret")
        resp = self.client.post(
            "/login", json={"identifier": "alice", "password": "s3cret"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json(), {"status": "ok"})
        me = self.client.get("/me")
        self.assertEqual(me.json(), {"owner_id": "o1", "role": "user"})

    def test_json_login_failure_is_json_401(self):
        resp = self.client.post(
            "/login", json={"identifier": "ghost", "password": "x"})
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json(), {"detail": "invalid credentials"})


class HardeningTest(_WebUITestBase):
    """Fast-follow hardenings (re-gate security -5 + reviewer -4)."""

    def test_non_ascii_csrf_token_is_403_not_500(self):
        # compare_digest would TypeError on a str codepoint > 127 (-> 500);
        # comparing in bytes makes it a clean mismatch -> 403.
        self._add_owner("o1", "alice", "s3cret")
        self._login("alice", "s3cret")
        # Bytes header value so a raw >127 octet (0xe9) reaches the server as a
        # latin-1 str (httpx refuses to ascii-encode a non-ASCII str header).
        resp = self.client.post(
            "/products",
            data={"product_key": "x"},
            headers={"X-CSRF-Token": b"abc\xe9def"})
        self.assertEqual(resp.status_code, 403)

    def test_csrf_token_from_another_session_is_rejected(self):
        # Token bound to session A must not validate on session B.
        self._add_owner("o1", "alice", "s3cret")
        self._login("alice", "s3cret")
        token_a = self._csrf()

        client_b = self._fresh_client()
        self._login_on(client_b, "alice", "s3cret")  # a DIFFERENT session
        resp = client_b.post(
            "/products", data={"product_key": "rtx-4070", "csrf_token": token_a})
        self.assertEqual(resp.status_code, 403)

    def test_idor_cross_tenant_remove_product_is_404_and_no_deletion(self):
        # Owner A owns rtx-4070; owner B tries to delete A's REAL product_key.
        self._add_owner("oa", "alice", "s3cret")
        self._add_owner("ob", "bob", "s3cret")
        self._login("alice", "s3cret")
        self._add_site()
        token_a = self._csrf()
        self.client.post(
            "/products", data={"product_key": "rtx-4070", "csrf_token": token_a})

        client_b = self._fresh_client()
        self._login_on(client_b, "bob", "s3cret")
        token_b = self._csrf_on(client_b)
        resp = client_b.delete(
            "/products/rtx-4070", headers={"X-CSRF-Token": token_b})
        self.assertEqual(resp.status_code, 404)  # owner-scoped KeyError, generic
        # A's product is untouched.
        self.assertIn('id="product-rtx-4070"', self.client.get("/products").text)

    def test_logout_revokes_session_server_side(self):
        self._add_owner("o1", "alice", "s3cret")
        self._login("alice", "s3cret")
        stale = self.client.cookies.get("kerdoos_session")
        self.assertEqual(self.client.get("/me").status_code, 200)
        self.client.post("/auth/logout")
        # Replay the still-validly-signed cookie: server-side revocation -> 401.
        self.client.cookies.set("kerdoos_session", stale)
        self.assertEqual(self.client.get("/me").status_code, 401)

    def test_revoke_all_revokes_session_server_side(self):
        self._add_owner("o1", "alice", "s3cret")
        self._login("alice", "s3cret")
        stale = self.client.cookies.get("kerdoos_session")
        token = self._csrf()
        self.client.post("/profile/tokens/revoke-all", data={"csrf_token": token})
        self.client.cookies.set("kerdoos_session", stale)
        self.assertEqual(self.client.get("/me").status_code, 401)

    def test_unexpected_error_is_500_not_masked_as_400(self):
        # A domain error is a 400; an UNEXPECTED error must NOT be masked as 400.
        self._add_owner("o1", "alice", "s3cret")
        app = create_app()

        def _boom(*_a, **_k):
            raise RuntimeError("unexpected")

        app.state.app_service.add_product = _boom
        client = TestClient(app, raise_server_exceptions=False)
        self._login_on(client, "alice", "s3cret")
        token = self._csrf_on(client)
        resp = client.post(
            "/products", data={"product_key": "rtx-4070", "csrf_token": token})
        self.assertEqual(resp.status_code, 500)


class PrefillTest(_WebUITestBase):
    def test_profile_prefills_current_email(self):
        self._add_owner("o1", "alice", "s3cret", email="alice@example.com")
        self._login("alice", "s3cret")
        page = self.client.get("/profile")
        self.assertIn('value="alice@example.com"', page.text)


_TOKEN_ROW = re.compile(r'id="token-([0-9a-f]+)"')


class ProfileIntegrationTest(_WebUITestBase):
    """Profile use-cases wired to the real AuthService (post profile-core merge)."""

    def setUp(self):
        super().setUp()
        self._add_owner("o1", "alice", "s3cret")
        self._login("alice", "s3cret")

    # -- email --------------------------------------------------------------
    def test_set_email_updates_owner(self):
        token = self._csrf()
        resp = self.client.post(
            "/profile/email",
            data={"email": "alice@example.com", "csrf_token": token})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Email enregistré", resp.text)
        self.assertEqual(self._owner_email("o1"), "alice@example.com")

    def test_clear_email_removes_it(self):
        token = self._csrf()
        self.client.post("/profile/email",
                         data={"email": "alice@example.com", "csrf_token": token})
        self.client.post("/profile/email",
                         data={"email": "", "csrf_token": token})
        self.assertIsNone(self._owner_email("o1"))

    def test_email_already_taken_is_generic_no_leak(self):
        # A different owner already holds this email.
        self._add_owner("o2", "bob", "s3cret", email="taken@example.com")
        token = self._csrf()
        resp = self.client.post(
            "/profile/email",
            data={"email": "taken@example.com", "csrf_token": token})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Email indisponible", resp.text)
        # No cross-owner leak: the other owner's identity is never revealed.
        self.assertNotIn("bob", resp.text)
        self.assertNotIn("o2", resp.text)
        self.assertIsNone(self._owner_email("o1"))  # unchanged

    def test_invalid_email_format_is_rejected(self):
        token = self._csrf()
        resp = self.client.post(
            "/profile/email",
            data={"email": "not-an-email", "csrf_token": token})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Email invalide", resp.text)
        self.assertIsNone(self._owner_email("o1"))

    def test_email_post_without_csrf_is_403(self):
        resp = self.client.post(
            "/profile/email", data={"email": "alice@example.com"})
        self.assertEqual(resp.status_code, 403)

    # -- tokens -------------------------------------------------------------
    def test_token_create_then_listed_then_revoked(self):
        token = self._csrf()
        created = self.client.post(
            "/profile/tokens", data={"csrf_token": token})
        self.assertEqual(created.status_code, 200)
        self.assertIn("Jeton créé", created.text)

        # It now shows up in the real list_tokens table.
        page = self.client.get("/profile")
        match = _TOKEN_ROW.search(page.text)
        self.assertIsNotNone(match, "created token not listed")
        token_id = match.group(1)

        # Revoke it -> it disappears from the list.
        resp = self.client.delete(
            f"/profile/tokens/{token_id}", headers={"X-CSRF-Token": token})
        self.assertEqual(resp.status_code, 204)
        self.assertNotIn(f'id="token-{token_id}"', self.client.get("/profile").text)

    def test_token_revoke_without_csrf_is_403(self):
        token = self._csrf()
        self.client.post("/profile/tokens", data={"csrf_token": token})
        token_id = _TOKEN_ROW.search(self.client.get("/profile").text).group(1)
        resp = self.client.delete(f"/profile/tokens/{token_id}")  # no CSRF header
        self.assertEqual(resp.status_code, 403)


if __name__ == "__main__":
    unittest.main()
