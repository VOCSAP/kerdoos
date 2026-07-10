"""Phase 4b WebUI vertical: HTML views, CSRF, and authz surfaces.

Same harness as tests/test_web_auth.py (real TestClient(create_app()) over a
temp config.db seeded via SqliteConfigStore.ensure_owner + a real Argon2id
hash). These tests drive the SERVER-RENDERED surface (login form, dashboard,
products, admin) and the stateless CSRF guard.

Note: the profile screen's set_email / list_tokens integration is deliberately
NOT exercised here -- those use-cases land on the separate phase4b-profile-core
branch (team-lead coordination); the route degrades gracefully until then, and
the integration test is activated by the team-lead after that merge. create_token
+ revoke_all + the profile render ARE covered (they use existing use-cases).
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

    def _add_owner(self, owner_id, name, password, *, role="user"):
        store = SqliteConfigStore(self.config_db)
        try:
            store.ensure_owner(owner_id, name, role=role,
                               password_hash=self._hasher.hash(password))
        finally:
            store.close()

    def _login(self, identifier, password):
        """HTML login flow -> stores the session cookie on the client."""
        return self.client.post(
            "/auth/login",
            data={"identifier": identifier, "password": password})

    def _csrf(self):
        """Read this session's CSRF token from a rendered page's <meta>."""
        page = self.client.get("/")
        match = _CSRF_META.search(page.text)
        assert match, "no csrf-token meta on the dashboard"
        return match.group(1)

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


if __name__ == "__main__":
    unittest.main()
