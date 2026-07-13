"""Phase 6-web: WebUI Notifications (digest jobs) vertical.

Same TestClient(create_app()) harness as tests/test_web_ui.py (reused via
_WebUITestBase). These tests drive the server-rendered Notifications surface:
create / list / enable-disable / delete jobs, source linking, the rendered
digest preview, and the CSRF + owner-scope disciplines that mirror the Phase 4b
products/profile screens.
"""

from __future__ import annotations

import re

from tests.test_web_ui import _WebUITestBase

_JOB_ROW = re.compile(r'id="job-([0-9a-f-]+)"')
_SOURCE_OPT = re.compile(r'name="source_ids" value="([^"]+)"')


class _NotificationsBase(_WebUITestBase):
    def setUp(self):
        super().setUp()
        self._add_owner("o1", "alice", "s3cret")
        self._login("alice", "s3cret")
        self._add_site()

    def _make_source(self, product_key="rtx-4070"):
        """Create a product + source through the real write endpoints and
        return the generated source_id (read back from the job source picker)."""
        token = self._csrf()
        self.client.post(
            "/products",
            data={"product_key": product_key, "name": "RTX 4070",
                  "csrf_token": token})
        self.client.post(
            "/sources",
            data={"product_key": product_key, "site": "terabyte",
                  "url": "https://terabyteshop.com.br/rtx-4070",
                  "csrf_token": token})
        match = _SOURCE_OPT.search(self.client.get("/notifications").text)
        assert match, "created source not offered in the picker"
        return match.group(1)

    def _create_job(self, **overrides):
        token = self._csrf()
        data = {
            "name": "Veille GPU", "frequency_kind": "daily",
            "hour": "8", "minute": "0", "timezone": "UTC",
            "template_id": "default", "show_pix": "1", "show_card": "1",
            "csrf_token": token,
        }
        data.update(overrides)
        return self.client.post("/notifications", data=data)


class NotificationsPageTest(_NotificationsBase):
    def test_requires_session_html_401(self):
        client = self._fresh_client()  # no login
        resp = client.get("/notifications", headers={"accept": "text/html"})
        self.assertEqual(resp.status_code, 401)

    def test_empty_state_and_cadence_warning_present(self):
        page = self.client.get("/notifications")
        self.assertEqual(page.status_code, 200)
        self.assertIn("Aucune notification", page.text)
        # The anti-bot cadence warning is a required, product-specific element.
        self.assertIn("cadence-warn", page.text)
        self.assertIn("anti-bot", page.text)

    def test_nav_link_present(self):
        self.assertIn('href="/notifications"', self.client.get("/").text)


class CreateJobTest(_NotificationsBase):
    def test_create_daily_job_then_listed_with_schedule(self):
        resp = self._create_job(name="Quotidien 8h")
        self.assertEqual(resp.status_code, 200)  # 303 -> GET /notifications
        self.assertIn("Quotidien 8h", resp.text)
        self.assertIn("Chaque jour a 08:00", resp.text)
        self.assertIn("badge--on", resp.text)  # enabled by default

    def test_create_hourly_job(self):
        resp = self._create_job(
            name="Horaire", frequency_kind="hourly", minute="30")
        self.assertIn("Chaque heure a :30", resp.text)

    def test_create_with_linked_source(self):
        source_id = self._make_source()
        resp = self._create_job(name="Avec source", source_ids=source_id)
        self.assertEqual(resp.status_code, 200)
        # The linked source shows in the job's source table (count = 1).
        self.assertIn("RTX 4070", resp.text)

    def test_create_without_csrf_is_403(self):
        resp = self.client.post(
            "/notifications",
            data={"name": "x", "frequency_kind": "daily", "hour": "8",
                  "minute": "0", "timezone": "UTC", "template_id": "default"})
        self.assertEqual(resp.status_code, 403)

    def test_invalid_timezone_is_400_form_error(self):
        resp = self._create_job(timezone="Mars/Phobos")
        self.assertEqual(resp.status_code, 400)
        self.assertIn("refus", resp.text.lower())

    def test_bad_cron_expr_is_400(self):
        resp = self._create_job(frequency_kind="cron", cron_expr="only two")
        self.assertEqual(resp.status_code, 400)

    def test_out_of_range_threshold_is_400(self):
        resp = self._create_job(variation_threshold_pct="150")
        self.assertEqual(resp.status_code, 400)

    def test_non_numeric_threshold_is_400(self):
        resp = self._create_job(variation_threshold_pct="abc")
        self.assertEqual(resp.status_code, 400)


class JobLifecycleTest(_NotificationsBase):
    def _create_and_get_id(self, **kw):
        page = self._create_job(**kw)
        match = _JOB_ROW.search(page.text)
        assert match, "created job not listed"
        return match.group(1)

    def test_toggle_pauses_then_resumes(self):
        job_id = self._create_and_get_id()
        token = self._csrf()
        resp = self.client.post(
            f"/notifications/{job_id}/enabled", data={"csrf_token": token})
        self.assertEqual(resp.status_code, 200)  # 303 -> GET /notifications
        self.assertIn("badge--paused", resp.text)
        # Resume.
        self.client.post(
            f"/notifications/{job_id}/enabled", data={"csrf_token": token})
        self.assertIn("badge--on", self.client.get("/notifications").text)

    def test_toggle_without_csrf_is_403(self):
        job_id = self._create_and_get_id()
        resp = self.client.post(f"/notifications/{job_id}/enabled")
        self.assertEqual(resp.status_code, 403)

    def test_delete_removes_job(self):
        job_id = self._create_and_get_id()
        token = self._csrf()
        resp = self.client.delete(
            f"/notifications/{job_id}", headers={"X-CSRF-Token": token})
        self.assertEqual(resp.status_code, 204)
        self.assertEqual(resp.headers.get("HX-Redirect"), "/notifications")
        self.assertNotIn(
            f'id="job-{job_id}"', self.client.get("/notifications").text)

    def test_add_then_remove_source(self):
        source_id = self._make_source()
        job_id = self._create_and_get_id(name="Sans source")
        token = self._csrf()
        add = self.client.post(
            f"/notifications/{job_id}/sources",
            data={"source_id": source_id, "csrf_token": token})
        self.assertEqual(add.status_code, 200)
        self.assertIn("RTX 4070", self.client.get("/notifications").text)
        rem = self.client.delete(
            f"/notifications/{job_id}/sources/{source_id}",
            headers={"X-CSRF-Token": token})
        self.assertEqual(rem.status_code, 204)


class PreviewTest(_NotificationsBase):
    def test_preview_renders_sandboxed_iframe(self):
        page = self._create_job(name="Aperçu test")
        job_id = _JOB_ROW.search(page.text).group(1)
        resp = self.client.get(f"/notifications/{job_id}/preview")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("digest-frame", resp.text)
        self.assertIn("sandbox", resp.text)
        self.assertIn("srcdoc=", resp.text)

    def test_preview_unknown_job_is_404(self):
        resp = self.client.get("/notifications/ghost-id/preview")
        self.assertEqual(resp.status_code, 404)


class XssTest(_NotificationsBase):
    def test_job_name_is_html_escaped_in_list(self):
        self._create_job(name="<script>alert(1)</script>")
        page = self.client.get("/notifications")
        self.assertNotIn("<script>alert(1)</script>", page.text)
        self.assertIn("&lt;script&gt;", page.text)

    def test_job_name_is_escaped_in_preview_srcdoc(self):
        page = self._create_job(name="<script>alert(2)</script>")
        job_id = _JOB_ROW.search(page.text).group(1)
        resp = self.client.get(f"/notifications/{job_id}/preview")
        # The raw script tag must never appear un-escaped anywhere on the page,
        # neither in the shell nor inside the srcdoc attribute value.
        self.assertNotIn("<script>alert(2)</script>", resp.text)


class OwnerScopeTest(_NotificationsBase):
    def _other_client_with_alice_job(self):
        """Alice creates a job; return (bob_client, bob_csrf, alice_job_id)."""
        page = self._create_job(name="Alice job")
        job_id = _JOB_ROW.search(page.text).group(1)
        self._add_owner("ob", "bob", "s3cret")
        bob = self._fresh_client()
        self._login_on(bob, "bob", "s3cret")
        token = self._csrf_on(bob)
        return bob, token, job_id

    def test_cross_tenant_preview_is_404(self):
        bob, _token, job_id = self._other_client_with_alice_job()
        resp = bob.get(f"/notifications/{job_id}/preview")
        self.assertEqual(resp.status_code, 404)

    def test_cross_tenant_toggle_is_404_and_no_change(self):
        bob, token, job_id = self._other_client_with_alice_job()
        resp = bob.post(
            f"/notifications/{job_id}/enabled", data={"csrf_token": token})
        self.assertEqual(resp.status_code, 404)
        # Alice's job is untouched (still enabled).
        self.assertIn("badge--on", self.client.get("/notifications").text)

    def test_cross_tenant_delete_is_404_and_no_deletion(self):
        bob, token, job_id = self._other_client_with_alice_job()
        resp = bob.delete(
            f"/notifications/{job_id}", headers={"X-CSRF-Token": token})
        self.assertEqual(resp.status_code, 404)
        self.assertIn(
            f'id="job-{job_id}"', self.client.get("/notifications").text)


if __name__ == "__main__":
    import unittest
    unittest.main()
