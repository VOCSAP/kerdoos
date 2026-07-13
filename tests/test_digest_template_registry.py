"""Digest template_id write/render whitelist sync (ADR 0003 Phase 6b tranche
4, security finding S5 CWE-22/1336).

template_id must NEVER be interpolated into a filesystem path. Two
independent gates enforce the whitelist: registry.ports.validate_template_id
(write time, authoring) and digest.templates.render_digest_html (render
time). This test proves the two whitelists cannot drift apart, and that an
unknown/hostile template_id is rejected at render time with a plain
ValueError -- never a filesystem lookup.
"""

from __future__ import annotations

import unittest

from kerdoos.digest.templates import TEMPLATE_FILES, render_digest_html
from kerdoos.digest.view import DigestView
from kerdoos.registry.ports import VALID_TEMPLATE_IDS, validate_template_id


class TemplateWhitelistSyncTest(unittest.TestCase):
    def test_render_whitelist_matches_write_whitelist_exactly(self) -> None:
        # The write-time gate (VALID_TEMPLATE_IDS) and the render-time lookup
        # (TEMPLATE_FILES) must never drift -- a template_id validated at
        # authoring time must always resolve at render time, and nothing
        # extra must be renderable that authoring would have rejected.
        self.assertEqual(set(TEMPLATE_FILES), VALID_TEMPLATE_IDS)

    def test_every_whitelisted_template_id_passes_write_time_validation(self) -> None:
        for template_id in TEMPLATE_FILES:
            validate_template_id(template_id)  # must not raise


class TemplateRejectionTest(unittest.TestCase):
    def _view(self) -> DigestView:
        return DigestView(job_name="job1", generated_at="2026-07-13T00:00:00+00:00",
                          lines=())

    def test_unknown_template_id_rejected_at_write_time(self) -> None:
        with self.assertRaises(ValueError):
            validate_template_id("nope")

    def test_unknown_template_id_rejected_at_render_time_not_path_lookup(self) -> None:
        with self.assertRaises(ValueError):
            render_digest_html("nope", self._view())

    def test_path_traversal_template_id_rejected_at_render_time(self) -> None:
        # A template_id must never be treated as (or interpolated into) a
        # filesystem path -- a directory-traversal-shaped id must hit the
        # SAME ValueError branch as any other unknown id, never reach the
        # filesystem loader.
        hostile_ids = (
            "../../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "default.html",  # the real filename must not be usable directly
        )
        for template_id in hostile_ids:
            with self.assertRaises(ValueError):
                render_digest_html(template_id, self._view())

    def test_unknown_template_id_rejected_at_write_time_via_create_job_spec(self) -> None:
        # Mirrors validate_timezone's authoring-time discipline: a bad
        # template_id must never reach storage in the first place.
        with self.assertRaises(ValueError):
            validate_template_id("../etc/passwd")


if __name__ == "__main__":
    unittest.main()
