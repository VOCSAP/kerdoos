"""autolycos.challenge.looks_challenged: tightened markers, regression-locked.

The shared heuristic drives the core retry loop for every tier, so it must NOT
false-positive on healthy pages that legitimately embed Google reCAPTCHA v3 or
Cloudflare's passive telemetry script, yet MUST still catch a real interstitial.
Every committed HTML fixture (a real, healthy 200 page) is asserted non-challenged
as a regression lock.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from autolycos.challenge import CHALLENGE_MARKERS, looks_challenged

_FIXTURES = Path(__file__).parent / "fixtures"
_HEALTHY_FIXTURES = (
    "kabum_aw3225qf.html",
    "amazon_b0cvqgsrz9.html",
    "mercadolivre_mlb35045987.html",
    "terabyte_40561.html",
    # Pichau: Cloudflare-fronted but its only residual is the PASSIVE
    # challenge-platform script (already excluded); no active marker survives.
    "pichau_cv700b.html",
)


class HealthyFixturesNotChallengedTest(unittest.TestCase):
    def test_every_real_page_is_not_challenged(self) -> None:
        for name in _HEALTHY_FIXTURES:
            html = (_FIXTURES / name).read_text(encoding="utf-8", errors="replace")
            with self.subTest(fixture=name):
                self.assertFalse(
                    looks_challenged(200, html),
                    f"{name} wrongly flagged challenged")


class BroadMarkersRemovedTest(unittest.TestCase):
    def test_bare_captcha_and_challenge_platform_are_gone(self) -> None:
        # These matched reCAPTCHA v3 and Cloudflare's passive script on healthy
        # pages; they must not be in the marker set anymore.
        self.assertNotIn("captcha", CHALLENGE_MARKERS)
        self.assertNotIn("challenge-platform", CHALLENGE_MARKERS)

    def test_recaptcha_v3_only_page_is_not_challenged(self) -> None:
        page = ('<html><head>'
                '<style>.grecaptcha-badge{visibility:hidden}</style>'
                '<script src="https://www.google.com/recaptcha/api.js?render=KEY">'
                '</script></head><body>' + "content " * 400 + '</body></html>')
        self.assertFalse(looks_challenged(200, page))

    def test_cloudflare_passive_script_page_is_not_challenged(self) -> None:
        page = ('<html><body>' + "content " * 400 +
                '<script src="/cdn-cgi/challenge-platform/h/g/scripts/jsd/main.js">'
                '</script></body></html>')
        self.assertFalse(looks_challenged(200, page))


class RealInterstitialStillChallengedTest(unittest.TestCase):
    def test_cloudflare_just_a_moment(self) -> None:
        self.assertTrue(looks_challenged(200, "<title>Just a moment...</title>"
                                         + "x" * 5000))

    def test_cloudflare_active_challenge_markers(self) -> None:
        self.assertTrue(looks_challenged(
            200, '<div class="cf-chl-widget"></div>' + "x" * 5000))
        self.assertTrue(looks_challenged(
            200, "window._cf_chl_opt={cvId:'3'}" + "x" * 5000))

    def test_akamai_sec_cpt(self) -> None:
        self.assertTrue(looks_challenged(
            200, '<div id="sec-cpt-challenge"></div>' + "x" * 5000))

    def test_amazon_robot_check_validatecaptcha(self) -> None:
        # Amazon's Robot Check anti-bot wall (served at HTTP 200) posts to
        # /errors/validateCaptcha; it must be flagged so retry gets a chance.
        page = ('<form method="get" action="/errors/validateCaptcha">'
                '<h4>Type the characters you see in this image</h4></form>'
                + "x" * 5000)
        self.assertTrue(looks_challenged(200, page))

    def test_perimeterx_and_datadome(self) -> None:
        self.assertTrue(looks_challenged(200, "px-captcha " + "x" * 5000))
        self.assertTrue(looks_challenged(200, "datadome " + "x" * 5000))

    def test_ml_micro_landing_shell(self) -> None:
        self.assertTrue(looks_challenged(
            200, '<div class="micro-landing-container"></div>' + "x" * 5000))

    def test_block_status_and_short_body(self) -> None:
        self.assertTrue(looks_challenged(503, "x" * 5000))
        self.assertTrue(looks_challenged(200, "tiny"))


if __name__ == "__main__":
    unittest.main()
