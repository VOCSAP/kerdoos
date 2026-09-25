"""autolycos.challenge.looks_challenged: tightened markers, regression-locked.

The shared heuristic drives the core retry loop for every tier, so it must NOT
false-positive on healthy pages that legitimately embed Google reCAPTCHA v3 or
Cloudflare's passive telemetry script, yet MUST still catch a real interstitial.
Known challenge walls are excluded by name; every other committed HTML fixture
is asserted non-challenged as a regression lock.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from autolycos.challenge import (
    CHALLENGE_MARKERS,
    looks_challenged,
    looks_like_chrome_error_page,
)

_FIXTURES = Path(__file__).parent / "fixtures"
_ROOT_FIXTURES = Path(__file__).parents[3] / "tests" / "fixtures"
_CHALLENGE_FIXTURES = {
    "magalu_cffi.html": "Akamai Bot Manager wall",
    "mercadolivre_captcha_wall_camoufox.html": "MercadoLivre captcha wall",
}


def _fixture_roots() -> tuple[Path, ...]:
    assert _FIXTURES.is_dir(), "Package fixtures directory must exist"
    assert any(_FIXTURES.glob("*.html")), (
        "Package fixtures directory must contain HTML")
    return tuple(
        directory for directory in (_FIXTURES, _ROOT_FIXTURES)
        if directory.is_dir())


def _healthy_fixtures() -> tuple[Path, ...]:
    return tuple(
        fixture
        for directory in _fixture_roots()
        for fixture in sorted(directory.glob("*.html"))
        if fixture.name not in _CHALLENGE_FIXTURES
    )


class HealthyFixturesNotChallengedTest(unittest.TestCase):
    def test_every_real_page_is_not_challenged(self) -> None:
        for fixture in _healthy_fixtures():
            html = fixture.read_text(encoding="utf-8", errors="replace")
            with self.subTest(fixture=fixture):
                self.assertFalse(
                    looks_challenged(200, html),
                    f"{fixture} wrongly flagged challenged")


class MercadoLivreCaptchaWallTest(unittest.TestCase):
    def test_captcha_wall_index_is_challenged(self) -> None:
        html = (_FIXTURES / "mercadolivre_captcha_wall_camoufox.html").read_text(
            encoding="utf-8", errors="replace")
        self.assertTrue(looks_challenged(200, html))

    def test_account_verification_wall_remains_challenged(self) -> None:
        self.assertTrue(looks_challenged(
            200, "account-verification" + "x" * 5000))


class HealthyFixtureDiscoveryTest(unittest.TestCase):
    def test_missing_root_fixture_directory_is_optional(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            module = sys.modules[__name__]
            missing_root = Path(temporary_directory) / "missing"
            with patch.object(module, "_ROOT_FIXTURES", missing_root,
                              create=True):
                self.assertEqual(_fixture_roots(), (_FIXTURES,))

    def test_missing_package_fixture_directory_fails(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            module = sys.modules[__name__]
            missing_fixtures = Path(temporary_directory) / "missing"
            with patch.object(module, "_FIXTURES", missing_fixtures):
                with self.assertRaises(AssertionError):
                    _fixture_roots()

    def test_empty_package_fixture_directory_fails(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            module = sys.modules[__name__]
            with patch.object(module, "_FIXTURES", Path(temporary_directory)):
                with self.assertRaises(AssertionError):
                    _fixture_roots()

    def test_fixture_added_to_a_directory_is_collected(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            fixture = Path(temporary_directory) / "unknown_healthy.html"
            fixture.write_text(
                "<html>" + "healthy content " * 200 + "</html>",
                encoding="utf-8")
            self.assertFalse(looks_challenged(
                200, fixture.read_text(encoding="utf-8")))
            with patch.object(sys.modules[__name__], "_ROOT_FIXTURES",
                              fixture.parent):
                self.assertIn(fixture, _healthy_fixtures())

    def test_every_challenge_exclusion_exists_in_every_directory(self) -> None:
        self.assertTrue(_CHALLENGE_FIXTURES,
                        "Challenge exclusions must not be empty")
        for directory in _fixture_roots():
            for name in _CHALLENGE_FIXTURES:
                with self.subTest(directory=directory, fixture=name):
                    self.assertTrue((directory / name).is_file())


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

    def test_real_akamai_bot_manager_page_is_challenged(self) -> None:
        # The real Akamai challenge (Magalu, served at HTTP 200) must be flagged
        # via its DOM markers (scf-akamai / sec-if-cpt-container), else the core
        # retry loop never fires on a Magalu block.
        akamai = (_FIXTURES / "magalu_cffi.html").read_text(
            encoding="utf-8", errors="replace")
        self.assertTrue(looks_challenged(200, akamai))

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


class ChromeErrorPageDetectionTest(unittest.TestCase):
    """Card 1bddf3fa: Chrome's own internal error interstitial (a failed
    navigation, not anti-bot content served BY a site) must be detected by
    CONTENT, never by size -- the real interstitial is large (~188KB)."""

    def test_error_code_marker_in_dom_is_detected(self) -> None:
        page = (
            '<html><body><script>window.errorData = '
            '{"errorCode":"ERR_CONNECTION_REFUSED"};</script>'
            + "x" * 200000 + "</body></html>")
        self.assertTrue(looks_like_chrome_error_page(None, page))

    def test_chrome_error_scheme_url_is_detected_even_without_marker(
        self,
    ) -> None:
        self.assertTrue(
            looks_like_chrome_error_page("chrome-error://chromewebdata/",
                                          "<html></html>"))

    def test_healthy_fixture_is_not_flagged(self) -> None:
        html = (_FIXTURES / "kabum_aw3225qf.html").read_text(
            encoding="utf-8", errors="replace")
        self.assertFalse(looks_like_chrome_error_page(
            "https://www.kabum.com.br/produto/1", html))

    def test_large_healthy_page_is_not_flagged_by_size_alone(self) -> None:
        # A genuinely large page (larger than the real error interstitial)
        # must never be flagged on size -- content is the only signal.
        page = "<html><body>real content " * 20000 + "</body></html>"
        self.assertGreater(len(page), 200000)
        self.assertFalse(looks_like_chrome_error_page(
            "https://example.com/", page))


if __name__ == "__main__":
    unittest.main()
