"""kerdoos.config.get_settings() -- SMTP env-var wiring (ADR 0003 Phase 6b
tranche 4).

No hardcoded infra defaults: smtp_host/from/username/password must be None
(not empty string) unless the operator explicitly sets the corresponding
KERDOOS_SMTP_* env var. smtp_port defaults to 587 (STARTTLS submission) even
when unset, since that default is inert until digest.factory.build_sender
also sees a non-None smtp_host/smtp_from (falls back to LogDigestSender
otherwise -- covered in tests/test_digest_factory.py-equivalent coverage
elsewhere, not re-tested here).
"""

from __future__ import annotations

import os
import unittest

from kerdoos.config import (
    DEFAULT_DIGEST_REAPER_TIMEOUT_SECONDS, DEFAULT_SMTP_PORT,
    DEFAULT_SMTP_TIMEOUT_SECONDS, DEFAULT_WORKERS, get_settings,
)

_SMTP_ENV_VARS = (
    "KERDOOS_SMTP_HOST", "KERDOOS_SMTP_PORT", "KERDOOS_SMTP_FROM",
    "KERDOOS_SMTP_USERNAME", "KERDOOS_SMTP_PASSWORD", "KERDOOS_SMTP_USE_TLS",
    "KERDOOS_SMTP_TIMEOUT_SECONDS", "KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS",
    "KERDOOS_WORKERS",
)


class _SettingsTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = {var: os.environ.pop(var, None) for var in _SMTP_ENV_VARS}

    def tearDown(self) -> None:
        for var, value in self._saved.items():
            if value is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = value


class SmtpUnsetDefaultsTest(_SettingsTestBase):
    def test_smtp_host_is_none_not_empty_string_when_unset(self) -> None:
        settings = get_settings()
        self.assertIsNone(settings.smtp_host)

    def test_smtp_from_username_password_are_none_when_unset(self) -> None:
        settings = get_settings()
        self.assertIsNone(settings.smtp_from)
        self.assertIsNone(settings.smtp_username)
        self.assertIsNone(settings.smtp_password)

    def test_smtp_port_defaults_to_587_even_without_host(self) -> None:
        settings = get_settings()
        self.assertEqual(settings.smtp_port, DEFAULT_SMTP_PORT)
        self.assertEqual(settings.smtp_port, 587)

    def test_smtp_use_tls_defaults_true(self) -> None:
        settings = get_settings()
        self.assertTrue(settings.smtp_use_tls)

    def test_smtp_timeout_defaults_below_reaper_timeout(self) -> None:
        # The ordering invariant (roadmap 58d88fe0) must hold even between
        # the two DEFAULTS, not just when an operator sets both explicitly --
        # otherwise a fresh deployment starts already wedged.
        settings = get_settings()
        self.assertEqual(settings.smtp_timeout_seconds, DEFAULT_SMTP_TIMEOUT_SECONDS)
        self.assertLess(
            settings.smtp_timeout_seconds, DEFAULT_DIGEST_REAPER_TIMEOUT_SECONDS)


class SmtpSetFromEnvTest(_SettingsTestBase):
    def test_all_smtp_fields_read_from_env(self) -> None:
        os.environ["KERDOOS_SMTP_HOST"] = "smtp.example.com"
        os.environ["KERDOOS_SMTP_PORT"] = "2525"
        os.environ["KERDOOS_SMTP_FROM"] = "digest@example.com"
        os.environ["KERDOOS_SMTP_USERNAME"] = "digestuser"
        os.environ["KERDOOS_SMTP_PASSWORD"] = "s3cret"
        os.environ["KERDOOS_SMTP_USE_TLS"] = "false"
        os.environ["KERDOOS_SMTP_TIMEOUT_SECONDS"] = "45"

        settings = get_settings()

        self.assertEqual(settings.smtp_host, "smtp.example.com")
        self.assertEqual(settings.smtp_port, 2525)
        self.assertEqual(settings.smtp_from, "digest@example.com")
        self.assertEqual(settings.smtp_username, "digestuser")
        self.assertEqual(settings.smtp_password, "s3cret")
        self.assertFalse(settings.smtp_use_tls)
        self.assertEqual(settings.smtp_timeout_seconds, 45.0)

    def test_empty_string_host_is_treated_as_unset(self) -> None:
        # KERDOOS_SMTP_HOST="" (e.g. an env template with a blank default)
        # must not be mistaken for a configured relay -- `or None` in
        # get_settings() collapses "" to None, same as fully unset.
        os.environ["KERDOOS_SMTP_HOST"] = ""
        settings = get_settings()
        self.assertIsNone(settings.smtp_host)

    def test_smtp_use_tls_default_true_when_var_set_to_arbitrary_value(self) -> None:
        os.environ["KERDOOS_SMTP_USE_TLS"] = "true"
        self.assertTrue(get_settings().smtp_use_tls)


class ReaperTimeoutFloorTest(_SettingsTestBase):
    """roadmap 58d88fe0 gate fix: digest_reaper_timeout_seconds feeds a raw
    asyncio.wait_for deadline in core.evaluator -- a non-positive value must
    never reach that deadline, or every digest send fails instantly."""

    def test_zero_floors_to_default_with_warning(self) -> None:
        os.environ["KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS"] = "0"
        with self.assertLogs("kerdoos.config", level="WARNING") as cm:
            settings = get_settings()
        self.assertEqual(
            settings.digest_reaper_timeout_seconds,
            DEFAULT_DIGEST_REAPER_TIMEOUT_SECONDS)
        self.assertTrue(
            any("KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS" in msg for msg in cm.output),
            cm.output)

    def test_non_numeric_floors_to_default_with_warning(self) -> None:
        # gate ae0a343 C3: the bare int() this used to feed raised before
        # ever reaching the positive-value floor below.
        os.environ["KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS"] = "abc"
        with self.assertLogs("kerdoos.config", level="WARNING"):
            settings = get_settings()
        self.assertEqual(
            settings.digest_reaper_timeout_seconds,
            DEFAULT_DIGEST_REAPER_TIMEOUT_SECONDS)

    def test_negative_floors_to_default_with_warning(self) -> None:
        os.environ["KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS"] = "-5"
        with self.assertLogs("kerdoos.config", level="WARNING"):
            settings = get_settings()
        self.assertEqual(
            settings.digest_reaper_timeout_seconds,
            DEFAULT_DIGEST_REAPER_TIMEOUT_SECONDS)

    def test_positive_value_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS"] = "1"
        settings = get_settings()
        self.assertEqual(settings.digest_reaper_timeout_seconds, 1)


class SmtpPortFloorTest(_SettingsTestBase):
    """gate ae0a343 C3: a non-numeric KERDOOS_SMTP_PORT must warn and fall
    back to the default, never raise ValueError."""

    def test_non_numeric_floors_to_default_with_warning(self) -> None:
        os.environ["KERDOOS_SMTP_PORT"] = "abc"
        with self.assertLogs("kerdoos.config", level="WARNING") as cm:
            settings = get_settings()
        self.assertEqual(settings.smtp_port, DEFAULT_SMTP_PORT)
        self.assertTrue(any("KERDOOS_SMTP_PORT" in msg for msg in cm.output), cm.output)


class SmtpTimeoutFloorTest(_SettingsTestBase):
    """gate ae0a343 C3: a non-numeric KERDOOS_SMTP_TIMEOUT_SECONDS must warn
    and fall back to the default, never raise ValueError."""

    def test_non_numeric_floors_to_default_with_warning(self) -> None:
        os.environ["KERDOOS_SMTP_TIMEOUT_SECONDS"] = "abc"
        with self.assertLogs("kerdoos.config", level="WARNING") as cm:
            settings = get_settings()
        self.assertEqual(settings.smtp_timeout_seconds, DEFAULT_SMTP_TIMEOUT_SECONDS)
        self.assertTrue(
            any("KERDOOS_SMTP_TIMEOUT_SECONDS" in msg for msg in cm.output), cm.output)


class WorkersFloorTest(_SettingsTestBase):
    """A malformed KERDOOS_WORKERS warns and falls back instead of crashing."""

    def test_empty_string_floors_to_default_with_warning(self) -> None:
        os.environ["KERDOOS_WORKERS"] = ""
        with self.assertLogs("kerdoos.config", level="WARNING") as cm:
            settings = get_settings()
        self.assertEqual(settings.workers, DEFAULT_WORKERS)
        self.assertTrue(any("KERDOOS_WORKERS" in msg for msg in cm.output), cm.output)

    def test_non_numeric_text_floors_to_default_with_warning(self) -> None:
        os.environ["KERDOOS_WORKERS"] = "banana"
        with self.assertLogs("kerdoos.config", level="WARNING"):
            settings = get_settings()
        self.assertEqual(settings.workers, DEFAULT_WORKERS)

    def test_shell_injection_shaped_value_floors_to_default_with_warning(
        self,
    ) -> None:
        os.environ["KERDOOS_WORKERS"] = "1 --reload --app-dir /tmp"
        with self.assertLogs("kerdoos.config", level="WARNING"):
            settings = get_settings()
        self.assertEqual(settings.workers, DEFAULT_WORKERS)

    def test_unset_uses_default_unaffected_by_validation(self) -> None:
        settings = get_settings()
        self.assertEqual(settings.workers, DEFAULT_WORKERS)

    def test_valid_positive_integer_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_WORKERS"] = "4"
        settings = get_settings()
        self.assertEqual(settings.workers, 4)

    def test_shapes_the_shell_guard_rejects_also_floor_in_python(self) -> None:
        # gate ae0a343 C2: int() is looser than the Dockerfile's shell case
        # guard (whitespace, a leading sign, PEP 515 underscores) -- Python
        # must reject exactly what the shell rejects, or the two disagree on
        # the same value and the container silently runs with no evaluator.
        for raw in (" 4", "4 ", "+4", "4_0", "0", "-3"):
            with self.subTest(raw=raw):
                os.environ["KERDOOS_WORKERS"] = raw
                with self.assertLogs("kerdoos.config", level="WARNING"):
                    settings = get_settings()
                self.assertEqual(settings.workers, DEFAULT_WORKERS)


if __name__ == "__main__":
    unittest.main()
