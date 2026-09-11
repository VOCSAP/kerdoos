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
    DEFAULT_BROWSER_ACQUIRE_TIMEOUT_SECONDS,
    DEFAULT_BROWSER_LAUNCH_TIMEOUT_SECONDS, DEFAULT_BROWSER_MAX_CONCURRENT,
    DEFAULT_DIGEST_REAPER_TIMEOUT_SECONDS,
    DEFAULT_LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
    DEFAULT_LOGIN_RATE_LIMIT_ROW_CAP,
    DEFAULT_LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    DEFAULT_RUN_NOW_COOLDOWN_SECONDS,
    DEFAULT_RUN_QUEUE_BACKLOG_WARN_THRESHOLD, DEFAULT_RUN_QUEUE_MAX_RESTARTS,
    DEFAULT_SMTP_PORT, DEFAULT_SMTP_RETRY_ATTEMPTS,
    DEFAULT_SMTP_RETRY_BACKOFF_SECONDS, DEFAULT_SMTP_TIMEOUT_SECONDS,
    DEFAULT_UC_LAUNCH_TIMEOUT_SECONDS, DEFAULT_WORKERS,
    MAX_SMTP_RETRY_ATTEMPTS, MIN_SMTP_RETRY_BACKOFF_SECONDS, get_settings,
)

_SMTP_ENV_VARS = (
    "KERDOOS_SMTP_HOST", "KERDOOS_SMTP_PORT", "KERDOOS_SMTP_FROM",
    "KERDOOS_SMTP_USERNAME", "KERDOOS_SMTP_PASSWORD", "KERDOOS_SMTP_USE_TLS",
    "KERDOOS_SMTP_TIMEOUT_SECONDS", "KERDOOS_SMTP_RETRY_ATTEMPTS",
    "KERDOOS_SMTP_RETRY_BACKOFF_SECONDS", "KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS",
    "KERDOOS_WORKERS", "KERDOOS_BROWSER_MAX_CONCURRENT",
    "KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS",
    "KERDOOS_RUN_QUEUE_MAX_RESTARTS", "KERDOOS_RUN_QUEUE_BACKLOG_WARN_THRESHOLD",
    "KERDOOS_RUN_NOW_COOLDOWN_SECONDS",
    "KERDOOS_UC_LAUNCH_TIMEOUT_SECONDS",
    "KERDOOS_BROWSER_LAUNCH_TIMEOUT_SECONDS",
    "KERDOOS_LOGIN_RATE_LIMIT_WINDOW_SECONDS",
    "KERDOOS_LOGIN_RATE_LIMIT_MAX_ATTEMPTS",
    "KERDOOS_LOGIN_RATE_LIMIT_ROW_CAP",
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
        os.environ["KERDOOS_SMTP_RETRY_ATTEMPTS"] = "3"
        os.environ["KERDOOS_SMTP_RETRY_BACKOFF_SECONDS"] = "1.5"

        settings = get_settings()

        self.assertEqual(settings.smtp_host, "smtp.example.com")
        self.assertEqual(settings.smtp_port, 2525)
        self.assertEqual(settings.smtp_from, "digest@example.com")
        self.assertEqual(settings.smtp_username, "digestuser")
        self.assertEqual(settings.smtp_password, "s3cret")
        self.assertFalse(settings.smtp_use_tls)
        self.assertEqual(settings.smtp_timeout_seconds, 45.0)
        self.assertEqual(settings.smtp_retry_attempts, 3)
        self.assertEqual(settings.smtp_retry_backoff_seconds, 1.5)

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
    """A non-numeric or out-of-range KERDOOS_SMTP_PORT warns and falls back
    to the default, never raises ValueError."""

    def test_non_numeric_floors_to_default_with_warning(self) -> None:
        os.environ["KERDOOS_SMTP_PORT"] = "abc"
        with self.assertLogs("kerdoos.config", level="WARNING") as cm:
            settings = get_settings()
        self.assertEqual(settings.smtp_port, DEFAULT_SMTP_PORT)
        self.assertTrue(any("KERDOOS_SMTP_PORT" in msg for msg in cm.output), cm.output)

    def test_out_of_range_floors_to_default_with_warning(self) -> None:
        os.environ["KERDOOS_SMTP_PORT"] = "99999"
        with self.assertLogs("kerdoos.config", level="WARNING") as cm:
            settings = get_settings()
        self.assertEqual(settings.smtp_port, DEFAULT_SMTP_PORT)
        self.assertTrue(any("KERDOOS_SMTP_PORT" in msg for msg in cm.output), cm.output)

    def test_max_valid_port_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_SMTP_PORT"] = "65535"
        settings = get_settings()
        self.assertEqual(settings.smtp_port, 65535)


class SmtpTimeoutFloorTest(_SettingsTestBase):
    """A non-numeric KERDOOS_SMTP_TIMEOUT_SECONDS warns and falls back to
    the default, never raises ValueError."""

    def test_non_numeric_floors_to_default_with_warning(self) -> None:
        os.environ["KERDOOS_SMTP_TIMEOUT_SECONDS"] = "abc"
        with self.assertLogs("kerdoos.config", level="WARNING") as cm:
            settings = get_settings()
        self.assertEqual(settings.smtp_timeout_seconds, DEFAULT_SMTP_TIMEOUT_SECONDS)
        self.assertTrue(
            any("KERDOOS_SMTP_TIMEOUT_SECONDS" in msg for msg in cm.output), cm.output)


class SmtpRetryFloorTest(_SettingsTestBase):
    """Malformed KERDOOS_SMTP_RETRY_ATTEMPTS/BACKOFF_SECONDS warn and fall
    back to the default, never raise ValueError; unset stays silent."""

    def test_unset_uses_defaults(self) -> None:
        settings = get_settings()
        self.assertEqual(settings.smtp_retry_attempts, DEFAULT_SMTP_RETRY_ATTEMPTS)
        self.assertEqual(
            settings.smtp_retry_backoff_seconds, DEFAULT_SMTP_RETRY_BACKOFF_SECONDS)

    def test_non_numeric_attempts_floors_to_default_with_warning(self) -> None:
        os.environ["KERDOOS_SMTP_RETRY_ATTEMPTS"] = "abc"
        with self.assertLogs("kerdoos.config", level="WARNING") as cm:
            settings = get_settings()
        self.assertEqual(settings.smtp_retry_attempts, DEFAULT_SMTP_RETRY_ATTEMPTS)
        self.assertTrue(
            any("KERDOOS_SMTP_RETRY_ATTEMPTS" in msg for msg in cm.output), cm.output)

    def test_negative_attempts_floors_to_default_with_warning(self) -> None:
        os.environ["KERDOOS_SMTP_RETRY_ATTEMPTS"] = "-1"
        with self.assertLogs("kerdoos.config", level="WARNING"):
            settings = get_settings()
        self.assertEqual(settings.smtp_retry_attempts, DEFAULT_SMTP_RETRY_ATTEMPTS)

    def test_zero_attempts_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_SMTP_RETRY_ATTEMPTS"] = "0"
        settings = get_settings()
        self.assertEqual(settings.smtp_retry_attempts, 0)

    def test_non_numeric_backoff_floors_to_default_with_warning(self) -> None:
        os.environ["KERDOOS_SMTP_RETRY_BACKOFF_SECONDS"] = "abc"
        with self.assertLogs("kerdoos.config", level="WARNING") as cm:
            settings = get_settings()
        self.assertEqual(
            settings.smtp_retry_backoff_seconds, DEFAULT_SMTP_RETRY_BACKOFF_SECONDS)
        self.assertTrue(
            any("KERDOOS_SMTP_RETRY_BACKOFF_SECONDS" in msg for msg in cm.output),
            cm.output)

    def test_negative_backoff_floors_to_default_with_warning(self) -> None:
        os.environ["KERDOOS_SMTP_RETRY_BACKOFF_SECONDS"] = "-1"
        with self.assertLogs("kerdoos.config", level="WARNING"):
            settings = get_settings()
        self.assertEqual(
            settings.smtp_retry_backoff_seconds, DEFAULT_SMTP_RETRY_BACKOFF_SECONDS)

    def test_attempts_above_the_cap_floors_to_default_with_warning(self) -> None:
        # Gate LOW: the send_deadline_seconds budget bounds TIME, not the
        # NUMBER of attempts -- an unbounded count with a relay that
        # refuses instantly is a tight reconnect loop.
        os.environ["KERDOOS_SMTP_RETRY_ATTEMPTS"] = str(MAX_SMTP_RETRY_ATTEMPTS + 1)
        with self.assertLogs("kerdoos.config", level="WARNING") as cm:
            settings = get_settings()
        self.assertEqual(settings.smtp_retry_attempts, DEFAULT_SMTP_RETRY_ATTEMPTS)
        self.assertTrue(
            any("KERDOOS_SMTP_RETRY_ATTEMPTS" in msg for msg in cm.output), cm.output)

    def test_max_attempts_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_SMTP_RETRY_ATTEMPTS"] = str(MAX_SMTP_RETRY_ATTEMPTS)
        settings = get_settings()
        self.assertEqual(settings.smtp_retry_attempts, MAX_SMTP_RETRY_ATTEMPTS)

    def test_zero_backoff_floors_to_default_with_warning(self) -> None:
        # Gate LOW: backoff=0 combined with an instantly-refusing relay is
        # the same tight-reconnect-loop risk as an unbounded attempt count.
        os.environ["KERDOOS_SMTP_RETRY_BACKOFF_SECONDS"] = "0"
        with self.assertLogs("kerdoos.config", level="WARNING"):
            settings = get_settings()
        self.assertEqual(
            settings.smtp_retry_backoff_seconds, DEFAULT_SMTP_RETRY_BACKOFF_SECONDS)

    def test_min_backoff_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_SMTP_RETRY_BACKOFF_SECONDS"] = str(
            MIN_SMTP_RETRY_BACKOFF_SECONDS)
        settings = get_settings()
        self.assertEqual(
            settings.smtp_retry_backoff_seconds, MIN_SMTP_RETRY_BACKOFF_SECONDS)


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
        # int() is looser than the Dockerfile's shell case guard
        # (whitespace, a leading sign, PEP 515 underscores) -- Python must
        # reject exactly what the shell rejects, or the two disagree on the
        # same value and the container silently runs with no evaluator.
        for raw in (" 4", "4 ", "+4", "4_0", "0", "-3"):
            with self.subTest(raw=raw):
                os.environ["KERDOOS_WORKERS"] = raw
                with self.assertLogs("kerdoos.config", level="WARNING"):
                    settings = get_settings()
                self.assertEqual(settings.workers, DEFAULT_WORKERS)


class BrowserMaxConcurrentFloorTest(_SettingsTestBase):
    """Card ca30b736: a malformed KERDOOS_BROWSER_MAX_CONCURRENT warns and
    falls back to 1 instead of crashing at settings-read time."""

    def test_unset_uses_default(self) -> None:
        settings = get_settings()
        self.assertEqual(
            settings.browser_max_concurrent, DEFAULT_BROWSER_MAX_CONCURRENT)

    def test_valid_positive_integer_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_BROWSER_MAX_CONCURRENT"] = "3"
        settings = get_settings()
        self.assertEqual(settings.browser_max_concurrent, 3)

    def test_invalid_or_non_positive_values_float_to_one_with_warning(self) -> None:
        for raw in ("abc", "0", "-1", ""):
            with self.subTest(raw=raw):
                os.environ["KERDOOS_BROWSER_MAX_CONCURRENT"] = raw
                with self.assertLogs("kerdoos.config", level="WARNING") as cm:
                    settings = get_settings()
                self.assertEqual(settings.browser_max_concurrent, 1)
                self.assertTrue(
                    any("KERDOOS_BROWSER_MAX_CONCURRENT" in msg
                        for msg in cm.output), cm.output)


class BrowserAcquireTimeoutFloorTest(_SettingsTestBase):
    """Card ca30b736: a malformed KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS
    warns and floors to the default instead of crashing at settings-read
    time."""

    def test_unset_uses_default(self) -> None:
        settings = get_settings()
        self.assertEqual(
            settings.browser_acquire_timeout_seconds,
            DEFAULT_BROWSER_ACQUIRE_TIMEOUT_SECONDS)

    def test_valid_value_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS"] = "45"
        settings = get_settings()
        self.assertEqual(settings.browser_acquire_timeout_seconds, 45.0)

    def test_invalid_or_non_positive_values_float_to_default_with_warning(
        self,
    ) -> None:
        for raw in ("abc", "0", "-1", ""):
            with self.subTest(raw=raw):
                os.environ["KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS"] = raw
                with self.assertLogs("kerdoos.config", level="WARNING") as cm:
                    settings = get_settings()
                self.assertEqual(
                    settings.browser_acquire_timeout_seconds,
                    DEFAULT_BROWSER_ACQUIRE_TIMEOUT_SECONDS)
                self.assertTrue(
                    any("KERDOOS_BROWSER_ACQUIRE_TIMEOUT_SECONDS" in msg
                        for msg in cm.output), cm.output)


class RunQueueMaxRestartsFloorTest(_SettingsTestBase):
    """Card 65cef071: a malformed KERDOOS_RUN_QUEUE_MAX_RESTARTS warns and
    floors to the default instead of crashing at settings-read time."""

    def test_unset_uses_default(self) -> None:
        settings = get_settings()
        self.assertEqual(
            settings.run_queue_max_restarts, DEFAULT_RUN_QUEUE_MAX_RESTARTS)

    def test_valid_value_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_RUN_QUEUE_MAX_RESTARTS"] = "3"
        settings = get_settings()
        self.assertEqual(settings.run_queue_max_restarts, 3)

    def test_zero_is_valid(self) -> None:
        os.environ["KERDOOS_RUN_QUEUE_MAX_RESTARTS"] = "0"
        settings = get_settings()
        self.assertEqual(settings.run_queue_max_restarts, 0)

    def test_invalid_or_negative_values_float_to_default_with_warning(
        self,
    ) -> None:
        for raw in ("abc", "-1", ""):
            with self.subTest(raw=raw):
                os.environ["KERDOOS_RUN_QUEUE_MAX_RESTARTS"] = raw
                with self.assertLogs("kerdoos.config", level="WARNING") as cm:
                    settings = get_settings()
                self.assertEqual(
                    settings.run_queue_max_restarts,
                    DEFAULT_RUN_QUEUE_MAX_RESTARTS)
                self.assertTrue(
                    any("KERDOOS_RUN_QUEUE_MAX_RESTARTS" in msg
                        for msg in cm.output), cm.output)


class RunQueueBacklogWarnThresholdFloorTest(_SettingsTestBase):
    """roadmap 3c557a9c item 6: a malformed
    KERDOOS_RUN_QUEUE_BACKLOG_WARN_THRESHOLD warns and floors to the
    default instead of crashing at settings-read time."""

    def test_unset_uses_default(self) -> None:
        settings = get_settings()
        self.assertEqual(
            settings.run_queue_backlog_warn_threshold,
            DEFAULT_RUN_QUEUE_BACKLOG_WARN_THRESHOLD)

    def test_valid_value_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_RUN_QUEUE_BACKLOG_WARN_THRESHOLD"] = "3"
        settings = get_settings()
        self.assertEqual(settings.run_queue_backlog_warn_threshold, 3)

    def test_zero_disables_and_is_valid(self) -> None:
        os.environ["KERDOOS_RUN_QUEUE_BACKLOG_WARN_THRESHOLD"] = "0"
        settings = get_settings()
        self.assertEqual(settings.run_queue_backlog_warn_threshold, 0)

    def test_invalid_or_negative_values_float_to_default_with_warning(
        self,
    ) -> None:
        for raw in ("abc", "-1", ""):
            with self.subTest(raw=raw):
                os.environ["KERDOOS_RUN_QUEUE_BACKLOG_WARN_THRESHOLD"] = raw
                with self.assertLogs("kerdoos.config", level="WARNING") as cm:
                    settings = get_settings()
                self.assertEqual(
                    settings.run_queue_backlog_warn_threshold,
                    DEFAULT_RUN_QUEUE_BACKLOG_WARN_THRESHOLD)
                self.assertTrue(
                    any("KERDOOS_RUN_QUEUE_BACKLOG_WARN_THRESHOLD" in msg
                        for msg in cm.output), cm.output)


class RunNowCooldownFloorTest(_SettingsTestBase):
    """Card 1af8b18b: a malformed KERDOOS_RUN_NOW_COOLDOWN_SECONDS warns and
    floors to the default instead of crashing at settings-read time."""

    def test_unset_uses_default(self) -> None:
        settings = get_settings()
        self.assertEqual(
            settings.run_now_cooldown_seconds, DEFAULT_RUN_NOW_COOLDOWN_SECONDS)

    def test_valid_value_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_RUN_NOW_COOLDOWN_SECONDS"] = "60"
        settings = get_settings()
        self.assertEqual(settings.run_now_cooldown_seconds, 60.0)

    def test_zero_is_valid(self) -> None:
        os.environ["KERDOOS_RUN_NOW_COOLDOWN_SECONDS"] = "0"
        settings = get_settings()
        self.assertEqual(settings.run_now_cooldown_seconds, 0)

    def test_invalid_or_negative_values_float_to_default_with_warning(
        self,
    ) -> None:
        for raw in ("abc", "-1", ""):
            with self.subTest(raw=raw):
                os.environ["KERDOOS_RUN_NOW_COOLDOWN_SECONDS"] = raw
                with self.assertLogs("kerdoos.config", level="WARNING") as cm:
                    settings = get_settings()
                self.assertEqual(
                    settings.run_now_cooldown_seconds,
                    DEFAULT_RUN_NOW_COOLDOWN_SECONDS)
                self.assertTrue(
                    any("KERDOOS_RUN_NOW_COOLDOWN_SECONDS" in msg
                        for msg in cm.output), cm.output)


class UcLaunchTimeoutFloorTest(_SettingsTestBase):
    """Roadmap 65cef071: a malformed KERDOOS_UC_LAUNCH_TIMEOUT_SECONDS warns
    and floors to the default instead of crashing at settings-read time, and
    an unset one uses the uc tier's own default (uc.UC_LAUNCH_TIMEOUT_SECONDS)."""

    def test_unset_uses_default(self) -> None:
        settings = get_settings()
        self.assertEqual(
            settings.uc_launch_timeout_seconds,
            DEFAULT_UC_LAUNCH_TIMEOUT_SECONDS)

    def test_valid_value_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_UC_LAUNCH_TIMEOUT_SECONDS"] = "45"
        settings = get_settings()
        self.assertEqual(settings.uc_launch_timeout_seconds, 45.0)

    def test_invalid_or_non_positive_values_float_to_default_with_warning(
        self,
    ) -> None:
        for raw in ("abc", "0", "-1", ""):
            with self.subTest(raw=raw):
                os.environ["KERDOOS_UC_LAUNCH_TIMEOUT_SECONDS"] = raw
                with self.assertLogs("kerdoos.config", level="WARNING") as cm:
                    settings = get_settings()
                self.assertEqual(
                    settings.uc_launch_timeout_seconds,
                    DEFAULT_UC_LAUNCH_TIMEOUT_SECONDS)
                self.assertTrue(
                    any("KERDOOS_UC_LAUNCH_TIMEOUT_SECONDS" in msg
                        for msg in cm.output), cm.output)


class BrowserLaunchTimeoutFloorTest(_SettingsTestBase):
    """Roadmap b3213f3c: a malformed KERDOOS_BROWSER_LAUNCH_TIMEOUT_SECONDS
    warns and floors to the default instead of crashing at settings-read
    time, and an unset one uses the browser tier's own default
    (browser.BROWSER_LAUNCH_TIMEOUT_SECONDS)."""

    def test_unset_uses_default(self) -> None:
        settings = get_settings()
        self.assertEqual(
            settings.browser_launch_timeout_seconds,
            DEFAULT_BROWSER_LAUNCH_TIMEOUT_SECONDS)

    def test_valid_value_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_BROWSER_LAUNCH_TIMEOUT_SECONDS"] = "15"
        settings = get_settings()
        self.assertEqual(settings.browser_launch_timeout_seconds, 15.0)

    def test_invalid_or_non_positive_values_float_to_default_with_warning(
        self,
    ) -> None:
        for raw in ("abc", "0", "-1", ""):
            with self.subTest(raw=raw):
                os.environ["KERDOOS_BROWSER_LAUNCH_TIMEOUT_SECONDS"] = raw
                with self.assertLogs("kerdoos.config", level="WARNING") as cm:
                    settings = get_settings()
                self.assertEqual(
                    settings.browser_launch_timeout_seconds,
                    DEFAULT_BROWSER_LAUNCH_TIMEOUT_SECONDS)
                self.assertTrue(
                    any("KERDOOS_BROWSER_LAUNCH_TIMEOUT_SECONDS" in msg
                        for msg in cm.output), cm.output)


class LoginRateLimitWindowFloorTest(_SettingsTestBase):
    """roadmap f1048ab8: a malformed KERDOOS_LOGIN_RATE_LIMIT_WINDOW_SECONDS
    warns and floors to the default instead of crashing at settings-read
    time."""

    def test_unset_uses_default(self) -> None:
        settings = get_settings()
        self.assertEqual(
            settings.login_rate_limit_window_seconds,
            DEFAULT_LOGIN_RATE_LIMIT_WINDOW_SECONDS)

    def test_valid_value_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_LOGIN_RATE_LIMIT_WINDOW_SECONDS"] = "60"
        settings = get_settings()
        self.assertEqual(settings.login_rate_limit_window_seconds, 60.0)

    def test_invalid_or_non_positive_values_float_to_default_with_warning(
        self,
    ) -> None:
        for raw in ("abc", "0", "-1", ""):
            with self.subTest(raw=raw):
                os.environ["KERDOOS_LOGIN_RATE_LIMIT_WINDOW_SECONDS"] = raw
                with self.assertLogs("kerdoos.config", level="WARNING") as cm:
                    settings = get_settings()
                self.assertEqual(
                    settings.login_rate_limit_window_seconds,
                    DEFAULT_LOGIN_RATE_LIMIT_WINDOW_SECONDS)
                self.assertTrue(
                    any("KERDOOS_LOGIN_RATE_LIMIT_WINDOW_SECONDS" in msg
                        for msg in cm.output), cm.output)


class LoginRateLimitMaxAttemptsFloorTest(_SettingsTestBase):
    """roadmap f1048ab8: 0 explicitly disables the limiter (valid, not
    floored); a malformed or negative value warns and floors instead."""

    def test_unset_uses_default(self) -> None:
        settings = get_settings()
        self.assertEqual(
            settings.login_rate_limit_max_attempts,
            DEFAULT_LOGIN_RATE_LIMIT_MAX_ATTEMPTS)

    def test_valid_value_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_LOGIN_RATE_LIMIT_MAX_ATTEMPTS"] = "3"
        settings = get_settings()
        self.assertEqual(settings.login_rate_limit_max_attempts, 3)

    def test_zero_disables_and_is_valid(self) -> None:
        os.environ["KERDOOS_LOGIN_RATE_LIMIT_MAX_ATTEMPTS"] = "0"
        settings = get_settings()
        self.assertEqual(settings.login_rate_limit_max_attempts, 0)

    def test_invalid_or_negative_values_float_to_default_with_warning(
        self,
    ) -> None:
        for raw in ("abc", "-1", ""):
            with self.subTest(raw=raw):
                os.environ["KERDOOS_LOGIN_RATE_LIMIT_MAX_ATTEMPTS"] = raw
                with self.assertLogs("kerdoos.config", level="WARNING") as cm:
                    settings = get_settings()
                self.assertEqual(
                    settings.login_rate_limit_max_attempts,
                    DEFAULT_LOGIN_RATE_LIMIT_MAX_ATTEMPTS)
                self.assertTrue(
                    any("KERDOOS_LOGIN_RATE_LIMIT_MAX_ATTEMPTS" in msg
                        for msg in cm.output), cm.output)


class LoginRateLimitRowCapFloorTest(_SettingsTestBase):
    """roadmap f1048ab8: a malformed KERDOOS_LOGIN_RATE_LIMIT_ROW_CAP warns
    and floors to the default instead of crashing at settings-read time."""

    def test_unset_uses_default(self) -> None:
        settings = get_settings()
        self.assertEqual(
            settings.login_rate_limit_row_cap,
            DEFAULT_LOGIN_RATE_LIMIT_ROW_CAP)

    def test_valid_value_passes_through_unchanged(self) -> None:
        os.environ["KERDOOS_LOGIN_RATE_LIMIT_ROW_CAP"] = "500"
        settings = get_settings()
        self.assertEqual(settings.login_rate_limit_row_cap, 500)

    def test_invalid_or_non_positive_values_float_to_default_with_warning(
        self,
    ) -> None:
        for raw in ("abc", "0", "-1", ""):
            with self.subTest(raw=raw):
                os.environ["KERDOOS_LOGIN_RATE_LIMIT_ROW_CAP"] = raw
                with self.assertLogs("kerdoos.config", level="WARNING") as cm:
                    settings = get_settings()
                self.assertEqual(
                    settings.login_rate_limit_row_cap,
                    DEFAULT_LOGIN_RATE_LIMIT_ROW_CAP)
                self.assertTrue(
                    any("KERDOOS_LOGIN_RATE_LIMIT_ROW_CAP" in msg
                        for msg in cm.output), cm.output)


if __name__ == "__main__":
    unittest.main()
