"""digest.factory.build_sender: SMTP timeout wiring and the timeout-ordering
invariant (roadmap 58d88fe0).

smtp_timeout_seconds must be strictly between 0 and digest_reaper_timeout_seconds.
A misconfigured value (>= reaper_timeout, zero, negative, or NaN) is CLAMPED
to a safe value with a logged warning rather than raising: build_sender runs
inside interfaces/web/app.py's ASGI lifespan, where an uncaught exception
fails the ENTIRE WebUI startup (no /health, no login), not just the digest
path -- mirrors this module's existing degrade-not-crash policy for a
missing SMTP host/from.
"""

from __future__ import annotations

import math
import os
import shutil
import tempfile
import unittest

from autolycos.safety import DomainPolicy

from kerdoos.config import get_settings
from kerdoos.digest.factory import build_sender
from kerdoos.digest.smtp_sender import SmtpDigestSender

_SMTP_ENV_VARS = (
    "KERDOOS_SMTP_HOST", "KERDOOS_SMTP_PORT", "KERDOOS_SMTP_FROM",
    "KERDOOS_SMTP_USERNAME", "KERDOOS_SMTP_PASSWORD", "KERDOOS_SMTP_USE_TLS",
    "KERDOOS_SMTP_TIMEOUT_SECONDS", "KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS",
)


class _FactoryTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = {var: os.environ.pop(var, None) for var in _SMTP_ENV_VARS}
        self._dir = tempfile.mkdtemp(prefix="kerdoos-digest-factory-")
        self.addCleanup(shutil.rmtree, self._dir, ignore_errors=True)
        os.environ["KERDOOS_SMTP_HOST"] = "smtp.example.com"
        os.environ["KERDOOS_SMTP_FROM"] = "digest@example.com"
        self.addCleanup(self._restore_env)

    def _restore_env(self) -> None:
        for var, value in self._saved.items():
            if value is None:
                os.environ.pop(var, None)
            else:
                os.environ[var] = value

    def _build(self) -> SmtpDigestSender:
        settings = get_settings()
        config_db = os.path.join(self._dir, "config.db")
        sender = build_sender(
            settings, config_store=object(),
            domain_policy=DomainPolicy(allowed_domains=frozenset()),
            config_db_path=config_db,
        )
        self.assertIsInstance(sender, SmtpDigestSender)
        return sender


class SmtpTimeoutOrderingTest(_FactoryTestBase):
    def test_timeout_lt_reaper_timeout_builds_smtp_sender_with_that_timeout(
        self,
    ) -> None:
        os.environ["KERDOOS_SMTP_TIMEOUT_SECONDS"] = "17"
        os.environ["KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS"] = "300"

        sender = self._build()

        self.assertEqual(sender._smtp.timeout_seconds, 17.0)
        self.assertLess(sender._smtp.timeout_seconds, 300)

    def test_timeout_gte_reaper_timeout_is_clamped_not_raised(self) -> None:
        # roadmap 58d88fe0 gate fix: a misconfigured pair must DEGRADE (the
        # WebUI keeps starting), never crash the whole ASGI lifespan.
        os.environ["KERDOOS_SMTP_TIMEOUT_SECONDS"] = "300"
        os.environ["KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS"] = "300"

        with self.assertLogs("kerdoos.digest.factory", level="WARNING") as cm:
            sender = self._build()

        self.assertLess(sender._smtp.timeout_seconds, 300)
        self.assertGreater(sender._smtp.timeout_seconds, 0)
        self.assertTrue(any("clamping" in msg for msg in cm.output), cm.output)

    def test_zero_timeout_is_clamped_not_raised(self) -> None:
        os.environ["KERDOOS_SMTP_TIMEOUT_SECONDS"] = "0"
        os.environ["KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS"] = "300"

        with self.assertLogs("kerdoos.digest.factory", level="WARNING"):
            sender = self._build()

        self.assertGreater(sender._smtp.timeout_seconds, 0)
        self.assertLess(sender._smtp.timeout_seconds, 300)

    def test_negative_timeout_is_clamped_not_raised(self) -> None:
        os.environ["KERDOOS_SMTP_TIMEOUT_SECONDS"] = "-5"
        os.environ["KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS"] = "300"

        with self.assertLogs("kerdoos.digest.factory", level="WARNING"):
            sender = self._build()

        self.assertGreater(sender._smtp.timeout_seconds, 0)
        self.assertLess(sender._smtp.timeout_seconds, 300)

    def test_nan_timeout_is_clamped_not_raised(self) -> None:
        # nan defeats a plain `>=` comparison (any comparison against NaN is
        # False in Python) -- the guard must use a range check that rejects
        # it explicitly rather than silently passing it through to smtplib.
        os.environ["KERDOOS_SMTP_TIMEOUT_SECONDS"] = "nan"
        os.environ["KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS"] = "300"

        with self.assertLogs("kerdoos.digest.factory", level="WARNING"):
            sender = self._build()

        self.assertFalse(math.isnan(sender._smtp.timeout_seconds))
        self.assertGreater(sender._smtp.timeout_seconds, 0)
        self.assertLess(sender._smtp.timeout_seconds, 300)


if __name__ == "__main__":
    unittest.main()
