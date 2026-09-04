"""digest.factory.build_sender: SMTP timeout wiring and the timeout-ordering
invariant (Phase 7a fast-follow, roadmap 58d88fe0).

smtp_timeout_seconds must be strictly LESS than digest_reaper_timeout_seconds
-- a wedged SMTP send must always unblock before the reaper's own staleness
window would need to reclaim the stranded job_runs row. build_sender enforces
this at construction time (fail fast, not a coincidence of two defaults).
"""

from __future__ import annotations

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


class SmtpTimeoutOrderingTest(_FactoryTestBase):
    def test_timeout_gte_reaper_timeout_raises_value_error(self) -> None:
        os.environ["KERDOOS_SMTP_TIMEOUT_SECONDS"] = "300"
        os.environ["KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS"] = "300"
        settings = get_settings()
        config_db = os.path.join(self._dir, "config.db")

        with self.assertRaises(ValueError) as ctx:
            build_sender(
                settings, config_store=object(),
                domain_policy=DomainPolicy(allowed_domains=frozenset()),
                config_db_path=config_db,
            )
        self.assertIn("strictly less than", str(ctx.exception))

    def test_timeout_lt_reaper_timeout_builds_smtp_sender_with_that_timeout(
        self,
    ) -> None:
        os.environ["KERDOOS_SMTP_TIMEOUT_SECONDS"] = "17"
        os.environ["KERDOOS_DIGEST_REAPER_TIMEOUT_SECONDS"] = "300"
        settings = get_settings()
        config_db = os.path.join(self._dir, "config.db")

        sender = build_sender(
            settings, config_store=object(),
            domain_policy=DomainPolicy(allowed_domains=frozenset()),
            config_db_path=config_db,
        )

        self.assertIsInstance(sender, SmtpDigestSender)
        self.assertEqual(sender._smtp.timeout_seconds, 17.0)
        self.assertLess(
            sender._smtp.timeout_seconds, settings.digest_reaper_timeout_seconds)


if __name__ == "__main__":
    unittest.main()
