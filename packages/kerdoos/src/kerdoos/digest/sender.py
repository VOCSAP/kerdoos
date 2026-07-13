"""DigestSender adapters (ADR 0003 Phase 6b evaluator, core.evaluator.DigestSender).

LogDigestSender is a PLACEHOLDER: it renders the digest (reusing
digest.render.render_digest) and logs it instead of emailing it. It exists so
the tranche-2 evaluator ships genuinely runnable/testable end-to-end without
pulling in tranche 4's scope (HTML rendering, SMTP delivery, and the S1/S3/S5
security hardening -- CRLF header sanitization, href scheme-allowlist,
template_id whitelist -- that a real email-sending adapter requires). Tranche
4 replaces this adapter; core.evaluator.DigestSender's Protocol is the only
contract callers need to keep satisfying.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping

from kerdoos.digest.render import render_digest
from kerdoos.persistence.ports import ScrapeRecord
from kerdoos.registry.ports import DigestJob

logger = logging.getLogger(__name__)


class LogDigestSender:
    """Renders the digest body and logs it at INFO instead of sending email."""

    def send(
        self,
        job: DigestJob,
        records: list[ScrapeRecord],
        generated_at: str,
        tier2_labels: Mapping[str, str],
    ) -> None:
        body = render_digest(records, generated_at, tier2_labels)
        logger.info(
            "digest for job=%s (%s) owner=%s:\n%s",
            job.id, job.name, job.owner_id, body,
        )
