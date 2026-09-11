"""Flat view-model for digest HTML rendering (ADR 0003 Phase 6b tranche 4,
security finding S3 CWE-79).

digest/templates.py's Jinja2 environment must NEVER receive a DigestJob,
ScrapeRecord, SiteConfig, or Registry object in its render context -- only
plain strings, so a template author (or a future template_id) cannot reach
into a domain object and accidentally render an unescaped/unexpected field.
build_digest_view() is the single choke point that flattens domain data into
DigestView/DigestLineView BEFORE anything touches Jinja.

href handling (S3 defense in depth): every candidate URL is validated via
autolycos.safety.check_scheme_and_domain (the SAME shared predicate reused by
registry.url_validation.validate_source_url -- not reimplemented here).
Unlike that validator, a rejected href does NOT abort the digest: this module
catches SSRFError and sets href=None, so one bad/off-policy link degrades to
plain text instead of failing the whole job's digest (invariant #8: exactly
one digest, never silently dropped over a single link).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from autolycos.errors import SSRFError
from autolycos.safety import DomainPolicy, check_scheme_and_domain

from kerdoos.digest.render import _price_field, _sanitize_error, _scraped_at_label
from kerdoos.persistence.ports import ScrapeRecord
from kerdoos.registry.ports import DigestJob


@dataclass(frozen=True, slots=True)
class DigestLineView:
    source_label: str
    status_label: str
    price_line: str
    availability_label: str
    scraped_at: str
    error: str | None
    href: str | None


@dataclass(frozen=True, slots=True)
class DigestView:
    job_name: str
    generated_at: str
    lines: tuple[DigestLineView, ...]


def _safe_href(url: str | None, domain_policy: DomainPolicy) -> str | None:
    if not url:
        return None
    try:
        check_scheme_and_domain(url, domain_policy)
    except SSRFError:
        # A rejected/off-policy link must never abort the whole digest for
        # this job (invariant #8) -- degrade to a plain-text label instead.
        return None
    return url


def build_digest_view(
    job: DigestJob,
    records: Sequence[ScrapeRecord],
    generated_at: str,
    tier2_labels: dict[str, str],
    source_urls: dict[str, str],
    domain_policy: DomainPolicy,
) -> DigestView:
    """Flatten job + records into a DigestView of plain strings only.

    tier2_labels and source_urls are both keyed by source_id -- the same
    convention core/evaluator.py's _collect_job_digest and
    AppService.run_now already use for tier2_labels.
    """
    lines: list[DigestLineView] = []
    for record in records:
        error = _sanitize_error(record.error) if record.error else None
        lines.append(DigestLineView(
            source_label=record.source_id,
            status_label=record.status.value,
            price_line=_price_field(record, tier2_labels.get(record.source_id)),
            availability_label=record.availability.value,
            scraped_at=_scraped_at_label(
                record.ts, generated_at, tz_name=job.timezone),
            error=error,
            href=_safe_href(source_urls.get(record.source_id), domain_policy),
        ))
    return DigestView(
        job_name=job.name,
        generated_at=generated_at,
        lines=tuple(lines),
    )
