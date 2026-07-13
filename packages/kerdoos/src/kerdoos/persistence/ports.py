"""StateStore port + ScrapeRecord DTO.

ScrapeRecord is the full history row (successes AND errors). It imports domain
enums (adapters -> domain). No storage engine leaks through this port, so the
SQLite MVP can migrate to Postgres without touching callers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from kerdoos.core.domain import Availability, ScrapeStatus


@dataclass(frozen=True, slots=True)
class ScrapeRecord:
    """One scrape outcome. Prices are integer cents (BRL), nullable.

    raw_ref is a dormant opaque key at the MVP (schema column, not populated):
    it must never carry a filesystem path (CWE-22).
    """

    source_id: str
    ts: str                       # ISO-8601 UTC
    status: ScrapeStatus
    price_pix_cents: int | None
    price_card_cents: int | None
    currency: str | None
    availability: Availability
    method: str | None
    error: str | None
    # Membership-gated tier (same 'member' axis as Extract); None when the site
    # exposes no gated price. Nullable columns, additive migration (user_version 2).
    price_pix_member_cents: int | None = None
    price_card_member_cents: int | None = None
    raw_ref: str | None = None


@dataclass(frozen=True, slots=True)
class JobRun:
    """One digest-job evaluator firing (ADR 0003 Decision 3, Phase 6a schema
    only -- the evaluator itself is a 6b concern). (job_id, window_start) is
    the idempotence key: the SAME tick can be recorded at most once per job,
    so a crash-and-retry of the evaluator never double-sends a digest.

    No FK to config.db's digest_jobs (ADR 0003 T2 -- state.db and config.db
    are physically separate files, no cross-DB FK is possible in SQLite).
    owner_id is carried here redundantly (not just derivable via a join) so
    every read/write can filter it inline, same discipline as ScrapeRecord's
    table.
    """

    job_id: str
    owner_id: str
    # ISO-8601 UTC. NOT the raw evaluator tick timestamp -- the most recent
    # occurrence of the job's OWN cron schedule (in the job's own IANA tz)
    # that is <= the tick time, quantized via
    # core.scheduler.compute_window_start (ADR 0003 Phase 6b, architect
    # finding #5). A daily job ticked every 60s must resolve to the SAME
    # window_start for every tick within that day's window, or the
    # (job_id, window_start) idempotence key below is defeated and the job
    # re-fires on every tick.
    window_start: str
    fired_at: str                 # ISO-8601 UTC, when the evaluator actually ran this
    # 'queued' | 'running' | 'sent' | 'skipped' | 'skipped_no_email' | 'error'
    # (Phase 6a persisted only 'sent'/'skipped'/'error'; Phase 6b adds
    # 'queued'/'running' as the evaluator's own in-flight states -- see
    # StateStore.has_active_job_run -- and 'skipped_no_email' for an owner
    # without an email at send time, ADR 0003 Decision 9).
    status: str
    sent_at: str | None = None
    error: str | None = None


@runtime_checkable
class StateStore(Protocol):
    """Persist and read back scrape history, tenant-scoped (ADR 0001 S4).

    owner is REQUIRED on every method and filters every SQL statement inline
    -- never a trailing/optional filter -- so a tenant can never read or
    accidentally write another tenant's history, even by guessing a
    source_id.
    """

    def record(self, owner: str, scrape: ScrapeRecord) -> None:
        ...

    def history(
        self, owner: str, source_id: str, limit: int = 50
    ) -> list[ScrapeRecord]:
        ...

    def latest_all(self, owner: str) -> list[ScrapeRecord]:
        """Most recent record per source_id, scoped to owner (no N+1)."""
        ...

    def record_job_run(self, run: JobRun) -> bool:
        """Persist one evaluator firing. Returns True if this is the FIRST
        record for (job_id, window_start), False if it was already recorded
        (idempotent no-op -- ADR 0003 Decision 3 idempotence key). Never
        raises on a duplicate; the bool return is the only signal."""
        ...

    def update_job_run(
        self,
        job_id: str,
        window_start: str,
        *,
        status: str,
        sent_at: str | None = None,
        error: str | None = None,
    ) -> bool:
        """Transition an EXISTING (job_id, window_start) row's status
        (Phase 6b lifecycle -- ADR 0003 architect finding #6, e.g.
        'queued' -> 'running' -> 'sent'/'skipped'/'error'). Returns True if a
        row was found and updated, False if no row exists for that
        (job_id, window_start) pair (never raises on a missing row)."""
        ...

    def has_active_job_run(self, owner: str, job_id: str) -> bool:
        """True while `job_id` (scoped to `owner`, IDOR-safe double-scoping
        per ADR 0003 finding S2) has a job_runs row with status 'queued' or
        'running' -- the per-job singleton coalescing check: the evaluator
        must skip a tick for a job that is still in flight from a previous
        tick (ADR 0003 Decision 4 / architect finding #6)."""
        ...
