"""Exactly-once scheduling primitive: quantized window_start (ADR 0003 Phase
6b, architect finding #5).

`window_start` is the idempotence key half of `(job_id, window_start)`
(persistence/ports.py JobRun) -- it must be the most recent CRON-GRID
occurrence <= now, quantized in the job's OWN IANA timezone, NOT the raw
60s evaluator tick timestamp. Using the raw tick timestamp as window_start
would make a daily job "re-fire" at every tick (each tick has a distinct
timestamp, so INSERT ... ON CONFLICT DO NOTHING would never collide and the
idempotence key would be useless).

Pure function, no I/O, no store/port imports -- core/ stays tool-agnostic
(invariant #1). Only croniter + stdlib zoneinfo/datetime.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from croniter import croniter

# croniter.get_prev(datetime) is EXCLUSIVE of an exact-boundary base time: if
# `now` lands EXACTLY on a scheduled occurrence, get_prev skips past it and
# returns the PREVIOUS one instead. Nudging the base time forward by a single
# microsecond before constructing the croniter instance makes the boundary
# INCLUSIVE (the occurrence at `now` itself is then correctly returned),
# without affecting any non-boundary case (the nudge is far smaller than any
# realistic cron grid resolution of whole minutes).
_INCLUSIVE_EPSILON = timedelta(microseconds=1)


def compute_window_start(schedule_cron: str, tz_name: str, now: datetime) -> str:
    """Most recent scheduled occurrence <= `now`, quantized on the cron grid
    in the job's own local timezone, returned as UTC ISO-8601.

    `now` may be naive (assumed UTC) or aware (converted to UTC first) --
    the evaluator always passes an aware UTC `now`, but this stays permissive
    for direct unit-test callers.
    """
    if now.tzinfo is None:
        now_utc = now.replace(tzinfo=timezone.utc)
    else:
        now_utc = now.astimezone(timezone.utc)

    local_now = now_utc.astimezone(ZoneInfo(tz_name))
    cron = croniter(schedule_cron, local_now + _INCLUSIVE_EPSILON)
    occurrence_local = cron.get_prev(datetime)
    # croniter.get_prev(datetime) returns a naive datetime carrying the SAME
    # wall-clock fields as the (aware) base -- it drops tzinfo, so it must be
    # re-attached before converting back to UTC (croniter issue: the result
    # is tz-naive even when the base was tz-aware).
    if occurrence_local.tzinfo is None:
        occurrence_local = occurrence_local.replace(tzinfo=ZoneInfo(tz_name))
    occurrence_utc = occurrence_local.astimezone(timezone.utc)
    return occurrence_utc.isoformat()
