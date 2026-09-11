"""Subprocess probe for roadmap f3b644ab gate C1a: proves the
single-recipient guard in digest/smtp_sender.py is `if ...: raise`, not
`assert` -- `assert` statements are compiled out entirely under
`python -O` / PYTHONOPTIMIZE, which would silently disable this security
guard. Invoked with `-O` by test_smtp_sender.py's
test_guard_still_fires_under_python_dash_o; not collected by pytest (no
test_/_test naming).
"""

from __future__ import annotations

from autolycos.safety import DomainPolicy

from kerdoos.digest.smtp_sender import SmtpDigestSender, SmtpSettings, _UnsafeRecipientError
from kerdoos.registry.ports import DigestJob, Registry


class _EmptyConfigStore:
    def load(self, owner: str) -> Registry:
        return Registry(sites={}, products=())


def main() -> None:
    settings = SmtpSettings(host="smtp.example.com", port=587, from_addr="digest@example.com")
    sender = SmtpDigestSender(
        _EmptyConfigStore(), DomainPolicy(allowed_domains=frozenset()),
        lambda owner: "a@example.com,b@example.com", settings,
    )
    job = DigestJob(
        id="job1", owner_id="owner1", name="job1", frequency_kind="hourly",
        schedule_cron="0 * * * *",
    )
    try:
        sender.send(job, [], "2026-07-13T00:00:00+00:00", {})
    except _UnsafeRecipientError:
        print("GUARD_FIRED")
    except Exception as exc:  # noqa: BLE001 -- reported to the parent test, not swallowed
        print(f"WRONG_EXCEPTION:{type(exc).__name__}: {exc}")
    else:
        print("GUARD_DID_NOT_FIRE")


if __name__ == "__main__":
    main()
