"""Jinja2 template environment for the WebUI (autoescape ON).

Jinja2Templates is a pure renderer: it captures only the template directory (a
static path), no runtime/DB/env state, so a module-level instance is safe here
(unlike the stateful singletons -- AuthService/AppService -- which live on
app.state). Autoescape is ON by default for .html, so every rendered value is
HTML-escaped unless a template explicitly opts out with |safe (which this UI
never does on tenant-supplied data).

Presentation-only filters live here (cents -> BRL, three-state status class,
fetcher cost tier), so routes stay thin and templates stay declarative.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

from autolycos.router import known_tiers
from kerdoos.core.domain import Availability, ScrapeStatus

_TEMPLATE_DIR = Path(__file__).parent / "templates"

# Cost-ascending rank (invariant #6) -- presentation only. Membership comes
# from the router, so a tier the router gains cannot silently miss the admin
# form nor the micro-indicator; a tier missing here only loses its rank.
_TIER_COST_ORDER = ("http", "tls", "browser", "uc", "camoufox")


def _ordered_tiers() -> tuple[str, ...]:
    """Every tier the router knows, cost-ascending. known_tiers() is a
    frozenset, so sorting is also what keeps the rendering deterministic
    across processes; an unranked tier sorts last, by name."""
    rank = {name: idx for idx, name in enumerate(_TIER_COST_ORDER)}
    return tuple(sorted(
        known_tiers(), key=lambda name: (rank.get(name, len(rank)), name)))


# The tier micro-indicator shows how hard we had to push to read this price.
_TIER_LADDER = _ordered_tiers()


def format_brl(cents: int | None) -> str:
    """Integer BRL cents -> "R$ 1.234,56" (pt-BR: dot thousands, comma
    decimals). None -> a neutral placeholder, never "R$ 0,00" (NULL != 0)."""
    if cents is None:
        return "--"
    sign = "-" if cents < 0 else ""
    reais, centavos = divmod(abs(cents), 100)
    grouped = f"{reais:,}".replace(",", ".")  # 1,234 -> 1.234 (pt-BR thousands)
    return f"{sign}R$ {grouped},{centavos:02d}"


def status_class(status: ScrapeStatus | str) -> str:
    """Three-state -> CSS modifier suffix. Never collapses the three."""
    value = status.value if isinstance(status, ScrapeStatus) else str(status)
    return {
        ScrapeStatus.OK.value: "ok",
        ScrapeStatus.INDETERMINATE.value: "indet",
        ScrapeStatus.UNAVAILABLE.value: "unavail",
    }.get(value, "indet")


def status_label(status: ScrapeStatus | str) -> str:
    value = status.value if isinstance(status, ScrapeStatus) else str(status)
    return {
        ScrapeStatus.OK.value: "OK",
        ScrapeStatus.INDETERMINATE.value: "Indetermine",
        ScrapeStatus.UNAVAILABLE.value: "Indisponible",
    }.get(value, "Indetermine")


def availability_label(availability: Availability | str) -> str:
    value = (
        availability.value if isinstance(availability, Availability)
        else str(availability))
    return {
        Availability.IN_STOCK.value: "En stock",
        Availability.OUT_OF_STOCK.value: "Rupture",
        Availability.UNKNOWN.value: "Inconnu",
    }.get(value, "Inconnu")


def tier_level(method: str | None) -> int:
    """Cost rank for the tier micro-indicator: 0 = unknown, otherwise
    the 1-based rank in the ladder (whose length follows the router)."""
    if not method:
        return 0
    key = method.strip().lower()
    for idx, name in enumerate(_TIER_LADDER, start=1):
        if key == name:
            return idx
    return 0


# -- digest jobs (Phase 6-web) -------------------------------------------

_TEMPLATE_LABELS = {"default": "Standard"}


def schedule_label(job) -> str:
    """Human-readable cadence from a DigestJob (round-trips schedule_cron).

    ASCII-only to match the other presentation filters. Falls back to the raw
    cron for any shape it does not recognise (never raises on a bad field)."""
    fields = str(job.schedule_cron).split()
    try:
        if job.frequency_kind == "hourly" and len(fields) == 5:
            return f"Chaque heure a :{int(fields[0]):02d}"
        if job.frequency_kind == "daily" and len(fields) == 5:
            return f"Chaque jour a {int(fields[1]):02d}:{int(fields[0]):02d}"
    except ValueError:
        pass
    if job.frequency_kind == "cron":
        return f"Cron : {job.schedule_cron}"
    return str(job.schedule_cron)


def frequency_label(frequency_kind: str) -> str:
    return {
        "hourly": "Horaire",
        "daily": "Quotidien",
        "cron": "Cron",
    }.get(frequency_kind, frequency_kind)


def template_label(template_id: str) -> str:
    return _TEMPLATE_LABELS.get(template_id, template_id)


# job_runs.status -> badge CSS modifier suffix / label (roadmap 3c557a9c
# item 7). System semantics (sent/error/needs-attention), NOT the product
# three-state signal (ok/indet/unavail) -- a job's send outcome is a
# different axis from a source's price-reading determinacy.
_JOB_RUN_STATUS_CLASS = {
    "sent": "sent",
    "error": "error",
    "skipped_no_email": "attention",
}
_JOB_RUN_STATUS_LABEL = {
    "sent": "Envoyé",
    "error": "Erreur",
    "skipped_no_email": "Ajoutez un e-mail",
    "queued": "En file",
    "running": "En cours",
}

# core.evaluator persists job_runs.error as
# f"{type(exc).__name__}: {exc}"[:500]; the reaper's own sweep uses the
# literal prefix "reaped" instead of an exception class name
# (persistence.sqlite_store.reap_stale_job_run). The raw text can carry
# the SMTP relay's internal hostname, an operator auth identifier, or raw
# relay response text -- only a generic label ever reaches the tenant.
_JOB_RUN_ERROR_REFUSED = frozenset({
    "SMTPRecipientsRefused", "SMTPSenderRefused", "SMTPDataError",
})
_JOB_RUN_ERROR_TRANSIENT = frozenset({
    "TimeoutError", "OSError", "SMTPConnectError", "SMTPServerDisconnected",
    "reaped",
})
_JOB_RUN_ERROR_CONFIG = frozenset({
    "SMTPAuthenticationError", "SMTPNotSupportedError",
})


def job_run_status_class(summary) -> str:
    if summary is None:
        return "pending"
    return _JOB_RUN_STATUS_CLASS.get(summary.latest.status, "pending")


def job_run_status_label(summary) -> str:
    if summary is None:
        return "Jamais envoyé"
    return _JOB_RUN_STATUS_LABEL.get(summary.latest.status, "Statut inconnu")


def job_run_error_label(summary) -> str:
    if summary is None or not summary.latest.error:
        return "Erreur d'envoi"
    # type(exc).__name__ for an SSL exception is the concrete subclass
    # (e.g. SSLCertVerificationError), never the base class name
    # "SSLError" -- matched by prefix rather than an exact-match set.
    prefix = summary.latest.error.split(":", 1)[0]
    if prefix == "_UnsafeRecipientError":
        return "Adresse e-mail invalide, mettez-la à jour dans votre profil"
    if prefix in _JOB_RUN_ERROR_REFUSED:
        return "Adresse refusée par le serveur de messagerie"
    if prefix in _JOB_RUN_ERROR_TRANSIENT:
        return "Échec d'envoi temporaire, nouvel essai à la prochaine fenêtre"
    if prefix in _JOB_RUN_ERROR_CONFIG or prefix.startswith("SSL"):
        return ("Problème de configuration du serveur d'envoi, contactez "
                "l'administrateur")
    return "Erreur d'envoi"


templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))
templates.env.filters["brl"] = format_brl
templates.env.filters["status_class"] = status_class
templates.env.filters["status_label"] = status_label
templates.env.filters["availability_label"] = availability_label
templates.env.filters["tier_level"] = tier_level
templates.env.filters["schedule_label"] = schedule_label
templates.env.filters["frequency_label"] = frequency_label
templates.env.filters["template_label"] = template_label
templates.env.filters["job_run_status_class"] = job_run_status_class
templates.env.filters["job_run_status_label"] = job_run_status_label
templates.env.filters["job_run_error_label"] = job_run_error_label
templates.env.globals["tier_ladder"] = _TIER_LADDER
