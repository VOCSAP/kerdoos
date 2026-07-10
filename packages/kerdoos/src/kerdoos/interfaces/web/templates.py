"""Jinja2 template environment for the WebUI (autoescape ON).

Jinja2Templates is a pure renderer: it captures only the template directory (a
static path), no runtime/DB/env state, so a module-level instance is safe here
(unlike the stateful singletons -- AuthService/AppService -- which live on
app.state). Autoescape is ON by default for .html, so every rendered value is
HTML-escaped unless a template explicitly opts out with |safe (which this UI
never does on tenant-supplied data).

Presentation-only filters live here (cents -> BRL, three-state status class,
fetcher escalation tier), so routes stay thin and templates stay declarative.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.templating import Jinja2Templates

from kerdoos.core.domain import Availability, ScrapeStatus

_TEMPLATE_DIR = Path(__file__).parent / "templates"

# Fetcher escalation ladder (invariant #6): the tier micro-indicator shows how
# hard we had to push to read this price. Order is cost-ascending.
_TIER_LADDER = ("http", "tls", "browser", "uc_selenium")


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
    """Escalation depth 0..4 for the tier micro-indicator (0 = unknown)."""
    if not method:
        return 0
    key = method.strip().lower()
    for idx, name in enumerate(_TIER_LADDER, start=1):
        if key == name:
            return idx
    return 0


templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))
templates.env.filters["brl"] = format_brl
templates.env.filters["status_class"] = status_class
templates.env.filters["status_label"] = status_label
templates.env.filters["availability_label"] = availability_label
templates.env.filters["tier_level"] = tier_level
templates.env.globals["tier_ladder"] = _TIER_LADDER
