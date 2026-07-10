"""Admin-gated router (ADR 0001): every route requires a valid session AND
role == 'admin' (Depends(require_admin) at the ROUTER level, rule FastAPI
"auth au niveau router"). Unsafe methods additionally carry CSRF
(Depends(verify_csrf)).

Holds the JSON `/admin/whoami` probe (Phase 4a, unchanged) plus the Phase 4b
HTML admin surface: the site catalogue (a global, admin-only allowlist of
merchant domains). Same visual world as the tenant UI, differentiated by a
bronze "ADMIN" eyebrow, not by colour -- the distinction is semantic and
enforced server-side, not chromatic.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request, Response, status

from kerdoos.core.app.services import AppService, Principal
from kerdoos.interfaces.web.csrf import csrf_token_for, verify_csrf
from kerdoos.interfaces.web.deps import get_app_service, require_admin
from kerdoos.interfaces.web.templates import templates
from kerdoos.parsers.ports import ParserSpec
from kerdoos.registry.ports import SiteConfig

router = APIRouter(
    prefix="/admin",
    dependencies=[Depends(require_admin), Depends(verify_csrf)],
)

_NEXT_CUT = "06:00"


@router.get("/whoami")
def whoami(principal: Principal = Depends(require_admin)) -> dict[str, str]:
    return {"owner_id": principal.owner_id, "role": principal.role}


def _render_admin(
    request: Request, principal: Principal, svc: AppService, csrf: str,
    *, form_error: str | None = None, site_saved: str | None = None,
    status_code: int = 200,
) -> Response:
    registry = svc.list_config(principal.owner_id)
    ctx = {
        "request": request, "principal": principal, "csrf_token": csrf,
        "active": "admin", "next_cut": _NEXT_CUT,
        "sites": registry.sites, "form_error": form_error,
        "site_saved": site_saved,
    }
    return templates.TemplateResponse(
        request, "admin/index.html", ctx, status_code=status_code)


@router.get("")
def admin_home(
    request: Request,
    principal: Principal = Depends(require_admin),
    svc: AppService = Depends(get_app_service),
    csrf: str = Depends(csrf_token_for),
) -> Response:
    return _render_admin(request, principal, svc, csrf)


@router.post("/sites")
def add_site(
    request: Request,
    name: str = Form(...),
    fetcher: str = Form(...),
    domain: str = Form(...),
    parser_kind: str = Form(...),
    parser_pix: str = Form(""),
    parser_card: str = Form(""),
    parser_availability: str = Form(""),
    tier2_label: str = Form(""),
    principal: Principal = Depends(require_admin),
    svc: AppService = Depends(get_app_service),
    csrf: str = Depends(csrf_token_for),
) -> Response:
    spec = SiteConfig(
        name=name.strip(),
        fetcher=fetcher.strip(),
        parser=ParserSpec(
            kind=parser_kind.strip(),
            pix=parser_pix.strip() or None,
            card=parser_card.strip() or None,
            availability=parser_availability.strip() or None,
        ),
        domain=domain.strip(),
        tier2_label=tier2_label.strip() or None,
    )
    try:
        svc.add_site(principal, spec)  # re-checks admin role (second rampart)
    except PermissionError:
        # Should be unreachable behind require_admin, but fail closed.
        return _render_admin(
            request, principal, svc, csrf,
            form_error="Action réservée aux administrateurs.",
            status_code=status.HTTP_403_FORBIDDEN)
    except Exception:  # noqa: BLE001 -- generic (duplicate name / invalid config)
        return _render_admin(
            request, principal, svc, csrf,
            form_error="Site refusé : nom déjà pris ou configuration invalide.",
            status_code=status.HTTP_400_BAD_REQUEST)
    return _render_admin(request, principal, svc, csrf, site_saved=spec.name)
