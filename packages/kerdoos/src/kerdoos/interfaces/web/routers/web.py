"""Tenant WebUI (server-rendered Jinja2 + HTMX). Thin views over AppService /
AuthService (invariant #9): each handler resolves the principal, calls a
use-case with owner = principal.owner_id, and renders a template. No business
logic here.

Auth AND CSRF are attached at the ROUTER level (rule FastAPI "au niveau
router"): verify_session gates every route, verify_csrf gates every unsafe
method. owner_id ALWAYS comes from the session Principal, never from the request
body/query, and is never serialised back to the client.
"""

from __future__ import annotations

from datetime import datetime, timezone as _utc

from autolycos.safety import DomainPolicy
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from kerdoos.auth.ports import EmailAlreadyTakenError
from kerdoos.core.app.auth import AuthService
from kerdoos.core.app.services import (
    AppService,
    DigestJobSpec,
    Principal,
    ProductSpec,
)
from kerdoos.core.run_queue import RunQueue
from kerdoos.digest.templates import render_digest_html
from kerdoos.digest.view import build_digest_view
from kerdoos.interfaces.web.csrf import csrf_token_for, verify_csrf
from kerdoos.interfaces.web.deps import (
    get_app_service,
    get_auth_service,
    get_domain_policy,
    get_run_queue,
    get_session_cookie,
    verify_session,
)
from kerdoos.interfaces.web.security import SessionCookie
from kerdoos.interfaces.web.templates import templates
from kerdoos.registry.ports import VALID_TEMPLATE_IDS, dump_job_options

# Digest cut-off shown in the topbar (ambient time anchor of the watch station).
_NEXT_CUT = "06:00"

router = APIRouter(dependencies=[Depends(verify_session), Depends(verify_csrf)])


def _base(request: Request, principal: Principal, csrf: str, active: str) -> dict:
    return {
        "request": request,
        "principal": principal,
        "csrf_token": csrf,
        "active": active,
        "next_cut": _NEXT_CUT,
    }


# ===== Dashboard =========================================================
@router.get("/")
def dashboard(
    request: Request,
    principal: Principal = Depends(verify_session),
    svc: AppService = Depends(get_app_service),
    queue: RunQueue = Depends(get_run_queue),
    csrf: str = Depends(csrf_token_for),
) -> Response:
    owner = principal.owner_id
    records = svc.list_state(owner)
    registry = svc.list_config(owner)
    run_status = queue.status_for(owner)
    cooldown_remaining = queue.cooldown_remaining_seconds(owner)

    # Presentation join (invariant #9: orchestration, not business logic):
    # list_state yields ScrapeRecord keyed only by source_id, so pair each with
    # its product name / site / url from the config. Built directly from
    # products (not iter_sources) so a dangling site reference never 500s.
    index: dict[str, tuple] = {}
    for product in registry.products:
        for source in product.sources:
            index[source.source_id] = (product, source)

    rows = []
    counts = {"ok": 0, "indeterminate": 0, "unavailable": 0}
    for rec in records:
        counts[rec.status.value] = counts.get(rec.status.value, 0) + 1
        meta = index.get(rec.source_id)
        if meta is not None:
            product, source = meta
            rows.append({
                "record": rec,
                "product_name": product.name or product.id,
                "site": source.site,
                "url": source.url,
            })
        else:
            rows.append({
                "record": rec, "product_name": rec.source_id,
                "site": "--", "url": None,
            })

    briefing = {
        "ok": counts["ok"],
        "indeterminate": counts["indeterminate"],
        "unavailable": counts["unavailable"],
        "to_watch": counts["indeterminate"] + counts["unavailable"],
    }
    # Admin-only, never serialised to a non-admin tenant (invariant 10 --
    # instance-wide operational load, not owner-scoped data, but still
    # restricted to the operator persona per DESIGN.md).
    backlog_warning_depth = (
        queue.queued_count
        if principal.role == "admin" and queue.backlog_warning_active
        else None)

    ctx = _base(request, principal, csrf, "dashboard")
    ctx.update(
        rows=rows, briefing=briefing, run_status=run_status,
        cooldown_remaining=cooldown_remaining,
        backlog_warning_depth=backlog_warning_depth)
    return templates.TemplateResponse(request, "dashboard/index.html", ctx)


@router.post("/run")
async def run_now(
    principal: Principal = Depends(verify_session),
    queue: RunQueue = Depends(get_run_queue),
) -> Response:
    # Enqueue and redirect immediately (card ca30b736: the request must
    # never block on a scrape). A second POST /run while this owner's run is
    # already queued/running is silently coalesced -- enqueue()'s return
    # value is not surfaced as an error, matching that intent.
    await queue.enqueue(principal.owner_id)
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


# ===== History ===========================================================
@router.get("/history/{source_id}")
def history(
    source_id: str,
    request: Request,
    principal: Principal = Depends(verify_session),
    svc: AppService = Depends(get_app_service),
    csrf: str = Depends(csrf_token_for),
) -> Response:
    owner = principal.owner_id
    records = svc.get_history(owner, source_id, limit=50)
    registry = svc.list_config(owner)
    product_name = source_id
    site = None
    for product in registry.products:
        for source in product.sources:
            if source.source_id == source_id:
                product_name = product.name or product.id
                site = source.site
    ctx = _base(request, principal, csrf, "products")
    ctx.update(records=records, source_id=source_id,
               product_name=product_name, site=site)
    return templates.TemplateResponse(request, "history/detail.html", ctx)


# ===== Products / sources ================================================
def _render_products(
    request: Request, principal: Principal, svc: AppService, csrf: str,
    *, form_error: str | None = None, status_code: int = 200,
) -> Response:
    registry = svc.list_config(principal.owner_id)
    ctx = _base(request, principal, csrf, "products")
    ctx.update(registry=registry, form_error=form_error)
    return templates.TemplateResponse(
        request, "products/index.html", ctx, status_code=status_code)


@router.get("/products")
def products(
    request: Request,
    principal: Principal = Depends(verify_session),
    svc: AppService = Depends(get_app_service),
    csrf: str = Depends(csrf_token_for),
) -> Response:
    return _render_products(request, principal, svc, csrf)


@router.post("/products")
def add_product(
    request: Request,
    product_key: str = Form(...),
    name: str = Form(""),
    principal: Principal = Depends(verify_session),
    svc: AppService = Depends(get_app_service),
    csrf: str = Depends(csrf_token_for),
) -> Response:
    clean_name = name.strip() or None
    try:
        svc.add_product(
            principal.owner_id,
            ProductSpec(product_key=product_key.strip(), name=clean_name))
    except (ValueError, KeyError):
        # DOMAIN errors only (bad product_key -> ValueError). Anything
        # unexpected propagates to 500 -- never masked as a client 400.
        return _render_products(
            request, principal, svc, csrf,
            form_error="Clé produit invalide.",
            status_code=status.HTTP_400_BAD_REQUEST)
    return RedirectResponse("/products", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/sources")
def add_source(
    request: Request,
    product_key: str = Form(...),
    site: str = Form(...),
    url: str = Form(...),
    principal: Principal = Depends(verify_session),
    svc: AppService = Depends(get_app_service),
    csrf: str = Depends(csrf_token_for),
) -> Response:
    try:
        svc.add_source(principal.owner_id, product_key.strip(), site.strip(),
                       url.strip())
    except (ValueError, KeyError):
        # DOMAIN errors only: KeyError (unknown site), UrlValidationError /
        # ConfigError (both ValueError subclasses: rejected URL / domain,
        # invalid product_key). Anything unexpected propagates to 500.
        return _render_products(
            request, principal, svc, csrf,
            form_error="Source refusée : site inconnu ou URL non autorisée.",
            status_code=status.HTTP_400_BAD_REQUEST)
    return RedirectResponse("/products", status_code=status.HTTP_303_SEE_OTHER)


@router.delete("/products/{product_key}")
def remove_product(
    product_key: str,
    principal: Principal = Depends(verify_session),
    svc: AppService = Depends(get_app_service),
) -> Response:
    try:
        svc.remove_product(principal.owner_id, product_key)
    except KeyError:
        # Owner-scoped: unknown OR not-owned both raise KeyError. Return a
        # generic 404 so the response never reveals whether the key exists for
        # another tenant (no cross-tenant existence oracle).
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT,
                    headers={"HX-Redirect": "/products"})


@router.delete("/sources/{source_id}")
def remove_source(
    source_id: str,
    principal: Principal = Depends(verify_session),
    svc: AppService = Depends(get_app_service),
) -> Response:
    svc.remove_source(principal.owner_id, source_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT,
                    headers={"HX-Redirect": "/products"})


# ===== Profile ===========================================================
@router.get("/profile")
def profile(
    request: Request,
    principal: Principal = Depends(verify_session),
    auth: AuthService = Depends(get_auth_service),
    csrf: str = Depends(csrf_token_for),
) -> Response:
    ctx = _base(request, principal, csrf, "profile")
    ctx.update(tokens=auth.list_tokens(principal),
               email=auth.get_email(principal), new_token=None)
    return templates.TemplateResponse(request, "profile/index.html", ctx)


@router.post("/profile/tokens")
def create_token(
    request: Request,
    principal: Principal = Depends(verify_session),
    auth: AuthService = Depends(get_auth_service),
    csrf: str = Depends(csrf_token_for),
) -> Response:
    issued = auth.create_token(principal)  # self-only; no target-owner param
    ctx = _base(request, principal, csrf, "profile")
    # Render (not redirect): the plaintext token is shown ONCE, here only.
    ctx.update(tokens=auth.list_tokens(principal),
               email=auth.get_email(principal), new_token=issued)
    return templates.TemplateResponse(request, "profile/index.html", ctx)


@router.delete("/profile/tokens/{token_id}")
def revoke_token(
    token_id: str,
    principal: Principal = Depends(verify_session),
    auth: AuthService = Depends(get_auth_service),
) -> Response:
    auth.revoke_token(principal, token_id)  # owner-scoped, own tokens only
    return Response(status_code=status.HTTP_204_NO_CONTENT,
                    headers={"HX-Redirect": "/profile"})


@router.post("/profile/tokens/revoke-all")
def revoke_all_tokens(
    principal: Principal = Depends(verify_session),
    auth: AuthService = Depends(get_auth_service),
    cookie: SessionCookie = Depends(get_session_cookie),
) -> Response:
    # revoke_all cuts ALL of the owner's tokens AND sessions -- including the
    # current one -- so this logs the caller out. Send them to /login (a
    # /profile redirect would just 401 on the now-dead session).
    auth.revoke_all(principal, principal.owner_id)  # self-service, full cut
    redirect = RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)
    # Clear the now-revoked cookie client-side too (mirror logout): the session
    # is dead server-side, so the stale cookie must not linger in the browser.
    redirect.delete_cookie(**cookie.clear_kwargs())
    return redirect


@router.post("/profile/email")
def set_email(
    request: Request,
    email: str = Form(""),
    principal: Principal = Depends(verify_session),
    auth: AuthService = Depends(get_auth_service),
    csrf: str = Depends(csrf_token_for),
) -> Response:
    # Self-scope (owner from Principal): set or clear the caller's own email.
    value = email.strip() or None
    ctx = _base(request, principal, csrf, "profile")
    try:
        auth.set_email(principal, value)
    except EmailAlreadyTakenError:
        # Generic: never confirm WHICH other account holds the address (no
        # cross-owner enumeration).
        ctx.update(tokens=auth.list_tokens(principal), email=value,
                   new_token=None, email_error="Email indisponible.")
        return templates.TemplateResponse(request, "profile/index.html", ctx)
    except ValueError:
        ctx.update(tokens=auth.list_tokens(principal), email=value,
                   new_token=None, email_error="Email invalide.")
        return templates.TemplateResponse(request, "profile/index.html", ctx)
    ctx.update(tokens=auth.list_tokens(principal), email=value,
               new_token=None, email_saved=True)
    return templates.TemplateResponse(request, "profile/index.html", ctx)


# ===== Notifications (digest jobs, ADR 0003, Phase 6-web) ================
# Curated IANA zones for the picker. The product monitors Brazilian e-commerce,
# so Sao_Paulo leads. This is only the shortlist offered in the UI -- the store
# validates against the FULL IANA set via registry.validate_timezone, so a job
# authored elsewhere (CLI/MCP) with another zone is never rejected on read.
_TIMEZONES = (
    "America/Sao_Paulo", "America/Manaus", "America/Fortaleza",
    "UTC", "Europe/Paris", "Europe/Lisbon",
)


def _owner_sources(registry) -> list[dict]:
    """Flatten the owner's registry into picker rows (presentation join,
    invariant #9: orchestration, not business logic)."""
    rows: list[dict] = []
    for product in registry.products:
        for source in product.sources:
            rows.append({
                "source_id": source.source_id,
                "product_name": product.name or product.id,
                "site": source.site,
                "url": source.url,
            })
    return rows


def _spec_from_job(job, *, enabled: bool) -> DigestJobSpec:
    """Rebuild an update-ready DigestJobSpec from a stored DigestJob, round-
    tripping schedule_cron back into minute/hour/cron_expr. Used to flip the
    enabled flag without re-authoring the whole schedule."""
    fields = str(job.schedule_cron).split()
    minute = hour = 0
    cron_expr: str | None = None
    if job.frequency_kind == "hourly" and len(fields) >= 1:
        minute = int(fields[0])
    elif job.frequency_kind == "daily" and len(fields) >= 2:
        minute, hour = int(fields[0]), int(fields[1])
    elif job.frequency_kind == "cron":
        cron_expr = job.schedule_cron
    return DigestJobSpec(
        name=job.name, frequency_kind=job.frequency_kind,
        minute=minute, hour=hour, cron_expr=cron_expr,
        timezone=job.timezone, template_id=job.template_id,
        options=dump_job_options(job.options), enabled=enabled)


def _render_notifications(
    request: Request, principal: Principal, svc: AppService, csrf: str,
    *, form_error: str | None = None, status_code: int = 200,
) -> Response:
    ctx = _base(request, principal, csrf, "notifications")
    sources = _owner_sources(svc.list_config(principal.owner_id))
    ctx.update(
        jobs=svc.list_jobs_with_status(principal.owner_id),
        sources=sources,
        source_by_id={s["source_id"]: s for s in sources},
        timezones=_TIMEZONES,
        template_ids=sorted(VALID_TEMPLATE_IDS),
        form_error=form_error,
    )
    return templates.TemplateResponse(
        request, "notifications/index.html", ctx, status_code=status_code)


@router.get("/notifications")
def notifications(
    request: Request,
    principal: Principal = Depends(verify_session),
    svc: AppService = Depends(get_app_service),
    csrf: str = Depends(csrf_token_for),
) -> Response:
    return _render_notifications(request, principal, svc, csrf)


@router.post("/notifications")
def create_notification(
    request: Request,
    name: str = Form(...),
    frequency_kind: str = Form(...),
    minute: int = Form(0),
    hour: int = Form(0),
    cron_expr: str = Form(""),
    timezone: str = Form("UTC"),
    template_id: str = Form("default"),
    show_pix: str | None = Form(None),
    show_card: str | None = Form(None),
    variation_threshold_pct: str = Form(""),
    source_ids: list[str] = Form([]),
    principal: Principal = Depends(verify_session),
    svc: AppService = Depends(get_app_service),
    csrf: str = Depends(csrf_token_for),
) -> Response:
    # Checkbox semantics: an unchecked box is ABSENT from the form body, so a
    # missing value means "off" (JobOptions defaults on; the form pre-checks).
    options: dict = {"show_pix": show_pix is not None,
                     "show_card": show_card is not None}
    threshold = variation_threshold_pct.strip()
    if threshold:
        try:
            options["variation_threshold_pct"] = float(threshold)
        except ValueError:
            return _render_notifications(
                request, principal, svc, csrf,
                form_error="Seuil de variation invalide.",
                status_code=status.HTTP_400_BAD_REQUEST)
    spec = DigestJobSpec(
        name=name.strip(), frequency_kind=frequency_kind.strip(),
        minute=minute, hour=hour, cron_expr=cron_expr.strip() or None,
        timezone=timezone.strip(), template_id=template_id.strip(),
        options=options, enabled=True,
        # owner_id is taken from the Principal inside create_job (ADR 0003 S2),
        # never from the body -- source_ids are re-verified owner-side at persist.
        source_ids=tuple(s for s in source_ids if s),
    )
    try:
        svc.create_job(principal, spec)
    except (ValueError, KeyError):
        # DOMAIN errors only: bad cadence/tz/template/options (ValueError, incl.
        # ConfigError name conflict) or unknown source (KeyError). Anything
        # unexpected propagates to 500 -- never masked as a client 400.
        return _render_notifications(
            request, principal, svc, csrf,
            form_error="Notification refusée : cadence, fuseau, "
                       "template ou options invalides.",
            status_code=status.HTTP_400_BAD_REQUEST)
    return RedirectResponse(
        "/notifications", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/notifications/{job_id}/enabled")
def toggle_notification(
    job_id: str,
    principal: Principal = Depends(verify_session),
    svc: AppService = Depends(get_app_service),
) -> Response:
    try:
        job = svc.get_job(principal.owner_id, job_id)
        svc.update_job(principal.owner_id, job_id,
                       _spec_from_job(job, enabled=not job.enabled))
    except KeyError:
        # Owner-scoped: unknown OR not-owned both raise KeyError -> generic 404
        # (no cross-tenant existence oracle).
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return RedirectResponse(
        "/notifications", status_code=status.HTTP_303_SEE_OTHER)


@router.delete("/notifications/{job_id}")
def remove_notification(
    job_id: str,
    principal: Principal = Depends(verify_session),
    svc: AppService = Depends(get_app_service),
) -> Response:
    try:
        svc.delete_job(principal.owner_id, job_id)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT,
                    headers={"HX-Redirect": "/notifications"})


@router.post("/notifications/{job_id}/sources")
def add_notification_source(
    job_id: str,
    source_id: str = Form(...),
    principal: Principal = Depends(verify_session),
    svc: AppService = Depends(get_app_service),
) -> Response:
    try:
        # A source that is not the owner's simply does not link (owner-scoped
        # INSERT...SELECT server-side) -- no error, no cross-tenant link.
        svc.add_job_source(principal.owner_id, job_id, source_id.strip())
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    return RedirectResponse(
        "/notifications", status_code=status.HTTP_303_SEE_OTHER)


@router.delete("/notifications/{job_id}/sources/{source_id}")
def remove_notification_source(
    job_id: str,
    source_id: str,
    principal: Principal = Depends(verify_session),
    svc: AppService = Depends(get_app_service),
) -> Response:
    # Owner-scoped, silent no-op if the link is absent (mirrors remove_source).
    svc.remove_job_source(principal.owner_id, job_id, source_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT,
                    headers={"HX-Redirect": "/notifications"})


@router.get("/notifications/{job_id}/preview")
def preview_notification(
    request: Request,
    job_id: str,
    principal: Principal = Depends(verify_session),
    svc: AppService = Depends(get_app_service),
    csrf: str = Depends(csrf_token_for),
    domain_policy: DomainPolicy = Depends(get_domain_policy),
) -> Response:
    owner = principal.owner_id
    try:
        job = svc.get_job(owner, job_id)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    registry = svc.list_config(owner)
    url_by_id: dict[str, str] = {}
    site_by_id: dict[str, str] = {}
    for product in registry.products:
        for source in product.sources:
            url_by_id[source.source_id] = source.url
            site_by_id[source.source_id] = source.site
    source_urls = {sid: url_by_id[sid]
                   for sid in job.source_ids if sid in url_by_id}
    tier2_labels: dict[str, str] = {}
    for sid in job.source_ids:
        site = registry.sites.get(site_by_id.get(sid, ""))
        if site is not None and getattr(site, "tier2_label", None):
            tier2_labels[sid] = site.tier2_label
    latest = {r.source_id: r for r in svc.list_state(owner)}
    records = [latest[sid] for sid in job.source_ids if sid in latest]
    generated_at = datetime.now(_utc.utc).isoformat(timespec="seconds")
    view = build_digest_view(
        job, records, generated_at, tier2_labels, source_urls, domain_policy)
    # render_digest_html returns a self-contained email document. It is passed
    # to the template as a STRING and rendered inside a sandboxed <iframe
    # srcdoc="{{ preview_html }}"> -- autoescape escapes it into the attribute
    # (browser decodes, iframe isolates), so NO |safe is ever needed (S3 CWE-79).
    preview_html = render_digest_html(job.template_id, view)
    ctx = _base(request, principal, csrf, "notifications")
    ctx.update(job=job, preview_html=preview_html)
    return templates.TemplateResponse(request, "notifications/preview.html", ctx)
