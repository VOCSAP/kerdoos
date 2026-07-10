"""Public, unauthenticated auth endpoints: login + logout.

Kept on its own APIRouter with no auth dependency (rule FastAPI "auth au
niveau router" -- a public endpoint never lives on a gated router with a
per-route `dependencies=[]` override).

Login is anti-enumeration end to end: AuthService.authenticate() already pays
exactly one Argon2id verify on every failure branch (unknown identifier, NULL
password_hash, wrong password) and returns a uniform None; this router turns
that uniform None into a single 401 with an identical status+body regardless
of which branch failed, so no additional enumeration surface is added here.

Logout is idempotent: a missing/tampered/expired cookie still gets a 200 (the
cookie is cleared either way), matching "logout always succeeds" from the
client's point of view.
"""

from __future__ import annotations

from fastapi import (
    APIRouter, Depends, Form, HTTPException, Request, Response, status,
)
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from kerdoos.core.app.auth import AuthService
from kerdoos.interfaces.web.deps import get_auth_service, get_session_cookie
from kerdoos.interfaces.web.security import COOKIE_NAME, SessionCookie
from kerdoos.interfaces.web.templates import templates

router = APIRouter()


class LoginBody(BaseModel):
    identifier: str
    password: str


@router.post("/login")
def login(
    body: LoginBody,
    response: Response,
    auth: AuthService = Depends(get_auth_service),
    cookie: SessionCookie = Depends(get_session_cookie),
) -> dict[str, str]:
    principal = auth.authenticate(body.identifier, body.password)
    if principal is None:
        # Uniform 401 on all 3 failure branches (anti-enum) -- see module docstring.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid credentials",
        )
    session_id = auth.create_session(principal)
    response.set_cookie(
        **cookie.set_kwargs(cookie.issue(session_id), auth.session_ttl_seconds)
    )
    return {"status": "ok"}


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    auth: AuthService = Depends(get_auth_service),
    cookie: SessionCookie = Depends(get_session_cookie),
) -> dict[str, str]:
    session_id = cookie.read(request.cookies.get(COOKIE_NAME))
    if session_id is not None:
        principal = auth.verify_session(session_id)
        if principal is not None:
            auth.revoke_session(principal, session_id)
    response.delete_cookie(**cookie.clear_kwargs())
    return {"status": "ok"}


# ===== HTML auth flow (server-rendered WebUI, Phase 4b) ==================
# Distinct paths from the JSON API above (GET /login form + POST /auth/login /
# POST /auth/logout), so the Phase 4a JSON contract stays intact. The HTML form
# is form-encoded and redirects (PRG); the JSON endpoints keep returning JSON.


@router.get("/login")
def login_form(request: Request) -> Response:
    return templates.TemplateResponse(request, "auth/login.html", {})


@router.post("/auth/login")
def login_submit(
    request: Request,
    identifier: str = Form(...),
    password: str = Form(...),
    auth: AuthService = Depends(get_auth_service),
    cookie: SessionCookie = Depends(get_session_cookie),
) -> Response:
    # Pre-session POST: there is no session yet, so the session-bound CSRF token
    # cannot exist here. Login CSRF (a forged login into an attacker account) is
    # a low-severity, distinct threat mitigated by SameSite=Lax on the cookie;
    # the session-bound CSRF guard covers every AUTHENTICATED write instead.
    principal = auth.authenticate(identifier, password)
    if principal is None:
        # Uniform failure: same page + generic message on all branches (anti-enum).
        return templates.TemplateResponse(
            request, "auth/login.html",
            {"error": True, "identifier": identifier},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )
    session_id = auth.create_session(principal)
    redirect = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    redirect.set_cookie(
        **cookie.set_kwargs(cookie.issue(session_id), auth.session_ttl_seconds)
    )
    return redirect


@router.post("/auth/logout")
def logout_submit(
    request: Request,
    auth: AuthService = Depends(get_auth_service),
    cookie: SessionCookie = Depends(get_session_cookie),
) -> Response:
    session_id = cookie.read(request.cookies.get(COOKIE_NAME))
    if session_id is not None:
        principal = auth.verify_session(session_id)
        if principal is not None:
            auth.revoke_session(principal, session_id)
    redirect = RedirectResponse(
        "/login", status_code=status.HTTP_303_SEE_OTHER)
    redirect.delete_cookie(**cookie.clear_kwargs())
    return redirect
