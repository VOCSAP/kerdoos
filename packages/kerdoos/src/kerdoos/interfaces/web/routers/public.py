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

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel

from kerdoos.core.app.auth import AuthService
from kerdoos.interfaces.web.deps import get_auth_service, get_session_cookie
from kerdoos.interfaces.web.security import COOKIE_NAME, SessionCookie

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
