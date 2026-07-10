"""Stateless CSRF protection for the authenticated write surface.

SameSite=Lax on the session cookie stops cross-site *navigation* POSTs, but
stops being sufficient the moment there are write endpoints (top-level POST from
a hostile page can still ride a Lax cookie). So every unsafe request on the
authenticated routers must also carry a CSRF token.

The token is derived, not stored (no extra write-path for the MVP):

    csrf = HMAC-SHA256(session_secret, b"csrf:" + session_id)

Design conditions (frozen with the team-lead, verified at the gate):
  * DOMAIN SEPARATION: the explicit b"csrf:" prefix keeps this HMAC output from
    ever colliding with the session-cookie signature (which signs the bare
    session_id). Different message space -> different token.
  * CONSTANT-TIME comparison (hmac.compare_digest), never ==.
  * BOUND TO THE SESSION: the token is a function of session_id, so a token
    minted for one session is rejected on another. Logout / a new session
    rotates the session_id and therefore the token implicitly.
  * STRICT REJECT: an unsafe request (POST/PUT/PATCH/DELETE) without a valid
    token -> 403 before any state mutation.
  * BOTH transports accepted with identical validation: the X-CSRF-Token header
    (HTMX hx-headers) OR a hidden `csrf_token` form field.
"""

from __future__ import annotations

import hashlib
import hmac

from fastapi import Depends, HTTPException, Request, status

from kerdoos.interfaces.web.deps import get_session_cookie
from kerdoos.interfaces.web.security import COOKIE_NAME, SessionCookie

CSRF_HEADER = "X-CSRF-Token"
CSRF_FIELD = "csrf_token"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


def issue_csrf(secret: str, session_id: str) -> str:
    """Derive the CSRF token for a session id. b"csrf:" domain-separates this
    HMAC from the session-cookie signature over the bare id."""
    return hmac.new(
        secret.encode("utf-8"),
        b"csrf:" + session_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def get_csrf_secret(request: Request) -> str:
    return request.app.state.csrf_secret


def session_id_from_request(
    request: Request, cookie: SessionCookie
) -> str | None:
    """The validated (signature-checked) plaintext session id, or None."""
    return cookie.read(request.cookies.get(COOKIE_NAME))


def csrf_token_for(
    request: Request,
    cookie: SessionCookie = Depends(get_session_cookie),
    secret: str = Depends(get_csrf_secret),
) -> str:
    """Template-facing dependency: the CSRF token to embed in this session's
    forms and <meta>. Empty string if there is no valid session (the caller
    should not be rendering a protected form in that case)."""
    session_id = session_id_from_request(request, cookie)
    if session_id is None:
        return ""
    return issue_csrf(secret, session_id)


async def verify_csrf(
    request: Request,
    cookie: SessionCookie = Depends(get_session_cookie),
    secret: str = Depends(get_csrf_secret),
) -> None:
    """Router-level guard (method-aware): a no-op on safe methods, a hard 403
    on any unsafe request lacking a valid, session-bound token. Attaching it at
    the router level (like verify_session) makes it impossible to add a write
    route and forget the check."""
    if request.method in _SAFE_METHODS:
        return
    session_id = session_id_from_request(request, cookie)
    if session_id is None:
        # No session context -> no CSRF context. verify_session on the same
        # router already 401s this, but fail closed here regardless.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="missing session")

    submitted = request.headers.get(CSRF_HEADER)
    if not submitted:
        # Starlette caches the parsed form on the request, so the endpoint's
        # own Form(...) parameters still see it after this read.
        form = await request.form()
        raw = form.get(CSRF_FIELD)
        submitted = raw if isinstance(raw, str) else None

    expected = issue_csrf(secret, session_id)
    if not submitted or not hmac.compare_digest(expected, submitted):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="invalid csrf token")
