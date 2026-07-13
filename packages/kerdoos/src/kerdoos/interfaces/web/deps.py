"""FastAPI auth dependencies (attached at the ROUTER level, never per-endpoint).

verify_session (WebUI, signed cookie) and verify_bearer (MCP, Authorization:
Bearer -- built now, wired to the MCP surface in Phase 5) both resolve to a
Principal or raise 401. require_admin additionally raises 403 for a
non-admin (authenticated but not authorized). Singletons (AuthService,
AppService, SessionCookie) are read from app.state, built once by create_app
(rule FastAPI "singletons on app.state, jamais module-level").
"""

from __future__ import annotations

from autolycos.safety import DomainPolicy
from fastapi import Depends, HTTPException, Request, status

from kerdoos.core.app.auth import AuthService
from kerdoos.core.app.services import AppService, Principal
from kerdoos.interfaces.web.security import COOKIE_NAME, SessionCookie


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def get_app_service(request: Request) -> AppService:
    return request.app.state.app_service


def get_domain_policy(request: Request) -> DomainPolicy:
    # Notifications digest preview (Phase 6-web): the same DomainPolicy the run
    # path uses, so build_digest_view scheme/domain-checks preview hrefs
    # identically (no divergence between preview and the real dispatched digest).
    return request.app.state.domain_policy


def get_session_cookie(request: Request) -> SessionCookie:
    return request.app.state.session_cookie


def verify_session(
    request: Request,
    auth: AuthService = Depends(get_auth_service),
    cookie: SessionCookie = Depends(get_session_cookie),
) -> Principal:
    session_id = cookie.read(request.cookies.get(COOKIE_NAME))
    principal = auth.verify_session(session_id) if session_id else None
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired session",
        )
    return principal


def verify_bearer(
    request: Request,
    auth: AuthService = Depends(get_auth_service),
) -> Principal:
    header = request.headers.get("Authorization", "")
    scheme, _, token = header.partition(" ")
    principal = (
        auth.verify_bearer(token)
        if scheme.lower() == "bearer" and token else None
    )
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired token",
        )
    return principal


def require_admin(
    principal: Principal = Depends(verify_session),
) -> Principal:
    if principal.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin role required",
        )
    return principal
