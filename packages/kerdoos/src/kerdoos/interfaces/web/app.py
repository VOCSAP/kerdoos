"""Kerdoos WebUI ASGI app -- factory only, no module-level instance.

Composition root (ADR 0001 S4/S6): wires the real AuthService
(SqliteAuthStore + Argon2Hasher, both over KERDOOS_CONFIG_DB) and AppService
(SqliteConfigStore + SqliteStateStore, per-op connections -- FD3) from
Settings (env), then attaches the singletons to app.state so deps.py can
read them lazily per-request (rule FastAPI "singletons sur app.state, jamais
module-level"). Fails fast (RuntimeError) if KERDOOS_SESSION_SECRET is
absent -- no insecure default for the cookie HMAC key. Run via:

    uvicorn kerdoos.interfaces.web.app:create_app --factory

(rule FastAPI "create_app() factory + uvicorn ... factory=True -- pas
d'instance module-level": a module-level `app = FastAPI()` would capture
import-time state and make per-test app instances impossible.)
"""

from __future__ import annotations

from fastapi import FastAPI

from autolycos.router import StaticRouter

from kerdoos.config import get_settings
from kerdoos.core.app.auth import AuthService
from kerdoos.core.app.services import AppService
from kerdoos.interfaces.web import health
from kerdoos.interfaces.web.routers import admin, protected, public
from kerdoos.interfaces.web.security import SessionCookie
from kerdoos.parsers.factory import build_parser
from kerdoos.persistence.sqlite_store import SqliteStateStore
from kerdoos.registry.auth_store import Argon2Hasher, SqliteAuthStore
from kerdoos.registry.domain_policy import CatalogueDomainPolicy
from kerdoos.registry.sqlite_store import SqliteConfigStore


def create_app() -> FastAPI:
    settings = get_settings()
    secret = settings.require_session_secret()  # fail fast, no insecure default

    config_store = SqliteConfigStore(settings.config_db)
    state_store = SqliteStateStore(settings.state_db)
    domain_policy = CatalogueDomainPolicy(config_store)
    router = StaticRouter(domain_policy)

    app = FastAPI(title="Kerdoos")
    app.state.auth_service = AuthService(
        SqliteAuthStore(settings.config_db), Argon2Hasher())
    app.state.app_service = AppService(
        config_store, state_store, router, domain_policy, build_parser)
    app.state.session_cookie = SessionCookie(secret, secure=settings.cookie_secure)

    app.include_router(health.router)
    app.include_router(public.router)
    app.include_router(protected.router)
    app.include_router(admin.router)
    return app
