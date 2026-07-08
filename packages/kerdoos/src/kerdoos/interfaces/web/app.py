"""Kerdoos WebUI ASGI app -- factory only, no module-level instance.

Phase 0 (structural): `/health` (public) + an empty protected router
placeholder. No auth, no use-cases, no digest, no SQLite config store yet
(ADR 0001 items land in later phases). Run via:

    uvicorn kerdoos.interfaces.web.app:create_app --factory

(rule FastAPI "create_app() factory + uvicorn ... factory=True -- pas
d'instance module-level": a module-level `app = FastAPI()` would capture
import-time state and make per-test app instances impossible.)
"""

from __future__ import annotations

from fastapi import FastAPI

from kerdoos.interfaces.web import health
from kerdoos.interfaces.web.routers import protected


def create_app() -> FastAPI:
    app = FastAPI(title="Kerdoos")
    app.include_router(health.router)
    app.include_router(protected.router)
    return app
