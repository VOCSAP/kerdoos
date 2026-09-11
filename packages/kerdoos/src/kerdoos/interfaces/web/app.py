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

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from autolycos.browser_gate import BrowserGate
from autolycos.router import StaticRouter

from kerdoos.config import get_settings
from kerdoos.core.app.auth import AuthService
from kerdoos.core.app.services import AppService
from kerdoos.core.evaluator import (
    run_evaluator_loop, should_start_intra_process_evaluator)
from kerdoos.core.run_queue import RunQueue
from kerdoos.digest.factory import build_sender
from kerdoos.interfaces.boot_checks import log_unavailable_fetcher_tiers
from kerdoos.interfaces.web import health
from kerdoos.interfaces.web.routers import admin, protected, public, web
from kerdoos.interfaces.web.security import SessionCookie
from kerdoos.interfaces.web.templates import templates
from kerdoos.parsers.factory import build_parser
from kerdoos.persistence.sqlite_store import SqliteStateStore
from kerdoos.registry.auth_store import Argon2Hasher, SqliteAuthStore
from kerdoos.registry.domain_policy import CatalogueDomainPolicy
from kerdoos.registry.sqlite_store import SqliteConfigStore

_STATIC_DIR = Path(__file__).parent / "static"
logger = logging.getLogger(__name__)


def _wants_html(request: Request) -> bool:
    return "text/html" in request.headers.get("accept", "")


async def _auth_error_handler(
    request: Request, exc: StarletteHTTPException
) -> Response:
    """Render 401/403 as full HTML surfaces for a BROWSER (Accept: text/html),
    but keep the JSON contract for API clients (Accept: */*, the httpx default),
    so the Phase 4a JSON probes (/me, JSON /login, /admin/whoami) are unchanged.
    Every other HTTPException keeps the default JSON shape."""
    if exc.status_code in (401, 403) and _wants_html(request):
        name = "errors/401.html" if exc.status_code == 401 else "errors/403.html"
        return templates.TemplateResponse(
            request, name, {}, status_code=exc.status_code)
    return JSONResponse(
        {"detail": exc.detail}, status_code=exc.status_code,
        headers=getattr(exc, "headers", None))


def create_app() -> FastAPI:
    settings = get_settings()
    secret = settings.require_session_secret()  # fail fast, no insecure default

    config_store = SqliteConfigStore(settings.config_db)
    state_store = SqliteStateStore(settings.state_db)
    domain_policy = CatalogueDomainPolicy(config_store)
    # ADR 0002 Decision 1/2 (card ca30b736): ONE gate shared by the browser
    # AND uc tiers, inter-process via the STATE_DB directory (the shared
    # /data volume in production) -- injected here, autolycos never reads
    # KERDOOS_BROWSER_MAX_CONCURRENT/ACQUIRE_TIMEOUT_SECONDS itself
    # (invariant 2).
    browser_gate = BrowserGate(
        max_concurrent=settings.browser_max_concurrent,
        lock_dir=Path(settings.state_db).parent,
        acquire_timeout_seconds=settings.browser_acquire_timeout_seconds)
    router = StaticRouter(domain_policy, browser_gate=browser_gate)
    log_unavailable_fetcher_tiers(config_store)
    app_service = AppService(
        config_store, state_store, router, domain_policy, build_parser)
    # Card ca30b736: POST /run enqueues here instead of blocking on a scrape
    # (now also gated by the browser gate above). Started unconditionally
    # below, not behind a flag.
    run_queue = RunQueue(app_service)

    @asynccontextmanager
    async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
        run_queue_stop = asyncio.Event()
        run_queue_task = asyncio.create_task(
            run_queue.run_forever(run_queue_stop))
        run_queue_task.add_done_callback(run_queue.handle_consumer_crash)

        # Default OFF (KERDOOS_DIGEST_EVALUATOR_ENABLED unset/false): this
        # branch is a true no-op, so the 3 pre-existing TestClient(create_app())
        # test files see zero behavior change (pytest.md rule -- every new
        # lifespan worker must be gated behind an explicit opt-in).
        evaluator_task: asyncio.Task | None = None
        stop_event = asyncio.Event()
        if settings.digest_evaluator_enabled:
            if should_start_intra_process_evaluator(settings.workers):
                sender = build_sender(settings, config_store, domain_policy)
                evaluator_task = asyncio.create_task(
                    run_evaluator_loop(
                        config_store=config_store, state_store=state_store,
                        router=router, parser_factory=build_parser,
                        sender=sender, stop_event=stop_event,
                        reaper_timeout_seconds=settings.digest_reaper_timeout_seconds,
                    )
                )
            else:
                logger.warning(
                    "digest evaluator: KERDOOS_WORKERS=%d > 1, refusing to "
                    "start the intra-process evaluator (ADR 0003 Decision 4) "
                    "-- use external cron calling `kerdoos digest` instead.",
                    settings.workers,
                )
        try:
            yield
        finally:
            if evaluator_task is not None:
                stop_event.set()
                evaluator_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await evaluator_task
            run_queue_stop.set()
            run_queue_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await run_queue_task

    app = FastAPI(title="Kerdoos", lifespan=_lifespan)
    app.state.auth_service = AuthService(
        SqliteAuthStore(settings.config_db), Argon2Hasher())
    app.state.app_service = app_service
    app.state.run_queue = run_queue
    # Exposed for the Notifications digest preview (Phase 6-web): build_digest_view
    # needs the SAME DomainPolicy the run path uses to scheme/domain-check hrefs.
    app.state.domain_policy = domain_policy
    app.state.session_cookie = SessionCookie(secret, secure=settings.cookie_secure)
    # CSRF tokens are derived from this same secret (domain-separated by a
    # b"csrf:" prefix inside csrf.issue_csrf), so no separate key to manage.
    app.state.csrf_secret = secret

    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
    app.add_exception_handler(StarletteHTTPException, _auth_error_handler)

    app.include_router(health.router)
    app.include_router(public.router)
    app.include_router(protected.router)
    app.include_router(admin.router)
    app.include_router(web.router)  # tenant HTML views (verify_session + CSRF)
    return app
