from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from . import __version__
from .auth import AuthMiddleware, LoginRateLimiter, SessionStore, seed_admin
from .config import Settings, settings_from_env
from .db import TemplateIndex, init_db, make_engine, make_session_factory
from .issues import backfill_issues
from .jobs import JobRunner, fail_interrupted_jobs
from .authz import Forbidden
from .render import STATIC_DIR, render
from .routers import (audit as audit_router, auth as auth_router, campaigns as campaigns_router, issues as issues_router,
                      integrations as integrations_router, reports as reports_router, schedules as schedules_router,
                      scopes as scopes_router, api as api_router, apikeys as apikeys_router, ai as ai_router,
                      ai_features as ai_features_router, dashboard as dashboard_router, inventory as inventory_router, jobs as jobs_router,
                      nmap as nmap_router, nuclei as nuclei_router, rules as rules_router, templates as templates_router,
                      updates as updates_router, users as users_router, watch as watch_router)
from .routers.templates import reindex_in_background
from .routers.updates import start_update_job
from .rules import seed_example_rule
from .scanners.nuclei_runner import backfill_nuclei_warnings


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or settings_from_env()
    engine = make_engine(settings.db_url)
    init_db(engine)
    SessionLocal = make_session_factory(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        with SessionLocal() as db:
            seed_admin(db)
            seed_example_rule(db)
            fail_interrupted_jobs(db)
            backfill_nuclei_warnings(db)
            backfill_issues(db)
            needs_index = db.scalar(select(TemplateIndex).limit(1)) is None
        app.state.job_runner = JobRunner(SessionLocal)
        app.state.indexing = False
        app.state.last_index_counts = None
        if not settings.nuclei_templates_dir.is_dir():
            with SessionLocal() as db:
                start_update_job(app, db, "nuclei-templates")
        elif needs_index:
            asyncio.get_running_loop().create_task(reindex_in_background(app))
        from .scheduler import scheduler_loop
        from .ai import refresh_ready
        refresh_ready(app)
        from .notifications import notifications_loop
        app.state.scheduler_task = asyncio.get_running_loop().create_task(scheduler_loop(app))
        app.state.notifications_task = asyncio.get_running_loop().create_task(notifications_loop(app))
        yield
        app.state.scheduler_task.cancel()
        app.state.notifications_task.cancel()

    app = FastAPI(title="0-Day Rapid Scanner", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.SessionLocal = SessionLocal
    app.state.sessions = SessionStore(settings.secret_key)
    app.state.login_limiter = LoginRateLimiter()
    from . import channels
    from .secretbox import SecretBox
    app.state.secretbox = SecretBox(settings.secret_key)
    app.state.http = channels.real_http
    app.state.smtp_send = channels.real_smtp_send
    from . import llm
    app.state.llm = llm.complete
    app.state.ai_ready = False
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.add_middleware(AuthMiddleware)
    for r in (auth_router, dashboard_router, jobs_router, nmap_router, inventory_router, nuclei_router,
              templates_router, rules_router, updates_router, users_router, audit_router, issues_router, campaigns_router, scopes_router, schedules_router, integrations_router, reports_router,
              api_router, apikeys_router, ai_router, ai_features_router, watch_router):
        app.include_router(r.router)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        from fastapi.exception_handlers import http_exception_handler
        if isinstance(exc, Forbidden):
            from .audit import audit
            with request.app.state.SessionLocal() as db:
                audit(db, request, "auth.denied", target=f"{request.method} {request.url.path}", permission=exc.perm)
        accept = request.headers.get("accept", "")
        wants_json = "application/json" in accept and "text/html" not in accept
        if exc.status_code not in (403, 404) or wants_json or request.url.path.startswith("/api/") \
                or request.url.path.endswith(("/status", "/stream", "/search")):
            return await http_exception_handler(request, exc)
        if isinstance(exc, Forbidden):
            title, message = "Access denied", f"Your role does not allow this action ({exc.perm})."
        elif exc.status_code == 403:
            title, message = "Access denied", "The form expired or the request was not sent from this application. Reload the page and try again."
        else:
            title, message = "Not found", "The page or item you asked for does not exist."
        return render(request, "error.html", status_code=exc.status_code, title=title, message=message, status=exc.status_code)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__}

    return app
