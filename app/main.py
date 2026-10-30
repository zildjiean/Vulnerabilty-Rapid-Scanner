from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from .auth import AuthMiddleware, LoginRateLimiter, SessionStore, seed_admin
from .config import Settings, settings_from_env
from .db import TemplateIndex, init_db, make_engine, make_session_factory
from .issues import backfill_issues
from .jobs import JobRunner, fail_interrupted_jobs
from .authz import Forbidden
from .render import STATIC_DIR, render
from .routers import (audit as audit_router, auth as auth_router, issues as issues_router, dashboard as dashboard_router, inventory as inventory_router, jobs as jobs_router,
                      nmap as nmap_router, nuclei as nuclei_router, rules as rules_router, templates as templates_router,
                      updates as updates_router, users as users_router)
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
        yield

    app = FastAPI(title="0-Day Rapid Scanner", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.SessionLocal = SessionLocal
    app.state.sessions = SessionStore(settings.secret_key)
    app.state.login_limiter = LoginRateLimiter()
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.add_middleware(AuthMiddleware)
    for r in (auth_router, dashboard_router, jobs_router, nmap_router, inventory_router, nuclei_router,
              templates_router, rules_router, updates_router, users_router, audit_router, issues_router):
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
        if exc.status_code not in (403, 404) or wants_json or request.url.path.endswith(("/status", "/stream", "/search")):
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
        return {"status": "ok"}

    return app
