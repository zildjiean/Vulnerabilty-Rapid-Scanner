from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from .auth import AuthMiddleware, LoginRateLimiter, SessionStore, seed_admin
from .config import Settings, settings_from_env
from .db import TemplateIndex, init_db, make_engine, make_session_factory
from .jobs import JobRunner, fail_interrupted_jobs
from .render import STATIC_DIR
from .routers import (auth as auth_router, dashboard as dashboard_router, inventory as inventory_router, jobs as jobs_router,
                      nmap as nmap_router, nuclei as nuclei_router, rules as rules_router, templates as templates_router,
                      updates as updates_router)
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
              templates_router, rules_router, updates_router):
        app.include_router(r.router)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    return app
