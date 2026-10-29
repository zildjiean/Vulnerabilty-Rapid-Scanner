from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from .auth import AuthMiddleware, LoginRateLimiter, SessionStore, seed_admin
from .config import Settings, settings_from_env
from sqlalchemy import select

from .db import TemplateIndex, init_db, make_engine, make_session_factory
from .render import STATIC_DIR, render
from .jobs import JobRunner
from .routers import auth as auth_router, inventory as inventory_router, jobs as jobs_router, nmap as nmap_router, nuclei as nuclei_router, templates as templates_router
from .routers.templates import reindex_in_background


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or settings_from_env()
    engine = make_engine(settings.db_url)
    init_db(engine)
    SessionLocal = make_session_factory(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        with SessionLocal() as db:
            seed_admin(db)
            needs_index = db.scalar(select(TemplateIndex).limit(1)) is None
        app.state.job_runner = JobRunner(SessionLocal)
        app.state.indexing = False
        app.state.last_index_counts = None
        if needs_index:
            asyncio.get_running_loop().create_task(reindex_in_background(app))
        yield

    app = FastAPI(title="0-Day Rapid Scanner", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.SessionLocal = SessionLocal
    app.state.sessions = SessionStore(settings.secret_key)
    app.state.login_limiter = LoginRateLimiter()
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.add_middleware(AuthMiddleware)
    app.include_router(auth_router.router)
    app.include_router(jobs_router.router)
    app.include_router(nmap_router.router)
    app.include_router(inventory_router.router)
    app.include_router(nuclei_router.router)
    app.include_router(templates_router.router)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/")
    def dashboard_placeholder(request: Request):
        return render(request, "base.html", active="dashboard")

    return app
