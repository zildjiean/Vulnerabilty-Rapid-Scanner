from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from .auth import AuthMiddleware, LoginRateLimiter, SessionStore, seed_admin
from .config import Settings, settings_from_env
from .db import init_db, make_engine, make_session_factory
from .render import STATIC_DIR, render
from .routers import auth as auth_router


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or settings_from_env()
    engine = make_engine(settings.db_url)
    init_db(engine)
    SessionLocal = make_session_factory(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        with SessionLocal() as db:
            seed_admin(db)
        yield

    app = FastAPI(title="0-Day Rapid Scanner", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.SessionLocal = SessionLocal
    app.state.sessions = SessionStore(settings.secret_key)
    app.state.login_limiter = LoginRateLimiter()
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.add_middleware(AuthMiddleware)
    app.include_router(auth_router.router)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/")
    def dashboard_placeholder(request: Request):
        return render(request, "base.html", active="dashboard")

    return app
