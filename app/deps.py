from __future__ import annotations

from typing import Iterator

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session


def get_db(request: Request) -> Iterator[Session]:
    db: Session = request.app.state.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_settings(request: Request):
    return request.app.state.settings


def get_runner(request: Request):
    return request.app.state.job_runner


async def verify_csrf(request: Request) -> None:
    """Dependency for mutating routes: the form field `csrf` must equal the session's token."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        form = await request.form()
        token = form.get("csrf") or request.headers.get("x-csrf")
        expected = getattr(request.state, "csrf", None)
        if not token or not expected or token != expected:
            raise HTTPException(status_code=403, detail="CSRF token mismatch")
