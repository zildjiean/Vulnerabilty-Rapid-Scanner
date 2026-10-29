from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import (clear_session_cookie, hash_password, set_session_cookie, validate_new_password, verify_password)
from ..db import User
from ..deps import get_db, get_settings, verify_csrf
from ..render import render

router = APIRouter()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.get("/login")
def login_page(request: Request):
    if request.state.user is not None:
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html")


@router.post("/login")
def login(request: Request, username: str = Form(""), password: str = Form(""),
          db: Session = Depends(get_db), settings=Depends(get_settings)):
    limiter = request.app.state.login_limiter
    ip = _client_ip(request)
    if not limiter.allowed(ip):
        return render(request, "login.html", status_code=429, error="Too many failed attempts. Try again in a minute.")
    user = db.scalar(select(User).where(User.username == username.strip()))
    if user is None or not verify_password(password, user.password_hash):
        limiter.record_failure(ip)
        return render(request, "login.html", status_code=401, error="Invalid username or password.")
    limiter.reset(ip)
    response = RedirectResponse("/", status_code=303)
    set_session_cookie(response, request.app.state.sessions.encode(user.id), secure=settings.https)
    return response


@router.post("/logout", dependencies=[Depends(verify_csrf)])
def logout():
    response = RedirectResponse("/login", status_code=303)
    clear_session_cookie(response)
    return response


@router.get("/change-password")
def change_password_page(request: Request):
    return render(request, "change_password.html")


@router.post("/change-password", dependencies=[Depends(verify_csrf)])
def change_password(request: Request, current_password: str = Form(""), new_password: str = Form(""),
                    confirm_password: str = Form(""), db: Session = Depends(get_db), settings=Depends(get_settings)):
    user = db.get(User, request.state.user.id)
    if not verify_password(current_password, user.password_hash):
        return render(request, "change_password.html", status_code=400, error="Current password is incorrect.")
    err = validate_new_password(new_password, confirm_password, current_password)
    if err:
        return render(request, "change_password.html", status_code=400, error=err)
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    db.commit()
    response = RedirectResponse("/?msg=Password+updated", status_code=303)
    set_session_cookie(response, request.app.state.sessions.encode(user.id), secure=settings.https)
    return response
