from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import (clear_session_cookie, hash_password, set_session_cookie, validate_new_password, verify_password)
from ..authz import PERMISSIONS, ROLE_DESCRIPTIONS, ROLE_PERMISSIONS
from ..db import AuditLog, User, utcnow
from ..audit import audit
from ..deps import get_db, get_settings, verify_csrf
from ..i18n import flash, tr
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
        return render(request, "login.html", status_code=429, error=tr(request, "Too many failed attempts. Try again in a minute."))
    user = db.scalar(select(User).where(User.username == username.strip()))
    if user is None or not verify_password(password, user.password_hash) or not user.is_active:
        limiter.record_failure(ip)
        reason = "unknown user" if user is None else ("inactive user" if not user.is_active and verify_password(password, user.password_hash) else "bad password")
        audit(db, request, "auth.login_failed", user=user, username=username.strip()[:64], reason=reason)
        return render(request, "login.html", status_code=401, error=tr(request, "Invalid username or password."))
    limiter.reset(ip)
    user.last_login_at = utcnow()
    db.commit()
    audit(db, request, "auth.login", user=user)
    response = RedirectResponse("/", status_code=303)
    set_session_cookie(response, request.app.state.sessions.encode(user.id, user.session_version), secure=settings.https)
    return response


@router.post("/logout", dependencies=[Depends(verify_csrf)])
def logout(request: Request, db: Session = Depends(get_db)):
    audit(db, request, "auth.logout")
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
        return render(request, "change_password.html", status_code=400, error=tr(request, "Current password is incorrect."))
    err = validate_new_password(new_password, confirm_password, current_password)
    if err:
        return render(request, "change_password.html", status_code=400, error=tr(request, err))
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    db.commit()
    audit(db, request, "auth.password_changed", user=user)
    response = RedirectResponse("/?msg=" + flash(request, "Password updated"), status_code=303)
    set_session_cookie(response, request.app.state.sessions.encode(user.id, user.session_version), secure=settings.https)
    return response


def _profile(request: Request, db: Session, status_code: int = 200, error: str | None = None):
    me = request.state.user
    activity = list(db.scalars(select(AuditLog).where(AuditLog.user_id == me.id).order_by(AuditLog.id.desc()).limit(15)))
    perms = [(p, label) for p, label in PERMISSIONS.items() if p in ROLE_PERMISSIONS.get(me.role, ())]
    return render(request, "profile.html", status_code=status_code, active="profile", error=error, activity=activity,
                  perms=perms, role_description=ROLE_DESCRIPTIONS.get(me.role, ""))


@router.get("/profile")
def profile_page(request: Request, db: Session = Depends(get_db)):
    return _profile(request, db)


@router.post("/profile", dependencies=[Depends(verify_csrf)])
def profile_update(request: Request, display_name: str = Form(""), email: str = Form(""), db: Session = Depends(get_db)):
    from .users import _clean_profile
    display_name, email, err = _clean_profile(display_name, email)
    if err:
        return _profile(request, db, status_code=400, error=tr(request, err))
    me = db.get(User, request.state.user.id)
    changes = {k: f"{getattr(me, k)} -> {v}" for k, v in (("display_name", display_name), ("email", email)) if getattr(me, k) != v}
    me.display_name, me.email = display_name, email
    db.commit()
    if changes:
        audit(db, request, "profile.updated", target=me.username, user=me, **changes)
    return RedirectResponse("/profile?msg=" + flash(request, "Profile saved"), status_code=303)


@router.post("/profile/menus", dependencies=[Depends(verify_csrf)])
def profile_menus(request: Request, show_all_menus: str = Form(""), db: Session = Depends(get_db)):
    """Show every menu item the user may open, instead of the focused menu for their role. Display only."""
    me = db.get(User, request.state.user.id)
    new = bool(show_all_menus)
    if bool(me.show_all_menus) != new:
        me.show_all_menus = new
        db.commit()
        audit(db, request, "profile.menus", target=me.username, user=me, show_all_menus=new)
    return RedirectResponse("/profile?msg=" + flash(request, "Menu preference saved") + "#menus", status_code=303)


def _safe_back(path: str) -> str:
    """A same-site relative path to return to (``/`` for anything else), without a stale ?msg= / ?err=."""
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    path = (path or "").strip()
    if not path.startswith("/") or path.startswith(("//", "/\\")) or any(c in path for c in "\\\r\n\t") \
            or any(ord(c) < 32 for c in path):
        return "/"
    parts = urlsplit(path)
    if parts.scheme or parts.netloc:
        return "/"
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in ("msg", "err")])
    return urlunsplit(("", "", parts.path or "/", query, parts.fragment))


@router.post("/profile/language", dependencies=[Depends(verify_csrf)])
def profile_language(request: Request, language: str = Form(""), next: str = Form("/"), db: Session = Depends(get_db)):
    """The signed-in user's interface language (also allowed during a forced password change)."""
    from ..i18n import LANGS
    me = db.get(User, request.state.user.id)
    if language in LANGS and me.language != language:
        old = me.language
        me.language = language
        db.commit()
        audit(db, request, "profile.language", target=me.username, user=me, language=f"{old} -> {language}")
    return RedirectResponse(_safe_back(next), status_code=303)
