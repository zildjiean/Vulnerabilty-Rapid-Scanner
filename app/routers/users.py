"""User management (admin only): create, edit, activate / deactivate, reset password, delete."""
from __future__ import annotations

import re
import secrets

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..audit import audit
from ..auth import hash_password
from ..authz import ROLE_DESCRIPTIONS, ROLES, require
from ..db import User
from ..deps import get_db, verify_csrf
from ..render import render

router = APIRouter(dependencies=[Depends(require("users.manage"))])

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def temp_password() -> str:
    return secrets.token_urlsafe(12)  # 16 URL-safe characters


def active_admin_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User).where(User.role == "admin", User.is_active.is_(True))) or 0


def user_change_error(db: Session, actor: User, target: User, change: str) -> str | None:
    """Why ``actor`` may not apply ``change`` (demote | deactivate | delete | reset) to ``target``; None if allowed."""
    if actor.id == target.id:
        return {
            "demote": "You cannot change your own role. Ask another administrator.",
            "deactivate": "You cannot deactivate yourself.",
            "delete": "You cannot delete yourself.",
            "reset": "You cannot reset your own password here. Use Profile → Change password.",
        }[change]
    if change in ("demote", "deactivate", "delete") and target.role == "admin" and target.is_active \
            and active_admin_count(db) <= 1:
        return "This is the last active admin. Promote or activate another admin first."
    return None


def _clean_profile(display_name: str, email: str) -> tuple[str, str, str | None]:
    display_name, email = display_name.strip()[:128], email.strip()[:255]
    if email and not EMAIL_RE.match(email):
        return display_name, email, "That email address does not look valid."
    return display_name, email, None


def _list(request: Request, db: Session, status_code: int = 200, **ctx):
    users = list(db.scalars(select(User).order_by(User.username)))
    ctx.setdefault("form", {"username": "", "display_name": "", "email": "", "role": "analyst"})
    return render(request, "users.html", status_code=status_code, active="users", users=users, roles=ROLES,
                  role_descriptions=ROLE_DESCRIPTIONS, **ctx)


def _get(db: Session, user_id: int) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404)
    return user


def _actor(request: Request, db: Session) -> User:
    return db.get(User, request.state.user.id)


@router.get("/users")
def users_page(request: Request, db: Session = Depends(get_db)):
    return _list(request, db)


@router.post("/users", dependencies=[Depends(verify_csrf)])
def user_create(request: Request, username: str = Form(""), display_name: str = Form(""), email: str = Form(""),
                role: str = Form("analyst"), db: Session = Depends(get_db)):
    username = username.strip()
    form = {"username": username, "display_name": display_name, "email": email, "role": role}
    display_name, email, err = _clean_profile(display_name, email)
    if not USERNAME_RE.match(username):
        err = "Username must be 2-64 characters: letters, digits, dot, dash, underscore or @, starting with a letter or digit."
    elif role not in ROLES:
        err = "Unknown role."
    elif db.scalar(select(User).where(func.lower(User.username) == username.lower())) is not None:
        err = f"A user named '{username}' already exists."
    if err:
        return _list(request, db, status_code=400, error=err, form=form)
    password = temp_password()
    user = User(username=username, display_name=display_name, email=email, role=role,
                password_hash=hash_password(password), must_change_password=True, is_active=True)
    db.add(user)
    db.commit()
    audit(db, request, "user.created", target=username, user_id=user.id, role=role)
    return _list(request, db, secret={"username": username, "password": password, "reason": "created"})


@router.get("/users/{user_id}")
def user_edit_page(request: Request, user_id: int, db: Session = Depends(get_db)):
    return render(request, "user_form.html", active="users", target=_get(db, user_id), roles=ROLES,
                  role_descriptions=ROLE_DESCRIPTIONS)


@router.post("/users/{user_id}", dependencies=[Depends(verify_csrf)])
def user_edit(request: Request, user_id: int, role: str = Form(""), display_name: str = Form(""), email: str = Form(""),
              db: Session = Depends(get_db)):
    target = _get(db, user_id)
    display_name, email, err = _clean_profile(display_name, email)
    if role not in ROLES:
        err = "Unknown role."
    elif role != target.role:
        if target.role == "admin" or target.id == request.state.user.id:
            err = err or user_change_error(db, _actor(request, db), target, "demote")
    if err:
        return render(request, "user_form.html", status_code=400, active="users", target=target, roles=ROLES,
                      role_descriptions=ROLE_DESCRIPTIONS, error=err)
    changes = {k: [getattr(target, k), v] for k, v in (("role", role), ("display_name", display_name), ("email", email))
               if getattr(target, k) != v}
    target.role, target.display_name, target.email = role, display_name, email
    if "role" in changes:
        target.session_version += 1  # new permissions take effect on next sign-in
    db.commit()
    if changes:
        audit(db, request, "user.updated", target=target.username, user_id=target.id,
              **{k: f"{a} -> {b}" for k, (a, b) in changes.items()})
    return RedirectResponse(f"/users?msg=Saved+{target.username}", status_code=303)


@router.post("/users/{user_id}/active", dependencies=[Depends(verify_csrf)])
def user_toggle_active(request: Request, user_id: int, db: Session = Depends(get_db)):
    target = _get(db, user_id)
    if target.is_active:
        err = user_change_error(db, _actor(request, db), target, "deactivate")
        if err:
            return _list(request, db, status_code=400, error=err)
        target.is_active = False
        target.session_version += 1  # sign the user out everywhere
        action, msg = "user.deactivated", "Deactivated"
    else:
        target.is_active = True
        action, msg = "user.activated", "Activated"
    db.commit()
    audit(db, request, action, target=target.username, user_id=target.id)
    return RedirectResponse(f"/users?msg={msg}+{target.username}", status_code=303)


@router.post("/users/{user_id}/reset-password", dependencies=[Depends(verify_csrf)])
def user_reset_password(request: Request, user_id: int, db: Session = Depends(get_db)):
    target = _get(db, user_id)
    err = user_change_error(db, _actor(request, db), target, "reset")
    if err:
        return _list(request, db, status_code=400, error=err)
    password = temp_password()
    target.password_hash = hash_password(password)
    target.must_change_password = True
    target.session_version += 1
    db.commit()
    audit(db, request, "user.password_reset", target=target.username, user_id=target.id)
    return _list(request, db, secret={"username": target.username, "password": password, "reason": "reset"})


@router.post("/users/{user_id}/delete", dependencies=[Depends(verify_csrf)])
def user_delete(request: Request, user_id: int, db: Session = Depends(get_db)):
    target = _get(db, user_id)
    err = user_change_error(db, _actor(request, db), target, "delete")
    if err:
        return _list(request, db, status_code=400, error=err)
    name = target.username
    db.delete(target)
    db.commit()
    audit(db, request, "user.deleted", target=name, user_id=user_id)
    return RedirectResponse(f"/users?msg=Deleted+{name}", status_code=303)
