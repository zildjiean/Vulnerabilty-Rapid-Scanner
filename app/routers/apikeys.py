"""API key management page and the in-app API reference."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..apikeys import EXPIRY_CHOICES, allowed_roles, create_key
from ..audit import audit
from ..authz import has_perm
from ..db import ApiKey, User, utcnow
from ..deps import get_db, verify_csrf
from ..notifications import get_base_url
from ..render import render

router = APIRouter()


def _page(request: Request, db: Session, status_code: int = 200, error: str | None = None, new_key: str | None = None):
    me = request.state.user
    show_all = has_perm(me, "users.manage")
    stmt = select(ApiKey).order_by(ApiKey.created_at.desc())
    if not show_all:
        stmt = stmt.where(ApiKey.user_id == me.id)
    return render(request, "api_keys.html", status_code=status_code, active="api", error=error, keys=list(db.scalars(stmt)),
                  show_all=show_all, roles=allowed_roles(me.role), expiries=EXPIRY_CHOICES, new_key=new_key, now=utcnow())


@router.get("/api-keys")
def api_keys_page(request: Request, db: Session = Depends(get_db)):
    return _page(request, db)


@router.post("/api-keys", dependencies=[Depends(verify_csrf)])
def api_key_create(request: Request, name: str = Form(""), role: str = Form("viewer"), expires: str = Form("90"),
                   db: Session = Depends(get_db)):
    owner = db.get(User, request.state.user.id)
    try:
        key, raw = create_key(db, owner, name, role, expires)
    except ValueError as e:
        db.rollback()
        return _page(request, db, 400, str(e))
    db.commit()
    audit(db, request, "apikey.created", target=key.name, key_id=key.id, role=role, expires=expires, prefix=key.prefix)
    return _page(request, db, new_key=raw)


@router.post("/api-keys/{kid}/revoke", dependencies=[Depends(verify_csrf)])
def api_key_revoke(request: Request, kid: int, db: Session = Depends(get_db)):
    key = db.get(ApiKey, kid)
    me = request.state.user
    if key is None or (key.user_id != me.id and not has_perm(me, "users.manage")):
        raise HTTPException(404)
    if key.revoked_at is None:
        key.revoked_at = utcnow()
        db.commit()
        audit(db, request, "apikey.revoked", target=key.name, key_id=key.id, owner=key.owner.username)
    return RedirectResponse("/api-keys?msg=Key+revoked", status_code=303)


@router.get("/api-docs")
def api_docs(request: Request, db: Session = Depends(get_db)):
    return render(request, "api_docs.html", active="api", base=get_base_url(db))
