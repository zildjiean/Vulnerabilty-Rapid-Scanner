"""Guided tours: remember finished tours and the dismissed Dashboard prompt. UI preferences, so not audited.

Every signed-in user (viewers too) may use these; they only ever change the signed-in user's own row."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from .. import tours
from ..db import User, utcnow
from ..deps import get_db, verify_csrf
from ..i18n import flash, safe_back

router = APIRouter()


def _me(request: Request, db: Session) -> User:
    return db.get(User, request.state.user.id)


@router.post("/tours/prompt/dismiss", dependencies=[Depends(verify_csrf)])
def tour_prompt_dismiss(request: Request, next: str = Form("/"), db: Session = Depends(get_db)):
    me = _me(request, db)
    if me.tour_prompt_dismissed_at is None:
        me.tour_prompt_dismissed_at = utcnow()
        db.commit()
    if request.headers.get("x-requested-with") == "fetch":
        return Response(status_code=204)
    return RedirectResponse(safe_back(next), status_code=303)


@router.post("/tours/{key}/done", dependencies=[Depends(verify_csrf)])
def tour_done(request: Request, key: str, db: Session = Depends(get_db)):
    if tours.get(key) is None:
        raise HTTPException(status_code=404)
    me = _me(request, db)
    keys = [k for k in (me.tours_done or "").split(",") if k]
    if key not in keys:
        me.tours_done = ",".join([*keys, key])
        db.commit()
    return Response(status_code=204)


@router.post("/profile/tours/reset", dependencies=[Depends(verify_csrf)])
def tours_reset(request: Request, db: Session = Depends(get_db)):
    me = _me(request, db)
    me.tours_done, me.tour_prompt_dismissed_at = "", None
    db.commit()
    return RedirectResponse("/profile?msg=" + flash(request, "Tours reset") + "#guided-tours", status_code=303)
