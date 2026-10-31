"""Attack-surface changes: what each nmap scan changed in the inventory, with acknowledgement."""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import surface
from ..audit import audit
from ..authz import require
from ..db import Scope, SurfaceChange
from ..deps import get_db, verify_csrf
from ..render import render

router = APIRouter()
PAGE_SIZE = 50
DAYS_LABELS = {"1": "Last 24 hours", "7": "Last 7 days", "30": "Last 30 days", "90": "Last 90 days", "all": "All time"}


def _int(value: str) -> int | None:
    value = (value or "").strip()
    return int(value) if value.isdigit() and int(value) > 0 else None


def filters(kind: str = "", scope: str = "", days: str = "", job: str = "", state: str = "") -> dict:
    """Normalised filters. A job link without ``days`` shows that job whatever its age."""
    job_id = _int(job)
    return {"kind": kind if kind in surface.KIND_LABELS else "", "scope": _int(scope),
            "days": surface.parse_days(days, "all" if job_id and not days else surface.DEFAULT_DAYS),
            "job": job_id, "state": "all" if state == "all" else "open"}


def _query(db: Session, f: dict):
    return surface.query(db, kind=f["kind"], scope_id=f["scope"], days=f["days"], job_id=f["job"], state=f["state"])


def _params(f: dict) -> dict:
    return {k: v for k, v in f.items() if v not in (None, "")}


def _back(f: dict, msg: str, page: int = 1) -> RedirectResponse:
    q = {**_params(f), **({"page": page} if page > 1 else {}), "msg": msg}
    return RedirectResponse("/changes?" + urlencode(q), status_code=303)


@router.get("/changes")
def changes_page(request: Request, kind: str = "", scope: str = "", days: str = "", job: str = "", state: str = "",
                 page: str = "1", db: Session = Depends(get_db)):
    f = filters(kind, scope, days, job, state)
    stmt = _query(db, f)
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    pages = max(1, -(-total // PAGE_SIZE))
    page = min(_int(page) or 1, pages)
    rows = list(db.scalars(stmt.limit(PAGE_SIZE).offset((page - 1) * PAGE_SIZE)))
    open_count, max_id = db.execute(select(func.count(SurfaceChange.id), func.max(SurfaceChange.id))
                                    .where(*surface.conditions(f["kind"], f["scope"], f["days"], f["job"], "open"))).one()

    def page_url(n: int) -> str:
        return "/changes?" + urlencode({**_params(f), "page": n})

    scopes = list(db.scalars(select(Scope).order_by(Scope.name)))
    return render(request, "changes.html", active="changes", rows=rows, total=total, page=page, pages=pages,
                  page_url=page_url, f=f, open_count=open_count or 0, max_id=max_id or 0, kind_labels=surface.KIND_LABELS,
                  days_labels=DAYS_LABELS, scopes=scopes, scope_names={s.id: s.name for s in scopes})


@router.post("/changes/ack-all", dependencies=[Depends(require("issues.manage")), Depends(verify_csrf)])
def changes_ack_all(request: Request, kind: str = Form(""), scope: str = Form(""), days: str = Form(""),
                    job: str = Form(""), state: str = Form(""), max_id: str = Form(""), db: Session = Depends(get_db)):
    """Acks only what the page showed: rows up to ``max_id`` (the newest id at render time). No max_id, nothing acked."""
    f = filters(kind, scope, days, job, state)
    n = surface.acknowledge_matching(db, getattr(request.state.user, "username", ""), _int(max_id) or 0, kind=f["kind"],
                                     scope_id=f["scope"], days=f["days"], job_id=f["job"])
    db.commit()
    audit(db, request, "surface.ack", target=f"{n} change(s)", count=n, **_params(f))
    return _back(f, f"Acknowledged {n} change(s)")


@router.post("/changes/{cid}/ack", dependencies=[Depends(require("issues.manage")), Depends(verify_csrf)])
def changes_ack(request: Request, cid: int, kind: str = Form(""), scope: str = Form(""), days: str = Form(""),
                job: str = Form(""), state: str = Form(""), page: str = Form("1"), db: Session = Depends(get_db)):
    c = db.get(SurfaceChange, cid)
    if c is None:
        raise HTTPException(404)
    n = surface.acknowledge([c], getattr(request.state.user, "username", ""))
    db.commit()
    audit(db, request, "surface.ack", target=f"change #{c.id} {c.kind} on {c.address}", count=n, change_id=c.id)
    return _back(filters(kind, scope, days, job, state), "Change acknowledged", _int(page) or 1)
