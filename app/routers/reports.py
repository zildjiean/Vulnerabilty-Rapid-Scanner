"""Printable reports (executive, campaign, scope) and issue exports (CSV / JSON)."""
from __future__ import annotations

import csv
import io
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import campaigns as camp
from .. import reports as rep
from ..audit import audit
from ..db import Campaign, Issue, Scope, utcnow
from ..deps import get_db
from ..issues import ACTIVE
from ..notifications import get_base_url
from ..render import render
from .issues import list_context
from .scopes import scope_hosts

router = APIRouter()
EXPORT_LIMIT = 100_000


def _days(value: str) -> int:
    return int(value) if value.isdigit() and 1 <= int(value) <= 3650 else rep.DEFAULT_DAYS


@router.get("/reports")
def executive_report(request: Request, days: str = str(rep.DEFAULT_DAYS), db: Session = Depends(get_db)):
    d = _days(days)
    campaigns = [(c, camp.progress(camp.campaign_issues(db, c)))
                 for c in db.scalars(select(Campaign).where(Campaign.status == "active").order_by(Campaign.created_at.desc()))]
    return render(request, "report_executive.html", active="reports", r=rep.executive(db, d), periods=rep.PERIODS,
                  campaigns=campaigns)


@router.get("/reports/campaigns/{cid}")
def campaign_report(request: Request, cid: int, db: Session = Depends(get_db)):
    c = db.get(Campaign, cid)
    if c is None:
        raise HTTPException(404)
    issues = camp.campaign_issues(db, c)
    return render(request, "report_campaign.html", active="reports", c=c, issues=issues, p=camp.progress(issues),
                  refs=camp.references(c), generated=utcnow())


@router.get("/reports/scopes/{sid}")
def scope_report(request: Request, sid: int, db: Session = Depends(get_db)):
    s = db.get(Scope, sid)
    if s is None:
        raise HTTPException(404)
    issues = list(db.scalars(select(Issue).where(Issue.scope_id == sid, Issue.status.in_(ACTIVE))
                             .order_by(Issue.due_at)))
    return render(request, "report_scope.html", active="reports", s=s, issues=issues, hosts=scope_hosts(db, s),
                  generated=utcnow())


def _export(request: Request, db: Session, fmt: str, **filters):
    ctx = list_context(request, db, limit=EXPORT_LIMIT, **filters)
    base = get_base_url(db)
    rows = [rep.export_row(i, base) for i in ctx["issues"]]
    audit(db, request, "report.exported", target=f"issues.{fmt}", rows=len(rows),
          **{k: v for k, v in filters.items() if v})
    stamp = utcnow().strftime("%Y%m%d-%H%M%S")
    if fmt == "json":
        return JSONResponse({"generated_at": stamp, "count": len(rows), "filters": {k: v for k, v in filters.items() if v},
                             "issues": rows}, headers={"Content-Disposition": f'attachment; filename="issues-{stamp}.json"'})
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=rep.EXPORT_FIELDS)
    w.writeheader()
    for row in rows:
        w.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") else v)
                    for k, v in row.items()})
    return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="issues-{stamp}.csv"'})


@router.get("/reports/issues.csv")
def export_csv(request: Request, view: str = "active", severity: str = "", status: str = "", assignee: str = "",
               confidence: str = "", overdue: str = "", q: str = "", scope: str = "", db: Session = Depends(get_db)):
    return _export(request, db, "csv", view=view, severity=severity, status=status, assignee=assignee,
                   confidence=confidence, overdue=overdue, q=q, scope=scope)


@router.get("/reports/issues.json")
def export_json(request: Request, view: str = "active", severity: str = "", status: str = "", assignee: str = "",
                confidence: str = "", overdue: str = "", q: str = "", scope: str = "", db: Session = Depends(get_db)):
    return _export(request, db, "json", view=view, severity=severity, status=status, assignee=assignee,
                   confidence=confidence, overdue=overdue, q=q, scope=scope)
