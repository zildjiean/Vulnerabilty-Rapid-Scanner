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
    from ..ai import latest_note
    return render(request, "report_executive.html", active="reports", r=rep.executive(db, d), periods=rep.PERIODS,
                  campaigns=campaigns, ai_summary=latest_note(db, "summary", "report", d))


def _proof_on(value: str) -> bool:
    return value != "0"


@router.get("/reports/campaigns/{cid}")
def campaign_report(request: Request, cid: int, proof: str = "1", db: Session = Depends(get_db)):
    c = db.get(Campaign, cid)
    if c is None:
        raise HTTPException(404)
    issues = camp.campaign_issues(db, c)
    show = _proof_on(proof)
    return render(request, "report_campaign.html", active="reports", c=c, issues=issues, p=camp.progress(issues),
                  refs=camp.references(c), generated=utcnow(), show_proof=show,
                  evidence=rep.evidence(db, issues) if show else [])


@router.get("/reports/scopes/{sid}")
def scope_report(request: Request, sid: int, proof: str = "1", db: Session = Depends(get_db)):
    s = db.get(Scope, sid)
    if s is None:
        raise HTTPException(404)
    issues = list(db.scalars(select(Issue).where(Issue.scope_id == sid, Issue.status.in_(ACTIVE))
                             .order_by(Issue.due_at)))
    show = _proof_on(proof)
    return render(request, "report_scope.html", active="reports", s=s, issues=issues, hosts=scope_hosts(db, s),
                  generated=utcnow(), show_proof=show, evidence=rep.evidence(db, issues) if show else [])


@router.get("/reports/issues/{iid}")
def issue_report(request: Request, iid: int, db: Session = Depends(get_db)):
    """Printable evidence report for one issue: risk, intel, a short timeline and the full proof."""
    issue = db.get(Issue, iid)
    if issue is None:
        raise HTTPException(404)
    from ..campaigns import campaigns_for_issue
    from ..db import IssueEvent
    from ..proof import VERIFY_LABELS
    from ..risk import scores_for
    events = list(db.scalars(select(IssueEvent).where(IssueEvent.issue_id == issue.id)
                             .order_by(IssueEvent.id.desc()).limit(15)))
    return render(request, "report_issue.html", active="reports", issue=issue, proof=rep.issue_proof(db, issue),
                  risk=scores_for(db, [issue])[issue.id],
                  campaigns=campaigns_for_issue(db, issue), events=events, verify_labels=VERIFY_LABELS,
                  generated=utcnow())


def _export(request: Request, db: Session, fmt: str, **filters):
    ctx = list_context(request, db, limit=EXPORT_LIMIT, **filters)
    base = get_base_url(db)
    rows = [rep.export_row(i, base, ctx["risk"][i.id]) for i in ctx["issues"]]
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
