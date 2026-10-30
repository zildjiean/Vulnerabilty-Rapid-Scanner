from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import Finding, Host, Rule, RuleMatch, Service, TemplateIndex
from ..deps import get_db
from ..render import SEVERITIES, render
from .jobs import job_summary, recent_jobs

router = APIRouter()


@router.get("/")
def dashboard(request: Request, db: Session = Depends(get_db)):
    sev_counts = {s: 0 for s in SEVERITIES}
    for sev, n in db.execute(select(Finding.severity, func.count()).group_by(Finding.severity)).all():
        sev_counts[sev] = n
    stats = {
        "hosts": db.scalar(select(func.count(Host.id))) or 0,
        "services": db.scalar(select(func.count(Service.id))) or 0,
        "findings": db.scalar(select(func.count(Finding.id))) or 0,
        "rule_matches": db.scalar(select(func.count(RuleMatch.id))) or 0,
        "rules": db.scalar(select(func.count(Rule.id)).where(Rule.enabled.is_(True))) or 0,
        "templates": db.scalar(select(func.count(TemplateIndex.id))) or 0,
    }
    from .issues import issue_kpis
    return render(request, "dashboard.html", active="dashboard", stats=stats, sev_counts=sev_counts, kpis=issue_kpis(db),
                  jobs=recent_jobs(db, limit=10), job_summary=job_summary)
