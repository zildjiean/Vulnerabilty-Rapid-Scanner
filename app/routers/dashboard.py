from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from ..db import Finding, Host, Rule, RuleMatch, Service, TemplateIndex
from ..deps import get_db
from ..render import SEVERITIES, render
from .jobs import job_summary, recent_jobs

router = APIRouter()


def top_risks(db: Session, limit: int = 5) -> list:
    """The highest-risk active issues as (issue, RiskScore)."""
    from .. import issues as iss
    from ..db import Issue
    from ..risk import scores_for
    from .issues import _sort_key
    active = list(db.scalars(select(Issue).where(Issue.status.in_(iss.ACTIVE)).options(selectinload(Issue.scope))))
    scores = scores_for(db, active)
    active.sort(key=lambda i: (-scores[i.id].total, *_sort_key(i)))
    return [(i, scores[i.id]) for i in active[:limit]]


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
    from .. import campaigns as camp
    from ..db import Campaign
    from .issues import issue_kpis
    active_campaigns = [(c, camp.progress(camp.campaign_issues(db, c)))
                        for c in db.scalars(select(Campaign).where(Campaign.status == "active")
                                            .order_by(Campaign.created_at.desc()).limit(5))]
    return render(request, "dashboard.html", active="dashboard", stats=stats, sev_counts=sev_counts, kpis=issue_kpis(db),
                  active_campaigns=active_campaigns, top_risks=top_risks(db),
                  jobs=recent_jobs(db, limit=10), job_summary=job_summary)
