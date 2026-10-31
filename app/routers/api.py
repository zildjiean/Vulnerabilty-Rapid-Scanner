"""REST API v1. Authenticated by API key only (see AuthMiddleware); permissions follow the key's role."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import __version__
from .. import campaigns as camp
from .. import issues as iss
from .. import reports as rep
from ..audit import audit
from ..authz import require
from ..db import Campaign, Finding, Host, Issue, IssueTicket, Job, Rule, Service, TemplateIndex, User
from ..deps import get_db, get_runner, get_settings
from ..jobs import job_warnings
from ..notifications import get_base_url
from ..scanners.nuclei_runner import (DEFAULT_PROFILE, PROFILES, all_template_paths, profile_flags, resolve_group_paths,
                                      validate_template_paths)
from ..validation import parse_nmap_targets, parse_nuclei_targets
from .issues import list_context
from .jobs import job_summary

router = APIRouter(prefix="/api/v1", tags=["api"])
VIEW = [Depends(require("view"))]
MAX_LIMIT = 500


def _ts(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else None


def _bad(message: str):
    raise HTTPException(400, message)


@router.get("/me", dependencies=VIEW)
def me(request: Request):
    p = request.state.user
    return {"username": p.owner_username, "role": p.role, "key": p.key_name, "version": __version__}


# ----------------------------------------------------------------- issues
@router.get("/issues", dependencies=VIEW)
def issues_list(request: Request, view: str = "active", severity: str = "", status: str = "", assignee: str = "",
                confidence: str = "", overdue: str = "", q: str = "", scope: str = "", limit: int = 100, offset: int = 0,
                db: Session = Depends(get_db)):
    ctx = list_context(request, db, view, severity, status, assignee, confidence, overdue, q, scope, limit=10**6)
    rows, base = ctx["issues"], get_base_url(db)
    limit, offset = max(1, min(limit, MAX_LIMIT)), max(0, offset)
    return {"count": len(rows), "limit": limit, "offset": offset,
            "issues": [rep.export_row(i, base, ctx["risk"][i.id]) for i in rows[offset:offset + limit]]}


def _issue(db: Session, iid: int) -> Issue:
    i = db.get(Issue, iid)
    if i is None:
        raise HTTPException(404, "Issue not found.")
    return i


@router.get("/issues/{iid}", dependencies=VIEW)
def issue_get(iid: int, db: Session = Depends(get_db)):
    i = _issue(db, iid)
    out = rep.export_row(i, get_base_url(db))
    out["events"] = [{"at": _ts(e.created_at), "by": e.username, "kind": e.kind, "from": e.from_value, "to": e.to_value,
                      "body": e.body} for e in i.events]
    out["findings"] = db.scalar(select(func.count()).select_from(Finding).where(Finding.issue_id == i.id))
    out["tickets"] = [{"key": t.key, "url": t.url, "state": t.state}
                      for t in db.scalars(select(IssueTicket).where(IssueTicket.issue_id == i.id))]
    return out


class IssuePatch(BaseModel):
    status: str | None = None
    comment: str | None = None
    severity: str | None = None
    assignee: str | None = Field(default=None, description="Username; null unassigns (send the key explicitly).")


@router.patch("/issues/{iid}", dependencies=[Depends(require("issues.manage"))])
def issue_patch(request: Request, iid: int, body: IssuePatch, db: Session = Depends(get_db)):
    i = _issue(db, iid)
    actor = request.state.user
    label = f"#{i.id} {i.vuln_id} on {i.asset}"
    try:
        if "assignee" in body.model_fields_set:
            user = None
            if body.assignee:
                user = db.scalar(select(User).where(User.username == body.assignee, User.is_active.is_(True),
                                                    User.role.in_(("admin", "analyst"))))
                if user is None:
                    _bad(f"'{body.assignee}' is not an active admin or analyst.")
            iss.assign(db, i, user, actor)
            audit(db, request, "issue.assigned", target=label, assignee=user.username if user else "unassigned")
        if body.severity:
            old = i.severity
            iss.set_severity(db, i, body.severity, actor)
            audit(db, request, "issue.severity_changed", target=label, severity=f"{old} -> {body.severity}")
        if body.status:
            old = i.status
            iss.change_status(db, i, body.status, actor, body.comment or "")
            audit(db, request, "issue.status_changed", target=label, status=f"{old} -> {body.status}")
        elif body.comment:
            iss.add_comment(db, i, body.comment, actor)
            audit(db, request, "issue.commented", target=label)
    except ValueError as e:
        db.rollback()
        _bad(str(e))
    db.commit()
    return issue_get(iid, db)


# ----------------------------------------------------------------- assets
@router.get("/assets", dependencies=VIEW)
def assets(db: Session = Depends(get_db)):
    from ..scopes import scope_of_hosts
    scope_of = scope_of_hosts(db)
    services: dict[int, list] = {}
    for s in db.scalars(select(Service).order_by(Service.port)):
        services.setdefault(s.host_id, []).append({"port": s.port, "protocol": s.protocol, "service": s.service_name,
                                                   "product": s.product, "version": s.version, "cpe": s.cpe,
                                                   "tunnel": s.tunnel})
    return {"assets": [{"address": h.address, "hostname": h.hostname, "first_seen": _ts(h.first_seen),
                        "last_seen": _ts(h.last_seen), "scope": scope_of[h.id].name if h.id in scope_of else None,
                        "services": services.get(h.id, [])} for h in db.scalars(select(Host).order_by(Host.address))]}


# ----------------------------------------------------------------- campaigns
def _campaign_out(db: Session, c: Campaign) -> dict:
    issues = camp.campaign_issues(db, c)
    return {"id": c.id, "name": c.name, "cve_id": c.cve_id, "severity": c.severity, "status": c.status,
            "cvss": c.cvss_score, "kev": c.kev, "kev_due": c.kev_due or None, "created_at": _ts(c.created_at),
            "templates": [t.template_id for t in c.templates],
            "rules": [{"product": r.product_pattern, "versions": r.version_constraint}
                      for r in db.scalars(select(Rule).where(Rule.campaign_id == c.id))],
            "progress": camp.progress(issues), "url": f"{get_base_url(db)}/campaigns/{c.id}"}


@router.get("/campaigns", dependencies=VIEW)
def campaigns_list(status: str = "", db: Session = Depends(get_db)):
    stmt = select(Campaign).order_by(Campaign.created_at.desc())
    if status in ("active", "draft", "closed", "dismissed"):
        stmt = stmt.where(Campaign.status == status)
    return {"campaigns": [_campaign_out(db, c) for c in db.scalars(stmt)]}


def _campaign(db: Session, cid: int) -> Campaign:
    c = db.get(Campaign, cid)
    if c is None:
        raise HTTPException(404, "Campaign not found.")
    return c


@router.get("/campaigns/{cid}", dependencies=VIEW)
def campaign_get(cid: int, db: Session = Depends(get_db)):
    return _campaign_out(db, _campaign(db, cid))


class CampaignIn(BaseModel):
    cve_id: str = ""
    name: str = ""
    severity: str = "auto"
    description: str = ""
    product_pattern: str = ""
    version_constraint: str = ""
    attach_templates: bool = True
    fetch_intel: bool = True


@router.post("/campaigns", status_code=201, dependencies=[Depends(require("campaigns.manage"))])
async def campaign_create(request: Request, body: CampaignIn, db: Session = Depends(get_db)):
    from .campaigns import create_from_request
    try:
        c = await create_from_request(request, db, **body.model_dump())
    except ValueError as e:
        _bad(str(e))
    return _campaign_out(db, c)


class VerifyIn(BaseModel):
    profile: Literal["gentle", "normal", "aggressive"] = DEFAULT_PROFILE
    extra_targets: list[str] = []


@router.post("/campaigns/{cid}/verify", status_code=202, dependencies=[Depends(require("scan.run"))])
async def campaign_verify(request: Request, cid: int, body: VerifyIn, db: Session = Depends(get_db),
                    settings=Depends(get_settings), runner=Depends(get_runner)):
    from .campaigns import start_verify
    try:
        job = start_verify(request, db, settings, runner, _campaign(db, cid), body.profile, "\n".join(body.extra_targets))
    except ValueError as e:
        _bad(str(e))
    return {"job_id": job.id, "url": f"{get_base_url(db)}/jobs/{job.id}"}


# ----------------------------------------------------------------- surface changes
@router.get("/changes", dependencies=VIEW)
def changes_list(days: str = "", kind: str = "", job: str = "", state: str = "open", limit: int = 100,
                 db: Session = Depends(get_db)):
    """Same filter rules as the Changes page: ``days`` defaults to 30, or all time when ``job`` is given."""
    from .. import surface
    from .changes import filters
    f = filters(kind, "", days, job, state)
    limit = max(1, min(limit, MAX_LIMIT))
    rows = list(db.scalars(surface.query(db, kind=f["kind"], days=f["days"], job_id=f["job"], state=f["state"])
                           .limit(limit)))
    return {"items": [{"id": c.id, "job_id": c.job_id, "kind": c.kind, "severity": c.severity, "address": c.address,
                       "hostname": c.hostname, "port": c.port, "protocol": c.protocol, "before": c.before,
                       "after": c.after, "scope_id": c.scope_id, "created_at": _ts(c.created_at),
                       "acknowledged_at": _ts(c.acknowledged_at), "acknowledged_by": c.acknowledged_by or None}
                      for c in rows], "count": len(rows)}


# ----------------------------------------------------------------- trends
@router.get("/trends", dependencies=VIEW)
def trends_series(days: str = "", scope: str = "", db: Session = Depends(get_db)):
    """Dashboard trend series: ``days`` 30 / 90 / 180 / 365 (default 90), optional ``scope`` id."""
    from .. import trends
    from .dashboard import trend_scope
    t = trends.trends(db, trends.parse_days(days), trend_scope(db, scope))
    t["points"] = [{**p, "start": _ts(p["start"]), "end": _ts(p["end"])} for p in t["points"]]
    return t


# ----------------------------------------------------------------- scans and jobs
class NmapIn(BaseModel):
    targets: list[str]
    port_mode: Literal["top", "all", "custom"] = "top"
    custom_ports: str = ""
    timing: Literal["T2", "T3", "T4"] = "T3"
    scan_type: Literal["syn", "connect"] = "syn"
    skip_ping: bool = False


@router.post("/scans/nmap", status_code=202, dependencies=[Depends(require("scan.run"))])
async def scan_nmap(request: Request, body: NmapIn, db: Session = Depends(get_db), settings=Depends(get_settings),
              runner=Depends(get_runner)):
    from .nmap import launch_nmap
    try:
        targets = parse_nmap_targets("\n".join(body.targets))
        job = launch_nmap(db, settings, runner, targets, port_mode=body.port_mode, custom_ports=body.custom_ports,
                          timing=body.timing, skip_ping=body.skip_ping, scan_type=body.scan_type)
    except ValueError as e:
        _bad(str(e))
    audit(db, request, "scan.nmap", target=", ".join(targets), job_id=job.id, port_mode=body.port_mode,
          scan_type=body.scan_type)
    return {"job_id": job.id, "url": f"{get_base_url(db)}/jobs/{job.id}"}


class NucleiIn(BaseModel):
    targets: list[str]
    mode: Literal["selected", "all", "groups"] = "selected"
    template_ids: list[str] = []
    groups: list[str] = []
    severities: list[Literal["critical", "high", "medium", "low", "info"]] = []
    profile: Literal["gentle", "normal", "aggressive"] = DEFAULT_PROFILE


@router.post("/scans/nuclei", status_code=202, dependencies=[Depends(require("scan.run"))])
async def scan_nuclei(request: Request, body: NucleiIn, db: Session = Depends(get_db), settings=Depends(get_settings),
                runner=Depends(get_runner)):
    from .nuclei import launch_nuclei
    try:
        targets = parse_nuclei_targets("\n".join(body.targets))
        if body.mode == "all":
            paths = all_template_paths(settings)
        elif body.mode == "groups":
            paths = resolve_group_paths(settings, body.groups)
        else:
            if not body.template_ids:
                raise ValueError("List template_ids, or use mode 'all' / 'groups'.")
            found = {t.template_id: t.path for t in db.scalars(select(TemplateIndex)
                                                                .where(TemplateIndex.template_id.in_(body.template_ids)))}
            missing = [t for t in body.template_ids if t not in found]
            if missing:
                raise ValueError(f"Unknown template id(s): {', '.join(missing[:5])}")
            paths = validate_template_paths(settings, list(found.values()))
        prof = PROFILES[body.profile]
        params = {"targets": targets, "template_ids": body.template_ids, "mode": body.mode, "groups": body.groups,
                  "severities": list(body.severities), "profile": body.profile}
        job = launch_nuclei(db, settings, runner, targets, paths, params, rate_limit=prof["rate_limit"],
                            timeout=prof["timeout"], extra_flags=profile_flags(body.profile, False),
                            severities=list(body.severities))
    except ValueError as e:
        _bad(str(e))
    audit(db, request, "scan.nuclei", target=", ".join(targets), job_id=job.id, mode=body.mode, profile=body.profile,
          templates=len(paths))
    return {"job_id": job.id, "url": f"{get_base_url(db)}/jobs/{job.id}"}


@router.get("/jobs/{job_id}", dependencies=VIEW)
def job_get(job_id: int, log: bool = False, db: Session = Depends(get_db)):
    j = db.get(Job, job_id)
    if j is None:
        raise HTTPException(404, "Job not found.")
    out = {"id": j.id, "kind": j.kind, "status": j.status, "exit_code": j.exit_code, "summary": job_summary(j),
           "warnings": job_warnings(j), "created_at": _ts(j.created_at), "started_at": _ts(j.started_at),
           "finished_at": _ts(j.finished_at), "campaign_id": j.campaign_id, "schedule_id": j.schedule_id}
    if j.kind == "nuclei":
        out["findings"] = db.scalar(select(func.count()).select_from(Finding).where(Finding.job_id == j.id))
    if log:
        out["log_tail"] = (j.log or "")[-20000:]
    return JSONResponse(out)
