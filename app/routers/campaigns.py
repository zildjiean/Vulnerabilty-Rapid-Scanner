"""Threat campaigns: create from a CVE, see exposure, verify with nuclei, track remediation."""
from __future__ import annotations

import asyncio
from urllib.parse import quote_plus

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import campaigns as camp
from ..audit import audit
from ..authz import require
from ..db import Campaign, CampaignTemplate, Job, Rule, WatchHit, utcnow
from ..deps import get_db, get_runner, get_settings, verify_csrf
from ..intel import enrich, http_get_json, normalize_cve
from ..risk import intel_for
from ..issues import CLOSED, ISSUE_SEVERITIES
from ..render import render
from ..scanners.nuclei_runner import DEFAULT_PROFILE, PROFILES, profile_flags, validate_template_paths
from ..validation import parse_nuclei_targets
from .jobs import job_summary
from .nuclei import launch_nuclei

router = APIRouter()
VIEWS = ("active", "draft", "closed", "all")
MANAGE = [Depends(require("campaigns.manage")), Depends(verify_csrf)]


async def load_intel(request: Request, cve: str, refresh: bool = False):
    get_json = getattr(request.app.state, "get_json", None) or http_get_json
    cache = request.app.state.settings.data_dir / "kev.json"
    return await asyncio.to_thread(enrich, cve, cache, get_json, refresh)


def _get(db: Session, cid: int) -> Campaign:
    c = db.get(Campaign, cid)
    if c is None:
        raise HTTPException(404)
    return c


@router.get("/campaigns")
def campaigns_page(request: Request, view: str = "active", db: Session = Depends(get_db)):
    view = view if view in VIEWS else "active"
    stmt = select(Campaign).order_by(Campaign.created_at.desc())
    if view != "all":
        stmt = stmt.where(Campaign.status == view)
    rows = [(c, camp.progress(camp.campaign_issues(db, c))) for c in db.scalars(stmt)]
    drafts = db.scalar(select(func.count(Campaign.id)).where(Campaign.status == "draft")) or 0
    return render(request, "campaigns.html", active="campaigns", rows=rows, view=view, drafts=drafts)


def _new_form(request: Request, status_code: int = 200, error: str | None = None, form: dict | None = None,
              ai_draft: dict | None = None):
    defaults = {"cve_id": "", "name": "", "severity": "auto", "description": "", "product_pattern": "",
                "version_constraint": "", "attach_templates": True, "fetch_intel": True}
    return render(request, "campaign_new.html", status_code=status_code, active="campaigns", error=error,
                  form={**defaults, **(form or {})}, severities=ISSUE_SEVERITIES, ai_draft=ai_draft)


@router.get("/campaigns/new", dependencies=[Depends(require("campaigns.manage"))])
def campaign_new(request: Request, cve: str = ""):
    return _new_form(request, form={"cve_id": cve})


async def create_from_request(request: Request, db: Session, *, cve_id: str, name: str, severity: str, description: str,
                              product_pattern: str, version_constraint: str, attach_templates: bool,
                              fetch_intel: bool) -> Campaign:
    """Shared by the web form and the API. Raises ValueError with a user-facing message."""
    cve = normalize_cve(cve_id) if cve_id.strip() else ""
    intel = await load_intel(request, cve) if cve and fetch_intel else None
    if intel and not name.strip() and intel[0].get("kev_name"):
        name = f"{cve} {intel[0]['kev_name']}"
    try:
        c = camp.create_campaign(db, name=name, cve_id=cve, description=description, severity=severity,
                                 product_pattern=product_pattern, version_constraint=version_constraint,
                                 attach_templates=attach_templates, intel=intel, created_by=request.state.user.username)
    except ValueError:
        db.rollback()
        raise
    from ..notifications import campaign_message, notify
    notify(db, "campaign.created", message=campaign_message(db, c), severity=c.severity)
    db.commit()
    audit(db, request, "campaign.created", target=c.name, campaign_id=c.id, cve=c.cve_id, severity=c.severity,
          kev=c.kev, templates=len(c.templates))
    return c


@router.post("/campaigns", dependencies=MANAGE)
async def campaign_create(request: Request, cve_id: str = Form(""), name: str = Form(""), severity: str = Form("auto"),
                          description: str = Form(""), product_pattern: str = Form(""),
                          version_constraint: str = Form(""), attach_templates: bool = Form(False),
                          fetch_intel: bool = Form(False), db: Session = Depends(get_db)):
    form = {"cve_id": cve_id, "name": name, "severity": severity, "description": description,
            "product_pattern": product_pattern, "version_constraint": version_constraint,
            "attach_templates": attach_templates, "fetch_intel": fetch_intel}
    try:
        c = await create_from_request(request, db, cve_id=cve_id, name=name, severity=severity, description=description,
                                      product_pattern=product_pattern, version_constraint=version_constraint,
                                      attach_templates=attach_templates, fetch_intel=fetch_intel)
    except ValueError as e:
        return _new_form(request, 400, str(e), form)
    return RedirectResponse(f"/campaigns/{c.id}", status_code=303)


def _detail(request: Request, db: Session, c: Campaign, status_code: int = 200, error: str | None = None):
    issues = camp.campaign_issues(db, c)
    jobs = list(db.scalars(select(Job).where(Job.campaign_id == c.id).order_by(Job.id.desc()).limit(20)))
    rules = list(db.scalars(select(Rule).where(Rule.campaign_id == c.id).order_by(Rule.id)))
    from ..watch import hit_matches
    hit = db.scalar(select(WatchHit).where(WatchHit.campaign_id == c.id))
    from ..watch import unversioned
    matches = hit_matches(hit)
    return render(request, "campaign_detail.html", watch_hit=hit, watch_matches=matches,
                  watch_unversioned=len(unversioned(matches)), status_code=status_code, active="campaigns", c=c, error=error,
                  issues=issues, p=camp.progress(issues), rules=rules, suggestions=camp.suggested_templates(db, c),
                  jobs=jobs, job_summary=job_summary, targets=camp.verify_targets(db, c), profiles=PROFILES,
                  default_profile=DEFAULT_PROFILE, refs=camp.references(c),
                  cve_intel=intel_for(db, c.cve_id), proof_candidates=len(_proof_candidates(issues)))


def _proof_candidates(issues: list) -> list:
    """Open campaign issues that have a verification template (what Verify all with proof runs)."""
    return [i for i in issues if i.status not in CLOSED and i.template_id]


@router.get("/campaigns/{cid}")
def campaign_detail(request: Request, cid: int, db: Session = Depends(get_db)):
    return _detail(request, db, _get(db, cid))


def start_verify(request: Request, db: Session, settings, runner, c: Campaign, profile: str, extra_targets: str) -> Job:
    """Validate and launch a campaign verification job. Raises ValueError with a user-facing message."""
    if c.status in ("draft", "dismissed"):
        raise ValueError("Activate this draft campaign before verifying it.")
    if not c.templates:
        raise ValueError("Attach at least one nuclei template before verifying.")
    paths = validate_template_paths(settings, [t.path for t in c.templates])
    targets = camp.verify_targets(db, c)
    extra = parse_nuclei_targets(extra_targets) if extra_targets.strip() else []
    targets += [t for t in extra if t not in targets]
    if not targets:
        raise ValueError("No exposed assets to verify. Add a version rule, run an nmap scan, or type extra targets.")
    flags = profile_flags(profile, False)
    prof = PROFILES[profile]
    params = {"targets": targets, "template_ids": [t.template_id for t in c.templates], "mode": "selected",
              "profile": profile, "campaign": c.cve_id or c.name}
    job = launch_nuclei(db, settings, runner, targets, paths, params, rate_limit=prof["rate_limit"],
                        timeout=prof["timeout"], extra_flags=flags, campaign_id=c.id)
    audit(db, request, "campaign.verified", target=c.name, campaign_id=c.id, job_id=job.id, targets=len(targets),
          profile=profile)
    return job


@router.post("/campaigns/{cid}/verify", dependencies=[Depends(require("scan.run")), Depends(verify_csrf)])
async def campaign_verify(request: Request, cid: int, profile: str = Form(DEFAULT_PROFILE), extra_targets: str = Form(""),
                          db: Session = Depends(get_db), settings=Depends(get_settings), runner=Depends(get_runner)):
    c = _get(db, cid)
    try:
        job = start_verify(request, db, settings, runner, c, profile, extra_targets)
    except ValueError as e:
        return _detail(request, db, c, status_code=400, error=str(e))
    return RedirectResponse(f"/jobs/{job.id}", status_code=303)


@router.post("/campaigns/{cid}/verify-issues", dependencies=[Depends(require("scan.run")), Depends(verify_csrf)])
async def campaign_verify_issues(request: Request, cid: int, db: Session = Depends(get_db)):
    """Verify now with proof for every open campaign issue that has a template: one job per template."""
    from .issues import _redirect, bulk_verify
    c = _get(db, cid)
    if c.status != "active":
        return _redirect(f"/campaigns/{cid}", err="Only an active campaign can verify its issues.")
    issues = [i for i in camp.campaign_issues(db, c) if i.status not in CLOSED]
    if not issues:
        return _redirect(f"/campaigns/{cid}", err="This campaign has no open issues to verify.")
    return bulk_verify(request, db, issues, f"/campaigns/{cid}", "campaign.verify_issues", c.name, campaign_id=c.id)


@router.post("/campaigns/{cid}/rules", dependencies=MANAGE)
def campaign_rule_add(request: Request, cid: int, product_pattern: str = Form(""), version_constraint: str = Form(""),
                      db: Session = Depends(get_db)):
    c = _get(db, cid)
    try:
        rule = camp.add_rule(db, c, product_pattern, version_constraint)
    except ValueError as e:
        db.rollback()
        return _detail(request, db, _get(db, cid), status_code=400, error=f"Version rule: {e}")
    db.commit()
    audit(db, request, "campaign.rule_added", target=c.name, campaign_id=c.id, rule_id=rule.id,
          product=rule.product_pattern, constraint=rule.version_constraint)
    return RedirectResponse(f"/campaigns/{cid}?msg=Rule+added+and+evaluated", status_code=303)


@router.post("/campaigns/{cid}/rules/{rid}/delete", dependencies=MANAGE)
def campaign_rule_remove(request: Request, cid: int, rid: int, db: Session = Depends(get_db)):
    c = _get(db, cid)
    rule = camp.remove_rule(db, c, rid)
    db.commit()
    if rule:
        audit(db, request, "campaign.rule_removed", target=c.name, campaign_id=c.id, rule_id=rid)
    return RedirectResponse(f"/campaigns/{cid}?msg=Rule+removed", status_code=303)


@router.post("/campaigns/{cid}/templates", dependencies=MANAGE)
def campaign_template_add(request: Request, cid: int, path: str = Form(""), db: Session = Depends(get_db)):
    c = _get(db, cid)
    try:
        ct = camp.attach_template(db, c, path)
    except ValueError as e:
        return _detail(request, db, c, status_code=400, error=str(e))
    db.commit()
    if ct:
        audit(db, request, "campaign.template_added", target=c.name, campaign_id=c.id, template=ct.template_id)
    return RedirectResponse(f"/campaigns/{cid}?msg=Template+attached", status_code=303)


@router.post("/campaigns/{cid}/templates/{tid}/delete", dependencies=MANAGE)
def campaign_template_remove(request: Request, cid: int, tid: int, db: Session = Depends(get_db)):
    c = _get(db, cid)
    ct = db.get(CampaignTemplate, tid)
    if ct is not None and ct.campaign_id == c.id:
        name = ct.template_id
        db.delete(ct)
        db.commit()
        audit(db, request, "campaign.template_removed", target=c.name, campaign_id=c.id, template=name)
    return RedirectResponse(f"/campaigns/{cid}?msg=Template+removed", status_code=303)


@router.post("/campaigns/{cid}/status", dependencies=MANAGE)
def campaign_toggle_status(request: Request, cid: int, db: Session = Depends(get_db)):
    c = _get(db, cid)
    if c.status == "draft":
        return RedirectResponse(f"/campaigns/{cid}?err=Activate+or+dismiss+this+draft+first", status_code=303)
    if c.status == "dismissed":
        return campaign_reopen(request, cid, db)
    if c.status == "active":
        c.status, c.closed_at, action = "closed", utcnow(), "campaign.closed"
    else:
        c.status, c.closed_at, action = "active", None, "campaign.reopened"
    db.commit()
    audit(db, request, action, target=c.name, campaign_id=c.id)
    return RedirectResponse(f"/campaigns/{cid}?msg=Campaign+{c.status}", status_code=303)


@router.post("/campaigns/{cid}/activate", dependencies=MANAGE)
def campaign_activate(request: Request, cid: int, db: Session = Depends(get_db)):
    """Draft (0-day watch) -> active: enable its rules, evaluate them and announce the campaign."""
    c = _get(db, cid)
    try:
        enabled = camp.activate_campaign(db, c)
        from ..watch import open_unversioned_issues
        unversioned = open_unversioned_issues(db, c)
    except ValueError as e:
        db.rollback()
        return RedirectResponse(f"/campaigns/{cid}?err={quote_plus(str(e))}", status_code=303)
    from ..notifications import campaign_message, notify
    notify(db, "campaign.created", message=campaign_message(db, c), severity=c.severity)
    db.commit()
    audit(db, request, "campaign.activated", target=c.name, campaign_id=c.id, cve=c.cve_id, rules=enabled,
          version_unknown_issues=unversioned)
    return RedirectResponse(f"/campaigns/{cid}?msg=Campaign+activated:+rules+enabled+and+evaluated", status_code=303)


@router.post("/campaigns/{cid}/dismiss", dependencies=MANAGE)
def campaign_dismiss(request: Request, cid: int, db: Session = Depends(get_db)):
    c = _get(db, cid)
    try:
        camp.dismiss_campaign(db, c)
    except ValueError as e:
        db.rollback()
        return RedirectResponse(f"/campaigns/{cid}?err={quote_plus(str(e))}", status_code=303)
    db.commit()
    audit(db, request, "campaign.dismissed", target=c.name, campaign_id=c.id, cve=c.cve_id)
    return RedirectResponse(f"/campaigns/{cid}?msg=Draft+dismissed", status_code=303)


@router.post("/campaigns/{cid}/reopen", dependencies=MANAGE)
def campaign_reopen(request: Request, cid: int, db: Session = Depends(get_db)):
    """Dismissed -> draft (closed -> active stays on /status)."""
    c = _get(db, cid)
    if c.status != "dismissed":
        return RedirectResponse(f"/campaigns/{cid}?err=Only+a+dismissed+draft+can+be+reopened+here", status_code=303)
    c.status = "draft"
    db.commit()
    audit(db, request, "campaign.reopened", target=c.name, campaign_id=c.id, to="draft")
    return RedirectResponse(f"/campaigns/{cid}?msg=Draft+reopened", status_code=303)


@router.post("/campaigns/{cid}/refresh", dependencies=MANAGE)
async def campaign_refresh(request: Request, cid: int, db: Session = Depends(get_db)):
    c = _get(db, cid)
    if not c.cve_id:
        return _detail(request, db, c, status_code=400, error="This campaign has no CVE id to look up.")
    info, errors = await load_intel(request, c.cve_id, refresh=True)
    camp.apply_intel(c, info, errors)
    db.commit()
    audit(db, request, "campaign.enriched", target=c.name, campaign_id=c.id, kev=c.kev, cvss=c.cvss_score,
          errors=len(errors))
    msg = "Intel+refreshed" if not errors else "Intel+refreshed+with+errors"
    return RedirectResponse(f"/campaigns/{cid}?msg={msg}", status_code=303)
