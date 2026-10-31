"""Issues: list with KPIs and bulk actions, detail with timeline, triage actions; SLA settings."""
from __future__ import annotations

from datetime import timedelta
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from .. import issues as iss
from .. import proof
from .. import risk as rk
from ..audit import audit
from ..campaigns import campaigns_for_issue
from ..ai import latest_note
from ..ai_features import TRIAGE_LABELS
from ..reverify import get_reverify_settings
from ..authz import require
from ..db import Finding, Issue, IssueTicket, NotificationChannel, Rule, TemplateIndex, User, utcnow
from ..deps import get_db, get_settings, verify_csrf
from ..render import SEVERITY_ORDER, render, templates
from ..templates_index import index_single, save_custom_template

router = APIRouter()
LIST_LIMIT = 1000
VIEWS = {"active": iss.ACTIVE, "closed": iss.CLOSED, "all": iss.STATUSES}

templates.env.globals.update(
    issue_status_labels=iss.STATUS_LABELS, issue_confidence_labels=iss.CONFIDENCE_LABELS,
    issue_is_overdue=iss.is_overdue, issue_severities=iss.ISSUE_SEVERITIES,
)


def assignable_users(db: Session) -> list[User]:
    return list(db.scalars(select(User).where(User.is_active.is_(True), User.role.in_(("admin", "analyst")))
                           .order_by(User.username)))


def issue_kpis(db: Session) -> dict:
    now = utcnow()
    active = list(db.scalars(select(Issue).where(Issue.status.in_(iss.ACTIVE))))
    open_work = [i for i in active if i.status in iss.OPEN_WORK]
    return {
        "active": len(active),
        "overdue": sum(1 for i in open_work if iss.is_overdue(i, now)),
        "due_soon": sum(1 for i in open_work if i.due_at and now <= i.due_at <= now + timedelta(days=7)),
        "unassigned": sum(1 for i in open_work if i.assignee_id is None),
        "confirmed": sum(1 for i in active if i.confidence == "confirmed"),
        "conf_verified": sum(1 for i in active if i.confidence == "verified"),
        "suspected": sum(1 for i in active if i.confidence == "suspected"),
        "scan_confirmed": sum(1 for i in active if i.confidence in iss.SCAN_CONFIRMED),
        "awaiting_verification": sum(1 for i in active if i.status == "fixed"),
        "critical": sum(1 for i in open_work if i.severity == "critical"),
    }


def _sort_key(i: Issue):
    return (SEVERITY_ORDER.get(i.severity, 99), i.due_at or utcnow() + timedelta(days=36500), -i.id)


def list_context(request: Request, db: Session, view: str = "active", severity: str = "", status: str = "",
                 assignee: str = "", confidence: str = "", overdue: str = "", q: str = "", scope: str = "",
                 limit: int = LIST_LIMIT) -> dict:
    view = view if view in VIEWS else "active"
    stmt = select(Issue).options(selectinload(Issue.assignee), selectinload(Issue.scope))
    if scope == "none":
        stmt = stmt.where(Issue.scope_id.is_(None))
    elif scope.isdigit():
        stmt = stmt.where(Issue.scope_id == int(scope))
    stmt = stmt.where(Issue.status == status) if status in iss.STATUSES else stmt.where(Issue.status.in_(VIEWS[view]))
    if severity in iss.ISSUE_SEVERITIES:
        stmt = stmt.where(Issue.severity == severity)
    if confidence in iss.CONFIDENCE_LABELS:
        stmt = stmt.where(Issue.confidence == confidence)
    if assignee == "me":
        stmt = stmt.where(Issue.assignee_id == request.state.user.id)
    elif assignee == "none":
        stmt = stmt.where(Issue.assignee_id.is_(None))
    elif assignee.isdigit():
        stmt = stmt.where(Issue.assignee_id == int(assignee))
    ql = q.strip()
    if ql:
        like = f"%{ql}%"
        stmt = stmt.where(or_(Issue.title.ilike(like), Issue.asset.ilike(like), Issue.vuln_id.ilike(like),
                              Issue.hostname.ilike(like), Issue.template_id.ilike(like)))
    rows = list(db.scalars(stmt))
    if overdue:
        rows = [i for i in rows if iss.is_overdue(i)]
    scores = rk.scores_for(db, rows)
    truncated = len(rows) > limit
    rows.sort(key=lambda i: (-scores[i.id].total, *_sort_key(i)))
    rows = rows[:limit]
    filters = {"view": view, "severity": severity, "status": status, "assignee": assignee, "confidence": confidence,
               "overdue": overdue, "q": q, "scope": scope}
    from ..db import Scope
    return dict(scopes=list(db.scalars(select(Scope).order_by(Scope.name))), active="issues", issues=rows, truncated=truncated,
                risk={i.id: scores[i.id] for i in rows}, kpis=issue_kpis(db),
                users=assignable_users(db), f=filters, statuses=iss.STATUSES)


@router.get("/issues")
def issues_page(request: Request, view: str = "active", severity: str = "", status: str = "", assignee: str = "",
                confidence: str = "", overdue: str = "", q: str = "", scope: str = "", db: Session = Depends(get_db)):
    return render(request, "issues.html", **list_context(request, db, view, severity, status, assignee, confidence,
                                                         overdue, q, scope))


def _get(db: Session, issue_id: int) -> Issue:
    issue = db.get(Issue, issue_id)
    if issue is None:
        raise HTTPException(404)
    return issue


def _detail(request: Request, db: Session, issue: Issue, status_code: int = 200, error: str | None = None, **extra):
    findings = list(db.scalars(select(Finding).where(Finding.issue_id == issue.id).order_by(Finding.id.desc()).limit(50)))
    wanted = request.query_params.get("proof", "")
    selected = next((f for f in findings if str(f.id) == wanted), None)
    if selected is None and wanted.isascii() and wanted.isdigit() and len(wanted) < 12:   # older than the 50 listed
        older = db.get(Finding, int(wanted))
        selected = older if older is not None and older.issue_id == issue.id else None
    selected = selected or (findings[0] if findings else None)
    rule = db.get(Rule, issue.rule_id) if issue.rule_id else None
    return render(request, "issue_detail.html", status_code=status_code, active="issues", issue=issue, error=error,
                  findings=findings, rule=rule, users=assignable_users(db), verify_labels=proof.VERIFY_LABELS,
                  proof=proof.proof_from_finding(selected),
                  transitions=iss.allowed_transitions(issue.status), needs_reason=iss.NEEDS_REASON,
                  sla=iss.get_sla(db), campaigns=campaigns_for_issue(db, issue), reverify=get_reverify_settings(db),
                  ai_explain=latest_note(db, "explain", "issue", issue.id), ai_triage=latest_note(db, "triage", "issue", issue.id),
                  triage_labels=TRIAGE_LABELS, has_evidence=bool(findings), risk=rk.scores_for(db, [issue])[issue.id],
                  tickets=list(db.scalars(select(IssueTicket).where(IssueTicket.issue_id == issue.id))),
                  ticket_channels=list(db.scalars(select(NotificationChannel).where(
                      NotificationChannel.kind.in_(("jira", "gitlab")), NotificationChannel.enabled.is_(True)))),
                  **extra)


def _label(issue: Issue) -> str:
    return f"#{issue.id} {issue.vuln_id} on {issue.asset}"


def _actor(request: Request, db: Session) -> User:
    return db.get(User, request.state.user.id)


def _redirect(url: str, **q) -> RedirectResponse:
    """Redirect with ?msg= / ?err=, replacing any flash left in the URL by an earlier redirect."""
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in ("msg", "err")]
    query += list(q.items())
    return RedirectResponse(urlunsplit(parts._replace(query=urlencode(query))), status_code=303)


def _safe_back(back: str, issue: Issue) -> str:
    """Only same-site paths are honoured; anything else returns to the issue page."""
    return back if back.startswith("/") and not back.startswith(("//", "/\\")) else f"/issues/{issue.id}"


def _verify(request: Request, db: Session, issue: Issue, back: str):
    """Shared by the Play button and by 'Save & run as proof'. Must be called from an async route."""
    url = _safe_back(back, issue)
    live = proof.live_verify_job(db, issue)
    if live is not None:
        return _redirect(url, msg=f"Verification already running (job #{live.id}).")
    if not issue.template_id:
        return RedirectResponse(f"/issues/{issue.id}#verify", status_code=303)
    try:
        job = proof.start_verify(db, request.app, issue, _actor(request, db))
    except proof.VerifyError as e:
        if back:
            return _redirect(url, err=str(e))
        return _detail(request, db, issue, status_code=400, error=str(e))
    audit(db, request, "issue.verify", target=_label(issue), job_id=job.id, template_id=issue.template_id)
    return _redirect(url, msg=f"Verification started for {issue.asset} (job #{job.id}).")


@router.get("/issues/{issue_id}")
def issue_detail(request: Request, issue_id: int, db: Session = Depends(get_db)):
    return _detail(request, db, _get(db, issue_id))


@router.post("/issues/bulk", dependencies=[Depends(require("issues.manage")), Depends(verify_csrf)])
def issues_bulk(request: Request, issue_ids: list[int] = Form(default=[]), action: str = Form(""),
                assignee: str = Form(""), status: str = Form(""), comment: str = Form(""), db: Session = Depends(get_db)):
    if not issue_ids or action not in ("assign", "status"):
        return render(request, "issues.html", status_code=400, error="Select at least one issue and an action.",
                      **list_context(request, db))
    actor = _actor(request, db)
    target_user = db.get(User, int(assignee)) if action == "assign" and assignee.isdigit() else None
    updated = skipped = 0
    for issue in db.scalars(select(Issue).where(Issue.id.in_(issue_ids))):
        try:
            if action == "assign":
                if issue.assignee_id != (target_user.id if target_user else None):
                    iss.assign(db, issue, target_user, actor)
            else:
                iss.change_status(db, issue, status, actor, comment)
            updated += 1
        except ValueError:
            skipped += 1
    db.commit()
    audit(db, request, "issue.bulk_updated", target=f"{updated} issue(s)", operation=action,
          value=(target_user.username if target_user else "unassigned") if action == "assign" else status,
          skipped=skipped)
    msg = f"Updated {updated} issue(s)" + (f", skipped {skipped} (transition not allowed)" if skipped else "")
    return RedirectResponse("/issues?msg=" + msg.replace(" ", "+"), status_code=303)


@router.post("/issues/{issue_id}/status", dependencies=[Depends(require("issues.manage")), Depends(verify_csrf)])
def issue_status(request: Request, issue_id: int, status: str = Form(""), comment: str = Form(""),
                 db: Session = Depends(get_db)):
    issue = _get(db, issue_id)
    old = issue.status
    try:
        iss.change_status(db, issue, status, _actor(request, db), comment)
    except ValueError as e:
        db.rollback()
        return _detail(request, db, _get(db, issue_id), status_code=400, error=str(e))
    db.commit()
    audit(db, request, "issue.status_changed", target=_label(issue), status=f"{old} -> {status}",
          **({"comment": comment.strip()[:200]} if comment.strip() else {}))
    return RedirectResponse(f"/issues/{issue_id}?msg=Status+updated", status_code=303)


@router.post("/issues/{issue_id}/assign", dependencies=[Depends(require("issues.manage")), Depends(verify_csrf)])
def issue_assign(request: Request, issue_id: int, assignee: str = Form(""), db: Session = Depends(get_db)):
    issue = _get(db, issue_id)
    user = db.get(User, int(assignee)) if assignee.isdigit() else None
    if assignee and (user is None or user not in assignable_users(db)):
        return _detail(request, db, issue, status_code=400, error="That user cannot be assigned issues.")
    iss.assign(db, issue, user, _actor(request, db))
    db.commit()
    audit(db, request, "issue.assigned", target=_label(issue), assignee=user.username if user else "unassigned")
    return RedirectResponse(f"/issues/{issue_id}?msg=Assignee+updated", status_code=303)


@router.post("/issues/{issue_id}/severity", dependencies=[Depends(require("issues.manage")), Depends(verify_csrf)])
def issue_severity(request: Request, issue_id: int, severity: str = Form(""), db: Session = Depends(get_db)):
    issue = _get(db, issue_id)
    old = issue.severity
    try:
        iss.set_severity(db, issue, severity, _actor(request, db))
    except ValueError as e:
        db.rollback()
        return _detail(request, db, _get(db, issue_id), status_code=400, error=str(e))
    db.commit()
    audit(db, request, "issue.severity_changed", target=_label(issue), severity=f"{old} -> {severity}")
    return RedirectResponse(f"/issues/{issue_id}?msg=Severity+updated", status_code=303)


@router.post("/issues/{issue_id}/comment", dependencies=[Depends(require("issues.manage")), Depends(verify_csrf)])
def issue_comment(request: Request, issue_id: int, body: str = Form(""), db: Session = Depends(get_db)):
    issue = _get(db, issue_id)
    try:
        iss.add_comment(db, issue, body, _actor(request, db))
    except ValueError as e:
        return _detail(request, db, issue, status_code=400, error=str(e))
    db.commit()
    audit(db, request, "issue.commented", target=_label(issue))
    return RedirectResponse(f"/issues/{issue_id}?msg=Comment+added#timeline", status_code=303)


@router.post("/issues/{issue_id}/verify", dependencies=[Depends(require("scan.run")), Depends(verify_csrf)])
async def issue_verify(request: Request, issue_id: int, back: str = Form(""), db: Session = Depends(get_db)):
    return _verify(request, db, _get(db, issue_id), back)


@router.post("/issues/{issue_id}/template", dependencies=[Depends(require("issues.manage")), Depends(verify_csrf)])
def issue_template(request: Request, issue_id: int, template_id: str = Form(""), db: Session = Depends(get_db)):
    issue = _get(db, issue_id)
    if proof.live_verify_job(db, issue) is not None:   # complete_verify matches findings on the template id
        return _redirect(f"/issues/{issue.id}", err="Wait for the running verification to finish before changing the template.")
    tid = template_id.strip()
    row = db.scalar(select(TemplateIndex).where(TemplateIndex.template_id == tid).limit(1)) if tid else None
    if row is None:
        return _detail(request, db, issue, status_code=400, error="Pick a template that exists in the template index.")
    issue.template_id = tid
    iss._event(db, issue, "verify", _actor(request, db), body=f"Linked verification template {tid}.")
    audit(db, request, "issue.template", target=_label(issue), template_id=tid)
    db.commit()
    return _redirect(f"/issues/{issue.id}", msg="Template linked. Press Verify now to run it.")


@router.post("/issues/{issue_id}/template/save-run",
             dependencies=[Depends(require("templates.manage")), Depends(require("scan.run")), Depends(verify_csrf)])
async def issue_template_save_run(request: Request, issue_id: int, yaml: str = Form(""), db: Session = Depends(get_db),
                                  settings=Depends(get_settings)):
    """Save the reviewed draft as a custom template, link it to the issue and start the verification scan."""
    from .templates import validate_and_check
    issue = _get(db, issue_id)
    if proof.live_verify_job(db, issue) is not None:   # complete_verify matches findings on the template id
        return _redirect(f"/issues/{issue.id}", err="Wait for the running verification to finish before changing the template.")
    if issue.template_id:
        return _redirect(f"/issues/{issue.id}", err="This issue already has a verification template. Press Verify now to run it.")
    def failed(message: str):
        draft = {"yaml": yaml, "ok": False, "message": message, "notes": "", "provider": "", "model": ""}
        return _detail(request, db, issue, status_code=400, verify_draft=draft)
    try:
        info, ok, line = await validate_and_check(settings, yaml)
        if not ok:
            raise ValueError(line or "nuclei -validate failed")
    except ValueError as e:
        return failed(f"Validation failed: {e}")
    if db.scalar(select(TemplateIndex).where(TemplateIndex.template_id == info.template_id, TemplateIndex.source != "custom")):
        return failed(f"Template id '{info.template_id}' already exists in the library; change the id.")
    path = save_custom_template(settings, yaml)
    index_single(db, path, "custom")
    issue.template_id = info.template_id
    iss._event(db, issue, "verify", _actor(request, db), body=f"Saved verification template {info.template_id} (custom).")
    audit(db, request, "template.saved", target=info.template_id, issue=issue.id, source="ai-draft")
    db.commit()
    return _verify(request, db, issue, back="")


# ----------------------------------------------------------------- settings
def _settings(request: Request, db: Session, status_code: int = 200, error: str | None = None, sla=None, tz=None):
    from ..notifications import get_base_url, get_smtp
    from ..reverify import get_reverify_settings
    from ..scheduler import get_timezone
    smtp = get_smtp(db, request.app.state.secretbox)
    return render(request, "settings.html", status_code=status_code, active="settings", error=error,
                  sla=sla or iss.get_sla(db), defaults=iss.DEFAULT_SLA, timezone=tz or get_timezone(db),
                  common_timezones=COMMON_TIMEZONES, base_url=get_base_url(db), reverify=get_reverify_settings(db),
                  smtp={k: v for k, v in smtp.items() if k != "password"}, smtp_password_set=bool(smtp.get("password")),
                  intel_refresh=rk.last_refresh(db), intel_refreshing=getattr(request.app.state, "intel_refreshing", False))


@router.post("/settings/reverify", dependencies=[Depends(require("settings.manage")), Depends(verify_csrf)])
def settings_reverify(request: Request, enabled: bool = Form(False), delay_minutes: str = Form("15"),
                      db: Session = Depends(get_db)):
    from ..reverify import set_reverify_settings
    try:
        set_reverify_settings(db, enabled, int(delay_minutes) if delay_minutes.strip().lstrip("-").isdigit() else -1)
    except ValueError as e:
        db.rollback()
        return _settings(request, db, 400, str(e))
    db.commit()
    audit(db, request, "settings.updated", target="re-verify", enabled=enabled, delay_minutes=delay_minutes)
    return RedirectResponse("/settings?msg=Re-verify+settings+saved#reverify", status_code=303)


@router.post("/settings/intel/refresh", dependencies=[Depends(require("settings.manage")), Depends(verify_csrf)])
async def settings_intel_refresh(request: Request, db: Session = Depends(get_db)):
    summary = await rk.run_refresh(request.app)
    if summary is None:
        return _redirect("/settings#intel", msg="A threat intel refresh is already running.")
    audit(db, request, "intel.refreshed", target=f"{summary['cves']} CVE(s)", epss=summary["epss"], kev=summary["kev"],
          nvd=summary["nvd"], errors=len(summary["errors"]))
    if summary["errors"]:
        return _redirect("/settings#intel", err=rk.summary_text(summary))
    return _redirect("/settings#intel", msg=rk.summary_text(summary))


@router.post("/settings/notifications", dependencies=[Depends(require("settings.manage")), Depends(verify_csrf)])
def settings_notifications(request: Request, base_url: str = Form(""), smtp_host: str = Form(""), smtp_port: str = Form("587"),
                           smtp_security: str = Form("starttls"), smtp_username: str = Form(""),
                           smtp_password: str = Form(""), smtp_from: str = Form(""), db: Session = Depends(get_db)):
    from ..notifications import set_base_url, set_smtp
    try:
        set_base_url(db, base_url)
        set_smtp(db, request.app.state.secretbox, smtp_host, smtp_port, smtp_security, smtp_username, smtp_from, smtp_password)
    except ValueError as e:
        db.rollback()
        return _settings(request, db, 400, str(e))
    db.commit()
    audit(db, request, "settings.updated", target="notifications", base_url=base_url.strip(), smtp_host=smtp_host.strip(),
          smtp_password_changed=bool(smtp_password))
    return RedirectResponse("/settings?msg=Notification+settings+saved#notifications", status_code=303)


COMMON_TIMEZONES = ("Asia/Bangkok", "UTC", "Asia/Singapore", "Asia/Tokyo", "Asia/Kolkata", "Europe/London",
                    "Europe/Berlin", "America/New_York", "America/Los_Angeles", "Australia/Sydney")


@router.get("/settings", dependencies=[Depends(require("settings.manage"))])
def settings_page(request: Request, db: Session = Depends(get_db)):
    return _settings(request, db)


@router.post("/settings/timezone", dependencies=[Depends(require("settings.manage")), Depends(verify_csrf)])
def settings_timezone(request: Request, timezone: str = Form(""), db: Session = Depends(get_db)):
    from ..scheduler import get_timezone, set_timezone
    old = get_timezone(db)
    try:
        set_timezone(db, timezone)
    except ValueError as e:
        db.rollback()
        return _settings(request, db, 400, str(e), tz=timezone)
    db.commit()
    audit(db, request, "settings.updated", target="timezone", timezone=f"{old} -> {timezone.strip()}")
    return RedirectResponse("/settings?msg=Timezone+saved;+schedules+recalculated", status_code=303)


@router.post("/settings", dependencies=[Depends(require("settings.manage")), Depends(verify_csrf)])
def settings_save(request: Request, critical: str = Form(""), high: str = Form(""), medium: str = Form(""),
                  low: str = Form(""), db: Session = Depends(get_db)):
    values = {"critical": critical, "high": high, "medium": medium, "low": low}
    old = iss.get_sla(db)
    try:
        sla = iss.set_sla(db, values)
    except ValueError as e:
        db.rollback()
        return _settings(request, db, 400, str(e), sla={**old, **values})
    db.commit()
    audit(db, request, "settings.updated", target="SLA days",
          **{k: f"{old[k]} -> {sla[k]}" for k in sla if old[k] != sla[k]})
    return RedirectResponse("/settings?msg=SLA+saved;+due+dates+recalculated", status_code=303)
