"""Notification rules, the delivery outbox, ticket synchronisation and the background loop."""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import channels as ch
from .db import (AppSetting, Delivery, Issue, IssueEvent, IssueTicket, Job, NotificationChannel, NotificationRule,
                 User, utcnow)

log = logging.getLogger(__name__)

EVENTS = {
    "issue.created": "New issue",
    "issue.reopened": "Issue reopened",
    "issue.overdue": "Issue past its SLA",
    "issue.assigned": "Issue assigned",
    "issue.status_changed": "Issue status changed",
    "campaign.created": "Campaign started",
    "campaign.draft": "0-day watch drafted a campaign",
    "scan.problem": "Scan failed or incomplete",
    "schedule.error": "Scheduled run failed",
    "surface.changed": "Attack surface changed",
}
TICKET_EVENTS = ("issue.created", "issue.reopened")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
RETRY_MINUTES = (1, 5, 15, 60)
MAX_ATTEMPTS = len(RETRY_MINUTES) + 1
DISPATCH_SECONDS = 10
POLL_TICKETS_SECONDS = 15 * 60
BASE_URL_KEY, SMTP_KEY, SMTP_SECRET_KEY, JOB_CURSOR_KEY = "base_url", "smtp", "smtp_secret", "notify_job_cursor"
DEFAULT_BASE_URL = "http://localhost:8000"
KIND_LABEL = {"jira": "Jira", "gitlab": "GitLab"}


# ----------------------------------------------------------------- settings
def _setting(db: Session, key: str, default: str = "") -> str:
    row = db.get(AppSetting, key)
    return row.value if row and row.value else default


def _put(db: Session, key: str, value: str) -> None:
    row = db.get(AppSetting, key) or AppSetting(key=key)
    row.value = value
    db.add(row)


def get_base_url(db: Session) -> str:
    return _setting(db, BASE_URL_KEY, DEFAULT_BASE_URL).rstrip("/")


def set_base_url(db: Session, url: str) -> None:
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")) or " " in url:
        raise ValueError("Public URL must start with http:// or https://.")
    _put(db, BASE_URL_KEY, url)


def get_smtp(db: Session, box=None) -> dict:
    try:
        cfg = json.loads(_setting(db, SMTP_KEY, "{}"))
    except json.JSONDecodeError:
        cfg = {}
    if box is not None:
        cfg["password"] = box.decrypt(_setting(db, SMTP_SECRET_KEY)).get("password", "")
    return cfg


def set_smtp(db: Session, box, host: str, port: str, security: str, username: str, from_addr: str, password: str) -> None:
    if security not in ("none", "starttls", "ssl"):
        raise ValueError("Unknown SMTP security mode.")
    if host and (not port.isdigit() or not 1 <= int(port) <= 65535):
        raise ValueError("SMTP port must be a number between 1 and 65535.")
    if from_addr and not ch.EMAIL_RE.match(from_addr):
        raise ValueError("The sender must be an email address.")
    _put(db, SMTP_KEY, json.dumps({"host": host.strip(), "port": int(port) if port.isdigit() else 587,
                                   "security": security, "username": username.strip(), "from_addr": from_addr.strip()}))
    _put(db, SMTP_SECRET_KEY, box.merge(_setting(db, SMTP_SECRET_KEY), {"password": password}))


# ----------------------------------------------------------------- messages
def issue_message(db: Session, issue: Issue, event: str, note: str = "") -> ch.Message:
    label = {"issue.created": "New issue", "issue.reopened": "Reopened", "issue.overdue": "Overdue",
             "issue.assigned": "Assigned", "issue.status_changed": "Status changed"}.get(event, "Issue")
    from .issues import CONFIDENCE_LABELS, STATUS_LABELS
    fields = [("Asset", issue.asset + (f" ({issue.hostname})" if issue.hostname and issue.hostname != issue.address else "")),
              ("Vulnerability", issue.vuln_id), ("Status", STATUS_LABELS.get(issue.status, issue.status)),
              ("Confidence", CONFIDENCE_LABELS.get(issue.confidence, issue.confidence))]
    if issue.scope_id and issue.scope:
        fields.append(("Scope", f"{issue.scope.name} ({issue.scope.criticality})"))
    from .risk import scores_for
    score = scores_for(db, [issue])[issue.id]
    fields.append(("Risk", f"{score.total} · {score.band}"))
    assignee = db.get(User, issue.assignee_id) if issue.assignee_id else None
    fields.append(("Assignee", (assignee.display_name or assignee.username) if assignee else "unassigned"))
    if issue.due_at:
        fields.append(("Due", issue.due_at.strftime("%Y-%m-%d %H:%M UTC")))
    title = f"[{issue.severity.upper()}] {label}: {issue.title or issue.vuln_id} on {issue.asset}"
    return ch.Message(event=event, title=title[:500], text=note or f"{label}: {issue.title or issue.vuln_id}",
                      severity=issue.severity, url=f"{get_base_url(db)}/issues/{issue.id}", fields=fields,
                      data={"issue_id": issue.id, "vuln_id": issue.vuln_id, "asset": issue.asset, "status": issue.status})


def _assignee_email(db: Session, issue_id: int | None) -> list[str]:
    issue = db.get(Issue, issue_id) if issue_id else None
    user = db.get(User, issue.assignee_id) if issue and issue.assignee_id else None
    return [user.email] if user and user.email and user.is_active else []


# ----------------------------------------------------------------- enqueue
def _matching_rules(db: Session, event: str, severity: str, scope_id: int | None) -> list[NotificationRule]:
    out = []
    for rule in db.scalars(select(NotificationRule).join(NotificationChannel)
                           .where(NotificationRule.enabled.is_(True), NotificationChannel.enabled.is_(True))):
        try:
            events = json.loads(rule.events or "[]")
        except json.JSONDecodeError:
            continue
        if event not in events:
            continue
        if SEVERITY_RANK.get(severity, 1) > SEVERITY_RANK.get(rule.min_severity, 4):
            continue
        if rule.scope_id is not None and rule.scope_id != scope_id:
            continue
        out.append(rule)
    return out


def enqueue(db: Session, channel_id: int, event: str, title: str, payload: dict, issue_id: int | None = None) -> Delivery:
    d = Delivery(channel_id=channel_id, event=event, title=title[:512], payload=json.dumps(payload), issue_id=issue_id,
                 status="pending", next_attempt_at=utcnow())
    db.add(d)
    return d


def notify(db: Session, event: str, *, issue: Issue | None = None, message: ch.Message | None = None,
           severity: str = "high", note: str = "") -> int:
    """Queue deliveries for every rule matching ``event``. Returns the number queued."""
    if issue is not None:
        message = issue_message(db, issue, event, note)
        severity, scope_id = issue.severity, issue.scope_id
    else:
        scope_id = None
    if message is None:
        return 0
    queued = 0
    for rule in _matching_rules(db, event, severity, scope_id):
        if rule.channel.kind in ch.TICKET_KINDS:
            if issue is None or event not in TICKET_EVENTS:
                continue
            enqueue(db, rule.channel_id, event, message.title, {"op": "ticket.ensure", "message": message.to_dict()}, issue.id)
        else:
            enqueue(db, rule.channel_id, event, message.title, {"op": "message", "message": message.to_dict()},
                    issue.id if issue else None)
        queued += 1
    db.flush()
    return queued


def on_status_change(db: Session, issue: Issue, old: str, new: str, kind: str, actor, sync_tickets: bool = True) -> None:
    """Called by issues._set_status: notify rules and keep linked tickets in step."""
    from .issues import STATUS_LABELS
    who = getattr(actor, "username", None) or "the scanner"
    change = f"{STATUS_LABELS.get(old, old)} → {STATUS_LABELS.get(new, new)}"
    event = "issue.reopened" if kind == "reopened" else "issue.status_changed"
    notify(db, event, issue=issue, note=f"{change} by {who}.")
    if not sync_tickets:
        return
    ops: list[tuple[str, str]] = []
    if kind == "reopened" or (old in ("verified", "false_positive", "accepted_risk") and new not in ("verified", "false_positive", "accepted_risk")):
        ops = [("ticket.reopen", f"Reopened in the scanner ({change}).")]
    elif new == "fixed":
        ops = [("ticket.comment", f"Marked fixed in the scanner by {who}. Awaiting verification by re-scan.")]
    elif new in ("verified", "false_positive", "accepted_risk"):
        ops = [("ticket.close", f"Closed in the scanner: {change} by {who}.")]
    for t in db.scalars(select(IssueTicket).where(IssueTicket.issue_id == issue.id)):
        for op, body in ops:
            enqueue(db, t.channel_id, "ticket.sync", f"{t.key}: {body}", {"op": op, "body": body}, issue.id)
    db.flush()


# ----------------------------------------------------------------- periodic checks
def check_overdue(db: Session) -> int:
    from .issues import OPEN_WORK
    n = 0
    for issue in db.scalars(select(Issue).where(Issue.status.in_(OPEN_WORK), Issue.due_at.is_not(None),
                                                Issue.due_at < utcnow(), Issue.overdue_notified_at.is_(None))):
        issue.overdue_notified_at = utcnow()
        notify(db, "issue.overdue", issue=issue, note=f"Past its SLA since {issue.due_at:%Y-%m-%d %H:%M} UTC.")
        n += 1
    db.flush()
    return n


def check_jobs(db: Session) -> int:
    """Notify failed / incomplete scans. A cursor makes this exactly-once; the first run skips history."""
    from .jobs import job_warnings
    cursor = _setting(db, JOB_CURSOR_KEY)
    if not cursor:
        _put(db, JOB_CURSOR_KEY, str(db.scalar(select(Job.id).order_by(Job.id.desc()).limit(1)) or 0))
        db.flush()
        return 0
    n, last = 0, int(cursor)
    for job in db.scalars(select(Job).where(Job.id > last).order_by(Job.id)):
        if job.status in ("queued", "running"):
            break  # keep the cursor contiguous: look at this job again next time
        last = job.id
        warnings = job_warnings(job) if job.status == "done" else []
        if job.status == "failed" or warnings:
            what = "failed" if job.status == "failed" else "finished with warnings"
            text = f"{job.kind} job #{job.id} {what}." + (f" {warnings[0]}" if warnings else "")
            msg = ch.Message(event="scan.problem", title=f"[SCAN] {job.kind} job #{job.id} {what}", text=text,
                             severity="high", url=f"{get_base_url(db)}/jobs/{job.id}",
                             fields=[("Job", f"#{job.id} ({job.kind})"), ("Status", job.status)], data={"job_id": job.id})
            notify(db, "scan.problem", message=msg)
            n += 1
    _put(db, JOB_CURSOR_KEY, str(last))
    db.flush()
    return n


def campaign_message(db: Session, c, event: str = "campaign.created", assets: int | None = None) -> ch.Message:
    """``campaign.created`` when a campaign starts; ``campaign.draft`` when the 0-day watch drafts one for review."""
    fields = [("CVE", c.cve_id or "—"), ("Severity", c.severity)]
    if c.cvss_score is not None:
        fields.append(("CVSS", str(c.cvss_score)))
    if c.kev:
        fields.append(("CISA KEV", f"known exploited, due {c.kev_due}" + (" · ransomware" if c.kev_ransomware else "")))
    if event == "campaign.draft":
        n = assets or 0
        fields.append(("Status", "draft: review the rules, then activate or dismiss"))
        title = f"[{c.severity.upper()}] 0-day watch: {c.cve_id or c.name} affects {n} asset{'s' if n != 1 else ''}"
    else:
        title = f"[{c.severity.upper()}] Campaign started: {c.name}"
    title += " (known exploited)" if c.kev else ""
    return ch.Message(event=event, title=title, text=(c.description or c.name)[:600], severity=c.severity,
                      url=f"{get_base_url(db)}/campaigns/{c.id}", fields=fields, data={"campaign_id": c.id, "cve": c.cve_id})


def schedule_message(db: Session, s, message: str) -> ch.Message:
    return ch.Message(event="schedule.error", title=f"[SCHEDULE] {s.name} failed", text=message, severity="high",
                      url=f"{get_base_url(db)}/schedules", fields=[("Schedule", s.name)], data={"schedule_id": s.id})


# ----------------------------------------------------------------- delivery
def _timeline(db: Session, issue_id: int, body: str) -> None:
    db.add(IssueEvent(issue_id=issue_id, kind="ticket", username="system", body=body))


def _execute(app, db: Session, d: Delivery) -> None:
    channel = d.channel
    config, secret = json.loads(channel.config or "{}"), app.state.secretbox.decrypt(channel.secret)
    payload = json.loads(d.payload or "{}")
    op, http = payload.get("op", "message"), app.state.http
    if op == "message":
        msg = ch.Message.from_dict(payload.get("message") or {})
        extra = _assignee_email(db, d.issue_id) if channel.kind == "email" and config.get("to_assignee") else []
        ch.send_message(channel.kind, http, app.state.smtp_send, get_smtp(db, app.state.secretbox), config, secret, msg, extra)
        return
    ticket = db.scalar(select(IssueTicket).where(IssueTicket.issue_id == d.issue_id, IssueTicket.channel_id == channel.id))
    label = KIND_LABEL.get(channel.kind, channel.kind)
    if op == "ticket.ensure":
        if ticket is None:
            t = ch.ticket_create(channel.kind, http, config, secret, ch.Message.from_dict(payload["message"]))
            db.add(IssueTicket(issue_id=d.issue_id, channel_id=channel.id, key=t.key, external_id=t.external_id, url=t.url,
                               state="open", last_synced_at=utcnow()))
            _timeline(db, d.issue_id, f"Ticket {t.key} created in {label}: {t.url}")
        elif ticket.state == "closed":
            ch.ticket_reopen(channel.kind, http, config, secret, ticket.key, ticket.external_id)
            ch.ticket_comment(channel.kind, http, config, secret, ticket.key, ticket.external_id, "Seen again by the scanner.")
            ticket.state = "open"
        return
    if ticket is None:
        return  # ticket was unlinked meanwhile; nothing to do
    body = payload.get("body", "")
    if op == "ticket.reopen":
        ch.ticket_reopen(channel.kind, http, config, secret, ticket.key, ticket.external_id)
        ticket.state = "open"
    ch.ticket_comment(channel.kind, http, config, secret, ticket.key, ticket.external_id, body)
    if op == "ticket.close" and ticket.state != "closed":
        ch.ticket_close(channel.kind, http, config, secret, ticket.key, ticket.external_id)
        ticket.state = "closed"
    ticket.last_synced_at = utcnow()


def _deliver_sync(app, delivery_id: int) -> bool:
    with app.state.SessionLocal() as db:
        d = db.get(Delivery, delivery_id)
        if d is None or d.status == "sent":
            return False
        d.attempts += 1
        try:
            _execute(app, db, d)
        except Exception as e:  # noqa: BLE001 - any failure is recorded and retried
            db.rollback()  # discards partial work and the uncommitted attempt increment above
            d = db.get(Delivery, delivery_id)
            d.attempts += 1
            d.last_error = str(e)[:1000] if isinstance(e, ch.DeliveryError) else f"{type(e).__name__}: {e}"[:1000]
            if d.attempts >= MAX_ATTEMPTS:
                d.status = "failed"
            else:
                d.next_attempt_at = utcnow() + timedelta(minutes=RETRY_MINUTES[d.attempts - 1])
            db.commit()
            return False
        d.status, d.sent_at, d.last_error = "sent", utcnow(), ""
        db.commit()
        return True


async def deliver(app, delivery_id: int) -> bool:
    return await asyncio.to_thread(_deliver_sync, app, delivery_id)


async def dispatch_due(app, limit: int = 25) -> int:
    with app.state.SessionLocal() as db:
        ids = list(db.scalars(select(Delivery.id).where(Delivery.status == "pending", Delivery.next_attempt_at <= utcnow())
                              .order_by(Delivery.id).limit(limit)))
    for did in ids:
        await deliver(app, did)
    return len(ids)


def _poll_sync(app) -> int:
    from .issues import OPEN_WORK, _set_status
    changed = 0
    with app.state.SessionLocal() as db:
        for t in list(db.scalars(select(IssueTicket).where(IssueTicket.state == "open"))):
            channel = t.channel
            if not channel.enabled or channel.kind not in ch.TICKET_KINDS:
                continue
            try:
                closed = ch.ticket_is_closed(channel.kind, app.state.http, json.loads(channel.config or "{}"),
                                             app.state.secretbox.decrypt(channel.secret), t.key, t.external_id)
            except ch.DeliveryError as e:
                log.warning("ticket poll %s failed: %s", t.key, e)
                continue
            t.last_synced_at = utcnow()
            if not closed:
                continue
            t.state = "closed"
            issue = db.get(Issue, t.issue_id)
            if issue is not None and issue.status in OPEN_WORK:
                _set_status(db, issue, "fixed", None, body=f"Ticket {t.key} closed in {KIND_LABEL[channel.kind]}.",
                            sync_tickets=False)
            changed += 1
        db.commit()
    return changed


async def poll_tickets(app) -> int:
    return await asyncio.to_thread(_poll_sync, app)


async def notifications_loop(app, interval: int = DISPATCH_SECONDS) -> None:
    last_poll = 0.0
    while True:
        await asyncio.sleep(interval)
        try:
            with app.state.SessionLocal() as db:
                check_overdue(db)
                check_jobs(db)
                db.commit()
            await dispatch_due(app)
            if time.monotonic() - last_poll >= POLL_TICKETS_SECONDS:
                last_poll = time.monotonic()
                await poll_tickets(app)
        except Exception:  # noqa: BLE001 - the loop must survive
            log.exception("notification loop iteration failed")
