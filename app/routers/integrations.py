"""Integrations (admin): notification channels, rules, delivery log; ticket creation from issues."""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import channels as ch
from .. import notifications as nt
from ..audit import audit
from ..authz import require
from ..db import Delivery, Issue, IssueTicket, NotificationChannel, NotificationRule, Scope, utcnow
from ..deps import get_db, verify_csrf
from ..render import render

router = APIRouter()
VIEW = [Depends(require("integrations.manage"))]
MANAGE = [Depends(require("integrations.manage")), Depends(verify_csrf)]
RULE_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _split_fields(kind: str, form) -> tuple[dict, dict]:
    """Read ``<kind>__<field>`` inputs into (config, secret) according to channels.FIELDS."""
    config, secret = {}, {}
    for name, _label, is_secret in ch.FIELDS.get(kind, []):
        value = str(form.get(f"{kind}__{name}", "") or "").strip()
        (secret if is_secret else config)[name] = value
    if kind == "email":
        config["to_assignee"] = "1" if config.get("to_assignee") else ""
    return config, secret


def _common(db: Session) -> dict:
    return dict(kinds=ch.KINDS, fields=ch.FIELDS, events=nt.EVENTS, ticket_events=nt.TICKET_EVENTS,
                ticket_kinds=ch.TICKET_KINDS, rule_severities=RULE_SEVERITIES,
                scopes=list(db.scalars(select(Scope).order_by(Scope.name))))


def _list(request: Request, db: Session, status_code: int = 200, error: str | None = None, form: dict | None = None):
    channels = list(db.scalars(select(NotificationChannel).order_by(NotificationChannel.name)))
    counts = {(cid, st): n for cid, st, n in db.execute(
        select(Delivery.channel_id, Delivery.status, func.count()).group_by(Delivery.channel_id, Delivery.status))}
    return render(request, "integrations.html", status_code=status_code, active="integrations", error=error,
                  channels=channels, counts=counts, form=form or {}, **_common(db))


def _get(db: Session, cid: int) -> NotificationChannel:
    c = db.get(NotificationChannel, cid)
    if c is None:
        raise HTTPException(404)
    return c


def _detail(request: Request, db: Session, c: NotificationChannel, status_code: int = 200, error: str | None = None):
    deliveries = list(db.scalars(select(Delivery).where(Delivery.channel_id == c.id).order_by(Delivery.id.desc()).limit(25)))
    stored = request.app.state.secretbox.decrypt(c.secret)
    return render(request, "integration_channel.html", status_code=status_code, active="integrations", error=error, c=c,
                  config=json.loads(c.config or "{}"), stored={k: bool(v) for k, v in stored.items()},
                  deliveries=deliveries, **_common(db))


@router.get("/integrations", dependencies=VIEW)
def integrations_page(request: Request, db: Session = Depends(get_db)):
    return _list(request, db)


@router.post("/integrations/channels", dependencies=MANAGE)
async def channel_create(request: Request, db: Session = Depends(get_db)):
    form = await request.form()
    kind, name = str(form.get("kind", "")), str(form.get("name", "")).strip()
    config, secret = _split_fields(kind, form)
    err = "Give the channel a name." if not name else ch.validate_channel(kind, config, secret)
    if not err and kind in ("slack", "teams") and not secret.get("webhook_url"):
        err = "Paste the webhook URL."
    if err:
        return _list(request, db, 400, err, {"kind": kind, "name": name})
    c = NotificationChannel(name=name[:128], kind=kind, config=json.dumps(config),
                            secret=request.app.state.secretbox.encrypt(secret), enabled=True)
    db.add(c)
    db.commit()
    audit(db, request, "integration.channel_created", target=c.name, channel_id=c.id, kind=kind)
    return RedirectResponse(f"/integrations/channels/{c.id}?msg=Channel+created.+Add+a+rule+and+send+a+test.", status_code=303)


@router.get("/integrations/channels/{cid}", dependencies=VIEW)
def channel_detail(request: Request, cid: int, db: Session = Depends(get_db)):
    return _detail(request, db, _get(db, cid))


@router.post("/integrations/channels/{cid}", dependencies=MANAGE)
async def channel_update(request: Request, cid: int, db: Session = Depends(get_db)):
    c = _get(db, cid)
    form = await request.form()
    name = str(form.get("name", "")).strip()
    config, secret_updates = _split_fields(c.kind, form)
    merged = request.app.state.secretbox.decrypt(request.app.state.secretbox.merge(c.secret, secret_updates))
    err = "Give the channel a name." if not name else ch.validate_channel(c.kind, config, merged)
    if err:
        return _detail(request, db, c, 400, err)
    c.name, c.config = name[:128], json.dumps(config)
    c.secret = request.app.state.secretbox.merge(c.secret, secret_updates)
    db.commit()
    audit(db, request, "integration.channel_updated", target=c.name, channel_id=c.id,
          secrets_changed=sorted(k for k, v in secret_updates.items() if v))
    return RedirectResponse(f"/integrations/channels/{cid}?msg=Channel+saved", status_code=303)


@router.post("/integrations/channels/{cid}/toggle", dependencies=MANAGE)
def channel_toggle(request: Request, cid: int, db: Session = Depends(get_db)):
    c = _get(db, cid)
    c.enabled = not c.enabled
    db.commit()
    audit(db, request, "integration.channel_toggled", target=c.name, channel_id=c.id, enabled=c.enabled)
    return RedirectResponse(f"/integrations/channels/{cid}?msg=Channel+{'enabled' if c.enabled else 'paused'}", status_code=303)


@router.post("/integrations/channels/{cid}/delete", dependencies=MANAGE)
def channel_delete(request: Request, cid: int, db: Session = Depends(get_db)):
    c = _get(db, cid)
    name = c.name
    for t in db.scalars(select(IssueTicket).where(IssueTicket.channel_id == cid)):
        db.delete(t)
    db.delete(c)
    db.commit()
    audit(db, request, "integration.channel_deleted", target=name, channel_id=cid)
    return RedirectResponse("/integrations?msg=Channel+deleted", status_code=303)


@router.post("/integrations/channels/{cid}/test", dependencies=MANAGE)
async def channel_test(request: Request, cid: int, db: Session = Depends(get_db)):
    c = _get(db, cid)
    app = request.app
    smtp, base = nt.get_smtp(db, app.state.secretbox), nt.get_base_url(db)
    config, secret = json.loads(c.config or "{}"), app.state.secretbox.decrypt(c.secret)
    try:
        message = await asyncio.to_thread(ch.test_channel, c.kind, app.state.http, app.state.smtp_send, smtp, config,
                                          secret, base)
        ok = True
    except ch.DeliveryError as e:
        ok, message = False, str(e)
    c.last_test_at, c.last_test_ok, c.last_test_message = utcnow(), ok, message[:1000]
    db.commit()
    audit(db, request, "integration.channel_tested", target=c.name, channel_id=c.id, ok=ok)
    return RedirectResponse(f"/integrations/channels/{cid}?msg=" + ("Test+succeeded" if ok else "Test+failed"), status_code=303)


@router.post("/integrations/channels/{cid}/rules", dependencies=MANAGE)
def rule_create(request: Request, cid: int, events: list[str] = Form(default=[]), min_severity: str = Form("high"),
                scope_id: str = Form(""), db: Session = Depends(get_db)):
    c = _get(db, cid)
    allowed = nt.TICKET_EVENTS if c.kind in ch.TICKET_KINDS else tuple(nt.EVENTS)
    chosen = [e for e in events if e in nt.EVENTS]
    err = None
    if not chosen:
        err = "Pick at least one event."
    elif any(e not in allowed for e in chosen):
        err = "Jira and GitLab channels open tickets: choose 'New issue' and / or 'Issue reopened'."
    elif min_severity not in RULE_SEVERITIES:
        err = "Unknown severity."
    scope = db.get(Scope, int(scope_id)) if scope_id.isdigit() else None
    if err:
        return _detail(request, db, c, 400, err)
    rule = NotificationRule(channel_id=c.id, events=json.dumps(chosen), min_severity=min_severity,
                            scope_id=scope.id if scope else None, enabled=True)
    db.add(rule)
    db.commit()
    audit(db, request, "integration.rule_created", target=c.name, channel_id=c.id, rule_id=rule.id, events=",".join(chosen),
          min_severity=min_severity, scope=scope.name if scope else "")
    return RedirectResponse(f"/integrations/channels/{cid}?msg=Rule+added", status_code=303)


def _rule(db: Session, rid: int) -> NotificationRule:
    r = db.get(NotificationRule, rid)
    if r is None:
        raise HTTPException(404)
    return r


@router.post("/integrations/rules/{rid}/toggle", dependencies=MANAGE)
def rule_toggle(request: Request, rid: int, db: Session = Depends(get_db)):
    r = _rule(db, rid)
    r.enabled = not r.enabled
    db.commit()
    audit(db, request, "integration.rule_toggled", target=r.channel.name, rule_id=r.id, enabled=r.enabled)
    return RedirectResponse(f"/integrations/channels/{r.channel_id}", status_code=303)


@router.post("/integrations/rules/{rid}/delete", dependencies=MANAGE)
def rule_delete(request: Request, rid: int, db: Session = Depends(get_db)):
    r = _rule(db, rid)
    cid, name = r.channel_id, r.channel.name
    db.delete(r)
    db.commit()
    audit(db, request, "integration.rule_deleted", target=name, rule_id=rid)
    return RedirectResponse(f"/integrations/channels/{cid}?msg=Rule+deleted", status_code=303)


@router.get("/integrations/deliveries", dependencies=VIEW)
def deliveries_page(request: Request, status: str = "", db: Session = Depends(get_db)):
    stmt = select(Delivery).order_by(Delivery.id.desc()).limit(200)
    if status in ("pending", "sent", "failed"):
        stmt = stmt.where(Delivery.status == status)
    return render(request, "deliveries.html", active="integrations", rows=list(db.scalars(stmt)), status=status)


@router.post("/integrations/deliveries/{did}/retry", dependencies=MANAGE)
async def delivery_retry(request: Request, did: int, db: Session = Depends(get_db)):
    d = db.get(Delivery, did)
    if d is None:
        raise HTTPException(404)
    d.status, d.attempts, d.next_attempt_at, d.last_error = "pending", 0, utcnow(), ""
    db.commit()
    ok = await nt.deliver(request.app, did)
    audit(db, request, "integration.delivery_retried", target=d.title[:200], delivery_id=did, ok=ok)
    return RedirectResponse("/integrations/deliveries?msg=" + ("Delivered" if ok else "Still+failing"), status_code=303)


# ----------------------------------------------------------------- tickets from the issue page
@router.post("/issues/{iid}/tickets", dependencies=[Depends(require("issues.manage")), Depends(verify_csrf)])
async def issue_ticket_create(request: Request, iid: int, channel_id: str = Form(""), db: Session = Depends(get_db)):
    issue = db.get(Issue, iid)
    c = db.get(NotificationChannel, int(channel_id)) if channel_id.isdigit() else None
    if issue is None or c is None or c.kind not in ch.TICKET_KINDS or not c.enabled:
        raise HTTPException(404)
    msg = nt.issue_message(db, issue, "issue.created", note=f"Opened from the scanner by {request.state.user.username}.")
    d = nt.enqueue(db, c.id, "issue.created", msg.title, {"op": "ticket.ensure", "message": msg.to_dict()}, issue.id)
    db.commit()
    ok = await nt.deliver(request.app, d.id)
    db.expire_all()
    ticket = db.scalar(select(IssueTicket).where(IssueTicket.issue_id == iid, IssueTicket.channel_id == c.id))
    audit(db, request, "issue.ticket_created", target=f"#{iid} {issue.vuln_id} on {issue.asset}", channel=c.name,
          ok=ok, ticket=ticket.key if ticket else "")
    note = f"Ticket+{ticket.key}+linked" if ok and ticket else "Ticket+not+created:+see+Integrations+%E2%86%92+Delivery+log"
    return RedirectResponse(f"/issues/{iid}?msg={note}", status_code=303)
