"""Append-only audit trail of security-relevant actions."""
from __future__ import annotations

import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import AuditLog

PAGE_SIZE = 50

# Action prefixes offered as filters on the Audit page.
ACTION_GROUPS = {
    "auth": "Sign-in and passwords",
    "profile": "Profile",
    "user": "User management",
    "scan": "Scans started",
    "job": "Jobs",
    "inventory": "Inventory",
    "rule": "Version rules",
    "template": "Templates",
    "system": "System updates",
    "audit": "Audit exports",
}


def client_ip(request) -> str:
    return request.client.host if getattr(request, "client", None) else ""


def audit(db: Session, request, action: str, target: str = "", user=None, **details) -> AuditLog:
    """Record ``action`` by the request's user (or ``user``) and commit it."""
    actor = user if user is not None else getattr(getattr(request, "state", None), "user", None)
    row = AuditLog(
        user_id=getattr(actor, "id", None),
        username=details.pop("username", None) or getattr(actor, "username", "") or "",
        action=action,
        target=str(target)[:512],
        details=json.dumps(details, default=str, sort_keys=True),
        ip=client_ip(request),
    )
    db.add(row)
    db.commit()
    return row


def audit_query(username: str = "", action: str = "", since: datetime | None = None, until: datetime | None = None):
    stmt = select(AuditLog)
    if username:
        stmt = stmt.where(AuditLog.username == username)
    if action:
        stmt = stmt.where((AuditLog.action == action) | AuditLog.action.like(action.rstrip(".") + ".%"))
    if since:
        stmt = stmt.where(AuditLog.created_at >= since)
    if until:
        stmt = stmt.where(AuditLog.created_at < until)
    return stmt.order_by(AuditLog.id.desc())


def details_text(row: AuditLog) -> str:
    try:
        data = json.loads(row.details or "{}")
    except json.JSONDecodeError:
        return row.details or ""
    return ", ".join(f"{k}={v}" for k, v in data.items()) if isinstance(data, dict) else str(data)
