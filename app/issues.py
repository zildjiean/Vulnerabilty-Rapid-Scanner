"""Issue lifecycle: identity, deduplication, rule sync, status transitions, SLA.

Functions flush but never commit; callers own the transaction.
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import AppSetting, Finding, Host, Issue, IssueEvent, Rule, RuleMatch, Service, utcnow
from .render import SEVERITY_ORDER, normalize_severity

STATUSES = ("new", "triaged", "in_progress", "fixed", "verified", "false_positive", "accepted_risk")
STATUS_LABELS = {"new": "New", "triaged": "Triaged", "in_progress": "In progress", "fixed": "Fixed",
                 "verified": "Verified", "false_positive": "False positive", "accepted_risk": "Accepted risk"}
ACTIVE = ("new", "triaged", "in_progress", "fixed")       # fixed = awaiting verification
OPEN_WORK = ("new", "triaged", "in_progress")              # still needs remediation; the SLA clock runs
CLOSED = ("verified", "false_positive", "accepted_risk")
RESOLVED = ("fixed", "verified", "false_positive", "accepted_risk")
NEEDS_REASON = ("false_positive", "accepted_risk")
TRANSITIONS = {
    "new": ["triaged", "in_progress", "fixed", "false_positive", "accepted_risk"],
    "triaged": ["in_progress", "fixed", "false_positive", "accepted_risk"],
    "in_progress": ["fixed", "triaged", "false_positive", "accepted_risk"],
    "fixed": ["verified", "in_progress"],
    "verified": ["triaged"],
    "false_positive": ["triaged"],
    "accepted_risk": ["triaged"],
}
CONFIDENCE_LABELS = {"suspected": "Suspected", "confirmed": "Confirmed"}
ISSUE_SEVERITIES = ("critical", "high", "medium", "low")   # info / unknown never become issues
DEFAULT_SLA = {"critical": 3, "high": 7, "medium": 30, "low": 90}
SLA_KEY = "sla_days"
_DEFAULT_PORTS = {"https": "443", "http": "80"}


# ----------------------------------------------------------------- identity
def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _split_hostport(value: str) -> tuple[str, str]:
    if value.count(":") == 1:
        h, p = value.rsplit(":", 1)
        if p.isdigit():
            return h, p
    return value, ""


def _from_location(value: str) -> tuple[str, str]:
    if "://" in value:
        u = urlsplit(value)
        try:
            port = str(u.port) if u.port else _DEFAULT_PORTS.get(u.scheme, "")
        except ValueError:
            port = ""
        return u.hostname or "", port
    return _split_hostport(value) if value else ("", "")


def asset_from_raw(raw: dict) -> tuple[str, str, str]:
    """(address, port, hostname) of a nuclei result. Address prefers the resolved IP."""
    host = str(raw.get("host") or "").strip()
    matched = str(raw.get("matched-at") or "").strip()
    name, port = _from_location(host or matched)
    if not port and matched:
        port = _from_location(matched)[1]
    port = str(raw.get("port") or "").strip() or port
    address = str(raw.get("ip") or "").strip() or name
    hostname = "" if _is_ip(name) else name
    return address, port, hostname


def vuln_from_raw(raw: dict) -> tuple[str, str]:
    """(vuln_id, cve_id): the CVE when nuclei classifies one, else the template id."""
    cls = (raw.get("info") or {}).get("classification") or {}
    cve = cls.get("cve-id")
    if isinstance(cve, list):
        cve = next((c for c in cve if c), "")
    cve = str(cve or "").strip().upper()
    return (cve or str(raw.get("template-id") or "")), cve


def asset_key(address: str, port: str) -> str:
    return f"{address}:{port}" if port else address


# ----------------------------------------------------------------- SLA
def get_sla(db: Session) -> dict[str, int]:
    row = db.get(AppSetting, SLA_KEY)
    sla = dict(DEFAULT_SLA)
    if row and row.value:
        try:
            sla.update({k: int(v) for k, v in json.loads(row.value).items() if k in DEFAULT_SLA})
        except (ValueError, TypeError, AttributeError):
            pass
    return sla


def compute_due(first_seen: datetime, severity: str, sla: dict[str, int]) -> datetime | None:
    days = sla.get(severity)
    return first_seen + timedelta(days=days) if days else None


def set_sla(db: Session, values: dict) -> dict[str, int]:
    sla = {}
    for sev in DEFAULT_SLA:
        try:
            days = int(values.get(sev))
        except (TypeError, ValueError):
            raise ValueError(f"{sev.capitalize()} SLA must be a whole number of days.")
        if not 1 <= days <= 3650:
            raise ValueError(f"{sev.capitalize()} SLA must be between 1 and 3650 days.")
        sla[sev] = days
    row = db.get(AppSetting, SLA_KEY) or AppSetting(key=SLA_KEY)
    row.value = json.dumps(sla)
    db.add(row)
    for issue in db.scalars(select(Issue)):
        issue.due_at = compute_due(issue.first_seen, issue.severity, sla)
    db.flush()
    return sla


def is_active(issue: Issue) -> bool:
    return issue.status in ACTIVE


def is_overdue(issue: Issue, now: datetime | None = None) -> bool:
    return issue.status in OPEN_WORK and issue.due_at is not None and issue.due_at < (now or utcnow())


# ----------------------------------------------------------------- events
def _event(db: Session, issue: Issue, kind: str, actor=None, from_value="", to_value="", body="",
           at: datetime | None = None) -> IssueEvent:
    ev = IssueEvent(issue_id=issue.id, kind=kind, created_at=at or utcnow(), user_id=getattr(actor, "id", None),
                    username=getattr(actor, "username", None) or "system",
                    from_value=str(from_value or "")[:255], to_value=str(to_value or "")[:255], body=body or "")
    db.add(ev)
    return ev


def _set_status(db: Session, issue: Issue, new: str, actor, kind: str = "status", body: str = "") -> None:
    old = issue.status
    issue.status = new
    issue.status_changed_at = utcnow()
    if new in RESOLVED:
        issue.resolved_at = issue.resolved_at or issue.status_changed_at
    else:
        issue.resolved_at = None
    _event(db, issue, kind, actor, old, new, body)


# ----------------------------------------------------------------- upsert
def upsert_issue(db: Session, *, address: str, port: str, hostname: str, vuln_id: str, cve_id: str, template_id: str,
                 rule_id: int | None, title: str, severity: str, confidence: str, seen_at: datetime, source: str,
                 count_sighting: bool, reopen: bool) -> tuple[Issue, bool]:
    asset = asset_key(address, port)
    key = f"{asset}|{vuln_id}"[:600]
    issue = db.scalar(select(Issue).where(Issue.key == key))
    sla = get_sla(db)
    if issue is None:
        issue = Issue(key=key, asset=asset, address=address, port=port, hostname=hostname, vuln_id=vuln_id,
                      cve_id=cve_id, template_id=template_id, rule_id=rule_id, title=title[:512], severity=severity,
                      confidence=confidence, status="new", first_seen=seen_at, last_seen=seen_at,
                      status_changed_at=utcnow(), occurrences=1, due_at=compute_due(seen_at, severity, sla))
        db.add(issue)
        db.flush()
        _event(db, issue, "created", body=source, at=seen_at)
        return issue, True

    if seen_at < issue.first_seen:
        issue.first_seen = seen_at
        issue.due_at = compute_due(issue.first_seen, issue.severity, sla)
    issue.last_seen = max(issue.last_seen, seen_at)
    issue.hostname = issue.hostname or hostname
    issue.cve_id = issue.cve_id or cve_id
    issue.template_id = issue.template_id or template_id
    issue.rule_id = issue.rule_id or rule_id
    if count_sighting:
        issue.occurrences += 1
        _event(db, issue, "seen", body=source, at=seen_at)
    if confidence == "confirmed" and issue.confidence != "confirmed":
        issue.confidence = "confirmed"
        issue.title = title[:512] or issue.title
        _event(db, issue, "confirmed", from_value="suspected", to_value="confirmed", body=source)
    if not issue.severity_overridden and SEVERITY_ORDER.get(severity, 99) < SEVERITY_ORDER.get(issue.severity, 99):
        _event(db, issue, "severity", from_value=issue.severity, to_value=severity, body=source)
        issue.severity = severity
        issue.due_at = compute_due(issue.first_seen, severity, sla)
    if reopen and issue.status in ("fixed", "verified"):
        _set_status(db, issue, "triaged", None, kind="reopened", body=f"Seen again: {source}")
    return issue, False


def issues_from_findings(db: Session, findings: list[Finding], job=None) -> int:
    """Create or update issues for nuclei findings (info / unknown are skipped). Returns issues created."""
    created = 0
    for f in sorted(findings, key=lambda x: (x.created_at or utcnow(), x.id or 0)):
        severity = normalize_severity(f.severity)
        if severity not in ISSUE_SEVERITIES:
            continue
        try:
            raw = json.loads(f.raw_json or "{}")
        except json.JSONDecodeError:
            raw = {}
        raw.setdefault("template-id", f.template_id)
        raw.setdefault("host", f.host)
        raw.setdefault("matched-at", f.matched_at)
        address, port, hostname = asset_from_raw(raw)
        if not address:
            continue
        vuln_id, cve_id = vuln_from_raw(raw)
        seen = f.created_at or utcnow()
        issue, new = upsert_issue(
            db, address=address, port=port, hostname=hostname, vuln_id=vuln_id or f.template_id, cve_id=cve_id,
            template_id=f.template_id, rule_id=None, title=f.template_name or f.template_id, severity=severity,
            confidence="confirmed", seen_at=seen, source=f"nuclei template {f.template_id} in job #{f.job_id}",
            count_sighting=True, reopen=seen >= _status_time(db, address, port, vuln_id))
        f.issue_id = issue.id
        created += int(new)
    db.flush()
    return created


def _status_time(db: Session, address: str, port: str, vuln_id: str) -> datetime:
    issue = db.scalar(select(Issue).where(Issue.key == f"{asset_key(address, port)}|{vuln_id}"))
    return issue.status_changed_at if issue else datetime.min


def sync_rule_issues(db: Session) -> int:
    """Mirror current rule matches into suspected issues and auto-fix ones that no longer match."""
    rows = db.execute(select(RuleMatch, Rule, Service, Host).join(Rule, Rule.id == RuleMatch.rule_id)
                      .join(Service, Service.id == RuleMatch.service_id).join(Host, Host.id == Service.host_id)).all()
    created, matched = 0, set()
    for _m, rule, svc, host in rows:
        severity = normalize_severity(rule.severity)
        if severity not in ISSUE_SEVERITIES:
            severity = "high"
        cve = (rule.cve_id or "").strip().upper()
        vuln_id = cve or f"rule-{rule.id}"
        port = str(svc.port)
        seen = host.last_seen or utcnow()
        product = " ".join(x for x in (svc.product, svc.version) if x)
        issue, new = upsert_issue(
            db, address=host.address, port=port, hostname=host.hostname or "", vuln_id=vuln_id, cve_id=cve,
            template_id="", rule_id=rule.id, title=f"{rule.name} ({product})" if product else rule.name,
            severity=severity, confidence="suspected", seen_at=seen,
            source=f"version rule '{rule.name}' matched {product or svc.service_name}",
            count_sighting=False, reopen=seen >= _status_time(db, host.address, port, vuln_id))
        matched.add(issue.id)
        created += int(new)

    enabled = set(db.scalars(select(Rule.id).where(Rule.enabled.is_(True))))
    inventory = {asset_key(h.address, str(s.port)) for s, h in db.execute(select(Service, Host).join(Host, Host.id == Service.host_id))}
    stale = db.scalars(select(Issue).where(Issue.rule_id.is_not(None), Issue.confidence == "suspected",
                                           Issue.status.in_(OPEN_WORK)))
    for issue in stale:
        if issue.id in matched or issue.rule_id not in enabled or issue.asset not in inventory:
            continue
        _set_status(db, issue, "fixed", None, kind="auto_fixed",
                    body="The service no longer matches the version rule (re-scan shows a different version).")
    db.flush()
    return created


def backfill_issues(db: Session) -> int:
    """Create issues for findings and rule matches recorded before issues existed. Idempotent."""
    pending = list(db.scalars(select(Finding).where(Finding.issue_id.is_(None),
                                                     Finding.severity.in_(ISSUE_SEVERITIES))))
    created = issues_from_findings(db, pending) + sync_rule_issues(db)
    db.commit()
    return created


# ----------------------------------------------------------------- user actions
def allowed_transitions(status: str) -> list[str]:
    return list(TRANSITIONS.get(status, []))


def change_status(db: Session, issue: Issue, new: str, actor, comment: str = "") -> None:
    if new not in STATUSES:
        raise ValueError("Unknown status.")
    if new not in TRANSITIONS.get(issue.status, []):
        raise ValueError(f"Cannot move an issue from {STATUS_LABELS[issue.status]} to {STATUS_LABELS[new]}.")
    comment = (comment or "").strip()
    if new in NEEDS_REASON and not comment:
        raise ValueError(f"{STATUS_LABELS[new]} needs a reason in the comment.")
    _set_status(db, issue, new, actor)
    if comment:
        _event(db, issue, "comment", actor, body=comment)
    db.flush()


def assign(db: Session, issue: Issue, user, actor) -> None:
    old = issue.assignee.username if issue.assignee else ""
    issue.assignee_id = user.id if user else None
    issue.assignee = user
    _event(db, issue, "assigned", actor, old, user.username if user else "")
    db.flush()


def set_severity(db: Session, issue: Issue, severity: str, actor) -> None:
    if severity not in ISSUE_SEVERITIES:
        raise ValueError("Unknown severity.")
    old = issue.severity
    issue.severity = severity
    issue.severity_overridden = True
    issue.due_at = compute_due(issue.first_seen, severity, get_sla(db))
    _event(db, issue, "severity", actor, old, severity)
    db.flush()


def add_comment(db: Session, issue: Issue, body: str, actor) -> None:
    body = (body or "").strip()
    if not body:
        raise ValueError("Comment is empty.")
    _event(db, issue, "comment", actor, body=body[:5000])
    db.flush()
