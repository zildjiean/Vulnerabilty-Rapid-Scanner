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

from .db import AppSetting, Finding, Host, Issue, IssueEvent, Job, Rule, RuleMatch, Service, utcnow
from .render import SEVERITY_ORDER, normalize_severity

STATUSES = ("new", "triaged", "in_progress", "fixed", "verified", "false_positive", "accepted_risk")
STATUS_LABELS = {"new": "New", "triaged": "Triaged", "in_progress": "In progress", "fixed": "Fixed",
                 "verified": "Fix verified", "false_positive": "False positive", "accepted_risk": "Accepted risk"}
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
CONFIDENCE_LABELS = {"suspected": "Suspected", "confirmed": "Confirmed", "verified": "Verified"}
SCAN_CONFIRMED = ("confirmed", "verified")   # seen by a scan; verified = Verify now reproduced it with proof
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


def _set_status(db: Session, issue: Issue, new: str, actor, kind: str = "status", body: str = "",
                sync_tickets: bool = True) -> None:
    old = issue.status
    issue.status = new
    issue.status_changed_at = utcnow()
    if new in RESOLVED:
        issue.resolved_at = issue.resolved_at or issue.status_changed_at
    else:
        issue.resolved_at = None
    # confirmed fixes are re-scanned automatically (app/reverify.py); any other move cancels a pending request
    if new == "fixed" and issue.confidence in SCAN_CONFIRMED and issue.template_id:
        issue.reverify_requested_at, issue.reverify_job_id = issue.status_changed_at, None
    else:
        issue.reverify_requested_at = None
    _event(db, issue, kind, actor, old, new, body)
    from .notifications import on_status_change
    on_status_change(db, issue, old, new, kind, actor, sync_tickets)


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
        _apply_scope(db, issue)
        from .notifications import notify
        notify(db, "issue.created", issue=issue, note=f"New {confidence} issue from {source}.")
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
    if confidence == "confirmed" and issue.confidence == "suspected":   # never downgrades verified
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


def _apply_scope(db: Session, issue: Issue) -> None:
    """Place a new issue in its scope and hand it to the scope owner when that owner can triage."""
    from .db import User
    from .scopes import scope_for_asset
    scope = scope_for_asset(db, issue.address, issue.hostname)
    if scope is None:
        return
    issue.scope_id = scope.id
    owner = db.get(User, scope.owner_id) if scope.owner_id else None
    if owner is not None and owner.is_active and owner.role in ("admin", "analyst"):
        issue.assignee_id = owner.id
        _event(db, issue, "assigned", None, "", owner.username, body=f"Auto-assigned to the owner of scope {scope.name}")


def finding_raw(f: Finding) -> dict:
    """The finding's nuclei JSON, with the stored columns filled in where the JSON lacks them."""
    try:
        raw = json.loads(f.raw_json or "{}")
    except json.JSONDecodeError:
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    raw.setdefault("template-id", f.template_id)
    raw.setdefault("host", f.host)
    raw.setdefault("matched-at", f.matched_at)
    return raw


def finding_on_issue_asset(f: Finding, issue: Issue) -> bool:
    """Did this finding hit the issue's asset? Same address (or hostname) and, when the issue has one, the same port."""
    address, port, hostname = asset_from_raw(finding_raw(f))
    names = {issue.address, issue.hostname} - {""}
    if address not in names and (not hostname or hostname not in names):
        return False
    return not issue.port or port == issue.port


def issues_from_findings(db: Session, findings: list[Finding], job=None) -> int:
    """Create or update issues for nuclei findings (info / unknown are skipped). Returns issues created."""
    created = 0
    for f in sorted(findings, key=lambda x: (x.created_at or utcnow(), x.id or 0)):
        severity = normalize_severity(f.severity)
        if severity not in ISSUE_SEVERITIES:
            continue
        raw = finding_raw(f)
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
    # suspected fixes are verified once a scan *after* the fix still shows a non-matching version
    seen = {asset_key(h.address, str(s.port)): h.last_seen
            for s, h in db.execute(select(Service, Host).join(Host, Host.id == Service.host_id))}
    for issue in db.scalars(select(Issue).where(Issue.rule_id.is_not(None), Issue.confidence == "suspected",
                                                Issue.status == "fixed")):
        last = seen.get(issue.asset)
        if issue.id in matched or issue.rule_id not in enabled or last is None or last <= issue.status_changed_at:
            continue
        _set_status(db, issue, "verified", None,
                    body=f"nmap re-scan on {last:%Y-%m-%d %H:%M} UTC shows a version the rule no longer matches.")
    db.flush()
    return created


def backfill_issues(db: Session) -> int:
    """Create issues for findings and rule matches recorded before issues existed. Idempotent."""
    pending = list(db.scalars(select(Finding).where(Finding.issue_id.is_(None),
                                                     Finding.severity.in_(ISSUE_SEVERITIES))))
    created = issues_from_findings(db, pending) + sync_rule_issues(db)
    backfill_verified(db)
    db.commit()
    return created


def backfill_verified(db: Session) -> int:
    """Issues reproduced by Verify now before the verified confidence existed become verified. Idempotent."""
    todo = list(db.scalars(select(Issue).where(Issue.verify_result == "reproduced", Issue.confidence == "confirmed")))
    if not todo:
        return 0
    last_job: dict[int, int] = {}
    for jid, params in db.execute(select(Job.id, Job.params_json).where(Job.params_json.like('%"verify_issue"%'))
                                  .order_by(Job.id)):
        try:
            iid = json.loads(params or "{}").get("verify_issue")
        except (json.JSONDecodeError, AttributeError):
            continue
        if isinstance(iid, int):
            last_job[iid] = jid
    for issue in todo:
        newest = select(Finding.id).where(Finding.issue_id == issue.id).order_by(Finding.id.desc()).limit(1)
        fid = db.scalar(newest.where(Finding.job_id == last_job[issue.id])) if issue.id in last_job else None
        issue.verified_finding_id = fid or db.scalar(newest)
        issue.confidence = "verified"
    db.flush()
    return len(todo)


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
    if user is not None:
        from .notifications import notify
        notify(db, "issue.assigned", issue=issue, note=f"Assigned to {user.display_name or user.username}.")
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
