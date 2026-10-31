"""Report figures: open exposure, overdue, MTTR, SLA compliance, weekly trend, riskiest assets, scopes."""
from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Finding, Issue, Scope, utcnow
from .issues import OPEN_WORK, RESOLVED, is_overdue

SEVERITIES = ("critical", "high", "medium", "low")
RISK_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1}
DEFAULT_DAYS = 30
PERIODS = (7, 30, 90, 180, 365)


def executive(db: Session, days: int = DEFAULT_DAYS, now: datetime | None = None) -> dict:
    now = now or utcnow()
    since = now - timedelta(days=days)
    issues = list(db.scalars(select(Issue)))
    open_work = [i for i in issues if i.status in OPEN_WORK]
    new = [i for i in issues if since <= i.first_seen <= now]
    resolved = [i for i in issues if i.status in RESOLVED and i.resolved_at and since <= i.resolved_at <= now]
    remediated = [i for i in resolved if i.status in ("fixed", "verified")]   # false positives / accepted risk excluded
    mttr = (sum((i.resolved_at - i.first_seen).total_seconds() for i in remediated) / len(remediated) / 86400
            if remediated else None)
    with_due = [i for i in remediated if i.due_at]
    sla_pct = round(100 * sum(1 for i in with_due if i.resolved_at <= i.due_at) / len(with_due)) if with_due else None

    weeks = max(1, math.ceil(days / 7))
    trend = []
    for w in range(weeks):
        start = since + timedelta(days=7 * w)
        end = now if w == weeks - 1 else start + timedelta(days=7)
        trend.append({"start": start, "new": sum(1 for i in new if start <= i.first_seen < end or (w == weeks - 1 and i.first_seen == now)),
                      "resolved": sum(1 for i in resolved if start <= i.resolved_at < end or (w == weeks - 1 and i.resolved_at == now))})
    peak = max([1] + [max(t["new"], t["resolved"]) for t in trend])

    by_asset: dict[str, dict] = {}
    for i in open_work:
        a = by_asset.setdefault(i.asset, {"asset": i.asset, "hostname": i.hostname, "score": 0, "overdue": 0,
                                          **{s: 0 for s in SEVERITIES}})
        if i.severity in SEVERITIES:
            a[i.severity] += 1
            a["score"] += RISK_WEIGHT[i.severity]
        a["overdue"] += int(is_overdue(i, now))
    top_assets = sorted(by_asset.values(), key=lambda a: (-a["score"], a["asset"]))[:10]

    scope_names = {s.id: (s.name, s.criticality) for s in db.scalars(select(Scope))}
    per_scope: dict = defaultdict(lambda: {"open": 0, "overdue": 0, "critical": 0})
    for i in open_work:
        key = i.scope_id if i.scope_id in scope_names else None
        per_scope[key]["open"] += 1
        per_scope[key]["overdue"] += int(is_overdue(i, now))
        per_scope[key]["critical"] += int(i.severity == "critical")
    scopes = [{"id": sid, "name": scope_names[sid][0] if sid else "No scope",
               "criticality": scope_names[sid][1] if sid else "", **vals} for sid, vals in per_scope.items()]
    scopes.sort(key=lambda s: (s["id"] is None, -s["open"], s["name"]))

    return {
        "days": days, "since": since, "now": now,
        "open_by_severity": {s: sum(1 for i in open_work if i.severity == s) for s in SEVERITIES},
        "open_total": len(open_work), "overdue": sum(1 for i in open_work if is_overdue(i, now)),
        "awaiting_verification": sum(1 for i in issues if i.status == "fixed"),
        "new_in_period": len(new), "resolved_in_period": len(resolved),
        "mttr_days": mttr, "sla_pct": sla_pct, "trend": trend, "trend_peak": peak,
        "top_assets": top_assets, "scopes": scopes,
    }


EXPORT_FIELDS = ("id", "severity", "title", "vuln_id", "cve_id", "asset", "hostname", "confidence", "status",
                 "assignee", "scope", "first_seen", "last_seen", "due_at", "resolved_at", "occurrences", "url",
                 "risk_score", "risk_band", "epss", "epss_percentile", "kev")


def export_row(issue: Issue, base_url: str, risk=None) -> dict:
    """One issue for CSV/JSON/API. ``risk`` is its ``app.risk.RiskScore`` (computed here when omitted)."""
    if risk is None:
        from .risk import scores_for
        from sqlalchemy.orm import object_session
        risk = scores_for(object_session(issue), [issue])[issue.id]
    def ts(d):
        return d.strftime("%Y-%m-%dT%H:%M:%SZ") if d else ""
    return {"id": issue.id, "severity": issue.severity, "title": issue.title, "vuln_id": issue.vuln_id,
            "cve_id": issue.cve_id, "asset": issue.asset, "hostname": issue.hostname, "confidence": issue.confidence,
            "status": issue.status, "assignee": issue.assignee.username if issue.assignee else "",
            "scope": issue.scope.name if issue.scope else "", "first_seen": ts(issue.first_seen),
            "last_seen": ts(issue.last_seen), "due_at": ts(issue.due_at), "resolved_at": ts(issue.resolved_at),
            "occurrences": issue.occurrences, "url": f"{base_url}/issues/{issue.id}",
            "risk_score": risk.total, "risk_band": risk.band, "epss": risk.epss, "epss_percentile": risk.epss_percentile,
            "kev": risk.kev}


# ----------------------------------------------------------------- proof
EVIDENCE_LIMIT = 2000   # characters of request / response per issue in the campaign and scope appendix


def issue_finding(db: Session, issue: Issue) -> Finding | None:
    """The finding that verified the issue, else its newest one."""
    if issue.verified_finding_id:
        f = db.get(Finding, issue.verified_finding_id)
        if f is not None and f.issue_id == issue.id:
            return f
    return db.scalar(select(Finding).where(Finding.issue_id == issue.id).order_by(Finding.id.desc()).limit(1))


def _full(part: dict | None, limit: int | None) -> dict | None:
    if not part:
        return None
    text = part["text"] + part["rest"]
    shown = text if limit is None else text[:limit]
    return {"text": shown, "length": len(text), "truncated": len(shown) < len(text)}


def issue_proof(db: Session, issue: Issue, limit: int | None = None) -> dict | None:
    """proof_from_finding for the issue, with request / response joined back and cut at ``limit`` characters."""
    from .proof import proof_from_finding
    p = proof_from_finding(issue_finding(db, issue))
    if p is not None:
        p["request"], p["response"] = _full(p["request"], limit), _full(p["response"], limit)
    return p


def evidence(db: Session, issues: list[Issue]) -> list[tuple[Issue, dict | None]]:
    """Appendix rows: each verified issue with its (truncated) proof."""
    return [(i, issue_proof(db, i, EVIDENCE_LIMIT)) for i in issues if i.confidence == "verified"]
