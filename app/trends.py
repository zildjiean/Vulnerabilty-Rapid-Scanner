"""Trend series for the dashboard and the executive report, rebuilt from issue and surface-change history.

Known limitation: an issue is counted by its current state, so a reopened issue (resolved_at cleared) looks open
for its whole life.
"""
from __future__ import annotations

import math
from datetime import datetime, timedelta
from types import SimpleNamespace

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Issue, SurfaceChange, utcnow
from .issues import ISSUE_SEVERITIES, OPEN_WORK
from .reports import REMEDIATED, is_resolved, mttr_days, sla_percent

PERIODS = (30, 90, 180, 365)
PERIOD_LABELS = {30: "30 days", 90: "90 days", 180: "6 months", 365: "12 months"}
DEFAULT_DAYS = 90
SURFACE_ADDED = ("host_new", "port_opened")   # everything else (port_closed, service_changed, host_gone) is "other"


def parse_days(value) -> int:
    """An allowed period from a query string or int; anything else is the default."""
    try:
        d = int(value)
    except (TypeError, ValueError):
        return DEFAULT_DAYS
    return d if d in PERIODS else DEFAULT_DAYS


def nearest_days(days: int) -> int:
    """The allowed period closest to a report's own period (ties go to the shorter one)."""
    return min(PERIODS, key=lambda p: (abs(p - days), p))


def _label(d: datetime) -> str:
    return f"{d:%b} {d.day}"


def buckets(days: int, now: datetime) -> list[dict]:
    """Contiguous buckets ending at ``now``: daily for 30 days, else ceil(days / 7) weeks."""
    step, n = (timedelta(days=1), 30) if days == 30 else (timedelta(days=7), math.ceil(days / 7))
    out = []
    for k in range(n):
        end = now - step * (n - 1 - k)
        start = end - step
        rng = _label(end) if step.days == 1 else f"{_label(start)}–{_label(end)}"
        if end.year != now.year:
            rng += f", {end.year}"          # 12-month charts reach into last year
        out.append({"start": start, "end": end, "label": _label(end), "range": rng})
    return out


def _open_at(i, t: datetime) -> bool:
    """Exposed at ``t``: seen by then and not yet resolved. False positives were never exposure, and a resolved
    issue without a resolution time is left out because its open period is unknown."""
    if i.status == "false_positive" or i.first_seen is None or i.first_seen > t:
        return False
    if is_resolved(i):
        return i.resolved_at > t
    return i.status in OPEN_WORK


def _in(d: datetime | None, b: dict, last: bool) -> bool:
    """[start, end), with the last bucket closed so events stamped exactly ``now`` are counted (as the report does)."""
    return d is not None and (b["start"] <= d < b["end"] or (last and d == b["end"]))


def trends(db: Session, days=DEFAULT_DAYS, scope_id: int | None = None, now: datetime | None = None) -> dict:
    now = now or utcnow()
    days = parse_days(days)
    pts = buckets(days, now)
    since = pts[0]["start"]

    q = select(Issue.severity, Issue.status, Issue.first_seen, Issue.resolved_at, Issue.due_at)
    sq = select(SurfaceChange.kind, SurfaceChange.created_at).where(SurfaceChange.created_at >= since)
    if scope_id is not None:
        q, sq = q.where(Issue.scope_id == scope_id), sq.where(SurfaceChange.scope_id == scope_id)
    issues = [SimpleNamespace(severity=r[0], status=r[1], first_seen=r[2], resolved_at=r[3], due_at=r[4])
              for r in db.execute(q)]
    changes = db.execute(sq).all()

    for n, b in enumerate(pts):
        last = n == len(pts) - 1
        opened = [i for i in issues if _open_at(i, b["end"])]
        b["open"] = {s: sum(1 for i in opened if i.severity == s) for s in ISSUE_SEVERITIES}
        b["other"] = len(opened) - sum(b["open"].values())          # info / unknown: in the table, not charted
        b["open_total"] = len(opened)
        b["new"] = sum(1 for i in issues if _in(i.first_seen, b, last))
        resolved = [i for i in issues if is_resolved(i) and _in(i.resolved_at, b, last)]
        remediated = [i for i in resolved if i.status in REMEDIATED]
        b["resolved"], b["remediated"] = len(resolved), len(remediated)
        m = mttr_days(remediated)
        b["mttr_days"] = round(m, 1) if m is not None else None
        b["sla_pct"] = sla_percent(remediated)
        b["with_due"] = sum(1 for i in remediated if i.due_at)
        kinds = [k for k, at in changes if _in(at, b, last)]
        b["surface_added"] = sum(1 for k in kinds if k in SURFACE_ADDED)
        b["surface_other"] = len(kinds) - b["surface_added"]

    peaks = {"open": max(sum(p["open"].values()) for p in pts),
             "flow": max(max(p["new"], p["resolved"]) for p in pts),
             "mttr": max([p["mttr_days"] for p in pts if p["mttr_days"] is not None], default=0),
             "surface": max(max(p["surface_added"], p["surface_other"]) for p in pts)}
    return {"days": days, "bucket": "day" if days == 30 else "week", "scope_id": scope_id, "points": pts,
            "peaks": peaks}
