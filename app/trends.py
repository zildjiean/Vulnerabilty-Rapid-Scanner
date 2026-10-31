"""Trend series for the dashboard and the executive report, rebuilt from issue and surface-change history.

Known limitation: an issue is counted by its current state, so a reopened issue (resolved_at cleared) looks open
for its whole life.
"""
from __future__ import annotations

import math
from bisect import bisect_left, bisect_right
from datetime import datetime, timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .db import Issue, SurfaceChange, utcnow
from .issues import ISSUE_SEVERITIES, OPEN_WORK, RESOLVED
from .reports import REMEDIATED

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
    """Contiguous calendar buckets (UTC midnight) ending at ``now``: 30 days (29 full days plus today so far), or
    ceil(days / 7) weeks of 7 days, the last of which is the 6 full days before today plus today so far."""
    daily = days == 30
    n, step = (30, timedelta(days=1)) if daily else (math.ceil(days / 7), timedelta(days=7))
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    last_start = today if daily else today - timedelta(days=6)
    out = []
    for k in range(n):
        start = last_start - step * (n - 1 - k)
        end = now if k == n - 1 else start + step
        last_day = today if k == n - 1 else end - timedelta(days=1)    # inclusive, so ranges never overlap
        rng = _label(last_day) if daily else f"{_label(start)}–{_label(last_day)}"
        if last_day.year != now.year:
            rng += f", {last_day.year}"          # 12-month charts reach into last year
        out.append({"start": start, "end": end, "label": _label(last_day), "range": rng})
    return out


def trends(db: Session, days=DEFAULT_DAYS, scope_id: int | None = None, now: datetime | None = None) -> dict:
    """Per bucket: issues open at its end by severity, new, resolved, MTTR and SLA of the issues remediated in it,
    and surface changes. Definitions follow app.reports.executive: false positives were never exposure; a resolved
    issue without a resolution time is left out of "open" because its open period is unknown.

    Each issue is placed with bisect once (difference arrays for the open counts), so the cost is
    O(issues x log buckets) rather than O(issues x buckets)."""
    now = now or utcnow()
    days = parse_days(days)
    pts = buckets(days, now)
    n, since = len(pts), pts[0]["start"]
    starts, ends = [p["start"] for p in pts], [p["end"] for p in pts]

    q = (select(Issue.severity, Issue.status, Issue.first_seen, Issue.resolved_at, Issue.due_at)
         .where(or_(Issue.resolved_at.is_(None), Issue.resolved_at >= since, Issue.status.in_(OPEN_WORK))))
    sq = select(SurfaceChange.kind, SurfaceChange.created_at).where(SurfaceChange.created_at >= since)
    if scope_id is not None:
        q, sq = q.where(Issue.scope_id == scope_id), sq.where(SurfaceChange.scope_id == scope_id)

    def bucket_of(d: datetime | None) -> int | None:
        """[start, end) per bucket, the last one closed so events stamped exactly ``now`` count (as the report)."""
        if d is None or d < since or d > now:
            return None
        return bisect_right(starts, d) - 1

    keys = (*ISSUE_SEVERITIES, "other")
    diff = {k: [0] * (n + 1) for k in keys}
    new, resolved, remediated, secs, with_due, on_time = ([0] * n for _ in range(6))
    for sev, status, first, res, due in db.execute(q):
        is_res = status in RESOLVED and res is not None
        k = bucket_of(first)
        if k is not None:
            new[k] += 1
        if first is not None and status != "false_positive" and (is_res or status in OPEN_WORK):
            k0 = bisect_left(ends, first)                        # first bucket whose end is on/after first seen
            k1 = bisect_left(ends, res) - 1 if is_res else n - 1  # last bucket that ends before the resolution
            if k0 <= k1:
                d = diff[sev if sev in ISSUE_SEVERITIES else "other"]
                d[k0] += 1
                d[k1 + 1] -= 1
        if is_res and (k := bucket_of(res)) is not None:
            resolved[k] += 1
            if status in REMEDIATED:                             # MTTR / SLA as in app.reports
                remediated[k] += 1
                secs[k] += (res - first).total_seconds()
                if due:
                    with_due[k] += 1
                    on_time[k] += res <= due
    added, other = [0] * n, [0] * n
    for kind, at in db.execute(sq):
        if (k := bucket_of(at)) is not None:
            (added if kind in SURFACE_ADDED else other)[k] += 1

    running = dict.fromkeys(keys, 0)
    for k, b in enumerate(pts):
        for key in keys:
            running[key] += diff[key][k]
        b["open"] = {s: running[s] for s in ISSUE_SEVERITIES}
        b["other"] = running["other"]                            # info / unknown: in the table, not charted
        b["open_total"] = sum(running.values())
        b["new"], b["resolved"], b["remediated"] = new[k], resolved[k], remediated[k]
        b["mttr_days"] = round(secs[k] / remediated[k] / 86400, 1) if remediated[k] else None
        b["sla_pct"] = round(100 * on_time[k] / with_due[k]) if with_due[k] else None
        b["with_due"] = with_due[k]
        b["surface_added"], b["surface_other"] = added[k], other[k]

    peaks = {"open": max(p["open_total"] for p in pts),
             "flow": max(max(p["new"], p["resolved"]) for p in pts),
             "mttr": max([p["mttr_days"] for p in pts if p["mttr_days"] is not None], default=0),
             "surface": max(max(p["surface_added"], p["surface_other"]) for p in pts)}
    return {"days": days, "bucket": "day" if days == 30 else "week", "scope_id": scope_id, "points": pts,
            "peaks": peaks}
