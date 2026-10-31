from datetime import datetime, timedelta

import pytest

from app import reports, trends
from app.db import Issue, Scope, SurfaceChange

NOW = datetime(2026, 10, 31, 12, 0)


def add(db, n, severity="high", status="new", first=None, resolved=None, due=None, scope=None):
    i = Issue(key=f"192.0.2.{n}:443|CVE-{n}", asset=f"192.0.2.{n}:443", address=f"192.0.2.{n}", port="443",
              vuln_id=f"CVE-{n}", title=f"bug {n}", severity=severity, confidence="confirmed", status=status,
              first_seen=first, last_seen=first, status_changed_at=first, due_at=due, resolved_at=resolved,
              scope_id=scope.id if scope else None)
    db.add(i)
    return i


@pytest.fixture
def db(client):
    with client.app.state.SessionLocal() as s:
        yield s


def ago(days, hours=0):
    return NOW - timedelta(days=days, hours=hours)


# ----------------------------------------------------------------- buckets
def test_buckets_daily_weekly_and_fallback(db):
    t = trends.trends(db, 30, now=NOW)
    assert t["bucket"] == "day" and t["days"] == 30 and len(t["points"]) == 30
    assert t["points"][-1]["end"] == NOW and t["points"][0]["start"] == NOW - timedelta(days=30)
    assert all(p["end"] - p["start"] == timedelta(days=1) for p in t["points"])
    assert all(a["end"] == b["start"] for a, b in zip(t["points"], t["points"][1:]))
    t = trends.trends(db, 90, now=NOW)
    assert t["bucket"] == "week" and len(t["points"]) == 13 and t["points"][-1]["end"] == NOW
    assert all(p["end"] - p["start"] == timedelta(days=7) for p in t["points"])
    assert len(trends.trends(db, 180, now=NOW)["points"]) == 26
    assert len(trends.trends(db, 365, now=NOW)["points"]) == 53
    for bad in (7, 0, -5, 1000, "abc", None):
        assert trends.trends(db, bad, now=NOW)["days"] == 90
    p = t["points"][-1]
    assert p["label"] == "Oct 31" and p["range"] == "Oct 24–Oct 31"
    assert trends.trends(db, 30, now=NOW)["points"][-1]["range"] == "Oct 31"
    assert trends.trends(db, 365, now=NOW)["points"][0]["range"] == "Oct 25–Nov 1, 2025"


def test_parse_days():
    assert trends.parse_days("30") == 30 and trends.parse_days("365") == 365
    assert trends.parse_days("31") == 90 and trends.parse_days("") == 90 and trends.parse_days(None) == 90
    assert trends.nearest_days(7) == 30 and trends.nearest_days(100) == 90 and trends.nearest_days(3650) == 365


# ----------------------------------------------------------------- issue figures
def test_open_new_resolved_per_bucket(db):
    add(db, 1, "critical", "new", first=ago(20))                                      # open throughout
    add(db, 2, "high", "verified", first=ago(20), resolved=ago(10), due=ago(13))       # open until 10 days ago
    add(db, 3, "medium", "fixed", first=ago(5), resolved=ago(2), due=ago(-25))         # fixed, awaiting verification
    add(db, 4, "low", "false_positive", first=ago(15), resolved=ago(14))               # never real exposure
    add(db, 5, "info", "new", first=ago(3))                                            # counted as other
    add(db, 6, "high", "triaged", first=ago(40))                                       # before the window
    db.commit()
    t = trends.trends(db, 30, now=NOW)
    pts = t["points"]
    last, day10 = pts[-1], pts[-11]          # day10 ends 10 days ago
    assert last["open"] == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    assert last["other"] == 1 and last["open_total"] == 3            # info / unknown stay in the total
    # 10 days ago issue 2 was resolved exactly at the end of that bucket → not open at its end
    assert day10["end"] == ago(10) and day10["open"]["high"] == 1   # only issue 6
    assert pts[-12]["open"]["high"] == 2                             # one bucket earlier: 2 and 6 open
    assert pts[-4]["open"]["medium"] == 1 and last["open"]["medium"] == 0
    assert sum(p["new"] for p in pts) == 5                           # issue 6 started before the window
    assert sum(p["resolved"] for p in pts) == 3                      # 2, 3 and the false positive
    # resolved exactly at a bucket boundary lands in the bucket that starts there
    assert pts[-10]["resolved"] >= 1 and pts[-10]["start"] == ago(10)
    # the current open total matches the executive report
    assert last["open_total"] == reports.executive(db, 30, now=NOW)["open_total"]


def test_reopened_issue_counts_by_current_state(db):
    add(db, 1, "high", "triaged", first=ago(20), resolved=None)
    db.commit()
    pts = trends.trends(db, 30, now=NOW)["points"]
    assert all(p["open"]["high"] == 1 for p in pts if p["end"] >= ago(20))


def test_mttr_and_sla_per_bucket(db):
    add(db, 1, "high", "verified", first=ago(12), resolved=ago(2, 1), due=ago(5))        # 9.96 d, late
    add(db, 2, "high", "fixed", first=ago(5), resolved=ago(2, 2), due=ago(1))            # 2.92 d, in time
    add(db, 3, "low", "accepted_risk", first=ago(9), resolved=ago(2, 3), due=ago(30))    # excluded
    add(db, 4, "medium", "verified", first=ago(8), resolved=ago(6))                      # no due date
    db.commit()
    pts = trends.trends(db, 30, now=NOW)["points"]
    b = pts[-3]                                                       # [3 days ago, 2 days ago)
    assert b["resolved"] == 3 and b["remediated"] == 2
    assert b["mttr_days"] == pytest.approx(6.4)
    assert b["sla_pct"] == 50 and b["with_due"] == 2
    assert pts[-6]["mttr_days"] == 2.0 and pts[-6]["sla_pct"] is None   # resolved exactly at its start
    assert pts[-1]["mttr_days"] is None and pts[-1]["sla_pct"] is None


def test_scope_filter(db):
    dmz = Scope(name="DMZ", targets="192.0.2.0/24")
    db.add(dmz)
    db.flush()
    add(db, 1, "critical", "new", first=ago(3), scope=dmz)
    add(db, 2, "high", "new", first=ago(3))
    db.add(SurfaceChange(kind="host_new", address="192.0.2.1", scope_id=dmz.id, created_at=ago(1)))
    db.add(SurfaceChange(kind="host_new", address="198.51.100.1", created_at=ago(1)))
    db.commit()
    t = trends.trends(db, 30, scope_id=dmz.id, now=NOW)
    assert t["scope_id"] == dmz.id
    assert t["points"][-1]["open"] == {"critical": 1, "high": 0, "medium": 0, "low": 0}
    assert sum(p["surface_added"] for p in t["points"]) == 1
    assert trends.trends(db, 30, now=NOW)["points"][-1]["open_total"] == 2


def test_surface_counts_per_bucket(db):
    for kind, d in (("host_new", 1), ("port_opened", 1), ("port_closed", 1), ("service_changed", 8),
                    ("host_gone", 8), ("port_opened", 40)):
        db.add(SurfaceChange(kind=kind, address="203.0.113.5", created_at=ago(d, 1)))
    db.commit()
    t = trends.trends(db, 90, now=NOW)
    last, prev = t["points"][-1], t["points"][-2]
    assert last["surface_added"] == 2 and last["surface_other"] == 1
    assert prev["surface_added"] == 0 and prev["surface_other"] == 2
    assert sum(p["surface_added"] for p in t["points"]) == 3
    assert t["peaks"]["surface"] == 2


def test_peaks(db):
    add(db, 1, "critical", "new", first=ago(3))
    add(db, 2, "high", "verified", first=ago(4), resolved=ago(1))
    db.commit()
    peaks = trends.trends(db, 30, now=NOW)["peaks"]
    assert peaks["open"] == 2 and peaks["flow"] == 1 and peaks["mttr"] == 3.0


# ----------------------------------------------------------------- API
def test_api_trends(auth):
    from tests.test_api import api, new_key
    with auth.app.state.SessionLocal() as s:
        sc = Scope(name="Lab", targets="198.51.100.0/24")
        s.add(sc)
        s.commit()
        sid = sc.id
    key = new_key(auth, role="viewer")
    r = api(auth, key, "GET", "/trends")
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"days", "bucket", "scope_id", "points", "peaks"}
    assert body["days"] == 90 and body["bucket"] == "week" and len(body["points"]) == 13 and body["scope_id"] is None
    p = body["points"][-1]
    assert p["start"].endswith("Z") and p["end"].endswith("Z")
    assert {"label", "range", "open", "other", "open_total", "new", "resolved", "mttr_days", "sla_pct",
            "surface_added", "surface_other"} <= set(p)
    body = api(auth, key, "GET", f"/trends?days=30&scope={sid}").json()
    assert body["days"] == 30 and len(body["points"]) == 30 and body["scope_id"] == sid
    assert api(auth, key, "GET", "/trends?days=abc&scope=xyz").json()["days"] == 90
    assert api(auth, key, "GET", "/trends?scope=999").json()["scope_id"] is None
    assert auth.get("/api/v1/trends", headers={"Authorization": "Bearer nope"}).status_code == 401
