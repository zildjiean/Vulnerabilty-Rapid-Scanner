import random
from datetime import datetime, timedelta

import pytest

from app import reports, trends
from app.db import Issue, Scope, SurfaceChange
from app.issues import ISSUE_SEVERITIES, OPEN_WORK

NOW = datetime(2026, 10, 31, 12, 0)
TODAY = datetime(2026, 10, 31)


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


def day(k, hour=12):
    """``hour`` o'clock, ``k`` days before NOW's day; day(k) lies in daily bucket points[-1 - k]."""
    return TODAY - timedelta(days=k) + timedelta(hours=hour)


def mid(k):
    """Midnight starting the day ``k`` days ago: the start of daily bucket points[-1 - k]."""
    return day(k, 0)


# ----------------------------------------------------------------- buckets
def test_daily_buckets_align_to_midnight(db):
    t = trends.trends(db, 30, now=NOW)
    pts = t["points"]
    assert t["bucket"] == "day" and t["days"] == 30 and len(pts) == 30
    assert pts[-1]["start"] == TODAY and pts[-1]["end"] == NOW              # today so far
    assert pts[0]["start"] == mid(29)
    assert all(p["end"] - p["start"] == timedelta(days=1) for p in pts[:-1])
    assert all(a["end"] == b["start"] for a, b in zip(pts, pts[1:]))
    assert pts[-1]["range"] == pts[-1]["label"] == "Oct 31" and pts[-2]["range"] == "Oct 30"


def test_weekly_buckets_and_fallback(db):
    t = trends.trends(db, 90, now=NOW)
    pts = t["points"]
    assert t["bucket"] == "week" and len(pts) == 13
    assert pts[-1]["start"] == mid(6) and pts[-1]["end"] == NOW
    assert all(p["end"] - p["start"] == timedelta(days=7) for p in pts[:-1])
    assert all(a["end"] == b["start"] for a, b in zip(pts, pts[1:]))
    # inclusive end dates: consecutive rows never share a day
    assert pts[-1]["range"] == "Oct 25–Oct 31" and pts[-1]["label"] == "Oct 31"
    assert pts[-2]["range"] == "Oct 18–Oct 24" and pts[-2]["label"] == "Oct 24"
    assert len(trends.trends(db, 180, now=NOW)["points"]) == 26
    year = trends.trends(db, 365, now=NOW)["points"]
    assert len(year) == 53 and year[0]["range"] == "Oct 26–Nov 1, 2025"
    for bad in (7, 0, -5, 1000, "abc", None):
        assert trends.trends(db, bad, now=NOW)["days"] == 90


def test_parse_days():
    assert trends.parse_days("30") == 30 and trends.parse_days("365") == 365
    assert trends.parse_days("31") == 90 and trends.parse_days("") == 90 and trends.parse_days(None) == 90
    assert trends.nearest_days(7) == 30 and trends.nearest_days(100) == 90 and trends.nearest_days(3650) == 365


# ----------------------------------------------------------------- issue figures
def test_open_new_resolved_per_bucket(db):
    add(db, 1, "critical", "new", first=day(20))                                      # open throughout
    add(db, 2, "high", "verified", first=day(20), resolved=mid(10), due=day(13))       # resolved at a boundary
    add(db, 3, "medium", "fixed", first=day(5), resolved=day(2), due=day(-25))         # fixed, awaiting verification
    add(db, 4, "low", "false_positive", first=day(15), resolved=day(14))               # never real exposure
    add(db, 5, "info", "new", first=day(3))                                            # counted as other
    add(db, 6, "high", "triaged", first=day(40))                                       # before the window
    db.commit()
    pts = trends.trends(db, 30, now=NOW)["points"]
    last = pts[-1]
    assert last["open"] == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    assert last["other"] == 1 and last["open_total"] == 3            # info / unknown stay in the total
    # issue 2 was resolved exactly at the end of pts[-12] → not open there, open one bucket earlier
    assert pts[-12]["end"] == mid(10) and pts[-12]["open"]["high"] == 1
    assert pts[-13]["open"]["high"] == 2
    assert pts[-4]["open"]["medium"] == 1 and last["open"]["medium"] == 0
    assert sum(p["new"] for p in pts) == 5                           # issue 6 started before the window
    assert sum(p["resolved"] for p in pts) == 3                      # 2, 3 and the false positive
    assert pts[-11]["start"] == mid(10) and pts[-11]["resolved"] == 1   # a boundary lands in the bucket it starts
    # the current open total matches the executive report
    assert last["open_total"] == reports.executive(db, 30, now=NOW)["open_total"]


def test_reopened_issue_counts_by_current_state(db):
    add(db, 1, "high", "triaged", first=day(20), resolved=None)
    db.commit()
    pts = trends.trends(db, 30, now=NOW)["points"]
    assert all(p["open"]["high"] == 1 for p in pts if p["end"] >= day(20))
    assert all(p["open"]["high"] == 0 for p in pts if p["end"] < day(20))


def test_mttr_and_sla_per_bucket(db):
    add(db, 1, "high", "verified", first=day(12), resolved=day(2, 11), due=day(5))       # 9.96 d, late
    add(db, 2, "high", "fixed", first=day(5), resolved=day(2, 10), due=day(1))           # 2.92 d, in time
    add(db, 3, "low", "accepted_risk", first=day(9), resolved=day(2, 9), due=day(30))    # excluded
    add(db, 4, "medium", "verified", first=day(8), resolved=mid(6))                      # no due date, 1.5 d
    db.commit()
    pts = trends.trends(db, 30, now=NOW)["points"]
    b = pts[-3]
    assert b["resolved"] == 3 and b["remediated"] == 2
    assert b["mttr_days"] == pytest.approx(6.4)
    assert b["sla_pct"] == 50 and b["with_due"] == 2
    assert pts[-7]["mttr_days"] == 1.5 and pts[-7]["sla_pct"] is None   # resolved exactly at its start
    assert pts[-1]["mttr_days"] is None and pts[-1]["sla_pct"] is None


def test_scope_filter(db):
    dmz = Scope(name="DMZ", targets="192.0.2.0/24")
    db.add(dmz)
    db.flush()
    add(db, 1, "critical", "new", first=day(3), scope=dmz)
    add(db, 2, "high", "new", first=day(3))
    db.add(SurfaceChange(kind="host_new", address="192.0.2.1", scope_id=dmz.id, created_at=day(1)))
    db.add(SurfaceChange(kind="host_new", address="198.51.100.1", created_at=day(1)))
    db.commit()
    t = trends.trends(db, 30, scope_id=dmz.id, now=NOW)
    assert t["scope_id"] == dmz.id
    assert t["points"][-1]["open"] == {"critical": 1, "high": 0, "medium": 0, "low": 0}
    assert sum(p["surface_added"] for p in t["points"]) == 1
    assert trends.trends(db, 30, now=NOW)["points"][-1]["open_total"] == 2


def test_surface_counts_per_bucket(db):
    for kind, d in (("host_new", 1), ("port_opened", 1), ("port_closed", 1), ("service_changed", 8),
                    ("host_gone", 8), ("port_opened", 40)):
        db.add(SurfaceChange(kind=kind, address="203.0.113.5", created_at=day(d, 11)))
    db.commit()
    t = trends.trends(db, 90, now=NOW)
    last, prev = t["points"][-1], t["points"][-2]
    assert last["surface_added"] == 2 and last["surface_other"] == 1
    assert prev["surface_added"] == 0 and prev["surface_other"] == 2
    assert sum(p["surface_added"] for p in t["points"]) == 3
    assert t["peaks"]["surface"] == 2


def test_peaks(db):
    add(db, 1, "critical", "new", first=day(3))
    add(db, 2, "high", "verified", first=day(4), resolved=day(1))
    add(db, 3, "info", "new", first=day(2))
    db.commit()
    peaks = trends.trends(db, 30, now=NOW)["peaks"]
    assert peaks["open"] == 3 and peaks["flow"] == 1 and peaks["mttr"] == 3.0     # open counts the total


# ----------------------------------------------------------------- matches the straightforward definition
def naive(db, days, scope_id=None, now=NOW):
    """The per-bucket O(issues x buckets) definition the bisect version must reproduce exactly."""
    pts = trends.buckets(trends.parse_days(days), now)
    issues = [i for i in db.query(Issue).all() if scope_id is None or i.scope_id == scope_id]
    changes = [c for c in db.query(SurfaceChange).all() if scope_id is None or c.scope_id == scope_id]

    def inside(d, b, last):
        return d is not None and (b["start"] <= d < b["end"] or (last and d == b["end"]))

    def open_at(i, t):
        if i.status == "false_positive" or i.first_seen is None or i.first_seen > t:
            return False
        return i.resolved_at > t if reports.is_resolved(i) else i.status in OPEN_WORK

    out = []
    for n, b in enumerate(pts):
        last = n == len(pts) - 1
        opened = [i for i in issues if open_at(i, b["end"])]
        res = [i for i in issues if reports.is_resolved(i) and inside(i.resolved_at, b, last)]
        rem = [i for i in res if i.status in reports.REMEDIATED]
        m = reports.mttr_days(rem)
        kinds = [c.kind for c in changes if inside(c.created_at, b, last)]
        o = {s: sum(1 for i in opened if i.severity == s) for s in ISSUE_SEVERITIES}
        out.append({**b, "open": o, "other": len(opened) - sum(o.values()), "open_total": len(opened),
                    "new": sum(1 for i in issues if inside(i.first_seen, b, last)), "resolved": len(res),
                    "remediated": len(rem), "mttr_days": round(m, 1) if m is not None else None,
                    "sla_pct": reports.sla_percent(rem), "with_due": sum(1 for i in rem if i.due_at),
                    "surface_added": sum(1 for k in kinds if k in trends.SURFACE_ADDED),
                    "surface_other": sum(1 for k in kinds if k not in trends.SURFACE_ADDED)})
    return out


def test_matches_naive_definition_on_random_data(db):
    rnd = random.Random(1234)
    scopes = [Scope(name=f"S{k}", targets=f"192.0.2.{k}") for k in range(2)]
    db.add_all(scopes)
    db.flush()
    statuses = ("new", "triaged", "in_progress", "fixed", "verified", "false_positive", "accepted_risk")
    sevs = ("critical", "high", "medium", "low", "info", "unknown")

    def when():
        # mostly random, sometimes exactly on a midnight boundary or on NOW
        r = rnd.random()
        if r < .15:
            return mid(rnd.randrange(0, 400))
        return NOW if r < .2 else NOW - timedelta(seconds=rnd.uniform(0, 400 * 86400))

    for n in range(500):
        first = when()
        status = rnd.choice(statuses)
        resolved = None
        if status in ("fixed", "verified", "false_positive", "accepted_risk") and rnd.random() < .95:
            resolved = min(NOW, first + timedelta(seconds=rnd.uniform(0, 40 * 86400)))
        elif rnd.random() < .03:
            resolved = first + timedelta(days=1)                  # stale resolved_at on an open issue
        due = first + timedelta(days=rnd.choice((3, 7, 30))) if rnd.random() < .8 else None
        add(db, n, rnd.choice(sevs), status, first=first, resolved=resolved, due=due, scope=rnd.choice(scopes + [None]))
    for n in range(200):
        db.add(SurfaceChange(kind=rnd.choice(("host_new", "port_opened", "port_closed", "service_changed", "host_gone")),
                             address="203.0.113.1", created_at=when(), scope_id=rnd.choice((scopes[0].id, None))))
    db.commit()
    for days in trends.PERIODS:
        for sid in (None, scopes[0].id):
            assert trends.trends(db, days, scope_id=sid, now=NOW)["points"] == naive(db, days, sid), (days, sid)
    midnight = mid(0)                                             # a zero-length "today" bucket
    assert trends.trends(db, 30, now=midnight)["points"] == naive(db, 30, now=midnight)


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
    assert api(auth, key, "GET", "/trends?days=abc").json()["days"] == 90
    assert api(auth, key, "GET", "/trends?scope=").json()["scope_id"] is None
    for bad in ("999", "xyz", "99999999999999999999999", "²", "-1", "1.0", " 1"):
        assert api(auth, key, "GET", "/trends", params={"scope": bad}).status_code == 404, bad
    assert auth.get("/api/v1/trends", headers={"Authorization": "Bearer nope"}).status_code == 401


def test_scope_id_parsing(db):
    from app.routers.dashboard import parse_scope_id, trend_scope
    sc = Scope(name="Lab", targets="198.51.100.0/24")
    db.add(sc)
    db.commit()
    assert parse_scope_id(str(sc.id)) == sc.id and parse_scope_id("") is None
    for bad in ("99999999999999999999999", "²", "١", "-1", "1.5", "x", " 1", "0x1", None):
        assert parse_scope_id(bad) is None, bad
    assert parse_scope_id("9" * 18) == int("9" * 18) and parse_scope_id("9" * 19) is None
    assert trend_scope(db, str(sc.id)) == sc.id
    assert trend_scope(db, "999") is None and trend_scope(db, "99999999999999999999999") is None
    assert trend_scope(db, "²") is None


def test_mttr_and_sla_match_report_helpers(db):
    rem = [add(db, 1, status="fixed", first=day(9), resolved=day(1), due=day(3)),
           add(db, 2, status="verified", first=day(20), resolved=day(1, 15), due=day(5)),
           add(db, 3, status="fixed", first=day(4), resolved=day(1, 18))]
    db.commit()
    b = trends.trends(db, 30, now=NOW)["points"][-2]
    assert b["mttr_days"] == round(reports.mttr_days(rem), 1)
    assert b["sla_pct"] == reports.sla_percent(rem)
