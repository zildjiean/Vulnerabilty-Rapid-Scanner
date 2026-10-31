import csv
import io
import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app import reports
from app.db import AuditLog, Issue, Scope
from tests.conftest import get_csrf
from tests.test_rbac import login_as, make_user

NOW = datetime(2026, 10, 30, 12, 0)


def add(db, asset, severity, status, first_days_ago, resolved_days_ago=None, due_days=7, scope=None, title=None):
    first = NOW - timedelta(days=first_days_ago)
    i = Issue(key=f"{asset}|{title or severity}{first_days_ago}", asset=asset, address=asset.split(":")[0],
              port=asset.split(":")[1], vuln_id=title or f"CVE-{severity}", title=title or f"{severity} bug",
              severity=severity, confidence="confirmed", status=status, first_seen=first, last_seen=first,
              status_changed_at=first, due_at=first + timedelta(days=due_days),
              resolved_at=NOW - timedelta(days=resolved_days_ago) if resolved_days_ago is not None else None,
              scope_id=scope.id if scope else None)
    db.add(i)
    return i


@pytest.fixture
def data(auth):
    with auth.app.state.SessionLocal() as db:
        dmz = Scope(name="DMZ", targets="10.0.0.0/24", criticality="critical")
        db.add(dmz)
        db.flush()
        add(db, "10.0.0.5:443", "critical", "new", 10, scope=dmz)                       # open, overdue
        add(db, "10.0.0.5:443", "high", "in_progress", 2, scope=dmz, title="=cmd|'/c calc'!A1")  # open, formula title
        add(db, "10.0.0.9:22", "medium", "triaged", 3)                                  # open
        add(db, "10.0.0.7:80", "high", "verified", 20, resolved_days_ago=16, due_days=7)  # resolved in time (4d)
        add(db, "10.0.0.8:80", "critical", "fixed", 12, resolved_days_ago=1, due_days=3)  # resolved late (11d)
        add(db, "10.0.0.6:80", "low", "false_positive", 5, resolved_days_ago=4)          # excluded from MTTR / SLA
        add(db, "10.0.0.1:80", "high", "verified", 100, resolved_days_ago=90)           # outside the period
        db.commit()
    return auth


def test_executive_numbers(data):
    with data.app.state.SessionLocal() as db:
        r = reports.executive(db, days=30, now=NOW)
    assert r["open_by_severity"] == {"critical": 1, "high": 1, "medium": 1, "low": 0}
    assert r["open_total"] == 3 and r["overdue"] == 1
    assert r["new_in_period"] == 6 and r["resolved_in_period"] == 3
    assert r["mttr_days"] == pytest.approx(7.5)            # (4 + 11) / 2
    assert r["sla_pct"] == 50                               # 1 of 2 remediated in time
    assert len(r["trend"]) == 5 and sum(w["new"] for w in r["trend"]) == 6 and sum(w["resolved"] for w in r["trend"]) == 3
    top = r["top_assets"][0]
    assert top["asset"] == "10.0.0.5:443" and top["critical"] == 1 and top["high"] == 1
    scopes = {s["name"]: s for s in r["scopes"]}
    assert scopes["DMZ"]["open"] == 2 and scopes["DMZ"]["overdue"] == 1 and scopes["No scope"]["open"] == 1


def test_report_pages(data):
    r = data.get("/reports?days=30")
    assert r.status_code == 200 and "Executive summary" in r.text and "Print" in r.text
    assert "10.0.0.5:443" in r.text and "<svg" in r.text and "DMZ" in r.text
    assert data.get("/reports?days=abc").status_code == 200   # falls back to the default period
    with data.app.state.SessionLocal() as db:
        sid = db.scalar(select(Scope.id))
    r = data.get(f"/reports/scopes/{sid}")
    assert r.status_code == 200 and "DMZ" in r.text and "critical bug" in r.text
    assert data.get("/reports/scopes/999").status_code == 404


def test_issue_exports(data):
    r = data.get("/reports/issues.csv?view=all&severity=high")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert {row["severity"] for row in rows} == {"high"} and len(rows) == 3
    assert any(row["title"].startswith("'=cmd") for row in rows)   # formula neutralised
    j = data.get("/reports/issues.json?view=active").json()
    # "active" includes fixed issues awaiting verification
    assert j["count"] == 4 and {i["asset"] for i in j["issues"]} == {"10.0.0.5:443", "10.0.0.9:22", "10.0.0.8:80"}
    assert "scope" in j["issues"][0] and "due_at" in j["issues"][0]
    with data.app.state.SessionLocal() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action == "report.exported")) is not None
    assert 'href="/reports/issues.csv' in data.get("/issues").text


def test_campaign_report(data):
    from tests.test_campaigns import NVD_PHP, PHP_CVE
    from tests.test_intel import FakeNet
    data.app.state.get_json = FakeNet(nvd={PHP_CVE: NVD_PHP})
    csrf = get_csrf(data, "/campaigns/new")
    r = data.post("/campaigns", data={"csrf": csrf, "cve_id": PHP_CVE, "severity": "auto", "fetch_intel": "true"},
                  follow_redirects=False)
    cid = int(r.headers["location"].rsplit("/", 1)[1])
    page = data.get(f"/reports/campaigns/{cid}").text
    assert PHP_CVE in page and "PHP use-after-free." in page and "Remediated" in page


def test_viewer_can_read_reports(data):
    make_user(data, "vee", "viewer")
    login_as(data, "vee")
    assert data.get("/reports").status_code == 200
    assert data.get("/reports/issues.csv").status_code == 200


def test_exports_carry_verified_confidence(data):
    with data.app.state.SessionLocal() as db:
        i = db.scalar(select(Issue).where(Issue.status == "new"))
        i.confidence = "verified"
        db.commit()
        iid = i.id
    rows = list(csv.DictReader(io.StringIO(data.get("/reports/issues.csv?view=all&confidence=verified").text)))
    assert [(int(r["id"]), r["confidence"]) for r in rows] == [(iid, "verified")]
    j = data.get("/reports/issues.json?view=all&confidence=verified").json()
    assert j["count"] == 1 and j["issues"][0]["confidence"] == "verified"
