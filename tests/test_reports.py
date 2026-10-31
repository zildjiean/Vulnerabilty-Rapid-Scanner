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


# ----------------------------------------------------------------- proof in reports
PROOF_CVE = "CVE-2021-41773"


def proven_issue(client, response="HTTP/1.1 200 OK\r\n\r\nroot:x:0:0", verified=True):
    """One issue with an HTTP proof; marked verified with that finding unless verified=False."""
    from app.db import Finding
    from tests.test_issue_routes import seed
    iid = seed(client, [(PROOF_CVE, "critical", "10.0.0.5", "443", PROOF_CVE)])[PROOF_CVE]
    with client.app.state.SessionLocal() as db:
        f = db.scalar(select(Finding).where(Finding.issue_id == iid))
        raw = json.loads(f.raw_json)
        raw.update({"request": "GET /cgi-bin/.%2e/etc/passwd HTTP/1.1\r\nHost: 10.0.0.5", "response": response,
                    "curl-command": "curl -k https://10.0.0.5/cgi-bin/<x>", "matcher-name": "passwd",
                    "timestamp": "2026-10-31T09:00:00Z"})
        f.raw_json = json.dumps(raw)
        i = db.get(Issue, iid)
        if verified:
            i.confidence, i.verified_finding_id, i.last_verified_at = "verified", f.id, NOW
        db.commit()
    return iid


def test_issue_evidence_report_shows_proof_risk_and_timeline(auth):
    iid = proven_issue(auth, response="HTTP/1.1 200 OK\r\n\r\n" + "R" * 5000 + "<script>x</script>")
    r = auth.get(f"/reports/issues/{iid}")
    assert r.status_code == 200
    page = r.text
    assert "Evidence report" in page and PROOF_CVE in page and "10.0.0.5:443" in page
    assert "GET /cgi-bin/.%2e/etc/passwd HTTP/1.1" in page and "passwd" in page
    assert "R" * 5000 in page                                     # full response, not truncated
    assert "&lt;script&gt;x&lt;/script&gt;" in page and "<script>x</script>" not in page
    assert "curl -k https://10.0.0.5/cgi-bin/&lt;x&gt;" in page
    assert 'aria-label="Risk score breakdown"' in page and "EPSS" in page and "CISA KEV" in page
    assert "conf-verified" in page and "Timeline" in page and "Print / Save as PDF" in page
    assert 'href="/reports/issues/' in auth.get(f"/issues/{iid}").text and "Print proof" in auth.get(f"/issues/{iid}").text
    assert auth.get("/reports/issues/99999").status_code == 404
    make_user(auth, "vee", "viewer")
    login_as(auth, "vee")
    assert auth.get(f"/reports/issues/{iid}").status_code == 200


def test_issue_evidence_report_without_findings(auth):
    with auth.app.state.SessionLocal() as db:
        i = add(db, "10.0.0.9:22", "medium", "triaged", 3)
        db.commit()
        iid = i.id
    page = auth.get(f"/reports/issues/{iid}").text
    assert "No scan evidence yet" in page


def test_campaign_and_scope_reports_have_an_evidence_appendix(auth):
    iid = proven_issue(auth, response="Z" * 2500)
    with auth.app.state.SessionLocal() as db:
        from app.campaigns import create_campaign
        c = create_campaign(db, name="Apache traversal", cve_id=PROOF_CVE, description="", severity="critical",
                            product_pattern="", version_constraint="", attach_templates=False, intel=None, created_by="admin")
        s = Scope(name="Edge", targets="10.0.0.0/24", criticality="high")
        db.add(s)
        db.flush()
        db.get(Issue, iid).scope_id = s.id
        db.commit()
        cid, sid = c.id, s.id
    for url in (f"/reports/campaigns/{cid}", f"/reports/scopes/{sid}"):
        page = auth.get(url).text
        assert 'id="evidence"' in page and "GET /cgi-bin/.%2e/etc/passwd" in page, url
        assert "Z" * 2000 in page and "Z" * 2001 not in page, url        # truncated to 2,000 characters
        assert "truncated, see the issue report" in page and f'href="/reports/issues/{iid}"' in page, url
        assert "Include proof" in page and 'class="no-print' in page, url
        hidden = auth.get(url + "?proof=0").text
        assert 'id="evidence"' not in hidden and "GET /cgi-bin" not in hidden, url
        assert 'id="evidence"' in auth.get(url + "?proof=1").text, url


def test_evidence_appendix_lists_only_verified_issues(auth):
    proven_issue(auth, verified=False)
    with auth.app.state.SessionLocal() as db:
        from app.campaigns import create_campaign
        c = create_campaign(db, name="Apache traversal", cve_id=PROOF_CVE, description="", severity="critical",
                            product_pattern="", version_constraint="", attach_templates=False, intel=None, created_by="admin")
        db.commit()
        cid = c.id
    page = auth.get(f"/reports/campaigns/{cid}").text
    assert "GET /cgi-bin" not in page and "No verified issues" in page


def test_huge_proof_is_capped_on_the_issue_page_and_report(auth):
    from app.proof import REPORT_FULL_LIMIT
    iid = proven_issue(auth, response="Q" * (REPORT_FULL_LIMIT + 50))
    for url in (f"/issues/{iid}", f"/reports/issues/{iid}"):
        page = auth.get(url).text
        assert "… 50 more characters not shown" in page, url
        assert REPORT_FULL_LIMIT <= page.count("Q") < REPORT_FULL_LIMIT + 50, url   # the page splits it at 4,000


def test_executive_report_charts(data):
    r = data.get("/reports?days=30")
    assert r.status_code == 200
    for title in ("Open exposure", "New vs resolved", "Mean time to remediate (days)", "SLA compliance (%)"):
        assert title in r.text
    assert "Surface changes</" not in r.text
    assert r.text.count('class="chart-hit"') == 4 * 30                # 30 days → daily buckets
    assert r.text.count("<summary>Show data</summary>") == 4 and "<table" in r.text
    assert 'class="trend"' not in r.text                               # the old weekly bar chart is gone
    assert data.get("/reports?days=7").text.count('class="chart-hit"') == 4 * 30     # nearest period
    assert data.get("/reports?days=365").text.count('class="chart-hit"') == 4 * 53
    with data.app.state.SessionLocal() as db:
        assert "trend" in reports.executive(db, days=30, now=NOW)            # still feeds the AI summary


def test_executive_report_notes_chart_span(data):
    from app import trends
    from app.db import utcnow
    pts = trends.buckets(90, utcnow())
    start = f"{pts[0]['start']:%b} {pts[0]['start'].day}"
    r = data.get("/reports?days=90")
    assert f"Charts cover {start} – {pts[-1]['label']}" in r.text
