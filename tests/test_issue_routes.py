import json
import re
from datetime import timedelta

import pytest
from sqlalchemy import select

from app import issues as iss
from app.db import AuditLog, Finding, Issue, IssueEvent, Job, User, utcnow
from tests.conftest import get_csrf
from tests.test_rbac import login_as, make_user


def seed(client, specs):
    """specs: list of (template_id, severity, ip, port, cve)."""
    with client.app.state.SessionLocal() as db:
        j = Job(kind="nuclei", status="done")
        db.add(j)
        db.commit()
        rows = []
        for tid, sev, ip, port, cve in specs:
            raw = {"template-id": tid, "host": ip, "ip": ip, "port": port, "matched-at": f"https://{ip}:{port}/",
                   "info": {"name": f"{tid} title", "severity": sev, "classification": {"cve-id": [cve] if cve else None}}}
            f = Finding(job_id=j.id, template_id=tid, template_name=f"{tid} title", severity=sev, host=ip,
                        matched_at=raw["matched-at"], raw_json=json.dumps(raw))
            db.add(f)
            rows.append(f)
        db.flush()
        iss.issues_from_findings(db, rows, j)
        db.commit()
        return {i.vuln_id: i.id for i in db.scalars(select(Issue))}


SPECS = [("CVE-2021-41773", "critical", "10.0.0.5", "443", "CVE-2021-41773"),
         ("exposed-panel", "medium", "10.0.0.6", "8080", None),
         ("weak-cipher", "low", "10.0.0.7", "443", None)]


def issue(client, iid):
    with client.app.state.SessionLocal() as db:
        return db.get(Issue, iid)


def audit_actions(client):
    with client.app.state.SessionLocal() as db:
        return [a.action for a in db.scalars(select(AuditLog))]


def test_issue_list_kpis_and_filters(auth):
    ids = seed(auth, SPECS)
    with auth.app.state.SessionLocal() as db:
        db.get(Issue, ids["exposed-panel"]).due_at = utcnow() - timedelta(days=1)
        db.commit()
    r = auth.get("/issues")
    assert r.status_code == 200
    for text in ("CVE-2021-41773 title", "exposed-panel title", "weak-cipher title", "10.0.0.5:443", "Overdue"):
        assert text in r.text, text
    assert r.text.index("CVE-2021-41773 title") < r.text.index("weak-cipher title")  # severity order
    assert 'data-kpi="active">3<' in r.text and 'data-kpi="overdue">1<' in r.text and 'data-kpi="unassigned">3<' in r.text
    assert "weak-cipher title" not in auth.get("/issues?severity=critical").text
    r = auth.get("/issues?overdue=1")
    assert "exposed-panel title" in r.text and "weak-cipher title" not in r.text
    r = auth.get("/issues?q=10.0.0.7")
    assert "weak-cipher title" in r.text and "exposed-panel title" not in r.text
    r = auth.get("/issues?view=closed")
    assert "No issues" in r.text


def test_issue_detail_and_actions(auth):
    ids = seed(auth, SPECS)
    iid = ids["CVE-2021-41773"]
    r = auth.get(f"/issues/{iid}")
    assert r.status_code == 200 and "Confirmed" in r.text and "job #" in r.text.lower() and "Created" in r.text
    csrf = get_csrf(auth, f"/issues/{iid}")
    me = auth.app.state.SessionLocal().scalar(select(User.id).where(User.username == "admin"))

    r = auth.post(f"/issues/{iid}/assign", data={"csrf": csrf, "assignee": str(me)}, follow_redirects=False)
    assert r.status_code == 303 and issue(auth, iid).assignee_id == me
    r = auth.post(f"/issues/{iid}/status", data={"csrf": csrf, "status": "in_progress", "comment": "patching"}, follow_redirects=False)
    assert r.status_code == 303 and issue(auth, iid).status == "in_progress"
    r = auth.post(f"/issues/{iid}/status", data={"csrf": csrf, "status": "accepted_risk", "comment": ""})
    assert r.status_code == 400 and "needs a reason" in r.text
    r = auth.post(f"/issues/{iid}/status", data={"csrf": csrf, "status": "verified"})
    assert r.status_code == 400 and "Cannot move" in r.text
    r = auth.post(f"/issues/{iid}/severity", data={"csrf": csrf, "severity": "high"}, follow_redirects=False)
    assert r.status_code == 303 and issue(auth, iid).severity == "high" and issue(auth, iid).severity_overridden
    r = auth.post(f"/issues/{iid}/comment", data={"csrf": csrf, "body": "Vendor patch 2.4.51 applied"}, follow_redirects=False)
    assert r.status_code == 303
    page = auth.get(f"/issues/{iid}").text
    assert "Vendor patch 2.4.51 applied" in page and "patching" in page
    assert {"issue.assigned", "issue.status_changed", "issue.severity_changed", "issue.commented"} <= set(audit_actions(auth))
    assert "CVE-2021-41773 title" in auth.get("/issues?assignee=me").text
    assert "CVE-2021-41773 title" not in auth.get("/issues?assignee=none").text
    assert auth.get("/issues/99999").status_code == 404


def test_bulk_actions(auth):
    ids = seed(auth, SPECS)
    me = auth.app.state.SessionLocal().scalar(select(User.id).where(User.username == "admin"))
    csrf = get_csrf(auth, "/issues")
    all_ids = [str(i) for i in ids.values()]
    r = auth.post("/issues/bulk", data={"csrf": csrf, "issue_ids": all_ids, "action": "assign", "assignee": str(me)},
                  follow_redirects=False)
    assert r.status_code == 303 and "Updated+3" in r.headers["location"]
    assert all(issue(auth, i).assignee_id == me for i in ids.values())
    auth.post(f"/issues/{ids['weak-cipher']}/status", data={"csrf": csrf, "status": "fixed"})
    r = auth.post("/issues/bulk", data={"csrf": csrf, "issue_ids": all_ids, "action": "status", "status": "triaged"},
                  follow_redirects=False)
    assert "Updated+2" in r.headers["location"] and "skipped+1" in r.headers["location"]
    assert issue(auth, ids["weak-cipher"]).status == "fixed"
    r = auth.post("/issues/bulk", data={"csrf": csrf, "action": "status", "status": "triaged"})
    assert r.status_code == 400
    assert "issue.bulk_updated" in audit_actions(auth)


def test_viewer_reads_but_cannot_triage(auth):
    ids = seed(auth, SPECS)
    iid = ids["CVE-2021-41773"]
    make_user(auth, "vee", "viewer")
    login_as(auth, "vee")
    r = auth.get(f"/issues/{iid}")
    assert r.status_code == 200 and 'action="/issues/' + str(iid) + '/status"' not in r.text
    assert 'name="issue_ids"' not in auth.get("/issues").text
    csrf = get_csrf(auth, "/issues")
    for path, data in ((f"/issues/{iid}/status", {"status": "triaged"}), (f"/issues/{iid}/assign", {"assignee": ""}),
                       (f"/issues/{iid}/severity", {"severity": "low"}), (f"/issues/{iid}/comment", {"body": "x"}),
                       ("/issues/bulk", {"issue_ids": [str(iid)], "action": "status", "status": "triaged"})):
        assert auth.post(path, data={"csrf": csrf, **data}).status_code == 403, path


def test_analyst_triages_but_cannot_change_sla(auth):
    ids = seed(auth, SPECS)
    make_user(auth, "ana", "analyst")
    login_as(auth, "ana")
    csrf = get_csrf(auth, "/issues")
    r = auth.post(f"/issues/{ids['exposed-panel']}/status", data={"csrf": csrf, "status": "triaged"}, follow_redirects=False)
    assert r.status_code == 303
    assert auth.get("/settings").status_code == 403


def test_sla_settings_page(auth):
    ids = seed(auth, SPECS)
    r = auth.get("/settings")
    assert r.status_code == 200 and re.search(r'name="critical"[^>]*value="3"', r.text)
    csrf = get_csrf(auth, "/settings")
    r = auth.post("/settings", data={"csrf": csrf, "critical": "1", "high": "5", "medium": "20", "low": "60"}, follow_redirects=False)
    assert r.status_code == 303
    i = issue(auth, ids["CVE-2021-41773"])
    assert i.due_at == i.first_seen + timedelta(days=1)
    r = auth.post("/settings", data={"csrf": csrf, "critical": "0", "high": "5", "medium": "20", "low": "60"})
    assert r.status_code == 400 and "between 1 and 3650" in r.text
    assert "settings.updated" in audit_actions(auth)


def test_dashboard_and_findings_link_issues(auth):
    ids = seed(auth, SPECS)
    r = auth.get("/")
    assert 'href="/issues"' in r.text and "Active issues" in r.text
    r = auth.get("/findings")
    assert f'href="/issues/{ids["CVE-2021-41773"]}"' in r.text
