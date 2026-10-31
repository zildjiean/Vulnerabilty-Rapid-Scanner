import json

import pytest
from sqlalchemy import select

from app.db import AuditLog, Issue, Job, Rule
from app.rules import evaluate_rules
from app.templates_index import reindex
from tests.conftest import get_csrf, wait_job
from tests.test_inventory import seed_inventory
from tests.test_issue_routes import seed
from tests.test_rbac import login_as, make_user

CVE = "CVE-2026-109619"
SPECS = [(CVE, "critical", "192.168.1.10", "8080", CVE), ("exposed-panel", "medium", "10.0.0.6", "8080", None)]


@pytest.fixture
def env(auth):
    seed_inventory(auth)
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
        db.commit()
    return auth


def suspected_issue(client, cve="CVE-2026-1"):
    with client.app.state.SessionLocal() as db:
        db.add(Rule(name="PHP", product_pattern="php", version_constraint="< 8.3.15", cve_id=cve, severity="high"))
        db.commit()
        evaluate_rules(db)
        db.commit()
        return db.scalar(select(Issue.id).where(Issue.vuln_id == cve))


def test_verify_button_starts_a_job_and_blocks_a_second_click(env, monkeypatch):
    iid = seed(env, SPECS)[CVE]
    started = []   # keep the job queued so the "running" state is deterministic (the fake nuclei finishes instantly)
    monkeypatch.setattr(env.app.state.job_runner, "start", lambda job_id, argv, **kw: started.append(job_id))
    page = env.get(f"/issues/{iid}").text
    assert "Verify now" in page and f'action="/issues/{iid}/verify"' in page
    r = env.post(f"/issues/{iid}/verify", data={"csrf": get_csrf(env, f"/issues/{iid}")}, follow_redirects=False)
    assert r.status_code == 303 and "Verification+started" in r.headers["location"]
    with env.app.state.SessionLocal() as db:
        issue = db.get(Issue, iid)
        assert issue.verify_job_id == started[0]
        assert json.loads(db.get(Job, started[0]).params_json)["verify_issue"] == iid
        assert db.scalar(select(AuditLog).where(AuditLog.action == "issue.verify")) is not None
    page = env.get(f"/issues/{iid}").text
    assert f"verifying (job #{started[0]})" in page and "Verify now" not in page
    r = env.post(f"/issues/{iid}/verify", data={"csrf": get_csrf(env, f"/issues/{iid}")}, follow_redirects=False)
    assert "already+running" in r.headers["location"] and len(started) == 1


def test_completed_verification_shows_result_and_timeline(env):
    iid = seed(env, SPECS)[CVE]
    r = env.post(f"/issues/{iid}/verify", data={"csrf": get_csrf(env, f"/issues/{iid}")}, follow_redirects=False)
    assert r.status_code == 303
    with env.app.state.SessionLocal() as db:
        jid = db.scalar(select(Job.id).order_by(Job.id.desc()))
    wait_job(env, jid)
    page = env.get(f"/issues/{iid}").text
    assert "reproduced" in page and "Verify now" in page and "Proof captured" in page


def test_verify_with_back_redirects_to_the_list_and_errors_go_to_err(env):
    ids = seed(env, SPECS)
    r = env.post(f"/issues/{ids[CVE]}/verify", data={"csrf": get_csrf(env, "/issues"), "back": "/issues?view=active"},
                 follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/issues?view=active&msg=")
    r = env.post(f"/issues/{ids['exposed-panel']}/verify", data={"csrf": get_csrf(env, "/issues"), "back": "/issues"},
                 follow_redirects=False)
    assert "err=" in r.headers["location"] and "template+index" in r.headers["location"]
    r = env.post(f"/issues/{ids['exposed-panel']}/verify", data={"csrf": get_csrf(env, "/issues")})
    assert r.status_code == 400 and "not in the template index" in r.text
    # an external back URL is ignored
    r = env.post(f"/issues/{ids[CVE]}/verify", data={"csrf": get_csrf(env, "/issues"), "back": "//evil.example/x"},
                 follow_redirects=False)
    assert r.headers["location"].startswith(f"/issues/{ids[CVE]}?")
    with env.app.state.SessionLocal() as db:   # do not leave the verification subprocess running at teardown
        wait_job(env, db.scalar(select(Job.id).where(Job.kind == "nuclei").order_by(Job.id.desc())))


def test_issue_without_template_is_sent_to_the_verify_card(env):
    iid = suspected_issue(env)
    r = env.post(f"/issues/{iid}/verify", data={"csrf": get_csrf(env, f"/issues/{iid}")}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/issues/{iid}#verify"


def test_viewer_sees_no_button_and_cannot_verify(env):
    iid = seed(env, SPECS)[CVE]
    make_user(env, "vera", "viewer")
    login_as(env, "vera")
    assert "Verify now" not in env.get(f"/issues/{iid}").text
    r = env.post(f"/issues/{iid}/verify", data={"csrf": get_csrf(env, f"/issues/{iid}")})
    assert r.status_code == 403
