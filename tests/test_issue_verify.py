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
    assert "verify-reproduced" in page and "Verify now" in page and "Proof captured" in page


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


def test_proof_card_shows_request_response_and_curl(env):
    iid = seed(env, SPECS)[CVE]
    long_body = "B" * 4100
    with env.app.state.SessionLocal() as db:
        from app.db import Finding
        f = db.scalar(select(Finding).where(Finding.issue_id == iid))
        raw = json.loads(f.raw_json)
        raw.update({"request": "GET /index.php HTTP/1.1\r\nHost: 192.168.1.10", "response": "HTTP/1.1 200 OK\r\n\r\n" + long_body,
                    "curl-command": "curl -X GET http://192.168.1.10:8080/index.php", "matcher-name": "php-version"})
        f.raw_json = json.dumps(raw)
        db.commit()
        first_id = f.id
    page = env.get(f"/issues/{iid}").text
    assert 'id="proof"' in page and "GET /index.php HTTP/1.1" in page and "php-version" in page
    assert 'data-copy="curl -X GET http://192.168.1.10:8080/index.php"' in page
    assert "data-proof-more" in page and 'class="proof-rest" hidden' in page        # 4,100 chars → split
    assert f"?proof={first_id}#proof" in page                                       # evidence row link
    # a second (non-HTTP) finding becomes the newest proof; ?proof= selects the old one
    seed(env, [("CVE-2026-109619", "critical", "192.168.1.10", "8080", CVE)])
    page = env.get(f"/issues/{iid}").text
    assert "did not record a request/response" in page
    assert "GET /index.php HTTP/1.1" in env.get(f"/issues/{iid}?proof={first_id}").text
    r = env.get(f"/issues/{iid}?proof=%C2%B2")          # '²'.isdigit() is True but int() rejects it
    assert r.status_code == 200 and "did not record a request/response" in r.text


def test_play_icons_in_list_and_campaign_only_for_scanners(env):
    ids = seed(env, SPECS)
    page = env.get("/issues").text
    assert f'action="/issues/{ids[CVE]}/verify"' in page and 'aria-label="Verify now' in page
    assert 'name="back" value="/issues"' in page
    # a stale flash in the list URL is replaced, not piled up
    r = env.post(f"/issues/{ids[CVE]}/verify", data={"csrf": get_csrf(env, "/issues"), "back": "/issues?view=active&msg=old"},
                 follow_redirects=False)
    assert r.headers["location"].count("msg=") == 1 and "msg=old" not in r.headers["location"]
    assert r.headers["location"].startswith("/issues?view=active&msg=")
    # the other two states: a live job shows the chip, no template shows the muted link
    with env.app.state.SessionLocal() as db:
        job = Job(kind="nuclei", status="running")
        db.add(job)
        db.flush()
        db.get(Issue, ids[CVE]).verify_job_id = job.id
        db.commit()
        jid = job.id
    page = env.get("/issues").text
    assert f'href="/jobs/{jid}"' in page and f'action="/issues/{ids[CVE]}/verify"' not in page
    assert f'class="play-btn muted" href="/issues/{ids["exposed-panel"]}#verify"' not in page   # it has a template
    sus = suspected_issue(env)
    assert f'class="play-btn muted" href="/issues/{sus}#verify"' in env.get("/issues").text
    with env.app.state.SessionLocal() as db:   # back to the idle state for the campaign checks below
        db.get(Issue, ids[CVE]).verify_job_id = None
        db.commit()
    from app.campaigns import create_campaign
    with env.app.state.SessionLocal() as db:
        c = create_campaign(db, name="PHP UAF", cve_id=CVE, description="", severity="critical", product_pattern="php",
                            version_constraint="< 8.3.15", attach_templates=False, intel=None, created_by="admin")
        db.commit()
        cid = c.id
    page = env.get(f"/campaigns/{cid}").text
    assert "/verify" in page and f'name="back" value="/campaigns/{cid}"' in page
    make_user(env, "vera", "viewer")
    login_as(env, "vera")
    assert "/verify" not in env.get("/issues").text and "/verify" not in env.get(f"/campaigns/{cid}").text
