import json

import pytest
from sqlalchemy import select

from app import proof
from app import reverify as rv
from app.db import Finding, Issue, IssueEvent, Job, Rule
from app.proof import PROOF_LIMIT, proof_from_finding
from app.rules import evaluate_rules
from app.templates_index import reindex
from tests.conftest import wait_job
from tests.test_inventory import seed_inventory
from tests.test_issue_routes import seed

CVE = "CVE-2026-109619"   # fixture template; the fake nuclei reports it on http://192.168.1.10:8080
SPECS = [(CVE, "critical", "192.168.1.10", "8080", CVE), ("exposed-panel", "medium", "10.0.0.6", "8080", None)]


def finding(raw: dict, **cols) -> Finding:
    base = dict(id=7, job_id=3, template_id="CVE-2026-109619", template_name="PHP UAF", severity="critical",
                host="http://192.0.2.11:8080", matched_at="http://192.0.2.11:8080/index.php", type="http")
    base.update(cols)
    return Finding(raw_json=json.dumps(raw), **base)


def test_http_finding_has_request_response_curl_and_matcher():
    raw = {"request": "GET /index.php HTTP/1.1\r\nHost: x\r\n\r\n", "response": "HTTP/1.1 200 OK\r\n\r\nX-Powered-By: PHP/8.3.10",
           "curl-command": "curl -X GET http://192.0.2.11:8080/index.php", "matcher-name": "version", "matcher-status": True,
           "extracted-results": ["8.3.10"], "timestamp": "2026-10-31T09:00:00Z"}
    p = proof_from_finding(finding(raw))
    assert p["has_http"] is True
    assert p["request"]["text"].startswith("GET /index.php") and p["request"]["rest"] == ""
    assert "PHP/8.3.10" in p["response"]["text"]
    assert p["curl"].startswith("curl ") and p["matcher"] == "version" and p["extracted"] == ["8.3.10"]
    assert p["finding_id"] == 7 and p["job_id"] == 3 and p["timestamp"] == "2026-10-31T09:00:00Z"


def test_non_http_finding_only_has_metadata():
    p = proof_from_finding(finding({"matcher-status": True}, type="tcp", matched_at="203.0.113.40:6379"))
    assert p["has_http"] is False and p["request"] is None and p["response"] is None and p["curl"] == ""
    assert p["matched_at"] == "203.0.113.40:6379" and p["type"] == "tcp"


def test_long_response_is_split_at_the_limit_and_bad_json_is_tolerated():
    p = proof_from_finding(finding({"response": "A" * (PROOF_LIMIT + 10)}))
    assert len(p["response"]["text"]) == PROOF_LIMIT and p["response"]["rest"] == "A" * 10
    assert proof_from_finding(Finding(id=1, job_id=1, raw_json="{not json"))["has_http"] is False
    assert proof_from_finding(Finding(id=1, job_id=1, raw_json="[]"))["has_http"] is False
    assert proof_from_finding(finding({"extracted-results": "8.3.10"}))["extracted"] == ["8.3.10"]
    assert proof_from_finding(None) is None


@pytest.fixture
def env(auth):
    seed_inventory(auth)
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
        db.commit()
    return auth


def get(client, iid):
    with client.app.state.SessionLocal() as db:
        i = db.get(Issue, iid)
        db.expunge(i)
        return i


def events(client, iid):
    with client.app.state.SessionLocal() as db:
        return [(e.kind, e.body) for e in db.scalars(select(IssueEvent).where(IssueEvent.issue_id == iid).order_by(IssueEvent.id))]


def start(client, iid):
    def _go():
        with client.app.state.SessionLocal() as db:
            return proof.start_verify(db, client.app, db.get(Issue, iid), actor=None).id
    return client.portal.call(_go)


def test_start_verify_runs_the_template_against_the_asset_and_reproduces(env):
    ids = seed(env, SPECS)
    iid = ids[CVE]
    jid = start(env, iid)
    with env.app.state.SessionLocal() as db:
        job = db.get(Job, jid)
        params = json.loads(job.params_json)
        assert params["verify_issue"] == iid and params["targets"] == ["http://192.168.1.10:8080"]
        assert params["template_ids"] == [CVE] and CVE + ".yaml" in job.command
    assert any(kind == "verify" and "started" in body for kind, body in events(env, iid))
    wait_job(env, jid)   # the fake nuclei finishes fast, so verify_job_id is only checked after completion
    i = get(env, iid)
    assert i.verify_result == "reproduced" and i.verify_job_id is None and i.last_verified_at is not None
    assert i.confidence == "verified" and i.verified_finding_id is not None
    assert any(kind == "verify" and "reproduced it" in body for kind, body in events(env, iid))


def test_complete_verify_not_reproduced_and_inconclusive(env):
    ids = seed(env, SPECS)
    iid = ids[CVE]
    with env.app.state.SessionLocal() as db:
        job = Job(kind="nuclei", status="done", params_json=json.dumps({"verify_issue": iid}))
        db.add(job)
        db.flush()
        db.get(Issue, iid).verify_job_id = job.id
        assert proof.complete_verify(db, job, []) == "not_reproduced"
        db.commit()
    assert get(env, iid).verify_result == "not_reproduced"
    assert any("did not reproduce" in body for kind, body in events(env, iid) if kind == "verify")
    with env.app.state.SessionLocal() as db:
        job = Job(kind="nuclei", status="done", params_json=json.dumps({"verify_issue": iid}))
        db.add(job)
        db.flush()
        db.get(Issue, iid).verify_job_id = job.id
        assert proof.complete_verify(db, job, ["Target was dropped as unresponsive"]) == "inconclusive"
        db.commit()
    assert get(env, iid).verify_result == "inconclusive"
    with env.app.state.SessionLocal() as db:   # a stale job (not the one on the issue) is ignored
        job = Job(kind="nuclei", status="done", params_json=json.dumps({"verify_issue": iid}))
        db.add(job)
        db.flush()
        assert proof.complete_verify(db, job, []) == ""


def test_start_verify_errors(env):
    ids = seed(env, SPECS)
    with env.app.state.SessionLocal() as db:
        with pytest.raises(proof.VerifyError, match="not in the template index"):
            proof.start_verify(db, env.app, db.get(Issue, ids["exposed-panel"]), actor=None)
        db.add(Rule(name="PHP", product_pattern="php", version_constraint="< 8.3.15", cve_id="CVE-2026-1", severity="high"))
        db.commit()
        evaluate_rules(db)
        db.commit()
        suspected = db.scalar(select(Issue).where(Issue.vuln_id == "CVE-2026-1"))
        assert suspected.template_id == ""
        with pytest.raises(proof.VerifyError, match="no nuclei template"):
            proof.start_verify(db, env.app, suspected, actor=None)


def test_dead_verify_job_is_cleaned_up_by_the_reverify_tick_but_a_running_one_is_kept(env):
    ids = seed(env, SPECS)
    dead, live = ids[CVE], ids["exposed-panel"]
    with env.app.state.SessionLocal() as db:
        failed = Job(kind="nuclei", status="failed", params_json=json.dumps({"verify_issue": dead}))
        running = Job(kind="nuclei", status="running", params_json=json.dumps({"verify_issue": live}))
        db.add_all([failed, running])
        db.flush()
        db.get(Issue, dead).verify_job_id = failed.id
        db.get(Issue, live).verify_job_id = running.id
        db.commit()
        running_id = running.id
    assert env.portal.call(rv.run_reverify, env.app) == []
    i = get(env, dead)
    assert i.verify_job_id is None and i.verify_result == ""
    assert any("failed" in body for kind, body in events(env, dead) if kind == "verify")
    assert get(env, live).verify_job_id == running_id
    assert not any(kind == "verify" for kind, _ in events(env, live))


def test_complete_verify_counts_an_info_template_match_as_reproduced(env):
    """issues_from_findings skips info findings, so Finding.issue_id is unset; the verify job only ran one template on one asset."""
    ids = seed(env, SPECS)
    iid = ids[CVE]
    with env.app.state.SessionLocal() as db:
        issue = db.get(Issue, iid)
        issue.template_id, issue.confidence, issue.status = "php-detect", "suspected", "fixed"
        job = Job(kind="nuclei", status="done", params_json=json.dumps({"verify_issue": iid}))
        db.add(job)
        db.flush()
        issue.verify_job_id = job.id
        f = Finding(job_id=job.id, template_id="php-detect", template_name="PHP Detect", severity="info", issue_id=None,
                    host="http://192.168.1.10:8080", matched_at="http://192.168.1.10:8080/", raw_json="{}")
        db.add(f)
        db.flush()
        assert proof.complete_verify(db, job, []) == "reproduced"
        db.commit()
        fid = f.id
    with env.app.state.SessionLocal() as db:
        assert db.get(Finding, fid).issue_id == iid
    i = get(env, iid)
    assert i.verify_result == "reproduced" and i.confidence == "verified" and i.verified_finding_id == fid
    assert i.status == "triaged" and i.resolved_at is None   # a closed issue that reproduces is reopened
    assert ("confirmed", f"verification job #{job.id}") in events(env, iid)
    assert ("reopened", f"Seen again: verification job #{job.id}") in events(env, iid)


def confidence_events(client, iid):
    with client.app.state.SessionLocal() as db:
        return [(e.from_value, e.to_value, e.body) for e in db.scalars(
            select(IssueEvent).where(IssueEvent.issue_id == iid, IssueEvent.kind == "confirmed").order_by(IssueEvent.id))]


def verify_job(db, iid):
    job = Job(kind="nuclei", status="done", params_json=json.dumps({"verify_issue": iid}))
    db.add(job)
    db.flush()
    db.get(Issue, iid).verify_job_id = job.id
    return job


def test_reproduced_marks_the_issue_verified_and_not_reproduced_takes_it_back(env):
    ids = seed(env, SPECS)
    iid = ids[CVE]
    with env.app.state.SessionLocal() as db:
        job = verify_job(db, iid)
        f = Finding(job_id=job.id, template_id=CVE, template_name="PHP", severity="critical", issue_id=iid,
                    host="http://192.168.1.10:8080", matched_at="http://192.168.1.10:8080/", raw_json="{}")
        db.add(f)
        db.flush()
        assert proof.complete_verify(db, job, []) == "reproduced"
        db.commit()
        fid, jid = f.id, job.id
    i = get(env, iid)
    assert i.confidence == "verified" and i.verified_finding_id == fid
    assert confidence_events(env, iid)[-1] == ("confirmed", "verified", f"Verified by job #{jid}; proof captured.")

    with env.app.state.SessionLocal() as db:   # inconclusive changes nothing
        job = verify_job(db, iid)
        assert proof.complete_verify(db, job, ["Target was dropped as unresponsive"]) == "inconclusive"
        db.commit()
    i = get(env, iid)
    assert i.confidence == "verified" and i.verified_finding_id == fid

    with env.app.state.SessionLocal() as db:
        job = verify_job(db, iid)
        assert proof.complete_verify(db, job, []) == "not_reproduced"
        db.commit()
        jid = job.id
    i = get(env, iid)
    assert i.confidence == "confirmed" and i.verified_finding_id is None
    assert confidence_events(env, iid)[-1] == (
        "verified", "confirmed", f"Verification job #{jid} did not reproduce it; confidence back to confirmed.")


def test_not_reproduced_leaves_a_confirmed_issue_confirmed(env):
    ids = seed(env, SPECS)
    iid = ids[CVE]
    with env.app.state.SessionLocal() as db:
        assert proof.complete_verify(db, verify_job(db, iid), []) == "not_reproduced"
        db.commit()
    assert get(env, iid).confidence == "confirmed" and confidence_events(env, iid) == []
