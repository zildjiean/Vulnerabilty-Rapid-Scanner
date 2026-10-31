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


def test_huge_response_is_capped_with_a_count_of_what_is_not_shown():
    p = proof_from_finding(finding({"response": "A" * (proof.REPORT_FULL_LIMIT + 123), "request": "GET /"}))
    assert len(p["response"]["text"]) + len(p["response"]["rest"]) == proof.REPORT_FULL_LIMIT
    assert p["response"]["omitted"] == 123 and p["request"]["omitted"] == 0


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


# ----------------------------------------------------------------- bulk verify
def start_many(client, ids):
    def _go():
        with client.app.state.SessionLocal() as db:
            issues = [db.get(Issue, i) for i in ids]
            return proof.start_verify_many(db, client.app, issues, actor=None)
    return client.portal.call(_go)


@pytest.fixture
def held(env, monkeypatch):
    """Keep started jobs queued (the fake nuclei would finish instantly) and record their ids."""
    started = []
    monkeypatch.setattr(env.app.state.job_runner, "start", lambda job_id, argv, **kw: started.append(job_id))
    return started


def php_detect_issue(client, address="192.168.1.10", port="8080"):
    """A second issue whose template (php-detect) is indexed, on its own asset."""
    from app.issues import upsert_issue
    from app.db import utcnow
    with client.app.state.SessionLocal() as db:
        issue, _ = upsert_issue(db, address=address, port=port, hostname="", vuln_id="php-detect", cve_id="",
                                template_id="php-detect", rule_id=None, title="PHP detect", severity="low",
                                confidence="confirmed", seen_at=utcnow(), source="test", count_sighting=True, reopen=True)
        db.commit()
        return issue.id


def test_start_verify_many_groups_by_template_and_dedupes_targets(env, held):
    seed(env, SPECS)
    seed(env, [(CVE, "critical", "10.0.0.6", "8080", None)])   # same template, another asset
    detect = php_detect_issue(env)
    with env.app.state.SessionLocal() as db:
        cve_issues = list(db.scalars(select(Issue.id).where(Issue.template_id == CVE)))
    res = start_many(env, cve_issues + [detect])
    assert len(res.jobs) == 2 and res.issues == len(cve_issues) + 1 and sum(res.skipped.values()) == 0
    with env.app.state.SessionLocal() as db:
        by_template = {}
        for jid in res.jobs:
            p = json.loads(db.get(Job, jid).params_json)
            by_template[p["template_ids"][0]] = p
            assert p["mode"] == "selected" and p["profile"] == "normal" and "verify_issue" not in p
        assert sorted(by_template) == [CVE, "php-detect"]
        assert sorted(by_template[CVE]["verify_issues"]) == sorted(cve_issues)
        assert len(by_template[CVE]["targets"]) == len(set(by_template[CVE]["targets"]))
        assert by_template["php-detect"]["verify_issues"] == [detect]
        for iid in cve_issues + [detect]:
            assert db.get(Issue, iid).verify_job_id in res.jobs
    assert any(kind == "verify" and "started" in body for kind, body in events(env, detect))


def test_start_verify_many_skips_by_reason_and_limit(env, held, monkeypatch):
    ids = seed(env, SPECS)
    with env.app.state.SessionLocal() as db:
        db.add(Rule(name="PHP", product_pattern="php", version_constraint="< 8.3.15", cve_id="CVE-2026-1", severity="high"))
        db.commit()
        evaluate_rules(db)
        db.commit()
        no_template = db.scalar(select(Issue.id).where(Issue.vuln_id == "CVE-2026-1"))
    res = start_many(env, [ids[CVE]])
    assert len(res.jobs) == 1
    res = start_many(env, [ids[CVE], ids["exposed-panel"], no_template])   # running, not indexed, no template
    assert res.jobs == [] and res.issues == 0
    assert res.skipped == {"running": 1, "not_indexed": 1, "no_template": 1}
    text = res.summary()
    assert text.startswith("Started 0 job(s) for 0 issue(s); skipped") and "1 (already running)" in text
    assert "1 (no template)" in text and "1 (template not indexed)" in text
    monkeypatch.setattr(proof, "BULK_LIMIT", 1)
    extra = php_detect_issue(env)
    with env.app.state.SessionLocal() as db:
        db.get(Issue, ids[CVE]).verify_job_id = None
        db.commit()
    # skipped issues do not use up the limit; duplicates count once
    res = start_many(env, [no_template, ids["exposed-panel"], ids[CVE], ids[CVE], extra])
    assert len(res.jobs) == 1 and res.issues == 1
    assert res.skipped == {"no_template": 1, "not_indexed": 1, "over_limit": 1} and "1 (over limit)" in res.summary()
    with env.app.state.SessionLocal() as db:
        p = json.loads(db.get(Job, res.jobs[0]).params_json)
    assert p["verify_issues"] == [ids[CVE]] and p["verify_targets"] == {str(ids[CVE]): "http://192.168.1.10:8080"}


def test_complete_verify_many_info_fallback_matches_the_issues_own_target(env):
    ids = seed(env, SPECS)
    seed(env, [(CVE, "critical", "10.0.0.6", "8443", None)])   # same template, another asset
    with env.app.state.SessionLocal() as db:
        a = ids[CVE]
        b = db.scalar(select(Issue.id).where(Issue.template_id == CVE, Issue.address == "10.0.0.6"))
        db.get(Issue, a).confidence = "confirmed"
        db.get(Issue, b).confidence, db.get(Issue, b).verified_finding_id = "verified", None
        job = Job(kind="nuclei", status="done", params_json=json.dumps({
            "verify_issues": [a, b], "verify_targets": {str(a): "http://192.168.1.10:8080", str(b): "https://10.0.0.6:8443"}}))
        db.add(job)
        db.flush()
        db.get(Issue, a).verify_job_id = job.id
        db.get(Issue, b).verify_job_id = job.id
        # the job found the template on asset a only (unlinked, like an info template)
        f = Finding(job_id=job.id, template_id=CVE, template_name="PHP", severity="critical", issue_id=None,
                    host="http://192.168.1.10:8080", matched_at="http://192.168.1.10:8080/", raw_json="{}")
        db.add(f)
        db.flush()
        out = proof.complete_verify_many(db, job, [])
        db.commit()
        fid, jid = f.id, job.id
    assert out == {"reproduced": 1, "not_reproduced": 1}
    ia, ib = get(env, a), get(env, b)
    assert ia.verify_result == "reproduced" and ia.confidence == "verified" and ia.verified_finding_id == fid
    assert ia.verify_job_id is None and ia.last_verified_at is not None
    assert ib.verify_result == "not_reproduced" and ib.confidence == "confirmed" and ib.verify_job_id is None
    assert any(f"job #{jid} did not reproduce" in body for kind, body in events(env, b) if kind == "verify")


def test_complete_verify_many_ignores_a_finding_linked_to_another_issue(env):
    """Reviewer probe: issue A keyed www.x.com:443, issue B 10.0.0.2:443 with hostname www.x.com. Only www.x.com
    answered (resolving to 10.0.0.1), so ingest linked the finding to a third issue; neither A nor B is reproduced."""
    from app.db import utcnow
    from app.issues import upsert_issue
    with env.app.state.SessionLocal() as db:
        def mk(address, hostname):
            i, _ = upsert_issue(db, address=address, port="443", hostname=hostname, vuln_id=CVE, cve_id=CVE,
                                template_id=CVE, rule_id=None, title="PHP", severity="critical", confidence="confirmed",
                                seen_at=utcnow(), source="test", count_sighting=True, reopen=True)
            return i
        ia, ib, ic = mk("www.x.com", ""), mk("10.0.0.2", "www.x.com"), mk("10.0.0.1", "www.x.com")
        db.flush()
        job = Job(kind="nuclei", status="done", params_json=json.dumps({
            "verify_issues": [ia.id, ib.id], "verify_targets": {str(ia.id): "https://www.x.com:443",
                                                                 str(ib.id): "https://10.0.0.2:443"}}))
        db.add(job)
        db.flush()
        ia.verify_job_id = ib.verify_job_id = job.id
        db.add(Finding(job_id=job.id, template_id=CVE, severity="critical", issue_id=ic.id, host="https://www.x.com",
                       matched_at="https://www.x.com/", raw_json=json.dumps({"ip": "10.0.0.1"})))
        db.flush()
        assert proof.complete_verify_many(db, job, []) == {"not_reproduced": 2}
        db.commit()
        a, b = ia.id, ib.id
    for iid in (a, b):
        i = get(env, iid)
        assert i.verify_result == "not_reproduced" and i.verified_finding_id is None and i.confidence == "confirmed"


def test_complete_verify_many_counts_the_finding_ingest_linked_to_the_issue(env):
    ids = seed(env, SPECS)
    with env.app.state.SessionLocal() as db:
        job = Job(kind="nuclei", status="done", params_json=json.dumps({"verify_issues": [ids[CVE]], "verify_targets": {}}))
        db.add(job)
        db.flush()
        db.get(Issue, ids[CVE]).verify_job_id = job.id
        f = Finding(job_id=job.id, template_id=CVE, severity="critical", issue_id=ids[CVE], host="http://elsewhere:1",
                    matched_at="http://elsewhere:1/", raw_json="{}")
        db.add(f)
        db.flush()
        assert proof.complete_verify_many(db, job, []) == {"reproduced": 1}
        db.commit()
        fid = f.id
    assert get(env, ids[CVE]).verified_finding_id == fid


def test_complete_verify_many_inconclusive_and_stale_and_end_to_end(env):
    ids = seed(env, SPECS)
    with env.app.state.SessionLocal() as db:
        job = Job(kind="nuclei", status="done", params_json=json.dumps({"verify_issues": [ids[CVE], ids["exposed-panel"]]}))
        db.add(job)
        db.flush()
        db.get(Issue, ids[CVE]).verify_job_id = job.id     # exposed-panel's verify_job_id is not this job: ignored
        assert proof.complete_verify_many(db, job, ["Target dropped"]) == {"inconclusive": 1}
        db.commit()
    assert get(env, ids[CVE]).verify_result == "inconclusive" and get(env, ids["exposed-panel"]).verify_result == ""
    # end to end through the nuclei completion hook: the fake nuclei reports CVE on 192.168.1.10:8080
    res = start_many(env, [ids[CVE]])
    wait_job(env, res.jobs[0])
    i = get(env, ids[CVE])
    assert i.verify_result == "reproduced" and i.confidence == "verified" and i.verify_job_id is None
    with env.app.state.SessionLocal() as db:
        assert json.loads(db.get(Job, res.jobs[0]).params_json)["result"]["verify"] == {"reproduced": 1}
