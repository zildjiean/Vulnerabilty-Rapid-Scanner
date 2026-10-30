import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app import issues as iss
from app import reverify as rv
from app.db import Issue, IssueEvent, Job, Rule, utcnow
from app.rules import evaluate_rules
from app.templates_index import reindex
from tests.conftest import wait_job
from tests.test_inventory import seed_inventory
from tests.test_issue_routes import seed

CVE = "CVE-2026-109619"   # indexed fixture template
SPECS = [(CVE, "critical", "192.168.1.10", "8080", CVE), (CVE, "critical", "192.168.1.11", "80", CVE),
         ("exposed-panel", "medium", "10.0.0.6", "8080", None)]


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


def set_status(client, iid, status, back_minutes=0):
    with client.app.state.SessionLocal() as db:
        i = db.get(Issue, iid)
        iss.change_status(db, i, status, actor=None, comment="x" if status in iss.NEEDS_REASON else "")
        if back_minutes and i.reverify_requested_at:
            i.reverify_requested_at -= timedelta(minutes=back_minutes)
        db.commit()


def ids_for(client, ip):
    with client.app.state.SessionLocal() as db:
        return db.scalar(select(Issue.id).where(Issue.address == ip))


def test_request_is_set_only_for_confirmed_fixed_issues(env):
    seed(env, SPECS)
    a, panel = ids_for(env, "192.168.1.10"), ids_for(env, "10.0.0.6")
    set_status(env, a, "fixed")
    assert get(env, a).reverify_requested_at is not None
    set_status(env, a, "in_progress")
    assert get(env, a).reverify_requested_at is None
    with env.app.state.SessionLocal() as db:   # suspected issues are verified by inventory, not nuclei
        db.get(Issue, panel).confidence = "suspected"
        db.commit()
    set_status(env, panel, "fixed")
    assert get(env, panel).reverify_requested_at is None


def test_waits_for_delay_then_groups_by_template_and_verifies(env):
    seed(env, SPECS)
    a, b = ids_for(env, "192.168.1.10"), ids_for(env, "192.168.1.11")
    set_status(env, a, "fixed")
    set_status(env, b, "fixed")
    assert env.portal.call(rv.run_reverify, env.app) == []          # still inside the 15 minute delay
    for iid in (a, b):
        with env.app.state.SessionLocal() as db:
            db.get(Issue, iid).reverify_requested_at -= timedelta(minutes=16)
            db.commit()
    jobs = env.portal.call(rv.run_reverify, env.app)
    assert len(jobs) == 1                                              # one job per template
    with env.app.state.SessionLocal() as db:
        job = db.get(Job, jobs[0])
        params = json.loads(job.params_json)
        assert sorted(params["reverify"]) == sorted([a, b])
        assert set(params["targets"]) == {"http://192.168.1.10:8080", "192.168.1.11:80"}
        assert CVE + ".yaml" in job.command
    assert get(env, a).reverify_job_id == jobs[0]
    wait_job(env, jobs[0])   # the fake nuclei output still reports the CVE on 192.168.1.10:8080 only
    still_there, gone = get(env, a), get(env, b)
    assert still_there.status == "triaged" and still_there.reverify_requested_at is None
    assert any(kind == "reopened" for kind, _ in events(env, a))
    assert gone.status == "verified" and gone.reverify_requested_at is None
    assert any("did not find it" in body for kind, body in events(env, b))
    assert env.portal.call(rv.run_reverify, env.app) == []


def test_inconclusive_when_scan_has_warnings(env):
    seed(env, SPECS)
    a = ids_for(env, "192.168.1.10")
    set_status(env, a, "fixed")
    with env.app.state.SessionLocal() as db:
        job = Job(kind="nuclei", status="done", params_json=json.dumps({"reverify": [a]}))
        db.add(job)
        db.flush()
        db.get(Issue, a).reverify_job_id = job.id
        rv.complete_reverify(db, job, ["Target 192.168.1.10:8080 was dropped as unresponsive"])
        db.commit()
    i = get(env, a)
    assert i.status == "fixed" and i.reverify_requested_at is None
    assert any(kind == "reverify" and "inconclusive" in body.lower() for kind, body in events(env, a))


def test_seen_again_reopens_and_clears(env):
    seed(env, SPECS)
    a = ids_for(env, "192.168.1.10")
    set_status(env, a, "fixed")
    with env.app.state.SessionLocal() as db:
        job = Job(kind="nuclei", status="done", params_json=json.dumps({"reverify": [a]}))
        db.add(job)
        db.flush()
        db.get(Issue, a).reverify_job_id = job.id
        db.commit()
    seed(env, SPECS[:1])   # the re-scan finds it again
    with env.app.state.SessionLocal() as db:
        rv.complete_reverify(db, db.get(Job, job.id), [])
        db.commit()
    i = get(env, a)
    assert i.status == "triaged" and i.reverify_requested_at is None


def test_failed_job_is_cleaned_up(env):
    seed(env, SPECS)
    a = ids_for(env, "192.168.1.10")
    set_status(env, a, "fixed")
    with env.app.state.SessionLocal() as db:
        job = Job(kind="nuclei", status="failed", params_json=json.dumps({"reverify": [a]}))
        db.add(job)
        db.flush()
        db.get(Issue, a).reverify_job_id = job.id
        db.commit()
    assert env.portal.call(rv.run_reverify, env.app) == []
    i = get(env, a)
    assert i.status == "fixed" and i.reverify_requested_at is None and i.reverify_job_id is None
    assert any("failed" in body for kind, body in events(env, a) if kind == "reverify")


def test_disabled_and_missing_template(env):
    seed(env, SPECS)
    a, panel = ids_for(env, "192.168.1.10"), ids_for(env, "10.0.0.6")
    set_status(env, a, "fixed", back_minutes=30)
    set_status(env, panel, "fixed", back_minutes=30)   # template "exposed-panel" is not in the index
    with env.app.state.SessionLocal() as db:
        rv.set_reverify_settings(db, enabled=False, delay_minutes=15)
        db.commit()
    assert env.portal.call(rv.run_reverify, env.app) == []
    with env.app.state.SessionLocal() as db:
        rv.set_reverify_settings(db, enabled=True, delay_minutes=15)
        db.commit()
    jobs = env.portal.call(rv.run_reverify, env.app)
    assert len(jobs) == 1
    assert get(env, panel).reverify_requested_at is None
    assert any("not in the template index" in body for kind, body in events(env, panel))
    wait_job(env, jobs[0])
    with pytest.raises(ValueError):
        with env.app.state.SessionLocal() as db:
            rv.set_reverify_settings(db, enabled=True, delay_minutes=-1)


def test_suspected_fixed_issue_verified_by_next_inventory_scan(env):
    with env.app.state.SessionLocal() as db:
        db.add(Rule(name="PHP", product_pattern="php", version_constraint="< 8.3.15", cve_id=CVE, severity="critical"))
        db.commit()
        evaluate_rules(db)
        db.commit()
        issue = db.scalar(select(Issue).where(Issue.confidence == "suspected"))
        iss.change_status(db, issue, "fixed", actor=None)
        db.commit()
        evaluate_rules(db)   # nothing re-scanned yet: still fixed
        assert issue.status == "fixed"
        from app.db import Host, Service
        host = db.scalar(select(Host).where(Host.address == "192.168.1.10"))
        svc = db.scalar(select(Service).where(Service.host_id == host.id, Service.port == 8080))
        svc.version, host.last_seen = "8.3.20", utcnow() + timedelta(seconds=1)
        db.commit()
        evaluate_rules(db)
        db.commit()
        assert issue.status == "verified"


def test_settings_and_issue_page(env):
    from tests.conftest import get_csrf
    csrf = get_csrf(env, "/settings")
    r = env.post("/settings/reverify", data={"csrf": csrf, "delay_minutes": "5"}, follow_redirects=False)
    assert r.status_code == 303
    with env.app.state.SessionLocal() as db:
        assert rv.get_reverify_settings(db) == {"enabled": False, "delay_minutes": 5}
    assert env.post("/settings/reverify", data={"csrf": csrf, "enabled": "true", "delay_minutes": "-3"}).status_code == 400
    seed(env, SPECS)
    a = ids_for(env, "192.168.1.10")
    set_status(env, a, "fixed")
    assert "re-verify paused" in env.get(f"/issues/{a}").text
