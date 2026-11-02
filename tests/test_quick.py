"""Quick scan: nmap, then nuclei with a preset on the services found, as one guided action."""
import json
import re
import shutil
import time

import pytest
from sqlalchemy import select

from app import quick
from app.db import AuditLog, Host, Job
from app.routers.jobs import job_summary
from tests.conftest import FIXTURES, get_csrf, wait_job
from tests.test_rbac import login_as, make_user

NMAP_XML = (FIXTURES / "nmap_sample.xml").read_text()
SERVICES_10 = ["192.168.1.10:22", "http://192.168.1.10:80", "http://192.168.1.10:8080", "https://192.168.1.10:8443"]


class FakeRunner:
    def __init__(self, cancelled=False):
        self.started = []
        self.cancelled = cancelled

    def create_job(self, db, kind, argv, params=None):
        job = Job(kind=kind, status="queued", command=" ".join(argv), params_json=json.dumps(params or {}))
        db.add(job)
        db.commit()
        return job

    def start(self, job_id, argv, **kw):
        self.started.append((job_id, argv, kw))

    def cancel_requested(self, job_id):
        return self.cancelled


@pytest.fixture
def db(client):
    with client.app.state.SessionLocal() as s:
        yield s


def nmap_job(db, targets, level="standard"):
    job = Job(kind="nmap", status="running",
              params_json=json.dumps({"targets": targets, "quick": {"level": level, "step": 1}}))
    db.add(job)
    db.commit()
    return job


def params(job):
    return json.loads(job.params_json)


# ----------------------------------------------------------------- chain (hook)
def test_launch_quick_starts_nmap_with_level_options(client, db, settings):
    runner = FakeRunner()
    job = quick.launch_quick(db, settings, runner, ["192.168.1.10"], "thorough")
    p = params(job)
    assert job.kind == "nmap" and p["quick"] == {"level": "thorough", "step": 1} and p["port_mode"] == "all"
    jid, argv, kw = runner.started[0]
    assert jid == job.id and "-p-" in argv and "-T3" in argv and "-sS" in argv
    assert kw["on_complete"] is not None
    job = quick.launch_quick(db, settings, runner, ["192.168.1.10"], "standard")
    assert "--top-ports" in runner.started[1][1] or "-p-" not in runner.started[1][1]
    with pytest.raises(ValueError, match="Invalid scan level"):
        quick.launch_quick(db, settings, runner, ["192.168.1.10"], "bogus")


def test_hook_starts_nuclei_on_services_inside_targets(client, db, settings):
    runner = FakeRunner()
    job = nmap_job(db, ["192.168.1.10"])
    note = quick.quick_hook(settings, runner, "standard", ["192.168.1.10"])(db, job, NMAP_XML)
    db.commit()
    assert db.scalar(select(Host).where(Host.address == "192.168.1.12")) is not None  # ingest ran for everything
    nuclei = db.scalar(select(Job).where(Job.kind == "nuclei"))
    np_ = params(nuclei)
    assert np_["targets"] == SERVICES_10                                            # .12 is outside the targets
    assert np_["quick"] == {"level": "standard", "step": 2, "parent_job": job.id} and np_["preset"] == "recommended"
    assert params(job)["quick"]["nuclei_job"] == nuclei.id and "result" in params(job)
    assert f"[quick] nuclei step started: job #{nuclei.id} on 4 service(s)." in note and note.startswith("[nmap]")
    assert runner.started[0][0] == nuclei.id and "-severity" in runner.started[0][1]


def test_hook_thorough_uses_full_preset(client, db, settings):
    runner = FakeRunner()
    job = nmap_job(db, ["192.168.1.0/24"], "thorough")
    quick.quick_hook(settings, runner, "thorough", ["192.168.1.0/24"])(db, job, NMAP_XML)
    nuclei = db.scalar(select(Job).where(Job.kind == "nuclei"))
    assert params(nuclei)["preset"] == "full" and "-severity" not in runner.started[0][1]
    assert "192.168.1.12:3306" in params(nuclei)["targets"]


def test_hook_cancelled_starts_no_nuclei(client, db, settings):
    runner = FakeRunner(cancelled=True)
    job = nmap_job(db, ["192.168.1.10"])
    note = quick.quick_hook(settings, runner, "standard", ["192.168.1.10"])(db, job, NMAP_XML)
    assert "[quick] cancelled: nuclei step not started." in note
    assert db.scalar(select(Job).where(Job.kind == "nuclei")) is None and runner.started == []


def test_hook_no_services_skips_with_warning(client, db, settings):
    runner = FakeRunner()
    job = nmap_job(db, ["10.99.0.1"])
    note = quick.quick_hook(settings, runner, "standard", ["10.99.0.1"])(db, job, NMAP_XML)
    db.commit()
    assert "[quick] no open services found: nuclei step skipped." in note
    p = params(job)
    assert p["quick"]["nuclei"] == "skipped" and p["warnings"] and "result" in p
    assert db.scalar(select(Job).where(Job.kind == "nuclei")) is None


def test_hook_nuclei_start_error_is_a_warning(client, db, settings):
    shutil.rmtree(settings.nuclei_templates_dir)
    runner = FakeRunner()
    job = nmap_job(db, ["192.168.1.10"])
    note = quick.quick_hook(settings, runner, "standard", ["192.168.1.10"])(db, job, NMAP_XML)
    db.commit()
    assert "[quick] nuclei step could not start: No templates available yet" in note
    p = params(job)
    assert any("could not start" in w for w in p["warnings"]) and p["result"]["hosts"] == 2
    assert db.scalar(select(Job).where(Job.kind == "nuclei")) is None


def test_quick_targets_shared_helper(client, db):
    from app.scheduler import scope_services
    from app.scopes import services_in
    job = nmap_job(db, [])
    from app.scanners.nmap_runner import ingest_nmap_results
    ingest_nmap_results(db, job, NMAP_XML)
    db.commit()
    assert quick.quick_targets(db, ["192.168.1.10"]) == SERVICES_10
    assert quick.quick_targets(db, ["192.168.1.10-12"]) == SERVICES_10 + ["192.168.1.12:3306"]
    assert quick.quick_targets(db, ["web01.lab"]) == SERVICES_10
    assert services_in(db, ["192.168.1.0/24"], ["192.168.1.12"]) == SERVICES_10
    assert callable(scope_services)


# ----------------------------------------------------------------- page and route
def test_page_and_sidebar(auth):
    r = auth.get("/quick?targets=10.0.0.1")
    assert r.status_code == 200
    assert '>10.0.0.1</textarea>' in r.text and 'id="quick-start"' in r.text
    assert 'name="level" value="standard" checked' in r.text and 'name="level" value="thorough"' in r.text
    assert "nmap 1 target(s) (1,000 ports) → nuclei (Recommended) on the services found" in r.text
    nav = r.text[r.text.index("Scanning"):]
    assert nav.index('href="/quick"') < nav.index('href="/nmap"')
    assert 'href="/quick"' in auth.get("/").text


def job_id_of(r):
    assert r.status_code == 303, r.text[:800]
    return int(r.headers["location"].rsplit("/", 1)[1])


def wait_for_nuclei(client, parent_id, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with client.app.state.SessionLocal() as s:
            for j in s.scalars(select(Job).where(Job.kind == "nuclei")):
                if params(j).get("quick", {}).get("parent_job") == parent_id:
                    return j.id
        time.sleep(0.05)
    raise AssertionError("no nuclei step")


def test_quick_scan_end_to_end(auth):
    csrf = get_csrf(auth, "/quick")
    jid = job_id_of(auth.post("/quick/scan", data={"csrf": csrf, "targets": "192.168.1.10", "level": "standard"},
                              follow_redirects=False))
    assert wait_job(auth, jid)["status"] == "done"
    nid = wait_for_nuclei(auth, jid)
    assert wait_job(auth, nid)["status"] == "done"
    with auth.app.state.SessionLocal() as s:
        nm, nu = s.get(Job, jid), s.get(Job, nid)
        assert params(nm)["quick"]["nuclei_job"] == nid and params(nu)["targets"] == SERVICES_10
        assert "[quick] nuclei step started" in nm.log
        a = s.scalar(select(AuditLog).where(AuditLog.action == "scan.quick"))
        d = json.loads(a.details)
        assert a.target == "192.168.1.10" and d["job_id"] == jid and d["level"] == "standard"
        assert job_summary(nm).startswith("Quick scan step 1/2: nmap")
        assert job_summary(nu).startswith(f"Quick scan step 2/2: nuclei on 4 service(s) from job #{jid}")
    page = auth.get(f"/jobs/{jid}").text
    assert "Quick scan · step 1 of 2" in page and f'href="/jobs/{nid}"' in page
    page = auth.get(f"/jobs/{nid}").text
    assert "Quick scan · step 2 of 2" in page and f'href="/jobs/{jid}"' in page


def test_validation_rerenders_with_typed_values(auth):
    csrf = get_csrf(auth, "/quick")
    r = auth.post("/quick/scan", data={"csrf": csrf, "targets": "-oN /tmp/x", "level": "thorough"})
    assert r.status_code == 400 and "Invalid nmap target" in r.text
    assert "-oN /tmp/x</textarea>" in r.text and 'name="level" value="thorough" checked' in r.text
    r = auth.post("/quick/scan", data={"csrf": csrf, "targets": "10.0.0.1", "level": "bogus"})
    assert r.status_code == 400 and "Invalid scan level" in r.text
    r = auth.post("/quick/scan", data={"csrf": csrf, "targets": ""})
    assert r.status_code == 400
    with auth.app.state.SessionLocal() as s:
        assert s.scalar(select(Job)) is None


def test_permission_and_csrf(auth):
    r = auth.post("/quick/scan", data={"csrf": "nope", "targets": "10.0.0.1"}, follow_redirects=False)
    assert r.status_code == 403
    make_user(auth, "vera", "viewer")
    login_as(auth, "vera")
    r = auth.get("/quick")
    assert r.status_code == 200 and re.search(r'id="quick-start"[^>]*disabled', r.text)
    csrf = get_csrf(auth, "/quick")
    r = auth.post("/quick/scan", data={"csrf": csrf, "targets": "10.0.0.1"}, follow_redirects=False)
    assert r.status_code == 403
    with auth.app.state.SessionLocal() as s:
        assert s.scalar(select(Job)) is None


# ----------------------------------------------------------------- API
def test_api_quick(auth):
    from tests.test_api import api, new_key, wait_api_job
    viewer = new_key(auth, name="v", role="viewer")
    analyst = new_key(auth, name="a", role="analyst")
    assert api(auth, viewer, "POST", "/scans/quick", json={"targets": ["192.168.1.10"]}).status_code == 403
    r = api(auth, analyst, "POST", "/scans/quick", json={"targets": ["-oN x"]})
    assert r.status_code == 400 and "Invalid nmap target" in r.json()["detail"]
    assert api(auth, analyst, "POST", "/scans/quick", json={"targets": ["10.0.0.1"], "level": "x"}).status_code == 422
    r = api(auth, analyst, "POST", "/scans/quick", json={"targets": ["192.168.1.10"], "level": "thorough"})
    assert r.status_code == 202
    jid = r.json()["job_id"]
    assert wait_api_job(auth, analyst, jid) == "done"
    with auth.app.state.SessionLocal() as s:
        j = s.get(Job, jid)
        assert j.kind == "nmap" and params(j)["quick"]["level"] == "thorough"
        assert s.scalar(select(AuditLog).where(AuditLog.action == "scan.quick")) is not None
    nid = wait_for_nuclei(auth, jid)
    assert wait_api_job(auth, analyst, nid) == "done"


def test_api_docs_list_quick(auth):
    assert "/api/v1/scans/quick" in auth.get("/api-docs").text
