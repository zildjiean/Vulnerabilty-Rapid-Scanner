import json

import pytest
from sqlalchemy import select

from app.db import Job
from app.jobs import job_warnings
from app.scanners.nuclei_runner import PROFILES, analyze_nuclei_log, build_nuclei_argv, profile_flags
from app.templates_index import reindex
from tests.conftest import get_csrf, wait_job

USER_LOG = """[INF] Templates loaded for current scan: 4457
[INF] Targets loaded for current scan: 1
[INF] Found 1 URL from httpx
{"duration":"0:00:30","errors":"4","hosts":"1","matched":"0","percent":"58","requests":"6271","rps":"207","templates":"4457","total":"10782"}
[INF] Skipped 27.254.134.126:443 from target list as found unresponsive permanently: cause="i/o timeout" address=27.254.134.126:443
{"duration":"0:01:27","errors":"88","hosts":"1","matched":"0","percent":"99","requests":"10694","rps":"122","templates":"4457","total":"10782"}
[INF] Scan completed in 1m. 0 matches found.
"""


def test_profiles_and_flags():
    assert set(PROFILES) == {"gentle", "normal", "aggressive"}
    assert PROFILES["gentle"]["rate_limit"] < PROFILES["normal"]["rate_limit"] < PROFILES["aggressive"]["rate_limit"]
    g = profile_flags("gentle", no_mhe=False)
    assert g[g.index("-retries") + 1] == "2" and g[g.index("-max-host-error") + 1] == "100" and "-c" in g
    assert profile_flags("normal", no_mhe=False) == []
    assert "-no-mhe" in profile_flags("normal", no_mhe=True)
    a = profile_flags("aggressive", no_mhe=False)
    assert "-c" in a and "-bulk-size" in a
    with pytest.raises(ValueError):
        profile_flags("turbo", no_mhe=False)


def test_build_argv_appends_extra_flags():
    argv = build_nuclei_argv("nuclei", ["/t"], "/f.txt", "/t", extra=["-retries", "2", "-no-mhe"])
    assert argv[-3:] == ["-retries", "2", "-no-mhe"]


def test_analyze_nuclei_log_detects_skipped_host_and_errors():
    w = analyze_nuclei_log(USER_LOG)
    assert any("unresponsive" in x and "27.254.134.126:443" in x for x in w)
    assert any("88 request errors" in x for x in w)
    assert analyze_nuclei_log("[INF] Targets loaded for current scan: 1\n[INF] Found 1 URL from httpx\n[INF] Scan completed in 1s. 2 matches found.\n") == []


def test_analyze_nuclei_log_no_targets_and_errors():
    w = analyze_nuclei_log("[INF] Templates loaded for current scan: 10\n[INF] Targets loaded for current scan: 1\n[INF] Running httpx on input host\n[INF] Found 0 URL from httpx\n")
    assert any("did not answer over HTTP" in x for x in w)
    w = analyze_nuclei_log("[ERR] Could not run nuclei: something bad\n[WRN] rate limited\n")
    assert any("[ERR]" in x for x in w) and any("[WRN]" in x for x in w)


def test_job_warnings_reads_params():
    j = Job(kind="nuclei", status="done", params_json=json.dumps({"warnings": ["a", "b"]}))
    assert job_warnings(j) == ["a", "b"]
    assert job_warnings(Job(kind="nuclei", status="done", params_json="{}")) == []
    assert job_warnings(Job(kind="nuclei", status="done", params_json="not json")) == []


def test_scan_with_gentle_profile_and_no_mhe(auth):
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
    csrf = get_csrf(auth, "/nuclei")
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://10.0.0.1", "mode": "all", "profile": "gentle",
                                        "no_mhe": "true", "rate_limit": "20", "timeout": "20"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    job_id = int(r.headers["location"].rsplit("/", 1)[1])
    assert wait_job(auth, job_id)["status"] == "done"
    with auth.app.state.SessionLocal() as db:
        job = db.get(Job, job_id)
        assert "-retries 2" in job.command and "-max-host-error 100" in job.command and "-no-mhe" in job.command
        assert "-rate-limit 20" in job.command and "-timeout 20" in job.command
        assert json.loads(job.params_json)["profile"] == "gentle"
        assert job_warnings(job) == []  # fake nuclei log has no problems
    assert "gentle" in auth.get("/jobs").text
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://10.0.0.1", "mode": "all", "profile": "turbo"})
    assert r.status_code == 400 and "Invalid scan profile" in r.text


def test_job_with_warnings_is_flagged_in_ui(auth):
    with auth.app.state.SessionLocal() as db:
        job = Job(kind="nuclei", status="done", params_json=json.dumps({"targets": ["http://x"], "mode": "all",
                  "result": {"findings": 0}, "warnings": ["Target 27.254.134.126:443 was dropped as unresponsive (i/o timeout); templates after that point were not tested."]}))
        db.add(job)
        db.commit()
        job_id = job.id
    page = auth.get("/jobs")
    assert "Done with warnings" in page.text
    detail = auth.get(f"/jobs/{job_id}")
    assert "Done with warnings" in detail.text and "dropped as unresponsive" in detail.text
    findings = auth.get(f"/findings?job={job_id}")
    assert "incomplete" in findings.text.lower() and "dropped as unresponsive" in findings.text
    all_findings = auth.get("/findings")
    assert f"#{job_id}" in all_findings.text and "warnings" in all_findings.text.lower()


def test_hook_records_warnings_from_log(settings):
    from app.db import init_db, make_engine, make_session_factory
    from app.scanners.nuclei_runner import on_nuclei_complete
    engine = make_engine(settings.db_url)
    init_db(engine)
    with make_session_factory(engine)() as db:
        job = Job(kind="nuclei", status="running", log=USER_LOG, params_json="{}")
        db.add(job)
        db.commit()
        note = on_nuclei_complete(db, job, "")
        db.commit()
        assert "WARNING" in note and "incomplete" in note.lower()
        w = job_warnings(job)
        assert len(w) >= 2 and any("unresponsive" in x for x in w)


def test_backfill_marks_old_jobs(settings):
    from app.db import init_db, make_engine, make_session_factory
    from app.scanners.nuclei_runner import backfill_nuclei_warnings
    engine = make_engine(settings.db_url)
    init_db(engine)
    SessionLocal = make_session_factory(engine)
    with SessionLocal() as db:
        db.add(Job(kind="nuclei", status="done", log=USER_LOG, params_json=json.dumps({"targets": ["x"]})))
        db.add(Job(kind="nuclei", status="done", log="[INF] Scan completed in 1s. 0 matches found.", params_json="{}"))
        db.add(Job(kind="nmap", status="done", log=USER_LOG, params_json="{}"))
        db.commit()
        assert backfill_nuclei_warnings(db) == 2
        assert backfill_nuclei_warnings(db) == 0  # idempotent
        jobs = list(db.scalars(select(Job).order_by(Job.id)))
        assert job_warnings(jobs[0]) and not job_warnings(jobs[1]) and not job_warnings(jobs[2])
