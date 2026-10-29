from pathlib import Path

import pytest
from sqlalchemy import select

from app.db import Finding, Job, TemplateIndex
from app.scanners.nuclei_runner import build_nuclei_argv
from app.templates_index import reindex
from tests.conftest import get_csrf, wait_job


def test_build_nuclei_argv():
    argv = build_nuclei_argv("/opt/nuclei", ["/t/a.yaml", "/t/b.yaml"], "/data/jobs/t.txt", "/data/nuclei-templates", rate_limit=50, timeout=7)
    assert argv[:2] == ["/opt/nuclei", "-jsonl"]
    assert "-silent" not in argv and "-disable-update-check" in argv and "-no-color" in argv
    assert argv[argv.index("-stats-interval") + 1] == "30"
    assert argv[argv.index("-ud") + 1] == "/data/nuclei-templates"
    assert argv[argv.index("-l") + 1] == "/data/jobs/t.txt"
    assert argv.count("-t") == 2 and "/t/a.yaml" in argv and "/t/b.yaml" in argv
    assert argv[argv.index("-rate-limit") + 1] == "50" and argv[argv.index("-timeout") + 1] == "7"


def test_build_nuclei_argv_requires_templates():
    with pytest.raises(ValueError):
        build_nuclei_argv("nuclei", [], "/t.txt", "/d")


def _template_paths(client):
    with client.app.state.SessionLocal() as db:
        reindex(db, client.app.state.settings)
        return {t.template_id: t.path for t in db.scalars(select(TemplateIndex))}


def test_nuclei_page_renders(auth):
    r = auth.get("/nuclei")
    assert r.status_code == 200 and 'id="tpl-q"' in r.text


def test_nuclei_scan_rejects_missing_templates_and_bad_targets(auth):
    paths = _template_paths(auth)
    csrf = get_csrf(auth, "/nuclei")
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://10.0.0.1"})
    assert r.status_code == 400 and "Select at least one template" in r.text
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "-bad", "template_paths": [paths["php-detect"]]})
    assert r.status_code == 400 and "Invalid nuclei target" in r.text
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://10.0.0.1", "template_paths": ["/etc/passwd"]})
    assert r.status_code == 400 and "not in the template directories" in r.text
    with auth.app.state.SessionLocal() as db:
        assert db.scalar(select(Job)) is None


def test_nuclei_scan_end_to_end_with_fake_nuclei(auth):
    paths = _template_paths(auth)
    csrf = get_csrf(auth, "/nuclei")
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://192.168.1.10:8080\n192.168.1.12:3306",
                                        "template_paths": [paths["php-detect"], paths["CVE-2026-109619"]],
                                        "rate_limit": "100", "timeout": "5"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    job_id = int(r.headers["location"].rsplit("/", 1)[1])
    data = wait_job(auth, job_id)
    assert data["status"] == "done", auth.get(f"/jobs/{job_id}").text
    with auth.app.state.SessionLocal() as db:
        job = db.get(Job, job_id)
        assert job.command.count("-t ") == 2
        targets_file = job.command.split("-l ")[1].split()[0]
        assert Path(targets_file).read_text() == "http://192.168.1.10:8080\n192.168.1.12:3306\n"
        findings = list(db.scalars(select(Finding).where(Finding.job_id == job_id)))
        assert sorted(f.template_id for f in findings) == ["CVE-2026-109619", "php-detect"]
        crit = next(f for f in findings if f.severity == "critical")
        assert crit.matched_at == "http://192.168.1.10:8080/index.php"
    r = auth.get(f"/findings?job={job_id}")
    assert r.status_code == 200 and "CVE-2026-109619" in r.text and "php-detect" in r.text
    r = auth.get("/findings?severity=critical")
    assert "CVE-2026-109619" in r.text and "php-detect" not in r.text
    r = auth.get(f"/jobs/{job_id}")
    assert "CVE-2026-109619" in r.text
    assert "[nuclei] 2 finding(s) stored" in r.text
