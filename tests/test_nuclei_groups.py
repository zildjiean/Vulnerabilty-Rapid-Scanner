from pathlib import Path

import pytest
from sqlalchemy import select

from app.db import Job
from app.scanners.nuclei_runner import build_nuclei_argv, parse_tags, resolve_group_paths, validate_template_paths
from app.templates_index import list_template_groups, reindex
from tests.conftest import get_csrf, wait_job


def test_build_argv_with_tags_and_severity():
    argv = build_nuclei_argv("nuclei", ["/t"], "/f.txt", "/t", tags=["cve", "php"], severities=["critical", "high"])
    assert argv[argv.index("-tags") + 1] == "cve,php"
    assert argv[argv.index("-severity") + 1] == "critical,high"
    argv = build_nuclei_argv("nuclei", ["/t"], "/f.txt", "/t")
    assert "-tags" not in argv and "-severity" not in argv


def test_parse_tags():
    assert parse_tags("cve, php rce,,apache") == ["cve", "php", "rce", "apache"]
    assert parse_tags("") == []
    with pytest.raises(ValueError):
        parse_tags("cve;rm -rf")


def test_validate_template_paths_accepts_directories(settings):
    d = str(settings.nuclei_templates_dir / "http")
    assert validate_template_paths(settings, [d]) == [str(Path(d).resolve())]
    with pytest.raises(ValueError):
        validate_template_paths(settings, [str(settings.data_dir)])  # parent of roots, not inside


def test_resolve_group_paths(settings):
    paths = resolve_group_paths(settings, ["http/cves", "custom"])
    assert paths == [str((settings.nuclei_templates_dir / "http/cves").resolve()), str(settings.custom_templates_dir.resolve())]
    with pytest.raises(ValueError):
        resolve_group_paths(settings, ["../etc"])
    with pytest.raises(ValueError):
        resolve_group_paths(settings, ["does/not/exist"])
    with pytest.raises(ValueError):
        resolve_group_paths(settings, [])


def test_list_template_groups(settings):
    from app.db import init_db, make_engine, make_session_factory
    engine = make_engine(settings.db_url)
    init_db(engine)
    with make_session_factory(engine)() as db:
        reindex(db, settings)
        groups = list_template_groups(db, settings)
    by_key = {g["key"]: g for g in groups}
    assert by_key["http"]["count"] == 2 and by_key["http"]["depth"] == 1
    assert by_key["http/cves"]["count"] == 1 and by_key["http/cves/2026"]["count"] == 1
    assert by_key["http/technologies"]["count"] == 1
    assert by_key["custom"]["count"] == 0 and by_key["custom"]["label"] == "Custom (0-day) templates"
    assert [g["key"] for g in groups][:4] == ["http", "http/cves", "http/cves/2026", "http/technologies"]


def test_scan_all_templates_mode(auth):
    from app.templates_index import save_custom_template
    from tests.test_templates_index import CUSTOM_YAML
    save_custom_template(auth.app.state.settings, CUSTOM_YAML)
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
    csrf = get_csrf(auth, "/nuclei")
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://10.0.0.1", "mode": "all", "tags": "php, cve",
                                        "severities": ["critical", "high"]}, follow_redirects=False)
    assert r.status_code == 303, r.text
    job_id = int(r.headers["location"].rsplit("/", 1)[1])
    assert wait_job(auth, job_id)["status"] == "done"
    with auth.app.state.SessionLocal() as db:
        job = db.get(Job, job_id)
        s = auth.app.state.settings
        assert f"-t {s.nuclei_templates_dir}" in job.command and f"-t {s.custom_templates_dir}" in job.command
        assert "-tags php,cve" in job.command and "-severity critical,high" in job.command
    assert "all templates" in auth.get("/jobs").text


def test_scan_groups_mode(auth):
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
    csrf = get_csrf(auth, "/nuclei")
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://10.0.0.1", "mode": "groups", "groups": ["http/cves/2026", "http/technologies"]}, follow_redirects=False)
    assert r.status_code == 303, r.text
    job_id = int(r.headers["location"].rsplit("/", 1)[1])
    assert wait_job(auth, job_id)["status"] == "done"
    with auth.app.state.SessionLocal() as db:
        job = db.get(Job, job_id)
        assert job.command.count("-t ") == 2 and "http/cves/2026" in job.command and "http/technologies" in job.command
    page = auth.get("/jobs")
    assert "http/cves/2026" in page.text
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://10.0.0.1", "mode": "groups"})
    assert r.status_code == 400 and "Select at least one template group" in r.text


def test_nuclei_page_lists_groups(auth):
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
    r = auth.get("/nuclei")
    assert 'name="mode"' in r.text and 'value="http/cves/2026"' in r.text and 'name="tags"' in r.text
