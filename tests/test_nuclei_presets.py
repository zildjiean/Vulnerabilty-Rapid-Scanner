"""Nuclei presets: Recommended / Critical CVEs only / Full / Custom on the nuclei page, in schedules and for Quick scan."""
import json

import pytest
from sqlalchemy import select

from app import nuclei_presets as np
from app.db import AuditLog, Job, Schedule
from app.templates_index import reindex
from tests.conftest import get_csrf, wait_job
from tests.test_inventory import seed_inventory
from tests.test_scheduler import make_schedule, make_scope, run


class FakeRunner:
    def __init__(self):
        self.started = []
        self._id = 0

    def create_job(self, db, kind, argv, params=None):
        job = Job(kind=kind, status="queued", command=" ".join(argv), params_json=json.dumps(params or {}))
        db.add(job)
        db.commit()
        return job

    def start(self, job_id, argv, **kw):
        self.started.append((job_id, argv))


def _arg(argv, flag):
    return argv[argv.index(flag) + 1] if flag in argv else None


@pytest.mark.parametrize("key,sev,tags", [
    ("recommended", "critical,high,medium", None),
    ("critical_cves", "critical,high", "cve"),
    ("full", None, None),
])
def test_preset_launch_resolves_args(client, settings, key, sev, tags):
    runner = FakeRunner()
    with client.app.state.SessionLocal() as db:
        job = np.preset_launch(db, settings, runner, ["http://10.0.0.1"], key, {"extra": 1})
        params = json.loads(job.params_json)
    argv = runner.started[0][1]
    assert _arg(argv, "-severity") == sev and _arg(argv, "-tags") == tags
    assert _arg(argv, "-t") == str(settings.nuclei_templates_dir.resolve())  # all templates
    assert _arg(argv, "-rate-limit") == "150" and _arg(argv, "-timeout") == "10"  # normal profile
    assert params["preset"] == key and params["mode"] == "all" and params["extra"] == 1
    assert params["targets"] == ["http://10.0.0.1"] and params["profile"] == "normal"


def test_preset_table():
    assert list(np.PRESETS) == ["recommended", "critical_cves", "full", "custom"]
    assert np.DEFAULT_PRESET == "recommended"
    assert all(p["label"] and p["help"] for p in np.PRESETS.values())
    assert np.PRESETS["recommended"]["label"] == "Recommended"


@pytest.mark.parametrize("key", ["bogus", "custom", ""])
def test_invalid_preset(client, settings, key):
    with client.app.state.SessionLocal() as db, pytest.raises(ValueError, match="Invalid preset."):
        np.preset_launch(db, settings, FakeRunner(), ["http://10.0.0.1"], key, {})


def test_preset_needs_templates(client, settings):
    import shutil
    shutil.rmtree(settings.nuclei_templates_dir)
    with client.app.state.SessionLocal() as db:
        with pytest.raises(ValueError, match="No templates"):
            np.preset_launch(db, settings, FakeRunner(), ["http://10.0.0.1"], "recommended", {})
        assert db.scalar(select(Job)) is None


# ----------------------------------------------------------------- nuclei page
def test_nuclei_page_shows_presets_and_closed_advanced(auth):
    r = auth.get("/nuclei")
    assert r.status_code == 200
    for key in np.PRESETS:
        assert f'name="preset" value="{key}"' in r.text
    assert 'name="preset" value="recommended" checked' in r.text
    assert '<details class="advanced mb" id="nuclei-advanced">' in r.text  # closed by default


def _job_of(r):
    assert r.status_code == 303, r.text[:800]
    return int(r.headers["location"].rsplit("/", 1)[1])


NO_JS_DEFAULTS = {"mode": "selected", "profile": "normal", "rate_limit": "150", "timeout": "10", "tags": ""}


def test_preset_with_untouched_advanced_fields_runs_the_preset(auth):
    """A browser without JS posts every advanced field with its default value: the preset applies."""
    csrf = get_csrf(auth, "/nuclei")
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://192.168.1.10:8080", "preset": "recommended",
                                        **NO_JS_DEFAULTS}, follow_redirects=False)
    jid = _job_of(r)
    wait_job(auth, jid)
    with auth.app.state.SessionLocal() as db:
        job = db.get(Job, jid)
        params = json.loads(job.params_json)
        assert params["preset"] == "recommended" and params["mode"] == "all"
        assert "-severity critical,high,medium" in job.command and "-rate-limit 150" in job.command
        a = db.scalar(select(AuditLog).where(AuditLog.action == "scan.nuclei"))
        assert json.loads(a.details)["preset"] == "recommended"


@pytest.mark.parametrize("field,value", [
    ("profile", "gentle"), ("rate_limit", "20"), ("timeout", "30"), ("tags", "php"), ("severities", ["low"]),
    ("no_mhe", "true"), ("groups", ["http"]),
])
def test_changed_advanced_field_with_a_preset_is_treated_as_custom(auth, field, value):
    """With JS off, a user who edits Advanced options but leaves the default preset gets the Custom path: here the
    (default) 'Pick templates' mode without templates, so the form comes back asking for templates."""
    csrf = get_csrf(auth, "/nuclei")
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://192.168.1.10:8080", "preset": "recommended",
                                        **NO_JS_DEFAULTS, field: value})
    assert r.status_code == 400 and "Select at least one template" in r.text
    assert 'name="preset" value="custom" checked' in r.text and 'id="nuclei-advanced" open' in r.text
    with auth.app.state.SessionLocal() as db:
        assert db.scalar(select(Job)) is None


def test_changed_mode_and_speed_with_a_preset_runs_the_users_settings(auth):
    csrf = get_csrf(auth, "/nuclei")
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://192.168.1.10:8080", "preset": "recommended",
                                        **NO_JS_DEFAULTS, "mode": "all", "profile": "gentle", "rate_limit": "20",
                                        "no_mhe": "true"}, follow_redirects=False)
    jid = _job_of(r)
    wait_job(auth, jid)
    with auth.app.state.SessionLocal() as db:
        job = db.get(Job, jid)
        assert json.loads(job.params_json)["preset"] == "custom"
        assert "-rate-limit 20" in job.command and "-retries" in job.command and "-no-mhe" in job.command
        assert "-severity" not in job.command


def test_selected_templates_with_a_preset_are_treated_as_custom(auth):
    from tests.test_nuclei_scan import _template_paths
    paths = _template_paths(auth)
    csrf = get_csrf(auth, "/nuclei")
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://192.168.1.10:8080", "preset": "full",
                                        **NO_JS_DEFAULTS, "template_paths": [paths["php-detect"]]},
                  follow_redirects=False)
    jid = _job_of(r)
    wait_job(auth, jid)
    with auth.app.state.SessionLocal() as db:
        job = db.get(Job, jid)
        assert json.loads(job.params_json)["preset"] == "custom" and paths["php-detect"] in job.command
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://10.0.0.1", "preset": "full",
                                        **NO_JS_DEFAULTS, "template_paths": ["/etc/passwd"]})
    assert r.status_code == 400 and "not in the template directories" in r.text  # validated like Custom


def test_custom_preset_keeps_todays_behaviour(auth):
    csrf = get_csrf(auth, "/nuclei")
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://192.168.1.10:8080", "preset": "custom",
                                        "mode": "all", "tags": "php", "severities": ["low"], "profile": "gentle"},
                  follow_redirects=False)
    jid = _job_of(r)
    wait_job(auth, jid)
    with auth.app.state.SessionLocal() as db:
        job = db.get(Job, jid)
        assert "-tags php" in job.command and "-severity low" in job.command and "-retries" in job.command
        assert json.loads(job.params_json)["preset"] == "custom"


def test_post_without_preset_is_custom(auth):
    csrf = get_csrf(auth, "/nuclei")
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://10.0.0.1"})
    assert r.status_code == 400 and "Select at least one template" in r.text
    assert '<details class="advanced mb" id="nuclei-advanced" open>' in r.text
    assert 'name="preset" value="custom" checked' in r.text


def test_error_with_preset_reopens_advanced_and_keeps_values(auth):
    csrf = get_csrf(auth, "/nuclei")
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "-bad", "preset": "critical_cves"})
    assert r.status_code == 400 and "Invalid nuclei target" in r.text
    assert 'id="nuclei-advanced" open' in r.text and 'name="preset" value="critical_cves" checked' in r.text
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://10.0.0.1", "preset": "bogus"})
    assert r.status_code == 400 and "Invalid preset." in r.text
    with auth.app.state.SessionLocal() as db:
        assert db.scalar(select(Job)) is None


def test_job_summary_names_preset(auth):
    from app.routers.jobs import job_summary
    job = Job(kind="nuclei", params_json=json.dumps({"targets": ["a:1"], "mode": "all", "preset": "critical_cves",
                                                     "severities": ["critical", "high"], "tags": ["cve"]}))
    assert "Critical CVEs only preset" in job_summary(job)
    job = Job(kind="nuclei", params_json=json.dumps({"targets": ["a:1"], "mode": "all", "preset": "custom"}))
    assert "preset" not in job_summary(job)


# ----------------------------------------------------------------- schedules
def _seed(auth):
    seed_inventory(auth)
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
        db.commit()


def test_schedule_with_preset_runs_preset(auth):
    _seed(auth)
    sid = make_schedule(auth, "nuclei", make_scope(auth), {"preset": "critical_cves"})
    job_id = run(auth, sid)
    wait_job(auth, job_id)
    with auth.app.state.SessionLocal() as db:
        job = db.get(Job, job_id)
        p = json.loads(job.params_json)
        assert p["preset"] == "critical_cves" and p["schedule"] == "nuclei test" and job.schedule_id == sid
        assert "-tags cve" in job.command and "-severity critical,high" in job.command
        assert "http://192.168.1.10:80" in p["targets"] and not any("192.168.1.12" in t for t in p["targets"])


def test_schedule_without_preset_runs_as_today(auth):
    _seed(auth)
    sid = make_schedule(auth, "nuclei", make_scope(auth), {"mode": "all", "severities": ["critical"], "profile": "gentle"})
    job_id = run(auth, sid)
    wait_job(auth, job_id)
    with auth.app.state.SessionLocal() as db:
        job = db.get(Job, job_id)
        assert "-severity critical" in job.command and "-retries" in job.command and "-tags" not in job.command
        assert "preset" not in json.loads(job.params_json)


def test_schedule_form_preset(auth):
    scope_id = make_scope(auth)
    page = auth.get("/schedules").text
    assert 'name="preset"' in page and 'value="recommended" selected' in page
    csrf = get_csrf(auth, "/schedules")
    base = {"csrf": csrf, "kind": "nuclei", "scope_id": str(scope_id), "frequency": "daily", "time_of_day": "03:00"}
    r = auth.post("/schedules", data={**base, "name": "p", "preset": "full"}, follow_redirects=False)
    assert r.status_code == 303
    r = auth.post("/schedules", data={**base, "name": "c", "preset": "custom", "nuclei_mode": "all",
                                      "severities": ["high"], "profile": "gentle"}, follow_redirects=False)
    assert r.status_code == 303
    r = auth.post("/schedules", data={**base, "name": "old", "nuclei_mode": "all", "profile": "normal"},
                  follow_redirects=False)
    assert r.status_code == 303
    r = auth.post("/schedules", data={**base, "name": "bad", "preset": "bogus"})
    assert r.status_code == 400 and "Invalid preset." in r.text
    with auth.app.state.SessionLocal() as db:
        cfg = {s.name: json.loads(s.config) for s in db.scalars(select(Schedule))}
    assert cfg["p"] == {"preset": "full"}
    assert cfg["c"] == {"mode": "all", "groups": [], "severities": ["high"], "profile": "gentle"}
    assert cfg["old"] == {"mode": "all", "groups": [], "severities": [], "profile": "normal"}
