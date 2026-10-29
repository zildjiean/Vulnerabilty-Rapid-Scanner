import asyncio
import json

from app.updates import UPDATE_ACTIONS, build_update_argv, parse_nmap_version, parse_nuclei_version, templates_info, tool_versions
from tests.conftest import get_csrf, wait_job


def test_parse_versions():
    assert parse_nmap_version("Nmap version 7.97 ( https://nmap.org )\nPlatform: x") == "7.97"
    assert parse_nuclei_version("[INF] Nuclei Engine Version: v3.8.0\n[INF] Config dir") == "v3.8.0"
    assert parse_nmap_version("") == "unknown" and parse_nuclei_version("garbage") == "unknown"


def test_tool_versions_with_fake_bins(settings):
    v = asyncio.run(tool_versions(settings))
    assert v == {"nmap": "7.97", "nuclei": "v3.8.0"}


def test_templates_info_reads_config(settings, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    cfg = tmp_path / "home" / ".config" / "nuclei"
    cfg.mkdir(parents=True)
    (cfg / ".templates-config.json").write_text(json.dumps({"templates-version": "v10.2.9", "latest-templates-version": "v10.3.0", "nuclei-latest-version": "v3.9.0"}))
    info = templates_info(settings)
    assert info["templates_version"] == "v10.2.9" and info["latest_templates_version"] == "v10.3.0" and info["nuclei_latest_version"] == "v3.9.0"
    assert info["dir_exists"] is True and info["yaml_files"] == 2


def test_build_update_argv(settings):
    assert build_update_argv(settings, "nuclei-templates")[1] == "-update-templates"
    assert build_update_argv(settings, "nuclei-engine")[1] == "-update"
    assert build_update_argv(settings, "nmap-scripts")[1] == "--script-updatedb"
    assert set(UPDATE_ACTIONS) == {"nuclei-templates", "nuclei-engine", "nmap-scripts"}


def test_updates_page_and_actions(auth):
    r = auth.get("/updates")
    assert r.status_code == 200 and "7.97" in r.text and "v3.8.0" in r.text
    csrf = get_csrf(auth, "/updates")
    r = auth.post("/updates/nuclei-templates", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    job_id = int(r.headers["location"].rsplit("/", 1)[1])
    data = wait_job(auth, job_id)
    assert data["status"] == "done"
    assert "Successfully updated nuclei-templates" in auth.get(f"/jobs/{job_id}").text
    r = auth.post("/updates/nope", data={"csrf": csrf})
    assert r.status_code == 404
