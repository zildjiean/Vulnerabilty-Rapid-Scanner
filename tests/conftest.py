import re
import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

FIXTURES = Path(__file__).parent / "fixtures"

FAKE_NMAP = """#!/bin/sh
for a in "$@"; do
  case "$a" in
    --version) echo "Nmap version 7.97 ( https://nmap.org )"; exit 0;;
    --script-updatedb) echo "NSE: Updating rule database."; echo "NSE: Script Database updated successfully."; exit 0;;
  esac
done
echo "Starting Nmap 7.97 (fake)" 1>&2
cat "$(dirname "$0")/nmap_sample.xml"
"""

FAKE_NUCLEI = """#!/bin/sh
for a in "$@"; do
  case "$a" in
    -version) echo "[INF] Nuclei Engine Version: v3.8.0" 1>&2; exit 0;;
    -validate) echo "[INF] All templates validated successfully" 1>&2; exit 0;;
    -update-templates|-ut) echo "[INF] Successfully updated nuclei-templates (v10.2.9)"; exit 0;;
    -update|-up) echo "[INF] nuclei is already updated to latest version"; exit 0;;
  esac
done
cat "$(dirname "$0")/nuclei_sample.jsonl"
"""


@pytest.fixture
def fake_bins(tmp_path):
    bins = tmp_path / "bin"
    bins.mkdir()
    for name, body in (("nmap", FAKE_NMAP), ("nuclei", FAKE_NUCLEI)):
        p = bins / name
        p.write_text(body)
        p.chmod(0o755)
    for fx in ("nmap_sample.xml", "nuclei_sample.jsonl"):
        src = FIXTURES / fx
        if src.exists():
            shutil.copy(src, bins / fx)
    return bins


@pytest.fixture
def settings(tmp_path, fake_bins):
    data = tmp_path / "data"
    tdir = data / "nuclei-templates"
    tdir.mkdir(parents=True)
    if (FIXTURES / "templates").exists():
        shutil.copytree(FIXTURES / "templates", tdir, dirs_exist_ok=True)
    return Settings(
        data_dir=data,
        nmap_bin=str(fake_bins / "nmap"),
        nuclei_bin=str(fake_bins / "nuclei"),
        secret_key="test-secret-key",
    )


@pytest.fixture
def client(settings):
    app = create_app(settings)
    with TestClient(app) as c:
        yield c


NEW_PASSWORD = "CorrectHorse-Battery9"


def get_csrf(client, path="/"):
    r = client.get(path)
    m = re.search(r'name="csrf" value="([^"]+)"', r.text)
    assert m, f"no csrf token on {path}"
    return m.group(1)


def login_and_change_password(client, new_password=NEW_PASSWORD):
    r = client.post("/login", data={"username": "admin", "password": "changeme"}, follow_redirects=False)
    assert r.status_code == 303
    csrf = get_csrf(client, "/change-password")
    r = client.post(
        "/change-password",
        data={"csrf": csrf, "current_password": "changeme", "new_password": new_password, "confirm_password": new_password},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    return client


@pytest.fixture
def auth(client):
    return login_and_change_password(client)


def wait_job(client, job_id, timeout=15.0):
    deadline = time.time() + timeout
    data = None
    while time.time() < deadline:
        data = client.get(f"/jobs/{job_id}/status").json()
        if data["status"] not in ("queued", "running"):
            return data
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish: {data}")
