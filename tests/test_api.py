import re
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.db import ApiKey, AuditLog, Issue, Job, utcnow
from app.templates_index import reindex
from tests.conftest import NEW_PASSWORD, get_csrf
from tests.test_inventory import seed_inventory
from tests.test_issue_routes import SPECS, seed
from tests.test_rbac import login_as, make_user


def new_key(client, name="ci", role="analyst", expires="90"):
    csrf = get_csrf(client, "/api-keys")
    r = client.post("/api-keys", data={"csrf": csrf, "name": name, "role": role, "expires": expires})
    assert r.status_code == 200, r.text[:300]
    m = re.search(r'data-secret="(zdrs_[^"]+)"', r.text)
    assert m, "key not shown"
    return m.group(1)


def api(client, key, method, path, **kw):
    client.cookies.clear()   # the API must never rely on the browser session
    return client.request(method, f"/api/v1{path}", headers={"Authorization": f"Bearer {key}"}, **kw)


def wait_api_job(client, key, job_id, timeout=15.0):
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = api(client, key, "GET", f"/jobs/{job_id}").json()["status"]
        if status not in ("queued", "running"):
            return status
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish")


def test_key_lifecycle_and_storage(auth):
    key = new_key(auth)
    with auth.app.state.SessionLocal() as db:
        k = db.scalar(select(ApiKey))
        assert k.role == "analyst" and k.key_hash != key and key.startswith(k.prefix)
        assert k.expires_at is not None and timedelta(days=89) < k.expires_at - utcnow() <= timedelta(days=90)
    assert key not in auth.get("/api-keys").text   # shown once only
    me = api(auth, key, "GET", "/me").json()
    assert me["username"] == "admin" and me["role"] == "analyst" and me["key"] == "ci"
    with auth.app.state.SessionLocal() as db:
        assert db.scalar(select(ApiKey)).last_used_at is not None
    assert "apikey.created" in [a.action for a in auth.app.state.SessionLocal().scalars(select(AuditLog))]


def test_authentication_failures(auth):
    key = new_key(auth)
    auth.cookies.clear()
    assert auth.get("/api/v1/me").status_code == 401
    assert api(auth, "zdrs_wrong", "GET", "/me").status_code == 401
    assert auth.get("/api/v1/me", headers={"X-API-Key": key}).status_code == 200
    # a logged-in browser session is not accepted on the API
    login_as(auth, "admin", NEW_PASSWORD)
    assert auth.get("/api/v1/me").status_code == 401
    with auth.app.state.SessionLocal() as db:
        db.scalar(select(ApiKey)).expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert api(auth, key, "GET", "/me").status_code == 401


def test_revocation_and_inactive_owner(auth):
    make_user(auth, "ana", "analyst")
    login_as(auth, "ana")
    key = new_key(auth, role="viewer")
    assert api(auth, key, "GET", "/me").status_code == 200
    login_as(auth, "ana")
    with auth.app.state.SessionLocal() as db:
        kid = db.scalar(select(ApiKey.id))
    auth.post(f"/api-keys/{kid}/revoke", data={"csrf": get_csrf(auth, "/api-keys")})
    assert api(auth, key, "GET", "/me").status_code == 401
    login_as(auth, "ana")
    key2 = new_key(auth, name="second", role="viewer")
    with auth.app.state.SessionLocal() as db:
        from app.db import User
        db.scalar(select(User).where(User.username == "ana")).is_active = False
        db.commit()
    assert api(auth, key2, "GET", "/me").status_code == 401


def test_role_ceiling(auth):
    make_user(auth, "ana", "analyst")
    login_as(auth, "ana")
    csrf = get_csrf(auth, "/api-keys")
    r = auth.post("/api-keys", data={"csrf": csrf, "name": "x", "role": "admin", "expires": "30"})
    assert r.status_code == 400 and "cannot exceed" in r.text
    assert 'value="admin"' not in auth.get("/api-keys").text


def test_issue_endpoints(auth):
    ids = seed(auth, SPECS)
    key = new_key(auth)
    r = api(auth, key, "GET", "/issues", params={"severity": "critical"})
    assert r.status_code == 200 and r.json()["count"] == 1 and r.json()["issues"][0]["vuln_id"] == "CVE-2021-41773"
    assert api(auth, key, "GET", "/issues", params={"limit": 1, "offset": 1}).json()["count"] == 3
    assert len(api(auth, key, "GET", "/issues", params={"limit": 1}).json()["issues"]) == 1
    iid = ids["exposed-panel"]
    detail = api(auth, key, "GET", f"/issues/{iid}").json()
    assert detail["asset"] == "10.0.0.6:8080" and detail["events"][0]["kind"] == "created"
    r = api(auth, key, "PATCH", f"/issues/{iid}", json={"status": "triaged", "comment": "seen by CI", "assignee": "admin",
                                                        "severity": "high"})
    assert r.status_code == 200, r.text
    with auth.app.state.SessionLocal() as db:
        i = db.get(Issue, iid)
        assert i.status == "triaged" and i.severity == "high" and i.assignee_id is not None
        names = [e.username for e in i.events]
        assert "admin (api:ci)" in names
        audit = db.scalar(select(AuditLog).where(AuditLog.action == "issue.status_changed"))
        assert audit.username == "admin (api:ci)"
    r = api(auth, key, "PATCH", f"/issues/{iid}", json={"status": "verified"})
    assert r.status_code == 400 and "Cannot move" in r.json()["detail"]
    assert api(auth, key, "PATCH", f"/issues/{iid}", json={"assignee": "nobody"}).status_code == 400
    assert api(auth, key, "GET", "/issues/99999").status_code == 404


def test_viewer_key_is_read_only(auth):
    ids = seed(auth, SPECS)
    key = new_key(auth, role="viewer")
    assert api(auth, key, "GET", "/issues").status_code == 200
    r = api(auth, key, "PATCH", f"/issues/{ids['exposed-panel']}", json={"status": "triaged"})
    assert r.status_code == 403 and r.json()["detail"] == "issues.manage"
    assert api(auth, key, "POST", "/scans/nmap", json={"targets": ["10.0.0.1"]}).status_code == 403


def test_scan_endpoints_and_jobs(auth):
    seed_inventory(auth)
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
        db.commit()
    key = new_key(auth)
    r = api(auth, key, "POST", "/scans/nmap", json={"targets": ["192.168.1.0/30"], "port_mode": "custom", "custom_ports": "22,80"})
    assert r.status_code == 202, r.text
    job_id = r.json()["job_id"]
    assert wait_api_job(auth, key, job_id) == "done"
    j = api(auth, key, "GET", f"/jobs/{job_id}").json()
    assert j["status"] == "done" and j["kind"] == "nmap"
    assert api(auth, key, "POST", "/scans/nmap", json={"targets": ["10.0.0.1;rm"]}).status_code == 400
    r = api(auth, key, "POST", "/scans/nuclei", json={"targets": ["http://192.168.1.10:8080"], "template_ids": ["CVE-2026-109619"]})
    assert r.status_code == 202, r.text
    wait_api_job(auth, key, r.json()["job_id"])
    with auth.app.state.SessionLocal() as db:
        assert "CVE-2026-109619.yaml" in db.get(Job, r.json()["job_id"]).command
    assert api(auth, key, "POST", "/scans/nuclei", json={"targets": ["x.test"], "template_ids": ["nope"]}).status_code == 400
    assets = api(auth, key, "GET", "/assets").json()["assets"]
    assert any(a["address"] == "192.168.1.10" and any(s["port"] == 8080 for s in a["services"]) for a in assets)


def test_campaign_endpoints(auth):
    from tests.test_campaigns import NVD_PHP, PHP_CVE
    from tests.test_intel import FakeNet
    seed_inventory(auth)
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
        db.commit()
    auth.app.state.get_json = FakeNet(nvd={PHP_CVE: NVD_PHP})
    key = new_key(auth)
    r = api(auth, key, "POST", "/campaigns", json={"cve_id": PHP_CVE, "product_pattern": "php", "version_constraint": "< 8.3.15"})
    assert r.status_code == 201, r.text
    c = r.json()
    assert c["cve_id"] == PHP_CVE and c["severity"] == "critical" and c["progress"]["total"] == 1
    assert api(auth, key, "GET", "/campaigns").json()["campaigns"][0]["id"] == c["id"]
    r = api(auth, key, "POST", f"/campaigns/{c['id']}/verify", json={"profile": "gentle"})
    assert r.status_code == 202, r.text
    wait_api_job(auth, key, r.json()["job_id"])
    assert api(auth, key, "POST", "/campaigns", json={"cve_id": "bad"}).status_code == 400


def test_pages(auth):
    new_key(auth)
    assert "API reference" in auth.get("/api-docs").text and "Authorization: Bearer" in auth.get("/api-docs").text
    page = auth.get("/api-keys").text
    assert "ci" in page and "analyst" in page
