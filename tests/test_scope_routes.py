import re

from sqlalchemy import select

from app.db import AuditLog, Issue, Job, Schedule, Scope, User
from tests.conftest import get_csrf, wait_job
from tests.test_inventory import seed_inventory
from tests.test_issue_routes import SPECS, seed
from tests.test_rbac import login_as, make_user


def actions(client):
    with client.app.state.SessionLocal() as db:
        return [a.action for a in db.scalars(select(AuditLog))]


def create_scope(client, **form):
    csrf = get_csrf(client, "/scopes/new")
    data = {"csrf": csrf, "name": "DMZ", "description": "Public web", "targets": "10.0.0.0/24",
            "exclusions": "10.0.0.7", "criticality": "critical", "owner_id": ""}
    data.update(form)
    return client.post("/scopes", data=data, follow_redirects=False)


def scope_id(client, name="DMZ"):
    with client.app.state.SessionLocal() as db:
        return db.scalar(select(Scope.id).where(Scope.name == name))


def test_scope_crud_rescopes_issues(auth):
    ids = seed(auth, SPECS)  # 10.0.0.5 critical, 10.0.0.6 medium, 10.0.0.7 low
    me = auth.app.state.SessionLocal().scalar(select(User.id).where(User.username == "admin"))
    r = create_scope(auth, owner_id=str(me))
    assert r.status_code == 303
    sid = scope_id(auth)
    with auth.app.state.SessionLocal() as db:
        scoped = {i.vuln_id: i.scope_id for i in db.scalars(select(Issue))}
        assert scoped["CVE-2021-41773"] == sid and scoped["exposed-panel"] == sid and scoped["weak-cipher"] is None
        assert all(i.assignee_id is None for i in db.scalars(select(Issue)))  # existing issues keep their assignee
    page = auth.get("/scopes").text
    assert "DMZ" in page and "critical" in page and "admin" in page
    detail = auth.get(f"/scopes/{sid}").text
    assert "10.0.0.0/24" in detail and "exposed-panel title" in detail
    assert create_scope(auth).status_code == 400  # duplicate name
    assert create_scope(auth, name="Bad", targets="10.0.0.1 ; rm").status_code == 400
    csrf = get_csrf(auth, f"/scopes/{sid}")
    r = auth.post(f"/scopes/{sid}", data={"csrf": csrf, "name": "DMZ", "description": "", "targets": "10.0.0.5",
                                          "exclusions": "", "criticality": "high", "owner_id": ""}, follow_redirects=False)
    assert r.status_code == 303
    with auth.app.state.SessionLocal() as db:
        assert db.get(Issue, ids["exposed-panel"]).scope_id is None and db.get(Scope, sid).criticality == "high"
    auth.post(f"/scopes/{sid}/delete", data={"csrf": csrf})
    with auth.app.state.SessionLocal() as db:
        assert db.get(Scope, sid) is None and db.get(Issue, ids["CVE-2021-41773"]).scope_id is None
    assert {"scope.created", "scope.updated", "scope.deleted"} <= set(actions(auth))


def test_issue_scope_column_filter_and_auto_assign(auth):
    me = auth.app.state.SessionLocal().scalar(select(User.id).where(User.username == "admin"))
    create_scope(auth, owner_id=str(me))
    sid = scope_id(auth)
    ids = seed(auth, SPECS)
    with auth.app.state.SessionLocal() as db:
        assert db.get(Issue, ids["CVE-2021-41773"]).assignee_id == me  # new issue -> scope owner
        assert db.get(Issue, ids["weak-cipher"]).assignee_id is None    # excluded host
    r = auth.get(f"/issues?scope={sid}")
    assert "CVE-2021-41773 title" in r.text and "weak-cipher title" not in r.text
    r = auth.get("/issues?scope=none")
    assert "weak-cipher title" in r.text and "CVE-2021-41773 title" not in r.text
    assert "DMZ" in auth.get(f"/issues/{ids['CVE-2021-41773']}").text


def test_schedules_create_toggle_run_delete(auth):
    create_scope(auth, targets="192.168.1.0/24", exclusions="")
    sid = scope_id(auth)
    csrf = get_csrf(auth, "/schedules")
    base = {"csrf": csrf, "name": "Nightly discovery", "kind": "nmap", "scope_id": str(sid), "frequency": "daily",
            "time_of_day": "02:00", "weekday": "0", "interval_hours": "24", "port_mode": "top", "timing": "T3",
            "scan_type": "connect", "profile": "normal", "nuclei_mode": "all"}
    r = auth.post("/schedules", data=base, follow_redirects=False)
    assert r.status_code == 303
    with auth.app.state.SessionLocal() as db:
        s = db.scalar(select(Schedule))
        assert s.next_run_at is not None and s.created_by == "admin" and s.enabled
        sched_id = s.id
    page = auth.get("/schedules").text
    assert "Nightly discovery" in page and "02:00" in page and "Asia/Bangkok" in page
    assert "Nightly discovery" in auth.get(f"/scopes/{sid}").text
    assert auth.post("/schedules", data={**base, "time_of_day": "99:00"}).status_code == 400
    assert auth.post("/schedules", data={**base, "scope_id": ""}).status_code == 400
    assert auth.post("/schedules", data={**base, "port_mode": "custom", "custom_ports": "abc"}).status_code == 400

    auth.post(f"/schedules/{sched_id}/toggle", data={"csrf": csrf})
    with auth.app.state.SessionLocal() as db:
        assert not db.get(Schedule, sched_id).enabled
    r = auth.post(f"/schedules/{sched_id}/run", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/jobs/")
    wait_job(auth, int(r.headers["location"].rsplit("/", 1)[1]))
    with auth.app.state.SessionLocal() as db:
        run = db.scalar(select(AuditLog).where(AuditLog.action == "schedule.run"))
        assert run.username == "admin"  # manual run is attributed to the user
    auth.post(f"/schedules/{sched_id}/delete", data={"csrf": csrf})
    with auth.app.state.SessionLocal() as db:
        assert db.get(Schedule, sched_id) is None
    assert {"schedule.created", "schedule.toggled", "schedule.deleted"} <= set(actions(auth))


def test_campaign_verify_schedule_needs_no_scope(auth):
    csrf = get_csrf(auth, "/schedules")
    r = auth.post("/schedules", data={"csrf": csrf, "name": "Re-verify campaigns", "kind": "campaign_verify",
                                      "scope_id": "", "frequency": "interval", "interval_hours": "6",
                                      "time_of_day": "", "weekday": "0", "profile": "gentle"}, follow_redirects=False)
    assert r.status_code == 303
    assert "Every 6 hours" in auth.get("/schedules").text


def test_timezone_setting(auth):
    csrf = get_csrf(auth, "/settings")
    r = auth.post("/settings/timezone", data={"csrf": csrf, "timezone": "UTC"}, follow_redirects=False)
    assert r.status_code == 303
    assert re.search(r'name="timezone"[^>]*value="UTC"', auth.get("/settings").text)
    assert auth.post("/settings/timezone", data={"csrf": csrf, "timezone": "Nowhere/Land"}).status_code == 400


def test_inventory_group_by_scope(auth):
    seed_inventory(auth)
    create_scope(auth, name="Office", targets="192.168.1.10", exclusions="", criticality="high")
    r = auth.get("/inventory?group=scope")
    assert 'class="group-row"' in r.text and "Office" in r.text and "Unscoped" in r.text


def test_permissions(auth):
    create_scope(auth)
    sid = scope_id(auth)
    make_user(auth, "vee", "viewer")
    login_as(auth, "vee")
    assert auth.get("/scopes").status_code == 200 and auth.get(f"/scopes/{sid}").status_code == 200
    assert auth.get("/schedules").status_code == 200 and auth.get("/scopes/new").status_code == 403
    csrf = get_csrf(auth, "/scopes")
    for path in ("/scopes", f"/scopes/{sid}", f"/scopes/{sid}/delete", "/schedules", "/schedules/1/toggle",
                 "/schedules/1/run", "/schedules/1/delete"):
        assert auth.post(path, data={"csrf": csrf}).status_code == 403, path
    assert "New scope" not in auth.get("/scopes").text
