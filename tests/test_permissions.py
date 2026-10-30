"""Every mutating route enforces its permission, and pages hide what the role cannot do."""
import pytest
from sqlalchemy import select

from app.db import AuditLog, Rule
from tests.conftest import get_csrf, wait_job
from tests.test_inventory import seed_inventory
from tests.test_rbac import login_as, make_user

# (method path, form data, permission)
MUTATING = [
    ("/nmap/scan", {"targets": "10.0.0.1"}, "scan.run"),
    ("/nuclei/scan", {"targets": "http://10.0.0.1", "mode": "all"}, "scan.run"),
    ("/inventory/to-nuclei", {"service_ids": ["1"]}, "scan.run"),
    ("/jobs/1/cancel", {}, "scan.run"),
    ("/inventory/delete", {"service_ids": ["1"]}, "inventory.manage"),
    ("/inventory/clear", {}, "inventory.manage"),
    ("/rules", {"name": "x", "product_pattern": "php", "version_constraint": "< 9"}, "rules.manage"),
    ("/rules/1/edit", {"name": "x", "product_pattern": "php", "version_constraint": "< 9"}, "rules.manage"),
    ("/rules/1/toggle", {}, "rules.manage"),
    ("/rules/1/delete", {}, "rules.manage"),
    ("/rules/evaluate", {}, "rules.manage"),
    ("/templates/reindex", {}, "templates.manage"),
    ("/templates/pull", {"url": "https://example.invalid/t.yaml"}, "templates.manage"),
    ("/templates/delete", {"path": "/nope.yaml"}, "templates.manage"),
    ("/updates/nuclei-templates", {}, "system.update"),
]
ANALYST_DENIED = {"system.update"}


def _as(client, role):
    make_user(client, f"u-{role}", role)
    return login_as(client, f"u-{role}")


@pytest.mark.parametrize("path,data,perm", MUTATING, ids=[m[0] for m in MUTATING])
def test_viewer_is_denied_every_mutation(auth, path, data, perm):
    seed_inventory(auth)
    _as(auth, "viewer")
    csrf = get_csrf(auth, "/")
    r = auth.post(path, data={"csrf": csrf, **data}, follow_redirects=False)
    assert r.status_code == 403, (path, r.status_code)
    assert perm in r.text


@pytest.mark.parametrize("path,data,perm", MUTATING, ids=[m[0] for m in MUTATING])
def test_analyst_is_denied_only_admin_actions(auth, path, data, perm):
    seed_inventory(auth)
    _as(auth, "analyst")
    csrf = get_csrf(auth, "/")
    r = auth.post(path, data={"csrf": csrf, **data}, follow_redirects=False)
    if perm in ANALYST_DENIED:
        assert r.status_code == 403
    else:
        assert r.status_code != 403, (path, r.text[:300])
    # let any scan the analyst started finish so its subprocess does not outlive the test
    if r.status_code == 303 and r.headers["location"].startswith("/jobs/"):
        wait_job(auth, int(r.headers["location"].rsplit("/", 1)[1]))


def test_viewer_cannot_open_rule_edit_form(auth):
    with auth.app.state.SessionLocal() as db:
        rid = db.scalar(select(Rule.id))
    _as(auth, "viewer")
    assert auth.get(f"/rules/{rid}/edit").status_code == 403


def test_viewer_pages_are_read_only(auth):
    seed_inventory(auth)
    _as(auth, "viewer")
    pages = {
        "/": ["New nmap scan"],
        "/nmap": [],
        "/nuclei": [],
        "/inventory": ["Clear inventory", "Delete selected", "Scan selected with nuclei"],
        "/rules": ["Create rule", "Evaluate now", "/toggle"],
        "/templates": ["Upload &amp; validate", "Pull &amp; validate", "Re-index"],
        "/updates": [],
    }
    for path, hidden in pages.items():
        r = auth.get(path)
        assert r.status_code == 200, path
        for text in hidden:
            assert text not in r.text, (path, text)
    for path in ("/nmap", "/nuclei", "/updates", "/rules", "/templates"):
        assert "Read-only" in auth.get(path).text, path
    assert "disabled><svg class=\"icon\"><use href=\"#i-play\"/></svg>Start nmap scan" in auth.get("/nmap").text
    # data stays visible
    assert "192.168.1.10" in auth.get("/inventory").text


def test_admin_sees_everything(auth):
    seed_inventory(auth)
    r = auth.get("/inventory")
    assert "Clear inventory" in r.text and "Scan selected with nuclei" in r.text
    assert "Read-only" not in auth.get("/nmap").text and "Read-only" not in auth.get("/updates").text


def test_actions_are_audited(auth):
    seed_inventory(auth)
    csrf = get_csrf(auth, "/")
    r = auth.post("/nmap/scan", data={"csrf": csrf, "targets": "10.0.0.9"}, follow_redirects=False)
    wait_job(auth, int(r.headers["location"].rsplit("/", 1)[1]))
    auth.post("/rules", data={"csrf": csrf, "name": "PHP old", "product_pattern": "php", "version_constraint": "< 9"})
    auth.post("/rules/evaluate", data={"csrf": csrf})
    auth.post("/inventory/clear", data={"csrf": csrf})
    r = auth.post("/updates/nuclei-templates", data={"csrf": csrf}, follow_redirects=False)
    wait_job(auth, int(r.headers["location"].rsplit("/", 1)[1]))
    with auth.app.state.SessionLocal() as db:
        got = {a.action: a for a in db.scalars(select(AuditLog))}
    for action in ("scan.nmap", "rule.created", "rule.evaluated", "inventory.cleared", "system.update"):
        assert action in got, action
        assert got[action].username == "admin"
    assert got["scan.nmap"].target == "10.0.0.9"
    assert got["rule.created"].target == "PHP old"
    assert got["system.update"].target == "nuclei-templates"


def test_denied_attempts_are_audited(auth):
    _as(auth, "viewer")
    csrf = get_csrf(auth, "/")
    auth.post("/inventory/clear", data={"csrf": csrf})
    auth.get("/users")
    with auth.app.state.SessionLocal() as db:
        denied = list(db.scalars(select(AuditLog).where(AuditLog.action == "auth.denied").order_by(AuditLog.id)))
    assert [(d.username, d.target) for d in denied] == [("u-viewer", "POST /inventory/clear"), ("u-viewer", "GET /users")]
    assert "inventory.manage" in denied[0].details
