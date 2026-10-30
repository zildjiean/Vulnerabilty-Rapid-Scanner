import sqlite3

import pytest
from sqlalchemy import select

from app.db import AuditLog, User, init_db, make_engine, make_session_factory

OLD_USERS_SCHEMA = """
CREATE TABLE users (
    id INTEGER NOT NULL PRIMARY KEY,
    username VARCHAR(64) UNIQUE,
    password_hash VARCHAR(128),
    must_change_password BOOLEAN,
    created_at DATETIME
);
INSERT INTO users (id, username, password_hash, must_change_password, created_at)
VALUES (1, 'admin', 'x', 0, '2026-10-29 00:00:00');
"""


def test_migration_upgrades_old_users_table(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript(OLD_USERS_SCHEMA)
    con.commit()
    con.close()
    engine = make_engine(f"sqlite:///{path}")
    init_db(engine)
    init_db(engine)  # idempotent
    with make_session_factory(engine)() as db:
        u = db.scalar(select(User))
        assert u.role == "admin" and u.is_active is True and u.session_version == 0
        assert u.display_name == "" and u.email == "" and u.last_login_at is None
        db.add(AuditLog(username="admin", action="test"))
        db.commit()
        assert db.query(AuditLog).count() == 1


def test_new_user_defaults(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'new.db'}")
    init_db(engine)
    with make_session_factory(engine)() as db:
        db.add(User(username="u", password_hash="x"))
        db.commit()
        u = db.scalar(select(User))
        assert u.role == "viewer" and u.is_active is True and u.session_version == 0


# ---------------------------------------------------------------- permissions
from app.auth import hash_password  # noqa: E402
from app.authz import PERMISSIONS, ROLES, has_perm  # noqa: E402
from tests.conftest import NEW_PASSWORD, get_csrf  # noqa: E402


def test_permission_matrix():
    assert ROLES == ("admin", "analyst", "viewer")
    admin, analyst, viewer = (User(username=r, role=r, is_active=True) for r in ROLES)
    for perm in PERMISSIONS:
        assert has_perm(admin, perm)
    for perm in ("view", "scan.run", "inventory.manage", "rules.manage", "templates.manage"):
        assert has_perm(analyst, perm)
    for perm in ("system.update", "users.manage", "audit.view"):
        assert not has_perm(analyst, perm)
    assert has_perm(viewer, "view")
    assert not any(has_perm(viewer, p) for p in PERMISSIONS if p != "view")
    assert not has_perm(None, "view")
    assert not has_perm(User(username="x", role="admin", is_active=False), "view")
    assert not has_perm(User(username="x", role="bogus", is_active=True), "view")
    with pytest.raises(KeyError):
        has_perm(admin, "no.such.permission")


def make_user(client, username, role, password=NEW_PASSWORD, **kw):
    with client.app.state.SessionLocal() as db:
        u = User(username=username, role=role, password_hash=hash_password(password), must_change_password=False, **kw)
        db.add(u)
        db.commit()
        return u.id


def login_as(client, username, password=NEW_PASSWORD):
    client.cookies.clear()
    r = client.post("/login", data={"username": username, "password": password}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return client


def test_forbidden_renders_access_denied_page(auth):
    make_user(auth, "vera", "viewer")
    login_as(auth, "vera")
    csrf = get_csrf(auth, "/nmap")
    r = auth.post("/nmap/scan", data={"csrf": csrf, "targets": "10.0.0.1"})
    assert r.status_code == 403
    assert "Access denied" in r.text and "viewer" in r.text


# ---------------------------------------------------------------- sessions
def test_inactive_user_cannot_log_in(client):
    make_user(client, "ina", "analyst", is_active=False)
    r = client.post("/login", data={"username": "ina", "password": NEW_PASSWORD}, follow_redirects=False)
    assert r.status_code == 401 and "Invalid username or password" in r.text


def test_login_records_last_login(client):
    uid = make_user(client, "ann", "analyst")
    login_as(client, "ann")
    with client.app.state.SessionLocal() as db:
        assert db.get(User, uid).last_login_at is not None


@pytest.mark.parametrize("change", ["deactivate", "bump"])
def test_existing_session_ends_when_user_changes(client, change):
    uid = make_user(client, "sam", "analyst")
    login_as(client, "sam")
    assert client.get("/", follow_redirects=False).status_code == 200
    with client.app.state.SessionLocal() as db:
        u = db.get(User, uid)
        if change == "deactivate":
            u.is_active = False
        else:
            u.session_version += 1
        db.commit()
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
