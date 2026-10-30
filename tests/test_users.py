import re

from sqlalchemy import select

from app.db import AuditLog, User
from tests.conftest import NEW_PASSWORD, get_csrf
from tests.test_rbac import login_as, make_user


def uid_of(client, username):
    with client.app.state.SessionLocal() as db:
        return db.scalar(select(User.id).where(User.username == username))


def get_user(client, username):
    with client.app.state.SessionLocal() as db:
        return db.scalar(select(User).where(User.username == username))


def actions(client):
    with client.app.state.SessionLocal() as db:
        return [a.action for a in db.scalars(select(AuditLog).order_by(AuditLog.id))]


def temp_password(html):
    m = re.search(r'data-secret="([^"]+)"', html)
    assert m, "temporary password not shown"
    return m.group(1)


def test_create_user_shows_temp_password_once_and_forces_change(auth):
    csrf = get_csrf(auth, "/users")
    r = auth.post("/users", data={"csrf": csrf, "username": "alice", "display_name": "Alice A", "email": "a@corp.test",
                                  "role": "analyst"})
    assert r.status_code == 200
    pw = temp_password(r.text)
    assert len(pw) >= 12
    assert "data-secret" not in auth.get("/users").text  # shown once
    u = get_user(auth, "alice")
    assert u.role == "analyst" and u.must_change_password and u.display_name == "Alice A" and u.email == "a@corp.test"
    assert "user.created" in actions(auth)
    with auth.app.state.SessionLocal() as db:
        assert all(pw not in a.details for a in db.scalars(select(AuditLog)))  # secrets never reach the audit log

    login_as(auth, "alice", pw)
    r = auth.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/change-password"


def test_create_user_validation(auth):
    csrf = get_csrf(auth, "/users")
    for data, msg in (
        ({"username": "admin", "role": "viewer"}, "already exists"),
        ({"username": "a b", "role": "viewer"}, "Username"),
        ({"username": "ok.user", "role": "root"}, "Unknown role"),
        ({"username": "ok.user", "role": "viewer", "email": "not-an-email"}, "email"),
    ):
        r = auth.post("/users", data={"csrf": csrf, **data})
        assert r.status_code == 400 and msg in r.text, (data, r.text[:200])


def test_edit_user(auth):
    make_user(auth, "bob", "viewer")
    uid = uid_of(auth, "bob")
    csrf = get_csrf(auth, f"/users/{uid}")
    r = auth.post(f"/users/{uid}", data={"csrf": csrf, "role": "analyst", "display_name": "Bob", "email": "b@corp.test"},
                  follow_redirects=False)
    assert r.status_code == 303
    u = get_user(auth, "bob")
    assert u.role == "analyst" and u.display_name == "Bob"
    assert "user.updated" in actions(auth)


def test_deactivate_and_reactivate_ends_sessions(auth):
    make_user(auth, "carol", "analyst")
    uid = uid_of(auth, "carol")
    csrf = get_csrf(auth, "/users")
    auth.post(f"/users/{uid}/active", data={"csrf": csrf})
    u = get_user(auth, "carol")
    assert not u.is_active and u.session_version == 1
    auth.post(f"/users/{uid}/active", data={"csrf": csrf})
    assert get_user(auth, "carol").is_active
    assert {"user.deactivated", "user.activated"} <= set(actions(auth))


def test_reset_password(auth):
    make_user(auth, "dave", "viewer")
    uid = uid_of(auth, "dave")
    csrf = get_csrf(auth, "/users")
    r = auth.post(f"/users/{uid}/reset-password", data={"csrf": csrf})
    pw = temp_password(r.text)
    u = get_user(auth, "dave")
    assert u.must_change_password and u.session_version == 1
    login_as(auth, "dave", pw)
    assert "user.password_reset" in actions(auth)
    login_as(auth, "dave", pw)  # still the temp password until changed
    r = auth.post("/login", data={"username": "dave", "password": NEW_PASSWORD})
    assert r.status_code == 401


def test_delete_user(auth):
    make_user(auth, "erin", "viewer")
    uid = uid_of(auth, "erin")
    csrf = get_csrf(auth, "/users")
    r = auth.post(f"/users/{uid}/delete", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert get_user(auth, "erin") is None
    assert "user.deleted" in actions(auth)


def test_self_and_last_admin_guards(auth):
    me = uid_of(auth, "admin")
    csrf = get_csrf(auth, "/users")
    for path, data in ((f"/users/{me}/active", {}), (f"/users/{me}/delete", {}), (f"/users/{me}/reset-password", {}),
                       (f"/users/{me}", {"role": "viewer"})):
        r = auth.post(path, data={"csrf": csrf, **data})
        assert r.status_code == 400 and ("yourself" in r.text or "your own" in r.text), path
    assert get_user(auth, "admin").role == "admin" and get_user(auth, "admin").is_active

    # a second admin cannot remove the last *other* admin either once only one active admin remains
    make_user(auth, "root2", "admin")
    login_as(auth, "root2")
    csrf = get_csrf(auth, "/users")
    auth.post(f"/users/{me}/active", data={"csrf": csrf})  # deactivate the original admin: allowed, root2 remains
    assert not get_user(auth, "admin").is_active
    make_user(auth, "root3", "admin", is_active=False)
    r = auth.post(f"/users/{uid_of(auth, 'root3')}/delete", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303  # deleting an inactive admin is fine


def test_last_active_admin_guard(auth):
    """Defence in depth: through the UI the self-guard fires first, so test the guard function directly."""
    from app.routers.users import active_admin_count, user_change_error
    make_user(auth, "viewer1", "viewer")
    with auth.app.state.SessionLocal() as db:
        admin = db.scalar(select(User).where(User.username == "admin"))
        other = db.scalar(select(User).where(User.username == "viewer1"))
        assert active_admin_count(db) == 1
        for change in ("demote", "deactivate", "delete"):
            assert "last active admin" in user_change_error(db, actor=other, target=admin, change=change)
        assert user_change_error(db, actor=other, target=other, change="delete") is not None  # self
        assert user_change_error(db, actor=admin, target=other, change="delete") is None


def test_analyst_cannot_manage_users(auth):
    make_user(auth, "ana", "analyst")
    login_as(auth, "ana")
    assert auth.get("/users").status_code == 403
    csrf = get_csrf(auth, "/")
    assert auth.post("/users", data={"csrf": csrf, "username": "x", "role": "admin"}).status_code == 403
    assert "/users" not in auth.get("/").text.split('class="nav"')[1].split("</nav>")[0]
