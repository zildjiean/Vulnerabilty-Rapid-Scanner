from sqlalchemy import select

from app.db import AuditLog, User
from tests.conftest import get_csrf
from tests.test_rbac import login_as, make_user


def test_profile_update_and_activity(auth):
    make_user(auth, "vic", "viewer")
    login_as(auth, "vic")
    r = auth.get("/profile")
    assert r.status_code == 200 and "Viewer" in r.text and "Read every page" in r.text
    csrf = get_csrf(auth, "/profile")
    r = auth.post("/profile", data={"csrf": csrf, "display_name": "Victor V", "email": "v@corp.test"}, follow_redirects=False)
    assert r.status_code == 303
    with auth.app.state.SessionLocal() as db:
        u = db.scalar(select(User).where(User.username == "vic"))
        assert u.display_name == "Victor V" and u.email == "v@corp.test" and u.role == "viewer"
        assert db.scalar(select(AuditLog).where(AuditLog.action == "profile.updated")).username == "vic"
    r = auth.get("/profile")
    assert "Victor V" in r.text and "profile.updated" in r.text  # own recent activity
    assert "Victor V" in auth.get("/").text  # top bar shows display name


def test_profile_rejects_bad_email_and_ignores_role(auth):
    csrf = get_csrf(auth, "/profile")
    r = auth.post("/profile", data={"csrf": csrf, "display_name": "x", "email": "nope"})
    assert r.status_code == 400 and "email" in r.text
    r = auth.post("/profile", data={"csrf": csrf, "display_name": "x", "email": "", "role": "viewer"}, follow_redirects=False)
    with auth.app.state.SessionLocal() as db:
        assert db.scalar(select(User).where(User.username == "admin")).role == "admin"
