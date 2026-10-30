import json

from sqlalchemy import select

from app.db import AuditLog
from tests.conftest import NEW_PASSWORD, get_csrf


def rows(client, action=None):
    with client.app.state.SessionLocal() as db:
        stmt = select(AuditLog).order_by(AuditLog.id)
        if action:
            stmt = stmt.where(AuditLog.action == action)
        return list(db.scalars(stmt))


def test_auth_events_are_audited(client):
    client.post("/login", data={"username": "admin", "password": "wrong"})
    client.post("/login", data={"username": "ghost", "password": "wrong"})
    failed = rows(client, "auth.login_failed")
    assert [r.username for r in failed] == ["admin", "ghost"]
    assert failed[0].user_id is not None and failed[1].user_id is None
    assert failed[0].ip

    from tests.conftest import login_and_change_password
    login_and_change_password(client)
    assert rows(client, "auth.login")[0].username == "admin"
    assert len(rows(client, "auth.password_changed")) == 1

    csrf = get_csrf(client, "/")
    client.post("/logout", data={"csrf": csrf})
    assert len(rows(client, "auth.logout")) == 1
    # passwords never land in the audit trail
    assert all("changeme" not in r.details and NEW_PASSWORD not in r.details for r in rows(client))
    assert json.loads(failed[1].details) == {"reason": "unknown user"}
