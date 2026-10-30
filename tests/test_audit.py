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


# ---------------------------------------------------------------- audit page
import csv  # noqa: E402
import io  # noqa: E402
from datetime import datetime, timedelta  # noqa: E402

from tests.test_rbac import login_as, make_user  # noqa: E402


def seed_audit(client, n=0):
    with client.app.state.SessionLocal() as db:
        base = datetime(2026, 10, 1, 12, 0, 0)
        db.add(AuditLog(username="alice", action="scan.nmap", target="10.0.0.1", created_at=base, ip="10.9.9.9"))
        db.add(AuditLog(username="bob", action="rule.created", target="PHP", created_at=base + timedelta(days=2)))
        db.add(AuditLog(username="alice", action="user.deleted", target="mallory", created_at=base + timedelta(days=5),
                        details='{"user_id": 7}'))
        for i in range(n):
            db.add(AuditLog(username="bulk", action="job.cancelled", target=f"job #{i}", created_at=base + timedelta(days=10)))
        db.commit()


def test_audit_page_filters(auth):
    seed_audit(auth)
    r = auth.get("/audit")
    assert r.status_code == 200 and "mallory" in r.text and "auth.login" in r.text
    r = auth.get("/audit?username=alice")
    assert "mallory" in r.text and "PHP" not in r.text
    r = auth.get("/audit?action=rule")
    assert "PHP" in r.text and "mallory" not in r.text
    r = auth.get("/audit?since=2026-10-02&until=2026-10-03")
    assert "PHP" in r.text and "mallory" not in r.text and "10.0.0.1" not in r.text
    r = auth.get("/audit?since=2026-10-07")  # until defaults to now: includes today's sign-in rows
    assert "auth.login" in r.text and "mallory" not in r.text
    assert auth.get("/audit?since=not-a-date").status_code == 200  # bad dates are ignored, not 500
    assert "user_id=7" in auth.get("/audit?action=user").text


def test_audit_pagination(auth):
    seed_audit(auth, n=60)
    r = auth.get("/audit?username=bulk")
    assert r.text.count("job.cancelled") >= 50 and "job #59" in r.text and "job #0<" not in r.text
    assert 'href="/audit?username=bulk&amp;page=2"' in r.text
    r = auth.get("/audit?username=bulk&page=2")
    assert "job #0<" in r.text and "job #59" not in r.text


def test_audit_csv_export(auth):
    seed_audit(auth)
    r = auth.get("/audit.csv?username=alice")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert [x["action"] for x in rows] == ["user.deleted", "scan.nmap"]
    assert rows[1]["ip"] == "10.9.9.9" and rows[0]["details"] == "user_id=7"
    # export is itself audited
    assert any(a.action == "audit.exported" for a in rows_all(auth))


def rows_all(client):
    return rows(client)


def test_audit_csv_neutralises_formulas(auth):
    with auth.app.state.SessionLocal() as db:
        db.add(AuditLog(username="x", action="template.pulled", target="=HYPERLINK(\"http://evil\")"))
        db.commit()
    r = auth.get("/audit.csv?username=x")
    assert "'=HYPERLINK" in r.text


def test_audit_requires_admin(auth):
    make_user(auth, "ana", "analyst")
    login_as(auth, "ana")
    assert auth.get("/audit").status_code == 403
    assert auth.get("/audit.csv").status_code == 403
