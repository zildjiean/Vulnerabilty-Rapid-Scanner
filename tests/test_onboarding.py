"""Get started checklist on the Dashboard: steps, done rules, permissions, dismiss / reset."""
import time

import pytest
from sqlalchemy import delete, select

from app import onboarding as ob
from app.db import Issue, Job, NotificationChannel, Schedule, TemplateIndex, User
from tests.conftest import get_csrf
from tests.test_rbac import login_as, make_user


@pytest.fixture
def db(client):
    deadline = time.time() + 10  # the app indexes the fixture templates on start-up: let it finish, then clear it
    while client.app.state.last_index_counts is None and time.time() < deadline:
        time.sleep(0.02)
    with client.app.state.SessionLocal() as s:
        s.execute(delete(TemplateIndex))
        s.commit()
        yield s


def admin(db):
    return db.scalar(select(User).where(User.username == "admin"))


def steps(db, user):
    return {s.key: s for s in ob.checklist(db, user)}


def test_steps_in_order_with_links_and_permissions(db):
    out = ob.checklist(db, admin(db))
    assert [s.key for s in out] == ["templates", "scan", "triage", "schedule", "notify"]
    assert [s.href for s in out] == ["/updates", "/quick", "/issues", "/schedules", "/integrations"]
    assert all(s.allowed and not s.done and s.title and s.help for s in out)


def test_done_rules(db):
    u = admin(db)
    db.add(TemplateIndex(template_id="x", path="/t/x.yaml", name="x", severity="high"))
    db.add(Job(kind="nmap", status="failed"))
    db.add(Issue(key="a|CVE-1", vuln_id="CVE-1", asset="a", status="new"))
    db.commit()
    s = steps(db, u)
    assert s["templates"].done and not s["scan"].done and not s["triage"].done
    db.add(Job(kind="nmap", status="done"))
    db.add(Issue(key="a|CVE-2", vuln_id="CVE-2", asset="a", status="triaged"))
    db.add(Schedule(name="s", kind="campaign_verify", frequency="daily", time_of_day="02:00"))
    db.add(NotificationChannel(name="c", kind="webhook"))
    db.commit()
    assert all(x.done for x in ob.checklist(db, u))


def test_steps_hidden_by_permission(client, db):
    make_user(client, "ana", "analyst")
    make_user(client, "vera", "viewer")
    ana = db.scalar(select(User).where(User.username == "ana"))
    vera = db.scalar(select(User).where(User.username == "vera"))
    assert [s.key for s in ob.visible(ob.checklist(db, ana))] == ["scan", "triage", "schedule"]
    assert ob.visible(ob.checklist(db, vera)) == []
    assert not ob.show_card(db, vera)
    assert ob.show_card(db, ana)


def test_card_on_dashboard_and_hidden_when_done(auth, db):
    r = auth.get("/")
    assert 'id="get-started"' in r.text and "0 of 5 done" in r.text
    assert r.text.index('id="get-started"') < r.text.index('data-stat="issues_active"')  # above the KPIs
    assert 'href="/quick"' in r.text
    db.add(TemplateIndex(template_id="x", path="/t/x.yaml", name="x", severity="high"))
    db.add(Job(kind="nmap", status="done"))
    db.commit()
    assert "2 of 5 done" in auth.get("/").text
    db.add(Issue(key="a|CVE-2", vuln_id="CVE-2", asset="a", status="fixed"))
    db.add(Schedule(name="s", kind="campaign_verify", frequency="daily", time_of_day="02:00"))
    db.add(NotificationChannel(name="c", kind="webhook"))
    db.commit()
    assert 'id="get-started"' not in auth.get("/").text


def test_viewer_sees_no_card(auth):
    make_user(auth, "vera", "viewer")
    login_as(auth, "vera")
    assert 'id="get-started"' not in auth.get("/").text


def test_dismiss_and_reset(auth, db):
    csrf = get_csrf(auth, "/")
    assert auth.post("/onboarding/dismiss", data={"csrf": "nope"}, follow_redirects=False).status_code == 403
    r = auth.post("/onboarding/dismiss", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/")
    db.expire_all()
    assert admin(db).onboarding_dismissed_at is not None
    assert 'id="get-started"' not in auth.get("/").text
    page = auth.get("/profile").text
    assert 'action="/onboarding/reset"' in page and "Show Get started again" in page
    assert auth.post("/onboarding/reset", data={"csrf": "nope"}, follow_redirects=False).status_code == 403
    r = auth.post("/onboarding/reset", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    db.expire_all()
    assert admin(db).onboarding_dismissed_at is None
    assert 'id="get-started"' in auth.get("/").text


def test_column_added_to_existing_db():
    from app.db import _ADDED_COLUMNS
    assert ("users", "onboarding_dismissed_at", "DATETIME") in _ADDED_COLUMNS
