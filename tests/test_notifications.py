import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app import issues as iss
from app import notifications as nt
from app.db import (Delivery, Issue, IssueEvent, IssueTicket, Job, NotificationChannel, NotificationRule, Scope, User,
                    utcnow)
from tests.test_channels import FakeHttp
from tests.test_issue_routes import SPECS, seed


@pytest.fixture
def env(auth):
    auth.app.state.http = FakeHttp({
        ("POST", "/rest/api/2/issue/SEC-1/comment"): (201, {}),
        ("GET", "/rest/api/2/issue/SEC-1/transitions"): (200, {"transitions": [{"id": "31", "to": {"statusCategory": {"key": "done"}}}]}),
        ("POST", "/rest/api/2/issue/SEC-1/transitions"): (204, ""),
        ("POST", "/rest/api/2/issue"): (201, {"id": "1", "key": "SEC-1"}),
        ("GET", "/api/v4/projects/sec%2Fvulns/issues/9"): (200, {"state": "closed"}),
    })
    auth.app.state.sent_mail = []
    auth.app.state.smtp_send = lambda cfg, m: auth.app.state.sent_mail.append(m)
    return auth


def channel(client, kind, config=None, secret=None, events=("issue.created",), min_severity="high", scope_id=None):
    box = client.app.state.secretbox
    with client.app.state.SessionLocal() as db:
        c = NotificationChannel(name=f"{kind} channel", kind=kind, config=json.dumps(config or {}),
                                secret=box.encrypt(secret or {}))
        db.add(c)
        db.flush()
        db.add(NotificationRule(channel_id=c.id, events=json.dumps(list(events)), min_severity=min_severity, scope_id=scope_id))
        db.commit()
        return c.id


def deliveries(client, **filters):
    with client.app.state.SessionLocal() as db:
        stmt = select(Delivery).order_by(Delivery.id)
        for k, v in filters.items():
            stmt = stmt.where(getattr(Delivery, k) == v)
        rows = list(db.scalars(stmt))
        db.expunge_all()
        return rows


def dispatch(client):
    return client.portal.call(nt.dispatch_due, client.app)


SLACK = {"webhook_url": "https://hooks.slack.com/services/T/B/x"}


def test_rule_severity_threshold_and_delivery(env):
    channel(env, "slack", secret=SLACK, min_severity="high")
    seed(env, SPECS)  # critical, medium, low
    pending = deliveries(env)
    assert len(pending) == 1 and pending[0].event == "issue.created" and pending[0].status == "pending"
    assert dispatch(env) == 1
    sent = deliveries(env)[0]
    assert sent.status == "sent" and sent.sent_at and sent.attempts == 1
    call = env.app.state.http.calls[-1]
    assert call["url"] == SLACK["webhook_url"] and "CVE-2021-41773" in json.dumps(call["json"])
    assert "/issues/" in json.dumps(call["json"])


def test_scope_filtered_rule(env):
    with env.app.state.SessionLocal() as db:
        s = Scope(name="DMZ", targets="10.0.0.6", criticality="high")
        db.add(s)
        db.commit()
        sid = s.id
    channel(env, "slack", secret=SLACK, min_severity="low", scope_id=sid)
    seed(env, SPECS)
    rows = deliveries(env)
    assert len(rows) == 1 and "10.0.0.6" in rows[0].title


def test_retries_then_failed(env):
    env.app.state.http = FakeHttp(default=(500, "boom"))
    channel(env, "slack", secret=SLACK, min_severity="critical")
    seed(env, SPECS)
    dispatch(env)
    d = deliveries(env)[0]
    assert d.status == "pending" and d.attempts == 1 and "HTTP 500" in d.last_error
    assert timedelta(seconds=50) < d.next_attempt_at - utcnow() < timedelta(seconds=70)
    for _ in range(4):
        with env.app.state.SessionLocal() as db:
            db.get(Delivery, d.id).next_attempt_at = utcnow() - timedelta(seconds=1)
            db.commit()
        dispatch(env)
    d = deliveries(env)[0]
    assert d.status == "failed" and d.attempts == 5


def test_jira_ticket_created_then_synced_on_status_changes(env):
    jira = {"base_url": "https://corp.atlassian.net", "email": "bot@corp.test", "project_key": "SEC", "issue_type": "Bug"}
    cid = channel(env, "jira", config=jira, secret={"api_token": "tok"}, min_severity="critical")
    ids = seed(env, SPECS)
    dispatch(env)
    with env.app.state.SessionLocal() as db:
        t = db.scalar(select(IssueTicket))
        assert (t.issue_id, t.channel_id, t.key, t.state) == (ids["CVE-2021-41773"], cid, "SEC-1", "open")
        assert t.url == "https://corp.atlassian.net/browse/SEC-1"
        assert "ticket" in [e.kind for e in db.scalars(select(IssueEvent).where(IssueEvent.issue_id == t.issue_id))]
        issue = db.get(Issue, t.issue_id)
        iss.change_status(db, issue, "fixed", actor=None)
        iss.change_status(db, issue, "verified", actor=None)
        db.commit()
    ops = [json.loads(d.payload)["op"] for d in deliveries(env, status="pending")]
    assert ops == ["ticket.comment", "ticket.close"]
    dispatch(env)
    urls = [c["url"] for c in env.app.state.http.calls]
    assert any(u.endswith("/SEC-1/comment") for u in urls) and urls[-1].endswith("/SEC-1/transitions")
    with env.app.state.SessionLocal() as db:
        assert db.scalar(select(IssueTicket)).state == "closed"


def test_ticket_closed_externally_marks_issue_fixed_without_echo(env):
    gitlab = {"base_url": "https://gitlab.corp.test", "project": "sec/vulns"}
    cid = channel(env, "gitlab", config=gitlab, secret={"token": "glpat"}, events=())
    ids = seed(env, SPECS)
    iid = ids["CVE-2021-41773"]
    with env.app.state.SessionLocal() as db:
        db.add(IssueTicket(issue_id=iid, channel_id=cid, key="#9", external_id="9", url="u", state="open"))
        db.commit()
    assert env.portal.call(nt.poll_tickets, env.app) == 1
    with env.app.state.SessionLocal() as db:
        issue = db.get(Issue, iid)
        assert issue.status == "fixed" and db.scalar(select(IssueTicket)).state == "closed"
        ev = db.scalars(select(IssueEvent).where(IssueEvent.issue_id == iid, IssueEvent.kind == "status")).all()
        assert "closed in GitLab" in ev[-1].body
    assert not [d for d in deliveries(env) if json.loads(d.payload).get("op", "").startswith("ticket.")]


def test_email_goes_to_assignee(env):
    with env.app.state.SessionLocal() as db:
        from app.db import AppSetting
        db.add(AppSetting(key="smtp", value=json.dumps({"host": "smtp.corp.test", "port": 587, "security": "starttls",
                                                       "from_addr": "scanner@corp.test"})))
        u = User(username="olivia", password_hash="x", role="analyst", email="olivia@corp.test")
        db.add(u)
        db.commit()
        uid = u.id
    channel(env, "email", config={"recipients": "soc@corp.test", "to_assignee": "1"}, events=("issue.assigned",), min_severity="low")
    ids = seed(env, SPECS)
    with env.app.state.SessionLocal() as db:
        iss.assign(db, db.get(Issue, ids["weak-cipher"]), db.get(User, uid), actor=None)
        db.commit()
    dispatch(env)
    m = env.app.state.sent_mail[0]
    assert m["To"] == "soc@corp.test, olivia@corp.test" and "assigned" in m["Subject"].lower()


def test_overdue_notified_once(env):
    channel(env, "slack", secret=SLACK, events=("issue.overdue",), min_severity="low")
    ids = seed(env, SPECS)
    with env.app.state.SessionLocal() as db:
        db.get(Issue, ids["exposed-panel"]).due_at = utcnow() - timedelta(hours=1)
        db.commit()
        assert nt.check_overdue(db) == 1
        assert nt.check_overdue(db) == 0
        db.commit()
    rows = deliveries(env)
    assert len(rows) == 1 and rows[0].event == "issue.overdue"


def test_job_problems_use_a_cursor(env):
    channel(env, "slack", secret=SLACK, events=("scan.problem",), min_severity="low")
    with env.app.state.SessionLocal() as db:
        db.add(Job(kind="nmap", status="failed"))
        db.commit()
        assert nt.check_jobs(db) == 0          # first run only sets the cursor: no history flood
        db.add(Job(kind="nuclei", status="failed"))
        db.add(Job(kind="nuclei", status="done", params_json=json.dumps({"warnings": ["target dropped"]})))
        db.add(Job(kind="nuclei", status="done", params_json="{}"))
        db.commit()
        assert nt.check_jobs(db) == 2
        assert nt.check_jobs(db) == 0
        db.commit()
    titles = [d.title for d in deliveries(env)]
    assert any("failed" in t for t in titles) and any("warnings" in t for t in titles)


def test_status_change_event_message(env):
    channel(env, "webhook", config={"url": "https://hooks.example/in"}, events=("issue.status_changed",), min_severity="low")
    ids = seed(env, SPECS)
    with env.app.state.SessionLocal() as db:
        iss.change_status(db, db.get(Issue, ids["weak-cipher"]), "triaged", actor=None)
        db.commit()
    d = deliveries(env)[0]
    assert d.event == "issue.status_changed" and "New → Triaged" in json.loads(d.payload)["message"]["text"]
