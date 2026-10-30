import json

from sqlalchemy import select

from app.db import AuditLog, Delivery, IssueTicket, NotificationChannel, NotificationRule
from tests.conftest import get_csrf
from tests.test_channels import FakeHttp
from tests.test_issue_routes import SPECS, seed
from tests.test_rbac import login_as, make_user

SLACK_URL = "https://hooks.slack.com/services/T000/B000/supersecretvalue"


def actions(client):
    with client.app.state.SessionLocal() as db:
        return [a.action for a in db.scalars(select(AuditLog))]


def create_channel(client, kind="slack", name="SOC Slack", **fields):
    csrf = get_csrf(client, "/integrations")
    data = {"csrf": csrf, "name": name, "kind": kind}
    data.update({f"{kind}__{k}": v for k, v in fields.items()})
    return client.post("/integrations/channels", data=data, follow_redirects=False)


def chan(client):
    with client.app.state.SessionLocal() as db:
        c = db.scalar(select(NotificationChannel).order_by(NotificationChannel.id.desc()))
        db.expunge(c)
        return c


def test_channel_secret_is_encrypted_and_never_rendered(auth):
    r = create_channel(auth, webhook_url=SLACK_URL)
    assert r.status_code == 303
    c = chan(auth)
    assert c.kind == "slack" and "supersecretvalue" not in c.secret
    assert auth.app.state.secretbox.decrypt(c.secret) == {"webhook_url": SLACK_URL}
    for page in ("/integrations", f"/integrations/channels/{c.id}"):
        assert "supersecretvalue" not in auth.get(page).text
    assert "stored" in auth.get(f"/integrations/channels/{c.id}").text
    # blank secret keeps the stored value; name changes
    csrf = get_csrf(auth, f"/integrations/channels/{c.id}")
    auth.post(f"/integrations/channels/{c.id}", data={"csrf": csrf, "name": "SOC", "slack__webhook_url": ""})
    c = chan(auth)
    assert c.name == "SOC" and auth.app.state.secretbox.decrypt(c.secret) == {"webhook_url": SLACK_URL}
    assert {"integration.channel_created", "integration.channel_updated"} <= set(actions(auth))
    assert all("supersecretvalue" not in a.details for a in auth.app.state.SessionLocal().scalars(select(AuditLog)))


def test_channel_validation(auth):
    assert create_channel(auth, webhook_url="ftp://x").status_code == 400
    assert create_channel(auth, kind="jira", base_url="https://corp.atlassian.net", email="", project_key="SEC").status_code == 400
    assert create_channel(auth, kind="email", recipients="not-an-email").status_code == 400
    assert create_channel(auth, kind="nope").status_code == 400


def test_send_test_message(auth):
    auth.app.state.http = FakeHttp()
    create_channel(auth, webhook_url=SLACK_URL)
    c = chan(auth)
    csrf = get_csrf(auth, f"/integrations/channels/{c.id}")
    r = auth.post(f"/integrations/channels/{c.id}/test", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303 and auth.app.state.http.calls[-1]["url"] == SLACK_URL
    assert chan(auth).last_test_ok is True
    auth.app.state.http = FakeHttp(default=(403, "invalid_token"))
    auth.post(f"/integrations/channels/{c.id}/test", data={"csrf": csrf})
    c = chan(auth)
    assert c.last_test_ok is False and "HTTP 403" in c.last_test_message
    assert "HTTP 403" in auth.get(f"/integrations/channels/{c.id}").text


def test_jira_test_checks_credentials(auth):
    auth.app.state.http = FakeHttp({("GET", "/rest/api/2/myself"): (200, {"displayName": "Bot"}),
                                    ("GET", "/rest/api/2/project/SEC"): (200, {"key": "SEC"})})
    create_channel(auth, kind="jira", name="Jira SEC", base_url="https://corp.atlassian.net", email="bot@corp.test",
                   project_key="SEC", issue_type="Bug", api_token="tok")
    c = chan(auth)
    auth.post(f"/integrations/channels/{c.id}/test", data={"csrf": get_csrf(auth, "/integrations")})
    assert chan(auth).last_test_ok is True and "SEC" in chan(auth).last_test_message


def test_rules_crud_and_ticket_event_limits(auth):
    create_channel(auth, webhook_url=SLACK_URL)
    c = chan(auth)
    csrf = get_csrf(auth, f"/integrations/channels/{c.id}")
    r = auth.post(f"/integrations/channels/{c.id}/rules", data={"csrf": csrf, "events": ["issue.created", "issue.overdue"],
                                                                 "min_severity": "high", "scope_id": ""}, follow_redirects=False)
    assert r.status_code == 303
    with auth.app.state.SessionLocal() as db:
        rule = db.scalar(select(NotificationRule))
        assert json.loads(rule.events) == ["issue.created", "issue.overdue"] and rule.min_severity == "high"
        rid = rule.id
    assert auth.post(f"/integrations/channels/{c.id}/rules", data={"csrf": csrf, "events": [], "min_severity": "high"}).status_code == 400
    auth.post(f"/integrations/rules/{rid}/toggle", data={"csrf": csrf})
    with auth.app.state.SessionLocal() as db:
        assert db.get(NotificationRule, rid).enabled is False
    auth.post(f"/integrations/rules/{rid}/delete", data={"csrf": csrf})
    with auth.app.state.SessionLocal() as db:
        assert db.get(NotificationRule, rid) is None
    create_channel(auth, kind="gitlab", name="GL", base_url="https://gitlab.corp.test", project="sec/vulns", token="t")
    g = chan(auth)
    r = auth.post(f"/integrations/channels/{g.id}/rules", data={"csrf": csrf, "events": ["issue.overdue"], "min_severity": "high"})
    assert r.status_code == 400 and "tickets" in r.text


def test_deliveries_log_and_retry(auth):
    auth.app.state.http = FakeHttp(default=(500, "down"))
    create_channel(auth, webhook_url=SLACK_URL)
    c = chan(auth)
    csrf = get_csrf(auth, f"/integrations/channels/{c.id}")
    auth.post(f"/integrations/channels/{c.id}/rules", data={"csrf": csrf, "events": ["issue.created"], "min_severity": "low"})
    seed(auth, SPECS)
    from app import notifications as nt
    auth.portal.call(nt.dispatch_due, auth.app)
    page = auth.get("/integrations/deliveries?status=pending").text
    assert "HTTP 500" in page and "CVE-2021-41773" in page
    auth.app.state.http = FakeHttp()
    with auth.app.state.SessionLocal() as db:
        did = db.scalar(select(Delivery.id).where(Delivery.title.contains("CVE-2021-41773")))
    r = auth.post(f"/integrations/deliveries/{did}/retry", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    with auth.app.state.SessionLocal() as db:
        assert db.get(Delivery, did).status == "sent"
    assert "integration.delivery_retried" in actions(auth)


def test_create_ticket_from_issue_page(auth):
    auth.app.state.http = FakeHttp({("POST", "/api/v4/projects/sec%2Fvulns/issues"): (201, {"iid": 3, "web_url": "https://gitlab.corp.test/sec/vulns/-/issues/3"})})
    create_channel(auth, kind="gitlab", name="GitLab SEC", base_url="https://gitlab.corp.test", project="sec/vulns", token="t")
    g = chan(auth)
    ids = seed(auth, SPECS)
    iid = ids["exposed-panel"]
    page = auth.get(f"/issues/{iid}").text
    assert "Create ticket in GitLab SEC" in page
    r = auth.post(f"/issues/{iid}/tickets", data={"csrf": get_csrf(auth, f"/issues/{iid}"), "channel_id": str(g.id)},
                  follow_redirects=False)
    assert r.status_code == 303
    with auth.app.state.SessionLocal() as db:
        t = db.scalar(select(IssueTicket))
        assert t.key == "#3" and t.issue_id == iid
    assert "https://gitlab.corp.test/sec/vulns/-/issues/3" in auth.get(f"/issues/{iid}").text
    assert "issue.ticket_created" in actions(auth)


def test_notification_settings(auth):
    csrf = get_csrf(auth, "/settings")
    r = auth.post("/settings/notifications", data={"csrf": csrf, "base_url": "https://scanner.corp.test/",
                                                   "smtp_host": "smtp.corp.test", "smtp_port": "587", "smtp_security": "starttls",
                                                   "smtp_username": "bot", "smtp_password": "mailpass", "smtp_from": "scanner@corp.test"},
                  follow_redirects=False)
    assert r.status_code == 303
    from app import notifications as nt
    with auth.app.state.SessionLocal() as db:
        assert nt.get_base_url(db) == "https://scanner.corp.test"
        smtp = nt.get_smtp(db, auth.app.state.secretbox)
        assert smtp["host"] == "smtp.corp.test" and smtp["password"] == "mailpass"
    page = auth.get("/settings").text
    assert "mailpass" not in page and "smtp.corp.test" in page
    assert auth.post("/settings/notifications", data={"csrf": csrf, "base_url": "scanner", "smtp_security": "starttls"}).status_code == 400


def test_permissions(auth):
    create_channel(auth, webhook_url=SLACK_URL)
    c = chan(auth)
    make_user(auth, "ana", "analyst")
    login_as(auth, "ana")
    for path in ("/integrations", f"/integrations/channels/{c.id}", "/integrations/deliveries"):
        assert auth.get(path).status_code == 403, path
    csrf = get_csrf(auth, "/")
    for path in ("/integrations/channels", f"/integrations/channels/{c.id}", f"/integrations/channels/{c.id}/test",
                 f"/integrations/channels/{c.id}/delete", f"/integrations/channels/{c.id}/rules", "/settings/notifications"):
        assert auth.post(path, data={"csrf": csrf}).status_code == 403, path
