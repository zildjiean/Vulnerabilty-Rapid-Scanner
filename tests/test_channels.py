import hashlib
import hmac
import json
import json as _json

import pytest

from app import channels as ch

MSG = ch.Message(event="issue.created", title="[CRITICAL] Apache traversal on 10.0.0.5:443", text="New confirmed issue.",
                 severity="critical", url="http://scanner.local/issues/7",
                 fields=[("Asset", "10.0.0.5:443"), ("Status", "New")], data={"issue_id": 7})


class FakeHttp:
    """Records requests; responses are scripted as (method, url-substring) -> (status, body)."""

    def __init__(self, routes=None, default=(200, "ok")):
        self.routes, self.default, self.calls = routes or {}, default, []

    def __call__(self, method, url, headers=None, json=None, content=None, auth=None):
        self.calls.append({"method": method, "url": url, "headers": headers or {}, "json": json,
                           "content": content, "auth": auth})
        for (m, frag), (status, body) in self.routes.items():
            if m == method and frag in url:
                return ch.HttpResponse(status, body if isinstance(body, str) else _json.dumps(body))
        return ch.HttpResponse(*self.default)


def test_webhook_payload_and_signature():
    http = FakeHttp()
    ch.send_message("webhook", http, None, {}, {"url": "https://hooks.example/in"}, {"signing_secret": "k"}, MSG)
    call = http.calls[0]
    body = call["content"]
    assert json.loads(body)["event"] == "issue.created" and json.loads(body)["data"] == {"issue_id": 7}
    expected = "sha256=" + hmac.new(b"k", body, hashlib.sha256).hexdigest()
    assert call["headers"]["X-ZDRS-Signature"] == expected and call["headers"]["X-ZDRS-Event"] == "issue.created"


def test_slack_and_teams_payloads():
    http = FakeHttp()
    ch.send_message("slack", http, None, {}, {}, {"webhook_url": "https://hooks.slack.com/services/x"}, MSG)
    slack = http.calls[0]["json"]
    assert slack["text"].startswith("[CRITICAL]") and "http://scanner.local/issues/7" in json.dumps(slack["blocks"])
    ch.send_message("teams", http, None, {}, {}, {"webhook_url": "https://prod.logic.azure.com/x"}, MSG)
    card = http.calls[1]["json"]["attachments"][0]
    assert card["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert card["content"]["actions"][0]["url"] == "http://scanner.local/issues/7"
    assert {"title": "Asset", "value": "10.0.0.5:443"} in card["content"]["body"][2]["facts"]


def test_http_errors_raise():
    with pytest.raises(ch.DeliveryError, match="HTTP 500"):
        ch.send_message("slack", FakeHttp(default=(500, "boom")), None, {}, {}, {"webhook_url": "https://x"}, MSG)
    with pytest.raises(ch.DeliveryError, match="not configured"):
        ch.send_message("slack", FakeHttp(), None, {}, {}, {}, MSG)


def test_email():
    sent = []
    smtp = {"host": "smtp.example", "port": 587, "security": "starttls", "from_addr": "scanner@corp.test"}
    ch.send_message("email", None, lambda cfg, m: sent.append((cfg, m)), smtp, {"recipients": "a@corp.test, b@corp.test"},
                    {}, MSG, extra_recipients=["owner@corp.test", "a@corp.test"])
    cfg, m = sent[0]
    assert m["To"] == "a@corp.test, b@corp.test, owner@corp.test" and m["From"] == "scanner@corp.test"
    assert m["Subject"].startswith("[CRITICAL]") and "http://scanner.local/issues/7" in m.get_content()
    with pytest.raises(ch.DeliveryError, match="SMTP"):
        ch.send_message("email", None, lambda c, m: None, {}, {"recipients": "a@corp.test"}, {}, MSG)
    with pytest.raises(ch.DeliveryError, match="recipient"):
        ch.send_message("email", None, lambda c, m: None, smtp, {"recipients": ""}, {}, MSG)


JIRA = {"base_url": "https://corp.atlassian.net", "email": "bot@corp.test", "project_key": "SEC", "issue_type": "Bug"}


def test_jira_ticket_lifecycle():
    http = FakeHttp({
        ("POST", "/rest/api/2/issue/SEC-12/comment"): (201, {}),
        ("GET", "/rest/api/2/issue/SEC-12/transitions"): (200, {"transitions": [
            {"id": "11", "to": {"statusCategory": {"key": "indeterminate"}}},
            {"id": "31", "to": {"statusCategory": {"key": "done"}}}]}),
        ("POST", "/rest/api/2/issue/SEC-12/transitions"): (204, ""),
        ("GET", "/rest/api/2/issue/SEC-12"): (200, {"fields": {"status": {"statusCategory": {"key": "done"}}}}),
        ("POST", "/rest/api/2/issue"): (201, {"id": "10012", "key": "SEC-12"}),
    })
    t = ch.ticket_create("jira", http, JIRA, {"api_token": "tok"}, MSG)
    assert t.key == "SEC-12" and t.url == "https://corp.atlassian.net/browse/SEC-12"
    create = http.calls[0]
    assert create["auth"] == ("bot@corp.test", "tok") and create["json"]["fields"]["project"]["key"] == "SEC"
    assert "http://scanner.local/issues/7" in create["json"]["fields"]["description"]
    ch.ticket_comment("jira", http, JIRA, {"api_token": "tok"}, t.key, t.external_id, "Fixed in scanner")
    ch.ticket_close("jira", http, JIRA, {"api_token": "tok"}, t.key, t.external_id)
    assert http.calls[-1]["json"] == {"transition": {"id": "31"}}
    assert ch.ticket_is_closed("jira", http, JIRA, {"api_token": "tok"}, t.key, t.external_id) is True


GITLAB = {"base_url": "https://gitlab.corp.test", "project": "sec/vulns", "labels": "security"}


def test_gitlab_ticket_lifecycle():
    http = FakeHttp({
        ("POST", "/issues/4/notes"): (201, {}),
        ("PUT", "/issues/4"): (200, {"state": "closed"}),
        ("GET", "/issues/4"): (200, {"state": "opened"}),
        ("POST", "/api/v4/projects/sec%2Fvulns/issues"): (201, {"iid": 4, "web_url": "https://gitlab.corp.test/sec/vulns/-/issues/4"}),
    })
    secret = {"token": "glpat-x"}
    t = ch.ticket_create("gitlab", http, GITLAB, secret, MSG)
    assert t.key == "#4" and t.external_id == "4" and t.url.endswith("/issues/4")
    assert http.calls[0]["headers"]["PRIVATE-TOKEN"] == "glpat-x"
    assert "severity::critical" in http.calls[0]["json"]["labels"] and "security" in http.calls[0]["json"]["labels"]
    ch.ticket_comment("gitlab", http, GITLAB, secret, t.key, t.external_id, "note")
    ch.ticket_close("gitlab", http, GITLAB, secret, t.key, t.external_id)
    assert http.calls[-1]["json"] == {"state_event": "close"}
    ch.ticket_reopen("gitlab", http, GITLAB, secret, t.key, t.external_id)
    assert http.calls[-1]["json"] == {"state_event": "reopen"}
    assert ch.ticket_is_closed("gitlab", http, GITLAB, secret, t.key, t.external_id) is False


def test_validate_channel_config():
    assert ch.validate_channel("slack", {}, {"webhook_url": "https://hooks.slack.com/x"}) is None
    assert "URL" in ch.validate_channel("slack", {}, {"webhook_url": "ftp://x"})
    assert ch.validate_channel("jira", {**JIRA}, {"api_token": "t"}) is None
    assert "project" in ch.validate_channel("jira", {**JIRA, "project_key": ""}, {"api_token": "t"}).lower()
    assert "email" in ch.validate_channel("email", {"recipients": "nope"}, {}).lower()
    assert ch.validate_channel("bogus", {}, {})
