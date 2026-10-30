"""Delivery to external systems: webhook, Slack, Teams, email, Jira and GitLab tickets.

Every function takes an injectable ``http`` callable (and ``smtp_send`` for email) so tests run offline.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import smtplib
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Callable
from urllib.parse import quote

import httpx

KINDS = {"webhook": "Webhook (JSON)", "slack": "Slack", "teams": "Microsoft Teams", "email": "Email",
         "jira": "Jira", "gitlab": "GitLab"}
TICKET_KINDS = ("jira", "gitlab")
# form fields per kind: (name, label, secret?)
FIELDS = {
    "webhook": [("url", "Endpoint URL", False), ("signing_secret", "Signing secret (HMAC-SHA256)", True)],
    "slack": [("webhook_url", "Incoming webhook URL", True)],
    "teams": [("webhook_url", "Workflows webhook URL", True)],
    "email": [("recipients", "Recipients (comma separated)", False), ("to_assignee", "Also email the issue assignee", False)],
    "jira": [("base_url", "Jira URL", False), ("email", "Account email / username", False),
             ("project_key", "Project key", False), ("issue_type", "Issue type", False), ("api_token", "API token", True)],
    "gitlab": [("base_url", "GitLab URL", False), ("project", "Project id or path", False),
               ("labels", "Extra labels", False), ("token", "Access token (api scope)", True)],
}
EMAIL_RE = re.compile(r"^[^@\s,]+@[^@\s,]+\.[^@\s,]+$")


class DeliveryError(Exception):
    pass


@dataclass
class Message:
    event: str
    title: str
    text: str
    severity: str = ""
    url: str = ""
    fields: list = field(default_factory=list)
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"event": self.event, "title": self.title, "text": self.text, "severity": self.severity,
                "url": self.url, "fields": [list(f) for f in self.fields], "data": self.data}

    @classmethod
    def from_dict(cls, d: dict) -> "Message":
        return cls(event=d.get("event", ""), title=d.get("title", ""), text=d.get("text", ""),
                   severity=d.get("severity", ""), url=d.get("url", ""),
                   fields=[tuple(f) for f in d.get("fields") or []], data=d.get("data") or {})


@dataclass
class HttpResponse:
    status: int
    text: str

    def json(self):
        return json.loads(self.text or "null")


@dataclass
class Ticket:
    key: str
    url: str
    external_id: str


Http = Callable[..., HttpResponse]


def real_http(method: str, url: str, headers=None, json=None, content=None, auth=None) -> HttpResponse:
    try:
        r = httpx.request(method, url, headers=headers, json=json, content=content, auth=auth, timeout=20,
                          follow_redirects=False)
    except httpx.HTTPError as e:
        raise DeliveryError(f"{type(e).__name__}: {e}") from e
    return HttpResponse(r.status_code, r.text)


def real_smtp_send(cfg: dict, msg: EmailMessage) -> None:
    host, port = cfg.get("host", ""), int(cfg.get("port") or 25)
    security = cfg.get("security", "starttls")
    try:
        if security == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=20, context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(host, port, timeout=20)
        with server:
            if security == "starttls":
                server.starttls(context=ssl.create_default_context())
            if cfg.get("username"):
                server.login(cfg["username"], cfg.get("password", ""))
            server.send_message(msg)
    except (OSError, smtplib.SMTPException) as e:
        raise DeliveryError(f"SMTP: {e}") from e


def _check(r: HttpResponse, what: str) -> HttpResponse:
    if not 200 <= r.status < 300:
        raise DeliveryError(f"{what}: HTTP {r.status} {r.text[:200]}")
    return r


def _need(value: str, what: str) -> str:
    if not value:
        raise DeliveryError(f"{what} is not configured.")
    return value


def _facts(msg: Message) -> str:
    return " · ".join(f"{k}: {v}" for k, v in msg.fields)


# ----------------------------------------------------------------- messages
def _webhook(http: Http, config: dict, secret: dict, msg: Message) -> None:
    url = _need(config.get("url", ""), "Webhook URL")
    body = json.dumps(msg.to_dict(), sort_keys=True).encode()
    headers = {"Content-Type": "application/json", "X-ZDRS-Event": msg.event}
    if secret.get("signing_secret"):
        headers["X-ZDRS-Signature"] = "sha256=" + hmac.new(secret["signing_secret"].encode(), body, hashlib.sha256).hexdigest()
    _check(http("POST", url, headers=headers, content=body), "Webhook")


def _slack(http: Http, secret: dict, msg: Message) -> None:
    url = _need(secret.get("webhook_url", ""), "Slack webhook URL")
    link = f"*<{msg.url}|{msg.title}>*" if msg.url else f"*{msg.title}*"
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": f"{link}\n{msg.text}"}}]
    if msg.fields:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": _facts(msg)}]})
    _check(http("POST", url, json={"text": msg.title, "blocks": blocks}), "Slack")


def _teams(http: Http, secret: dict, msg: Message) -> None:
    url = _need(secret.get("webhook_url", ""), "Teams webhook URL")
    card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
            "body": [{"type": "TextBlock", "text": msg.title, "weight": "Bolder", "size": "Medium", "wrap": True},
                     {"type": "TextBlock", "text": msg.text, "wrap": True},
                     {"type": "FactSet", "facts": [{"title": k, "value": str(v)} for k, v in msg.fields]}],
            "actions": [{"type": "Action.OpenUrl", "title": "Open in scanner", "url": msg.url}] if msg.url else []}
    payload = {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
                                                   "content": card}]}
    _check(http("POST", url, json=payload), "Teams")


def parse_recipients(text: str) -> list[str]:
    return [r.strip() for r in (text or "").replace(";", ",").replace("\n", ",").split(",") if r.strip()]


def _email(smtp_send, smtp: dict, config: dict, msg: Message, extra: list[str]) -> None:
    if not smtp.get("host") or not smtp.get("from_addr"):
        raise DeliveryError("SMTP server is not configured (Settings → Email).")
    to: list[str] = []
    for addr in parse_recipients(config.get("recipients", "")) + list(extra or []):
        if addr and addr not in to:
            to.append(addr)
    if not to:
        raise DeliveryError("No email recipient.")
    m = EmailMessage()
    m["Subject"], m["From"], m["To"] = msg.title[:200], smtp["from_addr"], ", ".join(to)
    lines = [msg.text, ""] + [f"{k}: {v}" for k, v in msg.fields] + ([f"\n{msg.url}"] if msg.url else [])
    m.set_content("\n".join(lines))
    smtp_send(smtp, m)


def send_message(kind: str, http: Http, smtp_send, smtp: dict, config: dict, secret: dict, msg: Message,
                 extra_recipients: list[str] | None = None) -> None:
    if kind == "webhook":
        _webhook(http, config, secret, msg)
    elif kind == "slack":
        _slack(http, secret, msg)
    elif kind == "teams":
        _teams(http, secret, msg)
    elif kind == "email":
        _email(smtp_send, smtp, config, msg, extra_recipients or [])
    else:
        raise DeliveryError(f"{kind} channels deliver tickets, not messages.")


# ----------------------------------------------------------------- tickets
def _jira(config: dict, secret: dict) -> tuple[str, tuple[str, str]]:
    base = _need(config.get("base_url", "").rstrip("/"), "Jira URL")
    return base, (_need(config.get("email", ""), "Jira account"), _need(secret.get("api_token", ""), "Jira API token"))


def _gitlab(config: dict, secret: dict) -> tuple[str, dict]:
    base = _need(config.get("base_url", "").rstrip("/"), "GitLab URL")
    project = quote(_need(config.get("project", ""), "GitLab project"), safe="")
    return f"{base}/api/v4/projects/{project}", {"PRIVATE-TOKEN": _need(secret.get("token", ""), "GitLab token")}


def _ticket_body(msg: Message) -> str:
    return "\n".join([msg.text, ""] + [f"{k}: {v}" for k, v in msg.fields] + ["", f"Scanner: {msg.url}"])


def ticket_create(kind: str, http: Http, config: dict, secret: dict, msg: Message) -> Ticket:
    if kind == "jira":
        base, auth = _jira(config, secret)
        fields = {"project": {"key": _need(config.get("project_key", ""), "Jira project key")},
                  "summary": msg.title[:250], "description": _ticket_body(msg),
                  "issuetype": {"name": config.get("issue_type") or "Bug"},
                  "labels": ["zero-day-scanner"] + ([msg.severity] if msg.severity else [])}
        data = _check(http("POST", f"{base}/rest/api/2/issue", json={"fields": fields}, auth=auth), "Jira create").json()
        return Ticket(key=data["key"], url=f"{base}/browse/{data['key']}", external_id=data["key"])
    if kind == "gitlab":
        api, headers = _gitlab(config, secret)
        labels = ["zero-day-scanner"] + ([f"severity::{msg.severity}"] if msg.severity else []) + \
            [x.strip() for x in (config.get("labels") or "").split(",") if x.strip()]
        data = _check(http("POST", f"{api}/issues", headers=headers,
                           json={"title": msg.title[:250], "description": _ticket_body(msg), "labels": ",".join(labels)}),
                      "GitLab create").json()
        return Ticket(key=f"#{data['iid']}", url=data.get("web_url", ""), external_id=str(data["iid"]))
    raise DeliveryError(f"{kind} does not create tickets.")


def ticket_comment(kind: str, http: Http, config: dict, secret: dict, key: str, external_id: str, body: str) -> None:
    if kind == "jira":
        base, auth = _jira(config, secret)
        _check(http("POST", f"{base}/rest/api/2/issue/{external_id}/comment", json={"body": body}, auth=auth), "Jira comment")
    else:
        api, headers = _gitlab(config, secret)
        _check(http("POST", f"{api}/issues/{external_id}/notes", headers=headers, json={"body": body}), "GitLab note")


def ticket_close(kind: str, http: Http, config: dict, secret: dict, key: str, external_id: str) -> None:
    if kind == "jira":
        base, auth = _jira(config, secret)
        data = _check(http("GET", f"{base}/rest/api/2/issue/{external_id}/transitions", auth=auth), "Jira transitions").json()
        done = next((t for t in data.get("transitions", [])
                     if ((t.get("to") or {}).get("statusCategory") or {}).get("key") == "done"), None)
        if done is None:
            raise DeliveryError("Jira: no transition to a done status is available for this ticket.")
        _check(http("POST", f"{base}/rest/api/2/issue/{external_id}/transitions", json={"transition": {"id": done["id"]}},
                    auth=auth), "Jira transition")
    else:
        api, headers = _gitlab(config, secret)
        _check(http("PUT", f"{api}/issues/{external_id}", headers=headers, json={"state_event": "close"}), "GitLab close")


def ticket_reopen(kind: str, http: Http, config: dict, secret: dict, key: str, external_id: str) -> None:
    if kind == "gitlab":
        api, headers = _gitlab(config, secret)
        _check(http("PUT", f"{api}/issues/{external_id}", headers=headers, json={"state_event": "reopen"}), "GitLab reopen")
    # Jira workflows differ too much to reopen safely; the caller adds a comment instead.


def ticket_is_closed(kind: str, http: Http, config: dict, secret: dict, key: str, external_id: str) -> bool:
    if kind == "jira":
        base, auth = _jira(config, secret)
        data = _check(http("GET", f"{base}/rest/api/2/issue/{external_id}?fields=status", auth=auth), "Jira status").json()
        return ((data.get("fields") or {}).get("status") or {}).get("statusCategory", {}).get("key") == "done"
    api, headers = _gitlab(config, secret)
    return _check(http("GET", f"{api}/issues/{external_id}", headers=headers), "GitLab status").json().get("state") == "closed"


# ----------------------------------------------------------------- validation
def _url_ok(u: str) -> bool:
    return u.startswith(("https://", "http://")) and " " not in u


def validate_channel(kind: str, config: dict, secret: dict) -> str | None:
    if kind not in KINDS:
        return "Unknown channel type."
    if kind == "webhook" and not _url_ok(config.get("url", "")):
        return "Webhook URL must start with http:// or https://."
    if kind in ("slack", "teams") and secret.get("webhook_url") is not None and not _url_ok(secret.get("webhook_url", "")):
        return "Webhook URL must start with https://."
    if kind == "email":
        bad = [r for r in parse_recipients(config.get("recipients", "")) if not EMAIL_RE.match(r)]
        if bad:
            return f"Not an email address: {bad[0]}"
        if not parse_recipients(config.get("recipients", "")) and not config.get("to_assignee"):
            return "Add at least one recipient email or tick 'also email the assignee'."
    if kind == "jira":
        if not _url_ok(config.get("base_url", "")):
            return "Jira URL must start with https://."
        if not config.get("email") or not config.get("project_key"):
            return "Jira needs the account email and the project key."
    if kind == "gitlab":
        if not _url_ok(config.get("base_url", "")):
            return "GitLab URL must start with https://."
        if not config.get("project"):
            return "GitLab needs the project id or path."
    return None


def test_channel(kind: str, http: Http, smtp_send, smtp: dict, config: dict, secret: dict, base_url: str) -> str:
    """Send a test message, or check ticketing credentials. Returns a human-readable success message."""
    if kind == "jira":
        base, auth = _jira(config, secret)
        me = _check(http("GET", f"{base}/rest/api/2/myself", auth=auth), "Jira login").json()
        project = config.get("project_key", "")
        _check(http("GET", f"{base}/rest/api/2/project/{project}", auth=auth), f"Jira project {project}")
        return f"Signed in to Jira as {me.get('displayName') or me.get('name') or 'the account'}; project {project} is reachable."
    if kind == "gitlab":
        api, headers = _gitlab(config, secret)
        data = _check(http("GET", api, headers=headers), "GitLab project").json()
        return f"GitLab project {data.get('path_with_namespace') or config.get('project')} is reachable."
    msg = Message(event="test", title="[TEST] 0-Day Rapid Scanner notification",
                  text="This is a test message. If you can read it, the channel works.", severity="info",
                  url=base_url, fields=[("Channel", KINDS.get(kind, kind))], data={"test": True})
    send_message(kind, http, smtp_send, smtp, config, secret, msg)
    return "Test message sent."
