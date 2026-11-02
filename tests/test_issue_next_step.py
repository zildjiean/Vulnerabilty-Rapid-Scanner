"""Issue page: Next step card (one-click lifecycle moves), More actions section, "Resolved" label."""
import re
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app import issues as iss
from app.db import Issue, User
from tests.conftest import get_csrf
from tests.test_issue_routes import SPECS, issue, seed
from tests.test_rbac import login_as, make_user


def set_status(client, iid, status, **fields):
    with client.app.state.SessionLocal() as db:
        i = db.get(Issue, iid)
        i.status = status
        for k, v in fields.items():
            setattr(i, k, v)
        db.commit()


def card(html):
    m = re.search(r'<section class="card next-step" id="next-step".*?</section>', html, re.S)
    return m and m.group(0)


def status_buttons(c):
    """[(status value, button label)] of the one-click status forms in the card."""
    return re.findall(r'name="status" value="([a-z_]+)">\s*<button[^>]*>(?:<svg.*?</svg>)?([^<]+)</button>', c, re.S)


def admin_id(client):
    with client.app.state.SessionLocal() as db:
        return db.scalar(select(User.id).where(User.username == "admin"))


# ----------------------------------------------------------------- unit
def test_next_actions_table():
    me = 7
    def acts(status, **kw):
        i = SimpleNamespace(status=status, assignee_id=kw.get("assignee"), template_id=kw.get("template", ""),
                            verify_job_id=kw.get("verify_job"), reverify_job_id=kw.get("reverify_job"))
        return iss.next_actions(i, me, can_scan=kw.get("can_scan", True))
    a = acts("new")
    assert (a["primary"]["kind"], a["primary"]["status"], a["primary"]["label"]) == ("status", "triaged", "Triage")
    assert [s["label"] for s in a["secondary"]] == ["Assign to me", "False positive…"]
    assert [s["label"] for s in acts("new", assignee=me)["secondary"]] == ["False positive…"]
    a = acts("triaged")
    assert a["primary"]["status"] == "in_progress" and a["primary"]["label"] == "Start work"
    assert [s["label"] for s in a["secondary"]] == ["Assign to me"]
    assert acts("triaged", assignee=me)["secondary"] == []
    a = acts("in_progress")
    assert a["primary"]["status"] == "fixed" and a["primary"]["label"] == "Mark fixed" and a["secondary"] == []
    a = acts("fixed", template="t-1")
    assert a["primary"]["kind"] == "verify" and a["primary"]["label"] == "Verify now"
    for kw, why in (({"template": ""}, "no_template"), ({"template": "t-1", "can_scan": False}, "no_scan"),
                    ({"template": "t-1", "verify_job": 3}, "running"), ({"template": "t-1", "reverify_job": 4}, "running")):
        a = acts("fixed", **kw)
        assert a["primary"] is None and a["note"] == "Waiting for re-verification" and a["why"] == why, kw
    assert acts("fixed", template="t-1", reverify_job=4)["job_id"] == 4
    assert acts("fixed", template="t-1", verify_job=3)["job_id"] == 3
    for st in ("verified", "false_positive", "accepted_risk"):
        a = acts(st)
        assert a["primary"]["status"] == "triaged" and a["primary"]["label"] == "Reopen"
    for st, a in ((s, acts(s)) for s in iss.STATUSES):   # never offers a transition the lifecycle forbids
        for x in [a["primary"], *a["secondary"]]:
            if x and x["kind"] == "status":
                assert x["status"] in iss.TRANSITIONS[st], (st, x)


def test_resolved_label():
    assert iss.STATUS_LABELS["verified"] == "Resolved"


# ----------------------------------------------------------------- page
@pytest.mark.parametrize("status,expected", [
    ("new", [("triaged", "Triage")]),
    ("triaged", [("in_progress", "Start work")]),
    ("in_progress", [("fixed", "Mark fixed")]),
    ("verified", [("triaged", "Reopen")]),
    ("false_positive", [("triaged", "Reopen")]),
    ("accepted_risk", [("triaged", "Reopen")]),
])
def test_card_buttons_per_status(auth, status, expected):
    ids = seed(auth, SPECS)
    iid = ids["exposed-panel"]
    set_status(auth, iid, status)
    html = auth.get(f"/issues/{iid}").text
    c = card(html)
    assert c, html[:500]
    assert [(s, label.strip()) for s, label in status_buttons(c)] == expected
    assert c.count("primary") >= 1
    assert ("Assign to me" in c) == (status in ("new", "triaged"))
    assert ("False positive…" in c) == (status == "new")
    # every other action sits in the closed More actions section
    m = re.search(r'<details class="more-actions" id="more-actions"( open)?>(.*?)</details>\s*<!-- /more-actions -->', html, re.S)
    assert m and m.group(1) is None
    assert f'action="/issues/{iid}/status"' in m.group(2) and 'id="change-status"' in m.group(2)
    assert f'action="/issues/{iid}/assign"' in m.group(2) and f'action="/issues/{iid}/severity"' in m.group(2)
    assert 'id="timeline"' in html and f'action="/issues/{iid}/comment"' in html.split('id="more-actions"')[0]


def test_fixed_shows_verify_or_waiting(auth):
    ids = seed(auth, SPECS)
    iid = ids["exposed-panel"]          # nuclei issue: has a template
    set_status(auth, iid, "fixed")
    c = card(auth.get(f"/issues/{iid}").text)
    assert f'action="/issues/{iid}/verify"' in c and "Verify now" in c
    set_status(auth, iid, "fixed", template_id="")
    c = card(auth.get(f"/issues/{iid}").text)
    assert "Waiting for re-verification" in c and "/verify" not in c and 'name="status"' not in c
    assert "The next scan of" in c


def test_fixed_message_while_a_verification_runs(auth):
    from app.db import Job
    ids = seed(auth, SPECS)
    iid = ids["exposed-panel"]
    with auth.app.state.SessionLocal() as db:
        j = Job(kind="nuclei", status="running")
        db.add(j)
        db.commit()
        jid = j.id
    for field in ("reverify_job_id", "verify_job_id"):
        set_status(auth, iid, "fixed", **{field: jid})
        html = auth.get(f"/issues/{iid}").text
        c = card(html)
        assert f"A verification scan is running (job #{jid})" in c and "The next scan of" not in c, field
        assert f'action="/issues/{iid}/verify"' not in html, field     # no second scan of the same asset
        set_status(auth, iid, "fixed", **{field: None})


def test_fixed_message_without_scan_rights(auth):
    from unittest.mock import patch
    ids = seed(auth, SPECS)
    iid = ids["exposed-panel"]
    set_status(auth, iid, "fixed")
    from app import authz
    real = authz.has_perm
    with patch("app.authz.has_perm", lambda u, p: False if p == "scan.run" else real(u, p)), \
         patch("app.routers.issues.has_perm", lambda u, p: False if p == "scan.run" else real(u, p)):
        c = card(auth.get(f"/issues/{iid}").text)
    assert "Ask someone with scan rights to run Verify now." in c


def test_buttons_post_the_transition(auth):
    ids = seed(auth, SPECS)
    iid = ids["exposed-panel"]
    csrf = get_csrf(auth, f"/issues/{iid}")
    for status, nxt in (("new", "triaged"), ("triaged", "in_progress"), ("in_progress", "fixed"), ("verified", "triaged")):
        set_status(auth, iid, status)
        c = card(auth.get(f"/issues/{iid}").text)
        form = re.search(rf'<form method="post" action="/issues/{iid}/status"[^>]*>(.*?)</form>', c, re.S).group(1)
        assert f'name="csrf" value="{csrf}"' in form and f'value="{nxt}"' in form
        r = auth.post(f"/issues/{iid}/status", data={"csrf": csrf, "status": nxt}, follow_redirects=False)
        assert r.status_code == 303 and issue(auth, iid).status == nxt


def test_assign_to_me(auth):
    ids = seed(auth, SPECS)
    iid = ids["exposed-panel"]
    me = admin_id(auth)
    c = card(auth.get(f"/issues/{iid}").text)
    form = re.search(rf'<form method="post" action="/issues/{iid}/assign"[^>]*>(.*?)</form>', c, re.S).group(1)
    assert f'name="assignee" value="{me}"' in form and "Assign to me" in form
    csrf = get_csrf(auth, f"/issues/{iid}")
    r = auth.post(f"/issues/{iid}/assign", data={"csrf": csrf, "assignee": str(me)}, follow_redirects=False)
    assert r.status_code == 303 and issue(auth, iid).assignee_id == me
    assert "Assign to me" not in card(auth.get(f"/issues/{iid}").text)


def test_false_positive_link_prefills_status_form(auth):
    ids = seed(auth, SPECS)
    iid = ids["exposed-panel"]
    c = card(auth.get(f"/issues/{iid}").text)
    href = re.search(r'<a [^>]*href="([^"]+)"[^>]*>False positive…</a>', c).group(1).replace("&amp;", "&")
    assert href == f"/issues/{iid}?status=false_positive#change-status"
    html = auth.get(href.split("#")[0]).text
    assert '<details class="more-actions" id="more-actions" open>' in html
    assert '<option value="false_positive" selected>' in html
    ta = re.search(r'<textarea id="comment" name="comment"[^>]*>', html).group(0)
    assert "autofocus" in ta and "required" not in ta      # switching to another status must still submit
    # no reason -> 400 with More actions open; the form never posts by itself
    csrf = get_csrf(auth, f"/issues/{iid}")
    r = auth.post(f"/issues/{iid}/status", data={"csrf": csrf, "status": "false_positive", "comment": ""})
    assert r.status_code == 400 and "needs a reason" in r.text and 'id="more-actions" open' in r.text
    assert issue(auth, iid).status == "new"
    # an unknown prefill is ignored
    assert '<details class="more-actions" id="more-actions">' in auth.get(f"/issues/{iid}?status=bogus").text


def test_read_only_users_see_no_buttons(auth):
    ids = seed(auth, SPECS)
    iid = ids["exposed-panel"]
    make_user(auth, "vns", "viewer")
    login_as(auth, "vns")
    html = auth.get(f"/issues/{iid}").text
    assert card(html) is None and "Read-only" in html and 'name="status"' not in html


def test_resolved_shown_but_api_keeps_verified(auth):
    from tests.test_api import api, new_key
    ids = seed(auth, SPECS)
    iid = ids["exposed-panel"]
    set_status(auth, iid, "verified")
    assert "Resolved" in auth.get(f"/issues/{iid}").text and "Fix verified" not in auth.get(f"/issues/{iid}").text
    assert "Resolved" in auth.get("/issues?view=closed").text
    key = new_key(auth, role="viewer")
    r = api(auth, key, "GET", f"/issues/{iid}")
    assert r.status_code == 200 and r.json()["status"] == "verified"


def test_header_verify_now_is_not_a_second_primary(auth):
    ids = seed(auth, SPECS)
    iid = ids["exposed-panel"]
    html = auth.get(f"/issues/{iid}").text
    head = html[html.index('<div class="page-actions">'):html.index('<div class="issue-head')]
    assert "Verify now" in head and "btn primary" not in head
    make_user(auth, "vhv", "viewer")
    login_as(auth, "vhv")
    assert card(auth.get(f"/issues/{iid}").text) is None


def more(html):
    m = re.search(r'<details class="more-actions" id="more-actions"( open)?>', html)
    return m and (m.group(1) is not None)


def test_more_actions_opens_on_err_and_open_flag(auth):
    ids = seed(auth, SPECS)
    iid = ids["exposed-panel"]
    assert more(auth.get(f"/issues/{iid}").text) is False
    assert more(auth.get(f"/issues/{iid}?err=Something+failed").text) is True
    assert more(auth.get(f"/issues/{iid}?open=ai").text) is True
    assert more(auth.get(f"/issues/{iid}?open=bogus").text) is False


def test_more_actions_summary_lists_what_is_inside(auth):
    ids = seed(auth, SPECS)
    html = auth.get(f"/issues/{ids['exposed-panel']}").text
    summary = re.search(r'<summary>.*?</summary>', html.split('id="more-actions"')[1], re.S).group(0)
    assert "status, owner, severity" in summary and "tickets" not in summary and "verification template" not in summary


def test_read_only_users_see_tickets_and_ai_results_outside(auth):
    from app.db import AiNote, IssueTicket, NotificationChannel
    ids = seed(auth, SPECS)
    iid = ids["exposed-panel"]
    with auth.app.state.SessionLocal() as db:
        ch = NotificationChannel(name="Jira", kind="jira", enabled=True)
        db.add(ch)
        db.flush()
        db.add(IssueTicket(issue_id=iid, channel_id=ch.id, key="SEC-42", url="https://jira.example/SEC-42", state="open"))
        db.add(AiNote(feature="explain", subject_type="issue", subject_id=str(iid), content="Patch the **panel**."))
        db.commit()
    make_user(auth, "vro", "viewer")
    login_as(auth, "vro")
    html = auth.get(f"/issues/{iid}").text
    assert "SEC-42" in html and "<strong>panel</strong>" in html
    assert 'id="more-actions"' not in html


def test_verify_without_template_redirect_opens_more_actions(auth):
    ids = seed(auth, SPECS)
    iid = ids["exposed-panel"]
    set_status(auth, iid, "new", template_id="")
    csrf = get_csrf(auth, f"/issues/{iid}")
    r = auth.post(f"/issues/{iid}/verify", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/issues/{iid}?open=more#verify"
    assert more(auth.get(r.headers["location"].split("#")[0]).text) is True
