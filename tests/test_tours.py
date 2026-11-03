"""Guided tours: registry per role, every target present on its page, Thai text, routes, Dashboard prompt, Profile."""
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app import i18n, tours
from app.db import Issue, User
from app.i18n_th import CATALOG_TH
from tests.conftest import get_csrf
from tests.test_rbac import login_as, make_user

THAI = re.compile(r"[฀-๿]")


def u(role, show_all=False, done=""):
    return SimpleNamespace(role=role, is_active=True, show_all_menus=show_all, tours_done=done,
                           tour_prompt_dismissed_at=None)


def shape(user):
    return {tr.key: [s.target for s in tr.steps] for tr in tours.available(user)}


# ----------------------------------------------------------------- registry
def test_four_tours_defined():
    assert [tr.key for tr in tours.TOURS] == ["menus", "first-scan", "triage", "admin"]
    assert tours.get("triage").perm == "issues.manage" and tours.get("nope") is None
    for tr in tours.TOURS:
        for s in tr.steps:
            assert len(s.title.split()) <= 6, s.title
            assert s.body.count(". ") <= 1, s.body


def test_admin_gets_every_tour_and_step():
    got = shape(u("admin"))
    assert list(got) == ["menus", "first-scan", "triage", "admin"]
    assert got["menus"] == ["", "nav-dashboard", "nav-issues", "nav-campaigns", "nav-inventory", "nav-reports",
                            "nav-group-scan", "nav-group-system", "lang-switch", "user-chip", "guide-button"]
    assert len(got["first-scan"]) == 8 and len(got["triage"]) == 7
    assert got["admin"] == ["nav-scopes", "nav-schedules", "nav-users", "nav-settings", "nav-integrations",
                            "nav-updates", "nav-audit"]


def test_analyst_tours():
    got = shape(u("analyst"))
    assert list(got) == ["menus", "first-scan", "triage", "admin"]
    assert len(got["menus"]) == 11 and len(got["first-scan"]) == 8 and len(got["triage"]) == 7
    assert got["admin"] == ["nav-scopes", "nav-schedules"]


def test_viewer_gets_only_menus_without_hidden_items():
    got = shape(u("viewer"))
    assert list(got) == ["menus"]
    assert "nav-group-scan" not in got["menus"] and "nav-group-system" not in got["menus"]
    assert len(got["menus"]) == 9


def test_show_all_menus_keeps_nav_steps_in_step_with_the_sidebar():
    from app.navigation import nav_items
    for role in ("admin", "analyst", "viewer"):
        for show_all in (False, True):
            user = u(role, show_all)
            groups = nav_items(user)
            shown = {f"nav-{i.key}" for g in groups for i in g.items} | {f"nav-group-{g.key}" for g in groups}
            for tr in tours.available(user):
                for s in tr.steps:
                    if s.target.startswith("nav-"):
                        assert s.target in shown, (role, show_all, tr.key, s.target)
    assert "nav-group-scan" in shape(u("viewer", True))["menus"]


def test_payload_is_translated_and_marks_done():
    user = u("viewer", done="menus,bogus")
    out = tours.payload(user, tours.done_keys(user))
    assert out[0]["key"] == "menus" and out[0]["done"] is True
    assert set(out[0]) == {"key", "title", "summary", "done", "href", "steps"}
    assert out[0]["href"] == "/?tour=menus&step=0"
    assert set(out[0]["steps"][0]) == {"path", "target", "title", "body"}
    assert out[0]["title"] == "Get to know the menus"
    token = i18n.use_lang("th")
    try:
        th = tours.payload(user, set())
    finally:
        i18n.reset_lang(token)
    assert th[0]["done"] is False
    assert THAI.search(th[0]["title"]) and THAI.search(th[0]["summary"])
    assert all(THAI.search(s["body"]) for s in th[0]["steps"])


def test_every_tour_string_has_thai():
    missing = [s for s in tours.strings() if not CATALOG_TH.get(s)]
    assert not missing, missing
    assert tours.strings() <= i18n.dynamic_keys()
    for s in ("Back", "Next", "Done", "Skip tour", "Step {n} of {total}", "Nothing more to show here yet"):
        assert s in i18n.JS_STRINGS and CATALOG_TH.get(s)


# ----------------------------------------------------------------- targets exist on their pages
def _target_on(html, target):
    return f'data-tour="{target}"' in html


def _href_of(html, target):
    m = re.search(r'<a\b[^>]*data-tour="' + re.escape(target) + r'"[^>]*>', html) or \
        re.search(r'<a\b[^>]*href="([^"]+)"[^>]*data-tour="' + re.escape(target) + '"', html)
    assert m, target
    return re.search(r'href="([^"]+)"', m.group(0)).group(1)


def test_every_target_exists(auth):
    from tests.test_issue_routes import SPECS, seed
    seed(auth, SPECS[:1])
    for tr in tours.available(u("admin")):
        prev_page, prev_target = None, None
        for s in tr.steps:
            if s.path == "@follow":
                page = _href_of(auth.get(prev_page).text, prev_target) if prev_target != "@follow" else prev_page
            else:
                page = s.path
            html = auth.get(page).text
            if s.target:
                assert html.count(f'data-tour="{s.target}"') == 1, (tr.key, s.target, page)
            if s.path == "@follow":
                prev_target = "@follow"
            else:
                prev_target = s.target
            prev_page = page


def test_verify_target_on_a_version_rule_issue(auth):
    with auth.app.state.SessionLocal() as db:
        i = Issue(key="10.0.0.9:22|rule-x", vuln_id="rule-x", asset="10.0.0.9:22", address="10.0.0.9", status="new")
        db.add(i)
        db.commit()
        iid = i.id
    html = auth.get(f"/issues/{iid}").text
    assert html.count('data-tour="issue-verify"') == 1


def test_issue_link_only_on_first_row(auth):
    from tests.test_issue_routes import SPECS, seed
    seed(auth, SPECS)
    assert auth.get("/issues").text.count('data-tour="issue-link"') == 1


def test_tour_json_embedded_for_signed_in_users(auth, client):
    html = auth.get("/").text
    m = re.search(r'<script type="application/json" id="tours"[^>]*>(.*?)</script>', html, re.S)
    assert m
    data = json.loads(m.group(1))
    assert [x["key"] for x in data] == ["menus", "first-scan", "triage", "admin"]
    assert 'data-tour="guide-button"' in html
    client.cookies.clear()
    assert 'id="tours"' not in client.get("/login").text


# ----------------------------------------------------------------- routes
def _me(client, name="admin"):
    with client.app.state.SessionLocal() as db:
        return db.scalar(select(User).where(User.username == name))


def test_done_route(auth):
    csrf = get_csrf(auth, "/")
    assert auth.post("/tours/menus/done", data={"csrf": "nope"}).status_code == 403
    assert auth.post("/tours/nope/done", data={"csrf": csrf}).status_code == 404
    r = auth.post("/tours/menus/done", data={"csrf": csrf})
    assert r.status_code == 204
    assert auth.post("/tours/menus/done", data={"csrf": csrf}).status_code == 204
    assert auth.post("/tours/admin/done", headers={"X-CSRF": csrf}).status_code == 204
    assert _me(auth).tours_done == "menus,admin"


def test_dismiss_route(auth):
    csrf = get_csrf(auth, "/")
    assert auth.post("/tours/prompt/dismiss", data={"csrf": "x"}, follow_redirects=False).status_code == 403
    r = auth.post("/tours/prompt/dismiss", data={"csrf": csrf, "next": "/issues?msg=x"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/issues"
    assert _me(auth).tour_prompt_dismissed_at is not None
    r = auth.post("/tours/prompt/dismiss", data={"csrf": csrf, "next": "https://evil.example/"}, follow_redirects=False)
    assert r.headers["location"] == "/"
    r = auth.post("/tours/prompt/dismiss", headers={"X-CSRF": csrf, "X-Requested-With": "fetch"})
    assert r.status_code == 204


def test_reset_route(auth):
    csrf = get_csrf(auth, "/")
    auth.post("/tours/menus/done", data={"csrf": csrf})
    auth.post("/tours/prompt/dismiss", data={"csrf": csrf})
    assert auth.post("/profile/tours/reset", data={"csrf": "x"}, follow_redirects=False).status_code == 403
    r = auth.post("/profile/tours/reset", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/profile?msg=Tours+reset")
    me = _me(auth)
    assert me.tours_done == "" and me.tour_prompt_dismissed_at is None


def test_viewer_may_use_all_routes(auth):
    make_user(auth, "vera", "viewer")
    login_as(auth, "vera")
    csrf = get_csrf(auth, "/")
    assert auth.post("/tours/menus/done", data={"csrf": csrf}).status_code == 204
    assert auth.post("/tours/prompt/dismiss", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    assert auth.post("/profile/tours/reset", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    assert _me(auth, "vera").tours_done == ""
    assert _me(auth).tours_done == ""   # only their own profile


def test_columns_added_to_existing_db():
    from app.db import _ADDED_COLUMNS
    assert ("users", "tours_done", "TEXT NOT NULL DEFAULT ''") in _ADDED_COLUMNS
    assert ("users", "tour_prompt_dismissed_at", "DATETIME") in _ADDED_COLUMNS


# ----------------------------------------------------------------- dashboard prompt and profile
def test_prompt_shown_until_dismissed_or_a_tour_is_done(auth):
    html = auth.get("/").text
    assert 'id="tour-prompt"' in html
    assert html.index('id="tour-prompt"') < html.index('id="get-started"')
    assert 'data-tour-start="menus"' in html and 'action="/tours/prompt/dismiss"' in html
    csrf = get_csrf(auth, "/")
    auth.post("/tours/menus/done", data={"csrf": csrf})
    assert 'id="tour-prompt"' not in auth.get("/").text
    auth.post("/profile/tours/reset", data={"csrf": csrf})
    assert 'id="tour-prompt"' in auth.get("/").text
    auth.post("/tours/prompt/dismiss", data={"csrf": csrf})
    assert 'id="tour-prompt"' not in auth.get("/").text


def test_prompt_shown_to_viewer(auth):
    make_user(auth, "vera", "viewer")
    login_as(auth, "vera")
    assert 'id="tour-prompt"' in auth.get("/").text


def test_profile_section(auth):
    csrf = get_csrf(auth, "/")
    auth.post("/tours/first-scan/done", data={"csrf": csrf})
    html = auth.get("/profile").text
    assert 'id="guided-tours"' in html
    assert 'action="/profile/tours/reset"' in html
    assert 'href="/?tour=menus&amp;step=0"' in html and 'href="/issues?tour=triage&amp;step=0"' in html
    sec = html[html.index('id="guided-tours"'):]
    assert re.search(r'data-tour-key="first-scan"[^>]*data-done="1"', sec)
    assert re.search(r'data-tour-key="menus"[^>]*data-done="0"', sec)


def test_tour_pages_in_thai_have_no_missing_strings(auth, monkeypatch):
    from tests.test_i18n import set_lang
    monkeypatch.setattr(i18n, "RECORD_MISSING", True)
    i18n.MISSING.clear()
    set_lang(auth, "th")
    for path in ("/", "/profile", "/quick", "/issues", "/jobs"):
        html = auth.get(path).text
        assert THAI.search(html)
    assert not i18n.MISSING, sorted(i18n.MISSING)
    i18n.MISSING.clear()


def test_start_href_is_the_first_steps_page():
    assert tours.start_href(tours.get("triage")) == "/issues?tour=triage&step=0"
    assert tours.start_href(tours.get("first-scan")) == "/?tour=first-scan&step=0"


@pytest.mark.parametrize("status", ["new", "fixed"])
def test_verify_target_on_a_nuclei_issue(auth, status):
    """A templated issue offers Verify now as admin: in the page header while it is open, in the Next step card once
    it is marked fixed. Either way the issue-verify target is present exactly once."""
    from tests.test_issue_routes import SPECS, seed
    iid = seed(auth, SPECS[:1])["CVE-2021-41773"]
    with auth.app.state.SessionLocal() as db:
        db.get(Issue, iid).status = status
        db.commit()
    html = auth.get(f"/issues/{iid}").text
    assert html.count('data-tour="issue-verify"') == 1
    form = re.search(r'<form[^>]*data-tour="issue-verify"[^>]*>', html).group(0)
    assert f'action="/issues/{iid}/verify"' in form


def test_engine_script_only_with_tours(auth, client):
    html = auth.get("/").text
    assert re.search(r'<script src="/static/tours\.js\?v=[0-9a-f]+"></script>', html)
    assert html.index('id="tours"') < html.index("/static/tours.js")
    assert auth.get("/static/tours.js").status_code == 200
    client.cookies.clear()
    assert "/static/tours.js" not in client.get("/login").text
    app_js = (Path(tours.__file__).parent / "static" / "app.js").read_text()
    assert "tour-pop" not in app_js   # the engine lives in tours.js only


def test_guide_and_profile_links_use_start_href(auth):
    for path in ("/", "/profile"):
        html = auth.get(path).text
        assert 'href="/issues?tour=triage&amp;step=0" data-tour-start="triage"' in html, path
