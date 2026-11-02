"""Merged menus: one navigation structure drives the sidebar (per role) and the page tab bars."""
import re
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app import navigation as nav
from app.db import AuditLog, User
from tests.conftest import get_csrf
from tests.test_rbac import login_as, make_user


def u(role, show_all=False):
    return SimpleNamespace(role=role, is_active=True, show_all_menus=show_all)


def hrefs(groups):
    return [i.href for g in groups for i in g.items]


def groups_of(groups):
    return [g.key for g in groups]


CORE = ["/", "/issues", "/campaigns", "/inventory", "/reports"]


# ----------------------------------------------------------------- unit: nav_items per role
def test_structure_keys_and_tabs():
    full = {g.key: g for g in nav.NAV}
    assert list(full) == ["core", "scan", "automation", "library", "system"]
    assert [i.href for i in full["core"].items] == CORE
    assert [i.href for i in full["scan"].items] == ["/quick", "/jobs"]
    assert [i.href for i in full["automation"].items] == ["/scopes", "/schedules"]
    assert [i.href for i in full["library"].items] == ["/templates"]
    assert full["system"].closed_by_default
    items = {i.key: i for g in nav.NAV for i in g.items}
    assert [t.href for t in items["issues"].tabs] == ["/issues", "/findings"]
    assert [t.href for t in items["campaigns"].tabs] == ["/campaigns", "/watch"]
    assert [t.href for t in items["inventory"].tabs] == ["/inventory", "/changes", "/discovery#assets"]
    assert [t.href for t in items["quick"].tabs] == ["/quick", "/nmap", "/nuclei", "/discovery"]
    assert [t.href for t in items["templates"].tabs] == ["/templates", "/rules"]
    assert set(items["quick"].active) == {"quick", "nmap", "nuclei", "discovery"}
    assert set(items["inventory"].active) == {"inventory", "changes"}
    assert set(items["issues"].active) == {"issues", "findings"}
    assert set(items["campaigns"].active) == {"campaigns", "watch"}
    assert set(items["templates"].active) == {"templates", "rules"}


def test_viewer_sees_core_only():
    g = nav.nav_items(u("viewer"))
    assert groups_of(g) == ["core"] and hrefs(g) == CORE
    items = {i.key: i for i in g[0].items}
    assert [t.href for t in items["issues"].tabs] == ["/issues", "/findings"]   # reading raw findings is allowed
    assert [t.href for t in items["inventory"].tabs] == ["/inventory", "/changes", "/discovery#assets"]


def test_analyst_sees_work_groups_but_not_admin_system_items():
    g = nav.nav_items(u("analyst"))
    assert groups_of(g) == ["core", "scan", "automation", "library", "system"]
    system = [i.href for i in g[-1].items]
    assert system == ["/api-keys"]          # no Updates (system.update), no admin-only items
    assert "/quick" in hrefs(g) and "/jobs" in hrefs(g)


def test_admin_sees_everything():
    g = nav.nav_items(u("admin"))
    assert [i.href for i in g[-1].items] == ["/updates", "/api-keys", "/users", "/settings", "/integrations", "/ai", "/audit"]
    assert len(hrefs(g)) == sum(len(x.items) for x in nav.NAV)


def test_show_all_menus_lists_every_page_the_user_may_open():
    g = nav.nav_items(u("viewer", show_all=True))
    assert groups_of(g) == ["core", "scan", "automation", "library", "system"]
    assert "/quick" in hrefs(g) and "/jobs" in hrefs(g) and "/updates" in hrefs(g) and "/api-keys" in hrefs(g)
    assert "/users" not in hrefs(g) and "/settings" not in hrefs(g) and "/audit" not in hrefs(g)
    quick = next(i for x in g for i in x.items if i.key == "quick")
    assert [t.href for t in quick.tabs] == ["/quick", "/nmap", "/nuclei", "/discovery"]
    a = nav.nav_items(u("analyst", show_all=True))
    assert "/updates" in hrefs(a) and "/users" not in hrefs(a)


def test_inactive_or_missing_user_gets_nothing():
    assert nav.nav_items(None) == []
    assert nav.nav_items(SimpleNamespace(role="admin", is_active=False)) == []


def test_page_tabs_for_pages_and_detail_pages():
    t = nav.page_tabs_for(u("admin"), "discovery", "/discovery")
    assert t.label == "New scan" and t.current == "/discovery"
    assert [x.href for x in t.tabs] == ["/quick", "/nmap", "/nuclei", "/discovery"]
    assert nav.page_tabs_for(u("admin"), "changes", "/changes").current == "/changes"
    assert nav.page_tabs_for(u("admin"), "issues", "/issues/5") is None        # detail pages: no tab bar
    assert nav.page_tabs_for(u("admin"), "dashboard", "/") is None             # single-page item
    assert nav.page_tabs_for(u("viewer"), "nmap", "/nmap") is None             # no New scan tabs without scan.run
    assert nav.page_tabs_for(u("viewer", True), "nmap", "/nmap").current == "/nmap"
    assert nav.section_for("nuclei") == "Scanning" and nav.section_for("issues") == "Issues"


# ----------------------------------------------------------------- pages
PAGES = [  # path, sidebar item href that must be highlighted, current tab href (None = no tab bar)
    ("/", "/", None),
    ("/issues", "/issues", "/issues"),
    ("/findings", "/issues", "/findings"),
    ("/campaigns", "/campaigns", "/campaigns"),
    ("/watch", "/campaigns", "/watch"),
    ("/inventory", "/inventory", "/inventory"),
    ("/changes", "/inventory", "/changes"),
    ("/reports", "/reports", None),
    ("/quick", "/quick", "/quick"),
    ("/nmap", "/quick", "/nmap"),
    ("/nuclei", "/quick", "/nuclei"),
    ("/discovery", "/quick", "/discovery"),
    ("/jobs", "/jobs", None),
    ("/scopes", "/scopes", None),
    ("/schedules", "/schedules", None),
    ("/templates", "/templates", "/templates"),
    ("/rules", "/templates", "/rules"),
    ("/updates", "/updates", None),
    ("/users", "/users", None),
    ("/settings", "/settings", None),
    ("/audit", "/audit", None),
    ("/ai", "/ai", None),
    ("/integrations", "/integrations", None),
    ("/api-keys", "/api-keys", None),
    ("/api-docs", "/api-keys", None),
]


def sidebar(html):
    return html[html.index('<aside class="sidebar"'):html.index("</aside>")]


def tabbar(html):
    m = re.search(r'<nav class="page-tabs"[^>]*>(.*?)</nav>', html, re.S)
    return m and m.group(0)


@pytest.mark.parametrize("path,item,tab", PAGES, ids=[p[0] for p in PAGES])
def test_pages_highlight_item_and_tab(auth, path, item, tab):
    r = auth.get(path)
    assert r.status_code == 200, path
    side = sidebar(r.text)
    assert re.search(rf'<a href="{re.escape(item)}" class="active" aria-current="page"', side), (path, item)
    assert side.count('class="active"') == 1
    bar = tabbar(r.text)
    if tab is None:
        assert bar is None, path
    else:
        assert bar and re.search(rf'<a href="{re.escape(tab)}"[^>]*aria-current="page"', bar), (path, bar)
        assert bar.count('aria-current="page"') == 1


def test_discovery_has_assets_anchor_and_breadcrumbs(auth):
    r = auth.get("/discovery")
    assert 'id="assets"' in r.text
    for path, section in (("/nuclei", "Scanning"), ("/nmap", "Scanning"), ("/jobs", "Scanning"), ("/findings", "Issues"),
                          ("/watch", "Campaigns"), ("/changes", "Inventory"), ("/rules", "Detection library"),
                          ("/schedules", "Automation"), ("/scopes", "Automation")):
        assert f'aria-label="Breadcrumb"><span>{section}</span>' in auth.get(path).text, path


def test_viewer_sidebar_and_tabs(auth):
    make_user(auth, "vnav", "viewer")
    login_as(auth, "vnav")
    side = sidebar(auth.get("/").text)
    for h in CORE:
        assert f'href="{h}"' in side
    for h in ("/quick", "/jobs", "/scopes", "/templates", "/updates", "/api-keys"):
        assert f'href="{h}"' not in side, h
    assert "data-nav-group" not in side
    assert 'href="/findings"' in tabbar(auth.get("/issues").text)
    assert tabbar(auth.get("/nmap").text) is None         # page still reachable, no scan tabs
    assert auth.get("/jobs").status_code == 200


def test_profile_show_all_menus_toggle(auth):
    make_user(auth, "vall", "viewer")
    login_as(auth, "vall")
    page = auth.get("/profile").text
    assert 'action="/profile/menus"' in page and 'name="show_all_menus"' in page
    csrf = get_csrf(auth, "/profile")
    assert auth.post("/profile/menus", data={"show_all_menus": "1"}, follow_redirects=False).status_code in (400, 403)
    r = auth.post("/profile/menus", data={"csrf": csrf, "show_all_menus": "1"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/profile")
    with auth.app.state.SessionLocal() as db:
        assert db.scalar(select(User).where(User.username == "vall")).show_all_menus is True
        assert db.scalar(select(AuditLog).where(AuditLog.action == "profile.menus")) is not None
    side = sidebar(auth.get("/").text)
    assert 'href="/quick"' in side and 'href="/jobs"' in side and 'href="/users"' not in side
    assert tabbar(auth.get("/nmap").text) is not None
    assert "checked" in re.search(r'<input[^>]*name="show_all_menus"[^>]*>', auth.get("/profile").text).group(0)
    r = auth.post("/profile/menus", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert 'href="/quick"' not in sidebar(auth.get("/").text)


def test_show_all_menus_column_is_migrated(tmp_path):
    from app.db import _ADDED_COLUMNS
    assert ("users", "show_all_menus", "BOOLEAN NOT NULL DEFAULT 0") in _ADDED_COLUMNS


def test_detail_pages_highlight_parent_without_tab_bar(auth):
    from app.db import Campaign, Job
    from tests.test_issue_routes import SPECS, seed
    ids = seed(auth, SPECS)
    with auth.app.state.SessionLocal() as db:
        jid = db.scalar(select(Job.id))
        c = Campaign(name="Nav camp")
        db.add(c)
        db.commit()
        cid = c.id
    for path, item in ((f"/issues/{ids['exposed-panel']}", "/issues"), (f"/jobs/{jid}", "/jobs"),
                       (f"/campaigns/{cid}", "/campaigns")):
        r = auth.get(path)
        assert r.status_code == 200, path
        assert re.search(rf'<a href="{re.escape(item)}" class="active" aria-current="page"', sidebar(r.text)), path
        assert tabbar(r.text) is None, path


def test_analyst_with_show_all_menus():
    g = nav.nav_items(u("analyst", show_all=True))
    assert groups_of(g) == ["core", "scan", "automation", "library", "system"]
    assert [i.href for i in g[-1].items] == ["/updates", "/api-keys"]


def test_viewer_on_discovery_gets_inventory_tabs():
    t = nav.page_tabs_for(u("viewer"), "discovery", "/discovery")
    assert t.label == "Inventory" and t.current == "/discovery#assets"
    assert nav.active_for(u("viewer"), "discovery", "/discovery") == "inventory"
    assert nav.active_for(u("viewer", True), "discovery", "/discovery") == "discovery"
    assert nav.page_tabs_for(u("viewer", True), "discovery", "/discovery").label == "New scan"
    assert nav.active_for(u("analyst"), "discovery", "/discovery") == "discovery"


def test_viewer_discovery_page_highlights_inventory(auth):
    make_user(auth, "vdisc", "viewer")
    login_as(auth, "vdisc")
    html = auth.get("/discovery").text
    assert re.search(r'<a href="/inventory" class="active" aria-current="page"', sidebar(html))
    bar = tabbar(html)
    assert bar and re.search(r'<a href="/discovery#assets"[^>]*aria-current="page"', bar)
    assert 'aria-label="Breadcrumb"><span>Inventory</span>' in html


def test_breadcrumbs_come_from_navigation():
    from app.render import TEMPLATES_DIR
    for name in ("issues.html", "findings.html", "nmap.html", "nuclei.html", "jobs.html", "rules.html", "changes.html"):
        assert "set section" not in (TEMPLATES_DIR / name).read_text(), name
