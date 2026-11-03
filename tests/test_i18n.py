"""Thai user interface: translate(), request language, the language switch and catalog completeness."""
import ast
import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from sqlalchemy import select

from app import i18n
from app.db import AuditLog, User
from app.i18n import Msg, flash, lang_from_accept, translate
from app.i18n_th import CATALOG_TH
from tests.conftest import get_csrf, login_and_change_password

APP = Path(__file__).resolve().parent.parent / "app"
THAI = re.compile(r"[\u0E00-\u0E7F]")


@pytest.fixture(autouse=True)
def _record_missing(monkeypatch):
    """Missing Thai lookups are recorded only while a test asks for it."""
    monkeypatch.setattr(i18n, "RECORD_MISSING", True)
    i18n.MISSING.clear()
    yield
    i18n.MISSING.clear()


# ----------------------------------------------------------------- translate
def test_translate_lookup_and_fallback(monkeypatch):
    monkeypatch.setitem(CATALOG_TH, "Deleted {n} service(s).", "ลบ {n} service แล้ว")
    assert translate("th", "Deleted {n} service(s).", n=3) == "ลบ 3 service แล้ว"
    assert translate("en", "Deleted {n} service(s).", n=3) == "Deleted 3 service(s)."
    assert translate("th", "No such English string") == "No such English string"
    assert translate("th", "") == "" and translate("th", None) == ""


def test_translate_never_raises_on_bad_placeholders(monkeypatch):
    monkeypatch.setitem(CATALOG_TH, "Hello {name}", "สวัสดี {nme}")      # broken Thai value: English template used
    assert translate("th", "Hello {name}", name="ann") == "Hello ann"
    assert translate("en", "Hello {name}") == "Hello {name}"                # no params: no formatting
    assert translate("en", "Hello {name}", other=1) == "Hello {name}"       # missing param: raw text
    assert translate("en", "Odd { brace", x=1) == "Odd { brace"


def test_missing_thai_lookups_are_recorded():
    i18n.MISSING.clear()
    translate("th", "Certainly not in the catalog")
    translate("en", "Also not in the catalog")
    assert i18n.MISSING == {"Certainly not in the catalog"}
    i18n.MISSING.clear()


def test_missing_lookups_not_recorded_by_default(monkeypatch):
    monkeypatch.setattr(i18n, "RECORD_MISSING", False)
    for n in range(50):
        translate("th", f"provider error {n}")
    assert not i18n.MISSING


def test_context_keys(monkeypatch):
    assert i18n.translate_ctx("th", "issues", "Active") == CATALOG_TH["issues|Active"] != CATALOG_TH["Active"]
    assert i18n.translate_ctx("en", "issues", "Active") == "Active"
    assert i18n.translate_ctx("th", "nowhere", "Active") == "Active"
    monkeypatch.setitem(CATALOG_TH, "x|{n} left", "เหลือ {n}")
    assert i18n.translate_ctx("th", "x", "{n} left", n=2) == "เหลือ 2"
    assert i18n.translate_ctx("en", "x", "{n} left", n=2) == "2 left"


def test_words_with_two_meanings_have_distinct_thai():
    assert CATALOG_TH["issues|Active"] == "ยังไม่ปิด" and CATALOG_TH["Active"] != "ยังไม่ปิด"
    assert CATALOG_TH["issues|Closed"] != CATALOG_TH["Resolved"]
    assert CATALOG_TH["issue|Owner"] == CATALOG_TH["Owner:"].rstrip(":") == "ผู้รับผิดชอบ"
    assert CATALOG_TH["dismissed"] != CATALOG_TH["cancelled"]


def test_nested_labels_are_translated():
    from app import validation
    from app.issues import STATUS_LABELS
    with pytest.raises(ValueError) as e:
        validation.parse_nmap_targets("")
    assert CATALOG_TH["nmap target"] in translate("th", e.value)
    assert translate("en", e.value) == "Enter at least one nmap target."
    with pytest.raises(ValueError) as e:
        validation.parse_nuclei_targets("bad target!!")
    assert CATALOG_TH["nuclei target"] in translate("th", e.value)
    m = Msg("Cannot move an issue from {old} to {new}.", old=Msg(STATUS_LABELS["new"]), new=Msg(STATUS_LABELS["verified"]))
    th = translate("th", ValueError(m))
    assert CATALOG_TH["New"] in th and CATALOG_TH["Resolved"] in th


def test_msg_keeps_template_and_params(monkeypatch):
    monkeypatch.setitem(CATALOG_TH, "Bad port {p}", "พอร์ต {p} ไม่ถูกต้อง")
    m = Msg("Bad port {p}", p=99999)
    assert str(m) == "Bad port 99999" and m == "Bad port 99999"
    e = ValueError(m)
    assert translate("th", e) == "พอร์ต 99999 ไม่ถูกต้อง"
    assert translate("en", e) == "Bad port 99999"
    assert translate("th", ValueError("plain")) == "plain"


def test_flash_encoding_matches_old_urls(monkeypatch):
    class R:
        class state:
            user = None
        headers = {}
    assert flash(R, "Campaign activated: rules enabled and evaluated") == "Campaign+activated:+rules+enabled+and+evaluated"
    assert flash(R, "Removed {n} host(s) from the inventory", n=2) == "Removed+2+host(s)+from+the+inventory"
    monkeypatch.setitem(CATALOG_TH, "Rule deleted", "ลบกฎแล้ว")
    R.headers = {"accept-language": "th"}
    assert flash(R, "Rule deleted") == "%E0%B8%A5%E0%B8%9A%E0%B8%81%E0%B8%8E%E0%B9%81%E0%B8%A5%E0%B9%89%E0%B8%A7"


@pytest.mark.parametrize("header,lang", [
    ("", "en"), (None, "en"), ("th", "th"), ("th-TH,th;q=0.9,en;q=0.8", "th"), ("en-US,en;q=0.9,th;q=0.8", "en"),
    ("en;q=0.5,th;q=0.9", "th"), ("fr-FR,th;q=0.5", "th"), ("fr,de", "en"), ("th;q=0", "en"), ("*", "en"),
    ("th;q=abc,en", "en"), ("garbage;;;,,", "en"),
])
def test_accept_language(header, lang):
    assert lang_from_accept(header) == lang


# ----------------------------------------------------------------- pages and the switch
def set_lang(client, lang, next_="/"):
    csrf = get_csrf(client, "/profile")
    return client.post("/profile/language", data={"csrf": csrf, "language": lang, "next": next_}, follow_redirects=False)


def test_login_page_follows_accept_language(client):
    r = client.get("/login", headers={"Accept-Language": "th-TH,th;q=0.9"})
    assert '<html lang="th">' in r.text and THAI.search(r.text)
    r = client.get("/login", headers={"Accept-Language": "en-US"})
    assert '<html lang="en">' in r.text and 'id="i18n"' not in r.text
    assert "lang" not in r.headers.get("set-cookie", "")


def test_default_is_english_and_switch_persists(auth):
    r = auth.get("/", headers={"Accept-Language": "th"})          # signed in: the user's setting wins
    assert '<html lang="en">' in r.text and 'id="i18n"' not in r.text
    assert 'action="/profile/language"' in r.text
    r = set_lang(auth, "th", "/issues?view=active&msg=old")
    assert r.status_code == 303 and r.headers["location"] == "/issues?view=active"
    with auth.app.state.SessionLocal() as db:
        assert db.scalar(select(User.language).where(User.username == "admin")) == "th"
        assert db.scalar(select(AuditLog).where(AuditLog.action == "profile.language")) is not None
    r = auth.get("/")
    assert '<html lang="th">' in r.text and 'id="i18n"' in r.text and THAI.search(r.text)
    assert set_lang(auth, "en").headers["location"] == "/"
    assert '<html lang="en">' in auth.get("/").text


@pytest.mark.parametrize("bad", ["https://evil.example/", "//evil.example/x", "/\\evil.example", "javascript:alert(1)",
                                 "evil", "", "/ok\r\nSet-Cookie: x=1"])
def test_switch_redirects_only_to_same_site_paths(auth, bad):
    assert set_lang(auth, "th", bad).headers["location"] == "/"


def test_switch_needs_csrf_and_valid_language(auth):
    r = auth.post("/profile/language", data={"language": "th", "next": "/"}, follow_redirects=False)
    assert r.status_code == 403
    set_lang(auth, "xx")
    with auth.app.state.SessionLocal() as db:
        assert db.scalar(select(User.language).where(User.username == "admin")) == "en"


def test_switch_allowed_during_forced_password_change(client):
    r = client.post("/login", data={"username": "admin", "password": "changeme"}, follow_redirects=False)
    assert r.status_code == 303
    page = client.get("/change-password")
    assert 'action="/profile/language"' in page.text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = client.post("/profile/language", data={"csrf": csrf, "language": "th", "next": "/change-password"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/change-password"
    assert '<html lang="th">' in client.get("/change-password").text


def test_switch_from_a_post_rendered_page_returns_to_a_get_page(auth):
    from tests.test_issue_routes import SPECS, seed
    iid = seed(auth, SPECS)["CVE-2021-41773"]
    csrf = get_csrf(auth, f"/issues/{iid}")
    bad = {"csrf": csrf, "status": "false_positive", "comment": ""}       # needs a reason: the form is re-rendered
    nxt = lambda r: re.search(r'name="next" value="([^"]*)"', r.text).group(1)  # noqa: E731
    r = auth.post(f"/issues/{iid}/status", data=bad, headers={"Referer": f"http://testserver/issues/{iid}?x=1"})
    assert r.status_code == 400 and nxt(r) == f"/issues/{iid}?x=1"
    r = auth.post(f"/issues/{iid}/status", data=bad, headers={"Referer": "https://evil.example/issues/1"})
    assert nxt(r) == f"/issues/{iid}"                                          # nearest page that answers GET
    r = auth.post(f"/issues/{iid}/status", data=bad)
    assert nxt(r) == f"/issues/{iid}"
    assert set_lang(auth, "th", nxt(r)).headers["location"] == f"/issues/{iid}"


def test_translations_are_escaped(auth, monkeypatch):
    monkeypatch.setitem(CATALOG_TH, "Dashboard", "<b>x</b>")
    set_lang(auth, "th")
    r = auth.get("/")
    assert "<b>x</b>" not in r.text and "&lt;b&gt;x&lt;/b&gt;" in r.text
    r = auth.get("/?msg=<script>alert(1)</script>")
    assert "<script>alert(1)</script>" not in r.text


# ----------------------------------------------------------------- catalog checks (static)
_T_CALL = re.compile(r"""\bt\(\s*(?P<q>["'])(?P<s>(?:\\.|(?!(?P=q)).)*)(?P=q)""", re.S)
_TP_CALL = re.compile(r"""\btp\(\s*(["'])(?P<c>[^"']+)\1\s*,\s*(?P<q>["'])(?P<s>(?:\\.|(?!(?P=q)).)*)(?P=q)""", re.S)


def _template_keys() -> dict[str, str]:
    out = {}
    for f in sorted((APP / "templates").glob("*.html")):
        src = f.read_text()
        for m in _T_CALL.finditer(src):
            s = m.group("s").replace("\\'", "'").replace('\\"', '"')
            out.setdefault(s, f.name)
        for m in _TP_CALL.finditer(src):
            out.setdefault(f"{m.group('c')}|{m.group('s')}", f.name)
    return out


def _python_keys() -> dict[str, str]:
    """Literal first-text arguments of tr(request, "..."), flash(request, "..."), Msg("...") and t("...") in app/."""
    out = {}
    for f in sorted(APP.rglob("*.py")):
        if f.name.startswith("i18n"):
            continue
        tree = ast.parse(f.read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", "")
            idx = {"tr": 1, "flash": 1, "Msg": 0, "t": 0, "N_": 0}.get(name)
            if idx is None or len(node.args) <= idx:
                continue
            arg = node.args[idx]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                out.setdefault(arg.value, str(f.relative_to(APP)))
            elif isinstance(arg, ast.IfExp):
                for b in (arg.body, arg.orelse):
                    if isinstance(b, ast.Constant) and isinstance(b.value, str):
                        out.setdefault(b.value, str(f.relative_to(APP)))
    return out


def test_every_literal_has_a_thai_entry():
    missing = {k: where for k, where in {**_template_keys(), **_python_keys()}.items()
               if not CATALOG_TH.get(k)}
    assert not missing, f"{len(missing)} strings without Thai: {sorted(missing.items())[:40]}"


def test_every_dynamic_label_has_a_thai_entry():
    missing = sorted(k for k in i18n.dynamic_keys() if not CATALOG_TH.get(k))
    assert not missing, missing[:40]


def test_no_unused_catalog_entries():
    used = set(_template_keys()) | set(_python_keys()) | i18n.dynamic_keys()
    unused = sorted(set(CATALOG_TH) - used)
    assert not unused, f"{len(unused)} unused: {unused[:40]}"


def test_catalog_values_are_plain_thai_text():
    bad = []
    for k, v in CATALOG_TH.items():
        if not v or "<" in v and "<" not in k:
            bad.append(k)
        fields = lambda s: sorted(set(re.findall(r"\{(\w*)[^{}]*\}", s)))  # noqa: E731
        if fields(k) != fields(v):
            bad.append(k)
        if "ครับ" in v or "ค่ะ" in v:
            bad.append(k)
    assert not bad, bad[:40]


# Buttons whose names Thai sentences mention: the sentence must use the Thai label shown on the button.
BUTTON_LABELS = ("Verify now", "Update nuclei templates", "Show Get started again", "Remove stored key",
                 "Probe web services with httpx")


def test_thai_sentences_quote_thai_button_labels():
    bad = []
    for label in BUTTON_LABELS:
        short = label.replace(" with httpx", "")
        for k, v in CATALOG_TH.items():
            if k != label and short in k and (short in v or CATALOG_TH[label] not in v):
                bad.append((label, k, v))
    assert not bad, bad


def _confirm_keys() -> set[str]:
    keys = set()
    for f in (APP / "templates").glob("*.html"):
        for m in re.finditer(r'data-confirm="\{\{\s*(.*?)\}\}"', f.read_text()):
            keys |= {mm.group("s") for mm in _T_CALL.finditer(m.group(1))}
    return keys


def test_confirm_dialogs_ask_with_rue_mai():
    keys = _confirm_keys()
    assert len(keys) >= 15
    bad = {k: CATALOG_TH.get(k) for k in keys if "?" in CATALOG_TH.get(k, "?") or "หรือไม่" not in CATALOG_TH.get(k, "")}
    assert not bad, bad


def test_js_strings_are_in_app_js():
    js = "".join((APP / "static" / f).read_text() for f in ("app.js", "tours.js"))
    for s in i18n.JS_STRINGS:
        assert f't("{s}"' in js, s


# ----------------------------------------------------------------- every page in Thai
class _Text(HTMLParser):
    """Visible text nodes plus user-facing attributes, outside <script>/<style>/<code>/<pre>/<textarea>."""
    SKIP = {"script", "style", "code", "pre", "textarea", "svg"}
    ATTRS = ("title", "aria-label", "placeholder", "alt", "data-confirm")

    def __init__(self):
        super().__init__()
        self.depth, self.out = 0, []

    def handle_starttag(self, tag, attrs):
        if tag in self.SKIP:
            self.depth += 1
        if not self.depth:
            self.out += [v for k, v in attrs if k in self.ATTRS and v]

    def handle_endtag(self, tag):
        if tag in self.SKIP and self.depth:
            self.depth -= 1

    def handle_data(self, data):
        if not self.depth and data.strip():
            self.out.append(data.strip())


def visible_text(html: str) -> list[str]:
    p = _Text()
    p.feed(html)
    return p.out


@pytest.fixture
def thai(auth):
    """Admin in Thai, with representative data on every page."""
    from tests.test_ai_admin import add_provider
    from tests.test_integration_routes import create_channel
    from tests.test_inventory import seed_inventory
    from tests.test_issue_routes import SPECS, seed
    from tests.test_rbac import make_user
    from tests.test_scheduler import make_schedule, make_scope
    seed_inventory(auth)
    seed(auth, SPECS)
    sid = make_scope(auth)
    make_schedule(auth, "nmap", scope_id=sid)
    make_user(auth, "vera", "viewer")
    create_channel(auth)
    add_provider(auth)
    csrf = get_csrf(auth, "/rules")
    auth.post("/rules", data={"csrf": csrf, "name": "OpenSSH old", "product_pattern": "openssh",
                              "version_constraint": "< 9.0", "severity": "high", "description": "", "enabled": "on"})
    auth.post("/campaigns", data={"csrf": csrf, "cve_id": "CVE-2021-41773", "name": "Apache path traversal",
                                  "severity": "critical", "description": "", "product_pattern": "apache",
                                  "version_constraint": "< 2.4.50", "attach_templates": "true", "fetch_intel": ""})
    auth.post("/api-keys", data={"csrf": csrf, "name": "CI"})
    set_lang(auth, "th")
    return auth


def _pages(client):
    from app.db import AiProvider, Campaign, Issue, Job, NotificationChannel, Rule, Scope
    with client.app.state.SessionLocal() as db:
        first = lambda m: db.scalar(select(m.id).order_by(m.id))  # noqa: E731
        ids = {"job": first(Job), "rule": first(Rule), "user": first(User), "issue": first(Issue),
               "campaign": first(Campaign), "scope": first(Scope), "channel": first(NotificationChannel),
               "provider": first(AiProvider)}
    pages = ["/", "/profile", "/change-password", "/jobs", "/quick", "/nmap", "/inventory", "/nuclei", "/findings",
             "/discovery", "/templates", "/rules", "/updates", "/users", "/audit", "/issues", "/settings",
             "/campaigns", "/campaigns/new", "/scopes", "/scopes/new", "/schedules", "/integrations",
             "/integrations/deliveries", "/reports", "/api-keys", "/api-docs", "/ai", "/watch", "/changes",
             "/inventory?group=host", "/issues?view=closed", "/no-such-page"]
    pages += [f"/jobs/{ids['job']}", f"/users/{ids['user']}", f"/issues/{ids['issue']}",
              f"/reports/issues/{ids['issue']}"]
    if ids["rule"]:
        pages.append(f"/rules/{ids['rule']}/edit")
    if ids["campaign"]:
        pages += [f"/campaigns/{ids['campaign']}", f"/reports/campaigns/{ids['campaign']}"]
    if ids["scope"]:
        pages += [f"/scopes/{ids['scope']}", f"/reports/scopes/{ids['scope']}"]
    if ids["channel"]:
        pages.append(f"/integrations/channels/{ids['channel']}")
    if ids["provider"]:
        pages.append(f"/ai/providers/{ids['provider']}")
    return pages


def test_every_page_renders_in_thai(thai):
    i18n.MISSING.clear()
    seen = {}
    for path in _pages(thai):
        r = thai.get(path)
        assert r.status_code in (200, 404), (path, r.status_code)
        assert '<html lang="th">' in r.text, path
        assert THAI.search(r.text), path
        for s in sorted(i18n.MISSING):
            seen.setdefault(s, path)
        i18n.MISSING.clear()
    assert not seen, f"{len(seen)} strings without Thai: {sorted(seen.items())[:60]}"


def test_signed_out_pages_in_thai(client):
    i18n.MISSING.clear()
    for path in ("/login", "/no-such-page"):
        r = client.get(path, headers={"Accept-Language": "th"})
        assert THAI.search(r.text), path
    assert not i18n.MISSING, sorted(i18n.MISSING)


def test_scope_group_criticality_is_its_own_field(thai):
    from app.inventory_groups import group_rows
    from types import SimpleNamespace as NS
    sc = NS(id=1, name="LAN", criticality="high")
    g = group_rows([(NS(id=1, product="x"), NS(id=1, address="10.0.0.1", hostname=""))], "scope", {}, {1: sc})[0]
    assert g.criticality == "high" and g.sublabel == "high criticality"
    r = thai.get("/inventory?group=scope")
    assert CATALOG_TH["{level} criticality"].format(level="high") in r.text


def test_error_page_role_is_translated(thai):
    from tests.test_rbac import login_as
    with thai.app.state.SessionLocal() as db:
        db.query(User).filter(User.username == "vera").update({"language": "th"})
        db.commit()
    login_as(thai, "vera")
    r = thai.get("/users")
    assert r.status_code == 403 and CATALOG_TH["Viewer"] in r.text and ">viewer<" not in r.text
