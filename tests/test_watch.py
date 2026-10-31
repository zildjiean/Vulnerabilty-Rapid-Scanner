import asyncio
import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

from app import intel, watch
from app.db import (AppSetting, AuditLog, Campaign, CampaignTemplate, Delivery, Issue, NotificationChannel,
                    NotificationRule, Rule, TemplateIndex, WatchHit, utcnow)
from app.rules import evaluate_rules
from app.templates_index import reindex
from tests.conftest import get_csrf
from tests.test_inventory import seed_inventory
from tests.test_rbac import login_as, make_user

NO_SLEEP = lambda s: None  # noqa: E731
NOW = datetime(2026, 10, 31, 12, 0, 0)
PHP_CVE = "CVE-2026-109619"      # an indexed fixture template exists for it
APACHE_CVE = "CVE-2026-20001"
SSH_CVE = "CVE-2026-20002"
LOW_CVE = "CVE-2026-20003"
KEV_CVE = "CVE-2026-20004"


def cpe_match(vendor, product, version="*", **bounds):
    m = {"vulnerable": True, "criteria": f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"}
    names = {"si": "versionStartIncluding", "se": "versionStartExcluding", "ei": "versionEndIncluding",
             "ee": "versionEndExcluding"}
    m.update({names[k]: v for k, v in bounds.items()})
    return m


def nvd_cve(cve, score=9.8, matches=(), desc="Something bad."):
    return {"cve": {"id": cve, "published": "2026-10-30T10:00:00.000",
                    "descriptions": [{"lang": "es", "value": "Algo."}, {"lang": "en", "value": desc}],
                    "metrics": {"cvssMetricV31": [
                        {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 5.0, "baseSeverity": "MEDIUM"}},
                        {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": score,
                                                         "baseSeverity": "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM",
                                                         "vectorString": "CVSS:3.1/AV:N"}}]},
                    "references": [{"url": f"https://example.test/{cve}"}],
                    "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": list(matches)}]}]}}


DEFAULT_ITEMS = [
    nvd_cve(PHP_CVE, 9.8, [cpe_match("php", "php", si="8.3.0", ee="8.3.15")], "PHP use-after-free."),
    nvd_cve(APACHE_CVE, 8.1, [cpe_match("apache", "http_server", si="2.4.0", ee="2.4.62")]),
    nvd_cve(SSH_CVE, 9.0, [cpe_match("openbsd", "openssh", ee="9.0")]),          # 9.6p1 is outside -> dropped
    nvd_cve(LOW_CVE, 4.3, [cpe_match("f5", "nginx", ee="1.26.0")]),              # below the CVSS threshold
]


class WatchNet:
    """Fake NVD (lastMod window paging + single-CVE lookups) and CISA KEV."""

    def __init__(self, items=None, kev=None, lookups=None, fail=(), page_total=None):
        self.items = DEFAULT_ITEMS if items is None else items
        self.kev = kev if kev is not None else {"vulnerabilities": []}
        self.lookups, self.fail, self.page_total, self.calls = lookups or {}, set(fail), page_total, []

    def __call__(self, url, params=None):
        self.calls.append((url, dict(params or {})))
        if url == intel.NVD_URL:
            if "nvd" in self.fail:
                raise httpx.ConnectError("nvd offline")
            if "cveId" in params:
                item = self.lookups.get(params["cveId"])
                return {"totalResults": int(bool(item)), "vulnerabilities": [item] if item else []}
            start = params["startIndex"]
            total = self.page_total if self.page_total is not None else len(self.items)
            page = self.items if start == 0 else self.items[:1]
            return {"totalResults": total, "resultsPerPage": len(page), "startIndex": start, "vulnerabilities": page}
        if url == intel.KEV_URL:
            if "kev" in self.fail:
                raise httpx.ConnectError("kev offline")
            return self.kev
        raise AssertionError(url)

    def nvd(self):
        return [p for u, p in self.calls if u == intel.NVD_URL]


@pytest.fixture
def env(auth):
    seed_inventory(auth)   # 192.168.1.10: OpenSSH 9.6p1, Apache httpd 2.4.58, PHP cli server 8.3.10, nginx 1.24.0
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
        db.commit()
    return auth


def run(client, net, now=NOW, sleep=NO_SLEEP):
    with client.app.state.SessionLocal() as db:
        summary = watch.run_watch(db, client.app.state.settings, net, now=now, sleep=sleep)
        db.commit()
    return summary


def campaigns(client):
    with client.app.state.SessionLocal() as db:
        out = {c.cve_id: c for c in db.scalars(select(Campaign))}
        for c in out.values():
            _ = c.templates
        db.expunge_all()
        return out


def rules_of(client, cid):
    with client.app.state.SessionLocal() as db:
        out = list(db.scalars(select(Rule).where(Rule.campaign_id == cid).order_by(Rule.id)))
        db.expunge_all()
        return out


def issues(client):
    with client.app.state.SessionLocal() as db:
        out = list(db.scalars(select(Issue)))
        db.expunge_all()
        return out


# ----------------------------------------------------------------- parsing
def test_split_cpe23():
    assert watch.split_cpe23("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*") == ("apache", "http_server", "2.4.49")
    assert watch.split_cpe23("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*") == ("f5", "nginx", "*")
    assert watch.split_cpe23("cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*") == ("linux", "linux_kernel", "*")
    assert watch.split_cpe23("cpe:/a:apache:http_server:2.4.49") is None
    assert watch.split_cpe23("") is None


def test_parse_nvd_item_ranges_and_best_cvss():
    item = nvd_cve(APACHE_CVE, 8.1, [cpe_match("apache", "http_server", si="2.4.0", ee="2.4.62"),
                                     cpe_match("apache", "http_server", "2.2.34"),
                                     {"vulnerable": False, "criteria": "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*"}])
    rec = watch.parse_nvd_item(item)
    assert rec["cve_id"] == APACHE_CVE and rec["cvss_score"] == 8.1 and rec["cvss_severity"] == "high"
    assert rec["description"] == "Something bad." and rec["references"] == [f"https://example.test/{APACHE_CVE}"]
    assert rec["published"] == datetime(2026, 10, 30, 10, 0)
    assert [(r["vendor"], r["product"], r["version"], r["start_incl"], r["end_excl"]) for r in rec["ranges"]] == [
        ("apache", "http_server", "*", "2.4.0", "2.4.62"), ("apache", "http_server", "2.2.34", "", "")]
    assert watch.range_constraint(rec["ranges"][0]) == ">= 2.4.0, < 2.4.62"
    assert watch.range_constraint(rec["ranges"][1]) == "== 2.2.34"
    assert watch.range_constraint({"version": "*"}) == ""
    assert watch.parse_nvd_item({"cve": {"id": "nope"}}) is None
    with pytest.raises(ValueError):
        watch.parse_nvd_page(["not", "a", "dict"])


def test_nvd_paging_dates_and_window():
    net, sleeps = WatchNet(page_total=2500), []
    pacer = watch._Pacer(sleeps.append)
    recs = watch.fetch_nvd_changes(net, NOW - timedelta(days=3), NOW, pacer)
    calls = net.nvd()
    assert [c["startIndex"] for c in calls] == [0, 2000] and sleeps == [6]
    assert calls[0]["lastModStartDate"] == "2026-10-28T12:00:00.000"
    assert calls[0]["lastModEndDate"] == "2026-10-31T12:00:00.000" and calls[0]["resultsPerPage"] == 2000
    assert len(recs) == len(DEFAULT_ITEMS) + 1
    net = WatchNet()
    watch.fetch_nvd_changes(net, NOW - timedelta(days=400), NOW, watch._Pacer(NO_SLEEP))
    assert net.nvd()[0]["lastModStartDate"] == "2026-07-03T12:00:00.000"   # clamped to 120 days


def test_new_kev_entries_by_date():
    feed = {"vulnerabilities": [{"cveID": "CVE-2026-1001", "dateAdded": "2026-10-20"},
                                {"cveID": "cve-2026-1002", "dateAdded": "2026-10-30"},
                                {"cveID": "CVE-2026-1003", "dateAdded": "2026-10-31"},
                                {"cveID": "bogus", "dateAdded": "2026-10-31"}, "junk"]}
    assert [e["cveID"] for e in watch.new_kev_entries(feed, "2026-10-30")] == ["CVE-2026-1002", "CVE-2026-1003"]
    with pytest.raises(ValueError):
        watch.new_kev_entries([], "2026-10-30")


# ----------------------------------------------------------------- matching
def svc(product, version="", cpe="", sid=1, port=80):
    return SimpleNamespace(id=sid, product=product, version=version, cpe=cpe, port=port, service_name="http"), \
        SimpleNamespace(address="10.0.0.1")


def rec(ranges=(), **kw):
    return {"cve_id": "CVE-2026-1000", "ranges": [watch.parse_nvd_item(nvd_cve("CVE-2026-1000", matches=[r]))["ranges"][0]
                                               for r in ranges], **kw}


def test_match_by_cpe_alias_and_similarity():
    apache = svc("Apache httpd", "2.4.58", "cpe:/a:apache:http_server:2.4.58")
    assert watch.service_keys(apache[0]) == {("apache", "http_server")}
    assert ("php", "php") in watch.service_keys(svc("PHP cli server")[0])          # alias, prefix of the name
    assert watch.service_keys(svc("nginx")[0]) == {("f5", "nginx"), ("nginx", "nginx")}
    assert watch.service_keys(svc("Microsoft IIS httpd")[0]) >= {("microsoft", "internet_information_services")}

    m = watch.match_cve(rec([cpe_match("apache", "http_server", si="2.4.0", ee="2.4.62")]), [apache])
    assert [(x.quality, x.constraint) for x in m] == [("confirmed", ">= 2.4.0, < 2.4.62")]
    # similarity: every CPE word appears in the service product
    m = watch.match_cve(rec([cpe_match("acme", "widget_server")]), [svc("Acme Widget Server", "3.1")])
    assert [(x.quality, x.reason) for x in m] == [("possible", "name similar to acme:widget_server")]
    # KEV vendor/product words
    m = watch.match_cve(rec(kev_vendor="Acme", kev_product="Widget"), [svc("acme   widget daemon")])
    assert [x.quality for x in m] == ["possible"]
    assert watch.match_cve(rec(kev_vendor="Acme", kev_product="Gadget"), [svc("acme widget daemon")]) == []


@pytest.mark.parametrize("version,match,quality", [
    ("2.4.58", cpe_match("apache", "http_server", si="2.4.0", ee="2.4.62"), "confirmed"),    # in range
    ("2.4.62", cpe_match("apache", "http_server", si="2.4.0", ee="2.4.62"), None),           # outside
    ("2.4.49", cpe_match("apache", "http_server", "2.4.49"), "confirmed"),                   # exact
    ("2.4.50", cpe_match("apache", "http_server", "2.4.49"), None),                          # exact, other version
    ("unknown", cpe_match("apache", "http_server", si="2.4.0", ee="2.4.62"), "possible"),    # unparseable
    ("", cpe_match("apache", "http_server", ee="2.4.62"), "possible"),                       # missing
    ("2.4.58", cpe_match("apache", "http_server"), "possible"),                              # no range
])
def test_version_decisions(version, match, quality):
    s = svc("Apache httpd", version, "cpe:/a:apache:http_server")
    m = watch.match_cve(rec([match]), [s])
    assert [x.quality for x in m] == ([quality] if quality else [])


def test_best_match_per_service_wins():
    s = svc("Apache httpd", "2.4.58", "cpe:/a:apache:http_server")
    m = watch.match_cve(rec([cpe_match("apache", "http_server"),
                             cpe_match("apache", "http_server", si="2.4.0", ee="2.4.62")]), [s])
    assert len(m) == 1 and m[0].quality == "confirmed"


# ----------------------------------------------------------------- drafts
def test_run_drafts_campaigns_with_disabled_rules_templates_and_hits(env):
    with env.app.state.SessionLocal() as db:
        ch = NotificationChannel(name="hook", kind="webhook", config=json.dumps({"url": "https://hook.test/x"}))
        db.add(ch)
        db.flush()
        db.add(NotificationRule(channel_id=ch.id, events=json.dumps(["campaign.draft"]), min_severity="low"))
        db.commit()
    before = len(issues(env))
    summary = run(env, WatchNet())
    assert summary["errors"] == [] and summary["cves"] == 4
    assert summary["matched"] == 2 and summary["drafts"] == 2      # PHP + Apache; SSH outside, nginx below 7.0
    cs = campaigns(env)
    assert set(cs) == {PHP_CVE, APACHE_CVE}
    php = cs[PHP_CVE]
    assert php.status == "draft" and php.created_by == "0-day watch" and php.severity == "critical"
    assert php.cvss_score == 9.8 and php.description == "PHP use-after-free."
    assert [t.template_id for t in php.templates] == [PHP_CVE]
    rules = rules_of(env, php.id)
    assert [(r.product_pattern, r.version_constraint, r.enabled) for r in rules] == [
        (r"php\ cli\ server", ">= 8.3.0, < 8.3.15", False)]
    assert len(issues(env)) == before                                # drafts never open issues
    with env.app.state.SessionLocal() as db:
        hit = db.scalar(select(WatchHit).where(WatchHit.cve_id == PHP_CVE))
        assert hit.campaign_id == php.id and hit.quality == "confirmed" and hit.source == "nvd" and hit.cvss_score == 9.8
        m = json.loads(hit.matches)
        assert m == [{"service_id": m[0]["service_id"], "host": "192.168.1.10", "port": 8080, "product": "PHP cli server",
                      "version": "8.3.10", "quality": "confirmed", "reason": "php:php 8.3.10 is in >= 8.3.0, < 8.3.15"}]
        deliveries = list(db.scalars(select(Delivery)))
        assert [d.event for d in deliveries] == ["campaign.draft", "campaign.draft"]
        assert any("0-day watch: CVE-2026-109619 affects 1 asset" in d.title for d in deliveries)
        assert db.scalar(select(AuditLog).where(AuditLog.action == "campaign.drafted")) is not None
        state = watch.load_state(db)
    assert state["last_nvd_check"] == "2026-10-31T12:00:00" and state["last_run"]["drafts"] == 2


def test_rules_of_drafts_never_evaluate_even_when_enabled(env):
    run(env, WatchNet())
    php = campaigns(env)[PHP_CVE]
    with env.app.state.SessionLocal() as db:
        for r in db.scalars(select(Rule).where(Rule.campaign_id == php.id)):
            r.enabled = True
        db.flush()
        assert evaluate_rules(db) == 0
        db.commit()
    assert not [i for i in issues(env) if i.vuln_id == PHP_CVE]


def test_no_duplicate_draft_for_existing_or_dismissed(env):
    run(env, WatchNet())
    assert run(env, WatchNet(), now=NOW + timedelta(hours=1))["drafts"] == 0
    with env.app.state.SessionLocal() as db:
        c = db.scalar(select(Campaign).where(Campaign.cve_id == PHP_CVE))
        c.status = "dismissed"
        db.query(Campaign).filter(Campaign.cve_id == APACHE_CVE).delete()
        db.add(Campaign(name="manual", cve_id=APACHE_CVE, status="active"))
        db.commit()
    summary = run(env, WatchNet(), now=NOW + timedelta(hours=2))
    assert summary["drafts"] == 0 and summary["matched"] == 2
    cs = campaigns(env)
    assert cs[PHP_CVE].status == "dismissed" and cs[APACHE_CVE].name == "manual"
    with env.app.state.SessionLocal() as db:
        assert db.scalar(select(WatchHit).where(WatchHit.cve_id == APACHE_CVE)).campaign_id == cs[APACHE_CVE].id
        assert len(list(db.scalars(select(WatchHit)))) == 2


def test_thresholds_and_possible_matches(env):
    with env.app.state.SessionLocal() as db:
        watch.set_watch_settings(db, True, "4.0", True, False)
        db.commit()
    items = DEFAULT_ITEMS + [nvd_cve("CVE-2026-20009", 9.9, [cpe_match("openbsd", "openssh")])]   # possible only
    summary = run(env, WatchNet(items=items))
    assert set(campaigns(env)) == {PHP_CVE, APACHE_CVE, LOW_CVE}   # LOW passes 4.0; possible-only OpenSSH dropped
    assert summary["drafts"] == 3
    with env.app.state.SessionLocal() as db:
        with pytest.raises(ValueError):
            watch.set_watch_settings(db, True, "11", True, True)


def test_kev_entries_lookup_nvd_and_kev_always(env):
    kev = {"vulnerabilities": [
        {"cveID": KEV_CVE, "dateAdded": "2026-10-29", "vendorProject": "nginx", "product": "nginx",
         "vulnerabilityName": "nginx resolver bug", "dueDate": "2026-11-19", "knownRansomwareCampaignUse": "Known",
         "requiredAction": "Patch it."},
        {"cveID": "CVE-2026-20005", "dateAdded": "2026-09-01", "vendorProject": "nginx", "product": "nginx"}]}
    lookups = {KEV_CVE: nvd_cve(KEV_CVE, 5.0, [cpe_match("f5", "nginx", si="1.20.0", ee="1.26.0")])}
    net, sleeps = WatchNet(items=[], kev=kev, lookups=lookups), []
    summary = run(env, net, sleep=sleeps.append)
    assert summary["errors"] == [] and summary["drafts"] == 1
    assert [p for p in net.nvd() if "cveId" in p] == [{"cveId": KEV_CVE}] and sleeps == [6]
    c = campaigns(env)[KEV_CVE]
    assert c.kev and c.kev_ransomware and c.kev_due == "2026-11-19" and c.name == f"{KEV_CVE} nginx resolver bug"
    assert c.cvss_score == 5.0                                       # below 7.0 but known exploited
    with env.app.state.SessionLocal() as db:
        hit = db.scalar(select(WatchHit).where(WatchHit.cve_id == KEV_CVE))
        assert hit.source == "kev" and hit.kev and hit.quality == "confirmed"
        assert watch.load_state(db)["last_kev_date"] == "2026-10-29"
        watch.set_watch_settings(db, True, "7.0", False, True)
        db.query(Campaign).delete()
        db.commit()
    assert run(env, WatchNet(items=[], kev=kev, lookups=lookups), now=NOW + timedelta(hours=1))["drafts"] == 0


def test_kev_lookups_are_capped(env):
    kev = {"vulnerabilities": [{"cveID": f"CVE-2026-3000{n}", "dateAdded": "2026-10-30", "vendorProject": "x",
                                "product": "y"} for n in range(8)]}
    net = WatchNet(items=[], kev=kev)
    run(env, net)
    assert len([p for p in net.nvd() if "cveId" in p]) == 5


def test_one_source_failing_keeps_the_others(env):
    kev = {"vulnerabilities": [{"cveID": KEV_CVE, "dateAdded": "2026-10-30", "vendorProject": "nginx", "product": "nginx"}]}
    summary = run(env, WatchNet(kev=kev, fail={"nvd"}))
    assert summary["errors"][0] == "NVD: ConnectError" and summary["drafts"] == 1     # KEV name similarity: nginx
    with env.app.state.SessionLocal() as db:
        state = watch.load_state(db)
    assert "last_nvd_check" not in state and state["last_kev_date"] == "2026-10-30"
    summary = run(env, WatchNet(fail={"kev"}), now=NOW + timedelta(hours=1))
    assert summary["errors"] == ["CISA KEV: download failed, used the cached feed"] and summary["drafts"] == 2
    (env.app.state.settings.data_dir / "kev.json").unlink()
    summary = run(env, WatchNet(fail={"kev"}), now=NOW + timedelta(hours=2))
    assert summary["errors"] == ["CISA KEV: ConnectError"]


# ----------------------------------------------------------------- templates
def test_auto_attach_after_template_appears(env):
    items = [nvd_cve(APACHE_CVE, 8.1, [cpe_match("apache", "http_server", si="2.4.0", ee="2.4.62")])]
    run(env, WatchNet(items=items))
    assert campaigns(env)[APACHE_CVE].templates == []
    with env.app.state.SessionLocal() as db:
        db.add(TemplateIndex(template_id=APACHE_CVE, path="/t/apache.yaml", name="Apache", cve_ids=APACHE_CVE))
        db.add(Campaign(name="closed one", cve_id=APACHE_CVE, status="closed"))
        db.commit()
        assert watch.attach_new_templates(db) == 1
        db.commit()
        assert watch.attach_new_templates(db) == 0
        row = db.scalar(select(AuditLog).where(AuditLog.action == "campaign.template_added"))
        assert row.username == "0-day watch" and "attached automatically" in row.details
        assert len(list(db.scalars(select(CampaignTemplate)))) == 1


# ----------------------------------------------------------------- scheduler
def tick(app, at):
    async def go():
        task = await watch.maybe_watch(app, at)
        if task is not None:
            await task
        return task
    return asyncio.run(go())


def test_maybe_watch_gating(env):
    net = WatchNet()
    env.app.state.get_json = net
    env.app.state.watch_sleep = NO_SLEEP
    now = utcnow()
    assert tick(env.app, now) is None                                  # not straight after startup
    assert tick(env.app, now + timedelta(minutes=2)) is None
    assert tick(env.app, now + timedelta(minutes=3)) is not None
    calls = len(net.calls)
    assert tick(env.app, now + timedelta(minutes=30)) is None and len(net.calls) == calls
    assert tick(env.app, now + timedelta(minutes=70)) is not None
    with env.app.state.SessionLocal() as db:
        watch.set_watch_settings(db, False, "7", True, True)
        db.commit()
    assert tick(env.app, now + timedelta(hours=5)) is None


def test_failed_run_records_the_attempt(env, monkeypatch):
    monkeypatch.setattr(watch, "run_watch", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    now = utcnow()
    env.app.state.watch_started_at = now - timedelta(minutes=5)
    assert tick(env.app, now) is not None
    with env.app.state.SessionLocal() as db:
        assert watch.last_run(db)["errors"] == ["watch: RuntimeError"]
    assert tick(env.app, now + timedelta(seconds=30)) is None
    assert env.app.state.watch_running is False


def test_scheduler_loop_calls_maybe_watch():
    import inspect
    from app import scheduler
    assert "maybe_watch" in inspect.getsource(scheduler.scheduler_loop)


# ----------------------------------------------------------------- routes
def wait_watch(client, timeout=10.0):
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not getattr(client.app.state, "watch_running", False):
            with client.app.state.SessionLocal() as db:
                if watch.last_run(db):
                    return
        time.sleep(0.05)
    raise AssertionError("watch run did not finish")


def test_watch_page_check_now_and_settings(env):
    env.app.state.get_json = WatchNet()
    env.app.state.watch_sleep = NO_SLEEP
    page = env.get("/watch")
    assert page.status_code == 200 and "0-day watch" in page.text and "Never" in page.text and "Check now" in page.text
    assert 'href="/watch"' in env.get("/").text
    csrf = get_csrf(env, "/watch")
    assert env.post("/watch/run", data={}, follow_redirects=False).status_code in (400, 403)
    r = env.post("/watch/run", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/watch?msg=")
    wait_watch(env)
    page = env.get("/watch").text
    assert PHP_CVE in page and APACHE_CVE in page and "Drafts created" in page and "draft" in page
    r = env.post("/watch/settings", data={"csrf": csrf, "enabled": "true", "min_cvss": "8.5", "kev_always": "true"},
                 follow_redirects=False)
    assert r.status_code == 303
    with env.app.state.SessionLocal() as db:
        cfg = watch.load_state(db)
        assert cfg["min_cvss"] == 8.5 and cfg["include_possible"] is False and cfg["enabled"] is True
        assert db.scalar(select(AuditLog).where(AuditLog.action == "watch.run_started")) is not None
    r = env.post("/watch/settings", data={"csrf": csrf, "min_cvss": "abc"})
    assert r.status_code == 400 and "Minimum CVSS" in r.text


def test_watch_permissions(env):
    make_user(env, "vera", "viewer")
    make_user(env, "ana", "analyst")
    env.app.state.get_json = WatchNet(items=[])
    env.app.state.watch_sleep = NO_SLEEP
    login_as(env, "vera")
    assert env.get("/watch").status_code == 200
    csrf = get_csrf(env, "/watch")
    assert env.post("/watch/run", data={"csrf": csrf}, follow_redirects=False).status_code == 403
    assert env.post("/watch/settings", data={"csrf": csrf, "min_cvss": "5"}, follow_redirects=False).status_code == 403
    login_as(env, "ana")
    csrf = get_csrf(env, "/watch")
    assert env.post("/watch/settings", data={"csrf": csrf, "min_cvss": "5"}, follow_redirects=False).status_code == 403
    assert env.post("/watch/run", data={"csrf": csrf}, follow_redirects=False).status_code == 303
    wait_watch(env)


def test_activate_creates_suspected_issues_and_announces(env):
    run(env, WatchNet())
    c = campaigns(env)[PHP_CVE]
    page = env.get(f"/campaigns/{c.id}").text
    assert "data-draft-banner" in page and "Activate" in page and "Dismiss" in page and "data-watch-matches" in page
    assert "Verify now" not in page and "confirmed" in page
    csrf = get_csrf(env, f"/campaigns/{c.id}")
    assert env.post(f"/campaigns/{c.id}/verify", data={"csrf": csrf}).status_code == 400
    r = env.post(f"/campaigns/{c.id}/activate", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303 and "activated" in r.headers["location"]
    assert campaigns(env)[PHP_CVE].status == "active"
    assert all(r.enabled for r in rules_of(env, c.id))
    php_issues = [i for i in issues(env) if i.vuln_id == PHP_CVE]
    assert len(php_issues) == 1 and php_issues[0].confidence == "suspected" and php_issues[0].asset == "192.168.1.10:8080"
    with env.app.state.SessionLocal() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action == "campaign.activated")) is not None
    r = env.post(f"/campaigns/{c.id}/activate", data={"csrf": csrf}, follow_redirects=False)
    assert "err=" in r.headers["location"]
    assert "Verify now" in env.get(f"/campaigns/{c.id}").text


def test_dismiss_and_reopen_as_draft(env):
    run(env, WatchNet())
    c = campaigns(env)[APACHE_CVE]
    csrf = get_csrf(env, f"/campaigns/{c.id}")
    assert env.post(f"/campaigns/{c.id}/status", data={"csrf": csrf}, follow_redirects=False).headers["location"] \
        .endswith("err=Activate+or+dismiss+this+draft+first")
    r = env.post(f"/campaigns/{c.id}/dismiss", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303 and campaigns(env)[APACHE_CVE].status == "dismissed"
    assert not any(r.enabled for r in rules_of(env, c.id))
    assert "Reopen as draft" in env.get(f"/campaigns/{c.id}").text
    r = env.post(f"/campaigns/{c.id}/reopen", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303 and campaigns(env)[APACHE_CVE].status == "draft"
    with env.app.state.SessionLocal() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action == "campaign.dismissed")) is not None
    make_user(env, "vera", "viewer")
    login_as(env, "vera")
    csrf = get_csrf(env, "/watch")
    assert env.post(f"/campaigns/{c.id}/activate", data={"csrf": csrf}, follow_redirects=False).status_code == 403


def test_campaign_tabs_and_dashboard_exclude_drafts(env):
    run(env, WatchNet())
    with env.app.state.SessionLocal() as db:
        db.add(Campaign(name="Live one", cve_id="CVE-2026-40000", status="active"))
        db.commit()
    active = env.get("/campaigns").text
    assert "Live one" in active and APACHE_CVE not in active and 'data-drafts="2"' in active
    drafts = env.get("/campaigns?view=draft").text
    assert APACHE_CVE in drafts and PHP_CVE in drafts and "Live one" not in drafts
    with env.app.state.SessionLocal() as db:
        db.query(Campaign).filter(Campaign.cve_id == APACHE_CVE).update({"status": "dismissed"})
        db.commit()
    everything = env.get("/campaigns?view=all").text
    assert "st-cancelled" in everything and "dismissed" in everything
    dash = env.get("/").text
    assert 'data-stat="drafts_waiting"' in dash and "Drafts waiting" in dash
    assert "Live one" in dash and f"{PHP_CVE} " not in dash.split("Active campaigns")[-1].split("Quick start")[0]
    from tests.test_api import api, new_key
    key = new_key(env)
    assert [c["cve_id"] for c in api(env, key, "GET", "/campaigns?status=draft").json()["campaigns"]] == [PHP_CVE]


def test_draft_event_is_offered_to_channel_rules():
    from app.notifications import EVENTS
    assert "campaign.draft" in EVENTS


def test_reindex_after_template_update_attaches_new_templates(env):
    items = [nvd_cve(APACHE_CVE, 8.1, [cpe_match("apache", "http_server", si="2.4.0", ee="2.4.62")])]
    run(env, WatchNet(items=items))
    settings = env.app.state.settings
    src = (settings.nuclei_templates_dir / "http/cves/2026/CVE-2026-109619.yaml").read_text()
    dest = settings.nuclei_templates_dir / f"http/cves/2026/{APACHE_CVE}.yaml"
    dest.write_text(src.replace(PHP_CVE, APACHE_CVE))
    from app.routers.templates import reindex_in_background
    asyncio.run(reindex_in_background(env.app))
    assert [t.template_id for t in campaigns(env)[APACHE_CVE].templates] == [APACHE_CVE]
