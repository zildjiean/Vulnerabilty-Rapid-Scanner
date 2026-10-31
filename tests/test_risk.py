import csv
import io
import json
from datetime import timedelta
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import select

from app import intel, risk
from app.db import AppSetting, AuditLog, Campaign, CveIntel, Issue, Scope, utcnow
from tests.conftest import get_csrf
from tests.test_intel import NVD_V31
from tests.test_issue_routes import SPECS, seed
from tests.test_rbac import login_as, make_user


def mk_issue(severity="high", confidence="suspected", cve="CVE-2021-41773", iid=1):
    return SimpleNamespace(id=iid, severity=severity, confidence=confidence, cve_id=cve, scope=None)


def mk_intel(cvss=None, epss=None, pct=None, kev=False, ransomware=False):
    return SimpleNamespace(cve_id="CVE-2021-41773", cvss_score=cvss, cvss_severity="", epss=epss, epss_percentile=pct,
                           epss_date="2026-10-30" if epss is not None else "", kev=kev, kev_ransomware=ransomware,
                           kev_due="", updated_at=utcnow())


# ----------------------------------------------------------------- score
@pytest.mark.parametrize("sev,points", [("critical", 47), ("high", 37), ("medium", 25), ("low", 12), ("info", 0),
                                         ("unknown", 0)])
def test_severity_fallback_without_cvss(sev, points):
    s = risk.risk_score(mk_issue(sev), None, None)
    assert s.total == points and s.parts[0][1] == points and s.parts[0][0] == f"severity {sev}"


def test_cvss_beats_severity_and_rounds_half_up():
    s = risk.risk_score(mk_issue("low"), mk_intel(cvss=9.8), None)
    assert s.total == 49 and s.parts[0][0] == "CVSS 9.8"
    assert risk.risk_score(mk_issue(), mk_intel(cvss=6.5), None).total == 33   # 32.5 -> 33
    assert risk.risk_score(mk_issue(), mk_intel(cvss=10.0), None).total == 50


def test_kev_beats_epss_and_ransomware_adds():
    assert risk.risk_score(mk_issue(), mk_intel(cvss=5.0, epss=0.2, pct=0.5), None).total == 25 + 10
    s = risk.risk_score(mk_issue(), mk_intel(cvss=5.0, epss=0.9, pct=0.99, kev=True), None)
    assert s.total == 25 + 25 and s.kev
    s = risk.risk_score(mk_issue(), mk_intel(cvss=5.0, kev=True, ransomware=True), None)
    assert s.total == 25 + 25 + 5 and [p[0] for p in s.parts] == ["CVSS 5.0", "KEV", "ransomware"]
    assert risk.risk_score(mk_issue(), mk_intel(cvss=5.0), None).total == 25   # exploitation unknown -> 0


def test_confidence_scope_cap_and_title():
    assert risk.risk_score(mk_issue(confidence="confirmed"), None, None).total == 37 + 5
    assert risk.risk_score(mk_issue(confidence="verified"), None, "high").total == 37 + 10 + 6
    assert risk.risk_score(mk_issue(), None, "medium").total == 37 + 3
    assert risk.risk_score(mk_issue(), None, "low").total == 37
    s = risk.risk_score(mk_issue(confidence="verified"), mk_intel(cvss=10.0, kev=True, ransomware=True), "critical")
    assert s.total == 100 and s.band == "critical"   # 50 + 25 + 5 + 10 + 10
    s = risk.risk_score(mk_issue(confidence="verified"), mk_intel(cvss=10.0, kev=True, ransomware=True), "critical")
    s2 = risk.risk_score(SimpleNamespace(id=2, severity="critical", confidence="verified", cve_id="", scope=None),
                         mk_intel(cvss=10.0, kev=True, ransomware=True), "critical")
    assert s.total == s2.total == 100
    s = risk.risk_score(mk_issue(confidence="verified"), mk_intel(cvss=9.8, kev=True), "critical")
    assert s.title == "CVSS 9.8 → 49 · KEV → 25 · verified → 10 · scope critical → 10" and s.total == 94


@pytest.mark.parametrize("total,band", [(100, "critical"), (80, "critical"), (79, "high"), (60, "high"),
                                        (59, "medium"), (40, "medium"), (39, "low"), (0, "low")])
def test_band_edges(total, band):
    assert risk.band_for(total) == band


# ----------------------------------------------------------------- EPSS parser
def test_parse_epss():
    data = {"data": [{"cve": "CVE-2021-41773", "epss": "0.94", "percentile": "0.999", "date": "2026-10-30"},
                     {"cve": "cve-2026-0001", "epss": "0.00049", "percentile": "0.14", "date": "2026-10-30"},
                     {"cve": "CVE-2026-0002", "epss": "abc", "percentile": "0.1"},
                     {"cve": "CVE-2026-0003", "epss": "1.5", "percentile": "0.1"},
                     {"epss": "0.1"}, "junk"]}
    assert risk.parse_epss(data) == {"CVE-2021-41773": (0.94, 0.999, "2026-10-30"),
                                     "CVE-2026-0001": (0.00049, 0.14, "2026-10-30")}
    assert risk.parse_epss({"data": []}) == {}
    assert risk.parse_epss(None) == {} and risk.parse_epss({"status": "error"}) == {}


# ----------------------------------------------------------------- refresh
KEV_FEED = {"vulnerabilities": [{"cveID": "CVE-2021-41773", "dueDate": "2021-11-17",
                                 "knownRansomwareCampaignUse": "Known"}]}


class IntelNet:
    def __init__(self, epss=None, nvd=None, fail=()):
        self.epss, self.nvd, self.fail, self.calls = epss or {}, nvd or {}, set(fail), []

    def __call__(self, url, params=None):
        self.calls.append((url, params))
        if url == risk.EPSS_URL:
            if "epss" in self.fail:
                raise httpx.ConnectError("epss offline")
            rows = [{"cve": c, "epss": str(self.epss[c][0]), "percentile": str(self.epss[c][1]), "date": "2026-10-30"}
                    for c in params["cve"].split(",") if c in self.epss]
            return {"status": "OK", "data": rows}
        if url == intel.KEV_URL:
            if "kev" in self.fail:
                raise httpx.ConnectError("kev offline")
            return KEV_FEED
        if url == intel.NVD_URL:
            if "nvd" in self.fail:
                raise httpx.ConnectError("nvd offline")
            return self.nvd.get(params["cveId"], {"totalResults": 0, "vulnerabilities": []})
        raise AssertionError(url)

    def urls(self, url):
        return [p for u, p in self.calls if u == url]


def add_issue_cves(client, cves):
    with client.app.state.SessionLocal() as db:
        for n, cve in enumerate(cves):
            db.add(Issue(key=f"10.9.{n // 250}.{n % 250}:80|{cve}", asset=f"10.9.{n // 250}.{n % 250}:80", vuln_id=cve,
                         cve_id=cve, title=cve, severity="high"))
        db.commit()


def intel_rows(client):
    with client.app.state.SessionLocal() as db:
        rows = {r.cve_id: r for r in db.scalars(select(CveIntel))}
        db.expunge_all()
        return rows


def test_refresh_intel_epss_batches_kev_campaign_cvss_and_nvd_limit(auth):
    seed(auth, SPECS)   # CVE-2021-41773 plus two non-CVE issues
    extra = [f"CVE-2026-{1000 + n}" for n in range(150)]
    add_issue_cves(auth, extra + ["cve-2026-9999 "])   # odd spelling is normalised
    with auth.app.state.SessionLocal() as db:
        db.add(Campaign(name="PHP", cve_id="CVE-2026-1000", cvss_score=8.8, cvss_severity="high"))
        db.add(Campaign(name="no cve", cve_id=""))
        db.commit()
    net = IntelNet(epss={"CVE-2021-41773": (0.94, 0.999), "CVE-2026-1001": (0.01, 0.4)},
                   nvd={"CVE-2021-41773": NVD_V31})
    with auth.app.state.SessionLocal() as db:
        summary = risk.refresh_intel(db, auth.app.state.settings, net, nvd_limit=3)
        db.commit()
    batches = net.urls(risk.EPSS_URL)
    assert len(batches) == 2 and len(batches[0]["cve"].split(",")) == 100
    assert summary["cves"] == 152 and summary["epss"] == 2 and summary["kev"] == 1
    assert summary["cvss_from_campaigns"] == 1 and summary["nvd"] == 3 and summary["errors"] == []
    assert len(net.urls(intel.NVD_URL)) == 3
    rows = intel_rows(auth)
    assert len(rows) == 152 and "CVE-2026-9999" in rows
    a = rows["CVE-2021-41773"]
    assert (a.epss, a.epss_percentile, a.epss_date) == (0.94, 0.999, "2026-10-30")
    assert a.kev and a.kev_ransomware and a.kev_due == "2021-11-17" and a.cvss_score == 7.5 and a.cvss_severity == "high"
    assert rows["CVE-2026-1000"].cvss_score == 8.8 and not rows["CVE-2026-1000"].kev
    with auth.app.state.SessionLocal() as db:
        stored = json.loads(db.get(AppSetting, "intel_refresh").value)
    assert stored["cves"] == 152 and stored["at"]
    # next run asks NVD about different CVEs (the oldest-checked first), not the same three again
    first = {p["cveId"] for p in net.urls(intel.NVD_URL)}
    net.calls.clear()
    with auth.app.state.SessionLocal() as db:
        risk.refresh_intel(db, auth.app.state.settings, net, nvd_limit=3)
        db.commit()
    second = {p["cveId"] for p in net.urls(intel.NVD_URL)}
    assert len(second) == 3 and not first & second and "CVE-2021-41773" not in second   # scored ones are skipped


def test_refresh_intel_one_source_failing_keeps_the_others(auth):
    seed(auth, SPECS)
    net = IntelNet(epss={"CVE-2021-41773": (0.5, 0.8)}, nvd={"CVE-2021-41773": NVD_V31}, fail={"kev"})
    with auth.app.state.SessionLocal() as db:
        summary = risk.refresh_intel(db, auth.app.state.settings, net)
        db.commit()
    assert len(summary["errors"]) == 1 and "KEV" in summary["errors"][0]
    row = intel_rows(auth)["CVE-2021-41773"]
    assert row.epss == 0.5 and row.cvss_score == 7.5 and row.kev is False
    net = IntelNet(fail={"epss", "nvd"})   # earlier EPSS value survives a failed run
    with auth.app.state.SessionLocal() as db:
        summary = risk.refresh_intel(db, auth.app.state.settings, net)
        db.commit()
    assert any("EPSS" in e for e in summary["errors"]) and summary["kev"] == 1
    row = intel_rows(auth)["CVE-2021-41773"]
    assert row.epss == 0.5 and row.kev is True


def test_refresh_intel_without_cves_makes_no_requests(auth):
    net = IntelNet()
    with auth.app.state.SessionLocal() as db:
        summary = risk.refresh_intel(db, auth.app.state.settings, net)
    assert net.calls == [] and summary["cves"] == 0


def test_refresh_shares_the_campaign_kev_cache(auth):
    seed(auth, SPECS)
    cache = auth.app.state.settings.data_dir / "kev.json"
    cache.write_text(json.dumps(KEV_FEED))
    net = IntelNet()
    with auth.app.state.SessionLocal() as db:
        risk.refresh_intel(db, auth.app.state.settings, net)
    assert net.urls(intel.KEV_URL) == []   # fresh cache reused


# ----------------------------------------------------------------- scheduler gating
def test_maybe_refresh_intel_gating(auth):
    import asyncio
    seed(auth, SPECS)
    net = IntelNet()
    auth.app.state.get_json = net
    now = utcnow()
    assert asyncio.run(risk.maybe_refresh_intel(auth.app, now)) is None             # not straight after startup
    assert asyncio.run(risk.maybe_refresh_intel(auth.app, now + timedelta(minutes=3))) is not None
    calls = len(net.calls)
    assert asyncio.run(risk.maybe_refresh_intel(auth.app, now + timedelta(minutes=30))) is None   # within the hour
    assert len(net.calls) == calls
    assert asyncio.run(risk.maybe_refresh_intel(auth.app, now + timedelta(minutes=70))) is not None


# ----------------------------------------------------------------- routes
def test_settings_intel_refresh_route(auth):
    seed(auth, SPECS)
    auth.app.state.get_json = IntelNet(epss={"CVE-2021-41773": (0.5, 0.8)}, nvd={"CVE-2021-41773": NVD_V31})
    page = auth.get("/settings").text
    assert "Threat intel" in page and "never" in page.lower()
    csrf = get_csrf(auth, "/settings")
    assert auth.post("/settings/intel/refresh", data={}, follow_redirects=False).status_code in (400, 403)
    r = auth.post("/settings/intel/refresh", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303 and "msg=" in r.headers["location"] and "1+CVE" in r.headers["location"]
    page = auth.get("/settings").text
    assert "Refresh threat intel now" in page and "EPSS rows" in page
    with auth.app.state.SessionLocal() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action == "intel.refreshed")) is not None


def test_settings_intel_refresh_needs_settings_manage(auth):
    make_user(auth, "ana", "analyst")
    login_as(auth, "ana")
    csrf = get_csrf(auth, "/issues")
    assert auth.post("/settings/intel/refresh", data={"csrf": csrf}, follow_redirects=False).status_code == 403


def store_intel(client, **kw):
    with client.app.state.SessionLocal() as db:
        db.add(CveIntel(cve_id="CVE-2021-41773", updated_at=utcnow(), **kw))
        db.commit()


def test_issue_list_risk_column_and_default_order(auth):
    ids = seed(auth, SPECS)
    store_intel(auth, cvss_score=9.8, epss=0.94, epss_percentile=0.999, epss_date="2026-10-30", kev=True)
    with auth.app.state.SessionLocal() as db:
        s = Scope(name="Core", criticality="critical")
        db.add(s)
        db.flush()
        db.get(Issue, ids["weak-cipher"]).scope_id = s.id
        db.get(Issue, ids["weak-cipher"]).confidence = "verified"
        db.commit()
    page = auth.get("/issues").text
    assert ">Risk</th>" in page and "risk-high" in page and "CVSS 9.8 → 49 · KEV → 25" in page
    # low verified on a critical scope (12+10+10=32) outranks medium suspected (25)
    assert page.index("CVE-2021-41773 title") < page.index("weak-cipher title") < page.index("exposed-panel title")
    with auth.app.state.SessionLocal() as db:
        for i in db.scalars(select(Issue)):
            db.delete(i)
        db.commit()
    page = auth.get("/issues").text
    assert 'colspan="12"' in page   # manage + play + 10 data columns


def test_issue_page_risk_card(auth):
    ids = seed(auth, SPECS)
    store_intel(auth, cvss_score=9.8, epss=0.0234, epss_percentile=0.87, epss_date="2026-10-30", kev=True,
                kev_ransomware=True)
    page = auth.get(f"/issues/{ids['CVE-2021-41773']}").text
    assert 'id="risk"' in page and "2.34 %" in page and "top 13 %" in page and "2026-10-30" in page
    assert "Known exploited" in page and "Intel updated" in page
    page = auth.get(f"/issues/{ids['exposed-panel']}").text
    assert 'id="risk"' in page and "severity medium" in page


def test_dashboard_top_risks(auth):
    seed(auth, SPECS)
    store_intel(auth, cvss_score=9.8, kev=True)
    page = auth.get("/").text
    assert "Top risks" in page and "risk-high" in page
    assert page.index("Top risks") < page.index("CVE-2021-41773 title")


def test_exports_and_api_have_risk_fields(auth):
    ids = seed(auth, SPECS)
    store_intel(auth, cvss_score=9.8, epss=0.5, epss_percentile=0.8, kev=True)
    rows = list(csv.DictReader(io.StringIO(auth.get("/reports/issues.csv").text)))
    top = rows[0]
    assert top["vuln_id"] == "CVE-2021-41773" and top["risk_score"] == "79" and top["risk_band"] == "high"
    assert top["epss"] == "0.5" and top["epss_percentile"] == "0.8" and top["kev"] == "True"
    j = auth.get("/reports/issues.json").json()["issues"]
    assert j[0]["risk_score"] == 79 and j[0]["kev"] is True and j[1]["epss"] is None
    from tests.test_api import api, new_key
    key = new_key(auth)
    body = api(auth, key, "GET", "/issues").json()
    assert body["issues"][0]["risk_score"] == 79
    one = api(auth, key, "GET", f"/issues/{ids['CVE-2021-41773']}").json()
    assert one["risk_band"] == "high" and one["epss_percentile"] == 0.8


def test_campaign_page_shows_epss(auth):
    with auth.app.state.SessionLocal() as db:
        c = Campaign(name="Apache", cve_id="CVE-2021-41773", cvss_score=7.5)
        db.add(c)
        db.commit()
        cid = c.id
    store_intel(auth, epss=0.94, epss_percentile=0.999, epss_date="2026-10-30")
    page = auth.get(f"/campaigns/{cid}").text
    assert "EPSS" in page and "94.00 %" in page


def test_notification_message_has_risk(auth):
    from app.notifications import issue_message
    ids = seed(auth, SPECS)
    store_intel(auth, cvss_score=9.8, kev=True)
    with auth.app.state.SessionLocal() as db:
        msg = issue_message(db, db.get(Issue, ids["CVE-2021-41773"]), "issue.created")
    assert ("Risk", "79 · high") in msg.fields
