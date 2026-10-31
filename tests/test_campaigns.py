import json

import pytest
from sqlalchemy import select

from app import campaigns as camp
from app import issues as iss
from app.db import AuditLog, Campaign, CampaignTemplate, Issue, Job, Rule, TemplateIndex
from app.templates_index import reindex
from tests.conftest import get_csrf, wait_job
from tests.test_intel import KEV, NVD_V31, FakeNet
from tests.test_inventory import seed_inventory
from tests.test_rbac import login_as, make_user

PHP_CVE = "CVE-2026-109619"  # fixture template http/cves/2026/CVE-2026-109619.yaml; PHP 8.3.10 on 192.168.1.10:8080
NVD_PHP = {"totalResults": 1, "vulnerabilities": [{"cve": {
    "id": PHP_CVE, "published": "2026-10-20T10:00:00.000", "descriptions": [{"lang": "en", "value": "PHP use-after-free."}],
    "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {
        "version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N"}}]},
    "references": [{"url": "https://php.example/advisory"}]}}]}


@pytest.fixture
def env(auth):
    """Inventory with PHP 8.3.10, an indexed template for the CVE, and a fake intel network."""
    seed_inventory(auth)
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
        db.commit()
    auth.app.state.get_json = FakeNet(nvd={PHP_CVE: NVD_PHP, "CVE-2021-41773": NVD_V31})
    return auth


def create(client, **form):
    csrf = get_csrf(client, "/campaigns/new")
    data = {"csrf": csrf, "cve_id": PHP_CVE, "name": "", "severity": "auto", "description": "",
            "product_pattern": "php", "version_constraint": "< 8.3.15", "attach_templates": "true", "fetch_intel": "true"}
    data.update(form)
    return client.post("/campaigns", data=data, follow_redirects=False)


def campaign(client, cid=None):
    with client.app.state.SessionLocal() as db:
        c = db.get(Campaign, cid) if cid else db.scalar(select(Campaign))
        db.expunge_all()
        return c


def test_create_campaign_end_to_end(env):
    r = create(env)
    assert r.status_code == 303
    cid = int(r.headers["location"].rsplit("/", 1)[1])
    c = campaign(env, cid)
    assert c.cve_id == PHP_CVE and c.name == PHP_CVE and c.severity == "critical" and c.cvss_score == 9.8
    assert c.description == "PHP use-after-free." and c.kev is False and c.intel_error == ""
    with env.app.state.SessionLocal() as db:
        rule = db.scalar(select(Rule).where(Rule.campaign_id == cid))
        assert rule.cve_id == PHP_CVE and rule.severity == "critical" and rule.enabled
        tpl = list(db.scalars(select(CampaignTemplate).where(CampaignTemplate.campaign_id == cid)))
        assert [t.template_id for t in tpl] == [PHP_CVE]
        issues = camp.campaign_issues(db, db.get(Campaign, cid))
        assert [(i.asset, i.confidence) for i in issues] == [("192.168.1.10:8080", "suspected")]
    page = env.get(f"/campaigns/{cid}").text
    for text in ("PHP use-after-free.", "9.8", "192.168.1.10:8080", "Suspected", PHP_CVE + ".yaml", "php"):
        assert text in page, text
    assert "campaign.created" in [a.action for a in env.app.state.SessionLocal().scalars(select(AuditLog))]


def test_create_validates_and_survives_offline_intel(env):
    r = create(env, cve_id="not-a-cve")
    assert r.status_code == 400 and "CVE id must look like" in r.text
    r = create(env, cve_id="", name="")
    assert r.status_code == 400 and "name or a CVE" in r.text
    r = create(env, version_constraint="<<< nope")
    assert r.status_code == 400
    env.app.state.get_json = FakeNet(fail={"nvd", "kev"})
    r = create(env, name="Offline drill", severity="auto")
    assert r.status_code == 303
    c = campaign(env)
    assert c.name == "Offline drill" and c.severity == "high" and "offline" in c.intel_error


def test_kev_campaign_shows_badge(env):
    r = create(env, cve_id="CVE-2021-41773", product_pattern="apache", version_constraint="< 2.4.51")
    cid = int(r.headers["location"].rsplit("/", 1)[1])
    c = campaign(env, cid)
    assert c.kev and c.kev_due == "2021-11-17" and c.kev_ransomware and c.severity == "high"
    assert "Known exploited" in env.get(f"/campaigns/{cid}").text
    assert "Known exploited" in env.get("/campaigns").text


def test_progress_and_verify_targets(env):
    cid = int(create(env).headers["location"].rsplit("/", 1)[1])
    with env.app.state.SessionLocal() as db:
        c = db.get(Campaign, cid)
        assert camp.verify_targets(db, c) == ["http://192.168.1.10:8080"]
        p = camp.progress(camp.campaign_issues(db, c))
        assert p["total"] == 1 and p["suspected"] == 1 and p["remediated_pct"] == 0
        issue = camp.campaign_issues(db, c)[0]
        iss.change_status(db, issue, "fixed", actor=None)
        db.commit()
        p = camp.progress(camp.campaign_issues(db, c))
        assert p["remediated_pct"] == 100 and p["fixed"] == 1
        iss.change_status(db, issue, "verified", actor=None)
        db.commit()
        assert camp.verify_targets(db, c) == []  # closed issues are not re-scanned


def test_verify_runs_campaign_templates_against_exposed_assets(env):
    cid = int(create(env).headers["location"].rsplit("/", 1)[1])
    csrf = get_csrf(env, f"/campaigns/{cid}")
    r = env.post(f"/campaigns/{cid}/verify", data={"csrf": csrf, "profile": "gentle", "extra_targets": "https://extra.example"},
                 follow_redirects=False)
    assert r.status_code == 303
    job_id = int(r.headers["location"].rsplit("/", 1)[1])
    wait_job(env, job_id)
    with env.app.state.SessionLocal() as db:
        job = db.get(Job, job_id)
        assert job.campaign_id == cid and job.kind == "nuclei"
        assert PHP_CVE + ".yaml" in job.command and "-retries" in job.command
        params = json.loads(job.params_json)
        assert params["targets"] == ["http://192.168.1.10:8080", "https://extra.example"]
        assert params["campaign"] == PHP_CVE
    assert f"/jobs/{job_id}" in env.get(f"/campaigns/{cid}").text
    assert "campaign.verified" in [a.action for a in env.app.state.SessionLocal().scalars(select(AuditLog))]


def test_verify_without_templates_or_targets_explains(env):
    r = create(env, cve_id="CVE-2021-41773", product_pattern="", version_constraint="", attach_templates="")
    cid = int(r.headers["location"].rsplit("/", 1)[1])
    csrf = get_csrf(env, f"/campaigns/{cid}")
    r = env.post(f"/campaigns/{cid}/verify", data={"csrf": csrf, "profile": "normal"})
    assert r.status_code == 400 and "Attach at least one nuclei template" in r.text
    with env.app.state.SessionLocal() as db:
        path = db.scalar(select(TemplateIndex.path).where(TemplateIndex.template_id == PHP_CVE))
    env.post(f"/campaigns/{cid}/templates", data={"csrf": csrf, "path": path})
    r = env.post(f"/campaigns/{cid}/verify", data={"csrf": csrf, "profile": "normal"})
    assert r.status_code == 400 and "No exposed assets" in r.text


def test_rules_and_templates_management(env):
    cid = int(create(env, product_pattern="", version_constraint="", attach_templates="").headers["location"].rsplit("/", 1)[1])
    csrf = get_csrf(env, f"/campaigns/{cid}")
    page = env.get(f"/campaigns/{cid}").text
    assert "Suggested" in page and PHP_CVE + ".yaml" in page  # suggestion from the index
    r = env.post(f"/campaigns/{cid}/rules", data={"csrf": csrf, "product_pattern": "php", "version_constraint": "< 8.3.15"},
                 follow_redirects=False)
    assert r.status_code == 303
    with env.app.state.SessionLocal() as db:
        rid = db.scalar(select(Rule.id).where(Rule.campaign_id == cid))
        assert len(camp.campaign_issues(db, db.get(Campaign, cid))) == 1
        path = db.scalar(select(TemplateIndex.path).where(TemplateIndex.template_id == PHP_CVE))
    env.post(f"/campaigns/{cid}/templates", data={"csrf": csrf, "path": path})
    env.post(f"/campaigns/{cid}/templates", data={"csrf": csrf, "path": path})  # idempotent
    r = env.post(f"/campaigns/{cid}/templates", data={"csrf": csrf, "path": "/etc/passwd"})
    assert r.status_code == 400
    with env.app.state.SessionLocal() as db:
        assert db.query(CampaignTemplate).filter_by(campaign_id=cid).count() == 1
        tid = db.scalar(select(CampaignTemplate.id))
    env.post(f"/campaigns/{cid}/templates/{tid}/delete", data={"csrf": csrf})
    env.post(f"/campaigns/{cid}/rules/{rid}/delete", data={"csrf": csrf})
    with env.app.state.SessionLocal() as db:
        assert db.query(CampaignTemplate).count() == 0 and db.get(Rule, rid) is None
    actions = {a.action for a in env.app.state.SessionLocal().scalars(select(AuditLog))}
    assert {"campaign.rule_added", "campaign.rule_removed", "campaign.template_added", "campaign.template_removed"} <= actions


def test_close_reopen_refresh_and_list(env):
    cid = int(create(env).headers["location"].rsplit("/", 1)[1])
    csrf = get_csrf(env, f"/campaigns/{cid}")
    env.post(f"/campaigns/{cid}/status", data={"csrf": csrf})
    assert campaign(env, cid).status == "closed" and campaign(env, cid).closed_at
    assert PHP_CVE not in env.get("/campaigns").text.split("<tbody>")[1]  # active view hides it
    assert PHP_CVE in env.get("/campaigns?view=all").text
    env.post(f"/campaigns/{cid}/status", data={"csrf": csrf})
    assert campaign(env, cid).status == "active"
    env.app.state.get_json = FakeNet(nvd={PHP_CVE: NVD_PHP}, kev={"vulnerabilities": [{"cveID": PHP_CVE, "dateAdded": "2026-10-30", "dueDate": "2026-11-20", "knownRansomwareCampaignUse": "Unknown", "vulnerabilityName": "PHP UAF"}]})
    env.post(f"/campaigns/{cid}/refresh", data={"csrf": csrf})
    assert campaign(env, cid).kev and campaign(env, cid).kev_due == "2026-11-20"
    page = env.get("/campaigns").text
    assert PHP_CVE in page and "0%" in page


def test_issue_detail_and_dashboard_link_campaign(env):
    cid = int(create(env).headers["location"].rsplit("/", 1)[1])
    with env.app.state.SessionLocal() as db:
        iid = db.scalar(select(Issue.id))
    assert f'href="/campaigns/{cid}"' in env.get(f"/issues/{iid}").text
    assert f'href="/campaigns/{cid}"' in env.get("/").text


def test_permissions(env):
    cid = int(create(env).headers["location"].rsplit("/", 1)[1])
    make_user(env, "vee", "viewer")
    login_as(env, "vee")
    assert env.get(f"/campaigns/{cid}").status_code == 200
    assert env.get("/campaigns/new").status_code == 403
    csrf = get_csrf(env, "/campaigns")
    for path in ("/campaigns", f"/campaigns/{cid}/verify", f"/campaigns/{cid}/rules", f"/campaigns/{cid}/templates",
                 f"/campaigns/{cid}/status", f"/campaigns/{cid}/refresh"):
        assert env.post(path, data={"csrf": csrf}).status_code == 403, path
    assert "New campaign" not in env.get("/campaigns").text


def test_progress_counts_verified_issues_and_links_the_badge(env):
    cid = int(create(env).headers["location"].rsplit("/", 1)[1])
    with env.app.state.SessionLocal() as db:
        c = db.get(Campaign, cid)
        issue = camp.campaign_issues(db, c)[0]
        issue.confidence = "verified"
        db.commit()
        iid = issue.id
        p = camp.progress(camp.campaign_issues(db, c))
        assert (p["confirmed"], p["conf_verified"], p["suspected"], p["scan_confirmed"]) == (0, 1, 0, 1)
    page = env.get(f"/campaigns/{cid}").text
    assert "0 confirmed · 1 verified · 0 suspected" in page
    assert f'class="badge conf-verified" href="/issues/{iid}#proof"' in page
    assert f'class="badge conf-verified" href="/issues/{iid}#proof"' in env.get(f"/reports/campaigns/{cid}").text
