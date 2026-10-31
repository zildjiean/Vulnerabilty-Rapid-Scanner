import json

import pytest
from sqlalchemy import select

from app.db import AiNote, AiUsage, Issue, IssueEvent, Job, Scope
from app.templates_index import reindex
from tests.conftest import get_csrf
from tests.test_ai_admin import FakeLLM, add_provider
from tests.test_inventory import seed_inventory
from tests.test_issue_routes import SPECS, seed
from tests.test_rbac import login_as, make_user


@pytest.fixture
def env(auth):
    seed_inventory(auth)
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
        db.commit()
    auth.app.state.llm = FakeLLM()
    add_provider(auth)
    return auth


def script(client, text="", data=None, error=None):
    client.app.state.llm = FakeLLM(text=text, data=data, error=error)
    return client.app.state.llm


def notes(client, feature):
    with client.app.state.SessionLocal() as db:
        rows = list(db.scalars(select(AiNote).where(AiNote.feature == feature)))
        db.expunge_all()
        return rows


def test_campaign_draft_fills_the_form(env):
    fake = script(env, data={"name": "Apache path traversal", "summary": "Path traversal in 2.4.49.",
                             "product_pattern": "apache", "version_constraint": ">= 2.4.49, < 2.4.51",
                             "severity": "critical", "template_search_terms": ["CVE-2021-41773"], "confidence": "high",
                             "notes": "Only 2.4.49 and 2.4.50 are affected."})
    csrf = get_csrf(env, "/campaigns/new")
    r = env.post("/ai/campaign-draft", data={"csrf": csrf, "cve_id": "CVE-2021-41773",
                                             "advisory": "Apache 2.4.49 on 192.168.1.10 is vulnerable"})
    assert r.status_code == 200
    for text in ('value="apache"', 'value="&gt;= 2.4.49, &lt; 2.4.51"', "Apache path traversal", "Only 2.4.49",
                 "/templates?q=CVE-2021-41773"):
        assert text in r.text, text
    prompt = fake.calls[0]["request"].prompt
    assert "192.168.1.10" not in prompt and "HOST-" in prompt                      # redacted before sending
    assert fake.calls[0]["request"].json_schema["required"]


def test_campaign_draft_flags_invalid_rule(env):
    script(env, data={"name": "x", "summary": "", "product_pattern": "(", "version_constraint": "nonsense",
                      "severity": "high", "template_search_terms": [], "confidence": "low", "notes": ""})
    r = env.post("/ai/campaign-draft", data={"csrf": get_csrf(env, "/campaigns/new"), "cve_id": "", "advisory": "something"})
    assert r.status_code == 200 and "check the suggested rule" in r.text.lower()


def test_template_draft_validates_and_saves(env):
    yaml_text = """id: cve-2026-9999-detect
info:
  name: Example detection
  author: ai-draft
  severity: high
  tags: cve,cve2026
  classification:
    cve-id: CVE-2026-9999
http:
  - method: GET
    path:
      - "{{BaseURL}}/version"
    matchers:
      - type: word
        words: ["ExampleServer/1.2"]
"""
    script(env, data={"yaml": yaml_text, "notes": "Matches the banner only."})
    csrf = get_csrf(env, "/templates")
    r = env.post("/ai/template-draft", data={"csrf": csrf, "cve_id": "CVE-2026-9999", "advisory": "ExampleServer 1.2 bug"})
    assert r.status_code == 200 and "cve-2026-9999-detect" in r.text and "Validation passed" in r.text
    r = env.post("/templates/save-text", data={"csrf": csrf, "yaml": yaml_text}, follow_redirects=False)
    assert r.status_code == 303
    from app.db import TemplateIndex
    with env.app.state.SessionLocal() as db:
        assert db.scalar(select(TemplateIndex).where(TemplateIndex.template_id == "cve-2026-9999-detect")).source == "custom"
    script(env, data={"yaml": "not: [valid", "notes": ""})
    r = env.post("/ai/template-draft", data={"csrf": csrf, "cve_id": "", "advisory": "x"})
    assert r.status_code == 200 and "Validation failed" in r.text


def test_issue_explain_triage_and_comment(env):
    ids = seed(env, SPECS)
    iid = ids["CVE-2021-41773"]
    fake = script(env, text="## Summary\n\nPath traversal on **10.0.0.5**.\n\n- Upgrade to `2.4.51`")
    csrf = get_csrf(env, f"/issues/{iid}")
    r = env.post(f"/ai/issues/{iid}/explain", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert "10.0.0.5" not in fake.calls[0]["request"].prompt
    page = env.get(f"/issues/{iid}").text
    assert "<strong>10.0.0.5</strong>" in page and "<code>2.4.51</code>" in page and "AI assistant" in page
    script(env, data={"verdict": "likely_false_positive", "confidence": 70, "reasoning": "Generic 200 page.",
                      "checks": ["Request the path manually"]})
    env.post(f"/ai/issues/{iid}/triage", data={"csrf": csrf})
    page = env.get(f"/issues/{iid}").text
    assert "Likely false positive" in page and "Generic 200 page." in page
    with env.app.state.SessionLocal() as db:
        assert db.get(Issue, iid).status == "new"            # AI never changes the status
    env.post(f"/ai/issues/{iid}/explain/comment", data={"csrf": csrf})
    with env.app.state.SessionLocal() as db:
        comment = db.scalar(select(IssueEvent).where(IssueEvent.issue_id == iid, IssueEvent.kind == "comment"))
        assert comment.body.startswith("AI remediation notes") and "2.4.51" in comment.body


def test_natural_language_search(env):
    seed(env, SPECS)
    with env.app.state.SessionLocal() as db:
        db.add(Scope(name="DMZ", targets="10.0.0.0/24", criticality="high"))
        db.commit()
        sid = db.scalar(select(Scope.id))
    script(env, data={"target": "issues", "view": "active", "severity": "critical", "status": "", "assignee": "",
                      "confidence": "", "overdue": False, "scope": "DMZ", "q": "", "product": "", "port": "",
                      "explanation": "Critical issues in DMZ"})
    r = env.post("/ai/search", data={"csrf": get_csrf(env, "/issues"), "question": "critical stuff in the DMZ"},
                 follow_redirects=False)
    loc = r.headers["location"]
    assert loc.startswith("/issues?") and "severity=critical" in loc and f"scope={sid}" in loc
    fake = script(env, data={"target": "inventory", "view": "active", "severity": "", "status": "", "assignee": "",
                             "confidence": "", "overdue": False, "scope": "", "q": "HOST-1", "product": "", "port": "8080",
                             "explanation": "Port 8080 on that host"})
    r = env.post("/ai/search", data={"csrf": get_csrf(env, "/inventory"), "question": "what runs on 192.168.1.10 port 8080"},
                 follow_redirects=False)
    loc = r.headers["location"]
    assert loc.startswith("/inventory?") and "q=192.168.1.10" in loc and "port=8080" in loc
    assert "192.168.1.10" not in fake.calls[0]["request"].prompt


def test_report_summary_and_job_diagnosis(env):
    seed(env, SPECS)
    script(env, text="Exposure is concentrated on HOST-1.")
    r = env.post("/ai/reports/summary", data={"csrf": get_csrf(env, "/reports"), "days": "30"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/reports?days=30")
    assert "Exposure is concentrated" in env.get("/reports?days=30").text
    with env.app.state.SessionLocal() as db:
        job = Job(kind="nuclei", status="failed", log="[ERR] Could not run nuclei: no templates found", command="nuclei -l x")
        db.add(job)
        db.commit()
        jid = job.id
    script(env, text="The templates directory is empty. Run *Update nuclei templates*.")
    env.post(f"/ai/jobs/{jid}/diagnose", data={"csrf": get_csrf(env, f"/jobs/{jid}")})
    assert "templates directory is empty" in env.get(f"/jobs/{jid}").text


def test_errors_are_shown_and_recorded(env):
    ids = seed(env, SPECS)
    iid = ids["CVE-2021-41773"]
    script(env, error="The request was declined by the model's safety classifier (cyber).")
    r = env.post(f"/ai/issues/{iid}/explain", data={"csrf": get_csrf(env, f"/issues/{iid}")}, follow_redirects=False)
    assert r.status_code == 303 and "err=" in r.headers["location"]
    assert "safety classifier" in env.get(r.headers["location"]).text
    with env.app.state.SessionLocal() as db:
        assert db.scalar(select(AiUsage).where(AiUsage.ok.is_(False))) is not None


def test_permissions_and_no_provider(auth):
    ids = seed(auth, SPECS)
    iid = ids["CVE-2021-41773"]
    # no provider configured: buttons hidden, routes explain why
    assert "Explain &amp; remediate" not in auth.get(f"/issues/{iid}").text
    r = auth.post(f"/ai/issues/{iid}/explain", data={"csrf": get_csrf(auth, f"/issues/{iid}")}, follow_redirects=False)
    assert "No+AI+provider" in r.headers["location"] or "No%20AI%20provider" in r.headers["location"]
    auth.app.state.llm = FakeLLM()
    add_provider(auth)
    make_user(auth, "vee", "viewer")
    login_as(auth, "vee")
    assert "Explain &amp; remediate" not in auth.get(f"/issues/{iid}").text
    csrf = get_csrf(auth, f"/issues/{iid}")
    for path in (f"/ai/issues/{iid}/explain", f"/ai/issues/{iid}/triage", "/ai/search", "/ai/reports/summary",
                 "/ai/campaign-draft", "/ai/template-draft"):
        assert auth.post(path, data={"csrf": csrf}).status_code == 403, path


from app import llm
from app.db import Job, Rule, TemplateIndex
from app.rules import evaluate_rules

YAML_OK = """id: cve-2026-1-php-detect
info:
  name: PHP vulnerable version banner
  author: ai-draft
  severity: high
  tags: cve,php
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: regex
        part: header
        regex: ["PHP/8\\\\.3\\\\.1[0-4]"]
"""


def suspected(client, cve="CVE-2026-1"):
    with client.app.state.SessionLocal() as db:
        db.add(Rule(name="PHP", product_pattern="php", version_constraint="< 8.3.15", cve_id=cve, severity="high"))
        db.commit()
        evaluate_rules(db)
        db.commit()
        return db.scalar(select(Issue.id).where(Issue.vuln_id == cve))


def test_issue_template_draft_then_save_and_run(env):
    iid = suspected(env)
    fake = script(env, data={"yaml": YAML_OK, "notes": "Banner check only."})
    csrf = get_csrf(env, f"/issues/{iid}")
    r = env.post(f"/ai/issues/{iid}/template-draft", data={"csrf": csrf})
    assert r.status_code == 200 and "cve-2026-1-php-detect" in r.text and "Validation passed" in r.text
    assert "Save &amp; run as proof" in r.text and "Banner check only." in r.text
    prompt = fake.calls[0]["request"].prompt
    assert "CVE-2026-1" in prompt and "authorized internal testing" in prompt and "PHP" in prompt
    assert "HOST-" in prompt and "192.168.1.10" not in prompt            # redacted
    assert "request:" not in prompt                                     # no proof text is sent
    r = env.post(f"/issues/{iid}/template/save-run", data={"csrf": csrf, "yaml": "not: [valid"})
    assert r.status_code == 400 and "Validation failed" in r.text and "not: [valid" in r.text   # YAML kept for editing
    r = env.post(f"/issues/{iid}/template/save-run", data={"csrf": csrf, "yaml": YAML_OK}, follow_redirects=False)
    assert r.status_code == 303 and "Verification+started" in r.headers["location"]
    with env.app.state.SessionLocal() as db:
        issue = db.get(Issue, iid)
        assert issue.template_id == "cve-2026-1-php-detect"
        job = db.scalar(select(Job).order_by(Job.id.desc()))      # the job may already have finished (fake nuclei)
        assert json.loads(job.params_json)["verify_issue"] == iid
        assert db.scalar(select(TemplateIndex).where(TemplateIndex.template_id == "cve-2026-1-php-detect")).source == "custom"


def test_issue_template_draft_refusal_shows_english_guidance(env):
    iid = suspected(env)
    script(env, error=llm.LLMRefusal("The request was declined by the model's safety classifier (cyber)."))
    r = env.post(f"/ai/issues/{iid}/template-draft", data={"csrf": get_csrf(env, f"/issues/{iid}")})
    assert r.status_code == 400
    assert "The configured AI model declined this request" in r.text and 'href="/ai"' in r.text
    assert "authorized security testing" in r.text
    with env.app.state.SessionLocal() as db:
        assert db.scalar(select(AiUsage).where(AiUsage.ok.is_(False))) is not None
    script(env, error="Claude API error 500: boom")                      # other errors use the generic notice
    r = env.post(f"/ai/issues/{iid}/template-draft", data={"csrf": get_csrf(env, f"/issues/{iid}")})
    assert r.status_code == 400 and "boom" in r.text and "declined this request" not in r.text
