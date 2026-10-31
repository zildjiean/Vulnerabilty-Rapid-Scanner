# Issue verification (Play) and Proof panel — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A *Verify now* (Play) button re-runs the nuclei template of an issue against its asset, records the result, and a Proof card shows the HTTP request/response nuclei captured; issues without a template get a pick-or-AI-draft path with English refusal guidance.

**Architecture:** New module `app/proof.py` owns proof extraction (`proof_from_finding`), the verify job lifecycle (`start_verify`, `complete_verify`, `cleanup_dead_verify_jobs`) and reuses `launch_nuclei` + the `on_nuclei_complete` hook exactly like `app/reverify.py`. Routes live in `app/routers/issues.py` (verify, link template, save-and-run) and `app/routers/ai_features.py` (AI draft for an issue). `app/llm.py` gains `LLMRefusal` so the UI can tell a refusal from other errors.

**Tech Stack:** FastAPI, SQLAlchemy 2 (SQLite), Jinja2, vanilla JS, pytest. Run tests with `.venv/bin/python -m pytest -q <file>`; the whole suite takes ~4 min, run single files while working.

**Spec:** `docs/superpowers/specs/2026-10-31-issue-verify-proof-design.md`

**Branch:** `git checkout -b feature/issue-verify-proof` from `master` before Task 1. Commit messages end with
`Co-Authored-By: Claude Mythos 5.1 <noreply@anthropic.com>`.

---

## File map

| File | Responsibility |
|---|---|
| `app/proof.py` (new) | `proof_from_finding`, `VerifyError`, `live_verify_job`, `start_verify`, `complete_verify`, `cleanup_dead_verify_jobs`, `VERIFY_LABELS` |
| `app/db.py` | 3 new `Issue` columns + `_ADDED_COLUMNS` rows |
| `app/reverify.py` | `_target` renamed to `issue_target` (public); dead-verify cleanup called from its tick |
| `app/scanners/nuclei_runner.py` | call `complete_verify` after ingest when `params.verify_issue` |
| `app/llm.py` | `LLMRefusal`, `_REFUSAL_RE`, `_parse_or_refusal` |
| `app/ai_features.py` | `_service`, `issue_context(evidence=)`, `issue_template_prompt`, one more sentence in `TEMPLATE_RULES` |
| `app/routers/issues.py` | `_detail(**extra)`, `/issues/{id}/verify`, `/issues/{id}/template`, `/issues/{id}/template/save-run` |
| `app/routers/ai_features.py` | `draft_from_result` helper (shared), `/ai/issues/{id}/template-draft` |
| `app/templates/issue_detail.html` | Play button, verify chips, Proof card, Verification template card, timeline kind |
| `app/templates/_issue_macros.html` | `play_button` macro |
| `app/templates/issues.html`, `campaign_detail.html` | Play column |
| `app/static/app.css`, `app/static/app.js` | `.play-btn`, `.status.verify-*`, proof details, template search |
| `tests/test_proof.py` (new), `tests/test_issue_verify.py` (new), `tests/test_llm.py`, `tests/test_ai_features.py`, `tests/test_ai_admin.py` | tests |
| `README.md`, `CHANGELOG.md`, `docs/USER_GUIDE.th.md` | docs |

---

### Task 1: Issue columns and `proof_from_finding`

**Files:**
- Modify: `app/db.py` (Issue class ~line 200, `_ADDED_COLUMNS` ~line 440)
- Create: `app/proof.py`
- Test: `tests/test_proof.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_proof.py
import json

from app.db import Finding
from app.proof import PROOF_LIMIT, proof_from_finding


def finding(raw: dict, **cols) -> Finding:
    base = dict(id=7, job_id=3, template_id="CVE-2026-109619", template_name="PHP UAF", severity="critical",
                host="http://192.0.2.11:8080", matched_at="http://192.0.2.11:8080/index.php", type="http")
    base.update(cols)
    return Finding(raw_json=json.dumps(raw), **base)


def test_http_finding_has_request_response_curl_and_matcher():
    raw = {"request": "GET /index.php HTTP/1.1\r\nHost: x\r\n\r\n", "response": "HTTP/1.1 200 OK\r\n\r\nX-Powered-By: PHP/8.3.10",
           "curl-command": "curl -X GET http://192.0.2.11:8080/index.php", "matcher-name": "version", "matcher-status": True,
           "extracted-results": ["8.3.10"], "timestamp": "2026-10-31T09:00:00Z"}
    p = proof_from_finding(finding(raw))
    assert p["has_http"] is True
    assert p["request"]["text"].startswith("GET /index.php") and p["request"]["rest"] == ""
    assert "PHP/8.3.10" in p["response"]["text"]
    assert p["curl"].startswith("curl ") and p["matcher"] == "version" and p["extracted"] == ["8.3.10"]
    assert p["finding_id"] == 7 and p["job_id"] == 3 and p["timestamp"] == "2026-10-31T09:00:00Z"


def test_non_http_finding_only_has_metadata():
    p = proof_from_finding(finding({"matcher-status": True}, type="tcp", matched_at="203.0.113.40:6379"))
    assert p["has_http"] is False and p["request"] is None and p["response"] is None and p["curl"] == ""
    assert p["matched_at"] == "203.0.113.40:6379" and p["type"] == "tcp"


def test_long_response_is_split_at_the_limit_and_bad_json_is_tolerated():
    p = proof_from_finding(finding({"response": "A" * (PROOF_LIMIT + 10)}))
    assert len(p["response"]["text"]) == PROOF_LIMIT and p["response"]["rest"] == "A" * 10
    assert proof_from_finding(Finding(id=1, job_id=1, raw_json="{not json"))["has_http"] is False
    assert proof_from_finding(None) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_proof.py`
Expected: `ModuleNotFoundError: No module named 'app.proof'`

- [ ] **Step 3: Add the columns**

In `app/db.py`, inside `class Issue`, directly after the `reverify_job_id` line:

```python
    verify_job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)       # one-click "Verify now" scan
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    verify_result: Mapped[str] = mapped_column(String(16), default="")              # "" | reproduced | not_reproduced | inconclusive
```

Append to `_ADDED_COLUMNS`:

```python
    ("issues", "verify_job_id", "INTEGER"),
    ("issues", "last_verified_at", "DATETIME"),
    ("issues", "verify_result", "VARCHAR(16) NOT NULL DEFAULT ''"),
```

- [ ] **Step 4: Create `app/proof.py` with the extraction half**

```python
"""Proof of a finding (the request/response nuclei recorded) and one-click verification of an issue."""
from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Finding, Issue, IssueEvent, Job, TemplateIndex, utcnow

PROOF_LIMIT = 4000   # characters shown before "Show full"
VERIFY_LABELS = {"reproduced": "reproduced", "not_reproduced": "not reproduced", "inconclusive": "inconclusive"}


def _part(value) -> dict | None:
    text = str(value or "")
    return {"text": text[:PROOF_LIMIT], "rest": text[PROOF_LIMIT:]} if text else None


def proof_from_finding(finding: Finding | None) -> dict | None:
    """What nuclei recorded for one finding. nuclei v3 puts request/response/curl-command in its JSONL by default."""
    if finding is None:
        return None
    try:
        raw = json.loads(finding.raw_json or "{}")
    except json.JSONDecodeError:
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    extracted = raw.get("extracted-results") or []
    if isinstance(extracted, str):
        extracted = [extracted]
    proof = {
        "finding_id": finding.id, "job_id": finding.job_id, "template_id": finding.template_id or "",
        "matched_at": finding.matched_at or "", "type": finding.type or "", "timestamp": str(raw.get("timestamp") or ""),
        "request": _part(raw.get("request")), "response": _part(raw.get("response")),
        "curl": str(raw.get("curl-command") or ""), "matcher": str(raw.get("matcher-name") or ""),
        "matcher_status": bool(raw.get("matcher-status", True)), "extracted": [str(x) for x in extracted],
    }
    proof["has_http"] = bool(proof["request"] or proof["response"])
    return proof
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest -q tests/test_proof.py`
Expected: `3 passed`

- [ ] **Step 6: Commit**

```bash
git add app/db.py app/proof.py tests/test_proof.py
git commit -m "feat(proof): issue verify columns and proof extraction from nuclei findings

Co-Authored-By: Claude Mythos 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Verify job lifecycle (`start_verify`, `complete_verify`, dead-job cleanup)

**Files:**
- Modify: `app/proof.py`
- Modify: `app/reverify.py` (`_target` → `issue_target`, cleanup call)
- Modify: `app/scanners/nuclei_runner.py:215-219`
- Test: `tests/test_proof.py`

- [ ] **Step 1: Write the failing tests** (append to `tests/test_proof.py`)

```python
import pytest
from sqlalchemy import select

from app import proof
from app.db import Issue, IssueEvent, Job, Rule
from app.rules import evaluate_rules
from app.templates_index import reindex
from tests.conftest import wait_job
from tests.test_inventory import seed_inventory
from tests.test_issue_routes import seed

CVE = "CVE-2026-109619"   # fixture template; the fake nuclei reports it on http://192.168.1.10:8080
SPECS = [(CVE, "critical", "192.168.1.10", "8080", CVE), ("exposed-panel", "medium", "10.0.0.6", "8080", None)]


@pytest.fixture
def env(auth):
    seed_inventory(auth)
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
        db.commit()
    return auth


def get(client, iid):
    with client.app.state.SessionLocal() as db:
        i = db.get(Issue, iid)
        db.expunge(i)
        return i


def events(client, iid):
    with client.app.state.SessionLocal() as db:
        return [(e.kind, e.body) for e in db.scalars(select(IssueEvent).where(IssueEvent.issue_id == iid).order_by(IssueEvent.id))]


def start(client, iid):
    def _go():
        with client.app.state.SessionLocal() as db:
            return proof.start_verify(db, client.app, db.get(Issue, iid), actor=None).id
    return client.portal.call(_go)


def test_start_verify_runs_the_template_against_the_asset_and_reproduces(env):
    ids = seed(env, SPECS)
    iid = ids[CVE]
    jid = start(env, iid)
    with env.app.state.SessionLocal() as db:
        job = db.get(Job, jid)
        params = json.loads(job.params_json)
        assert params["verify_issue"] == iid and params["targets"] == ["http://192.168.1.10:8080"]
        assert params["template_ids"] == [CVE] and CVE + ".yaml" in job.command
    assert any(kind == "verify" and "started" in body for kind, body in events(env, iid))
    wait_job(env, jid)   # the fake nuclei finishes fast, so verify_job_id is only checked after completion
    i = get(env, iid)
    assert i.verify_result == "reproduced" and i.verify_job_id is None and i.last_verified_at is not None
    assert i.confidence == "confirmed"
    assert any(kind == "verify" and "reproduced it" in body for kind, body in events(env, iid))


def test_complete_verify_not_reproduced_and_inconclusive(env):
    ids = seed(env, SPECS)
    iid = ids[CVE]
    with env.app.state.SessionLocal() as db:
        job = Job(kind="nuclei", status="done", params_json=json.dumps({"verify_issue": iid}))
        db.add(job)
        db.flush()
        db.get(Issue, iid).verify_job_id = job.id
        assert proof.complete_verify(db, job, []) == "not_reproduced"
        db.commit()
    assert get(env, iid).verify_result == "not_reproduced"
    assert any("did not reproduce" in body for kind, body in events(env, iid) if kind == "verify")
    with env.app.state.SessionLocal() as db:
        job = Job(kind="nuclei", status="done", params_json=json.dumps({"verify_issue": iid}))
        db.add(job)
        db.flush()
        db.get(Issue, iid).verify_job_id = job.id
        assert proof.complete_verify(db, job, ["Target was dropped as unresponsive"]) == "inconclusive"
        db.commit()
    assert get(env, iid).verify_result == "inconclusive"
    with env.app.state.SessionLocal() as db:   # a stale job (not the one on the issue) is ignored
        job = Job(kind="nuclei", status="done", params_json=json.dumps({"verify_issue": iid}))
        db.add(job)
        db.flush()
        assert proof.complete_verify(db, job, []) == ""


def test_start_verify_errors(env):
    ids = seed(env, SPECS)
    with env.app.state.SessionLocal() as db:
        with pytest.raises(proof.VerifyError, match="not in the template index"):
            proof.start_verify(db, env.app, db.get(Issue, ids["exposed-panel"]), actor=None)
        db.add(Rule(name="PHP", product_pattern="php", version_constraint="< 8.3.15", cve_id="CVE-2026-1", severity="high"))
        db.commit()
        evaluate_rules(db)
        db.commit()
        suspected = db.scalar(select(Issue).where(Issue.vuln_id == "CVE-2026-1"))
        assert suspected.template_id == ""
        with pytest.raises(proof.VerifyError, match="no nuclei template"):
            proof.start_verify(db, env.app, suspected, actor=None)


def test_dead_verify_job_is_cleaned_up(env):
    ids = seed(env, SPECS)
    iid = ids[CVE]
    with env.app.state.SessionLocal() as db:
        job = Job(kind="nuclei", status="failed", params_json=json.dumps({"verify_issue": iid}))
        db.add(job)
        db.flush()
        db.get(Issue, iid).verify_job_id = job.id
        db.commit()
        assert proof.cleanup_dead_verify_jobs(db) == 1
        db.commit()
    i = get(env, iid)
    assert i.verify_job_id is None and i.verify_result == ""
    assert any("failed" in body for kind, body in events(env, iid) if kind == "verify")
```

Also add `import json` at the top of the file if the first block did not (it did).

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_proof.py`
Expected: 4 failures with `AttributeError: module 'app.proof' has no attribute 'start_verify'` (and similar).

- [ ] **Step 3: Make `issue_target` public in `app/reverify.py`**

Rename the helper and its two call sites:

```bash
sed -i '' 's/^def _target(db: Session, issue: Issue) -> str:/def issue_target(db: Session, issue: Issue) -> str:/; s/t = _target(db, issue)/t = issue_target(db, issue)/' app/reverify.py
grep -n "_target\|issue_target" app/reverify.py
```
Expected: only `def issue_target` and `t = issue_target(db, issue)` remain.

Add the docstring line under `def issue_target`:
```python
    """Scan target for an issue: scheme://address:port from the inventory service, or the bare asset."""
```

In `run_reverify`, directly after `_cleanup_dead_jobs(db)` add:
```python
        from .proof import cleanup_dead_verify_jobs
        cleanup_dead_verify_jobs(db)
```

- [ ] **Step 4: Add the lifecycle to `app/proof.py`** (append)

```python
class VerifyError(ValueError):
    """The verification scan cannot be started; the message is shown to the user."""


def _event(db: Session, issue: Issue, body: str, actor=None) -> None:
    db.add(IssueEvent(issue_id=issue.id, kind="verify", user_id=getattr(actor, "id", None),
                      username=getattr(actor, "username", None) or "system", body=body))


def live_verify_job(db: Session, issue: Issue) -> Job | None:
    job = db.get(Job, issue.verify_job_id) if issue.verify_job_id else None
    return job if job is not None and job.status in ("queued", "running") else None


def start_verify(db: Session, app, issue: Issue, actor) -> Job:
    """Re-run the issue's template against its asset only. Must run inside the event loop (async route or portal)."""
    from .reverify import issue_target
    from .routers.nuclei import launch_nuclei
    from .scanners.nuclei_runner import PROFILES
    if not issue.template_id:
        raise VerifyError("This issue has no nuclei template yet. Link one or draft it with the AI first.")
    path = db.scalar(select(TemplateIndex.path).where(TemplateIndex.template_id == issue.template_id).limit(1))
    if path is None:
        raise VerifyError(f"Template {issue.template_id} is not in the template index. Reindex templates or pick another template.")
    target = issue_target(db, issue)
    prof = PROFILES["normal"]
    params = {"targets": [target], "template_ids": [issue.template_id], "mode": "selected", "profile": "normal",
              "verify_issue": issue.id}
    job = launch_nuclei(db, app.state.settings, app.state.job_runner, [target], [path], params,
                        rate_limit=prof["rate_limit"], timeout=prof["timeout"], extra_flags=[])
    issue.verify_job_id = job.id
    _event(db, issue, f"Verification scan started: job #{job.id} against {target}.", actor)
    db.commit()
    return job


def complete_verify(db: Session, job: Job, warnings: list[str]) -> str:
    """Called after a nuclei job's findings were ingested. Returns the verify_result written, or "" when not ours."""
    try:
        iid = json.loads(job.params_json or "{}").get("verify_issue")
    except json.JSONDecodeError:
        return ""
    issue = db.get(Issue, iid) if iid else None
    if issue is None or issue.verify_job_id != job.id:
        return ""
    finding = db.scalar(select(Finding).where(Finding.job_id == job.id, Finding.issue_id == issue.id)
                        .order_by(Finding.id.desc()).limit(1))
    if finding is not None:   # the ingest already set confidence=confirmed, bumped last_seen and reopened if needed
        result = "reproduced"
        p = proof_from_finding(finding)
        detail = f" (matcher {p['matcher']})" if p and p["matcher"] else ""
        body = f"Verified: job #{job.id} reproduced it{detail}. Proof captured."
    elif warnings:
        result = "inconclusive"
        body = f"Verification inconclusive: job #{job.id} had incomplete coverage ({warnings[0]})."
    else:
        result = "not_reproduced"
        body = f"Verification: job #{job.id} did not reproduce it. Decide whether it is fixed or a false positive."
    issue.verify_result, issue.last_verified_at, issue.verify_job_id = result, utcnow(), None
    _event(db, issue, body)
    db.flush()
    return result


def cleanup_dead_verify_jobs(db: Session) -> int:
    """Clear verify_job_id for jobs that failed, were cancelled or vanished (the completion hook never ran)."""
    n = 0
    for issue in db.scalars(select(Issue).where(Issue.verify_job_id.is_not(None))):
        job = db.get(Job, issue.verify_job_id)
        if job is None or job.status in ("failed", "cancelled"):
            status = job.status if job is not None else "missing"
            _event(db, issue, f"Verification job #{issue.verify_job_id} {status}; try again.")
            issue.verify_job_id = None
            n += 1
    db.flush()
    return n
```

- [ ] **Step 5: Call the hook from `app/scanners/nuclei_runner.py`**

Replace the `if params.get("reverify"):` block (lines ~215-219) with:

```python
    if params.get("reverify"):
        from ..reverify import complete_reverify
        verified = complete_reverify(db, job, warnings)
        params["result"]["verified"] = verified
        job.params_json = json.dumps(params)
    if params.get("verify_issue"):
        from ..proof import complete_verify
        params["result"]["verify"] = complete_verify(db, job, warnings)
        job.params_json = json.dumps(params)
```

- [ ] **Step 6: Run tests**

Run: `.venv/bin/python -m pytest -q tests/test_proof.py tests/test_reverify.py`
Expected: all pass (7 in test_proof, re-verify unchanged).

- [ ] **Step 7: Commit**

```bash
git add app/proof.py app/reverify.py app/scanners/nuclei_runner.py tests/test_proof.py
git commit -m "feat(proof): start/complete one-click verification scans and clean up dead jobs

Co-Authored-By: Claude Mythos 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Verify route, Play button and verify chips on the issue page

**Files:**
- Modify: `app/routers/issues.py`
- Modify: `app/templates/issue_detail.html`
- Modify: `app/static/app.css`
- Test: `tests/test_issue_verify.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_issue_verify.py
import json

import pytest
from sqlalchemy import select

from app.db import AuditLog, Issue, Job, Rule
from app.rules import evaluate_rules
from app.templates_index import reindex
from tests.conftest import get_csrf, wait_job
from tests.test_inventory import seed_inventory
from tests.test_issue_routes import seed
from tests.test_rbac import login_as, make_user

CVE = "CVE-2026-109619"
SPECS = [(CVE, "critical", "192.168.1.10", "8080", CVE), ("exposed-panel", "medium", "10.0.0.6", "8080", None)]


@pytest.fixture
def env(auth):
    seed_inventory(auth)
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
        db.commit()
    return auth


def suspected_issue(client, cve="CVE-2026-1"):
    with client.app.state.SessionLocal() as db:
        db.add(Rule(name="PHP", product_pattern="php", version_constraint="< 8.3.15", cve_id=cve, severity="high"))
        db.commit()
        evaluate_rules(db)
        db.commit()
        return db.scalar(select(Issue.id).where(Issue.vuln_id == cve))


def test_verify_button_starts_a_job_and_blocks_a_second_click(env, monkeypatch):
    iid = seed(env, SPECS)[CVE]
    started = []   # keep the job queued so the "running" state is deterministic (the fake nuclei finishes instantly)
    monkeypatch.setattr(env.app.state.job_runner, "start", lambda job_id, argv, **kw: started.append(job_id))
    page = env.get(f"/issues/{iid}").text
    assert "Verify now" in page and f'action="/issues/{iid}/verify"' in page
    r = env.post(f"/issues/{iid}/verify", data={"csrf": get_csrf(env, f"/issues/{iid}")}, follow_redirects=False)
    assert r.status_code == 303 and "Verification+started" in r.headers["location"]
    with env.app.state.SessionLocal() as db:
        issue = db.get(Issue, iid)
        assert issue.verify_job_id == started[0]
        assert json.loads(db.get(Job, started[0]).params_json)["verify_issue"] == iid
        assert db.scalar(select(AuditLog).where(AuditLog.action == "issue.verify")) is not None
    page = env.get(f"/issues/{iid}").text
    assert f"verifying (job #{started[0]})" in page and "Verify now" not in page
    r = env.post(f"/issues/{iid}/verify", data={"csrf": get_csrf(env, f"/issues/{iid}")}, follow_redirects=False)
    assert "already+running" in r.headers["location"] and len(started) == 1


def test_completed_verification_shows_result_and_timeline(env):
    iid = seed(env, SPECS)[CVE]
    r = env.post(f"/issues/{iid}/verify", data={"csrf": get_csrf(env, f"/issues/{iid}")}, follow_redirects=False)
    assert r.status_code == 303
    with env.app.state.SessionLocal() as db:
        jid = db.scalar(select(Job.id).order_by(Job.id.desc()))
    wait_job(env, jid)
    page = env.get(f"/issues/{iid}").text
    assert "reproduced" in page and "Verify now" in page and "Proof captured" in page


def test_verify_with_back_redirects_to_the_list_and_errors_go_to_err(env):
    ids = seed(env, SPECS)
    r = env.post(f"/issues/{ids[CVE]}/verify", data={"csrf": get_csrf(env, "/issues"), "back": "/issues?view=active"},
                 follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/issues?view=active&msg=")
    r = env.post(f"/issues/{ids['exposed-panel']}/verify", data={"csrf": get_csrf(env, "/issues"), "back": "/issues"},
                 follow_redirects=False)
    assert "err=" in r.headers["location"] and "template+index" in r.headers["location"]
    r = env.post(f"/issues/{ids['exposed-panel']}/verify", data={"csrf": get_csrf(env, "/issues")})
    assert r.status_code == 400 and "not in the template index" in r.text
    # an external back URL is ignored
    r = env.post(f"/issues/{ids[CVE]}/verify", data={"csrf": get_csrf(env, "/issues"), "back": "//evil.example/x"},
                 follow_redirects=False)
    assert r.headers["location"].startswith(f"/issues/{ids[CVE]}?")


def test_issue_without_template_is_sent_to_the_verify_card(env):
    iid = suspected_issue(env)
    r = env.post(f"/issues/{iid}/verify", data={"csrf": get_csrf(env, f"/issues/{iid}")}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == f"/issues/{iid}#verify"


def test_viewer_sees_no_button_and_cannot_verify(env):
    iid = seed(env, SPECS)[CVE]
    make_user(env, "vera", "viewer")
    login_as(env, "vera")
    assert "Verify now" not in env.get(f"/issues/{iid}").text
    r = env.post(f"/issues/{iid}/verify", data={"csrf": get_csrf(env, f"/issues/{iid}")})
    assert r.status_code == 403
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_issue_verify.py`
Expected: 5 failures (`Verify now` missing / 404 on the route).

- [ ] **Step 3: Add the route and helpers to `app/routers/issues.py`**

Imports: add `from urllib.parse import urlencode` after `from datetime import timedelta`; add `from .. import proof` after `from .. import issues as iss`; add `from ..deps import get_db, get_settings, verify_csrf` (replace the existing deps import).

Change `_detail` to accept extra context and expose verify labels — replace its signature and the `render(` call head:

```python
def _detail(request: Request, db: Session, issue: Issue, status_code: int = 200, error: str | None = None, **extra):
    findings = list(db.scalars(select(Finding).where(Finding.issue_id == issue.id).order_by(Finding.id.desc()).limit(50)))
    rule = db.get(Rule, issue.rule_id) if issue.rule_id else None
    return render(request, "issue_detail.html", status_code=status_code, active="issues", issue=issue, error=error,
                  findings=findings, rule=rule, users=assignable_users(db), verify_labels=proof.VERIFY_LABELS,
```
(keep the rest of the existing keyword arguments) and end the call with `..., **extra)`.

Add after `_actor`:

```python
def _redirect(url: str, **q) -> RedirectResponse:
    sep = "&" if "?" in url else "?"
    return RedirectResponse(url + (sep + urlencode(q) if q else ""), status_code=303)


def _safe_back(back: str, issue: Issue) -> str:
    """Only same-site paths are honoured; anything else returns to the issue page."""
    return back if back.startswith("/") and not back.startswith("//") else f"/issues/{issue.id}"


def _verify(request: Request, db: Session, issue: Issue, back: str):
    """Shared by the Play button and by 'Save & run as proof'. Must be called from an async route."""
    url = _safe_back(back, issue)
    live = proof.live_verify_job(db, issue)
    if live is not None:
        return _redirect(url, msg=f"Verification already running (job #{live.id}).")
    if not issue.template_id:
        return RedirectResponse(f"/issues/{issue.id}#verify", status_code=303)
    try:
        job = proof.start_verify(db, request.app, issue, _actor(request, db))
    except proof.VerifyError as e:
        if back:
            return _redirect(url, err=str(e))
        return _detail(request, db, issue, status_code=400, error=str(e))
    audit(db, request, "issue.verify", target=_label(issue), job_id=job.id, template_id=issue.template_id)
    db.commit()
    return _redirect(url, msg=f"Verification started for {issue.asset} (job #{job.id}).")


@router.post("/issues/{issue_id}/verify", dependencies=[Depends(require("scan.run")), Depends(verify_csrf)])
async def issue_verify(request: Request, issue_id: int, back: str = Form(""), db: Session = Depends(get_db)):
    return _verify(request, db, _get(db, issue_id), back)
```

- [ ] **Step 4: Issue page — header button, chips, timeline kind**

In `app/templates/issue_detail.html` replace the `page_actions` block (line 8) with:

```jinja
{% block page_actions %}{% if can('scan.run') and issue.template_id and not issue.verify_job_id %}<form method="post" action="/issues/{{ issue.id }}/verify" data-loading><input type="hidden" name="csrf" value="{{ csrf }}"><button type="submit" class="btn primary" title="Re-run {{ issue.template_id }} against {{ issue.asset }} and keep the proof"><svg class="icon"><use href="#i-play"/></svg>Verify now</button></form>{% endif %}<a class="btn ghost" href="/issues">Back to issues</a>{% endblock %}
```

In the header card, after the re-verify chips (`{% elif issue.status == 'fixed' and issue.reverify_requested_at %}...{% endif %}`) add:

```jinja
  {% if issue.verify_job_id %}<span class="status st-running" title="Verification scan"><a href="/jobs/{{ issue.verify_job_id }}">verifying (job #{{ issue.verify_job_id }})</a></span>
  {% elif issue.verify_result %}<span class="status verify-{{ issue.verify_result }}" title="Last verified {{ issue.last_verified_at.strftime('%Y-%m-%d %H:%M') if issue.last_verified_at else '' }} UTC"><svg class="icon sm"><use href="#i-play"/></svg>{{ verify_labels.get(issue.verify_result, issue.verify_result) }}</span>{% endif %}
```

Timeline: change `{% elif e.kind in ('ticket', 'reverify') %}` to `{% elif e.kind in ('ticket', 'reverify', 'verify') %}`.

- [ ] **Step 5: CSS** (append to `app/static/app.css` after the `.status.is-false_positive` line)

```css
.status.verify-reproduced{background:var(--success-soft);color:var(--success)}
.status.verify-not_reproduced{background:var(--surface-2);color:var(--text-2)}
.status.verify-inconclusive{background:var(--warning-soft);color:var(--warning)}
.status .icon.sm{width:12px;height:12px;margin-right:4px}
.timeline li.ev-verify::before{border-color:var(--primary)}
```

- [ ] **Step 6: Run tests**

Run: `.venv/bin/python -m pytest -q tests/test_issue_verify.py tests/test_issue_routes.py`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add app/routers/issues.py app/templates/issue_detail.html app/static/app.css tests/test_issue_verify.py
git commit -m "feat(issues): Verify now button re-runs the template against the asset

Co-Authored-By: Claude Mythos 5.1 <noreply@anthropic.com>"
```

---

### Task 4: Proof card on the issue page

**Files:**
- Modify: `app/routers/issues.py` (`_detail`)
- Modify: `app/templates/issue_detail.html` (Proof card + Evidence proof links)
- Modify: `app/static/app.css`, `app/static/app.js`
- Test: `tests/test_issue_verify.py`

- [ ] **Step 1: Write the failing test** (append)

```python
def test_proof_card_shows_request_response_and_curl(env):
    iid = seed(env, SPECS)[CVE]
    long_body = "B" * 4100
    with env.app.state.SessionLocal() as db:
        from app.db import Finding
        f = db.scalar(select(Finding).where(Finding.issue_id == iid))
        raw = json.loads(f.raw_json)
        raw.update({"request": "GET /index.php HTTP/1.1\r\nHost: 192.168.1.10", "response": "HTTP/1.1 200 OK\r\n\r\n" + long_body,
                    "curl-command": "curl -X GET http://192.168.1.10:8080/index.php", "matcher-name": "php-version"})
        f.raw_json = json.dumps(raw)
        db.commit()
        first_id = f.id
    page = env.get(f"/issues/{iid}").text
    assert 'id="proof"' in page and "GET /index.php HTTP/1.1" in page and "php-version" in page
    assert 'data-copy="curl -X GET http://192.168.1.10:8080/index.php"' in page
    assert "data-proof-more" in page and 'class="proof-rest" hidden' in page        # 4,100 chars → split
    assert f"?proof={first_id}#proof" in page                                       # evidence row link
    # a second (non-HTTP) finding becomes the newest proof; ?proof= selects the old one
    seed(env, [("CVE-2026-109619", "critical", "192.168.1.10", "8080", CVE)])
    page = env.get(f"/issues/{iid}").text
    assert "did not record a request/response" in page
    assert "GET /index.php HTTP/1.1" in env.get(f"/issues/{iid}?proof={first_id}").text
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest -q tests/test_issue_verify.py::test_proof_card_shows_request_response_and_curl`
Expected: FAIL (`id="proof"` not in page).

- [ ] **Step 3: Select the proof finding in `_detail`**

In `_detail`, after `findings = ...` add:

```python
    wanted = request.query_params.get("proof", "")
    selected = next((f for f in findings if wanted.isdigit() and f.id == int(wanted)), findings[0] if findings else None)
```
and pass `proof=proof.proof_from_finding(selected)` to `render(...)`.

- [ ] **Step 4: Template**

Evidence table: change the header to `<thead><tr><th>Severity</th><th>Matched at</th><th>Job</th><th>Time</th><th>Proof</th></tr></thead>`, add `<td><a href="/issues/{{ issue.id }}?proof={{ fd.id }}#proof">proof</a></td>` as the last cell of the row, and `colspan="5"` on the empty row.

Directly after the Evidence card's closing `</div>` (before `<div class="card" id="timeline">`) insert:

```jinja
    {% if proof %}
    <div class="card" id="proof">
      <div class="card-head"><h2><svg class="icon"><use href="#i-play"/></svg>Proof <span class="small text-2 cell-mono">{{ proof.template_id }} · <a href="/jobs/{{ proof.job_id }}">job #{{ proof.job_id }}</a>{% if proof.timestamp %} · {{ proof.timestamp[:19]|replace('T', ' ') }} UTC{% endif %}</span></h2>
        {% if proof.curl %}<button type="button" class="sm ghost" data-copy="{{ proof.curl }}"><svg class="icon sm"><use href="#i-copy"/></svg>Copy curl</button>{% endif %}</div>
      <div class="card-body stack">
        <dl class="kv">
          <dt>Matched at</dt><dd class="cell-mono">{{ proof.matched_at }}</dd>
          {% if proof.matcher %}<dt>Matcher</dt><dd class="cell-mono">{{ proof.matcher }}</dd>{% endif %}
          {% if proof.extracted %}<dt>Extracted</dt><dd class="cell-mono">{{ proof.extracted|join(', ') }}</dd>{% endif %}
        </dl>
        {% if proof.has_http %}
        {% for label, part in [('Request', proof.request), ('Response', proof.response)] if part %}
        <details class="proof"{{ ' open' if label == 'Request' }}>
          <summary>{{ label }} <span class="small text-2">({{ (part.text|length) + (part.rest|length) }} chars)</span></summary>
          <pre class="code proof-text">{{ part.text }}<span class="proof-rest" hidden>{{ part.rest }}</span></pre>
          {% if part.rest %}<button type="button" class="sm ghost" data-proof-more>Show full {{ label|lower }}</button>{% endif %}
        </details>
        {% endfor %}
        {% else %}<p class="small text-2">nuclei did not record a request/response for this template type ({{ proof.type or 'unknown' }}); the matched location above is the evidence.</p>{% endif %}
      </div>
    </div>
    {% endif %}
```

- [ ] **Step 5: CSS and JS**

`app/static/app.css` (append after `pre.code`):
```css
details.proof summary{cursor:pointer;font-weight:500;padding:6px 0}
details.proof pre.proof-text{max-height:50vh;overflow:auto;margin-top:6px}
details.proof [data-proof-more]{margin-top:8px}
```

`app/static/app.js`: after the `// ---------- Copy to clipboard` block add:
```js
  // ---------- Proof: reveal the part cut at PROOF_LIMIT ----------
  $$("[data-proof-more]").forEach((b) => b.addEventListener("click", () => {
    const rest = b.parentElement.querySelector(".proof-rest");
    if (rest) rest.hidden = false;
    b.remove();
  }));
```

- [ ] **Step 6: Run tests**

Run: `.venv/bin/python -m pytest -q tests/test_issue_verify.py tests/test_issue_routes.py`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add app/routers/issues.py app/templates/issue_detail.html app/static/app.css app/static/app.js tests/test_issue_verify.py
git commit -m "feat(issues): Proof card with the request, response and curl nuclei recorded

Co-Authored-By: Claude Mythos 5.1 <noreply@anthropic.com>"
```

---

### Task 5: Play icon in the Issues list and the Campaign exposure table

**Files:**
- Modify: `app/templates/_issue_macros.html`, `app/templates/issues.html`, `app/templates/campaign_detail.html`
- Modify: `app/static/app.css`
- Test: `tests/test_issue_verify.py`

- [ ] **Step 1: Write the failing test** (append)

```python
def test_play_icons_in_list_and_campaign_only_for_scanners(env):
    ids = seed(env, SPECS)
    page = env.get("/issues").text
    assert f'action="/issues/{ids[CVE]}/verify"' in page and 'aria-label="Verify now' in page
    assert 'name="back" value="/issues"' in page
    from app.campaigns import create_campaign
    with env.app.state.SessionLocal() as db:
        c = create_campaign(db, name="PHP UAF", cve_id=CVE, description="", severity="critical", product_pattern="php",
                            version_constraint="< 8.3.15", attach_templates=False, intel=None, created_by="admin")
        db.commit()
        cid = c.id
    page = env.get(f"/campaigns/{cid}").text
    assert "/verify" in page and f'name="back" value="/campaigns/{cid}"' in page
    make_user(env, "vera", "viewer")
    login_as(env, "vera")
    assert "/verify" not in env.get("/issues").text and "/verify" not in env.get(f"/campaigns/{cid}").text
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest -q tests/test_issue_verify.py::test_play_icons_in_list_and_campaign_only_for_scanners`
Expected: FAIL on the first `assert`.

- [ ] **Step 3: Macro** (append to `app/templates/_issue_macros.html`)

```jinja
{% macro play_button(i, csrf, back) -%}
{% if i.verify_job_id %}<a class="status st-running" href="/jobs/{{ i.verify_job_id }}" title="Verification running (job #{{ i.verify_job_id }})">verifying</a>
{% elif i.template_id %}<form method="post" action="/issues/{{ i.id }}/verify" class="play-form" data-loading><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="back" value="{{ back }}"><button type="submit" class="play-btn" aria-label="Verify now: re-run {{ i.template_id }} against {{ i.asset }}" title="Verify now"><svg class="icon"><use href="#i-play"/></svg></button></form>
{% else %}<a class="play-btn muted" href="/issues/{{ i.id }}#verify" aria-label="No template yet: pick or draft a verification template" title="No template yet: pick or draft one"><svg class="icon"><use href="#i-play"/></svg></a>{% endif %}
{%- endmacro %}
```

- [ ] **Step 4: Issues list** (`app/templates/issues.html`)

Change the macro import on line 2 to include `play_button`. Near the top (after `{% set manage = ... %}`) add
`{% set playcol = can('scan.run') %}` and `{% set back = request.url.path ~ ('?' ~ request.url.query if request.url.query else '') %}`.
In `<thead>` append `{% if playcol %}<th><span class="sr-only">Verify</span></th>{% endif %}` after the *Last seen* header.
In the row, after the *Last seen* cell append `{% if playcol %}<td class="num">{{ play_button(i, csrf, back) }}</td>{% endif %}`.
Change the empty row colspan to `{{ (10 if manage else 9) + (1 if playcol else 0) }}`.

(`.sr-only` already exists in `app.css`.)

- [ ] **Step 5: Campaign exposure table** (`app/templates/campaign_detail.html`)

Import `play_button` in the macro import line; add `{% set playcol = can('scan.run') %}` after it.
Header: append `{% if playcol %}<th><span class="sr-only">Verify</span></th>{% endif %}` after `<th>Due</th>`.
Row: append `{% if playcol %}<td class="num">{{ play_button(i, csrf, '/campaigns/' ~ c.id) }}</td>{% endif %}` after the Due cell.
Empty row: `colspan="{{ 7 if playcol else 6 }}"`.

- [ ] **Step 6: CSS** (append)

```css
.play-btn{display:inline-flex;align-items:center;justify-content:center;width:36px;height:36px;min-height:36px;padding:0;border-radius:8px;border:1px solid var(--border-strong);background:var(--surface);color:var(--primary);cursor:pointer}
.play-btn:hover{background:var(--primary-soft);border-color:var(--primary)}
.play-btn.muted{color:var(--text-3)}
.play-form{display:inline-block;margin:0}
```

- [ ] **Step 7: Run tests**

Run: `.venv/bin/python -m pytest -q tests/test_issue_verify.py tests/test_issue_routes.py tests/test_campaigns.py`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add app/templates/_issue_macros.html app/templates/issues.html app/templates/campaign_detail.html app/static/app.css tests/test_issue_verify.py
git commit -m "feat(issues): Play icon per row in the Issues list and campaign exposure table

Co-Authored-By: Claude Mythos 5.1 <noreply@anthropic.com>"
```

---

### Task 6: Link an existing template to a suspected issue (Verification template card, part A)

**Files:**
- Modify: `app/routers/issues.py`
- Modify: `app/templates/issue_detail.html`, `app/static/app.js`
- Test: `tests/test_issue_verify.py`

- [ ] **Step 1: Write the failing test** (append)

```python
def test_link_existing_template_then_play_works(env):
    iid = suspected_issue(env)
    page = env.get(f"/issues/{iid}").text
    assert 'id="verify"' in page and "Use an existing template" in page and "Verify now" not in page
    csrf = get_csrf(env, f"/issues/{iid}")
    r = env.post(f"/issues/{iid}/template", data={"csrf": csrf, "template_id": "does-not-exist"})
    assert r.status_code == 400 and "exists in the template index" in r.text
    r = env.post(f"/issues/{iid}/template", data={"csrf": csrf, "template_id": CVE}, follow_redirects=False)
    assert r.status_code == 303
    with env.app.state.SessionLocal() as db:
        assert db.get(Issue, iid).template_id == CVE
    page = env.get(f"/issues/{iid}").text
    assert "Verify now" in page and 'id="verify"' not in page and f"Linked verification template {CVE}" in page
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest -q tests/test_issue_verify.py::test_link_existing_template_then_play_works`
Expected: FAIL (`id="verify"` missing).

- [ ] **Step 3: Route** (append to `app/routers/issues.py`; add `TemplateIndex` to the `..db` import)

```python
@router.post("/issues/{issue_id}/template", dependencies=[Depends(require("issues.manage")), Depends(verify_csrf)])
def issue_template(request: Request, issue_id: int, template_id: str = Form(""), db: Session = Depends(get_db)):
    issue = _get(db, issue_id)
    tid = template_id.strip()
    row = db.scalar(select(TemplateIndex).where(TemplateIndex.template_id == tid).limit(1)) if tid else None
    if row is None:
        return _detail(request, db, issue, status_code=400, error="Pick a template that exists in the template index.")
    issue.template_id = tid
    iss._event(db, issue, "verify", _actor(request, db), body=f"Linked verification template {tid}.")
    audit(db, request, "issue.template", target=_label(issue), template_id=tid)
    db.commit()
    return _redirect(f"/issues/{issue.id}", msg="Template linked. Press Verify now to run it.")
```

- [ ] **Step 4: Card** — in `issue_detail.html`, at the top of the right-hand `<div class="stack">` (before the AI assistant card) insert:

```jinja
    {% if not issue.template_id and can('scan.run') %}
    <div class="card" id="verify">
      <div class="card-head"><h2><svg class="icon"><use href="#i-play"/></svg>Verification template</h2></div>
      <div class="card-body stack">
        <p class="small text-2">This issue comes from a version rule, so there is no nuclei template to run yet. Pick one from the library{% if ai_ready and can('templates.manage') %} or let the AI draft a detection check{% endif %}; <b>Verify now</b> then re-runs it against {{ issue.asset }} and keeps the proof.</p>
        {% if verify_refusal %}<div class="alert error" role="alert"><svg class="icon"><use href="#i-alert-circle"/></svg><div><b>The configured AI model declined this request</b> ({{ verify_refusal }}). Writing a verification template for your own assets is a legitimate security-testing task, but some models refuse it. Switch the default provider or model under <a href="/ai">System → AI</a> to one that supports authorized security testing, then try again.</div></div>{% endif %}
        {% if verify_draft %}
        <form method="post" action="/issues/{{ issue.id }}/template/save-run" class="stack" data-loading>
          <input type="hidden" name="csrf" value="{{ csrf }}">
          <div class="row center" style="gap:8px">{{ ai_badge() }}<span class="status {{ 'st-done' if verify_draft.ok else 'st-failed' }}">{{ verify_draft.message }}</span></div>
          {% if verify_draft.notes %}<p class="small text-2">{{ verify_draft.notes }}</p>{% endif %}
          <div class="field"><label for="verify-yaml">Review and edit before running{% if verify_draft.provider %} (drafted by {{ verify_draft.provider }} · {{ verify_draft.model }}){% endif %}</label>
            <textarea id="verify-yaml" name="yaml" rows="16" class="code-input" spellcheck="false">{{ verify_draft.yaml }}</textarea></div>
          <div><button type="submit" class="primary"><svg class="icon"><use href="#i-play"/></svg>Save &amp; run as proof</button></div>
        </form>
        {% endif %}
        {% if can('issues.manage') %}
        <form method="post" action="/issues/{{ issue.id }}/template" class="stack" id="verify-search">
          <input type="hidden" name="csrf" value="{{ csrf }}">
          <div class="field"><label for="verify-q">Use an existing template</label><input id="verify-q" type="search" placeholder="Search the template index: CVE id, product, keyword" autocomplete="off"></div>
          <div id="verify-results" class="stack" aria-live="polite"></div>
          <div><button type="submit"><svg class="icon"><use href="#i-link"/></svg>Link template</button></div>
        </form>
        {% endif %}
        {% if ai_ready and can('templates.manage') %}
        <form method="post" action="/ai/issues/{{ issue.id }}/template-draft" data-loading><input type="hidden" name="csrf" value="{{ csrf }}"><button type="submit"><svg class="icon"><use href="#i-spark"/></svg>Draft verification template with AI</button></form>
        {% endif %}
      </div>
    </div>
    {% endif %}
```

(`verify_refusal` and `verify_draft` are filled by Task 8. The app's Jinja environment uses the default `Undefined`,
so they render as empty until then.)

- [ ] **Step 5: JS search** (append inside the IIFE in `app/static/app.js`)

```js
  // ---------- Issue page: search the template index to link a verification template ----------
  const vq = document.getElementById("verify-q"), vres = document.getElementById("verify-results");
  if (vq && vres) {
    const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    let timer;
    const run = async () => {
      const q = vq.value.trim();
      if (q.length < 2) { vres.innerHTML = ""; return; }
      try {
        const rows = await (await fetch("/templates/search?q=" + encodeURIComponent(q))).json();
        vres.innerHTML = rows.length ? "" : '<p class="small text-2">No templates match.</p>';
        rows.slice(0, 20).forEach((row, i) => {
          const l = document.createElement("label");
          l.className = "list-row row center";
          l.style.gap = "8px";
          l.innerHTML = `<input type="radio" name="template_id" value="${esc(row.template_id)}"${i === 0 ? " checked" : ""}>` +
            `<span class="cell-mono small">${esc(row.template_id)}</span><span class="small">${esc(row.name)}</span>` +
            `<span class="badge sev-${esc(row.severity)}">${esc(row.severity)}</span>`;
          vres.appendChild(l);
        });
      } catch (e) { vres.innerHTML = '<p class="small text-2">Search failed; try again.</p>'; }
    };
    vq.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(run, 250); });
  }
```

- [ ] **Step 6: Run tests**

Run: `.venv/bin/python -m pytest -q tests/test_issue_verify.py`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add app/routers/issues.py app/templates/issue_detail.html app/static/app.js tests/test_issue_verify.py
git commit -m "feat(issues): link an indexed template to a suspected issue so it can be verified

Co-Authored-By: Claude Mythos 5.1 <noreply@anthropic.com>"
```

---

### Task 7: `LLMRefusal` for every provider

**Files:**
- Modify: `app/llm.py`
- Test: `tests/test_llm.py`

- [ ] **Step 1: Write the failing tests** (append to `tests/test_llm.py`; `req` and `SCHEMA` already exist there)

```python
def test_refusals_are_typed_for_every_provider(fake_anthropic, fake_openai):
    fake_anthropic(claude_response("", stop="refusal", category="cyber"))
    with pytest.raises(llm.LLMRefusal, match="safety classifier"):
        llm.complete("anthropic", {"model": "claude-opus-5-5"}, {"api_key": "k"}, req())
    fake_openai("", finish="content_filter")
    with pytest.raises(llm.LLMRefusal, match="content filter"):
        llm.complete("openai", {"model": "gpt-5"}, {"api_key": "k"}, req())
    # a refusal written as prose where JSON was required
    fake_openai("I'm sorry, but I can't help with creating exploit templates.")
    with pytest.raises(llm.LLMRefusal, match="can't help"):
        llm.complete("openai_compatible", {"model": "llama3", "base_url": "http://ollama:11434/v1"}, {}, req(SCHEMA))
    fake_anthropic(claude_response("I cannot assist with that request."))
    with pytest.raises(llm.LLMRefusal):
        llm.complete("anthropic", {"model": "claude-opus-5-5"}, {"api_key": "k"}, req(SCHEMA))
    # plain bad JSON stays a generic error, and valid JSON containing "cannot" is not a refusal
    fake_openai("not json at all")
    with pytest.raises(llm.LLMError) as ei:
        llm.complete("openai", {"model": "gpt-5"}, {"api_key": "k"}, req(SCHEMA))
    assert not isinstance(ei.value, llm.LLMRefusal)
    fake_openai('{"verdict": "The server cannot be reached; I cannot confirm."}')
    assert llm.complete("openai", {"model": "gpt-5"}, {"api_key": "k"}, req(SCHEMA)).data["verdict"].startswith("The server")
    assert issubclass(llm.LLMRefusal, llm.LLMError)
```

- [ ] **Step 2: Run to verify it fails**

Run: `.venv/bin/python -m pytest -q tests/test_llm.py -k refusals`
Expected: FAIL with `AttributeError: module 'app.llm' has no attribute 'LLMRefusal'`.

- [ ] **Step 3: Implement in `app/llm.py`**

After `class LLMError`:

```python
class LLMRefusal(LLMError):
    """The model declined: safety classifier, provider content filter, or a refusal written as prose."""


_REFUSAL_RE = re.compile(
    r"\b(I can(?:')?t|I cannot|I(?:'m| am) unable|I won(?:')?t|not able to (?:help|assist|provide|create)|"
    r"against (?:my|our) (?:guidelines|policies)|can(?:')?t help with)\b", re.I)
```

After `_parse_json` add:

```python
def _parse_or_refusal(text: str, r: LLMRequest) -> dict | None:
    """Structured answers must parse; prose that reads like a refusal is reported as one."""
    if r.json_schema is None:
        return None
    try:
        return _parse_json(text)
    except LLMError:
        if _REFUSAL_RE.search(text[:600]):
            raise LLMRefusal(f'the model answered: "{text.strip()[:160]}"') from None
        raise
```

In `_claude`: change the refusal raise to `raise LLMRefusal(...)` (same message) and replace
`data=_parse_json(text) if r.json_schema else None` with `data=_parse_or_refusal(text, r)`.

In `_openai_family`: change `raise LLMError("The provider's content filter blocked the answer.")` to
`raise LLMRefusal("the provider's content filter blocked the answer")` and replace
`data=_parse_json(text) if r.json_schema else None` with `data=_parse_or_refusal(text, r)`.

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest -q tests/test_llm.py`
Expected: all pass (the existing `test_claude_refusal_truncation_and_errors` still matches `LLMError` because `LLMRefusal` subclasses it).

- [ ] **Step 5: Commit**

```bash
git add app/llm.py tests/test_llm.py
git commit -m "feat(llm): LLMRefusal distinguishes declined requests from other provider errors

Co-Authored-By: Claude Mythos 5.1 <noreply@anthropic.com>"
```

---

### Task 8: AI draft for an issue, Save & run as proof, refusal notice

**Files:**
- Modify: `app/ai_features.py`, `app/routers/ai_features.py`, `app/routers/issues.py`
- Modify: `tests/test_ai_admin.py` (FakeLLM accepts an exception)
- Test: `tests/test_ai_features.py`

- [ ] **Step 1: Let `FakeLLM` raise a typed error** — in `tests/test_ai_admin.py` replace the two lines

```python
        if self.error:
            raise llm.LLMError(self.error)
```
with
```python
        if self.error:
            raise self.error if isinstance(self.error, Exception) else llm.LLMError(self.error)
```

- [ ] **Step 2: Write the failing tests** (append to `tests/test_ai_features.py`)

```python
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
    r = env.post(f"/issues/{iid}/template/save-run", data={"csrf": csrf, "yaml": YAML_OK}, follow_redirects=False)
    assert r.status_code == 303 and "Verification+started" in r.headers["location"]
    with env.app.state.SessionLocal() as db:
        issue = db.get(Issue, iid)
        assert issue.template_id == "cve-2026-1-php-detect"
        job = db.scalar(select(Job).order_by(Job.id.desc()))      # the job may already have finished (fake nuclei)
        assert json.loads(job.params_json)["verify_issue"] == iid
        assert db.scalar(select(TemplateIndex).where(TemplateIndex.template_id == "cve-2026-1-php-detect")).source == "custom"
    r = env.post(f"/issues/{iid}/template/save-run", data={"csrf": csrf, "yaml": "not: [valid"})
    assert r.status_code == 400 and "Validation failed" in r.text


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
```

- [ ] **Step 3: Run to verify they fail**

Run: `.venv/bin/python -m pytest -q tests/test_ai_features.py -k "issue_template"`
Expected: 2 failures (404 on `/ai/issues/{id}/template-draft`).

- [ ] **Step 4: Prompt builders in `app/ai_features.py`**

Append one sentence to `TEMPLATE_RULES` (before the final `"""`):
```
- The template verifies a vulnerability on an asset owned by the team that runs this scanner: a detection check
  for authorized internal testing, not an exploit.
```

Extract the service lookup from `issue_context` into a helper and make the evidence optional:

```python
def _service(db: Session, issue: Issue) -> Service | None:
    if not issue.port.isdigit():
        return None
    return db.scalar(select(Service).join(Host, Host.id == Service.host_id)
                     .where(Host.address == issue.address, Service.port == int(issue.port)))


def issue_context(db: Session, issue: Issue, evidence: bool = True) -> str:
```
Inside `issue_context` replace the `svc = None ... svc = db.scalar(...)` lines with `svc = _service(db, issue)` and
make the last line conditional:
```python
    if evidence:
        lines.append("Evidence:\n" + _evidence(db, issue))
    return "\n".join(lines)
```

Add after `template_prompt`:

```python
def issue_template_prompt(db: Session, issue: Issue) -> str:
    """Draft a verification template for one issue: its context without scan evidence, plus the service as a hint."""
    svc = _service(db, issue)
    product = " ".join(x for x in ((svc.product if svc else ""), (svc.version if svc else "")) if x)
    hints = f"{issue.asset} running {product}" if product else issue.asset
    return template_prompt(issue.cve_id or issue.vuln_id, issue_context(db, issue, evidence=False), hints)
```

- [ ] **Step 5: Shared validation helper and the issue route in `app/routers/ai_features.py`**

Add `from ..llm import LLMError, LLMRefusal` (replace the existing import). Add above `template_draft`:

```python
async def draft_from_result(settings, result, provider, cve_id: str = "", advisory: str = "") -> dict:
    """Strip fences, validate the YAML and run nuclei -validate; returns the dict the templates render."""
    from ..templates_index import validate_template_yaml
    from .templates import nuclei_validate
    yaml_text = re.sub(r"^```(?:ya?ml)?\s*|\s*```$", "", (result.data or {}).get("yaml", "").strip())
    draft = {"yaml": yaml_text, "notes": (result.data or {}).get("notes", ""), "provider": provider.name,
             "model": result.model, "cve_id": cve_id, "advisory": advisory}
    try:
        info = validate_template_yaml(yaml_text)
        tmp = settings.data_dir / "ai-drafts"
        tmp.mkdir(parents=True, exist_ok=True)
        path = tmp / f"{info.template_id}.yaml"
        path.write_text(yaml_text)
        ok, line = await nuclei_validate(settings, path)
        path.unlink(missing_ok=True)
        draft.update(ok=ok, message="Validation passed (nuclei -validate)." if ok else f"Validation failed: {line}",
                     template_id=info.template_id)
    except ValueError as e:
        draft.update(ok=False, message=f"Validation failed: {e}")
    return draft
```

Rewrite `template_draft` to use it (behaviour unchanged):

```python
@router.post("/template-draft", dependencies=[Depends(require("templates.manage")), *USE])
async def template_draft(request: Request, cve_id: str = Form(""), advisory: str = Form(""), hints: str = Form(""),
                         db: Session = Depends(get_db), settings=Depends(get_settings)):
    from .templates import _page
    if not cve_id.strip() and not advisory.strip():
        return _page(request, db, settings, error="Describe the vulnerability or give a CVE id for the AI draft.", status_code=400)
    try:
        result, provider = await ai.generate(request, db, "template_draft", af.SYSTEM,
                                             af.template_prompt(cve_id.strip(), advisory, hints), schema=af.TEMPLATE_SCHEMA,
                                             effort="high")
    except LLMError as e:
        return _page(request, db, settings, error=str(e), status_code=400)
    return _page(request, db, settings, draft=await draft_from_result(settings, result, provider, cve_id, advisory))
```

Add the issue route after `issue_triage`:

```python
@router.post("/issues/{iid}/template-draft", dependencies=[Depends(require("templates.manage")), *USE])
async def issue_template_draft(request: Request, iid: int, db: Session = Depends(get_db), settings=Depends(get_settings)):
    from .issues import _detail
    issue = _issue(db, iid)
    try:
        result, provider = await ai.generate(request, db, "template_draft", af.SYSTEM, af.issue_template_prompt(db, issue),
                                             schema=af.TEMPLATE_SCHEMA, effort="high")
    except LLMRefusal as e:
        return _detail(request, db, issue, status_code=400, verify_refusal=str(e).rstrip("."))
    except LLMError as e:
        return _detail(request, db, issue, status_code=400, error=str(e))
    return _detail(request, db, issue, verify_draft=await draft_from_result(settings, result, provider))
```

- [ ] **Step 6: Save & run route in `app/routers/issues.py`**

Add `from ..templates_index import index_single, save_custom_template, validate_template_yaml` to the imports and append:

```python
@router.post("/issues/{issue_id}/template/save-run",
             dependencies=[Depends(require("templates.manage")), Depends(require("scan.run")), Depends(verify_csrf)])
async def issue_template_save_run(request: Request, issue_id: int, yaml: str = Form(""), db: Session = Depends(get_db),
                                  settings=Depends(get_settings)):
    """Save the reviewed draft as a custom template, link it to the issue and start the verification scan."""
    from .templates import nuclei_validate
    issue = _get(db, issue_id)
    try:
        info = validate_template_yaml(yaml)
        tmp = settings.data_dir / "ai-drafts"
        tmp.mkdir(parents=True, exist_ok=True)
        tmp_path = tmp / f"{info.template_id}.yaml"
        tmp_path.write_text(yaml)
        ok, line = await nuclei_validate(settings, tmp_path)
        tmp_path.unlink(missing_ok=True)
        if not ok:
            raise ValueError(line or "nuclei -validate failed")
    except ValueError as e:
        draft = {"yaml": yaml, "ok": False, "message": f"Validation failed: {e}", "notes": "", "provider": "", "model": ""}
        return _detail(request, db, issue, status_code=400, verify_draft=draft)
    path = save_custom_template(settings, yaml)
    index_single(db, path, "custom")
    issue.template_id = info.template_id
    iss._event(db, issue, "verify", _actor(request, db), body=f"Saved verification template {info.template_id} (custom).")
    audit(db, request, "templates.saved", target=info.template_id, issue=issue.id)
    db.commit()
    return _verify(request, db, issue, back="")
```

- [ ] **Step 7: Run tests**

Run: `.venv/bin/python -m pytest -q tests/test_ai_features.py tests/test_issue_verify.py tests/test_llm.py`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
git add app/ai_features.py app/routers/ai_features.py app/routers/issues.py tests/test_ai_admin.py tests/test_ai_features.py
git commit -m "feat(ai): draft a verification template for an issue, save & run it; English refusal guidance

Co-Authored-By: Claude Mythos 5.1 <noreply@anthropic.com>"
```

---

### Task 9: Documentation

**Files:**
- Modify: `README.md`, `CHANGELOG.md`, `docs/USER_GUIDE.th.md`

- [ ] **Step 1: CHANGELOG** — under `## [Unreleased]` → `### Added`, first bullets:

```markdown
- **Verify now (Play)** on every issue: re-runs the issue's nuclei template against that asset only, records
  *reproduced / not reproduced / inconclusive* on the issue timeline and marks it confirmed when reproduced.
  Available on the issue page, as a Play icon in the Issues list and in a campaign's exposure table.
- **Proof** card on the issue page: the HTTP request and response nuclei matched on, the matcher, extracted values
  and a copyable curl command, for every finding (nuclei records them by default).
- Suspected issues without a template can link an indexed template or ask the AI to draft a verification template,
  review it and *Save & run as proof*. When the model declines, the page explains in English how to switch the
  provider/model under System → AI.
```

- [ ] **Step 2: README** — in `## Features`, after the *Automatic re-verification* bullet add:

```markdown
- **One-click proof**: *Verify now* re-runs an issue's template against its asset and the Proof card shows the exact
  request/response nuclei matched on (plus a curl command to reproduce it by hand). Issues raised by a version rule
  can link or AI-draft a verification template first.
```

In `## Workflow`, after the step that triages issues, add a step: `Press **Verify now** on an issue to re-run its template and capture proof before assigning the fix.`

- [ ] **Step 3: Thai user guide** — in `## 6. จัดการงาน: Issues` add a sub-section before section 7:

```markdown
### ตรวจสอบซ้ำและเก็บหลักฐาน (Verify now / Proof)

- ปุ่ม **Verify now** (ไอคอน ▶) บนหน้า issue, ท้ายแถวในตาราง Issues และในตาราง Exposure ของ Campaign จะรัน nuclei
  ด้วย template ตัวเดิมต่อ asset นั้นตัวเดียว ผลขึ้นเป็นป้าย **reproduced** / **not reproduced** / **inconclusive**
  พร้อมบันทึกใน timeline ถ้า reproduced issue จะกลายเป็น confirmed
- การ์ด **Proof** แสดง HTTP request/response ที่ nuclei ใช้ match, matcher, ค่าที่ดึงได้ และปุ่ม **Copy curl**
  สำหรับยิงซ้ำด้วยมือ กด *proof* ที่แถวใน Evidence เพื่อดูของ job อื่น
- issue ที่มาจาก version rule ยังไม่มี template: การ์ด **Verification template** ให้ค้นหา template ที่มีอยู่แล้ว
  **Link template** หรือกด **Draft verification template with AI** → ตรวจ YAML → **Save & run as proof**
- ถ้าโมเดล AI ปฏิเสธ หน้าจอจะขึ้นข้อความภาษาอังกฤษแนะนำให้เปลี่ยน provider/model ที่ **System → AI**
  แล้วลองใหม่ (บางโมเดลไม่ยอมเขียน template ตรวจช่องโหว่แม้เป็นการทดสอบระบบของตัวเอง)
- ต้องมีสิทธิ์ `scan.run` จึงเห็นปุ่ม Play; viewer เห็น Proof ได้แต่สั่งสแกนไม่ได้
```

Update the table of contents only if section 6's entry lists sub-sections.

- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md docs/USER_GUIDE.th.md
git commit -m "docs: Verify now, Proof card and verification templates

Co-Authored-By: Claude Mythos 5.1 <noreply@anthropic.com>"
```

---

### Task 10: Full test run, browser check, merge

- [ ] **Step 1: Full suite** (background, ~4 min)

Run: `.venv/bin/python -m pytest -q`
Expected: all pass (362 existing + new ones).

- [ ] **Step 2: Browser check on a throwaway instance** — never the owner's container on port 8000.

```bash
docker build -t zdrs-dev .
docker volume create zdrs-dev-data
docker run -d --name zdrs-dev -p 127.0.0.1:8001:8000 -v zdrs-dev-data:/data zdrs-dev
```
Log in on `http://127.0.0.1:8001` (admin / changeme → set a throwaway password), run a nuclei scan with the
`http/technologies` group against `http://honey.scanme.sh`, open an issue: Proof card shows request/response and
Copy curl works; press *Verify now* → chip `verifying (job #N)` → after the job, chip `reproduced` and a timeline
entry; Issues list shows Play icons; add a version rule that matches an inventory service → the issue shows the
Verification template card; test search + Link template; light and dark theme; no console errors.
Then `docker rm -f zdrs-dev && docker volume rm zdrs-dev-data`.

- [ ] **Step 3: Merge and push**

```bash
git checkout master && git merge --no-ff feature/issue-verify-proof -m "Merge feature/issue-verify-proof

Co-Authored-By: Claude Mythos 5.1 <noreply@anthropic.com>" && git push origin master && git branch -d feature/issue-verify-proof
```
