"""AI assist features: drafts, explanations, triage, search, summaries, diagnosis. Advisory output only."""
from __future__ import annotations

import re
from urllib.parse import quote, urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import ai, ai_features as af
from ..audit import audit
from ..authz import require
from ..db import Issue, Job, Scope, User
from ..deps import get_db, get_settings, verify_csrf
from ..jobs import job_warnings
from ..llm import LLMError, LLMRefusal
from ..rules import validate_rule

router = APIRouter(prefix="/ai")
USE = [Depends(require("ai.use")), Depends(verify_csrf)]


def _back(url: str, err: str) -> RedirectResponse:
    return RedirectResponse(f"{url}{'&' if '?' in url else '?'}err={quote(err[:300])}", status_code=303)


# ----------------------------------------------------------------- 1. campaign draft
@router.post("/campaign-draft", dependencies=[Depends(require("campaigns.manage")), *USE])
async def campaign_draft(request: Request, cve_id: str = Form(""), advisory: str = Form(""), db: Session = Depends(get_db)):
    from ..intel import normalize_cve
    from .campaigns import _new_form, load_intel
    form = {"cve_id": cve_id, "description": ""}
    try:
        cve = normalize_cve(cve_id) if cve_id.strip() else ""
    except ValueError as e:
        return _new_form(request, 400, str(e), form)
    if not cve and not advisory.strip():
        return _new_form(request, 400, "Paste the advisory text or enter a CVE id for the AI draft.", form)
    description = ""
    if cve and not advisory.strip():
        info, _errors = await load_intel(request, cve)
        description = info.get("description", "")
    try:
        result, provider = await ai.generate(request, db, "campaign_draft", af.SYSTEM,
                                             af.campaign_prompt(cve, advisory, description), schema=af.CAMPAIGN_SCHEMA,
                                             effort="medium")
    except LLMError as e:
        return _new_form(request, 400, str(e), form)
    d = result.data or {}
    warning = None
    if d.get("product_pattern"):
        warning = validate_rule(d["product_pattern"], d.get("version_constraint", ""))
    form = {"cve_id": cve, "name": d.get("name", ""), "severity": d.get("severity", "auto"),
            "description": d.get("summary", ""), "product_pattern": d.get("product_pattern", ""),
            "version_constraint": d.get("version_constraint", ""), "attach_templates": True, "fetch_intel": True}
    draft = {"notes": d.get("notes", ""), "confidence": d.get("confidence", ""), "terms": d.get("template_search_terms") or [],
             "warning": warning, "provider": provider.name, "model": result.model}
    return _new_form(request, 200, None, form, ai_draft=draft)


# ----------------------------------------------------------------- 2. template draft
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


# ----------------------------------------------------------------- 3 / 4. issues
def _issue(db: Session, iid: int) -> Issue:
    issue = db.get(Issue, iid)
    if issue is None:
        raise HTTPException(404)
    return issue


@router.post("/issues/{iid}/explain", dependencies=USE)
async def issue_explain(request: Request, iid: int, db: Session = Depends(get_db)):
    issue = _issue(db, iid)
    try:
        result, provider = await ai.generate(request, db, "explain", af.SYSTEM,
                                             af.issue_context(db, issue) + "\n\n" + af.EXPLAIN_TASK, effort="medium")
    except LLMError as e:
        return _back(f"/issues/{iid}", str(e))
    ai.save_note(db, request, "explain", "issue", iid, result.text, None, provider, result.model)
    return RedirectResponse(f"/issues/{iid}?msg=AI+explanation+ready#ai", status_code=303)


@router.post("/issues/{iid}/triage", dependencies=USE)
async def issue_triage(request: Request, iid: int, db: Session = Depends(get_db)):
    issue = _issue(db, iid)
    try:
        result, provider = await ai.generate(request, db, "triage", af.SYSTEM,
                                             af.issue_context(db, issue) + "\n\n" + af.TRIAGE_TASK,
                                             schema=af.TRIAGE_SCHEMA, effort="medium")
    except LLMError as e:
        return _back(f"/issues/{iid}", str(e))
    d = result.data or {}
    d["confidence"] = max(0, min(100, int(d.get("confidence") or 0)))
    ai.save_note(db, request, "triage", "issue", iid, d.get("reasoning", ""), d, provider, result.model)
    return RedirectResponse(f"/issues/{iid}?msg=AI+triage+ready#ai", status_code=303)


@router.post("/issues/{iid}/template-draft", dependencies=[Depends(require("templates.manage")), *USE])
async def issue_template_draft(request: Request, iid: int, db: Session = Depends(get_db), settings=Depends(get_settings)):
    from .issues import _detail
    issue = _issue(db, iid)
    try:
        result, provider = await ai.generate(request, db, "template_draft", af.SYSTEM, af.issue_template_prompt(db, issue),
                                             schema=af.TEMPLATE_SCHEMA, effort="high")
    except LLMRefusal as e:
        reason = str(e).rstrip(".")
        return _detail(request, db, issue, status_code=400, verify_refusal=reason[:1].lower() + reason[1:])   # mid-sentence
    except LLMError as e:
        return _detail(request, db, issue, status_code=400, error=str(e))
    return _detail(request, db, issue, verify_draft=await draft_from_result(settings, result, provider))


@router.post("/issues/{iid}/explain/comment", dependencies=[Depends(require("issues.manage")), Depends(verify_csrf)])
def issue_explain_comment(request: Request, iid: int, db: Session = Depends(get_db)):
    from .. import issues as iss
    issue = _issue(db, iid)
    note = ai.latest_note(db, "explain", "issue", iid)
    if note is None:
        return _back(f"/issues/{iid}", "Generate an explanation first.")
    iss.add_comment(db, issue, f"AI remediation notes ({note.provider_name} / {note.model}):\n\n{note.content}",
                    db.get(User, request.state.user.id))
    db.commit()
    audit(db, request, "issue.commented", target=f"#{iid} {issue.vuln_id} on {issue.asset}", source="ai")
    return RedirectResponse(f"/issues/{iid}?msg=Added+to+the+timeline#timeline", status_code=303)


# ----------------------------------------------------------------- 5. search
@router.post("/search", dependencies=USE)
async def ai_search(request: Request, question: str = Form(""), back: str = Form("/issues"), db: Session = Depends(get_db)):
    back = back if back in ("/issues", "/inventory") else "/issues"
    if not question.strip():
        return _back(back, "Type a question first.")
    try:
        result, _ = await ai.generate(request, db, "search", af.SYSTEM,
                                      af.search_prompt(db, question, request.state.user.username),
                                      schema=af.SEARCH_SCHEMA, effort="low", max_tokens=2000)
    except LLMError as e:
        return _back(back, str(e))
    d = result.data or {}
    if d.get("target") == "inventory":
        params = {k: d.get(k, "") for k in ("q", "product", "port")}
        url = "/inventory"
    else:
        assignee = d.get("assignee", "")
        if assignee not in ("", "me", "none"):
            uid = db.scalar(select(User.id).where(User.username == assignee))
            assignee = str(uid) if uid else ""
        scope = d.get("scope", "")
        if scope and scope != "none":
            sid = db.scalar(select(Scope.id).where(Scope.name == scope))
            scope = str(sid) if sid else ""
        params = {"view": d.get("view", "active"), "severity": d.get("severity", ""), "status": d.get("status", ""),
                  "assignee": assignee, "confidence": d.get("confidence", ""), "overdue": "1" if d.get("overdue") else "",
                  "scope": scope, "q": d.get("q", "")}
        url = "/issues"
    query = urlencode({k: v for k, v in params.items() if v})
    msg = quote(("AI: " + d.get("explanation", "")).strip()[:200])
    return RedirectResponse(f"{url}?{query}{'&' if query else ''}msg={msg}", status_code=303)


# ----------------------------------------------------------------- 6. executive summary
@router.post("/reports/summary", dependencies=USE)
async def report_summary(request: Request, days: str = Form("30"), db: Session = Depends(get_db)):
    from .. import reports as rep
    from .reports import _days
    d = _days(days)
    try:
        result, provider = await ai.generate(request, db, "summary", af.SYSTEM, af.summary_prompt(rep.executive(db, d)),
                                             effort="medium")
    except LLMError as e:
        return _back(f"/reports?days={d}", str(e))
    ai.save_note(db, request, "summary", "report", d, result.text, None, provider, result.model)
    return RedirectResponse(f"/reports?days={d}&msg=AI+summary+ready", status_code=303)


# ----------------------------------------------------------------- 7. job diagnosis
@router.post("/jobs/{jid}/diagnose", dependencies=USE)
async def job_diagnose(request: Request, jid: int, db: Session = Depends(get_db)):
    job = db.get(Job, jid)
    if job is None:
        raise HTTPException(404)
    try:
        result, provider = await ai.generate(request, db, "diagnose", af.SYSTEM, af.diagnose_prompt(job, job_warnings(job)),
                                             effort="low")
    except LLMError as e:
        return _back(f"/jobs/{jid}", str(e))
    ai.save_note(db, request, "diagnose", "job", jid, result.text, None, provider, result.model)
    return RedirectResponse(f"/jobs/{jid}?msg=AI+diagnosis+ready#ai", status_code=303)
