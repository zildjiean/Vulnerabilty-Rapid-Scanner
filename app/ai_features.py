"""Prompts, output schemas and context builders for the AI assist features."""
from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Finding, Host, Issue, Rule, Scope, Service, User

SYSTEM = (
    "You are a senior vulnerability analyst helping an internal security team that runs an nmap + nuclei scanner. "
    "Be precise, practical and brief. Host names and addresses may appear as HOST-n placeholders: keep them exactly "
    "as written. Never invent CVE ids, versions, vendor advisories or URLs; when unsure, say what to check instead."
)
MAX_EVIDENCE = 1500
MAX_ADVISORY = 20000
MAX_LOG = 6000


def _obj(properties: dict) -> dict:
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


SEVERITY_ENUM = {"type": "string", "enum": ["critical", "high", "medium", "low"]}

CAMPAIGN_SCHEMA = _obj({
    "name": {"type": "string"},
    "summary": {"type": "string"},
    "product_pattern": {"type": "string"},
    "version_constraint": {"type": "string"},
    "severity": SEVERITY_ENUM,
    "template_search_terms": {"type": "array", "items": {"type": "string"}},
    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
    "notes": {"type": "string"},
})
TEMPLATE_SCHEMA = _obj({"yaml": {"type": "string"}, "notes": {"type": "string"}})
TRIAGE_SCHEMA = _obj({
    "verdict": {"type": "string", "enum": ["likely_true_positive", "likely_false_positive", "uncertain"]},
    "confidence": {"type": "integer"},
    "reasoning": {"type": "string"},
    "checks": {"type": "array", "items": {"type": "string"}},
})
TRIAGE_LABELS = {"likely_true_positive": "Likely true positive", "likely_false_positive": "Likely false positive",
                 "uncertain": "Uncertain"}
SEARCH_SCHEMA = _obj({
    "target": {"type": "string", "enum": ["issues", "inventory"]},
    "view": {"type": "string", "enum": ["active", "closed", "all"]},
    "severity": {"type": "string", "enum": ["", "critical", "high", "medium", "low"]},
    "status": {"type": "string", "enum": ["", "new", "triaged", "in_progress", "fixed", "verified", "false_positive",
                                          "accepted_risk"]},
    "assignee": {"type": "string"},
    "confidence": {"type": "string", "enum": ["", "confirmed", "verified", "suspected"]},
    "overdue": {"type": "boolean"},
    "scope": {"type": "string"},
    "q": {"type": "string"},
    "product": {"type": "string"},
    "port": {"type": "string"},
    "explanation": {"type": "string"},
})


# ----------------------------------------------------------------- 1. campaign draft
def campaign_prompt(cve: str, advisory: str, intel_description: str = "") -> str:
    return f"""A new vulnerability needs a response campaign. Propose how to detect exposed services in our inventory.

The inventory holds nmap service fingerprints: product names such as "Apache httpd", "nginx", "OpenSSH",
"PHP cli server", "Microsoft IIS httpd", "Exim smtpd", with versions such as "2.4.49" or "9.6p1".

Fields:
- name: short campaign title.
- summary: 2-3 sentences for the team in plain language.
- product_pattern: a case-insensitive Python regular expression matched against the nmap product, service name
  and CPE (keep it simple, e.g. "apache" or "openssh|ssh"). Empty string if the product cannot be fingerprinted by nmap.
- version_constraint: vulnerable versions as comma-separated comparators, e.g. ">= 2.4.49, < 2.4.51" (operators
  <, <=, >, >=, ==, !=). Use the narrowest range the advisory supports. Empty string if unknown.
- severity: critical, high, medium or low.
- template_search_terms: words to search the nuclei template index (CVE id, product).
- confidence: how sure you are about the pattern and range.
- notes: caveats (backports, distribution packages, multiple branches).

CVE: {cve or "not given"}
{("NVD description: " + intel_description) if intel_description else ""}
Advisory / notes from the analyst:
{advisory[:MAX_ADVISORY] or "(none)"}"""


# ----------------------------------------------------------------- 2. template draft
TEMPLATE_RULES = """Write a nuclei v3 template in YAML that DETECTS the vulnerability without exploiting it.
Rules:
- Top level: id (lowercase, letters digits dashes), info (name, author: ai-draft, severity, description,
  reference list only with URLs given to you, tags including the CVE and product, classification.cve-id when known).
- Prefer passive checks: version banners, distinctive files, headers or error pages that prove the vulnerable version.
- Only GET or HEAD requests. No payloads that write, delete, execute commands or change state. No out-of-band
  interactsh callbacks. No brute force.
- Use matchers-condition: and with at least two matchers (e.g. status + word/regex) to avoid false positives.
- Put the YAML in the "yaml" field without code fences; explain limits in "notes".
- The template verifies a vulnerability on an asset owned by the team that runs this scanner: a detection check
  for authorized internal testing, not an exploit."""


def template_prompt(cve: str, advisory: str, hints: str = "") -> str:
    return f"""{TEMPLATE_RULES}

CVE: {cve or "not given"}
Advisory / analyst notes:
{advisory[:MAX_ADVISORY] or "(none)"}
{("Target hints: " + hints) if hints else ""}"""


def issue_template_prompt(db: Session, issue: Issue) -> str:
    """Draft a verification template for one issue: its context without scan evidence, plus the service as a hint."""
    svc = _service(db, issue)
    product = " ".join(x for x in ((svc.product if svc else ""), (svc.version if svc else "")) if x)
    hints = f"{issue.asset} running {product}" if product else issue.asset
    return template_prompt(issue.cve_id or issue.vuln_id, issue_context(db, issue, evidence=False), hints)


# ----------------------------------------------------------------- 3 / 4. issue explain + triage
def _evidence(db: Session, issue: Issue, limit: int = 3) -> str:
    out = []
    for f in db.scalars(select(Finding).where(Finding.issue_id == issue.id).order_by(Finding.id.desc()).limit(limit)):
        try:
            raw = json.loads(f.raw_json or "{}")
        except json.JSONDecodeError:
            raw = {}
        out.append(f"- template {f.template_id} ({f.template_name}), severity {f.severity}, matched at {f.matched_at}"
                   + (f", extracted: {f.extracted}" if f.extracted else "")
                   + (f"\n  request:\n{str(raw.get('request', ''))[:MAX_EVIDENCE]}" if raw.get("request") else "")
                   + (f"\n  response:\n{str(raw.get('response', ''))[:MAX_EVIDENCE]}" if raw.get("response") else ""))
    return "\n".join(out) or "(no scan evidence: suspected from the installed version)"


def _service(db: Session, issue: Issue) -> Service | None:
    if not issue.port.isdigit():
        return None
    return db.scalar(select(Service).join(Host, Host.id == Service.host_id)
                     .where(Host.address == issue.address, Service.port == int(issue.port)))


def issue_context(db: Session, issue: Issue, evidence: bool = True) -> str:
    from .campaigns import campaigns_for_issue
    conf = {"suspected": "suspected (version match only, not scanned)", "confirmed": "confirmed (matched by a nuclei scan)",
            "verified": "verified (reproduced on demand, request/response proof stored)"}.get(issue.confidence, issue.confidence)
    lines = [f"Vulnerability: {issue.vuln_id} - {issue.title}", f"Severity: {issue.severity}; confidence: {conf};"
             f" status: {issue.status}", f"Asset: {issue.asset}" + (f" ({issue.hostname})" if issue.hostname else "")]
    svc = _service(db, issue)
    if svc:
        lines.append(f"Service (nmap): {svc.service_name} {svc.product} {svc.version} {svc.extra_info} {svc.cpe}".strip())
    if issue.scope_id:
        scope = db.get(Scope, issue.scope_id)
        if scope:
            lines.append(f"Scope: {scope.name} ({scope.criticality} business criticality)")
    if issue.rule_id:
        rule = db.get(Rule, issue.rule_id)
        if rule:
            lines.append(f"Version rule: product ~ /{rule.product_pattern}/ versions {rule.version_constraint}")
    for c in campaigns_for_issue(db, issue):
        lines.append(f"Campaign intel: {c.description[:800]}" + (f" CVSS {c.cvss_score}." if c.cvss_score else "")
                     + (" Listed in CISA KEV (known exploited)." if c.kev else ""))
    if evidence:
        lines.append("Evidence:\n" + _evidence(db, issue))
    return "\n".join(lines)


EXPLAIN_TASK = """Write markdown with exactly these sections:
## Summary - 2-3 sentences: what it is and what an attacker gains.
## Impact - for this asset, considering exposure, confidence and scope criticality.
## Remediation - numbered concrete steps for this product and version (fixed version to upgrade to if known,
configuration workaround, compensating controls).
## Verify the fix - how to confirm, including a re-scan in this scanner.
Keep it under 350 words."""

TRIAGE_TASK = """Judge from the evidence only whether this nuclei finding is likely real. Generic catch-all pages,
WAF block pages, redirects to login, or a matcher that only checks a status code suggest a false positive.
Give: verdict, confidence 0-100, reasoning (2-4 sentences) and up to 4 concrete manual checks."""


# ----------------------------------------------------------------- 5. natural-language search
def search_prompt(db: Session, question: str, me: str) -> str:
    scopes = [s for (s,) in db.execute(select(Scope.name).order_by(Scope.name))]
    products = [p for (p,) in db.execute(select(Service.product).where(Service.product != "").distinct().limit(200))]
    users = [u for (u,) in db.execute(select(User.username).where(User.role.in_(("admin", "analyst"))))]
    return f"""Translate the question into filters for the scanner UI. Use empty strings for filters that do not apply.
- target "issues" for vulnerabilities / risk / remediation questions; "inventory" for "what runs where" questions.
- issues filters: view, severity, status, assignee ("me" = {me}, "none" = unassigned, or a username from the list),
  confidence ("suspected" = version match only, "confirmed" = seen by a nuclei scan, "verified" = reproduced with
  proof by Verify now), overdue, scope (exact scope name or "none"), q (free text: CVE, title, address, host name).
- inventory filters: q (address, host name, product, version, CPE), product (exact name from the list), port.
- explanation: one short sentence describing the filter you chose.
Scopes: {scopes}
Products in inventory: {products}
Users who can own issues: {users}
Question: {question[:2000]}"""


# ----------------------------------------------------------------- 6 / 7. summary + diagnosis
def summary_prompt(r: dict) -> str:
    figures = {k: v for k, v in r.items() if k not in ("trend", "since", "now", "trend_peak")}
    figures["weekly_trend"] = [{"week": t["start"].strftime("%Y-%m-%d"), "new": t["new"], "resolved": t["resolved"]}
                               for t in r["trend"]]
    return f"""Write an executive summary of the scanner's last {r['days']} days for leadership.
Two short paragraphs in plain language, then 3-5 bullet recommendations. Use only the figures below; do not invent
numbers. Mention SLA performance and the riskiest areas.

Figures (JSON):
{json.dumps(figures, default=str, indent=1)[:12000]}"""


def diagnose_prompt(job, warnings: list[str]) -> str:
    return f"""A {job.kind} job in the scanner ended with status "{job.status}".
Explain the most likely cause and the concrete next steps in this scanner. Options available: nuclei profiles
Gentle / Normal / Aggressive, "Never drop unresponsive hosts", Updates (nuclei templates, nuclei engine, nmap
scripts), nmap scan type SYN or Connect, skip host discovery (-Pn), narrower targets or ports.
Markdown, at most 200 words.

Command: {job.command[:1000]}
Warnings: {warnings or "none"}
Log tail:
{(job.log or "")[-MAX_LOG:]}"""

