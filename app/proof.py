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
