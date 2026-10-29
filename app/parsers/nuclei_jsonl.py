"""Parse `nuclei -jsonl` output. One finding per JSON line; non-JSON lines are ignored."""
from __future__ import annotations

import json

from ..render import normalize_severity


def parse_nuclei_jsonl(text: str) -> list[dict]:
    findings: list[dict] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict) or "template-id" not in obj:
            continue
        info = obj.get("info") or {}
        extracted = obj.get("extracted-results") or []
        if isinstance(extracted, str):
            extracted = [extracted]
        findings.append({
            "template_id": str(obj.get("template-id", "")),
            "template_name": str(info.get("name", "") or ""),
            "severity": normalize_severity(info.get("severity")),
            "host": str(obj.get("host", "") or ""),
            "matched_at": str(obj.get("matched-at", "") or ""),
            "type": str(obj.get("type", "") or ""),
            "extracted": ", ".join(str(x) for x in extracted),
            "raw": obj,
        })
    return findings
