from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from ..config import Settings
from ..db import Finding, Job
from ..parsers.nuclei_jsonl import parse_nuclei_jsonl


def build_nuclei_argv(nuclei_bin: str, template_paths: list[str], targets_file: str, templates_dir: str,
                      rate_limit: int | None = None, timeout: int | None = None) -> list[str]:
    if not template_paths:
        raise ValueError("Select at least one template.")
    argv = [nuclei_bin, "-jsonl", "-silent", "-disable-update-check", "-no-color", "-ud", templates_dir, "-l", targets_file]
    for p in template_paths:
        argv += ["-t", p]
    if rate_limit:
        argv += ["-rate-limit", str(int(rate_limit))]
    if timeout:
        argv += ["-timeout", str(int(timeout))]
    return argv


def validate_template_paths(settings: Settings, paths: list[str]) -> list[str]:
    roots = [settings.nuclei_templates_dir.resolve(), settings.custom_templates_dir.resolve()]
    out: list[str] = []
    for p in paths:
        rp = Path(p).resolve()
        if not any(rp.is_relative_to(r) for r in roots):
            raise ValueError(f"Template path is not in the template directories: {p}")
        if not rp.is_file():
            raise ValueError(f"Template file not found: {p}")
        if str(rp) not in out:
            out.append(str(rp))
    if not out:
        raise ValueError("Select at least one template.")
    return out


def write_targets_file(settings: Settings, job_id: int, targets: list[str]) -> Path:
    path = settings.jobs_dir / f"nuclei-{job_id}-targets.txt"
    path.write_text("\n".join(targets) + "\n")
    return path


def ingest_nuclei_results(db: Session, job: Job, jsonl_text: str) -> int:
    findings = parse_nuclei_jsonl(jsonl_text)
    for f in findings:
        db.add(Finding(job_id=job.id, template_id=f["template_id"], template_name=f["template_name"], severity=f["severity"],
                       host=f["host"], matched_at=f["matched_at"], type=f["type"], extracted=f["extracted"],
                       raw_json=json.dumps(f["raw"])))
    db.flush()
    return len(findings)


def on_nuclei_complete(db: Session, job: Job, output: str) -> None:
    n = ingest_nuclei_results(db, job, output)
    try:
        params = json.loads(job.params_json or "{}")
    except json.JSONDecodeError:
        params = {}
    params["result"] = {"findings": n}
    job.params_json = json.dumps(params)
