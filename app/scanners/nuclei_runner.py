from __future__ import annotations

import json
import re
from pathlib import Path

from sqlalchemy.orm import Session

from ..config import Settings
from ..db import Finding, Job
from ..parsers.nuclei_jsonl import parse_nuclei_jsonl


_TAG_RE = re.compile(r"^[A-Za-z0-9_.\-]+$")
_GROUP_RE = re.compile(r"^[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)*$")
CUSTOM_GROUP_KEY = "custom"


def build_nuclei_argv(nuclei_bin: str, template_paths: list[str], targets_file: str, templates_dir: str,
                      rate_limit: int | None = None, timeout: int | None = None,
                      tags: list[str] | None = None, severities: list[str] | None = None) -> list[str]:
    """template_paths may be template files or directories (nuclei runs every template below a directory)."""
    if not template_paths:
        raise ValueError("Select at least one template.")
    argv = [nuclei_bin, "-jsonl", "-silent", "-disable-update-check", "-no-color", "-ud", templates_dir, "-l", targets_file]
    for p in template_paths:
        argv += ["-t", p]
    if tags:
        argv += ["-tags", ",".join(tags)]
    if severities:
        argv += ["-severity", ",".join(severities)]
    if rate_limit:
        argv += ["-rate-limit", str(int(rate_limit))]
    if timeout:
        argv += ["-timeout", str(int(timeout))]
    return argv


def parse_tags(text: str) -> list[str]:
    """'cve, php rce' -> ['cve', 'php', 'rce']; rejects anything that is not a plain tag token."""
    out: list[str] = []
    for raw in re.split(r"[,\s]+", text or ""):
        t = raw.strip().lower()
        if not t:
            continue
        if not _TAG_RE.match(t):
            raise ValueError(f"Invalid tag {raw!r}: use letters, digits, '-', '_' or '.' only.")
        if t not in out:
            out.append(t)
    return out


def _template_roots(settings: Settings) -> list[Path]:
    return [settings.nuclei_templates_dir.resolve(), settings.custom_templates_dir.resolve()]


def validate_template_paths(settings: Settings, paths: list[str]) -> list[str]:
    """Accept template files or directories, as long as they live inside the official or custom template roots."""
    roots = _template_roots(settings)
    out: list[str] = []
    for p in paths:
        rp = Path(p).resolve()
        if not any(rp == r or rp.is_relative_to(r) for r in roots):
            raise ValueError(f"Template path is not in the template directories: {p}")
        if not (rp.is_file() or rp.is_dir()):
            raise ValueError(f"Template path not found: {p}")
        if str(rp) not in out:
            out.append(str(rp))
    if not out:
        raise ValueError("Select at least one template.")
    return out


def resolve_group_paths(settings: Settings, groups: list[str]) -> list[str]:
    """Map group keys ('http/cves/2026', 'custom') to directories under the template roots."""
    if not groups:
        raise ValueError("Select at least one template group.")
    out: list[str] = []
    for g in groups:
        g = g.strip().strip("/")
        if g == CUSTOM_GROUP_KEY:
            path = settings.custom_templates_dir.resolve()
        else:
            if not _GROUP_RE.match(g) or ".." in g.split("/"):
                raise ValueError(f"Invalid template group {g!r}.")
            path = (settings.nuclei_templates_dir / g).resolve()
            if not path.is_relative_to(settings.nuclei_templates_dir.resolve()):
                raise ValueError(f"Invalid template group {g!r}.")
        if not path.is_dir():
            raise ValueError(f"Template group not found: {g}")
        if str(path) not in out:
            out.append(str(path))
    return out


def all_template_paths(settings: Settings) -> list[str]:
    """Official templates directory plus the custom directory when it holds any template."""
    out = []
    if settings.nuclei_templates_dir.is_dir():
        out.append(str(settings.nuclei_templates_dir.resolve()))
    if settings.custom_templates_dir.is_dir() and any(settings.custom_templates_dir.glob("*.y*ml")):
        out.append(str(settings.custom_templates_dir.resolve()))
    if not out:
        raise ValueError("No templates available yet. Run 'Update nuclei templates' first.")
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
