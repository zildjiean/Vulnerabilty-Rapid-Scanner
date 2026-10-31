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

# Scan profiles: UI defaults for rate/timeout plus extra nuclei flags that control resilience.
PROFILES = {
    "gentle": {"label": "Gentle", "rate_limit": 20, "timeout": 20,
               "help": "Slow and tolerant: for targets behind WAF/rate limits or fragile servers. Retries twice, keeps going after 100 host errors.",
               "flags": ["-retries", "2", "-max-host-error", "100", "-c", "10", "-bulk-size", "10"]},
    "normal": {"label": "Normal", "rate_limit": 150, "timeout": 10,
               "help": "nuclei defaults: 25 concurrent templates, host dropped after 30 consecutive errors.",
               "flags": []},
    "aggressive": {"label": "Aggressive", "rate_limit": 400, "timeout": 8,
                   "help": "Fast: 50 concurrent templates and larger batches. Only for robust targets you control.",
                   "flags": ["-c", "50", "-bulk-size", "50"]},
}
DEFAULT_PROFILE = "normal"


def profile_flags(profile: str, no_mhe: bool) -> list[str]:
    if profile not in PROFILES:
        raise ValueError("Invalid scan profile.")
    flags = list(PROFILES[profile]["flags"])
    if no_mhe:
        flags.append("-no-mhe")
    return flags


def build_nuclei_argv(nuclei_bin: str, template_paths: list[str], targets_file: str, templates_dir: str,
                      rate_limit: int | None = None, timeout: int | None = None,
                      tags: list[str] | None = None, severities: list[str] | None = None,
                      extra: list[str] | None = None) -> list[str]:
    """template_paths may be template files or directories (nuclei runs every template below a directory)."""
    if not template_paths:
        raise ValueError("Select at least one template.")
    # No -silent: nuclei's INF lines (templates/targets loaded, httpx probing, errors) go to stderr and end up in the
    # job log, so an empty result can be told apart from an unreachable target. Findings stay on stdout as JSONL.
    argv = [nuclei_bin, "-jsonl", "-disable-update-check", "-no-color", "-stats", "-stats-interval", "30",
            "-ud", templates_dir, "-l", targets_file]
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
    if extra:
        argv += list(extra)
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


def ingest_nuclei_results(db: Session, job: Job, jsonl_text: str) -> tuple[int, int]:
    """Store findings and open / update their issues. Returns (findings stored, issues created)."""
    findings = parse_nuclei_jsonl(jsonl_text)
    rows = []
    for f in findings:
        row = Finding(job_id=job.id, template_id=f["template_id"], template_name=f["template_name"], severity=f["severity"],
                      host=f["host"], matched_at=f["matched_at"], type=f["type"], extracted=f["extracted"],
                      raw_json=json.dumps(f["raw"]))
        db.add(row)
        rows.append(row)
    db.flush()
    from ..issues import issues_from_findings  # local import keeps the parser module light
    return len(findings), issues_from_findings(db, rows, job)


_SKIPPED_RE = re.compile(r"Skipped (\S+) from target list as found unresponsive permanently(?::\s*cause=\"([^\"]+)\")?")
_STATS_RE = re.compile(r'^\{"duration".*"errors":"(\d+)".*"requests":"(\d+)".*\}$')
_HTTPX_RE = re.compile(r"Found (\d+) URL from httpx")
_TARGETS_RE = re.compile(r"Targets loaded for current scan: (\d+)")
ERROR_RATIO_WARN = 0.02  # 2 % of requests failing is suspicious ...
ERROR_COUNT_MIN = 5      # ... but only once at least this many requests failed (tiny scans are noisy)
ANALYSIS_VERSION = 2     # bump when the rules change so backfill_nuclei_warnings re-analyzes finished jobs


def analyze_nuclei_log(log_text: str) -> list[str]:
    """Turn nuclei's own status lines into operator-facing warnings about incomplete coverage."""
    warnings: list[str] = []
    errors = requests = None
    targets = httpx_urls = None
    err_lines: list[str] = []
    for line in (log_text or "").splitlines():
        line = line.strip()
        m = _SKIPPED_RE.search(line)
        if m:
            cause = f" ({m.group(2)})" if m.group(2) else ""
            warnings.append(f"Target {m.group(1)} was dropped as unresponsive{cause}; templates after that point were not tested.")
            continue
        m = _STATS_RE.match(line)
        if m:
            errors, requests = int(m.group(1)), int(m.group(2))
            continue
        m = _TARGETS_RE.search(line)
        if m:
            targets = int(m.group(1))
        m = _HTTPX_RE.search(line)
        if m:
            httpx_urls = int(m.group(1))
        if line.startswith("[ERR]") or line.startswith("[WRN]") or line.startswith("[FTL]"):
            err_lines.append(line)
    if targets and httpx_urls == 0:
        warnings.append(f"{targets} target(s) loaded but they did not answer over HTTP(S) (httpx found 0 URLs); HTTP templates had nothing to test.")
    if errors and requests and errors >= ERROR_COUNT_MIN and errors / requests >= ERROR_RATIO_WARN:
        warnings.append(f"{errors} request errors out of {requests} ({errors * 100 / requests:.1f}%): timeouts or blocks, likely a WAF / rate limit. Try the Gentle profile.")
    for line in err_lines[:5]:
        warnings.append(line)
    if len(err_lines) > 5:
        warnings.append(f"… {len(err_lines) - 5} more [ERR]/[WRN] line(s) in the log.")
    return warnings


def on_nuclei_complete(db: Session, job: Job, output: str) -> str:
    n, new_issues = ingest_nuclei_results(db, job, output)
    try:
        params = json.loads(job.params_json or "{}")
    except json.JSONDecodeError:
        params = {}
    params["result"] = {"findings": n, "new_issues": new_issues}
    warnings = analyze_nuclei_log(job.log or "")
    if warnings:
        params["warnings"] = warnings
    params["analyzed"] = ANALYSIS_VERSION
    job.params_json = json.dumps(params)
    if params.get("reverify"):
        from ..reverify import complete_reverify
        verified = complete_reverify(db, job, warnings)
        params["result"]["verified"] = verified
        job.params_json = json.dumps(params)
    if params.get("verify_issue"):
        from ..proof import complete_verify
        params["result"]["verify"] = complete_verify(db, job, warnings)
        job.params_json = json.dumps(params)
    issues_note = f" {new_issues} new issue(s) opened." if new_issues else ""
    if warnings:
        return (f"[nuclei] WARNING: coverage is incomplete, {n} finding(s) stored.{issues_note} " + " | ".join(warnings[:3]))
    if n == 0:
        return ("[nuclei] 0 findings stored. Check the INF lines above: 'Templates loaded' and 'Targets loaded' show what "
                "actually ran; 'Found N URL from httpx' confirms the target answered over HTTP(S).")
    return f"[nuclei] {n} finding(s) stored;{issues_note} open the Issues page to triage them."


def backfill_nuclei_warnings(db: Session) -> int:
    """(Re-)analyze logs of finished nuclei jobs whose stored analysis predates ANALYSIS_VERSION. Runs once per job and version."""
    from sqlalchemy import select
    changed = 0
    for job in db.scalars(select(Job).where(Job.kind == "nuclei", Job.status == "done")):
        try:
            params = json.loads(job.params_json or "{}")
        except json.JSONDecodeError:
            params = {}
        if not isinstance(params, dict) or params.get("analyzed") == ANALYSIS_VERSION:
            continue
        warnings = analyze_nuclei_log(job.log or "")
        if warnings:
            params["warnings"] = warnings
        else:
            params.pop("warnings", None)
        params["analyzed"] = ANALYSIS_VERSION
        job.params_json = json.dumps(params)
        changed += 1
    if changed:
        db.commit()
    return changed
