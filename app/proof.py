"""Proof of a finding (the request/response nuclei recorded) and one-click verification of an issue."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

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


BULK_LIMIT = 200   # issues per bulk request
SKIP_LABELS = {"no_template": "no template", "not_indexed": "template not indexed", "running": "already running",
               "over_limit": "over limit"}


@dataclass
class BulkResult:
    jobs: list[int] = field(default_factory=list)
    issues: int = 0
    skipped: dict[str, int] = field(default_factory=dict)

    def summary(self) -> str:
        text = f"Started {len(self.jobs)} job(s) for {self.issues} issue(s)"
        parts = [f"{n} ({SKIP_LABELS[k]})" for k, n in self.skipped.items() if n]
        return text + ("; skipped " + ", ".join(parts) if parts else "") + "."


def start_verify_many(db: Session, app, issues: list[Issue], actor) -> BulkResult:
    """Verify many issues at once: one nuclei job per template, run against each issue's asset.
    Must run inside the event loop (async route or portal), like start_verify."""
    from .reverify import issue_target
    from .routers.nuclei import launch_nuclei
    from .scanners.nuclei_runner import PROFILES
    res = BulkResult()

    def skip(reason: str) -> None:
        res.skipped[reason] = res.skipped.get(reason, 0) + 1

    paths: dict[str, str | None] = {}
    by_path: dict[str, list[Issue]] = {}
    for n, issue in enumerate(issues):
        if n >= BULK_LIMIT:
            skip("over_limit")
        elif not issue.template_id:
            skip("no_template")
        elif live_verify_job(db, issue) is not None:
            skip("running")
        else:
            if issue.template_id not in paths:
                paths[issue.template_id] = db.scalar(select(TemplateIndex.path).where(
                    TemplateIndex.template_id == issue.template_id).limit(1))
            path = paths[issue.template_id]
            if path is None:
                skip("not_indexed")
            else:
                by_path.setdefault(path, []).append(issue)
    prof = PROFILES["normal"]
    for path, group in by_path.items():
        targets: list[str] = []
        target_of: dict[int, str] = {}
        for issue in group:
            target_of[issue.id] = issue_target(db, issue)
            if target_of[issue.id] not in targets:
                targets.append(target_of[issue.id])
        params = {"targets": targets, "template_ids": [group[0].template_id], "mode": "selected", "profile": "normal",
                  "verify_issues": [i.id for i in group]}
        job = launch_nuclei(db, app.state.settings, app.state.job_runner, targets, [path], params,
                            rate_limit=prof["rate_limit"], timeout=prof["timeout"], extra_flags=[])
        for issue in group:
            issue.verify_job_id = job.id
            _event(db, issue, f"Verification scan started: job #{job.id} against {target_of[issue.id]} "
                              f"(bulk, {len(group)} issue(s)).", actor)
        res.jobs.append(job.id)
        res.issues += len(group)
    db.commit()
    return res


def complete_verify(db: Session, job: Job, warnings: list[str]) -> str:
    """Called after a nuclei job's findings were ingested. Returns the verify_result written, or "" when not ours."""
    try:
        iid = json.loads(job.params_json or "{}").get("verify_issue")
    except json.JSONDecodeError:
        return ""
    issue = db.get(Issue, iid) if iid else None
    if issue is None or issue.verify_job_id != job.id:
        return ""
    # The job ran exactly one template against exactly one asset, so any finding of that template reproduces the issue.
    # Matching on issue_id alone would miss info templates: issues_from_findings skips them and never links them.
    finding = db.scalar(select(Finding).where(Finding.job_id == job.id, Finding.template_id == issue.template_id)
                        .order_by(Finding.id.desc()).limit(1))
    return _record_result(db, job, issue, finding, warnings)


def complete_verify_many(db: Session, job: Job, warnings: list[str]) -> dict[str, int]:
    """The bulk counterpart: one job verified several issues of one template. Returns {verify_result: count}."""
    from .issues import finding_on_issue_asset
    try:
        ids = json.loads(job.params_json or "{}").get("verify_issues") or []
    except json.JSONDecodeError:
        return {}
    ids = [i for i in ids if isinstance(i, int)]
    counts: dict[str, int] = {}
    for issue in db.scalars(select(Issue).where(Issue.id.in_(ids)).order_by(Issue.id)) if ids else []:
        if issue.verify_job_id != job.id:
            continue
        # The job scanned many assets, so a finding only counts for the issue whose asset it hit.
        finding = next((f for f in db.scalars(select(Finding).where(
            Finding.job_id == job.id, Finding.template_id == issue.template_id).order_by(Finding.id.desc()))
            if finding_on_issue_asset(f, issue)), None)
        result = _record_result(db, job, issue, finding, warnings)
        counts[result] = counts.get(result, 0) + 1
    return counts


def _record_result(db: Session, job: Job, issue: Issue, finding: Finding | None, warnings: list[str]) -> str:
    """Write reproduced / not_reproduced / inconclusive for one issue of a finished verification job."""
    from .issues import _event as issue_event, _set_status
    if finding is not None:
        result = "reproduced"
        if finding.issue_id is None:   # not ingested as an issue sighting (info severity); link it so the proof panel finds it
            finding.issue_id = issue.id
            if issue.confidence != "confirmed":
                issue_event(db, issue, "confirmed", from_value=issue.confidence, to_value="confirmed",
                            body=f"verification job #{job.id}")
                issue.confidence = "confirmed"
            if issue.status in ("fixed", "verified"):   # issues_from_findings would have reopened a non-info match
                _set_status(db, issue, "triaged", None, kind="reopened", body=f"Seen again: verification job #{job.id}")
        if issue.confidence != "verified":
            issue_event(db, issue, "confirmed", from_value=issue.confidence, to_value="verified",
                        body=f"Verified by job #{job.id}; proof captured.")
            issue.confidence = "verified"
        issue.verified_finding_id = finding.id
        p = proof_from_finding(finding)
        detail = f" (matcher {p['matcher']})" if p and p["matcher"] else ""
        body = f"Verified: job #{job.id} reproduced it{detail}. Proof captured."
    elif warnings:
        result = "inconclusive"
        body = f"Verification inconclusive: job #{job.id} had incomplete coverage ({warnings[0]})."
    else:
        result = "not_reproduced"
        body = f"Verification: job #{job.id} did not reproduce it. Decide whether it is fixed or a false positive."
        if issue.confidence == "verified":
            issue_event(db, issue, "confirmed", from_value="verified", to_value="confirmed",
                        body=f"Verification job #{job.id} did not reproduce it; confidence back to confirmed.")
            issue.confidence, issue.verified_finding_id = "confirmed", None
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
