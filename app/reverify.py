"""Automatic re-verification: re-scan confirmed issues marked fixed and close the loop to verified / reopened."""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import AppSetting, Host, Issue, IssueEvent, Job, Service, TemplateIndex, utcnow

SETTINGS_KEY = "reverify"
DEFAULTS = {"enabled": True, "delay_minutes": 15}


def get_reverify_settings(db: Session) -> dict:
    row = db.get(AppSetting, SETTINGS_KEY)
    out = dict(DEFAULTS)
    if row and row.value:
        try:
            out.update(json.loads(row.value))
        except json.JSONDecodeError:
            pass
    return out


def set_reverify_settings(db: Session, enabled: bool, delay_minutes: int) -> None:
    if not 0 <= int(delay_minutes) <= 1440:
        raise ValueError("Re-verify delay must be between 0 and 1440 minutes.")
    row = db.get(AppSetting, SETTINGS_KEY) or AppSetting(key=SETTINGS_KEY)
    row.value = json.dumps({"enabled": bool(enabled), "delay_minutes": int(delay_minutes)})
    db.add(row)
    db.flush()


def _note(db: Session, issue: Issue, body: str) -> None:
    db.add(IssueEvent(issue_id=issue.id, kind="reverify", username="system", body=body))


def _target(db: Session, issue: Issue) -> str:
    from .routers.inventory import service_to_target
    svc = None
    if issue.port.isdigit():
        svc = db.scalar(select(Service).join(Host, Host.id == Service.host_id)
                        .where(Host.address == issue.address, Service.port == int(issue.port)))
    return service_to_target(issue.address, svc) if svc else issue.asset


def _cleanup_dead_jobs(db: Session) -> None:
    """Requests whose re-scan job failed or was cancelled are cleared with a note (the hook never ran)."""
    for issue in db.scalars(select(Issue).where(Issue.reverify_requested_at.is_not(None), Issue.reverify_job_id.is_not(None))):
        job = db.get(Job, issue.reverify_job_id)
        if job is not None and job.status in ("failed", "cancelled"):
            _note(db, issue, f"Re-verification job #{job.id} {job.status}; the issue stays fixed. Verify manually or re-run.")
            issue.reverify_requested_at, issue.reverify_job_id = None, None


async def run_reverify(app, now=None) -> list[int]:
    """Start re-scans for due requests, one nuclei job per template. Returns job ids started."""
    from .routers.nuclei import launch_nuclei
    from .scanners.nuclei_runner import PROFILES
    now = now or utcnow()
    started: list[int] = []
    with app.state.SessionLocal() as db:
        _cleanup_dead_jobs(db)
        cfg = get_reverify_settings(db)
        if not cfg["enabled"]:
            db.commit()
            return started
        due = list(db.scalars(select(Issue).where(
            Issue.status == "fixed", Issue.reverify_requested_at.is_not(None), Issue.reverify_job_id.is_(None),
            Issue.reverify_requested_at <= now - timedelta(minutes=cfg["delay_minutes"]))))
        by_path: dict[str, list[Issue]] = defaultdict(list)
        for issue in due:
            path = db.scalar(select(TemplateIndex.path).where(TemplateIndex.template_id == issue.template_id).limit(1))
            if path is None:
                _note(db, issue, f"Re-verification skipped: template {issue.template_id} is not in the template index.")
                issue.reverify_requested_at = None
                continue
            by_path[path].append(issue)
        prof = PROFILES["normal"]
        for path, issues in by_path.items():
            targets: list[str] = []
            for issue in issues:
                t = _target(db, issue)
                if t not in targets:
                    targets.append(t)
            params = {"targets": targets, "template_ids": [issues[0].template_id], "mode": "selected",
                      "profile": "normal", "reverify": [i.id for i in issues]}
            job = launch_nuclei(db, app.state.settings, app.state.job_runner, targets, [path], params,
                                rate_limit=prof["rate_limit"], timeout=prof["timeout"], extra_flags=[])
            for issue in issues:
                issue.reverify_job_id = job.id
                _note(db, issue, f"Re-verification scan started: job #{job.id}.")
            started.append(job.id)
        db.commit()
    return started


def complete_reverify(db: Session, job: Job, warnings: list[str]) -> int:
    """Called after a nuclei job's findings were ingested. Returns the number of issues verified."""
    from .issues import _set_status
    try:
        ids = json.loads(job.params_json or "{}").get("reverify") or []
    except json.JSONDecodeError:
        return 0
    verified = 0
    for issue in db.scalars(select(Issue).where(Issue.id.in_(ids))):
        if issue.reverify_job_id != job.id:
            continue
        if issue.status == "fixed":
            if warnings:
                _note(db, issue, f"Re-verification inconclusive: job #{job.id} had incomplete coverage "
                                 f"({warnings[0]}). The issue stays fixed.")
                issue.reverify_requested_at = None
            else:
                _set_status(db, issue, "verified", None, body=f"Re-scan job #{job.id} did not find it.")
                verified += 1
        else:  # reopened by the ingest because the re-scan saw it again
            issue.reverify_requested_at = None
        issue.reverify_job_id = None
    db.flush()
    return verified
