from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import Job
from ..audit import audit
from ..authz import require
from ..deps import get_db, get_runner, verify_csrf
from ..i18n import current_lang, request_lang, translate
from ..render import render

router = APIRouter()


def recent_jobs(db: Session, kind: str | None = None, limit: int = 20) -> list[Job]:
    stmt = select(Job).order_by(Job.id.desc()).limit(limit)
    if kind:
        stmt = stmt.where(Job.kind == kind)
    return list(db.scalars(stmt))


def _result_value(value) -> str:
    """A bulk verification result {"reproduced": 1, "not_reproduced": 2} reads "reproduced 1, not reproduced 2"."""
    if isinstance(value, dict):
        from ..proof import VERIFY_LABELS
        return ", ".join(f"{VERIFY_LABELS.get(k, k)} {n}" for k, n in value.items())
    return str(value)


def job_summary(job: Job, lang: str | None = None) -> str:
    """One-line description of a job's parameters, in ``lang`` (default: the page being rendered)."""
    lang = lang or current_lang()

    def t(text, **params):
        return translate(lang, text, **params)

    try:
        p = json.loads(job.params_json or "{}")
    except json.JSONDecodeError:
        p = {}
    targets = p.get("targets") or []
    tpl = p.get("template_ids") or []
    parts = []

    def listed(n, items):
        return ", ".join(items[:3]) + ("…" if len(items) > 3 else "")

    domains = p.get("domains") or []
    if domains:
        parts.append(t("{n} domain(s): {items}", n=len(domains), items=listed(len(domains), domains)))
        if p.get("probe") is False:
            parts.append(t("no web probe"))
    quick = p.get("quick") if isinstance(p.get("quick"), dict) else None
    if quick and quick.get("step") == 2:
        targets = []  # the head already counts them
    if p.get("parent_job"):
        parts.append(t("web probe of {hosts} host(s) from discovery job #{job}", hosts=p.get("hosts", 0),
                       job=p["parent_job"]))
    if targets:
        parts.append(t("{n} target(s): {items}", n=len(targets), items=listed(len(targets), targets)))
    mode = p.get("mode")
    preset = p.get("preset")
    if preset and preset != "custom":
        from ..nuclei_presets import preset_label
        parts.append(t("{preset} preset", preset=t(preset_label(preset))))
    if mode == "all":
        parts.append(t("all templates"))
    elif mode == "groups":
        groups = p.get("groups") or []
        parts.append(t("{n} group(s): {items}", n=len(groups), items=listed(len(groups), groups)))
    elif tpl:
        parts.append(t("{n} template(s): {items}", n=len(tpl), items=listed(len(tpl), tpl)))
    if p.get("profile") and p["profile"] != "normal":
        parts.append(t("{profile} profile", profile=p["profile"]))
    if p.get("tags"):
        parts.append(t("tags {tags}", tags=",".join(p["tags"])))
    if p.get("severities"):
        parts.append(t("severity {severities}", severities=",".join(p["severities"])))
    if p.get("action"):
        parts.append(p["action"])
    if p.get("campaign"):
        parts.append(t("campaign {name}", name=str(p["campaign"])))
    if p.get("schedule"):
        parts.append(t("scheduled: {name}", name=str(p["schedule"])))
    result = p.get("result")
    if isinstance(result, dict):
        parts.append(", ".join(f"{k} {_result_value(v)}" for k, v in result.items()))
    text = " · ".join(parts)
    if quick:
        if quick.get("step") == 2:
            head = t("Quick scan step 2/2: nuclei on {n} service(s) from job #{job}", n=len(p.get("targets") or []),
                     job=quick.get("parent_job"))
        else:
            head = t("Quick scan step 1/2: nmap")
        text = head + (" · " + text if text else "")
    return text


@router.get("/jobs")
def jobs_list(request: Request, db: Session = Depends(get_db)):
    jobs = recent_jobs(db, limit=200)
    return render(request, "jobs.html", active="jobs", jobs=jobs, job_summary=job_summary)


@router.get("/jobs/{job_id}")
def job_detail(request: Request, job_id: int, db: Session = Depends(get_db), runner=Depends(get_runner)):
    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(404)
    live = runner.is_live(job_id)
    log = "\n".join(runner.live_log(job_id)) if live else job.log
    try:
        params = json.loads(job.params_json or "{}")
    except json.JSONDecodeError:
        params = {}
    from ..ai import latest_note
    changes = None
    if job.kind in ("nmap", "discovery"):
        from .. import surface
        counts = surface.job_counts(db, job.id)
        rows = list(db.scalars(surface.query(db, days="all", job_id=job.id, state="all").limit(20)))
        changes = {"counts": counts, "rows": rows, "total": sum(counts.values()), "labels": surface.KIND_LABELS}
    quick = params.get("quick") if isinstance(params, dict) and isinstance(params.get("quick"), dict) else None
    return render(request, "job_detail.html", active="jobs", job=job, log=log, live=live, params=params, quick=quick,
                  summary=job_summary(job, request_lang(request)),
                  ai_diagnosis=latest_note(db, "diagnose", "job", job.id), changes=changes)


@router.get("/jobs/{job_id}/status")
def job_status(job_id: int, db: Session = Depends(get_db)):
    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(404)
    return JSONResponse({"id": job.id, "kind": job.kind, "status": job.status, "exit_code": job.exit_code})


@router.post("/jobs/{job_id}/cancel", dependencies=[Depends(require("scan.run")), Depends(verify_csrf)])
def job_cancel(request: Request, job_id: int, runner=Depends(get_runner), db: Session = Depends(get_db)):
    runner.cancel(job_id)
    audit(db, request, "job.cancelled", target=f"job #{job_id}", job_id=job_id)
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


def _sse(event: str, data: str) -> str:
    payload = "\n".join(f"data: {line}" for line in (data.split("\n") or [""]))
    return f"event: {event}\n{payload}\n\n"


@router.get("/jobs/{job_id}/stream")
async def job_stream(request: Request, job_id: int, runner=Depends(get_runner)):
    async def gen():
        with request.app.state.SessionLocal() as db:
            job = db.get(Job, job_id)
            if job is None:
                yield _sse("error", "job not found")
                return
            status, stored_log = job.status, job.log
        q = runner.subscribe(job_id)
        try:
            if not runner.is_live(job_id):
                runner.unsubscribe(job_id, q)
                for line in stored_log.splitlines():
                    yield _sse("log", line)
                yield _sse("done", status)
                return
            snapshot = runner.live_log(job_id)
            for line in snapshot:
                yield _sse("log", line)
            next_idx = len(snapshot)
            while True:
                try:
                    item = await asyncio.wait_for(q.get(), timeout=15)
                except asyncio.TimeoutError:
                    if await request.is_disconnected():
                        return
                    yield ": ping\n\n"
                    continue
                if item is None:
                    break
                idx, line = item
                if idx < next_idx:
                    continue
                next_idx = idx + 1
                yield _sse("log", line)
            with request.app.state.SessionLocal() as db:
                job = db.get(Job, job_id)
                yield _sse("done", job.status if job else "done")
        finally:
            runner.unsubscribe(job_id, q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
