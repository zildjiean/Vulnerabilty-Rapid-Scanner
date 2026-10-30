from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..audit import audit
from ..authz import require
from ..deps import get_db, get_settings, verify_csrf
from ..render import render
from ..templates_index import count_templates
from ..updates import UPDATE_ACTIONS, build_update_argv, templates_info, tool_versions
from .jobs import job_summary, recent_jobs
from .templates import reindex_in_background

router = APIRouter()


def start_update_job(app, db: Session, action: str):
    """Create and start an update job; after a templates update, re-index in the background."""
    settings, runner = app.state.settings, app.state.job_runner
    argv = build_update_argv(settings, action)
    job = runner.create_job(db, "update", argv, params={"action": action})
    task = runner.start(job.id, argv, stdout_to_log=True)
    if action == "nuclei-templates":
        task.add_done_callback(lambda _t: asyncio.get_running_loop().create_task(reindex_in_background(app)))
    return job


@router.get("/updates")
async def updates_page(request: Request, db: Session = Depends(get_db), settings=Depends(get_settings)):
    versions = await tool_versions(settings)
    return render(request, "updates.html", active="updates", versions=versions, templates=templates_info(settings),
                  counts=count_templates(db), actions=UPDATE_ACTIONS, jobs=recent_jobs(db, kind="update"), job_summary=job_summary,
                  indexing=getattr(request.app.state, "indexing", False))


@router.post("/updates/{action}", dependencies=[Depends(require("system.update")), Depends(verify_csrf)])
async def updates_run(request: Request, action: str, db: Session = Depends(get_db)):
    if action not in UPDATE_ACTIONS:
        raise HTTPException(404)
    job = start_update_job(request.app, db, action)
    audit(db, request, "system.update", target=action, job_id=job.id)
    return RedirectResponse(f"/jobs/{job.id}", status_code=303)
