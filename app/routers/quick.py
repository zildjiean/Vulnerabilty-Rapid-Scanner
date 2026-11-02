"""Quick scan page: targets + level, then nmap -> nuclei (preset) without any scanner options."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import quick
from ..audit import audit
from ..authz import require
from ..db import Job
from ..deps import get_db, get_runner, get_settings, verify_csrf
from ..render import render
from ..validation import parse_nmap_targets
from .jobs import job_summary

router = APIRouter()


def recent_quick_jobs(db: Session, limit: int = 10) -> list[Job]:
    """The latest Quick scans (both steps), newest first."""
    out = []
    for j in db.scalars(select(Job).where(Job.kind.in_(("nmap", "nuclei"))).order_by(Job.id.desc()).limit(200)):
        try:
            if isinstance(json.loads(j.params_json or "{}").get("quick"), dict):
                out.append(j)
        except (json.JSONDecodeError, AttributeError):
            continue
        if len(out) >= limit:
            break
    return out


def _count(targets: str) -> int:
    return len([t for t in targets.replace(",", "\n").splitlines() if t.strip()])


def _page(request: Request, db: Session, targets: str = "", level: str = quick.DEFAULT_LEVEL,
          error: str | None = None, status_code: int = 200):
    return render(request, "quick.html", status_code=status_code, active="quick", error=error,
                  form={"targets": targets, "level": level}, levels=quick.LEVELS,
                  summary=quick.summary(_count(targets), level), jobs=recent_quick_jobs(db), job_summary=job_summary,
                  preset_label=quick.preset_label)


@router.get("/quick")
def quick_page(request: Request, targets: str = "", db: Session = Depends(get_db)):
    """``targets`` pre-fills the form."""
    return _page(request, db, targets=targets[:200_000])


@router.post("/quick/scan", dependencies=[Depends(require("scan.run")), Depends(verify_csrf)])
async def quick_scan(request: Request, targets: str = Form(""), level: str = Form(quick.DEFAULT_LEVEL),
                     db: Session = Depends(get_db), settings=Depends(get_settings), runner=Depends(get_runner)):
    try:
        if level not in quick.LEVELS:
            raise ValueError("Invalid scan level. Choose Standard or Thorough.")
        target_list = parse_nmap_targets(targets)
        job = quick.launch_quick(db, settings, runner, target_list, level)
    except ValueError as e:
        return _page(request, db, targets=targets, level=level, error=str(e), status_code=400)
    audit(db, request, "scan.quick", target=", ".join(target_list), job_id=job.id, level=level)
    return RedirectResponse(f"/jobs/{job.id}", status_code=303)
