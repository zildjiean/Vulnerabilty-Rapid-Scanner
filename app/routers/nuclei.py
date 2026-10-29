from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import Finding, TemplateIndex
from ..deps import get_db, get_runner, get_settings, verify_csrf
from ..jobs import quote_argv
from ..render import SEVERITY_ORDER, render
from ..scanners.nuclei_runner import build_nuclei_argv, on_nuclei_complete, validate_template_paths, write_targets_file
from ..validation import parse_nuclei_targets
from .jobs import job_summary, recent_jobs

router = APIRouter()

DEFAULT_NUCLEI_FORM = {"targets": "", "selected": [], "rate_limit": 150, "timeout": 10}


def selected_from_paths(db: Session, paths: list[str]) -> list[dict]:
    """Rebuild the 'selected templates' list (for re-rendering the form) from template paths."""
    if not paths:
        return []
    rows = {t.path: t for t in db.scalars(select(TemplateIndex).where(TemplateIndex.path.in_(paths)))}
    out = []
    for p in paths:
        t = rows.get(p)
        out.append({"path": p, "template_id": t.template_id if t else p, "name": t.name if t else "",
                    "severity": t.severity if t else "unknown"})
    return out


def nuclei_page_context(db: Session, targets: str = "", selected=None, error: str | None = None, **extra) -> dict:
    form = dict(DEFAULT_NUCLEI_FORM)
    form["targets"] = targets
    form["selected"] = selected or []
    form.update(extra)
    return {"active": "nuclei", "form": form, "error": error, "jobs": recent_jobs(db, kind="nuclei"), "job_summary": job_summary}


@router.get("/nuclei")
def nuclei_page(request: Request, targets: str = "", db: Session = Depends(get_db)):
    return render(request, "nuclei.html", **nuclei_page_context(db, targets=targets))


@router.post("/nuclei/scan", dependencies=[Depends(verify_csrf)])
async def nuclei_scan(request: Request, targets: str = Form(""), template_paths: list[str] = Form(default=[]),
                      rate_limit: int = Form(150), timeout: int = Form(10),
                      db: Session = Depends(get_db), settings=Depends(get_settings), runner=Depends(get_runner)):
    selected = selected_from_paths(db, template_paths)

    def fail(msg: str):
        return render(request, "nuclei.html", status_code=400,
                      **nuclei_page_context(db, targets=targets, selected=selected, error=msg, rate_limit=rate_limit, timeout=timeout))

    try:
        paths = validate_template_paths(settings, template_paths)
        target_list = parse_nuclei_targets(targets)
    except ValueError as e:
        return fail(str(e))
    rate_limit = max(1, min(rate_limit, 1000))
    timeout = max(1, min(timeout, 120))
    template_ids = [s["template_id"] for s in selected]
    job = runner.create_job(db, "nuclei", [settings.nuclei_bin], params={"targets": target_list, "template_ids": template_ids})
    targets_file = write_targets_file(settings, job.id, target_list)
    argv = build_nuclei_argv(settings.nuclei_bin, paths, str(targets_file), str(settings.nuclei_templates_dir),
                             rate_limit=rate_limit, timeout=timeout)
    job.command = quote_argv(argv)
    db.commit()
    runner.start(job.id, argv, on_complete=on_nuclei_complete, stdout_to_log=True)
    return RedirectResponse(f"/jobs/{job.id}", status_code=303)


@router.get("/findings")
def findings_page(request: Request, job: int | None = None, severity: str = "", q: str = "", db: Session = Depends(get_db)):
    stmt = select(Finding).order_by(Finding.id.desc())
    if job:
        stmt = stmt.where(Finding.job_id == job)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    rows = list(db.scalars(stmt.limit(2000)))
    ql = q.strip().lower()
    if ql:
        rows = [f for f in rows if ql in " ".join([f.template_id, f.template_name, f.host, f.matched_at, f.extracted]).lower()]
    rows.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.id))
    jobs = recent_jobs(db, kind="nuclei", limit=50)
    return render(request, "findings.html", active="findings", findings=rows, job=job, severity=severity, q=q, jobs=jobs)
