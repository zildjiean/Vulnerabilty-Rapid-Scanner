from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import TemplateIndex
from ..deps import get_db, get_settings, verify_csrf
from ..render import render
from .. import templates_index as ti
from ..templates_index import (count_templates, fetch_template_from_url, index_single, is_custom_path, reindex,
                               remove_from_index, save_custom_template, search_templates)

router = APIRouter()


async def reindex_in_background(app) -> None:
    if getattr(app.state, "indexing", False):
        return
    app.state.indexing = True
    try:
        def _work():
            with app.state.SessionLocal() as db:
                return reindex(db, app.state.settings)
        app.state.last_index_counts = await asyncio.to_thread(_work)
    finally:
        app.state.indexing = False


async def nuclei_validate(settings, path: Path) -> tuple[bool, str]:
    """Run `nuclei -validate` on one template; returns (ok, last_output_line)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            settings.nuclei_bin, "-validate", "-t", str(path), "-ud", str(settings.nuclei_templates_dir),
            "-disable-update-check", "-no-color",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
    except FileNotFoundError:
        return True, "nuclei binary not found; skipped engine validation"
    except asyncio.TimeoutError:
        return False, "nuclei -validate timed out"
    text = out.decode("utf-8", "replace").strip()
    last = text.splitlines()[-1] if text else ""
    return proc.returncode == 0, last


def _page(request: Request, db: Session, settings, q: str = "", severity: str = "", error: str | None = None, status_code: int = 200):
    custom = list(db.scalars(select(TemplateIndex).where(TemplateIndex.source == "custom").order_by(TemplateIndex.template_id)))
    results = search_templates(db, q, severity=severity) if q else []
    return render(request, "templates.html", status_code=status_code, active="templates", counts=count_templates(db),
                  indexing=getattr(request.app.state, "indexing", False), custom=custom, q=q, severity=severity,
                  results=results, error=error, templates_dir=str(settings.nuclei_templates_dir),
                  templates_dir_exists=settings.nuclei_templates_dir.is_dir())


@router.get("/templates")
def templates_page(request: Request, q: str = "", severity: str = "", db: Session = Depends(get_db), settings=Depends(get_settings)):
    return _page(request, db, settings, q=q, severity=severity)


@router.get("/templates/search")
def templates_search(q: str = "", severity: str = "", source: str = "", db: Session = Depends(get_db)):
    rows = search_templates(db, q, severity=severity, source=source)
    return JSONResponse([{"template_id": r.template_id, "name": r.name, "severity": r.severity, "tags": r.tags,
                          "cve_ids": r.cve_ids, "source": r.source, "path": r.path} for r in rows])


@router.post("/templates/reindex", dependencies=[Depends(verify_csrf)])
async def templates_reindex(request: Request):
    asyncio.get_running_loop().create_task(reindex_in_background(request.app))
    return RedirectResponse("/templates?msg=Re-indexing+started", status_code=303)


@router.post("/templates/upload", dependencies=[Depends(verify_csrf)])
async def templates_upload(request: Request, files: list[UploadFile], db: Session = Depends(get_db), settings=Depends(get_settings)):
    saved, errors = [], []
    for f in files:
        raw = await f.read()
        text = raw.decode("utf-8", "replace")
        try:
            path = save_custom_template(settings, text)
        except ValueError as e:
            errors.append(f"{f.filename}: {e}")
            continue
        ok, line = await nuclei_validate(settings, path)
        if not ok:
            path.unlink(missing_ok=True)
            errors.append(f"{f.filename}: nuclei validation failed: {line}")
            continue
        index_single(db, path, "custom")
        saved.append(path.name)
    if errors:
        return _page(request, db, settings, error="; ".join(errors), status_code=400)
    return RedirectResponse(f"/templates?msg=Saved+{len(saved)}+template(s)", status_code=303)


@router.post("/templates/pull", dependencies=[Depends(verify_csrf)])
async def templates_pull(request: Request, url: str = Form(""), db: Session = Depends(get_db), settings=Depends(get_settings)):
    try:
        text = await asyncio.to_thread(fetch_template_from_url, url.strip(), ti.http_fetch)
        path = save_custom_template(settings, text)
    except ValueError as e:
        return _page(request, db, settings, error=str(e), status_code=400)
    ok, line = await nuclei_validate(settings, path)
    if not ok:
        path.unlink(missing_ok=True)
        return _page(request, db, settings, error=f"nuclei validation failed: {line}", status_code=400)
    index_single(db, path, "custom")
    return RedirectResponse(f"/templates?msg=Pulled+{path.name}", status_code=303)


@router.post("/templates/delete", dependencies=[Depends(verify_csrf)])
def templates_delete(request: Request, path: str = Form(""), db: Session = Depends(get_db), settings=Depends(get_settings)):
    if not is_custom_path(settings, path):
        return _page(request, db, settings, error="Only custom templates can be deleted.", status_code=400)
    p = Path(path)
    p.unlink(missing_ok=True)
    remove_from_index(db, p)
    return RedirectResponse(f"/templates?msg=Deleted+{p.name}", status_code=303)
