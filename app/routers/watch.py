"""0-day watch page: last run, settings, Check now, and the CVEs that matched the inventory."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import watch as w
from ..audit import audit
from ..authz import require
from ..db import CveIntel, WatchHit
from ..deps import get_db, verify_csrf
from ..render import render

router = APIRouter()


def _page(request: Request, db: Session, status_code: int = 200, error: str | None = None):
    hits = w.recent_hits(db)
    cves = [h.cve_id for h, *_rest in hits]
    epss = {r.cve_id: r for r in db.scalars(select(CveIntel).where(CveIntel.cve_id.in_(cves)))} if cves else {}
    return render(request, "watch.html", status_code=status_code, active="watch", error=error, cfg=w.load_state(db),
                  last=w.last_run(db), running=getattr(request.app.state, "watch_running", False), hits=hits, epss=epss)


@router.get("/watch")
def watch_page(request: Request, db: Session = Depends(get_db)):
    return _page(request, db)


@router.post("/watch/settings", dependencies=[Depends(require("settings.manage")), Depends(verify_csrf)])
def watch_settings(request: Request, enabled: bool = Form(False), min_cvss: str = Form("7.0"),
                   kev_always: bool = Form(False), include_possible: bool = Form(False), max_drafts: str = Form("20"),
                   db: Session = Depends(get_db)):
    try:
        cfg = w.set_watch_settings(db, enabled, min_cvss, kev_always, include_possible, max_drafts)
    except ValueError as e:
        db.rollback()
        return _page(request, db, 400, str(e))
    db.commit()
    audit(db, request, "settings.updated", target="0-day watch", enabled=cfg["enabled"], min_cvss=cfg["min_cvss"],
          kev_always=cfg["kev_always"], include_possible=cfg["include_possible"], max_drafts=cfg["max_drafts"])
    return RedirectResponse("/watch?msg=0-day+watch+settings+saved", status_code=303)


@router.post("/watch/hits/{hid}/draft", dependencies=[Depends(require("campaigns.manage")), Depends(verify_csrf)])
def watch_draft_now(request: Request, hid: int, db: Session = Depends(get_db)):
    """Draft one hit immediately, whatever the per-run cap."""
    hit = db.get(WatchHit, hid)
    if hit is None:
        raise HTTPException(404)
    try:
        c = w.draft_hit(db, hit)
    except ValueError as e:
        db.rollback()
        return _page(request, db, 400, str(e))
    db.commit()
    audit(db, request, "watch.draft_now", target=c.name, campaign_id=c.id, cve=c.cve_id)
    return RedirectResponse(f"/campaigns/{c.id}?msg=Draft+created", status_code=303)


@router.post("/watch/run", dependencies=[Depends(require("campaigns.manage")), Depends(verify_csrf)])
async def watch_run(request: Request, db: Session = Depends(get_db)):
    if w.start_watch(request.app) is None:
        return RedirectResponse("/watch?msg=A+0-day+watch+run+is+already+in+progress", status_code=303)
    audit(db, request, "watch.run_started", target="0-day watch")
    return RedirectResponse("/watch?msg=0-day+watch+started.+Reload+in+a+minute+for+the+result", status_code=303)
