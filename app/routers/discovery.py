"""External discovery: start subfinder (+ httpx) jobs, list discovered assets, hand them to nmap / nuclei, ignore."""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import discovery as dsc
from ..audit import audit
from ..authz import require
from ..db import DiscoveredAsset, Job, Scope, utcnow
from ..deps import get_db, get_runner, get_settings, verify_csrf
from ..render import render
from .jobs import job_summary

router = APIRouter()
MAX_AUDIT_NAMES = 20


def _int(value: str) -> int | None:
    value = (value or "").strip()
    return int(value) if value.isdigit() and int(value) > 0 else None


def filters(root: str = "", q: str = "", web: str = "", state: str = "", new: str = "") -> dict:
    return {"root": (root or "").strip().lower()[:253], "q": (q or "").strip()[:200],
            "web": web if web in dsc.WEB_FILTERS else "any", "state": state if state in dsc.STATES else "active",
            "new": new in ("1", "true", "on")}


def _params(f: dict) -> dict:
    out = {k: v for k, v in f.items() if v and k != "new" and not (k == "web" and v == "any")
           and not (k == "state" and v == "active")}
    if f["new"]:
        out["new"] = "1"
    return out


def _recent_jobs(db: Session, limit: int = 10) -> list[Job]:
    return list(db.scalars(select(Job).where(Job.kind.in_(("discovery", "discovery_probe")))
                           .order_by(Job.id.desc()).limit(limit)))


def _page(request: Request, db: Session, f: dict | None = None, page: str = "1", form: dict | None = None,
          error: str | None = None, status_code: int = 200):
    f = f or filters()
    stmt = dsc.query(f["root"], f["q"], f["web"], f["state"], f["new"])
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    pages = max(1, -(-total // dsc.PAGE_SIZE))
    page_n = min(_int(page) or 1, pages)
    rows = list(db.scalars(stmt.limit(dsc.PAGE_SIZE).offset((page_n - 1) * dsc.PAGE_SIZE)))
    roots = list(db.scalars(select(DiscoveredAsset.root_domain).distinct().order_by(DiscoveredAsset.root_domain)))
    scopes = {s.id: s.name for s in db.scalars(select(Scope))}
    params = _params(f)

    def page_url(n: int) -> str:
        return "/discovery?" + urlencode({**params, "page": n})

    return render(request, "discovery.html", status_code=status_code, active="discovery", rows=rows, total=total,
                  page=page_n, pages=pages, page_url=page_url, f=f, back="/discovery?" + urlencode(params),
                  roots=roots, scope_names=scopes, web_filters=dsc.WEB_FILTERS, states=dsc.STATES,
                  form=form or {"domains": "", "probe": True}, tools=dsc.tools_status(request.app.state.settings),
                  missing={t: dsc.missing_tool_message(request.app.state.settings, t) for t in ("subfinder", "httpx")},
                  jobs=_recent_jobs(db), job_summary=job_summary, max_roots=dsc.MAX_ROOTS, new_days=dsc.NEW_DAYS,
                  now=utcnow(), error=error)


@router.get("/discovery")
def discovery_page(request: Request, root: str = "", q: str = "", web: str = "", state: str = "", new: str = "",
                   page: str = "1", db: Session = Depends(get_db)):
    return _page(request, db, filters(root, q, web, state, new), page)


@router.post("/discovery/scan", dependencies=[Depends(require("scan.run")), Depends(verify_csrf)])
async def discovery_scan(request: Request, domains: str = Form(""), probe: bool = Form(False),
                         db: Session = Depends(get_db), settings=Depends(get_settings), runner=Depends(get_runner)):
    form = {"domains": domains, "probe": probe}
    try:
        roots = dsc.parse_root_domains(domains)
        job = dsc.launch_discovery(db, settings, runner, request.app.state.secretbox, roots, probe)
    except ValueError as e:
        return _page(request, db, form=form, error=str(e), status_code=400)
    audit(db, request, "scan.discovery", target=", ".join(roots), job_id=job.id, probe=probe)
    return RedirectResponse(f"/jobs/{job.id}", status_code=303)


def _selected(db: Session, asset_ids: list[int]) -> list[DiscoveredAsset]:
    if not asset_ids:
        return []
    return list(db.scalars(select(DiscoveredAsset).where(DiscoveredAsset.id.in_(asset_ids[:5000]))
                           .order_by(DiscoveredAsset.hostname)))


def _back(back: str, msg: str) -> RedirectResponse:
    """Only ever redirect to the discovery page itself (``back`` keeps the filters)."""
    target = back if back.startswith("/discovery?") or back == "/discovery" else "/discovery"
    sep = "&" if "?" in target else "?"
    return RedirectResponse(f"{target}{sep}{urlencode({'msg': msg})}", status_code=303)


def _prefill(path: str, targets: list[str]) -> RedirectResponse:
    return RedirectResponse(f"{path}?{urlencode({'targets': chr(10).join(targets)})}", status_code=303)


@router.post("/discovery/to-nmap", dependencies=[Depends(require("scan.run")), Depends(verify_csrf)])
def to_nmap(asset_ids: list[int] = Form(default=[]), back: str = Form("/discovery"), db: Session = Depends(get_db)):
    rows = _selected(db, asset_ids)
    if not rows:
        return _back(back, "Select at least one asset to scan.")
    return _prefill("/nmap", [a.hostname for a in rows])


@router.post("/discovery/to-nuclei", dependencies=[Depends(require("scan.run")), Depends(verify_csrf)])
def to_nuclei(asset_ids: list[int] = Form(default=[]), back: str = Form("/discovery"), db: Session = Depends(get_db)):
    rows = _selected(db, asset_ids)
    if not rows:
        return _back(back, "Select at least one asset to scan.")
    targets: list[str] = []
    for a in rows:
        t = dsc.nuclei_target(a)
        if t not in targets:
            targets.append(t)
    return _prefill("/nuclei", targets)


def _set_ignored(request: Request, db: Session, asset_ids: list[int], back: str, ignored: bool):
    rows = [a for a in _selected(db, asset_ids) if a.ignored != ignored]
    user = getattr(request.state.user, "username", "")
    now = utcnow()
    for a in rows:
        a.ignored = ignored
        a.ignored_by, a.ignored_at = (user[:64], now) if ignored else ("", None)
    db.commit()
    names = [a.hostname for a in rows]
    action = "discovery.ignore" if ignored else "discovery.unignore"
    audit(db, request, action, target=f"{len(rows)} asset(s)", count=len(rows),
          hostnames=", ".join(names[:MAX_AUDIT_NAMES]) + (" …" if len(names) > MAX_AUDIT_NAMES else ""))
    return _back(back, f"{'Ignored' if ignored else 'Restored'} {len(rows)} asset(s)")


@router.post("/discovery/ignore", dependencies=[Depends(require("issues.manage")), Depends(verify_csrf)])
def discovery_ignore(request: Request, asset_ids: list[int] = Form(default=[]), back: str = Form("/discovery"),
                     db: Session = Depends(get_db)):
    return _set_ignored(request, db, asset_ids, back, True)


@router.post("/discovery/unignore", dependencies=[Depends(require("issues.manage")), Depends(verify_csrf)])
def discovery_unignore(request: Request, asset_ids: list[int] = Form(default=[]), back: str = Form("/discovery"),
                       db: Session = Depends(get_db)):
    return _set_ignored(request, db, asset_ids, back, False)
