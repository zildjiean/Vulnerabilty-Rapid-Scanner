from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import Host, Rule, RuleMatch, Service
from ..audit import audit
from ..authz import require
from ..deps import get_db, verify_csrf
from ..inventory_groups import DEFAULT_GROUP, GROUP_LABELS, group_rows, normalize_group_mode
from ..render import render

router = APIRouter()

HTTP_NAMES = {"http", "http-proxy", "http-alt", "www", "www-http", "webcache", "http-mgmt"}
HTTPS_NAMES = {"https", "https-alt", "ssl/http", "ssl"}


def service_to_target(address: str, svc) -> str:
    name = (svc.service_name or "").lower()
    if ((svc.tunnel or "") == "ssl" and name in HTTP_NAMES) or name in HTTPS_NAMES:
        return f"https://{address}:{svc.port}"
    if name in HTTP_NAMES:
        return f"http://{address}:{svc.port}"
    return f"{address}:{svc.port}"


def rule_matches_by_service(db: Session) -> dict[int, list[tuple[RuleMatch, Rule]]]:
    out: dict[int, list[tuple[RuleMatch, Rule]]] = {}
    for m, r in db.execute(select(RuleMatch, Rule).join(Rule, Rule.id == RuleMatch.rule_id)).all():
        out.setdefault(m.service_id, []).append((m, r))
    return out


def load_inventory(db: Session, q: str = "", product: str = "", port: str = "", only_matches: bool = False):
    rows = db.execute(select(Service, Host).join(Host, Host.id == Service.host_id).order_by(Host.address, Service.port)).all()
    matches = rule_matches_by_service(db)
    products = sorted({s.product for s, _ in rows if s.product})
    ql = q.strip().lower()
    out = []
    for svc, host in rows:
        if product and svc.product != product:
            continue
        if port and str(svc.port) != port.strip():
            continue
        if only_matches and svc.id not in matches:
            continue
        if ql:
            hay = " ".join([host.address, host.hostname or "", svc.service_name, svc.product, svc.version, svc.cpe, svc.extra_info]).lower()
            if ql not in hay:
                continue
        out.append((svc, host))
    return out, products, matches


@router.get("/inventory")
def inventory(request: Request, q: str = "", product: str = "", port: str = "", only_matches: bool = False,
              group: str = DEFAULT_GROUP, db: Session = Depends(get_db)):
    rows, products, matches = load_inventory(db, q, product, port, only_matches)
    group_mode = normalize_group_mode(group)
    scope_of = None
    if group_mode == "scope":
        from ..scopes import scope_of_hosts
        scope_of = scope_of_hosts(db)
    return render(request, "inventory.html", active="inventory", rows=rows, products=products, matches=matches,
                  host_count=len({h.id for _, h in rows}), q=q, product=product, port=port, only_matches=only_matches,
                  group_mode=group_mode, group_labels=GROUP_LABELS, groups=group_rows(rows, group_mode, matches, scope_of))


@router.post("/inventory/to-nuclei", dependencies=[Depends(require("scan.run")), Depends(verify_csrf)])
def to_nuclei(request: Request, service_ids: list[int] = Form(default=[]), db: Session = Depends(get_db)):
    if not service_ids:
        return _inventory_error(request, db, "Select at least one service to scan.")
    rows = db.execute(select(Service, Host).join(Host, Host.id == Service.host_id).where(Service.id.in_(service_ids))
                      .order_by(Host.address, Service.port)).all()
    targets = "\n".join(service_to_target(host.address, svc) for svc, host in rows)
    from .nuclei import nuclei_page_context  # local import: nuclei router imports inventory helpers
    return render(request, "nuclei.html", **nuclei_page_context(db, targets=targets, settings=request.app.state.settings))


def _inventory_error(request: Request, db: Session, message: str):
    rows, products, matches = load_inventory(db)
    return render(request, "inventory.html", status_code=400, active="inventory", rows=rows, products=products,
                  matches=matches, host_count=len({h.id for _, h in rows}), q="", product="", port="",
                  only_matches=False, error=message, group_mode=DEFAULT_GROUP, group_labels=GROUP_LABELS,
                  groups=group_rows(rows, DEFAULT_GROUP, matches))


def delete_services(db: Session, service_ids: list[int]) -> tuple[int, int]:
    """Delete the given services; hosts left without any service are removed too. Returns (services, hosts)."""
    services = list(db.scalars(select(Service).where(Service.id.in_(service_ids))))
    host_ids = {s.host_id for s in services}
    for s in services:
        db.delete(s)
    db.flush()
    removed_hosts = 0
    for host in db.scalars(select(Host).where(Host.id.in_(host_ids))):
        if not host.services:
            db.delete(host)
            removed_hosts += 1
    db.commit()
    return len(services), removed_hosts


@router.post("/inventory/delete", dependencies=[Depends(require("inventory.manage")), Depends(verify_csrf)])
def inventory_delete(request: Request, service_ids: list[int] = Form(default=[]), db: Session = Depends(get_db)):
    if not service_ids:
        return _inventory_error(request, db, "Select at least one service to delete.")
    n_services, n_hosts = delete_services(db, service_ids)
    audit(db, request, "inventory.deleted", target=f"{n_services} service(s)", services=n_services, hosts=n_hosts)
    msg = f"Deleted {n_services} service(s)" + (f" and {n_hosts} host(s) with no remaining services" if n_hosts else "")
    return RedirectResponse(f"/inventory?msg={msg.replace(' ', '+')}", status_code=303)


@router.post("/inventory/clear", dependencies=[Depends(require("inventory.manage")), Depends(verify_csrf)])
def inventory_clear(request: Request, db: Session = Depends(get_db)):
    hosts = list(db.scalars(select(Host)))
    for h in hosts:
        db.delete(h)
    db.commit()
    audit(db, request, "inventory.cleared", target=f"{len(hosts)} host(s)", hosts=len(hosts))
    return RedirectResponse(f"/inventory?msg=Removed+{len(hosts)}+host(s)+from+the+inventory", status_code=303)
