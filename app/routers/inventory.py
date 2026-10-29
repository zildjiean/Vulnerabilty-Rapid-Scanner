from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import Host, Rule, RuleMatch, Service
from ..deps import get_db, verify_csrf
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
              db: Session = Depends(get_db)):
    rows, products, matches = load_inventory(db, q, product, port, only_matches)
    host_count = len({h.id for _, h in rows})
    return render(request, "inventory.html", active="inventory", rows=rows, products=products, matches=matches,
                  host_count=host_count, q=q, product=product, port=port, only_matches=only_matches)


@router.post("/inventory/to-nuclei", dependencies=[Depends(verify_csrf)])
def to_nuclei(request: Request, service_ids: list[int] = Form(default=[]), db: Session = Depends(get_db)):
    if not service_ids:
        rows, products, matches = load_inventory(db)
        return render(request, "inventory.html", status_code=400, active="inventory", rows=rows, products=products,
                      matches=matches, host_count=len({h.id for _, h in rows}), q="", product="", port="",
                      only_matches=False, error="Select at least one service to scan.")
    rows = db.execute(select(Service, Host).join(Host, Host.id == Service.host_id).where(Service.id.in_(service_ids))
                      .order_by(Host.address, Service.port)).all()
    targets = "\n".join(service_to_target(host.address, svc) for svc, host in rows)
    from .nuclei import nuclei_page_context  # local import: nuclei router imports inventory helpers
    return render(request, "nuclei.html", **nuclei_page_context(db, targets=targets))
