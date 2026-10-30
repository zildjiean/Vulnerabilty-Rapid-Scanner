"""Scopes: named asset groups with owner and criticality; their assets, open issues and schedules."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..audit import audit
from ..authz import require
from ..db import Host, Issue, Schedule, Scope, Service, User
from ..deps import get_db, verify_csrf
from ..issues import ACTIVE
from ..render import render
from ..scopes import CRITICALITIES, Matcher, _split, rescope_issues, validate_scope_fields
from .issues import assignable_users
from .schedules import schedule_form_context

router = APIRouter()
MANAGE = [Depends(require("scopes.manage")), Depends(verify_csrf)]


def _get(db: Session, sid: int) -> Scope:
    s = db.get(Scope, sid)
    if s is None:
        raise HTTPException(404)
    return s


def scope_hosts(db: Session, scope: Scope) -> list[tuple[Host, int]]:
    include, exclude = Matcher.parse(_split(scope.targets)), Matcher.parse(_split(scope.exclusions))
    counts = dict(db.execute(select(Service.host_id, func.count()).group_by(Service.host_id)).all())
    return [(h, counts.get(h.id, 0)) for h in db.scalars(select(Host).order_by(Host.address))
            if include.matches(h.address, h.hostname or "") and not exclude.matches(h.address, h.hostname or "")]


@router.get("/scopes")
def scopes_page(request: Request, db: Session = Depends(get_db)):
    open_counts = dict(db.execute(select(Issue.scope_id, func.count()).where(Issue.status.in_(ACTIVE))
                                  .group_by(Issue.scope_id)).all())
    sched_counts = dict(db.execute(select(Schedule.scope_id, func.count()).group_by(Schedule.scope_id)).all())
    rows = [(s, len(scope_hosts(db, s)), open_counts.get(s.id, 0), sched_counts.get(s.id, 0))
            for s in db.scalars(select(Scope).order_by(Scope.name))]
    rows.sort(key=lambda r: (CRITICALITIES.index(r[0].criticality) if r[0].criticality in CRITICALITIES else 9, r[0].name))
    return render(request, "scopes.html", active="scopes", rows=rows, split=_split)


def _form(request: Request, db: Session, scope: Scope | None, form: dict, status_code: int = 200, error=None):
    tpl = "scope_detail.html" if scope else "scope_new.html"
    ctx = dict(active="scopes", scope=scope, form=form, error=error, users=assignable_users(db),
               criticalities=CRITICALITIES)
    if scope:
        ctx.update(hosts=scope_hosts(db, scope),
                   issues=list(db.scalars(select(Issue).where(Issue.scope_id == scope.id, Issue.status.in_(ACTIVE))
                                          .order_by(Issue.due_at).limit(50))),
                   **schedule_form_context(db, scope_filter=scope.id))
    return render(request, tpl, status_code=status_code, **ctx)


def _form_values(name, description, targets, exclusions, criticality, owner_id) -> dict:
    return {"name": name.strip(), "description": description.strip(), "targets": targets.strip(),
            "exclusions": exclusions.strip(), "criticality": criticality, "owner_id": owner_id}


def _validate(db: Session, form: dict, current: Scope | None) -> str | None:
    err = validate_scope_fields(form["name"], form["targets"], form["exclusions"], form["criticality"])
    if err:
        return err
    clash = db.scalar(select(Scope).where(func.lower(Scope.name) == form["name"].lower()))
    if clash is not None and (current is None or clash.id != current.id):
        return f"A scope named '{form['name']}' already exists."
    if form["owner_id"] and (not form["owner_id"].isdigit() or db.get(User, int(form["owner_id"])) not in assignable_users(db)):
        return "The owner must be an active admin or analyst."
    return None


def _apply(scope: Scope, form: dict) -> None:
    scope.name, scope.description = form["name"][:128], form["description"]
    scope.targets, scope.exclusions, scope.criticality = form["targets"], form["exclusions"], form["criticality"]
    scope.owner_id = int(form["owner_id"]) if form["owner_id"] else None


@router.get("/scopes/new", dependencies=[Depends(require("scopes.manage"))])
def scope_new(request: Request, db: Session = Depends(get_db)):
    return _form(request, db, None, _form_values("", "", "", "", "medium", ""))


@router.post("/scopes", dependencies=MANAGE)
def scope_create(request: Request, name: str = Form(""), description: str = Form(""), targets: str = Form(""),
                 exclusions: str = Form(""), criticality: str = Form("medium"), owner_id: str = Form(""),
                 db: Session = Depends(get_db)):
    form = _form_values(name, description, targets, exclusions, criticality, owner_id)
    err = _validate(db, form, None)
    if err:
        return _form(request, db, None, form, 400, err)
    scope = Scope()
    _apply(scope, form)
    db.add(scope)
    db.flush()
    n = rescope_issues(db)
    db.commit()
    audit(db, request, "scope.created", target=scope.name, scope_id=scope.id, criticality=scope.criticality,
          targets=scope.targets[:200], issues_rescoped=n)
    return RedirectResponse(f"/scopes/{scope.id}?msg=Scope+created", status_code=303)


@router.get("/scopes/{sid}")
def scope_detail(request: Request, sid: int, db: Session = Depends(get_db)):
    scope = _get(db, sid)
    return _form(request, db, scope, {"name": scope.name, "description": scope.description, "targets": scope.targets,
                                      "exclusions": scope.exclusions, "criticality": scope.criticality,
                                      "owner_id": str(scope.owner_id or "")})


@router.post("/scopes/{sid}", dependencies=MANAGE)
def scope_update(request: Request, sid: int, name: str = Form(""), description: str = Form(""), targets: str = Form(""),
                 exclusions: str = Form(""), criticality: str = Form("medium"), owner_id: str = Form(""),
                 db: Session = Depends(get_db)):
    scope = _get(db, sid)
    form = _form_values(name, description, targets, exclusions, criticality, owner_id)
    err = _validate(db, form, scope)
    if err:
        return _form(request, db, scope, form, 400, err)
    _apply(scope, form)
    db.flush()
    n = rescope_issues(db)
    db.commit()
    audit(db, request, "scope.updated", target=scope.name, scope_id=scope.id, criticality=scope.criticality,
          targets=scope.targets[:200], issues_rescoped=n)
    return RedirectResponse(f"/scopes/{sid}?msg=Scope+saved", status_code=303)


@router.post("/scopes/{sid}/delete", dependencies=MANAGE)
def scope_delete(request: Request, sid: int, db: Session = Depends(get_db)):
    scope = _get(db, sid)
    name = scope.name
    for s in db.scalars(select(Schedule).where(Schedule.scope_id == sid)):
        db.delete(s)
    db.delete(scope)
    db.flush()
    rescope_issues(db)
    db.commit()
    audit(db, request, "scope.deleted", target=name, scope_id=sid)
    return RedirectResponse(f"/scopes?msg=Deleted+{name.replace(' ', '+')}", status_code=303)
