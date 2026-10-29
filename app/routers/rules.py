from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import Host, Rule, RuleMatch, Service
from ..deps import get_db, verify_csrf
from ..render import SEVERITIES, render
from ..rules import evaluate_rules, validate_rule

router = APIRouter()

EMPTY_RULE = {"name": "", "product_pattern": "", "version_constraint": "", "cve_id": "", "severity": "high", "description": "", "enabled": True}


def _matches(db: Session):
    stmt = (select(RuleMatch, Rule, Service, Host).join(Rule, Rule.id == RuleMatch.rule_id)
            .join(Service, Service.id == RuleMatch.service_id).join(Host, Host.id == Service.host_id)
            .order_by(Rule.severity, Host.address, Service.port))
    return db.execute(stmt).all()


def _rules_page(request: Request, db: Session, form: dict | None = None, error: str | None = None, status_code: int = 200):
    rules = list(db.scalars(select(Rule).order_by(Rule.id)))
    return render(request, "rules.html", status_code=status_code, active="rules", rules=rules, matches=_matches(db),
                  form=form or dict(EMPTY_RULE), error=error)


def _form_from(name, product_pattern, version_constraint, cve_id, severity, description, enabled) -> dict:
    return {"name": name.strip(), "product_pattern": product_pattern.strip(), "version_constraint": version_constraint.strip(),
            "cve_id": cve_id.strip(), "severity": severity if severity in SEVERITIES else "high",
            "description": description.strip(), "enabled": enabled}


def _validate_form(form: dict) -> str | None:
    if not form["name"]:
        return "Name is required."
    if not form["product_pattern"]:
        return "Product pattern is required."
    return validate_rule(form["product_pattern"], form["version_constraint"])


@router.get("/rules")
def rules_page(request: Request, db: Session = Depends(get_db)):
    return _rules_page(request, db)


@router.post("/rules", dependencies=[Depends(verify_csrf)])
def rules_create(request: Request, name: str = Form(""), product_pattern: str = Form(""), version_constraint: str = Form(""),
                 cve_id: str = Form(""), severity: str = Form("high"), description: str = Form(""), enabled: bool = Form(False),
                 db: Session = Depends(get_db)):
    form = _form_from(name, product_pattern, version_constraint, cve_id, severity, description, enabled)
    err = _validate_form(form)
    if err:
        return _rules_page(request, db, form=form, error=err, status_code=400)
    db.add(Rule(**form))
    db.commit()
    evaluate_rules(db)
    db.commit()
    return RedirectResponse("/rules?msg=Rule+created+and+evaluated", status_code=303)


@router.get("/rules/{rule_id}/edit")
def rule_edit_page(request: Request, rule_id: int, db: Session = Depends(get_db)):
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(404)
    form = {k: getattr(rule, k) for k in EMPTY_RULE}
    return render(request, "rule_form.html", active="rules", rule=rule, form=form)


@router.post("/rules/{rule_id}/edit", dependencies=[Depends(verify_csrf)])
def rule_edit(request: Request, rule_id: int, name: str = Form(""), product_pattern: str = Form(""), version_constraint: str = Form(""),
              cve_id: str = Form(""), severity: str = Form("high"), description: str = Form(""), enabled: bool = Form(False),
              db: Session = Depends(get_db)):
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(404)
    form = _form_from(name, product_pattern, version_constraint, cve_id, severity, description, enabled)
    err = _validate_form(form)
    if err:
        return render(request, "rule_form.html", status_code=400, active="rules", rule=rule, form=form, error=err)
    for k, v in form.items():
        setattr(rule, k, v)
    db.commit()
    evaluate_rules(db)
    db.commit()
    return RedirectResponse("/rules?msg=Rule+updated+and+evaluated", status_code=303)


@router.post("/rules/{rule_id}/toggle", dependencies=[Depends(verify_csrf)])
def rule_toggle(rule_id: int, db: Session = Depends(get_db)):
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(404)
    rule.enabled = not rule.enabled
    db.commit()
    evaluate_rules(db)
    db.commit()
    return RedirectResponse("/rules", status_code=303)


@router.post("/rules/{rule_id}/delete", dependencies=[Depends(verify_csrf)])
def rule_delete(rule_id: int, db: Session = Depends(get_db)):
    rule = db.get(Rule, rule_id)
    if rule is not None:
        db.delete(rule)
        db.commit()
    return RedirectResponse("/rules?msg=Rule+deleted", status_code=303)


@router.post("/rules/evaluate", dependencies=[Depends(verify_csrf)])
def rules_evaluate(db: Session = Depends(get_db)):
    n = evaluate_rules(db)
    db.commit()
    return RedirectResponse(f"/rules?msg={n}+match(es)+found", status_code=303)
