"""AI providers (admin) and AI usage."""
from __future__ import annotations

import json
from datetime import timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import ai
from ..audit import audit
from ..authz import require
from ..db import AiProvider, AiUsage, utcnow
from ..deps import get_db, verify_csrf
from ..llm import DEFAULT_MODELS, GEMINI_BASE_URL, PROVIDER_KINDS, LLMError, validate_provider
from ..render import render

router = APIRouter()
VIEW = [Depends(require("ai.manage"))]
MANAGE = [Depends(require("ai.manage")), Depends(verify_csrf)]


def _page(request: Request, db: Session, status_code: int = 200, error: str | None = None, form: dict | None = None):
    since = utcnow() - timedelta(days=30)
    summary = db.execute(select(AiUsage.provider_name, AiUsage.feature, func.count(), func.sum(AiUsage.input_tokens),
                                func.sum(AiUsage.output_tokens), func.sum(func.iif(AiUsage.ok, 0, 1)))
                         .where(AiUsage.created_at >= since).group_by(AiUsage.provider_name, AiUsage.feature)
                         .order_by(func.count().desc())).all()
    by_user = db.execute(select(AiUsage.username, func.count(), func.sum(AiUsage.input_tokens + AiUsage.output_tokens))
                         .where(AiUsage.created_at >= since).group_by(AiUsage.username)
                         .order_by(func.count().desc())).all()
    recent = list(db.scalars(select(AiUsage).order_by(AiUsage.id.desc()).limit(25)))
    return render(request, "ai.html", status_code=status_code, active="ai", error=error, form=form or {},
                  providers=list(db.scalars(select(AiProvider).order_by(AiProvider.id))), kinds=PROVIDER_KINDS,
                  summary=summary, by_user=by_user, recent=recent, default_models=DEFAULT_MODELS,
                  gemini_base=GEMINI_BASE_URL, config_of=lambda p: json.loads(p.config or "{}"))


def _fields(kind: str, model: str, base_url: str, api_version: str) -> dict:
    config = {"model": model.strip() or DEFAULT_MODELS.get(kind, ""), "base_url": base_url.strip().rstrip("/")}
    if kind == "azure_openai":
        config["api_version"] = api_version.strip()
    return config


def _max_tokens(value: str) -> int:
    n = int(value) if value.strip().isdigit() else 0
    if not 256 <= n <= 128000:
        raise ValueError("Max output tokens must be between 256 and 128000.")
    return n


@router.get("/ai", dependencies=VIEW)
def ai_page(request: Request, db: Session = Depends(get_db)):
    return _page(request, db)


@router.post("/ai/providers", dependencies=MANAGE)
def provider_create(request: Request, name: str = Form(""), kind: str = Form(""), model: str = Form(""),
                    base_url: str = Form(""), api_version: str = Form(""), api_key: str = Form(""),
                    max_tokens: str = Form("8000"), redact: bool = Form(False), db: Session = Depends(get_db)):
    form = {"name": name, "kind": kind, "model": model, "base_url": base_url, "api_version": api_version,
            "max_tokens": max_tokens, "redact": redact}
    config = _fields(kind, model, base_url, api_version)
    err = "Give the provider a name." if not name.strip() else validate_provider(kind, config, {"api_key": api_key.strip()})
    try:
        tokens = _max_tokens(max_tokens)
    except ValueError as e:
        err = err or str(e)
    if err:
        return _page(request, db, 400, err, form)
    first = db.scalar(select(func.count()).select_from(AiProvider)) == 0
    p = AiProvider(name=name.strip()[:64], kind=kind, config=json.dumps(config), max_tokens=tokens, redact=redact,
                   secret=request.app.state.secretbox.encrypt({"api_key": api_key.strip()}), enabled=True, is_default=first)
    db.add(p)
    db.commit()
    ai.refresh_ready(request.app)
    audit(db, request, "ai.provider_created", target=p.name, provider_id=p.id, kind=kind, model=config["model"], redact=redact)
    return RedirectResponse(f"/ai?msg=Provider+added.+Press+Test+to+check+the+key.#p{p.id}", status_code=303)


def _get(db: Session, pid: int) -> AiProvider:
    p = db.get(AiProvider, pid)
    if p is None:
        raise HTTPException(404)
    return p


@router.get("/ai/providers/{pid}", dependencies=VIEW)
def provider_edit_page(request: Request, pid: int, db: Session = Depends(get_db)):
    p = _get(db, pid)
    return render(request, "ai_provider.html", active="ai", p=p, config=json.loads(p.config or "{}"), kinds=PROVIDER_KINDS,
                  key_stored=bool(request.app.state.secretbox.decrypt(p.secret).get("api_key")))


@router.post("/ai/providers/{pid}", dependencies=MANAGE)
def provider_update(request: Request, pid: int, name: str = Form(""), model: str = Form(""), base_url: str = Form(""),
                    api_version: str = Form(""), api_key: str = Form(""), max_tokens: str = Form("8000"),
                    redact: bool = Form(False), db: Session = Depends(get_db)):
    p = _get(db, pid)
    box = request.app.state.secretbox
    config = _fields(p.kind, model, base_url, api_version)
    merged = box.merge(p.secret, {"api_key": api_key.strip()})
    err = "Give the provider a name." if not name.strip() else validate_provider(p.kind, config, box.decrypt(merged))
    try:
        tokens = _max_tokens(max_tokens)
    except ValueError as e:
        err = err or str(e)
    if err:
        return render(request, "ai_provider.html", status_code=400, active="ai", p=p, config=config, kinds=PROVIDER_KINDS,
                      key_stored=bool(box.decrypt(p.secret).get("api_key")), error=err)
    p.name, p.config, p.secret, p.max_tokens, p.redact = name.strip()[:64], json.dumps(config), merged, tokens, redact
    db.commit()
    audit(db, request, "ai.provider_updated", target=p.name, provider_id=p.id, model=config["model"], redact=redact,
          key_changed=bool(api_key.strip()))
    return RedirectResponse("/ai?msg=Provider+saved", status_code=303)


@router.post("/ai/providers/{pid}/default", dependencies=MANAGE)
def provider_default(request: Request, pid: int, db: Session = Depends(get_db)):
    p = _get(db, pid)
    for other in db.scalars(select(AiProvider)):
        other.is_default = other.id == p.id
    p.enabled = True
    db.commit()
    ai.refresh_ready(request.app)
    audit(db, request, "ai.provider_updated", target=p.name, provider_id=p.id, default=True)
    return RedirectResponse("/ai?msg=Default+provider+changed", status_code=303)


@router.post("/ai/providers/{pid}/toggle", dependencies=MANAGE)
def provider_toggle(request: Request, pid: int, db: Session = Depends(get_db)):
    p = _get(db, pid)
    p.enabled = not p.enabled
    db.commit()
    ai.refresh_ready(request.app)
    audit(db, request, "ai.provider_updated", target=p.name, provider_id=p.id, enabled=p.enabled)
    return RedirectResponse("/ai", status_code=303)


@router.post("/ai/providers/{pid}/delete", dependencies=MANAGE)
def provider_delete(request: Request, pid: int, db: Session = Depends(get_db)):
    p = _get(db, pid)
    name, was_default = p.name, p.is_default
    db.delete(p)
    db.flush()
    if was_default:
        nxt = db.scalar(select(AiProvider).order_by(AiProvider.id).limit(1))
        if nxt is not None:
            nxt.is_default = True
    db.commit()
    ai.refresh_ready(request.app)
    audit(db, request, "ai.provider_deleted", target=name, provider_id=pid)
    return RedirectResponse("/ai?msg=Provider+deleted", status_code=303)


@router.post("/ai/providers/{pid}/test", dependencies=MANAGE)
async def provider_test(request: Request, pid: int, db: Session = Depends(get_db)):
    p = _get(db, pid)
    try:
        result, _ = await ai.generate(request, db, "test", "You are a connectivity check.",
                                      "Reply with the single word OK.", effort="low", max_tokens=512, provider=p)
        ok, message = True, f"Model {result.model} answered: {result.text[:80]}"
    except LLMError as e:
        ok, message = False, str(e)
    p = _get(db, pid)
    p.last_test_at, p.last_test_ok, p.last_test_message = utcnow(), ok, message[:1000]
    db.commit()
    return RedirectResponse("/ai?msg=" + ("Test+succeeded" if ok else "Test+failed") + f"#p{pid}", status_code=303)
