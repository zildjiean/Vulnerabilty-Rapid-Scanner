"""AI assist service: provider selection, redaction, the call itself, usage accounting, notes."""
from __future__ import annotations

import asyncio
import json
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from .ai_redact import Redactor
from .audit import audit
from .db import AiNote, AiProvider, AiUsage, Host, Issue
from .llm import LLMError, LLMRequest, LLMResult


def default_provider(db: Session) -> AiProvider | None:
    enabled = list(db.scalars(select(AiProvider).where(AiProvider.enabled.is_(True)).order_by(AiProvider.id)))
    return next((p for p in enabled if p.is_default), enabled[0] if enabled else None)


def refresh_ready(app) -> None:
    with app.state.SessionLocal() as db:
        app.state.ai_ready = default_provider(db) is not None


def known_hosts(db: Session) -> list[str]:
    names: set[str] = set()
    for address, hostname in db.execute(select(Host.address, Host.hostname)):
        names.update(x for x in (address, hostname) if x)
    for address, hostname in db.execute(select(Issue.address, Issue.hostname)):
        names.update(x for x in (address, hostname) if x)
    return sorted(names)


async def generate(request, db: Session, feature: str, system: str, prompt: str, *, schema: dict | None = None,
                   effort: str = "medium", max_tokens: int | None = None,
                   provider: AiProvider | None = None) -> tuple[LLMResult, AiProvider]:
    """Redact, call the provider in a worker thread, restore, record usage and audit. Raises LLMError."""
    app = request.app
    provider = provider or default_provider(db)
    if provider is None:
        raise LLMError("No AI provider is configured. An admin can add one under Administration → AI.")
    config = json.loads(provider.config or "{}")
    secret = app.state.secretbox.decrypt(provider.secret)
    redactor = Redactor(known_hosts(db), enabled=provider.redact)
    req = LLMRequest(system=system, prompt=redactor.redact(prompt),
                     max_tokens=min(max_tokens or provider.max_tokens, provider.max_tokens), json_schema=schema,
                     effort=effort)
    user = getattr(request.state, "user", None)
    usage = AiUsage(user_id=getattr(user, "id", None), username=getattr(user, "username", "") or "",
                    provider_id=provider.id, provider_name=provider.name, model=config.get("model", ""), feature=feature)
    started = time.monotonic()
    try:
        result = await asyncio.to_thread(app.state.llm, provider.kind, config, secret, req)
    except LLMError as e:
        usage.ok, usage.error, usage.duration_ms = False, str(e)[:1000], int((time.monotonic() - started) * 1000)
        db.add(usage)
        db.commit()
        audit(db, request, "ai.generated", target=feature, provider=provider.name, ok=False, error=str(e)[:200])
        raise
    result.text = redactor.restore(result.text)
    result.data = redactor.restore_data(result.data) if result.data is not None else None
    usage.model = result.model or usage.model
    usage.input_tokens, usage.output_tokens = result.input_tokens, result.output_tokens
    usage.duration_ms = int((time.monotonic() - started) * 1000)
    db.add(usage)
    db.commit()
    audit(db, request, "ai.generated", target=feature, provider=provider.name, model=usage.model,
          input_tokens=result.input_tokens, output_tokens=result.output_tokens, redacted=provider.redact)
    return result, provider


def save_note(db: Session, request, feature: str, subject_type: str, subject_id, content: str, data: dict | None,
              provider: AiProvider, model: str) -> AiNote:
    note = AiNote(feature=feature, subject_type=subject_type, subject_id=str(subject_id), content=content,
                  data=json.dumps(data or {}), provider_name=provider.name, model=model,
                  created_by=getattr(request.state.user, "username", ""))
    db.add(note)
    db.commit()
    return note


def latest_note(db: Session, feature: str, subject_type: str, subject_id) -> AiNote | None:
    return db.scalar(select(AiNote).where(AiNote.feature == feature, AiNote.subject_type == subject_type,
                                          AiNote.subject_id == str(subject_id)).order_by(AiNote.id.desc()).limit(1))
