from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy.orm import Session

router = APIRouter()

DEFAULT_NUCLEI_FORM = {"targets": "", "selected": [], "rate_limit": 150, "timeout": 10}


def nuclei_page_context(db: Session, targets: str = "", selected=None, error: str | None = None, **extra) -> dict:
    form = dict(DEFAULT_NUCLEI_FORM)
    form["targets"] = targets
    form["selected"] = selected or []
    form.update(extra)
    return {"active": "nuclei", "form": form, "error": error, "jobs": [], "job_summary": lambda j: ""}
