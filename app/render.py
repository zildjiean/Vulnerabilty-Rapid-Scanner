from __future__ import annotations

import json
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters["fromjson"] = json.loads

SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"]
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def normalize_severity(value) -> str:
    v = str(value or "").strip().lower()
    return v if v in SEVERITY_ORDER else "unknown"


def render(request: Request, name: str, status_code: int = 200, **ctx):
    ctx.setdefault("user", getattr(request.state, "user", None))
    ctx.setdefault("csrf", getattr(request.state, "csrf", "") or "")
    ctx.setdefault("msg", request.query_params.get("msg"))
    ctx.setdefault("error", None)
    ctx.setdefault("active", "")
    ctx.setdefault("severities", SEVERITIES)
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)
