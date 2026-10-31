from __future__ import annotations

import json
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters["fromjson"] = json.loads
from .jobs import job_warnings  # noqa: E402
templates.env.globals["job_warnings"] = job_warnings


def static_version() -> str:
    """Cache-busting token derived from the static files' contents (changes on every release)."""
    import hashlib
    h = hashlib.sha1()
    for f in sorted(STATIC_DIR.glob("*")):
        if f.is_file():
            h.update(f.read_bytes())
    return h.hexdigest()[:10]


templates.env.globals["static_v"] = static_version()
from . import __version__  # noqa: E402
templates.env.globals["app_version"] = __version__
from .mdlite import render_markdown  # noqa: E402
templates.env.filters["mdlite"] = render_markdown

SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"]
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def normalize_severity(value) -> str:
    v = str(value or "").strip().lower()
    return v if v in SEVERITY_ORDER else "unknown"


def render(request: Request, name: str, status_code: int = 200, **ctx):
    from .authz import ROLE_LABELS, has_perm
    ctx.setdefault("user", getattr(request.state, "user", None))
    user = ctx["user"]
    ctx.setdefault("can", lambda perm: has_perm(user, perm))
    ctx.setdefault("role_labels", ROLE_LABELS)
    ctx.setdefault("ai_ready", bool(getattr(request.app.state, "ai_ready", False)) and has_perm(user, "ai.use"))
    ctx.setdefault("csrf", getattr(request.state, "csrf", "") or "")
    ctx.setdefault("msg", request.query_params.get("msg"))
    if ctx.get("error") is None:  # errors from a redirect (e.g. a failed AI call) arrive as ?err=
        ctx["error"] = request.query_params.get("err")
    ctx.setdefault("active", "")
    ctx.setdefault("severities", SEVERITIES)
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)
