"""Audit log viewer and CSV export (admin only)."""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..audit import ACTION_GROUPS, PAGE_SIZE, audit, audit_query, details_text
from ..authz import require
from ..db import AuditLog
from ..deps import get_db
from ..render import render

router = APIRouter(dependencies=[Depends(require("audit.view"))])
CSV_LIMIT = 50_000


def _date(value: str) -> datetime | None:
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d")
    except (ValueError, AttributeError):
        return None


def _filters(username: str, action: str, since: str, until: str):
    start = _date(since)
    end = _date(until)
    return dict(username=username.strip(), action=action.strip(), since=start,
                until=end + timedelta(days=1) if end else None)  # "until" is inclusive of that day


@router.get("/audit")
def audit_page(request: Request, username: str = "", action: str = "", since: str = "", until: str = "", page: int = 1,
               db: Session = Depends(get_db)):
    f = _filters(username, action, since, until)
    stmt = audit_query(**f)
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    pages = max(1, -(-total // PAGE_SIZE))
    page = min(max(1, page), pages)
    rows = list(db.scalars(stmt.limit(PAGE_SIZE).offset((page - 1) * PAGE_SIZE)))
    usernames = [u for u in db.scalars(select(AuditLog.username).distinct().order_by(AuditLog.username)) if u]
    query = {k: v for k, v in (("username", f["username"]), ("action", f["action"]),
                                ("since", since.strip() if f["since"] else ""), ("until", until.strip() if until and f["until"] else ""))
             if v}

    def page_url(n: int) -> str:
        return "/audit?" + urlencode({**query, "page": n})

    return render(request, "audit.html", active="audit", rows=rows, total=total, page=page, pages=pages,
                  page_url=page_url, usernames=usernames, action_groups=ACTION_GROUPS, details_text=details_text,
                  f=query, csv_url="/audit.csv" + ("?" + urlencode(query) if query else ""))


def _cell(value) -> str:
    """Neutralise spreadsheet formula injection in exported cells."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@router.get("/audit.csv")
def audit_csv(request: Request, username: str = "", action: str = "", since: str = "", until: str = "",
              db: Session = Depends(get_db)):
    rows = list(db.scalars(audit_query(**_filters(username, action, since, until)).limit(CSV_LIMIT)))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time_utc", "username", "action", "target", "details", "ip"])
    for r in rows:
        w.writerow([r.created_at.strftime("%Y-%m-%d %H:%M:%S"), _cell(r.username), _cell(r.action), _cell(r.target),
                    _cell(details_text(r)), _cell(r.ip)])
    audit(db, request, "audit.exported", target=f"{len(rows)} row(s)",
          **{k: v for k, v in (("username", username), ("action", action), ("since", since), ("until", until)) if v})
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="audit-{stamp}.csv"'})
