"""Attack-surface change detection: diff each nmap scan against the inventory before it is updated."""
from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from . import channels as ch
from . import notifications as nt
from .db import Host, Job, SurfaceChange, utcnow
from .scopes import Matcher, compile_scopes, resolve_scope

log = logging.getLogger(__name__)

KIND_LABELS = {
    "host_new": "New host",
    "port_opened": "Port opened",
    "port_closed": "Port closed",
    "service_changed": "Version changed",
    "host_gone": "Not responding",
}
KIND_SEVERITY = {"host_new": "medium", "port_opened": "medium", "port_closed": "low", "service_changed": "low",
                 "host_gone": "low"}
TITLE_PARTS = (("host_new", "new host", "new hosts"), ("port_opened", "opened", "opened"),
               ("port_closed", "closed", "closed"), ("service_changed", "changed", "changed"),
               ("host_gone", "gone", "gone"))
DAYS_CHOICES = ("1", "7", "30", "90", "all")
DEFAULT_DAYS = "30"
MAX_TEXT = 2000
NOTIFY_LINES = 10


def _join(*parts: str) -> str:
    return " ".join(p.strip() for p in parts if p and p.strip())


def is_scanned(scanned: dict[str, set[int]], port: int, protocol: str) -> bool:
    """Was (port, protocol) part of this scan? Without scaninfo every port counts as scanned."""
    return not scanned or port in scanned.get(protocol, ())


def diff_and_record(db: Session, job: Job, parsed_hosts, scanned: dict[str, set[int]], targets: list[str],
                    exclude: list[str] | None = None) -> list[SurfaceChange]:
    """Compare parsed nmap hosts with the inventory (call before ingest mutates it) and add SurfaceChange rows."""
    now = utcnow()
    compiled = compile_scopes(db)
    known = {h.address: h for h in db.scalars(select(Host).options(selectinload(Host.services)))}
    out: list[SurfaceChange] = []

    def add(kind: str, address: str, hostname: str, host: Host | None, port: int | None = None, protocol: str = "",
            before: str = "", after: str = "") -> None:
        scope = resolve_scope(compiled, address, hostname)
        c = SurfaceChange(job_id=job.id, host_id=host.id if host else None, address=address, hostname=hostname or "",
                          port=port, protocol=protocol, kind=kind, before=before[:MAX_TEXT], after=after[:MAX_TEXT],
                          severity=KIND_SEVERITY[kind], scope_id=scope.id if scope else None, created_at=now)
        db.add(c)
        out.append(c)

    seen: set[str] = set()
    for h in parsed_hosts:
        seen.add(h.address)
        host = known.get(h.address)
        name = h.hostname or (host.hostname if host else "") or ""
        if host is None:
            ports = "; ".join(_join(f"{p.port}/{p.protocol}", p.service, p.product, p.version) for p in h.ports)
            add("host_new", h.address, name, None, after=ports)
            continue
        existing = {(s.port, s.protocol): s for s in host.services}
        reported: set[tuple[int, str]] = set()
        for p in h.ports:
            key = (p.port, p.protocol)
            reported.add(key)
            svc = existing.get(key)
            if svc is None:
                add("port_opened", h.address, name, host, p.port, p.protocol, after=_join(p.service, p.product, p.version))
                continue
            old = ((svc.product or "").strip(), (svc.version or "").strip())
            new = ((p.product or "").strip(), (p.version or "").strip())
            if old != new:
                add("service_changed", h.address, name, host, p.port, p.protocol, before=_join(*old), after=_join(*new))
        for (port, protocol), svc in existing.items():
            if (port, protocol) not in reported and is_scanned(scanned, port, protocol):
                add("port_closed", h.address, name, host, port, protocol,
                    before=_join(svc.service_name, svc.product, svc.version))

    include, skip = Matcher.parse(targets or []), Matcher.parse(exclude or [])
    if include:
        last_gone = dict(db.execute(select(SurfaceChange.address, func.max(SurfaceChange.created_at))
                                    .where(SurfaceChange.kind == "host_gone").group_by(SurfaceChange.address)).all())
        for address, host in known.items():
            name = host.hostname or ""
            if address in seen or not include.matches(address, name) or skip.matches(address, name):
                continue
            if address in last_gone and last_gone[address] >= host.last_seen:
                continue  # already reported, not seen since
            add("host_gone", address, name, host)
    db.flush()
    return out


# ----------------------------------------------------------------- summaries and notification
def summarize(changes) -> dict[str, int]:
    counts = {k: 0 for k in KIND_LABELS}
    for c in changes:
        counts[c.kind] = counts.get(c.kind, 0) + 1
    return counts


def title_counts(counts: dict[str, int]) -> str:
    return ", ".join(f"{counts[k]} {one if counts[k] == 1 else many}" for k, one, many in TITLE_PARTS if counts.get(k))


def change_line(c: SurfaceChange) -> str:
    asset = c.address + (f" ({c.hostname})" if c.hostname and c.hostname != c.address else "")
    where = f"{c.address}:{c.port}/{c.protocol}"
    if c.kind == "host_new":
        return f"+ {asset} new host" + (f": {c.after}" if c.after else "")
    if c.kind == "port_opened":
        return _join(f"+ {where}", c.after)
    if c.kind == "port_closed":
        return _join(f"- {where}", c.before)
    if c.kind == "service_changed":
        return f"~ {where} {c.before or '?'} → {c.after or '?'}"
    return f"- {asset} not responding"


def notify_changes(db: Session, job: Job, changes: list[SurfaceChange]) -> int:
    """One ``surface.changed`` message per job. Returns the number of deliveries queued."""
    if not changes:
        return 0
    counts = summarize(changes)
    severity = "medium" if any(c.severity == "medium" for c in changes) else "low"
    lines = [change_line(c)[:300] for c in changes[:NOTIFY_LINES]]
    if len(changes) > NOTIFY_LINES:
        lines.append(f"… and {len(changes) - NOTIFY_LINES} more")
    fields = [("Job", f"#{job.id} (nmap)")] + [(KIND_LABELS[k], str(n)) for k, n in counts.items() if n]
    msg = ch.Message(event="surface.changed", title=f"[SURFACE] nmap job #{job.id}: {title_counts(counts)}",
                     text="\n".join(lines), severity=severity, url=f"{nt.get_base_url(db)}/changes?job={job.id}",
                     fields=fields, data={"job_id": job.id, "counts": counts})
    return nt.notify(db, "surface.changed", message=msg, severity=severity)


# ----------------------------------------------------------------- listing
def parse_days(value: str, default: str = DEFAULT_DAYS) -> str:
    value = (value or "").strip()
    return value if value in DAYS_CHOICES else default


def query(db: Session, kind: str = "", scope_id: int | None = None, days: str = DEFAULT_DAYS, job_id: int | None = None,
          state: str = "open"):
    """Select of matching changes, newest first. ``days`` is one of DAYS_CHOICES; ``state`` open | all."""
    stmt = select(SurfaceChange)
    if kind in KIND_LABELS:
        stmt = stmt.where(SurfaceChange.kind == kind)
    if scope_id:
        stmt = stmt.where(SurfaceChange.scope_id == scope_id)
    if days != "all":
        stmt = stmt.where(SurfaceChange.created_at >= utcnow() - timedelta(days=int(parse_days(days))))
    if job_id:
        stmt = stmt.where(SurfaceChange.job_id == job_id)
    if state != "all":
        stmt = stmt.where(SurfaceChange.acknowledged_at.is_(None))
    return stmt.order_by(SurfaceChange.created_at.desc(), SurfaceChange.id.desc())


def acknowledge(changes, username: str) -> int:
    now, n = utcnow(), 0
    for c in changes:
        if c.acknowledged_at is None:
            c.acknowledged_at, c.acknowledged_by = now, username[:64]
            n += 1
    return n


def open_counts(db: Session, days: int = 7) -> dict[str, int]:
    """Unacknowledged changes per kind in the last ``days`` days."""
    counts = {k: 0 for k in KIND_LABELS}
    for kind, n in db.execute(select(SurfaceChange.kind, func.count()).where(
            SurfaceChange.acknowledged_at.is_(None), SurfaceChange.created_at >= utcnow() - timedelta(days=days))
            .group_by(SurfaceChange.kind)).all():
        counts[kind] = n
    return counts
