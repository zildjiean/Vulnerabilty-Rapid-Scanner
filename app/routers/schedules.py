"""Scheduled scans: list, create, enable / disable, run now, delete."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import scheduler as sch
from ..audit import audit
from ..authz import require
from ..db import Job, Schedule, Scope, User, utcnow
from ..deps import get_db, verify_csrf
from ..render import render
from ..scanners.nmap_runner import PORT_MODES, SCAN_TYPES, TIMINGS, build_nmap_argv
from ..scanners.nuclei_runner import _GROUP_RE, DEFAULT_PROFILE, PROFILES

router = APIRouter()
MANAGE = [Depends(require("scopes.manage")), Depends(verify_csrf)]
NUCLEI_SEVERITIES = ("critical", "high", "medium", "low", "info")


def schedule_form_context(db: Session, scope_filter: int | None = None) -> dict:
    tz = sch.tzinfo(db)
    stmt = select(Schedule).order_by(Schedule.next_run_at)
    if scope_filter is not None:
        stmt = stmt.where(Schedule.scope_id == scope_filter)
    schedules = list(db.scalars(stmt))
    jobs = {j.id: j for j in db.scalars(select(Job).where(Job.id.in_([s.last_job_id for s in schedules if s.last_job_id])))}
    return dict(schedules=schedules, last_jobs=jobs, tz_name=sch.get_timezone(db), to_local=lambda d: sch.to_local(d, tz),
                kinds=sch.KINDS, frequencies=sch.FREQUENCIES, weekdays=sch.WEEKDAYS, all_scopes=list(db.scalars(select(Scope).order_by(Scope.name))),
                port_modes=PORT_MODES, timings=TIMINGS, scan_types=SCAN_TYPES, profiles=PROFILES,
                default_profile=DEFAULT_PROFILE, nuclei_severities=NUCLEI_SEVERITIES, scope_filter=scope_filter,
                describe=describe)


def describe(s: Schedule) -> str:
    if s.frequency == "interval":
        return f"Every {s.interval_hours} hour{'s' if s.interval_hours != 1 else ''}"
    if s.frequency == "weekly":
        return f"Weekly on {sch.WEEKDAYS[s.weekday]} at {s.time_of_day}"
    return f"Daily at {s.time_of_day}"


@router.get("/schedules")
def schedules_page(request: Request, db: Session = Depends(get_db)):
    return render(request, "schedules.html", active="schedules", **schedule_form_context(db))


def _to_int(value: str, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def build_config(kind: str, port_mode: str, custom_ports: str, timing: str, scan_type: str, skip_ping: bool,
                 nuclei_mode: str, groups: str, severities: list[str], profile: str, domains: str = "",
                 probe: bool = False) -> dict:
    if kind == "discovery":
        from ..discovery import parse_root_domains
        return {"domains": parse_root_domains(domains), "probe": probe}
    if kind == "nmap":
        # dry-run the argv builder so bad ports / modes are rejected now, not at 2 a.m.
        build_nmap_argv("nmap", ["127.0.0.1"], port_mode=port_mode, custom_ports=custom_ports, timing=timing,
                        skip_ping=skip_ping, scan_type=scan_type)
        return {"port_mode": port_mode, "custom_ports": custom_ports, "timing": timing, "scan_type": scan_type,
                "skip_ping": skip_ping}
    if profile not in PROFILES:
        raise ValueError("Unknown scan profile.")
    if kind == "campaign_verify":
        return {"profile": profile}
    if nuclei_mode not in ("all", "groups"):
        raise ValueError("Template selection must be all templates or groups.")
    group_list = [g.strip().strip("/") for g in groups.replace(",", "\n").splitlines() if g.strip()]
    if nuclei_mode == "groups" and not group_list:
        raise ValueError("List at least one template group, e.g. http/cves.")
    for g in group_list:
        if not _GROUP_RE.match(g) or ".." in g:
            raise ValueError(f"Invalid template group {g!r}.")
    return {"mode": nuclei_mode, "groups": group_list, "severities": [x for x in severities if x in NUCLEI_SEVERITIES],
            "profile": profile}


def _back(back: str) -> str:
    """Only redirect back to our own schedule or scope pages."""
    return back if back.startswith("/scopes/") or back == "/schedules" else "/schedules"


@router.post("/schedules", dependencies=MANAGE)
def schedule_create(request: Request, name: str = Form(""), kind: str = Form(""), scope_id: str = Form(""),
                    frequency: str = Form("daily"), interval_hours: str = Form("24"), time_of_day: str = Form("02:00"),
                    weekday: str = Form("0"), port_mode: str = Form("top"), custom_ports: str = Form(""),
                    timing: str = Form("T3"), scan_type: str = Form("syn"), skip_ping: bool = Form(False),
                    nuclei_mode: str = Form("all"), groups: str = Form(""), severities: list[str] = Form(default=[]),
                    profile: str = Form(DEFAULT_PROFILE), domains: str = Form(""), probe: bool = Form(False),
                    back: str = Form("/schedules"), db: Session = Depends(get_db)):
    scope = db.get(Scope, int(scope_id)) if scope_id.isdigit() else None
    hours, day = _to_int(interval_hours, 0), _to_int(weekday, -1)
    err = sch.validate_schedule(kind, scope.id if scope else None, frequency, hours, time_of_day, day)
    config = {}
    if not err:
        try:
            config = build_config(kind, port_mode, custom_ports, timing, scan_type, skip_ping, nuclei_mode, groups,
                                  severities, profile, domains, probe)
        except ValueError as e:
            err = str(e)
    if err:
        ctx = schedule_form_context(db, scope_filter=scope.id if scope and back.startswith("/scopes/") else None)
        return render(request, "schedules.html", status_code=400, active="schedules", error=err, **ctx)
    if kind == "discovery":
        roots = config["domains"]
        default_name = f"{sch.KINDS[kind]} of {', '.join(roots[:2])}{'…' if len(roots) > 2 else ''}"
    else:
        default_name = f"{sch.KINDS[kind]}{' of ' + scope.name if scope else ''}"
    s = Schedule(name=(name.strip() or default_name)[:128], kind=kind,
                 scope_id=None if kind in ("campaign_verify", "discovery") else scope.id, frequency=frequency, interval_hours=hours or 24, time_of_day=time_of_day or "02:00",
                 weekday=max(day, 0), config=json.dumps(config), enabled=True, created_by=request.state.user.username)
    s.next_run_at = sch.compute_next_run(s, utcnow(), sch.tzinfo(db))
    db.add(s)
    db.commit()
    audit(db, request, "schedule.created", target=s.name, schedule_id=s.id, kind=kind, frequency=describe(s),
          scope=scope.name if scope and kind not in ("campaign_verify", "discovery") else "")
    return RedirectResponse(_back(back) + "?msg=Schedule+created", status_code=303)


def _get(db: Session, sid: int) -> Schedule:
    s = db.get(Schedule, sid)
    if s is None:
        raise HTTPException(404)
    return s


@router.post("/schedules/{sid}/toggle", dependencies=MANAGE)
def schedule_toggle(request: Request, sid: int, back: str = Form("/schedules"), db: Session = Depends(get_db)):
    s = _get(db, sid)
    s.enabled = not s.enabled
    if s.enabled:
        s.next_run_at = sch.compute_next_run(s, utcnow(), sch.tzinfo(db))
    db.commit()
    audit(db, request, "schedule.toggled", target=s.name, schedule_id=s.id, enabled=s.enabled)
    return RedirectResponse(_back(back) + f"?msg=Schedule+{'enabled' if s.enabled else 'paused'}", status_code=303)


@router.post("/schedules/{sid}/run", dependencies=MANAGE)
async def schedule_run(request: Request, sid: int, back: str = Form("/schedules"), db: Session = Depends(get_db)):
    s = _get(db, sid)
    actor = db.get(User, request.state.user.id)
    job_id = await sch.run_schedule(request.app, s.id, manual=True, actor=actor, request=request)
    if job_id:
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)
    db.expire_all()
    s = _get(db, sid)
    return RedirectResponse(_back(back) + "?msg=" + (s.last_message or "Nothing to run").replace(" ", "+"), status_code=303)


@router.post("/schedules/{sid}/delete", dependencies=MANAGE)
def schedule_delete(request: Request, sid: int, back: str = Form("/schedules"), db: Session = Depends(get_db)):
    s = _get(db, sid)
    name = s.name
    db.delete(s)
    db.commit()
    audit(db, request, "schedule.deleted", target=name, schedule_id=sid)
    return RedirectResponse(_back(back) + "?msg=Schedule+deleted", status_code=303)
