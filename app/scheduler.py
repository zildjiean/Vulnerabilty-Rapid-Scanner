"""Recurring jobs: nmap discovery and nuclei scans of scopes, and re-verification of active campaigns."""
from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import audit
from .db import AppSetting, Campaign, Host, Job, Schedule, Scope, Service, utcnow

log = logging.getLogger(__name__)

KINDS = {"nmap": "nmap discovery", "nuclei": "nuclei scan", "campaign_verify": "Verify active campaigns"}
FREQUENCIES = {"interval": "Every N hours", "daily": "Daily", "weekly": "Weekly"}
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
TZ_KEY = "timezone"
DEFAULT_TZ = "Asia/Bangkok"
LOOP_SECONDS = 30
_TIME_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


# ----------------------------------------------------------------- time
def get_timezone(db: Session) -> str:
    row = db.get(AppSetting, TZ_KEY)
    return row.value if row and row.value else DEFAULT_TZ


def tzinfo(db: Session) -> ZoneInfo:
    try:
        return ZoneInfo(get_timezone(db))
    except ZoneInfoNotFoundError:
        return ZoneInfo("UTC")


def set_timezone(db: Session, name: str, now: datetime | None = None) -> None:
    name = name.strip()
    try:
        tz = ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(f"Unknown timezone {name!r}. Use an IANA name such as Asia/Bangkok or UTC.")
    row = db.get(AppSetting, TZ_KEY) or AppSetting(key=TZ_KEY)
    row.value = name
    db.add(row)
    now = now or utcnow()
    for s in db.scalars(select(Schedule).where(Schedule.frequency.in_(("daily", "weekly")))):
        s.next_run_at = compute_next_run(s, now, tz)
    db.flush()


def compute_next_run(s, after: datetime, tz: ZoneInfo) -> datetime:
    """Next run strictly after ``after`` (naive UTC) for schedule-like ``s``; returns naive UTC."""
    if s.frequency == "interval":
        return after + timedelta(hours=s.interval_hours)
    hour, minute = (int(x) for x in s.time_of_day.split(":"))
    local_now = after.replace(tzinfo=timezone.utc).astimezone(tz)

    def at(day) -> datetime:
        return datetime(day.year, day.month, day.day, hour, minute, tzinfo=tz)

    day = local_now.date()
    if s.frequency == "weekly":
        day = day + timedelta(days=(s.weekday - day.weekday()) % 7)
        step = timedelta(days=7)
    else:
        step = timedelta(days=1)
    candidate = at(day)
    while candidate <= local_now:
        day = day + step
        candidate = at(day)
    return candidate.astimezone(timezone.utc).replace(tzinfo=None)


def to_local(dt: datetime | None, tz: ZoneInfo) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc).astimezone(tz) if dt else None


# ----------------------------------------------------------------- validation
def validate_schedule(kind: str, scope_id: int | None, frequency: str, interval_hours: int, time_of_day: str,
                      weekday: int) -> str | None:
    if kind not in KINDS:
        return "Unknown schedule type."
    if kind in ("nmap", "nuclei") and not scope_id:
        return "Choose the scope to scan."
    if frequency not in FREQUENCIES:
        return "Unknown frequency."
    if frequency == "interval" and not 1 <= interval_hours <= 168:
        return "Interval must be between 1 and 168 hours."
    if frequency in ("daily", "weekly") and not _TIME_RE.match(time_of_day or ""):
        return "Time must be HH:MM (24-hour)."
    if frequency == "weekly" and not 0 <= weekday <= 6:
        return "Unknown weekday."
    return None


# ----------------------------------------------------------------- running
def _scope_targets(scope: Scope) -> tuple[list[str], list[str]]:
    from .scopes import _split
    return _split(scope.targets), _split(scope.exclusions)


def scope_services(db: Session, scope: Scope) -> list[str]:
    """nuclei targets for every inventory service inside the scope's own targets / exclusions."""
    from .routers.inventory import service_to_target
    from .scopes import Matcher
    include, exclude = (Matcher.parse(x) for x in _scope_targets(scope))
    out = []
    for svc, host in db.execute(select(Service, Host).join(Host, Host.id == Service.host_id).order_by(Host.address, Service.port)):
        name = host.hostname or ""
        if include.matches(host.address, name) and not exclude.matches(host.address, name):
            t = service_to_target(host.address, svc)
            if t not in out:
                out.append(t)
    return out


def _run_nmap(app, db: Session, s: Schedule, cfg: dict) -> tuple[Job | None, str]:
    from .routers.nmap import launch_nmap
    targets, exclude = _scope_targets(s.scope)
    job = launch_nmap(db, app.state.settings, app.state.job_runner, targets, port_mode=cfg.get("port_mode", "top"),
                      custom_ports=cfg.get("custom_ports", ""), timing=cfg.get("timing", "T3"),
                      skip_ping=bool(cfg.get("skip_ping")), scan_type=cfg.get("scan_type", "syn"), exclude=exclude,
                      extra_params={"schedule": s.name, "scope": s.scope.name}, schedule_id=s.id)
    return job, f"nmap discovery of {len(targets)} target(s) in {s.scope.name}"


def _run_nuclei(app, db: Session, s: Schedule, cfg: dict) -> tuple[Job | None, str]:
    from .routers.nuclei import launch_nuclei
    from .scanners.nuclei_runner import PROFILES, all_template_paths, profile_flags, resolve_group_paths
    targets = scope_services(db, s.scope)
    if not targets:
        return None, f"No services in the inventory for {s.scope.name} yet. Run nmap discovery first."
    settings = app.state.settings
    mode = cfg.get("mode", "all")
    paths = resolve_group_paths(settings, cfg.get("groups") or []) if mode == "groups" else all_template_paths(settings)
    profile = cfg.get("profile", "normal")
    prof = PROFILES.get(profile, PROFILES["normal"])
    severities = [x for x in cfg.get("severities") or [] if x in ("critical", "high", "medium", "low", "info")]
    params = {"targets": targets, "mode": mode, "groups": cfg.get("groups") or [], "severities": severities,
              "profile": profile, "schedule": s.name, "scope": s.scope.name}
    job = launch_nuclei(db, settings, app.state.job_runner, targets, paths, params, rate_limit=prof["rate_limit"],
                        timeout=prof["timeout"], extra_flags=profile_flags(profile, False), severities=severities,
                        schedule_id=s.id)
    return job, f"nuclei scan of {len(targets)} service(s) in {s.scope.name}"


def _run_campaigns(app, db: Session, s: Schedule, cfg: dict) -> tuple[Job | None, str]:
    from . import campaigns as camp
    from .routers.nuclei import launch_nuclei
    from .scanners.nuclei_runner import PROFILES, profile_flags, validate_template_paths
    profile = cfg.get("profile", "normal")
    prof = PROFILES.get(profile, PROFILES["normal"])
    started, skipped, last = 0, 0, None
    for c in db.scalars(select(Campaign).where(Campaign.status == "active").order_by(Campaign.id)):
        targets = camp.verify_targets(db, c)
        if not c.templates or not targets:
            skipped += 1
            continue
        try:
            paths = validate_template_paths(app.state.settings, [t.path for t in c.templates])
        except ValueError:
            skipped += 1
            continue
        params = {"targets": targets, "template_ids": [t.template_id for t in c.templates], "mode": "selected",
                  "profile": profile, "campaign": c.cve_id or c.name, "schedule": s.name}
        last = launch_nuclei(db, app.state.settings, app.state.job_runner, targets, paths, params,
                             rate_limit=prof["rate_limit"], timeout=prof["timeout"],
                             extra_flags=profile_flags(profile, False), campaign_id=c.id, schedule_id=s.id)
        started += 1
    msg = f"{started} campaign(s) verified" + (f", {skipped} skipped (no templates or no exposed assets)" if skipped else "")
    return last, msg


RUNNERS = {"nmap": _run_nmap, "nuclei": _run_nuclei, "campaign_verify": _run_campaigns}


async def run_schedule(app, schedule_id: int, manual: bool = False, actor=None, request=None) -> int | None:
    """Run one schedule now. Returns the (last) job id started, or None when skipped / failed.
    ``actor`` / ``request`` attribute a manual "Run now" to the user; automatic runs are audited as ``scheduler``."""
    with app.state.SessionLocal() as db:
        s = db.get(Schedule, schedule_id)
        if s is None:
            return None
        now = utcnow()
        if not manual:
            s.next_run_at = compute_next_run(s, now, tzinfo(db))
        s.last_run_at = now
        prev = db.get(Job, s.last_job_id) if s.last_job_id else None
        job, status = None, "started"
        if prev is not None and prev.status in ("queued", "running"):
            status, message = "skipped", f"Previous run (job #{prev.id}) is still running."
        elif s.kind in ("nmap", "nuclei") and s.scope is None:
            status, message = "error", "The scope of this schedule no longer exists."
        else:
            try:
                cfg = json.loads(s.config or "{}")
                job, message = RUNNERS[s.kind](app, db, s, cfg)
                if job is None:
                    status = "skipped"
            except (ValueError, KeyError, OSError) as e:
                db.rollback()
                s = db.get(Schedule, schedule_id)
                status, message = "error", str(e)
        s.last_status, s.last_message = status, message
        if job is not None:
            s.last_job_id = job.id
        if status == "error":
            from .notifications import notify, schedule_message
            notify(db, "schedule.error", message=schedule_message(db, s, message))
        db.commit()
        audit(db, request, "schedule.run", target=s.name, user=actor,
              **({} if actor else {"username": "scheduler"}), schedule_id=s.id, status=status,
              job_id=job.id if job else None, manual=manual, message=message[:200])
        return job.id if job else None


async def run_due(app, now: datetime | None = None) -> int:
    now = now or utcnow()
    with app.state.SessionLocal() as db:
        due = list(db.scalars(select(Schedule.id).where(Schedule.enabled.is_(True), Schedule.next_run_at.is_not(None),
                                                         Schedule.next_run_at <= now).order_by(Schedule.next_run_at)))
    for sid in due:
        await run_schedule(app, sid)
    return len(due)


async def scheduler_loop(app, interval: int = LOOP_SECONDS) -> None:
    while True:
        await asyncio.sleep(interval)
        try:
            await run_due(app)
        except Exception:  # noqa: BLE001 - the loop must survive a bad schedule
            log.exception("scheduler iteration failed")
        try:
            from .reverify import run_reverify
            await run_reverify(app)
        except Exception:  # noqa: BLE001
            log.exception("re-verify iteration failed")
