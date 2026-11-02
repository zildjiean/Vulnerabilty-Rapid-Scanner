"""Quick scan: one guided action for people who do not know nmap or nuclei. Step 1 is an nmap job; its completion
hook ingests the results as usual, then starts step 2, a nuclei job with a preset over the inventory services of the
hosts that were asked for. The hook runs in the runner's worker thread (like discovery -> web probe)."""
from __future__ import annotations

import ipaddress
import json
import logging

from sqlalchemy.orm import Session

from .config import Settings
from .db import Job
from .nuclei_presets import preset_label, preset_launch
from .scopes import services_in

log = logging.getLogger(__name__)

LEVELS = {
    "standard": {"label": "Standard", "help": "The 1,000 most common ports, then the Recommended checks. A few minutes "
                                              "for a small network.",
                 "port_mode": "top", "timing": "T3", "scan_type": "syn", "preset": "recommended",
                 "ports_label": "1,000 ports"},
    "thorough": {"label": "Thorough", "help": "All 65,535 ports, then every check at every severity. Much slower; "
                                              "best for a few important hosts.",
                 "port_mode": "all", "timing": "T3", "scan_type": "syn", "preset": "full",
                 "ports_label": "all 65,535 ports"},
}
DEFAULT_LEVEL = "standard"


def summary(n_targets: int, level: str) -> str:
    lv = LEVELS.get(level, LEVELS[DEFAULT_LEVEL])
    return (f"nmap {n_targets} target(s) ({lv['ports_label']}) → nuclei ({preset_label(lv['preset'])}) "
            "on the services found")


def quick_targets(db: Session, nmap_targets: list[str]) -> list[str]:
    """nuclei targets for every inventory service on a host matching the nmap targets."""
    return services_in(db, nmap_targets)


def check_targets(targets: list[str]) -> None:
    """Quick scan matches the inventory against the targets afterwards, which works for addresses, networks, nmap
    ranges and plain host names. ``host/prefix`` (nmap expands it, the inventory match cannot) is refused so the
    nuclei step is not silently skipped."""
    for t in targets:
        if "/" not in t:
            continue
        try:
            ipaddress.ip_network(t, strict=False)
        except ValueError:
            raise ValueError(f"{t!r}: Use an IP/CIDR or a plain host name for a quick scan "
                             "(a host name with a /prefix is not supported).") from None


def launch_quick(db: Session, settings: Settings, runner, targets: list[str], level: str) -> Job:
    """Start step 1 (nmap) for validated ``targets``. Raises ValueError for an unknown level or bad options."""
    from .routers.nmap import launch_nmap
    lv = LEVELS.get(level)
    if lv is None:
        raise ValueError("Invalid scan level. Choose Standard or Thorough.")
    check_targets(targets)
    return launch_nmap(db, settings, runner, targets, port_mode=lv["port_mode"], timing=lv["timing"],
                       scan_type=lv["scan_type"], extra_params={"quick": {"level": level, "step": 1}},
                       on_complete=quick_hook(settings, runner, level, targets))


def _update(job: Job, quick: dict | None = None, warning: str | None = None) -> None:
    try:
        p = json.loads(job.params_json or "{}")
    except json.JSONDecodeError:
        p = {}
    if quick:
        p["quick"] = {**(p.get("quick") or {}), **quick}
    if warning:
        p["warnings"] = [*(p.get("warnings") or []), warning]
    job.params_json = json.dumps(p)


def quick_hook(settings: Settings, runner, level: str, targets: list[str]):
    preset = LEVELS[level]["preset"]

    def hook(db: Session, job: Job, output: str) -> str:
        from .scanners.nmap_runner import on_nmap_complete
        note = on_nmap_complete(db, job, output)
        db.commit()  # the ingest is complete: release the write lock; nothing below may fail this job

        def cancelled() -> str:
            _update(job, {"nuclei": "cancelled"})
            return note + "\n[quick] cancelled: nuclei step not started."

        if runner.cancel_requested(job.id):
            return cancelled()
        services = quick_targets(db, targets)
        if not services:  # an empty network is a result, not a scan problem: a note, not a warning
            _update(job, {"nuclei": "skipped"})
            return note + "\n[quick] no open services found: nuclei step skipped."
        if runner.cancel_requested(job.id):  # cancelled while the services were collected
            return cancelled()
        try:
            nuclei = preset_launch(db, settings, runner, services, preset,
                                   {"quick": {"level": level, "step": 2, "parent_job": job.id}})
        except Exception as e:  # noqa: BLE001
            db.rollback()
            if isinstance(e, (ValueError, OSError)):
                reason = str(e)
            else:
                log.exception("quick scan %s: starting the nuclei step failed", job.id)
                reason = type(e).__name__
            _update(job, {"nuclei": "error"}, f"Quick scan: the nuclei step could not start: {reason}")
            return note + f"\n[quick] nuclei step could not start: {reason}"
        _update(job, {"nuclei_job": nuclei.id})
        return note + f"\n[quick] nuclei step started: job #{nuclei.id} on {len(services)} service(s)."
    return hook
