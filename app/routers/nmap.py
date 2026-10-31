from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..audit import audit
from ..authz import require
from ..deps import get_db, get_runner, get_settings, verify_csrf
from ..render import render
from ..scanners.nmap_runner import build_nmap_argv, on_nmap_complete
from ..validation import parse_nmap_targets
from .jobs import job_summary, recent_jobs

router = APIRouter()

DEFAULT_FORM = {"targets": "", "port_mode": "top", "custom_ports": "", "timing": "T3", "skip_ping": False, "scan_type": "syn"}


def _page(request: Request, db: Session, form: dict, error: str | None = None, status_code: int = 200):
    return render(request, "nmap.html", status_code=status_code, active="nmap", form=form, error=error,
                  jobs=recent_jobs(db, kind="nmap"), job_summary=job_summary)


def launch_nmap(db: Session, settings, runner, target_list: list[str], *, port_mode: str = "top",
                custom_ports: str = "", timing: str = "T3", skip_ping: bool = False, scan_type: str = "syn",
                exclude: list[str] | None = None, extra_params: dict | None = None, schedule_id: int | None = None):
    """Validate options, create and start an nmap job. Raises ValueError for bad options."""
    argv = build_nmap_argv(settings.nmap_bin, target_list, port_mode=port_mode, custom_ports=custom_ports,
                           timing=timing, skip_ping=skip_ping, scan_type=scan_type, exclude=exclude)
    params = {"targets": target_list, "port_mode": port_mode, "custom_ports": custom_ports, "scan_type": scan_type,
              **(extra_params or {})}
    if exclude:
        params["exclude"] = list(exclude)
    job = runner.create_job(db, "nmap", argv, params=params)
    if schedule_id is not None:
        job.schedule_id = schedule_id
        db.commit()
    runner.start(job.id, argv, on_complete=on_nmap_complete, stdout_to_log=False)
    return job


@router.get("/nmap")
def nmap_page(request: Request, targets: str = "", db: Session = Depends(get_db)):
    """``targets`` pre-fills the form (Discovery → "Scan with nmap")."""
    return _page(request, db, {**DEFAULT_FORM, "targets": targets[:200_000]})


@router.post("/nmap/scan", dependencies=[Depends(require("scan.run")), Depends(verify_csrf)])
async def nmap_scan(request: Request, targets: str = Form(""), port_mode: str = Form("top"), custom_ports: str = Form(""),
              timing: str = Form("T3"), skip_ping: bool = Form(False), scan_type: str = Form("syn"),
              db: Session = Depends(get_db), settings=Depends(get_settings), runner=Depends(get_runner)):
    form = {"targets": targets, "port_mode": port_mode, "custom_ports": custom_ports, "timing": timing,
            "skip_ping": skip_ping, "scan_type": scan_type}
    try:
        target_list = parse_nmap_targets(targets)
        job = launch_nmap(db, settings, runner, target_list, port_mode=port_mode, custom_ports=custom_ports,
                          timing=timing, skip_ping=skip_ping, scan_type=scan_type)
    except ValueError as e:
        return _page(request, db, form, error=str(e), status_code=400)
    audit(db, request, "scan.nmap", target=", ".join(target_list), job_id=job.id, port_mode=port_mode, scan_type=scan_type)
    return RedirectResponse(f"/jobs/{job.id}", status_code=303)
