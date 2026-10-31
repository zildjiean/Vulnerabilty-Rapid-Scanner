from __future__ import annotations

import re

TIMINGS = ("T2", "T3", "T4")
SCAN_TYPES = {"syn": ["-sS", "--privileged"], "connect": ["-sT"]}
PORT_MODES = ("top", "all", "custom")
_PORT_SPEC_RE = re.compile(r"^[0-9][0-9,\-]*$")


def build_nmap_argv(nmap_bin: str, targets: list[str], port_mode: str = "top", custom_ports: str = "",
                    timing: str = "T3", skip_ping: bool = False, scan_type: str = "syn",
                    exclude: list[str] | None = None) -> list[str]:
    if not targets:
        raise ValueError("No targets.")
    if timing not in TIMINGS:
        raise ValueError(f"Invalid timing {timing!r}.")
    if scan_type not in SCAN_TYPES:
        raise ValueError(f"Invalid scan type {scan_type!r}.")
    if port_mode not in PORT_MODES:
        raise ValueError(f"Invalid port mode {port_mode!r}.")
    argv = [nmap_bin, "-sV", f"-{timing}", *SCAN_TYPES[scan_type]]
    if port_mode == "all":
        argv.append("-p-")
    elif port_mode == "custom":
        spec = custom_ports.replace(" ", "")
        if not spec or not _PORT_SPEC_RE.match(spec):
            raise ValueError("Custom ports must look like 22,80,8000-9000.")
        argv += ["-p", spec]
    if skip_ping:
        argv.append("-Pn")
    if exclude:
        argv += ["--exclude", ",".join(exclude)]
    argv += ["-oX", "-"]
    argv += targets
    return argv


# ---------------------------------------------------------------------------
# Result ingestion
# ---------------------------------------------------------------------------
import json  # noqa: E402
import logging  # noqa: E402

from sqlalchemy import select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from .. import surface  # noqa: E402
from ..db import Host, Job, Service, SurfaceChange, utcnow  # noqa: E402
from ..parsers.nmap_xml import parse_nmap_scaninfo, parse_nmap_xml  # noqa: E402
from ..rules import evaluate_rules  # noqa: E402

log = logging.getLogger(__name__)


def _job_params(job: Job) -> dict:
    try:
        p = json.loads(job.params_json or "{}")
    except json.JSONDecodeError:
        p = {}
    return p if isinstance(p, dict) else {}


def ingest_nmap_results(db: Session, job: Job, xml_text: str) -> dict:
    """Record surface changes, then upsert hosts and replace each seen host's services within the scanned port set."""
    hosts = parse_nmap_xml(xml_text)
    scanned = parse_nmap_scaninfo(xml_text)
    params = _job_params(job)
    changes = surface.diff_and_record(db, job, hosts, scanned, params.get("targets") or [], params.get("exclude") or [])
    now = utcnow()
    service_count = 0
    host_ids: dict[str, int] = {}
    for h in hosts:
        host = db.scalar(select(Host).where(Host.address == h.address))
        if host is None:
            host = Host(address=h.address, first_seen=now)
            db.add(host)
            db.flush()
        host_ids[h.address] = host.id
        if h.hostname:
            host.hostname = h.hostname
        host.last_seen = now
        host.last_job_id = job.id
        existing = {(s.port, s.protocol): s for s in host.services}
        seen: set[tuple[int, str]] = set()
        for p in h.ports:
            key = (p.port, p.protocol)
            seen.add(key)
            svc = existing.get(key)
            if svc is None:
                svc = Service(host=host, port=p.port, protocol=p.protocol)
                db.add(svc)
            svc.state = p.state
            svc.service_name = p.service
            svc.product = p.product
            svc.version = p.version
            svc.extra_info = p.extra_info
            svc.cpe = p.cpe
            svc.tunnel = p.tunnel
            svc.job_id = job.id
            service_count += 1
        for key, svc in existing.items():
            if key not in seen and surface.is_scanned(scanned, *key):  # ports this scan did not probe are kept
                db.delete(svc)
    for c in changes:
        if c.host_id is None:
            c.host_id = host_ids.get(c.address)
    db.flush()
    return {"hosts": len(hosts), "services": service_count, "changes": len(changes)}


def _merge_params(params_json: str, extra: dict) -> str:
    try:
        p = json.loads(params_json or "{}")
    except json.JSONDecodeError:
        p = {}
    p.update(extra)
    return json.dumps(p)


def on_nmap_complete(db: Session, job: Job, output: str) -> str:
    stats = ingest_nmap_results(db, job, output)
    stats["rule_matches"] = evaluate_rules(db)
    job.params_json = _merge_params(job.params_json, {"result": stats})
    if stats["changes"]:
        try:
            with db.begin_nested():
                changes = list(db.scalars(select(SurfaceChange).where(SurfaceChange.job_id == job.id)
                                          .order_by(SurfaceChange.id)))
                surface.notify_changes(db, job, changes)
        except Exception:  # noqa: BLE001 - a notification problem must never fail the ingest
            log.exception("surface change notification for job %s failed", job.id)
    return (f"[nmap] {stats['hosts']} host(s) up, {stats['services']} open service(s) stored, "
            f"{stats['rule_matches']} version-rule match(es), {stats['changes']} surface change(s).")
