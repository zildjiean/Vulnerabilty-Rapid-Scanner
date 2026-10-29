from __future__ import annotations

import re

TIMINGS = ("T2", "T3", "T4")
SCAN_TYPES = {"syn": ["-sS", "--privileged"], "connect": ["-sT"]}
PORT_MODES = ("top", "all", "custom")
_PORT_SPEC_RE = re.compile(r"^[0-9][0-9,\-]*$")


def build_nmap_argv(nmap_bin: str, targets: list[str], port_mode: str = "top", custom_ports: str = "",
                    timing: str = "T3", skip_ping: bool = False, scan_type: str = "syn") -> list[str]:
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
    argv += ["-oX", "-"]
    argv += targets
    return argv


# ---------------------------------------------------------------------------
# Result ingestion
# ---------------------------------------------------------------------------
import json  # noqa: E402

from sqlalchemy import select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from ..db import Host, Job, Service, utcnow  # noqa: E402
from ..parsers.nmap_xml import parse_nmap_xml  # noqa: E402


def ingest_nmap_results(db: Session, job: Job, xml_text: str) -> dict:
    """Upsert hosts; replace each seen host's service set with the ports found in this scan."""
    hosts = parse_nmap_xml(xml_text)
    now = utcnow()
    service_count = 0
    for h in hosts:
        host = db.scalar(select(Host).where(Host.address == h.address))
        if host is None:
            host = Host(address=h.address, first_seen=now)
            db.add(host)
            db.flush()
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
            if key not in seen:
                db.delete(svc)
    db.flush()
    return {"hosts": len(hosts), "services": service_count}


def _merge_params(params_json: str, extra: dict) -> str:
    try:
        p = json.loads(params_json or "{}")
    except json.JSONDecodeError:
        p = {}
    p.update(extra)
    return json.dumps(p)


def on_nmap_complete(db: Session, job: Job, output: str) -> None:
    stats = ingest_nmap_results(db, job, output)
    job.params_json = _merge_params(job.params_json, {"result": stats})
