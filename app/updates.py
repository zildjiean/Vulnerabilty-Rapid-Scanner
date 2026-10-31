from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from .config import Settings

UPDATE_ACTIONS = {
    "nuclei-templates": {"label": "Update nuclei templates", "help": "Downloads the latest official nuclei-templates release into the data volume, then re-indexes."},
    "nuclei-engine": {"label": "Update nuclei engine", "help": "Self-updates the nuclei binary (nuclei -update). Lost on image rebuild; bump NUCLEI_VERSION in the Dockerfile for a permanent change."},
    "nmap-scripts": {"label": "Update nmap script DB", "help": "Rebuilds the NSE script index (nmap --script-updatedb). The nmap binary itself is updated by rebuilding the image."},
    "subfinder": {"label": "Update subfinder", "help": "Self-updates the subfinder binary (subfinder -update). Lost on image rebuild; bump SUBFINDER_VERSION in the Dockerfile for a permanent change."},
    "httpx": {"label": "Update httpx", "help": "Self-updates the ProjectDiscovery httpx binary (httpx -update). Lost on image rebuild; bump HTTPX_VERSION in the Dockerfile for a permanent change."},
}


def build_update_argv(settings: Settings, action: str) -> list[str]:
    if action == "nuclei-templates":
        return [settings.nuclei_bin, "-update-templates", "-ud", str(settings.nuclei_templates_dir), "-no-color"]
    if action == "nuclei-engine":
        return [settings.nuclei_bin, "-update", "-no-color"]
    if action == "nmap-scripts":
        return [settings.nmap_bin, "--script-updatedb"]
    if action == "subfinder":
        return [settings.subfinder_bin, "-update"]
    if action == "httpx":
        return [settings.httpx_bin, "-update"]
    raise KeyError(action)


def parse_nmap_version(text: str) -> str:
    m = re.search(r"Nmap version (\S+)", text or "")
    return m.group(1) if m else "unknown"


def parse_nuclei_version(text: str) -> str:
    """Also reads subfinder / httpx ("[INF] Current Version: v2.17.0")."""
    m = re.search(r"Version:\s*(v?\d[\w.\-]*)", text or "")
    return m.group(1) if m else "unknown"


async def _run_capture(argv: list[str], timeout: float = 15) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (FileNotFoundError, PermissionError, asyncio.TimeoutError, OSError):
        return ""
    return out.decode("utf-8", "replace")


async def tool_versions(settings: Settings) -> dict:
    nmap_out, nuclei_out, subfinder_out, httpx_out = await asyncio.gather(
        _run_capture([settings.nmap_bin, "--version"]),
        _run_capture([settings.nuclei_bin, "-version", "-disable-update-check"]),
        _run_capture([settings.subfinder_bin, "-version"]),
        _run_capture([settings.httpx_bin, "-version"]),
    )
    return {"nmap": parse_nmap_version(nmap_out), "nuclei": parse_nuclei_version(nuclei_out),
            "subfinder": parse_nuclei_version(subfinder_out), "httpx": parse_nuclei_version(httpx_out)}


def templates_info(settings: Settings) -> dict:
    info = {"templates_version": "unknown", "latest_templates_version": "unknown", "nuclei_latest_version": "unknown",
            "dir_exists": settings.nuclei_templates_dir.is_dir(), "yaml_files": 0}
    if info["dir_exists"]:
        info["yaml_files"] = sum(1 for p in settings.nuclei_templates_dir.rglob("*.yaml") if ".git" not in p.parts)
    cfg = Path.home() / ".config" / "nuclei" / ".templates-config.json"
    if cfg.is_file():
        try:
            data = json.loads(cfg.read_text())
            info["templates_version"] = data.get("templates-version") or info["templates_version"]
            info["latest_templates_version"] = data.get("latest-templates-version") or info["latest_templates_version"]
            info["nuclei_latest_version"] = data.get("nuclei-latest-version") or info["nuclei_latest_version"]
        except (json.JSONDecodeError, OSError):
            pass
    return info
