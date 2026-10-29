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
