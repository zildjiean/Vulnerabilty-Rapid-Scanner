"""Validate operator-supplied target lists. Targets are passed to subprocesses as argv items
(never via a shell), so the goal here is: no whitespace, no leading '-', sane length, allowlisted chars."""
from __future__ import annotations

import re

_NMAP_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:/]*$")
_NUCLEI_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:/_?=&%@\[\]~+]*$")
MAX_TARGET_LEN = 253
MAX_TARGETS = 5000


def _split(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in (text or "").replace(",", "\n").splitlines():
        t = raw.strip()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


def _validate(items: list[str], pattern: re.Pattern[str], label: str) -> list[str]:
    if not items:
        raise ValueError(f"Enter at least one {label}.")
    if len(items) > MAX_TARGETS:
        raise ValueError(f"Too many targets (max {MAX_TARGETS}).")
    for t in items:
        if len(t) > MAX_TARGET_LEN:
            raise ValueError(f"Target too long: {t[:40]}…")
        if t.startswith("-") or not pattern.match(t):
            raise ValueError(f"Invalid {label}: {t!r}")
    return items


def parse_nmap_targets(text: str) -> list[str]:
    """IPs, CIDRs, nmap ranges (10.0.0.1-20), hostnames, IPv6."""
    return _validate(_split(text), _NMAP_TARGET_RE, "nmap target")


def parse_nuclei_targets(text: str) -> list[str]:
    """URLs (http/https) or host[:port] entries."""
    items = _validate(_split(text), _NUCLEI_TARGET_RE, "nuclei target")
    for t in items:
        if "://" in t and not (t.startswith("http://") or t.startswith("https://")):
            raise ValueError(f"Only http:// and https:// URLs are supported: {t!r}")
    return items
