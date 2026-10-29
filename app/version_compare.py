"""Tiny dependency-free version comparison for software versions reported by nmap.

Rules: split into numeric and alphabetic segments; numeric segments compare numerically;
alphabetic segments compare lexically; pre-release markers sort below a number (1.0 > 1.0rc1)
while other suffixes sort above (9.6p1 > 9.6); missing segments count as 0.
"""
from __future__ import annotations

import re

_VERSION_TOKEN_RE = re.compile(r"\d+(?:[.\-_]?[A-Za-z0-9]+)*")
_SEGMENT_RE = re.compile(r"\d+|[A-Za-z]+")
_PRERELEASE = {"rc", "alpha", "beta", "a", "b", "dev", "pre", "snapshot", "nightly"}
_CLAUSE_RE = re.compile(r"^(<=|>=|==|!=|<|>)\s*([A-Za-z0-9][A-Za-z0-9.\-_]*)$")


def extract_version(raw: str | None) -> str | None:
    """Pull the leading version token out of an nmap version string (optional leading 'v').
    Returns None when the string does not start with a digit."""
    if not raw:
        return None
    s = raw.strip()
    if len(s) > 1 and s[0] in "vV" and s[1].isdigit():
        s = s[1:]
    m = _VERSION_TOKEN_RE.match(s)
    return m.group(0) if m else None


def _segments(version: str) -> list[int | str]:
    out: list[int | str] = []
    for seg in _SEGMENT_RE.findall(version):
        out.append(int(seg) if seg.isdigit() else seg.lower())
    return out


def _cmp_segment(a: int | str | None, b: int | str | None) -> int:
    """Pre-release markers (rc, beta, ...) sort below numbers; other alpha suffixes (p1, patch) above."""
    a = 0 if a is None else a
    b = 0 if b is None else b
    if isinstance(a, int) and isinstance(b, int):
        return (a > b) - (a < b)
    if isinstance(a, int):  # b is str
        return 1 if b in _PRERELEASE else -1
    if isinstance(b, int):  # a is str
        return -1 if a in _PRERELEASE else 1
    return (a > b) - (a < b)


def compare_versions(a: str, b: str) -> int:
    sa, sb = _segments(a), _segments(b)
    for i in range(max(len(sa), len(sb))):
        c = _cmp_segment(sa[i] if i < len(sa) else None, sb[i] if i < len(sb) else None)
        if c:
            return c
    return 0


def parse_constraint(expr: str) -> list[tuple[str, str]]:
    """'>=8.0, <8.3.15' -> [('>=','8.0'), ('<','8.3.15')]. Raises ValueError when malformed."""
    clauses: list[tuple[str, str]] = []
    for part in (expr or "").split(","):
        part = part.strip()
        if not part:
            continue
        m = _CLAUSE_RE.match(part)
        if not m:
            raise ValueError(f"Invalid version clause {part!r}. Use <, <=, >, >=, ==, != followed by a version.")
        clauses.append((m.group(1), m.group(2)))
    if not clauses:
        raise ValueError("Version constraint is empty.")
    return clauses


def check_clauses(version: str | None, clauses: list[tuple[str, str]]) -> bool:
    v = extract_version(version)
    if not v:
        return False
    for op, target in clauses:
        c = compare_versions(v, target)
        ok = {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "==": c == 0, "!=": c != 0}[op]
        if not ok:
            return False
    return True


def version_satisfies(version: str | None, constraint: str) -> bool:
    return check_clauses(version, parse_constraint(constraint))
