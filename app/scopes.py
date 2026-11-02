"""Scopes: named asset groups. Matching addresses / host names against nmap-style target lists."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import Host, Issue, Scope, Service
from .i18n import Msg
from .validation import parse_nmap_targets

CRITICALITIES = ("critical", "high", "medium", "low")
CRIT_RANK = {c: i for i, c in enumerate(CRITICALITIES)}
_OCTET = r"(?:\*|\d{1,3}(?:-\d{1,3})?)"
_OCTET_RANGE_RE = re.compile(rf"^{_OCTET}(?:\.{_OCTET}){{3}}$")


def _split(text: str) -> list[str]:
    return [t.strip() for t in (text or "").replace(",", "\n").splitlines() if t.strip()]


def _octet_ok(spec: str, value: int) -> bool:
    if spec == "*":
        return True
    if "-" in spec:
        lo, hi = (int(x) for x in spec.split("-", 1))
        return lo <= value <= hi
    return int(spec) == value


@dataclass
class Matcher:
    networks: list = field(default_factory=list)
    octet_ranges: list[list[str]] = field(default_factory=list)
    names: set[str] = field(default_factory=set)

    @classmethod
    def parse(cls, targets: list[str]) -> "Matcher":
        m = cls()
        for t in targets:
            try:
                m.networks.append(ipaddress.ip_network(t, strict=False))
                continue
            except ValueError:
                pass
            if _OCTET_RANGE_RE.match(t):
                m.octet_ranges.append(t.split("."))
            else:
                m.names.add(t.lower().rstrip("."))
        return m

    def matches(self, address: str, hostname: str = "") -> bool:
        names = {n.lower().rstrip(".") for n in (address, hostname) if n}
        if names & self.names:
            return True
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        if any(ip in net for net in self.networks if net.version == ip.version):
            return True
        if ip.version == 4 and self.octet_ranges:
            octets = [int(x) for x in address.split(".")]
            return any(all(_octet_ok(s, v) for s, v in zip(spec, octets)) for spec in self.octet_ranges)
        return False

    def __bool__(self) -> bool:
        return bool(self.networks or self.octet_ranges or self.names)


def services_in(db: Session, include: list[str], exclude: list[str] | tuple = ()) -> list[str]:
    """nuclei targets (``service_to_target``) for every inventory service whose host matches ``include`` and not
    ``exclude`` (scope / nmap target syntax), de-duplicated, ordered by address and port. Used by nuclei schedules
    and by the Quick scan nuclei step."""
    from .routers.inventory import service_to_target  # local import: the inventory router imports this module
    inc, exc = Matcher.parse(list(include)), Matcher.parse(list(exclude))
    out: list[str] = []
    seen: set[str] = set()
    for svc, host in db.execute(select(Service, Host).join(Host, Host.id == Service.host_id)
                                .order_by(Host.address, Service.port)):
        name = host.hostname or ""
        if inc.matches(host.address, name) and not exc.matches(host.address, name):
            t = service_to_target(host.address, svc)
            if t not in seen:
                seen.add(t)
                out.append(t)
    return out


def validate_scope_fields(name: str, targets: str, exclusions: str, criticality: str) -> str | None:
    if not name.strip():
        return Msg("Give the scope a name.")
    if len(name.strip()) > 128:
        return Msg("Scope name is too long (max 128).")
    if criticality not in CRITICALITIES:
        return Msg("Unknown criticality.")
    try:
        parse_nmap_targets(targets)
    except ValueError as e:
        return Msg("Targets: {error}", error=e.args[0] if e.args else str(e))
    if exclusions.strip():
        try:
            parse_nmap_targets(exclusions)
        except ValueError as e:
            return Msg("Exclusions: {error}", error=e.args[0] if e.args else str(e))
    return None


CompiledScope = tuple[Scope, Matcher, Matcher]


def compile_scopes(db: Session) -> list[CompiledScope]:
    out = [(s, Matcher.parse(_split(s.targets)), Matcher.parse(_split(s.exclusions))) for s in db.scalars(select(Scope))]
    out.sort(key=lambda x: (CRIT_RANK.get(x[0].criticality, 99), x[0].id))
    return out


def resolve_scope(compiled: list[CompiledScope], address: str, hostname: str = "") -> Scope | None:
    for scope, include, exclude in compiled:
        if include.matches(address, hostname) and not exclude.matches(address, hostname):
            return scope
    return None


def inventory_hostname(db: Session, address: str) -> str:
    return db.scalar(select(Host.hostname).where(Host.address == address)) or ""


def scope_for_asset(db: Session, address: str, hostname: str = "", compiled=None) -> Scope | None:
    compiled = compiled if compiled is not None else compile_scopes(db)
    return resolve_scope(compiled, address, hostname or inventory_hostname(db, address))


def rescope_issues(db: Session) -> int:
    """Recompute scope_id for every issue (assignees are never touched). Returns issues changed."""
    compiled = compile_scopes(db)
    hostnames = {h.address: h.hostname or "" for h in db.scalars(select(Host))}
    changed = 0
    for issue in db.scalars(select(Issue)):
        scope = resolve_scope(compiled, issue.address, issue.hostname or hostnames.get(issue.address, ""))
        new = scope.id if scope else None
        if issue.scope_id != new:
            issue.scope_id = new
            changed += 1
    db.flush()
    return changed


def scope_of_hosts(db: Session) -> dict[int, Scope]:
    """host id -> scope, for grouping the inventory."""
    compiled = compile_scopes(db)
    out = {}
    for h in db.scalars(select(Host)):
        s = resolve_scope(compiled, h.address, h.hostname or "")
        if s:
            out[h.id] = s
    return out
