"""Grouping of inventory rows for the Inventory page.

Pure functions over already-loaded ``(Service, Host)`` tuples; no database access.
"""
from __future__ import annotations

from dataclasses import dataclass, field

GROUP_MODES = ("host", "product", "type", "scope", "none")
GROUP_LABELS = {"host": "Host", "product": "Product", "type": "Service type", "scope": "Scope", "none": "None (flat list)"}
_CRIT_ORDER = ("critical", "high", "medium", "low")
DEFAULT_GROUP = "host"

# Service categories in display order. Classification uses the nmap service name first,
# then a well-known port fallback when the name is empty or unknown.
TYPE_ORDER = ("Web", "Database", "Remote access", "Mail", "File sharing", "Directory & auth",
              "Network services", "Other")

_NAMES: dict[str, set[str]] = {
    "Web": {"http", "https", "http-proxy", "http-alt", "www", "www-http", "webcache", "http-mgmt", "websocket",
            "caddy", "nginx", "apache"},
    "Database": {"mysql", "mariadb", "postgresql", "postgres", "ms-sql-s", "ms-sql", "mssql", "oracle", "oracle-tns",
                 "mongodb", "mongod", "redis", "memcached", "memcache", "couchdb", "cassandra", "elasticsearch",
                 "db2", "cockroachdb", "clickhouse", "neo4j", "influxdb"},
    "Remote access": {"ssh", "telnet", "rdp", "ms-wbt-server", "vnc", "vnc-http", "x11", "winrm", "wsman", "wsmans",
                      "shell", "login", "exec", "rlogin", "rsh", "teamviewer", "anydesk", "spice"},
    "Mail": {"smtp", "smtps", "submission", "imap", "imaps", "pop3", "pop3s", "exchange", "lmtp"},
    "File sharing": {"ftp", "ftps", "ftp-data", "sftp", "tftp", "smb", "microsoft-ds", "netbios-ssn", "nfs",
                     "rsync", "afp", "webdav", "cifs"},
    "Directory & auth": {"ldap", "ldaps", "ldapssl", "kerberos", "kerberos-sec", "kpasswd5", "radius", "msrpc",
                         "epmap", "globalcatldap", "globalcatldapssl", "tacacs", "saml"},
    "Network services": {"domain", "dns", "dhcp", "dhcps", "snmp", "ntp", "syslog", "bgp", "sip", "mdns", "upnp",
                         "ipp", "printer", "netbios-ns", "ssdp"},
}

_PORTS: dict[str, set[int]] = {
    "Web": {80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9443},
    "Database": {1433, 1521, 3306, 5432, 5984, 6379, 7474, 7687, 8086, 9042, 9200, 11211, 27017},
    "Remote access": {22, 23, 3389, 5900, 5901, 5902, 5903, 5985, 5986},
    "Mail": {25, 110, 143, 465, 587, 993, 995},
    "File sharing": {20, 21, 69, 139, 445, 873, 2049},
    "Directory & auth": {88, 135, 389, 636, 1812, 3268, 3269},
    "Network services": {53, 67, 123, 161, 514, 631, 5353},
}


def service_type(svc) -> str:
    """Return the category label for a service (see TYPE_ORDER)."""
    name = (svc.service_name or "").strip().lower()
    if name.startswith("ssl/"):
        name = name[4:]
    if name:
        for label, names in _NAMES.items():
            if name in names:
                return label
    try:
        port = int(svc.port)
    except (TypeError, ValueError):
        return "Other"
    for label, ports in _PORTS.items():
        if port in ports:
            return label
    return "Other"


def normalize_group_mode(mode: str | None) -> str:
    return mode if mode in GROUP_MODES else DEFAULT_GROUP


@dataclass
class Group:
    key: str
    label: str
    sublabel: str = ""
    rows: list = field(default_factory=list)
    host_count: int = 0
    match_count: int = 0


def group_rows(rows, mode: str, matches: dict, scope_of: dict | None = None) -> list[Group]:
    """Split ``(service, host)`` rows into ordered groups for ``mode``.

    ``matches`` maps service id -> list of rule matches; only its lengths are used.
    ``scope_of`` maps host id -> Scope (mode ``scope``); hosts without one go to "Unscoped".
    Returns ``[]`` for mode ``none``.
    """
    mode = normalize_group_mode(mode)
    if mode == "none":
        return []
    buckets: dict[str, Group] = {}
    for svc, host in rows:
        if mode == "host":
            key, label, sub = f"h{host.id}", host.address, host.hostname or ""
        elif mode == "scope":
            sc = (scope_of or {}).get(host.id)
            key, label, sub = (f"s{sc.id}", sc.name, f"{sc.criticality} criticality") if sc else ("s:", "Unscoped", "")
        elif mode == "product":
            prod = (svc.product or "").strip()
            key, label, sub = ("p:" + prod.lower()) if prod else "p:", prod or "Unknown product", ""
        else:
            label = service_type(svc)
            key, sub = "t:" + label.lower().replace(" ", "-").replace("&", "and"), ""
        g = buckets.get(key)
        if g is None:
            g = buckets[key] = Group(key=key, label=label, sublabel=sub)
        g.rows.append((svc, host))
        g.match_count += len(matches.get(svc.id, ()))
    for g in buckets.values():
        g.host_count = len({host.id for _, host in g.rows})
    groups = list(buckets.values())
    if mode == "product":
        groups.sort(key=lambda g: (g.key == "p:", g.label.lower()))
    elif mode == "type":
        groups.sort(key=lambda g: TYPE_ORDER.index(g.label))
    elif mode == "scope":
        crit = {s.id: s.criticality for s in (scope_of or {}).values()}
        groups.sort(key=lambda g: (g.key == "s:", _CRIT_ORDER.index(crit.get(int(g.key[1:]), "low"))
                                   if g.key != "s:" else 9, g.label.lower()))
    return groups
