"""External asset discovery. subfinder finds subdomains of the operator's root domains (passive sources), httpx then
probes which of them serve web content (active). Results land in ``discovered_assets``; names seen for the first time
become ``subdomain_new`` surface changes. Everything the tools return, and everything the probed web servers say
(titles, server headers, tech names, URLs), is hostile text: validated or truncated here, autoescaped when rendered."""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from . import surface
from .config import Settings
from .db import AppSetting, DiscoveredAsset, Job, SurfaceChange, utcnow
from .jobs import quote_argv
from .scopes import compile_scopes, scope_for_asset

log = logging.getLogger(__name__)

MAX_ROOTS = 20
MAX_PROBE_HOSTS = 5000
HTTPX_RATE_LIMIT = 50
NEW_DAYS = 7
PAGE_SIZE = 100
WEB_FILTERS = {"any": "Any", "web": "Web only", "none": "No web"}
STATES = {"active": "Active", "ignored": "Ignored", "all": "All"}
KEYS_SETTING = "discovery_source_keys"
MAX_KEY_LEN = 512
CHUNK = 500  # stay below SQLite's bound-parameter limit in IN (...) lists

# subfinder providers whose keys can be set on the Settings page (id: label, expected format, two-part key?)
PROVIDERS = {
    "securitytrails": ("SecurityTrails", "API key", False),
    "shodan": ("Shodan", "API key", False),
    "censys": ("Censys", "id:secret", True),
    "virustotal": ("VirusTotal", "API key", False),
    "chaos": ("Chaos", "API key", False),
    "github": ("GitHub", "token", False),
    "binaryedge": ("BinaryEdge", "API key", False),
    "fofa": ("FOFA", "email:key", True),
}

_ROOT_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HOST_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")  # names in the wild may carry '_'
_SOURCE_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")


# ----------------------------------------------------------------- validation
def _is_ip_or_cidr(text: str) -> bool:
    for parse in (ipaddress.ip_address, lambda t: ipaddress.ip_network(t, strict=False)):
        try:
            parse(text)
            return True
        except ValueError:
            pass
    return False


def _idna(name: str) -> str:
    """Unicode labels to punycode ('bücher.example' -> 'xn--bcher-kva.example'); raises UnicodeError."""
    return name if name.isascii() else name.encode("idna").decode("ascii")


def parse_root_domains(value: str | list[str]) -> list[str]:
    """Root domains from a textarea (one per line or comma separated) or a list. Lowercased, trailing dot dropped,
    IDNA-encoded, de-duplicated. Raises ValueError with an operator-facing message."""
    items = value if isinstance(value, list) else (value or "").replace(",", "\n").splitlines()
    out: list[str] = []
    for raw in items:
        t = str(raw).strip()
        if not t:
            continue
        if _is_ip_or_cidr(t):
            raise ValueError(f"{t!r} is an IP address or CIDR range. Enter domain names such as example.com; "
                             "scan IP ranges with nmap.")
        if "://" in t:
            raise ValueError(f"{t!r}: enter the domain without a scheme, e.g. example.com.")
        if "/" in t:
            raise ValueError(f"{t!r}: enter the domain without a path, e.g. example.com.")
        if "*" in t:
            raise ValueError(f"{t!r}: no wildcard needed, subfinder finds every subdomain of example.com.")
        name = t.lower().rstrip(".")
        try:
            name = _idna(name)
        except UnicodeError:
            raise ValueError(f"{t[:80]!r} is not a valid DNS name.")
        if len(name) > 253:
            raise ValueError(f"{t[:40]!r}… is longer than 253 characters.")
        if "." not in name:
            raise ValueError(f"{t!r}: a root domain needs at least one dot, e.g. example.com.")
        labels = name.split(".")
        if not all(_ROOT_LABEL_RE.match(lab) for lab in labels) or labels[-1].isdigit():
            raise ValueError(f"{t[:80]!r} is not a valid DNS name.")
        if name not in out:
            out.append(name)
    if not out:
        raise ValueError("Enter at least one root domain.")
    if len(out) > MAX_ROOTS:
        raise ValueError(f"Too many root domains ({len(out)}); the maximum is {MAX_ROOTS} per job.")
    return out


def normalize_hostname(value) -> str | None:
    """A host name reported by a tool, normalised (lowercase, no trailing dot), or None when it is not a DNS name."""
    if not isinstance(value, str):
        return None
    name = value.strip().lower().rstrip(".")
    try:
        name = _idna(name)
    except UnicodeError:
        return None
    if not name or len(name) > 253 or _is_ip_or_cidr(name):
        return None
    return name if all(_HOST_LABEL_RE.match(lab) for lab in name.split(".")) else None


def root_for(host: str, roots: list[str]) -> str | None:
    """The most specific root ``host`` belongs to (equal to it or ending in '.<root>'), else None."""
    matches = [r for r in roots if host == r or host.endswith("." + r)]
    return max(matches, key=len) if matches else None


def _clean(value, limit: int) -> str:
    """Remote text: control characters become spaces, whitespace is collapsed, length is capped."""
    if value is None or isinstance(value, (dict, list)):
        return ""
    return " ".join(_CONTROL_RE.sub(" ", str(value)).split())[:limit]


def _join_capped(items: list[str], limit: int) -> str:
    out: list[str] = []
    for it in items:
        if len(",".join(out + [it])) > limit:
            break
        out.append(it)
    return ",".join(out)


# ----------------------------------------------------------------- tool output
def _json_lines(text: str):
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            yield obj


def parse_subfinder_jsonl(text: str, roots: list[str]) -> dict[str, dict]:
    """subfinder ``-json`` lines -> {hostname: {"root", "sources"}}. Names outside every root, malformed lines and
    unsafe source names are dropped; duplicates (one line per source) are merged."""
    out: dict[str, dict] = {}
    for obj in _json_lines(text):
        host = normalize_hostname(obj.get("host"))
        root = root_for(host, roots) if host else None
        if root is None:
            continue
        entry = out.setdefault(host, {"root": root, "sources": []})
        sources = obj.get("sources") if isinstance(obj.get("sources"), list) else [obj.get("source")]
        for src in sources:
            if isinstance(src, str) and _SOURCE_RE.match(src) and src.lower() not in entry["sources"]:
                entry["sources"].append(src.lower())
    return out


def _input_host(value) -> str | None:
    """Host name from an httpx ``input`` / ``host`` value: bare name, name:port or a URL. IPs give None."""
    if not isinstance(value, str):
        return None
    v = value.strip()
    if "://" in v:
        try:
            v = urlsplit(v).hostname or ""
        except ValueError:
            return None
    else:
        v = v.split("/", 1)[0]
        if v.count(":") == 1:
            v = v.split(":", 1)[0]
    return normalize_hostname(v)


def _ips(obj: dict) -> list[str]:
    cands = list(obj.get("a") or []) if isinstance(obj.get("a"), list) else []
    cands += [obj.get("host"), obj.get("host_ip")]
    out: list[str] = []
    for c in cands:
        if isinstance(c, str):
            try:
                ip = str(ipaddress.ip_address(c.strip()))
            except ValueError:
                continue
            if ip not in out:
                out.append(ip)
    return out[:20]


def _status(value) -> int | None:
    try:
        code = int(value)
    except (TypeError, ValueError):
        return None
    return code if 100 <= code <= 999 else None


def parse_httpx_jsonl(text: str) -> dict[str, dict]:
    """httpx ``-json`` lines -> {hostname: {"url", "status_code", "title", "webserver", "tech", "ips"}}. The host is
    taken from ``input`` (what we asked for), else ``host``. The first answer per host wins; IPs are merged."""
    out: dict[str, dict] = {}
    for obj in _json_lines(text):
        host = _input_host(obj.get("input")) or _input_host(obj.get("host"))
        if not host:
            continue
        ips = _ips(obj)
        if host in out:
            out[host]["ips"] += [ip for ip in ips if ip not in out[host]["ips"]]
            continue
        tech = obj.get("tech") if isinstance(obj.get("tech"), list) else []
        out[host] = {"url": _clean(obj.get("url"), 2048), "status_code": _status(obj.get("status_code")),
                     "title": _clean(obj.get("title"), 255), "webserver": _clean(obj.get("webserver"), 255),
                     "tech": [t for t in (_clean(x, 100).replace(",", " ") for x in tech) if t], "ips": ips}
    return out


def build_subfinder_argv(subfinder_bin: str, domains_file: str, provider_config: str | None = None) -> list[str]:
    """Default sources only: ``-all`` is slow and noisy. Keys are never on the command line, only the config path."""
    argv = [subfinder_bin, "-dL", domains_file, "-silent", "-json"]
    if provider_config:
        argv += ["-pc", provider_config]
    return argv


def build_httpx_argv(httpx_bin: str, hosts_file: str) -> list[str]:
    return [httpx_bin, "-l", hosts_file, "-silent", "-json", "-title", "-status-code", "-tech-detect", "-web-server",
            "-ip", "-follow-redirects", "-no-color", "-rate-limit", str(HTTPX_RATE_LIMIT)]


# ----------------------------------------------------------------- ingest
def _params(job: Job) -> dict:
    try:
        p = json.loads(job.params_json or "{}")
    except json.JSONDecodeError:
        p = {}
    return p if isinstance(p, dict) else {}


def _merge_params(job: Job, **extra) -> None:
    p = _params(job)
    p.update(extra)
    job.params_json = json.dumps(p)


def _load(db: Session, hostnames: list[str]) -> dict[str, DiscoveredAsset]:
    out: dict[str, DiscoveredAsset] = {}
    for i in range(0, len(hostnames), CHUNK):
        chunk = hostnames[i:i + CHUNK]
        out.update((a.hostname, a) for a in db.scalars(select(DiscoveredAsset).where(DiscoveredAsset.hostname.in_(chunk))))
    return out


def _rescope(db: Session, compiled, a: DiscoveredAsset) -> None:
    ips = a.ip_list
    scope = scope_for_asset(db, ips[0] if ips else "", a.hostname, compiled)
    a.scope_id = scope.id if scope else None


def covered_roots(db: Session, job: Job) -> set[str]:
    """Root domains an earlier, successful discovery job already enumerated (the rest are this job's baseline)."""
    out: set[str] = set()
    for raw in db.scalars(select(Job.params_json).where(Job.kind == "discovery", Job.status == "done", Job.id != job.id)):
        try:
            domains = json.loads(raw or "{}").get("domains") or []
        except (json.JSONDecodeError, AttributeError):
            continue
        out.update(d for d in domains if isinstance(d, str))
    return out


def complete_discovery(db: Session, job: Job, output: str) -> dict:
    """Upsert the subdomains subfinder found, record ``subdomain_new`` changes for first-time names and send one
    ``surface.changed`` notification for them. Roots no earlier job covered are a silent baseline."""
    roots = [r for r in _params(job).get("domains") or [] if isinstance(r, str)]
    found = parse_subfinder_jsonl(output, roots)
    baseline = set(roots) - covered_roots(db, job)
    now, compiled = utcnow(), compile_scopes(db)
    existing = _load(db, sorted(found))
    changes: list[tuple[SurfaceChange, str]] = []
    for host in sorted(found):
        info = found[host]
        a = existing.get(host)
        is_new = a is None
        if is_new:
            a = DiscoveredAsset(root_domain=info["root"], hostname=host, first_seen=now, sources="", web=False,
                                ignored=False)
            db.add(a)
        old = [x for x in a.sources.split(",") if x]
        a.sources = _join_capped(old + [x for x in info["sources"] if x not in old], 500)
        a.last_seen, a.last_job_id = now, job.id
        _rescope(db, compiled, a)
        if is_new:
            c = SurfaceChange(job_id=job.id, address=host, hostname=host, kind="subdomain_new",
                              after=", ".join(info["sources"])[:surface.MAX_TEXT],
                              severity=surface.KIND_SEVERITY["subdomain_new"], scope_id=a.scope_id, created_at=now)
            db.add(c)
            changes.append((c, info["root"]))
    db.flush()
    to_notify = [c for c, root in changes if root not in baseline]
    if to_notify:
        try:
            with db.begin_nested():
                surface.notify_changes(db, job, to_notify)
        except Exception:  # noqa: BLE001 - a notification problem must never fail the ingest
            log.exception("discovery notification for job %s failed", job.id)
    return {"hosts": len(found), "new": len(changes), "baseline": bool(baseline), "notified": len(to_notify),
            "hostnames": sorted(found)}


def ingest_probe(db: Session, job: Job, hosts: list[str], results: dict[str, dict]) -> dict:
    """Apply httpx answers to the probed rows; a probed host without an answer gets web=False."""
    now, compiled = utcnow(), compile_scopes(db)
    rows = _load(db, list(hosts))
    probed = web = 0
    for host in hosts:
        a = rows.get(host)
        if a is None:
            continue
        probed += 1
        a.last_probed_at = now
        r = results.get(host)
        if r is None:
            a.web = False
        else:
            web += 1
            a.web, a.url, a.status_code = True, r["url"], r["status_code"]
            a.title, a.webserver, a.tech = r["title"], r["webserver"], _join_capped(r["tech"], 1000)
            if r["ips"]:
                a.ips = _join_capped(r["ips"], 1000)
        _rescope(db, compiled, a)
    db.flush()
    return {"probed": probed, "web": web}


# ----------------------------------------------------------------- source API keys
def get_source_keys(db: Session, box) -> dict[str, str]:
    row = db.get(AppSetting, KEYS_SETTING)
    values = box.decrypt(row.value) if row and row.value else {}
    return {k: v for k, v in values.items() if k in PROVIDERS and isinstance(v, str) and v}


def validate_source_key(name: str, value: str) -> str | None:
    """Error message for a bad key. Never includes the key itself."""
    label, fmt, pair = PROVIDERS[name]
    if len(value) > MAX_KEY_LEN:
        return f"{label} key is too long (max {MAX_KEY_LEN} characters)."
    if any(ch.isspace() for ch in value) or _CONTROL_RE.search(value):
        return f"{label} key must be a single value without spaces or line breaks."
    if pair:
        left, _, right = value.partition(":")
        if not left or not right:
            return f"{label} key must be in the form {fmt}."
    return None


def set_source_keys(db: Session, box, updates: dict[str, str], remove: set[str]) -> tuple[list[str], list[str]]:
    """Apply new keys (blank keeps the stored one) and removals. Returns (provider names set, names removed).
    Raises ValueError (without the key value) when a key is malformed."""
    for name, value in updates.items():
        if value:
            err = validate_source_key(name, value)
            if err:
                raise ValueError(err)
    keys = get_source_keys(db, box)
    removed = sorted(n for n in remove if n in keys and not updates.get(n))
    for n in removed:
        keys.pop(n)
    changed = sorted(n for n, v in updates.items() if v and n in PROVIDERS)
    keys.update({n: updates[n] for n in changed})
    row = db.get(AppSetting, KEYS_SETTING) or AppSetting(key=KEYS_SETTING)
    row.value = box.encrypt(keys)
    db.add(row)
    db.flush()
    return changed, removed


def write_provider_config(settings: Settings, job_id: int, keys: dict[str, str]) -> Path:
    """subfinder provider-config YAML (``provider: [key]``), mode 0600. Values are JSON-quoted, which YAML reads as
    double-quoted scalars, so nothing in a key can change the structure."""
    path = settings.tmp_dir / f"subfinder-{job_id}.yaml"
    lines: list[str] = []
    for name in PROVIDERS:
        if keys.get(name):
            lines += [f"{name}:", f"  - {json.dumps(keys[name])}"]
    path.unlink(missing_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)
    return path


# ----------------------------------------------------------------- jobs
def tools_status(settings: Settings) -> dict[str, bool]:
    return {"subfinder": shutil.which(settings.subfinder_bin) is not None,
            "httpx": shutil.which(settings.httpx_bin) is not None}


def missing_tool_message(settings: Settings, tool: str) -> str:
    path = settings.subfinder_bin if tool == "subfinder" else settings.httpx_bin
    return (f"{tool} is not installed ({path} not found). It ships in the Docker image; "
            f"set {tool.upper()}_BIN when running outside it.")


def _unlink(*paths) -> None:
    for p in paths:
        if p is not None:
            Path(p).unlink(missing_ok=True)


def sweep_tmp(settings: Settings) -> int:
    """On startup: no job is running, so every leftover input file (a crash skipped its cleanup) can go."""
    n = 0
    if settings.tmp_dir.is_dir():
        for p in settings.tmp_dir.iterdir():
            if p.is_file() or p.is_symlink():
                p.unlink(missing_ok=True)
                n += 1
    return n


def launch_discovery(db: Session, settings: Settings, runner, box, roots: list[str], probe: bool, *,
                     schedule_id: int | None = None, extra_params: dict | None = None) -> Job:
    """Create and start a subfinder job for validated ``roots``; on success it chains an httpx probe job when
    ``probe`` is on and hosts were found. Raises ValueError when a needed tool is missing."""
    tools = tools_status(settings)
    if not tools["subfinder"]:
        raise ValueError(missing_tool_message(settings, "subfinder"))
    if probe and not tools["httpx"]:
        raise ValueError(missing_tool_message(settings, "httpx") + " Untick 'Probe web services' to enumerate only.")
    job = runner.create_job(db, "discovery", [settings.subfinder_bin],
                            params={"domains": roots, "probe": bool(probe), **(extra_params or {})})
    job.schedule_id = schedule_id
    domains_file = settings.tmp_dir / f"discovery-{job.id}-domains.txt"
    domains_file.write_text("\n".join(roots) + "\n")
    keys = get_source_keys(db, box)
    try:
        pc = write_provider_config(settings, job.id, keys) if keys else None
    except OSError as e:
        _unlink(domains_file, settings.tmp_dir / f"subfinder-{job.id}.yaml")
        job.status, job.finished_at = "failed", utcnow()
        job.log = f"[discovery] cannot write the subfinder provider config: {e.strerror or type(e).__name__}"
        db.commit()
        raise ValueError("Cannot write the subfinder provider config in the data directory (see the job log).")
    argv = build_subfinder_argv(settings.subfinder_bin, str(domains_file), str(pc) if pc else None)
    job.command = quote_argv(argv)
    db.commit()
    runner.start(job.id, argv, on_complete=_discovery_hook(settings, runner, bool(probe)), stdout_to_log=False,
                 cleanup=lambda: _unlink(domains_file, pc))
    return job


def _discovery_hook(settings: Settings, runner, probe: bool):
    def hook(db: Session, job: Job, output: str) -> str:
        stats = complete_discovery(db, job, output)
        hostnames = stats.pop("hostnames")
        result = {"subdomains": stats["hosts"], "new": stats["new"]}
        note = (f"[discovery] {stats['hosts']} subdomain(s) found, {stats['new']} new"
                + (" (first run for some roots: baseline, not notified)" if stats["baseline"] and stats["new"] else ""))
        if probe and hostnames:
            ignored = set(db.scalars(select(DiscoveredAsset.hostname).where(DiscoveredAsset.ignored.is_(True))))
            hosts = [h for h in hostnames if h not in ignored]
            if hosts:
                probe_job, skipped = start_probe(db, settings, runner, job, hosts)
                result["probe_job"] = probe_job.id
                note += f"; httpx probe of {min(len(hosts), MAX_PROBE_HOSTS)} host(s) started as job #{probe_job.id} (/jobs/{probe_job.id})"
                if skipped:
                    note += f". {skipped} host(s) over the {MAX_PROBE_HOSTS}-host probe cap were not probed"
        elif not probe:
            note += "; web probe off"
        _merge_params(job, result=result)
        return note + "."
    return hook


def start_probe(db: Session, settings: Settings, runner, parent: Job, hosts: list[str]) -> tuple[Job, int]:
    """Chained ``discovery_probe`` job over at most MAX_PROBE_HOSTS hosts. Returns (job, hosts left out)."""
    selected, skipped = hosts[:MAX_PROBE_HOSTS], max(0, len(hosts) - MAX_PROBE_HOSTS)
    params: dict = {"parent_job": parent.id, "hosts": len(selected)}
    if skipped:
        params["warnings"] = [f"{skipped} host(s) over the {MAX_PROBE_HOSTS}-host probe cap were not probed."]
    job = runner.create_job(db, "discovery_probe", [settings.httpx_bin], params=params)
    job.schedule_id = parent.schedule_id
    hosts_file = settings.tmp_dir / f"httpx-{job.id}-hosts.txt"
    hosts_file.write_text("\n".join(selected) + "\n")
    argv = build_httpx_argv(settings.httpx_bin, str(hosts_file))
    job.command = quote_argv(argv)
    db.commit()
    runner.start(job.id, argv, on_complete=_probe_hook(selected), stdout_to_log=False,
                 cleanup=lambda: _unlink(hosts_file))
    return job, skipped


def _probe_hook(hosts: list[str]):
    def hook(db: Session, job: Job, output: str) -> str:
        stats = ingest_probe(db, job, hosts, parse_httpx_jsonl(output))
        _merge_params(job, result=stats)
        return f"[discovery] probed {stats['probed']} host(s): {stats['web']} answered over HTTP(S)."
    return hook


# ----------------------------------------------------------------- listing
def conditions(root: str = "", q: str = "", web: str = "any", state: str = "active", new: bool = False) -> list:
    out = []
    if root:
        out.append(DiscoveredAsset.root_domain == root)
    q = (q or "").strip()
    if q:
        cols = (DiscoveredAsset.hostname, DiscoveredAsset.title, DiscoveredAsset.webserver, DiscoveredAsset.tech,
                DiscoveredAsset.ips, DiscoveredAsset.sources, DiscoveredAsset.url)
        out.append(or_(*(c.contains(q, autoescape=True) for c in cols)))
    if web == "web":
        out.append(DiscoveredAsset.web.is_(True))
    elif web == "none":
        out.append(DiscoveredAsset.web.is_(False))
    if state == "active":
        out.append(DiscoveredAsset.ignored.is_(False))
    elif state == "ignored":
        out.append(DiscoveredAsset.ignored.is_(True))
    if new:
        out.append(DiscoveredAsset.first_seen >= utcnow() - timedelta(days=NEW_DAYS))
    return out


def query(root: str = "", q: str = "", web: str = "any", state: str = "active", new: bool = False):
    return (select(DiscoveredAsset).where(*conditions(root, q, web, state, new))
            .order_by(DiscoveredAsset.root_domain, DiscoveredAsset.hostname))


def nuclei_target(a: DiscoveredAsset) -> str:
    """The probed URL when it is a valid nuclei target, else the host name."""
    from .validation import parse_nuclei_targets
    if a.link:
        try:
            return parse_nuclei_targets(a.link)[0]
        except ValueError:
            pass
    return a.hostname
