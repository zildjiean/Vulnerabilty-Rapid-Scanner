"""0-day watch: every hour, find newly published or newly exploited CVEs (NVD, CISA KEV) that affect services in the
inventory and prepare a *draft* campaign for each one, for a person to review and activate.

Only public data is requested (NVD CVE API 2.0, the CISA KEV feed); no inventory data leaves the scanner.
The scheduler calls ``maybe_watch`` every tick (same pattern as ``risk.maybe_refresh_intel``).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Callable, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import AppSetting, AuditLog, Campaign, Host, Service, WatchHit, utcnow
from .intel import (MAX_REFERENCES, NVD_URL, GetJson, _best_metric, _parse_time, http_get_json, load_kev_feed,
                    normalize_cve, nvd_wait)
from .risk import short_error
from .rules import _service_version
from .version_compare import check_clauses, compare_versions, extract_version, parse_constraint

log = logging.getLogger(__name__)

WATCH_KEY = "watch"
WATCH_EVERY = timedelta(minutes=60)
STARTUP_DELAY = timedelta(minutes=3)
NVD_PAGE_SIZE = 500                      # big pages time out on the public API
NVD_TIMEOUT = 60                         # seconds per NVD request
NVD_SUB_WINDOW = timedelta(days=1)       # the checkpoint advances after each fully read sub-window
NVD_OVERLAP = timedelta(minutes=30)      # each window starts a little before the previous end (drafting is idempotent)
KEV_OVERLAP = timedelta(days=1)
DRAFT_MAX_AGE = timedelta(days=30)       # older CVEs that NVD reports as modified are kept as hits, not drafted
NVD_MAX_WINDOW = timedelta(days=120)     # NVD rejects lastMod ranges longer than 120 days
FIRST_NVD_BACK = timedelta(days=3)
FIRST_KEV_BACK = timedelta(days=14)
KEV_NVD_LOOKUPS = 5                      # single-CVE NVD lookups for KEV entries without CPE ranges, per run
MAX_RULES = 5
HIT_ROWS = 100
AUTHOR = "0-day watch"
DEFAULTS = {"enabled": True, "min_cvss": 7.0, "kev_always": True, "include_possible": True, "max_drafts": 20}
QUALITY_RANK = {"confirmed": 0, "possible": 1}

# Normalised nmap product name (prefix) -> NVD CPE (vendor, product) keys.
PRODUCT_ALIASES: dict[str, list[tuple[str, str]]] = {
    "apache httpd": [("apache", "http_server")],
    "apache tomcat": [("apache", "tomcat")],
    "apache struts": [("apache", "struts")],
    "nginx": [("f5", "nginx"), ("nginx", "nginx")],
    "openssh": [("openbsd", "openssh")],
    "microsoft iis httpd": [("microsoft", "internet_information_services"), ("microsoft", "iis")],
    "php": [("php", "php")],
    "mysql": [("oracle", "mysql"), ("mysql", "mysql")],
    "mariadb": [("mariadb", "mariadb")],
    "postgresql db": [("postgresql", "postgresql")],
    "exim smtpd": [("exim", "exim")],
    "postfix smtpd": [("postfix", "postfix")],
    "dovecot imapd": [("dovecot", "dovecot")],
    "dovecot pop3d": [("dovecot", "dovecot")],
    "samba smbd": [("samba", "samba")],
    "vsftpd": [("vsftpd_project", "vsftpd"), ("beasts", "vsftpd")],
    "proftpd": [("proftpd", "proftpd")],
    "openldap": [("openldap", "openldap")],
    "redis key-value store": [("redis", "redis")],
    "elasticsearch rest api": [("elastic", "elasticsearch")],
    "jetty": [("eclipse", "jetty")],
    "lighttpd": [("lighttpd", "lighttpd")],
    "microsoft exchange smtpd": [("microsoft", "exchange_server")],
    "microsoft terminal services": [("microsoft", "remote_desktop_services")],
    "jenkins": [("jenkins", "jenkins")],
    "gitlab": [("gitlab", "gitlab")],
    "grafana": [("grafana", "grafana")],
    "squid http proxy": [("squid-cache", "squid")],
    "varnish": [("varnish-cache", "varnish")],
    "haproxy": [("haproxy", "haproxy")],
    "node.js express framework": [("expressjs", "express")],
    "busybox": [("busybox", "busybox")],
    "openssl": [("openssl", "openssl")],
    "atlassian confluence": [("atlassian", "confluence_server"), ("atlassian", "confluence_data_center")],
    "fortinet fortigate": [("fortinet", "fortios")],
    "citrix netscaler": [("citrix", "netscaler_application_delivery_controller")],
}


# ----------------------------------------------------------------- settings and state
def load_state(db: Session) -> dict:
    """Settings (enabled, min_cvss, kev_always, include_possible) and state (last_nvd_check, last_kev_date, last_run)."""
    row = db.get(AppSetting, WATCH_KEY)
    try:
        data = json.loads(row.value) if row and row.value else {}
    except json.JSONDecodeError:
        data = {}
    return {**DEFAULTS, **(data if isinstance(data, dict) else {})}


def save_state(db: Session, data: dict) -> None:
    row = db.get(AppSetting, WATCH_KEY) or AppSetting(key=WATCH_KEY)
    row.value = json.dumps(data, default=str)
    db.add(row)


def set_watch_settings(db: Session, enabled: bool, min_cvss: str, kev_always: bool, include_possible: bool,
                       max_drafts: str | int = DEFAULTS["max_drafts"]) -> dict:
    try:
        score = float(str(min_cvss).strip())
    except ValueError:
        raise ValueError("Minimum CVSS must be a number between 0 and 10.")
    if not 0 <= score <= 10:
        raise ValueError("Minimum CVSS must be a number between 0 and 10.")
    limit = str(max_drafts).strip()
    if not limit.isdigit() or not 1 <= int(limit) <= 200:
        raise ValueError("Drafts per run must be a whole number between 1 and 200.")
    data = load_state(db)
    data.update(enabled=bool(enabled), min_cvss=score, kev_always=bool(kev_always), include_possible=bool(include_possible),
                max_drafts=int(limit))
    save_state(db, data)
    db.flush()
    return data


def last_run(db: Session) -> dict | None:
    """The last run's summary with ``at`` as a datetime; None before the first run."""
    run = load_state(db).get("last_run")
    if not isinstance(run, dict):
        return None
    try:
        return {**run, "at": datetime.fromisoformat(run["at"])}
    except (KeyError, TypeError, ValueError):
        return None


# ----------------------------------------------------------------- NVD
def nvd_time(dt: datetime) -> str:
    """NVD 2.0 date parameter: '2026-10-30T00:00:00.000' (UTC)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def split_cpe23(criteria: str) -> tuple[str, str, str] | None:
    """'cpe:2.3:a:apache:http_server:2.4.49:*:…' -> ('apache', 'http_server', '2.4.49'); '*' / '-' versions -> '*'."""
    parts = (criteria or "").split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    vendor, product, version = parts[3].lower(), parts[4].lower(), parts[5]
    if not vendor or not product:
        return None
    return vendor.replace("\\", ""), product.replace("\\", ""), "*" if version in ("", "*", "-") else version.replace("\\", "")


def _ranges(cve: dict) -> list[dict]:
    out, seen = [], set()
    for conf in cve.get("configurations") or []:
        for node in (conf.get("nodes") or []) if isinstance(conf, dict) else []:
            for m in (node.get("cpeMatch") or []) if isinstance(node, dict) else []:
                if not isinstance(m, dict) or not m.get("vulnerable"):
                    continue
                cpe = split_cpe23(str(m.get("criteria", "")))
                if cpe is None:
                    continue
                r = {"vendor": cpe[0], "product": cpe[1], "version": cpe[2],
                     "start_incl": str(m.get("versionStartIncluding") or ""),
                     "start_excl": str(m.get("versionStartExcluding") or ""),
                     "end_incl": str(m.get("versionEndIncluding") or ""),
                     "end_excl": str(m.get("versionEndExcluding") or "")}
                key = tuple(r.values())
                if key not in seen:
                    seen.add(key)
                    out.append(r)
    return out


def parse_nvd_item(item: dict) -> dict | None:
    """One ``vulnerabilities[]`` entry -> watch record (id, intel and vulnerable CPE ranges); None when malformed."""
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        return None
    try:
        cve_id = normalize_cve(str(cve.get("id", "")))
    except ValueError:
        return None
    desc = next((d.get("value", "") for d in cve.get("descriptions") or [] if isinstance(d, dict) and d.get("lang") == "en"), "")
    rec = {"cve_id": cve_id, "published": _parse_time(cve.get("published", "")), "description": desc,
           "cvss_score": None, "cvss_severity": "", "cvss_vector": "", "cvss_version": "",
           "references": [r["url"] for r in cve.get("references") or [] if isinstance(r, dict) and r.get("url")][:MAX_REFERENCES],
           "ranges": _ranges(cve), "source": "nvd", "kev": False}
    best = _best_metric(cve.get("metrics") or {})
    if best:
        metric = best[0]
        data = metric.get("cvssData") or {}
        try:
            rec["cvss_score"] = float(data["baseScore"]) if data.get("baseScore") is not None else None
        except (TypeError, ValueError):
            rec["cvss_score"] = None
        rec["cvss_severity"] = str(data.get("baseSeverity") or metric.get("baseSeverity") or "").lower()
        rec["cvss_vector"] = str(data.get("vectorString", ""))
        rec["cvss_version"] = str(data.get("version", ""))
    return rec


def parse_nvd_page(data) -> tuple[list[dict], int]:
    if not isinstance(data, dict):
        raise ValueError("unexpected NVD response format")
    recs = [r for r in (parse_nvd_item(v) for v in data.get("vulnerabilities") or []) if r]
    try:
        total = int(data.get("totalResults") or 0)
    except (TypeError, ValueError):
        total = 0
    return recs, total


class _Pacer:
    """Every NVD request goes through the process-wide limiter (``intel.nvd_wait``, shared with the intel refresh).
    The real HTTP client gets a longer timeout for NVD; injected fakes are called as ``get_json(url, params)``."""

    def __init__(self, sleep: Callable[[float], None]):
        self.sleep, self.calls = sleep, 0

    def __call__(self, get_json: GetJson, params: dict):
        nvd_wait(self.sleep)
        self.calls += 1
        if get_json is http_get_json:
            return http_get_json(NVD_URL, params, timeout=NVD_TIMEOUT)
        return get_json(NVD_URL, params)


def fetch_nvd_changes(get_json: GetJson, start: datetime, end: datetime,
                      pacer: _Pacer) -> tuple[list[dict], datetime | None, Exception | None]:
    """CVEs modified in [start, end] (window clamped to 120 days), read in one-day sub-windows with ``startIndex``
    paging. Returns (records, end of the last fully read sub-window or None, the error that stopped it or None):
    records from a sub-window cut short are still returned, but the checkpoint does not pass it."""
    start = max(start, end - NVD_MAX_WINDOW)
    out: list[dict] = []
    done: datetime | None = None
    lo = start
    while lo < end:
        hi = min(lo + NVD_SUB_WINDOW, end)
        index = 0
        try:
            while True:
                recs, total = parse_nvd_page(pacer(get_json, {
                    "lastModStartDate": nvd_time(lo), "lastModEndDate": nvd_time(hi),
                    "resultsPerPage": NVD_PAGE_SIZE, "startIndex": index}))
                out.extend(recs)
                index += NVD_PAGE_SIZE
                if index >= total or not recs:
                    break
        except Exception as e:  # noqa: BLE001 - reported by the caller; earlier sub-windows stay checkpointed
            return out, done, e
        done, lo = hi, hi
    return out, done, None


# ----------------------------------------------------------------- KEV
def new_kev_entries(feed, since: str) -> list[dict]:
    """KEV entries with ``dateAdded`` (YYYY-MM-DD) on or after ``since``."""
    if not isinstance(feed, dict):
        raise ValueError("unexpected KEV feed format")
    out = []
    for v in feed.get("vulnerabilities") or []:
        if not isinstance(v, dict):
            continue
        added = str(v.get("dateAdded") or "")[:10]
        try:
            cve = normalize_cve(str(v.get("cveID", "")))
        except ValueError:
            continue
        if added and added >= since:
            out.append({**v, "cveID": cve, "dateAdded": added})
    return out


def _kev_fields(entry: dict) -> dict:
    return {"kev": True, "kev_name": str(entry.get("vulnerabilityName") or "")[:255],
            "kev_date_added": str(entry.get("dateAdded") or "")[:16], "kev_due": str(entry.get("dueDate") or "")[:16],
            "kev_ransomware": str(entry.get("knownRansomwareCampaignUse", "")).lower() == "known",
            "kev_action": str(entry.get("requiredAction") or ""),
            "kev_vendor": str(entry.get("vendorProject") or ""), "kev_product": str(entry.get("product") or "")}


# ----------------------------------------------------------------- matching
@dataclass
class Match:
    service_id: int
    host: str
    port: int
    product: str
    version: str
    quality: str            # confirmed | possible
    reason: str
    constraint: str = ""    # version constraint of the range that matched ("" when unknown)
    has_version: bool = True   # False: no readable version, so version rules cannot cover this service


def normalize_name(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _tokens(*values: str) -> list[str]:
    return [t for t in normalize_name(" ".join(v.replace("_", " ") for v in values if v)).split(" ") if t]


_ALIAS_RES = [(re.compile(rf"{re.escape(alias)}(\s|$)"), targets) for alias, targets in PRODUCT_ALIASES.items()]


def _cpe_key(svc) -> tuple[str, tuple[str, str]] | None:
    """('a' | 'o' | 'h', (vendor, product)) from an nmap CPE such as ``cpe:/a:apache:http_server:2.4.58``."""
    cpe = (svc.cpe or "").strip().lower()
    if not cpe.startswith("cpe:/"):
        return None
    parts = cpe[5:].split(":")
    if len(parts) >= 3 and parts[1] and parts[2]:
        return parts[0], (parts[1], parts[2])
    return None


def service_keys(svc) -> set[tuple[str, str]]:
    """(vendor, product) application CPE keys for an inventory service: its nmap CPE (not OS / hardware ones, see
    ``os_keys``) plus the alias table. An alias matches the start of the product name up to a word boundary."""
    keys: set[tuple[str, str]] = set()
    cpe = _cpe_key(svc)
    if cpe and cpe[0] == "a":
        keys.add(cpe[1])
    name = normalize_name(svc.product)
    if name:
        for alias_re, targets in _ALIAS_RES:
            if alias_re.match(name):
                keys.update(targets)
    return keys


def os_keys(svc) -> set[tuple[str, str]]:
    """OS / hardware CPE keys (``cpe:/o:microsoft:windows``): used only when the version is known and in range."""
    cpe = _cpe_key(svc)
    return {cpe[1]} if cpe and cpe[0] != "a" else set()


_PLAIN_SEGMENT = re.compile(r"\d+[a-z]*\d*")          # 10, 2k, 6p1, 0rc1
_RANGE_WORDS = re.compile(r"^(or\b|and\b|\+|-|through\b|to\b|later\b|earlier\b|x\b)", re.IGNORECASE)


def readable_version(raw: str | None) -> str | None:
    """The comparable version of an nmap version string, or None when it cannot be read reliably: every dot
    segment must start with a digit ('9.4.z-SNAPSHOT', '2.x', '5.7.33-0ubuntu0' are unreadable) and nothing may
    follow that widens it ('2.0 or later', '3.1+')."""
    v = extract_version(raw)
    if not v:
        return None
    if not all(_PLAIN_SEGMENT.fullmatch(seg.lower()) for seg in v.split(".")):
        return None
    rest = (raw or "").strip()
    rest = rest[rest.find(v) + len(v):].strip() if v in rest else ""
    return None if _RANGE_WORDS.match(rest) else v


@dataclass
class Inv:
    """An inventory service prepared once per run for matching."""
    svc: object
    host: object
    product: str
    words: frozenset
    version: str | None
    keys: frozenset
    os_keys: frozenset = frozenset()
    key_words: tuple = ()      # word sets of the application keys, for KEV name similarity

    @classmethod
    def of(cls, svc, host) -> "Inv":
        product = normalize_name(svc.product)
        keys = frozenset(service_keys(svc))
        return cls(svc, host, product, frozenset(product.split(" ")) - {""}, readable_version(_service_version(svc)),
                   keys, frozenset(os_keys(svc)), tuple(frozenset(_tokens(v, p)) for v, p in keys))


def inventory(pairs: Iterable) -> list[Inv]:
    return [p if isinstance(p, Inv) else Inv.of(*p) for p in pairs]


def range_constraint(r: dict) -> str:
    """'>= 2.4.0, < 2.4.62' from an NVD range; '== 2.4.49' for an exact CPE version; '' when unknown."""
    clauses = [f"{op} {r[k]}" for k, op in (("start_incl", ">="), ("start_excl", ">"), ("end_incl", "<="), ("end_excl", "<"))
               if r.get(k)]
    if not clauses and r.get("version", "*") != "*":
        clauses = [f"== {r['version']}"]
    return ", ".join(clauses)


def _decide(version: str | None, r: dict) -> tuple[str | None, str]:
    """(quality or None when the version is outside, constraint) for a range that names the service's product."""
    constraint = range_constraint(r)
    has_range = any(r.get(k) for k in ("start_incl", "start_excl", "end_incl", "end_excl"))
    if not version or not constraint:
        return "possible", constraint
    if has_range:
        try:
            return ("confirmed" if check_clauses(version, parse_constraint(constraint)) else None), constraint
        except ValueError:     # a range bound the comparator cannot read
            return "possible", constraint
    exact = extract_version(r["version"])
    if not exact:
        return "possible", constraint
    return ("confirmed" if compare_versions(version, exact) == 0 else None), constraint


def match_cve(cve: dict, services: Iterable) -> list[Match]:
    """Inventory services affected by ``cve`` (a watch record), best quality per service.
    ``services`` yields (Service, Host) pairs or ``Inv`` rows from ``inventory()``."""
    ranges = cve.get("ranges") or []
    names = [(r, _tokens(r["vendor"], r["product"])) for r in ranges]
    if cve.get("kev_vendor") or cve.get("kev_product"):
        names.append((None, _tokens(cve.get("kev_vendor", ""), cve.get("kev_product", ""))))
    out: list[Match] = []
    for inv in inventory(services):
        svc, host, product, version, keys = inv.svc, inv.host, inv.product, inv.version, inv.keys
        best: tuple[str, str, str] | None = None   # (quality, reason, constraint)

        def offer(quality, reason, constraint):
            nonlocal best
            if quality and (best is None or QUALITY_RANK[quality] < QUALITY_RANK[best[0]]):
                best = (quality, reason, constraint)

        key_hit = False
        for r in ranges:
            key = (r["vendor"], r["product"])
            if key in keys:
                quality, constraint = _decide(version, r)
            elif key in inv.os_keys:
                quality, constraint = _decide(version, r)
                if quality != "confirmed":    # an OS CPE alone says little about the service: version must be in range
                    continue
            else:
                continue
            key_hit = True
            what = f"{r['vendor']}:{r['product']}"
            if quality == "confirmed":
                offer(quality, f"{what} {version} is in {constraint}", constraint)
            elif quality == "possible":
                offer(quality, f"{what}: " + ("version unknown" if not version else
                                               f"cannot compare {version} with {constraint or 'the CPE'}"), constraint)
        if not key_hit and (product or inv.key_words):
            for r, tokens in names:
                if not tokens:
                    continue
                by_name = all(t in inv.words for t in tokens)
                by_key = r is None and any(all(t in kw for t in tokens) for kw in inv.key_words)   # KEV vs CPE key
                if not (by_name or by_key):
                    continue
                if r is not None:
                    quality, constraint = _decide(version, r)
                    if quality is None:
                        continue        # the product name looks alike but the version is outside the range
                    label = f"{r['vendor']}:{r['product']}"
                else:
                    constraint, label = "", f"KEV {cve.get('kev_vendor', '')} {cve.get('kev_product', '')}".strip()
                offer("possible", f"name similar to {label}", constraint)
        if best is not None:
            out.append(Match(service_id=svc.id, host=host.address, port=svc.port, product=svc.product,
                             version=svc.version, quality=best[0], reason=best[1][:300], constraint=best[2],
                             has_version=bool(version)))
    return out


def best_quality(matches: Iterable) -> str:
    qualities = [m["quality"] if isinstance(m, dict) else m.quality for m in matches]
    return min(qualities, key=lambda q: QUALITY_RANK.get(q, 9), default="possible")


# ----------------------------------------------------------------- drafting
def _log(db: Session, action: str, target: str, **details) -> None:
    db.add(AuditLog(username=AUTHOR, action=action, target=str(target)[:512],
                    details=json.dumps(details, default=str, sort_keys=True)))


def _dump_record(rec: dict) -> dict:
    return {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in rec.items()}


def hit_record(hit: WatchHit) -> dict | None:
    """The stored watch record of a hit (published as a datetime), or None for rows without one."""
    try:
        rec = json.loads(hit.record or "{}")
    except json.JSONDecodeError:
        return None
    if not isinstance(rec, dict) or rec.get("cve_id") != hit.cve_id:
        return None
    rec["published"] = _parse_time(str(rec.get("published") or "")) if rec.get("published") else None
    rec.setdefault("ranges", [])
    rec.setdefault("source", hit.source)
    return rec


def upsert_hit(db: Session, cve: dict, matches: list[Match], now: datetime) -> WatchHit:
    hit = db.scalar(select(WatchHit).where(WatchHit.cve_id == cve["cve_id"]))
    stored = (hit_record(hit) or {}) if hit is not None else {}
    merged = {**stored, **{k: v for k, v in cve.items() if v not in (None, "", [])}}
    merged["kev"] = bool(stored.get("kev") or cve.get("kev"))
    new = [{k: v for k, v in asdict(m).items() if k != "constraint"} for m in matches]
    if hit is None:
        hit = WatchHit(cve_id=cve["cve_id"], source=cve["source"], created_at=now, matches="[]")
        db.add(hit)
    else:
        try:
            old = json.loads(hit.matches or "[]")
        except json.JSONDecodeError:
            old = []
        ids = {m["service_id"] for m in new}
        new = [m for m in old if isinstance(m, dict) and m.get("service_id") not in ids] + new
        if hit.source != cve["source"]:
            hit.source = "both"
    hit.title = (cve.get("kev_name") or cve.get("description") or "")[:512]
    hit.cvss_score = cve.get("cvss_score") if cve.get("cvss_score") is not None else hit.cvss_score
    hit.kev = bool(hit.kev or cve.get("kev"))
    hit.matches = json.dumps(new)
    hit.record = json.dumps(_dump_record(merged), default=str)
    hit.quality = best_quality(new)
    hit.updated_at = now
    db.flush()
    return hit


def draft_rules(matches: list[Match]) -> list[tuple[str, str]]:
    """(product pattern, constraint) per distinct pair, at most ``MAX_RULES``; '>= 0' when the range is unknown
    (any parseable version matches; a rule needs a constraint)."""
    out: list[tuple[str, str]] = []
    for m in sorted(matches, key=lambda m: QUALITY_RANK[m.quality]):
        if not normalize_name(m.product):
            continue
        pair = (re.escape(normalize_name(m.product)), m.constraint or ">= 0")
        if pair not in out:
            out.append(pair)
    return out[:MAX_RULES]


def draft_campaign(db: Session, cve: dict, matches: list[Match]) -> Campaign:
    from . import campaigns as camp
    from .notifications import campaign_message, notify
    info = {k: cve.get(k) for k in ("description", "cvss_score", "cvss_severity", "cvss_vector", "cvss_version",
                                    "published", "references")}
    info.update({k: cve.get(k, "") for k in ("kev_name", "kev_date_added", "kev_due", "kev_action")},
                kev=bool(cve.get("kev")), kev_ransomware=bool(cve.get("kev_ransomware")))
    if info["cvss_severity"] is None:
        info["cvss_severity"] = ""
    label = cve.get("kev_name") or next((m.product for m in matches if m.product), "")
    c = camp.create_campaign(db, name=f"{cve['cve_id']} {label}".strip(), cve_id=cve["cve_id"], description="",
                             severity="auto", product_pattern="", version_constraint="", attach_templates=True,
                             intel=(info, []), created_by=AUTHOR, status="draft")
    for pattern, constraint in draft_rules(matches):
        try:
            camp.add_rule(db, c, pattern, constraint)
        except ValueError:      # e.g. a version string the rule syntax cannot express
            continue
    assets = len({(m.host, m.port) for m in matches})
    notify(db, "campaign.draft", message=campaign_message(db, c, event="campaign.draft", assets=assets), severity=c.severity)
    _log(db, "campaign.drafted", c.name, campaign_id=c.id, cve=c.cve_id, assets=assets, kev=c.kev,
         templates=len(c.templates))
    return c


def attach_new_templates(db: Session) -> int:
    """Attach index templates for the CVE of every draft or active campaign that has none yet. Caller commits."""
    from . import campaigns as camp
    attached = 0
    for c in db.scalars(select(Campaign).where(Campaign.status.in_(("draft", "active")), Campaign.cve_id != "")
                        .order_by(Campaign.id)):
        if c.templates:
            continue
        for t in camp.templates_for_cve(db, c.cve_id):
            if camp.attach_template(db, c, t.path) is not None:
                attached += 1
                _log(db, "campaign.template_added", c.name, campaign_id=c.id, template=t.template_id, auto=True,
                     note=f"Template {t.template_id} attached automatically")
        db.refresh(c)
    db.flush()
    return attached


def _campaigns_by_cve(db: Session) -> dict[str, Campaign]:
    out: dict[str, Campaign] = {}
    for c in db.scalars(select(Campaign).where(Campaign.cve_id != "").order_by(Campaign.id)):
        out.setdefault(c.cve_id, c)
    return out


def _current_matches(rec: dict, services: list, state: dict) -> list[Match]:
    matches = match_cve(rec, services)
    if not state.get("include_possible", True):
        matches = [m for m in matches if m.quality == "confirmed"]
    return matches


def hit_draftable(hit: WatchHit, now: datetime | None = None) -> bool:
    """Shown with a Draft now button: no campaign yet, a stored record, and eligible (recent or known exploited)."""
    if hit.campaign_id is not None:
        return False
    rec = hit_record(hit)
    return rec is not None and draftable(rec, now or utcnow())


def draft_hit(db: Session, hit: WatchHit) -> Campaign:
    """Draft one hit now (Draft now on the watch page), whatever the per-run cap. Raises ValueError with a
    user-facing message. Caller commits."""
    if hit.campaign_id is not None or hit.cve_id in _campaigns_by_cve(db):
        raise ValueError(f"{hit.cve_id} already has a campaign.")
    rec = hit_record(hit)
    if rec is None:
        raise ValueError(f"No stored details for {hit.cve_id}; wait for the next watch run.")
    services = inventory(db.execute(select(Service, Host).join(Host, Host.id == Service.host_id)
                                    .order_by(Host.address, Service.port)).tuples())
    matches = _current_matches(rec, services, load_state(db))
    if not matches:
        raise ValueError(f"{hit.cve_id} no longer matches the inventory.")
    upsert_hit(db, rec, matches, utcnow())
    c = draft_campaign(db, rec, matches)
    hit.campaign_id = c.id
    db.flush()
    return c


def unversioned(matches: Iterable[dict]) -> list[dict]:
    """Possible matches whose service has no readable version: version rules can never cover them."""
    return [m for m in matches if m.get("quality") == "possible" and not m.get("has_version", True)]


def open_unversioned_issues(db: Session, c: Campaign) -> int:
    """On Activate: a suspected issue per version-unknown match, so those assets are not silently lost.
    Returns the number of new issues. Caller commits."""
    from .issues import ISSUE_SEVERITIES, upsert_issue
    hit = db.scalar(select(WatchHit).where(WatchHit.campaign_id == c.id))
    if hit is None or not c.cve_id:
        return 0
    severity = c.severity if c.severity in ISSUE_SEVERITIES else "high"
    created = 0
    for m in unversioned(hit_matches(hit)):
        row = db.execute(select(Service, Host).join(Host, Host.id == Service.host_id)
                         .where(Service.id == m.get("service_id"))).first()
        if row is None:          # the service left the inventory since the draft was made
            continue
        svc, host = row
        product = svc.product or svc.service_name
        _issue, new = upsert_issue(
            db, address=host.address, port=str(svc.port), hostname=host.hostname or "", vuln_id=c.cve_id,
            cve_id=c.cve_id, template_id="", rule_id=None, title=f"{c.name} ({product})" if product else c.name,
            severity=severity, confidence="suspected", seen_at=host.last_seen or utcnow(),
            source="0-day watch (version unknown)", count_sighting=False, reopen=False)
        created += int(new)
    db.flush()
    return created


def _wanted(cve: dict, cfg: dict) -> bool:
    if cve.get("kev") and cfg.get("kev_always", True):
        return True
    score = cve.get("cvss_score")
    return score is not None and score >= float(cfg.get("min_cvss", DEFAULTS["min_cvss"]))


def draftable(cve: dict, now: datetime) -> bool:
    """Known exploited, or published in the last 30 days. NVD's lastMod window also returns old CVEs that were only
    edited (new references, reanalysis): they are kept as watch hits but do not flood the team with drafts."""
    if cve.get("kev"):
        return True
    published = cve.get("published")
    return isinstance(published, datetime) and now - published <= DRAFT_MAX_AGE


def _priority(cve: dict) -> tuple:
    """Drafts are made in this order until the per-run limit: known exploited, then highest CVSS, newest first."""
    published = cve.get("published")
    return (not cve.get("kev"), -(cve.get("cvss_score") or 0), -(published.timestamp() if published else 0), cve["cve_id"])


def run_watch(db: Session, settings, get_json: GetJson, now: datetime | None = None,
              sleep: Callable[[float], None] = time.sleep) -> dict:
    """One watch run. Each source fails on its own (short error in ``errors``); the run state only advances for
    sources that succeeded. Caller commits."""
    now = now or utcnow()
    state = load_state(db)
    summary = {"cves": 0, "matched": 0, "drafts": 0, "templates": 0, "not_drafted_limit": 0, "hits_only": 0,
               "notes": [], "errors": []}
    errors = summary["errors"]
    pacer = _Pacer(sleep)
    cves: dict[str, dict] = {}

    nvd_done: datetime | None = None
    try:
        last_check = _parse_time(str(state.get("last_nvd_check") or ""))
        since = last_check - NVD_OVERLAP if last_check else now - FIRST_NVD_BACK
        recs, nvd_done, nvd_error = fetch_nvd_changes(get_json, since, now, pacer)
        for rec in recs:
            cves[rec["cve_id"]] = rec
        if nvd_error is not None:
            errors.append(short_error("NVD", nvd_error))
    except Exception as e:  # noqa: BLE001 - one bad source must not stop the others
        errors.append(short_error("NVD", e))

    prev_kev = str(state.get("last_kev_date") or "")
    kev_ok, kev_last = False, prev_kev
    try:
        if prev_kev:
            since_kev = (datetime.fromisoformat(prev_kev) - KEV_OVERLAP).date().isoformat()
        else:
            since_kev = (now - FIRST_KEV_BACK).date().isoformat()
        feed, downloaded = load_kev_feed(settings.data_dir / "kev.json", get_json, refresh=True)   # shared cache
        if not downloaded:
            errors.append("CISA KEV: download failed, used the cached feed")
        for entry in new_kev_entries(feed, since_kev):
            cve = entry["cveID"]
            rec = cves.get(cve)
            if rec is None:
                rec = cves[cve] = {"cve_id": cve, "source": "kev", "ranges": [], "description": "", "references": [],
                                   "cvss_score": None, "cvss_severity": "", "cvss_vector": "", "cvss_version": "",
                                   "published": None}
            else:
                rec["source"] = "both"
            rec.update(_kev_fields(entry))
            kev_last = max(kev_last, entry["dateAdded"])
        kev_ok = True
    except Exception as e:  # noqa: BLE001
        errors.append(short_error("CISA KEV", e))

    # KEV entries that this run did not already read from NVD: one lookup each, at most KEV_NVD_LOOKUPS
    lookups = [r for r in cves.values() if r.get("source") == "kev" and not r.get("ranges")][:KEV_NVD_LOOKUPS]
    for rec in lookups:
        try:
            found, _ = parse_nvd_page(pacer(get_json, {"cveId": rec["cve_id"]}))
        except Exception as e:  # noqa: BLE001
            errors.append(short_error("NVD lookup", e))
            break
        if found:
            nvd = found[0]
            rec["ranges"] = nvd["ranges"]
            for k in ("description", "references", "published", "cvss_score", "cvss_severity", "cvss_vector", "cvss_version"):
                if not rec.get(k) and nvd.get(k) not in (None, "", []):
                    rec[k] = nvd[k]

    summary["cves"] = len(cves)
    services = inventory(db.execute(select(Service, Host).join(Host, Host.id == Service.host_id)
                                    .order_by(Host.address, Service.port)).tuples())
    existing = _campaigns_by_cve(db)
    max_drafts = int(state.get("max_drafts") or DEFAULTS["max_drafts"])
    candidates: dict[str, tuple[dict, list[Match], int]] = {}   # cve -> (record, matches, hit id)

    # 1. this run's CVEs: record a hit, link an existing campaign, or queue for drafting
    for rec in sorted(cves.values(), key=_priority):
        cve_id = rec["cve_id"]
        if not _wanted(rec, state):
            continue
        try:
            with db.begin_nested():
                matches = _current_matches(rec, services, state)
                if not matches:
                    continue
                summary["matched"] += 1
                hit = upsert_hit(db, rec, matches, now)
                campaign = existing.get(cve_id)
                if campaign is not None:      # any status, dismissed included: never drafted twice
                    hit.campaign_id = campaign.id
                elif not draftable(rec, now):
                    summary["hits_only"] += 1
                else:
                    candidates[cve_id] = (rec, matches, hit.id)
        except Exception as e:  # noqa: BLE001 - one bad CVE must not stop the run
            log.exception("0-day watch: matching %s failed", cve_id)
            errors.append(short_error(f"match {cve_id}", e))

    # 2. earlier hits still without a campaign (held back by the cap, or the inventory changed): same rules
    for hit in db.scalars(select(WatchHit).where(WatchHit.campaign_id.is_(None)).order_by(WatchHit.id)):
        if hit.cve_id in candidates or hit.cve_id in cves:
            continue
        rec = hit_record(hit)
        if rec is None:
            continue
        if hit.cve_id in existing:
            hit.campaign_id = existing[hit.cve_id].id
            continue
        if not _wanted(rec, state) or not draftable(rec, now):
            continue
        matches = _current_matches(rec, services, state)
        if matches:
            candidates[hit.cve_id] = (rec, matches, hit.id)

    # 3. draft in priority order up to the per-run cap; the rest stay hits for the next run
    for rec, matches, hit_id in sorted(candidates.values(), key=lambda t: _priority(t[0])):
        if summary["drafts"] >= max_drafts:
            summary["not_drafted_limit"] += 1
            continue
        try:
            with db.begin_nested():
                campaign = draft_campaign(db, rec, matches)
                existing[rec["cve_id"]] = campaign
                db.get(WatchHit, hit_id).campaign_id = campaign.id
                summary["drafts"] += 1
        except Exception as e:  # noqa: BLE001
            log.exception("0-day watch: drafting %s failed", rec["cve_id"])
            errors.append(short_error(f"draft {rec['cve_id']}", e))

    try:
        with db.begin_nested():
            summary["templates"] = attach_new_templates(db)
    except Exception as e:  # noqa: BLE001
        errors.append(short_error("templates", e))

    if summary["not_drafted_limit"]:
        summary["notes"].append(f"{summary['not_drafted_limit']} more not drafted (limit)")
    if summary["hits_only"]:
        summary["notes"].append(f"{summary['hits_only']} older CVE(s) kept as hits only (published over 30 days ago)")
    state = load_state(db)
    if nvd_done is not None:
        state["last_nvd_check"] = nvd_done.isoformat(timespec="seconds")
    if kev_ok:
        state["last_kev_date"] = kev_last or since_kev
    state["last_run"] = {"at": now.isoformat(timespec="seconds"), **summary}
    save_state(db, state)
    db.flush()
    return summary


# ----------------------------------------------------------------- background run
def _store_failure(db: Session, now: datetime, error: str) -> None:
    state = load_state(db)
    state["last_run"] = {"at": now.isoformat(timespec="seconds"), "cves": 0, "matched": 0, "drafts": 0, "templates": 0,
                         "errors": [error]}
    save_state(db, state)


def _watch_sync(app, now: datetime | None) -> dict:
    """Worker-thread body. Never raises: a crash is stored as the run's summary so the next try waits an hour."""
    now = now or utcnow()
    get_json = getattr(app.state, "get_json", None) or http_get_json
    sleep = getattr(app.state, "watch_sleep", None) or time.sleep
    with app.state.SessionLocal() as db:
        try:
            summary = run_watch(db, app.state.settings, get_json, now=now, sleep=sleep)
            db.commit()
            return summary
        except Exception as e:  # noqa: BLE001
            log.exception("0-day watch run failed")
            db.rollback()
            error = short_error("watch", e)
            try:
                _store_failure(db, now, error)
                db.commit()
            except Exception:  # noqa: BLE001 - the in-memory attempt time still gates the next try
                db.rollback()
            return {"cves": 0, "matched": 0, "drafts": 0, "templates": 0, "errors": [error]}


async def _run(app, now: datetime | None) -> dict:
    try:
        summary = await asyncio.to_thread(_watch_sync, app, now)
        if summary["errors"]:
            log.warning("0-day watch: %s", "; ".join(summary["errors"]))
        return summary
    finally:
        app.state.watch_running = False


def _log_task_failure(task: asyncio.Task) -> None:
    if not task.cancelled() and task.exception() is not None:
        log.error("0-day watch task failed", exc_info=task.exception())


def start_watch(app, now: datetime | None = None) -> asyncio.Task | None:
    """Start a run in the background (worker thread); None when one is already running. Call from the event loop."""
    if getattr(app.state, "watch_running", False):
        return None
    app.state.watch_running = True
    app.state.watch_last_attempt = now or utcnow()
    try:
        app.state.watch_task = asyncio.get_running_loop().create_task(_run(app, now))
    except BaseException:
        app.state.watch_running = False
        raise
    app.state.watch_task.add_done_callback(_log_task_failure)
    return app.state.watch_task


async def maybe_watch(app, now: datetime | None = None) -> asyncio.Task | None:
    """Called every scheduler tick; never waits for the run. First run 3 minutes after start, then at most hourly
    (failed attempts count). Skipped while the watch is disabled in its settings."""
    now = now or utcnow()
    started = getattr(app.state, "watch_started_at", None)
    if started is None:
        app.state.watch_started_at = started = now
    if now - started < STARTUP_DELAY or getattr(app.state, "watch_running", False):
        return None
    attempt = getattr(app.state, "watch_last_attempt", None)
    if attempt is not None and now - attempt < WATCH_EVERY:
        return None
    with app.state.SessionLocal() as db:
        if not load_state(db).get("enabled", True):
            return None
        last = last_run(db)
    if last is not None and now - last["at"] < WATCH_EVERY:
        return None
    return start_watch(app, now)


async def attach_templates_in_background(app) -> int:
    """After a template update / re-index: attach new templates to campaigns that had none."""
    def _work():
        with app.state.SessionLocal() as db:
            n = attach_new_templates(db)
            db.commit()
            return n
    try:
        return await asyncio.to_thread(_work)
    except Exception:  # noqa: BLE001
        log.exception("automatic template attach failed")
        return 0


def recent_hits(db: Session, limit: int = HIT_ROWS) -> list[tuple[WatchHit, Campaign | None, list[dict], bool]]:
    """(hit, campaign, matches, can be drafted now), newest first."""
    hits = list(db.scalars(select(WatchHit).order_by(WatchHit.created_at.desc(), WatchHit.id.desc()).limit(limit)))
    ids = {h.campaign_id for h in hits if h.campaign_id}
    campaigns = {c.id: c for c in db.scalars(select(Campaign).where(Campaign.id.in_(ids)))} if ids else {}
    now = utcnow()
    return [(h, campaigns.get(h.campaign_id), hit_matches(h), hit_draftable(h, now)) for h in hits]


def hit_matches(hit: WatchHit | None) -> list[dict]:
    if hit is None:
        return []
    try:
        data = json.loads(hit.matches or "[]")
    except json.JSONDecodeError:
        return []
    return sorted((m for m in data if isinstance(m, dict)),
                  key=lambda m: (QUALITY_RANK.get(m.get("quality"), 9), str(m.get("host")), m.get("port") or 0))
