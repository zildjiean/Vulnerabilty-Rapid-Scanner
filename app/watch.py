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
from .intel import MAX_REFERENCES, NVD_URL, GetJson, _best_metric, _load_kev_feed, _parse_time, http_get_json, normalize_cve
from .risk import NVD_PAUSE, short_error
from .rules import _service_version
from .version_compare import check_clauses, compare_versions, extract_version, parse_constraint

log = logging.getLogger(__name__)

WATCH_KEY = "watch"
WATCH_EVERY = timedelta(minutes=60)
STARTUP_DELAY = timedelta(minutes=3)
NVD_PAGE_SIZE = 2000
NVD_MAX_WINDOW = timedelta(days=120)     # NVD rejects lastMod ranges longer than 120 days
FIRST_NVD_BACK = timedelta(days=3)
FIRST_KEV_BACK = timedelta(days=14)
KEV_NVD_LOOKUPS = 5                      # single-CVE NVD lookups for KEV entries without CPE ranges, per run
MAX_RULES = 5
HIT_ROWS = 100
AUTHOR = "0-day watch"
DEFAULTS = {"enabled": True, "min_cvss": 7.0, "kev_always": True, "include_possible": True}
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
    "fortinet": [("fortinet", "fortios")],
    "fortigate": [("fortinet", "fortios")],
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


def set_watch_settings(db: Session, enabled: bool, min_cvss: str, kev_always: bool, include_possible: bool) -> dict:
    try:
        score = float(str(min_cvss).strip())
    except ValueError:
        raise ValueError("Minimum CVSS must be a number between 0 and 10.")
    if not 0 <= score <= 10:
        raise ValueError("Minimum CVSS must be a number between 0 and 10.")
    data = load_state(db)
    data.update(enabled=bool(enabled), min_cvss=score, kev_always=bool(kev_always), include_possible=bool(include_possible))
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
    """Keeps NVD calls ``NVD_PAUSE`` seconds apart (public limit: 5 requests per 30 s without an API key)."""

    def __init__(self, sleep: Callable[[float], None]):
        self.sleep, self.calls = sleep, 0

    def __call__(self, get_json: GetJson, params: dict):
        if self.calls:
            self.sleep(NVD_PAUSE)
        self.calls += 1
        return get_json(NVD_URL, params)


def fetch_nvd_changes(get_json: GetJson, start: datetime, end: datetime, pacer: _Pacer) -> list[dict]:
    """CVEs modified in [start, end] (window clamped to 120 days), following ``startIndex`` paging."""
    start = max(start, end - NVD_MAX_WINDOW)
    out: list[dict] = []
    index = 0
    while True:
        recs, total = parse_nvd_page(pacer(get_json, {"lastModStartDate": nvd_time(start), "lastModEndDate": nvd_time(end),
                                                      "resultsPerPage": NVD_PAGE_SIZE, "startIndex": index}))
        out.extend(recs)
        index += NVD_PAGE_SIZE
        if index >= total or not recs:
            return out


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


def normalize_name(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip().lower())


def _tokens(*values: str) -> list[str]:
    return [t for t in normalize_name(" ".join(v.replace("_", " ") for v in values if v)).split(" ") if t]


def service_keys(svc) -> set[tuple[str, str]]:
    """(vendor, product) CPE keys for an inventory service: its nmap CPE plus the alias table."""
    keys: set[tuple[str, str]] = set()
    cpe = (svc.cpe or "").strip().lower()
    if cpe.startswith("cpe:/"):
        parts = cpe[5:].split(":")
        if len(parts) >= 3 and parts[1] and parts[2]:
            keys.add((parts[1], parts[2]))
    name = normalize_name(svc.product)
    if name:
        for alias, targets in PRODUCT_ALIASES.items():
            if name.startswith(alias):
                keys.update(targets)
    return keys


@dataclass
class Inv:
    """An inventory service prepared once per run for matching."""
    svc: object
    host: object
    product: str
    words: frozenset
    version: str | None
    keys: frozenset

    @classmethod
    def of(cls, svc, host) -> "Inv":
        product = normalize_name(svc.product)
        return cls(svc, host, product, frozenset(product.split(" ")) - {""}, extract_version(_service_version(svc)),
                   frozenset(service_keys(svc)))


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
            if (r["vendor"], r["product"]) not in keys:
                continue
            key_hit = True
            quality, constraint = _decide(version, r)
            what = f"{r['vendor']}:{r['product']}"
            if quality == "confirmed":
                offer(quality, f"{what} {version} is in {constraint}", constraint)
            elif quality == "possible":
                offer(quality, f"{what}: " + ("version unknown" if not version else
                                               f"cannot compare {version} with {constraint or 'the CPE'}"), constraint)
        if not key_hit and product:
            for r, tokens in names:
                if not tokens or not all(t in inv.words for t in tokens):
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
                             version=svc.version, quality=best[0], reason=best[1][:300], constraint=best[2]))
    return out


def best_quality(matches: Iterable) -> str:
    qualities = [m["quality"] if isinstance(m, dict) else m.quality for m in matches]
    return min(qualities, key=lambda q: QUALITY_RANK.get(q, 9), default="possible")


# ----------------------------------------------------------------- drafting
def _log(db: Session, action: str, target: str, **details) -> None:
    db.add(AuditLog(username=AUTHOR, action=action, target=str(target)[:512],
                    details=json.dumps(details, default=str, sort_keys=True)))


def upsert_hit(db: Session, cve: dict, matches: list[Match], now: datetime) -> WatchHit:
    hit = db.scalar(select(WatchHit).where(WatchHit.cve_id == cve["cve_id"]))
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


def _wanted(cve: dict, cfg: dict) -> bool:
    if cve.get("kev") and cfg.get("kev_always", True):
        return True
    score = cve.get("cvss_score")
    return score is not None and score >= float(cfg.get("min_cvss", DEFAULTS["min_cvss"]))


def run_watch(db: Session, settings, get_json: GetJson, now: datetime | None = None,
              sleep: Callable[[float], None] = time.sleep) -> dict:
    """One watch run. Each source fails on its own (short error in ``errors``); the run state only advances for
    sources that succeeded. Caller commits."""
    now = now or utcnow()
    state = load_state(db)
    summary = {"cves": 0, "matched": 0, "drafts": 0, "templates": 0, "errors": []}
    errors = summary["errors"]
    pacer = _Pacer(sleep)
    cves: dict[str, dict] = {}

    nvd_ok = False
    try:
        since = _parse_time(str(state.get("last_nvd_check") or "")) or now - FIRST_NVD_BACK
        for rec in fetch_nvd_changes(get_json, since, now, pacer):
            cves[rec["cve_id"]] = rec
        nvd_ok = True
    except Exception as e:  # noqa: BLE001 - one bad source must not stop the others
        errors.append(short_error("NVD", e))

    kev_ok, kev_last = False, str(state.get("last_kev_date") or "")
    try:
        since_kev = kev_last or (now - FIRST_KEV_BACK).date().isoformat()
        cache = settings.data_dir / "kev.json"
        before = cache.stat().st_mtime_ns if cache.exists() else None
        feed = _load_kev_feed(cache, get_json, refresh=True)   # shared cache; falls back to it when offline
        if before is not None and cache.stat().st_mtime_ns == before:
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

    lookups = [r for r in cves.values() if r.get("kev") and not r.get("ranges")][:KEV_NVD_LOOKUPS]
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
                                    .order_by(Host.address, Service.port)).tuples()) if cves else []
    existing: dict[str, Campaign] = {}
    for c in db.scalars(select(Campaign).where(Campaign.cve_id != "").order_by(Campaign.id)):
        existing.setdefault(c.cve_id, c)
    for cve_id in sorted(cves):
        rec = cves[cve_id]
        if not _wanted(rec, state):
            continue
        try:
            with db.begin_nested():
                matches = match_cve(rec, services)
                if not state.get("include_possible", True):
                    matches = [m for m in matches if m.quality == "confirmed"]
                if not matches:
                    continue
                summary["matched"] += 1
                hit = upsert_hit(db, rec, matches, now)
                campaign = existing.get(cve_id)
                if campaign is None:          # any status, dismissed included: never drafted twice
                    campaign = draft_campaign(db, rec, matches)
                    existing[cve_id] = campaign
                    summary["drafts"] += 1
                hit.campaign_id = campaign.id
        except Exception as e:  # noqa: BLE001 - one bad CVE must not stop the run
            log.exception("0-day watch: drafting %s failed", cve_id)
            errors.append(short_error(f"draft {cve_id}", e))

    try:
        with db.begin_nested():
            summary["templates"] = attach_new_templates(db)
    except Exception as e:  # noqa: BLE001
        errors.append(short_error("templates", e))

    state = load_state(db)
    if nvd_ok:
        state["last_nvd_check"] = now.isoformat(timespec="seconds")
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


def recent_hits(db: Session, limit: int = HIT_ROWS) -> list[tuple[WatchHit, Campaign | None, list[dict]]]:
    hits = list(db.scalars(select(WatchHit).order_by(WatchHit.created_at.desc(), WatchHit.id.desc()).limit(limit)))
    ids = {h.campaign_id for h in hits if h.campaign_id}
    campaigns = {c.id: c for c in db.scalars(select(Campaign).where(Campaign.id.in_(ids)))} if ids else {}
    return [(h, campaigns.get(h.campaign_id), hit_matches(h)) for h in hits]


def hit_matches(hit: WatchHit | None) -> list[dict]:
    if hit is None:
        return []
    try:
        data = json.loads(hit.matches or "[]")
    except json.JSONDecodeError:
        return []
    return sorted((m for m in data if isinstance(m, dict)),
                  key=lambda m: (QUALITY_RANK.get(m.get("quality"), 9), str(m.get("host")), m.get("port") or 0))
