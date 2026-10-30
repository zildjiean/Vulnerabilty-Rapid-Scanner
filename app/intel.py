"""Vulnerability intelligence: NVD CVE API 2.0 and the CISA Known Exploited Vulnerabilities feed."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MAX_AGE = 24 * 3600
MAX_REFERENCES = 15
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

GetJson = Callable[[str, "dict | None"], Any]


def http_get_json(url: str, params: dict | None = None) -> Any:
    with httpx.Client(timeout=15, follow_redirects=True, headers={"User-Agent": "zero-day-rapid-scanner"}) as c:
        r = c.get(url, params=params)
        r.raise_for_status()
        return r.json()


def normalize_cve(value: str) -> str:
    cve = (value or "").strip().upper()
    if not CVE_RE.match(cve):
        raise ValueError("CVE id must look like CVE-2026-12345.")
    return cve


def _parse_time(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", ""))
    except (ValueError, AttributeError):
        return None


def _best_metric(metrics: dict) -> tuple[dict, str] | None:
    """Newest CVSS version first; within a version the NVD 'Primary' score wins."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if items:
            items = sorted(items, key=lambda m: m.get("type") != "Primary")
            return items[0], key
    return None


def parse_nvd(data: dict) -> dict | None:
    vulns = (data or {}).get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve") or {}
    desc = next((d.get("value", "") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
    out = {"description": desc, "cvss_score": None, "cvss_severity": "", "cvss_vector": "", "cvss_version": "",
           "published": _parse_time(cve.get("published", "")),
           "references": [r["url"] for r in (cve.get("references") or []) if r.get("url")][:MAX_REFERENCES]}
    best = _best_metric(cve.get("metrics") or {})
    if best:
        metric, _key = best
        data_ = metric.get("cvssData") or {}
        out["cvss_score"] = data_.get("baseScore")
        out["cvss_severity"] = str(data_.get("baseSeverity") or metric.get("baseSeverity") or "").lower()
        out["cvss_vector"] = data_.get("vectorString", "")
        out["cvss_version"] = str(data_.get("version", ""))
    return out


def fetch_nvd(cve: str, get_json: GetJson) -> dict | None:
    return parse_nvd(get_json(NVD_URL, {"cveId": cve}))


def _load_kev_feed(cache: Path, get_json: GetJson, refresh: bool = False) -> dict:
    fresh = not refresh and cache.exists() and time.time() - cache.stat().st_mtime < KEV_MAX_AGE
    if not fresh:
        try:
            feed = get_json(KEV_URL, None)
            cache.parent.mkdir(parents=True, exist_ok=True)
            tmp = cache.with_suffix(".tmp")
            tmp.write_text(json.dumps(feed))
            tmp.replace(cache)
            return feed
        except (httpx.HTTPError, OSError, ValueError):
            if not cache.exists():
                raise
    return json.loads(cache.read_text())


def kev_entry(cve: str, cache: Path, get_json: GetJson, refresh: bool = False) -> dict | None:
    feed = _load_kev_feed(cache, get_json, refresh)
    return next((v for v in feed.get("vulnerabilities") or [] if v.get("cveID") == cve), None)


def enrich(cve: str, kev_cache: Path, get_json: GetJson, refresh: bool = False) -> tuple[dict, list[str]]:
    """Gather NVD + KEV data. Never raises for network problems: errors are returned for display.
    ``refresh`` re-downloads the KEV feed instead of trusting the 24 h cache (used by "Refresh intel")."""
    info: dict = {"description": "", "cvss_score": None, "cvss_severity": "", "cvss_vector": "", "cvss_version": "",
                  "published": None, "references": [], "kev": False, "kev_name": "", "kev_date_added": "",
                  "kev_due": "", "kev_ransomware": False, "kev_action": ""}
    errors: list[str] = []
    try:
        nvd = fetch_nvd(cve, get_json)
        if nvd:
            info.update(nvd)
        else:
            errors.append(f"NVD has no record of {cve} yet (it may still be reserved).")
    except (httpx.HTTPError, OSError, ValueError) as e:
        errors.append(f"NVD lookup failed: {e}")
    try:
        k = kev_entry(cve, kev_cache, get_json, refresh)
        if k:
            info.update(kev=True, kev_name=k.get("vulnerabilityName", ""), kev_date_added=k.get("dateAdded", ""),
                        kev_due=k.get("dueDate", ""), kev_action=k.get("requiredAction", ""),
                        kev_ransomware=str(k.get("knownRansomwareCampaignUse", "")).lower() == "known")
    except (httpx.HTTPError, OSError, ValueError) as e:
        errors.append(f"CISA KEV lookup failed: {e}")
    return info, errors
