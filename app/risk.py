"""Risk score (0-100) per issue from CVSS, FIRST EPSS, CISA KEV, confidence and scope criticality.

The intel behind it lives in ``cve_intel`` and is refreshed hourly by the scheduler (``maybe_refresh_intel``) or on
demand from Settings. Scores are computed on read, so they always reflect the latest intel and triage state.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Iterable

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import AppSetting, Campaign, CveIntel, Issue, utcnow
from .intel import NVD_PAUSE, GetJson, _load_kev_feed, fetch_nvd, http_get_json, normalize_cve, nvd_wait

log = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH = 100
NVD_LIMIT = 5
REFRESH_KEY = "intel_refresh"
REFRESH_EVERY = timedelta(minutes=60)
STARTUP_DELAY = timedelta(minutes=2)

SEVERITY_POINTS = {"critical": 47, "high": 37, "medium": 25, "low": 12}
CONFIDENCE_POINTS = {"verified": 10, "confirmed": 5}
SCOPE_POINTS = {"critical": 10, "high": 6, "medium": 3}
BANDS = ((80, "critical"), (60, "high"), (40, "medium"), (0, "low"))


# ----------------------------------------------------------------- score
def _half_up(x: float) -> int:
    return int(math.floor(x + 0.5))


def band_for(total: int) -> str:
    return next(name for floor, name in BANDS if total >= floor)


def top_pct(percentile: float) -> str:
    v = max(0.0, (1 - percentile) * 100)
    return f"{v:.0f}" if v >= 10 else f"{v:.2g}"


@dataclass(frozen=True)
class RiskScore:
    total: int
    band: str
    parts: tuple            # ((label, points, detail), ...)
    cvss_score: float | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    epss_date: str = ""
    kev: bool = False
    kev_ransomware: bool = False
    kev_due: str = ""
    intel_updated: datetime | None = None

    @property
    def title(self) -> str:
        return " · ".join(f"{label} → {points}" for label, points, _ in self.parts)

    @property
    def epss_text(self) -> str:
        """'2.34 %' (probability of exploitation in the next 30 days)."""
        return f"{self.epss * 100:.2f} %" if self.epss is not None else ""

    @property
    def epss_top(self) -> str:
        """'top 13 %' (share of all scored CVEs at least as likely to be exploited)."""
        return f"top {top_pct(self.epss_percentile)} %" if self.epss_percentile is not None else ""


def risk_score(issue, intel: CveIntel | None, scope_criticality: str | None) -> RiskScore:
    parts: list[tuple[str, int, str]] = []
    cvss = intel.cvss_score if intel is not None else None
    if cvss is not None:
        parts.append((f"CVSS {cvss:.1f}", min(50, _half_up(cvss * 5)), "CVSS base score × 5"))
    else:
        parts.append((f"severity {issue.severity}", SEVERITY_POINTS.get(issue.severity, 0),
                      "Issue severity (no CVSS score known)"))
    if intel is not None and intel.kev:
        parts.append(("KEV", 25, "Listed in CISA Known Exploited Vulnerabilities"))
        if intel.kev_ransomware:
            parts.append(("ransomware", 5, "Known use in ransomware campaigns"))
    elif intel is not None and intel.epss_percentile is not None:
        parts.append((f"EPSS top {top_pct(intel.epss_percentile)} %", min(20, _half_up(20 * intel.epss_percentile)),
                      "FIRST EPSS percentile × 20"))
    if issue.confidence in CONFIDENCE_POINTS:
        parts.append((issue.confidence, CONFIDENCE_POINTS[issue.confidence], "Detection confidence"))
    if scope_criticality in SCOPE_POINTS:
        parts.append((f"scope {scope_criticality}", SCOPE_POINTS[scope_criticality], "Scope criticality"))
    total = min(100, sum(p for _, p, _ in parts))
    kw = {}
    if intel is not None:
        kw = dict(cvss_score=intel.cvss_score, epss=intel.epss, epss_percentile=intel.epss_percentile,
                  epss_date=intel.epss_date or "", kev=bool(intel.kev), kev_ransomware=bool(intel.kev_ransomware),
                  kev_due=intel.kev_due or "", intel_updated=intel.updated_at)
    return RiskScore(total=total, band=band_for(total), parts=tuple(parts), **kw)


def _norm(cve: str | None) -> str:
    return (cve or "").strip().upper()


def scores_for(db: Session, issues: Iterable[Issue]) -> dict[int, RiskScore]:
    """Scores for many issues with one intel query. Scopes are read through ``Issue.scope``."""
    issues = list(issues)
    cves = {_norm(i.cve_id) for i in issues} - {""}
    if not cves:
        intel: dict[str, CveIntel] = {}
    elif len(cves) > 500:   # stay well below SQLite's bound-parameter limit
        intel = {r.cve_id: r for r in db.scalars(select(CveIntel))}
    else:
        intel = {r.cve_id: r for r in db.scalars(select(CveIntel).where(CveIntel.cve_id.in_(cves)))}
    return {i.id: risk_score(i, intel.get(_norm(i.cve_id)), i.scope.criticality if i.scope else None) for i in issues}


def intel_for(db: Session, cve: str | None) -> CveIntel | None:
    cve = _norm(cve)
    return db.get(CveIntel, cve) if cve else None


# ----------------------------------------------------------------- EPSS
def parse_epss(data) -> dict[str, tuple[float, float, str]]:
    """FIRST EPSS API response -> {cve: (epss, percentile, date)}; bad rows are skipped."""
    out: dict[str, tuple[float, float, str]] = {}
    rows = data.get("data") if isinstance(data, dict) else None
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        try:
            cve = normalize_cve(str(row.get("cve", "")))
            epss, pct = float(row.get("epss")), float(row.get("percentile"))
        except (TypeError, ValueError):
            continue
        if not (0 <= epss <= 1 and 0 <= pct <= 1):
            continue
        out[cve] = (epss, pct, str(row.get("date") or "")[:16])
    return out


# ----------------------------------------------------------------- refresh
def collect_cves(db: Session) -> list[str]:
    raw = set(db.scalars(select(Issue.cve_id).distinct())) | set(db.scalars(select(Campaign.cve_id).distinct()))
    out = set()
    for value in raw:
        try:
            out.add(normalize_cve(value or ""))
        except ValueError:
            pass
    return sorted(out)


def short_error(source: str, e: BaseException) -> str:
    """'EPSS: HTTPStatusError 503' - the exception type and HTTP status only, never a URL or response body."""
    text = f"{source}: {type(e).__name__}"
    if isinstance(e, httpx.HTTPStatusError):
        text += f" {e.response.status_code}"
    return text[:200]


def refresh_intel(db: Session, settings, get_json: GetJson, nvd_limit: int = NVD_LIMIT,
                  now: datetime | None = None, sleep: Callable[[float], None] = time.sleep) -> dict:
    """Refresh EPSS, KEV and CVSS for every CVE on an issue or campaign. Any error is recorded per source in
    ``errors`` (short text); a failing source keeps its previous values and never blocks the others. NVD calls go
    through the process-wide limiter (``intel.nvd_wait``, ``NVD_PAUSE`` s apart). Caller commits."""
    now = now or utcnow()
    cves = collect_cves(db)
    summary = {"cves": len(cves), "epss": 0, "kev": 0, "nvd": 0, "cvss_from_campaigns": 0, "errors": []}
    errors = summary["errors"]
    if cves:
        existing = {r.cve_id: r for r in db.scalars(select(CveIntel))}
        rows: dict[str, CveIntel] = {}
        for cve in cves:
            row = existing.get(cve)
            if row is None:
                row = CveIntel(cve_id=cve, cvss_severity="", epss_date="", kev=False, kev_ransomware=False, kev_due="")
                db.add(row)
            rows[cve] = row

        try:
            for start in range(0, len(cves), EPSS_BATCH):
                batch = cves[start:start + EPSS_BATCH]
                for cve, (epss, pct, date) in parse_epss(get_json(EPSS_URL, {"cve": ",".join(batch)})).items():
                    if cve in rows:
                        rows[cve].epss, rows[cve].epss_percentile, rows[cve].epss_date = epss, pct, date
                        summary["epss"] += 1
        except Exception as e:  # noqa: BLE001 - one bad source must not stop the others
            errors.append(short_error("EPSS", e))

        try:
            feed = _load_kev_feed(settings.data_dir / "kev.json", get_json)
            if not isinstance(feed, dict):
                raise ValueError("unexpected KEV feed format")
            kev = {v.get("cveID"): v for v in feed.get("vulnerabilities") or [] if isinstance(v, dict)}
            flags = {}
            for cve in rows:
                entry = kev.get(cve)
                flags[cve] = (entry is not None,
                              bool(entry) and str(entry.get("knownRansomwareCampaignUse", "")).lower() == "known",
                              str(entry.get("dueDate") or "")[:16] if entry else "")
            for cve, (is_kev, ransomware, due) in flags.items():   # applied only once the whole feed parsed
                rows[cve].kev, rows[cve].kev_ransomware, rows[cve].kev_due = is_kev, ransomware, due
                summary["kev"] += int(is_kev)
        except Exception as e:  # noqa: BLE001
            errors.append(short_error("CISA KEV", e))

        try:
            scored: dict[str, Campaign] = {}
            for c in db.scalars(select(Campaign).where(Campaign.cvss_score.is_not(None)).order_by(Campaign.id)):
                try:
                    scored.setdefault(normalize_cve(c.cve_id or ""), c)
                except ValueError:
                    continue
            for cve, row in rows.items():
                c = scored.get(cve)
                if c is not None:
                    row.cvss_score, row.cvss_severity = c.cvss_score, c.cvss_severity or ""
                    summary["cvss_from_campaigns"] += 1
        except Exception as e:  # noqa: BLE001
            errors.append(short_error("campaign CVSS", e))

        # Unscored CVEs least recently asked first, so a small per-run budget eventually covers all of them.
        missing = sorted((r for r in rows.values() if r.cvss_score is None),
                         key=lambda r: (r.nvd_checked_at or datetime.min, r.cve_id))[:max(0, nvd_limit)]
        for row in missing:
            nvd_wait(sleep)
            try:
                nvd = fetch_nvd(row.cve_id, get_json)
            except Exception as e:  # noqa: BLE001
                errors.append(short_error("NVD", e))
                break
            row.nvd_checked_at = now
            summary["nvd"] += 1
            try:
                score = float(nvd["cvss_score"]) if nvd and nvd.get("cvss_score") is not None else None
            except (TypeError, ValueError):
                score = None
            if score is not None and 0 <= score <= 10:
                row.cvss_score, row.cvss_severity = score, str(nvd.get("cvss_severity") or "")[:16]

        for row in rows.values():
            row.updated_at = now

    _store_summary(db, now, summary)
    db.flush()
    return summary


def _store_summary(db: Session, now: datetime, summary: dict) -> None:
    setting = db.get(AppSetting, REFRESH_KEY) or AppSetting(key=REFRESH_KEY)
    setting.value = json.dumps({"at": now.isoformat(timespec="seconds"), **summary})
    db.add(setting)


def last_refresh(db: Session) -> dict | None:
    """The stored summary of the last run, with ``at`` as a datetime; None before the first run."""
    row = db.get(AppSetting, REFRESH_KEY)
    if row is None or not row.value:
        return None
    try:
        data = json.loads(row.value)
        data["at"] = datetime.fromisoformat(data["at"])
    except (ValueError, KeyError, TypeError):
        return None
    return data


def _refresh_sync(app, now: datetime | None) -> dict:
    """Worker-thread body. Never raises: a crash is stored as the run's summary so the next try waits an hour."""
    now = now or utcnow()
    get_json = getattr(app.state, "get_json", None) or http_get_json
    with app.state.SessionLocal() as db:
        try:
            summary = refresh_intel(db, app.state.settings, get_json, now=now)
            db.commit()
            return summary
        except Exception as e:  # noqa: BLE001
            log.exception("threat intel refresh failed")
            db.rollback()
            summary = {"cves": 0, "epss": 0, "kev": 0, "nvd": 0, "cvss_from_campaigns": 0,
                       "errors": [short_error("refresh", e)]}
            try:
                _store_summary(db, now, summary)
                db.commit()
            except Exception:  # noqa: BLE001 - the in-memory attempt time in maybe_refresh_intel still gates
                db.rollback()
            return summary


async def _run(app, now: datetime | None) -> dict:
    try:
        summary = await asyncio.to_thread(_refresh_sync, app, now)
        if summary["errors"]:
            log.warning("threat intel refresh: %s", "; ".join(summary["errors"]))
        return summary
    finally:
        app.state.intel_refreshing = False


def start_refresh(app, now: datetime | None = None) -> asyncio.Task | None:
    """Start a refresh in the background (worker thread). Returns None when one is already running.
    Must be called from the event loop; the task is kept on ``app.state.intel_task``."""
    if getattr(app.state, "intel_refreshing", False):
        return None
    app.state.intel_refreshing = True
    app.state.intel_last_attempt = now or utcnow()
    try:
        app.state.intel_task = asyncio.get_running_loop().create_task(_run(app, now))
    except BaseException:
        app.state.intel_refreshing = False
        raise
    app.state.intel_task.add_done_callback(_log_task_failure)
    return app.state.intel_task


def _log_task_failure(task: asyncio.Task) -> None:
    """Nothing awaits the background task, so surface a failure that escaped _run instead of losing it."""
    if not task.cancelled() and task.exception() is not None:
        log.error("threat intel refresh task failed", exc_info=task.exception())


async def maybe_refresh_intel(app, now: datetime | None = None) -> asyncio.Task | None:
    """Called every scheduler tick; never waits for the refresh. Starts one shortly after startup and then at most
    once an hour (counting failed attempts too). Returns the started task or None."""
    now = now or utcnow()
    started = getattr(app.state, "intel_started_at", None)
    if started is None:
        app.state.intel_started_at = started = now
    if now - started < STARTUP_DELAY or getattr(app.state, "intel_refreshing", False):
        return None
    attempt = getattr(app.state, "intel_last_attempt", None)
    if attempt is not None and now - attempt < REFRESH_EVERY:
        return None
    with app.state.SessionLocal() as db:
        last = last_refresh(db)
    if last is not None and now - last["at"] < REFRESH_EVERY:
        return None
    return start_refresh(app, now)
