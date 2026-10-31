# Risk score with EPSS — design

**Date:** 2026-10-31 · **Status:** approved by the project owner · **Target version:** 1.3.0
Part 1 of the roadmap agreed on 2026-10-31: risk score → 0-day watcher → bulk verify + proof in reports →
attack-surface diff → trend charts → external discovery. The intel cache built here is reused by the watcher.

## Data

New table `cve_intel` (model `CveIntel` in `app/db.py`, created by `Base.metadata.create_all`):

| column | type |
|---|---|
| `cve_id` | String(32), primary key |
| `cvss_score` | Float, nullable |
| `cvss_severity` | String(16), default "" |
| `epss` | Float, nullable (probability 0–1) |
| `epss_percentile` | Float, nullable (0–1) |
| `epss_date` | String(16), default "" |
| `kev` | Boolean, default False |
| `kev_ransomware` | Boolean, default False |
| `kev_due` | String(16), default "" |
| `updated_at` | DateTime |

## Intel refresh (`app/risk.py`)

`refresh_intel(db, settings, get_json, nvd_limit=10) -> dict` (summary counts):
1. CVE set = distinct non-empty `Issue.cve_id` ∪ `Campaign.cve_id`, normalised with `intel.normalize_cve`.
2. **EPSS**: `GET https://api.first.org/data/v1/epss?cve=<comma list>` in batches of 100. Response
   `{"data": [{"cve": "...", "epss": "0.00049", "percentile": "0.14", "date": "2026-10-30"}, ...]}` (strings).
   Parser `parse_epss(data) -> dict[cve, (epss, percentile, date)]` tolerates missing/invalid rows.
3. **KEV**: reuse `intel._load_kev_feed(cache, get_json)` (24 h cache) — `kev`, `kev_ransomware`
   (`knownRansomwareCampaignUse == "Known"`), `kev_due` (`dueDate`).
4. **CVSS**: first copy from a campaign with the same CVE; otherwise `intel.fetch_nvd` for at most `nvd_limit`
   CVEs still missing a score per run (oldest `updated_at` first).
5. Upsert rows, `updated_at = now`. Network errors are caught per source and reported in the summary
   (`errors: [...]`); a failing source never blocks the others.
6. Store the summary as JSON in `AppSetting("intel_refresh")` with the run time.

Scheduling: the scheduler loop (`app/scheduler.py::scheduler_loop`) calls `maybe_refresh_intel(app)` each tick;
it runs `refresh_intel` in a worker thread when the last run is older than 60 minutes (and once shortly after
startup). Uses `app.state.get_json` (already injectable for tests; default `intel.http_get_json`).
Manual: `POST /settings/intel/refresh` (`settings.manage` + CSRF, async) runs it now and redirects with a summary
flash; the Settings page shows last run time, counts and errors.

## Score (`app/risk.py`)

`risk_score(issue, intel: CveIntel | None, scope_criticality: str | None) -> RiskScore` — pure function returning
`total` (0–100 int), `band` and `parts` (list of (label, points, detail)):

| part | points |
|---|---|
| Severity: `cvss_score × 5` rounded; without CVSS by issue severity: critical 47, high 37, medium 25, low 12 | 0–50 |
| Exploitation: KEV → 25; else `round(20 × epss_percentile)`; unknown → 0 | 0–25 |
| KEV ransomware use | +5 |
| Confidence: verified +10, confirmed +5, suspected 0 | 0–10 |
| Scope criticality: critical +10, high +6, medium +3, low/none 0 | 0–10 |

Capped at 100. Bands: ≥80 `critical`, 60–79 `high`, 40–59 `medium`, <40 `low`.
`scores_for(db, issues) -> dict[issue_id, RiskScore]` loads intel rows in one query (by cve_id) and scopes via the
relationship. Scores are computed on read (no stored column), so they are always current.

## UI and outputs

- **Issues list**: new **Risk** column after Severity: number in a pill coloured by band (`risk-critical` …) with a
  `title` breakdown (`"CVSS 9.8 → 49 · KEV → 25 · verified → 10 · scope critical → 10"`), `data-value` for sorting.
  Default order: risk desc, then the existing severity/due/id key. The CSV/JSON export and API issue objects gain
  `risk_score`, `risk_band`, `epss`, `epss_percentile`, `kev`.
- **Issue page**: card **Risk** at the top of the right column: big number + band, the parts table, EPSS
  "x.xx % (top y %)" with date, KEV badge, and "Intel updated …".
- **Dashboard**: card **Top risks** (5 highest active issues: risk pill, title, asset, link).
- **Campaign page**: EPSS next to CVSS in the intel card when known.
- **Notifications**: field "Risk" (`87 · critical`).
- CSS: risk pill colours reuse severity tokens; dark mode via existing tokens.

## Tests (`tests/test_risk.py` + extensions)

Score parts and caps (CVSS vs severity fallback, KEV vs EPSS, ransomware, confidence, scope, cap); band edges;
`parse_epss` (valid, missing, bad numbers); `refresh_intel` with a fake `get_json` (EPSS batches, KEV, campaign
CVSS copy, NVD limit, one source failing → summary error, others stored); scheduler gating (not twice within an
hour); `/settings/intel/refresh` permission and flash; Issues list shows the Risk column and default order;
issue page card; dashboard Top risks; export/API fields.
