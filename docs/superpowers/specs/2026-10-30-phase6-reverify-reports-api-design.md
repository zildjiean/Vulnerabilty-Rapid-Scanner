# Phase 6: Auto Re-verify, Reports, REST API — Design

**Date:** 2026-10-30 · **Status:** approved · Roadmap: `2026-10-30-enterprise-roadmap-and-phase1-rbac-design.md`

## Auto re-verify

- A **confirmed** issue that enters `fixed` (any source) with a known nuclei template gets
  `reverify_requested_at`. After a configurable delay (Settings, default 15 min, can be disabled) the scheduler
  loop groups pending issues by template path and starts one nuclei job per template against the issues'
  assets (`jobs.params.reverify = [issue ids]`, issue `reverify_job_id`).
- On completion: issues seen again are reopened by the normal upsert logic. The others become **verified**
  ("Re-scan job #N did not find it") when the job finished cleanly; when the job failed or finished with warnings
  they stay fixed with an "inconclusive" timeline note. Either way the request is cleared.
- **Suspected** fixed issues are verified by inventory: when the service is re-scanned after the fix and no
  longer matches the rule, the issue becomes verified.

## Reports (`view`)

- **Executive** (`/reports?days=30`): active issues by severity, overdue, MTTR, SLA compliance, weekly new vs
  resolved (inline SVG), top 10 assets by open risk, scopes and campaigns tables. Print stylesheet; "Print / Save
  as PDF" button.
- **Campaign** and **scope** reports: printable summaries with exposure tables.
- **Exports**: `/reports/issues.csv` and `/reports/issues.json` with the Issues page filters (formula-safe CSV);
  exports are audited.

## REST API `/api/v1`

- API keys: `zdrs_<random>` shown once, SHA-256 stored with an 8-char prefix; owner, role (≤ owner's role),
  optional expiry (30 / 90 / 365 days), last used time / IP, revocation. Owners manage their keys on
  `/api-keys`; admins see and revoke all.
- Authentication only via `Authorization: Bearer <key>` (or `X-API-Key`). Session cookies are ignored on
  `/api/*`, so no CSRF exposure. Invalid / expired / revoked keys or inactive owners → 401 JSON.
- The principal acts with the key's role through the normal permission checks; actions are audited as
  `<owner> (api:<key name>)`.
- Endpoints: `GET /me`; `GET /issues`, `GET /issues/{id}`, `PATCH /issues/{id}` (status, comment, assignee,
  severity); `GET /assets`; `GET /campaigns`, `GET /campaigns/{id}`, `POST /campaigns`,
  `POST /campaigns/{id}/verify`; `POST /scans/nmap`, `POST /scans/nuclei`; `GET /jobs/{id}`.
- In-app API reference page with curl examples (no external assets).

## Testing

Re-verify queueing, grouping, delay, verified / reopened / inconclusive outcomes, suspected verification;
report maths (MTTR, SLA compliance, trend buckets) and pages; exports; API key lifecycle, auth failures,
role ceiling, every endpoint, permission denials, audit attribution, cookie not accepted on the API.
