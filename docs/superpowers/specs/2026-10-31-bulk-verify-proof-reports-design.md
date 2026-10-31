# Bulk verify and proof in reports — design

**Date:** 2026-10-31 · **Status:** approved by the project owner ("ทำรอบถัดไปต่อเลย") · **Target version:** 1.5.0
Part 3 of the roadmap.

## Bulk verify

- `proof.start_verify_many(db, app, issues, actor) -> BulkResult` groups eligible issues by template path and starts
  one nuclei job per template (targets = each issue's `reverify.issue_target`, deduplicated), params
  `{"targets", "template_ids", "mode": "selected", "profile": "normal", "verify_issues": [ids]}`. Each issue gets
  `verify_job_id` and a `verify` timeline event. Skips (counted per reason): no template, template not indexed,
  verification already running. Hard limit 200 issues per request (extra ones skipped as "over limit").
- `complete_verify` handles both `verify_issue` (single, unchanged) and `verify_issues` (list): per issue the same
  reproduced / not_reproduced / inconclusive logic, matching findings by `job_id` + issue (template id), so one
  job can verify many issues. `cleanup_dead_verify_jobs` already works per issue.
- **Issues list**: bulk action button **Verify selected** (shown with `scan.run`) next to the existing bulk
  actions, posting `POST /issues/bulk-verify` (`scan.run` + CSRF, `issue_ids` list, `back`). Flash: "Started N
  job(s) for M issue(s); skipped K (no template), L (already running), …". Audit `issue.bulk_verify`.
- **Campaign page**: button **Verify all with proof** (shown with `scan.run` on active campaigns that have open
  issues with templates) → `POST /campaigns/{id}/verify-issues` runs `start_verify_many` on the campaign's open
  issues; redirects back with the same summary. The existing campaign *Verify* (attached templates + extra
  targets) stays as is.

## Proof in reports

- **Single-issue evidence report** `GET /reports/issues/{id}` (`view`): printable page (reuse the report layout
  and print CSS) with title, severity, risk score + breakdown, confidence badge, asset/scope/owner/status/due,
  campaign(s), CVE intel (CVSS, EPSS, KEV), a short timeline (last 15 events), and the **proof** of the finding that
  verified it (`verified_finding_id`, else the newest finding): request, response (full, wrapped), curl, matcher,
  extracted values, timestamp. Without findings it says "No scan evidence yet". Button **Print proof** on the issue
  page header (icon `printer` if present else `file`), opening this report.
- **Campaign and scope reports**: an **Evidence** appendix after the issue table listing, for each *Verified*
  issue, a block with asset, issue title, verification time and the proof (request/response truncated to 2,000
  characters each with "… truncated, see the issue report" link, curl). Toggle `?proof=0|1` (default 1) through a
  no-print checkbox "Include proof" at the top of the report. Truncation uses `proof.proof_from_finding` + slicing;
  everything autoescaped.
- Executive report unchanged.

## Tests

`start_verify_many` grouping (two templates → two jobs), skips by reason, limit, params; `complete_verify` with
`verify_issues` (one reproduced, one not); route permissions (viewer 403), CSRF, flash text, audit; campaign
button visibility and route; issue evidence report content (proof text, risk, no-evidence case, print button on
the issue page); campaign/scope report Evidence appendix present for verified issues, truncated, and hidden with
`?proof=0`.
