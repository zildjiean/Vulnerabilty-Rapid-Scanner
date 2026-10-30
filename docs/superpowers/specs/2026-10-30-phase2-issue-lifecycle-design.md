# Phase 2: Issue Lifecycle — Design

**Date:** 2026-10-30 · **Status:** approved · Roadmap: `2026-10-30-enterprise-roadmap-and-phase1-rbac-design.md`

## Goal

Turn raw findings and version-rule matches into deduplicated, owned, time-boxed **issues** that the team drives
from detection to verified fix.

## Issue identity

- **Asset** = `address:port`. For nuclei results the address is the resolved `ip` (falling back to the host
  name) and the port comes from the result or its URL; for rule matches it is the inventory host and service port.
- **Vulnerability** = the CVE id when known (nuclei classification or the rule's CVE), otherwise the nuclei
  template id, otherwise `rule-<id>`.
- `key = asset|vulnerability` is unique. Repeated sightings update the same issue.
- **Confidence**: version-rule match → `suspected`; nuclei finding → `confirmed`. A suspected issue confirmed
  by nuclei is upgraded (event recorded).
- Findings with severity `info` / `unknown` never create issues (they stay on the Findings page).
- Severity = highest severity seen, unless a user changed it manually (`severity_overridden`).

## Lifecycle

Statuses: `new`, `triaged`, `in_progress`, `fixed`, `verified`, `false_positive`, `accepted_risk`.
Active = new, triaged, in_progress, fixed (awaiting verification). Closed = verified, false_positive, accepted_risk.

| From | Allowed to |
|---|---|
| new | triaged, in_progress, fixed, false_positive, accepted_risk |
| triaged | in_progress, fixed, false_positive, accepted_risk |
| in_progress | triaged, fixed, false_positive, accepted_risk |
| fixed | verified, in_progress |
| verified / false_positive / accepted_risk | triaged (reopen) |

`false_positive` and `accepted_risk` require a comment.

Automation (recorded as events by `system`):
- **Reopen**: a fixed or verified issue seen again is moved to `triaged`. For rule matches this only happens
  when the service was re-scanned after the issue's last status change, so marking an issue fixed is not undone
  by an unrelated rule re-evaluation. False positive / accepted risk are never reopened automatically.
- **Auto-fix**: a suspected, active (not yet fixed) issue whose rule is still enabled, whose service is still in
  the inventory, but which no longer matches (e.g. the version was upgraded) moves to `fixed`.

## SLA

Default days from first seen: critical 3, high 7, medium 30, low 90 (no SLA for info / unknown). Stored in
`app_settings`; admins edit them on a Settings page, which recomputes due dates of active issues.
Overdue = new, triaged or in progress and past due (fixed counts as remediated for the SLA).

## Data model

- `issues`: key, asset, address, port, hostname, vuln_id, cve_id, template_id, rule_id, title, severity,
  severity_overridden, confidence, status, assignee_id (FK users, SET NULL), due_at, first_seen, last_seen,
  status_changed_at, resolved_at, occurrences, created_at, updated_at.
- `issue_events`: issue_id (cascade), created_at, user_id, username, kind
  (created | seen | confirmed | status | assigned | severity | comment | reopened | auto_fixed), from_value,
  to_value, body.
- `app_settings`: key, value.
- `findings.issue_id` (nullable) links evidence to its issue.

## Permissions

New `issues.manage` (admin, analyst): change status, assign, change severity, comment, bulk actions.
New `settings.manage` (admin): SLA settings. Viewers read issues.

## UI

- **Issues** (Detection nav): KPI cards (active, overdue, due in 7 days, unassigned, confirmed / suspected),
  filters (view active / closed / all, severity, status, assignee incl. me / unassigned, confidence, overdue,
  search), table sorted by severity then due date, bulk assign / status.
- **Issue detail**: summary, status / assignee / severity actions, evidence (findings with job links, rule),
  timeline with comments.
- **Settings** (Administration): SLA days per severity.
- Dashboard KPIs for active and overdue issues; Findings rows link to their issue.
- Audit: `issue.status_changed`, `issue.assigned`, `issue.severity_changed`, `issue.commented`,
  `issue.bulk_updated`, `settings.updated`.

## Backfill

On startup, findings without an issue and current rule matches are converted (idempotent).

## Testing

Identity and dedup, confidence upgrade, info ignored, severity raise / override, transitions and reasons,
reopen rules (finding vs rule timing), auto-fix, SLA and recompute, backfill idempotency, routes and permissions,
bulk actions, audit rows.
