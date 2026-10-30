# Phase 4: Scopes and Scheduler — Design

**Date:** 2026-10-30 · **Status:** approved · Roadmap: `2026-10-30-enterprise-roadmap-and-phase1-rbac-design.md`

## Scopes

A scope is a named group of assets with an owner and a business criticality.

- Fields: name (unique), description, targets (nmap syntax: IP, CIDR, IPv4 octet ranges `10.0.0.1-50`,
  hostnames), exclusions (same syntax), owner (active admin / analyst, optional), criticality
  (critical / high / medium / low).
- Membership: an asset belongs to a scope when its address (or host name) matches a target and no exclusion.
  When several scopes match, the most critical wins, then the oldest.
- Issues get `scope_id`. A **new** issue inside a scope with an owner is auto-assigned to that owner
  (timeline event by `system`). Editing / deleting scopes recomputes `scope_id` for every issue but never
  changes existing assignees.
- Issues list: scope column (name + criticality) and scope filter. Issue detail shows the scope.
  Inventory gains *Group by → Scope*.

## Schedules

| Kind | Scope | What runs |
|---|---|---|
| `nmap` | required | nmap discovery of the scope targets, exclusions passed as `--exclude`; port mode, custom ports, timing, scan type, skip ping |
| `nuclei` | required | nuclei against the scope's inventory services (`http(s)://addr:port` for web), template mode all / groups, severities, profile |
| `campaign_verify` | none | Verify every active campaign that has templates and exposed assets |

- Frequency: every N hours (1–168), daily at HH:MM, or weekly on a weekday at HH:MM, in the platform
  timezone (Settings, default `Asia/Bangkok`; changing it recomputes daily / weekly next runs).
- An in-process loop checks every 30 s. A due schedule whose previous job is still queued / running is
  skipped for that occurrence (recorded). Each run stores last run time, status (started / skipped / error),
  message and job; jobs carry `schedule_id`. "Run now" runs immediately without moving the next run.
- Scheduled runs are audited as user `scheduler`.

## Permissions

`scopes.manage` (admin, analyst) for scopes and schedules. Viewers can read both pages.

## UI

- Discovery → **Scopes** (list with criticality, owner, asset count, open issues, schedules), scope detail
  with edit form, assets, open issues and its schedules (add / toggle / run / delete).
- System → **Schedules**: every schedule with next run (local time), last result and job link; add schedules
  for any scope or campaign verify.
- Settings: platform timezone.

## Testing

Target matching (IP, CIDR, octet ranges, IPv6, hostnames, exclusions), priority, rescope, auto-assign rules,
next-run maths across days / weeks / timezones, each schedule kind, skip-while-running, due selection,
routes, permissions, audit.
