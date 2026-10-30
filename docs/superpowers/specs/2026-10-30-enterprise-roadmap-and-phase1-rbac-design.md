# Enterprise Roadmap and Phase 1 (Users, Roles, Audit) — Design

**Date:** 2026-10-30
**Status:** approved by user in brainstorming

## Context

The scanner is used by **one internal security team**. Its main goal is **fastest possible 0-day
response**: when a new CVE appears, know within minutes which assets are exposed, verify them,
and drive the fix to closure. Notifications must cover in-app lifecycle, webhooks (Slack / Teams /
generic), email and Jira / GitLab tickets.

Architecture decision: keep extending the current stack (FastAPI + SQLite + one container, in-process
scheduler later). No Postgres or external queue.

## Target workflow

```
1 Scope ─▶ 2 Discovery ─▶ 3 Threat campaign ─▶ 4 Exposure (passive match → verify)
                                                        │
8 Report ◀─ 7 Re-verify ◀─ 6 Notify ◀─ 5 Issue lifecycle ◀┘
cross-cutting: users & roles · audit log · scheduler · REST API
```

- **Scope**: asset groups with owner, criticality, tags and a discovery schedule.
- **Threat campaign**: one object combining CVE, version rule(s) and nuclei template(s). Creating it
  matches the inventory passively at once; "Verify" runs the templates only against matching assets.
- **Issue**: deduplicated per (asset, CVE/template) across scans. Lifecycle New → Triaged →
  In progress → Fixed → Verified, or False positive / Accepted risk. Assignee, SLA due date from
  severity, comments, history.
- **Re-verify**: marking an issue Fixed re-runs its template; pass → Verified, fail → reopened.

## Phases

| Phase | Content |
|---|---|
| 1 | Users and roles, audit log, Users / Profile / Audit pages (this document) |
| 2 | Issue lifecycle, assignment, SLA, comments, history, Issues page |
| 3 | Threat campaigns: CVE + rule + template, passive match, verify, campaign page |
| 4 | Scopes and scheduler (discovery and verify on a schedule) |
| 5 | Notifications: webhook, email, Jira / GitLab tickets |
| 6 | Reports / export, REST API with API keys, automatic re-verify |

Each phase ships working software and gets its own spec / plan section.

---

## Phase 1 design

### Roles and permissions

Permissions are defined once in `app/authz.py`.

| Permission | admin | analyst | viewer |
|---|---|---|---|
| `view` (all read pages, logs, findings, inventory) | ✓ | ✓ | ✓ |
| `scan.run` (nmap / nuclei scan, inventory → nuclei, cancel jobs) | ✓ | ✓ | |
| `inventory.manage` (delete selected, clear) | ✓ | ✓ | |
| `rules.manage` (create, edit, toggle, delete, evaluate) | ✓ | ✓ | |
| `templates.manage` (upload, pull, delete, reindex) | ✓ | ✓ | |
| `system.update` (update nmap / nuclei / templates) | ✓ | | |
| `users.manage` | ✓ | | |
| `audit.view` | ✓ | | |

- Routes: `Depends(require("perm"))` → 403 page when missing.
- Templates: `can("perm")` hides or disables controls; viewers get a read-only notice on scan forms.

### Users and sessions

- `users` gains `role` (admin | analyst | viewer), `display_name`, `email`, `is_active`,
  `last_login_at`, `session_version`. A startup migration adds missing columns to existing databases;
  existing users become `admin`.
- Session cookies carry `sv` (session version). The middleware rejects sessions of inactive users or
  with a stale `sv`. Reset password and deactivate bump `session_version`, signing that user out.
- **Users page** (`users.manage`): create (server generates a temporary password shown once; the user
  must change it on first login), edit role / name / email, activate / deactivate, reset password,
  delete.
- Guards: you cannot delete, deactivate or demote yourself; the last active admin cannot be demoted,
  deactivated or deleted.
- **Profile page** (everyone): edit display name and email; link to change password. The user chip in
  the top bar links to it and shows the role.
- Inactive users cannot log in (same generic "Invalid username or password." message).

### Audit log

- Table `audit_log`: `id, created_at, user_id, username, action, target, details (JSON), ip`.
  `username` is copied so entries survive user deletion.
- `app/audit.py` → `audit(db, request, action, target="", **details)` adds and commits a row.
- Recorded actions: `auth.login`, `auth.login_failed`, `auth.logout`, `auth.password_changed`,
  `profile.updated`, `user.created|updated|activated|deactivated|password_reset|deleted`,
  `scan.nmap`, `scan.nuclei`, `job.cancelled`, `inventory.deleted`, `inventory.cleared`,
  `rule.created|updated|toggled|deleted|evaluated`, `template.uploaded|pulled|deleted|reindexed`,
  `system.update`.
- **Audit page** (`audit.view`): filter by user, action prefix, date range; 50 rows per page; CSV
  export with the same filters.

### UI

- Sidebar group **Administration** (Users, Audit log), visible with `users.manage` / `audit.view`.
- 403 renders an in-app "Access denied" page instead of JSON.

### Out of scope

SSO / OIDC, 2FA, API keys (phase 6), per-scope permissions.

### Testing

- Permission matrix per role; viewer gets 403 on every mutating route and sees no action buttons.
- Self / last-admin guards; inactive user cannot log in; reset and deactivate end existing sessions.
- Audit rows written for login, scans, inventory, rules, templates, updates and user changes; filters
  and CSV export.
- Migration adds the new columns to a database created by the previous schema.
