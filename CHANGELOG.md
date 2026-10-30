# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Threat campaigns: create from a CVE to pull NVD (CVSS, description, references) and CISA KEV (known exploited,
  ransomware use, due date) intel, add version rules and attach nuclei templates (auto-attached from the index).
  Campaign pages show exposure, remediation progress, verification jobs, and run Verify against exposed assets
  plus extra targets. Dashboard lists active campaigns; issues link to their campaign. New permission
  `campaigns.manage` (analyst, admin).
- Issues: findings (low and above) and version-rule matches become deduplicated issues per asset (ip:port) and
  vulnerability (CVE, else template or rule). Rule matches are *suspected*, nuclei results *confirmed*.
  Lifecycle New / Triaged / In progress / Fixed / Verified / False positive / Accepted risk with transition rules
  and mandatory reasons, assignees, SLA due dates, severity override, comments and a full timeline.
  Fixed or verified issues reopen when seen again after the change; suspected issues are auto-fixed when a
  re-scan shows a version the rule no longer matches. Existing findings and rule matches are backfilled.
- Issues page with KPIs, filters and bulk assign / status; Settings page for SLA days (admin);
  dashboard issue KPIs; findings link to their issue. New permissions `issues.manage` (analyst, admin) and
  `settings.manage` (admin).
- Users and roles: admin, analyst and viewer. Every mutating route checks a permission, and pages hide or disable
  what the role cannot do. Existing users become admins through an automatic schema migration.
- Administration → Users: create users with a one-time temporary password, edit role and details,
  activate / deactivate, reset password, delete. Self and last-active-admin guards. Deactivation, password reset
  and role changes end the user's sessions.
- Profile page: display name, email, role permissions and your recent activity.
- Administration → Audit log: sign-ins (including failures), denied attempts, scans, inventory, rule, template, update and user
  changes with source IP. Filters, paging and CSV export (formula-safe; exports are audited).
- In-app "Access denied" / "Not found" pages.
- Inventory grouping: a "Group by" control (Host / Product / Service type / None) renders collapsible
  group header rows with service, host and rule-match counts and a checkbox that selects the whole group;
  column sorting works within each group. Services are classified into Web, Database, Remote access,
  Mail, File sharing, Directory & auth, Network services or Other from their nmap name and port.
- Static assets are served with a content-hash `?v=` token, so browsers pick up new CSS/JS after upgrades.
- Nuclei scan profiles (Gentle / Normal / Aggressive) and a "never drop unresponsive hosts" switch.
- Post-scan log analysis: jobs whose target was dropped as unresponsive, that had many request errors or
  nuclei [ERR]/[WRN] lines finish as "Done with warnings"; the Findings page flags incomplete results.
  Existing jobs are analyzed once on startup.

### Changed
- "Done with warnings" request-error rule: warn when at least 2 % of requests failed and at least 5 did
  (previously any 20+ errors warned, which flagged healthy 10k-request scans). Finished jobs are re-analyzed
  once on startup when the rules change.
- nuclei runs without `-silent` and with periodic stats, so the job log shows templates/targets loaded,
  httpx probing and errors; jobs end with a stored-findings summary line. nmap jobs report hosts/services stored.
- nuclei pinned to v3.11.1 in the Dockerfile.

## [0.1.0] - 2026-10-29

### Added
- Nmap scanning from the web UI (top 1000 / all / custom ports, SYN or connect) with live job logs.
- Inventory of hosts and services with filters, sorting, selection, deletion and hand-off to nuclei.
- Nuclei scanning with template search, template groups, all-templates mode, tag and severity filters.
- Findings view across jobs.
- Custom 0-day templates: upload or pull from URL, validated with `nuclei -validate`.
- Version-match rules evaluated against the inventory after every nmap scan.
- Update actions for nuclei templates, nuclei engine and nmap script DB.
- Forced password change for the default `admin` account, CSRF protection, login rate limiting.
- Single-container deployment (python:3.12-slim + nmap + nuclei, non-root).
- Enterprise UI: sidebar shell, light/dark theme, KPI cards, sortable tables, toasts, confirm dialogs.
