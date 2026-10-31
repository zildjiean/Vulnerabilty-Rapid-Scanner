# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Verify now (Play)** on every issue: re-runs the issue's nuclei template against that asset only, records
  *reproduced / not reproduced / inconclusive* on the issue timeline and marks it confirmed when reproduced.
  Available on the issue page, as a Play icon in the Issues list and in a campaign's exposure table.
- **Proof** card on the issue page: the HTTP request and response nuclei matched on, the matcher, extracted values
  and a copyable curl command, for every finding (nuclei records them by default).
- Suspected issues without a template can link an indexed template or ask the AI to draft a verification template,
  review it and *Save & run as proof*. When the model declines, the page explains in English how to switch the
  provider/model under System → AI.
- Thai user guide ([docs/USER_GUIDE.th.md](docs/USER_GUIDE.th.md)) covering setup, every menu and troubleshooting.
- Compact sidebar: daily pages (Dashboard, Issues, Campaigns, Inventory, Reports) on top; Scanning, Detection library
  and System as collapsible groups that remember their state. Administration links moved under System.
- AI assistant with your own provider and key (Administration → AI): Anthropic Claude (official SDK, default
  `claude-opus-5-5`, structured outputs, refusal handling and server-side fallback), OpenAI, Azure OpenAI, Google Gemini
  and any OpenAI-compatible server (official OpenAI SDK). Features: campaign draft from an advisory, detection-template
  draft validated with nuclei, issue explanation and remediation, evidence triage, natural-language search, executive
  report summary and job diagnosis. Suggestions only; redaction of IPs / host names (default on), encrypted keys,
  usage accounting and audit. New permissions `ai.use` (analyst, admin) and `ai.manage` (admin). New dependencies:
  `anthropic`, `openai`.
- Automatic re-verification: confirmed issues marked fixed are re-scanned with their template after a delay
  (Settings, default 15 minutes; one job per template). Not found → verified, found → reopened, incomplete scan or
  failed job → stays fixed with a note. Suspected issues are verified by the next nmap scan of the service.
- Reports: executive summary (open by severity, overdue, MTTR, SLA compliance, weekly new vs resolved, riskiest
  assets, scopes, campaigns) with a print stylesheet, campaign and scope reports, CSV / JSON issue exports.
- REST API v1 (`/api/v1`): issues, assets, campaigns, nmap / nuclei scans and jobs. API keys are hashed,
  role-scoped (never above the owner), expiring and revocable; `/api` accepts only API keys. API keys page and an
  in-app API reference with curl examples.
- Notifications and ticketing (Administration → Integrations): Slack, Microsoft Teams (Adaptive Cards), email
  (SMTP with STARTTLS / SSL, optional copy to the assignee), JSON webhooks signed with HMAC-SHA256, Jira and GitLab.
  Rules by event, minimum severity and scope. Two-way tickets: created by rule or from the issue page, commented /
  closed / reopened as the issue changes, polled every 15 minutes so a closed ticket marks the issue fixed.
  Outbox with retries (1, 5, 15, 60 minutes), delivery log with retry, per-channel test / connection check.
  Integration secrets and the SMTP password are encrypted at rest (new dependency: `cryptography`).
  Settings gain the public URL used in links and the SMTP server. New permission `integrations.manage` (admin).
- Scopes: named asset groups (nmap target syntax with exclusions), owner and criticality. New issues inside a
  scope are auto-assigned to its owner; issues show and filter by scope; inventory can group by scope.
- Schedules: nmap discovery and nuclei scans per scope and re-verification of active campaigns, every N hours,
  daily or weekly in the platform timezone (Settings, default Asia/Bangkok). Runs are skipped while the previous
  one is still running, can be triggered with Run now, and are audited. nmap gains `--exclude` support.
  New permission `scopes.manage` (analyst, admin).
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
