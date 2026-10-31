# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.6.0] - 2026-10-31

### Added
- **Attack-surface change detection**: every nmap scan is compared with the inventory as it was before the scan and
  records *New host* (one row listing its open ports), *Port opened*, *Port closed*, *Version changed* (product or
  version) and *Not responding* (a known host inside the scan's targets, not excluded, that was not up; the host is
  kept and not reported again until it is seen again). Duplicate `<host>` blocks for one address are merged.
- **Changes** page (core menu, after Inventory): filters for type, scope, period (default 30 days), job and state
  (open / all), 50 per page; **Acknowledge** one change or **Acknowledge all** matching the filters (only changes
  shown when the page was rendered; `issues.manage`, audit `surface.ack`).
- Nmap job pages show **Changes from this scan**; the Dashboard shows **Surface changes (7 days)**.
- Notification event `surface.changed`: one summary per scan (medium for new hosts / opened ports, else low). The
  first scan of an empty inventory is recorded as a baseline and not notified.
- `GET /api/v1/changes` (`days`, `kind`, `job`, `state`, `limit` up to 500).

### Fixed
- A scan of only some ports (custom or top ports) no longer deletes the host's other ports from the inventory. The
  scanned ports are read from nmap's `scaninfo`, and only those can be counted as closed.
- A service whose version detection returns nothing on a rescan keeps its previous product and version.

## [1.5.0] - 2026-10-31

### Added
- **Bulk verify**: **Verify selected** on the Issues list (with `scan.run`, `POST /issues/bulk-verify`, audit
  `issue.bulk_verify`) and **Verify all with proof** on active campaigns (`POST /campaigns/{id}/verify-issues`, audit
  `campaign.verify_issues`) verify many issues at once: one nuclei job per template, run against each issue's asset
  (targets deduplicated), at most 200 issues per request. The flash says how many jobs and issues started and how
  many were skipped and why (no template, template not indexed, already running, over limit). Each issue's result
  (reproduced / not reproduced / inconclusive, Verified confidence and proof) only counts the finding linked to that
  issue, or for info templates a finding from the issue's own scan target.
- **Evidence report** per issue (`/reports/issues/{id}`, **Print proof** button on the issue page): severity, risk
  score with breakdown, confidence, asset / scope / owner / status / due, campaigns, CVE intel (CVSS, EPSS, KEV), the
  last 15 timeline events and the full proof of the finding that verified it (else the newest finding).
- Campaign and scope reports end with an **Evidence** appendix for verified issues (request / response cut at 2,000
  characters with a link to the issue report, curl); the **Include proof** checkbox (`?proof=0`) leaves it out.
- The issue page and the evidence report show at most 200,000 characters of a request / response ("… N more
  characters not shown").

## [1.4.0] - 2026-10-31

### Added
- **0-day watch**: every hour (first run 3 minutes after start) the scanner reads CVEs published or changed in NVD
  since its last check (CVE API 2.0 `lastMod` window read in one-day sub-windows of 500 results, 60 s timeout,
  checkpointed after each sub-window, 30 minutes of overlap) and new CISA KEV entries (one day of overlap; KEV CVEs
  not already read from NVD are looked up one by one, at most 5 per run), keeps those at or above the minimum CVSS
  (default 7.0) or known exploited, and matches their vulnerable CPE ranges against the inventory: nmap application
  CPE, an alias table of common nmap product names (whole words only) and name similarity; OS CPEs count only when
  the version is known and in range. A match is *confirmed* when the service version is inside the range and
  *possible* when it cannot be checked.
- All NVD requests (0-day watch and threat intel refresh) share one process-wide limiter: at least 6 s apart.
- Only CVEs published in the last 30 days or known exploited are drafted (older CVEs that NVD reports as modified
  stay as hits), at most 20 drafts per run (setting *Drafts per run*; known exploited and highest CVSS first; the
  run summary notes how many more were not drafted). Hits held back by the limit are drafted by later runs in the
  same order, and each eligible hit on the watch page has a **Draft now** button (campaign managers).
- Version strings that cannot be read reliably (`9.4.z-SNAPSHOT`, `2.x`, `2.0 or later`, distro suffixes after a
  dash) count as unknown: the match is *possible*, never dropped.
- For each new hit a **draft campaign** is prepared: intel from NVD / KEV, up to 5 version rules (created
  disabled), matching nuclei templates, and a `campaign.draft` notification. The draft page shows the matched
  assets with quality badges; **Activate** enables the rules, opens suspected issues and sends `campaign.created`;
  **Dismiss** turns it down for good (it can be reopened as a draft). Matched assets without a readable version
  are flagged on the draft (version rules cannot cover them) and get a suspected issue on Activate. A CVE that already has a campaign, in any
  status, is never drafted again.
- Templates are attached automatically to draft and active campaigns that have none, after every watch run and
  every template re-index (for example after a nuclei-templates update).
- **0-day watch** page (sidebar, after Campaigns): last run, settings (enabled, minimum CVSS, always include KEV,
  include possible matches; administrators), **Check now** (campaign managers) and the 100 most recent hits with
  CVSS, KEV, EPSS, matched assets and their campaign.
- Campaigns list gains a **Draft** tab with a count; the dashboard shows **Drafts waiting** when there are any;
  the API `GET /campaigns` accepts `status=draft|dismissed`.

### Changed
- Draft and dismissed campaigns never produce issues: their rules are skipped by rule evaluation even when enabled,
  verification is refused until the campaign is activated, and they are not counted as active anywhere.
  The issue page does not list them; the Version rules page marks their rules *waiting for activation*, and
  editing such a rule returns to its campaign.

## [1.3.0] - 2026-10-31

### Added
- **Risk score** (0-100) on every issue: CVSS (or severity when no CVSS is known), exploitation from CISA KEV or the
  FIRST EPSS percentile, KEV ransomware use, confidence and scope criticality. Bands critical / high / medium / low.
  The Issues list has a sortable **Risk** column and is ordered by risk; the issue page has a **Risk** card with the
  breakdown, EPSS and KEV; the dashboard lists the **Top risks**; campaigns show EPSS next to CVSS; notifications
  carry a Risk field; CSV/JSON exports and the API gain `risk_score`, `risk_band`, `epss`, `epss_percentile`, `kev`.
- Threat intel cache (`cve_intel`): EPSS, KEV and missing CVSS scores (NVD, 5 per run) for the CVEs on issues and
  campaigns are refreshed hourly by the scheduler; Settings → **Threat intel** shows the last run and has
  *Refresh threat intel now*.

## [1.2.1] - 2026-10-31

### Fixed
UI/UX audit of all 35 pages in light and dark theme at 1440 px and 375 px (contrast, labels, control names,
target size, headings, horizontal overflow):
- Phones: 12 pages no longer scroll sideways (issue and campaign details, dashboard, nmap, schedules, scopes, rules,
  users, API keys, integrations, AI, reports). Long values wrap; choice cards stack; the user chip shows only the
  avatar below 520 px and topbar buttons keep their size.
- Contrast: the *Known exploited* badge in dark mode (2.8:1 → 6.4:1), inline code in hints and the nuclei scan
  footer note now meet WCAG AA 4.5:1.
- Readability: sidebar group labels, the brand tagline and the role label are at least 11.5 px.
- Forms: the read-only Username field on the profile and user pages has a label; checkboxes and radios are 18 px.
- The sidebar version link meets the 24 px minimum target size.

## [1.2.0] - 2026-10-31

### Added
- **Verified** confidence level: when *Verify now* reproduces a vulnerability the issue becomes *Verified*
  (Suspected → Confirmed → Verified) and its badge links to the proof (request/response) that verified it. Shown in
  the Issues list, issue page, campaign exposure table and campaign report; filterable, in KPIs, exports and the API.
  A later verification that does not reproduce it moves it back to Confirmed. Issues reproduced before this release
  are upgraded on startup.

### Changed
- The closed lifecycle status is displayed as **Fix verified** (stored value `verified` is unchanged), so "Verified"
  has one meaning in the UI.
- Marking a Verified issue Fixed triggers automatic re-verification, as for Confirmed issues.

## [1.1.0] - 2026-10-31

### Added
- AI providers can be fixed in place: an **Edit** button on System → AI opens a form with the same fields and hints
  as *Add provider*, including the **provider type**. A stored API key can be kept, replaced or removed
  (**Remove stored key**). **Save & test** saves and runs the connection test in one step.

### Changed
- Changing the type, model, base URL, API version or key of a provider clears its previous test result.
- A validation error on the provider form keeps everything that was typed.

### Fixed
- Switching a provider to the OpenAI type no longer keeps a base URL from its previous type, so the key is only
  sent to api.openai.com.

## [1.0.0] - 2026-10-31

First stable release: the scanner from 0.1.0 grows into a vulnerability-response platform.

### Added
- Version number shown in the sidebar footer, returned by `/healthz` and `/api/v1/me`, and set as the
  `org.opencontainers.image.version` label of the Docker image.
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

[Unreleased]: https://github.com/zildjiean/Vulnerabilty-Rapid-Scanner/compare/v1.6.0...HEAD
[1.6.0]: https://github.com/zildjiean/Vulnerabilty-Rapid-Scanner/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/zildjiean/Vulnerabilty-Rapid-Scanner/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/zildjiean/Vulnerabilty-Rapid-Scanner/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/zildjiean/Vulnerabilty-Rapid-Scanner/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/zildjiean/Vulnerabilty-Rapid-Scanner/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/zildjiean/Vulnerabilty-Rapid-Scanner/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/zildjiean/Vulnerabilty-Rapid-Scanner/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/zildjiean/Vulnerabilty-Rapid-Scanner/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/zildjiean/Vulnerabilty-Rapid-Scanner/releases/tag/v0.1.0
