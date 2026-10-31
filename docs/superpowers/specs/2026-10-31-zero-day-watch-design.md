# 0-day watch — design

**Date:** 2026-10-31 · **Status:** approved by the project owner · **Target version:** 1.4.0
Part 2 of the roadmap (after the risk score, 1.3.0). Owner decisions: create **draft** campaigns that a person
activates; the scanner may reach CISA KEV, NVD and FIRST over the internet (only public data is requested; no
inventory data leaves the scanner).

## Goal

Every hour, find newly published or newly exploited CVEs that affect services in the inventory, prepare a draft
campaign for each, notify the team, and attach a nuclei template as soon as one exists.

## Sources (`app/watch.py`)

- **NVD** `GET https://services.nvd.nist.gov/rest/json/cves/2.0` with `lastModStartDate` / `lastModEndDate`
  (ISO 8601 `2026-10-30T00:00:00.000`, window ≤ 120 days) from the last successful check to now
  (first run: 3 days back), `resultsPerPage=2000`, paging with `startIndex`, 6 s between pages (injectable sleep).
  Parse per CVE: id, published, description (en), best CVSS (reuse `intel._best_metric`), references, and the
  affected CPE ranges from `configurations[].nodes[].cpeMatch[]` where `vulnerable` is true:
  `criteria` (cpe 2.3 → vendor, product, exact version or `*`), `versionStartIncluding/Excluding`,
  `versionEndIncluding/Excluding`.
- **CISA KEV** feed (reuse `intel._load_kev_feed`, shared cache; refresh forced each watch run): entries with
  `dateAdded` ≥ the last processed date (first run: 14 days back) → vendorProject, product, name, due date,
  ransomware. A KEV CVE without NVD ranges in this run is looked up once with `intel.get_json(NVD_URL, {"cveId"})`
  (paced, at most 5 per run).
- Thresholds (Settings → 0-day watch): enabled (default on), minimum CVSS (default 7.0), KEV always included
  (default on). CVEs below the threshold and not in KEV are skipped.

## Matching inventory (`match_cve(cve, services) -> list[Match]`)

For each service (`Service` + `Host`) find product keys:
1. **CPE** from nmap (`cpe:/a:vendor:product[:version]`) → `(vendor, product)`.
2. **Alias table** `PRODUCT_ALIASES` in `app/watch.py`: normalised nmap product name → list of `(vendor, product)`.
   At least: Apache httpd→apache:http_server; Apache Tomcat→apache:tomcat; nginx→f5:nginx, nginx:nginx;
   OpenSSH→openbsd:openssh; Microsoft IIS httpd→microsoft:internet_information_services (+ microsoft:iis);
   PHP→php:php; MySQL→oracle:mysql, mysql:mysql; MariaDB→mariadb:mariadb; PostgreSQL DB→postgresql:postgresql;
   Exim smtpd→exim:exim; Postfix smtpd→postfix:postfix; Dovecot imapd/pop3d→dovecot:dovecot; Samba smbd→samba:samba;
   vsftpd→vsftpd_project:vsftpd, beasts:vsftpd; ProFTPD→proftpd:proftpd; OpenLDAP→openldap:openldap;
   Redis key-value store→redis:redis; Elasticsearch REST API→elastic:elasticsearch; Jetty→eclipse:jetty;
   lighttpd→lighttpd:lighttpd; Microsoft Exchange smtpd→microsoft:exchange_server; Microsoft Terminal Services→
   microsoft:remote_desktop_services; Apache Struts→apache:struts; Jenkins→jenkins:jenkins; GitLab→gitlab:gitlab;
   Grafana→grafana:grafana; Squid http proxy→squid-cache:squid; Varnish→varnish-cache:varnish;
   HAProxy→haproxy:haproxy; Node.js Express framework→expressjs:express; BusyBox→busybox:busybox;
   OpenSSL→openssl:openssl; Atlassian Confluence→atlassian:confluence_server, atlassian:confluence_data_center;
   Fortinet/FortiGate→fortinet:fortios; Citrix NetScaler→citrix:netscaler_application_delivery_controller.
   Matching is case-insensitive on the normalised name (lowercase, collapse spaces) as a prefix.
3. **Name similarity** (KEV entries and NVD CPEs without a key hit): normalised product tokens of the CVE
   (`vendorProject` + `product`, or CPE vendor/product with `_` → space) all contained in the normalised service
   product → match with quality `possible`.

Version check per match: inventory version via `version_compare.extract_version(service.version)`.
- Range known and version parseable: inside → `confirmed`; outside → dropped.
- Exact CPE version (not `*`) and version parseable: equal → `confirmed`; else dropped.
- Otherwise (no range or version unparseable/missing) → `possible`.
Optionally skip `possible` matches (Settings: "Include possible matches", default on).

## Draft campaigns

For each CVE with ≥ 1 match that has no campaign yet (any status, by `cve_id`) and was not dismissed:
- `create_campaign(..., status draft)` — add `status="draft"` support: `Campaign.status` gains `draft` and
  `dismissed` (String(16) already). Draft and dismissed campaigns do **not** evaluate rules and do not count as
  active anywhere (dashboard, campaign lists default to active).
- Intel from the watch data (CVSS, description, references, KEV fields via `apply_intel`-compatible dict),
  `severity="auto"`, `created_by="0-day watch"`.
- Version rules: one per distinct (product pattern, range) up to 5. Product pattern = regex-escaped, lower-cased
  inventory product name of the matched services (e.g. `apache httpd`); constraint built from the range
  (`>= 2.4.0, < 2.4.62`; empty when unknown). Rules are created with `enabled=False`.
- Templates: attach `templates_for_cve` immediately when present.
- Store the match list on a new table `watch_hits` (see below) and link it to the campaign.
- Notification: new event `campaign.draft` ("0-day watch: CVE affects N assets") through `notify` with the
  campaign message (severity from the campaign). Add it to `EVENTS` so channel rules can subscribe.
- Activate (`POST /campaigns/{id}/activate`, `campaigns.manage` + CSRF): status → active, rules enabled,
  `evaluate_rules`, audit `campaign.activated`, notify `campaign.created`. The draft page shows matched assets with
  quality badges and lets the user edit/delete rules before activating (existing rule editing).
- Dismiss (`POST /campaigns/{id}/dismiss`): status → dismissed, rules stay disabled, audit; dismissed CVEs are never
  drafted again. A dismissed campaign can be reopened as draft (`POST /campaigns/{id}/reopen` already exists for
  closed — extend to dismissed → draft).

## Template auto-attach

`attach_new_templates(db) -> int` for draft and active campaigns with a `cve_id` and no templates: attach
`templates_for_cve`, add a campaign note/audit "Template X attached automatically". Runs at the end of every
watch run and after a successful nuclei-templates update job (hook where `reindex` runs after updates).

## Table `watch_hits`

`id`, `cve_id` (index), `source` (`nvd`|`kev`|`both`), `title`, `cvss_score`, `kev` (bool), `matches` (JSON list of
`{service_id, host, port, product, version, quality, reason}`), `quality` (best of matches), `campaign_id`
(nullable), `created_at`. One row per CVE (upsert: merge new matches).

## Scheduling and state

`AppSetting("watch")`: settings (enabled, min_cvss, kev_always, include_possible) and state (last_nvd_check ISO,
last_kev_date, last_run summary: CVEs scanned, matched, drafts created, templates attached, errors).
`maybe_watch(app)` is called by the scheduler tick next to `maybe_refresh_intel`, as a background task (same
pattern: flag against overlap, attempt time recorded even on failure, hourly; first run 3 minutes after start).
Per-source `except Exception` with short errors (reuse `risk.short_error`). Manual run:
`POST /watch/run` (`campaigns.manage` + CSRF) starts it in the background and redirects.

## UI

- Sidebar: **0-day watch** item under Campaigns in the core section? → put it in the core list right after
  Campaigns (icon `radar` if present, else `activity`).
- `/watch` page: last run summary, settings form (admin: `settings.manage`), **Check now** button, table of recent
  hits (CVE, title, CVSS, KEV badge, EPSS if known, matched assets count with quality badges, campaign link and
  its status), newest first, 100 rows.
- Campaigns list: tabs Active / **Draft** / Closed / All (dismissed shown under All with a badge); draft count
  badge on the Draft tab.
- Campaign page in draft status: banner "Draft created by 0-day watch on … — review the rules, then Activate or
  Dismiss", matched assets table with quality badges (`confirmed` = version in range, `possible` = needs check),
  Activate (primary) and Dismiss buttons; Verify/run actions hidden until active.
- Dashboard: "Drafts waiting" KPI link when > 0.

## Tests (`tests/test_watch.py`)

NVD parser (ranges, cpe 2.3 split, best CVSS, paging); KEV new-entry filter by date; alias + CPE + similarity
matching; version decisions (in range, outside, exact, unparseable → possible); thresholds; draft creation
(rules disabled, no issues created, templates attached, notification event, watch_hits row); no duplicate draft
for an existing or dismissed CVE; activate creates suspected issues; dismiss; auto-attach after template
appears; scheduler gating and failure isolation; `/watch` page, settings save, Check now permissions; Campaigns
Draft tab. All network through a fake `get_json`.
