# Phase 3: Threat Campaigns — Design

**Date:** 2026-10-30 · **Status:** approved · Roadmap: `2026-10-30-enterprise-roadmap-and-phase1-rbac-design.md`

## Goal

One place to run the response to a single new vulnerability: what it is, who is exposed, prove it, and
track the fix to the end.

## Campaign

A campaign bundles:
- **Threat intel**: CVE id, name, description, CVSS score / severity / vector, published date, references,
  and **CISA KEV** status (date added, CISA due date, ransomware use, required action). Fetched from the NVD
  2.0 API and the CISA KEV feed (cached in `/data/kev.json` for 24 h). Fetch failures never block creation;
  the error is stored and "Refresh intel" retries.
- **Version rules** (`rules.campaign_id`): created from the campaign; evaluating them opens *suspected*
  issues immediately (phase 2 machinery).
- **Nuclei templates** (`campaign_templates`): templates from the index; on creation every indexed template
  whose `cve_ids` contain the CVE is attached (opt-out checkbox). Suggestions are shown on the detail page.
- Status `active` | `closed`.

## Exposure and progress

Campaign issues = issues whose `vuln_id` equals the campaign CVE, or whose `rule_id` is one of the campaign
rules, or whose `template_id` is one of the campaign templates. Progress counts per status, confirmed vs
suspected, and % remediated = (fixed + verified + false positive + accepted risk) / total.

## Verify

`Verify` runs nuclei with the campaign templates against:
- every asset of a campaign issue that is not closed (target URL built from the inventory service:
  `http(s)://addr:port` for web services, `addr:port` otherwise), plus
- optional extra targets typed by the user.
Profile selectable (Gentle / Normal / Aggressive). The job carries `jobs.campaign_id`; its results flow into
issues as usual (suspected → confirmed). No templates → clear error.

## UI

- **Campaigns** (first item under 0-Day intelligence): table with CVE, KEV badge, CVSS, exposed assets,
  confirmed, open, % remediated, status.
- **New campaign** form: CVE, name (defaults from NVD), severity (auto from CVSS unless chosen), description,
  first rule (product pattern + version constraint, optional), attach-templates and fetch-intel checkboxes.
- **Campaign detail**: intel card, progress bar + KPIs, exposure table, verify form, rules (add / remove),
  templates (attached, suggestions, add / remove), job history, close / reopen, refresh intel.
- Dashboard: active campaigns with progress. Issue detail links to its campaign(s).

## Permissions and audit

`campaigns.manage` (admin, analyst) for create / edit / rules / templates / close / refresh;
verify also needs `scan.run`. Audit: `campaign.created|updated|closed|reopened|enriched|rule_added|
rule_removed|template_added|template_removed|verified`.

## Testing

NVD parsing (v3.1 / v4.0 / none), KEV lookup + cache + failure, creation flow (rule, suspected issues,
auto-attached templates), exposure / progress maths, verify targets and argv, extra targets, no-template error,
permissions, close / reopen, audit rows.
