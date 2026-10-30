# Phase 3: Threat Campaigns — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Spec:** `docs/superpowers/specs/2026-10-30-phase3-threat-campaigns-design.md`

### Task 1: Intel client — `app/intel.py`, `tests/test_intel.py`
- [ ] Tests: NVD JSON parsing (v3.1, v4.0, missing metrics), KEV lookup, 24 h cache, network errors → message.
- [ ] Implement `parse_nvd`, `fetch_nvd`, `load_kev`, `kev_entry`, `enrich` with an injectable `get_json`.

### Task 2: Models + domain — `app/db.py`, `app/campaigns.py`, `tests/test_campaigns.py`
- [ ] Tests: migration columns, create with rule + auto templates, campaign issues, progress, verify targets.
- [ ] Implement `Campaign`, `CampaignTemplate`, `rules.campaign_id`, `jobs.campaign_id`; domain functions.

### Task 3: Nuclei launch helper — `app/routers/nuclei.py`
- [ ] Extract `launch_nuclei(...)` used by `/nuclei/scan` and campaign verify (existing tests stay green).

### Task 4: Routes + pages — `app/routers/campaigns.py`, templates
- [ ] Tests: list, new, detail, verify, rules / templates add-remove, close / reopen, refresh, permissions, audit.
- [ ] Implement; nav, dashboard panel, issue detail link.

### Task 5: Release — README / CHANGELOG, full pytest, rebuild, browser check, merge, push.
