# Phase 2: Issue Lifecycle — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Deduplicated issues with lifecycle, assignment, SLA, timeline and automation.
**Architecture:** Pure-ish domain module `app/issues.py` (identity, upsert, transitions, SLA, sync) called from the
nuclei completion hook and `evaluate_rules`; router `app/routers/issues.py` (+ settings); Jinja pages.
**Spec:** `docs/superpowers/specs/2026-10-30-phase2-issue-lifecycle-design.md`

### Task 1: Models + migration — `app/db.py`, `tests/test_issues.py`
- [ ] Test tables exist and `findings.issue_id` is added to an old DB. Implement `Issue`, `IssueEvent`, `AppSetting`.

### Task 2: Identity + upsert from findings — `app/issues.py`
- [ ] Tests: asset/vuln derivation (ip, port, URL, network host:port, CVE), dedup, info ignored, severity raise,
  occurrences, finding.issue_id, reopen of fixed issue. Implement `finding_identity`, `upsert_issue`, `issues_from_findings`.

### Task 3: Rule sync — `app/issues.py`, `app/rules.py`
- [ ] Tests: suspected issue from rule match, confirmed upgrade when nuclei agrees, auto-fix on version upgrade,
  no reopen without a newer scan, reopen after a newer scan. Implement `sync_rule_issues`, call from `evaluate_rules`.

### Task 4: Lifecycle, SLA, settings — `app/issues.py`
- [ ] Tests: transitions table, reasons required, resolved_at, SLA defaults / custom / recompute, overdue,
  backfill idempotent. Implement `change_status`, `assign`, `set_severity`, `add_comment`, `get_sla`, `set_sla`, `backfill_issues`.

### Task 5: Routes, pages, permissions — `app/routers/issues.py`, templates
- [ ] Tests: list filters + KPIs, detail, status / assign / severity / comment, bulk, settings, viewer 403, audit rows.
- [ ] Implement; nav, dashboard KPIs, findings link.

### Task 6: Release
- [ ] README / CHANGELOG, full pytest, rebuild, browser check, merge, push.
