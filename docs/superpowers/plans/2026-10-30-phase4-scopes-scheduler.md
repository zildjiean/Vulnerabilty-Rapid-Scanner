# Phase 4: Scopes and Scheduler — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Spec:** `docs/superpowers/specs/2026-10-30-phase4-scopes-scheduler-design.md`

### Task 1: Scope model + matching — `app/db.py`, `app/scopes.py`, `tests/test_scopes.py`
- [ ] Tests for matchers, priority, exclusions, rescope, auto-assign. Implement `Scope`, `issues.scope_id`,
  `compile_scopes`, `resolve_scope`, `rescope_issues`; hook into issue creation.

### Task 2: Scheduler core — `app/db.py`, `app/scheduler.py`, `tests/test_scheduler.py`
- [ ] Tests for `compute_next_run`, timezone setting, each kind, skip-while-running, `run_due`.
- [ ] Implement `Schedule`, `jobs.schedule_id`, `launch_nmap` (+ `--exclude`), runner, loop in lifespan.

### Task 3: Routes + pages — `app/routers/scopes.py`, `app/routers/schedules.py`, templates
- [ ] Tests for CRUD, toggle / run / delete, permissions, audit, issues scope filter, inventory group by scope,
  timezone setting. Implement.

### Task 4: Release — README / CHANGELOG, full pytest, rebuild, browser check, merge, push.
