# Phase 5: Notifications and Ticketing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Spec:** `docs/superpowers/specs/2026-10-30-phase5-notifications-design.md`

### Task 1: Secret box — `app/secretbox.py`, `tests/test_secretbox.py`
### Task 2: Channel senders — `app/channels.py`, `tests/test_channels.py` (fake HTTP + fake SMTP)
### Task 3: Models + notification core — `app/db.py`, `app/notifications.py`, `tests/test_notifications.py`
- rules, enqueue hooks (issues, campaigns, schedules, jobs, overdue), dispatcher with retries, ticket sync + poll.
### Task 4: Routes + pages — `app/routers/integrations.py`, templates, settings, issue tickets card, `tests/test_integration_routes.py`
### Task 5: Release — README / CHANGELOG, full pytest, rebuild (new dependency), browser check, merge, push.
