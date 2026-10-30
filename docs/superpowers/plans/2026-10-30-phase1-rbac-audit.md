# Phase 1: Users, Roles and Audit Log — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Multi-user access with admin / analyst / viewer roles, user management, profile page and a filterable audit log.

**Architecture:** `app/authz.py` maps roles to permissions and exposes a `require()` dependency and a `can()` template helper. `app/audit.py` writes audit rows. A tiny column migration in `app/db.py` upgrades existing databases. New routers `users.py`, `profile` (in `auth.py`) and `audit.py`.

**Tech Stack:** FastAPI, SQLAlchemy 2, Jinja2, pytest. Spec: `docs/superpowers/specs/2026-10-30-enterprise-roadmap-and-phase1-rbac-design.md`.

---

### Task 1: Schema and migration
**Files:** `app/db.py`, `tests/test_rbac.py`
- [ ] Test: a DB created with the old `users` schema gets `role`, `display_name`, `email`, `is_active`, `last_login_at`, `session_version` after `init_db`; existing rows read back as `admin`, active, version 0. `audit_log` table exists.
- [ ] Implement `User` columns, `AuditLog` model, `migrate_db(engine)` (PRAGMA table_info + `ALTER TABLE ADD COLUMN`), called from `init_db`.

### Task 2: Permissions
**Files:** `app/authz.py`, `app/render.py`, `app/main.py`, `templates/error.html`, `tests/test_rbac.py`
- [ ] Test the role → permission matrix and `require()` returning 403 page.
- [ ] Implement `ROLES`, `PERMISSIONS`, `has_perm`, `require`, render-context `can`, 403 exception handler.

### Task 3: Sessions bound to user state
**Files:** `app/auth.py`, `app/routers/auth.py`, `tests/test_rbac.py`
- [ ] Test: inactive user cannot log in; bumping `session_version` or deactivating ends an existing session; login sets `last_login_at`.
- [ ] Implement `sv` in session token, middleware checks, login changes.

### Task 4: Audit log core + auth events
**Files:** `app/audit.py`, `app/routers/auth.py`, `tests/test_audit.py`
- [ ] Test: login, failed login, logout, password change write rows with username / ip.
- [ ] Implement `audit()`; call it from auth routes.

### Task 5: Enforce permissions + audit on existing routes
**Files:** routers `nmap, nuclei, inventory, jobs, rules, templates, updates`; templates for those pages
- [ ] Test: viewer gets 403 on every mutating route and sees no scan / delete / update buttons; analyst gets 403 only on `/updates/*`; actions write audit rows.
- [ ] Add `require(...)` dependencies, `audit(...)` calls, `can()` guards in templates.

### Task 6: Users management
**Files:** `app/routers/users.py`, `templates/users.html`, `tests/test_users.py`
- [ ] Test: create (temp password shown once, forced change on first login), edit, deactivate / activate, reset password, delete; self and last-admin guards; analyst gets 403.
- [ ] Implement routes and page.

### Task 7: Profile page
**Files:** `app/routers/auth.py`, `templates/profile.html`, `templates/base.html`
- [ ] Test: profile update persists and is audited.
- [ ] Implement; user chip links to profile and shows role; sidebar Administration group.

### Task 8: Audit page
**Files:** `app/routers/audit.py`, `templates/audit.html`, `tests/test_audit.py`
- [ ] Test: filters (user, action prefix, dates), pagination, CSV export; analyst 403.
- [ ] Implement.

### Task 9: Docs, cleanup, release
- [ ] Remove the committed vim swap file, ignore `*.swp`. README (roles section), CHANGELOG.
- [ ] Full pytest, rebuild container, browser check (admin, analyst, viewer), merge to master, push.
