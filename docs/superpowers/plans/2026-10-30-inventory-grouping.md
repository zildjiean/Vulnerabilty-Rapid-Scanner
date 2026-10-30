# Inventory Grouping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Group the Inventory table by host, product or service type with collapsible, selectable group headers.

**Architecture:** A pure module `app/inventory_groups.py` classifies services and builds `Group` objects from the already-filtered `(service, host)` rows. The inventory router passes groups to the template, which renders header rows inside the existing table. Vanilla JS handles collapse, group selection and segment-aware sorting.

**Tech Stack:** FastAPI, SQLAlchemy, Jinja2, vanilla JS/CSS, pytest. Spec: `docs/superpowers/specs/2026-10-30-inventory-grouping-design.md`.

---

### Task 1: Service type classification

**Files:** Create `app/inventory_groups.py`; Test `tests/test_inventory_groups.py`

- [ ] Write failing tests for `service_type` (http → Web, http+ssl → Web, mysql → Database, empty name on port 3306 → Database, ssh → Remote access, smtp → Mail, ftp/microsoft-ds → File sharing, ldap → Directory & auth, domain → Network services, unknown "foo" on port 9999 → Other).
- [ ] Run `pytest tests/test_inventory_groups.py -v` → fails (module missing).
- [ ] Implement `TYPE_ORDER`, `_NAMES`, `_PORTS`, `service_type(svc)`.
- [ ] Run tests → pass. Commit `feat: classify inventory services into categories`.

### Task 2: group_rows

**Files:** Modify `app/inventory_groups.py`; Test `tests/test_inventory_groups.py`

- [ ] Write failing tests: host mode (one group per host, label=address, sublabel=hostname, host_count=1, match_count from matches dict); product mode (alphabetical, empty product → "Unknown product" last, host_count counts distinct hosts); type mode (taxonomy order, only non-empty categories); none → `[]`; invalid mode → treated as host via `normalize_group_mode`.
- [ ] Run → fails. Implement `Group` dataclass, `GROUP_MODES`, `GROUP_LABELS`, `DEFAULT_GROUP`, `normalize_group_mode`, `group_rows`.
- [ ] Run → pass. Commit `feat: build inventory groups by host, product or service type`.

### Task 3: Router + template

**Files:** Modify `app/routers/inventory.py`, `app/templates/inventory.html`; Test `tests/test_inventory_groups.py`

- [ ] Write failing route tests: default page has `class="group-row"` with `192.168.1.10` header and `4 services`; `?group=product` shows `Unknown product`; `?group=type` shows `Remote access` and `Database`; `?group=none` has no `group-row`; `?group=zzz` behaves like host; `?group=type&port=3306` shows only Database.
- [ ] Run → fails. Add `group` param, `groups`, `group_mode`, `group_labels` to both render paths; add select, buttons, header rows, `data-group` attributes in template.
- [ ] Run → pass. Commit `feat: inventory page renders selectable groups`.

### Task 4: JS + CSS behaviour

**Files:** Modify `app/static/app.js`, `app/static/app.css`

- [ ] Add `.group-row`, `.group-toggle`, `.group-meta` styles (light + dark tokens).
- [ ] JS: `[data-group-toggle]` toggles `aria-expanded` and `hidden` on sibling rows; `[data-groups-expand]` / `[data-groups-collapse]`; `[data-group-select]` checks its rows; table-level `change` delegation keeps group boxes checked/indeterminate; sorting sorts per segment when `.group-row` rows exist.
- [ ] Verify in browser (collapse, group select, sort within group, scan-selected still prefills). Commit `feat: collapsible and selectable inventory groups`.

### Task 5: Docs and release

- [ ] README Inventory section + CHANGELOG Unreleased entry. Run full `pytest`. Commit `docs: inventory grouping`.
- [ ] Rebuild container (`docker compose build && docker compose up -d`), verify at http://localhost:8000/inventory, merge to master, push.
