# Merged menus, role-based sidebar and Issue "Next step" (v1.10.0)

Round 2 of the usability work (round 1 = 1.9.0 quick scan / presets / Get started; round 3 = Thai UI → 2.0.0).
Approved 2026-11-02.

## 1. Merged menus (tabs)

Every page and URL stays; no route is removed or redirected. Related pages share a **page tab bar** under the page
header and one sidebar item.

| Sidebar item (href) | Tabs (href) | `active` keys that highlight it |
|---|---|---|
| Dashboard (/) | – | dashboard |
| Issues (/issues) | Issues (/issues), Raw findings (/findings) | issues, findings |
| Campaigns (/campaigns) | Campaigns (/campaigns), 0-day watch (/watch) | campaigns, watch |
| Inventory (/inventory) | Inventory (/inventory), Changes (/changes), Discovered (/discovery#assets) | inventory, changes |
| Reports (/reports) | – | reports |
| **Scanning** group: New scan (/quick) | Quick (/quick), Nmap (/nmap), Nuclei (/nuclei), Discovery (/discovery) | quick, nmap, nuclei, discovery |
| Scanning: Jobs (/jobs) | – | jobs |
| **Automation** group: Scopes (/scopes), Schedules (/schedules) | – | scopes, schedules |
| **Detection library** group: Templates & rules (/templates) | Templates (/templates), Version rules (/rules) | templates, rules |
| **System** group (collapsed, unchanged) | – | as today |

- Discovery belongs to *New scan* (it starts jobs). The *Discovered* tab under Inventory is a link to the Discovered
  assets table on the Discovery page (`/discovery#assets`, add `id="assets"`). On the Discovery page the sidebar
  highlights *New scan* and its tab bar shows *Discovery* as current.
- Tab bar: one Jinja macro `page_tabs(tabs, current)` in `_tabs.html`; markup `<nav class="page-tabs"
  aria-label="<section> pages">` with links, the current one `aria-current="page"`. Plain links, no ARIA tablist,
  no JS. Scrolls horizontally inside itself at narrow widths (no page overflow at 375 px).
- Detail pages (issue, campaign, job, scope, rule edit…) keep highlighting their parent item as today.
- Breadcrumb section names follow the new grouping (e.g. Nuclei: "Scanning", not "Detection").
- The sidebar groups' open/closed memory keeps working; group keys: `scan`, `automation`, `library`, `system`.

## 2. Role-based sidebar

- Item visibility (default "focused" menu):
  - **viewer**: Dashboard, Issues, Campaigns, Inventory, Reports only (no Scanning / Automation / Detection
    library / System groups).
  - **analyst**: everything except System items they lack the permission for (System items already use `can()`;
    *Updates* is shown only with `system.update`, *API* with `view` as today).
  - **admin**: everything.
  - Items that need a permission to *act* are hidden when the user lacks it: *New scan* needs `scan.run`.
- Tabs follow the same rule (a viewer on /issues sees the *Raw findings* tab — reading is allowed — but no tab whose
  only purpose is starting work, i.e. the *New scan* tabs are not shown to users without `scan.run`).
- Pages remain reachable by URL for anyone with `view` (no permission change).
- **Profile → "Show all menu items"** checkbox (`users.show_all_menus`, Boolean default False, via `_ADDED_COLUMNS`;
  `POST /profile/menus`, CSRF) shows every item the user may *open* (all items for `view`).
- Implemented with one helper `nav_items(user)` (Python, `app/navigation.py`) returning the sidebar structure
  (groups → items with href, key, icon, label, active keys, tabs); `base.html` renders it, pages render their tab
  bar from the same structure, so menu and tabs cannot drift apart. Unit-tested per role.

## 3. Issue page "Next step"

A **Next step** card at the top of the issue page (only with `issues.manage`; others see the existing read-only
note). One primary button and up to two secondary buttons, each a one-click POST to the existing endpoints:

| Status | Primary | Secondary |
|---|---|---|
| new | **Triage** → status `triaged` | **Assign to me** (if not the assignee); **False positive…** |
| triaged | **Start work** → `in_progress` | **Assign to me** (if not the assignee) |
| in_progress | **Mark fixed** → `fixed` | |
| fixed | **Verify now** (when the issue has a template, `scan.run`, no verify running) else note "Waiting for re-verification" | |
| verified / false_positive / accepted_risk | **Reopen** → `triaged` | |

- Buttons only offer transitions allowed by `TRANSITIONS`; the server still validates every change.
- *False positive…* needs a reason: it is a link to the status form (`#change-status`) with False positive
  pre-selected and focus in the comment field; it does not post by itself.
- **Assign to me** posts to `/issues/{id}/assign` with the current user's id.
- Everything else (Change status form, Assignee, Severity, tickets, AI, Link template / verification template) moves
  into `<details id="more-actions">` **More actions**, closed by default, open when the URL fragment targets an
  element inside it or after a validation error. Comments and the timeline stay visible.
- Each action keeps its audit entry and flash message as today.

## 4. Label rename

- Lifecycle status `verified` is displayed as **Resolved** (was "Fix verified") everywhere: `STATUS_LABELS`, the
  campaign report KPI, filters, exports' human-readable columns, notifications text, docs. Stored value, API values
  and CSV machine columns stay `verified`.

## Testing
- Every existing page still returns 200 and highlights the right sidebar item and tab.
- `nav_items` per role (viewer / analyst / admin) and with `show_all_menus`; the profile toggle (CSRF, persists).
- Next step: the right buttons for each status and permission; each button posts the right transition; False
  positive link; Assign to me; read-only users see no buttons.
- "Resolved" label shown; API still returns `verified`.
- Full suite green; light/dark, 1440 and 375 px, no horizontal overflow.
