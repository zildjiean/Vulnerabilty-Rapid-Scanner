# Inventory Grouping — Design

**Date:** 2026-10-30
**Status:** approved by user (brainstorm, option "selectable Group by: Host / Product / Service type")

## Goal

Make the Inventory page easier to read when it holds many services by grouping the rows,
with a user-selectable grouping dimension, collapsible groups and group-level selection.

## Scope

- New `Group by` control in the Inventory filter bar with four modes: `host` (default),
  `product`, `type` (service category), `none` (today's flat table).
- The mode travels as query parameter `group`; invalid values fall back to `host`.
  Filters (search, product, port, only matches) keep working and apply before grouping.
- Server renders one table. Each group is a header row followed by its service rows.
- Group header shows: label, sub-label, `N service(s)`, `N host(s)` (not in host mode),
  count of 0-day rule matches as a badge, a chevron toggle (collapse / expand), and a
  checkbox that selects / deselects every service in the group (indeterminate when partial).
- Toolbar gains `Expand all` / `Collapse all` buttons (hidden in `none` mode).
- Column sorting sorts rows **within** each group; group order never changes.
- Existing actions (Scan selected with nuclei, Delete selected, Clear) are unchanged and keep
  working with group selection because group checkboxes carry no `name`.

Out of scope: persisting collapse state, nested grouping, per-group bulk actions beyond select.

## Service type taxonomy

`service_type(service)` returns one of, in display order:
`Web`, `Database`, `Remote access`, `Mail`, `File sharing`, `Directory & auth`,
`Network services`, `Other`.

Classification uses the nmap service name first (lower-cased, `ssl/` prefix stripped; `tunnel=ssl`
with an HTTP name is still Web), then a well-known port fallback when the name is empty or
unknown. Name/port lists live in one module so a new category is a one-line change.

## Components

| Unit | Responsibility |
|---|---|
| `app/inventory_groups.py` (new) | `GROUP_MODES`, `GROUP_LABELS`, `DEFAULT_GROUP`, `service_type()`, `group_rows(rows, mode, matches) -> list[Group]` (pure, no DB) |
| `app/routers/inventory.py` | parse `group`, call `group_rows`, pass `groups`, `group_mode`, `group_labels` to template |
| `app/templates/inventory.html` | Group by select, expand/collapse buttons, group header rows, `data-group` on service rows |
| `app/static/app.js` | group toggle, expand/collapse all, group checkbox sync, segment-aware column sort |
| `app/static/app.css` | `.group-row`, `.group-toggle` styles |

`Group` is a dataclass: `key`, `label`, `sublabel`, `rows` (list of `(service, host)`),
`host_count`, `match_count`.

Group ordering: host → by address (as the query already orders); product → alphabetical,
empty product last as "Unknown product"; type → fixed taxonomy order; none → no groups.

## Error handling

Unknown `group` value → silently treated as `host`. No new failure modes; grouping is pure
Python over already-loaded rows.

## Testing

- Unit: `service_type` classification (name, ssl tunnel, port fallback, unknown → Other).
- Unit: `group_rows` for each mode (ordering, counts, match counts, "Unknown product" last).
- Route: `/inventory` default renders host groups with counts; `?group=product|type|none`
  render the expected headers / no headers; invalid value falls back to host; filters still
  narrow the grouped result.
