# Trend charts — design (v1.7.0)

Approved 2026-10-31. Round 5 of the post-1.2 roadmap.

## Goal
A **Trends** card on the Dashboard shows how exposure and remediation move over time, computed from
data already in the database (works immediately, no snapshot collection). The Executive report uses the
same charts in place of its weekly trend table.

## 1. Data (`app/trends.py`, pure functions + one loader)
`trends(db, days, scope_id=None, now=None) -> dict`

- `days` ∈ {30, 90, 180, 365} (anything else → 90). `days == 30` → daily buckets (30); otherwise weekly
  buckets (`ceil(days/7)`), each 7 days. Buckets are contiguous and end at `now` (UTC); the last bucket ends at
  `now`. Each point has `start`, `end` (datetimes) and a short `label` (`"Oct 31"`).
- Issues are loaded once (only the columns needed: severity, status, first_seen, resolved_at, due_at,
  scope_id), filtered by `scope_id` when given. Reuse the open/resolved/remediated definitions that
  `app/reports.py::executive` already uses (read it and `app/issues.py`; do not invent new ones — extract
  shared helpers if that keeps it DRY).
- Per bucket:
  - `open`: dict critical/high/medium/low (info and unknown counted in `low`? — NO: keep only the four;
    count info/unknown under `other`, not charted but in the table) = issues with `first_seen <= end` and
    (`resolved_at is None or resolved_at > end`) and not in a status that never counted as exposure per the
    reports definition. Known limitation: a reopened issue counts by its current state.
  - `new`: first_seen in [start, end). `resolved`: resolved_at in [start, end).
  - `mttr_days`: mean days (resolved_at − first_seen) of remediated issues resolved in the bucket, 1 decimal;
    `None` when there are none.
  - `sla_pct`: of issues with a due date resolved in the bucket, % resolved on/before due (int); `None` if none.
  - `surface_added` (host_new + port_opened) and `surface_other` (port_closed + service_changed + host_gone):
    counts of `SurfaceChange.created_at` in the bucket (scope filter applies via its scope_id).
- Return `{"days", "bucket": "day"|"week", "scope_id", "points": [...], "peaks": {...}}`.
- Performance: one query per table, O(issues × buckets) in Python is fine.

## 2. Chart geometry (`app/charts.py`, pure, unit-tested)
Server-side SVG, no JS chart library (the container must work offline). Python computes coordinates; Jinja
renders. viewBox 640×220, plot margins left 40 / right 12 / top 12 / bottom 28. Y axis starts at 0 with
"nice" ticks (1-2-5 steps, ≤ 5 ticks). X labels: at most ~6 evenly spaced labels.
- `stacked_bars(points, keys)` → per bucket the segments (x, y, w, h, key, value) — stack order bottom→top
  low, medium, high, critical; a 2 px surface-colour gap between segments and between bars; 4 px rounded top
  on the topmost segment only (use a path or clipPath; simplest acceptable: rx on the top segment).
- `grouped_bars(points, keys)` → two bars per bucket (new, resolved) with a 2 px gap.
- `line(points, key)` → polyline path segments (break at `None`), markers ≥ 8 px diameter at each non-null
  point, 2 px stroke. Y max for `sla_pct` fixed at 100.
- Every bucket gets one invisible full-height hit rect (`<rect class="chart-hit" tabindex="0"
  aria-label="Oct 24–Oct 31: 12 critical, …" data-tip="…">`) — wider than the mark.

## 3. Colours (validated with the dataviz validator)
CSS tokens in `app/static/app.css` for light, the dark `@media` block and `[data-theme=dark]` block:
- Severity (sequential single-hue red, ordinal; identity also carried by legend + table):
  light `--chart-critical:#7a1414; --chart-high:#b3261e; --chart-medium:#e0674f; --chart-low:#f2a68f`;
  dark `#ffa494, #f0705c, #c8432f, #8f3424` (critical brightest on dark).
- Two-series (new vs resolved, surface added vs other): light `--chart-1:#2a78d6; --chart-2:#eb6834`,
  dark `#3987e5, #d95926` (passes CVD/normal-vision/contrast checks).
- Single series lines (MTTR, SLA) use `--chart-1`.
- Grid lines `var(--border)`, axis text `var(--text-3)` 11px, values/labels never in series colour.
- SVG fills via classes (`.c-critical{fill:var(--chart-critical)}` …), so theme switching just works.
- `forced-colors` / print: segments keep a 1px `CanvasText` stroke in forced-colors.

## 4. UI
- Dashboard: card **Trends** after the KPI rows. Controls in one row in the card head: Period select
  (30 days / 90 days / 6 months / 12 months; default 90) and Scope select (All scopes + each scope) in a GET
  form (`trend_days`, `trend_scope` query params so other dashboard params are unaffected), auto-submit on
  change via existing app.js patterns plus a no-JS submit button (visually hidden is fine if keyboard
  reachable).
- Grid: 2 columns ≥ 1000 px, 1 column below. Charts: 1) **Open exposure** (stacked by severity, legend
  with 4 swatches + labels, direct total label on the last bar only), 2) **New vs resolved** (legend),
  3) **Mean time to remediate (days)**, 4) **SLA compliance (%)**, 5) **Surface changes** (Added vs Other,
  legend). Each chart: `<figure>` with `<figcaption>` title + one-line subtitle, `<svg role="img"
  aria-labelledby>` with `<title>`/`<desc>` summary (e.g. "Open issues went from 40 to 31"), and a
  `<details><summary>Show data</summary><table>…</table></details>` table.
- Empty state per chart when all values are 0/None ("No data in this period").
- Tooltip: one small JS addition in `app/static/app.js`: on hover/focus of `.chart-hit`, show a positioned
  tooltip div (`role="tooltip"`, text from `data-tip`, textContent only — never innerHTML) and highlight
  the bucket (class on the hit rect, e.g. a faint `var(--surface-3)` fill behind the marks). Hide on
  mouseleave/blur/Escape. Respect `prefers-reduced-motion` (no transitions).
- Executive report (`/reports/executive`): replace the weekly trend table with charts 1–4 for the report's
  `days` (map to nearest allowed value), plus their data tables; on print the tables print (details open
  via `@media print { details { display:block } details > *{display:block} }` or render tables directly
  in print). Remove the old `trend`/`trend_peak` only if nothing else uses them (AI summary context may —
  check `app/routers/ai_features.py`; keep whatever it needs).
- Jinja autoescape stays on; no `|safe` on data.

## 5. API
`GET /api/v1/trends?days=90&scope=<id>` (VIEW) → the dict from §1 with datetimes via `_ts`.

## 6. Tests (`tests/test_trends.py`, `tests/test_charts.py`)
- Bucketing (30 → 30 daily, 90 → 13 weekly, invalid → 90), last bucket ends at now.
- open/new/resolved/mttr/sla per bucket with hand-built issues (incl. issue resolved exactly at a boundary,
  reopened issue with resolved_at None, scope filter, info severity → other).
- surface counts per bucket.
- Geometry: nice ticks, stacked segment heights sum to bar height, line breaks at None, SLA y max 100,
  hit rects count = buckets.
- Dashboard renders the Trends card with params, invalid params fall back, viewer can see it; executive
  report renders charts; API shape; no `|safe` (escape test with a scope name containing `<script>`).

## Out of scope
Daily snapshot table, per-assignee charts, external discovery (round 6).
