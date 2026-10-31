# Attack-surface change detection — design (v1.6.0)

Approved 2026-10-31. Round 4 of the post-1.2 roadmap.

## Goal
Every nmap scan is compared with the inventory as it stood before the scan. The team sees what
changed (new host, newly opened port, closed port, product/version change, host no longer
responding), can acknowledge it, and can be notified once per scan.

## 1. What a change is
A `SurfaceChange` row is written during `ingest_nmap_results`, before the inventory is mutated:

| kind              | when                                                                 | severity |
|-------------------|----------------------------------------------------------------------|----------|
| `host_new`        | the address was not in `hosts` before this scan. ONE row per host; `after` lists its open ports (`"22/tcp ssh OpenSSH 9.6p1; 443/tcp …"`, max 2000 chars). No `port_opened` rows for that host. | medium |
| `port_opened`     | known host, (port, protocol) not in its services before                | medium |
| `port_closed`     | known host, service existed, port was in this scan's scanned set, and is not open now | low |
| `service_changed` | known host, same port, `product` or `version` differ (compared trimmed; both empty→no change). `before`/`after` = `"product version"` | low |
| `host_gone`       | host exists in inventory, was not reported up, and matches this job's targets (`scopes.Matcher.parse(targets).matches(address, hostname)`), excluding the job's `exclude` list. The host and its services are NOT deleted (current behaviour kept). | low |

Columns: `id, job_id, host_id (nullable, FK hosts ondelete SET NULL), address, hostname, port (nullable),
protocol, kind, before (str 2000), after (str 2000), severity, scope_id (nullable, resolved with
scopes.scope_for_asset / compile_scopes once per ingest), created_at, acknowledged_at, acknowledged_by`.
Index on `created_at` and `job_id`. New table via `create_all` (no `_ADDED_COLUMNS`).

Deleting a host from Inventory keeps its change rows (host_id becomes NULL; address is kept).

## 2. Scanned-port set (bug fix)
Today `ingest_nmap_results` deletes every service of a seen host that this scan did not report,
so a custom scan of `-p 443` silently removes port 22 from inventory.

- `parse_nmap_xml` additionally exposes the scanned ports from `<scaninfo protocol=".." services="1,3-4,…">`
  (all `scaninfo` elements, per protocol). New function `parse_nmap_scaninfo(xml_text) -> dict[str, set[int]]`
  (keeps `parse_nmap_xml`'s return type unchanged). Ranges expand; total capped by 65535 per protocol.
- A previously known service is removed (and may become `port_closed`) only if its port is in the
  scanned set for its protocol. Services outside the set are kept untouched.
- If the XML has no `scaninfo` at all, fall back to the old behaviour (every unreported service of a
  seen host counts as scanned). Real nmap always writes scaninfo; test fixtures may not.

## 3. Notification
New event `surface.changed` ("Attack surface changed") in `notifications.EVENTS`.
After ingest, if the job produced ≥1 change, `notify(db, "surface.changed", message=…, severity=…)`
once per job. Severity = highest of its changes (medium if any host_new/port_opened, else low).
Message title `[SURFACE] nmap job #N: 2 new hosts, 3 opened, 1 closed, 1 changed, 0 gone`
(zero parts omitted), text lists up to 10 changes (`+ 192.0.2.5:8080/tcp http nginx 1.25`),
url `/changes?job=N`, fields with counts, data `{"job_id": N, "counts": {...}}`.
**Baseline:** if the `hosts` table was empty before the ingest (first scan, or the first scan after
Inventory → Clear / deleting every host), the changes are recorded but not notified; the log line says
`(baseline, not notified)`.
A failure in notification must not fail the ingest (wrap like other callers).
`on_nmap_complete` log line gains `, N surface change(s)`; `result` params gain `"changes": N`.

## 4. UI
- Core sidebar item **Changes** (`/changes`, key `changes`, icon `activity` or an existing icon) right
  after Inventory. Requires `view`.
- `/changes` page: table newest first, 50 per page (`page` param): time, kind badge
  (New host / Port opened / Port closed / Version changed / Not responding), asset (address +
  hostname, link to `/inventory?q=<address>` as inventory supports), port/protocol, before → after,
  scope, job link, Acknowledge state. Filters: `kind`, `scope` (id), `days` (1/7/30/90/all, default 30),
  `job`, `state` (open = unacknowledged [default] / all). Empty state text.
- Acknowledge: POST `/changes/{id}/ack` and POST `/changes/ack-all` (acks everything matching the
  current filters; filters re-sent as hidden fields). Permission `issues.manage`. CSRF. Audit
  `surface.ack` with count. Redirect back to `/changes` with the same filters and `?msg=`.
- Job detail (nmap jobs): card "Changes from this scan" with counts and up to 20 rows + link
  `/changes?job=N&state=all`.
- Dashboard: card "Surface changes (7 days)" with counts per kind of unacknowledged changes in the
  last 7 days and link to `/changes?days=7`.
- Kind labels in one dict `surface.KIND_LABELS`; badges reuse existing badge classes
  (medium → warning-ish, low → neutral). Follow existing table/card markup in inventory.html / watch.html.

## 5. API
`GET /api/v1/changes?days=30&kind=&job=&state=open|all&limit=100` (VIEW, limit ≤ 500) →
`{"items":[{id, job_id, kind, severity, address, hostname, port, protocol, before, after, scope_id,
created_at, acknowledged_at, acknowledged_by}], "count": n}`. Timestamps via `_ts`.

## 6. Module layout
New `app/surface.py`: `KIND_LABELS`, `diff_and_record(db, job, parsed_hosts, scanned, targets, exclude) -> list[SurfaceChange]`
(called from ingest before mutation), `summarize(changes) -> dict counts`, `notify_changes(db, job, changes)`,
`query(db, kind, scope_id, days, job_id, state)` used by page, ack-all and API.
New router `app/routers/changes.py`. Model `SurfaceChange` in `app/db.py`.

## 7. Tests
- scaninfo parsing (ranges, multiple protocols, absent).
- custom-port scan keeps ports outside the scanned set (regression for the bug).
- each kind recorded; host_new produces exactly one row; no changes on identical rescan.
- host_gone only for hosts inside targets and not excluded.
- notification: one delivery per job with right severity; none when no changes.
- page filters, ack, ack-all with filters, permissions (viewer cannot ack), CSRF; job card; dashboard card; API.

## Out of scope
Trend charts (round 5), external discovery (round 6), diffing nuclei results.
