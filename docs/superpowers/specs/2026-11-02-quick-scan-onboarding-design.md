# Quick scan, nuclei presets and Get started checklist (v1.9.0)

Round 1 of the usability work (round 2 = merged menus, role-based menus, issue primary actions → 1.10.0;
round 3 = Thai UI, per-user language, default English → 2.0.0). Approved 2026-11-02.

Goal: a system admin who does not know nmap / nuclei can scan a target and see what to fix, and a new install tells
the user what to do first.

## 1. Quick scan

**Page** `GET /quick` (any signed-in user can view; starting needs `scan.run`), sidebar *Scanning → Quick scan*
(first item of the group), plus a **Quick scan** button in the Dashboard header next to New nmap / New nuclei scan.

Form:
- `targets` textarea, parsed with `parse_nmap_targets` (same rules and limits as the nmap page). `GET /quick?targets=`
  pre-fills it.
- `level` radio cards: **Standard** (default) = nmap `port_mode=top`, T3, SYN, then nuclei preset `recommended`;
  **Thorough** = nmap `port_mode=all`, T3, SYN, then nuclei preset `full`.
- A live summary under the form: "nmap N target(s) (1,000 ports | all 65,535 ports) → nuclei (<preset label>) on the
  services found". Start button `id="quick-start"`; nothing runs until it is pressed. No subdomain discovery.

`POST /quick/scan` (`scan.run`, CSRF): validates, calls `launch_quick(db, settings, runner, targets, level)` and
redirects to `/jobs/<nmap job id>`. Audit action `scan.quick` (target, job_id, level). Validation errors re-render
the page with status 400 and the typed values.

**Chaining** (`app/quick.py`):
- `LEVELS = {"standard": {...nmap options, "preset": "recommended"}, "thorough": {...}}`.
- `launch_quick` starts nmap through `launch_nmap(..., extra_params={"quick": {"level": level, "step": 1}})` with an
  `on_complete` hook that wraps `on_nmap_complete`. `launch_nmap` gains an optional `on_complete` argument (default
  `on_nmap_complete`).
- The hook runs `on_nmap_complete` first (inventory ingest, rules, surface changes as today), then:
  - if `runner.cancel_requested(job.id)`: no nuclei step; log line `[quick] cancelled: nuclei step not started.`
  - targets = `quick_targets(db, nmap_targets)`: every inventory service whose host matches the nmap targets
    (`scopes.Matcher`), converted with `service_to_target`, de-duplicated, ordered by address and port (same logic
    as `scheduler.scope_services`, factored into one shared helper used by both).
  - no targets: log `[quick] no open services found: nuclei step skipped.` and set
    `params.quick.nuclei = "skipped"`; the job also gets a warning so it shows as *Done with warnings*.
  - otherwise start nuclei with the level's preset through the shared preset launcher, nuclei params
    `{"quick": {"level", "step": 2, "parent_job": <nmap id>}, "preset": ...}`; nmap params get
    `quick.nuclei_job = <id>`; log `[quick] nuclei step started: job #<id> on <n> service(s).`
  - if the nuclei start raises (e.g. no templates yet): log `[quick] nuclei step could not start: <reason>` and
    add it to the nmap job's warnings; never fails the nmap ingest.
- The hook runs in the runner's worker thread, like the discovery → probe chain; `runner.start` from that thread
  is supported.

**Job page / lists**: a job with `params.quick` shows a "Quick scan · step 1 of 2" (or 2 of 2) badge and a link to
the other step (`/jobs/<id>`); `job_summary` reads "Quick scan step 1/2: nmap …" / "Quick scan step 2/2: nuclei on N
service(s) from job #X".

**API**: `POST /api/v1/scans/quick` `{"targets": [...], "level": "standard"|"thorough"}` (`scan.run`), returns
`202 {"job_id": <nmap id>}`; same validation and audit.

## 2. Nuclei presets

`app/nuclei_presets.py`:

| key | label | templates | severities | tags | profile |
|---|---|---|---|---|---|
| `recommended` (default) | Recommended | all (official + custom) | critical, high, medium | – | normal |
| `critical_cves` | Critical CVEs only | all | critical, high | `cve` | normal |
| `full` | Full | all | all (no filter) | – | normal |
| `custom` | Custom | the advanced form as today | | | |

`preset_launch(db, settings, runner, targets, key, params, **launch_kwargs)` resolves paths via
`all_template_paths`, applies the preset, and calls `launch_nuclei`. Unknown key → `ValueError("Invalid preset.")`.
Recorded in job params as `preset`.

**Nuclei page**: preset radio cards at the top (`name="preset"`, default `recommended`, each with a one-line help).
All current fields (mode, templates, groups, tags, severities, profile, rate, timeout, no-mhe) move into
`<details id="nuclei-advanced">` *Advanced options*. Choosing **Custom** opens it (JS) and it is rendered open when
`preset == "custom"` or the form comes back with an error. With a non-custom preset the server ignores the advanced
fields. Existing behaviour is unchanged for `preset=custom`; a POST without `preset` (old clients, tests) is treated
as `custom`.

**Nmap page**: timing, scan type and skip-ping move into `<details>` *Advanced options* (closed by default, open on
error or non-default values). Targets and port mode stay visible.

**Schedules (nuclei)**: the form gains the same preset choice; config key `preset`. A schedule without `preset`
(all existing ones) runs exactly as today (= custom).

## 3. Get started checklist

`app/onboarding.py` → `checklist(db, user) -> list[Step]` (`key, title, help, href, done, allowed`):

| key | done when | link | permission to act |
|---|---|---|---|
| templates | template index not empty | /updates | system.update |
| scan | any nmap job with status done / done with warnings | /quick | scan.run |
| triage | any issue whose status is not `new` | /issues | issues.manage |
| schedule | at least one schedule | /schedules | scopes.manage |
| notify | at least one notification channel | /integrations | integrations.manage |

Steps the user may not act on are shown as done-by-others or hidden: hidden. The Dashboard shows a **Get started**
card above the KPIs when the user can act on at least one step, at least one of those is not done, and
`users.onboarding_dismissed_at` is null. Card: progress "2 of 5 done", ordered list, each step with a check icon or
a button to its page. **Dismiss** = `POST /onboarding/dismiss` (CSRF) sets `onboarding_dismissed_at`; the Profile
page has **Show Get started again** (`POST /onboarding/reset`). New column via `_ADDED_COLUMNS`.

## Non-goals
Subdomain discovery in Quick scan; new scan engines; changing nmap/nuclei defaults outside the presets.

## Testing
- quick: chain starts nuclei with the right targets and preset; cancel → no nuclei; no services → skipped + warning;
  nuclei start error → warning, nmap job still done; matcher excludes hosts outside the targets; permission and
  CSRF; API endpoint; job summary/badge.
- presets: each preset's resolved args; invalid key; nuclei page default preset ignores advanced fields; custom keeps
  today's behaviour; POST without preset; schedule with / without preset.
- onboarding: each step's done rule; hidden steps by permission; card hidden when done / dismissed; dismiss and
  reset endpoints (CSRF).
- Full suite green; UI checked in light and dark at 1440 and 375 px.
