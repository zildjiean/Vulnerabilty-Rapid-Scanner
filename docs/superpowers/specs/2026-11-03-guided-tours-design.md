# Guided tours (spotlight walkthroughs, TH/EN) — design

Version target: **2.1.0**. Branch: `feature/guided-tours`.

## Goal

A new system admin or security admin can learn where to click without reading the manual. A **Guide** button in
the top bar starts a short step-by-step tour that dims the page, highlights one menu item or control, and explains it
in the user's language (English or Thai, following `users.language`). Tours may span several pages. A tour only
points; it never clicks, submits or changes data for the user.

## Non-goals

- No third-party tour library; no new JS dependency.
- No per-page help panel (may come later).
- Tours never perform actions (no auto-click, no form submit, no auto-fill).
- No tour authoring UI; tours are defined in code.

## Units

### 1. `app/tours.py` — registry (pure, testable)

```python
@dataclass(frozen=True)
class Step:
    path: str            # page the step lives on, e.g. "/quick"; "@follow" = the page the previous step's target links to
    target: str          # value of data-tour="..." on that page; "" = centred popover with no highlight
    title: str           # English source text (translated with t())
    body: str
    perm: str = "view"   # step hidden when the user lacks it

@dataclass(frozen=True)
class Tour:
    key: str
    title: str
    summary: str
    perm: str            # tour hidden without it
    steps: tuple[Step, ...]
```

Functions:
- `TOURS: tuple[Tour, ...]` — the four tours below.
- `available(user) -> list[Tour]` — tours the user may take, each with only the steps the user is allowed to see,
  respecting the same visibility rules as the sidebar (`navigation.nav_items`): a step whose target is a sidebar item
  (`nav-<item key>`) is dropped when that item is not in the user's sidebar. Tours left with no steps are dropped.
- `payload(user, done: set[str]) -> list[dict]` — JSON-ready, already translated with `t()` (current request
  language): `{key, title, summary, done, steps:[{path, target, title, body}]}`.
- `get(key) -> Tour | None`.

Tours (English source; Thai added to `app/i18n_th.py`):

| key | perm | steps (target on path) |
|---|---|---|
| `menus` "Get to know the menus" | `view` | centred welcome; `nav-dashboard` `/`; `nav-issues`; `nav-campaigns`; `nav-inventory`; `nav-reports`; `nav-group-scan` (the Scanning group header); `nav-group-system`; `lang-switch`; `user-chip`; `guide-button` ("reopen tours here") — all on `/` |
| `first-scan` "Run your first scan" | `scan.run` | `nav-quick` on `/`; `quick-targets`, `quick-level`, `quick-start` on `/quick`; `page-tabs` on `/quick` (Nmap / Nuclei / Discovery for advanced use); `nav-jobs` + `jobs-table` on `/jobs`; `nav-issues` on `/` ending "results land in Issues" |
| `triage` "Handle an issue" | `issues.manage` | `issues-filters`, `issues-table` on `/issues`; `issue-link` on `/issues` (first row link); `@follow`: `next-step`, `issue-status`, `issue-verify` (perm `scan.run`), `issue-proof` |
| `admin` "Set up for your team" | `view` (steps carry their own perms) | `nav-scopes` (`scopes.manage`); `nav-schedules` (`scopes.manage`); `nav-users` (`users.manage`); `nav-settings` (`settings.manage`); `nav-integrations` (`integrations.manage`); `nav-updates` (`system.update`); `nav-audit` (`audit.view`) — all on `/` |

Copy rule: title ≤ 6 words, body ≤ 2 short sentences, names UI labels exactly as rendered (so the Thai matches the
Thai labels in `i18n_th.py`).

### 2. `data-tour` targets in templates

- `base.html`: sidebar item macro adds `data-tour="nav-{{ i.key }}"`; group header button
  `data-tour="nav-group-{{ g.key }}"`; `lang-switch` on the language switch wrapper (`_lang_switch.html`);
  `user-chip`; `guide-button` on the new Guide button; `_tabs.html` adds `data-tour="page-tabs"`.
- `quick.html`: `quick-targets` (targets field wrapper), `quick-level` (level fieldset), `quick-start`.
- `jobs.html` / `_jobs_table.html`: `jobs-table`.
- `issues.html`: `issues-filters`, `issues-table`, `issue-link` on the first issue's title link only.
- `issue_detail.html`: `next-step` (Next step card), `issue-status` (`#change-status`), `issue-verify` (`#verify`),
  `issue-proof` (`#proof`).

Attributes only; no visual change.

### 3. Engine — `app/static/app.js` (+ `app.css`)

- Reads `<script type="application/json" id="tours">` (rendered by `base.html` for signed-in users; `|tojson`).
- **Guide button** (`?` icon + "Guide", label hidden ≤520px) in the top bar before the language switch opens a small
  menu (`<details>`-style popover, keyboard reachable) listing available tours with summary and a ✓ when done.
- Running a tour: state `{key, step}` in `sessionStorage` (`zdrs-tour`, wrapped in try/catch) **and** in the URL
  (`?tour=<key>&step=<n>`) when navigating, so a reload continues. On load, if `tour`/`step` query params name a
  known tour, the engine resumes and removes the params with `history.replaceState`.
- Step display: scroll target into view, spotlight = a fixed element sized to the target's rect with a large
  `box-shadow` scrim (pointer-events none on scrim except a click-catcher that does nothing), popover positioned
  below/above/right of the target (flip to fit), ≤520px a bottom sheet. Recompute on resize/scroll.
- Before showing a `nav-*` target: if inside a closed nav group, open the group; if the sidebar is collapsed, show
  the step anyway (icon is visible); on mobile (hamburger visible) open the drawer.
- Step on another page: Next navigates to `path?tour=..&step=..`. `@follow`: navigate to the previous step
  target's `href`. If a target is not on the page (no data, no permission), skip forward silently; if no later step
  is reachable, end the tour with a centred "Nothing more to show here yet" note.
- Controls: **Back**, **Next** (last step: **Done**), **Skip tour**, counter "2 / 6". Keyboard: `Esc` = skip,
  `←`/`→` = back/next. The popover is `role="dialog"` `aria-modal="false"` `aria-labelledby` its title; focus
  moves to it on each step; an `aria-live="polite"` region announces "Step 2 of 6: <title>". Focus returns to the
  Guide button when the tour ends. `prefers-reduced-motion`: no transitions.
- On Done: `POST /tours/<key>/done` (fetch with CSRF token from the page, ignore failures). Skip does not mark done.
- Light/dark via existing tokens; Thai font already loaded.
- No action is ever triggered by the engine. While a tour is open the page underneath does not react to clicks (a
  transparent click-catcher covers it, including the highlighted element), so a user cannot half-submit a form
  mid-tour. Closing the tour restores the page.

### 4. Persistence & routes — `app/routers/tours.py`

- New column `users.tours_done` TEXT NOT NULL DEFAULT `''` — comma-separated tour keys (added to `_ADDED_COLUMNS`);
  new column `users.tour_prompt_dismissed_at` DATETIME NULL.
- `POST /tours/{key}/done` — CSRF; unknown key → 404; adds key; returns 204. Not audited (UI preference).
- `POST /tours/prompt/dismiss` — CSRF; sets `tour_prompt_dismissed_at`; redirects back with `safe_back` (or 204
  for fetch).
- `POST /profile/tours/reset` — CSRF; clears both; flash "Tours reset"; redirect `/profile`.
- Viewer role may use all three (own profile only).

### 5. First-login prompt

On the Dashboard, when `tour_prompt_dismissed_at` is null and `tours_done` is empty, show a small card above the Get
started card: "New here? Take a 1-minute tour" with **Start tour** (starts `menus`) and **No thanks** (POST dismiss).
Starting a tour also dismisses the prompt (engine POSTs dismiss in the background). Without JS the Start button is
not rendered; No thanks still works.

### 6. Profile

A "Guided tours" section listing tours with done/not-done, a **Start** link for each (`/?tour=<key>&step=0`, or the
first step's path) and **Reset tours**.

### 7. i18n

All titles, bodies, summaries, buttons and messages go through `t()`/`tr()`; Thai entries added to `i18n_th.py`;
JS-only strings (Back, Next, Done, Skip tour, "Step {n} of {total}", "Nothing more to show here yet") added to the JS
catalog. The tour JSON is rendered in the request language, so TH/EN switching changes the tour text.

## Error handling

- Corrupt `sessionStorage`/query → ignore and do nothing.
- Target removed between render and display → skip.
- Fetch failures on done/dismiss → ignored (the tour still closes).
- A user without permission for a page in a tour never receives that tour/step; pages still enforce their own
  permissions.

## Testing

- `tests/test_tours.py`:
  - `available()` per role (admin, analyst/operator, viewer): expected tour keys and step counts; viewer gets only
    `menus` (and no `nav-*` steps for hidden items); `show_all_menus` keeps nav steps consistent with the sidebar.
  - **Every target exists**: for each tour/step as admin with seeded data (one issue), GET the step's page (for
    `@follow`, the href of the previous target) and assert `data-tour="<target>"` is in the HTML.
  - Every tour string has a Thai translation (`i18n_th`), and `payload` in `th` returns Thai text.
  - Routes: CSRF required; unknown key 404; done is idempotent; dismiss and reset work; viewer allowed.
  - Dashboard prompt shown/hidden rules; profile section renders.
- Full suite stays green (`.venv/bin/python -m pytest -q -p no:cacheprovider`).
- Visual check on the test instance (127.0.0.1:8001): each tour in TH and EN, light and dark, desktop and 390px,
  no horizontal overflow, keyboard-only run-through.

## Release

2.1.0: CHANGELOG, README feature line + screenshot, Thai guide section "ทัวร์แนะนำการใช้งาน", version bump, merge,
tag, push, live DB backup, rebuild, GitHub Release.
