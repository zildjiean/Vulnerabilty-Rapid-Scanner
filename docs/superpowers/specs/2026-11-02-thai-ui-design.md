# Thai user interface (v2.0.0)

Round 3 of the usability work (1.9.0 quick scan / presets / Get started; 1.10.0 menus / roles / Next step).
Approved 2026-11-02: per-user language, default English.

## Language selection
- New column `users.language` (`"en"` | `"th"`, default `"en"`, via `_ADDED_COLUMNS`).
- Top bar: a compact **TH / EN** switch (a small POST form, CSRF) next to the theme toggle; Profile page: a
  *Language* select. Both `POST /profile/language` (signed-in users, CSRF, also allowed during a forced password
  change so the change-password page can be read in Thai). Redirects back to the page the user was on (only a
  same-site relative path; otherwise `/`).
- Not signed in (login page, error pages before login): language from the `Accept-Language` header (`th` first →
  Thai), else English. No cookie.
- `<html lang>` follows the language.

## Mechanism (`app/i18n.py`)
- `CATALOG_TH: dict[str, str]` in `app/i18n_th.py`: key = the exact English source string, value = Thai. Strings
  with values use `str.format` placeholders: `"Deleted {n} service(s)."` → `"ลบ {n} service แล้ว"`.
- `translate(lang, text, **params)`: Thai lookup when `lang == "th"`, fallback to the English text; then
  `.format(**params)` if params are given. Never raises on a missing key or placeholder mismatch (falls back to the
  English template formatted, or the raw text).
- Jinja: global `t(text, **params)` bound to the current request's language in `render()` (and in any other place
  that renders templates, e.g. error pages, reports). Jinja autoescape stays on: translations are plain text; the
  few strings that need markup are split so markup stays in the template, never in the catalog.
- Python: `tr(request, text, **params)` for flash messages (`?msg=` / `?err=`), form-validation errors and other
  server-built UI text. Messages are translated when the redirect is built (the user's language is known), so the
  URL carries the final text. `ValueError` messages from validators are translated where they are shown
  (`tr(request, str(e))`), so validator modules keep English keys.
- JavaScript: `base.html` embeds `<script type="application/json" id="i18n">` with the Thai values of the strings
  `app.js` uses (confirm dialogs, "Copied", tooltips, live summaries, relative times…); `app.js` reads it via a tiny
  `t()` helper, falling back to English.
- Labels defined in Python dicts used by templates (STATUS_LABELS, CONFIDENCE_LABELS, ROLE_LABELS, preset and
  profile labels/help, onboarding steps, Next step labels, nav labels, chart titles…) stay English in code and are
  passed through `t()` at display time.

## Scope
Translated: every page template (sidebar, tabs, breadcrumbs, headings, buttons, form labels, help text, table
headers, empty states, confirm dialogs, Get started, Next step, More actions), flash and validation messages, the
in-browser report pages (executive / campaign / scope / issue proof), chart titles/legends/axis labels and their data
tables, page `<title>`s.

Not translated (stay as they are): data from scanners and intel sources (CVE titles/descriptions, finding names,
host names, logs, nuclei output, AI output), REST API responses and API docs page code samples, CSV/JSON exports,
notifications (Slack / Teams / email / webhook / tickets), the audit log, stored values.

Wording rules for Thai (match `docs/USER_GUIDE.th.md`): keep technical terms in English inside Thai sentences
(issue, scan, nuclei, nmap, template, scope, campaign, CVE, job, inventory, preset, severity names, status names
such as *New / Triaged / Resolved* may be translated in labels: ใหม่ / คัดกรองแล้ว / กำลังแก้ / แก้แล้ว / ปิดแล้ว
(Resolved) / False positive / ยอมรับความเสี่ยง); short, direct, polite-neutral tone without ครับ/ค่ะ; numbers and
dates stay in the current format (Gregorian, UTC labels as today).

## Font
Bundle **IBM Plex Sans Thai** (SIL OFL 1.1) woff2 (400/500/600/700, Thai subset) under
`app/static/fonts/` with its OFL licence file; pinned download with SHA-256 recorded in the commit message or a
`fonts/SOURCE.txt`. `@font-face` with `font-display: swap` and `unicode-range` for Thai (U+0E00–0E7F) so Latin text
keeps Inter/system fonts. Added after "Inter" in `--font-sans`. No external font requests.

## Layout
Thai strings are often longer: buttons, tabs, sidebar items, KPI labels and table headers must wrap or truncate
gracefully (no horizontal page overflow at 375 px, no clipped text at 1440 px). Line-height for Thai body text
≥ 1.5 (tone marks).

## Testing
- Unit: `translate` fallback / params / bad placeholders; `Accept-Language` parsing; the switch endpoint (CSRF,
  safe redirect, persists, forced-password-change allowed).
- **Completeness test**: render every page (as admin with representative data, plus login and error pages) in Thai
  and fail if any visible text node equals an English catalog key that has no Thai value — i.e. every string passed
  to `t()` / `tr()` has a Thai entry. Also a static check: every literal `t("...")` / `tr(..., "...")` in templates
  and Python has a catalog entry; no unused catalog entries.
- English rendering unchanged: existing tests keep passing in English (default).
- Full suite green; visual check of key pages in Thai, light/dark, 1440 and 375 px.
