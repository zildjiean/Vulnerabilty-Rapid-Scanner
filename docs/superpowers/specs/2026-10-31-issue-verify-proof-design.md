# Issue verification (Play button) and Proof panel — design

**Date:** 2026-10-31
**Status:** approved by the project owner, pending spec review

## Goal

Give analysts a one-click way to prove that an issue is real. A "Play" button (labelled *Verify now*) re-runs the
nuclei template that raised the issue against that single asset and keeps the HTTP request/response as proof. Issues
that have no template (suspected from a version rule) get a guided path: pick an existing template or let the AI
draft a verification template, review it, then run it. When the AI model declines, the UI explains in English how to
switch to a provider/model that supports authorized security testing.

Nuclei v3.11 already emits `request`, `response`, `curl-command` and `matcher-status` in its JSONL output and
`Finding.raw_json` stores the whole object, so proof data for existing findings is already in the database.

## Out of scope

- Proof excerpts in the PDF/HTML reports.
- Bulk verify of several issues at once.
- AI-generated raw exploit payloads. The AI only drafts nuclei detection templates (existing `template_draft` pipeline).

## 1. Proof panel (`issue_detail.html`)

A new card **Proof** below *Evidence*, built from the newest `Finding` linked to the issue
(`proof_from_finding(finding) -> dict | None` in a new module `app/proof.py`):

| Field | Source in `raw_json` |
|---|---|
| request / response | `request`, `response` (strings; absent for non-HTTP templates) |
| curl command | `curl-command` (copy button) |
| matcher | `matcher-name` when present, plus `matcher-status` |
| extracted values | `extracted-results` |
| when / where | `timestamp`, `matched-at`, job link |

Rendering rules:
- request and response in `<details>` blocks, monospace (`<pre class="proof">`), each truncated to 4,000 characters
  with a "Show full" toggle that reveals the rest (full text is in the page, hidden; no extra request).
- Non-HTTP findings show only the fields that exist; if nothing but `matched-at` exists the card shows
  "nuclei did not record a request/response for this template type".
- Each row of the *Evidence* table gets a `proof` link (`/issues/{id}?proof={finding_id}`) that renders that
  finding's proof instead of the newest one.
- Proof is shown raw (internal tool, no redaction). Viewers see the Proof card; they do not see the Play button.

## 2. Verify now (Play) — main path, no AI

### Data model (`app/db.py`, `_ADDED_COLUMNS`)

`Issue` gains:
- `verify_job_id: int | None`
- `last_verified_at: datetime | None`
- `verify_result: str` — `""` | `reproduced` | `not_reproduced` | `inconclusive`

### Route

`POST /issues/{id}/verify` — `require("scan.run")`, CSRF, optional form field `back` (default `/issues/{id}`).

1. `issue.verify_job_id` set and that job is `queued`/`running` → redirect back with notice "Verification already
   running (job #N)". No new job.
2. `issue.template_id` empty → redirect to `/issues/{id}#verify` (section 3 card).
3. Template path = `TemplateIndex.path` for `issue.template_id`; missing → error "Template X is not in the template
   index. Reindex templates or pick another template." (HTTP 400, rendered on the detail page).
4. Target = `reverify._target(db, issue)` (inventory service → scheme://host:port; falls back to `issue.asset`).
   The target is never taken from the form.
5. `launch_nuclei(... targets=[target], paths=[path], params={"targets": [target], "template_ids": [tid],
   "mode": "selected", "profile": "normal", "verify_issue": issue.id}, rate_limit/timeout from PROFILES["normal"])`.
6. `issue.verify_job_id = job.id`; timeline event kind `verify`, body "Verification scan started: job #N."; audit
   `issue.verify`.

### Completion hook

`on_nuclei_complete` already calls `complete_reverify` when `params.reverify` exists. Add, after findings are
ingested: `if params.get("verify_issue"): complete_verify(db, job, warnings)` (in `app/proof.py`).

`complete_verify(db, job, warnings) -> str`:
- Looks for a `Finding` from this job whose `issue_id == issue.id` (the ingest links it by key).
- Found → `verify_result = "reproduced"`, `confidence = "confirmed"` (via existing confirm path), event
  "Verified: job #N reproduced it (matcher …, status …)". `last_seen` is already bumped by the ingest.
- Not found and `warnings` non-empty → `inconclusive`, event "Verification inconclusive: job #N had incomplete
  coverage (<first warning>)."
- Not found, no warnings → `not_reproduced`, event "Verification: job #N did not reproduce it." Status is left
  unchanged; the analyst decides (fixed / false positive).
- Always: `last_verified_at = now`, `verify_job_id = None`.
- Jobs that end `failed`/`cancelled` never run the hook; `reverify._cleanup_dead_jobs`-style cleanup is added for
  `verify_job_id` (event "Verification job #N failed; try again.") and runs from the same scheduler tick.

### UI

- Issue header: `<button class="btn primary">` with `#i-play` icon and label **Verify now** when `template_id` is
  set and no verify job is live; while live, a `status st-running` chip "verifying (job #N)" linking to the job.
  After completion the header shows a chip from `verify_result`: `reproduced` (green, with time),
  `not reproduced` (neutral), `inconclusive` (amber).
- Issues list and Campaign *Exposed assets* table: last column gets an icon-only Play form button
  (`class="icon-btn"`, `aria-label="Verify now"`, `title="Verify now"`, min 36 px hit area) posting to
  `/issues/{id}/verify` with `back` = current URL. Rows whose verification is running show a small spinner chip
  instead. Only rendered when `can('scan.run')`.
- Flash/toast after redirect: "Verification started for <asset> (job #N)".

## 3. Issues without a template (suspected from a version rule)

Card **Verification template** (`id="verify"`), shown on the detail page only when `issue.template_id` is empty
and the user has `scan.run`:

**A. Use an existing template** — text input + "Search" (GET `/templates/search?q=…`, existing endpoint, fetched
by a small JS helper), results as a radio list (template id, name, severity). "Link template" posts
`POST /issues/{id}/template` (`require("issues.manage")`) with `template_id`; it must exist in the index.
After linking, the page shows the normal Play button.

**B. Draft verification template with AI** — visible when `ai_ready` and the user has `ai.use` and
`templates.manage`. `POST /ai/issues/{id}/template-draft` reuses `ai.generate(... "template_draft", SYSTEM,
template_prompt(cve, advisory, hints), schema=TEMPLATE_SCHEMA)` with:
- `cve` = `issue.cve_id` or `issue.vuln_id`
- `advisory` = issue title, rule name/pattern/constraint, campaign description if linked, and the service's product
  and version from the inventory
- `hints` = `"<asset> running <product> <version>"`

`TEMPLATE_RULES` gains one sentence: *"The template verifies a vulnerability on an asset owned by the team that
runs this scanner; it is a detection check for authorized internal testing, not an exploit."*

The draft is validated (`validate_template_yaml`, then `nuclei -validate` via `nuclei_validate`) and shown as an
editable `<textarea>` with the AI notes and the usual `ai_meta` line. Nothing is saved yet. **Save & run as proof**
posts `POST /issues/{id}/template/save-run` (`require("templates.manage")` + `scan.run`): re-validates the edited
YAML, `save_custom_template` + `index_single`, sets `issue.template_id`, then performs the Verify flow of
section 2 in the same request. Validation errors re-render the card with the YAML preserved.

## 4. AI refusal handling

`app/llm.py`:
- New `class LLMRefusal(LLMError)`.
- Claude: `stop_reason == "refusal"` → `LLMRefusal` (today it is a plain `LLMError`).
- OpenAI / Azure / Gemini (OpenAI-compatible): `finish_reason == "content_filter"` → `LLMRefusal`.
- Soft refusals, every provider: when the request had a JSON schema and the text does not parse as JSON, and the
  text matches `_REFUSAL_RE` (case-insensitive: `I can't|I cannot|I'm unable|I am unable|I won't|not able to
  (help|assist|provide|create)|against (my|our) (guidelines|policies)|can't help with`), raise `LLMRefusal` with the
  first 160 characters of the model's text as the reason. Plain `_parse_json` errors stay `LLMError`.

UI: the Verification template card catches `LLMRefusal` and renders a `.notice.error` box (English, verbatim):

> **The configured AI model declined this request** (<reason>). Writing a verification template for your own
> assets is a legitimate security-testing task, but some models refuse it. Switch the default provider or model
> under **System → AI** to one that supports authorized security testing, then try again.

with a link to `/ai`. Other `LLMError`s keep the existing generic error rendering. The failed call is still recorded
in `AiUsage` (ok=False) and the audit log, as today.

## 5. Permissions, safety, errors

- Play: `scan.run`. Link/save template: `issues.manage` / `templates.manage`. AI draft: `ai.use` +
  `templates.manage`. Viewers see Proof, no buttons.
- The verify target comes only from the issue (inventory lookup); form input never chooses targets.
- Errors (template not indexed, no target, runner refused) render on the detail page with the existing error
  notice pattern; no job is created.
- AI prompts still pass through the redactor; proof text is never sent to the AI by this feature.

## 6. Testing

Unit (`tests/test_proof.py`):
- `proof_from_finding`: HTTP finding with request/response; non-HTTP finding; truncation flag at 4,000 chars.
- `complete_verify`: reproduced / not_reproduced / inconclusive; clears `verify_job_id`, sets `last_verified_at`.
- Dead verify job cleanup.

Unit (`tests/test_llm.py`): refusal detection per provider with mocked clients; soft-refusal regex does not
trigger on valid JSON that merely contains "cannot".

Routes (`tests/test_issue_verify.py`, mirroring the re-verify tests with the fake runner):
- verify starts a job with the right template/target and params; permission denied for viewer; second click while
  running does not start a job; template missing from index → 400.
- Suspected issue without template → detail shows the Verification template card; linking a template enables Play.
- AI draft refusal → page contains the English notice and a link to `/ai`.
- Issues list and campaign page render the Play icon only for users with `scan.run`.

Browser check on a separate demo instance (never the owner's database): Proof card renders for an existing
finding, Play starts a job, the header chip updates after completion, no console errors, light and dark theme.
