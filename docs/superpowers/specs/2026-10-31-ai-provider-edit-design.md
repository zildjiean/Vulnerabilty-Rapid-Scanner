# Editing AI provider settings — design

**Date:** 2026-10-31 · **Status:** approved by the project owner · **Target version:** 1.1.0

## Problem

An edit page for AI providers exists (`/ai/providers/{id}`) but it is only reachable by clicking the provider name, and
it cannot fix the mistakes people actually make when adding a provider:

1. The provider type cannot be changed (OpenAI chosen for an Ollama server → delete and re-create).
2. The fields are hard-wired per type instead of switching with the type, and the hints of the Add form are missing.
3. A stored API key cannot be removed (a blank field keeps it), so moving to a key-less local server is impossible.
4. The last test result survives a configuration change and keeps saying "ok".
5. A validation error resets name, max tokens and redaction to the stored values.

## Design

- **Edit button** (`#i-edit`, label "Edit") in the actions column of the provider table on `/ai`.
- **Shared fields macro** `app/templates/_ai_provider_fields.html` → `provider_fields(form, kinds, default_models,
  gemini_base, key_stored=False)` renders type select, name, model, base URL, API version, API key and the max
  tokens / redaction row with the same kind-dependent hints as today's Add form (`data-show-kind`, toggled by the
  existing `.schedule-form` JS). Used by the Add form and the Edit page. When `key_stored`, the key field shows
  "Key stored · leave blank to keep" and a **Remove stored key** checkbox.
- **Edit page**: the macro, the last test status, and two buttons — **Save & test** (primary, `action=test`) and
  **Save** (`action=save`).
- **`POST /ai/providers/{id}`** (`ai.manage` + CSRF), now `async`:
  - `kind` may change (validated against `PROVIDER_KINDS`).
  - Key: a typed key replaces the stored one; otherwise **Remove stored key** clears it; otherwise it is kept.
  - Validation uses the new kind, config and effective key. On error the page re-renders (400) with every typed value.
  - When kind, model, base URL, API version or the key changed, `last_test_at/ok/message` are reset.
  - Changing the type while keeping a stored key adds to the flash: "The API key from the previous provider type
    was kept; tick Remove stored key if the new provider does not use it."
  - Audit `ai.provider_updated` with `changed=[…field names…]` (never values of the key), `key_changed`.
  - `action=test` runs the same connectivity test as the Test button (shared `_run_test` helper) and redirects back
    to the Edit page with "Test succeeded" / "Test failed"; `action=save` redirects to `/ai`.
  - `ai.refresh_ready(app)` after saving.
- No schema change.

## Tests (`tests/test_ai_admin.py`)

Edit button and kind select rendered; type change keeps the key with the warning, then Remove stored key clears it;
removing the key of a provider that needs one fails validation; config change clears the last test while a name-only
change does not; Save & test calls the provider with the new settings and lands on the Edit page with the result;
validation error keeps typed values; analyst gets 403 on the Edit page and the update route.
