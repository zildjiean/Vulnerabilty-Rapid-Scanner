# "Verified" confidence with proof — design

**Date:** 2026-10-31 · **Status:** approved by the project owner · **Target version:** 1.2.0

## Goal

An issue whose vulnerability was reproduced by **Verify now** is shown as **Verified** with a link to its proof,
everywhere issues are listed. The issue stays open (it is a real, still-unfixed vulnerability).

## Decision

"Verified" becomes a third **confidence** level, not a lifecycle status:

| Confidence | Meaning |
|---|---|
| `suspected` | the installed version matches a version rule; not scanned yet |
| `confirmed` | nuclei matched it in a scan |
| `verified` (new) | *Verify now* reproduced it and the request/response proof is stored |

The lifecycle status `verified` (closed: fix re-scanned and gone) keeps its key but is **displayed as
"Fix verified"** so the word "Verified" has one meaning in the UI. Data, API values and filters keep the key
`verified` for the status.

## Behaviour

- **New column** `Issue.verified_finding_id: int | None` (`_ADDED_COLUMNS`) — the finding that proved it.
- `proof.complete_verify`, result `reproduced` → `confidence = "verified"`, `verified_finding_id = <finding id>`,
  timeline event kind `confirmed` from the previous confidence to `verified`, body "Verified by job #N; proof
  captured." (The existing info-template branch that links the finding still applies first.)
- result `not_reproduced` on a `verified` issue → back to `confirmed`, `verified_finding_id = None`, event
  "Verification job #N did not reproduce it; confidence back to confirmed." `inconclusive` changes nothing.
- `issues.upsert_issue`: a confirmed sighting upgrades only `suspected → confirmed`; it never downgrades `verified`.
- Everywhere "confirmed" means "seen by a scan", `verified` counts too — a helper `iss.SCAN_CONFIRMED =
  ("confirmed", "verified")` used by: auto re-verification on Fixed (`_set_status`), issue KPIs
  (`routers/issues.issue_kpis`), campaign progress (`campaigns.progress`), and the suspected-only rule logic stays
  `== "suspected"`. KPI sub-labels gain the verified count ("9 confirmed · 2 verified · 4 suspected").
- Startup backfill: issues with `verify_result == "reproduced"` and confidence `confirmed` become `verified`, with
  `verified_finding_id` = newest finding of their last verify job if found, else newest finding.
- Labels: `CONFIDENCE_LABELS["verified"] = "Verified"`; `STATUS_LABELS["verified"] = "Fix verified"`.
  The AI search schema enum and its prompt accept `verified`; `api_docs.html` and `settings.html` wording follow.

## UI

- `confidence_badge(c, issue=None)`: `verified` renders a green badge with a check icon, title
  "Reproduced by Verify now; proof captured", and when `issue` is given it is a link to
  `/issues/{id}?proof={verified_finding_id}#proof` (fallback `#proof`). Used in the Issues list, campaign exposure
  table, issue header and campaign report.
- Issues list Confidence filter gets the `Verified` option (it loops over the labels).
- Issue page timeline renders the `confirmed` event as "Confidence: Confirmed → Verified — …" when `to_value` is
  `verified`.
- CSS `.badge.conf-verified` (success colours) in light and dark.

## Tests

complete_verify sets/clears verified and the finding id; a later nuclei sighting does not downgrade verified;
reverify on Fixed still triggers for verified issues; KPIs and campaign progress count verified; filter
`confidence=verified`; badge links to the proof finding; "Fix verified" label shown for the closed status;
backfill on startup; API/CSV export carry `verified`.
