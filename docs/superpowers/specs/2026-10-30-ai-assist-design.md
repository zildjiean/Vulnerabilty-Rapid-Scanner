# AI Assist (multi-provider LLM) — Design

**Date:** 2026-10-30 · **Status:** approved

## Goal

Let admins plug in their own LLM provider and API key, and use it where it speeds up 0-day response, without
letting the model act on its own.

## Providers (Administration → AI, `ai.manage` = admin)

| Kind | Client | Config | Secret |
|---|---|---|---|
| `anthropic` | official `anthropic` SDK (2.x) | model (default `claude-opus-5-5`), optional base URL | API key |
| `openai` | official `openai` SDK | model | API key |
| `azure_openai` | `openai.AzureOpenAI` | endpoint, deployment (model), API version | API key |
| `gemini` | `openai` SDK on Google's OpenAI-compatible endpoint | model, base URL (prefilled) | API key |
| `openai_compatible` | `openai` SDK with a custom base URL (Ollama, vLLM, LM Studio, OpenRouter, Groq, …) | base URL, model | optional API key |

Per provider: max output tokens, redaction on/off (default on), enabled, one default provider, Test button.
Keys are encrypted with the existing SecretBox and never rendered.

Claude specifics (from the Claude API skill): `claude-opus-5-5` default; thinking is left adaptive (omitted);
`output_config.effort` set per feature on models that support it; JSON features use `output_config.format`
(`json_schema`); `stop_reason == "refusal"` is handled; requests to Claude Fable 5.1 / Opus 5.5 / Opus 5 /
Sonnet 5.5 opt into server-side `fallbacks: "default"` (beta `server-side-fallback-2026-07-01`). No `temperature`
/ `top_p` / `top_k` (rejected on API version 2026-10-21, which anthropic 2.x sends).

OpenAI-family: `chat.completions`, JSON features use `response_format={"type": "json_object"}` with the schema
in the prompt and tolerant parsing.

## Privacy

With redaction on, IP addresses and inventory host names / addresses in prompts are replaced by `HOST-n`
tokens before sending and restored in the output. Every call is recorded in `ai_usage` (user, provider, model,
feature, tokens, duration, ok / error) and audited (`ai.generated`).

## Features (`ai.use` = admin, analyst; results readable by everyone)

1. **Campaign draft** (New campaign): advisory text + CVE → name, summary, product regex, version constraint,
   severity, template search terms; validated with the rule validator; fills the form for review.
2. **Template draft** (Templates, campaign page): detection-only nuclei YAML; checked with the YAML validator and
   `nuclei -validate`; saved only when the user presses Save.
3. **Explain & remediate** (issue page): markdown explanation, impact, remediation, verification; stored as a note;
   can be added to the timeline as a comment (`issues.manage`).
4. **Triage** (issue page): verdict likely true positive / likely false positive / uncertain + confidence +
   reasoning + checks; never changes the status.
5. **Ask** (Issues, Inventory): natural-language question → existing filters only (enumerated JSON), redirect.
6. **Executive summary** (Reports): narrative from report figures; stored per period and printed with the report.
7. **Diagnose job** (failed or done-with-warnings jobs): likely cause and next steps from the log tail.

AI output is untrusted text: HTML-escaped, rendered with a tiny markdown subset.

## Data

`ai_providers`, `ai_usage`, `ai_notes` (feature, subject type / id, content, data JSON, provider, model, author).

## Testing

Adapters against fake SDK clients (request shape: effort, schema, fallbacks, refusal, JSON parsing), redaction
round-trip, markdown escaping, provider admin + secrets, every feature route with a fake LLM, permissions, usage
and audit.
