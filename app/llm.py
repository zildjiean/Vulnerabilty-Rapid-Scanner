"""Provider-neutral LLM calls: Anthropic (official SDK) and the OpenAI family (official SDK: OpenAI, Azure OpenAI,
Gemini's OpenAI-compatible endpoint, Ollama / vLLM / OpenRouter / any OpenAI-compatible server)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

import anthropic
import openai

PROVIDER_KINDS = {
    "anthropic": "Anthropic Claude",
    "openai": "OpenAI",
    "azure_openai": "Azure OpenAI",
    "gemini": "Google Gemini",
    "openai_compatible": "OpenAI-compatible (Ollama, vLLM, LM Studio, OpenRouter, Groq …)",
}
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"
DEFAULT_MODELS = {"anthropic": "claude-opus-5-5"}
DEFAULT_AZURE_API_VERSION = "2024-10-21"
TIMEOUT_SECONDS = 180
# Claude models that accept server-side `fallbacks: "default"` (re-run a safety-declined request on another model).
CLAUDE_SERVER_FALLBACK = {"claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}
# Older Claude models that reject `output_config.effort` (it errors on Sonnet 4.5 / Haiku 4.5 and earlier).
_NO_EFFORT = ("claude-3", "claude-sonnet-4-5", "claude-haiku-4-5", "claude-opus-4-1", "claude-opus-4-0",
              "claude-sonnet-4-0", "claude-opus-4-2025", "claude-sonnet-4-2025")


class LLMError(Exception):
    pass


class LLMRefusal(LLMError):
    """The model declined: safety classifier, provider content filter, or a refusal written as prose."""


_REFUSAL_RE = re.compile(
    r"\b(I can(?:')?t|I cannot|I(?:'m| am) unable|I won(?:')?t|not able to (?:help|assist|provide|create)|"
    r"against (?:my|our) (?:guidelines|policies)|can(?:')?t help with)\b", re.I)


@dataclass
class LLMRequest:
    system: str
    prompt: str
    max_tokens: int = 4000
    json_schema: dict | None = None
    effort: str = "medium"   # low | medium | high (Claude); ignored by other providers


@dataclass
class LLMResult:
    text: str
    data: dict | None
    model: str
    input_tokens: int = 0
    output_tokens: int = 0


# Factories are module-level so tests can replace them with fakes.
def make_anthropic(**kwargs):
    return anthropic.Anthropic(**kwargs)


def make_openai(kind: str, **kwargs):
    return openai.AzureOpenAI(**kwargs) if kind == "azure_openai" else openai.OpenAI(**kwargs)


def _parse_json(text: str) -> dict:
    """Parse a JSON object, tolerating code fences or prose around it (non-Claude JSON mode is best effort)."""
    t = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*\})\s*```", t, re.S)
    if fence:
        t = fence.group(1)
    elif not t.startswith("{"):
        start, end = t.find("{"), t.rfind("}")
        t = t[start:end + 1] if start != -1 and end > start else t
    try:
        data = json.loads(t)
    except json.JSONDecodeError as e:
        raise LLMError(f"The model did not return valid JSON ({e.msg}). Try again or use a stronger model.") from e
    if not isinstance(data, dict):
        raise LLMError("The model returned JSON that is not an object.")
    return data


def _parse_or_refusal(text: str, r: LLMRequest) -> dict | None:
    """Structured answers must parse; prose that reads like a refusal is reported as one."""
    if r.json_schema is None:
        return None
    try:
        return _parse_json(text)
    except LLMError:
        if not text.lstrip().startswith("{") and _REFUSAL_RE.search(text[:600]):   # truncated JSON is never a prose refusal
            raise LLMRefusal(f'the model answered: "{text.strip()[:160]}"') from None
        raise


def _claude(config: dict, secret: dict, r: LLMRequest) -> LLMResult:
    if not secret.get("api_key"):
        raise LLMError("No API key configured for this provider.")
    model = config.get("model") or DEFAULT_MODELS["anthropic"]
    client = make_anthropic(api_key=secret["api_key"], base_url=config.get("base_url") or None,
                            timeout=TIMEOUT_SECONDS, max_retries=2)
    kwargs = {"model": model, "max_tokens": r.max_tokens, "system": r.system,
              "messages": [{"role": "user", "content": r.prompt}]}
    output_config: dict = {}
    if r.effort and not model.startswith(_NO_EFFORT):
        output_config["effort"] = r.effort
    if r.json_schema:
        output_config["format"] = {"type": "json_schema", "schema": r.json_schema}
    if output_config:
        kwargs["output_config"] = output_config
    try:
        if model in CLAUDE_SERVER_FALLBACK:
            resp = client.beta.messages.create(betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs)
        else:
            resp = client.messages.create(**kwargs)
    except anthropic.APIStatusError as e:
        raise LLMError(f"Claude API error {e.status_code}: {getattr(e, 'message', e)}") from e
    except anthropic.APIConnectionError as e:
        raise LLMError(f"Cannot reach the Claude API: {e}") from e
    if resp.stop_reason == "refusal":
        category = getattr(resp.stop_details, "category", None) if resp.stop_details else None
        raise LLMRefusal(f"The request was declined by the model's safety classifier ({category or 'unspecified'}).")
    text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text").strip()
    if resp.stop_reason == "max_tokens" and r.json_schema:
        raise LLMError("The answer hit the provider's max output tokens. Raise it in AI settings.")
    usage = getattr(resp, "usage", None)
    return LLMResult(text=text, data=_parse_or_refusal(text, r), model=getattr(resp, "model", model),
                     input_tokens=getattr(usage, "input_tokens", 0) or 0, output_tokens=getattr(usage, "output_tokens", 0) or 0)


def _openai_family(kind: str, config: dict, secret: dict, r: LLMRequest) -> LLMResult:
    model = config.get("model", "")
    key = secret.get("api_key") or ""
    if kind in ("openai", "azure_openai", "gemini") and not key:
        raise LLMError("No API key configured for this provider.")
    if kind == "azure_openai":
        client = make_openai(kind, api_key=key, azure_endpoint=config.get("base_url", ""),
                             api_version=config.get("api_version") or DEFAULT_AZURE_API_VERSION,
                             timeout=TIMEOUT_SECONDS, max_retries=2)
    else:
        base = config.get("base_url") or (GEMINI_BASE_URL if kind == "gemini" else None)
        client = make_openai(kind, api_key=key or "not-needed", base_url=base, timeout=TIMEOUT_SECONDS, max_retries=2)
    system = r.system
    if r.json_schema:
        system += ("\n\nRespond with a single JSON object only, no prose, matching this JSON schema:\n"
                   + json.dumps(r.json_schema))
    kwargs = {"model": model, "messages": [{"role": "system", "content": system}, {"role": "user", "content": r.prompt}]}
    # OpenAI / Azure reasoning-era models take max_completion_tokens; compatible servers expect max_tokens.
    kwargs["max_completion_tokens" if kind in ("openai", "azure_openai") else "max_tokens"] = r.max_tokens
    if r.json_schema:
        kwargs["response_format"] = {"type": "json_object"}
    try:
        resp = client.chat.completions.create(**kwargs)
    except openai.APIStatusError as e:
        raise LLMError(f"{PROVIDER_KINDS[kind]} error {e.status_code}: {getattr(e, 'message', e)}") from e
    except openai.APIConnectionError as e:
        raise LLMError(f"Cannot reach {PROVIDER_KINDS[kind]}: {e}") from e
    choice = resp.choices[0]
    text = (choice.message.content or "").strip()
    if choice.finish_reason == "length" and r.json_schema:
        raise LLMError("The answer hit the provider's max output tokens. Raise it in AI settings.")
    if choice.finish_reason == "content_filter":
        raise LLMRefusal("the provider's content filter blocked the answer")
    usage = getattr(resp, "usage", None)
    return LLMResult(text=text, data=_parse_or_refusal(text, r), model=getattr(resp, "model", model) or model,
                     input_tokens=getattr(usage, "prompt_tokens", 0) or 0, output_tokens=getattr(usage, "completion_tokens", 0) or 0)


def complete(kind: str, config: dict, secret: dict, request: LLMRequest) -> LLMResult:
    if kind == "anthropic":
        return _claude(config, secret, request)
    if kind in PROVIDER_KINDS:
        return _openai_family(kind, config, secret, request)
    raise LLMError(f"Unknown provider type {kind!r}.")


def validate_provider(kind: str, config: dict, secret: dict) -> str | None:
    if kind not in PROVIDER_KINDS:
        return "Unknown provider type."
    if not (config.get("model") or (kind == "anthropic")):
        return "Enter the model id (or the Azure deployment name)."
    if kind in ("anthropic", "openai", "azure_openai", "gemini") and not secret.get("api_key"):
        return "Enter the API key."
    base = config.get("base_url", "")
    if kind == "azure_openai" and not base.startswith("https://"):
        return "Enter the Azure OpenAI endpoint (https://<resource>.openai.azure.com)."
    if kind == "openai_compatible" and not base.startswith(("http://", "https://")):
        return "Enter the base URL of the OpenAI-compatible server, e.g. http://host.docker.internal:11434/v1 for Ollama."
    if base and (" " in base or not base.startswith(("http://", "https://"))):
        return "Base URL must start with http:// or https://."
    return None
