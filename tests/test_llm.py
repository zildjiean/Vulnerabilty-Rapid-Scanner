import json
from types import SimpleNamespace as NS

import anthropic
import openai
import pytest

from app import llm

SCHEMA = {"type": "object", "properties": {"verdict": {"type": "string"}}, "required": ["verdict"], "additionalProperties": False}


class FakeAnthropic:
    """Records calls to messages.create / beta.messages.create and returns a scripted response."""

    def __init__(self, response=None, error=None, **init):
        self.init, self.calls, self.response, self.error = init, [], response, error
        outer = self

        class _Messages:
            def create(self, **kw):
                outer.calls.append(("messages", kw))
                if outer.error:
                    raise outer.error
                return outer.response

        class _Beta:
            messages = None

        self.messages = _Messages()
        self.beta = _Beta()
        self.beta.messages = _BetaMessages(self)


class _BetaMessages:
    def __init__(self, outer):
        self.outer = outer

    def create(self, **kw):
        self.outer.calls.append(("beta", kw))
        if self.outer.error:
            raise self.outer.error
        return self.outer.response


def claude_response(text, stop="end_turn", category=None, model="claude-opus-5-5"):
    return NS(content=[NS(type="thinking", thinking=""), NS(type="text", text=text)], stop_reason=stop,
              stop_details=NS(category=category, explanation="x") if stop == "refusal" else None,
              usage=NS(input_tokens=120, output_tokens=45), model=model)


@pytest.fixture
def fake_anthropic(monkeypatch):
    holder = {}

    def factory(response=None, error=None):
        def make(**init):
            holder["client"] = FakeAnthropic(response=response, error=error, **init)
            return holder["client"]
        monkeypatch.setattr(llm, "make_anthropic", make)
        return holder
    return factory


def req(schema=None, effort="medium"):
    return llm.LLMRequest(system="You are a security analyst.", prompt="Assess this.", max_tokens=2000,
                          json_schema=schema, effort=effort)


def test_claude_opus_uses_fallbacks_effort_and_structured_output(fake_anthropic):
    h = fake_anthropic(claude_response('{"verdict": "likely_true_positive"}'))
    r = llm.complete("anthropic", {"model": "claude-opus-5-5"}, {"api_key": "sk-ant-x"}, req(SCHEMA, "low"))
    kind, kw = h["client"].calls[0]
    assert kind == "beta" and kw["betas"] == ["server-side-fallback-2026-07-01"] and kw["fallbacks"] == "default"
    assert kw["output_config"] == {"effort": "low", "format": {"type": "json_schema", "schema": SCHEMA}}
    assert kw["system"] == "You are a security analyst." and kw["messages"] == [{"role": "user", "content": "Assess this."}]
    assert not {"temperature", "top_p", "top_k", "thinking"} & set(kw)
    assert h["client"].init["api_key"] == "sk-ant-x"
    assert r.data == {"verdict": "likely_true_positive"} and (r.input_tokens, r.output_tokens) == (120, 45)


def test_claude_haiku_has_no_server_fallback_and_old_models_no_effort(fake_anthropic):
    h = fake_anthropic(claude_response("ok", model="claude-haiku-5-5"))
    llm.complete("anthropic", {"model": "claude-haiku-5-5"}, {"api_key": "k"}, req())
    kind, kw = h["client"].calls[0]
    assert kind == "messages" and "fallbacks" not in kw and kw["output_config"] == {"effort": "medium"}
    h = fake_anthropic(claude_response("ok", model="claude-sonnet-4-5"))
    llm.complete("anthropic", {"model": "claude-sonnet-4-5"}, {"api_key": "k"}, req())
    assert "output_config" not in h["client"].calls[0][1]


def test_claude_refusal_truncation_and_errors(fake_anthropic):
    fake_anthropic(claude_response("", stop="refusal", category="cyber"))
    with pytest.raises(llm.LLMError, match="declined.*cyber"):
        llm.complete("anthropic", {"model": "claude-opus-5-5"}, {"api_key": "k"}, req())
    fake_anthropic(claude_response('{"verd', stop="max_tokens"))
    with pytest.raises(llm.LLMError, match="max output tokens"):
        llm.complete("anthropic", {"model": "claude-opus-5-5"}, {"api_key": "k"}, req(SCHEMA))
    err = anthropic.AuthenticationError("invalid x-api-key", response=NS(status_code=401, headers={}, request=None), body=None)
    fake_anthropic(error=err)
    with pytest.raises(llm.LLMError, match="invalid x-api-key"):
        llm.complete("anthropic", {"model": "claude-opus-5-5"}, {"api_key": "k"}, req())
    with pytest.raises(llm.LLMError, match="API key"):
        llm.complete("anthropic", {"model": "claude-opus-5-5"}, {}, req())


class FakeOpenAI:
    def __init__(self, content, finish="stop", **init):
        self.init, self.calls = init, []
        outer = self

        class _Completions:
            def create(self, **kw):
                outer.calls.append(kw)
                return NS(choices=[NS(message=NS(content=content), finish_reason=finish)],
                          usage=NS(prompt_tokens=80, completion_tokens=20), model=kw["model"])

        self.chat = NS(completions=_Completions())


@pytest.fixture
def fake_openai(monkeypatch):
    holder = {}

    def factory(content, finish="stop"):
        def make(kind, **init):
            holder["kind"] = kind
            holder["client"] = FakeOpenAI(content, finish, **init)
            return holder["client"]
        monkeypatch.setattr(llm, "make_openai", make)
        return holder
    return factory


def test_openai_json_mode_and_params(fake_openai):
    h = fake_openai('```json\n{"verdict": "uncertain"}\n```')
    r = llm.complete("openai", {"model": "some-openai-model"}, {"api_key": "sk-x"}, req(SCHEMA))
    kw = h["client"].calls[0]
    assert kw["response_format"] == {"type": "json_object"} and kw["max_completion_tokens"] == 2000
    assert "max_tokens" not in kw and "temperature" not in kw
    assert kw["messages"][0]["role"] == "system" and '"verdict"' in kw["messages"][0]["content"]
    assert r.data == {"verdict": "uncertain"} and r.input_tokens == 80


def test_openai_compatible_gemini_and_azure(fake_openai):
    h = fake_openai("plain answer")
    r = llm.complete("openai_compatible", {"model": "llama3.1", "base_url": "http://host.docker.internal:11434/v1"}, {}, req())
    assert h["client"].init["base_url"] == "http://host.docker.internal:11434/v1" and h["client"].init["api_key"]
    assert h["client"].calls[0]["max_tokens"] == 2000 and r.text == "plain answer" and r.data is None
    h = fake_openai("x")
    llm.complete("gemini", {"model": "gemini-model"}, {"api_key": "g"}, req())
    assert h["client"].init["base_url"] == llm.GEMINI_BASE_URL
    h = fake_openai("x")
    llm.complete("azure_openai", {"model": "my-deployment", "base_url": "https://corp.openai.azure.com", "api_version": "2024-10-21"},
                 {"api_key": "a"}, req())
    assert h["kind"] == "azure_openai" and h["client"].init["azure_endpoint"] == "https://corp.openai.azure.com"
    assert h["client"].init["api_version"] == "2024-10-21" and h["client"].calls[0]["model"] == "my-deployment"


def test_openai_bad_json_and_truncation(fake_openai):
    fake_openai("not json at all")
    with pytest.raises(llm.LLMError, match="valid JSON"):
        llm.complete("openai", {"model": "m"}, {"api_key": "k"}, req(SCHEMA))
    fake_openai('{"verdict": "x"', finish="length")
    with pytest.raises(llm.LLMError, match="max output tokens"):
        llm.complete("openai", {"model": "m"}, {"api_key": "k"}, req(SCHEMA))


def test_validate_provider():
    assert llm.validate_provider("anthropic", {"model": "claude-opus-5-5"}, {"api_key": "k"}) is None
    assert "API key" in llm.validate_provider("openai", {"model": "m"}, {})
    assert "endpoint" in llm.validate_provider("azure_openai", {"model": "d"}, {"api_key": "k"}).lower()
    assert llm.validate_provider("openai_compatible", {"model": "llama", "base_url": "http://ollama:11434/v1"}, {}) is None
    assert "model" in llm.validate_provider("openai", {"model": ""}, {"api_key": "k"}).lower()
    assert llm.validate_provider("bogus", {}, {})


def test_refusals_are_typed_for_every_provider(fake_anthropic, fake_openai):
    fake_anthropic(claude_response("", stop="refusal", category="cyber"))
    with pytest.raises(llm.LLMRefusal, match="safety classifier"):
        llm.complete("anthropic", {"model": "claude-opus-5-5"}, {"api_key": "k"}, req())
    fake_openai("", finish="content_filter")
    with pytest.raises(llm.LLMRefusal, match="content filter"):
        llm.complete("openai", {"model": "gpt-5"}, {"api_key": "k"}, req())
    # a refusal written as prose where JSON was required
    fake_openai("I'm sorry, but I can't help with creating exploit templates.")
    with pytest.raises(llm.LLMRefusal, match="can't help"):
        llm.complete("openai_compatible", {"model": "llama3", "base_url": "http://ollama:11434/v1"}, {}, req(SCHEMA))
    fake_anthropic(claude_response("I cannot assist with that request."))
    with pytest.raises(llm.LLMRefusal):
        llm.complete("anthropic", {"model": "claude-opus-5-5"}, {"api_key": "k"}, req(SCHEMA))
    # plain bad JSON stays a generic error, and valid JSON containing "cannot" is not a refusal
    fake_openai("not json at all")
    with pytest.raises(llm.LLMError) as ei:
        llm.complete("openai", {"model": "gpt-5"}, {"api_key": "k"}, req(SCHEMA))
    assert not isinstance(ei.value, llm.LLMRefusal)
    fake_openai('{"yaml": "I cannot ...')                       # truncated JSON that mentions a refusal phrase
    with pytest.raises(llm.LLMError) as ei:
        llm.complete("openai", {"model": "gpt-5"}, {"api_key": "k"}, req(SCHEMA))
    assert not isinstance(ei.value, llm.LLMRefusal)
    fake_openai('{"verdict": "The server cannot be reached; I cannot confirm."}')
    assert llm.complete("openai", {"model": "gpt-5"}, {"api_key": "k"}, req(SCHEMA)).data["verdict"].startswith("The server")
    assert issubclass(llm.LLMRefusal, llm.LLMError)
