import json

import pytest
from sqlalchemy import select

from app import llm
from app.db import AiProvider, AiUsage, AuditLog
from tests.conftest import get_csrf
from tests.test_rbac import login_as, make_user


class FakeLLM:
    """Stands in for app.state.llm: records requests, returns scripted text / JSON, or raises."""

    def __init__(self, text="OK", data=None, error=None):
        self.text, self.data, self.error, self.calls = text, data, error, []

    def __call__(self, kind, config, secret, request):
        self.calls.append({"kind": kind, "config": config, "secret": secret, "request": request})
        if self.error:
            raise llm.LLMError(self.error)
        return llm.LLMResult(text=self.text if self.data is None else json.dumps(self.data), data=self.data,
                             model=config.get("model") or "claude-opus-5-5", input_tokens=100, output_tokens=20)


@pytest.fixture
def fake_llm(auth):
    f = FakeLLM()
    auth.app.state.llm = f
    return f


def add_provider(client, **form):
    csrf = get_csrf(client, "/ai")
    data = {"csrf": csrf, "name": "Claude", "kind": "anthropic", "model": "claude-opus-5-5", "base_url": "",
            "api_version": "", "api_key": "sk-ant-secretvalue", "max_tokens": "8000", "redact": "true"}
    data.update(form)
    return client.post("/ai/providers", data=data, follow_redirects=False)


def providers(client):
    with client.app.state.SessionLocal() as db:
        rows = list(db.scalars(select(AiProvider).order_by(AiProvider.id)))
        db.expunge_all()
        return rows


def test_provider_crud_secret_and_default(auth, fake_llm):
    assert add_provider(auth).status_code == 303
    p = providers(auth)[0]
    assert p.is_default and p.redact and "secretvalue" not in p.secret
    assert auth.app.state.secretbox.decrypt(p.secret) == {"api_key": "sk-ant-secretvalue"}
    assert "secretvalue" not in auth.get("/ai").text and "secretvalue" not in auth.get(f"/ai/providers/{p.id}").text
    assert auth.app.state.ai_ready is True
    assert add_provider(auth, name="Local", kind="openai_compatible", model="llama3.1",
                        base_url="http://host.docker.internal:11434/v1", api_key="", redact="").status_code == 303
    local = providers(auth)[1]
    assert not local.is_default and not local.redact
    csrf = get_csrf(auth, "/ai")
    auth.post(f"/ai/providers/{local.id}/default", data={"csrf": csrf})
    assert [x.is_default for x in providers(auth)] == [False, True]
    # blank key keeps the stored one
    auth.post(f"/ai/providers/{p.id}", data={"csrf": csrf, "name": "Claude prod", "model": "claude-sonnet-5-5", "base_url": "",
                                             "api_version": "", "api_key": "", "max_tokens": "4000", "redact": "true"})
    p = providers(auth)[0]
    assert p.name == "Claude prod" and json.loads(p.config)["model"] == "claude-sonnet-5-5" and p.max_tokens == 4000
    assert auth.app.state.secretbox.decrypt(p.secret) == {"api_key": "sk-ant-secretvalue"}
    auth.post(f"/ai/providers/{local.id}/delete", data={"csrf": csrf})
    remaining = providers(auth)
    assert len(remaining) == 1 and remaining[0].is_default   # default moves to the remaining provider
    actions = {a.action for a in auth.app.state.SessionLocal().scalars(select(AuditLog))}
    assert {"ai.provider_created", "ai.provider_updated", "ai.provider_deleted"} <= actions


def test_provider_validation(auth, fake_llm):
    assert add_provider(auth, api_key="").status_code == 400
    assert add_provider(auth, kind="azure_openai", model="dep", base_url="").status_code == 400
    assert add_provider(auth, kind="openai_compatible", model="m", base_url="ftp://x", api_key="").status_code == 400
    assert add_provider(auth, max_tokens="10").status_code == 400
    assert add_provider(auth, kind="nope").status_code == 400


def test_provider_test_records_usage(auth, fake_llm):
    add_provider(auth)
    p = providers(auth)[0]
    r = auth.post(f"/ai/providers/{p.id}/test", data={"csrf": get_csrf(auth, "/ai")}, follow_redirects=False)
    assert r.status_code == 303
    assert providers(auth)[0].last_test_ok is True
    call = fake_llm.calls[0]
    assert call["kind"] == "anthropic" and call["secret"] == {"api_key": "sk-ant-secretvalue"} and call["request"].effort == "low"
    fake_llm.error = "Claude API error 401: invalid x-api-key"
    auth.post(f"/ai/providers/{p.id}/test", data={"csrf": get_csrf(auth, "/ai")})
    p = providers(auth)[0]
    assert p.last_test_ok is False and "invalid x-api-key" in p.last_test_message
    with auth.app.state.SessionLocal() as db:
        usage = list(db.scalars(select(AiUsage).order_by(AiUsage.id)))
        assert [(u.feature, u.ok) for u in usage] == [("test", True), ("test", False)]
        assert usage[0].input_tokens == 100 and usage[0].username == "admin"
    page = auth.get("/ai").text
    assert "invalid x-api-key" in page and "test" in page


def test_permissions(auth, fake_llm):
    add_provider(auth)
    make_user(auth, "ana", "analyst")
    login_as(auth, "ana")
    assert auth.get("/ai").status_code == 403
    assert add_provider(auth).status_code == 403
