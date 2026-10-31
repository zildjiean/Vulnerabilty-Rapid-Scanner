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
            raise self.error if isinstance(self.error, Exception) else llm.LLMError(self.error)
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
    pid = providers(auth)[0].id
    assert auth.get(f"/ai/providers/{pid}").status_code == 403
    csrf = get_csrf(auth, "/")
    assert auth.post(f"/ai/providers/{pid}", data={"csrf": csrf, "name": "x", "kind": "anthropic"}).status_code == 403


def edit(client, p, follow_redirects=False, **form):
    """POST the edit form of ``p`` with its current values, overridden by ``form``."""
    config = json.loads(p.config)
    data = {"csrf": get_csrf(client, f"/ai/providers/{p.id}"), "name": p.name, "kind": p.kind,
            "model": config.get("model", ""), "base_url": config.get("base_url", ""),
            "api_version": config.get("api_version", ""), "api_key": "", "max_tokens": str(p.max_tokens),
            "redact": "true" if p.redact else ""}
    data.update(form)
    return client.post(f"/ai/providers/{p.id}", data=data, follow_redirects=follow_redirects)


def test_edit_button_and_kind_select(auth, fake_llm):
    add_provider(auth, kind="openai", model="gpt-5", api_key="sk-old")
    p = providers(auth)[0]
    page = auth.get("/ai").text
    assert f'href="/ai/providers/{p.id}"' in page and "Edit" in page and "#i-edit" in page
    edit_page = auth.get(f"/ai/providers/{p.id}").text
    assert 'name="kind"' in edit_page and '<option value="openai" selected>' in edit_page
    assert "data-show-kind" in edit_page and "schedule-form" in edit_page
    assert "Remove stored key" in edit_page and "sk-old" not in edit_page
    assert 'value="test"' in edit_page and "Save &amp; test" in edit_page


def test_edit_type_change_keeps_then_removes_key(auth, fake_llm):
    add_provider(auth, kind="openai", model="gpt-5", api_key="sk-old")
    p = providers(auth)[0]
    r = edit(auth, p, kind="openai_compatible", model="llama3.1", base_url="http://host.docker.internal:11434/v1")
    assert r.status_code == 303 and "previous+provider+type" in r.headers["location"]
    p = providers(auth)[0]
    assert p.kind == "openai_compatible" and json.loads(p.config)["base_url"] == "http://host.docker.internal:11434/v1"
    assert auth.app.state.secretbox.decrypt(p.secret) == {"api_key": "sk-old"}
    r = edit(auth, p, remove_key="true")
    assert r.status_code == 303 and "previous" not in r.headers["location"]
    p = providers(auth)[0]
    assert "api_key" not in auth.app.state.secretbox.decrypt(p.secret)
    with auth.app.state.SessionLocal() as db:
        rows = list(db.scalars(select(AuditLog).where(AuditLog.action == "ai.provider_updated").order_by(AuditLog.id)))
    first, second = json.loads(rows[0].details), json.loads(rows[1].details)
    assert "kind" in first["changed"] and first["key_changed"] is False
    assert second["changed"] == ["api_key"] and second["key_changed"] is True
    assert all("sk-old" not in r.details for r in rows)


def test_edit_remove_required_key_fails(auth, fake_llm):
    add_provider(auth)
    p = providers(auth)[0]
    r = edit(auth, p, remove_key="true")
    assert r.status_code == 400 and "Enter the API key." in r.text
    assert auth.app.state.secretbox.decrypt(providers(auth)[0].secret) == {"api_key": "sk-ant-secretvalue"}


def test_edit_resets_last_test_on_config_change(auth, fake_llm):
    add_provider(auth)
    p = providers(auth)[0]
    auth.post(f"/ai/providers/{p.id}/test", data={"csrf": get_csrf(auth, "/ai")})
    p = providers(auth)[0]
    assert p.last_test_ok is True
    edit(auth, p, name="Renamed", max_tokens="4000", redact="")
    p = providers(auth)[0]
    assert p.name == "Renamed" and p.last_test_ok is True and p.last_test_at is not None
    edit(auth, p, model="claude-sonnet-5-5")
    p = providers(auth)[0]
    assert p.last_test_at is None and p.last_test_ok is None and p.last_test_message == ""


def test_edit_save_and_test(auth, fake_llm):
    add_provider(auth)
    p = providers(auth)[0]
    r = edit(auth, p, model="claude-sonnet-5-5", action="test")
    assert r.status_code == 303 and r.headers["location"].startswith(f"/ai/providers/{p.id}?msg=Test+succeeded")
    assert fake_llm.calls[-1]["config"]["model"] == "claude-sonnet-5-5"
    p = providers(auth)[0]
    assert p.last_test_ok is True
    page = auth.get(r.headers["location"]).text
    assert "st-done" in page and "Model claude-sonnet-5-5 answered" in page


def test_edit_validation_keeps_typed_values(auth, fake_llm):
    add_provider(auth)
    p = providers(auth)[0]
    r = edit(auth, p, kind="azure_openai", model="dep", base_url="", name="Typed name", max_tokens="3000", redact="")
    assert r.status_code == 400
    assert 'value="Typed name"' in r.text and 'value="3000"' in r.text
    assert '<option value="azure_openai" selected>' in r.text
    p = providers(auth)[0]
    assert p.name == "Claude" and p.kind == "anthropic"


def test_edit_to_openai_drops_hidden_base_url(auth, fake_llm):
    add_provider(auth, kind="openai_compatible", model="m", base_url="https://openrouter.ai/api/v1", api_key="sk-or")
    p = providers(auth)[0]
    r = edit(auth, p, kind="openai", model="gpt-5", base_url="https://openrouter.ai/api/v1", api_key="sk-openai")
    assert r.status_code == 303
    p = providers(auth)[0]
    assert p.kind == "openai" and json.loads(p.config)["base_url"] == ""
    assert auth.app.state.secretbox.decrypt(p.secret) == {"api_key": "sk-openai"}


def test_edit_save_and_test_keeps_key_warning(auth, fake_llm):
    add_provider(auth, kind="openai", model="gpt-5", api_key="sk-old")
    p = providers(auth)[0]
    r = edit(auth, p, kind="openai_compatible", model="llama3.1", base_url="http://host.docker.internal:11434/v1",
             action="test")
    assert r.status_code == 303 and r.headers["location"].startswith(f"/ai/providers/{p.id}?msg=Test+succeeded")
    assert "previous+provider+type" in r.headers["location"]


def test_edit_typed_key_wins_over_remove(auth, fake_llm):
    add_provider(auth)
    p = providers(auth)[0]
    assert edit(auth, p, api_key="sk-ant-newvalue", remove_key="true").status_code == 303
    assert auth.app.state.secretbox.decrypt(providers(auth)[0].secret) == {"api_key": "sk-ant-newvalue"}


def test_edit_error_keeps_remove_ticked(auth, fake_llm):
    add_provider(auth)
    p = providers(auth)[0]
    r = edit(auth, p, remove_key="true")
    assert r.status_code == 400
    assert 'name="remove_key" value="true" checked' in r.text
    assert 'name="remove_key" value="true" checked' not in auth.get(f"/ai/providers/{p.id}").text
