import io
from pathlib import Path

import pytest

from app.templates_index import (fetch_template_from_url, read_template_info, reindex, save_custom_template, search_templates, validate_template_yaml)
from tests.conftest import get_csrf

FIXTURES = Path(__file__).parent / "fixtures" / "templates"

CUSTOM_YAML = """id: zero-day-example
info:
  name: Example 0-day check
  author: me
  severity: high
  tags: zero-day,php
  classification:
    cve-id:
      - CVE-2026-999999
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "example"
"""


def test_read_template_info():
    info = read_template_info(FIXTURES / "http/cves/2026/CVE-2026-109619.yaml", "official")
    assert info.template_id == "CVE-2026-109619"
    assert info.name == "PHP use-after-free vulnerability check"
    assert info.severity == "critical"
    assert info.tags == "cve,cve2026,php,uaf"
    assert info.cve_ids == "CVE-2026-109619"
    assert info.source == "official"


def test_read_template_info_rejects_non_template(tmp_path):
    p = tmp_path / "x.yaml"
    p.write_text("just: data\n")
    assert read_template_info(p, "custom") is None
    p.write_text(": : bad yaml [")
    assert read_template_info(p, "custom") is None


def test_reindex_and_search(settings):
    from app.db import init_db, make_engine, make_session_factory
    engine = make_engine(settings.db_url)
    init_db(engine)
    SessionLocal = make_session_factory(engine)
    save_custom_template(settings, CUSTOM_YAML)
    with SessionLocal() as db:
        counts = reindex(db, settings)
        assert counts == {"official": 2, "custom": 1}
        assert [t.template_id for t in search_templates(db, "CVE-2026-109619")] == ["CVE-2026-109619"]
        php = search_templates(db, "php")
        assert sorted(t.template_id for t in php) == ["CVE-2026-109619", "php-detect", "zero-day-example"]
        assert [t.template_id for t in search_templates(db, "php", severity="info")] == ["php-detect"]
        assert [t.template_id for t in search_templates(db, "php", source="custom")] == ["zero-day-example"]
        assert [t.template_id for t in search_templates(db, "use-after-free php")] == ["CVE-2026-109619"]
        assert [t.template_id for t in search_templates(db, "CVE-2026-999999")] == ["zero-day-example"]
        assert search_templates(db, "nothing-matches") == []
        assert [t.severity for t in php] == ["critical", "high", "info"]


def test_validate_template_yaml():
    info = validate_template_yaml(CUSTOM_YAML)
    assert info.template_id == "zero-day-example"
    with pytest.raises(ValueError):
        validate_template_yaml("info:\n  name: no id\n")
    with pytest.raises(ValueError):
        validate_template_yaml("id: ../evil\ninfo:\n  name: x\n")
    with pytest.raises(ValueError):
        validate_template_yaml("id: ok\ninfo: {}\n")
    with pytest.raises(ValueError):
        validate_template_yaml("- a list")


def test_save_custom_template_writes_by_id(settings):
    path = save_custom_template(settings, CUSTOM_YAML)
    assert path == settings.custom_templates_dir / "zero-day-example.yaml"
    assert path.read_text() == CUSTOM_YAML


def test_fetch_template_from_url_uses_fetch_callable_and_limits():
    calls = []

    def fake_fetch(url):
        calls.append(url)
        return 200, CUSTOM_YAML

    assert fetch_template_from_url("https://example.com/t.yaml", fetch=fake_fetch) == CUSTOM_YAML
    with pytest.raises(ValueError):
        fetch_template_from_url("ftp://example.com/t.yaml", fetch=fake_fetch)
    with pytest.raises(ValueError):
        fetch_template_from_url("https://example.com/404.yaml", fetch=lambda u: (404, ""))
    with pytest.raises(ValueError):
        fetch_template_from_url("https://example.com/big.yaml", fetch=lambda u: (200, "x" * (10 * 1024 * 1024 + 1)))


def test_templates_page_search_upload_delete(auth):
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
    r = auth.get("/templates")
    assert r.status_code == 200 and "Upload" in r.text
    r = auth.get("/templates/search?q=php")
    assert r.status_code == 200
    ids = [t["template_id"] for t in r.json()]
    assert "php-detect" in ids and "CVE-2026-109619" in ids
    assert set(r.json()[0]) >= {"template_id", "name", "severity", "tags", "source", "path"}

    csrf = get_csrf(auth, "/templates")
    r = auth.post("/templates/upload", data={"csrf": csrf},
                  files=[("files", ("my-0day.yaml", io.BytesIO(CUSTOM_YAML.encode()), "application/x-yaml"))],
                  follow_redirects=False)
    assert r.status_code == 303, r.text
    assert (auth.app.state.settings.custom_templates_dir / "zero-day-example.yaml").exists()
    r = auth.get("/templates/search?q=zero-day&source=custom")
    assert [t["template_id"] for t in r.json()] == ["zero-day-example"]

    r = auth.post("/templates/upload", data={"csrf": csrf},
                  files=[("files", ("bad.yaml", io.BytesIO(b"- not a template"), "application/x-yaml"))])
    assert r.status_code == 400 and "bad.yaml" in r.text

    path = str(auth.app.state.settings.custom_templates_dir / "zero-day-example.yaml")
    r = auth.post("/templates/delete", data={"csrf": csrf, "path": path}, follow_redirects=False)
    assert r.status_code == 303
    assert not Path(path).exists()
    assert auth.get("/templates/search?q=zero-day").json() == []

    r = auth.post("/templates/delete", data={"csrf": csrf, "path": "/etc/passwd"})
    assert r.status_code == 400


def test_templates_pull_from_url(auth, monkeypatch):
    import app.templates_index as tmod
    monkeypatch.setattr(tmod, "http_fetch", lambda url: (200, CUSTOM_YAML))
    csrf = get_csrf(auth, "/templates")
    r = auth.post("/templates/pull", data={"csrf": csrf, "url": "https://raw.githubusercontent.com/x/y/CVE.yaml"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    assert (auth.app.state.settings.custom_templates_dir / "zero-day-example.yaml").exists()
