# 0-Day Rapid Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single-container web app that runs nmap to build a host/software/version inventory, runs nuclei with searchable single/multi templates against selected hosts, supports custom 0-day templates and version-match rules, updates nmap/nuclei from the UI, and forces the seeded `admin`/`changeme` account to change its password on first login.

**Architecture:** FastAPI app (server-rendered Jinja2 + ~100 lines of vanilla JS, no build step) with SQLite via SQLAlchemy 2.0. A `JobRunner` launches nmap/nuclei/update commands as asyncio subprocesses, streams their output to the browser over Server-Sent Events, and calls a completion hook that parses stdout (nmap XML, nuclei JSONL) into the DB. Pure parser/validator modules have no I/O so they are unit tested directly; routers are tested through `TestClient` with fake `nmap`/`nuclei` shell scripts.

**Tech Stack:** Python 3.12, FastAPI 0.115, uvicorn, SQLAlchemy 2.0, Jinja2, itsdangerous (signed session cookie), bcrypt, PyYAML, httpx, pytest. Docker image `python:3.12-slim` + Debian `nmap` + nuclei release binary.

**Spec:** `docs/superpowers/specs/2026-10-29-zero-day-rapid-scanner-design.md`

**Deviation from spec:** the spec mentions HTMX; the plan uses ~100 lines of vanilla JS (`app/static/app.js`) for live search and SSE instead, so the image has no third-party frontend dependency and works offline.

---

## File structure

```
Dockerfile                      image: python slim + nmap + nuclei, non-root user
docker-compose.yml              one service, named volume at /data, NET_RAW/NET_ADMIN
.dockerignore
requirements.txt                runtime deps
requirements-dev.txt            pytest
README.md
app/__init__.py
app/config.py                   Settings dataclass; env loading; secret key persistence
app/db.py                       SQLAlchemy engine/session + all models
app/deps.py                     FastAPI dependencies: get_db, get_settings, get_runner, verify_csrf
app/render.py                   Jinja2 env + render() helper (injects user/csrf/msg)
app/auth.py                     password hashing, seed admin, SessionStore, LoginRateLimiter, AuthMiddleware
app/jobs.py                     JobRunner: subprocess execution, live log, SSE pub/sub, cancel
app/validation.py               target list validation (nmap targets, nuclei URL targets)
app/version_compare.py          version parsing/compare, constraint parsing/evaluation
app/parsers/__init__.py
app/parsers/nmap_xml.py         XML -> HostResult/PortResult (pure)
app/parsers/nuclei_jsonl.py     JSONL -> finding dicts (pure)
app/scanners/__init__.py
app/scanners/nmap_runner.py     build_nmap_argv, ingest_nmap_results, on_nmap_complete
app/scanners/nuclei_runner.py   build_nuclei_argv, ingest_nuclei_results, on_nuclei_complete
app/templates_index.py          scan template dirs -> TemplateIndex rows; search; validate/save/fetch custom
app/rules.py                    version-match rules evaluation; example rule seed
app/updates.py                  tool version detection; update command argv
app/main.py                     create_app() factory, lifespan, router registration
app/routers/__init__.py
app/routers/auth.py             /login /logout /change-password
app/routers/dashboard.py        /
app/routers/jobs.py             /jobs /jobs/{id} /jobs/{id}/status /jobs/{id}/stream /jobs/{id}/cancel
app/routers/nmap.py             /nmap /nmap/scan
app/routers/inventory.py        /inventory /inventory/to-nuclei
app/routers/nuclei.py           /nuclei /nuclei/scan /findings
app/routers/templates.py        /templates /templates/search /templates/upload /templates/pull /templates/delete /templates/reindex
app/routers/rules.py            /rules CRUD + /rules/evaluate
app/routers/updates.py          /updates /updates/{action}
app/templates/*.html            Jinja2 pages (base, login, change_password, dashboard, nmap, inventory,
                                nuclei, findings, templates, rules, rule_form, updates, jobs, job_detail, _jobs_table)
app/static/app.css
app/static/app.js
tests/conftest.py               fixtures: fake nmap/nuclei bins, Settings, TestClient, login helpers
tests/fixtures/nmap_sample.xml
tests/fixtures/nuclei_sample.jsonl
tests/fixtures/templates/http/technologies/php-detect.yaml
tests/fixtures/templates/http/cves/2026/CVE-2026-109619.yaml
tests/test_*.py                 one test module per app module
```

Conventions used throughout:
- All commands are run from the repo root with the venv active: `python3 -m venv .venv && source .venv/bin/activate`.
- Commit with `git add -A && git commit -m "<msg>"` (the repo has no remote).
- Datetimes are naive UTC via `utcnow()` from `app/db.py`.

---

### Task 1: Project skeleton, settings, database models, app factory

**Files:**
- Create: `requirements.txt`, `requirements-dev.txt`, `.gitignore`, `app/__init__.py`, `app/config.py`, `app/db.py`, `app/deps.py`, `app/render.py`, `app/main.py`, `app/routers/__init__.py`, `app/parsers/__init__.py`, `app/scanners/__init__.py`, `app/templates/base.html`, `app/static/app.css`, `app/static/app.js` (empty for now)
- Test: `tests/conftest.py`, `tests/test_config.py`, `tests/test_app.py`

- [ ] **Step 1: Create venv and dependency files**

`requirements.txt`:
```
fastapi==0.115.6
uvicorn[standard]==0.32.1
jinja2==3.1.4
python-multipart==0.0.17
sqlalchemy==2.0.36
itsdangerous==2.2.0
bcrypt==4.2.1
pyyaml==6.0.2
httpx==0.27.2
```

`requirements-dev.txt`:
```
-r requirements.txt
pytest==8.3.4
```

`.gitignore`:
```
.venv/
__pycache__/
*.pyc
.pytest_cache/
data/
*.db
```

Run:
```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -q -r requirements-dev.txt && python -c "import fastapi, sqlalchemy, yaml, bcrypt; print('ok')"
```
Expected: `ok`

- [ ] **Step 2: Write failing tests for Settings and health endpoint**

`tests/test_config.py`:
```python
from pathlib import Path

from app.config import Settings


def test_settings_creates_dirs_and_persists_secret(tmp_path):
    s1 = Settings(data_dir=tmp_path / "data")
    assert (tmp_path / "data").is_dir()
    assert s1.custom_templates_dir == tmp_path / "data" / "custom-templates"
    assert s1.custom_templates_dir.is_dir()
    assert s1.nuclei_templates_dir == tmp_path / "data" / "nuclei-templates"
    assert len(s1.secret_key) >= 32
    assert (tmp_path / "data" / "secret_key").read_text().strip() == s1.secret_key

    s2 = Settings(data_dir=tmp_path / "data")
    assert s2.secret_key == s1.secret_key


def test_settings_db_url(tmp_path):
    s = Settings(data_dir=tmp_path / "d", secret_key="x")
    assert s.db_url == f"sqlite:///{tmp_path / 'd' / 'scanner.db'}"
```

`tests/test_app.py`:
```python
def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
```

`tests/conftest.py` (complete version, used by all later tasks; the fixture files it copies are created in Tasks 2, 3 and 10, so create empty placeholders now):
```python
import re
import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

FIXTURES = Path(__file__).parent / "fixtures"

FAKE_NMAP = """#!/bin/sh
for a in "$@"; do
  case "$a" in
    --version) echo "Nmap version 7.97 ( https://nmap.org )"; exit 0;;
    --script-updatedb) echo "NSE: Updating rule database."; echo "NSE: Script Database updated successfully."; exit 0;;
  esac
done
echo "Starting Nmap 7.97 (fake)" 1>&2
cat "$(dirname "$0")/nmap_sample.xml"
"""

FAKE_NUCLEI = """#!/bin/sh
for a in "$@"; do
  case "$a" in
    -version) echo "[INF] Nuclei Engine Version: v3.8.0" 1>&2; exit 0;;
    -validate) echo "[INF] All templates validated successfully" 1>&2; exit 0;;
    -update-templates|-ut) echo "[INF] Successfully updated nuclei-templates (v10.2.9)"; exit 0;;
    -update|-up) echo "[INF] nuclei is already updated to latest version"; exit 0;;
  esac
done
cat "$(dirname "$0")/nuclei_sample.jsonl"
"""


@pytest.fixture
def fake_bins(tmp_path):
    bins = tmp_path / "bin"
    bins.mkdir()
    for name, body in (("nmap", FAKE_NMAP), ("nuclei", FAKE_NUCLEI)):
        p = bins / name
        p.write_text(body)
        p.chmod(0o755)
    for fx in ("nmap_sample.xml", "nuclei_sample.jsonl"):
        src = FIXTURES / fx
        if src.exists():
            shutil.copy(src, bins / fx)
    return bins


@pytest.fixture
def settings(tmp_path, fake_bins):
    data = tmp_path / "data"
    tdir = data / "nuclei-templates"
    tdir.mkdir(parents=True)
    if (FIXTURES / "templates").exists():
        shutil.copytree(FIXTURES / "templates", tdir, dirs_exist_ok=True)
    return Settings(
        data_dir=data,
        nmap_bin=str(fake_bins / "nmap"),
        nuclei_bin=str(fake_bins / "nuclei"),
        secret_key="test-secret-key",
    )


@pytest.fixture
def client(settings):
    app = create_app(settings)
    with TestClient(app) as c:
        yield c


NEW_PASSWORD = "CorrectHorse-Battery9"


def get_csrf(client, path="/"):
    r = client.get(path)
    m = re.search(r'name="csrf" value="([^"]+)"', r.text)
    assert m, f"no csrf token on {path}"
    return m.group(1)


def login_and_change_password(client, new_password=NEW_PASSWORD):
    r = client.post("/login", data={"username": "admin", "password": "changeme"}, follow_redirects=False)
    assert r.status_code == 303
    csrf = get_csrf(client, "/change-password")
    r = client.post(
        "/change-password",
        data={"csrf": csrf, "current_password": "changeme", "new_password": new_password, "confirm_password": new_password},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    return client


@pytest.fixture
def auth(client):
    return login_and_change_password(client)


def wait_job(client, job_id, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = client.get(f"/jobs/{job_id}/status").json()
        if data["status"] not in ("queued", "running"):
            return data
        time.sleep(0.05)
    raise AssertionError(f"job {job_id} did not finish: {data}")
```

Run:
```bash
mkdir -p tests/fixtures/templates && pytest tests/test_config.py tests/test_app.py -v
```
Expected: FAIL with `ModuleNotFoundError: No module named 'app'`

- [ ] **Step 3: Write `app/config.py`**

```python
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path


def _load_or_create_secret(path: Path) -> str:
    if path.exists():
        return path.read_text().strip()
    key = secrets.token_urlsafe(48)
    path.write_text(key)
    path.chmod(0o600)
    return key


@dataclass
class Settings:
    data_dir: Path
    nmap_bin: str = "nmap"
    nuclei_bin: str = "nuclei"
    secret_key: str = ""
    https: bool = False
    nuclei_templates_dir: Path | None = None
    custom_templates_dir: Path | None = None

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        if self.nuclei_templates_dir is None:
            self.nuclei_templates_dir = self.data_dir / "nuclei-templates"
        self.nuclei_templates_dir = Path(self.nuclei_templates_dir)
        if self.custom_templates_dir is None:
            self.custom_templates_dir = self.data_dir / "custom-templates"
        self.custom_templates_dir = Path(self.custom_templates_dir)
        self.custom_templates_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "jobs").mkdir(parents=True, exist_ok=True)
        if not self.secret_key:
            self.secret_key = _load_or_create_secret(self.data_dir / "secret_key")

    @property
    def db_url(self) -> str:
        return f"sqlite:///{self.data_dir / 'scanner.db'}"

    @property
    def jobs_dir(self) -> Path:
        return self.data_dir / "jobs"


def settings_from_env() -> Settings:
    def opt_path(name: str) -> Path | None:
        v = os.environ.get(name)
        return Path(v) if v else None

    return Settings(
        data_dir=Path(os.environ.get("DATA_DIR", "/data")),
        nmap_bin=os.environ.get("NMAP_BIN", "nmap"),
        nuclei_bin=os.environ.get("NUCLEI_BIN", "nuclei"),
        secret_key=os.environ.get("SECRET_KEY", ""),
        https=os.environ.get("HTTPS", "0") == "1",
        nuclei_templates_dir=opt_path("NUCLEI_TEMPLATES_DIR"),
        custom_templates_dir=opt_path("CUSTOM_TEMPLATES_DIR"),
    )
```

- [ ] **Step 4: Write `app/db.py` with all models**

```python
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, event)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # nmap | nuclei | update
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued|running|done|failed|cancelled
    command: Mapped[str] = mapped_column(Text, default="")
    log: Mapped[str] = mapped_column(Text, default="")
    output: Mapped[str] = mapped_column(Text, default="")
    params_json: Mapped[str] = mapped_column(Text, default="{}")
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    @property
    def duration(self) -> int | None:
        if self.started_at is None:
            return None
        end = self.finished_at or utcnow()
        return int((end - self.started_at).total_seconds())


class Host(Base):
    __tablename__ = "hosts"
    id: Mapped[int] = mapped_column(primary_key=True)
    address: Mapped[str] = mapped_column(String(64), unique=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    services: Mapped[list["Service"]] = relationship(back_populates="host", cascade="all, delete-orphan")


class Service(Base):
    __tablename__ = "services"
    __table_args__ = (UniqueConstraint("host_id", "port", "protocol"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8), default="tcp")
    state: Mapped[str] = mapped_column(String(16), default="open")
    service_name: Mapped[str] = mapped_column(String(64), default="")
    product: Mapped[str] = mapped_column(String(255), default="")
    version: Mapped[str] = mapped_column(String(255), default="")
    extra_info: Mapped[str] = mapped_column(String(255), default="")
    cpe: Mapped[str] = mapped_column(String(255), default="")
    tunnel: Mapped[str] = mapped_column(String(16), default="")
    job_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    host: Mapped["Host"] = relationship(back_populates="services")
    rule_matches: Mapped[list["RuleMatch"]] = relationship(back_populates="service", cascade="all, delete-orphan")


class TemplateIndex(Base):
    __tablename__ = "template_index"
    id: Mapped[int] = mapped_column(primary_key=True)
    template_id: Mapped[str] = mapped_column(String(255), index=True)
    path: Mapped[str] = mapped_column(String(1024), unique=True)
    name: Mapped[str] = mapped_column(String(512), default="")
    severity: Mapped[str] = mapped_column(String(16), default="unknown")
    tags: Mapped[str] = mapped_column(Text, default="")
    cve_ids: Mapped[str] = mapped_column(String(512), default="")
    source: Mapped[str] = mapped_column(String(16), default="official")  # official | custom
    indexed_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"))
    template_id: Mapped[str] = mapped_column(String(255), default="")
    template_name: Mapped[str] = mapped_column(String(512), default="")
    severity: Mapped[str] = mapped_column(String(16), default="unknown")
    host: Mapped[str] = mapped_column(String(512), default="")
    matched_at: Mapped[str] = mapped_column(Text, default="")
    type: Mapped[str] = mapped_column(String(32), default="")
    extracted: Mapped[str] = mapped_column(Text, default="")
    raw_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Rule(Base):
    __tablename__ = "rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    product_pattern: Mapped[str] = mapped_column(String(255))
    version_constraint: Mapped[str] = mapped_column(String(255))
    cve_id: Mapped[str] = mapped_column(String(64), default="")
    severity: Mapped[str] = mapped_column(String(16), default="high")
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    matches: Mapped[list["RuleMatch"]] = relationship(back_populates="rule", cascade="all, delete-orphan")


class RuleMatch(Base):
    __tablename__ = "rule_matches"
    __table_args__ = (UniqueConstraint("rule_id", "service_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("rules.id", ondelete="CASCADE"))
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"))
    evaluated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    rule: Mapped["Rule"] = relationship(back_populates="matches")
    service: Mapped["Service"] = relationship(back_populates="rule_matches")


def make_engine(url: str) -> Engine:
    engine = create_engine(url, connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()

    return engine


def make_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, expire_on_commit=False)


def init_db(engine: Engine) -> None:
    Base.metadata.create_all(engine)
```

- [ ] **Step 5: Write `app/deps.py` and `app/render.py`**

`app/deps.py`:
```python
from __future__ import annotations

from typing import Iterator

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session


def get_db(request: Request) -> Iterator[Session]:
    db: Session = request.app.state.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_settings(request: Request):
    return request.app.state.settings


def get_runner(request: Request):
    return request.app.state.job_runner


async def verify_csrf(request: Request) -> None:
    """Dependency for mutating routes: the form field `csrf` must equal the session's token."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        form = await request.form()
        token = form.get("csrf") or request.headers.get("x-csrf")
        expected = getattr(request.state, "csrf", None)
        if not token or not expected or token != expected:
            raise HTTPException(status_code=403, detail="CSRF token mismatch")
```

`app/render.py`:
```python
from __future__ import annotations

import json
from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters["fromjson"] = json.loads

SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"]
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def normalize_severity(value) -> str:
    v = str(value or "").strip().lower()
    return v if v in SEVERITY_ORDER else "unknown"


def render(request: Request, name: str, status_code: int = 200, **ctx):
    ctx.setdefault("user", getattr(request.state, "user", None))
    ctx.setdefault("csrf", getattr(request.state, "csrf", "") or "")
    ctx.setdefault("msg", request.query_params.get("msg"))
    ctx.setdefault("error", None)
    ctx.setdefault("active", "")
    ctx.setdefault("severities", SEVERITIES)
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)
```

- [ ] **Step 6: Write `app/main.py` (minimal; later tasks add middleware/routers/lifespan work)**

```python
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .config import Settings, settings_from_env
from .db import init_db, make_engine, make_session_factory
from .render import STATIC_DIR


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or settings_from_env()
    engine = make_engine(settings.db_url)
    init_db(engine)
    SessionLocal = make_session_factory(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield

    app = FastAPI(title="0-Day Rapid Scanner", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.SessionLocal = SessionLocal
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    return app
```

Create empty packages and placeholder static files:
```bash
touch app/__init__.py app/routers/__init__.py app/parsers/__init__.py app/scanners/__init__.py app/static/app.js
```

`app/templates/base.html`:
```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{% block title %}0-Day Rapid Scanner{% endblock %}</title>
<link rel="stylesheet" href="/static/app.css">
</head>
<body>
{% if user %}
<header class="topbar">
  <a class="brand" href="/">⚡ 0-Day Rapid Scanner</a>
  <nav>
    <a href="/" class="{{ 'active' if active == 'dashboard' }}">Dashboard</a>
    <a href="/nmap" class="{{ 'active' if active == 'nmap' }}">Nmap</a>
    <a href="/inventory" class="{{ 'active' if active == 'inventory' }}">Inventory</a>
    <a href="/nuclei" class="{{ 'active' if active == 'nuclei' }}">Nuclei</a>
    <a href="/findings" class="{{ 'active' if active == 'findings' }}">Findings</a>
    <a href="/templates" class="{{ 'active' if active == 'templates' }}">Templates</a>
    <a href="/rules" class="{{ 'active' if active == 'rules' }}">0-Day Rules</a>
    <a href="/updates" class="{{ 'active' if active == 'updates' }}">Updates</a>
    <a href="/jobs" class="{{ 'active' if active == 'jobs' }}">Jobs</a>
  </nav>
  <div class="account">
    <span class="muted">{{ user.username }}</span>
    <a href="/change-password">Password</a>
    <form method="post" action="/logout"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="link">Logout</button></form>
  </div>
</header>
{% endif %}
<main class="container">
  {% if msg %}<div class="flash ok">{{ msg }}</div>{% endif %}
  {% if error %}<div class="flash err">{{ error }}</div>{% endif %}
  {% block content %}{% endblock %}
</main>
<script src="/static/app.js"></script>
</body>
</html>
```

`app/static/app.css`:
```css
:root{--bg:#0b0f14;--panel:#121923;--panel2:#18222e;--line:#243242;--text:#dbe4ee;--muted:#8a9bb0;--accent:#38bdf8;--ok:#22c55e;--warn:#f59e0b;--err:#ef4444;--crit:#dc2626;--high:#f97316;--med:#eab308;--low:#3b82f6;--info:#64748b;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
h1{font-size:22px;margin:0 0 16px}h2{font-size:16px;margin:0 0 12px}h3{font-size:14px;margin:12px 0 6px}
.topbar{display:flex;align-items:center;gap:24px;padding:10px 20px;background:var(--panel);border-bottom:1px solid var(--line);flex-wrap:wrap}
.brand{font-weight:700;color:var(--text);letter-spacing:.3px}
.topbar nav{display:flex;gap:4px;flex-wrap:wrap}.topbar nav a{padding:6px 10px;border-radius:6px;color:var(--muted)}.topbar nav a.active,.topbar nav a:hover{background:var(--panel2);color:var(--text);text-decoration:none}
.account{margin-left:auto;display:flex;gap:12px;align-items:center}.account form{display:inline}
.container{max-width:1400px;margin:0 auto;padding:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}
@media (max-width:900px){.grid-2,.grid-3,.grid-4{grid-template-columns:1fr}}
.stack{display:flex;flex-direction:column;gap:12px}.row{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap}.between{justify-content:space-between;align-items:center}
label{display:flex;flex-direction:column;gap:4px;color:var(--muted);font-size:13px}label.inline{flex-direction:row;align-items:center;gap:8px;color:var(--text)}
input,select,textarea,button{font:inherit;color:var(--text);background:var(--panel2);border:1px solid var(--line);border-radius:6px;padding:8px 10px}
textarea{font-family:var(--mono);font-size:13px;resize:vertical}input[type=checkbox],input[type=radio]{width:auto;accent-color:var(--accent)}
fieldset{border:1px solid var(--line);border-radius:8px;padding:10px 12px;display:flex;gap:16px;flex-wrap:wrap}legend{color:var(--muted);padding:0 6px}
button,.btn{cursor:pointer;display:inline-block}button:hover,.btn:hover{border-color:var(--accent);text-decoration:none}
button.primary{background:var(--accent);color:#04111a;border-color:var(--accent);font-weight:600}
button.link{background:none;border:none;color:var(--accent);padding:0}button.link.danger{color:var(--err)}button.small,.btn.small{padding:4px 8px;font-size:12px}
table.data{width:100%;border-collapse:collapse;font-size:13px}table.data th,table.data td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}table.data th{color:var(--muted);font-weight:600;white-space:nowrap}
.mono{font-family:var(--mono)}.small{font-size:12px}.muted{color:var(--muted)}.warn{color:var(--warn)}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;background:var(--panel2);border:1px solid var(--line);margin-right:4px;text-transform:uppercase}
.sev-critical{background:var(--crit);color:#fff;border-color:var(--crit)}.sev-high{background:var(--high);color:#1a0a00;border-color:var(--high)}.sev-medium{background:var(--med);color:#1a1400;border-color:var(--med)}.sev-low{background:var(--low);color:#fff;border-color:var(--low)}.sev-info{background:var(--info);color:#fff;border-color:var(--info)}.sev-unknown{color:var(--muted)}
.st-queued{color:var(--muted)}.st-running{color:var(--accent)}.st-done{color:var(--ok)}.st-failed{color:var(--err)}.st-cancelled{color:var(--warn)}
.flash{padding:10px 14px;border-radius:8px;margin-bottom:16px;border:1px solid}.flash.ok{border-color:var(--ok);background:rgba(34,197,94,.1)}.flash.err{border-color:var(--err);background:rgba(239,68,68,.12)}
.auth-card{max-width:420px;margin:10vh auto;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:28px}
.stats .stat{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;display:flex;flex-direction:column}.stats .stat b{font-size:26px}.stats .stat span{color:var(--muted);font-size:12px}
pre.log{background:#05080c;border:1px solid var(--line);border-radius:8px;padding:12px;font-family:var(--mono);font-size:12px;max-height:60vh;overflow:auto;white-space:pre-wrap;word-break:break-all}
.tpl-results{max-height:260px;overflow:auto;border:1px solid var(--line);border-radius:8px;margin-top:8px;background:var(--panel2)}
.tpl-item{padding:6px 10px;border-bottom:1px solid var(--line);cursor:pointer;display:flex;gap:8px;align-items:center}.tpl-item:hover{background:#1f2c3a}.tpl-item .n{flex:1}
.tpl-selected{list-style:none;margin:0;padding:0}.tpl-selected li{padding:4px 0;display:flex;gap:8px;align-items:center}
.badge.src{text-transform:none;color:var(--muted)}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `pytest tests/test_config.py tests/test_app.py -v`
Expected: 3 passed

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "feat: project skeleton, settings, db models, app factory"
```

---

### Task 2: nmap XML parser

**Files:**
- Create: `app/parsers/nmap_xml.py`, `tests/fixtures/nmap_sample.xml`
- Test: `tests/test_nmap_xml.py`

- [ ] **Step 1: Create the fixture**

`tests/fixtures/nmap_sample.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - 192.168.1.0/24" start="1730000000" version="7.97">
<host starttime="1730000001" endtime="1730000020">
  <status state="up" reason="syn-ack"/>
  <address addr="192.168.1.10" addrtype="ipv4"/>
  <address addr="00:11:22:33:44:55" addrtype="mac"/>
  <hostnames><hostname name="web01.lab" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="9.6p1 Ubuntu 3ubuntu13" extrainfo="Ubuntu Linux; protocol 2.0" method="probed" conf="10"><cpe>cpe:/a:openbsd:openssh:9.6p1</cpe></service></port>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
      <service name="http" product="Apache httpd" version="2.4.58" extrainfo="(Ubuntu)" method="probed" conf="10"><cpe>cpe:/a:apache:http_server:2.4.58</cpe></service></port>
    <port protocol="tcp" portid="443"><state state="closed" reason="reset"/><service name="https" method="table" conf="3"/></port>
    <port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/>
      <service name="http" product="PHP cli server" version="8.3.10" method="probed" conf="10"/></port>
    <port protocol="tcp" portid="8443"><state state="open" reason="syn-ack"/>
      <service name="http" product="nginx" version="1.24.0" tunnel="ssl" method="probed" conf="10"/></port>
  </ports>
</host>
<host><status state="down" reason="no-response"/><address addr="192.168.1.11" addrtype="ipv4"/></host>
<host starttime="1730000001" endtime="1730000020">
  <status state="up" reason="syn-ack"/>
  <address addr="192.168.1.12" addrtype="ipv4"/>
  <ports>
    <port protocol="tcp" portid="3306"><state state="open" reason="syn-ack"/><service name="mysql" method="table" conf="3"/></port>
  </ports>
</host>
<runstats><finished time="1730000030" elapsed="30.0" summary="Nmap done"/><hosts up="2" down="1" total="3"/></runstats>
</nmaprun>
```

- [ ] **Step 2: Write failing tests**

`tests/test_nmap_xml.py`:
```python
from pathlib import Path

import pytest

from app.parsers.nmap_xml import HostResult, PortResult, parse_nmap_xml

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


def test_parses_only_up_hosts_and_open_ports():
    hosts = parse_nmap_xml(FIXTURE.read_text())
    assert [h.address for h in hosts] == ["192.168.1.10", "192.168.1.12"]
    web = hosts[0]
    assert isinstance(web, HostResult)
    assert web.hostname == "web01.lab"
    assert [p.port for p in web.ports] == [22, 80, 8080, 8443]


def test_port_fields():
    hosts = parse_nmap_xml(FIXTURE.read_text())
    ssh = hosts[0].ports[0]
    assert ssh == PortResult(
        port=22, protocol="tcp", state="open", service="ssh", product="OpenSSH",
        version="9.6p1 Ubuntu 3ubuntu13", extra_info="Ubuntu Linux; protocol 2.0",
        cpe="cpe:/a:openbsd:openssh:9.6p1", tunnel="",
    )
    php = hosts[0].ports[2]
    assert php.product == "PHP cli server" and php.version == "8.3.10" and php.cpe == ""
    nginx = hosts[0].ports[3]
    assert nginx.tunnel == "ssl"


def test_service_without_product_or_hostname():
    hosts = parse_nmap_xml(FIXTURE.read_text())
    db = hosts[1]
    assert db.hostname == ""
    assert db.ports[0].service == "mysql"
    assert db.ports[0].product == "" and db.ports[0].version == ""


def test_malformed_xml_raises():
    with pytest.raises(ValueError):
        parse_nmap_xml("<nmaprun><host>")


def test_empty_output_raises():
    with pytest.raises(ValueError):
        parse_nmap_xml("")
```

Run: `pytest tests/test_nmap_xml.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.parsers.nmap_xml'`

- [ ] **Step 3: Implement the parser**

`app/parsers/nmap_xml.py`:
```python
"""Parse `nmap -oX -` output into plain dataclasses. No I/O, no DB."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


@dataclass(frozen=True)
class PortResult:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: str = ""
    tunnel: str = ""


@dataclass
class HostResult:
    address: str
    hostname: str = ""
    ports: list[PortResult] = field(default_factory=list)


def parse_nmap_xml(xml_text: str) -> list[HostResult]:
    if not xml_text or not xml_text.strip():
        raise ValueError("nmap produced no XML output")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        raise ValueError(f"invalid nmap XML: {e}") from e
    if root.tag != "nmaprun":
        raise ValueError("not an nmap XML document")

    hosts: list[HostResult] = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue
        address = _pick_address(host_el)
        if not address:
            continue
        hn = host_el.find("hostnames/hostname")
        hostname = hn.get("name", "") if hn is not None else ""
        ports: list[PortResult] = []
        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            if state != "open":
                continue
            svc = port_el.find("service")
            cpe_el = svc.find("cpe") if svc is not None else None
            ports.append(PortResult(
                port=int(port_el.get("portid", "0")),
                protocol=port_el.get("protocol", "tcp"),
                state=state,
                service=svc.get("name", "") if svc is not None else "",
                product=svc.get("product", "") if svc is not None else "",
                version=svc.get("version", "") if svc is not None else "",
                extra_info=svc.get("extrainfo", "") if svc is not None else "",
                cpe=(cpe_el.text or "").strip() if cpe_el is not None else "",
                tunnel=svc.get("tunnel", "") if svc is not None else "",
            ))
        hosts.append(HostResult(address=address, hostname=hostname, ports=ports))
    return hosts


def _pick_address(host_el: ET.Element) -> str:
    addrs = {a.get("addrtype"): a.get("addr", "") for a in host_el.findall("address")}
    return addrs.get("ipv4") or addrs.get("ipv6") or ""
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_nmap_xml.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: nmap XML parser"
```

---

### Task 3: nuclei JSONL parser

**Files:**
- Create: `app/parsers/nuclei_jsonl.py`, `tests/fixtures/nuclei_sample.jsonl`
- Test: `tests/test_nuclei_jsonl.py`

- [ ] **Step 1: Create the fixture** (3 lines: two findings and one stray log line)

`tests/fixtures/nuclei_sample.jsonl`:
```
{"template-id":"php-detect","template-path":"/t/http/technologies/php-detect.yaml","info":{"name":"PHP Detect","author":["test"],"tags":["tech","php"],"severity":"info"},"type":"http","host":"http://192.168.1.10:8080","matched-at":"http://192.168.1.10:8080/","extracted-results":["8.3.10"],"timestamp":"2026-10-29T10:00:00Z","matcher-status":true}
[INF] Using Nuclei Engine 3.8.0 (stray line that must be skipped)
{"template-id":"CVE-2026-109619","template-path":"/t/http/cves/2026/CVE-2026-109619.yaml","info":{"name":"PHP use-after-free vulnerability check","severity":"critical","classification":{"cve-id":["CVE-2026-109619"]}},"type":"http","host":"http://192.168.1.10:8080","matched-at":"http://192.168.1.10:8080/index.php","timestamp":"2026-10-29T10:00:05Z","matcher-status":true}
```

- [ ] **Step 2: Write failing tests**

`tests/test_nuclei_jsonl.py`:
```python
from pathlib import Path

from app.parsers.nuclei_jsonl import parse_nuclei_jsonl

FIXTURE = Path(__file__).parent / "fixtures" / "nuclei_sample.jsonl"


def test_parses_findings_and_skips_non_json_lines():
    findings = parse_nuclei_jsonl(FIXTURE.read_text())
    assert len(findings) == 2
    first = findings[0]
    assert first["template_id"] == "php-detect"
    assert first["template_name"] == "PHP Detect"
    assert first["severity"] == "info"
    assert first["host"] == "http://192.168.1.10:8080"
    assert first["matched_at"] == "http://192.168.1.10:8080/"
    assert first["type"] == "http"
    assert first["extracted"] == "8.3.10"
    assert first["raw"]["template-id"] == "php-detect"


def test_missing_fields_default():
    findings = parse_nuclei_jsonl('{"template-id":"x"}\n')
    assert findings[0]["severity"] == "unknown"
    assert findings[0]["template_name"] == ""
    assert findings[0]["extracted"] == ""


def test_empty_input():
    assert parse_nuclei_jsonl("") == []
    assert parse_nuclei_jsonl("\n\n") == []
```

Run: `pytest tests/test_nuclei_jsonl.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement**

`app/parsers/nuclei_jsonl.py`:
```python
"""Parse `nuclei -jsonl` output. One finding per JSON line; non-JSON lines are ignored."""
from __future__ import annotations

import json

from ..render import normalize_severity


def parse_nuclei_jsonl(text: str) -> list[dict]:
    findings: list[dict] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict) or "template-id" not in obj:
            continue
        info = obj.get("info") or {}
        extracted = obj.get("extracted-results") or []
        if isinstance(extracted, str):
            extracted = [extracted]
        findings.append({
            "template_id": str(obj.get("template-id", "")),
            "template_name": str(info.get("name", "") or ""),
            "severity": normalize_severity(info.get("severity")),
            "host": str(obj.get("host", "") or ""),
            "matched_at": str(obj.get("matched-at", "") or ""),
            "type": str(obj.get("type", "") or ""),
            "extracted": ", ".join(str(x) for x in extracted),
            "raw": obj,
        })
    return findings
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_nuclei_jsonl.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: nuclei JSONL parser"
```

---

### Task 4: Target validation and nmap argv builder

**Files:**
- Create: `app/validation.py`, `app/scanners/nmap_runner.py` (argv builder only; ingestion added in Task 8)
- Test: `tests/test_validation.py`, `tests/test_nmap_argv.py`

- [ ] **Step 1: Write failing tests**

`tests/test_validation.py`:
```python
import pytest

from app.validation import parse_nmap_targets, parse_nuclei_targets


def test_nmap_targets_accepts_ip_cidr_range_hostname_and_trims():
    text = "192.168.1.0/24\n  scanme.nmap.org \n\n10.0.0.1-20\n2001:db8::1\n"
    assert parse_nmap_targets(text) == ["192.168.1.0/24", "scanme.nmap.org", "10.0.0.1-20", "2001:db8::1"]


@pytest.mark.parametrize("bad", [
    "",
    "   \n  ",
    "-oN /tmp/x",
    "1.2.3.4; rm -rf /",
    "host name with spaces",
    "a" * 300,
    "$(whoami)",
])
def test_nmap_targets_rejects(bad):
    with pytest.raises(ValueError):
        parse_nmap_targets(bad)


def test_nuclei_targets_accept_urls_and_hostports():
    text = "http://10.0.0.1:8080\nhttps://web01.lab/\n10.0.0.2:443\nscanme.nmap.org"
    assert parse_nuclei_targets(text) == ["http://10.0.0.1:8080", "https://web01.lab/", "10.0.0.2:443", "scanme.nmap.org"]


@pytest.mark.parametrize("bad", ["", "-l /etc/passwd", "http://x y", "ftp://a b"])
def test_nuclei_targets_reject(bad):
    with pytest.raises(ValueError):
        parse_nuclei_targets(bad)


def test_duplicates_removed_preserving_order():
    assert parse_nmap_targets("a.lab\nb.lab\na.lab") == ["a.lab", "b.lab"]
```

`tests/test_nmap_argv.py`:
```python
import pytest

from app.scanners.nmap_runner import build_nmap_argv


def test_default_top_ports_syn():
    argv = build_nmap_argv("/usr/bin/nmap", ["10.0.0.1", "10.0.0.2"])
    assert argv == ["/usr/bin/nmap", "-sV", "-T3", "-sS", "--privileged", "-oX", "-", "10.0.0.1", "10.0.0.2"]


def test_all_ports_connect_skip_ping_t4():
    argv = build_nmap_argv("nmap", ["h"], port_mode="all", scan_type="connect", skip_ping=True, timing="T4")
    assert argv == ["nmap", "-sV", "-T4", "-sT", "-p-", "-Pn", "-oX", "-", "h"]


def test_custom_ports():
    argv = build_nmap_argv("nmap", ["h"], port_mode="custom", custom_ports="22,80,8000-9000")
    assert "-p" in argv and argv[argv.index("-p") + 1] == "22,80,8000-9000"


@pytest.mark.parametrize("kwargs", [
    dict(port_mode="custom", custom_ports=""),
    dict(port_mode="custom", custom_ports="22; ls"),
    dict(port_mode="weird"),
    dict(timing="T9"),
    dict(scan_type="udp"),
])
def test_invalid_options_raise(kwargs):
    with pytest.raises(ValueError):
        build_nmap_argv("nmap", ["h"], **kwargs)


def test_no_targets_raises():
    with pytest.raises(ValueError):
        build_nmap_argv("nmap", [])
```

Run: `pytest tests/test_validation.py tests/test_nmap_argv.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 2: Implement `app/validation.py`**

```python
"""Validate operator-supplied target lists. Targets are passed to subprocesses as argv items
(never via a shell), so the goal here is: no whitespace, no leading '-', sane length, allowlisted chars."""
from __future__ import annotations

import re

_NMAP_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:/]*$")
_NUCLEI_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:/_?=&%@\[\]~+]*$")
MAX_TARGET_LEN = 253
MAX_TARGETS = 5000


def _split(text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in (text or "").replace(",", "\n").splitlines():
        t = raw.strip()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


def _validate(items: list[str], pattern: re.Pattern[str], label: str) -> list[str]:
    if not items:
        raise ValueError(f"Enter at least one {label}.")
    if len(items) > MAX_TARGETS:
        raise ValueError(f"Too many targets (max {MAX_TARGETS}).")
    for t in items:
        if len(t) > MAX_TARGET_LEN:
            raise ValueError(f"Target too long: {t[:40]}…")
        if t.startswith("-") or not pattern.match(t):
            raise ValueError(f"Invalid {label}: {t!r}")
    return items


def parse_nmap_targets(text: str) -> list[str]:
    """IPs, CIDRs, nmap ranges (10.0.0.1-20), hostnames, IPv6."""
    return _validate(_split(text), _NMAP_TARGET_RE, "nmap target")


def parse_nuclei_targets(text: str) -> list[str]:
    """URLs (http/https) or host[:port] entries."""
    items = _validate(_split(text), _NUCLEI_TARGET_RE, "nuclei target")
    for t in items:
        if "://" in t and not (t.startswith("http://") or t.startswith("https://")):
            raise ValueError(f"Only http:// and https:// URLs are supported: {t!r}")
    return items
```

- [ ] **Step 3: Implement the argv builder in `app/scanners/nmap_runner.py`**

```python
from __future__ import annotations

import re

TIMINGS = ("T2", "T3", "T4")
SCAN_TYPES = {"syn": ["-sS", "--privileged"], "connect": ["-sT"]}
PORT_MODES = ("top", "all", "custom")
_PORT_SPEC_RE = re.compile(r"^[0-9][0-9,\-]*$")


def build_nmap_argv(nmap_bin: str, targets: list[str], port_mode: str = "top", custom_ports: str = "",
                    timing: str = "T3", skip_ping: bool = False, scan_type: str = "syn") -> list[str]:
    if not targets:
        raise ValueError("No targets.")
    if timing not in TIMINGS:
        raise ValueError(f"Invalid timing {timing!r}.")
    if scan_type not in SCAN_TYPES:
        raise ValueError(f"Invalid scan type {scan_type!r}.")
    if port_mode not in PORT_MODES:
        raise ValueError(f"Invalid port mode {port_mode!r}.")
    argv = [nmap_bin, "-sV", f"-{timing}", *SCAN_TYPES[scan_type]]
    if port_mode == "all":
        argv.append("-p-")
    elif port_mode == "custom":
        spec = custom_ports.replace(" ", "")
        if not spec or not _PORT_SPEC_RE.match(spec):
            raise ValueError("Custom ports must look like 22,80,8000-9000.")
        argv += ["-p", spec]
    if skip_ping:
        argv.append("-Pn")
    argv += ["-oX", "-"]
    argv += targets
    return argv
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_validation.py tests/test_nmap_argv.py -v`
Expected: all passed (15 tests)

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: target validation and nmap argv builder"
```

---

### Task 5: Version comparison and constraint evaluation

**Files:**
- Create: `app/version_compare.py`
- Test: `tests/test_version_compare.py`

- [ ] **Step 1: Write failing tests**

`tests/test_version_compare.py`:
```python
import pytest

from app.version_compare import (check_clauses, compare_versions, extract_version, parse_constraint, version_satisfies)


@pytest.mark.parametrize("a,b,expected", [
    ("8.3.10", "8.3.15", -1),
    ("8.3.15", "8.3.15", 0),
    ("10.0", "9.9", 1),
    ("1.0", "1.0.0", 0),
    ("1.0", "1.0rc1", 1),
    ("1.0rc1", "1.0rc2", -1),
    ("9.6p1", "9.6", 1),
    ("2.4.58", "2.4.6", 1),
])
def test_compare(a, b, expected):
    assert compare_versions(a, b) == expected


@pytest.mark.parametrize("raw,expected", [
    ("2.4.58 (Ubuntu)", "2.4.58"),
    ("9.6p1 Ubuntu 3ubuntu13", "9.6p1"),
    ("8.3.10", "8.3.10"),
    ("", None),
    (None, None),
    ("unknown", None),
    ("v1.24.0", "1.24.0"),
])
def test_extract_version(raw, expected):
    assert extract_version(raw) == expected


def test_parse_constraint():
    assert parse_constraint("< 8.3.15") == [("<", "8.3.15")]
    assert parse_constraint(">=8.0, <8.3.15") == [(">=", "8.0"), ("<", "8.3.15")]
    assert parse_constraint("==1.2.3") == [("==", "1.2.3")]
    assert parse_constraint("!=1.2.3") == [("!=", "1.2.3")]


@pytest.mark.parametrize("bad", ["", "8.3.15", "<", "~>1.0", "< 8.3.15 extra", "<=a b"])
def test_parse_constraint_invalid(bad):
    with pytest.raises(ValueError):
        parse_constraint(bad)


@pytest.mark.parametrize("version,constraint,expected", [
    ("8.3.10", "< 8.3.15", True),
    ("8.3.15", "< 8.3.15", False),
    ("8.3.15", "<= 8.3.15", True),
    ("7.4.33", ">=8.0,<8.3.15", False),
    ("8.2.0", ">=8.0,<8.3.15", True),
    ("8.4.1", ">=8.0,<8.3.15", False),
    ("1.2.3", "==1.2.3", True),
    ("1.2.3", "!=1.2.3", False),
    ("", "< 1", False),
    ("2.4.58 (Ubuntu)", "< 2.4.60", True),
])
def test_version_satisfies(version, constraint, expected):
    assert version_satisfies(version, constraint) is expected


def test_check_clauses_with_preparsed():
    clauses = parse_constraint("<8.3.15")
    assert check_clauses("8.3.14", clauses) is True
```

Run: `pytest tests/test_version_compare.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 2: Implement**

`app/version_compare.py`:
```python
"""Tiny dependency-free version comparison for software versions reported by nmap.

Rules: split on '.', '-', '_' and at letter/digit boundaries; numeric segments compare
numerically; alphabetic segments compare lexically; a numeric segment beats an alphabetic one
(so 1.0 > 1.0rc1 and 9.6p1 > 9.6); missing segments count as 0.
"""
from __future__ import annotations

import re

_VERSION_TOKEN_RE = re.compile(r"\d+(?:[.\-_]?[A-Za-z0-9]+)*")
_SEGMENT_RE = re.compile(r"\d+|[A-Za-z]+")
_OPS = ("<=", ">=", "==", "!=", "<", ">")
_CLAUSE_RE = re.compile(r"^(<=|>=|==|!=|<|>)\s*([A-Za-z0-9][A-Za-z0-9.\-_]*)$")


def extract_version(raw: str | None) -> str | None:
    """Pull the leading version token out of an nmap version string (optional leading 'v').
    Returns None when the string does not start with a digit."""
    if not raw:
        return None
    s = raw.strip()
    if len(s) > 1 and s[0] in "vV" and s[1].isdigit():
        s = s[1:]
    m = _VERSION_TOKEN_RE.match(s)
    return m.group(0) if m else None


def _segments(version: str) -> list[int | str]:
    out: list[int | str] = []
    for seg in _SEGMENT_RE.findall(version):
        out.append(int(seg) if seg.isdigit() else seg.lower())
    return out


def _cmp_segment(a: int | str | None, b: int | str | None) -> int:
    a = 0 if a is None else a
    b = 0 if b is None else b
    if isinstance(a, int) and isinstance(b, int):
        return (a > b) - (a < b)
    if isinstance(a, int):
        return 1
    if isinstance(b, int):
        return -1
    return (a > b) - (a < b)


def compare_versions(a: str, b: str) -> int:
    sa, sb = _segments(a), _segments(b)
    for i in range(max(len(sa), len(sb))):
        c = _cmp_segment(sa[i] if i < len(sa) else None, sb[i] if i < len(sb) else None)
        if c:
            return c
    return 0


def parse_constraint(expr: str) -> list[tuple[str, str]]:
    """'>=8.0, <8.3.15' -> [('>=','8.0'), ('<','8.3.15')]. Raises ValueError when malformed."""
    clauses: list[tuple[str, str]] = []
    for part in (expr or "").split(","):
        part = part.strip()
        if not part:
            continue
        m = _CLAUSE_RE.match(part)
        if not m:
            raise ValueError(f"Invalid version clause {part!r}. Use <, <=, >, >=, ==, != followed by a version.")
        clauses.append((m.group(1), m.group(2)))
    if not clauses:
        raise ValueError("Version constraint is empty.")
    return clauses


def check_clauses(version: str | None, clauses: list[tuple[str, str]]) -> bool:
    v = extract_version(version)
    if not v:
        return False
    for op, target in clauses:
        c = compare_versions(v, target)
        ok = {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0, "==": c == 0, "!=": c != 0}[op]
        if not ok:
            return False
    return True


def version_satisfies(version: str | None, constraint: str) -> bool:
    return check_clauses(version, parse_constraint(constraint))
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/test_version_compare.py -v`
Expected: all passed. If `("9.6p1 Ubuntu 3ubuntu13", "9.6p1")` fails because the token regex grabs `9.6p1` correctly but then stops at the space: that is the expected behaviour (space is not in the token pattern). If `("2.4.58", "2.4.6", 1)` fails, check `_cmp_segment` uses int compare (58 > 6).

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat: version comparison and constraint evaluation"
```

---

### Task 6: Authentication, forced password change, CSRF, session middleware

**Files:**
- Create: `app/auth.py`, `app/routers/auth.py`, `app/templates/login.html`, `app/templates/change_password.html`
- Modify: `app/main.py` (seed admin in lifespan, add middleware, include router)
- Test: `tests/test_auth.py`

- [ ] **Step 1: Write failing tests**

`tests/test_auth.py`:
```python
from app.auth import hash_password, validate_new_password, verify_password
from tests.conftest import NEW_PASSWORD, get_csrf, login_and_change_password


def test_hash_roundtrip():
    h = hash_password("changeme")
    assert verify_password("changeme", h)
    assert not verify_password("wrong", h)
    assert not verify_password("x", "not-a-hash")


def test_validate_new_password_rules():
    assert validate_new_password("short", "short", "changeme") == "New password must be at least 12 characters."
    assert validate_new_password("CorrectHorse-Battery9", "nope", "changeme") == "Passwords do not match."
    assert validate_new_password("changeme-changeme", "changeme-changeme", "changeme-changeme") == "New password must differ from the current one."
    assert validate_new_password("CorrectHorse-Battery9", "CorrectHorse-Battery9", "changeme") is None


def test_unauthenticated_redirects_to_login(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/login").status_code == 200


def test_bad_login_shows_error(client):
    r = client.post("/login", data={"username": "admin", "password": "nope"})
    assert r.status_code == 401
    assert "Invalid username or password" in r.text


def test_login_rate_limited_after_5_failures(client):
    for _ in range(5):
        client.post("/login", data={"username": "admin", "password": "nope"})
    r = client.post("/login", data={"username": "admin", "password": "changeme"})
    assert r.status_code == 429


def test_first_login_forces_password_change(client):
    r = client.post("/login", data={"username": "admin", "password": "changeme"}, follow_redirects=False)
    assert r.status_code == 303
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/change-password"
    r = client.get("/nmap", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/change-password"
    page = client.get("/change-password")
    assert page.status_code == 200 and "default password must be changed" in page.text


def test_change_password_rejects_weak_and_csrf(client):
    client.post("/login", data={"username": "admin", "password": "changeme"})
    csrf = get_csrf(client, "/change-password")
    r = client.post("/change-password", data={"csrf": "bad", "current_password": "changeme", "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})
    assert r.status_code == 403
    r = client.post("/change-password", data={"csrf": csrf, "current_password": "changeme", "new_password": "short", "confirm_password": "short"})
    assert r.status_code == 400 and "at least 12" in r.text
    r = client.post("/change-password", data={"csrf": csrf, "current_password": "wrong", "new_password": NEW_PASSWORD, "confirm_password": NEW_PASSWORD})
    assert r.status_code == 400 and "Current password is incorrect" in r.text


def test_after_change_full_access_and_relogin_with_new_password(client):
    login_and_change_password(client)
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 200
    csrf = get_csrf(client, "/")
    r = client.post("/logout", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/", follow_redirects=False).status_code == 303
    r = client.post("/login", data={"username": "admin", "password": "changeme"})
    assert r.status_code == 401
    r = client.post("/login", data={"username": "admin", "password": NEW_PASSWORD}, follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/", follow_redirects=False).status_code == 200
```

`/` must exist for these tests: Task 6 adds a placeholder dashboard route in `app/main.py` that Task 14 replaces.

Run: `pytest tests/test_auth.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.auth'`

- [ ] **Step 2: Implement `app/auth.py`**

```python
from __future__ import annotations

import secrets
import time
from collections import defaultdict, deque

import bcrypt
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse

from .db import User

DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "changeme"
MIN_PASSWORD_LEN = 12
SESSION_COOKIE = "zdrs_session"
SESSION_MAX_AGE = 12 * 3600
PUBLIC_PATHS = {"/login", "/healthz"}
PUBLIC_PREFIXES = ("/static/",)
CHANGE_PASSWORD_ALLOWED = {"/change-password", "/logout"}


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


def validate_new_password(new: str, confirm: str, current: str) -> str | None:
    if len(new) < MIN_PASSWORD_LEN:
        return f"New password must be at least {MIN_PASSWORD_LEN} characters."
    if new != confirm:
        return "Passwords do not match."
    if new == current:
        return "New password must differ from the current one."
    return None


def seed_admin(db: Session) -> None:
    if db.scalar(select(User).limit(1)) is None:
        db.add(User(username=DEFAULT_USERNAME, password_hash=hash_password(DEFAULT_PASSWORD), must_change_password=True))
        db.commit()


class SessionStore:
    def __init__(self, secret_key: str):
        self._s = URLSafeTimedSerializer(secret_key, salt="zdrs-session")

    def encode(self, user_id: int) -> str:
        return self._s.dumps({"uid": user_id, "csrf": secrets.token_urlsafe(24)})

    def decode(self, token: str) -> dict | None:
        try:
            data = self._s.loads(token, max_age=SESSION_MAX_AGE)
        except BadSignature:
            return None
        if not isinstance(data, dict) or "uid" not in data or "csrf" not in data:
            return None
        return data


class LoginRateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, ip: str) -> deque[float]:
        q = self._failures[ip]
        cutoff = time.monotonic() - self.window
        while q and q[0] < cutoff:
            q.popleft()
        return q

    def allowed(self, ip: str) -> bool:
        return len(self._prune(ip)) < self.max_attempts

    def record_failure(self, ip: str) -> None:
        self._prune(ip).append(time.monotonic())

    def reset(self, ip: str) -> None:
        self._failures.pop(ip, None)


class AuthMiddleware(BaseHTTPMiddleware):
    """Loads the user from the session cookie, enforces login and the forced password change."""

    async def dispatch(self, request: Request, call_next):
        app = request.app
        request.state.user = None
        request.state.csrf = None
        token = request.cookies.get(SESSION_COOKIE)
        data = app.state.sessions.decode(token) if token else None
        if data:
            with app.state.SessionLocal() as db:
                user = db.get(User, data["uid"])
            if user is not None:
                request.state.user = user
                request.state.csrf = data["csrf"]

        path = request.url.path
        public = path in PUBLIC_PATHS or path.startswith(PUBLIC_PREFIXES)
        if request.state.user is None:
            if not public:
                return RedirectResponse("/login", status_code=303)
        elif request.state.user.must_change_password and not public and path not in CHANGE_PASSWORD_ALLOWED:
            return RedirectResponse("/change-password", status_code=303)
        return await call_next(request)


def set_session_cookie(response, token: str, secure: bool) -> None:
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_MAX_AGE, httponly=True, samesite="lax", secure=secure, path="/")


def clear_session_cookie(response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
```

- [ ] **Step 3: Implement `app/routers/auth.py`**

```python
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import (clear_session_cookie, hash_password, set_session_cookie, validate_new_password, verify_password)
from ..db import User
from ..deps import get_db, get_settings, verify_csrf
from ..render import render

router = APIRouter()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.get("/login")
def login_page(request: Request):
    if request.state.user is not None:
        return RedirectResponse("/", status_code=303)
    return render(request, "login.html")


@router.post("/login")
def login(request: Request, username: str = Form(""), password: str = Form(""),
          db: Session = Depends(get_db), settings=Depends(get_settings)):
    limiter = request.app.state.login_limiter
    ip = _client_ip(request)
    if not limiter.allowed(ip):
        return render(request, "login.html", status_code=429, error="Too many failed attempts. Try again in a minute.")
    user = db.scalar(select(User).where(User.username == username.strip()))
    if user is None or not verify_password(password, user.password_hash):
        limiter.record_failure(ip)
        return render(request, "login.html", status_code=401, error="Invalid username or password.")
    limiter.reset(ip)
    response = RedirectResponse("/", status_code=303)
    set_session_cookie(response, request.app.state.sessions.encode(user.id), secure=settings.https)
    return response


@router.post("/logout", dependencies=[Depends(verify_csrf)])
def logout():
    response = RedirectResponse("/login", status_code=303)
    clear_session_cookie(response)
    return response


@router.get("/change-password")
def change_password_page(request: Request):
    return render(request, "change_password.html")


@router.post("/change-password", dependencies=[Depends(verify_csrf)])
def change_password(request: Request, current_password: str = Form(""), new_password: str = Form(""),
                    confirm_password: str = Form(""), db: Session = Depends(get_db), settings=Depends(get_settings)):
    user = db.get(User, request.state.user.id)
    if not verify_password(current_password, user.password_hash):
        return render(request, "change_password.html", status_code=400, error="Current password is incorrect.")
    err = validate_new_password(new_password, confirm_password, current_password)
    if err:
        return render(request, "change_password.html", status_code=400, error=err)
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    db.commit()
    response = RedirectResponse("/?msg=Password+updated", status_code=303)
    set_session_cookie(response, request.app.state.sessions.encode(user.id), secure=settings.https)
    return response
```

- [ ] **Step 4: Templates**

`app/templates/login.html`:
```html
{% extends "base.html" %}
{% block title %}Login · 0-Day Rapid Scanner{% endblock %}
{% block content %}
<div class="auth-card">
  <h1>⚡ 0-Day Rapid Scanner</h1>
  <p class="muted">Sign in to continue.</p>
  {% if error %}<div class="flash err">{{ error }}</div>{% endif %}
  <form method="post" action="/login" class="stack">
    <label>Username <input name="username" autocomplete="username" required autofocus></label>
    <label>Password <input type="password" name="password" autocomplete="current-password" required></label>
    <button class="primary">Sign in</button>
  </form>
</div>
{% endblock %}
```
Because `base.html` already renders `error` inside `<main>`, remove the `{% if error %}` block from this template to avoid duplicates. Final `login.html` is the above without that line.

`app/templates/change_password.html`:
```html
{% extends "base.html" %}
{% block title %}Password · 0-Day Rapid Scanner{% endblock %}
{% block content %}
<div class="auth-card">
  <h1>{{ 'Set a new password' if user.must_change_password else 'Change password' }}</h1>
  {% if user.must_change_password %}<p class="warn">The default password must be changed before you can use the scanner.</p>{% endif %}
  <form method="post" action="/change-password" class="stack">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <label>Current password <input type="password" name="current_password" required autocomplete="current-password"></label>
    <label>New password (min 12 characters) <input type="password" name="new_password" required minlength="12" autocomplete="new-password"></label>
    <label>Confirm new password <input type="password" name="confirm_password" required minlength="12" autocomplete="new-password"></label>
    <button class="primary">Save password</button>
  </form>
</div>
{% endblock %}
```

- [ ] **Step 5: Wire into `app/main.py`**

Replace the file with:
```python
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from .auth import AuthMiddleware, LoginRateLimiter, SessionStore, seed_admin
from .config import Settings, settings_from_env
from .db import init_db, make_engine, make_session_factory
from .render import STATIC_DIR, render
from .routers import auth as auth_router


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or settings_from_env()
    engine = make_engine(settings.db_url)
    init_db(engine)
    SessionLocal = make_session_factory(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        with SessionLocal() as db:
            seed_admin(db)
        yield

    app = FastAPI(title="0-Day Rapid Scanner", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.SessionLocal = SessionLocal
    app.state.sessions = SessionStore(settings.secret_key)
    app.state.login_limiter = LoginRateLimiter()
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.add_middleware(AuthMiddleware)
    app.include_router(auth_router.router)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/")
    def dashboard_placeholder(request: Request):
        return render(request, "base.html", active="dashboard")

    return app
```

- [ ] **Step 6: Run tests**

Run: `pytest tests/test_auth.py tests/test_app.py -v`
Expected: all passed (9 tests)

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat: login, forced password change, CSRF and session middleware"
```

---

### Task 7: Job runner with live log streaming (SSE) and jobs pages

**Files:**
- Create: `app/jobs.py`, `app/routers/jobs.py`, `app/templates/jobs.html`, `app/templates/job_detail.html`, `app/templates/_jobs_table.html`
- Modify: `app/main.py` (create runner in lifespan, include router), `app/static/app.js`
- Test: `tests/test_jobs.py`

- [ ] **Step 1: Write failing tests**

`tests/test_jobs.py`:
```python
import asyncio
import sys

from sqlalchemy import select

from app.db import Job, init_db, make_engine, make_session_factory
from app.jobs import JobRunner
from tests.conftest import wait_job


def _runner(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 't.db'}")
    init_db(engine)
    return JobRunner(make_session_factory(engine))


def test_runner_captures_stdout_stderr_and_calls_hook(tmp_path):
    runner = _runner(tmp_path)
    seen = {}

    def hook(db, job, output):
        seen["output"] = output
        seen["job_id"] = job.id

    async def main():
        with runner.session_factory() as db:
            job = runner.create_job(db, "nmap", ["sh", "-c", "echo out1; echo err1 1>&2; echo out2"], {"a": 1})
            job_id = job.id
        await runner.start(job_id, ["sh", "-c", "echo out1; echo err1 1>&2; echo out2"], on_complete=hook, stdout_to_log=False)
        return job_id

    job_id = asyncio.run(main())
    with runner.session_factory() as db:
        job = db.get(Job, job_id)
    assert job.status == "done" and job.exit_code == 0
    assert job.output == "out1\nout2"
    assert "err1" in job.log and "out1" not in job.log
    assert "[runner] exit code 0 (done)" in job.log
    assert seen == {"output": "out1\nout2", "job_id": job_id}
    assert job.started_at is not None and job.finished_at is not None


def test_runner_marks_nonzero_exit_failed_and_skips_hook(tmp_path):
    runner = _runner(tmp_path)
    called = []

    async def main():
        with runner.session_factory() as db:
            job_id = runner.create_job(db, "update", ["sh", "-c", "echo boom; exit 3"]).id
        await runner.start(job_id, ["sh", "-c", "echo boom; exit 3"], on_complete=lambda *a: called.append(1))
        return job_id

    job_id = asyncio.run(main())
    with runner.session_factory() as db:
        job = db.get(Job, job_id)
    assert job.status == "failed" and job.exit_code == 3
    assert "boom" in job.log
    assert called == []


def test_hook_exception_marks_failed(tmp_path):
    runner = _runner(tmp_path)

    def hook(db, job, output):
        raise RuntimeError("parse error")

    async def main():
        with runner.session_factory() as db:
            job_id = runner.create_job(db, "nmap", ["true"]).id
        await runner.start(job_id, ["true"], on_complete=hook)
        return job_id

    job_id = asyncio.run(main())
    with runner.session_factory() as db:
        job = db.get(Job, job_id)
    assert job.status == "failed"
    assert "result processing failed" in job.log and "parse error" in job.log


def test_missing_binary_fails_cleanly(tmp_path):
    runner = _runner(tmp_path)

    async def main():
        with runner.session_factory() as db:
            job_id = runner.create_job(db, "nmap", ["/nonexistent/bin"]).id
        await runner.start(job_id, ["/nonexistent/bin"])
        return job_id

    job_id = asyncio.run(main())
    with runner.session_factory() as db:
        job = db.get(Job, job_id)
    assert job.status == "failed" and job.exit_code == 127
    assert "cannot start" in job.log


def test_cancel_running_job(tmp_path):
    runner = _runner(tmp_path)

    async def main():
        with runner.session_factory() as db:
            job_id = runner.create_job(db, "nmap", ["sleep", "30"]).id
        task = runner.start(job_id, ["sleep", "30"])
        for _ in range(100):
            await asyncio.sleep(0.05)
            if runner.cancel(job_id):
                break
        await task
        return job_id

    job_id = asyncio.run(main())
    with runner.session_factory() as db:
        job = db.get(Job, job_id)
    assert job.status == "cancelled"


def test_jobs_pages_and_status_endpoint(auth):
    runner = auth.app.state.job_runner
    with auth.app.state.SessionLocal() as db:
        job_id = runner.create_job(db, "update", ["echo", "hi"]).id
    # start on the app's loop via the portal used by TestClient
    auth.portal.call(runner.start, job_id, ["echo", "hi"])
    data = wait_job(auth, job_id)
    assert data["status"] == "done"
    assert auth.get("/jobs").status_code == 200
    page = auth.get(f"/jobs/{job_id}")
    assert page.status_code == 200 and "echo hi" in page.text and "hi" in page.text
    assert auth.get("/jobs/999").status_code == 404


def test_stream_endpoint_replays_log_for_finished_job(auth):
    runner = auth.app.state.job_runner
    with auth.app.state.SessionLocal() as db:
        job_id = runner.create_job(db, "update", ["echo", "streamed"]).id
    auth.portal.call(runner.start, job_id, ["echo", "streamed"])
    wait_job(auth, job_id)
    with auth.stream("GET", f"/jobs/{job_id}/stream") as r:
        body = "".join(r.iter_text())
    assert "event: log\ndata: streamed" in body
    assert "event: done\ndata: done" in body
```

Note: `auth.portal.call(runner.start, ...)` runs `runner.start` inside the app's event loop (TestClient exposes the anyio portal as `.portal`). `runner.start` must therefore be a plain (non-async) function that calls `asyncio.create_task` and returns the task.

Run: `pytest tests/test_jobs.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.jobs'`

- [ ] **Step 2: Implement `app/jobs.py`**

```python
"""Run scanner/update subprocesses as asyncio tasks, keep a live log in memory, persist it to the
Job row, and fan lines out to SSE subscribers."""
from __future__ import annotations

import asyncio
import json
import os
import shlex
from typing import Callable, Optional

from sqlalchemy.orm import Session

from .db import Job, utcnow

CompletionHook = Callable[[Session, Job, str], None]
MAX_LIVE_LINES = 20000


def quote_argv(argv: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)


class JobRunner:
    def __init__(self, session_factory):
        self.session_factory = session_factory
        self._subs: dict[int, set[asyncio.Queue]] = {}
        self._procs: dict[int, asyncio.subprocess.Process] = {}
        self._sems: dict[str, asyncio.Semaphore] = {}
        self._tasks: set[asyncio.Task] = set()
        self._live: dict[int, list[str]] = {}
        self._cancel_requested: set[int] = set()

    # ----- creation / start -------------------------------------------------
    def create_job(self, db: Session, kind: str, argv: list[str], params: dict | None = None) -> Job:
        job = Job(kind=kind, status="queued", command=quote_argv(argv), params_json=json.dumps(params or {}))
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    def start(self, job_id: int, argv: list[str], on_complete: Optional[CompletionHook] = None,
              env: dict | None = None, stdout_to_log: bool = True) -> asyncio.Task:
        task = asyncio.get_running_loop().create_task(self._run(job_id, argv, on_complete, env, stdout_to_log))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    # ----- observation ------------------------------------------------------
    def is_live(self, job_id: int) -> bool:
        return job_id in self._live

    def live_log(self, job_id: int) -> list[str]:
        return list(self._live.get(job_id, []))

    def subscribe(self, job_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subs.setdefault(job_id, set()).add(q)
        return q

    def unsubscribe(self, job_id: int, q: asyncio.Queue) -> None:
        subs = self._subs.get(job_id)
        if subs:
            subs.discard(q)

    def cancel(self, job_id: int) -> bool:
        proc = self._procs.get(job_id)
        if proc is not None and proc.returncode is None:
            proc.terminate()
            return True
        if job_id in self._live:  # queued, waiting for the semaphore
            self._cancel_requested.add(job_id)
            return True
        return False

    # ----- internals --------------------------------------------------------
    def _sem(self, kind: str) -> asyncio.Semaphore:
        return self._sems.setdefault(kind, asyncio.Semaphore(1))

    def _publish(self, job_id: int, line: str) -> None:
        lines = self._live.setdefault(job_id, [])
        if len(lines) >= MAX_LIVE_LINES:
            del lines[: len(lines) - MAX_LIVE_LINES + 1]
        lines.append(line)
        idx = len(lines) - 1
        for q in self._subs.get(job_id, ()):
            q.put_nowait((idx, line))

    def _update(self, job_id: int, **fields) -> None:
        with self.session_factory() as db:
            job = db.get(Job, job_id)
            if job is None:
                return
            for k, v in fields.items():
                setattr(job, k, v)
            db.commit()

    def _finish(self, job_id: int, status: str, exit_code: int | None, output: str) -> None:
        log = "\n".join(self._live.pop(job_id, []))
        self._cancel_requested.discard(job_id)
        self._update(job_id, status=status, exit_code=exit_code, finished_at=utcnow(), log=log, output=output)
        for q in self._subs.pop(job_id, set()):
            q.put_nowait(None)

    async def _flush_loop(self, job_id: int) -> None:
        while True:
            await asyncio.sleep(1.0)
            lines = self._live.get(job_id)
            if lines:
                self._update(job_id, log="\n".join(lines))

    async def _pump(self, job_id: int, stream, to_log: bool, collect: list[str] | None) -> None:
        while True:
            try:
                line = await stream.readline()
            except (ValueError, asyncio.LimitOverrunError):
                self._publish(job_id, "[runner] line too long, skipped")
                continue
            if not line:
                return
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            if collect is not None:
                collect.append(text)
            if to_log:
                self._publish(job_id, text)

    async def _run(self, job_id: int, argv: list[str], on_complete, env, stdout_to_log: bool) -> None:
        with self.session_factory() as db:
            job = db.get(Job, job_id)
            kind = job.kind if job else "other"
        self._live.setdefault(job_id, [])
        self._publish(job_id, f"[runner] queued: {quote_argv(argv)}")
        async with self._sem(kind):
            if job_id in self._cancel_requested:
                self._publish(job_id, "[runner] cancelled before start")
                self._finish(job_id, "cancelled", None, "")
                return
            self._update(job_id, status="running", started_at=utcnow())
            self._publish(job_id, "[runner] started")
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    env={**os.environ, **(env or {})}, limit=4 * 1024 * 1024,
                )
            except (FileNotFoundError, PermissionError, OSError) as e:
                self._publish(job_id, f"[runner] cannot start: {e}")
                self._finish(job_id, "failed", 127, "")
                return
            self._procs[job_id] = proc
            stdout_lines: list[str] = []
            flusher = asyncio.get_running_loop().create_task(self._flush_loop(job_id))
            try:
                await asyncio.gather(
                    self._pump(job_id, proc.stdout, stdout_to_log, stdout_lines),
                    self._pump(job_id, proc.stderr, True, None),
                )
                code = await proc.wait()
            finally:
                flusher.cancel()
                self._procs.pop(job_id, None)
            output = "\n".join(stdout_lines)
            if code < 0 or job_id in self._cancel_requested:
                status = "cancelled"
            elif code == 0:
                status = "done"
            else:
                status = "failed"
            if on_complete is not None and status == "done":
                try:
                    with self.session_factory() as db:
                        job = db.get(Job, job_id)
                        on_complete(db, job, output)
                        db.commit()
                    self._publish(job_id, "[runner] results processed")
                except Exception as e:  # noqa: BLE001 - surface anything to the operator
                    self._publish(job_id, f"[runner] result processing failed: {e!r}")
                    status = "failed"
            self._publish(job_id, f"[runner] exit code {code} ({status})")
            self._finish(job_id, status, code, output)
```

`cancel()` for a running process: `proc.terminate()` sends SIGTERM; the subprocess exits with a negative returncode, which `_run` maps to `cancelled`. Also mark the request so a `-15` exit is reported as cancelled even if the tool traps the signal and exits 0.

Adjust `cancel()` so a running job is also recorded in `_cancel_requested`:
```python
    def cancel(self, job_id: int) -> bool:
        if job_id not in self._live:
            return False
        self._cancel_requested.add(job_id)
        proc = self._procs.get(job_id)
        if proc is not None and proc.returncode is None:
            proc.terminate()
        return True
```
Use this version of `cancel()`.

- [ ] **Step 3: Implement `app/routers/jobs.py`**

```python
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import Job
from ..deps import get_db, get_runner, verify_csrf
from ..render import render

router = APIRouter()


def recent_jobs(db: Session, kind: str | None = None, limit: int = 20) -> list[Job]:
    stmt = select(Job).order_by(Job.id.desc()).limit(limit)
    if kind:
        stmt = stmt.where(Job.kind == kind)
    return list(db.scalars(stmt))


def job_summary(job: Job) -> str:
    try:
        p = json.loads(job.params_json or "{}")
    except json.JSONDecodeError:
        p = {}
    targets = p.get("targets") or []
    tpl = p.get("template_ids") or []
    parts = []
    if targets:
        parts.append(f"{len(targets)} target(s): " + ", ".join(targets[:3]) + ("…" if len(targets) > 3 else ""))
    if tpl:
        parts.append(f"{len(tpl)} template(s): " + ", ".join(tpl[:3]) + ("…" if len(tpl) > 3 else ""))
    if p.get("action"):
        parts.append(p["action"])
    return " · ".join(parts)


@router.get("/jobs")
def jobs_list(request: Request, db: Session = Depends(get_db)):
    jobs = recent_jobs(db, limit=200)
    return render(request, "jobs.html", active="jobs", jobs=jobs, job_summary=job_summary)


@router.get("/jobs/{job_id}")
def job_detail(request: Request, job_id: int, db: Session = Depends(get_db), runner=Depends(get_runner)):
    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(404)
    live = runner.is_live(job_id)
    log = "\n".join(runner.live_log(job_id)) if live else job.log
    try:
        params = json.loads(job.params_json or "{}")
    except json.JSONDecodeError:
        params = {}
    return render(request, "job_detail.html", active="jobs", job=job, log=log, live=live, params=params, summary=job_summary(job))


@router.get("/jobs/{job_id}/status")
def job_status(job_id: int, db: Session = Depends(get_db)):
    job = db.get(Job, job_id)
    if job is None:
        raise HTTPException(404)
    return JSONResponse({"id": job.id, "kind": job.kind, "status": job.status, "exit_code": job.exit_code})


@router.post("/jobs/{job_id}/cancel", dependencies=[Depends(verify_csrf)])
def job_cancel(job_id: int, runner=Depends(get_runner)):
    runner.cancel(job_id)
    return RedirectResponse(f"/jobs/{job_id}", status_code=303)


def _sse(event: str, data: str) -> str:
    payload = "\n".join(f"data: {line}" for line in (data.split("\n") or [""]))
    return f"event: {event}\n{payload}\n\n"


@router.get("/jobs/{job_id}/stream")
async def job_stream(request: Request, job_id: int, runner=Depends(get_runner)):
    async def gen():
        with request.app.state.SessionLocal() as db:
            job = db.get(Job, job_id)
            if job is None:
                yield _sse("error", "job not found")
                return
            status, stored_log = job.status, job.log
        q = runner.subscribe(job_id)
        try:
            if not runner.is_live(job_id):
                runner.unsubscribe(job_id, q)
                for line in stored_log.splitlines():
                    yield _sse("log", line)
                yield _sse("done", status)
                return
            snapshot = runner.live_log(job_id)
            for line in snapshot:
                yield _sse("log", line)
            next_idx = len(snapshot)
            while True:
                try:
                    item = await asyncio.wait_for(q.get(), timeout=15)
                except asyncio.TimeoutError:
                    if await request.is_disconnected():
                        return
                    yield ": ping\n\n"
                    continue
                if item is None:
                    break
                idx, line = item
                if idx < next_idx:
                    continue
                next_idx = idx + 1
                yield _sse("log", line)
            with request.app.state.SessionLocal() as db:
                job = db.get(Job, job_id)
                yield _sse("done", job.status if job else "done")
        finally:
            runner.unsubscribe(job_id, q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
```

- [ ] **Step 4: Templates and JS**

`app/templates/_jobs_table.html`:
```html
<table class="data">
  <thead><tr><th>#</th><th>Kind</th><th>Status</th><th>Summary</th><th>Started</th><th>Duration</th><th></th></tr></thead>
  <tbody>
  {% for j in jobs %}
  <tr>
    <td><a href="/jobs/{{ j.id }}">{{ j.id }}</a></td>
    <td>{{ j.kind }}</td>
    <td><span class="st-{{ j.status }}">{{ j.status }}</span></td>
    <td class="small">{{ job_summary(j) }}</td>
    <td class="small">{{ j.started_at.strftime('%Y-%m-%d %H:%M:%S') if j.started_at else '—' }}</td>
    <td class="small">{{ j.duration ~ 's' if j.duration is not none else '—' }}</td>
    <td class="small">
      {% if j.kind == 'nmap' and j.status == 'done' %}<a href="/inventory">inventory</a>{% endif %}
      {% if j.kind == 'nuclei' and j.status == 'done' %}<a href="/findings?job={{ j.id }}">findings</a>{% endif %}
    </td>
  </tr>
  {% else %}
  <tr><td colspan="7" class="muted">No jobs yet.</td></tr>
  {% endfor %}
  </tbody>
</table>
```

`app/templates/jobs.html`:
```html
{% extends "base.html" %}
{% block title %}Jobs · 0-Day Rapid Scanner{% endblock %}
{% block content %}
<h1>Jobs</h1>
<div class="card">{% include "_jobs_table.html" %}</div>
{% endblock %}
```

`app/templates/job_detail.html`:
```html
{% extends "base.html" %}
{% block title %}Job {{ job.id }} · 0-Day Rapid Scanner{% endblock %}
{% block content %}
<div class="row between">
  <h1>Job #{{ job.id }} · {{ job.kind }} · <span id="job-status" class="st-{{ job.status }}">{{ job.status }}</span></h1>
  <div class="row">
    {% if job.status in ('queued', 'running') %}
    <form method="post" action="/jobs/{{ job.id }}/cancel"><input type="hidden" name="csrf" value="{{ csrf }}"><button>Cancel</button></form>
    {% endif %}
    {% if job.kind == 'nmap' and job.status == 'done' %}<a class="btn" href="/inventory">View inventory →</a>{% endif %}
    {% if job.kind == 'nuclei' and job.status == 'done' %}<a class="btn" href="/findings?job={{ job.id }}">View findings →</a>{% endif %}
  </div>
</div>
<div class="card">
  <div class="muted small">{{ summary }}</div>
  <div class="mono small" style="margin:8px 0">$ {{ job.command }}</div>
  <div class="small muted">
    created {{ job.created_at.strftime('%Y-%m-%d %H:%M:%S') }}
    {% if job.started_at %} · started {{ job.started_at.strftime('%H:%M:%S') }}{% endif %}
    {% if job.finished_at %} · finished {{ job.finished_at.strftime('%H:%M:%S') }} ({{ job.duration }}s, exit {{ job.exit_code }}){% endif %}
  </div>
</div>
<pre class="log" id="joblog" data-job-id="{{ job.id }}" data-live="{{ 'yes' if live or job.status in ('queued','running') else 'no' }}">{{ log }}</pre>
{% endblock %}
```

`app/static/app.js` (replace the empty file; the template picker part is used in Task 11):
```js
(function () {
  // Live job log over Server-Sent Events
  const log = document.getElementById("joblog");
  if (log && log.dataset.live === "yes") {
    const id = log.dataset.jobId;
    const statusEl = document.getElementById("job-status");
    const es = new EventSource(`/jobs/${id}/stream`);
    log.textContent = "";
    es.addEventListener("log", (e) => {
      log.textContent += e.data + "\n";
      log.scrollTop = log.scrollHeight;
    });
    es.addEventListener("done", (e) => {
      es.close();
      if (statusEl) { statusEl.textContent = e.data; statusEl.className = "st-" + e.data; }
      setTimeout(() => location.reload(), 800);
    });
    es.addEventListener("error", () => { /* browser retries automatically */ });
  }

  // "select all" checkboxes: <input type=checkbox data-select-all="name">
  document.querySelectorAll("[data-select-all]").forEach((cb) => {
    cb.addEventListener("change", () => {
      document.querySelectorAll(`input[name="${cb.dataset.selectAll}"]`).forEach((x) => { x.checked = cb.checked; });
    });
  });

  // Nuclei template picker (page: /nuclei)
  const q = document.getElementById("tpl-q");
  if (q) {
    const results = document.getElementById("tpl-results");
    const selected = document.getElementById("tpl-selected");
    const count = document.getElementById("tpl-count");
    const sev = document.getElementById("tpl-sev");
    const src = document.getElementById("tpl-src");
    let timer = null;
    const refreshCount = () => { count.textContent = selected.children.length; };
    const isSelected = (p) => !!selected.querySelector(`li[data-path="${CSS.escape(p)}"]`);
    const addSel = (t) => {
      if (isSelected(t.path)) return;
      const li = document.createElement("li");
      li.dataset.path = t.path;
      li.innerHTML = '<input type="hidden" name="template_paths"><span class="badge"></span> <b></b> <span class="n muted"></span> <button type="button" class="link rm" title="remove">✕</button>';
      li.querySelector("input").value = t.path;
      const badge = li.querySelector(".badge"); badge.textContent = t.severity; badge.classList.add("sev-" + t.severity);
      li.querySelector("b").textContent = t.template_id;
      li.querySelector(".n").textContent = t.name;
      selected.appendChild(li);
      refreshCount();
    };
    selected.addEventListener("click", (e) => {
      if (e.target.classList.contains("rm")) { e.target.closest("li").remove(); refreshCount(); }
    });
    const search = async () => {
      const term = q.value.trim();
      if (term.length < 2) { results.innerHTML = ""; return; }
      const url = `/templates/search?q=${encodeURIComponent(term)}&severity=${encodeURIComponent(sev.value)}&source=${encodeURIComponent(src.value)}`;
      const r = await fetch(url);
      const items = await r.json();
      results.innerHTML = "";
      if (!items.length) { results.innerHTML = '<div class="tpl-item muted">No templates match.</div>'; return; }
      const all = document.createElement("div");
      all.className = "tpl-item";
      all.innerHTML = '<button type="button" class="btn small">Add all</button><span class="muted small"></span>';
      all.querySelector("span").textContent = `${items.length} result(s)`;
      all.querySelector("button").addEventListener("click", () => items.forEach(addSel));
      results.appendChild(all);
      items.forEach((t) => {
        const d = document.createElement("div");
        d.className = "tpl-item";
        d.innerHTML = '<span class="badge"></span><b></b><span class="n"></span><span class="muted small tags"></span><span class="badge src"></span>';
        const badge = d.querySelector(".badge"); badge.textContent = t.severity; badge.classList.add("sev-" + t.severity);
        d.querySelector("b").textContent = t.template_id;
        d.querySelector(".n").textContent = t.name;
        d.querySelector(".tags").textContent = t.tags;
        d.querySelector(".src").textContent = t.source;
        d.addEventListener("click", () => addSel(t));
        results.appendChild(d);
      });
    };
    q.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(search, 250); });
    sev.addEventListener("change", search);
    src.addEventListener("change", search);
    refreshCount();
  }
})();
```

- [ ] **Step 5: Wire into `app/main.py`**

In `create_app`, add imports and lines:
```python
from .jobs import JobRunner
from .routers import auth as auth_router, jobs as jobs_router
```
In `lifespan`, before `yield`:
```python
        app.state.job_runner = JobRunner(SessionLocal)
```
After `app.include_router(auth_router.router)`:
```python
    app.include_router(jobs_router.router)
```

- [ ] **Step 6: Run tests**

Run: `pytest tests/test_jobs.py -v`
Expected: 7 passed. If `test_cancel_running_job` reports `failed` instead of `cancelled`, confirm the `cancel()` version that adds to `_cancel_requested` is in place.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat: job runner with SSE log streaming and jobs pages"
```

---

### Task 8: Nmap scan page and inventory ingestion

**Files:**
- Modify: `app/scanners/nmap_runner.py` (add `ingest_nmap_results`, `on_nmap_complete`), `app/main.py`
- Create: `app/routers/nmap.py`, `app/templates/nmap.html`
- Test: `tests/test_nmap_scan.py`

- [ ] **Step 1: Write failing tests**

`tests/test_nmap_scan.py`:
```python
from pathlib import Path

from sqlalchemy import select

from app.db import Host, Job, Service, init_db, make_engine, make_session_factory
from app.scanners.nmap_runner import ingest_nmap_results
from tests.conftest import get_csrf, wait_job

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


def _db(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'i.db'}")
    init_db(engine)
    return make_session_factory(engine)


def test_ingest_upserts_hosts_and_replaces_services(tmp_path):
    SessionLocal = _db(tmp_path)
    with SessionLocal() as db:
        job = Job(kind="nmap", status="running")
        db.add(job)
        db.commit()
        stats = ingest_nmap_results(db, job, FIXTURE.read_text())
        db.commit()
        assert stats == {"hosts": 2, "services": 5}
        hosts = {h.address: h for h in db.scalars(select(Host))}
        assert set(hosts) == {"192.168.1.10", "192.168.1.12"}
        web = hosts["192.168.1.10"]
        assert web.hostname == "web01.lab"
        assert sorted(s.port for s in web.services) == [22, 80, 8080, 8443]
        php = next(s for s in web.services if s.port == 8080)
        assert php.product == "PHP cli server" and php.version == "8.3.10" and php.job_id == job.id
        assert next(s for s in web.services if s.port == 8443).tunnel == "ssl"

        # second scan of same host with fewer ports replaces the service set
        xml2 = FIXTURE.read_text().replace('<port protocol="tcp" portid="8080">', '<port protocol="tcp" portid="8081">')
        job2 = Job(kind="nmap", status="running")
        db.add(job2)
        db.commit()
        ingest_nmap_results(db, job2, xml2)
        db.commit()
        db.refresh(web)
        assert sorted(s.port for s in web.services) == [22, 80, 8081, 8443]
        assert db.scalar(select(Host).where(Host.address == "192.168.1.10")).last_job_id == job2.id
        assert len(list(db.scalars(select(Service)))) == 5


def test_nmap_page_renders(auth):
    r = auth.get("/nmap")
    assert r.status_code == 200
    assert "Start nmap scan" in r.text


def test_nmap_scan_rejects_bad_targets(auth):
    csrf = get_csrf(auth, "/nmap")
    r = auth.post("/nmap/scan", data={"csrf": csrf, "targets": "-oN /tmp/x", "port_mode": "top"})
    assert r.status_code == 400
    assert "Invalid nmap target" in r.text
    with auth.app.state.SessionLocal() as db:
        assert db.scalar(select(Job)) is None


def test_nmap_scan_end_to_end_with_fake_nmap(auth):
    csrf = get_csrf(auth, "/nmap")
    r = auth.post("/nmap/scan", data={"csrf": csrf, "targets": "192.168.1.0/24", "port_mode": "all", "scan_type": "connect", "timing": "T4", "skip_ping": "true"}, follow_redirects=False)
    assert r.status_code == 303
    job_id = int(r.headers["location"].rsplit("/", 1)[1])
    data = wait_job(auth, job_id)
    assert data["status"] == "done", auth.get(f"/jobs/{job_id}").text
    with auth.app.state.SessionLocal() as db:
        job = db.get(Job, job_id)
        assert "-sT" in job.command and "-p-" in job.command and "-Pn" in job.command and "-T4" in job.command
        assert "Starting Nmap 7.97 (fake)" in job.log
        assert "<nmaprun" not in job.log  # stdout (XML) is not copied into the log
        assert len(list(db.scalars(select(Host)))) == 2
```

Run: `pytest tests/test_nmap_scan.py -v`
Expected: FAIL with `ImportError: cannot import name 'ingest_nmap_results'`

- [ ] **Step 2: Add ingestion to `app/scanners/nmap_runner.py`**

Append to the file (add imports at top: `from sqlalchemy import select`, `from sqlalchemy.orm import Session`, `from ..db import Host, Job, Service, utcnow`, `from ..parsers.nmap_xml import parse_nmap_xml`):

```python
def ingest_nmap_results(db: Session, job: Job, xml_text: str) -> dict:
    """Upsert hosts; replace each seen host's service set with the ports found in this scan."""
    hosts = parse_nmap_xml(xml_text)
    now = utcnow()
    service_count = 0
    for h in hosts:
        host = db.scalar(select(Host).where(Host.address == h.address))
        if host is None:
            host = Host(address=h.address, first_seen=now)
            db.add(host)
            db.flush()
        if h.hostname:
            host.hostname = h.hostname
        host.last_seen = now
        host.last_job_id = job.id
        existing = {(s.port, s.protocol): s for s in host.services}
        seen: set[tuple[int, str]] = set()
        for p in h.ports:
            key = (p.port, p.protocol)
            seen.add(key)
            svc = existing.get(key)
            if svc is None:
                svc = Service(host=host, port=p.port, protocol=p.protocol)
                db.add(svc)
            svc.state = p.state
            svc.service_name = p.service
            svc.product = p.product
            svc.version = p.version
            svc.extra_info = p.extra_info
            svc.cpe = p.cpe
            svc.tunnel = p.tunnel
            svc.job_id = job.id
            service_count += 1
        for key, svc in existing.items():
            if key not in seen:
                db.delete(svc)
    db.flush()
    return {"hosts": len(hosts), "services": service_count}


def on_nmap_complete(db: Session, job: Job, output: str) -> None:
    stats = ingest_nmap_results(db, job, output)
    job.params_json = _merge_params(job.params_json, {"result": stats})


def _merge_params(params_json: str, extra: dict) -> str:
    import json
    try:
        p = json.loads(params_json or "{}")
    except json.JSONDecodeError:
        p = {}
    p.update(extra)
    return json.dumps(p)
```

(Task 12 adds a rules evaluation call inside `on_nmap_complete`.)

- [ ] **Step 3: Create `app/routers/nmap.py`**

```python
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..deps import get_db, get_runner, get_settings, verify_csrf
from ..render import render
from ..scanners.nmap_runner import build_nmap_argv, on_nmap_complete
from ..validation import parse_nmap_targets
from .jobs import job_summary, recent_jobs

router = APIRouter()

DEFAULT_FORM = {"targets": "", "port_mode": "top", "custom_ports": "", "timing": "T3", "skip_ping": False, "scan_type": "syn"}


def _page(request: Request, db: Session, form: dict, error: str | None = None, status_code: int = 200):
    return render(request, "nmap.html", status_code=status_code, active="nmap", form=form, error=error,
                  jobs=recent_jobs(db, kind="nmap"), job_summary=job_summary)


@router.get("/nmap")
def nmap_page(request: Request, db: Session = Depends(get_db)):
    return _page(request, db, dict(DEFAULT_FORM))


@router.post("/nmap/scan", dependencies=[Depends(verify_csrf)])
def nmap_scan(request: Request, targets: str = Form(""), port_mode: str = Form("top"), custom_ports: str = Form(""),
              timing: str = Form("T3"), skip_ping: bool = Form(False), scan_type: str = Form("syn"),
              db: Session = Depends(get_db), settings=Depends(get_settings), runner=Depends(get_runner)):
    form = {"targets": targets, "port_mode": port_mode, "custom_ports": custom_ports, "timing": timing,
            "skip_ping": skip_ping, "scan_type": scan_type}
    try:
        target_list = parse_nmap_targets(targets)
        argv = build_nmap_argv(settings.nmap_bin, target_list, port_mode=port_mode, custom_ports=custom_ports,
                               timing=timing, skip_ping=skip_ping, scan_type=scan_type)
    except ValueError as e:
        return _page(request, db, form, error=str(e), status_code=400)
    job = runner.create_job(db, "nmap", argv, params={"targets": target_list, "port_mode": port_mode,
                                                      "custom_ports": custom_ports, "scan_type": scan_type})
    runner.start(job.id, argv, on_complete=on_nmap_complete, stdout_to_log=False)
    return RedirectResponse(f"/jobs/{job.id}", status_code=303)
```

- [ ] **Step 4: Create `app/templates/nmap.html`**

```html
{% extends "base.html" %}
{% block title %}Nmap · 0-Day Rapid Scanner{% endblock %}
{% block content %}
<h1>Nmap scan</h1>
<div class="grid-2">
  <form method="post" action="/nmap/scan" class="card stack">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <label>Targets (one per line: IP, CIDR, range, hostname)
      <textarea name="targets" rows="6" required placeholder="192.168.1.0/24&#10;scanme.nmap.org&#10;10.0.0.1-50">{{ form.targets }}</textarea></label>
    <fieldset><legend>Ports</legend>
      <label class="inline"><input type="radio" name="port_mode" value="top" {{ 'checked' if form.port_mode == 'top' }}> Well-known (top 1000)</label>
      <label class="inline"><input type="radio" name="port_mode" value="all" {{ 'checked' if form.port_mode == 'all' }}> All ports (1-65535)</label>
      <label class="inline"><input type="radio" name="port_mode" value="custom" {{ 'checked' if form.port_mode == 'custom' }}> Custom
        <input name="custom_ports" placeholder="22,80,443,8000-9000" value="{{ form.custom_ports }}"></label>
    </fieldset>
    <div class="row">
      <label>Scan type
        <select name="scan_type">
          <option value="syn" {{ 'selected' if form.scan_type == 'syn' }}>SYN (-sS, fast, needs NET_RAW)</option>
          <option value="connect" {{ 'selected' if form.scan_type == 'connect' }}>Connect (-sT, no privileges)</option>
        </select></label>
      <label>Timing
        <select name="timing">
          <option value="T2" {{ 'selected' if form.timing == 'T2' }}>T2 polite</option>
          <option value="T3" {{ 'selected' if form.timing == 'T3' }}>T3 normal</option>
          <option value="T4" {{ 'selected' if form.timing == 'T4' }}>T4 aggressive</option>
        </select></label>
      <label class="inline"><input type="checkbox" name="skip_ping" value="true" {{ 'checked' if form.skip_ping }}> Skip host discovery (-Pn)</label>
    </div>
    <p class="muted small">Service/version detection (-sV) is always on. Output is parsed into the inventory when the job finishes.</p>
    <button class="primary">Start nmap scan</button>
  </form>
  <div class="card">
    <h2>Recent nmap jobs</h2>
    {% include "_jobs_table.html" %}
  </div>
</div>
{% endblock %}
```

- [ ] **Step 5: Register the router in `app/main.py`**

```python
from .routers import auth as auth_router, jobs as jobs_router, nmap as nmap_router
...
    app.include_router(nmap_router.router)
```

- [ ] **Step 6: Run tests**

Run: `pytest tests/test_nmap_scan.py -v`
Expected: 4 passed

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat: nmap scan page and inventory ingestion"
```

---

### Task 9: Inventory page with filters and hand-off to nuclei

**Files:**
- Create: `app/routers/inventory.py`, `app/templates/inventory.html`
- Modify: `app/main.py`
- Test: `tests/test_inventory.py`

The nuclei page (`/nuclei`) is built in Task 11; this task's `to-nuclei` handler renders `nuclei.html`, so Task 9 creates a minimal `nuclei.html` placeholder that Task 11 replaces.

- [ ] **Step 1: Write failing tests**

`tests/test_inventory.py`:
```python
from pathlib import Path

from app.db import Job
from app.routers.inventory import service_to_target
from app.scanners.nmap_runner import ingest_nmap_results
from tests.conftest import get_csrf

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


def seed_inventory(client):
    with client.app.state.SessionLocal() as db:
        job = Job(kind="nmap", status="done")
        db.add(job)
        db.commit()
        ingest_nmap_results(db, job, FIXTURE.read_text())
        db.commit()


class _Svc:
    def __init__(self, port, name, tunnel=""):
        self.port, self.service_name, self.tunnel = port, name, tunnel


def test_service_to_target():
    assert service_to_target("10.0.0.1", _Svc(80, "http")) == "http://10.0.0.1:80"
    assert service_to_target("10.0.0.1", _Svc(8443, "http", "ssl")) == "https://10.0.0.1:8443"
    assert service_to_target("10.0.0.1", _Svc(443, "https")) == "https://10.0.0.1:443"
    assert service_to_target("10.0.0.1", _Svc(22, "ssh")) == "10.0.0.1:22"


def test_inventory_lists_and_filters(auth):
    seed_inventory(auth)
    r = auth.get("/inventory")
    assert r.status_code == 200
    assert "192.168.1.10" in r.text and "192.168.1.12" in r.text and "OpenSSH" in r.text
    r = auth.get("/inventory?q=php")
    assert "PHP cli server" in r.text and "OpenSSH" not in r.text
    r = auth.get("/inventory?product=nginx")
    assert "nginx" in r.text and "OpenSSH" not in r.text
    r = auth.get("/inventory?port=3306")
    assert "192.168.1.12" in r.text and "192.168.1.10" not in r.text


def test_to_nuclei_prefills_targets(auth):
    seed_inventory(auth)
    with auth.app.state.SessionLocal() as db:
        from sqlalchemy import select
        from app.db import Service
        ids = [str(s.id) for s in db.scalars(select(Service)) if s.port in (80, 8443, 22)]
    csrf = get_csrf(auth, "/inventory")
    r = auth.post("/inventory/to-nuclei", data=[("csrf", csrf)] + [("service_ids", i) for i in ids])
    assert r.status_code == 200
    assert "http://192.168.1.10:80" in r.text
    assert "https://192.168.1.10:8443" in r.text
    assert "192.168.1.10:22" in r.text


def test_to_nuclei_without_selection_errors(auth):
    csrf = get_csrf(auth, "/inventory")
    r = auth.post("/inventory/to-nuclei", data={"csrf": csrf})
    assert r.status_code == 400 and "Select at least one" in r.text
```

Run: `pytest tests/test_inventory.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.routers.inventory'`

- [ ] **Step 2: Create `app/routers/inventory.py`**

```python
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import Host, Rule, RuleMatch, Service
from ..deps import get_db, verify_csrf
from ..render import render

router = APIRouter()

HTTP_NAMES = {"http", "http-proxy", "http-alt", "www", "www-http", "webcache", "http-mgmt"}
HTTPS_NAMES = {"https", "https-alt", "ssl/http", "ssl"}


def service_to_target(address: str, svc) -> str:
    name = (svc.service_name or "").lower()
    if (svc.tunnel or "") == "ssl" and name in HTTP_NAMES or name in HTTPS_NAMES:
        return f"https://{address}:{svc.port}"
    if name in HTTP_NAMES:
        return f"http://{address}:{svc.port}"
    return f"{address}:{svc.port}"


def rule_matches_by_service(db: Session) -> dict[int, list[tuple[RuleMatch, Rule]]]:
    out: dict[int, list[tuple[RuleMatch, Rule]]] = {}
    for m, r in db.execute(select(RuleMatch, Rule).join(Rule, Rule.id == RuleMatch.rule_id)).all():
        out.setdefault(m.service_id, []).append((m, r))
    return out


def load_inventory(db: Session, q: str = "", product: str = "", port: str = "", only_matches: bool = False):
    rows = db.execute(select(Service, Host).join(Host, Host.id == Service.host_id).order_by(Host.address, Service.port)).all()
    matches = rule_matches_by_service(db)
    products = sorted({s.product for s, _ in rows if s.product})
    ql = q.strip().lower()
    out = []
    for svc, host in rows:
        if product and svc.product != product:
            continue
        if port and str(svc.port) != port.strip():
            continue
        if only_matches and svc.id not in matches:
            continue
        if ql:
            hay = " ".join([host.address, host.hostname or "", svc.service_name, svc.product, svc.version, svc.cpe, svc.extra_info]).lower()
            if ql not in hay:
                continue
        out.append((svc, host))
    return out, products, matches


@router.get("/inventory")
def inventory(request: Request, q: str = "", product: str = "", port: str = "", only_matches: bool = False,
              db: Session = Depends(get_db)):
    rows, products, matches = load_inventory(db, q, product, port, only_matches)
    host_count = len({h.id for _, h in rows})
    return render(request, "inventory.html", active="inventory", rows=rows, products=products, matches=matches,
                  host_count=host_count, q=q, product=product, port=port, only_matches=only_matches)


@router.post("/inventory/to-nuclei", dependencies=[Depends(verify_csrf)])
def to_nuclei(request: Request, service_ids: list[int] = Form(default=[]), db: Session = Depends(get_db)):
    if not service_ids:
        rows, products, matches = load_inventory(db)
        return render(request, "inventory.html", status_code=400, active="inventory", rows=rows, products=products,
                      matches=matches, host_count=len({h.id for _, h in rows}), q="", product="", port="",
                      only_matches=False, error="Select at least one service to scan.")
    rows = db.execute(select(Service, Host).join(Host, Host.id == Service.host_id).where(Service.id.in_(service_ids))
                      .order_by(Host.address, Service.port)).all()
    targets = "\n".join(service_to_target(host.address, svc) for svc, host in rows)
    from .nuclei import nuclei_page_context  # local import: nuclei router imports inventory helpers
    return render(request, "nuclei.html", **nuclei_page_context(db, targets=targets))
```

- [ ] **Step 3: Create `app/templates/inventory.html`**

```html
{% extends "base.html" %}
{% block title %}Inventory · 0-Day Rapid Scanner{% endblock %}
{% block content %}
<h1>Inventory</h1>
<form method="get" action="/inventory" class="card row">
  <label>Search <input name="q" placeholder="address, hostname, product, version, cpe" value="{{ q }}" size="36"></label>
  <label>Product
    <select name="product"><option value="">All products</option>
      {% for p in products %}<option value="{{ p }}" {{ 'selected' if p == product }}>{{ p }}</option>{% endfor %}
    </select></label>
  <label>Port <input name="port" value="{{ port }}" size="6"></label>
  <label class="inline"><input type="checkbox" name="only_matches" value="true" {{ 'checked' if only_matches }}> Only 0-day rule matches</label>
  <button>Filter</button>
  <a class="btn" href="/inventory">Reset</a>
</form>
<form method="post" action="/inventory/to-nuclei" class="card">
  <input type="hidden" name="csrf" value="{{ csrf }}">
  <div class="row between" style="margin-bottom:10px">
    <span class="muted">{{ rows|length }} service(s) on {{ host_count }} host(s)</span>
    <button class="primary" type="submit">Scan selected with nuclei →</button>
  </div>
  <table class="data">
    <thead><tr>
      <th><input type="checkbox" data-select-all="service_ids" title="select all"></th>
      <th>Host</th><th>Hostname</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Extra</th><th>CPE</th><th>0-day rule</th><th>Last seen</th>
    </tr></thead>
    <tbody>
    {% for svc, host in rows %}
    <tr>
      <td><input type="checkbox" name="service_ids" value="{{ svc.id }}"></td>
      <td class="mono">{{ host.address }}</td>
      <td class="small">{{ host.hostname or '' }}</td>
      <td class="mono">{{ svc.port }}/{{ svc.protocol }}{% if svc.tunnel %} <span class="badge">{{ svc.tunnel }}</span>{% endif %}</td>
      <td>{{ svc.service_name }}</td>
      <td>{{ svc.product }}</td>
      <td class="mono">{{ svc.version }}</td>
      <td class="small muted">{{ svc.extra_info }}</td>
      <td class="mono small">{{ svc.cpe }}</td>
      <td>{% for m, r in matches.get(svc.id, []) %}<span class="badge sev-{{ r.severity }}" title="{{ r.name }}: {{ r.product_pattern }} {{ r.version_constraint }}">{{ r.cve_id or r.name }}</span>{% endfor %}</td>
      <td class="small">{{ host.last_seen.strftime('%Y-%m-%d %H:%M') }}</td>
    </tr>
    {% else %}
    <tr><td colspan="11" class="muted">No services found. Run an <a href="/nmap">nmap scan</a> first.</td></tr>
    {% endfor %}
    </tbody>
  </table>
</form>
{% endblock %}
```

- [ ] **Step 4: Placeholder nuclei context + template (replaced in Task 11)**

Create `app/routers/nuclei.py` with only:
```python
from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy.orm import Session

router = APIRouter()

DEFAULT_NUCLEI_FORM = {"targets": "", "selected": [], "rate_limit": 150, "timeout": 10}


def nuclei_page_context(db: Session, targets: str = "", selected=None, error: str | None = None, **extra) -> dict:
    form = dict(DEFAULT_NUCLEI_FORM)
    form["targets"] = targets
    form["selected"] = selected or []
    form.update(extra)
    return {"active": "nuclei", "form": form, "error": error, "jobs": [], "job_summary": lambda j: ""}
```

Create `app/templates/nuclei.html` placeholder:
```html
{% extends "base.html" %}
{% block content %}
<h1>Nuclei scan</h1>
<textarea name="targets">{{ form.targets }}</textarea>
{% endblock %}
```

Register in `app/main.py`:
```python
from .routers import auth as auth_router, inventory as inventory_router, jobs as jobs_router, nmap as nmap_router, nuclei as nuclei_router
...
    app.include_router(inventory_router.router)
    app.include_router(nuclei_router.router)
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_inventory.py -v`
Expected: 4 passed

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: inventory page with filters and nuclei hand-off"
```

---

### Task 10: Template index, search, custom upload, pull from URL

**Files:**
- Create: `app/templates_index.py`, `app/routers/templates.py`, `app/templates/templates.html`, `tests/fixtures/templates/http/technologies/php-detect.yaml`, `tests/fixtures/templates/http/cves/2026/CVE-2026-109619.yaml`
- Modify: `app/main.py` (background reindex on startup)
- Test: `tests/test_templates_index.py`

- [ ] **Step 1: Create fixture templates**

`tests/fixtures/templates/http/technologies/php-detect.yaml`:
```yaml
id: php-detect

info:
  name: PHP Detect
  author: test
  severity: info
  description: Detects PHP via the X-Powered-By header.
  tags: tech,php

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        regex:
          - "(?i)X-Powered-By: PHP"
    extractors:
      - type: regex
        part: header
        group: 1
        regex:
          - "(?i)X-Powered-By: PHP/([0-9.]+)"
```

`tests/fixtures/templates/http/cves/2026/CVE-2026-109619.yaml`:
```yaml
id: CVE-2026-109619

info:
  name: PHP use-after-free vulnerability check
  author: test
  severity: critical
  description: Passive PHP version check for CVE-2026-109619.
  classification:
    cve-id: CVE-2026-109619
    cvss-score: 9.8
  tags: cve,cve2026,php,uaf

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: regex
        part: header
        regex:
          - "(?i)X-Powered-By: PHP/8\\.3\\.(?:[0-9]|1[0-4])\\b"
```

- [ ] **Step 2: Write failing tests**

`tests/test_templates_index.py`:
```python
import io
from pathlib import Path

import pytest
from sqlalchemy import select

from app.db import TemplateIndex
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
        # severity ordering: critical first
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
    import app.routers.templates as tmod
    monkeypatch.setattr(tmod, "http_fetch", lambda url: (200, CUSTOM_YAML))
    csrf = get_csrf(auth, "/templates")
    r = auth.post("/templates/pull", data={"csrf": csrf, "url": "https://raw.githubusercontent.com/x/y/CVE.yaml"}, follow_redirects=False)
    assert r.status_code == 303, r.text
    assert (auth.app.state.settings.custom_templates_dir / "zero-day-example.yaml").exists()
```

Run: `pytest tests/test_templates_index.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.templates_index'`

- [ ] **Step 3: Implement `app/templates_index.py`**

```python
"""Index nuclei templates (official + custom) into the DB for fast search; manage custom templates."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import httpx
import yaml
from sqlalchemy import and_, delete, or_, select
from sqlalchemy.orm import Session

from .config import Settings
from .db import TemplateIndex, utcnow
from .render import SEVERITY_ORDER, normalize_severity

try:
    _Loader = yaml.CSafeLoader
except AttributeError:  # libyaml not available
    _Loader = yaml.SafeLoader

_TEMPLATE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$")
MAX_TEMPLATE_BYTES = 10 * 1024 * 1024
SKIP_DIRS = {".git", ".github", "helpers", "workflows", "profiles"}


@dataclass
class TemplateInfo:
    template_id: str
    path: str
    name: str
    severity: str
    tags: str
    cve_ids: str
    source: str


def _as_csv(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ",".join(str(v).strip() for v in value if str(v).strip())
    return ",".join(p.strip() for p in str(value).split(",") if p.strip())


def _info_from_doc(doc, path: str, source: str) -> TemplateInfo | None:
    if not isinstance(doc, dict):
        return None
    tid = doc.get("id")
    info = doc.get("info")
    if not isinstance(tid, str) or not isinstance(info, dict):
        return None
    classification = info.get("classification") or {}
    cve = classification.get("cve-id") if isinstance(classification, dict) else None
    return TemplateInfo(
        template_id=tid.strip(),
        path=path,
        name=str(info.get("name") or "").strip(),
        severity=normalize_severity(info.get("severity")),
        tags=_as_csv(info.get("tags")),
        cve_ids=_as_csv(cve),
        source=source,
    )


def read_template_info(path: Path, source: str) -> TemplateInfo | None:
    try:
        with open(path, "rb") as f:
            doc = yaml.load(f, Loader=_Loader)
    except (yaml.YAMLError, OSError, UnicodeDecodeError):
        return None
    return _info_from_doc(doc, str(path), source)


def scan_templates_dir(root: Path, source: str) -> list[TemplateInfo]:
    if not root.is_dir():
        return []
    infos: list[TemplateInfo] = []
    for p in sorted(root.rglob("*")):
        if p.suffix not in (".yaml", ".yml") or not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts[:-1]):
            continue
        info = read_template_info(p, source)
        if info is not None:
            infos.append(info)
    return infos


def reindex(db: Session, settings: Settings) -> dict:
    official = scan_templates_dir(settings.nuclei_templates_dir, "official")
    custom = scan_templates_dir(settings.custom_templates_dir, "custom")
    db.execute(delete(TemplateIndex))
    now = utcnow()
    seen: set[str] = set()
    rows = []
    for info in official + custom:
        if info.path in seen:
            continue
        seen.add(info.path)
        rows.append(dict(template_id=info.template_id, path=info.path, name=info.name, severity=info.severity,
                         tags=info.tags, cve_ids=info.cve_ids, source=info.source, indexed_at=now))
    if rows:
        db.execute(TemplateIndex.__table__.insert(), rows)
    db.commit()
    return {"official": len(official), "custom": len(custom)}


def index_single(db: Session, path: Path, source: str) -> TemplateInfo | None:
    info = read_template_info(path, source)
    if info is None:
        return None
    row = db.scalar(select(TemplateIndex).where(TemplateIndex.path == str(path)))
    if row is None:
        row = TemplateIndex(path=str(path))
        db.add(row)
    row.template_id, row.name, row.severity = info.template_id, info.name, info.severity
    row.tags, row.cve_ids, row.source, row.indexed_at = info.tags, info.cve_ids, info.source, utcnow()
    db.commit()
    return info


def remove_from_index(db: Session, path: Path) -> None:
    db.execute(delete(TemplateIndex).where(TemplateIndex.path == str(path)))
    db.commit()


def search_templates(db: Session, q: str, severity: str = "", source: str = "", limit: int = 100) -> list[TemplateIndex]:
    terms = [t for t in (q or "").lower().split() if t]
    if not terms:
        return []
    conds = []
    for t in terms:
        like = f"%{t}%"
        conds.append(or_(TemplateIndex.template_id.ilike(like), TemplateIndex.name.ilike(like),
                         TemplateIndex.tags.ilike(like), TemplateIndex.cve_ids.ilike(like)))
    stmt = select(TemplateIndex).where(and_(*conds))
    if severity:
        stmt = stmt.where(TemplateIndex.severity == severity)
    if source:
        stmt = stmt.where(TemplateIndex.source == source)
    rows = list(db.scalars(stmt.limit(2000)))
    rows.sort(key=lambda r: (SEVERITY_ORDER.get(r.severity, 99), r.template_id.lower()))
    return rows[:limit]


def count_templates(db: Session) -> dict:
    rows = db.execute(select(TemplateIndex.source, TemplateIndex.indexed_at)).all()
    counts = {"official": 0, "custom": 0, "last_indexed": None}
    for source, at in rows:
        counts[source] = counts.get(source, 0) + 1
        if counts["last_indexed"] is None or at > counts["last_indexed"]:
            counts["last_indexed"] = at
    return counts


def validate_template_yaml(text: str) -> TemplateInfo:
    if len(text.encode("utf-8", "replace")) > MAX_TEMPLATE_BYTES:
        raise ValueError("Template is larger than 10 MB.")
    try:
        doc = yaml.load(text, Loader=_Loader)
    except yaml.YAMLError as e:
        raise ValueError(f"Not valid YAML: {e}") from e
    info = _info_from_doc(doc, "", "custom")
    if info is None:
        raise ValueError("Not a nuclei template: needs a top-level 'id' and an 'info' mapping.")
    if not info.name:
        raise ValueError("Template 'info.name' is required.")
    if not _TEMPLATE_ID_RE.match(info.template_id):
        raise ValueError("Template 'id' may only contain letters, digits, '.', '_' and '-'.")
    return info


def save_custom_template(settings: Settings, text: str) -> Path:
    info = validate_template_yaml(text)
    path = settings.custom_templates_dir / f"{info.template_id}.yaml"
    path.write_text(text)
    return path


def is_custom_path(settings: Settings, path: str) -> bool:
    try:
        resolved = Path(path).resolve()
        return resolved.is_relative_to(settings.custom_templates_dir.resolve()) and resolved.suffix in (".yaml", ".yml")
    except (OSError, ValueError):
        return False


def http_fetch(url: str) -> tuple[int, str]:
    with httpx.Client(timeout=30, follow_redirects=True, headers={"User-Agent": "zero-day-rapid-scanner"}) as c:
        with c.stream("GET", url) as r:
            chunks = []
            size = 0
            for chunk in r.iter_bytes():
                size += len(chunk)
                if size > MAX_TEMPLATE_BYTES:
                    raise ValueError("Download exceeds 10 MB.")
                chunks.append(chunk)
            return r.status_code, b"".join(chunks).decode("utf-8", "replace")


def fetch_template_from_url(url: str, fetch: Callable[[str], tuple[int, str]] | None = None) -> str:
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("URL must start with http:// or https://")
    fetch = fetch or http_fetch
    try:
        status, text = fetch(url)
    except (httpx.HTTPError, OSError) as e:
        raise ValueError(f"Download failed: {e}") from e
    if status != 200:
        raise ValueError(f"Download failed with HTTP {status}.")
    if len(text.encode("utf-8", "replace")) > MAX_TEMPLATE_BYTES:
        raise ValueError("Download exceeds 10 MB.")
    return text
```

- [ ] **Step 4: Implement `app/routers/templates.py`**

```python
from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import TemplateIndex
from ..deps import get_db, get_settings, verify_csrf
from ..render import render
from ..templates_index import (count_templates, fetch_template_from_url, http_fetch, index_single, is_custom_path,
                               reindex, remove_from_index, save_custom_template, search_templates)

router = APIRouter()


async def reindex_in_background(app) -> None:
    if getattr(app.state, "indexing", False):
        return
    app.state.indexing = True
    try:
        def _work():
            with app.state.SessionLocal() as db:
                return reindex(db, app.state.settings)
        app.state.last_index_counts = await asyncio.to_thread(_work)
    finally:
        app.state.indexing = False


async def nuclei_validate(settings, path: Path) -> tuple[bool, str]:
    """Run `nuclei -validate` on one template; returns (ok, last_output_line)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            settings.nuclei_bin, "-validate", "-t", str(path), "-ud", str(settings.nuclei_templates_dir),
            "-disable-update-check", "-no-color",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
    except FileNotFoundError:
        return True, "nuclei binary not found; skipped engine validation"
    except asyncio.TimeoutError:
        return False, "nuclei -validate timed out"
    text = out.decode("utf-8", "replace").strip()
    last = text.splitlines()[-1] if text else ""
    return proc.returncode == 0, last


def _page(request: Request, db: Session, settings, q: str = "", severity: str = "", error: str | None = None, status_code: int = 200):
    custom = list(db.scalars(select(TemplateIndex).where(TemplateIndex.source == "custom").order_by(TemplateIndex.template_id)))
    results = search_templates(db, q, severity=severity) if q else []
    return render(request, "templates.html", status_code=status_code, active="templates", counts=count_templates(db),
                  indexing=getattr(request.app.state, "indexing", False), custom=custom, q=q, severity=severity,
                  results=results, error=error, templates_dir=str(settings.nuclei_templates_dir),
                  templates_dir_exists=settings.nuclei_templates_dir.is_dir())


@router.get("/templates")
def templates_page(request: Request, q: str = "", severity: str = "", db: Session = Depends(get_db), settings=Depends(get_settings)):
    return _page(request, db, settings, q=q, severity=severity)


@router.get("/templates/search")
def templates_search(q: str = "", severity: str = "", source: str = "", db: Session = Depends(get_db)):
    rows = search_templates(db, q, severity=severity, source=source)
    return JSONResponse([{"template_id": r.template_id, "name": r.name, "severity": r.severity, "tags": r.tags,
                          "cve_ids": r.cve_ids, "source": r.source, "path": r.path} for r in rows])


@router.post("/templates/reindex", dependencies=[Depends(verify_csrf)])
async def templates_reindex(request: Request):
    asyncio.get_running_loop().create_task(reindex_in_background(request.app))
    return RedirectResponse("/templates?msg=Re-indexing+started", status_code=303)


@router.post("/templates/upload", dependencies=[Depends(verify_csrf)])
async def templates_upload(request: Request, files: list[UploadFile], db: Session = Depends(get_db), settings=Depends(get_settings)):
    saved, errors = [], []
    for f in files:
        raw = await f.read()
        text = raw.decode("utf-8", "replace")
        try:
            path = save_custom_template(settings, text)
        except ValueError as e:
            errors.append(f"{f.filename}: {e}")
            continue
        ok, line = await nuclei_validate(settings, path)
        if not ok:
            path.unlink(missing_ok=True)
            errors.append(f"{f.filename}: nuclei validation failed: {line}")
            continue
        index_single(db, path, "custom")
        saved.append(path.name)
    if errors:
        return _page(request, db, settings, error="; ".join(errors), status_code=400)
    return RedirectResponse(f"/templates?msg=Saved+{len(saved)}+template(s)", status_code=303)


@router.post("/templates/pull", dependencies=[Depends(verify_csrf)])
async def templates_pull(request: Request, url: str = Form(""), db: Session = Depends(get_db), settings=Depends(get_settings)):
    try:
        text = await asyncio.to_thread(fetch_template_from_url, url.strip(), http_fetch)
        path = save_custom_template(settings, text)
    except ValueError as e:
        return _page(request, db, settings, error=str(e), status_code=400)
    ok, line = await nuclei_validate(settings, path)
    if not ok:
        path.unlink(missing_ok=True)
        return _page(request, db, settings, error=f"nuclei validation failed: {line}", status_code=400)
    index_single(db, path, "custom")
    return RedirectResponse(f"/templates?msg=Pulled+{path.name}", status_code=303)


@router.post("/templates/delete", dependencies=[Depends(verify_csrf)])
def templates_delete(request: Request, path: str = Form(""), db: Session = Depends(get_db), settings=Depends(get_settings)):
    if not is_custom_path(settings, path):
        return _page(request, db, settings, error="Only custom templates can be deleted.", status_code=400)
    p = Path(path)
    p.unlink(missing_ok=True)
    remove_from_index(db, p)
    return RedirectResponse(f"/templates?msg=Deleted+{p.name}", status_code=303)
```

Note: the `pull` test monkeypatches `tmod.http_fetch`; the handler must therefore reference `http_fetch` through the module global at call time, which the code above does (`fetch_template_from_url(..., http_fetch)` is evaluated inside the handler).

- [ ] **Step 5: Create `app/templates/templates.html`**

```html
{% extends "base.html" %}
{% block title %}Templates · 0-Day Rapid Scanner{% endblock %}
{% block content %}
<h1>Nuclei templates</h1>
<div class="grid-3 stats">
  <div class="stat"><b>{{ counts.official }}</b><span>official templates indexed</span></div>
  <div class="stat"><b>{{ counts.custom }}</b><span>custom (0-day) templates</span></div>
  <div class="stat"><b>{{ counts.last_indexed.strftime('%Y-%m-%d %H:%M') if counts.last_indexed else 'never' }}</b>
    <span>last indexed{% if indexing %} · <span class="warn">indexing now…</span>{% endif %}</span></div>
</div>
{% if not templates_dir_exists %}
<div class="flash err">Official templates directory <code>{{ templates_dir }}</code> does not exist yet. Go to <a href="/updates">Updates</a> and run "Update nuclei templates".</div>
{% endif %}
<div class="grid-2">
  <form method="post" action="/templates/upload" enctype="multipart/form-data" class="card stack">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <h2>Upload custom templates (0-day)</h2>
    <p class="muted small">YAML files are validated (structure + <code>nuclei -validate</code>) and stored under <code>custom-templates/&lt;id&gt;.yaml</code>. Uploading the same id overwrites.</p>
    <input type="file" name="files" accept=".yaml,.yml" multiple required>
    <button class="primary">Upload &amp; validate</button>
  </form>
  <form method="post" action="/templates/pull" class="card stack">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <h2>Pull template from URL</h2>
    <p class="muted small">Raw YAML over http(s), max 10 MB. Example: a raw GitHub/Gist link of a freshly published CVE template.</p>
    <input name="url" type="url" placeholder="https://raw.githubusercontent.com/.../CVE-2026-xxxxx.yaml" required>
    <button class="primary">Pull &amp; validate</button>
  </form>
</div>
<div class="card">
  <div class="row between">
    <h2>Custom templates ({{ custom|length }})</h2>
    <form method="post" action="/templates/reindex"><input type="hidden" name="csrf" value="{{ csrf }}"><button {{ 'disabled' if indexing }}>Re-index all templates</button></form>
  </div>
  <table class="data">
    <thead><tr><th>ID</th><th>Name</th><th>Severity</th><th>Tags</th><th>CVE</th><th></th></tr></thead>
    <tbody>
    {% for t in custom %}
    <tr>
      <td class="mono">{{ t.template_id }}</td><td>{{ t.name }}</td>
      <td><span class="badge sev-{{ t.severity }}">{{ t.severity }}</span></td>
      <td class="small">{{ t.tags }}</td><td class="mono small">{{ t.cve_ids }}</td>
      <td><form method="post" action="/templates/delete"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="path" value="{{ t.path }}"><button class="link danger">delete</button></form></td>
    </tr>
    {% else %}<tr><td colspan="6" class="muted">No custom templates yet.</td></tr>{% endfor %}
    </tbody>
  </table>
</div>
<div class="card">
  <h2>Search the index</h2>
  <form method="get" action="/templates" class="row">
    <label>Query <input name="q" value="{{ q }}" placeholder="CVE-2026-109619, php, apache …" size="40"></label>
    <label>Severity <select name="severity"><option value="">any</option>{% for s in severities %}<option value="{{ s }}" {{ 'selected' if s == severity }}>{{ s }}</option>{% endfor %}</select></label>
    <button>Search</button>
  </form>
  {% if q %}
  <table class="data" style="margin-top:12px">
    <thead><tr><th>ID</th><th>Name</th><th>Severity</th><th>Tags</th><th>Source</th><th>Path</th></tr></thead>
    <tbody>
    {% for t in results %}
    <tr><td class="mono">{{ t.template_id }}</td><td>{{ t.name }}</td><td><span class="badge sev-{{ t.severity }}">{{ t.severity }}</span></td><td class="small">{{ t.tags }}</td><td>{{ t.source }}</td><td class="mono small">{{ t.path }}</td></tr>
    {% else %}<tr><td colspan="6" class="muted">No templates match "{{ q }}".</td></tr>{% endfor %}
    </tbody>
  </table>
  <p class="muted small">Showing up to 100 results. Use the <a href="/nuclei">Nuclei</a> page to pick templates for a scan.</p>
  {% endif %}
</div>
{% endblock %}
```

- [ ] **Step 6: Wire into `app/main.py`**

Add import `from .routers import templates as templates_router` and `from .routers.templates import reindex_in_background`. In `lifespan` before `yield`:
```python
        app.state.indexing = False
        app.state.last_index_counts = None
        with SessionLocal() as db:
            from sqlalchemy import select
            from .db import TemplateIndex
            needs_index = db.scalar(select(TemplateIndex).limit(1)) is None
        if needs_index:
            asyncio.get_running_loop().create_task(reindex_in_background(app))
```
(add `import asyncio` at top). Register: `app.include_router(templates_router.router)`.

- [ ] **Step 7: Run tests**

Run: `pytest tests/test_templates_index.py -v`
Expected: 8 passed. If `test_reindex_and_search` fails on the severity ordering, check `search_templates` sorts with `SEVERITY_ORDER`.

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "feat: template index, search, custom upload and URL pull"
```

---

### Task 11: Nuclei scan page (template picker, single/multi select) and findings

**Files:**
- Create: `app/scanners/nuclei_runner.py`, `app/templates/findings.html`
- Replace: `app/routers/nuclei.py`, `app/templates/nuclei.html`
- Test: `tests/test_nuclei_scan.py`

- [ ] **Step 1: Write failing tests**

`tests/test_nuclei_scan.py`:
```python
from pathlib import Path

from sqlalchemy import select

from app.db import Finding, Job
from app.scanners.nuclei_runner import build_nuclei_argv
from app.templates_index import reindex
from tests.conftest import get_csrf, wait_job

FIXTURES = Path(__file__).parent / "fixtures" / "templates"


def test_build_nuclei_argv():
    argv = build_nuclei_argv("/opt/nuclei", ["/t/a.yaml", "/t/b.yaml"], "/data/jobs/t.txt", "/data/nuclei-templates", rate_limit=50, timeout=7)
    assert argv[:2] == ["/opt/nuclei", "-jsonl"]
    assert "-silent" in argv and "-disable-update-check" in argv and "-no-color" in argv
    assert argv[argv.index("-ud") + 1] == "/data/nuclei-templates"
    assert argv[argv.index("-l") + 1] == "/data/jobs/t.txt"
    assert argv.count("-t") == 2 and "/t/a.yaml" in argv and "/t/b.yaml" in argv
    assert argv[argv.index("-rate-limit") + 1] == "50" and argv[argv.index("-timeout") + 1] == "7"


def test_build_nuclei_argv_requires_templates():
    import pytest
    with pytest.raises(ValueError):
        build_nuclei_argv("nuclei", [], "/t.txt", "/d")


def _template_paths(client):
    with client.app.state.SessionLocal() as db:
        reindex(db, client.app.state.settings)
        from app.db import TemplateIndex
        return {t.template_id: t.path for t in db.scalars(select(TemplateIndex))}


def test_nuclei_page_renders_with_prefilled_targets(auth):
    r = auth.get("/nuclei")
    assert r.status_code == 200 and 'id="tpl-q"' in r.text


def test_nuclei_scan_rejects_missing_templates_and_bad_targets(auth):
    paths = _template_paths(auth)
    csrf = get_csrf(auth, "/nuclei")
    r = auth.post("/nuclei/scan", data={"csrf": csrf, "targets": "http://10.0.0.1"})
    assert r.status_code == 400 and "Select at least one template" in r.text
    r = auth.post("/nuclei/scan", data=[("csrf", csrf), ("targets", "-bad"), ("template_paths", paths["php-detect"])])
    assert r.status_code == 400 and "Invalid nuclei target" in r.text
    r = auth.post("/nuclei/scan", data=[("csrf", csrf), ("targets", "http://10.0.0.1"), ("template_paths", "/etc/passwd")])
    assert r.status_code == 400 and "not in the template directories" in r.text
    with auth.app.state.SessionLocal() as db:
        assert db.scalar(select(Job)) is None


def test_nuclei_scan_end_to_end_with_fake_nuclei(auth):
    paths = _template_paths(auth)
    csrf = get_csrf(auth, "/nuclei")
    r = auth.post("/nuclei/scan", data=[("csrf", csrf), ("targets", "http://192.168.1.10:8080\n192.168.1.12:3306"),
                                        ("template_paths", paths["php-detect"]), ("template_paths", paths["CVE-2026-109619"]),
                                        ("rate_limit", "100"), ("timeout", "5")], follow_redirects=False)
    assert r.status_code == 303, r.text
    job_id = int(r.headers["location"].rsplit("/", 1)[1])
    data = wait_job(auth, job_id)
    assert data["status"] == "done", auth.get(f"/jobs/{job_id}").text
    with auth.app.state.SessionLocal() as db:
        job = db.get(Job, job_id)
        assert job.command.count("-t ") == 2
        targets_file = job.command.split("-l ")[1].split()[0]
        assert Path(targets_file).read_text() == "http://192.168.1.10:8080\n192.168.1.12:3306\n"
        findings = list(db.scalars(select(Finding).where(Finding.job_id == job_id)))
        assert sorted(f.template_id for f in findings) == ["CVE-2026-109619", "php-detect"]
        crit = next(f for f in findings if f.severity == "critical")
        assert crit.matched_at == "http://192.168.1.10:8080/index.php"
    r = auth.get(f"/findings?job={job_id}")
    assert r.status_code == 200 and "CVE-2026-109619" in r.text and "php-detect" in r.text
    r = auth.get("/findings?severity=critical")
    assert "CVE-2026-109619" in r.text and "php-detect" not in r.text
    r = auth.get(f"/jobs/{job_id}")
    assert "CVE-2026-109619" in r.text  # JSONL lines are shown live in the log
```

Run: `pytest tests/test_nuclei_scan.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.scanners.nuclei_runner'`

- [ ] **Step 2: Implement `app/scanners/nuclei_runner.py`**

```python
from __future__ import annotations

import json
from pathlib import Path

from sqlalchemy.orm import Session

from ..config import Settings
from ..db import Finding, Job
from ..parsers.nuclei_jsonl import parse_nuclei_jsonl


def build_nuclei_argv(nuclei_bin: str, template_paths: list[str], targets_file: str, templates_dir: str,
                      rate_limit: int | None = None, timeout: int | None = None) -> list[str]:
    if not template_paths:
        raise ValueError("Select at least one template.")
    argv = [nuclei_bin, "-jsonl", "-silent", "-disable-update-check", "-no-color", "-ud", templates_dir, "-l", targets_file]
    for p in template_paths:
        argv += ["-t", p]
    if rate_limit:
        argv += ["-rate-limit", str(int(rate_limit))]
    if timeout:
        argv += ["-timeout", str(int(timeout))]
    return argv


def validate_template_paths(settings: Settings, paths: list[str]) -> list[str]:
    roots = [settings.nuclei_templates_dir.resolve(), settings.custom_templates_dir.resolve()]
    out: list[str] = []
    for p in paths:
        rp = Path(p).resolve()
        if not any(rp.is_relative_to(r) for r in roots):
            raise ValueError(f"Template path is not in the template directories: {p}")
        if not rp.is_file():
            raise ValueError(f"Template file not found: {p}")
        if str(rp) not in out:
            out.append(str(rp))
    if not out:
        raise ValueError("Select at least one template.")
    return out


def write_targets_file(settings: Settings, job_id: int, targets: list[str]) -> Path:
    path = settings.jobs_dir / f"nuclei-{job_id}-targets.txt"
    path.write_text("\n".join(targets) + "\n")
    return path


def ingest_nuclei_results(db: Session, job: Job, jsonl_text: str) -> int:
    findings = parse_nuclei_jsonl(jsonl_text)
    for f in findings:
        db.add(Finding(job_id=job.id, template_id=f["template_id"], template_name=f["template_name"], severity=f["severity"],
                       host=f["host"], matched_at=f["matched_at"], type=f["type"], extracted=f["extracted"],
                       raw_json=json.dumps(f["raw"])))
    db.flush()
    return len(findings)


def on_nuclei_complete(db: Session, job: Job, output: str) -> None:
    n = ingest_nuclei_results(db, job, output)
    try:
        params = json.loads(job.params_json or "{}")
    except json.JSONDecodeError:
        params = {}
    params["result"] = {"findings": n}
    job.params_json = json.dumps(params)
```

- [ ] **Step 3: Replace `app/routers/nuclei.py`**

```python
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import Finding, Job, TemplateIndex
from ..deps import get_db, get_runner, get_settings, verify_csrf
from ..render import render
from ..scanners.nuclei_runner import build_nuclei_argv, on_nuclei_complete, validate_template_paths, write_targets_file
from ..validation import parse_nuclei_targets
from .jobs import job_summary, recent_jobs

router = APIRouter()

DEFAULT_NUCLEI_FORM = {"targets": "", "selected": [], "rate_limit": 150, "timeout": 10}


def selected_from_paths(db: Session, paths: list[str]) -> list[dict]:
    """Rebuild the 'selected templates' list (for re-rendering the form) from template paths."""
    if not paths:
        return []
    rows = {t.path: t for t in db.scalars(select(TemplateIndex).where(TemplateIndex.path.in_(paths)))}
    out = []
    for p in paths:
        t = rows.get(p)
        out.append({"path": p, "template_id": t.template_id if t else p, "name": t.name if t else "", "severity": t.severity if t else "unknown"})
    return out


def nuclei_page_context(db: Session, targets: str = "", selected=None, error: str | None = None, **extra) -> dict:
    form = dict(DEFAULT_NUCLEI_FORM)
    form["targets"] = targets
    form["selected"] = selected or []
    form.update(extra)
    return {"active": "nuclei", "form": form, "error": error, "jobs": recent_jobs(db, kind="nuclei"), "job_summary": job_summary}


@router.get("/nuclei")
def nuclei_page(request: Request, targets: str = "", db: Session = Depends(get_db)):
    return render(request, "nuclei.html", **nuclei_page_context(db, targets=targets))


@router.post("/nuclei/scan", dependencies=[Depends(verify_csrf)])
def nuclei_scan(request: Request, targets: str = Form(""), template_paths: list[str] = Form(default=[]),
                rate_limit: int = Form(150), timeout: int = Form(10),
                db: Session = Depends(get_db), settings=Depends(get_settings), runner=Depends(get_runner)):
    selected = selected_from_paths(db, template_paths)

    def fail(msg: str):
        return render(request, "nuclei.html", status_code=400,
                      **nuclei_page_context(db, targets=targets, selected=selected, error=msg, rate_limit=rate_limit, timeout=timeout))

    try:
        paths = validate_template_paths(settings, template_paths)
        target_list = parse_nuclei_targets(targets)
    except ValueError as e:
        return fail(str(e))
    rate_limit = max(1, min(rate_limit, 1000))
    timeout = max(1, min(timeout, 120))
    template_ids = [s["template_id"] for s in selected]
    job = runner.create_job(db, "nuclei", [settings.nuclei_bin], params={"targets": target_list, "template_ids": template_ids})
    targets_file = write_targets_file(settings, job.id, target_list)
    argv = build_nuclei_argv(settings.nuclei_bin, paths, str(targets_file), str(settings.nuclei_templates_dir),
                             rate_limit=rate_limit, timeout=timeout)
    from ..jobs import quote_argv
    job.command = quote_argv(argv)
    db.commit()
    runner.start(job.id, argv, on_complete=on_nuclei_complete, stdout_to_log=True)
    return RedirectResponse(f"/jobs/{job.id}", status_code=303)


@router.get("/findings")
def findings_page(request: Request, job: int | None = None, severity: str = "", q: str = "", db: Session = Depends(get_db)):
    stmt = select(Finding).order_by(Finding.id.desc())
    if job:
        stmt = stmt.where(Finding.job_id == job)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    rows = list(db.scalars(stmt.limit(2000)))
    ql = q.strip().lower()
    if ql:
        rows = [f for f in rows if ql in " ".join([f.template_id, f.template_name, f.host, f.matched_at, f.extracted]).lower()]
    from ..render import SEVERITY_ORDER
    rows.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.id))
    jobs = recent_jobs(db, kind="nuclei", limit=50)
    return render(request, "findings.html", active="findings", findings=rows, job=job, severity=severity, q=q, jobs=jobs)
```

- [ ] **Step 4: Replace `app/templates/nuclei.html` and create `findings.html`**

`app/templates/nuclei.html`:
```html
{% extends "base.html" %}
{% block title %}Nuclei · 0-Day Rapid Scanner{% endblock %}
{% block content %}
<h1>Nuclei scan</h1>
<form method="post" action="/nuclei/scan" class="card stack" id="nuclei-form">
  <input type="hidden" name="csrf" value="{{ csrf }}">
  <div class="grid-2">
    <div class="stack">
      <label>Targets (one per line: URL or host:port) — prefill from <a href="/inventory">Inventory</a>
        <textarea name="targets" rows="10" required placeholder="http://192.168.1.10:8080&#10;https://web01.lab&#10;192.168.1.12:3306">{{ form.targets }}</textarea></label>
      <div class="row">
        <label>Rate limit (req/s) <input type="number" name="rate_limit" value="{{ form.rate_limit }}" min="1" max="1000"></label>
        <label>Timeout (s) <input type="number" name="timeout" value="{{ form.timeout }}" min="1" max="120"></label>
      </div>
    </div>
    <div class="stack">
      <label>Search templates (id, name, tag, CVE) — click a result to select; pick one or many
        <input id="tpl-q" placeholder="e.g. CVE-2026-109619, php, apache, rce" autocomplete="off"></label>
      <div class="row">
        <select id="tpl-sev"><option value="">any severity</option>{% for s in severities %}<option value="{{ s }}">{{ s }}</option>{% endfor %}</select>
        <select id="tpl-src"><option value="">official + custom</option><option value="official">official</option><option value="custom">custom (0-day)</option></select>
      </div>
      <div id="tpl-results" class="tpl-results"></div>
      <h3>Selected templates <span id="tpl-count" class="badge">0</span></h3>
      <ul id="tpl-selected" class="tpl-selected">
        {% for t in form.selected %}
        <li data-path="{{ t.path }}"><input type="hidden" name="template_paths" value="{{ t.path }}"><span class="badge sev-{{ t.severity }}">{{ t.severity }}</span> <b>{{ t.template_id }}</b> <span class="n muted">{{ t.name }}</span> <button type="button" class="link rm" title="remove">✕</button></li>
        {% endfor %}
      </ul>
    </div>
  </div>
  <button class="primary">Start nuclei scan</button>
</form>
<div class="card">
  <h2>Recent nuclei jobs</h2>
  {% include "_jobs_table.html" %}
</div>
{% endblock %}
```

`app/templates/findings.html`:
```html
{% extends "base.html" %}
{% block title %}Findings · 0-Day Rapid Scanner{% endblock %}
{% block content %}
<h1>Findings</h1>
<form method="get" action="/findings" class="card row">
  <label>Job <select name="job"><option value="">all jobs</option>{% for j in jobs %}<option value="{{ j.id }}" {{ 'selected' if j.id == job }}>#{{ j.id }} · {{ j.started_at.strftime('%Y-%m-%d %H:%M') if j.started_at else 'queued' }}</option>{% endfor %}</select></label>
  <label>Severity <select name="severity"><option value="">any</option>{% for s in severities %}<option value="{{ s }}" {{ 'selected' if s == severity }}>{{ s }}</option>{% endfor %}</select></label>
  <label>Search <input name="q" value="{{ q }}" placeholder="template, host, url"></label>
  <button>Filter</button> <a class="btn" href="/findings">Reset</a>
</form>
<div class="card">
  <table class="data">
    <thead><tr><th>Severity</th><th>Template</th><th>Name</th><th>Host</th><th>Matched at</th><th>Extracted</th><th>Job</th><th>Time</th></tr></thead>
    <tbody>
    {% for f in findings %}
    <tr>
      <td><span class="badge sev-{{ f.severity }}">{{ f.severity }}</span></td>
      <td class="mono">{{ f.template_id }}</td><td>{{ f.template_name }}</td>
      <td class="mono small">{{ f.host }}</td><td class="mono small">{{ f.matched_at }}</td>
      <td class="mono small">{{ f.extracted }}</td>
      <td><a href="/jobs/{{ f.job_id }}">#{{ f.job_id }}</a></td>
      <td class="small">{{ f.created_at.strftime('%Y-%m-%d %H:%M') }}</td>
    </tr>
    {% else %}<tr><td colspan="8" class="muted">No findings yet.</td></tr>{% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_nuclei_scan.py tests/test_inventory.py -v`
Expected: all passed (the inventory hand-off test now renders the real nuclei page)

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: nuclei scan page with template picker and findings"
```

---

### Task 12: Version-match rules (0-day without a template)

**Files:**
- Create: `app/rules.py`, `app/routers/rules.py`, `app/templates/rules.html`, `app/templates/rule_form.html`
- Modify: `app/scanners/nmap_runner.py` (`on_nmap_complete` evaluates rules), `app/main.py` (seed example rule, router)
- Test: `tests/test_rules.py`

- [ ] **Step 1: Write failing tests**

`tests/test_rules.py`:
```python
from pathlib import Path

from sqlalchemy import select

from app.db import Job, Rule, RuleMatch, Service, init_db, make_engine, make_session_factory
from app.rules import evaluate_rules, seed_example_rule
from app.scanners.nmap_runner import ingest_nmap_results
from tests.conftest import get_csrf

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


def _session(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'r.db'}")
    init_db(engine)
    return make_session_factory(engine)


def _seed(db):
    job = Job(kind="nmap", status="done")
    db.add(job)
    db.commit()
    ingest_nmap_results(db, job, FIXTURE.read_text())
    db.commit()


def test_evaluate_rules_matches_product_and_version(tmp_path):
    SessionLocal = _session(tmp_path)
    with SessionLocal() as db:
        _seed(db)
        db.add(Rule(name="PHP UAF", product_pattern=r"php", version_constraint="< 8.3.15", cve_id="CVE-2026-109619", severity="critical"))
        db.add(Rule(name="Old OpenSSH", product_pattern=r"^OpenSSH$", version_constraint="< 9.0", severity="high"))
        db.add(Rule(name="Disabled", product_pattern=r".*", version_constraint="> 0", enabled=False))
        db.add(Rule(name="Broken regex", product_pattern=r"(", version_constraint="< 1"))
        db.commit()
        n = evaluate_rules(db)
        db.commit()
        assert n == 1
        m = db.scalar(select(RuleMatch))
        svc = db.get(Service, m.service_id)
        assert svc.port == 8080 and m.rule.cve_id == "CVE-2026-109619"
        # re-evaluation is idempotent
        assert evaluate_rules(db) == 1


def test_rule_matches_cpe_when_product_empty(tmp_path):
    SessionLocal = _session(tmp_path)
    with SessionLocal() as db:
        _seed(db)
        db.add(Rule(name="Apache via cpe", product_pattern=r"apache:http_server", version_constraint="<= 2.4.58", severity="medium"))
        db.commit()
        assert evaluate_rules(db) == 1


def test_seed_example_rule(tmp_path):
    SessionLocal = _session(tmp_path)
    with SessionLocal() as db:
        seed_example_rule(db)
        seed_example_rule(db)
        rules = list(db.scalars(select(Rule)))
        assert len(rules) == 1 and rules[0].enabled is False and rules[0].cve_id == "CVE-2026-109619"


def test_rules_pages_crud_and_inventory_badges(auth):
    with auth.app.state.SessionLocal() as db:
        _seed(db)
    assert auth.get("/rules").status_code == 200
    csrf = get_csrf(auth, "/rules")
    r = auth.post("/rules", data={"csrf": csrf, "name": "PHP UAF", "product_pattern": "php", "version_constraint": "< 8.3.15",
                                  "cve_id": "CVE-2026-109619", "severity": "critical", "description": "x", "enabled": "true"}, follow_redirects=False)
    assert r.status_code == 303
    r = auth.post("/rules", data={"csrf": csrf, "name": "bad", "product_pattern": "(", "version_constraint": "< 1", "severity": "low"})
    assert r.status_code == 400 and "Invalid regex" in r.text
    r = auth.post("/rules", data={"csrf": csrf, "name": "bad2", "product_pattern": "x", "version_constraint": "~1", "severity": "low"})
    assert r.status_code == 400 and "Invalid version clause" in r.text
    page = auth.get("/rules")
    assert "PHP UAF" in page.text and "192.168.1.10" in page.text and "8.3.10" in page.text
    inv = auth.get("/inventory?only_matches=true")
    assert "8080" in inv.text and "CVE-2026-109619" in inv.text and "3306" not in inv.text
    with auth.app.state.SessionLocal() as db:
        rule = db.scalar(select(Rule).where(Rule.name == "PHP UAF"))
    r = auth.get(f"/rules/{rule.id}/edit")
    assert r.status_code == 200 and "PHP UAF" in r.text
    r = auth.post(f"/rules/{rule.id}/edit", data={"csrf": csrf, "name": "PHP UAF v2", "product_pattern": "php", "version_constraint": "< 8.3.15",
                                                   "cve_id": "CVE-2026-109619", "severity": "high", "description": "", "enabled": "true"}, follow_redirects=False)
    assert r.status_code == 303
    r = auth.post(f"/rules/{rule.id}/toggle", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert "CVE-2026-109619" not in auth.get("/inventory").text
    r = auth.post(f"/rules/{rule.id}/delete", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert "PHP UAF v2" not in auth.get("/rules").text
```

Run: `pytest tests/test_rules.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.rules'`

- [ ] **Step 2: Implement `app/rules.py`**

```python
"""Version-match rules: flag inventory services whose product matches a regex and whose version
satisfies a constraint. Lets the operator react to a new 0-day before any nuclei template exists."""
from __future__ import annotations

import re

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .db import Rule, RuleMatch, Service, utcnow
from .version_compare import check_clauses, parse_constraint


def validate_rule(product_pattern: str, version_constraint: str) -> str | None:
    try:
        re.compile(product_pattern)
    except re.error as e:
        return f"Invalid regex: {e}"
    try:
        parse_constraint(version_constraint)
    except ValueError as e:
        return str(e)
    return None


def _service_version(svc: Service) -> str:
    if svc.version:
        return svc.version
    if svc.cpe and svc.cpe.count(":") >= 4:
        return svc.cpe.split(":")[4]
    return ""


def evaluate_rules(db: Session) -> int:
    rules = list(db.scalars(select(Rule).where(Rule.enabled.is_(True))))
    services = list(db.scalars(select(Service)))
    db.execute(delete(RuleMatch))
    now = utcnow()
    count = 0
    for rule in rules:
        try:
            pattern = re.compile(rule.product_pattern, re.IGNORECASE)
            clauses = parse_constraint(rule.version_constraint)
        except (re.error, ValueError):
            continue
        for svc in services:
            haystack = " ".join(x for x in (svc.product, svc.service_name, svc.cpe) if x)
            if not pattern.search(haystack):
                continue
            if check_clauses(_service_version(svc), clauses):
                db.add(RuleMatch(rule_id=rule.id, service_id=svc.id, evaluated_at=now))
                count += 1
    db.flush()
    return count


def seed_example_rule(db: Session) -> None:
    if db.scalar(select(Rule).limit(1)) is not None:
        return
    db.add(Rule(
        name="Example: PHP < 8.3.15 (CVE-2026-109619 use-after-free)",
        product_pattern=r"php",
        version_constraint="< 8.3.15",
        cve_id="CVE-2026-109619",
        severity="critical",
        description="Example rule shipped disabled. Enable it, or edit it when a new PHP 0-day drops.",
        enabled=False,
    ))
    db.commit()
```

- [ ] **Step 3: Hook into nmap completion**

In `app/scanners/nmap_runner.py`, add `from ..rules import evaluate_rules` and change `on_nmap_complete`:
```python
def on_nmap_complete(db: Session, job: Job, output: str) -> None:
    stats = ingest_nmap_results(db, job, output)
    stats["rule_matches"] = evaluate_rules(db)
    job.params_json = _merge_params(job.params_json, {"result": stats})
```

- [ ] **Step 4: Implement `app/routers/rules.py`**

```python
from __future__ import annotations

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import Host, Rule, RuleMatch, Service
from ..deps import get_db, verify_csrf
from ..render import SEVERITIES, normalize_severity, render
from ..rules import evaluate_rules, validate_rule

router = APIRouter()

EMPTY_RULE = {"name": "", "product_pattern": "", "version_constraint": "", "cve_id": "", "severity": "high", "description": "", "enabled": True}


def _matches(db: Session):
    stmt = (select(RuleMatch, Rule, Service, Host).join(Rule, Rule.id == RuleMatch.rule_id)
            .join(Service, Service.id == RuleMatch.service_id).join(Host, Host.id == Service.host_id)
            .order_by(Rule.severity, Host.address, Service.port))
    return db.execute(stmt).all()


def _rules_page(request: Request, db: Session, form: dict | None = None, error: str | None = None, status_code: int = 200):
    rules = list(db.scalars(select(Rule).order_by(Rule.id)))
    return render(request, "rules.html", status_code=status_code, active="rules", rules=rules, matches=_matches(db),
                  form=form or dict(EMPTY_RULE), error=error)


def _form_from(name, product_pattern, version_constraint, cve_id, severity, description, enabled) -> dict:
    return {"name": name.strip(), "product_pattern": product_pattern.strip(), "version_constraint": version_constraint.strip(),
            "cve_id": cve_id.strip(), "severity": normalize_severity(severity) if severity in SEVERITIES else "high",
            "description": description.strip(), "enabled": enabled}


def _validate_form(form: dict) -> str | None:
    if not form["name"]:
        return "Name is required."
    if not form["product_pattern"]:
        return "Product pattern is required."
    return validate_rule(form["product_pattern"], form["version_constraint"])


@router.get("/rules")
def rules_page(request: Request, db: Session = Depends(get_db)):
    return _rules_page(request, db)


@router.post("/rules", dependencies=[Depends(verify_csrf)])
def rules_create(request: Request, name: str = Form(""), product_pattern: str = Form(""), version_constraint: str = Form(""),
                 cve_id: str = Form(""), severity: str = Form("high"), description: str = Form(""), enabled: bool = Form(False),
                 db: Session = Depends(get_db)):
    form = _form_from(name, product_pattern, version_constraint, cve_id, severity, description, enabled)
    err = _validate_form(form)
    if err:
        return _rules_page(request, db, form=form, error=err, status_code=400)
    db.add(Rule(**form))
    db.commit()
    evaluate_rules(db)
    db.commit()
    return RedirectResponse("/rules?msg=Rule+created+and+evaluated", status_code=303)


@router.get("/rules/{rule_id}/edit")
def rule_edit_page(request: Request, rule_id: int, db: Session = Depends(get_db)):
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(404)
    form = {k: getattr(rule, k) for k in EMPTY_RULE}
    return render(request, "rule_form.html", active="rules", rule=rule, form=form)


@router.post("/rules/{rule_id}/edit", dependencies=[Depends(verify_csrf)])
def rule_edit(request: Request, rule_id: int, name: str = Form(""), product_pattern: str = Form(""), version_constraint: str = Form(""),
              cve_id: str = Form(""), severity: str = Form("high"), description: str = Form(""), enabled: bool = Form(False),
              db: Session = Depends(get_db)):
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(404)
    form = _form_from(name, product_pattern, version_constraint, cve_id, severity, description, enabled)
    err = _validate_form(form)
    if err:
        return render(request, "rule_form.html", status_code=400, active="rules", rule=rule, form=form, error=err)
    for k, v in form.items():
        setattr(rule, k, v)
    db.commit()
    evaluate_rules(db)
    db.commit()
    return RedirectResponse("/rules?msg=Rule+updated+and+evaluated", status_code=303)


@router.post("/rules/{rule_id}/toggle", dependencies=[Depends(verify_csrf)])
def rule_toggle(rule_id: int, db: Session = Depends(get_db)):
    rule = db.get(Rule, rule_id)
    if rule is None:
        raise HTTPException(404)
    rule.enabled = not rule.enabled
    db.commit()
    evaluate_rules(db)
    db.commit()
    return RedirectResponse("/rules", status_code=303)


@router.post("/rules/{rule_id}/delete", dependencies=[Depends(verify_csrf)])
def rule_delete(rule_id: int, db: Session = Depends(get_db)):
    rule = db.get(Rule, rule_id)
    if rule is not None:
        db.delete(rule)
        db.commit()
    return RedirectResponse("/rules?msg=Rule+deleted", status_code=303)


@router.post("/rules/evaluate", dependencies=[Depends(verify_csrf)])
def rules_evaluate(db: Session = Depends(get_db)):
    n = evaluate_rules(db)
    db.commit()
    return RedirectResponse(f"/rules?msg={n}+match(es)+found", status_code=303)
```

- [ ] **Step 5: Templates**

`app/templates/rule_form.html` (shared form partial used standalone for edit):
```html
{% extends "base.html" %}
{% block title %}Edit rule · 0-Day Rapid Scanner{% endblock %}
{% block content %}
<h1>Edit rule #{{ rule.id }}</h1>
<form method="post" action="/rules/{{ rule.id }}/edit" class="card stack" style="max-width:720px">
  {% include "_rule_fields.html" %}
  <div class="row"><button class="primary">Save rule</button> <a class="btn" href="/rules">Cancel</a></div>
</form>
{% endblock %}
```

`app/templates/_rule_fields.html`:
```html
<input type="hidden" name="csrf" value="{{ csrf }}">
<label>Name <input name="name" value="{{ form.name }}" required placeholder="PHP < 8.3.15 use-after-free"></label>
<div class="row">
  <label>Product pattern (regex, case-insensitive; matched against product, service and CPE)
    <input name="product_pattern" value="{{ form.product_pattern }}" required placeholder="php|apache:http_server" class="mono" size="40"></label>
  <label>Version constraint (comma-separated: &lt; &lt;= &gt; &gt;= == !=)
    <input name="version_constraint" value="{{ form.version_constraint }}" required placeholder=">=8.0, <8.3.15" class="mono" size="24"></label>
</div>
<div class="row">
  <label>CVE id <input name="cve_id" value="{{ form.cve_id }}" placeholder="CVE-2026-109619" class="mono"></label>
  <label>Severity <select name="severity">{% for s in severities if s != 'unknown' %}<option value="{{ s }}" {{ 'selected' if s == form.severity }}>{{ s }}</option>{% endfor %}</select></label>
  <label class="inline"><input type="checkbox" name="enabled" value="true" {{ 'checked' if form.enabled }}> Enabled</label>
</div>
<label>Description <textarea name="description" rows="2">{{ form.description }}</textarea></label>
```

`app/templates/rules.html`:
```html
{% extends "base.html" %}
{% block title %}0-Day rules · 0-Day Rapid Scanner{% endblock %}
{% block content %}
<h1>0-Day version-match rules</h1>
<p class="muted">Rules flag inventory services by product + version without touching the target. Use them the moment a new CVE is announced, before a nuclei template exists. Rules are re-evaluated after every nmap scan.</p>
<div class="grid-2">
  <form method="post" action="/rules" class="card stack">
    <h2>New rule</h2>
    {% include "_rule_fields.html" %}
    <button class="primary">Create rule</button>
  </form>
  <div class="card">
    <div class="row between"><h2>Rules ({{ rules|length }})</h2>
      <form method="post" action="/rules/evaluate"><input type="hidden" name="csrf" value="{{ csrf }}"><button>Evaluate now</button></form></div>
    <table class="data">
      <thead><tr><th>On</th><th>Name</th><th>Pattern</th><th>Version</th><th>CVE</th><th>Sev</th><th></th></tr></thead>
      <tbody>
      {% for r in rules %}
      <tr class="{{ '' if r.enabled else 'muted' }}">
        <td><form method="post" action="/rules/{{ r.id }}/toggle"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="link">{{ '●' if r.enabled else '○' }}</button></form></td>
        <td>{{ r.name }}</td><td class="mono small">{{ r.product_pattern }}</td><td class="mono small">{{ r.version_constraint }}</td>
        <td class="mono small">{{ r.cve_id }}</td><td><span class="badge sev-{{ r.severity }}">{{ r.severity }}</span></td>
        <td class="small"><a href="/rules/{{ r.id }}/edit">edit</a> ·
          <form method="post" action="/rules/{{ r.id }}/delete" style="display:inline"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="link danger">delete</button></form></td>
      </tr>
      {% else %}<tr><td colspan="7" class="muted">No rules yet.</td></tr>{% endfor %}
      </tbody>
    </table>
  </div>
</div>
<div class="card">
  <h2>Potential 0-day exposure ({{ matches|length }})</h2>
  <table class="data">
    <thead><tr><th>Severity</th><th>Rule</th><th>CVE</th><th>Host</th><th>Port</th><th>Product</th><th>Version</th></tr></thead>
    <tbody>
    {% for m, r, s, h in matches %}
    <tr><td><span class="badge sev-{{ r.severity }}">{{ r.severity }}</span></td><td>{{ r.name }}</td><td class="mono">{{ r.cve_id }}</td>
      <td class="mono">{{ h.address }}</td><td class="mono">{{ s.port }}/{{ s.protocol }}</td><td>{{ s.product }}</td><td class="mono">{{ s.version or s.cpe }}</td></tr>
    {% else %}<tr><td colspan="7" class="muted">No matches. Enable a rule and run an nmap scan.</td></tr>{% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}
```

- [ ] **Step 6: Wire into `app/main.py`**

Add `from .rules import seed_example_rule` and `from .routers import rules as rules_router`; in `lifespan` after `seed_admin(db)`: `seed_example_rule(db)`; register `app.include_router(rules_router.router)`.

- [ ] **Step 7: Run tests**

Run: `pytest tests/test_rules.py tests/test_nmap_scan.py -v`
Expected: all passed

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "feat: version-match 0-day rules with evaluation after nmap scans"
```

---

### Task 13: Updates page (nuclei engine, nuclei templates, nmap script DB)

**Files:**
- Create: `app/updates.py`, `app/routers/updates.py`, `app/templates/updates.html`
- Modify: `app/main.py` (router + first-start template bootstrap)
- Test: `tests/test_updates.py`

- [ ] **Step 1: Write failing tests**

`tests/test_updates.py`:
```python
import asyncio
import json

from app.updates import UPDATE_ACTIONS, build_update_argv, parse_nmap_version, parse_nuclei_version, templates_info, tool_versions
from tests.conftest import get_csrf, wait_job


def test_parse_versions():
    assert parse_nmap_version("Nmap version 7.97 ( https://nmap.org )\nPlatform: x") == "7.97"
    assert parse_nuclei_version("[INF] Nuclei Engine Version: v3.8.0\n[INF] Config dir") == "v3.8.0"
    assert parse_nmap_version("") == "unknown" and parse_nuclei_version("garbage") == "unknown"


def test_tool_versions_with_fake_bins(settings):
    v = asyncio.run(tool_versions(settings))
    assert v == {"nmap": "7.97", "nuclei": "v3.8.0"}


def test_templates_info_reads_config(settings, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    cfg = tmp_path / "home" / ".config" / "nuclei"
    cfg.mkdir(parents=True)
    (cfg / ".templates-config.json").write_text(json.dumps({"templates-version": "v10.2.9", "latest-templates-version": "v10.3.0", "nuclei-latest-version": "v3.9.0"}))
    info = templates_info(settings)
    assert info["templates_version"] == "v10.2.9" and info["latest_templates_version"] == "v10.3.0" and info["nuclei_latest_version"] == "v3.9.0"
    assert info["dir_exists"] is True and info["yaml_files"] == 2


def test_build_update_argv(settings):
    assert build_update_argv(settings, "nuclei-templates")[1] == "-update-templates"
    assert build_update_argv(settings, "nuclei-engine")[1] == "-update"
    assert build_update_argv(settings, "nmap-scripts")[1] == "--script-updatedb"
    assert set(UPDATE_ACTIONS) == {"nuclei-templates", "nuclei-engine", "nmap-scripts"}


def test_updates_page_and_actions(auth):
    r = auth.get("/updates")
    assert r.status_code == 200 and "7.97" in r.text and "v3.8.0" in r.text
    csrf = get_csrf(auth, "/updates")
    r = auth.post("/updates/nuclei-templates", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    job_id = int(r.headers["location"].rsplit("/", 1)[1])
    data = wait_job(auth, job_id)
    assert data["status"] == "done"
    assert "Successfully updated nuclei-templates" in auth.get(f"/jobs/{job_id}").text
    r = auth.post("/updates/nope", data={"csrf": csrf})
    assert r.status_code == 404
```

Run: `pytest tests/test_updates.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.updates'`

- [ ] **Step 2: Implement `app/updates.py`**

```python
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

from .config import Settings

UPDATE_ACTIONS = {
    "nuclei-templates": {"label": "Update nuclei templates", "help": "Downloads the latest official nuclei-templates release into the data volume, then re-indexes."},
    "nuclei-engine": {"label": "Update nuclei engine", "help": "Self-updates the nuclei binary (nuclei -update). Lost on image rebuild; bump NUCLEI_VERSION in the Dockerfile for a permanent change."},
    "nmap-scripts": {"label": "Update nmap script DB", "help": "Rebuilds the NSE script index (nmap --script-updatedb). The nmap binary itself is updated by rebuilding the image."},
}


def build_update_argv(settings: Settings, action: str) -> list[str]:
    if action == "nuclei-templates":
        return [settings.nuclei_bin, "-update-templates", "-ud", str(settings.nuclei_templates_dir), "-no-color"]
    if action == "nuclei-engine":
        return [settings.nuclei_bin, "-update", "-no-color"]
    if action == "nmap-scripts":
        return [settings.nmap_bin, "--script-updatedb"]
    raise KeyError(action)


def parse_nmap_version(text: str) -> str:
    m = re.search(r"Nmap version (\S+)", text or "")
    return m.group(1) if m else "unknown"


def parse_nuclei_version(text: str) -> str:
    m = re.search(r"Version:\s*(v?\d[\w.\-]*)", text or "")
    return m.group(1) if m else "unknown"


async def _run_capture(argv: list[str], timeout: float = 15) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (FileNotFoundError, PermissionError, asyncio.TimeoutError, OSError):
        return ""
    return out.decode("utf-8", "replace")


async def tool_versions(settings: Settings) -> dict:
    nmap_out, nuclei_out = await asyncio.gather(
        _run_capture([settings.nmap_bin, "--version"]),
        _run_capture([settings.nuclei_bin, "-version", "-disable-update-check"]),
    )
    return {"nmap": parse_nmap_version(nmap_out), "nuclei": parse_nuclei_version(nuclei_out)}


def templates_info(settings: Settings) -> dict:
    info = {"templates_version": "unknown", "latest_templates_version": "unknown", "nuclei_latest_version": "unknown",
            "dir_exists": settings.nuclei_templates_dir.is_dir(), "yaml_files": 0}
    if info["dir_exists"]:
        info["yaml_files"] = sum(1 for p in settings.nuclei_templates_dir.rglob("*.yaml") if ".git" not in p.parts)
    cfg = Path.home() / ".config" / "nuclei" / ".templates-config.json"
    if cfg.is_file():
        try:
            data = json.loads(cfg.read_text())
            info["templates_version"] = data.get("templates-version") or info["templates_version"]
            info["latest_templates_version"] = data.get("latest-templates-version") or info["latest_templates_version"]
            info["nuclei_latest_version"] = data.get("nuclei-latest-version") or info["nuclei_latest_version"]
        except (json.JSONDecodeError, OSError):
            pass
    return info
```

- [ ] **Step 3: Implement `app/routers/updates.py`**

```python
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..deps import get_db, get_runner, get_settings, verify_csrf
from ..render import render
from ..templates_index import count_templates
from ..updates import UPDATE_ACTIONS, build_update_argv, templates_info, tool_versions
from .jobs import job_summary, recent_jobs
from .templates import reindex_in_background

router = APIRouter()


def start_update_job(app, db: Session, action: str):
    """Create and start an update job; after a templates update, re-index in the background."""
    settings, runner = app.state.settings, app.state.job_runner
    argv = build_update_argv(settings, action)
    job = runner.create_job(db, "update", argv, params={"action": action})
    task = runner.start(job.id, argv, stdout_to_log=True)
    if action == "nuclei-templates":
        task.add_done_callback(lambda _t: asyncio.get_running_loop().create_task(reindex_in_background(app)))
    return job


@router.get("/updates")
async def updates_page(request: Request, db: Session = Depends(get_db), settings=Depends(get_settings)):
    versions = await tool_versions(settings)
    return render(request, "updates.html", active="updates", versions=versions, templates=templates_info(settings),
                  counts=count_templates(db), actions=UPDATE_ACTIONS, jobs=recent_jobs(db, kind="update"), job_summary=job_summary,
                  indexing=getattr(request.app.state, "indexing", False))


@router.post("/updates/{action}", dependencies=[Depends(verify_csrf)])
def updates_run(request: Request, action: str, db: Session = Depends(get_db), runner=Depends(get_runner)):
    if action not in UPDATE_ACTIONS:
        raise HTTPException(404)
    job = start_update_job(request.app, db, action)
    return RedirectResponse(f"/jobs/{job.id}", status_code=303)
```

- [ ] **Step 4: Create `app/templates/updates.html`**

```html
{% extends "base.html" %}
{% block title %}Updates · 0-Day Rapid Scanner{% endblock %}
{% block content %}
<h1>Updates</h1>
<div class="grid-4 stats">
  <div class="stat"><b>{{ versions.nmap }}</b><span>nmap version</span></div>
  <div class="stat"><b>{{ versions.nuclei }}</b><span>nuclei engine{% if templates.nuclei_latest_version != 'unknown' %} · latest {{ templates.nuclei_latest_version }}{% endif %}</span></div>
  <div class="stat"><b>{{ templates.templates_version }}</b><span>nuclei-templates{% if templates.latest_templates_version != 'unknown' %} · latest {{ templates.latest_templates_version }}{% endif %}</span></div>
  <div class="stat"><b>{{ counts.official }} / {{ counts.custom }}</b><span>indexed official / custom{% if indexing %} · indexing…{% endif %}</span></div>
</div>
{% if not templates.dir_exists %}<div class="flash err">No nuclei templates downloaded yet. Run "Update nuclei templates" below.</div>{% endif %}
<div class="grid-3">
  {% for key, a in actions.items() %}
  <form method="post" action="/updates/{{ key }}" class="card stack">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <h2>{{ a.label }}</h2>
    <p class="muted small">{{ a.help }}</p>
    <button class="primary">Run</button>
  </form>
  {% endfor %}
</div>
<div class="card">
  <h2>Rebuilding the image (nmap binary / pinned nuclei)</h2>
  <pre class="log">docker compose build --pull --no-cache && docker compose up -d</pre>
  <p class="muted small">nmap comes from the Debian package of the base image; nuclei is pinned by <code>NUCLEI_VERSION</code> in the Dockerfile. Data, custom templates and downloaded nuclei-templates live in the <code>/data</code> volume and survive rebuilds.</p>
</div>
<div class="card"><h2>Recent update jobs</h2>{% include "_jobs_table.html" %}</div>
{% endblock %}
```

- [ ] **Step 5: Wire into `app/main.py`** including first-start template bootstrap

Add `from .routers import updates as updates_router` and `from .routers.updates import start_update_job`. Register `app.include_router(updates_router.router)`. In `lifespan`, after the `needs_index` block:
```python
        if not settings.nuclei_templates_dir.is_dir():
            with SessionLocal() as db:
                start_update_job(app, db, "nuclei-templates")
```
`start_update_job` needs `app.state.job_runner`, which is created earlier in the lifespan, so keep this block after the runner is created.

- [ ] **Step 6: Run tests**

Run: `pytest tests/test_updates.py -v`
Expected: 5 passed

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "feat: updates page for nuclei engine/templates and nmap script DB"
```

---

### Task 14: Dashboard and final `main.py`

**Files:**
- Create: `app/routers/dashboard.py`, `app/templates/dashboard.html`
- Modify: `app/main.py` (remove placeholder `/`, final shape)
- Test: `tests/test_dashboard.py`

- [ ] **Step 1: Write failing test**

`tests/test_dashboard.py`:
```python
from pathlib import Path

from app.db import Job
from app.scanners.nmap_runner import ingest_nmap_results

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


def test_dashboard_counts(auth):
    with auth.app.state.SessionLocal() as db:
        job = Job(kind="nmap", status="done")
        db.add(job)
        db.commit()
        ingest_nmap_results(db, job, FIXTURE.read_text())
        db.commit()
    r = auth.get("/")
    assert r.status_code == 200
    assert "2</b><span>hosts" in r.text
    assert "5</b><span>open services" in r.text
    assert "Quick start" in r.text
```

Run: `pytest tests/test_dashboard.py -v`
Expected: FAIL (`Quick start` not in placeholder page)

- [ ] **Step 2: Implement `app/routers/dashboard.py`**

```python
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import Finding, Host, Rule, RuleMatch, Service, TemplateIndex
from ..deps import get_db
from ..render import SEVERITIES, render
from .jobs import job_summary, recent_jobs

router = APIRouter()


@router.get("/")
def dashboard(request: Request, db: Session = Depends(get_db)):
    sev_counts = {s: 0 for s in SEVERITIES}
    for sev, n in db.execute(select(Finding.severity, func.count()).group_by(Finding.severity)).all():
        sev_counts[sev] = n
    stats = {
        "hosts": db.scalar(select(func.count(Host.id))) or 0,
        "services": db.scalar(select(func.count(Service.id))) or 0,
        "findings": db.scalar(select(func.count(Finding.id))) or 0,
        "rule_matches": db.scalar(select(func.count(RuleMatch.id))) or 0,
        "rules": db.scalar(select(func.count(Rule.id)).where(Rule.enabled.is_(True))) or 0,
        "templates": db.scalar(select(func.count(TemplateIndex.id))) or 0,
    }
    return render(request, "dashboard.html", active="dashboard", stats=stats, sev_counts=sev_counts,
                  jobs=recent_jobs(db, limit=10), job_summary=job_summary)
```

- [ ] **Step 3: Create `app/templates/dashboard.html`**

```html
{% extends "base.html" %}
{% block content %}
<h1>Dashboard</h1>
<div class="grid-4 stats">
  <div class="stat"><b>{{ stats.hosts }}</b><span>hosts</span></div>
  <div class="stat"><b>{{ stats.services }}</b><span>open services</span></div>
  <div class="stat"><b>{{ stats.findings }}</b><span>nuclei findings
    {% for s in ['critical','high','medium','low'] if sev_counts[s] %}<span class="badge sev-{{ s }}">{{ sev_counts[s] }}</span>{% endfor %}</span></div>
  <div class="stat"><b>{{ stats.rule_matches }}</b><span>potential 0-day (rules: {{ stats.rules }} on, templates indexed: {{ stats.templates }})</span></div>
</div>
<div class="grid-2">
  <div class="card">
    <h2>Quick start</h2>
    <ol>
      <li><a href="/updates">Updates</a> → "Update nuclei templates" (first run only, then whenever a CVE drops).</li>
      <li><a href="/nmap">Nmap</a> → scan a network (top ports or all ports). Results land in <a href="/inventory">Inventory</a>.</li>
      <li><a href="/inventory">Inventory</a> → filter by product/version, select hosts, "Scan selected with nuclei".</li>
      <li><a href="/nuclei">Nuclei</a> → search templates (e.g. <code>CVE-2026-109619</code>), pick one or many, start.</li>
      <li>New 0-day without a template? Add a <a href="/rules">version rule</a> or <a href="/templates">upload / pull a custom template</a>.</li>
    </ol>
  </div>
  <div class="card"><h2>Recent jobs</h2>{% include "_jobs_table.html" %}</div>
</div>
{% endblock %}
```

- [ ] **Step 4: Final `app/main.py`**

Replace the whole file:
```python
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from .auth import AuthMiddleware, LoginRateLimiter, SessionStore, seed_admin
from .config import Settings, settings_from_env
from .db import TemplateIndex, init_db, make_engine, make_session_factory
from .jobs import JobRunner
from .render import STATIC_DIR
from .routers import (auth as auth_router, dashboard as dashboard_router, inventory as inventory_router, jobs as jobs_router,
                      nmap as nmap_router, nuclei as nuclei_router, rules as rules_router, templates as templates_router,
                      updates as updates_router)
from .routers.templates import reindex_in_background
from .routers.updates import start_update_job
from .rules import seed_example_rule


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or settings_from_env()
    engine = make_engine(settings.db_url)
    init_db(engine)
    SessionLocal = make_session_factory(engine)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        with SessionLocal() as db:
            seed_admin(db)
            seed_example_rule(db)
            needs_index = db.scalar(select(TemplateIndex).limit(1)) is None
        app.state.job_runner = JobRunner(SessionLocal)
        app.state.indexing = False
        app.state.last_index_counts = None
        if not settings.nuclei_templates_dir.is_dir():
            with SessionLocal() as db:
                start_update_job(app, db, "nuclei-templates")
        elif needs_index:
            asyncio.get_running_loop().create_task(reindex_in_background(app))
        yield

    app = FastAPI(title="0-Day Rapid Scanner", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.SessionLocal = SessionLocal
    app.state.sessions = SessionStore(settings.secret_key)
    app.state.login_limiter = LoginRateLimiter()
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.add_middleware(AuthMiddleware)
    for r in (auth_router, dashboard_router, jobs_router, nmap_router, inventory_router, nuclei_router,
              templates_router, rules_router, updates_router):
        app.include_router(r.router)

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    return app
```

- [ ] **Step 5: Run the full suite**

Run: `pytest -q`
Expected: all tests pass (around 60). Fix anything that regressed before continuing.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat: dashboard and final app wiring"
```

---

### Task 15: Dockerfile, compose, README, container smoke test

**Files:**
- Create: `Dockerfile`, `docker-compose.yml`, `.dockerignore`, `README.md`

- [ ] **Step 1: `Dockerfile`**

```dockerfile
FROM python:3.12-slim

ARG NUCLEI_VERSION=3.8.0

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ca-certificates curl unzip libcap2-bin git \
 && rm -rf /var/lib/apt/lists/*

RUN ARCH="$(dpkg --print-architecture)" \
 && case "$ARCH" in amd64) NARCH=amd64 ;; arm64) NARCH=arm64 ;; *) echo "unsupported arch $ARCH" && exit 1 ;; esac \
 && curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${NARCH}.zip" \
 && mkdir -p /opt/nuclei && unzip -q /tmp/nuclei.zip nuclei -d /opt/nuclei && rm /tmp/nuclei.zip \
 && chmod +x /opt/nuclei/nuclei

RUN useradd -r -u 10001 -d /data -s /usr/sbin/nologin scanner \
 && mkdir -p /data && chown -R scanner:scanner /data /opt/nuclei \
 && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

ENV DATA_DIR=/data \
    HOME=/data \
    NMAP_BIN=/usr/bin/nmap \
    NUCLEI_BIN=/opt/nuclei/nuclei \
    NUCLEI_TEMPLATES_DIR=/data/nuclei-templates \
    PYTHONUNBUFFERED=1

USER scanner
EXPOSE 8000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD curl -fsS http://127.0.0.1:8000/healthz || exit 1
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
```

`git` is included because `nuclei -update-templates` can fall back to a git clone. `--proxy-headers` makes `request.client.host` correct behind a reverse proxy for the login rate limiter.

- [ ] **Step 2: `docker-compose.yml` and `.dockerignore`**

`docker-compose.yml`:
```yaml
services:
  scanner:
    build: .
    image: zero-day-rapid-scanner:latest
    container_name: zero-day-rapid-scanner
    ports:
      - "8000:8000"
    volumes:
      - scanner-data:/data
    cap_add:
      - NET_RAW
      - NET_ADMIN
    environment:
      - HTTPS=0
    restart: unless-stopped

volumes:
  scanner-data:
```

`.dockerignore`:
```
.venv
.git
.pytest_cache
__pycache__
*.pyc
tests
docs
data
*.db
```

- [ ] **Step 3: `README.md`**

```markdown
# 0-Day Rapid Scanner

Small self-hosted web UI around **nmap** and **nuclei** for reacting to new vulnerabilities fast:
scan a network, build a host/software/version inventory, run nuclei templates (official or your own
0-day templates) against selected hosts, and flag exposed versions with rules before a template exists.

## Run

```bash
docker compose up -d --build
```

Open http://localhost:8000 and log in with **admin / changeme**. You are forced to set a new password
(min 12 characters) before anything else works.

First start downloads the official nuclei-templates into the `/data` volume (watch it under *Jobs*).

## Workflow

1. **Nmap** – targets (IP, CIDR, range, hostname), ports: top 1000 / all 65535 / custom. SYN scan needs
   `NET_RAW`/`NET_ADMIN` (granted in compose); choose *Connect* if the container cannot get raw sockets.
2. **Inventory** – host / port / service / product / version / CPE. Filter, select rows, "Scan selected with nuclei".
3. **Nuclei** – type to search templates (id, name, tag, CVE), click to select one or many, start.
   Findings are listed under *Findings* with severity filters.
4. **0-day support**
   - *Templates* → upload YAML or pull from a raw URL. Files are validated with `nuclei -validate` and stored in `/data/custom-templates`.
   - *0-Day Rules* → product regex + version constraint (e.g. `php` and `< 8.3.15`). Evaluated against the inventory after every nmap scan, no traffic to targets.
5. **Updates** – buttons for nuclei templates, nuclei engine (self-update), nmap script DB. The nmap binary itself is updated by rebuilding the image:
   `docker compose build --pull --no-cache && docker compose up -d` (bump `NUCLEI_VERSION` in the Dockerfile to pin a newer nuclei).

## Configuration (environment)

| Variable | Default | Purpose |
|---|---|---|
| `DATA_DIR` | `/data` | SQLite DB, custom templates, nuclei templates, secret key |
| `SECRET_KEY` | generated, stored in `/data/secret_key` | session cookie signing |
| `HTTPS` | `0` | set `1` behind TLS so the cookie gets the Secure flag |
| `NMAP_BIN` / `NUCLEI_BIN` | image paths | binaries |
| `NUCLEI_TEMPLATES_DIR` | `/data/nuclei-templates` | official templates |

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
DATA_DIR=./data uvicorn app.main:create_app --factory --reload
```

Tests use fake `nmap`/`nuclei` shell scripts, so they run anywhere.

## Security notes

- Only run against systems you are authorized to test.
- Single admin account, session cookie (HttpOnly, SameSite=Lax), CSRF tokens on all forms, login rate limit.
- Subprocesses receive argv lists (no shell); targets are allow-list validated.
- Container runs as non-root; nmap has file capabilities for raw sockets.
```

- [ ] **Step 4: Build and smoke test the container**

```bash
docker compose build 2>&1 | tail -3
docker compose up -d
sleep 5 && curl -s localhost:8000/healthz
```
Expected: image builds, `{"status":"ok"}`.

Then in a browser (or with curl + cookie jar):
1. Login admin/changeme → forced to `/change-password` → set a new password → dashboard.
2. Updates → "Update nuclei templates" (or wait for the automatic first-start job) → job finishes `done`; Templates page shows thousands of official templates after indexing.
3. Nmap → target `scanme.nmap.org`, top ports, SYN → job finishes; Inventory shows ports 22/80 with product/version.
   If the job log says `Couldn't open a raw socket`, rerun with *Connect* and check `cap_add` in compose.
4. Inventory → select port 80 → Scan selected with nuclei → search `tech-detect` or `http-missing-security-headers`, select, start → Findings populated.
5. Templates → pull `https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/http/technologies/php-detect.yaml` → appears under custom.
6. 0-Day Rules → enable the example rule → "Evaluate now" → no match unless a PHP host exists (expected).

Curl variant of steps 1 and 3 for a terminal-only check:
```bash
J=/tmp/zdrs.jar
curl -s -c $J -b $J -o /dev/null -w "%{http_code}\n" -d "username=admin&password=changeme" localhost:8000/login
CSRF=$(curl -s -c $J -b $J localhost:8000/change-password | grep -o 'name="csrf" value="[^"]*"' | cut -d'"' -f4)
curl -s -c $J -b $J -o /dev/null -w "%{http_code}\n" -d "csrf=$CSRF&current_password=changeme&new_password=CorrectHorse-Battery9&confirm_password=CorrectHorse-Battery9" localhost:8000/change-password
CSRF=$(curl -s -c $J -b $J localhost:8000/nmap | grep -o 'name="csrf" value="[^"]*"' | cut -d'"' -f4)
curl -s -c $J -b $J -o /dev/null -w "%{redirect_url}\n" -d "csrf=$CSRF&targets=scanme.nmap.org&port_mode=top&scan_type=syn&timing=T4" localhost:8000/nmap/scan
```
Expected: `303`, `303`, then a redirect URL like `http://localhost:8000/jobs/2`. Poll `localhost:8000/jobs/2/status` with the cookie jar until `done`, then `curl -b $J localhost:8000/inventory | grep -c scanme`.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat: Dockerfile, compose, README"
```

---

## Self-review against the spec

- Nmap well-known / all / custom ports via WebUI → Task 4, 8.
- Inventory of hosts + software + versions with filters → Task 8, 9.
- Nuclei with template text search, single or multi select (e.g. `CVE-2026-109619`) → Task 10, 11.
- Update buttons for nmap (script DB + rebuild note), nuclei engine, nuclei templates → Task 13.
- admin/changeme with forced password change → Task 6.
- Single small container → Task 15.
- Future 0-days: upload custom template, pull from URL, version-match rules, official template update → Tasks 10, 12, 13.
- Jobs with live log + cancel → Task 7. Error handling (invalid targets, missing binary, parser failure, bad template, bad URL) → Tasks 4, 7, 10. Security (argv only, CSRF, cookie flags, non-root, rate limit) → Tasks 4, 6, 15.
