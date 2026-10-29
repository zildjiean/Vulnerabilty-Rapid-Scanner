# 0-Day Rapid Scanner — Design Spec

Date: 2026-10-29
Status: approved by user (brainstorming session)

## Goal

A small, self-contained web application that lets an operator:

1. Run nmap against targets (well-known ports, all ports, or a custom range) and build a host/software/version inventory.
2. Browse and filter that inventory.
3. Run nuclei against selected hosts (or typed targets) with one or many templates, found via text search.
4. Detect new 0-days quickly by uploading custom nuclei templates, pulling templates from a URL, or defining version-match rules against the inventory.
5. Update nmap script DB, nuclei engine and nuclei templates from the UI.
6. Log in as `admin` / `changeme`, and be forced to change the password on first login.
7. Run everything in a single small container.

## Non-goals

- Multi-user / RBAC. One admin account is enough.
- Distributed workers or horizontal scaling.
- Exploitation. The tool detects and reports only.
- Updating the nmap binary in place inside a running container (done by rebuilding the image).

## Architecture

Single Docker image (`python:3.12-slim` base) containing:

- `nmap` (Debian package) and `nuclei` (official release binary).
- FastAPI app served by uvicorn on port 8000.
- SQLite database on a mounted volume at `/data/scanner.db`.
- Custom templates at `/data/custom-templates/`.
- nuclei config/templates cache at `/data/nuclei/` (so template updates persist).

UI is server-rendered Jinja2 + HTMX + a small hand-written CSS file. No frontend build step. Live job output uses Server-Sent Events (SSE).

```
browser ──HTTP/HTMX/SSE──> FastAPI
                              ├── auth (session cookie, argon2/bcrypt hash)
                              ├── jobs runner (asyncio subprocess, one table row per job)
                              │     ├── nmap  -sV -oX -   ──> nmap_parser ──> hosts/ports/services
                              │     ├── nuclei -jsonl      ──> nuclei_parser ──> findings
                              │     └── update commands
                              ├── template index (scans nuclei-templates + custom dir, cached in DB)
                              ├── version rules engine (inventory × rules ──> potential findings)
                              └── SQLite via SQLAlchemy
```

## Modules (`app/`)

| Module | Responsibility | Depends on |
|---|---|---|
| `main.py` | FastAPI app factory, routers, startup (DB init, seed admin) | all routers |
| `config.py` | Settings from env: `DATA_DIR`, `SECRET_KEY`, `NMAP_BIN`, `NUCLEI_BIN`, `TEMPLATES_DIR`, `CUSTOM_TEMPLATES_DIR` | — |
| `db.py` | SQLAlchemy engine/session, models | config |
| `auth.py` | password hashing, login/logout, `must_change_password` enforcement middleware | db |
| `jobs.py` | `JobRunner`: start subprocess, stream stdout to job log + SSE subscribers, record exit, run completion hook | db |
| `scanners/nmap_runner.py` | build nmap argv from form options, run via JobRunner, parse XML on completion | jobs, parsers |
| `scanners/nuclei_runner.py` | build nuclei argv (templates, targets), run via JobRunner, parse JSONL on completion | jobs, parsers |
| `parsers/nmap_xml.py` | pure function: XML string → list of HostResult(address, hostname, ports[PortResult(port, proto, state, service, product, version, cpe)]) | stdlib only |
| `parsers/nuclei_jsonl.py` | pure function: JSONL text → list of Finding dicts | stdlib only |
| `templates_index.py` | walk templates dirs, read YAML `id`, `info.name`, `info.severity`, `info.tags`, `info.classification.cve-id`; store in `template_index` table; search by substring over id/name/tags/cve | db, pyyaml |
| `rules.py` | version-match rules: `product_pattern` (regex, case-insensitive), `version_constraint` (e.g. `< 8.3.15`, `>=8.0,<8.3.15`), evaluation against services | db, packaging-style version compare (own small impl) |
| `updates.py` | run `nuclei -update`, `nuclei -update-templates`, `nmap --script-updatedb`; read current versions | jobs |
| `routers/*.py` | HTTP routes per page: auth, dashboard, nmap, inventory, nuclei, templates, rules, updates, jobs | above |
| `templates/*.html` | Jinja2 pages | — |
| `static/app.css` | styles | — |

## Data model (SQLite)

- `users(id, username UNIQUE, password_hash, must_change_password BOOL, created_at)`
- `jobs(id, kind ENUM[nmap,nuclei,update], status ENUM[queued,running,done,failed,cancelled], command TEXT, log TEXT, started_at, finished_at, exit_code, params_json)`
- `hosts(id, address, hostname, last_seen_job_id, first_seen, last_seen)` UNIQUE(address)
- `services(id, host_id FK, port INT, protocol, state, service_name, product, version, extra_info, cpe, job_id)` UNIQUE(host_id, port, protocol)
- `template_index(id TEXT PK, path, name, severity, tags TEXT, cve_ids TEXT, source ENUM[official,custom], indexed_at)`
- `findings(id, job_id FK, template_id, template_name, severity, host, matched_at, type, extracted TEXT, raw_json, created_at)`
- `rules(id, name, product_pattern, version_constraint, cve_id, severity, description, enabled, created_at)`
- `rule_matches(id, rule_id FK, service_id FK, evaluated_at)` UNIQUE(rule_id, service_id)

## Features in detail

### Auth
- Seed `admin` / `changeme` with `must_change_password = true` on first startup if no users exist.
- Session cookie (itsdangerous-signed, `SECRET_KEY` from env, random generated and persisted to `/data/secret_key` if absent).
- Middleware: unauthenticated → `/login`. Authenticated with `must_change_password` → redirected to `/change-password` for any other page except logout and static.
- Change password: current + new + confirm, min 12 chars, must differ from current. Clears flag.
- Settings page allows later password changes.

### Nmap scan
Form fields: targets (textarea; one per line; IP, CIDR, hostname, range), port mode (`top` = nmap default top 1000, `all` = `-p-`, `custom` = `-p <expr>`), timing (`-T3` default, `-T4` option), service detection always on (`-sV`), optional `-Pn`.
Command: `nmap -sV [-Pn] [-T4] [-p- | -p X] -oX - <targets>`.
Target validation: each line must match IPv4/IPv6/CIDR/hostname/range regex; rejects shell metacharacters. Argv passed as list, never through a shell.
On completion: parse XML, upsert hosts/services (replace services for hosts seen in this job).

### Inventory
Table joined hosts × services. Filters: free text (matches address, hostname, product, version, service, cpe), product dropdown (distinct values), port, severity-of-rule-match. Checkbox per row + "select all filtered". Button "Scan selected with nuclei" carries host:port list into the nuclei form (builds `http://host:port` / `https://host:443` URLs when the service name is http/https/ssl, else bare `host:port`).
Also shows rule-match badges (potential 0-day) on rows.

### Nuclei scan
Form: targets textarea (prefilled from inventory), template search box (HTMX live search over `template_index`), results list with checkboxes (multi-select), selected list chip display, severity filter, optional `-rate-limit`, `-timeout`.
Command: `nuclei -jsonl -silent -disable-update-check -t <path> [-t ...] -l <targets_file>` with templates dir `-ud /data/nuclei`.
On completion: parse JSONL, store findings. Findings page lists per job and global with severity filter.

### Templates (0-day support)
- Index page shows counts (official/custom), last indexed time, "Re-index" button.
- Upload: one or more `.yaml` files → validated with `yaml.safe_load` and must have `id` and `info.name` → saved to custom dir under `<id>.yaml` → re-indexed. Also `nuclei -validate -t <file>` is run and its result shown.
- Pull from URL: HTTP(S) GET (10 MB limit, 30 s timeout) → same validation → saved.
- Delete custom template.

### Version-match rules (0-day without a template)
- CRUD page. Fields: name, product pattern (regex, e.g. `php|PHP`), version constraint (comma-separated clauses of `<,<=,>,>=,==,!=` + version), CVE id, severity, description, enabled.
- Version compare: split on `.`/`-`/`_`, compare numeric segments numerically, alpha segments lexically; missing segments treated as 0. Services with empty version never match (shown as "unknown version" in a separate count).
- Evaluate on: rule save, nmap job completion, manual "Evaluate now". Results in `rule_matches`, shown on inventory and on a "Potential 0-day" page.
- Ships with one example rule (disabled): PHP < 8.3.15 for CVE-2026-109619 (user-provided example; adjust as needed).

### Updates
Page shows: nmap version, nuclei version, nuclei templates version/last update, custom template count. Buttons (each creates an `update` job with live log):
- Update nuclei templates: `nuclei -update-templates -ud /data/nuclei`
- Update nuclei engine: `nuclei -update` (if it fails due to permissions/self-update constraints, log shows and page explains rebuild).
- Update nmap script DB: `nmap --script-updatedb`
- Note text: nmap binary is updated by rebuilding the image (`docker compose build --pull`).

### Jobs
List with status, kind, started/finished, duration. Detail page streams log via SSE while running; cancel button sends SIGTERM. Only one nmap and one nuclei job run concurrently; others queue (simple asyncio semaphore per kind).

## Error handling
- Invalid targets → form error, no job created.
- Subprocess missing binary → job failed with clear log line.
- Parser errors → job marked failed, raw output kept in log.
- Template upload invalid → inline error, file not saved.
- URL pull failure (network, size, non-YAML) → inline error.

## Security notes
- Argv lists only, strict target validation, no shell.
- Session cookie HttpOnly, SameSite=Lax; secure flag when `HTTPS=1` env.
- CSRF: all mutating forms include a token tied to the session.
- Container runs as non-root user `scanner`; nmap needs raw sockets for SYN scan so the image sets `cap_net_raw,cap_net_admin+eip` on the nmap binary and compose grants `NET_RAW`/`NET_ADMIN`. Falls back to connect scan (`-sT`) if not permitted.
- Rate limit login: 5 failures per minute per IP (in-memory).

## Testing
- Unit (pytest): `nmap_xml` parser on sample XML; `nuclei_jsonl` parser; version compare and constraint evaluation; target validation; template YAML validation; argv builders.
- Integration (pytest + httpx TestClient, temp SQLite): login → forced change password → access; CSRF; job runner with a fake `nmap` shell script that prints fixture XML; template upload; rule evaluation after fake scan.
- Container smoke: `docker compose up`, login, run nmap against `scanme.nmap.org` top ports, verify inventory rows, run nuclei with a `tech-detect`-type template.

## Deliverables
- `Dockerfile`, `docker-compose.yml`, `.dockerignore`, `README.md` (run, login, change password, update, add 0-day template/rule).
- `app/` as above, `tests/`, `requirements.txt`.
