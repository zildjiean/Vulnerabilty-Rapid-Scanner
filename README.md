# 0-Day Rapid Scanner

[![CI](https://github.com/zildjiean/Vulnerabilty-Rapid-Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/zildjiean/Vulnerabilty-Rapid-Scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-compose-2496ED.svg?logo=docker&logoColor=white)](docker-compose.yml)

A small, self-hosted web console around **nmap** and **nuclei** for reacting to new vulnerabilities fast.
Scan a network, build a host / software / version inventory, run nuclei templates (official or your own
0-day templates) against selected hosts, and flag exposed versions with rules **before** a public template exists.

Everything runs in one container. No external services, no accounts, works offline inside a lab network.

![Dashboard](docs/screenshots/dashboard.png)

## Features

- **Nmap discovery** from the browser: top 1000 ports, all 65 535 ports or a custom range; SYN or connect scan; live log.
- **Inventory** of every open service with product, version, CPE and hostname. Filter, sort, select, delete.
  Group the table by host, product or service type (Web, Database, Remote access, Mail, File sharing,
  Directory & auth, Network services, Other); groups collapse and select as a unit.
- **Nuclei scanning** with three selection modes: pick templates (search by id, name, tag, CVE), whole template
  groups (`http/cves/2026`, `network`, …) or all templates, plus tag and severity filters.
- **Findings** view across jobs with severity ordering and search.
- **0-day response** without waiting for upstream:
  - upload custom nuclei templates or pull them from a raw URL (validated with `nuclei -validate`);
  - version-match rules (`php` + `< 8.3.15`) evaluated against the inventory after every scan, no traffic to targets.
- **Updates** for nuclei templates, the nuclei engine and the nmap script DB, each as a tracked job.
- **Jobs** with persisted logs, Server-Sent Events streaming, cancel, and automatic cleanup after restarts.
- **Security basics**: forced password change on first login, CSRF tokens, login rate limiting, HttpOnly session
  cookie, argv-only subprocesses with allow-list validated targets, non-root container.
- **Enterprise-grade UI**: sidebar navigation, light/dark theme, KPI cards, sortable tables, keyboard and
  screen-reader friendly, no third-party frontend assets.

![Nuclei scan](docs/screenshots/nuclei.png)

## Quick start

```bash
git clone https://github.com/zildjiean/Vulnerabilty-Rapid-Scanner.git
cd Vulnerabilty-Rapid-Scanner
docker compose up -d --build
```

Open <http://localhost:8000> and sign in with **admin / changeme**. You must set a new password
(12+ characters) before anything else works. The first start downloads the official nuclei-templates into the
`/data` volume; watch it under *Jobs*.

## Workflow

1. **Nmap** – enter targets (IP, CIDR, range, hostname), choose the port range, start. SYN scans need
   `NET_RAW`/`NET_ADMIN` (granted in `docker-compose.yml`); pick *Connect* if raw sockets are unavailable.
2. **Inventory** – review hosts and services grouped by host, product or service type, filter by product or
   version, select rows or whole groups and hand them to nuclei.
3. **Nuclei** – pick templates, groups or everything, optionally narrow by tags / severity, start. Results land in *Findings*.
4. **0-day drops** – go to *Templates* to upload or pull a template, or to *Version rules* to flag vulnerable
   versions immediately.
5. **Updates** – refresh templates whenever needed. The nmap binary and the pinned nuclei version are updated by
   rebuilding the image: `docker compose build --pull --no-cache && docker compose up -d`.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DATA_DIR` | `/data` | SQLite DB, custom templates, nuclei templates, secret key |
| `SECRET_KEY` | generated, stored in `/data/secret_key` | session cookie signing |
| `HTTPS` | `0` | set `1` behind TLS so the cookie gets the `Secure` flag |
| `NMAP_BIN` / `NUCLEI_BIN` | image paths | binaries |
| `NUCLEI_TEMPLATES_DIR` | `/data/nuclei-templates` | official templates |

Put the container behind a reverse proxy with TLS for anything beyond a local lab.

## Development

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q                                   # fake nmap/nuclei shell scripts, runs anywhere
DATA_DIR=./data uvicorn app.main:create_app --factory --reload
```

Project layout:

```
app/            FastAPI application (routers, scanners, parsers, templates, static)
tests/          pytest suite with fixtures for nmap XML, nuclei JSONL and templates
docs/           design spec, implementation plan, screenshots
Dockerfile      python:3.12-slim + nmap + nuclei, non-root user
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and [SECURITY.md](SECURITY.md) for reporting
vulnerabilities.

## Responsible use

This tool sends packets to the targets you enter. **Only scan systems you own or are explicitly authorized to
test.** The authors accept no liability for misuse. See [LICENSE](LICENSE).

## Built with

[nmap](https://nmap.org) · [nuclei](https://github.com/projectdiscovery/nuclei) and
[nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) · [FastAPI](https://fastapi.tiangolo.com) ·
[SQLAlchemy](https://www.sqlalchemy.org) · [Jinja2](https://jinja.palletsprojects.com)

## License

[MIT](LICENSE) © 2026 zildjiean. nmap and nuclei are distributed under their own licenses.
