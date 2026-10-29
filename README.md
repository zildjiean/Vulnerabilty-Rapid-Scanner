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
python3.12 -m venv .venv && source .venv/bin/activate
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
