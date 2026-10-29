# Contributing

Thanks for helping improve 0-Day Rapid Scanner. Bug reports, feature ideas, templates, docs and code are all welcome.

## Ground rules

- Be respectful; see the [Code of Conduct](CODE_OF_CONDUCT.md).
- Open an issue before large changes so we can agree on the approach.
- Keep pull requests focused. One feature or fix per PR.
- Security vulnerabilities go through [SECURITY.md](SECURITY.md), not public issues.

## Development setup

```bash
git clone https://github.com/zildjiean/Vulnerabilty-Rapid-Scanner.git
cd Vulnerabilty-Rapid-Scanner
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q
```

Run the app locally without Docker (needs `nmap` and `nuclei` on your PATH):

```bash
DATA_DIR=./data uvicorn app.main:create_app --factory --reload
```

Or build the container: `docker compose up -d --build`.

## Making changes

1. Create a branch from `master`: `git checkout -b feat/short-name`.
2. Write tests first where practical. The suite uses fake `nmap` / `nuclei` shell scripts
   (`tests/conftest.py`), so it runs without the real binaries and without network access.
3. Keep subprocess invocations as argv lists and validate any operator input that reaches them
   (`app/validation.py`, `app/scanners/*`).
4. Run `pytest -q` and make sure everything passes.
5. Open a pull request using the template. CI runs the test suite and a Docker build.

## Code style

- Python 3.12, type hints, small focused modules. Routers stay thin; logic lives in `app/scanners`,
  `app/parsers`, `app/rules.py`, `app/templates_index.py`.
- Templates are server-rendered Jinja2; keep JavaScript in `app/static/app.js` and dependency-free.
- UI follows the existing design tokens in `app/static/app.css` (light + dark), SVG icons from
  `app/templates/_icons.html`, no emoji icons.

## Commit messages

Use conventional prefixes: `feat:`, `fix:`, `docs:`, `test:`, `build:`, `chore:`.
