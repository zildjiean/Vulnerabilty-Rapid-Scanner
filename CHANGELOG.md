# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Nuclei scan profiles (Gentle / Normal / Aggressive) and a "never drop unresponsive hosts" switch.
- Post-scan log analysis: jobs whose target was dropped as unresponsive, that had many request errors or
  nuclei [ERR]/[WRN] lines finish as "Done with warnings"; the Findings page flags incomplete results.
  Existing jobs are analyzed once on startup.

### Changed
- nuclei runs without `-silent` and with periodic stats, so the job log shows templates/targets loaded,
  httpx probing and errors; jobs end with a stored-findings summary line. nmap jobs report hosts/services stored.
- nuclei pinned to v3.11.1 in the Dockerfile.

## [0.1.0] - 2026-10-29

### Added
- Nmap scanning from the web UI (top 1000 / all / custom ports, SYN or connect) with live job logs.
- Inventory of hosts and services with filters, sorting, selection, deletion and hand-off to nuclei.
- Nuclei scanning with template search, template groups, all-templates mode, tag and severity filters.
- Findings view across jobs.
- Custom 0-day templates: upload or pull from URL, validated with `nuclei -validate`.
- Version-match rules evaluated against the inventory after every nmap scan.
- Update actions for nuclei templates, nuclei engine and nmap script DB.
- Forced password change for the default `admin` account, CSRF protection, login rate limiting.
- Single-container deployment (python:3.12-slim + nmap + nuclei, non-root).
- Enterprise UI: sidebar shell, light/dark theme, KPI cards, sortable tables, toasts, confirm dialogs.
