# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting on this repository
(*Security* → *Report a vulnerability*). If that is unavailable, open an issue titled
"Security contact request" without details and a maintainer will reach out.

Include: affected version or commit, steps to reproduce, impact, and any suggested fix.
You will get an acknowledgement within 7 days. Please allow up to 90 days for a fix before public disclosure.

## Scope

- The web application (`app/`), its authentication, CSRF protection, input validation and subprocess handling.
- The Docker image and compose configuration.

Vulnerabilities in nmap, nuclei or nuclei-templates should be reported to those projects.

## Deployment guidance

- Change the default password immediately (the app enforces this on first login).
- Run behind a reverse proxy with TLS and set `HTTPS=1`.
- Restrict network access to the UI; it is an operator console, not a public service.
- Only scan systems you are authorized to test.
