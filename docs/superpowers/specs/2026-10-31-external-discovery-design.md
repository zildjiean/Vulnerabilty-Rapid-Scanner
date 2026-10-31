# External asset discovery — design (v1.8.0)

Approved 2026-10-31. Round 6 (last) of the post-1.2 roadmap.

## Goal
Find internet-facing assets the team does not know about: subdomains of the organisation's root domains
(passive, subfinder) and which of them serve web content (active probe, httpx). Feed them into the
existing flow: Changes page, notifications, nmap/nuclei scans, schedules.

## 1. Tools in the image
- Add ProjectDiscovery **subfinder** and **httpx** binaries to the Dockerfile exactly like nuclei: `ARG
  SUBFINDER_VERSION` / `ARG HTTPX_VERSION` pinned to the latest stable releases (look them up on the GitHub
  releases pages and pin exact versions), amd64/arm64, unzip to `/opt/pd/`, owned by `scanner`.
- Env `SUBFINDER_BIN=/opt/pd/subfinder`, `HTTPX_BIN=/opt/pd/httpx` (absolute path — the Python `httpx`
  package may also install an `httpx` script). Add them to `app/config.py` settings like `NUCLEI_BIN`.
- Missing binary (local dev/tests) → the Discovery page shows a clear "not installed" notice and start is
  refused with a message; tests inject fakes like the existing nmap/nuclei tests.
- **Updates page**: "Update subfinder" and "Update httpx" buttons using each tool's `-update` flag as a
  tracked job, following the existing nuclei engine update pattern (read `app/routers/updates.py`). If the
  binary dir is not writable the job fails with the tool's own message (same as nuclei).

## 2. Discovery job
New job kind `discovery`, permission `scan.run`, page **Scanning → Discovery** (`/discovery`, sidebar key
`discovery`, after Nuclei scan). Form:
- **Root domains** (textarea, one per line, max 20). Validate each as a DNS name (no scheme, no path, no
  wildcard, at least one dot, IDNA ok, ≤ 253 chars); reject IPs/CIDRs with a helpful error.
- **Probe web services with httpx** (checkbox, default on) with help text that this contacts the hosts.
- Authorization notice: "Only enumerate domains you own or are authorized to test."

Execution (reuse `app/jobs.py` runner; no shell):
1. `subfinder -dL <domains file> -silent -oJ -all? ` — use `-silent -json` (JSONL with `host`, `source`) and
   `-pc <provider config>` only when keys are configured. Do not use `-all` (slow, noisy) — default sources.
   Timeout as other jobs. Write the domains file under `DATA_DIR/tmp/` and delete after completion.
2. On completion, ingest subdomains (§3). If probing is on and ≥ 1 host was found, start a chained job of
   kind `discovery_probe` running `httpx -l <hosts file> -silent -json -title -status-code -tech-detect
   -web-server -ip -follow-redirects -no-color` (+ `-rate-limit 50`), params `{"parent_job": id}`; its
   completion updates the same rows. Cap hosts per probe at 5,000 (excess noted in the job log).
   Both job kinds appear in Jobs with the usual log/cancel/warnings.

## 3. Data
New table `discovered_assets` (create_all):
`id, root_domain, hostname (unique), ips (comma list, from httpx `a`/`host` ip fields), url, status_code
(nullable int), title (≤ 255), webserver (≤ 255), tech (comma list ≤ 1000), sources (comma list of
subfinder sources ≤ 500), first_seen, last_seen, last_probed_at (nullable), web (bool: httpx answered on
the last probe), ignored (bool), ignored_by, ignored_at, scope_id (nullable, resolved via
scopes.scope_for_asset with address = first ip or "" and hostname), last_job_id`.
- Subfinder ingest upserts by hostname (lowercased, trailing dot stripped; must end with `.<root>` or
  equal root), updates last_seen/sources.
- httpx ingest matches by `input` (or host) hostname; sets url/status/title/webserver/tech/ips/web=true,
  last_probed_at; probed hosts with no httpx line get web=false, last_probed_at=now.
- Rows are never auto-deleted.

## 4. Changes + notification
- New `SurfaceChange` kind **`subdomain_new`** ("New subdomain"), severity medium, `address` = hostname,
  `hostname` = hostname, `after` = sources (and, when the probe answers, a follow-up is NOT a new row).
  Counted under "Added" in trends and in the dashboard card / Changes filters / labels (update
  `surface.KIND_LABELS`, `SURFACE_ADDED` in trends, any kind lists).
- Recorded when a hostname is first inserted. **Baseline**: the first discovery job that ever covers a given
  root domain records rows but does not notify (like the nmap baseline).
- After ingest, one `surface.changed` notification per job (reuse `surface.notify_changes` or its message
  builder; title `[SURFACE] discovery job #N: 7 new subdomains`), failure never fails the job.

## 5. UI
- `/discovery` page: the form (top, `scan.run` only) and the **Discovered assets** table below (view):
  hostname, IPs, web (status code badge + title + link to url, `rel="noopener noreferrer"
  target="_blank"`), server/tech (truncated with title attr), sources, scope, first/last seen. Filters: root
  domain, `q` text search, `web` (any / web only / no web), `state` (active [default] / ignored / all),
  `new` (first seen within 7 days). 100 per page.
- Bulk actions (checkbox selection, CSRF, `scan.run` for scan buttons, `issues.manage` for ignore):
  **Scan with nmap** / **Scan with nuclei** → redirect to `/nmap?targets=…` / `/nuclei?targets=…`
  pre-filled (check how inventory → nuclei prefill works today and reuse it; nuclei targets use the `url`
  when known, else hostname), **Ignore** / **Unignore** (audit `discovery.ignore`).
- External titles/tech are attacker-controlled text: autoescape only, never `|safe`; URLs rendered as
  links only when scheme is http/https.
- Schedules: new kind `discovery` ("External discovery") with root domains + probe option in the schedule
  form (follow the existing schedule kinds' params pattern in `app/scheduler.py` and `_schedule_parts.html`).

## 6. Source API keys (optional)
- **Settings → Discovery sources** (admin, `settings.manage`): key fields for a fixed list of subfinder
  providers: securitytrails, shodan, censys (id:secret), virustotal, chaos, github, binaryedge, fofa
  (email:key). Stored encrypted with the existing secret box (`app/secretbox.py`), shown only as "set" /
  "not set" with a Remove checkbox; never rendered, logged, audited or flashed. Audit `settings.discovery_keys`
  with provider names only.
- At job start, if any key is set, write a provider-config YAML (`provider: [key]` format subfinder
  expects) to `DATA_DIR/tmp/subfinder-<job>.yaml` with mode 0600, pass `-pc`, delete it when the job ends
  (also on failure/cancel). The job's stored command line must not contain keys (it only has the path).

## 7. API
`GET /api/v1/discovered?root=&web=&state=active|ignored|all&limit=100` (VIEW, limit ≤ 500).
`POST /api/v1/scans/discovery` (`scan.run`) body `{"domains": [...], "probe": true}` → 202 with job id.

## 8. Tests
Domain validation; subfinder JSONL + httpx JSONL parsing (fixtures with odd/malformed lines,
hostnames outside root ignored, uppercase/trailing dot); ingest upsert; probe updates incl. web=false;
chained probe job started only when hosts found and probe on; host cap; subdomain_new change rows +
baseline + single notification; ignore/unignore permissions + CSRF; prefill redirect; XSS (title with
`<script>`, `javascript:` url not linked); provider config file written 0600 with keys, deleted after,
keys absent from job.command/log/audit/HTML; schedule kind; API endpoints; page when binaries missing.

## Out of scope
dnsx/naabu, screenshots, ASN/IP-range discovery, certificate monitoring streams.
