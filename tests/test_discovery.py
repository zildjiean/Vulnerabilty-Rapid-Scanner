"""External asset discovery: subfinder enumeration, httpx probing, ingest, changes, UI, schedules, source keys, API."""
import json
import re
import time
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from sqlalchemy import select

from app import discovery as dsc
from app import surface, trends
from app.config import Settings
from app.db import AuditLog, Delivery, DiscoveredAsset, Job, Schedule, Scope, SurfaceChange, utcnow
from tests.conftest import FIXTURES, get_csrf, wait_job
from tests.test_notifications import SLACK, channel
from tests.test_rbac import login_as, make_user

SUBFINDER = (FIXTURES / "subfinder_sample.jsonl").read_text()
HTTPX = (FIXTURES / "httpx_sample.jsonl").read_text()
KEY = "SECRET-st-KEY-123456"


def sf(*hosts, root="example.com", source="crtsh"):
    return "\n".join(json.dumps({"host": h, "input": root, "source": source}) for h in hosts)


@pytest.fixture
def db(client):
    with client.app.state.SessionLocal() as s:
        yield s


def make_job(db, domains, kind="discovery", probe=True):
    job = Job(kind=kind, status="running", params_json=json.dumps({"domains": list(domains), "probe": probe}))
    db.add(job)
    db.commit()
    return job


def finish(db, job):
    job.status = "done"
    db.commit()


def assets(db):
    return {a.hostname: a for a in db.scalars(select(DiscoveredAsset))}


# ----------------------------------------------------------------- validation
def test_parse_root_domains_normalises():
    assert dsc.parse_root_domains("Example.COM.\n\nexample.org\nexample.com\n") == ["example.com", "example.org"]
    assert dsc.parse_root_domains("bücher.example") == ["xn--bcher-kva.example"]
    assert dsc.parse_root_domains(["sub.example.co.uk"]) == ["sub.example.co.uk"]


@pytest.mark.parametrize("bad, msg", [
    ("https://example.com", "scheme"),
    ("example.com/login", "path"),
    ("*.example.com", "wildcard"),
    ("localhost", "dot"),
    ("192.0.2.1", "IP"),
    ("192.0.2.0/24", "IP"),
    ("2001:db8::1", "IP"),
    ("-x.example.com", "valid DNS name"),
    ("exa mple.com", "valid DNS name"),
    ("a" * 64 + ".example.com", "valid DNS name"),
    (".".join(["abcdefghij"] * 25) + ".com", "253"),
    ("", "at least one"),
])
def test_parse_root_domains_rejects(bad, msg):
    with pytest.raises(ValueError, match=msg):
        dsc.parse_root_domains(bad)


def test_parse_root_domains_max_20():
    dsc.parse_root_domains("\n".join(f"d{i}.example.com" for i in range(20)))
    with pytest.raises(ValueError, match="20"):
        dsc.parse_root_domains("\n".join(f"d{i}.example.com" for i in range(21)))


# ----------------------------------------------------------------- parsing
def test_parse_subfinder_jsonl():
    found = dsc.parse_subfinder_jsonl(SUBFINDER, ["example.com", "example.org"])
    assert set(found) == {"www.example.com", "api.example.com", "mail.example.org", "dev.example.com"}
    assert found["api.example.com"] == {"root": "example.com", "sources": ["virustotal", "crtsh"]}
    assert found["mail.example.org"]["root"] == "example.org"
    assert found["dev.example.com"]["sources"] == []          # unsafe source name dropped
    assert dsc.parse_subfinder_jsonl("", ["example.com"]) == {}


def test_parse_subfinder_prefers_longest_root():
    found = dsc.parse_subfinder_jsonl(sf("a.dev.example.com", "example.com"), ["example.com", "dev.example.com"])
    assert found["a.dev.example.com"]["root"] == "dev.example.com" and found["example.com"]["root"] == "example.com"


def test_parse_httpx_jsonl():
    res = dsc.parse_httpx_jsonl(HTTPX)
    assert set(res) == {"www.example.com", "api.example.com", "unrelated.example.net"}
    www = res["www.example.com"]
    assert www["url"] == "https://www.example.com" and www["status_code"] == 200
    assert www["title"] == "<script>alert(1)</script>Welcome" and www["webserver"] == "nginx/1.25"
    assert www["tech"] == ["Nginx", "WordPress:6.4"] and www["ips"] == ["192.0.2.10", "192.0.2.11"]
    assert res["api.example.com"]["ips"] == ["198.51.100.5"]
    # input given as a URL with port
    res = dsc.parse_httpx_jsonl(json.dumps({"input": "https://Shop.Example.com:8443/x", "status_code": "301"}))
    assert res["shop.example.com"]["status_code"] == 301


def test_build_argv():
    argv = dsc.build_subfinder_argv("/opt/pd/subfinder", "/data/tmp/d.txt")
    assert argv == ["/opt/pd/subfinder", "-dL", "/data/tmp/d.txt", "-silent", "-json", "-duc"]
    argv = dsc.build_subfinder_argv("/opt/pd/subfinder", "/data/tmp/d.txt", "/data/tmp/subfinder-3.yaml")
    assert argv[-2:] == ["-pc", "/data/tmp/subfinder-3.yaml"] and "-all" not in argv
    argv = dsc.build_httpx_argv("/opt/pd/httpx", "/data/tmp/h.txt")
    assert argv[:3] == ["/opt/pd/httpx", "-l", "/data/tmp/h.txt"]
    for flag in ("-silent", "-json", "-title", "-status-code", "-tech-detect", "-web-server", "-ip",
                 "-follow-host-redirects", "-no-color", "-duc"):
        assert flag in argv
    assert "-follow-redirects" not in argv                     # never follow a redirect to another host
    assert argv[argv.index("-maxr") + 1] == "3"
    assert argv[argv.index("-rate-limit") + 1] == "50"


# ----------------------------------------------------------------- ingest
def test_ingest_upserts_by_hostname(db):
    j1 = make_job(db, ["example.com", "example.org"])
    stats = dsc.complete_discovery(db, j1, SUBFINDER)
    db.commit()
    rows = assets(db)
    assert set(rows) == {"www.example.com", "api.example.com", "mail.example.org", "dev.example.com"}
    api = rows["api.example.com"]
    assert api.root_domain == "example.com" and api.sources == "virustotal,crtsh" and api.last_job_id == j1.id
    assert api.web is False and api.last_probed_at is None and not api.ignored
    assert stats["hosts"] == 4 and stats["new"] == 4
    first_seen = api.first_seen
    finish(db, j1)
    j2 = make_job(db, ["example.com"])
    dsc.complete_discovery(db, j2, sf("api.example.com", source="chaos"))
    db.commit()
    db.expire_all()
    api = assets(db)["api.example.com"]
    assert len(assets(db)) == 4
    assert api.sources == "virustotal,crtsh,chaos" and api.first_seen == first_seen and api.last_job_id == j2.id
    assert api.last_seen >= first_seen


def test_probe_updates_rows_and_marks_silent_hosts(db):
    j1 = make_job(db, ["example.com", "example.org"])
    dsc.complete_discovery(db, j1, SUBFINDER)
    db.commit()
    probe = make_job(db, [], kind="discovery_probe")
    hosts = ["www.example.com", "api.example.com", "mail.example.org", "dev.example.com"]
    stats = dsc.ingest_probe(db, probe, hosts, dsc.parse_httpx_jsonl(HTTPX))
    db.commit()
    rows = assets(db)
    www = rows["www.example.com"]
    assert www.web is True and www.status_code == 200 and www.url == "https://www.example.com"
    assert www.ips == "192.0.2.10,192.0.2.11" and www.tech == "Nginx,WordPress:6.4" and www.webserver == "nginx/1.25"
    assert www.last_probed_at is not None and www.link == "https://www.example.com"
    assert rows["api.example.com"].web is True and rows["api.example.com"].link == ""   # javascript: never linked
    for h in ("mail.example.org", "dev.example.com"):
        assert rows[h].web is False and rows[h].last_probed_at is not None
    assert "unrelated.example.net" not in rows
    assert stats == {"probed": 4, "web": 2}


def test_scope_resolved_from_ip_or_hostname(db):
    db.add(Scope(name="DMZ", targets="192.0.2.0/24", exclusions="", criticality="high"))
    db.add(Scope(name="Mail", targets="mail.example.org", exclusions="", criticality="low"))
    db.commit()
    j1 = make_job(db, ["example.com", "example.org"])
    dsc.complete_discovery(db, j1, SUBFINDER)
    dsc.ingest_probe(db, make_job(db, [], kind="discovery_probe"), ["www.example.com"], dsc.parse_httpx_jsonl(HTTPX))
    db.commit()
    scopes = {s.name: s.id for s in db.scalars(select(Scope))}
    rows = assets(db)
    assert rows["www.example.com"].scope_id == scopes["DMZ"]
    assert rows["mail.example.org"].scope_id == scopes["Mail"]
    assert rows["api.example.com"].scope_id is None


# ----------------------------------------------------------------- changes + notification
def test_subdomain_new_changes_baseline_and_single_notification(client, db):
    channel(client, "slack", secret=SLACK, events=("surface.changed",), min_severity="low")
    j1 = make_job(db, ["example.com"])
    stats = dsc.complete_discovery(db, j1, sf("www.example.com", "api.example.com"))
    db.commit()
    finish(db, j1)
    rows = list(db.scalars(select(SurfaceChange).where(SurfaceChange.job_id == j1.id)))
    assert [(c.kind, c.address, c.hostname, c.severity, c.after) for c in rows] == [
        ("subdomain_new", "api.example.com", "api.example.com", "medium", "crtsh"),
        ("subdomain_new", "www.example.com", "www.example.com", "medium", "crtsh")]
    assert stats["baseline"] is True and list(db.scalars(select(Delivery))) == []

    j2 = make_job(db, ["example.com"])
    dsc.complete_discovery(db, j2, sf("www.example.com", "api.example.com", "vpn.example.com", "git.example.com"))
    db.commit()
    finish(db, j2)
    assert [c.address for c in db.scalars(select(SurfaceChange).where(SurfaceChange.job_id == j2.id))] == \
        ["git.example.com", "vpn.example.com"]
    deliveries = list(db.scalars(select(Delivery)))
    assert len(deliveries) == 1
    msg = json.loads(deliveries[0].payload)["message"]
    assert msg["title"] == f"[SURFACE] discovery job #{j2.id}: 2 new subdomains"
    assert msg["url"].endswith(f"/changes?job={j2.id}") and "+ vpn.example.com new subdomain" in msg["text"]

    # a new root in the same job is its own baseline: only example.com's newcomer is notified
    j3 = make_job(db, ["example.com", "example.org"])
    dsc.complete_discovery(db, j3, sf("new.example.com") + "\n" + sf("www.example.org", root="example.org"))
    db.commit()
    assert len(list(db.scalars(select(SurfaceChange).where(SurfaceChange.job_id == j3.id)))) == 2
    deliveries = list(db.scalars(select(Delivery).order_by(Delivery.id)))
    assert len(deliveries) == 2
    assert json.loads(deliveries[1].payload)["message"]["title"].endswith(": 1 new subdomain")


def test_notification_failure_never_fails_the_job(client, db, monkeypatch):
    from app import notifications as nt
    j1 = make_job(db, ["example.com"])
    dsc.complete_discovery(db, j1, sf("www.example.com"))
    finish(db, j1)

    def boom(*a, **kw):
        raise RuntimeError("channel exploded")
    monkeypatch.setattr(nt, "notify", boom)
    j2 = make_job(db, ["example.com"])
    stats = dsc.complete_discovery(db, j2, sf("vpn.example.com"))
    db.commit()
    assert stats["new"] == 1 and "vpn.example.com" in assets(db)


def test_subdomain_new_is_an_added_surface_kind():
    assert surface.KIND_LABELS["subdomain_new"] == "New subdomain"
    assert surface.KIND_SEVERITY["subdomain_new"] == "medium"
    assert "subdomain_new" in trends.SURFACE_ADDED
    rows = [SurfaceChange(kind="subdomain_new"), SurfaceChange(kind="subdomain_new"), SurfaceChange(kind="host_new")]
    assert surface.title_counts(surface.summarize(rows)) == "1 new host, 2 new subdomains"


def test_changes_page_filters_subdomain_new(auth, db):
    j1 = make_job(db, ["example.com"])
    dsc.complete_discovery(db, j1, sf("www.example.com"))
    db.commit()
    r = auth.get("/changes?kind=subdomain_new")
    assert r.status_code == 200 and "New subdomain" in r.text and "www.example.com" in r.text


# ----------------------------------------------------------------- end to end with fake tools
def start(client, domains="example.com\nexample.org", probe=True):
    csrf = get_csrf(client, "/discovery")
    data = {"csrf": csrf, "domains": domains}
    if probe:
        data["probe"] = "true"
    return client.post("/discovery/scan", data=data, follow_redirects=False)


def job_id_of(r):
    assert r.status_code == 303, r.text[:500]
    return int(r.headers["location"].rsplit("/", 1)[1])


def probe_job(client, parent_id):
    with client.app.state.SessionLocal() as s:
        for j in s.scalars(select(Job).where(Job.kind == "discovery_probe")):
            if json.loads(j.params_json).get("parent_job") == parent_id:
                return j.id
    return None


def wait_for_probe(client, parent_id, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        pid = probe_job(client, parent_id)
        if pid:
            return pid
        time.sleep(0.05)
    raise AssertionError("no probe job")


def tmp_files(client):
    d = client.app.state.settings.data_dir / "tmp"
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


def test_discovery_job_end_to_end(auth, fake_bins):
    jid = job_id_of(start(auth))
    assert wait_job(auth, jid)["status"] == "done"
    pid = wait_for_probe(auth, jid)
    assert wait_job(auth, pid)["status"] == "done"
    assert (fake_bins / "domains_seen.txt").read_text() == "example.com\nexample.org\n"
    assert not (fake_bins / "pc_seen.yaml").exists()            # no keys configured: no -pc
    assert sorted((fake_bins / "hosts_seen.txt").read_text().split()) == \
        ["api.example.com", "dev.example.com", "mail.example.org", "www.example.com"]
    assert tmp_files(auth) == []                                 # domains + hosts files removed
    with auth.app.state.SessionLocal() as s:
        job, probe = s.get(Job, jid), s.get(Job, pid)
        assert "-dL" in job.command and "-pc" not in job.command
        params = json.loads(probe.params_json)
        assert params["parent_job"] == jid and "-tech-detect" in probe.command
        rows = assets(s)
        assert rows["www.example.com"].web is True and rows["dev.example.com"].web is False
        audit = s.scalar(select(AuditLog).where(AuditLog.action == "scan.discovery"))
        assert audit is not None and "example.com" in audit.target
    r = auth.get(f"/jobs/{jid}")
    assert "[discovery] 4 subdomain(s)" in r.text and f"/jobs/{pid}" in r.text
    assert "Jobs" in auth.get("/jobs").text and "discovery_probe" in auth.get("/jobs").text


def test_no_probe_job_when_probe_off_or_no_hosts(auth):
    jid = job_id_of(start(auth, probe=False))
    assert wait_job(auth, jid)["status"] == "done"
    jid2 = job_id_of(start(auth, domains="example.net"))      # the fixture has nothing under example.net
    assert wait_job(auth, jid2)["status"] == "done"
    time.sleep(0.3)
    assert probe_job(auth, jid) is None and probe_job(auth, jid2) is None
    with auth.app.state.SessionLocal() as s:
        assert assets(s)["www.example.com"].last_probed_at is None


def test_probe_host_cap(auth, fake_bins, monkeypatch):
    monkeypatch.setattr(dsc, "MAX_PROBE_HOSTS", 2)
    jid = job_id_of(start(auth))
    wait_job(auth, jid)
    pid = wait_for_probe(auth, jid)
    wait_job(auth, pid)
    assert len((fake_bins / "hosts_seen.txt").read_text().split()) == 2
    assert "2 host(s) over the 2-host probe cap were not probed" in auth.get(f"/jobs/{jid}").text


def test_ignored_hosts_are_not_probed(auth, fake_bins):
    jid = job_id_of(start(auth, probe=False))
    wait_job(auth, jid)
    with auth.app.state.SessionLocal() as s:
        s.scalar(select(DiscoveredAsset).where(DiscoveredAsset.hostname == "dev.example.com")).ignored = True
        s.commit()
    jid = job_id_of(start(auth))
    wait_job(auth, jid)
    wait_job(auth, wait_for_probe(auth, jid))
    assert "dev.example.com" not in (fake_bins / "hosts_seen.txt").read_text()


def test_start_rejects_bad_domains(auth):
    r = start(auth, domains="https://example.com/x")
    assert r.status_code == 400 and "scheme" in r.text
    r = start(auth, domains="10.0.0.0/8")
    assert r.status_code == 400 and "IP" in r.text
    with auth.app.state.SessionLocal() as s:
        assert s.scalar(select(Job)) is None or s.scalar(select(Job).where(Job.kind == "discovery")) is None


def test_viewer_cannot_start(auth):
    make_user(auth, "vera", "viewer")
    login_as(auth, "vera")
    csrf = get_csrf(auth, "/discovery")
    r = auth.post("/discovery/scan", data={"csrf": csrf, "domains": "example.com"}, follow_redirects=False)
    assert r.status_code == 403


# ----------------------------------------------------------------- missing binaries
def test_page_and_start_when_binaries_missing(tmp_path):
    from fastapi.testclient import TestClient
    from app.main import create_app
    from tests.conftest import login_and_change_password, offline_get_json
    data = tmp_path / "data"
    (data / "nuclei-templates").mkdir(parents=True)
    s = Settings(data_dir=data, nmap_bin="/nonexistent/nmap", nuclei_bin="/nonexistent/nuclei",
                 subfinder_bin="/nonexistent/subfinder", httpx_bin="/nonexistent/httpx", secret_key="k")
    app = create_app(s)
    app.state.get_json = offline_get_json
    with TestClient(app) as c:
        login_and_change_password(c)
        r = c.get("/discovery")
        assert r.status_code == 200 and "subfinder is not installed" in r.text and "httpx is not installed" in r.text
        r = start(c)
        assert r.status_code == 400 and "subfinder is not installed" in r.text
        with app.state.SessionLocal() as db:
            assert db.scalar(select(Job).where(Job.kind == "discovery")) is None


def test_tools_status(settings):
    assert dsc.tools_status(settings) == {"subfinder": True, "httpx": True}
    settings.httpx_bin = "/nonexistent/httpx"
    assert dsc.tools_status(settings) == {"subfinder": True, "httpx": False}


def test_settings_defaults_from_env(monkeypatch, tmp_path):
    from app.config import settings_from_env
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "d"))
    monkeypatch.setenv("SUBFINDER_BIN", "/opt/pd/subfinder")
    monkeypatch.setenv("HTTPX_BIN", "/opt/pd/httpx")
    s = settings_from_env()
    assert s.subfinder_bin == "/opt/pd/subfinder" and s.httpx_bin == "/opt/pd/httpx"
    assert (s.data_dir / "tmp").is_dir() and s.tmp_dir == s.data_dir / "tmp"


# ----------------------------------------------------------------- page, XSS, bulk actions
def seeded(client):
    with client.app.state.SessionLocal() as s:
        j = make_job(s, ["example.com", "example.org"])
        dsc.complete_discovery(s, j, SUBFINDER)
        dsc.ingest_probe(s, make_job(s, [], kind="discovery_probe"),
                         ["www.example.com", "api.example.com", "mail.example.org", "dev.example.com"],
                         dsc.parse_httpx_jsonl(HTTPX))
        s.commit()
        return {a.hostname: a.id for a in s.scalars(select(DiscoveredAsset))}


def test_page_lists_assets_and_escapes_external_text(auth):
    seeded(auth)
    r = auth.get("/discovery")
    assert r.status_code == 200
    assert "www.example.com" in r.text and "mail.example.org" in r.text
    assert "<script>alert(1)" not in r.text and "&lt;script&gt;alert(1)&lt;/script&gt;Welcome" in r.text
    assert 'href="javascript:' not in r.text
    assert re.search(r'<a href="https://www.example.com" rel="noopener noreferrer" target="_blank"', r.text)
    assert "Only enumerate domains you own or are authorized to test." in r.text


def test_page_filters(auth):
    seeded(auth)
    page = lambda q: auth.get("/discovery?" + q).text  # noqa: E731
    t = page("web=web")
    assert "www.example.com" in t and "mail.example.org" not in t
    t = page("web=none")
    assert "mail.example.org" in t and "www.example.com" not in t
    t = page("root=example.org")
    assert "mail.example.org" in t and "www.example.com" not in t
    t = page("q=wordpress")
    assert "www.example.com" in t and "api.example.com" not in t
    with auth.app.state.SessionLocal() as s:
        a = s.scalar(select(DiscoveredAsset).where(DiscoveredAsset.hostname == "dev.example.com"))
        a.ignored = True
        s.scalar(select(DiscoveredAsset).where(DiscoveredAsset.hostname == "api.example.com")).first_seen = \
            utcnow() - timedelta(days=30)
        s.commit()
    assert "dev.example.com" not in page("")
    t = page("state=ignored")
    assert "dev.example.com" in t and "www.example.com" not in t
    assert "dev.example.com" in page("state=all")
    t = page("new=1")
    assert "www.example.com" in t and "api.example.com" not in t


def test_sidebar_has_discovery_after_nuclei(auth):
    r = auth.get("/")
    assert r.text.index('href="/nuclei"') < r.text.index('href="/discovery"') < r.text.index('href="/findings"')


def test_bulk_scan_prefill_redirects(auth):
    ids = seeded(auth)
    csrf = get_csrf(auth, "/discovery")
    sel = [ids["www.example.com"], ids["api.example.com"]]
    r = auth.post("/discovery/to-nmap", data={"csrf": csrf, "asset_ids": sel}, follow_redirects=False)
    assert r.status_code == 303
    loc = urlparse(r.headers["location"])
    assert loc.path == "/nmap"
    assert parse_qs(loc.query)["targets"][0].split("\n") == ["api.example.com", "www.example.com"]
    page = auth.get(r.headers["location"]).text
    assert "api.example.com\nwww.example.com</textarea>" in page
    r = auth.post("/discovery/to-nuclei", data={"csrf": csrf, "asset_ids": sel}, follow_redirects=False)
    loc = urlparse(r.headers["location"])
    assert loc.path == "/nuclei"
    assert parse_qs(loc.query)["targets"][0].split("\n") == ["api.example.com", "https://www.example.com"]
    r = auth.post("/discovery/to-nuclei", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303 and "msg=" in r.headers["location"] and r.headers["location"].startswith("/discovery")


def test_bulk_scan_needs_scan_run_and_csrf(auth):
    ids = seeded(auth)
    r = auth.post("/discovery/to-nmap", data={"csrf": "nope", "asset_ids": [ids["www.example.com"]]},
                  follow_redirects=False)
    assert r.status_code == 403
    make_user(auth, "vera", "viewer")
    login_as(auth, "vera")
    csrf = get_csrf(auth, "/discovery")
    r = auth.post("/discovery/to-nmap", data={"csrf": csrf, "asset_ids": [ids["www.example.com"]]},
                  follow_redirects=False)
    assert r.status_code == 403


def test_ignore_unignore(auth):
    ids = seeded(auth)
    csrf = get_csrf(auth, "/discovery")
    r = auth.post("/discovery/ignore", data={"csrf": csrf, "asset_ids": [ids["dev.example.com"]]}, follow_redirects=False)
    assert r.status_code == 303 and "msg=" in r.headers["location"]
    with auth.app.state.SessionLocal() as s:
        a = s.get(DiscoveredAsset, ids["dev.example.com"])
        assert a.ignored and a.ignored_by == "admin" and a.ignored_at is not None
        row = s.scalar(select(AuditLog).where(AuditLog.action == "discovery.ignore"))
        assert row is not None and "dev.example.com" in row.details
    r = auth.post("/discovery/unignore", data={"csrf": csrf, "asset_ids": [ids["dev.example.com"]]},
                  follow_redirects=False)
    assert r.status_code == 303
    with auth.app.state.SessionLocal() as s:
        a = s.get(DiscoveredAsset, ids["dev.example.com"])
        assert not a.ignored and a.ignored_by == "" and a.ignored_at is None
        assert s.scalar(select(AuditLog).where(AuditLog.action == "discovery.unignore")) is not None


def test_ignore_permissions_and_csrf(auth):
    ids = seeded(auth)
    r = auth.post("/discovery/ignore", data={"csrf": "bad", "asset_ids": [ids["dev.example.com"]]},
                  follow_redirects=False)
    assert r.status_code == 403
    make_user(auth, "vera", "viewer")
    login_as(auth, "vera")
    csrf = get_csrf(auth, "/discovery")
    r = auth.post("/discovery/ignore", data={"csrf": csrf, "asset_ids": [ids["dev.example.com"]]},
                  follow_redirects=False)
    assert r.status_code == 403
    with auth.app.state.SessionLocal() as s:
        assert not s.get(DiscoveredAsset, ids["dev.example.com"]).ignored
    page = auth.get("/discovery").text
    assert 'action="/discovery/scan"' not in page and 'formaction="/discovery/ignore"' not in page


# ----------------------------------------------------------------- source API keys
def save_keys(client, **fields):
    csrf = get_csrf(client, "/settings")
    return client.post("/settings/discovery-keys", data={"csrf": csrf, **fields}, follow_redirects=False)


def test_source_keys_stored_encrypted_and_never_rendered(auth):
    r = save_keys(auth, key_securitytrails=KEY, key_censys="cid:csecret-XYZ")
    assert r.status_code == 303 and KEY not in r.headers["location"]
    page = auth.get("/settings").text
    assert KEY not in page and "csecret-XYZ" not in page
    assert 'data-provider="securitytrails">set<' in page and 'data-provider="censys">set<' in page
    assert 'data-provider="shodan">not set<' in page
    with auth.app.state.SessionLocal() as s:
        from app.db import AppSetting
        raw = s.get(AppSetting, dsc.KEYS_SETTING).value
        assert KEY not in raw
        assert dsc.get_source_keys(s, auth.app.state.secretbox) == {"securitytrails": KEY, "censys": "cid:csecret-XYZ"}
        audit = s.scalar(select(AuditLog).where(AuditLog.action == "settings.discovery_keys"))
        assert "securitytrails" in audit.details and KEY not in audit.details and "csecret" not in audit.details
    # blank keeps, remove deletes
    save_keys(auth, remove_censys="true")
    with auth.app.state.SessionLocal() as s:
        assert dsc.get_source_keys(s, auth.app.state.secretbox) == {"securitytrails": KEY}


def test_source_key_validation_never_echoes_key(auth):
    r = save_keys(auth, key_fofa="no-colon-SECRETVALUE")
    assert r.status_code == 400 and "email:key" in r.text and "SECRETVALUE" not in r.text
    r = save_keys(auth, key_shodan="abc\ndef")
    assert r.status_code == 400 and "single value" in r.text and "abc\ndef" not in r.text and "abc&#10;def" not in r.text


def test_source_keys_need_settings_manage(auth):
    make_user(auth, "ana", "analyst")
    login_as(auth, "ana")
    csrf = get_csrf(auth, "/discovery")
    r = auth.post("/settings/discovery-keys", data={"csrf": csrf, "key_shodan": KEY}, follow_redirects=False)
    assert r.status_code == 403


def test_provider_config_written_0600_and_removed(auth, fake_bins):
    save_keys(auth, key_securitytrails=KEY, key_fofa="me@example.com:fofakey")
    jid = job_id_of(start(auth, probe=False))
    assert wait_job(auth, jid)["status"] == "done"
    assert (fake_bins / "pc_mode.txt").read_text().strip() == "-rw-------"
    cfg = (fake_bins / "pc_seen.yaml").read_text()
    assert f'securitytrails:\n  - "{KEY}"' in cfg and 'fofa:\n  - "me@example.com:fofakey"' in cfg
    assert tmp_files(auth) == []
    with auth.app.state.SessionLocal() as s:
        job = s.get(Job, jid)
        assert f"subfinder-{jid}.yaml" in job.command and KEY not in job.command and KEY not in (job.log or "")
        assert KEY not in job.params_json
        assert all(KEY not in (a.details + a.target) for a in s.scalars(select(AuditLog)))
    assert KEY not in auth.get(f"/jobs/{jid}").text


def test_provider_config_removed_on_failure(auth, fake_bins):
    save_keys(auth, key_shodan=KEY)
    jid = job_id_of(start(auth, domains="fail.example.com", probe=False))
    assert wait_job(auth, jid)["status"] == "failed"
    assert (fake_bins / "pc_seen.yaml").exists() and tmp_files(auth) == []


def test_provider_config_removed_on_cancel(auth, fake_bins):
    save_keys(auth, key_shodan=KEY)
    jid = job_id_of(start(auth, domains="slow.example.com", probe=False))
    deadline = time.time() + 10
    while not (fake_bins / "pc_seen.yaml").exists() and time.time() < deadline:
        time.sleep(0.05)
    assert tmp_files(auth) != []
    csrf = get_csrf(auth, f"/jobs/{jid}")
    auth.post(f"/jobs/{jid}/cancel", data={"csrf": csrf})
    assert wait_job(auth, jid)["status"] == "cancelled"
    assert tmp_files(auth) == []


def test_sweep_tmp_removes_leftovers(settings):
    settings.tmp_dir.mkdir(exist_ok=True)
    (settings.tmp_dir / "subfinder-9.yaml").write_text("shodan: [x]")
    (settings.tmp_dir / "discovery-9-domains.txt").write_text("example.com")
    dsc.sweep_tmp(settings)
    assert list(settings.tmp_dir.iterdir()) == []


# ----------------------------------------------------------------- schedules
def test_discovery_schedule_create_and_run(auth):
    import app.scheduler as sch
    assert sch.KINDS["discovery"] == "External discovery"
    csrf = get_csrf(auth, "/schedules")
    page = auth.get("/schedules").text
    assert 'value="discovery"' in page and 'name="domains"' in page
    r = auth.post("/schedules", data={"csrf": csrf, "kind": "discovery", "frequency": "daily", "time_of_day": "03:00",
                                      "domains": "https://bad.example.com"})
    assert r.status_code == 400 and "scheme" in r.text
    r = auth.post("/schedules", data={"csrf": csrf, "kind": "discovery", "frequency": "daily", "time_of_day": "03:00",
                                      "domains": "Example.com\nexample.org", "probe": "true"}, follow_redirects=False)
    assert r.status_code == 303
    with auth.app.state.SessionLocal() as s:
        sc = s.scalar(select(Schedule).where(Schedule.kind == "discovery"))
        assert sc.scope_id is None and json.loads(sc.config) == {"domains": ["example.com", "example.org"], "probe": True}
        assert "example.com" in sc.name
        sid = sc.id
    job_id = auth.portal.call(sch.run_schedule, auth.app, sid, True)
    assert wait_job(auth, job_id)["status"] == "done"
    assert wait_job(auth, wait_for_probe(auth, job_id))["status"] == "done"
    with auth.app.state.SessionLocal() as s:
        job = s.get(Job, job_id)
        assert job.kind == "discovery" and job.schedule_id == sid
        assert json.loads(job.params_json)["domains"] == ["example.com", "example.org"]
        assert s.get(Schedule, sid).last_status == "started"


def test_discovery_schedule_errors_when_tool_missing(auth):
    import app.scheduler as sch
    with auth.app.state.SessionLocal() as s:
        sc = Schedule(name="d", kind="discovery", frequency="daily", time_of_day="02:00",
                      config=json.dumps({"domains": ["example.com"], "probe": True}))
        s.add(sc)
        s.commit()
        sid = sc.id
    auth.app.state.settings.subfinder_bin = "/nonexistent/subfinder"
    assert auth.portal.call(sch.run_schedule, auth.app, sid, True) is None
    with auth.app.state.SessionLocal() as s:
        sc = s.get(Schedule, sid)
        assert sc.last_status == "error" and "not installed" in sc.last_message


# ----------------------------------------------------------------- updates
def test_update_actions_for_subfinder_and_httpx(auth, settings):
    from app.updates import UPDATE_ACTIONS, build_update_argv
    assert build_update_argv(settings, "subfinder") == [settings.subfinder_bin, "-update"]
    assert build_update_argv(settings, "httpx") == [settings.httpx_bin, "-update"]
    assert UPDATE_ACTIONS["subfinder"]["label"] == "Update subfinder" and UPDATE_ACTIONS["httpx"]["label"] == "Update httpx"
    r = auth.get("/updates")
    assert "v2.17.0" in r.text and "v1.12.0" in r.text
    csrf = get_csrf(auth, "/updates")
    for action in ("subfinder", "httpx"):
        r = auth.post(f"/updates/{action}", data={"csrf": csrf}, follow_redirects=False)
        jid = int(r.headers["location"].rsplit("/", 1)[1])
        assert wait_job(auth, jid)["status"] == "done"
        assert "already updated" in auth.get(f"/jobs/{jid}").text


# ----------------------------------------------------------------- API
def test_api_discovered_and_start(auth):
    from tests.test_api import api, new_key, wait_api_job
    seeded(auth)
    viewer = new_key(auth, name="v", role="viewer")
    analyst = new_key(auth, name="a", role="analyst")
    body = api(auth, viewer, "GET", "/discovered").json()
    assert body["count"] == 4
    item = next(i for i in body["items"] if i["hostname"] == "www.example.com")
    assert item["web"] is True and item["status_code"] == 200 and item["ips"] == ["192.0.2.10", "192.0.2.11"]
    assert item["tech"] == ["Nginx", "WordPress:6.4"] and item["root_domain"] == "example.com"
    assert item["first_seen"].endswith("Z") and item["ignored"] is False
    assert api(auth, viewer, "GET", "/discovered?root=example.org").json()["count"] == 1
    assert api(auth, viewer, "GET", "/discovered?web=web").json()["count"] == 2
    assert api(auth, viewer, "GET", "/discovered?web=none").json()["count"] == 2
    assert api(auth, viewer, "GET", "/discovered?limit=1").json()["count"] == 1
    assert api(auth, viewer, "GET", "/discovered?state=ignored").json()["count"] == 0
    assert api(auth, viewer, "POST", "/scans/discovery", json={"domains": ["example.com"]}).status_code == 403
    r = api(auth, analyst, "POST", "/scans/discovery", json={"domains": ["https://x.example.com"]})
    assert r.status_code == 400 and "scheme" in r.json()["detail"]
    r = api(auth, analyst, "POST", "/scans/discovery", json={"domains": ["example.com"], "probe": False})
    assert r.status_code == 202
    jid = r.json()["job_id"]
    assert wait_api_job(auth, analyst, jid) == "done"
    with auth.app.state.SessionLocal() as s:
        assert json.loads(s.get(Job, jid).params_json)["probe"] is False


def test_api_docs_list_discovery(auth):
    r = auth.get("/api-docs")
    assert "/api/v1/discovered" in r.text and "/api/v1/scans/discovery" in r.text


# ----------------------------------------------------------------- review fixes
def test_baseline_needs_existing_rows_for_the_root(client, db):
    """I1: a done job that found nothing does not end a root's baseline; rows for the root do."""
    channel(client, "slack", secret=SLACK, events=("surface.changed",), min_severity="low")
    j1 = make_job(db, ["example.com"])
    assert dsc.complete_discovery(db, j1, "")["baseline"] is True
    finish(db, j1)
    j2 = make_job(db, ["example.com"])
    stats = dsc.complete_discovery(db, j2, sf("www.example.com", "api.example.com"))
    db.commit()
    finish(db, j2)
    assert stats["baseline"] is True and stats["notified"] == 0 and list(db.scalars(select(Delivery))) == []
    j3 = make_job(db, ["example.com"])
    stats = dsc.complete_discovery(db, j3, sf("vpn.example.com"))
    db.commit()
    assert stats["baseline"] is False and stats["notified"] == 1 and len(list(db.scalars(select(Delivery)))) == 1


def test_idna_2008_uts46():
    """I2: IDNA 2008 / UTS46 non-transitional: ß is kept, not mapped to ss."""
    assert dsc.parse_root_domains("faß.de") == ["xn--fa-hia.de"]
    assert dsc.parse_root_domains("FAß.de") == ["xn--fa-hia.de"]
    assert dsc.normalize_hostname("WWW.Faß.de.") == "www.xn--fa-hia.de"
    assert dsc.normalize_hostname("_dmarc.example.com") == "_dmarc.example.com"   # ASCII path keeps '_'
    with pytest.raises(ValueError, match="valid DNS name"):
        dsc.parse_root_domains("a\u200db.example")


def test_probe_order_new_then_never_then_oldest(db):
    """I3: new hosts first, then never-probed, then the longest-unprobed; the cap rotates through the rest."""
    now = utcnow()
    j = make_job(db, ["example.com"])
    dsc.complete_discovery(db, j, sf("a.example.com", "b.example.com", "c.example.com"))
    rows = assets(db)
    rows["a.example.com"].last_probed_at = now - timedelta(days=2)
    rows["b.example.com"].last_probed_at = now - timedelta(days=1)
    db.commit()
    j2 = make_job(db, ["example.com"])
    stats = dsc.complete_discovery(db, j2, sf("a.example.com", "b.example.com", "c.example.com", "d.example.com"))
    assert stats["new_hostnames"] == ["d.example.com"]
    order = dsc.probe_order(db, stats["hostnames"], set(stats["new_hostnames"]))
    assert order == ["d.example.com", "c.example.com", "a.example.com", "b.example.com"]
    # with a cap of 2, the two left out are first next time
    dsc.ingest_probe(db, make_job(db, [], kind="discovery_probe"), order[:2], {})
    db.commit()
    assert dsc.probe_order(db, order, set())[:2] == ["a.example.com", "b.example.com"]


def test_ignored_hosts_left_out_of_probe_order(db):
    j = make_job(db, ["example.com"])
    dsc.complete_discovery(db, j, sf("a.example.com", "b.example.com"))
    assets(db)["a.example.com"].ignored = True
    db.commit()
    assert dsc.probe_order(db, ["a.example.com", "b.example.com"], set()) == ["b.example.com"]


def test_hooks_run_off_the_event_loop(auth, monkeypatch):
    """I5: ingest runs in a worker thread, so a large ingest never blocks HTTP; the chained probe still starts."""
    import asyncio
    seen = {}
    real = dsc.complete_discovery

    def spy(db, job, output):
        try:
            asyncio.get_running_loop()
            seen["loop"] = True
        except RuntimeError:
            seen["loop"] = False
        return real(db, job, output)
    monkeypatch.setattr(dsc, "complete_discovery", spy)
    jid = job_id_of(start(auth))
    assert wait_job(auth, jid)["status"] == "done"
    assert seen == {"loop": False}
    assert wait_job(auth, wait_for_probe(auth, jid))["status"] == "done"


def test_cancelling_parent_starts_no_probe(auth):
    jid = job_id_of(start(auth, domains="slow.example.com"))
    deadline = time.time() + 10
    while auth.get(f"/jobs/{jid}/status").json()["status"] != "running" and time.time() < deadline:
        time.sleep(0.05)
    csrf = get_csrf(auth, f"/jobs/{jid}")
    auth.post(f"/jobs/{jid}/cancel", data={"csrf": csrf})
    assert wait_job(auth, jid)["status"] == "cancelled"
    time.sleep(0.3)
    assert probe_job(auth, jid) is None


def test_failing_probe_hook_fails_only_the_probe(auth, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("probe ingest exploded")
    monkeypatch.setattr(dsc, "ingest_probe", boom)
    jid = job_id_of(start(auth))
    assert wait_job(auth, jid)["status"] == "done"
    pid = wait_for_probe(auth, jid)
    assert wait_job(auth, pid)["status"] == "failed"
    assert wait_job(auth, jid)["status"] == "done"
    assert tmp_files(auth) == []
    with auth.app.state.SessionLocal() as s:
        assert assets(s)["www.example.com"].last_probed_at is None


def test_probe_start_failure_keeps_parent_done(auth, monkeypatch):
    """M6: the parent's ingest is committed; a probe that cannot start is a failed probe job, not a failed parent."""
    real = dsc._write_tmp

    def flaky(path, lines):
        if path.name.startswith("httpx-"):
            raise OSError(28, "No space left on device")
        return real(path, lines)
    monkeypatch.setattr(dsc, "_write_tmp", flaky)
    jid = job_id_of(start(auth))
    assert wait_job(auth, jid)["status"] == "done"
    pid = probe_job(auth, jid)
    assert pid is not None and wait_job(auth, pid)["status"] == "failed"
    with auth.app.state.SessionLocal() as s:
        assert "No space left on device" in s.get(Job, pid).log and "www.example.com" in assets(s)
    assert "web probe could not start" in auth.get(f"/jobs/{jid}").text


def test_tmp_write_failure_fails_the_job_cleanly(auth):
    """M6: no stuck queued job and no 500 when DATA_DIR/tmp cannot be written."""
    tmp = auth.app.state.settings.tmp_dir
    tmp.rmdir()
    tmp.write_text("not a directory")
    try:
        r = start(auth)
        assert r.status_code == 400 and "temporary file" in r.text
        with auth.app.state.SessionLocal() as s:
            job = s.scalar(select(Job).where(Job.kind == "discovery"))
            assert job.status == "failed" and job.finished_at is not None and "temporary file" in job.log
    finally:
        tmp.unlink()
        tmp.mkdir()


def test_provider_config_yaml_round_trip(settings):
    import yaml
    keys = {"shodan": 'a"b\\c', "fofa": "me@example.com:k'ey\\\"", "github": "ghp_x#y: z"}
    path = dsc.write_provider_config(settings, 77, keys)
    assert yaml.safe_load(path.read_text()) == {k: [v] for k, v in keys.items()}


def test_source_keys_redacted_from_job_log(auth):
    """M8: whatever the tool prints, stored key values never reach the job log."""
    save_keys(auth, key_shodan=KEY, key_censys="censys_pat_ABCDEF:org-123456")
    jid = job_id_of(start(auth, domains="leak.example.com", probe=False))
    assert wait_job(auth, jid)["status"] == "done"
    with auth.app.state.SessionLocal() as s:
        log = s.get(Job, jid).log
    assert "provider config" in log and "[redacted]" in log
    assert KEY not in log and "censys_pat_ABCDEF" not in log and "org-123456" not in log
    page = auth.get(f"/jobs/{jid}").text
    assert KEY not in page and "censys_pat_ABCDEF" not in page


def test_censys_key_is_pat_with_optional_org(auth):
    """M1: subfinder 2.17 takes a Censys Personal Access Token, optionally with ':orgID'."""
    assert dsc.PROVIDERS["censys"][1] == "pat:orgID"
    assert save_keys(auth, key_censys="censys_pat_only").status_code == 303
    assert save_keys(auth, key_censys="censys_pat:org-1").status_code == 303
    assert "pat:orgID" in auth.get("/settings").text


def test_python_httpx_is_not_projectdiscovery(settings, fake_bins, monkeypatch):
    """M3: an httpx under sys.prefix is the Python client's script, not the prober."""
    import sys
    monkeypatch.setattr(sys, "prefix", str(fake_bins.parent))
    assert dsc.tools_status(settings) == {"subfinder": True, "httpx": False}
    assert "Python" in dsc.missing_tool_message(settings, "httpx")


def test_web_false_clears_status_and_nuclei_uses_url_only_when_web(db):
    """M4"""
    j = make_job(db, ["example.com"])
    dsc.complete_discovery(db, j, sf("www.example.com"))
    dsc.ingest_probe(db, make_job(db, [], kind="discovery_probe"), ["www.example.com"], dsc.parse_httpx_jsonl(HTTPX))
    a = assets(db)["www.example.com"]
    assert dsc.nuclei_target(a) == "https://www.example.com"
    dsc.ingest_probe(db, make_job(db, [], kind="discovery_probe"), ["www.example.com"], {})
    assert a.web is False and a.status_code is None
    assert dsc.nuclei_target(a) == "www.example.com"


def test_api_only_safe_links_and_no_stale_web_fields(auth):
    """M4 / M5"""
    from tests.test_api import api, new_key
    seeded(auth)
    key = new_key(auth, name="v", role="viewer")
    items = {i["hostname"]: i for i in api(auth, key, "GET", "/discovered").json()["items"]}
    assert items["api.example.com"]["url"] is None and items["api.example.com"]["title"] == "Forbidden"
    assert items["www.example.com"]["url"] == "https://www.example.com"
    with auth.app.state.SessionLocal() as s:
        a = s.scalar(select(DiscoveredAsset).where(DiscoveredAsset.hostname == "www.example.com"))
        a.web = False
        s.commit()
    w = next(i for i in api(auth, key, "GET", "/discovered").json()["items"] if i["hostname"] == "www.example.com")
    assert w["web"] is False and w["url"] is None and w["title"] is None and w["status_code"] is None
    assert w["webserver"] is None and w["tech"] == [] and w["last_probed_at"].endswith("Z")


def test_api_domains_cap_offset_and_public_suffix(auth):
    """M10"""
    from tests.test_api import api, new_key
    seeded(auth)
    viewer = new_key(auth, name="v", role="viewer")
    analyst = new_key(auth, name="a", role="analyst")
    r = api(auth, analyst, "POST", "/scans/discovery", json={"domains": [f"d{i}.example.com" for i in range(500)]})
    assert r.status_code == 400 and "20" in r.json()["detail"]
    for suffix in ("co.uk", "github.io", "com.au"):
        r = api(auth, analyst, "POST", "/scans/discovery", json={"domains": [suffix]})
        assert r.status_code == 400 and "public suffix" in r.json()["detail"]
    all_names = [i["hostname"] for i in api(auth, viewer, "GET", "/discovered").json()["items"]]
    page2 = api(auth, viewer, "GET", "/discovered?limit=2&offset=2").json()
    assert [i["hostname"] for i in page2["items"]] == all_names[2:4] and page2["offset"] == 2


def test_prefill_pages_never_create_a_job(auth):
    r1 = auth.get("/nmap?targets=" + "scanme.example.com%0A192.0.2.1")
    r2 = auth.get("/nuclei?targets=" + "https%3A%2F%2Fwww.example.com")
    assert r1.status_code == 200 and "scanme.example.com\n192.0.2.1</textarea>" in r1.text
    assert r2.status_code == 200 and "https://www.example.com</textarea>" in r2.text
    with auth.app.state.SessionLocal() as s:
        assert s.scalar(select(Job)) is None


def test_changes_page_links_subdomain_to_discovery(auth, db):
    """M7"""
    j1 = make_job(db, ["example.com"])
    dsc.complete_discovery(db, j1, sf("www.example.com"))
    db.commit()
    r = auth.get("/changes")
    assert 'href="/discovery?q=www.example.com"' in r.text and "Sources:" in r.text
    assert 'href="/inventory?q=www.example.com"' not in r.text
    long_name = ("a" * 60 + ".") * 3 + "example.com"
    j2 = make_job(db, ["example.com"])
    dsc.complete_discovery(db, j2, sf(long_name))
    db.commit()
    assert db.scalar(select(SurfaceChange).where(SurfaceChange.job_id == j2.id)).address == long_name
    assert SurfaceChange.__table__.c.address.type.length == 255


def test_notification_text(client, db):
    channel(client, "slack", secret=SLACK, events=("surface.changed",), min_severity="low")
    j1 = make_job(db, ["example.com"])
    dsc.complete_discovery(db, j1, sf("www.example.com"))
    finish(db, j1)
    j2 = make_job(db, ["example.com"])
    dsc.complete_discovery(db, j2, sf("vpn.example.com", source="chaos") + "\n" + sf("vpn.example.com", source="crtsh"))
    db.commit()
    msg = json.loads(db.scalar(select(Delivery)).payload)["message"]
    assert msg["text"] == "+ vpn.example.com new subdomain (chaos, crtsh)"
    assert msg["severity"] == "medium" and msg["data"]["counts"]["subdomain_new"] == 1
    assert ["Job", f"#{j2.id} (discovery)"] in msg["fields"] and ["New subdomain", "1"] in msg["fields"]


def test_probe_cap_warning_has_no_nuclei_advice(auth, monkeypatch):
    """M9"""
    monkeypatch.setattr(dsc, "MAX_PROBE_HOSTS", 2)
    jid = job_id_of(start(auth))
    wait_job(auth, jid)
    pid = wait_for_probe(auth, jid)
    wait_job(auth, pid)
    page = auth.get(f"/jobs/{pid}").text
    assert "Done with warnings" in page and "probe cap" in page
    assert "Gentle profile" not in page and "Never drop unresponsive hosts" not in page
    assert "next discovery run probes them first" in page


# ----------------------------------------------------------------- write-lock hold (re-review)
def _count_commits(db):
    from sqlalchemy import event
    n = {"commits": 0}

    def on_commit(_session):
        n["commits"] += 1
    event.listen(db, "after_commit", on_commit)
    return n, lambda: event.remove(db, "after_commit", on_commit)


def test_discovery_ingest_commits_in_chunks(client, db, monkeypatch):
    """The write lock is held per chunk, not for the whole ingest; changes, baseline and the single notification
    stay correct."""
    channel(client, "slack", secret=SLACK, events=("surface.changed",), min_severity="low")
    monkeypatch.setattr(dsc, "INGEST_CHUNK", 2)
    j1 = make_job(db, ["example.com"])
    dsc.complete_discovery(db, j1, sf("a.example.com"))
    db.commit()
    finish(db, j1)
    j2 = make_job(db, ["example.com"])
    n, stop = _count_commits(db)
    hosts = [f"h{i}.example.com" for i in range(7)] + ["a.example.com"]
    stats = dsc.complete_discovery(db, j2, sf(*hosts))
    stop()
    assert n["commits"] >= 4                      # 8 hosts in chunks of 2
    assert stats["new"] == 7 and stats["notified"] == 7 and stats["baseline"] is False
    assert len(list(db.scalars(select(SurfaceChange).where(SurfaceChange.job_id == j2.id)))) == 7
    deliveries = list(db.scalars(select(Delivery)))
    assert len(deliveries) == 1 and json.loads(deliveries[0].payload)["message"]["title"].endswith(": 7 new subdomains")


def test_probe_ingest_commits_in_chunks(db, monkeypatch):
    monkeypatch.setattr(dsc, "INGEST_CHUNK", 2)
    j = make_job(db, ["example.com", "example.org"])
    dsc.complete_discovery(db, j, SUBFINDER)
    n, stop = _count_commits(db)
    stats = dsc.ingest_probe(db, make_job(db, [], kind="discovery_probe"),
                             ["www.example.com", "api.example.com", "mail.example.org", "dev.example.com"],
                             dsc.parse_httpx_jsonl(HTTPX))
    stop()
    assert n["commits"] >= 2 and stats == {"probed": 4, "web": 2}
    assert assets(db)["www.example.com"].web is True


def test_cancel_during_hook_starts_no_probe(auth, monkeypatch):
    runner = auth.app.state.job_runner
    real = dsc.complete_discovery

    def cancel_midway(db, job, output):
        stats = real(db, job, output)
        runner.cancel(job.id)               # the operator hits Cancel while results are being processed
        return stats
    monkeypatch.setattr(dsc, "complete_discovery", cancel_midway)
    jid = job_id_of(start(auth))
    wait_job(auth, jid)
    time.sleep(0.3)
    assert probe_job(auth, jid) is None
    assert "cancel requested" in auth.get(f"/jobs/{jid}").text
    with auth.app.state.SessionLocal() as s:
        assert "www.example.com" in assets(s)        # the ingest itself is kept


def test_version_probe_disables_update_check(settings, monkeypatch):
    import asyncio
    from app import updates
    seen = []

    async def capture(argv, timeout=15):
        seen.append(argv)
        return ""
    monkeypatch.setattr(updates, "_run_capture", capture)
    asyncio.run(updates.tool_versions(settings))
    assert [settings.subfinder_bin, "-version", "-duc"] in seen and [settings.httpx_bin, "-version", "-duc"] in seen
