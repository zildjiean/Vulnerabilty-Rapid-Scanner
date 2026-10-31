"""Attack-surface change detection: diffing nmap scans against the inventory, notifications, page, API."""
import json
import re

import pytest
from sqlalchemy import select

from app import notifications as nt
from app import surface
from app.db import AuditLog, Delivery, Host, Job, Scope, Service, SurfaceChange, utcnow
from app.scanners.nmap_runner import ingest_nmap_results, on_nmap_complete
from tests.conftest import get_csrf
from tests.test_notifications import SLACK, channel
from tests.test_rbac import login_as, make_user

BASE = {
    "192.168.1.10": ("web01.lab", [(22, "tcp", "ssh", "OpenSSH", "9.6p1"), (80, "tcp", "http", "Apache httpd", "2.4.58")]),
    "192.168.1.12": ("", [(3306, "tcp", "mysql", "", "")]),
}


def make_xml(hosts: dict, scaninfo: dict | None = None) -> str:
    """hosts: address -> (hostname, [(port, proto, service, product, version)]); scaninfo: proto -> services spec."""
    out = ['<?xml version="1.0"?><nmaprun scanner="nmap">']
    for proto, spec in (scaninfo or {}).items():
        out.append(f'<scaninfo type="syn" protocol="{proto}" services="{spec}"/>')
    for addr, (name, ports) in hosts.items():
        out.append(f'<host><status state="up"/><address addr="{addr}" addrtype="ipv4"/>')
        if name:
            out.append(f'<hostnames><hostname name="{name}" type="PTR"/></hostnames>')
        out.append("<ports>")
        for port, proto, svc, product, version in ports:
            out.append(f'<port protocol="{proto}" portid="{port}"><state state="open"/>'
                       f'<service name="{svc}" product="{product}" version="{version}"/></port>')
        out.append("</ports></host>")
    out.append("</nmaprun>")
    return "".join(out)


def scan(db, xml, targets=("192.168.1.0/24",), exclude=None, complete=False):
    params = {"targets": list(targets)}
    if exclude:
        params["exclude"] = list(exclude)
    job = Job(kind="nmap", status="running", params_json=json.dumps(params))
    db.add(job)
    db.commit()
    if complete:
        note = on_nmap_complete(db, job, xml)
    else:
        ingest_nmap_results(db, job, xml)
        note = ""
    db.commit()
    return job, note


def baseline(db):
    """A first scan of an unrelated host, so later scans are not the (silent) baseline."""
    scan(db, make_xml({"10.9.9.9": ("", [])}), targets=["10.9.9.9"], complete=True)


def changes(db, job):
    return list(db.scalars(select(SurfaceChange).where(SurfaceChange.job_id == job.id).order_by(SurfaceChange.id)))


@pytest.fixture
def db(client):
    with client.app.state.SessionLocal() as s:
        yield s


# ----------------------------------------------------------------- detection
def test_first_scan_records_one_host_new_per_host(db):
    job, _ = scan(db, make_xml(BASE))
    rows = changes(db, job)
    assert [(c.kind, c.address) for c in rows] == [("host_new", "192.168.1.10"), ("host_new", "192.168.1.12")]
    web = rows[0]
    assert web.severity == "medium" and web.hostname == "web01.lab" and web.port is None
    assert web.after == "22/tcp ssh OpenSSH 9.6p1; 80/tcp http Apache httpd 2.4.58"
    assert web.host_id == db.scalar(select(Host.id).where(Host.address == "192.168.1.10"))


def test_identical_rescan_records_nothing(db):
    scan(db, make_xml(BASE))
    job, _ = scan(db, make_xml(BASE))
    assert changes(db, job) == []


def test_each_kind_is_recorded(db):
    scan(db, make_xml(BASE))
    web = ("web01.lab", [(22, "tcp", "ssh", "OpenSSH", "9.7p1"), (8080, "tcp", "http", "nginx", "1.25")])
    job, _ = scan(db, make_xml({"192.168.1.10": web, "192.168.1.20": ("", [])}))
    got = {(c.kind, c.address, c.port): c for c in changes(db, job)}
    assert set(got) == {("host_new", "192.168.1.20", None), ("port_opened", "192.168.1.10", 8080),
                        ("port_closed", "192.168.1.10", 80), ("service_changed", "192.168.1.10", 22),
                        ("host_gone", "192.168.1.12", None)}
    opened = got[("port_opened", "192.168.1.10", 8080)]
    assert opened.severity == "medium" and opened.after == "http nginx 1.25" and opened.protocol == "tcp"
    closed = got[("port_closed", "192.168.1.10", 80)]
    assert closed.severity == "low" and closed.before == "http Apache httpd 2.4.58"
    changed = got[("service_changed", "192.168.1.10", 22)]
    assert (changed.before, changed.after) == ("OpenSSH 9.6p1", "OpenSSH 9.7p1")
    # host_gone keeps the host and its services in the inventory
    gone = db.scalar(select(Host).where(Host.address == "192.168.1.12"))
    assert gone is not None and [s.port for s in gone.services] == [3306]


def test_trimmed_product_version_is_not_a_change(db):
    scan(db, make_xml(BASE))
    xml = make_xml(BASE).replace('version="9.6p1"', 'version=" 9.6p1 "')
    job, _ = scan(db, xml)
    assert changes(db, job) == []


def test_host_gone_only_inside_targets_and_not_excluded(db):
    scan(db, make_xml(BASE))
    only_web = {"192.168.1.10": BASE["192.168.1.10"]}
    job, _ = scan(db, make_xml(only_web), targets=["192.168.1.10"])
    assert changes(db, job) == []
    job, _ = scan(db, make_xml(only_web), exclude=["192.168.1.12"])
    assert changes(db, job) == []
    job, _ = scan(db, make_xml(only_web), targets=["192.168.1.1-50"])
    assert [c.kind for c in changes(db, job)] == ["host_gone"]
    job, _ = scan(db, make_xml(only_web))          # already reported gone, still not responding
    assert changes(db, job) == []


def test_custom_port_scan_keeps_ports_outside_scanned_set(db):
    scan(db, make_xml(BASE))
    xml = make_xml({"192.168.1.10": ("web01.lab", [(443, "tcp", "https", "nginx", "1.25")])}, scaninfo={"tcp": "443"})
    job, _ = scan(db, xml, targets=["192.168.1.10"])
    host = db.scalar(select(Host).where(Host.address == "192.168.1.10"))
    db.refresh(host)
    assert sorted(s.port for s in host.services) == [22, 80, 443]
    assert [(c.kind, c.port) for c in changes(db, job)] == [("port_opened", 443)]
    # a port inside the scanned set that is no longer open is removed and reported
    xml = make_xml({"192.168.1.10": ("web01.lab", [])}, scaninfo={"tcp": "80,443"})
    job, _ = scan(db, xml, targets=["192.168.1.10"])
    db.refresh(host)
    assert sorted(s.port for s in host.services) == [22]
    assert sorted((c.kind, c.port) for c in changes(db, job)) == [("port_closed", 80), ("port_closed", 443)]


def test_scope_is_resolved(db):
    db.add(Scope(name="DMZ", targets="192.168.1.10", criticality="high"))
    db.commit()
    job, _ = scan(db, make_xml(BASE))
    sid = db.scalar(select(Scope.id))
    assert {c.address: c.scope_id for c in changes(db, job)} == {"192.168.1.10": sid, "192.168.1.12": None}


def test_deleting_host_keeps_change_rows(db):
    job, _ = scan(db, make_xml(BASE))
    db.delete(db.scalar(select(Host).where(Host.address == "192.168.1.12")))
    db.commit()
    db.expire_all()
    row = next(c for c in changes(db, job) if c.address == "192.168.1.12")
    assert row.host_id is None


def test_on_complete_logs_and_stores_count(db):
    baseline(db)
    job, note = scan(db, make_xml(BASE), complete=True)
    assert note.endswith(", 2 surface change(s).")
    assert json.loads(job.params_json)["result"]["changes"] == 2


def test_baseline_scan_records_but_does_not_notify(client, db):
    channel(client, "slack", secret=SLACK, events=("surface.changed",), min_severity="low")
    job, note = scan(db, make_xml(BASE), complete=True)
    assert note.endswith(", 2 surface change(s) (baseline, not notified).")
    assert [c.kind for c in changes(db, job)] == ["host_new", "host_new"]
    assert list(db.scalars(select(Delivery))) == []


def test_duplicate_host_elements_are_merged(db):
    baseline(db)
    xml = make_xml(BASE).replace("</nmaprun>", "") + (
        '<host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/>'
        '<hostnames><hostname name="www.lab" type="user"/></hostnames><ports>'
        '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6p1"/></port>'
        '<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.25"/></port>'
        '</ports></host></nmaprun>')
    job, _ = scan(db, xml)
    rows = changes(db, job)
    assert [(c.kind, c.address) for c in rows] == [("host_new", "192.168.1.10"), ("host_new", "192.168.1.12")]
    assert rows[0].hostname == "web01.lab" and "443/tcp https nginx 1.25" in rows[0].after
    host = db.scalar(select(Host).where(Host.address == "192.168.1.10"))
    assert sorted(s.port for s in host.services) == [22, 80, 443]
    job, _ = scan(db, xml)                          # rescan of the same duplicated output: nothing new
    assert changes(db, job) == []


def test_host_gone_again_after_reappearing(db):
    scan(db, make_xml(BASE))
    only_web = make_xml({"192.168.1.10": BASE["192.168.1.10"]})
    job, _ = scan(db, only_web)
    assert [c.kind for c in changes(db, job)] == ["host_gone"]
    job, _ = scan(db, make_xml(BASE))               # back again: no change kind for that
    assert changes(db, job) == []
    job, _ = scan(db, only_web)
    assert [(c.kind, c.address) for c in changes(db, job)] == [("host_gone", "192.168.1.12")]


def test_hostname_target_triggers_host_gone(db):
    scan(db, make_xml(BASE))
    job, _ = scan(db, make_xml({}), targets=["web01.lab"])
    assert [(c.kind, c.address, c.hostname) for c in changes(db, job)] == [("host_gone", "192.168.1.10", "web01.lab")]


def test_udp_service_kept_on_tcp_only_scan(db):
    web = ("web01.lab", BASE["192.168.1.10"][1] + [(53, "udp", "domain", "ISC BIND", "9.18")])
    scan(db, make_xml({"192.168.1.10": web}))
    xml = make_xml({"192.168.1.10": BASE["192.168.1.10"]}, scaninfo={"tcp": "1-1000"})
    job, _ = scan(db, xml, targets=["192.168.1.10"])
    assert changes(db, job) == []
    host = db.scalar(select(Host).where(Host.address == "192.168.1.10"))
    db.refresh(host)
    assert sorted((s.port, s.protocol) for s in host.services) == [(22, "tcp"), (53, "udp"), (80, "tcp")]


def test_empty_fingerprint_is_not_a_version_change(db):
    scan(db, make_xml(BASE))
    web = ("web01.lab", [(22, "tcp", "ssh", "", ""), (80, "tcp", "http", "Apache httpd", "2.4.58")])
    job, _ = scan(db, make_xml({"192.168.1.10": web, "192.168.1.12": BASE["192.168.1.12"]}))
    assert changes(db, job) == []
    ssh = db.scalar(select(Service).where(Service.port == 22))
    assert (ssh.product, ssh.version) == ("OpenSSH", "9.6p1")


# ----------------------------------------------------------------- notification
def test_one_notification_per_job_with_highest_severity(client, db):
    channel(client, "slack", secret=SLACK, events=("surface.changed",), min_severity="low")
    baseline(db)
    job, _ = scan(db, make_xml(BASE), complete=True)
    rows = list(db.scalars(select(Delivery)))
    assert len(rows) == 1 and rows[0].event == "surface.changed"
    msg = json.loads(rows[0].payload)["message"]
    assert msg["severity"] == "medium" and msg["title"] == f"[SURFACE] nmap job #{job.id}: 2 new hosts"
    assert msg["url"].endswith(f"/changes?job={job.id}") and msg["data"]["job_id"] == job.id
    assert msg["data"]["counts"]["host_new"] == 2 and "+ 192.168.1.10" in msg["text"]
    scan(db, make_xml(BASE), complete=True)        # nothing changed: nothing sent
    assert len(list(db.scalars(select(Delivery)))) == 1


def test_low_only_changes_skip_medium_rules(client, db):
    channel(client, "slack", secret=SLACK, events=("surface.changed",), min_severity="medium")
    scan(db, make_xml(BASE), complete=True)
    n = len(list(db.scalars(select(Delivery))))
    web = ("web01.lab", [(22, "tcp", "ssh", "OpenSSH", "9.6p1")])
    job, _ = scan(db, make_xml({"192.168.1.10": web, "192.168.1.12": BASE["192.168.1.12"]}), complete=True)
    assert [c.kind for c in changes(db, job)] == ["port_closed"]
    assert len(list(db.scalars(select(Delivery)))) == n
    assert "surface.changed" in nt.EVENTS


def test_notification_failure_does_not_fail_ingest(client, db, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("channel exploded")
    baseline(db)
    monkeypatch.setattr(nt, "notify", boom)
    job, note = scan(db, make_xml(BASE), complete=True)
    assert "2 surface change(s)" in note and len(changes(db, job)) == 2
    assert db.scalar(select(Host).where(Host.address == "192.168.1.10")) is not None


def test_failure_after_queueing_is_rolled_back(client, db, monkeypatch):
    channel(client, "slack", secret=SLACK, events=("surface.changed",), min_severity="low")
    baseline(db)
    real = nt.notify

    def queue_then_fail(*a, **kw):
        assert real(*a, **kw) == 1
        raise RuntimeError("after enqueue")
    monkeypatch.setattr(nt, "notify", queue_then_fail)
    job, note = scan(db, make_xml(BASE), complete=True)
    assert "2 surface change(s)" in note and len(changes(db, job)) == 2
    assert list(db.scalars(select(Delivery))) == []


def test_summarize_and_title():
    rows = [SurfaceChange(kind=k) for k in ("host_new", "host_new", "port_opened", "port_closed", "host_gone")]
    counts = surface.summarize(rows)
    assert counts["host_new"] == 2 and counts["service_changed"] == 0
    assert surface.title_counts(counts) == "2 new hosts, 1 opened, 1 closed, 1 gone"


# ----------------------------------------------------------------- page
def _seed_changes(client):
    with client.app.state.SessionLocal() as s:
        j1, _ = scan(s, make_xml(BASE))
        web = ("web01.lab", [(22, "tcp", "ssh", "OpenSSH", "9.6p1"), (80, "tcp", "http", "Apache httpd", "2.4.58"),
                             (8080, "tcp", "http", "nginx", "1.25")])
        j2, _ = scan(s, make_xml({"192.168.1.10": web, "192.168.1.12": ("", [])}))
        return j1.id, j2.id


def test_changes_page_lists_and_filters(auth):
    j1, j2 = _seed_changes(auth)
    r = auth.get("/changes")
    assert r.status_code == 200
    assert "New host" in r.text and "Port opened" in r.text and "Port closed" in r.text
    assert 'href="/inventory?q=192.168.1.10"' in r.text and f'href="/jobs/{j2}"' in r.text
    r = auth.get("/changes?kind=port_opened")
    assert "8080/tcp" in r.text and "3306/tcp" not in r.text and "New host</span>" not in r.text
    r = auth.get(f"/changes?job={j1}")
    assert "8080/tcp" not in r.text and "New host" in r.text
    r = auth.get("/changes?kind=host_gone")
    assert "No changes" in r.text
    assert 'aria-current="page"' in auth.get("/changes").text
    assert auth.get("/changes?page=abc").status_code == 200


def test_scope_filter_on_page_and_ack_all(auth):
    with auth.app.state.SessionLocal() as s:
        sc = Scope(name="DMZ", targets="192.168.1.12", criticality="high")
        s.add(sc)
        s.commit()
        sid = sc.id
    _seed_changes(auth)
    r = auth.get(f"/changes?scope={sid}")
    assert "3306/tcp" in r.text and "8080/tcp" not in r.text and "192.168.1.10<" not in r.text
    csrf = get_csrf(auth, "/changes")
    max_id = re.search(r'name="max_id" value="(\d+)"', r.text).group(1)
    r = auth.post("/changes/ack-all", data={"csrf": csrf, "scope": str(sid), "days": "30", "max_id": max_id},
                  follow_redirects=False)
    assert f"scope={sid}" in r.headers["location"]
    with auth.app.state.SessionLocal() as s:
        acked = {c.address for c in s.scalars(select(SurfaceChange).where(SurfaceChange.acknowledged_at.is_not(None)))}
        assert acked == {"192.168.1.12"}


def test_ack_all_skips_rows_newer_than_the_page(auth):
    _seed_changes(auth)
    r = auth.get("/changes")
    max_id = int(re.search(r'name="max_id" value="(\d+)"', r.text).group(1))
    with auth.app.state.SessionLocal() as s:
        scan(s, make_xml({"192.168.1.30": ("", [])}), targets=["192.168.1.30"])   # arrives after the page rendered
    csrf = get_csrf(auth, "/changes")
    auth.post("/changes/ack-all", data={"csrf": csrf, "days": "30", "max_id": str(max_id)}, follow_redirects=False)
    with auth.app.state.SessionLocal() as s:
        still_open = [c.address for c in s.scalars(select(SurfaceChange).where(SurfaceChange.acknowledged_at.is_(None)))]
        assert still_open == ["192.168.1.30"]


def test_changes_days_filter(auth):
    _seed_changes(auth)
    with auth.app.state.SessionLocal() as s:
        from datetime import timedelta
        for c in s.scalars(select(SurfaceChange).where(SurfaceChange.kind == "host_new")):
            c.created_at = utcnow() - timedelta(days=40)
        s.commit()
    assert "New host</span>" not in auth.get("/changes").text
    assert "New host</span>" in auth.get("/changes?days=90").text
    assert "New host</span>" in auth.get("/changes?days=all").text


def test_ack_one_and_ack_all_with_filters(auth):
    _seed_changes(auth)
    with auth.app.state.SessionLocal() as s:
        first = s.scalar(select(SurfaceChange).where(SurfaceChange.kind == "port_opened"))
        cid = first.id
    csrf = get_csrf(auth, "/changes")
    r = auth.post(f"/changes/{cid}/ack", data={"csrf": csrf, "kind": "port_opened", "days": "30", "state": "open"},
                  follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/changes?")
    assert "kind=port_opened" in r.headers["location"] and "msg=" in r.headers["location"]
    with auth.app.state.SessionLocal() as s:
        row = s.get(SurfaceChange, cid)
        assert row.acknowledged_at is not None and row.acknowledged_by == "admin"
    assert "8080/tcp" not in auth.get("/changes").text
    assert "8080/tcp" in auth.get("/changes?state=all").text

    max_id = re.search(r'name="max_id" value="(\d+)"', auth.get("/changes?kind=host_new").text).group(1)
    r = auth.post("/changes/ack-all", data={"csrf": csrf, "kind": "host_new", "days": "30", "state": "open",
                                            "max_id": max_id}, follow_redirects=False)
    assert r.status_code == 303 and "kind=host_new" in r.headers["location"]
    with auth.app.state.SessionLocal() as s:
        open_kinds = {c.kind for c in s.scalars(select(SurfaceChange).where(SurfaceChange.acknowledged_at.is_(None)))}
        assert open_kinds == {"port_closed"}
        entry = s.scalar(select(AuditLog).where(AuditLog.action == "surface.ack").order_by(AuditLog.id.desc()))
        assert json.loads(entry.details)["count"] == 2


def test_ack_requires_permission_and_csrf(auth):
    _seed_changes(auth)
    with auth.app.state.SessionLocal() as s:
        cid = s.scalar(select(SurfaceChange.id))
    assert auth.post(f"/changes/{cid}/ack", data={}, follow_redirects=False).status_code == 403
    make_user(auth, "vera", "viewer")
    login_as(auth, "vera")
    r = auth.get("/changes")
    assert r.status_code == 200 and "/changes/ack-all" not in r.text and f"/changes/{cid}/ack" not in r.text
    csrf = get_csrf(auth, "/changes")
    assert auth.post(f"/changes/{cid}/ack", data={"csrf": csrf}, follow_redirects=False).status_code == 403
    assert auth.post("/changes/ack-all", data={"csrf": csrf}, follow_redirects=False).status_code == 403
    with auth.app.state.SessionLocal() as s:
        assert s.get(SurfaceChange, cid).acknowledged_at is None


def test_ack_unknown_change_is_404(auth):
    csrf = get_csrf(auth, "/changes")
    assert auth.post("/changes/999/ack", data={"csrf": csrf}, follow_redirects=False).status_code == 404


def test_job_detail_card(auth):
    j1, j2 = _seed_changes(auth)
    r = auth.get(f"/jobs/{j2}")
    assert "Changes from this scan" in r.text and f'href="/changes?job={j2}&amp;state=all"' in r.text
    assert "8080/tcp" in r.text


def test_dashboard_card(auth):
    _seed_changes(auth)
    r = auth.get("/")
    assert "Surface changes (7 days)" in r.text and 'href="/changes?days=7"' in r.text
    m = re.search(r'data-surface="host_new"[^>]*>\s*(\d+)', r.text)
    assert m and m.group(1) == "2"


def test_sidebar_has_changes_after_inventory(auth):
    r = auth.get("/")
    assert r.text.index('href="/inventory"') < r.text.index('href="/changes"') < r.text.index('href="/reports"')


# ----------------------------------------------------------------- API
def test_api_changes(auth):
    from tests.test_api import api, new_key
    j1, j2 = _seed_changes(auth)
    key = new_key(auth, role="viewer")
    r = api(auth, key, "GET", "/changes")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == len(body["items"]) == 4
    item = body["items"][0]
    assert set(item) == {"id", "job_id", "kind", "severity", "address", "hostname", "port", "protocol", "before", "after",
                         "scope_id", "created_at", "acknowledged_at", "acknowledged_by"}
    assert item["created_at"].endswith("Z")
    assert api(auth, key, "GET", f"/changes?job={j1}").json()["count"] == 2
    assert api(auth, key, "GET", "/changes?kind=port_opened").json()["count"] == 1
    assert api(auth, key, "GET", "/changes?limit=1").json()["count"] == 1
    from app.routers import api as api_router
    old_job = api(auth, key, "GET", f"/changes?job={j1}").json()["items"][0]["id"]
    with auth.app.state.SessionLocal() as s:
        from datetime import timedelta
        s.get(SurfaceChange, old_job).created_at = utcnow() - timedelta(days=60)
        s.commit()
    assert api(auth, key, "GET", f"/changes?job={j1}").json()["count"] == 2      # job without days: all time
    assert api(auth, key, "GET", f"/changes?job={j1}&days=30").json()["count"] == 1
    import pytest as _pytest
    mp = _pytest.MonkeyPatch()
    mp.setattr(api_router, "MAX_LIMIT", 2)
    try:
        assert api(auth, key, "GET", "/changes?limit=100000").json()["count"] == 2
    finally:
        mp.undo()


def test_job_detail_counts_without_loading_every_row(auth):
    with auth.app.state.SessionLocal() as s:
        many = {f"192.168.1.{i}": ("", [(22, "tcp", "ssh", "", "")]) for i in range(100, 130)}
        job, _ = scan(s, make_xml(many))
        jid = job.id
    r = auth.get(f"/jobs/{jid}")
    assert "New host: 30" in r.text and "Showing 20 of 30" in r.text


def test_index_is_added_to_an_existing_table(tmp_path):
    from sqlalchemy import inspect, text
    from app.db import init_db, make_engine
    engine = make_engine(f"sqlite:///{tmp_path / 'old.db'}")
    init_db(engine)
    with engine.begin() as conn:
        conn.execute(text("DROP INDEX ix_surface_kind_addr"))
    assert "ix_surface_kind_addr" not in {i["name"] for i in inspect(engine).get_indexes("surface_changes")}
    init_db(engine)
    assert "ix_surface_kind_addr" in {i["name"] for i in inspect(engine).get_indexes("surface_changes")}
