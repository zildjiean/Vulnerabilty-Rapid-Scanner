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
        assert "<nmaprun" not in job.log
        assert len(list(db.scalars(select(Host)))) == 2
