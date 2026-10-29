from pathlib import Path

from sqlalchemy import select

from app.db import Job, Service
from app.routers.inventory import service_to_target
from app.scanners.nmap_runner import ingest_nmap_results
from tests.conftest import get_csrf

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


def seed_inventory(client):
    with client.app.state.SessionLocal() as db:
        job = Job(kind="nmap", status="done")
        db.add(job)
        db.commit()
        ingest_nmap_results(db, job, FIXTURE.read_text())
        db.commit()


class _Svc:
    def __init__(self, port, name, tunnel=""):
        self.port, self.service_name, self.tunnel = port, name, tunnel


def test_service_to_target():
    assert service_to_target("10.0.0.1", _Svc(80, "http")) == "http://10.0.0.1:80"
    assert service_to_target("10.0.0.1", _Svc(8443, "http", "ssl")) == "https://10.0.0.1:8443"
    assert service_to_target("10.0.0.1", _Svc(443, "https")) == "https://10.0.0.1:443"
    assert service_to_target("10.0.0.1", _Svc(22, "ssh")) == "10.0.0.1:22"


def test_inventory_lists_and_filters(auth):
    seed_inventory(auth)
    r = auth.get("/inventory")
    assert r.status_code == 200
    assert "192.168.1.10" in r.text and "192.168.1.12" in r.text and "OpenSSH" in r.text
    # row-only markers (the product dropdown always lists every product): versions / cpe strings
    r = auth.get("/inventory?q=php")
    assert "8.3.10" in r.text and "9.6p1" not in r.text
    r = auth.get("/inventory?product=nginx")
    assert "1.24.0" in r.text and "9.6p1" not in r.text
    r = auth.get("/inventory?port=3306")
    assert "192.168.1.12" in r.text and "192.168.1.10" not in r.text


def test_to_nuclei_prefills_targets(auth):
    seed_inventory(auth)
    with auth.app.state.SessionLocal() as db:
        ids = [str(s.id) for s in db.scalars(select(Service)) if s.port in (80, 8443, 22)]
    csrf = get_csrf(auth, "/inventory")
    r = auth.post("/inventory/to-nuclei", data={"csrf": csrf, "service_ids": ids})
    assert r.status_code == 200
    assert "http://192.168.1.10:80" in r.text
    assert "https://192.168.1.10:8443" in r.text
    assert "192.168.1.10:22" in r.text


def test_to_nuclei_without_selection_errors(auth):
    csrf = get_csrf(auth, "/inventory")
    r = auth.post("/inventory/to-nuclei", data={"csrf": csrf})
    assert r.status_code == 400 and "Select at least one" in r.text
