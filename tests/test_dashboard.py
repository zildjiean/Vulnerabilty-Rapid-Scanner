from pathlib import Path

from app.db import Job
from app.scanners.nmap_runner import ingest_nmap_results

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


def test_dashboard_counts(auth):
    with auth.app.state.SessionLocal() as db:
        job = Job(kind="nmap", status="done")
        db.add(job)
        db.commit()
        ingest_nmap_results(db, job, FIXTURE.read_text())
        db.commit()
    r = auth.get("/")
    assert r.status_code == 200
    assert "2</b><span>hosts" in r.text
    assert "5</b><span>open services" in r.text
    assert "Quick start" in r.text
