from pathlib import Path

from sqlalchemy import select

from app.db import Job, Rule, RuleMatch, Service, init_db, make_engine, make_session_factory
from app.rules import evaluate_rules, seed_example_rule
from app.scanners.nmap_runner import ingest_nmap_results
from tests.conftest import get_csrf

FIXTURE = Path(__file__).parent / "fixtures" / "nmap_sample.xml"


def _session(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'r.db'}")
    init_db(engine)
    return make_session_factory(engine)


def _seed(db):
    job = Job(kind="nmap", status="done")
    db.add(job)
    db.commit()
    ingest_nmap_results(db, job, FIXTURE.read_text())
    db.commit()


def test_evaluate_rules_matches_product_and_version(tmp_path):
    SessionLocal = _session(tmp_path)
    with SessionLocal() as db:
        _seed(db)
        db.add(Rule(name="PHP UAF", product_pattern=r"php", version_constraint="< 8.3.15", cve_id="CVE-2026-109619", severity="critical"))
        db.add(Rule(name="Old OpenSSH", product_pattern=r"^OpenSSH$", version_constraint="< 9.0", severity="high"))
        db.add(Rule(name="Disabled", product_pattern=r".*", version_constraint="> 0", enabled=False))
        db.add(Rule(name="Broken regex", product_pattern=r"(", version_constraint="< 1"))
        db.commit()
        n = evaluate_rules(db)
        db.commit()
        assert n == 1
        m = db.scalar(select(RuleMatch))
        svc = db.get(Service, m.service_id)
        assert svc.port == 8080 and m.rule.cve_id == "CVE-2026-109619"
        assert evaluate_rules(db) == 1


def test_rule_matches_cpe_when_product_empty(tmp_path):
    SessionLocal = _session(tmp_path)
    with SessionLocal() as db:
        _seed(db)
        db.add(Rule(name="Apache via cpe", product_pattern=r"apache:http_server", version_constraint="<= 2.4.58", severity="medium"))
        db.commit()
        assert evaluate_rules(db) == 1


def test_seed_example_rule(tmp_path):
    SessionLocal = _session(tmp_path)
    with SessionLocal() as db:
        seed_example_rule(db)
        seed_example_rule(db)
        rules = list(db.scalars(select(Rule)))
        assert len(rules) == 1 and rules[0].enabled is False and rules[0].cve_id == "CVE-2026-109619"


def test_rules_pages_crud_and_inventory_badges(auth):
    with auth.app.state.SessionLocal() as db:
        _seed(db)
    assert auth.get("/rules").status_code == 200
    csrf = get_csrf(auth, "/rules")
    r = auth.post("/rules", data={"csrf": csrf, "name": "PHP UAF", "product_pattern": "php", "version_constraint": "< 8.3.15",
                                  "cve_id": "CVE-2026-109619", "severity": "critical", "description": "x", "enabled": "true"}, follow_redirects=False)
    assert r.status_code == 303
    r = auth.post("/rules", data={"csrf": csrf, "name": "bad", "product_pattern": "(", "version_constraint": "< 1", "severity": "low"})
    assert r.status_code == 400 and "Invalid regex" in r.text
    r = auth.post("/rules", data={"csrf": csrf, "name": "bad2", "product_pattern": "x", "version_constraint": "~1", "severity": "low"})
    assert r.status_code == 400 and "Invalid version clause" in r.text
    page = auth.get("/rules")
    assert "PHP UAF" in page.text and "192.168.1.10" in page.text and "8.3.10" in page.text
    inv = auth.get("/inventory?only_matches=true")
    assert "8080" in inv.text and "CVE-2026-109619" in inv.text and "3306" not in inv.text
    with auth.app.state.SessionLocal() as db:
        rule = db.scalar(select(Rule).where(Rule.name == "PHP UAF"))
    r = auth.get(f"/rules/{rule.id}/edit")
    assert r.status_code == 200 and "PHP UAF" in r.text
    r = auth.post(f"/rules/{rule.id}/edit", data={"csrf": csrf, "name": "PHP UAF v2", "product_pattern": "php", "version_constraint": "< 8.3.15",
                                                   "cve_id": "CVE-2026-109619", "severity": "high", "description": "", "enabled": "true"}, follow_redirects=False)
    assert r.status_code == 303
    r = auth.post(f"/rules/{rule.id}/toggle", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert "CVE-2026-109619" not in auth.get("/inventory").text
    r = auth.post(f"/rules/{rule.id}/delete", data={"csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert "PHP UAF v2" not in auth.get("/rules").text
