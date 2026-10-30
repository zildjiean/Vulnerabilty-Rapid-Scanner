"""Domain tests for app/issues.py: identity, dedup, rule sync, lifecycle, SLA."""
import json
import sqlite3
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.db import (AppSetting, Finding, Host, Issue, IssueEvent, Job, Rule, Service, User, init_db, make_engine,
                    make_session_factory, utcnow)
from app import issues as iss
from app.rules import evaluate_rules


@pytest.fixture
def db(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'issues.db'}")
    init_db(engine)
    with make_session_factory(engine)() as s:
        yield s


def job(db, kind="nuclei"):
    j = Job(kind=kind, status="done")
    db.add(j)
    db.commit()
    return j


def finding(db, j, template_id="CVE-2021-41773", severity="critical", host="10.0.0.5", ip="10.0.0.5", port="443",
            matched_at="https://10.0.0.5/cgi-bin/x", cve=("cve-2021-41773",), name="Apache path traversal", created_at=None):
    raw = {"template-id": template_id, "host": host, "matched-at": matched_at,
           "info": {"name": name, "severity": severity, "classification": {"cve-id": list(cve) if cve else None}}}
    if ip is not None:
        raw["ip"] = ip
    if port is not None:
        raw["port"] = port
    f = Finding(job_id=j.id, template_id=template_id, template_name=name, severity=severity, host=host,
                matched_at=matched_at, type="http", raw_json=json.dumps(raw), created_at=created_at or utcnow())
    db.add(f)
    db.flush()
    return f


def service(db, address="10.0.0.5", port=443, product="Apache httpd", version="2.4.49", last_seen=None):
    h = db.scalar(select(Host).where(Host.address == address))
    if h is None:
        h = Host(address=address, last_seen=last_seen or utcnow())
        db.add(h)
        db.flush()
    elif last_seen:
        h.last_seen = last_seen
    s = db.scalar(select(Service).where(Service.host_id == h.id, Service.port == port))
    if s is None:
        s = Service(host_id=h.id, port=port, protocol="tcp", service_name="http", product=product, version=version)
        db.add(s)
    else:
        s.product, s.version = product, version
    db.flush()
    return s


def events(db, issue):
    return [e.kind for e in db.scalars(select(IssueEvent).where(IssueEvent.issue_id == issue.id).order_by(IssueEvent.id))]


# ------------------------------------------------------------------ schema
def test_old_findings_table_gets_issue_id(tmp_path):
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript("CREATE TABLE findings (id INTEGER PRIMARY KEY, job_id INTEGER, template_id VARCHAR(255));")
    con.close()
    engine = make_engine(f"sqlite:///{path}")
    init_db(engine)
    con = sqlite3.connect(path)
    assert "issue_id" in [r[1] for r in con.execute("pragma table_info(findings)")]
    assert {"issues", "issue_events", "app_settings"} <= {r[0] for r in con.execute("select name from sqlite_master")}


# ------------------------------------------------------------------ identity
@pytest.mark.parametrize("raw,expected", [
    ({"host": "x", "ip": "10.0.0.5", "port": "443"}, ("10.0.0.5", "443", "x")),
    ({"host": "http://192.168.1.10:8080", "matched-at": "http://192.168.1.10:8080/"}, ("192.168.1.10", "8080", "")),
    ({"host": "honey.scanme.sh", "port": "443"}, ("honey.scanme.sh", "443", "honey.scanme.sh")),
    ({"host": "honey.scanme.sh", "ip": "67.205.158.113", "port": "443"}, ("67.205.158.113", "443", "honey.scanme.sh")),
    ({"host": "10.0.0.7:22", "matched-at": "10.0.0.7:22"}, ("10.0.0.7", "22", "")),
    ({"host": "https://example.test", "matched-at": "https://example.test/a"}, ("example.test", "443", "example.test")),
    ({"host": "http://example.test", "matched-at": "http://example.test/a"}, ("example.test", "80", "example.test")),
])
def test_asset_identity(raw, expected):
    assert iss.asset_from_raw(raw) == expected


def test_vulnerability_identity():
    assert iss.vuln_from_raw({"template-id": "t1", "info": {"classification": {"cve-id": ["cve-2024-1"]}}}) == ("CVE-2024-1", "CVE-2024-1")
    assert iss.vuln_from_raw({"template-id": "t1", "info": {"classification": {"cve-id": None}}}) == ("t1", "")
    assert iss.vuln_from_raw({"template-id": "t1", "info": {}}) == ("t1", "")
    assert iss.vuln_from_raw({"template-id": "t1", "info": {"classification": {"cve-id": "CVE-2023-2"}}}) == ("CVE-2023-2", "CVE-2023-2")


# ------------------------------------------------------------------ findings -> issues
def test_findings_create_and_deduplicate_issues(db):
    j1 = job(db)
    f1 = finding(db, j1)
    f2 = finding(db, j1, template_id="tech-detect", severity="info", cve=None)
    created = iss.issues_from_findings(db, [f1, f2], j1)
    db.commit()
    assert created == 1
    issue = db.scalar(select(Issue))
    assert issue.key == "10.0.0.5:443|CVE-2021-41773" and issue.asset == "10.0.0.5:443"
    assert issue.status == "new" and issue.confidence == "confirmed" and issue.severity == "critical"
    assert issue.occurrences == 1 and issue.cve_id == "CVE-2021-41773" and issue.template_id == "CVE-2021-41773"
    assert issue.title == "Apache path traversal"
    assert f1.issue_id == issue.id and f2.issue_id is None  # info never creates an issue
    assert issue.due_at == issue.first_seen + timedelta(days=3)

    j2 = job(db)
    f3 = finding(db, j2)
    assert iss.issues_from_findings(db, [f3], j2) == 0
    db.commit()
    assert db.query(Issue).count() == 1 and issue.occurrences == 2 and f3.issue_id == issue.id
    assert events(db, issue) == ["created", "seen"]


def test_severity_raises_unless_overridden(db):
    j = job(db)
    iss.issues_from_findings(db, [finding(db, j, severity="medium")], j)
    issue = db.scalar(select(Issue))
    first_due = issue.due_at
    iss.issues_from_findings(db, [finding(db, j, severity="high")], j)
    assert issue.severity == "high" and issue.due_at < first_due
    iss.set_severity(db, issue, "low", actor=None)
    iss.issues_from_findings(db, [finding(db, j, severity="critical")], j)
    assert issue.severity == "low" and issue.severity_overridden


def test_fixed_issue_reopens_when_found_again(db):
    j = job(db)
    iss.issues_from_findings(db, [finding(db, j)], j)
    issue = db.scalar(select(Issue))
    iss.change_status(db, issue, "fixed", actor=None)
    assert issue.resolved_at is not None
    iss.issues_from_findings(db, [finding(db, job(db))], j)
    assert issue.status == "triaged" and issue.resolved_at is None
    assert "reopened" in events(db, issue)


def test_false_positive_is_not_reopened(db):
    j = job(db)
    iss.issues_from_findings(db, [finding(db, j)], j)
    issue = db.scalar(select(Issue))
    iss.change_status(db, issue, "false_positive", actor=None, comment="WAF answers every path with 200")
    iss.issues_from_findings(db, [finding(db, job(db))], j)
    assert issue.status == "false_positive" and issue.occurrences == 2


# ------------------------------------------------------------------ rule matches -> issues
def add_rule(db, cve="CVE-2021-41773", severity="high", pattern="apache", constraint="< 2.4.51"):
    r = Rule(name="Apache traversal", product_pattern=pattern, version_constraint=constraint, cve_id=cve, severity=severity)
    db.add(r)
    db.commit()
    return r


def test_rule_match_creates_suspected_issue_and_nuclei_confirms(db):
    service(db)
    add_rule(db)
    evaluate_rules(db)
    db.commit()
    issue = db.scalar(select(Issue))
    assert issue.confidence == "suspected" and issue.key == "10.0.0.5:443|CVE-2021-41773" and issue.severity == "high"
    assert issue.rule_id is not None and issue.title.startswith("Apache traversal")
    evaluate_rules(db)  # re-evaluation does not duplicate or add noise
    db.commit()
    assert db.query(Issue).count() == 1 and events(db, issue) == ["created"]

    j = job(db)
    iss.issues_from_findings(db, [finding(db, j)], j)
    assert issue.confidence == "confirmed" and issue.severity == "critical"
    assert "confirmed" in events(db, issue)


def test_rule_without_cve_uses_rule_key(db):
    service(db)
    r = add_rule(db, cve="")
    evaluate_rules(db)
    assert db.scalar(select(Issue)).key == f"10.0.0.5:443|rule-{r.id}"


def test_version_upgrade_auto_fixes_suspected_issue(db):
    service(db)
    add_rule(db)
    evaluate_rules(db)
    issue = db.scalar(select(Issue))
    service(db, version="2.4.62")  # nmap re-scan saw the patched version
    evaluate_rules(db)
    assert issue.status == "fixed" and "auto_fixed" in events(db, issue)


def test_disabled_rule_or_removed_service_does_not_auto_fix(db):
    svc = service(db)
    r = add_rule(db)
    evaluate_rules(db)
    issue = db.scalar(select(Issue))
    r.enabled = False
    evaluate_rules(db)
    assert issue.status == "new"
    r.enabled = True
    db.delete(svc)
    db.flush()
    evaluate_rules(db)
    assert issue.status == "new"


def test_rule_reopen_needs_a_newer_scan(db):
    old = utcnow() - timedelta(hours=2)
    service(db, last_seen=old)
    add_rule(db)
    evaluate_rules(db)
    issue = db.scalar(select(Issue))
    iss.change_status(db, issue, "fixed", actor=None)  # analyst patched, nmap not re-run yet
    evaluate_rules(db)  # e.g. someone edited a rule
    assert issue.status == "fixed"
    service(db, last_seen=utcnow() + timedelta(seconds=1))  # re-scan still sees the vulnerable version
    evaluate_rules(db)
    assert issue.status == "triaged" and "reopened" in events(db, issue)


# ------------------------------------------------------------------ lifecycle
def test_transitions_and_reasons(db):
    j = job(db)
    iss.issues_from_findings(db, [finding(db, j)], j)
    issue = db.scalar(select(Issue))
    with pytest.raises(ValueError):
        iss.change_status(db, issue, "verified", actor=None)  # new -> verified is not allowed
    with pytest.raises(ValueError):
        iss.change_status(db, issue, "accepted_risk", actor=None, comment="  ")
    with pytest.raises(ValueError):
        iss.change_status(db, issue, "bogus", actor=None)
    iss.change_status(db, issue, "in_progress", actor=None)
    iss.change_status(db, issue, "fixed", actor=None)
    iss.change_status(db, issue, "verified", actor=None, comment="re-scan clean")
    assert issue.status == "verified" and not iss.is_active(issue) and issue.resolved_at
    iss.change_status(db, issue, "triaged", actor=None)
    assert iss.is_active(issue) and issue.resolved_at is None
    assert iss.allowed_transitions("fixed") == ["verified", "in_progress"]
    kinds = events(db, issue)
    assert kinds.count("status") == 4 and kinds.count("comment") == 1


def test_assign_and_comment(db):
    j = job(db)
    iss.issues_from_findings(db, [finding(db, j)], j)
    issue = db.scalar(select(Issue))
    u = User(username="ana", password_hash="x", role="analyst")
    db.add(u)
    db.commit()
    iss.assign(db, issue, u, actor=u)
    assert issue.assignee_id == u.id
    iss.assign(db, issue, None, actor=u)
    assert issue.assignee_id is None
    iss.add_comment(db, issue, "Owner notified", actor=u)
    ev = db.scalars(select(IssueEvent).where(IssueEvent.issue_id == issue.id)).all()
    assert [e.kind for e in ev][-3:] == ["assigned", "assigned", "comment"]
    assert ev[-1].username == "ana" and ev[-1].body == "Owner notified"
    with pytest.raises(ValueError):
        iss.add_comment(db, issue, "   ", actor=u)


# ------------------------------------------------------------------ SLA
def test_sla_settings_and_overdue(db):
    assert iss.get_sla(db) == {"critical": 3, "high": 7, "medium": 30, "low": 90}
    j = job(db)
    iss.issues_from_findings(db, [finding(db, j, severity="low")], j)
    issue = db.scalar(select(Issue))
    assert issue.due_at == issue.first_seen + timedelta(days=90)
    iss.set_sla(db, {"critical": 1, "high": 2, "medium": 3, "low": 4})
    assert issue.due_at == issue.first_seen + timedelta(days=4)
    assert db.get(AppSetting, "sla_days").value
    with pytest.raises(ValueError):
        iss.set_sla(db, {"critical": 0, "high": 2, "medium": 3, "low": 4})
    issue.due_at = utcnow() - timedelta(minutes=1)
    assert iss.is_overdue(issue)
    iss.change_status(db, issue, "false_positive", actor=None, comment="x")
    assert not iss.is_overdue(issue)


def test_backfill_is_idempotent(db):
    j = job(db)
    finding(db, j, created_at=datetime(2026, 10, 1, 8, 0))
    finding(db, j, created_at=datetime(2026, 10, 2, 8, 0))
    finding(db, j, template_id="tech", severity="info", cve=None)
    service(db, address="10.0.0.9", port=80)
    add_rule(db, cve="CVE-2099-1")
    from app.db import RuleMatch  # rule matches exist from before issues were introduced
    db.add(RuleMatch(rule_id=db.scalar(select(Rule.id)), service_id=db.scalar(select(Service.id))))
    db.commit()
    assert iss.backfill_issues(db) == 2
    assert iss.backfill_issues(db) == 0
    confirmed = db.scalar(select(Issue).where(Issue.confidence == "confirmed"))
    assert confirmed.first_seen == datetime(2026, 10, 1, 8, 0) and confirmed.last_seen == datetime(2026, 10, 2, 8, 0)
    assert confirmed.occurrences == 2
