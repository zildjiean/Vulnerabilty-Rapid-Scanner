import pytest
from sqlalchemy import select

from app import scopes as sc
from app.db import Issue, IssueEvent, Scope, User, init_db, make_engine, make_session_factory
from tests.test_issues import finding, job
from app import issues as iss


@pytest.fixture
def db(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 'scopes.db'}")
    init_db(engine)
    with make_session_factory(engine)() as s:
        yield s


@pytest.mark.parametrize("target,address,hostname,expected", [
    ("10.0.0.0/24", "10.0.0.77", "", True),
    ("10.0.0.0/24", "10.0.1.1", "", False),
    ("10.0.0.5", "10.0.0.5", "", True),
    ("10.0.0.1-50", "10.0.0.50", "", True),
    ("10.0.0.1-50", "10.0.0.51", "", False),
    ("10.0-1.*.1", "10.1.200.1", "", True),
    ("2001:db8::/32", "2001:db8::1", "", True),
    ("www.cpu.ac.th", "172.67.182.201", "www.cpu.ac.th", True),
    ("WWW.CPU.AC.TH", "172.67.182.201", "www.cpu.ac.th", True),
    ("honey.scanme.sh", "honey.scanme.sh", "", True),
    ("example.com", "10.0.0.5", "www.example.com", False),
])
def test_target_matching(target, address, hostname, expected):
    assert sc.Matcher.parse([target]).matches(address, hostname) is expected


def add_scope(db, name, targets, exclusions="", criticality="medium", owner=None):
    s = Scope(name=name, targets=targets, exclusions=exclusions, criticality=criticality,
              owner_id=owner.id if owner else None)
    db.add(s)
    db.commit()
    return s


def test_resolution_priority_and_exclusions(db):
    lab = add_scope(db, "Lab", "10.0.0.0/16", exclusions="10.0.5.0/24", criticality="low")
    prod = add_scope(db, "Prod web", "10.0.1.0/24", criticality="critical")
    compiled = sc.compile_scopes(db)
    assert sc.resolve_scope(compiled, "10.0.1.10", "").id == prod.id   # most critical wins
    assert sc.resolve_scope(compiled, "10.0.2.10", "").id == lab.id
    assert sc.resolve_scope(compiled, "10.0.5.10", "") is None          # excluded from Lab, not in Prod
    assert sc.resolve_scope(compiled, "192.168.0.1", "") is None


def test_validation():
    assert sc.validate_scope_fields("Prod", "10.0.0.0/24\nweb.example.com", "", "high") is None
    assert "name" in sc.validate_scope_fields("", "10.0.0.1", "", "high")
    assert "target" in sc.validate_scope_fields("x", "", "", "high").lower()
    assert sc.validate_scope_fields("x", "10.0.0.1; rm", "", "high")
    assert sc.validate_scope_fields("x", "10.0.0.1", "-oN /tmp/x", "high")
    assert "criticality" in sc.validate_scope_fields("x", "10.0.0.1", "", "urgent").lower()


def owner(db, username="olivia", role="analyst", active=True):
    u = User(username=username, password_hash="x", role=role, is_active=active)
    db.add(u)
    db.commit()
    return u


def test_new_issue_gets_scope_and_owner(db):
    o = owner(db)
    s = add_scope(db, "DMZ", "10.0.0.0/24", owner=o, criticality="high")
    j = job(db)
    iss.issues_from_findings(db, [finding(db, j)], j)  # 10.0.0.5:443
    issue = db.scalar(select(Issue))
    assert issue.scope_id == s.id and issue.assignee_id == o.id
    ev = [(e.kind, e.username, e.to_value) for e in db.scalars(select(IssueEvent).order_by(IssueEvent.id))]
    assert ("assigned", "system", "olivia") in ev


def test_no_auto_assign_for_inactive_or_viewer_owner(db):
    v = owner(db, "vic", role="viewer")
    add_scope(db, "DMZ", "10.0.0.0/24", owner=v)
    j = job(db)
    iss.issues_from_findings(db, [finding(db, j)], j)
    issue = db.scalar(select(Issue))
    assert issue.scope_id is not None and issue.assignee_id is None


def test_rescope_keeps_assignees(db):
    j = job(db)
    iss.issues_from_findings(db, [finding(db, j)], j)
    issue = db.scalar(select(Issue))
    assert issue.scope_id is None
    o = owner(db)
    s = add_scope(db, "DMZ", "10.0.0.5", owner=o)
    assert sc.rescope_issues(db) == 1
    assert issue.scope_id == s.id and issue.assignee_id is None  # existing issues are not re-assigned
    db.delete(s)
    db.commit()
    sc.rescope_issues(db)
    assert issue.scope_id is None


def test_hostname_scope_uses_inventory_hostname(db):
    from tests.test_issues import service
    from app.db import Host
    service(db, address="172.67.182.201", port=443)
    db.scalar(select(Host)).hostname = "www.cpu.ac.th"
    s = add_scope(db, "University", "www.cpu.ac.th")
    j = job(db)
    iss.issues_from_findings(db, [finding(db, j, host="172.67.182.201", ip="172.67.182.201")], j)
    assert db.scalar(select(Issue)).scope_id == s.id
