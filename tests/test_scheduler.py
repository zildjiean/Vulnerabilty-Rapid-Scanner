import json
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import select

from app import scheduler as sch
from app.db import AuditLog, Job, Schedule, Scope, utcnow
from app.templates_index import reindex
from tests.conftest import wait_job
from tests.test_inventory import seed_inventory

BKK = ZoneInfo("Asia/Bangkok")


class S:  # schedule-like
    def __init__(self, frequency, interval_hours=24, time_of_day="02:00", weekday=0):
        self.frequency, self.interval_hours, self.time_of_day, self.weekday = frequency, interval_hours, time_of_day, weekday


FRI_1700_BKK = datetime(2026, 10, 30, 10, 0)  # naive UTC; Friday 17:00 in Bangkok


@pytest.mark.parametrize("sched,after,tz,expected", [
    (S("interval", interval_hours=6), FRI_1700_BKK, BKK, datetime(2026, 10, 30, 16, 0)),
    (S("daily", time_of_day="02:00"), FRI_1700_BKK, BKK, datetime(2026, 10, 30, 19, 0)),   # Sat 02:00 BKK
    (S("daily", time_of_day="18:00"), FRI_1700_BKK, BKK, datetime(2026, 10, 30, 11, 0)),   # later today
    (S("daily", time_of_day="17:00"), FRI_1700_BKK, BKK, datetime(2026, 10, 31, 10, 0)),   # exactly now -> tomorrow
    (S("weekly", time_of_day="03:00", weekday=0), FRI_1700_BKK, BKK, datetime(2026, 11, 1, 20, 0)),  # Mon 03:00 BKK
    (S("weekly", time_of_day="18:00", weekday=4), FRI_1700_BKK, BKK, datetime(2026, 10, 30, 11, 0)),
    (S("weekly", time_of_day="16:00", weekday=4), FRI_1700_BKK, BKK, datetime(2026, 11, 6, 9, 0)),
    # DST ends in New York on 2026-11-01: 03:00 local is UTC-5 after the change
    (S("daily", time_of_day="03:00"), datetime(2026, 10, 31, 12, 0), ZoneInfo("America/New_York"), datetime(2026, 11, 1, 8, 0)),
])
def test_compute_next_run(sched, after, tz, expected):
    assert sch.compute_next_run(sched, after, tz) == expected


def test_validation():
    ok = dict(kind="nmap", scope_id=1, frequency="daily", interval_hours=24, time_of_day="02:00", weekday=0)
    assert sch.validate_schedule(**ok) is None
    assert "scope" in sch.validate_schedule(**{**ok, "scope_id": None}).lower()
    assert sch.validate_schedule(**{**ok, "kind": "campaign_verify", "scope_id": None}) is None
    assert sch.validate_schedule(**{**ok, "kind": "bogus"})
    assert sch.validate_schedule(**{**ok, "time_of_day": "25:00"})
    assert sch.validate_schedule(**{**ok, "frequency": "interval", "interval_hours": 0})
    assert sch.validate_schedule(**{**ok, "frequency": "weekly", "weekday": 7})


def test_timezone_setting(auth):
    with auth.app.state.SessionLocal() as db:
        assert sch.get_timezone(db) == "Asia/Bangkok"
        s = Schedule(name="x", kind="campaign_verify", frequency="daily", time_of_day="02:00",
                     next_run_at=datetime(2026, 10, 30, 19, 0))
        db.add(s)
        db.commit()
        sch.set_timezone(db, "UTC", now=FRI_1700_BKK)
        assert sch.get_timezone(db) == "UTC" and s.next_run_at == datetime(2026, 10, 31, 2, 0)
        with pytest.raises(ValueError):
            sch.set_timezone(db, "Mars/Olympus")


def make_scope(client, targets="192.168.1.0/24", exclusions="192.168.1.12"):
    with client.app.state.SessionLocal() as db:
        s = Scope(name="Office LAN", targets=targets, exclusions=exclusions, criticality="high")
        db.add(s)
        db.commit()
        return s.id


def make_schedule(client, kind, scope_id=None, config=None, next_run_at=None, enabled=True):
    with client.app.state.SessionLocal() as db:
        s = Schedule(name=f"{kind} test", kind=kind, scope_id=scope_id, frequency="daily", time_of_day="02:00",
                     config=json.dumps(config or {}), next_run_at=next_run_at or utcnow() + timedelta(days=1),
                     enabled=enabled)
        db.add(s)
        db.commit()
        return s.id


def run(client, sid, manual=True):
    return client.portal.call(sch.run_schedule, client.app, sid, manual)


def sched(client, sid):
    with client.app.state.SessionLocal() as db:
        s = db.get(Schedule, sid)
        db.expunge(s)
        return s


def test_nmap_schedule_scans_scope_with_exclusions(auth):
    sid = make_schedule(auth, "nmap", make_scope(auth), {"port_mode": "custom", "custom_ports": "22,80", "timing": "T4"})
    job_id = run(auth, sid)
    wait_job(auth, job_id)
    with auth.app.state.SessionLocal() as db:
        job = db.get(Job, job_id)
        assert job.schedule_id == sid and "192.168.1.0/24" in job.command
        assert "--exclude 192.168.1.12" in job.command and "-p 22,80" in job.command and "-T4" in job.command
        assert json.loads(job.params_json)["schedule"] == "nmap test"
    s = sched(auth, sid)
    assert s.last_status == "started" and s.last_job_id == job_id and s.last_run_at


def test_nuclei_schedule_targets_scope_inventory(auth):
    seed_inventory(auth)
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
        db.commit()
    sid = make_schedule(auth, "nuclei", make_scope(auth), {"mode": "all", "severities": ["critical", "high"], "profile": "gentle"})
    job_id = run(auth, sid)
    wait_job(auth, job_id)
    with auth.app.state.SessionLocal() as db:
        job = db.get(Job, job_id)
        targets = json.loads(job.params_json)["targets"]
        assert "http://192.168.1.10:80" in targets and "https://192.168.1.10:8443" in targets
        assert not any("192.168.1.12" in t for t in targets)  # excluded host
        assert "-severity critical,high" in job.command and "-retries" in job.command


def test_nuclei_schedule_without_inventory_is_skipped(auth):
    sid = make_schedule(auth, "nuclei", make_scope(auth, targets="10.99.0.0/24", exclusions=""), {"mode": "all"})
    assert run(auth, sid) is None
    s = sched(auth, sid)
    assert s.last_status == "skipped" and "no services" in s.last_message.lower()


def test_skip_while_previous_run_is_running(auth):
    sid = make_schedule(auth, "nmap", make_scope(auth))
    with auth.app.state.SessionLocal() as db:
        j = Job(kind="nmap", status="running")
        db.add(j)
        db.commit()
        db.get(Schedule, sid).last_job_id = j.id
        db.commit()
    assert run(auth, sid, manual=False) is None
    assert sched(auth, sid).last_status == "skipped" and "still running" in sched(auth, sid).last_message


def test_campaign_verify_schedule(auth):
    from tests.test_campaigns import NVD_PHP, PHP_CVE
    from tests.test_intel import FakeNet
    from tests.conftest import get_csrf
    seed_inventory(auth)
    with auth.app.state.SessionLocal() as db:
        reindex(db, auth.app.state.settings)
        db.commit()
    auth.app.state.get_json = FakeNet(nvd={PHP_CVE: NVD_PHP})
    csrf = get_csrf(auth, "/campaigns/new")
    auth.post("/campaigns", data={"csrf": csrf, "cve_id": PHP_CVE, "severity": "auto", "product_pattern": "php",
                                  "version_constraint": "< 8.3.15", "attach_templates": "true", "fetch_intel": "true"})
    sid = make_schedule(auth, "campaign_verify", None, {"profile": "normal"})
    job_id = run(auth, sid)
    wait_job(auth, job_id)
    with auth.app.state.SessionLocal() as db:
        job = db.get(Job, job_id)
        assert job.campaign_id is not None and job.schedule_id == sid
    assert "1 campaign" in sched(auth, sid).last_message


def test_run_due_only_runs_due_enabled_schedules_and_advances(auth):
    scope = make_scope(auth)
    past = utcnow() - timedelta(minutes=1)
    due = make_schedule(auth, "nmap", scope, next_run_at=past)
    later = make_schedule(auth, "nmap", scope)
    off = make_schedule(auth, "nmap", scope, next_run_at=past, enabled=False)
    n = auth.portal.call(sch.run_due, auth.app)
    assert n == 1
    assert sched(auth, due).last_status == "started" and sched(auth, due).next_run_at > utcnow()
    assert sched(auth, later).last_status == "" and sched(auth, off).last_status == ""
    wait_job(auth, sched(auth, due).last_job_id)
    with auth.app.state.SessionLocal() as db:
        a = db.scalar(select(AuditLog).where(AuditLog.action == "schedule.run"))
        assert a.username == "scheduler" and a.target == "nmap test"
