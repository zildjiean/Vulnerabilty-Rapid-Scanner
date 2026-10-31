import asyncio

from app.db import Job, init_db, make_engine, make_session_factory
from app.jobs import JobRunner
from tests.conftest import wait_job


def _runner(tmp_path):
    engine = make_engine(f"sqlite:///{tmp_path / 't.db'}")
    init_db(engine)
    return JobRunner(make_session_factory(engine))


def test_runner_captures_stdout_stderr_and_calls_hook(tmp_path):
    runner = _runner(tmp_path)
    seen = {}

    def hook(db, job, output):
        seen["output"] = output
        seen["job_id"] = job.id

    async def main():
        with runner.session_factory() as db:
            job = runner.create_job(db, "nmap", ["sh", "-c", "echo out1; echo err1 1>&2; echo out2"], {"a": 1})
            job_id = job.id
        await runner.start(job_id, ["sh", "-c", "echo out1; echo err1 1>&2; echo out2"], on_complete=hook, stdout_to_log=False)
        return job_id

    job_id = asyncio.run(main())
    with runner.session_factory() as db:
        job = db.get(Job, job_id)
    assert job.status == "done" and job.exit_code == 0
    assert job.output == "out1\nout2"
    assert "err1" in job.log
    assert job.log.count("out1") == 1  # only inside the echoed command line, not as captured stdout
    assert "[runner] exit code 0 (done)" in job.log
    assert seen == {"output": "out1\nout2", "job_id": job_id}
    assert job.started_at is not None and job.finished_at is not None


def test_runner_marks_nonzero_exit_failed_and_skips_hook(tmp_path):
    runner = _runner(tmp_path)
    called = []

    async def main():
        with runner.session_factory() as db:
            job_id = runner.create_job(db, "update", ["sh", "-c", "echo boom; exit 3"]).id
        await runner.start(job_id, ["sh", "-c", "echo boom; exit 3"], on_complete=lambda *a: called.append(1))
        return job_id

    job_id = asyncio.run(main())
    with runner.session_factory() as db:
        job = db.get(Job, job_id)
    assert job.status == "failed" and job.exit_code == 3
    assert "boom" in job.log
    assert called == []


def test_hook_exception_marks_failed(tmp_path):
    runner = _runner(tmp_path)

    def hook(db, job, output):
        raise RuntimeError("parse error")

    async def main():
        with runner.session_factory() as db:
            job_id = runner.create_job(db, "nmap", ["true"]).id
        await runner.start(job_id, ["true"], on_complete=hook)
        return job_id

    job_id = asyncio.run(main())
    with runner.session_factory() as db:
        job = db.get(Job, job_id)
    assert job.status == "failed"
    assert "result processing failed" in job.log and "parse error" in job.log


def test_missing_binary_fails_cleanly(tmp_path):
    runner = _runner(tmp_path)

    async def main():
        with runner.session_factory() as db:
            job_id = runner.create_job(db, "nmap", ["/nonexistent/bin"]).id
        await runner.start(job_id, ["/nonexistent/bin"])
        return job_id

    job_id = asyncio.run(main())
    with runner.session_factory() as db:
        job = db.get(Job, job_id)
    assert job.status == "failed" and job.exit_code == 127
    assert "cannot start" in job.log


def test_cancel_running_job(tmp_path):
    runner = _runner(tmp_path)

    async def main():
        with runner.session_factory() as db:
            job_id = runner.create_job(db, "nmap", ["sleep", "30"]).id
        task = runner.start(job_id, ["sleep", "30"])
        for _ in range(100):
            await asyncio.sleep(0.05)
            if runner.cancel(job_id):
                break
        await task
        return job_id

    job_id = asyncio.run(main())
    with runner.session_factory() as db:
        job = db.get(Job, job_id)
    assert job.status == "cancelled"


def test_jobs_pages_and_status_endpoint(auth):
    runner = auth.app.state.job_runner
    with auth.app.state.SessionLocal() as db:
        job_id = runner.create_job(db, "update", ["echo", "hi"]).id
    auth.portal.call(runner.start, job_id, ["echo", "hi"])
    data = wait_job(auth, job_id)
    assert data["status"] == "done"
    assert auth.get("/jobs").status_code == 200
    page = auth.get(f"/jobs/{job_id}")
    assert page.status_code == 200 and "echo hi" in page.text and "hi" in page.text
    assert auth.get("/jobs/999").status_code == 404


def test_stream_endpoint_replays_log_for_finished_job(auth):
    runner = auth.app.state.job_runner
    with auth.app.state.SessionLocal() as db:
        job_id = runner.create_job(db, "update", ["echo", "streamed"]).id
    auth.portal.call(runner.start, job_id, ["echo", "streamed"])
    wait_job(auth, job_id)
    with auth.stream("GET", f"/jobs/{job_id}/stream") as r:
        body = "".join(r.iter_text())
    assert "event: log\ndata: streamed" in body
    assert "event: done\ndata: done" in body


def test_interrupted_jobs_marked_failed_on_startup(settings):
    from fastapi.testclient import TestClient
    from app.main import create_app
    engine = make_engine(settings.db_url)
    init_db(engine)
    with make_session_factory(engine)() as db:
        db.add(Job(kind="nmap", status="running", log="[runner] started"))
        db.add(Job(kind="nuclei", status="queued"))
        db.add(Job(kind="update", status="done"))
        db.commit()
    app = create_app(settings)
    with TestClient(app) as c:
        with app.state.SessionLocal() as db:
            jobs = {j.kind: j for j in db.query(Job)}
        assert jobs["nmap"].status == "failed" and "interrupted by application restart" in jobs["nmap"].log
        assert jobs["nuclei"].status == "failed" and jobs["nuclei"].finished_at is not None
        assert jobs["update"].status == "done"
        assert c.get("/healthz").status_code == 200


# ----------------------------------------------------------------- robustness of the runner's own DB writes
def _locked():
    import sqlite3
    from sqlalchemy.exc import OperationalError
    return OperationalError("UPDATE jobs", {}, sqlite3.OperationalError("database is locked"))


def _run_echo(runner, session_factory):
    import asyncio

    async def go():
        with session_factory() as db:
            job = runner.create_job(db, "other", ["/bin/echo", "hi"])
        q = runner.subscribe(job.id)
        task = runner.start(job.id, ["/bin/echo", "hi"])
        await asyncio.wait_for(task, 10)
        items = []
        while not q.empty():
            items.append(q.get_nowait())
        return job.id, items
    return asyncio.run(go())


def test_finish_closes_streams_even_when_the_db_stays_locked(client, monkeypatch):
    from app import jobs as jobs_mod
    from app.jobs import JobRunner
    monkeypatch.setattr(jobs_mod, "RETRY_DELAYS", (0, 0, 0))
    runner = JobRunner(client.app.state.SessionLocal)
    real = runner._write
    calls = {"n": 0}

    def locked_finish(job_id, **fields):
        if "finished_at" in fields:
            calls["n"] += 1
            raise _locked()
        return real(job_id, **fields)
    runner._write = locked_finish
    jid, items = _run_echo(runner, client.app.state.SessionLocal)
    assert items and items[-1] is None                   # subscribers got the end of stream
    assert calls["n"] == 4                                # first try + 3 retries
    assert not runner.is_live(jid) and jid not in runner._subs and jid not in runner._cancel_requested


def test_finish_retries_a_briefly_locked_db(client, monkeypatch):
    from app import jobs as jobs_mod
    from app.db import Job
    from app.jobs import JobRunner
    monkeypatch.setattr(jobs_mod, "RETRY_DELAYS", (0, 0, 0))
    runner = JobRunner(client.app.state.SessionLocal)
    real = runner._write
    calls = {"n": 0}

    def flaky(job_id, **fields):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise _locked()
        return real(job_id, **fields)
    runner._write = flaky
    jid, items = _run_echo(runner, client.app.state.SessionLocal)
    with client.app.state.SessionLocal() as db:
        job = db.get(Job, jid)
        assert job.status == "done" and job.finished_at is not None and "hi" in job.log
    assert items[-1] is None


def test_runner_db_writes_run_off_the_loop(client):
    import asyncio
    import threading
    from app.jobs import JobRunner
    runner = JobRunner(client.app.state.SessionLocal)
    threads = set()
    real = runner._write

    def spy(job_id, **fields):
        threads.add(threading.current_thread() is threading.main_thread())
        return real(job_id, **fields)
    runner._write = spy
    _run_echo(runner, client.app.state.SessionLocal)
    assert threads == {False}


def test_late_log_flush_does_not_overwrite_finished_job(client):
    from app.db import Job
    runner = client.app.state.job_runner
    with client.app.state.SessionLocal() as db:
        job = Job(kind="nmap", status="done", command="x", log="final log")
        db.add(job)
        db.commit()
        jid = job.id
    runner._write(jid, only_running=True, log="partial")
    with client.app.state.SessionLocal() as db:
        assert db.get(Job, jid).log == "final log"
