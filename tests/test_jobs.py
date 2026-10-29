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
