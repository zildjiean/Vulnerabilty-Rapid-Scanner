"""Run scanner/update subprocesses as asyncio tasks, keep a live log in memory, persist it to the
Job row, and fan lines out to SSE subscribers."""
from __future__ import annotations

import asyncio
import json
import os
import shlex
from typing import Callable, Optional

from sqlalchemy.orm import Session

from .db import Job, utcnow

CompletionHook = Callable[[Session, Job, str], Optional[str]]
MAX_LIVE_LINES = 20000


def quote_argv(argv: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)


def fail_interrupted_jobs(db: Session) -> int:
    """On startup, any job still queued/running belongs to a previous process and cannot resume."""
    from sqlalchemy import select
    stale = list(db.scalars(select(Job).where(Job.status.in_(("queued", "running")))))
    for job in stale:
        job.status = "failed"
        job.finished_at = utcnow()
        job.log = (job.log + "\n" if job.log else "") + "[runner] interrupted by application restart; re-run the job"
    if stale:
        db.commit()
    return len(stale)


class JobRunner:
    def __init__(self, session_factory):
        self.session_factory = session_factory
        self._subs: dict[int, set[asyncio.Queue]] = {}
        self._procs: dict[int, asyncio.subprocess.Process] = {}
        self._sems: dict[str, asyncio.Semaphore] = {}
        self._tasks: set[asyncio.Task] = set()
        self._live: dict[int, list[str]] = {}
        self._cancel_requested: set[int] = set()

    # ----- creation / start -------------------------------------------------
    def create_job(self, db: Session, kind: str, argv: list[str], params: dict | None = None) -> Job:
        job = Job(kind=kind, status="queued", command=quote_argv(argv), params_json=json.dumps(params or {}))
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    def start(self, job_id: int, argv: list[str], on_complete: Optional[CompletionHook] = None,
              env: dict | None = None, stdout_to_log: bool = True) -> asyncio.Task:
        task = asyncio.get_running_loop().create_task(self._run(job_id, argv, on_complete, env, stdout_to_log))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    # ----- observation ------------------------------------------------------
    def is_live(self, job_id: int) -> bool:
        return job_id in self._live

    def live_log(self, job_id: int) -> list[str]:
        return list(self._live.get(job_id, []))

    def subscribe(self, job_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subs.setdefault(job_id, set()).add(q)
        return q

    def unsubscribe(self, job_id: int, q: asyncio.Queue) -> None:
        subs = self._subs.get(job_id)
        if subs:
            subs.discard(q)

    def cancel(self, job_id: int) -> bool:
        if job_id not in self._live:
            return False
        self._cancel_requested.add(job_id)
        proc = self._procs.get(job_id)
        if proc is not None and proc.returncode is None:
            proc.terminate()
        return True

    # ----- internals --------------------------------------------------------
    def _sem(self, kind: str) -> asyncio.Semaphore:
        return self._sems.setdefault(kind, asyncio.Semaphore(1))

    def _publish(self, job_id: int, line: str) -> None:
        lines = self._live.setdefault(job_id, [])
        if len(lines) >= MAX_LIVE_LINES:
            del lines[: len(lines) - MAX_LIVE_LINES + 1]
        lines.append(line)
        idx = len(lines) - 1
        for q in self._subs.get(job_id, ()):
            q.put_nowait((idx, line))

    def _update(self, job_id: int, **fields) -> None:
        with self.session_factory() as db:
            job = db.get(Job, job_id)
            if job is None:
                return
            for k, v in fields.items():
                setattr(job, k, v)
            db.commit()

    def _finish(self, job_id: int, status: str, exit_code: int | None, output: str) -> None:
        log = "\n".join(self._live.pop(job_id, []))
        self._cancel_requested.discard(job_id)
        self._update(job_id, status=status, exit_code=exit_code, finished_at=utcnow(), log=log, output=output)
        for q in self._subs.pop(job_id, set()):
            q.put_nowait(None)

    async def _flush_loop(self, job_id: int) -> None:
        while True:
            await asyncio.sleep(1.0)
            lines = self._live.get(job_id)
            if lines:
                self._update(job_id, log="\n".join(lines))

    async def _pump(self, job_id: int, stream, to_log: bool, collect: list[str] | None) -> None:
        while True:
            try:
                line = await stream.readline()
            except (ValueError, asyncio.LimitOverrunError):
                self._publish(job_id, "[runner] line too long, skipped")
                continue
            if not line:
                return
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            if collect is not None:
                collect.append(text)
            if to_log:
                self._publish(job_id, text)

    async def _run(self, job_id: int, argv: list[str], on_complete, env, stdout_to_log: bool) -> None:
        with self.session_factory() as db:
            job = db.get(Job, job_id)
            kind = job.kind if job else "other"
        self._live.setdefault(job_id, [])
        self._publish(job_id, f"[runner] queued: {quote_argv(argv)}")
        async with self._sem(kind):
            if job_id in self._cancel_requested:
                self._publish(job_id, "[runner] cancelled before start")
                self._finish(job_id, "cancelled", None, "")
                return
            self._update(job_id, status="running", started_at=utcnow())
            self._publish(job_id, "[runner] started")
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    env={**os.environ, **(env or {})}, limit=4 * 1024 * 1024,
                )
            except (FileNotFoundError, PermissionError, OSError) as e:
                self._publish(job_id, f"[runner] cannot start: {e}")
                self._finish(job_id, "failed", 127, "")
                return
            self._procs[job_id] = proc
            stdout_lines: list[str] = []
            flusher = asyncio.get_running_loop().create_task(self._flush_loop(job_id))
            try:
                await asyncio.gather(
                    self._pump(job_id, proc.stdout, stdout_to_log, stdout_lines),
                    self._pump(job_id, proc.stderr, True, None),
                )
                code = await proc.wait()
            finally:
                flusher.cancel()
                self._procs.pop(job_id, None)
            output = "\n".join(stdout_lines)
            if code < 0 or job_id in self._cancel_requested:
                status = "cancelled"
            elif code == 0:
                status = "done"
            else:
                status = "failed"
            if on_complete is not None and status == "done":
                try:
                    with self.session_factory() as db:
                        job = db.get(Job, job_id)
                        note = on_complete(db, job, output)
                        db.commit()
                    self._publish(job_id, "[runner] results processed")
                    if isinstance(note, str) and note:
                        self._publish(job_id, note)
                except Exception as e:  # noqa: BLE001 - surface anything to the operator
                    self._publish(job_id, f"[runner] result processing failed: {e!r}")
                    status = "failed"
            self._publish(job_id, f"[runner] exit code {code} ({status})")
            self._finish(job_id, status, code, output)
