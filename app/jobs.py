"""Run scanner/update subprocesses as asyncio tasks, keep a live log in memory, persist it to the
Job row, and fan lines out to SSE subscribers."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
from typing import Callable, Optional

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from .db import Job, utcnow

log = logging.getLogger(__name__)

CompletionHook = Callable[[Session, Job, str], Optional[str]]
MAX_LIVE_LINES = 20000
RETRY_DELAYS = (0.25, 1.0, 3.0)  # seconds between retries of a job-row write that hit "database is locked"


def quote_argv(argv: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)


def job_warnings(job: Job) -> list[str]:
    """Warnings recorded by the completion hook (e.g. nuclei dropped a target). Stored in params_json."""
    try:
        params = json.loads(job.params_json or "{}")
    except (json.JSONDecodeError, TypeError):
        return []
    w = params.get("warnings") if isinstance(params, dict) else None
    return [str(x) for x in w] if isinstance(w, list) else []


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
        self._redact: dict[int, list[str]] = {}
        self._loop: asyncio.AbstractEventLoop | None = None

    # ----- creation / start -------------------------------------------------
    def create_job(self, db: Session, kind: str, argv: list[str], params: dict | None = None) -> Job:
        job = Job(kind=kind, status="queued", command=quote_argv(argv), params_json=json.dumps(params or {}))
        db.add(job)
        db.commit()
        db.refresh(job)
        return job

    def start(self, job_id: int, argv: list[str], on_complete: Optional[CompletionHook] = None,
              env: dict | None = None, stdout_to_log: bool = True,
              cleanup: Optional[Callable[[], None]] = None, redact: list[str] | None = None) -> asyncio.Task | None:
        """``on_complete`` and ``cleanup`` run in a worker thread (a large ingest must not freeze HTTP); ``cleanup``
        runs once the job has ended, whatever the outcome (done, failed, cancelled, cannot start). Every string in
        ``redact`` is replaced by [redacted] in the live and stored log and output.
        Called from a worker thread (a completion hook chaining a job), the start is handed to the event loop and
        None is returned."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is None:
            if self._loop is None:
                raise RuntimeError("JobRunner.start called outside the event loop before any job ran")
            self._loop.call_soon_threadsafe(lambda: self.start(job_id, argv, on_complete, env, stdout_to_log, cleanup,
                                                               redact))
            return None
        self._loop = loop
        if redact:
            self._redact[job_id] = sorted({r for r in redact if r}, key=len, reverse=True)
        task = loop.create_task(self._run_and_clean(job_id, argv, on_complete, env, stdout_to_log, cleanup))
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

    def _scrub(self, job_id: int, text: str) -> str:
        for secret in self._redact.get(job_id, ()):
            text = text.replace(secret, "[redacted]")
        return text

    def _publish(self, job_id: int, line: str) -> None:
        line = self._scrub(job_id, line)
        lines = self._live.setdefault(job_id, [])
        if len(lines) >= MAX_LIVE_LINES:
            del lines[: len(lines) - MAX_LIVE_LINES + 1]
        lines.append(line)
        idx = len(lines) - 1
        for q in self._subs.get(job_id, ()):
            q.put_nowait((idx, line))

    def cancel_requested(self, job_id: int) -> bool:
        """For completion hooks (worker thread): did the operator cancel while results were being processed?"""
        return job_id in self._cancel_requested

    def _write(self, job_id: int, **fields) -> None:
        """Blocking job-row update; always called through ``_persist`` in a worker thread."""
        with self.session_factory() as db:
            job = db.get(Job, job_id)
            if job is None:
                return
            for k, v in fields.items():
                setattr(job, k, v)
            db.commit()

    async def _persist(self, job_id: int, retries: tuple[float, ...] | None = None, **fields) -> bool:
        """Write job fields off the event loop. A completion hook may hold SQLite's write lock: retry a locked
        database with backoff instead of failing. Never raises; returns whether the write landed."""
        delays = RETRY_DELAYS if retries is None else retries
        for attempt in range(len(delays) + 1):
            try:
                await asyncio.to_thread(self._write, job_id, **fields)
                return True
            except OperationalError as e:
                if attempt == len(delays):
                    log.error("job %s: giving up writing %s: %s", job_id, sorted(fields), e)
                    return False
                await asyncio.sleep(delays[attempt])
            except Exception:  # noqa: BLE001 - the runner must survive any storage problem
                log.exception("job %s: writing %s failed", job_id, sorted(fields))
                return False
        return False

    async def _finish(self, job_id: int, status: str, exit_code: int | None, output: str) -> None:
        """Persist the result, then always end the live state and close every subscriber's stream, even when the
        write failed (the row then stays 'running' until the restart sweep marks it interrupted)."""
        try:
            log_text = "\n".join(self._live.get(job_id, []))
            await self._persist(job_id, status=status, exit_code=exit_code, finished_at=utcnow(), log=log_text,
                                output=self._scrub(job_id, output))
        finally:
            self._live.pop(job_id, None)
            self._redact.pop(job_id, None)
            self._cancel_requested.discard(job_id)
            for q in self._subs.pop(job_id, set()):
                q.put_nowait(None)

    async def _flush_loop(self, job_id: int) -> None:
        while True:
            await asyncio.sleep(1.0)
            lines = self._live.get(job_id)
            if lines:
                await self._persist(job_id, retries=(), log="\n".join(lines))  # best effort; the next tick retries

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

    async def _run_and_clean(self, job_id: int, argv: list[str], on_complete, env, stdout_to_log: bool,
                             cleanup) -> None:
        try:
            await self._run(job_id, argv, on_complete, env, stdout_to_log)
        finally:
            if cleanup is not None:
                try:
                    await asyncio.to_thread(cleanup)
                except Exception:  # noqa: BLE001 - never let cleanup mask the job result
                    pass

    def _complete(self, job_id: int, on_complete: CompletionHook, output: str, live: str) -> Optional[str]:
        """Runs in a worker thread with its own session. Hooks only use the database; one that chains a job calls
        ``start``, which hands it back to the event loop."""
        with self.session_factory() as db:
            job = db.get(Job, job_id)
            job.log = live
            note = on_complete(db, job, output)
            db.commit()
        return note

    async def _run(self, job_id: int, argv: list[str], on_complete, env, stdout_to_log: bool) -> None:
        with self.session_factory() as db:
            job = db.get(Job, job_id)
            kind = job.kind if job else "other"
        self._live.setdefault(job_id, [])
        self._publish(job_id, f"[runner] queued: {quote_argv(argv)}")
        async with self._sem(kind):
            if job_id in self._cancel_requested:
                self._publish(job_id, "[runner] cancelled before start")
                await self._finish(job_id, "cancelled", None, "")
                return
            await self._persist(job_id, status="running", started_at=utcnow())
            self._publish(job_id, "[runner] started")
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    env={**os.environ, **(env or {})}, limit=4 * 1024 * 1024,
                )
            except (FileNotFoundError, PermissionError, OSError) as e:
                self._publish(job_id, f"[runner] cannot start: {e}")
                await self._finish(job_id, "failed", 127, "")
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
                    live = "\n".join(self._live.get(job_id, []))  # hooks may inspect the tool's own status lines
                    note = await asyncio.to_thread(self._complete, job_id, on_complete, output, live)
                    self._publish(job_id, "[runner] results processed")
                    if isinstance(note, str) and note:
                        self._publish(job_id, note)
                except Exception as e:  # noqa: BLE001 - surface anything to the operator
                    self._publish(job_id, f"[runner] result processing failed: {e!r}")
                    status = "failed"
            self._publish(job_id, f"[runner] exit code {code} ({status})")
            await self._finish(job_id, status, code, output)
