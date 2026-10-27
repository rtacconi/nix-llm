"""Job state, admission control, output buffering and event fan-out."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections import OrderedDict
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from .protocol import Frame, FrameType, Output, Stream
from .schemas import ErrorView, JobRequest, JobState, JobView
from .supervisor import SupervisorClient

TERMINAL: frozenset[JobState] = frozenset({"exited", "rejected", "failed"})
_ORDER: dict[JobState, int] = {"queued": 0, "submitted": 1, "running": 2, "exited": 3, "rejected": 3, "failed": 3}
FILE_MODES = {"0644": 0o644, "0755": 0o755, "0600": 0o600}


class Busy(Exception):
    """The admission queue is full."""


class Conflict(Exception):
    """Same job_id, different request."""


@dataclass
class Event:
    kind: str  # stdout | stderr | state | policy | exit
    data: dict[str, Any]


@dataclass
class JobRecord:
    job_id: uuid.UUID
    principal: str
    request: JobRequest
    request_hash: str
    state: JobState = "queued"
    result: dict[str, Any] | None = None
    error: ErrorView | None = None
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    truncated: bool = False
    done: asyncio.Event = field(default_factory=asyncio.Event)
    subscribers: list[asyncio.Queue[Event | None]] = field(default_factory=list)
    finished_at: float | None = None

    def view(self) -> JobView:
        return JobView(
            job_id=self.job_id,
            state=self.state,
            profile=self.request.profile,
            result=self.result,
            error=self.error,
            stdout=self.stdout.decode(errors="replace"),
            stderr=self.stderr.decode(errors="replace"),
            output_truncated=self.truncated,
        )


class JobManager:
    """Owns every job the orchestrator knows about.

    * Admission: at most ``max_running`` jobs at the supervisor, at most
      ``max_queued`` waiting; beyond that ``submit`` raises ``Busy``.
    * Jobs are keyed by (principal, job_id): one principal can never see or
      cancel another's job, whatever ``job_id`` it guesses.
    * Output kept per job is capped at ``output_keep_bytes``; credit is
      returned to the supervisor as output is stored, so supervisor memory
      stays bounded by its in-flight window.
    * Each SSE subscriber has a bounded queue and is dropped if it falls behind.
    """

    def __init__(
        self,
        client: SupervisorClient,
        *,
        max_running: int = 8,
        max_queued: int = 64,
        output_keep_bytes: int = 1 << 20,
        subscriber_queue: int = 256,
        max_results: int = 1_000,
        result_ttl_s: float = 600.0,
        deadline_slack_s: float = 10.0,
    ) -> None:
        self._client = client
        self._running = asyncio.Semaphore(max_running)
        self._capacity = max_running + max_queued
        self._active = 0  # admitted and not yet finished
        self._output_keep = output_keep_bytes
        self._subscriber_queue = subscriber_queue
        self._max_results = max_results
        self._result_ttl = result_ttl_s
        self._slack = deadline_slack_s
        self._jobs: OrderedDict[tuple[str, uuid.UUID], JobRecord] = OrderedDict()
        self._by_id: dict[uuid.UUID, JobRecord] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self.connected = False
        self.profiles: list[str] = []

    async def start(self) -> None:
        """Connect to the supervisor and learn which profiles it offers."""
        ack = await self._client.connect(self.on_frame, self.on_disconnect)
        self.profiles = list(ack.get("profiles", []))
        self.connected = True

    # ---- API used by the HTTP layer -------------------------------------

    async def submit(self, principal: str, req: JobRequest) -> JobRecord:
        job_id = req.job_id or uuid.uuid4()
        rhash = req.request_hash()
        existing = self._jobs.get((principal, job_id))
        if existing is not None:
            if existing.request_hash != rhash:
                raise Conflict(str(job_id))
            return existing
        if job_id in self._by_id:
            # Another principal used this id; do not reveal that it exists.
            raise Conflict(str(job_id))
        if self._active >= self._capacity:
            raise Busy()
        self._evict()
        rec = JobRecord(job_id=job_id, principal=principal, request=req, request_hash=rhash)
        self._jobs[(principal, job_id)] = rec
        self._by_id[job_id] = rec
        self._active += 1
        task = asyncio.create_task(self._run(rec))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return rec

    def get(self, principal: str, job_id: uuid.UUID) -> JobRecord | None:
        return self._jobs.get((principal, job_id))

    async def cancel(self, principal: str, job_id: uuid.UUID, grace_ms: int | None = None) -> JobRecord | None:
        rec = self.get(principal, job_id)
        if rec is None:
            return None
        if rec.state in ("submitted", "running"):
            await self._client.cancel(job_id, grace_ms if grace_ms is not None else rec.request.grace_ms or 2_000)
        elif rec.state == "queued":
            self._finish(rec, "failed", error=_error("admission", "cancelled", "cancelled before submission"))
        return rec

    async def events(self, rec: JobRecord) -> AsyncIterator[Event]:
        """Replay buffered output, then stream live events until the job ends."""
        q: asyncio.Queue[Event | None] = asyncio.Queue(maxsize=self._subscriber_queue)
        if rec.stdout:
            yield Event("stdout", {"data": rec.stdout.decode(errors="replace")})
        if rec.stderr:
            yield Event("stderr", {"data": rec.stderr.decode(errors="replace")})
        if rec.state in TERMINAL:
            yield Event("exit", rec.view().model_dump(mode="json"))
            return
        rec.subscribers.append(q)
        try:
            while (ev := await q.get()) is not None:
                yield ev
        finally:
            if q in rec.subscribers:
                rec.subscribers.remove(q)

    # ---- supervisor side --------------------------------------------------

    async def on_frame(self, frame: Frame) -> None:
        if frame.type is FrameType.OUTPUT:
            out = Output.parse(frame.payload)
            rec = self._by_id.get(out.job_id)
            if rec is not None:
                self._store_output(rec, out)
            # Credit even for unknown jobs, so a stale stream can drain.
            await self._client.credit(out.job_id, len(out.data))
            return
        if frame.type in (FrameType.PING, FrameType.PONG, FrameType.CREDIT):
            return
        msg = json.loads(frame.payload)
        rec = self._by_id.get(uuid.UUID(msg["job_id"])) if "job_id" in msg else None
        if frame.type is FrameType.ERROR:
            await self.on_disconnect(RuntimeError(msg.get("message", "supervisor error")))
        elif rec is None:
            return
        elif frame.type is FrameType.ACCEPTED:
            self._set_state(rec, "submitted")
        elif frame.type is FrameType.STARTED:
            self._set_state(rec, "running")
        elif frame.type is FrameType.REJECTED:
            self._finish(rec, "rejected", error=ErrorView(**msg["error"]))
        elif frame.type is FrameType.POLICY_EVENT:
            self._publish(rec, Event("policy", {k: v for k, v in msg.items() if k != "job_id"}))
        elif frame.type is FrameType.EXITED:
            rec.truncated = rec.truncated or bool(msg.get("output_truncated"))
            self._finish(rec, "exited", result=msg)

    async def on_disconnect(self, error: Exception | None) -> None:
        """Fail closed: every job in flight at the supervisor is lost."""
        self.connected = False
        for rec in list(self._jobs.values()):
            if rec.state in ("submitted", "running"):
                self._finish(
                    rec,
                    "failed",
                    error=_error(
                        "internal", "supervisor_unavailable", str(error or "connection closed"), retryable=True
                    ),
                )

    # ---- internals ----------------------------------------------------------

    async def _run(self, rec: JobRecord) -> None:
        try:
            async with self._running:
                if rec.state == "queued":
                    await self._submit_and_wait(rec)
        finally:
            self._active -= 1

    async def _submit_and_wait(self, rec: JobRecord) -> None:
        req = rec.request
        files = [{"path": f.path, "content_b64": f.content_b64, "mode": FILE_MODES[f.mode]} for f in req.files]
        await self._client.submit(
            {
                "job_id": str(rec.job_id),
                "request_hash": rec.request_hash,
                "principal": rec.principal,
                "request": req.policy_request(),
                "files": files,
                "stdin_b64": req.stdin_b64,
            }
        )
        self._set_state(rec, "submitted")
        # The supervisor enforces the deadline; this is the backstop for a
        # supervisor that stops answering.
        wall_s = (req.limits.wall_ms or 600_000) / 1000
        try:
            await asyncio.wait_for(rec.done.wait(), timeout=wall_s + self._slack)
        except TimeoutError:
            await self._client.cancel(rec.job_id, 0)
            try:
                await asyncio.wait_for(rec.done.wait(), timeout=self._slack)
            except TimeoutError:
                err = _error("internal", "supervisor_unresponsive", "no result after the deadline", retryable=True)
                self._finish(rec, "failed", error=err)

    def _store_output(self, rec: JobRecord, out: Output) -> None:
        buf = rec.stdout if out.stream is Stream.STDOUT else rec.stderr
        room = self._output_keep - (len(rec.stdout) + len(rec.stderr))
        if room <= 0:
            rec.truncated = True
        else:
            if len(out.data) > room:
                rec.truncated = True
            buf.extend(out.data[:room])
        kind = "stdout" if out.stream is Stream.STDOUT else "stderr"
        self._publish(rec, Event(kind, {"data": out.data.decode(errors="replace")}))

    def _set_state(self, rec: JobRecord, state: JobState) -> None:
        # Forward only: frames may race (Started can beat our own "submitted").
        if rec.state in TERMINAL or _ORDER[state] <= _ORDER[rec.state]:
            return
        rec.state = state
        self._publish(rec, Event("state", {"state": state}))

    def _finish(
        self, rec: JobRecord, state: JobState, *, result: dict[str, Any] | None = None, error: ErrorView | None = None
    ) -> None:
        if rec.state in TERMINAL:
            return
        rec.state, rec.result, rec.error = state, result, error
        rec.finished_at = time.monotonic()
        rec.done.set()
        self._publish(rec, Event("exit", rec.view().model_dump(mode="json")))
        for q in rec.subscribers:
            _offer(q, None)

    def _publish(self, rec: JobRecord, ev: Event) -> None:
        for q in list(rec.subscribers):
            if not _offer(q, ev):
                rec.subscribers.remove(q)  # slow consumer: drop it, never buffer without bound
                _force_close(q)

    def _evict(self) -> None:
        """Drop expired results, then the oldest finished jobs while over capacity.
        Jobs still in flight are never evicted."""
        now = time.monotonic()
        finished = [(k, r) for k, r in self._jobs.items() if r.finished_at is not None]
        for key, rec in finished:
            assert rec.finished_at is not None
            if now - rec.finished_at > self._result_ttl or len(self._jobs) >= self._max_results:
                del self._jobs[key]
                self._by_id.pop(rec.job_id, None)


def _offer(q: asyncio.Queue[Event | None], item: Event | None) -> bool:
    try:
        q.put_nowait(item)
        return True
    except asyncio.QueueFull:
        return False


def _force_close(q: asyncio.Queue[Event | None]) -> None:
    while not q.empty():
        q.get_nowait()
    q.put_nowait(None)


def _error(category: str, code: str, message: str, *, retryable: bool = False) -> ErrorView:
    return ErrorView(category=category, code=code, message=message, retryable=retryable)
