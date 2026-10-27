"""A scripted nsbx/1 supervisor for tests. Behaviour is chosen by the last argv
element so tests read naturally: ``wait`` blocks until cancelled, ``flood``
streams output under credit flow control, ``hang`` never answers."""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

from nsbx_orchestrator.protocol import (
    PROTOCOL_VERSION,
    Credit,
    FrameType,
    Output,
    Stream,
    decode,
    encode,
)

CHUNK = 4096
WINDOW = 16 * 1024


class FakeSupervisor:
    def __init__(self, profiles: list[str]) -> None:
        self.profiles = profiles
        self.submits: list[dict[str, Any]] = []
        self.cancels: list[dict[str, Any]] = []
        self.credits_received = 0
        self.max_inflight = 0
        self._cancel_events: dict[str, asyncio.Event] = {}
        self._credit = asyncio.Condition()
        self._inflight = 0
        self._server: asyncio.base_events.Server | None = None
        self._writers: list[asyncio.StreamWriter] = []

    async def start(self, path: str) -> None:
        self._server = await asyncio.start_unix_server(self._serve, path)

    async def stop(self) -> None:
        for w in self._writers:
            w.close()
        if self._server is not None:
            self._server.close()

    async def drop_connections(self) -> None:
        for w in self._writers:
            w.close()

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.append(writer)
        buf = bytearray()

        async def send(ftype: FrameType, payload: bytes) -> None:
            writer.write(encode(ftype, payload))
            await writer.drain()

        async def send_json(ftype: FrameType, msg: dict[str, Any]) -> None:
            await send(ftype, json.dumps(msg).encode())

        try:
            while chunk := await reader.read(65536):
                buf.extend(chunk)
                while (d := decode(buf)) is not None:
                    frame, n = d
                    del buf[:n]
                    if frame.type is FrameType.HELLO:
                        hello = json.loads(frame.payload)
                        assert PROTOCOL_VERSION in hello["proto"]
                        await send_json(
                            FrameType.HELLO_ACK,
                            {"proto": 1, "supervisor": "fake/0", "features": {}, "profiles": self.profiles},
                        )
                    elif frame.type is FrameType.SUBMIT:
                        msg = json.loads(frame.payload)
                        self.submits.append(msg)
                        asyncio.create_task(self._job(msg, send, send_json))
                    elif frame.type is FrameType.CANCEL:
                        msg = json.loads(frame.payload)
                        self.cancels.append(msg)
                        if ev := self._cancel_events.get(msg["job_id"]):
                            ev.set()
                    elif frame.type is FrameType.CREDIT:
                        c = Credit.parse(frame.payload)
                        async with self._credit:
                            self.credits_received += c.nbytes
                            self._inflight -= c.nbytes
                            self._credit.notify_all()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass

    async def _job(self, msg: dict[str, Any], send: Any, send_json: Any) -> None:
        job_id = msg["job_id"]
        jid = uuid.UUID(job_id)
        req = msg["request"]
        mode = req["argv"][-1]
        if req["profile"] == "deny":
            await send_json(
                FrameType.REJECTED,
                {
                    "job_id": job_id,
                    "error": {
                        "category": "policy",
                        "code": "limit_exceeds_allowed",
                        "message": "memory over limit",
                        "retryable": False,
                        "field": "limits.memory_bytes",
                        "requested": "999",
                        "allowed": "10",
                        "hint": "request at most 10",
                    },
                },
            )
            return
        await send_json(FrameType.ACCEPTED, {"job_id": job_id, "slot": 0})
        await send_json(FrameType.STARTED, {"job_id": job_id, "setup_us": 1})
        if mode == "hang":
            return
        reason = "exited"
        if mode == "wait":
            ev = self._cancel_events.setdefault(job_id, asyncio.Event())
            await ev.wait()
            await send_json(FrameType.POLICY_EVENT, {"job_id": job_id, "kind": "cancel_acknowledged", "detail": ""})
            reason = "cancelled"
        elif mode == "flood":
            for seq in range(32):
                async with self._credit:
                    await self._credit.wait_for(lambda: self._inflight + CHUNK <= WINDOW)
                    self._inflight += CHUNK
                    self.max_inflight = max(self.max_inflight, self._inflight)
                await send(FrameType.OUTPUT, Output(jid, Stream.STDOUT, seq, b"x" * CHUNK).to_bytes())
        else:
            text = (" ".join(req["argv"]) + "\n").encode()
            await send(FrameType.OUTPUT, Output(jid, Stream.STDOUT, 0, text).to_bytes())
            await send(FrameType.OUTPUT, Output(jid, Stream.STDERR, 1, b"warn\n").to_bytes())
        await send_json(
            FrameType.EXITED,
            {
                "job_id": job_id,
                "reason": reason,
                "exit_code": 0 if reason == "exited" else None,
                "output_truncated": False,
            },
        )
