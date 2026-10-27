"""asyncio client for the supervisor's nsbx/1 Unix socket."""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

from .protocol import (
    MAX_FRAME_LEN,
    PROTOCOL_VERSION,
    Credit,
    Frame,
    FrameError,
    FrameType,
    decode,
    encode,
)

FrameHandler = Callable[[Frame], Awaitable[None]]
DisconnectHandler = Callable[[Exception | None], Awaitable[None]]


class SupervisorError(RuntimeError):
    pass


class SupervisorClient:
    """One connection. Frames from the supervisor go to ``on_frame`` in order;
    any read error or EOF calls ``on_disconnect`` once and stops the reader."""

    def __init__(self, path: str, client_name: str = "nsbx-orchestrator/0.1") -> None:
        self._path = path
        self._client_name = client_name
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._write_lock = asyncio.Lock()
        self._task: asyncio.Task[None] | None = None
        self.hello_ack: dict[str, Any] = {}

    async def connect(self, on_frame: FrameHandler, on_disconnect: DisconnectHandler) -> dict[str, Any]:
        self._reader, self._writer = await asyncio.open_unix_connection(self._path, limit=MAX_FRAME_LEN * 2)
        await self._send(
            FrameType.HELLO, json.dumps({"proto": [PROTOCOL_VERSION], "client": self._client_name}).encode()
        )
        frame = await self._read_frame()
        if frame.type is FrameType.ERROR:
            raise SupervisorError(f"supervisor refused hello: {frame.payload.decode(errors='replace')}")
        if frame.type is not FrameType.HELLO_ACK:
            raise SupervisorError(f"expected HelloAck, got {frame.type.name}")
        ack: dict[str, Any] = json.loads(frame.payload)
        if ack.get("proto") != PROTOCOL_VERSION:
            raise SupervisorError(f"unsupported protocol version {ack.get('proto')}")
        self.hello_ack = ack
        self._task = asyncio.create_task(self._read_loop(on_frame, on_disconnect))
        return ack

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
        if self._writer is not None:
            self._writer.close()

    async def submit(self, message: dict[str, Any]) -> None:
        await self._send(FrameType.SUBMIT, json.dumps(message, separators=(",", ":")).encode())

    async def cancel(self, job_id: uuid.UUID, grace_ms: int) -> None:
        await self._send(FrameType.CANCEL, json.dumps({"job_id": str(job_id), "grace_ms": grace_ms}).encode())

    async def credit(self, job_id: uuid.UUID, nbytes: int) -> None:
        await self._send(FrameType.CREDIT, Credit(job_id, nbytes).to_bytes())

    async def _send(self, ftype: FrameType, payload: bytes) -> None:
        if self._writer is None:
            raise SupervisorError("not connected")
        async with self._write_lock:
            self._writer.write(encode(ftype, payload))
            await self._writer.drain()

    async def _read_frame(self) -> Frame:
        assert self._reader is not None
        header = await self._reader.readexactly(4)
        length = int.from_bytes(header, "big")
        if length == 0 or length > MAX_FRAME_LEN:
            raise FrameError(f"frame length {length} out of range")
        body = await self._reader.readexactly(length)
        decoded = decode(header + body)
        assert decoded is not None
        return decoded[0]

    async def _read_loop(self, on_frame: FrameHandler, on_disconnect: DisconnectHandler) -> None:
        error: Exception | None = None
        try:
            while True:
                await on_frame(await self._read_frame())
        except asyncio.CancelledError:
            raise
        except (asyncio.IncompleteReadError, ConnectionError, FrameError) as e:
            error = e
        finally:
            await on_disconnect(error)
