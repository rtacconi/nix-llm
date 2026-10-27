"""The nsbx/1 framing and binary payloads (mirror of crates/nsbx-proto).

Frame: ``len: u32 BE | type: u8 | payload`` where ``len`` counts the type byte
plus the payload and ``1 <= len <= MAX_FRAME_LEN``.
"""

from __future__ import annotations

import enum
import struct
import uuid
from dataclasses import dataclass

MAX_FRAME_LEN = 65_536
HEADER_LEN = 4
PROTOCOL_VERSION = 1


class FrameType(enum.IntEnum):
    HELLO = 0x01
    HELLO_ACK = 0x02
    SUBMIT = 0x10
    ACCEPTED = 0x11
    REJECTED = 0x12
    STARTED = 0x13
    OUTPUT = 0x20
    CREDIT = 0x21
    CANCEL = 0x30
    EXITED = 0x31
    ARTIFACT = 0x32
    POLICY_EVENT = 0x33
    PING = 0x40
    PONG = 0x41
    ERROR = 0x7F


class FrameError(ValueError):
    pass


@dataclass(frozen=True)
class Frame:
    type: FrameType
    payload: bytes


def encode(ftype: FrameType, payload: bytes) -> bytes:
    length = len(payload) + 1
    if length > MAX_FRAME_LEN:
        raise FrameError(f"payload of {len(payload)} bytes does not fit in a frame")
    return struct.pack(">IB", length, ftype) + payload


def decode(buf: bytes | bytearray) -> tuple[Frame, int] | None:
    """Decode one frame from the front of ``buf``; ``None`` if more bytes are needed."""
    if len(buf) < HEADER_LEN:
        return None
    (length,) = struct.unpack_from(">I", buf)
    if length == 0 or length > MAX_FRAME_LEN:
        raise FrameError(f"frame length {length} is zero or exceeds {MAX_FRAME_LEN}")
    total = HEADER_LEN + length
    if len(buf) < total:
        return None
    try:
        ftype = FrameType(buf[HEADER_LEN])
    except ValueError as e:
        raise FrameError(f"unknown frame type 0x{buf[HEADER_LEN]:02x}") from e
    return Frame(ftype, bytes(buf[HEADER_LEN + 1 : total])), total


class Stream(enum.IntEnum):
    STDOUT = 1
    STDERR = 2


@dataclass(frozen=True)
class Output:
    job_id: uuid.UUID
    stream: Stream
    seq: int
    data: bytes

    _FIXED = struct.Struct(">16sBQ")

    @classmethod
    def parse(cls, p: bytes) -> Output:
        if len(p) < cls._FIXED.size:
            raise FrameError(f"output payload has {len(p)} bytes, expected >= {cls._FIXED.size}")
        jid, stream, seq = cls._FIXED.unpack_from(p)
        try:
            s = Stream(stream)
        except ValueError as e:
            raise FrameError(f"unknown output stream {stream}") from e
        return cls(uuid.UUID(bytes=jid), s, seq, p[cls._FIXED.size :])

    def to_bytes(self) -> bytes:
        return self._FIXED.pack(self.job_id.bytes, self.stream, self.seq) + self.data


@dataclass(frozen=True)
class Credit:
    job_id: uuid.UUID
    nbytes: int

    _FMT = struct.Struct(">16sI")

    @classmethod
    def parse(cls, p: bytes) -> Credit:
        if len(p) != cls._FMT.size:
            raise FrameError(f"credit payload has {len(p)} bytes, expected {cls._FMT.size}")
        jid, n = cls._FMT.unpack(p)
        return cls(uuid.UUID(bytes=jid), n)

    def to_bytes(self) -> bytes:
        return self._FMT.pack(self.job_id.bytes, self.nbytes)
