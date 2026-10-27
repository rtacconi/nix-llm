from __future__ import annotations

import uuid

import pytest

from nsbx_orchestrator.protocol import (
    MAX_FRAME_LEN,
    Credit,
    FrameError,
    FrameType,
    Output,
    Stream,
    decode,
    encode,
)


def test_round_trip_every_type() -> None:
    for ftype in FrameType:
        frame, n = decode(encode(ftype, b"abc")) or pytest.fail("incomplete")
        assert (frame.type, frame.payload, n) == (ftype, b"abc", 8)


def test_partial_input_needs_more() -> None:
    data = encode(FrameType.PING, bytes(8))
    for cut in range(len(data)):
        assert decode(data[:cut]) is None


def test_rejects_bad_headers() -> None:
    with pytest.raises(FrameError):
        decode(b"\x00\x00\x00\x00")
    with pytest.raises(FrameError):
        decode((MAX_FRAME_LEN + 1).to_bytes(4, "big"))
    with pytest.raises(FrameError):
        decode(b"\x00\x00\x00\x01\x99")
    with pytest.raises(FrameError):
        encode(FrameType.OUTPUT, bytes(MAX_FRAME_LEN))


def test_binary_payloads_match_rust_layout() -> None:
    jid = uuid.UUID(int=7)
    out = Output(jid, Stream.STDERR, 42, b"hi")
    raw = out.to_bytes()
    # job_id[16] | stream u8 | seq u64 BE | data  (crates/nsbx-proto/src/msg.rs)
    assert raw == jid.bytes + b"\x02" + (42).to_bytes(8, "big") + b"hi"
    assert Output.parse(raw) == out
    c = Credit(jid, 65_536)
    assert c.to_bytes() == jid.bytes + (65_536).to_bytes(4, "big")
    assert Credit.parse(c.to_bytes()) == c
