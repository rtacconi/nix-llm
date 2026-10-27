"""Agent-facing request and response models (design §12.1).

These validate shape and size only. Narrowing against admin policy is done by
the supervisor (and later by the shared Rust ``narrow()`` through PyO3); the
orchestrator never decides what a job may do.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import uuid
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

MAX_FILES = 1024
MAX_INPUT_BYTES = 48 * 1024  # inline v1 limit: must fit one 64 KiB frame with JSON overhead


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Limits(Strict):
    wall_ms: Annotated[int, Field(gt=0)] | None = None
    cpu_ms: Annotated[int, Field(gt=0)] | None = None
    memory_bytes: Annotated[int, Field(gt=0)] | None = None
    pids: Annotated[int, Field(gt=0, lt=2**32)] | None = None
    output_bytes: Annotated[int, Field(gt=0)] | None = None


class InputFile(Strict):
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    content_b64: str
    mode: Literal["0644", "0755", "0600"] = "0644"

    @field_validator("content_b64")
    @classmethod
    def _is_base64(cls, v: str) -> str:
        try:
            base64.b64decode(v, validate=True)
        except binascii.Error as e:
            raise ValueError("content_b64 is not valid base64") from e
        return v

    def decoded_len(self) -> int:
        return len(base64.b64decode(self.content_b64))


class JobRequest(Strict):
    job_id: uuid.UUID | None = None
    profile: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,31}$")]
    argv: Annotated[list[Annotated[str, Field(max_length=4096)]], Field(min_length=1, max_length=256)]
    files: Annotated[list[InputFile], Field(max_length=MAX_FILES)] = []
    stdin_b64: str | None = None
    env: dict[Annotated[str, Field(pattern=r"^[A-Z_][A-Z0-9_]{0,63}$")], Annotated[str, Field(max_length=4096)]] = {}
    limits: Limits = Limits()
    network: Literal["none", "egress-proxy"] | None = None
    egress_domains: Annotated[list[str], Field(max_length=64)] = []
    collect: Annotated[list[str], Field(max_length=64)] = []
    grace_ms: Annotated[int, Field(ge=0)] | None = None

    @model_validator(mode="after")
    def _bounded_input(self) -> JobRequest:
        total = sum(f.decoded_len() for f in self.files)
        if self.stdin_b64 is not None:
            total += len(base64.b64decode(self.stdin_b64, validate=True))
        if total > MAX_INPUT_BYTES:
            raise ValueError(f"inline input is {total} bytes; the v1 limit is {MAX_INPUT_BYTES}")
        if len({f.path for f in self.files}) != len(self.files):
            raise ValueError("each input path may appear once")
        return self

    def request_hash(self) -> str:
        """SHA-256 over the canonical request without ``job_id`` (idempotency key)."""
        body = self.model_dump(mode="json", exclude={"job_id"})
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def policy_request(self) -> dict[str, object]:
        """The ``nsbx_policy::Request`` the supervisor narrows."""
        return {
            "profile": self.profile,
            "argv": self.argv,
            "env": self.env,
            "limits": self.limits.model_dump(exclude_none=True),
            "network": self.network,
            "egress_domains": sorted(self.egress_domains),
            "collect": self.collect,
            "files": [f.path for f in self.files],
            "input_bytes": sum(f.decoded_len() for f in self.files),
            "grace_ms": self.grace_ms,
        }


class ErrorView(Strict):
    category: str
    code: str
    message: str
    retryable: bool
    field: str | None = None
    requested: str | None = None
    allowed: str | None = None
    hint: str | None = None


JobState = Literal["queued", "submitted", "running", "exited", "rejected", "failed"]


class JobView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: uuid.UUID
    state: JobState
    profile: str
    result: dict[str, object] | None = None
    error: ErrorView | None = None
    stdout: str = ""
    stderr: str = ""
    output_truncated: bool = False
