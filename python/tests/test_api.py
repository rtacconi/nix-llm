"""End-to-end through HTTP → JobManager → nsbx/1 → fake supervisor."""

from __future__ import annotations

import asyncio
import base64
import shutil
import tempfile
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import httpx
import pytest

from nsbx_orchestrator.app import create_app
from nsbx_orchestrator.auth import Principal, TokenAuth
from nsbx_orchestrator.jobs import JobManager
from nsbx_orchestrator.supervisor import SupervisorClient

from .fake_supervisor import WINDOW, FakeSupervisor

TOKEN_A = "token-a"
TOKEN_B = "token-b"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class Env:
    http: httpx.AsyncClient
    sup: FakeSupervisor
    jobs: JobManager


@pytest.fixture
async def env() -> AsyncIterator[Env]:
    # macOS limits Unix socket paths to ~104 bytes, so avoid long tmp dirs.
    d = tempfile.mkdtemp(prefix="nsbx", dir="/tmp")
    path = f"{d}/s.sock"
    sup = FakeSupervisor(["python-compute", "cli-text", "deny"])
    await sup.start(path)
    client = SupervisorClient(path)
    jobs = JobManager(client, max_running=2, max_queued=2, output_keep_bytes=64 * 1024, deadline_slack_s=0.5)
    await jobs.start()
    auth = TokenAuth(
        {
            TokenAuth.digest(TOKEN_A): Principal("agent-a", frozenset({"python-compute", "deny"})),
            TokenAuth.digest(TOKEN_B): Principal("agent-b", frozenset({"python-compute"})),
        }
    )
    transport = httpx.ASGITransport(app=create_app(jobs, auth))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
        yield Env(http, sup, jobs)
    await client.close()
    await sup.stop()
    shutil.rmtree(d, ignore_errors=True)


def hdr(token: str = TOKEN_A) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def job(**kw: Any) -> dict[str, Any]:
    body: dict[str, Any] = {"profile": "python-compute", "argv": ["python3", "-c", "print(1)"]}
    body.update(kw)
    return body


async def wait_terminal(e: Env, job_id: str, token: str = TOKEN_A) -> dict[str, Any]:
    for _ in range(200):
        r = await e.http.get(f"/v1/jobs/{job_id}", headers=hdr(token))
        v: dict[str, Any] = r.json()
        if v["state"] in ("exited", "rejected", "failed"):
            return v
        await asyncio.sleep(0.01)
    raise AssertionError("job did not finish")


@pytest.mark.anyio
async def test_submit_and_collect_output(env: Env) -> None:
    r = await env.http.post("/v1/jobs", json=job(), headers=hdr())
    assert r.status_code == 202
    v = await wait_terminal(env, r.json()["job_id"])
    assert v["state"] == "exited"
    assert v["stdout"] == "python3 -c print(1)\n"
    assert v["stderr"] == "warn\n"
    sent = env.sup.submits[0]
    assert sent["principal"] == "agent-a"
    assert sent["request"]["argv"] == ["python3", "-c", "print(1)"]
    assert len(sent["request_hash"]) == 64


@pytest.mark.anyio
async def test_requires_auth(env: Env) -> None:
    assert (await env.http.post("/v1/jobs", json=job())).status_code == 401
    assert (await env.http.post("/v1/jobs", json=job(), headers=hdr("nope"))).status_code == 401


@pytest.mark.anyio
async def test_schema_errors_are_structured(env: Env) -> None:
    r = await env.http.post("/v1/jobs", json=job(env={"lower": "x"}, surprise=1), headers=hdr())
    assert r.status_code == 400
    fields = {d["field"] for d in r.json()["error"]["details"]}
    assert "surprise" in fields and any(f.startswith("env") for f in fields)


@pytest.mark.anyio
async def test_profile_not_allowed_names_alternatives(env: Env) -> None:
    r = await env.http.post("/v1/jobs", json=job(profile="cli-text"), headers=hdr())
    assert r.status_code == 403
    assert r.json()["error"]["allowed"] == ["deny", "python-compute"]


@pytest.mark.anyio
async def test_supervisor_rejection_is_passed_through(env: Env) -> None:
    r = await env.http.post("/v1/jobs", json=job(profile="deny"), headers=hdr())
    v = await wait_terminal(env, r.json()["job_id"])
    assert v["state"] == "rejected"
    assert v["error"]["field"] == "limits.memory_bytes"
    assert v["error"]["hint"] == "request at most 10"


@pytest.mark.anyio
async def test_jobs_are_scoped_to_their_principal(env: Env) -> None:
    jid = str(uuid.uuid4())
    r = await env.http.post("/v1/jobs", json=job(job_id=jid), headers=hdr())
    assert r.status_code == 202
    assert (await env.http.get(f"/v1/jobs/{jid}", headers=hdr(TOKEN_B))).status_code == 404
    assert (await env.http.post(f"/v1/jobs/{jid}/cancel", headers=hdr(TOKEN_B))).status_code == 404
    # Reusing another principal's id is refused without revealing the job.
    assert (await env.http.post("/v1/jobs", json=job(job_id=jid), headers=hdr(TOKEN_B))).status_code == 409


@pytest.mark.anyio
async def test_idempotent_resubmit(env: Env) -> None:
    jid = str(uuid.uuid4())
    a = await env.http.post("/v1/jobs", json=job(job_id=jid), headers=hdr())
    b = await env.http.post("/v1/jobs", json=job(job_id=jid), headers=hdr())
    assert a.json()["job_id"] == b.json()["job_id"] == jid
    await wait_terminal(env, jid)
    assert len(env.sup.submits) == 1
    c = await env.http.post("/v1/jobs", json=job(job_id=jid, argv=["python3", "other"]), headers=hdr())
    assert c.status_code == 409


@pytest.mark.anyio
async def test_cancel_reaches_supervisor(env: Env) -> None:
    r = await env.http.post("/v1/jobs", json=job(argv=["python3", "wait"]), headers=hdr())
    jid = r.json()["job_id"]
    for _ in range(100):
        if (await env.http.get(f"/v1/jobs/{jid}", headers=hdr())).json()["state"] == "running":
            break
        await asyncio.sleep(0.01)
    assert (await env.http.post(f"/v1/jobs/{jid}/cancel", headers=hdr())).status_code == 202
    v = await wait_terminal(env, jid)
    assert v["result"]["reason"] == "cancelled"
    assert env.sup.cancels[0]["job_id"] == jid


@pytest.mark.anyio
async def test_output_flow_control_bounds_inflight_bytes(env: Env) -> None:
    r = await env.http.post("/v1/jobs", json=job(argv=["python3", "flood"]), headers=hdr())
    v = await wait_terminal(env, r.json()["job_id"])
    assert v["state"] == "exited"
    # 128 KiB streamed, 64 KiB kept (the fixture's output_keep_bytes), flagged.
    assert len(v["stdout"]) == 64 * 1024
    assert v["output_truncated"] is True
    assert env.sup.max_inflight <= WINDOW
    assert env.sup.credits_received == 32 * 4096


@pytest.mark.anyio
async def test_admission_queue_is_bounded(env: Env) -> None:
    codes = []
    for _ in range(6):
        r = await env.http.post("/v1/jobs", json=job(argv=["python3", "wait"]), headers=hdr())
        codes.append(r.status_code)
    # max_running=2 + max_queued=2: the fifth and sixth submissions are refused.
    assert codes == [202, 202, 202, 202, 429, 429]


@pytest.mark.anyio
async def test_supervisor_disconnect_fails_closed(env: Env) -> None:
    r = await env.http.post("/v1/jobs", json=job(argv=["python3", "wait"]), headers=hdr())
    jid = r.json()["job_id"]
    await asyncio.sleep(0.05)
    await env.sup.drop_connections()
    v = await wait_terminal(env, jid)
    assert v["state"] == "failed"
    assert v["error"]["code"] == "supervisor_unavailable"
    assert (await env.http.get("/v1/health")).status_code == 503
    assert (await env.http.post("/v1/jobs", json=job(), headers=hdr())).status_code == 503


@pytest.mark.anyio
async def test_backstop_deadline_cancels_unresponsive_job(env: Env) -> None:
    r = await env.http.post("/v1/jobs", json=job(argv=["python3", "hang"], limits={"wall_ms": 100}), headers=hdr())
    v = await wait_terminal(env, r.json()["job_id"])
    assert v["error"]["code"] == "supervisor_unresponsive"
    assert env.sup.cancels and env.sup.cancels[0]["grace_ms"] == 0


@pytest.mark.anyio
async def test_sse_stream_replays_and_ends_with_exit(env: Env) -> None:
    r = await env.http.post("/v1/jobs", json=job(), headers=hdr())
    jid = r.json()["job_id"]
    await wait_terminal(env, jid)
    s = await env.http.get(f"/v1/jobs/{jid}/events", headers=hdr())
    assert s.headers["content-type"].startswith("text/event-stream")
    kinds = [line.split(": ", 1)[1] for line in s.text.splitlines() if line.startswith("event: ")]
    assert kinds == ["stdout", "stderr", "exit"]


@pytest.mark.anyio
async def test_inline_input_limit(env: Env) -> None:
    big = base64.b64encode(b"x" * 60_000).decode()
    r = await env.http.post("/v1/jobs", json=job(files=[{"path": "a.py", "content_b64": big}]), headers=hdr())
    assert r.status_code == 400


@pytest.mark.anyio
async def test_profiles_are_filtered_per_principal(env: Env) -> None:
    r = await env.http.get("/v1/profiles", headers=hdr(TOKEN_B))
    assert r.json() == {"profiles": ["python-compute"]}
