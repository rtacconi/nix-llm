"""One real nsbx-supervisor job. Skipped unless NSBX_SUPERVISOR is set.

The binary must be built with `--features insecure-dev-mode`, and nsbx-stage2
must sit in the same directory. The test fails when the variable is set and
the job does not print `1`.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import tempfile
from pathlib import Path

import httpx
import pytest
from nsbx_policy import Policy

from nsbx_orchestrator.app import create_app
from nsbx_orchestrator.auth import Principal, TokenAuth
from nsbx_orchestrator.jobs import JobManager
from nsbx_orchestrator.supervisor import SupervisorClient

ROOT = Path(__file__).resolve().parents[2]
TOKEN = "token-a"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _runtime() -> str:
    found = shutil.which("python3")
    if found is None:
        raise AssertionError("python3 is not on PATH")
    return str(Path(found).resolve().parents[1])


@pytest.mark.anyio
async def test_real_supervisor_runs_python() -> None:
    binary = os.environ.get("NSBX_SUPERVISOR")
    if not binary:
        pytest.skip("NSBX_SUPERVISOR is unset")
    d = Path(tempfile.mkdtemp(prefix="nsbx", dir="/tmp"))
    etc = d / "etc"
    etc.mkdir()
    (etc / "passwd").write_text("root:x:0:0:root:/:/bin/false\n")
    (etc / "group").write_text("root:x:0:\n")
    (etc / "hosts").write_text("127.0.0.1 localhost\n")
    (etc / "resolv.conf").write_text("")
    (d / "principals.json").write_text('[{"id":"agent-a","profiles":["python-compute"]}]\n')
    sock = d / "s.sock"
    log_f = (d / "log").open("wb")
    proc = await asyncio.create_subprocess_exec(
        binary,
        "--socket",
        str(sock),
        "--policy",
        str(ROOT / "policy" / "profiles"),
        "--seccomp",
        str(ROOT / "policy" / "seccomp"),
        "--principals",
        str(d / "principals.json"),
        "--etc",
        str(etc),
        "--runtime",
        f"python-compute={_runtime()}",
        stdout=log_f,
        stderr=asyncio.subprocess.STDOUT,
    )
    client: SupervisorClient | None = None
    try:
        for _ in range(200):
            if sock.exists():
                break
            if proc.returncode is not None:
                raise AssertionError((d / "log").read_text(errors="replace"))
            await asyncio.sleep(0.05)
        else:
            raise AssertionError((d / "log").read_text(errors="replace") or "supervisor did not listen")
        client = SupervisorClient(str(sock))
        jobs = JobManager(client, deadline_slack_s=30)
        await jobs.start()
        auth = TokenAuth({TokenAuth.digest(TOKEN): Principal("agent-a", frozenset({"python-compute"}))})
        policy = Policy.from_dir(str(ROOT / "policy" / "profiles"))
        transport = httpx.ASGITransport(app=create_app(jobs, auth, policy))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as http:
            response = await http.post(
                "/v1/jobs",
                json={"profile": "python-compute", "argv": ["python3", "-c", "print(1)"]},
                headers={"Authorization": f"Bearer {TOKEN}"},
            )
            assert response.status_code == 202, response.text
            job_id = response.json()["job_id"]
            view: dict[str, object] = {}
            for _ in range(300):
                got = await http.get(f"/v1/jobs/{job_id}", headers={"Authorization": f"Bearer {TOKEN}"})
                view = got.json()
                if view.get("state") in ("exited", "rejected", "failed"):
                    break
                await asyncio.sleep(0.1)
            else:
                raise AssertionError(view)
        assert view["state"] == "exited", (view, (d / "log").read_text(errors="replace"))
        assert view["stdout"] == "1\n", view
        result = view["result"]
        assert isinstance(result, dict)
        assert result["insecure_dev_mode"] is True
    finally:
        pid_path = d / "s.pid"
        if pid_path.exists():
            try:
                os.kill(int(pid_path.read_text().strip()), signal.SIGTERM)
            except ProcessLookupError:
                pass
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
        log_f.close()
        if client is not None:
            await client.close()
        shutil.rmtree(d, ignore_errors=True)
