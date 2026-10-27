"""Run the orchestrator: ``python -m nsbx_orchestrator CONFIG.json``.

Config keys: ``supervisor_socket``, ``listen_host``, ``listen_port`` and
``principals`` (a list of ``{"token_sha256", "id", "profiles"}``).
"""

from __future__ import annotations

import json
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from starlette.applications import Starlette

from .app import create_app
from .auth import Principal, TokenAuth
from .jobs import JobManager
from .supervisor import SupervisorClient


def main() -> None:
    with open(sys.argv[1]) as f:
        cfg = json.load(f)
    auth = TokenAuth({p["token_sha256"]: Principal(p["id"], frozenset(p["profiles"])) for p in cfg["principals"]})
    client = SupervisorClient(cfg["supervisor_socket"])
    jobs = JobManager(client)
    app = create_app(jobs, auth)

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        await jobs.start()
        yield
        await client.close()

    app.router.lifespan_context = lifespan
    uvicorn.run(app, host=cfg.get("listen_host", "127.0.0.1"), port=int(cfg.get("listen_port", 8700)))


if __name__ == "__main__":
    main()
