"""Starlette application: the agent-facing HTTP API (design §12.1)."""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from .auth import Principal, TokenAuth
from .jobs import Busy, Conflict, JobManager
from .schemas import JobRequest

MAX_BODY_BYTES = 128 * 1024

Handler = Callable[[Request, Principal], Awaitable[Response]]


def _problem(status: int, code: str, message: str, **extra: Any) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message, **extra}}, status_code=status)


def create_app(jobs: JobManager, auth: TokenAuth) -> Starlette:
    def authed(handler: Handler) -> Callable[[Request], Awaitable[Response]]:
        async def wrapper(request: Request) -> Response:
            principal = auth.authenticate(request.headers.get("authorization"))
            if principal is None:
                return _problem(401, "unauthenticated", "missing or invalid bearer token")
            return await handler(request, principal)

        return wrapper

    def job_id_of(request: Request) -> uuid.UUID | None:
        try:
            return uuid.UUID(request.path_params["job_id"])
        except ValueError:
            return None

    async def submit(request: Request, principal: Principal) -> Response:
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            return _problem(413, "request_too_large", f"body exceeds {MAX_BODY_BYTES} bytes")
        try:
            req = JobRequest.model_validate_json(body)
        except ValidationError as e:
            details = [{"field": ".".join(str(x) for x in err["loc"]), "message": err["msg"]} for err in e.errors()]
            return _problem(400, "invalid_request", "request failed validation", details=details)
        if req.profile not in principal.profiles:
            return _problem(
                403,
                "profile_not_allowed",
                f"profile {req.profile!r} is not allowed for this principal",
                field="profile",
                allowed=sorted(principal.profiles),
                hint="use GET /v1/profiles",
            )
        if not jobs.connected:
            return _problem(503, "supervisor_unavailable", "the sandbox supervisor is not connected", retryable=True)
        try:
            rec = await jobs.submit(principal.id, req)
        except Busy:
            return JSONResponse(
                {"error": {"code": "busy", "message": "admission queue is full", "retryable": True}},
                status_code=429,
                headers={"Retry-After": "2"},
            )
        except Conflict:
            return _problem(409, "idempotency_conflict", "job_id already used with a different request")
        return JSONResponse(rec.view().model_dump(mode="json"), status_code=202)

    async def get_job(request: Request, principal: Principal) -> Response:
        jid = job_id_of(request)
        rec = jobs.get(principal.id, jid) if jid else None
        if rec is None:
            return _problem(404, "not_found", "no such job")
        return JSONResponse(rec.view().model_dump(mode="json"))

    async def cancel(request: Request, principal: Principal) -> Response:
        jid = job_id_of(request)
        rec = await jobs.cancel(principal.id, jid) if jid else None
        if rec is None:
            return _problem(404, "not_found", "no such job")
        return JSONResponse(rec.view().model_dump(mode="json"), status_code=202)

    async def events(request: Request, principal: Principal) -> Response:
        jid = job_id_of(request)
        rec = jobs.get(principal.id, jid) if jid else None
        if rec is None:
            return _problem(404, "not_found", "no such job")

        async def stream() -> AsyncIterator[bytes]:
            async for ev in jobs.events(rec):
                yield f"event: {ev.kind}\ndata: {json.dumps(ev.data)}\n\n".encode()

        return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-store"})

    async def profiles(request: Request, principal: Principal) -> Response:
        offered = set(jobs.profiles)
        return JSONResponse({"profiles": sorted(principal.profiles & offered)})

    async def health(request: Request) -> Response:
        status = 200 if jobs.connected else 503
        return JSONResponse({"supervisor_connected": jobs.connected}, status_code=status)

    return Starlette(
        routes=[
            Route("/v1/jobs", authed(submit), methods=["POST"]),
            Route("/v1/jobs/{job_id}", authed(get_job), methods=["GET"]),
            Route("/v1/jobs/{job_id}/cancel", authed(cancel), methods=["POST"]),
            Route("/v1/jobs/{job_id}/events", authed(events), methods=["GET"]),
            Route("/v1/profiles", authed(profiles), methods=["GET"]),
            Route("/v1/health", health, methods=["GET"]),
        ]
    )
