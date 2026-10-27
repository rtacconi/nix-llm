# 08 — Protocol schemas and API

## Agent-facing HTTP API (orchestrator)

Base path `/v1`. JSON bodies. Bearer-token auth (tokens are configured per
agent; they map to a principal and a set of allowed profiles).

| Method & path | Purpose | Success | Errors |
|---------------|---------|---------|--------|
| `POST /v1/jobs` | Submit a job | `202 {job_id, state}` | `400` schema, `403` profile not allowed, `409` idempotency conflict, `413` too large, `429` queue full (`Retry-After`) |
| `GET /v1/jobs/{id}` | State and result | `200 JobView` | `404` |
| `GET /v1/jobs/{id}/events` | SSE stream: `stdout`, `stderr`, `state`, `exit` | `200 text/event-stream` | `404`; `410` if the result has expired |
| `POST /v1/jobs/{id}/cancel` | Cancel (idempotent) | `202` | `404` |
| `POST /v1/run` | Submit and stream in one call (convenience for agents) | SSE as above | as `POST /v1/jobs` |
| `GET /v1/profiles` | Profiles this principal may use, with limits | `200` | — |
| `GET /v1/health` | Liveness, plus supervisor `HostFeatures` | `200`/`503` | — |

### `JobRequest` (pydantic, `extra="forbid"`)

```json
{
  "job_id": "0b7d5c7e-6a9f-4d3e-9a51-2f3c8b1e9d10",
  "profile": "python",
  "argv": ["python3", "main.py"],
  "files": [
    {"path": "main.py", "content_b64": "cHJpbnQoImhlbGxvIikK", "mode": "0644"}
  ],
  "stdin_b64": null,
  "env": {"PYTHONUNBUFFERED": "1"},
  "limits": {"wall_ms": 30000, "cpu_ms": 20000, "memory_bytes": 268435456,
             "pids": 64, "output_bytes": 262144},
  "collect": ["out/result.json"],
  "grace_ms": 1000
}
```

Rules: `job_id` is optional (the server generates one) and is the idempotency key
together with a SHA-256 of the canonicalised request. `argv[0]` must resolve
inside the runtime's `PATH` view; absolute paths outside the closure are
rejected. `env` keys must match `^[A-Z_][A-Z0-9_]{0,63}$` and must not be in the
deny list (`LD_*`, `PYTHONSTARTUP`, `NODE_OPTIONS`, …, which are profile-
controlled). Limits may only be **≤** the profile's. Total decoded `files` ≤
profile `input_bytes_max`. (The base64 sample above is the source text
`print("hello")`.)

### `JobView`

```json
{
  "job_id": "0b7d5c7e-…",
  "state": "exited",
  "runtime": {"name": "python", "store_path": "/nix/store/…-nsbx-runtime-python",
              "closure_hash": "sha256-…"},
  "profile": {"name": "python", "version": "1.2.0", "hash": "sha256-…"},
  "result": {
    "reason": "exited",
    "exit_code": 0, "signal": null,
    "wall_ms": 412, "cpu_user_us": 180000, "cpu_sys_us": 41000,
    "memory_peak_bytes": 23592960, "oom_kills": 0, "pids_limit_hits": 0,
    "stdout_bytes": 6, "stderr_bytes": 0, "output_truncated": false,
    "artifacts": [{"path": "out/result.json", "size": 120, "sha256": "…"}],
    "cleanup": "ok",
    "timings_us": {"admit": 90, "cgroup": 240, "spawn": 610, "map": 380,
                   "mounts": 2900, "restrict": 150, "exec_to_exit": 405000,
                   "teardown": 1800}
  },
  "insecure_dev_mode": false
}
```

`reason` ∈ `exited | signaled | wall_timeout | cpu_budget | oom | output_limit |
seccomp_kill | cancelled | setup_failed | supervisor_shutdown |
supervisor_unavailable`. The `timings_us` values above are a **schema example,
not measurements**.

## Supervisor protocol (`nsbx/1`)

### Transport

- `SOCK_STREAM` Unix socket `/run/nixsandbox/supervisor.sock`, mode `0660`,
  group `nsbx-clients`, created by systemd socket activation (so the
  supervisor never runs `chmod` on a path).
- On accept: `getsockopt(SO_PEERCRED)`. The UID must equal the configured
  orchestrator UID, otherwise the connection is closed with no response. The
  PID is logged only (it is not used for authorisation).
- The supervisor reads with `read(2)`, never `recvmsg` with a control buffer, so
  `SCM_RIGHTS` fds sent by a client are never installed in the supervisor.
- At most `max_connections` (default 4).

### Framing

```text
+---------+--------+-------------------+
| len u32 | type u8| payload (len-1 B) |
+---------+--------+-------------------+
 big-endian; len ≤ 65 536 for control frames, ≤ 65 536 for data frames
```

| Type | Name | Direction | Payload |
|------|------|-----------|---------|
| 0x01 | `Hello` | C→S | JSON `{"proto":[1], "client":"nsbx-orchestrator/0.1"}` |
| 0x02 | `HelloAck` | S→C | JSON `{"proto":1, "supervisor":"0.1.0", "features":{…HostFeatures}, "profiles":[…]}` |
| 0x10 | `Submit` | C→S | JSON `SubmitV1` (validated spec, files as base64 in v1; see D9) |
| 0x11 | `Accepted` | S→C | JSON `{"job_id", "slot"}` |
| 0x12 | `Rejected` | S→C | JSON `{"job_id", "error": ErrorV1}` |
| 0x13 | `Started` | S→C | JSON `{"job_id", "setup_us"}` |
| 0x20 | `Output` | S→C | binary: `job_id[16] stream u8 seq u64 bytes…` |
| 0x21 | `Credit` | C→S | binary: `job_id[16] bytes u32` |
| 0x30 | `Cancel` | C→S | JSON `{"job_id", "grace_ms"}` |
| 0x31 | `Exited` | S→C | JSON `ResultV1` (as `result` above) |
| 0x32 | `Artifact` | S→C | binary: `job_id[16] idx u16 offset u64 bytes…` (counts against `artefact_bytes_max`) |
| 0x40 | `Ping`/`Pong` | both | 8-byte nonce |
| 0x7F | `Error` | S→C | JSON `ErrorV1` (connection-level; the connection is closed afterwards) |

`ErrorV1 = {"category", "code", "message", "retryable"}` where category ∈
`protocol | policy | admission | resource | setup | internal`.

### Rules and safety properties

- **Version negotiation:** the first frame must be `Hello`. Its `proto` list is
  intersected with the supported versions. An empty intersection → `Error` +
  close. A new major version means a new socket path, so old clients fail fast.
- **Unknown frame type, oversize `len`, invalid UTF-8/JSON, unknown JSON
  fields** → `Error{protocol}` and close the connection. Jobs owned by that
  connection are cancelled (fail closed).
- **Idempotency:** `Submit` with a known `job_id` and the same request hash
  returns the current state (`Accepted`/`Exited`). With a different hash it
  returns `Rejected{policy, idempotency_conflict}`. Results are kept for
  `result_ttl` (default 10 min) in a bounded LRU.
- **Ownership:** a job is owned by its submitting connection. `Cancel` from
  another connection is allowed (same UID) so the orchestrator can reconnect
  and clean up.
- **Credits:** initial credit per job is `inflight_bytes_max`. The supervisor
  never sends `Output` beyond credit.
- **Bounded parsing:** the frame header is read first, `len` is checked, then
  exactly `len` bytes are read into a pre-sized buffer. A per-connection read
  deadline (5 s for a frame body) stops slow-loris clients from pinning memory.
- Fuzzed with `cargo-fuzz` (decoder and JSON schema), see [10](10-testing.md).

### What is async and what is not

| Layer | Async | Blocking / synchronous |
|-------|-------|------------------------|
| Orchestrator | everything (asyncio) | none: pydantic validation is CPU-bound but bounded by size |
| Supervisor I/O | socket, pipes, timers, inotify, pidfd readiness (`AsyncFd` on the pidfd, which becomes readable on exit) | cgroup file writes (small, run inline), `clone3` (run on a dedicated blocking thread: `spawn_blocking`) |
| idmap | — | single-threaded blocking loop |
| Stage 2 / init | — | single-threaded, blocking syscalls only |
