# 07 — Resource management and cancellation

## cgroup layout

cgroup v2 has a **no-internal-processes rule**: a non-root cgroup that enables
controllers for its children in `cgroup.subtree_control` cannot itself contain
processes. So the supervisor rearranges its delegated subtree at startup:

```text
/sys/fs/cgroup/system.slice/nsbx.service/      (Delegate=yes, owned by nsbx)
├── supervisor/        ← supervisor moves itself here first
├── idmap/             ← systemd places the helper here (separate unit) or not at all
└── jobs/              ← subtree_control: +memory +pids +cpu (+io optional)
    ├── job-<uuid>/    ← one per job; limits written before clone3
    └── …
```

`jobs/` itself gets aggregate caps (`memory.max`, `pids.max`, `cpu.max`) equal
to the host budget for all sandboxes. A burst of jobs therefore cannot exceed the
host budget even if admission control has a bug.

## Per-job limits

| Resource | Mechanism | Default (`python` profile, illustrative, set in policy) | Exceeded → |
|----------|-----------|---------------------------------------------------------|------------|
| Memory | `memory.max`; `memory.high` = 90 % of max (reclaim pressure first); `memory.swap.max = 0`; `memory.oom.group = 1` | 512 MiB | Kernel OOM-kills the **whole job** (oom.group). The supervisor sees the `oom_kill` count rise in `memory.events` → `reason: oom` |
| CPU bandwidth | `cpu.max = "<quota> <period>"` | 1 CPU (`100000 100000`) | Throttled (`cpu.stat nr_throttled`) |
| CPU time budget | Supervisor polls `cpu.stat usage_usec` every 100 ms (and at exit) | 30 s | `cgroup.kill` → `reason: cpu_budget` |
| Wall clock | Supervisor deadline (Tokio timer, monotonic) | 60 s | Grace SIGTERM → `cgroup.kill` → `reason: wall_timeout` |
| Tasks | `pids.max` | 128 | `fork`/`clone` fail with `EAGAIN`; the supervisor reports `pids_limit_hits` from `pids.events max` (not fatal) |
| Writable storage | tmpfs `size=`/`nr_inodes=` | ws 256 MiB, tmp 64 MiB, shm 64 MiB | `ENOSPC` in the workload |
| Single file size | `RLIMIT_FSIZE` | = workspace size | `SIGXFSZ` / `EFBIG` |
| Open files | `RLIMIT_NOFILE` | 1024 | `EMFILE` |
| Core dumps | `RLIMIT_CORE = 0` | — | — |
| Locked memory | `RLIMIT_MEMLOCK = 0` | — | — |
| Output | Per-stream and combined byte caps in the supervisor | 1 MiB combined | Policy: `truncate` (keep draining, drop bytes, flag `truncated`) or `kill` → `reason: output_limit` |
| Stdin | Bounded request bytes written once, then EOF | 1 MiB | Rejected at admission |

The policy validator rejects profiles where the sum of tmpfs sizes is not well
below `memory.max`, or where the timers are inconsistent (`cpu_budget >
wall × cpu.max quota`).

## Output capture and backpressure

- stdout and stderr are separate `pipe2(O_CLOEXEC)` pairs. The read ends stay
  in the supervisor and are set non-blocking (Tokio `AsyncFd`). The pipe size
  is set with `F_SETPIPE_SZ` (64 KiB default, bounded by
  `/proc/sys/fs/pipe-max-size`).
- The supervisor forwards chunks to the orchestrator only while it holds
  **credits** for that job. Each job has at most `inflight_bytes_max` (256 KiB)
  of unacknowledged output.
- When credits run out, the supervisor stops reading the pipe. The pipe fills
  and the workload blocks in `write(2)`. **Deadlines keep running**, so a
  stalled consumer turns into a timeout, not into unbounded supervisor memory.
- Supervisor memory per job is bounded by `inflight + one read buffer`. Total
  supervisor memory is bounded by `max_jobs × that`, which is checked at startup.

## Deadlines and termination

Order of escalation (all steps are idempotent):

1. **Soft:** `pidfd_send_signal(init, SIGTERM)`. Init forwards it with
   `kill(-1, SIGTERM)` to every process in the PID namespace.
2. **Grace period:** `min(request.grace_ms, policy.grace_max_ms)`, default 2 s.
3. **Hard:** `write("1", cgroup.kill)`. The kernel sends SIGKILL to every task in
   the subtree and handles concurrent forks correctly.
4. **Reap:** `waitid(P_PIDFD, init_pidfd, WEXITED)` (the supervisor is init's
   parent).
5. **Drain:** wait for `cgroup.events` to report `populated 0`, using inotify
   on the file, bounded by `cleanup_timeout` (default 10 s).
6. **Account:** read `memory.events`, `memory.peak`, `pids.events`, `cpu.stat`.
7. **Remove:** `rmdir` the job cgroup.

If step 5 or 7 times out (for example a task in uninterruptible sleep on a hung
FUSE or NFS mount, which is not possible in our view but defended against
anyway), the job is reported with `cleanup: stuck`. Its slot is
**quarantined**, so its UID range is not reused until the cgroup is gone, and a
background task retries with backoff and emits `cleanup_failed` events.

## Cancellation propagation

```text
HTTP client disconnect / POST /cancel
  → orchestrator: task.cancel() on the job's stream task; JobManager.cancel(job_id)
  → protocol: Cancel{job_id, grace_ms}       (idempotent; unknown job → NotFound)
  → supervisor: job state machine → Terminating, escalation as above
  → kernel: SIGTERM (via init) → cgroup.kill
  → supervisor: Exited{reason: cancelled}
  → orchestrator: final state stored; SSE stream closed with `event: exit`
```

| Event | Behaviour |
|-------|-----------|
| Cancel before `Started` | The supervisor aborts at the next stage boundary and runs the reverse cleanup; reason `cancelled` with `stage` |
| Cancel during setup | Stage 2 is in the job cgroup, so `cgroup.kill` stops it at whatever step it is on. The supervisor then runs the remaining cleanup (rmdir, slot release) |
| Duplicate cancel | No-op, same final result |
| Orchestrator connection lost | All jobs **owned by that connection** are cancelled after `reconnect_grace` (default 0 s, meaning immediately). Rationale: fail closed; nobody would collect their output. A later decision (D8) may allow detached jobs. |
| Supervisor crash | systemd `KillMode=control-group` kills every job, because all jobs are under the service cgroup. On restart the supervisor sweeps `jobs/*` with `cgroup.kill`, waits, and runs `rmdir`. Orchestrator jobs in flight fail with `supervisor_unavailable` |
| Orchestrator SIGTERM | Stops admitting, cancels running jobs with `grace_ms`, waits up to its shutdown timeout |

## Concurrency

- The supervisor admits at most `max_jobs` (from policy, derived from the host
  budget) and returns `Busy` beyond that. The orchestrator's own queue sits in
  front of it.
- Slot allocation is a fixed-size bitmap. The slot determines the UID range. A
  slot is released only after `rmdir` succeeds.
- Setup is parallel across jobs. Per job, the steps are strictly sequential.
