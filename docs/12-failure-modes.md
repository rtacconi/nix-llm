# 12 — Failure-mode analysis

Every lifecycle state has exactly one owner and one undo action. Undo runs in
reverse order. A failure during undo is recorded and moves the slot to
quarantine, but never stops the remaining undo steps.

| # | Stage | Failure | Detection | Handling | Result reason |
|---|-------|---------|-----------|----------|---------------|
| F1 | Admission | Schema/policy violation | Validator | `Rejected{policy}`; nothing allocated | — |
| F2 | Admission | No slot / `max_jobs` reached | Slot bitmap | `Rejected{admission, busy, retryable}` | — |
| F3 | Cgroup | `mkdir` fails (`ENOSPC` from `cgroup.max.descendants`, `EACCES` from lost delegation) | errno | Release the slot; `setup_failed{cgroup}`; if `EACCES`, supervisor health → degraded, stop admitting | `setup_failed` |
| F4 | Cgroup | Limit write fails | errno | `rmdir`; release | `setup_failed` |
| F5 | Spawn | `clone3` fails (`EPERM` userns blocked, `ENOSPC` ns limits, `EAGAIN` pids) | errno | `rmdir`; release | `setup_failed{spawn}` |
| F6 | Spawn | `execveat(stage2)` fails in child | child `_exit(127)` seen via pidfd before sync | Reap; `rmdir` | `setup_failed{exec_stage2}` |
| F7 | Map | idmap error / timeout (2 s) | reply / timer | `cgroup.kill`; reap; `rmdir` | `setup_failed{map}` |
| F8 | Setup | Any stage-2 step fails | `SetupFailed{stage, errno}` on the status fd **or** status fd EOF without a record | Stage 2 has already `_exit`ed. Reap; `cgroup.kill` (defensive); `rmdir` | `setup_failed{stage}` |
| F9 | Setup | Stage 2 hangs | Setup deadline (policy, default 5 s) | `cgroup.kill` → as F8 | `setup_failed{timeout}` |
| F10 | Run | Workload exits | init reports | Normal teardown | `exited`/`signaled` |
| F11 | Run | OOM | `memory.events` `oom_kill` delta > 0 (read at exit; inotify on `memory.events` for early notice) | oom.group already killed everything; teardown | `oom` |
| F12 | Run | Wall deadline | timer | Escalation (SIGTERM → grace → `cgroup.kill`) | `wall_timeout` |
| F13 | Run | CPU budget | poll | `cgroup.kill` | `cpu_budget` |
| F14 | Run | Output cap (kill policy) | byte counter | `cgroup.kill` | `output_limit` |
| F15 | Run | Seccomp kill of the main workload process | `waitid` shows `SIGSYS` | Teardown | `seccomp_kill` |
| F16 | Run | Init dies unexpectedly (should not happen: it is protected by UID, seccomp, dumpable) | pidfd readable before the status record | PID namespace teardown kills the rest; `cgroup.kill`; flag `init_crash` in the event (investigate as a possible security incident) | `setup_failed{init}` or `signaled` |
| F17 | Run | Status record malformed or oversized | Bounded parser | Treat as F16; never trust its fields | as F16 |
| F18 | Teardown | `populated` never reaches 0 (D-state task) | cleanup timeout | Report `cleanup: stuck`; quarantine slot; background retry with backoff; metric and alert | original reason + `cleanup: stuck` |
| F19 | Teardown | `rmdir` `EBUSY` | errno | as F18 | — |
| F20 | Control | Orchestrator disconnects | read EOF / error | Cancel the connection's jobs (fail closed); results kept for `result_ttl` for a reconnecting client | `cancelled` |
| F21 | Control | Orchestrator sends garbage | codec | `Error` + close → F20 | `cancelled` |
| F22 | Supervisor | Panic in a job task | `JoinError` | `panic = "abort"` in release: the whole supervisor dies and systemd kills all jobs (F23). Rationale: the state after a panic cannot be trusted | `supervisor_unavailable` |
| F23 | Supervisor | Crash / OOM-kill / restart | systemd | `KillMode=control-group` kills everything. On start: sweep `jobs/*` (`cgroup.kill`, wait, `rmdir`), reset slots, log `supervisor.recovered` with counts | `supervisor_unavailable` |
| F24 | Host | Kernel lacks a feature after an upgrade or downgrade | startup detection | Refuse to start (required) or disable profiles (optional) | — |
| F25 | Host | Supervisor cgroup itself near memory limit | `memory.events` of `supervisor/` | Stop admitting (`Busy`) before the kernel OOM-kills the supervisor | — |
| F26 | idmap | Helper crashes | socket EOF | systemd restarts it; in-flight maps fail as F7 | `setup_failed{map}` |
| F27 | Orchestrator | Crash | systemd restart; supervisor sees EOF | F20 for its jobs; agents get connection errors and retry with the same `job_id` (idempotency) | `cancelled` |

## Invariants checked in tests

1. Every admitted job reaches exactly one terminal reason.
2. After a terminal reason (except `cleanup: stuck`): no cgroup, no process with
   the slot's UIDs, slot free.
3. No path where the workload `execve` runs without every restriction applied
   (stage 2 is linear code with `?` on every step and no fallback branches; a
   lint test greps for `unwrap_or`/`ok()` patterns in stage 2 restriction code).
4. Supervisor RSS ≤ configured bound under any client behaviour.
