# 11 — Benchmarks, profiling, observability and CI

No performance numbers appear anywhere in this design. Every number comes from
the procedure below, run on recorded hardware.

## Benchmark plan

### Environment controls

- Bare-metal host (not a cloud VM with noisy neighbours) for headline numbers.
  Record CPU model, core count, SMT state, kernel version and config hash,
  nixpkgs revision, and the `nsbx` git revision in every result file.
- `cpupower frequency-set -g performance`; turbo on/off recorded; benchmark
  driver pinned to separate cores (`taskset`) from the sandbox `jobs/` cpuset.
- Page cache warm-up is a parameter: **cold** = `echo 3 > drop_caches` before
  each sample (VM/dedicated host only); **warm** = after a warm-up run.

### Methodology

- Driver: `nsbx-bench` talks to the supervisor protocol directly (to exclude
  Python), and a second mode goes through the HTTP API (to measure the
  orchestrator).
- Warm-up: 100 jobs discarded. Samples: ≥ 2 000 per scenario for p99 (fewer
  than ~1 000 samples make p99 unreliable). Repeat in 5 independent runs. Report
  the median of the per-run percentiles and the run spread.
- Report p50, p95, p99, max, with an HDR histogram per scenario, saved as JSON
  in `out/bench/<timestamp>/`.
- A change counts as a regression only if it is outside the run-to-run spread on
  ≥ 3 of 5 runs.

### Scenarios

| ID | Scenario | Measured |
|----|----------|----------|
| B1 | `true` in `cli` runtime | End-to-end startup + teardown; per-stage `timings_us` |
| B2 | Same with `--no-landlock --no-seccomp` (bench-only feature, never in release) | Restriction setup overhead (B1 − B2) |
| B3 | Closure size sweep: runtimes with 10, 50, 200, 800 store paths | Mount setup cost vs path count (informs decision D1) |
| B4 | `python3 -c pass` | Realistic interpreter startup inside the sandbox vs on the bare host |
| B5 | `node -e 0` | Same |
| B6 | Syscall-heavy loop (`getppid` × 10⁷) with and without seccomp | Per-syscall filter overhead |
| B7 | Concurrency sweep 1, 2, 4, …, 2× cores | Throughput (jobs/s), latency percentiles, supervisor CPU |
| B8 | Output 100 MiB to stdout, credit window sweep | Streaming throughput and supervisor CPU per MiB |
| B9 | Teardown: normal exit; timeout with `ignore-term`; cancel with 1 000 live tasks | Cleanup latency until `rmdir` |
| B10 | Memory overhead: 50 idle sandboxes (`sleep`) | Host `MemAvailable` delta / 50; per-job `memory.current`; supervisor RSS |

### Tools

| Question | Tool |
|----------|------|
| Where does setup time go? | `timings_us` from stage 2 (monotonic timestamps at each step); `strace -f -tt -T -e trace=%process,%file,mount,pivot_root,clone3` on the supervisor in the dev VM |
| Kernel-side cost of mounts/clone | `perf record -g -a` during B3; `perf trace -s` |
| Context switches, CPU use | `perf stat -e context-switches,cpu-migrations,task-clock -G <job cgroup>` (cgroup mode); cgroup `cpu.stat` |
| Process creation/exit latency | `bpftrace` on `tracepoint:sched:sched_process_fork/exec/exit`, filtered with `cgroup == cgroupid("/sys/fs/cgroup/…/jobs/job-X")` |
| Syscall distribution of a workload | `bpftrace` `tracepoint:raw_syscalls:sys_enter` counted by cgroup id |
| Python orchestrator hot spots | `py-spy record` on the orchestrator; `asyncio` debug mode for slow callbacks |
| Memory | `memory.stat`, `memory.peak`, `/proc/<sup>/smaps_rollup` |

## Observability

### Structured events (JSON lines via `tracing`)

| Event | Fields |
|-------|--------|
| `sandbox.admitted` | job_id, profile@hash, runtime path, principal (from the orchestrator, informational), slot |
| `sandbox.stage` | job_id, stage, duration_us, ok/errno |
| `sandbox.started` | job_id, setup_us |
| `sandbox.limit` | job_id, kind (`oom`, `pids`, `cpu_budget`, `wall`, `output`, `tmpfs_enospc`¹), value |
| `sandbox.exited` | job_id, reason, exit_code/signal, usage summary |
| `sandbox.cleanup` | job_id, duration_us, result (`ok`/`stuck`), retry count |
| `supervisor.features` | HostFeatures at startup |
| `protocol.reject` | peer uid/pid, category, code (no payload bytes) |

¹ Not directly observable from the host. It is inferred only if the probe or the
workload reports it, so it is marked as best-effort.

### Metrics (OpenMetrics text on a local Unix socket, optional)

Counters: jobs by reason, setup failures by stage, cleanup failures, protocol
rejects. Histograms: setup_us, teardown_us, wall_ms. Gauges: running jobs,
quarantined slots, supervisor RSS.

### Denied syscalls

`ERRNO` returns are invisible to the host by design (no audit cost). Three
mechanisms, none of which gives the workload anything:

1. `KILL_PROCESS` → visible as `SIGSYS` in the job result (`reason: seccomp_kill`).
   The syscall number is available to the host through the kernel audit record
   if auditing is on. In production we record only the reason.
2. Dev/test **log-mode** profile variant (`SECCOMP_RET_LOG` for unlisted
   syscalls). Records appear in the kernel log/audit (`type=SECCOMP`) and are
   collected in VM tests only.
3. Host-side `bpftrace` on `raw_syscalls:sys_exit` with `ret == -ENOSYS`
   filtered by cgroup id, during development.

### Diagnostics without privileging the workload

All tracing runs **from the host**, as root, in dev VMs, targeting the job
cgroup or PIDs. Nothing is added to the sandbox: no `ptrace` allowance, no
`perf_event_open`, no debugfs or tracefs mounts. Stage 2 has a debug hook to
pause before `execve`, for attaching `strace -p` from the host. It is compiled
only with the `debug-hooks` feature and is refused by release supervisors.

### Logging policy

Workload stdout/stderr, file contents, `argv` and `env` values are **not**
logged by default. Events carry lengths and SHA-256 digests. A per-profile
`log_workload_output: true` (off by default, requires an admin policy change)
exists for debugging.

## CI strategy

| Stage | Runner | Contents |
|-------|--------|----------|
| `check` | Any (Linux or macOS) with Nix | `nix flake check --no-build` evaluation, `cargo fmt --check`, `clippy -D warnings`, T0 tests, `mypy --strict`, `ruff`, `cargo deny check`, `cargo audit`, Python dependency audit (`pip-audit` on the locked set) |
| `build` | Linux x86_64 with Nix | Build all packages and runtimes; `nix build --rebuild` reproducibility check for runtimes and `nsbx-stage2` |
| `fuzz-smoke` | Linux | 5 minutes per fuzz target on every MR; corpus in repo |
| `integration-rootless` | **Self-hosted** Linux runner with unprivileged userns and a user-delegated cgroup (systemd user session `Delegate=yes`) | T2 |
| `integration-vm` | **Self-hosted** Linux with `/dev/kvm` | T3: kernel matrix, crash injection, feature-absence VMs |
| `nightly` | Dedicated bare-metal | Long fuzz, soak, benchmarks (artefacts only, no gating on absolute numbers; regressions are flagged) |

Hosted shared runners are assumed to be unable to run `integration-*`. Those
jobs are tagged so that they never silently skip on the wrong runner: a missing
capability is a **failure** of the job, not a skip.
