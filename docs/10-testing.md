# 10 — Testing and security validation plan

Passing these tests does **not** prove there are no sandbox escapes. It shows that
each listed escape *class* is blocked on each tested kernel and configuration.

## Test tiers

| Tier | Runs on | Privileges | Contents |
|------|---------|------------|----------|
| T0 Unit | Any OS (incl. macOS) | none | `nsbx-proto`, `nsbx-policy` (validation, BPF snapshot), Python schemas, admission, JobManager with a fake supervisor |
| T1 Property / fuzz | Any Linux | none | `proptest`: policy narrowing never widens; path normaliser never yields an escaping path; frame codec round-trip. `cargo-fuzz`: frame decoder, JSON schemas, policy TOML parser. Hypothesis for Python schemas |
| T2 Rootless integration | Linux runner with unprivileged userns + a user systemd delegated cgroup | none (insecure-dev-mode) | Lifecycle, limits, cleanup, probes that do not depend on distinct UIDs |
| T3 VM integration | NixOS VM tests (`runNixOSTest`) under KVM | VM root, disposable | Full production configuration (idmap, system units), kernel matrix, disruptive tests, crash injection |
| T4 Nightly | Dedicated host | — | Long fuzz runs, benchmarks, soak (10k jobs) |

Ordinary hosted CI runners usually cannot do T3 (no nested KVM) and often not
T2 (no delegated cgroup, or userns restricted). See [11](11-benchmarks-observability.md#ci-strategy).

## Probe-based security regression suite

`nsbx-probe` runs **inside** the sandbox as the workload. The host-side test (a
Rust integration test in `tests/security/`) submits a job running one probe
subcommand with harness-chosen parameters and asserts on its single JSON
result line *and* on the job result (reason, exit status, cgroup stats). See
[content-safety.md](content-safety.md) for the naming and content rules.

| Test ID | Probe | Expected |
|---------|-------|----------|
| `isolation_fs_canary` | `fs-read --path <canary path chosen by harness in a host tmpdir>` and `fs-find --token <random>` walking `/` | `ENOENT`; token never in output |
| `isolation_fs_mountinfo_exact` | `mountinfo` | Exactly the expected mount set and flags ([05](05-filesystem-network.md)) |
| `isolation_fs_write_outside_ws` | `fs-write` on `/`, `/etc`, `/nix/store/...`, `/dev` | `EROFS`/`EACCES` |
| `isolation_fs_symlink_artefact` | Workload makes `out/x` a symlink to `/etc/passwd`; harness collects `out/x` | Artefact refused (`ELOOP`/`EXDEV`), job still `exited` |
| `isolation_env_empty` | `env-dump` | Exactly the allowlisted env; host env canary (set in the supervisor's environment by the harness) absent |
| `isolation_fd_census` | `fd-list` | Only 0,1,2 open |
| `isolation_proc_view` | `proc-list` | Only sandbox PIDs; `/proc/1` not readable (dumpable 0) |
| `isolation_net_none` | `tcp-connect --addr <harness listener on host loopback>`, `--addr` link-local and the metadata address | Connect fails (`ENETUNREACH`); harness listener sees no connection |
| `isolation_unix_abstract` | `unix-connect --abstract <name the harness listens on in host netns>` | `ECONNREFUSED`/`ENOENT` |
| `isolation_socket_families` | `socket --family netlink/packet/alg/vsock` | `EAFNOSUPPORT` |
| `isolation_syscall_matrix` | `syscall --name <each kill-listed syscall>` (generated per profile) | Job `reason: seccomp_kill` |
| `isolation_ns_create` | `ns-create --kind user/mount/net` via `unshare` and `clone` flags | kill / `EPERM`; `clone3` → `ENOSYS` |
| `isolation_caps` | `caps` | All five cap sets 0; securebits locked; `NoNewPrivs: 1`; `Seccomp: 2`; Landlock domain present (ABI ≥ 6 introspection when available, otherwise behavioural) |
| `isolation_signal_init` | `signal --pid 1 --sig TERM/KILL` | `EPERM`; init alive |
| `isolation_cgroup_escape` | `cgroup-self` (reads `/proc/self/cgroup`, tries to open cgroupfs paths, tries to mount cgroup2) | `/`; no cgroupfs; mount killed |
| `limits_memory` | `alloc --bytes <2× limit> --touch` | `reason: oom`, `oom_kills ≥ 1`, whole job dead |
| `limits_tmpfs` | `fill --path /workspace/f --bytes <2× size>` | `ENOSPC`, no OOM |
| `limits_pids` | `spawn --count <2× pids.max> --hold-ms 2000` | Successful spawns ≤ `pids.max`; `pids_limit_hits ≥ 1`; everything cleaned up |
| `limits_cpu_budget` | `spin --threads 4 --ms <budget × 3>` | `reason: cpu_budget` within the budget plus the polling interval |
| `limits_output` | `emit --bytes <10× cap>` | `output_truncated` or `output_limit` per policy; supervisor RSS bounded |
| `lifecycle_timeout_ignores_term` | `ignore-term --sleep-ms 600000` | `reason: wall_timeout` ≤ deadline + grace + ε |
| `lifecycle_descendants` | `spawn --count 20 --detach --daemonize` (double-fork, setsid) | After exit: cgroup removed, no host process with slot UID (`/proc` scan by harness) |
| `lifecycle_cancel_during_setup` | Fault injection: stage 2 sleeps at stage N (debug build hook) and harness cancels | Clean state; correct `stage` in the result |

## Reliability and fault-injection tests (T3)

- **Supervisor crash** during each lifecycle state (SIGKILL the supervisor at
  hook points): after the systemd restart there are no leftover processes,
  cgroups or slots, and the startup sweep is logged.
- **idmap unavailable / returns an error:** the job fails `setup_failed{stage:
  map}`; the cgroup is removed.
- **Partial setup failures:** inject `EPERM`/`ENOMEM` at each `nsbx-sys` call
  site through a test-only `FaultPlan` compiled under `cfg(feature =
  "fault-injection")`. Assert reverse cleanup.
- **Concurrency:** 200 concurrent create/cancel/exit cycles with random timing
  (seeded). Invariants: slot uniqueness, no double-free of a slot, every job
  reaches exactly one terminal state.
- **Malformed protocol:** fuzz corpus replay, oversize lengths, slow-loris,
  wrong peer UID, `SCM_RIGHTS` attached.
- **Kernel feature unavailability:** VM booted with `lsm=` lacking landlock →
  supervisor refuses to start; VM with kernel 6.1 → refuses (version check);
  VM with `user.max_user_namespaces=0` → refuses.

## Kernel-version compatibility

- Matrix: minimum (6.6 LTS), recommended (6.12 LTS), latest stable from the
  pinned nixpkgs. Implemented as `boot.kernelPackages` variants of the same VM
  test.
- A kernel enters the supported list only after the full T3 suite passes on it.
  A seccomp profile change must pass on every kernel in the matrix.
- Security advisories: track kernel CVEs in syscalls the profiles allow. Treat
  "a fix exists in a supported LTS" as a deployment-blocking upgrade for
  production hosts.

## Differential testing

Run the same probe set under `bubblewrap` and `nsjail` with comparable
configuration. A probe result that is *weaker* in `nsbx` than in either
reference is a finding to investigate.
