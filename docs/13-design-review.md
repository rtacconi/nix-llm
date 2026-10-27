# 13 — Design review (Phase 2): sceptical pass, residual risks, future hardening

Method: review the Phase 1 draft as an adversarial Linux security engineer. Look
for privilege-escalation paths, filesystem leaks, resource-control races,
inherited fds, cleanup gaps and excess TCB. Each finding records the change it
forced into the design (or why it was accepted).

## Findings

| # | Challenge | Finding | Resolution |
|---|-----------|---------|------------|
| R1 | "Fork from the Tokio supervisor and set up the namespaces in the child." | Unsafe: it is a multi-threaded process; allocator and logging locks can deadlock in the child, and any `Drop` can run there. | **Changed:** clone3 → immediate `execveat` of single-threaded static `nsbx-stage2` ([04](04-privilege-model.md#why-stage2-is-a-separate-exec)). |
| R2 | "Write the child PID to `cgroup.procs` after fork." | Window in which the child runs unlimited; PID-reuse race. | **Changed:** `CLONE_INTO_CGROUP`, with limits written before `clone3`. |
| R3 | "Fully rootless: map ns 0 → supervisor UID." | All sandboxes and the supervisor share one host UID. An escape from the mount namespace lets one job read another's workspace through `/proc/<pid>/root` and connect to the supervisor socket. | **Changed:** per-slot UID ranges via `nsbx-idmap` (2 caps). Rootless is dev-only and labelled in every result. |
| R4 | "Workload as ns-UID 0, caps dropped." | Same UID as init: it can signal or `ptrace` init (if `ptrace` is ever allowed) and open `/proc/1/*`. Root-owned files in the view are writable if DAC is the only check. | **Changed:** workload is ns-UID 1000 (a distinct host UID); init is non-dumpable. |
| R5 | "Seccomp blocks `unshare`, so nested user namespaces are impossible." | `clone` with `CLONE_NEWUSER` is a second path; `clone3` cannot be argument-filtered. | **Changed:** argument-filter `clone`, `clone3 → ENOSYS`, `unshare` killed, plus `max_user_namespaces=0` inside (experiment E3 must confirm). |
| R6 | "The supervisor reads artefacts through `/proc/<pid>/root/workspace/...`." | Magic-link traversal into an attacker-controlled tree from a host-privileged process; symlink and rename races while the workload is alive. | **Changed:** init collects artefacts after **all** workload processes are dead, using `openat2` `RESOLVE_*`, and streams them through a bounded channel. |
| R7 | "Bind the whole `/nix/store` and let Landlock limit it." | Makes Landlock the primary boundary. Landlock does not cover `stat` or path walk, and its coverage depends on the ABI. | **Changed:** per-path binds are primary; Landlock is depth. Cost measured in B3; decision D1. |
| R8 | "Output pump reads as fast as possible into a `Vec`." | A slow orchestrator → unbounded supervisor memory → the supervisor gets OOM-killed → every job dies (a DoS amplifier). | **Changed:** credit-based flow control; workload blocks on a full pipe; deadlines keep running. |
| R9 | "SIGKILL the workload PID at the deadline." | Misses double-forked and daemonised descendants; PID reuse. | **Changed:** `cgroup.kill` + PID-namespace init semantics + pidfds. |
| R10 | "Use `memory.max` only." | tmpfs fill charges memcg → OOM looks like a memory bug; swap lets jobs dodge the limit. | **Changed:** `swap.max=0`, tmpfs sizes below `memory.max`, `oom.group=1`. |
| R11 | "`/proc` mounted normally." | `/proc/cpuinfo` and similar are harmless, but `/proc/sys`, `kallsyms`, `sched_debug`, `timer_list` and `keys` reveal host information; `/proc/self/mountinfo` reveals the layout. | **Changed:** `subset=pid,hidepid=invisible` by default; masked full-proc mode per profile. |
| R12 | "The supervisor accepts any local connection on its socket." | A4 (local user) could submit jobs. | **Changed:** socket mode 0660 + group + `SO_PEERCRED` UID check. |
| R13 | "Return `EPERM` for every denied syscall." | Breaks runtimes with fallbacks (they expect `ENOSYS`) and hides real attacks. | **Changed:** default `ENOSYS`, explicit kill list. |
| R14 | "Node: kill on io_uring." | libuv probes io_uring at startup, so every Node job would die. | **Changed:** profile-specific `ENOSYS` for io_uring in `node`; io_uring stays blocked. |
| R15 | "Init keeps full userns caps for its whole life." | If the workload compromises init (via signals or `/proc`), it gets userns caps and can then reach `ns_capable` kernel paths. | **Mitigated:** UID separation, dumpable 0, init seccomp profile, Landlock v6 signal scoping. **Open (D5):** drop init to an unprivileged ns UID that keeps `CAP_KILL` only. |
| R16 | "The idmap helper writes maps by PID." | PID reuse could map a different process. | **Changed:** pidfd + `/proc/<pid>` dirfd + parent/cgroup checks + liveness re-check. |
| R17 | "Python orchestrator validates requests; the supervisor trusts them." | A3 (compromised orchestrator). | **Changed:** the supervisor re-validates everything against admin policy; requests can only narrow limits. |
| R18 | Excess TCB? | Supervisor ~5–8 k LOC estimated, plus Tokio, serde, seccompiler, landlock. | **Accepted with controls:** `unsafe` confined to `nsbx-sys`; the supervisor runs without caps under its own seccomp (M7); `cargo vet`/`deny`. Privileged TCB = idmap only. |
| R19 | Stage 2 deserialises the spec with serde in the sandbox's setup context. | A malicious spec could target the parser in a process with userns caps. | **Accepted:** the spec comes from the supervisor (trusted), is sealed in a memfd, has a size cap, and is a fixed schema. Not attacker-reachable unless the supervisor is already compromised. |
| R20 | Hidden host access via inherited mount namespace: systemd `ProtectSystem` etc. | Sandboxes are created from the supervisor's mount namespace. After `pivot_root` + detach none of it remains, but a bug there would expose the supervisor's view rather than the host's (an improvement). | Accepted; `mountinfo` exact-set test. |
| R21 | Time and side channels | Not addressed by namespaces. | **Accepted residual** → microVM for high assurance. |

## Residual risks (after the changes above)

1. **Kernel attack surface** of the allowed syscalls (hundreds), tmpfs,
   procfs, the mount and namespace code reachable by stage 2 with userns caps,
   and the memory manager. This is the dominant risk. Mitigations: seccomp
   minimisation, prompt patching, the microVM backend for higher-risk use.
2. **Unprivileged user namespaces enabled host-wide** for the service user. This
   increases kernel exposure for *any* compromise of that user. On distros that
   gate userns per program (Ubuntu AppArmor), scope the permission to the
   supervisor binary only.
3. **Supervisor parsing of sandbox-originated data** (status records, artefact
   frames). Mitigated by fixed-size records and bounded framing, and fuzzed.
   **v2:** moved out of the supervisor into per-job, seccomp-confined wardens
   ([16 N1](16-design-improvements.md#n1-per-job-warden-processes-privilege-separation-inside-the-supervisor)),
   with Kani-proved decoders (N8).
4. **Resource accounting gaps:** some kernel allocations are not charged to the
   job memcg, and there is cache and memory-bandwidth contention. Host-level
   `jobs/` caps limit the blast radius.
5. **memfd/JIT exec** paths bypass Landlock `EXECUTE` (Landlock governs
   filesystem exec, not anonymous memory).
6. **Supply chain:** nixpkgs runtimes run inside the sandbox (lower impact). The
   Rust and Python dependencies of the supervisor and orchestrator are trusted
   (higher impact). Mitigated by pinning, review and audit tooling, not
   eliminated.
7. **Policy mistakes** by administrators (e.g. binding a host socket into a
   profile). Mitigation: the policy validator denies binds outside
   `/nix/store` unless an explicit `unsafe_bind` with a written reason is set,
   and that flag is surfaced in every job result.

## Future hardening

- Supervisor seccomp profile and Landlock domain for the supervisor itself (M7).
- Drop init to minimal caps (D5).
- Landlock ABI 6+ required once 6.12 is the minimum.
- `SECCOMP_RET_USER_NOTIF` broker for selected path-based decisions (would need
  libseccomp-level tooling and a careful TOCTOU analysis; low priority).
- MicroVM backend with snapshot/restore for latency.
- Per-job `cpuset` + SMT-sibling isolation for side-channel-sensitive profiles.
- Signed policy bundles (minisign) checked by the supervisor at load.
