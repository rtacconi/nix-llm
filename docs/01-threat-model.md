# 01 — Threat model and security assumptions

## Assets

| Asset | Where it lives | Why it matters |
|-------|----------------|----------------|
| Host filesystem (home dirs, config, credentials) | Host mount namespace | Confidentiality and integrity of the host |
| Host and private network services (metadata endpoints, local daemons, RFC 1918 hosts) | Host network namespace | Lateral movement, credential theft |
| Other sandboxes' inputs and outputs | Other jobs' mount namespaces and cgroups | Cross-job confidentiality |
| Supervisor state and socket | Supervisor process, `/run/nixsandbox` | Controls every sandbox |
| Host availability (CPU, memory, PIDs, disk, fds) | Kernel | Denial of service |
| Orchestrator credentials (agent API auth) | Orchestrator process | Lets an attacker submit jobs |

## Adversaries

| ID | Adversary | Capability we assume |
|----|-----------|----------------------|
| A1 | **Malicious workload.** The main threat. | Runs arbitrary native code inside the sandbox as the workload UID. Knows this design. Can make any syscall the seccomp profile allows, with any arguments. Can race. Can spawn processes and threads up to the limits. Controls all its own output bytes. |
| A2 | Malicious or confused agent / API client | Sends any request the orchestrator accepts, including oversized, malformed, duplicated or rapid-fire requests and cancellations. |
| A3 | Compromised orchestrator | Speaks the supervisor protocol with valid peer credentials. Can submit any request that **policy** allows, but cannot change policy. |
| A4 | Local unprivileged host user (not the service user) | Can see `/proc` (subject to the host's `hidepid`) and can try to connect to the supervisor socket. |

**Out of scope:** host root, physical access, supply-chain compromise of
nixpkgs (partly mitigated by pinning and review; see [13](13-design-review.md)),
and hardware side channels beyond what is listed under residual risks.

## What A1 will try, and what stops it

| Attempt | Primary control (kernel-enforced) | Defence in depth | Residual risk |
|---------|-----------------------------------|------------------|---------------|
| Read host files, credentials, home dirs | Mount namespace + `pivot_root` + old root detached; only allow-listed binds | Landlock path rules; distinct host UID range per sandbox (DAC) | Kernel VFS/mount bugs |
| Read host environment variables | stage 2 is exec'd with an empty `envp`; workload env built only from the policy allowlist | `/proc` limited to the sandbox's own PID namespace with `hidepid=invisible` | None known |
| Inherited host fds | All supervisor fds `O_CLOEXEC`; stage 2 calls `close_range(3, ~0U, 0)` and keeps only listed fds | fd census test | Supervisor bug that leaves an fd without `CLOEXEC` *and* in the keep list (review) |
| Reach the network, metadata endpoint, host loopback services | New, empty network namespace: only `lo`, no routes | Seccomp `socket()` family filter (`AF_UNIX` only by default); Landlock v4 TCP rules when available | Netfilter or other netns-reachable kernel bugs |
| Host abstract Unix sockets (e.g. some desktop buses) | Abstract socket namespace is per network namespace, so they are unreachable | Landlock v6 abstract-socket scoping | — |
| Host path Unix sockets (`/run/...`) | Not mounted into the view | Landlock | Accidental bind in a profile (policy review) |
| Escape namespaces (`setns`, `unshare`, nested user namespace, `mount`) | No capabilities in any namespace (workload UID ≠ 0, caps dropped, securebits locked, `NO_NEW_PRIVS`) | Seccomp denies `setns`, `unshare`, `mount*`, `pivot_root`, `clone` with `CLONE_NEW*`, and `clone3` (returns `ENOSYS`); `user.max_user_namespaces=0` in the sandbox's user namespace (experiment E3) | Kernel bugs in allowed syscalls |
| Dangerous syscalls (`bpf`, `perf_event_open`, `ptrace`, `keyctl`, `userfaultfd`, `io_uring_*`, `kexec*`, module loading) | Seccomp default-deny allowlist | Missing capabilities; host sysctls (`kernel.unprivileged_bpf_disabled`, `kernel.perf_event_paranoid`, `kernel.io_uring_disabled`) checked at startup | Allowed-syscall kernel bugs |
| Signal/ptrace the sandbox init or the supervisor | Supervisor is outside the PID namespace, so it cannot be named. Init runs as a different in-namespace UID and is non-dumpable | `ptrace` denied by seccomp; Landlock v6 signal scoping | — |
| Memory exhaustion | `memory.max` with `memory.swap.max=0` and `memory.oom.group=1` | tmpfs `size=` caps below `memory.max`; tmpfs pages are charged to the job memcg | Kernel memory not fully accounted (some slab / page tables); watch `memory.stat` |
| CPU exhaustion | `cpu.max` (bandwidth), `cpu.weight` | Supervisor polls `cpu.stat usage_usec` for a total CPU-time budget | Cache/memory-bandwidth contention (noisy neighbour) |
| Process bomb | `pids.max` (counts tasks, i.e. threads too) | `RLIMIT_NPROC` is **not** relied on: it is per-UID and the UID is unique per slot anyway | — |
| Disk exhaustion | No host-disk writes; writable mounts are size-limited tmpfs | Memory cgroup charges tmpfs | Disk-backed workspaces are an open decision (D6) |
| Output flood | Bounded pipes, per-job byte cap, credit-based flow control to orchestrator | Kill-on-cap policy option | — |
| Hang / ignore SIGTERM | Wall-clock deadline in the supervisor, then `cgroup.kill` (SIGKILL to the whole cgroup, atomic with respect to forks) | PID-namespace teardown when init exits | Processes stuck in uninterruptible sleep (D state) delay the cgroup reaching empty; reported as `cleanup_stuck` |
| Cleanup races / leftover processes | `cgroup.kill` + waiting for `cgroup.events populated 0` before `rmdir` | Service-level `KillMode=control-group`; startup sweep of stale job cgroups | — |
| Migrate out of its cgroup | `CLONE_NEWCGROUP`; cgroupfs not mounted; host cgroup files are owned by the supervisor UID, not the sandbox UIDs | Seccomp blocks `mount` | Kernel bugs |
| Attack the supervisor through its outputs (exit status, artefacts, output bytes) | Supervisor treats all sandbox-originated bytes as untrusted: bounded, length-checked parsers, no interpretation | Artefacts are read by sandbox init with `openat2(RESOLVE_BENEATH\|RESOLVE_NO_SYMLINKS\|RESOLVE_NO_XDEV)` after every workload process is dead | Supervisor parser bugs (fuzzed) |
| Timing / microarchitectural side channels | Not addressed by the namespace backend | Optional `cpuset` pinning; SMT off for high assurance | **Accepted** on the namespace backend; use the microVM backend |

## Security assumptions (explicit)

1. The host kernel is ≥ 6.6, patched, and built with the options in
   [03](03-kernel-primitives.md#required-kernel-configuration). The supervisor
   checks this at startup and refuses to start if it is not met.
2. Unprivileged user namespaces are available to the service user. On Ubuntu with
   `kernel.apparmor_restrict_unprivileged_userns=1` this needs an AppArmor
   profile for the supervisor; that is a deployment step, not something the code
   bypasses.
3. The host runs systemd with cgroup v2 unified hierarchy and gives the
   service a delegated subtree (`Delegate=yes`).
4. Host sysctls are hardened: `kernel.unprivileged_bpf_disabled≥1`,
   `kernel.perf_event_paranoid≥2`, `kernel.io_uring_disabled=2` (or io_uring is
   blocked by seccomp, which it is regardless), `vm.unprivileged_userfaultfd=0`,
   `fs.protected_symlinks=1`, `fs.protected_hardlinks=1`. The supervisor reports
   any deviation; strict mode refuses to start.
5. `/nix/store` contents are not secret. They are world-readable on the host by
   design, but the sandbox still sees only its closure.
6. Policy files are written by an administrator, are root-owned and read-only
   to the service user, and are evaluated by the supervisor, never by the
   orchestrator.

## Protection versus residual risk

The namespace backend gives **kernel-enforced** protection against a malicious
*unprivileged* workload. It **does not** protect against:

- a bug in any kernel code path the workload can reach (every allowed syscall,
  the filesystems mounted in its view, the network stack within its netns,
  the memory manager, the scheduler);
- bugs in the supervisor's privileged code paths that the workload can trigger
  through data it controls (output bytes, artefact files, exit status);
- side channels through shared CPU caches, memory bandwidth, or timing.

Seccomp reduces the reachable kernel surface but cannot remove it. Python,
Node and compilers need a few hundred syscalls between them, including complex
ones (`mmap`, `futex`, `openat`, `clone`). No test suite proves the absence of
escapes. Tests only show that the specific escape classes we test are blocked.

## Shared kernel vs microVM

| Use the namespace backend when… | Use the microVM backend (mandatory) when… |
|----------------------------------|-------------------------------------------|
| All jobs act for one principal (e.g. one developer's agent) | Jobs come from mutually distrusting tenants |
| The host holds no credentials or data worth more than the job's inputs | The host holds credentials, signing keys, customer data, or is a CI/CD runner with deploy rights |
| The host has no privileged network position (no metadata endpoint that grants IAM, no internal-network reachability) | The host is a cloud VM whose instance role matters, or sits inside a private network |
| The kernel can be patched within days of a disclosure | Kernel patching is slow or out of your control |
| Startup latency and density matter more than the extra boundary | A kernel LPE in the allowed syscall surface would be a reportable incident |

The microVM backend still applies the namespace sandbox *inside* the guest
(defence in depth). Its host-side VMM process also runs in a namespace sandbox
with its own seccomp profile, as Firecracker's jailer does.
