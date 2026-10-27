# 03 — Kernel primitives: selection matrix, baseline and feature detection

Version numbers below are the mainline release where each feature first
appeared. They come from kernel documentation and man pages as known at design
time. **Milestone M0 re-checks every row** against
`Documentation/` in the pinned kernel source and the current man-pages
release, and records the result in `docs/verification.md`. Do not treat this
table as authoritative until that is done.

## Kernel baseline

- **Minimum: Linux 6.6 LTS.** It is the oldest LTS that has everything in the
  "required" column: Landlock ABI 3, `cgroup.kill`, `CLONE_INTO_CGROUP`,
  `close_range`, `proc` `subset=pid`, and the `kernel.io_uring_disabled` sysctl.
- **Recommended: Linux 6.12 LTS or newer.** It adds Landlock ABI 5 (ioctl on
  device files) and ABI 6 (scoping of abstract Unix sockets and signals).
- Architectures: x86_64 and aarch64. All other architectures are rejected at
  startup. On x86_64 the x32 ABI is denied by the seccomp filter in any case.

## Selection matrix

| Primitive | Purpose here | Since | Privilege needed | Failure modes | Security limits | Required? |
|-----------|--------------|-------|------------------|---------------|-----------------|-----------|
| `clone3()` | Create the child with every namespace, the pidfd and the cgroup in one atomic call | 5.3 (`CLONE_INTO_CGROUP` 5.7) | None beyond the namespace rules below | `ENOSPC`/`EUSERS` (namespace limits), `EPERM` (userns blocked by LSM/sysctl), `EBUSY` (target cgroup invalid) | Not a boundary itself | Required |
| User namespace | Gives the sandbox its own UID/GID space and capability scope; makes the other namespaces creatable without host root | 3.8; unprivileged creation depends on distro (Debian sysctl, Ubuntu AppArmor) | None if unprivileged userns is allowed | `EPERM`, `ENOSPC` (`user.max_user_namespaces`) | **Exposes kernel code paths gated on `ns_capable`** to *stage 2*. The workload holds no caps, so it reaches them only by creating a nested userns, which is blocked | Required |
| PID namespace | Hides host processes; init-death kills the tree; `kill(-1)` scope | 2.6.24 | `CAP_SYS_ADMIN` in owning userns | — | Shared kernel; `/proc` must be remounted | Required |
| Mount namespace | Private filesystem view | 2.4.19 | Same | Mounts inherited from a more privileged ns are **locked**: flags such as `ro`/`nosuid` cannot be cleared, which helps us | Mount bugs; it is only as tight as what we bind | Required |
| Network namespace | No interfaces except `lo`; separate abstract-socket namespace | 2.6.29 | Same | — | The netns still reaches the in-kernel network stack (netfilter etc. via netlink if caps were held; the workload has none) | Required |
| IPC namespace | Separate SysV IPC and POSIX mqueue | 2.6.19 | Same | — | — | Required |
| UTS namespace | Own hostname; avoids leaking host identity | 2.6.19 | Same | — | — | Required |
| Cgroup namespace | Workload's `/proc/self/cgroup` shows `/`; hides host layout | 4.6 | Same | — | Does not by itself stop migration; ownership and absence of cgroupfs do | Required |
| Time namespace | Not used | 5.6 | — | — | — | No |
| `mount()` / new mount API (`open_tree`, `move_mount`, `mount_setattr`) | Build the root. The new API gives fd-based, race-free binds and recursive attribute setting | Classic; new API 5.2, `mount_setattr` 5.12 | `CAP_SYS_ADMIN` in owning userns | `EINVAL` on propagation mistakes, `EPERM` on locked flags | Path-based classic `mount()` races if targets are in attacker-writable directories. We create every target in a fresh tmpfs before the workload exists | Required |
| Private propagation | `MS_REC\|MS_PRIVATE` on `/` first, so nothing propagates in or out | 2.6.15 | Same | Forgetting it lets the sandbox's mounts propagate to the host peer group (not possible from a userns in practice, but we set it regardless) | — | Required |
| `pivot_root()` + `umount2(MNT_DETACH)` | Swap root and detach the old root so host paths are unreachable | 2.3.41 | Same | `EINVAL` if the new root is not a mount point (we bind it to itself first) or if `/` is `MS_SHARED` | `chroot` alone is escapable with caps. `pivot_root` + detach removes the old tree | Required |
| UID/GID maps | ns 0 → per-slot host base, ns 1000 → base+1000 | 3.8 | Multi-range maps need `CAP_SETUID`/`CAP_SETGID` in the parent userns (our `nsbx-idmap`). Single-range self map is unprivileged but needs `setgroups=deny` for gid_map | Map written twice → `EPERM`; overlapping ranges → `EINVAL` | Wrong maps can grant host IDs; idmap validates slot ranges against `/etc/subuid`-style config | Required |
| Capabilities | Stage 2 has full caps *in the userns*; the workload has none | — | — | — | Caps in a userns still reach `ns_capable` kernel code, so they are dropped before exec | Required |
| `PR_SET_NO_NEW_PRIVS` | Stops privilege gain through setuid/fscaps on exec; required for unprivileged seccomp and Landlock | 3.5 | None | — | Irreversible, which is what we want | Required |
| seccomp-BPF | Syscall allowlist with argument checks | 3.5; `KILL_PROCESS` 4.14; `USER_NOTIF` 5.0 | `NO_NEW_PRIVS` | Profile incompatible with the runtime → `ENOSYS`/`EPERM` in workload | Cannot dereference pointers (no filtering of `clone3` flags, paths, `sockaddr`); does not see io_uring operations | Required |
| Landlock | Unprivileged filesystem access control (defence in depth behind the mount ns) | ABI 1: 5.13; 2 (REFER): 5.19; 3 (TRUNCATE): 6.2; 4 (TCP bind/connect): 6.7; 5 (IOCTL_DEV): 6.10; 6 (scope abstract-unix, signal): 6.12 | `NO_NEW_PRIVS` | LSM not enabled at boot (`lsm=` missing `landlock`) → `EOPNOTSUPP` | Does not control `stat`/path walk, so names leak but contents do not. Does not cover every operation | Required ABI ≥ 3 |
| cgroup v2 `memory.max`, `memory.swap.max`, `memory.high`, `memory.oom.group`, `memory.events`, `memory.peak` | Memory ceiling, no swap, whole-job OOM kill, accounting | `oom.group` 4.19, `peak` 5.19 | Write access to delegated subtree | No memory controller in `subtree_control` | Not all kernel memory is attributed | Required |
| `cpu.max`, `cpu.weight`, `cpu.stat` | Bandwidth cap, fairness, usage | 4.15 (cpu controller on v2) | Same | — | Throttling ≠ total-time limit; the supervisor enforces the budget by polling `cpu.stat` | Required |
| `pids.max`, `pids.events` | Task-count cap | 4.5 | Same | — | — | Required |
| `io.max` / `io.weight` | Block-I/O throttling | 4.5 | Same, plus device numbers | Irrelevant to tmpfs | Only matters for disk-backed workspaces (D6) | Optional |
| `cgroup.kill` | Atomic SIGKILL of the whole subtree, including tasks forked concurrently | 5.14 | Same | — | — | Required |
| `cgroup.events` (`populated`) | Notification that the subtree is empty, via inotify | 4.5 | Same | — | — | Required |
| `pidfd_open` / `CLONE_PIDFD` | Race-free process handle | `CLONE_PIDFD` 5.2, `pidfd_open` 5.3 | None | — | — | Required |
| `pidfd_send_signal` | Signal without PID reuse | 5.1 | Normal kill permission | — | — | Required |
| `waitid(P_PIDFD)` | Reap by pidfd | 5.4 | — | — | — | Required |
| `close_range` | Close all inherited fds | 5.9 (`CLOSE_RANGE_CLOEXEC` 5.11) | None | — | — | Required |
| `openat2` `RESOLVE_*` | Symlink-safe artefact reads | 5.6 | None | `EXDEV`/`ELOOP` on violations, by design | — | Required |
| `proc` `hidepid=invisible,subset=pid` | Minimal `/proc` | 5.8 | Mounting proc in a userns needs a fully visible proc elsewhere (it exists on the host) | Some runtimes want `/proc/cpuinfo` / `meminfo` (see profiles) | — | Required (per-profile override) |
| `memfd_create` + seals | Immutable job spec handed to stage 2 | 3.17 | None | — | — | Required |
| `prctl(PR_SET_CHILD_SUBREAPER)` | Not needed: the PID namespace init is the reaper | — | — | — | — | No |
| `rlimits` | `CORE=0`, `NOFILE`, `FSIZE`, `STACK`, `MEMLOCK=0` | — | — | — | Per-process; complements cgroups and does not replace them | Required |

## Required kernel configuration

`CONFIG_USER_NS, PID_NS, NET_NS, IPC_NS, UTS_NS, CGROUPS, MEMCG, CGROUP_PIDS,
CGROUP_SCHED, CFS_BANDWIDTH, SECCOMP, SECCOMP_FILTER, SECURITY_LANDLOCK
(and landlock in the active lsm= list), TMPFS, PROC_FS`. Recommended:
`CONFIG_IO_URING` either off or `kernel.io_uring_disabled=2`.

## Feature detection

At startup the supervisor runs a probe sequence, records a `HostFeatures` struct
in the `HelloAck` message, and logs it:

| Check | Method |
|-------|--------|
| Kernel version / arch | `uname(2)`; arch must be x86_64 or aarch64 |
| cgroup v2 unified | `statfs("/sys/fs/cgroup").f_type == CGROUP2_SUPER_MAGIC` |
| Delegated subtree writable, controllers available | Read own cgroup from `/proc/self/cgroup`, check `cgroup.controllers` ⊇ {memory, pids, cpu}, try `mkdir` + `rmdir` of a probe cgroup |
| `cgroup.kill` present | File exists in probe cgroup |
| `clone3` + `CLONE_INTO_CGROUP` | Spawn a probe child into the probe cgroup that exits at once; verify `/proc/<pid>/cgroup` |
| Unprivileged userns allowed | Probe `clone3(CLONE_NEWUSER)` child |
| Landlock ABI | `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` → ABI integer |
| seccomp | `prctl(PR_GET_SECCOMP)`; plus `seccomp(SECCOMP_GET_ACTION_AVAIL, …)` for `KILL_PROCESS`, `LOG` |
| `proc` `subset=pid` | Mount attempt inside the userns probe child |
| Host sysctls | Read `/proc/sys/...` values listed in [01](01-threat-model.md#security-assumptions-explicit) |
| idmap helper | `Hello` exchange over its socketpair; it reports its configured slot range |

**Behaviour when something is missing (fail closed):**

- A *required* feature is missing → the supervisor exits non-zero with a precise
  diagnostic. It never runs a "degraded" mode silently.
- An *optional* feature is missing (Landlock ABI 6 scoping, Landlock TCP) →
  profiles that list it under `requires:` are disabled and rejected with
  `profile_unavailable`. All others run, and `HostFeatures` reports the gap.
- The `landlock` crate's best-effort compatibility mode is **not** used. It is
  set to its hard-requirement level (exact API: check during M0) so that an
  unsupported access right is an error, not a silent no-op.
- A dev-only `--insecure-dev-mode` (single-UID mapping, no idmap helper) exists
  for laptop and CI work. It is compiled behind a Cargo feature that release
  builds leave out, and every job result carries `"insecure_dev_mode": true`.
