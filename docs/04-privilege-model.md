# 04 — Privilege and capability model

## Host identities

| Process | Host UID | Host capabilities | cgroup | Why |
|---------|----------|-------------------|--------|-----|
| `nsbx-orchestrator` | `nsbx-orch` | none | `nsbx-orch.service` | Network-facing parser. Holds nothing of value except API auth. |
| `nsbx-supervisor` | `nsbx` | **none** | `nsbx.service/supervisor` (delegated) | Creates namespaces through unprivileged user namespaces and manages its own delegated cgroup subtree. |
| `nsbx-idmap` | `nsbx-idmap` | `CAP_SETUID`, `CAP_SETGID` (ambient, via systemd `AmbientCapabilities=`, bounding set limited to these two) | `nsbx.service/idmap` | Writes multi-range UID/GID maps for sandbox children. Nothing else. |
| Sandbox stage 2 / init | slot base (e.g. `2_000_000 + slot·65536`) | none on the host; full set *inside its own userns* until it drops them | `nsbx.service/jobs/job-<id>` | — |
| Workload | slot base + 1000 | none anywhere | same | — |

The design has no root daemon and no setuid binary. The only host privilege is
two capabilities in a helper with roughly 300 lines of logic. It exists because
giving each sandbox its own host UID range is the cheapest strong
**cross-sandbox** boundary. If a workload escapes its mount namespace, ordinary
DAC still stops it from touching another slot's files or processes, or the
supervisor's.

### Alternatives considered

| Option | Rejected because |
|--------|------------------|
| Root daemon (Docker / runc model) | Every parser bug becomes host root. Too much TCB. |
| Setuid helper (bubblewrap-setuid model) | The setuid environment is hostile (env, fds, rlimits all come from the caller). A systemd-launched helper with ambient caps starts from a clean, known state. |
| Single-range self-mapping only (fully rootless) | Every sandbox and the supervisor share one host UID. One escape exposes all jobs and the supervisor socket. Kept only as `--insecure-dev-mode`. |
| `newuidmap` from shadow-utils (setuid) | It works, but it adds a setuid binary and parses `/etc/subuid`. Our helper is smaller and also checks cgroup membership and parentage. |

## `nsbx-idmap` contract

Request: `MapRequest { slot: u16 }` plus one pidfd via `SCM_RIGHTS` on a
`SOCK_SEQPACKET` socketpair that the supervisor inherits from systemd. The
helper is not reachable through the filesystem.

Steps:
1. `slot < configured_slots`. Base = `range_start + slot * 65536`. Ranges are
   fixed by config and checked at startup not to overlap any UID in host
   `passwd`.
2. From the pidfd, `/proc/self/fdinfo/<fd>` gives `Pid:`. Open `/proc/<pid>` as a
   dirfd.
3. Check `PPid` = the supervisor PID (taken from `SO_PEERCRED` of the
   socketpair), and that `/proc/<pid>/cgroup` is under `…/jobs/`.
4. Write `gid_map` then `uid_map` through `openat(dirfd, …)`. Content:
   `0 <base> 1\n1000 <base+1000> 1\n`. Only two IDs are mapped; any other ID
   appears as the overflow ID (65534).
5. `pidfd_send_signal(pidfd, 0)` must succeed **after** the writes. If the
   process died and its PID was reused between steps 2 and 4, the dirfd still
   refers to the dead process and the writes fail, but we check anyway and
   return an error.
6. Reply `MapOk` / `MapErr{code}`. The helper keeps no state and handles one
   request at a time, with a bounded queue.

The helper is single-threaded, runs `#![forbid(unsafe_code)]` outside one small
`sys` module, and runs under its own seccomp profile (`openat`, `write`,
`read`, `recvmsg`, `sendmsg`, `close`, `pidfd_send_signal`, `exit_group`, …).

## Why stage 2 is a separate exec

The supervisor is a multi-threaded Tokio process. After `fork`/`clone` in a
multi-threaded process, the child may only call async-signal-safe functions
until it execs. A Rust allocation, a `Drop` or a log call can deadlock on a lock
held by a thread that no longer exists. So the child does nothing except:

```text
dup2(spec_memfd, 3); dup2(sync_rd, 4); dup2(status_wr, 5);
dup2(stdin_rd, 0); dup2(stdout_wr, 1); dup2(stderr_wr, 2);
execveat(stage2_fd, "", argv, envp = {NULL}, AT_EMPTY_PATH);
_exit(127);            // only reached on failure
```

All of these are raw syscalls on values prepared before `clone3`, with no
allocation. `stage2_fd` is opened once at startup with `O_PATH|O_CLOEXEC`
from the supervisor's Nix store path, so a later change to `PATH` or the
filesystem cannot swap it. `execveat` with `AT_EMPTY_PATH` on an `O_PATH` fd works
on the target kernels; M0 adds a test for this.

runc solves the same problem with a C "nsexec" constructor and a re-exec. We use
a separate, statically linked Rust binary, which keeps the setup code in a clean
single-threaded image.

## Ordering of namespace creation and privilege transitions

The order is chosen so that **at no point does code that the workload controls
run with more privilege, fewer limits, or more visibility than its final
state**.

| # | Where | Step | Why here |
|---|-------|------|----------|
| 1 | Supervisor | Create job cgroup, write **all** limits, open dirfd | Limits must exist before any process is in the cgroup |
| 2 | Supervisor | `clone3` with every `CLONE_NEW*`, `CLONE_INTO_CGROUP`, `CLONE_PIDFD` | Atomic: the child is born in the namespaces and the cgroup. There is no "moved later" window. |
| 3 | Child | `dup2`s, `execveat(stage2)` | Leave the multi-threaded image at once |
| 4 | Stage 2 | Block on the sync pipe | No maps yet. The child is the overflow UID, so it can do almost nothing. |
| 5 | idmap | Write maps | Must come from outside the namespace with host caps |
| 6 | Stage 2 | `setresuid(0)`/`setresgid(0)` in the namespace (becomes the mapped ns root); read and verify the sealed spec | Gains caps *in the userns only* |
| 7 | Stage 2 | Mounts: rprivate, tmpfs root, binds, proc, dev; `pivot_root`; detach the old root; read-only root | Needs `CAP_SYS_ADMIN` in the userns. No untrusted code exists yet. |
| 8 | Stage 2 | `sethostname`; rlimits; write `/proc/sys/user/max_user_namespaces = 0` for this userns (experiment E3 confirms it is per-userns and writable here) | — |
| 9 | Stage 2 | `close_range` except the keep-list | Last point before forking untrusted code |
| 10 | Stage 2 | `PR_SET_DUMPABLE 0` | Stops a same-UID process from inspecting init. The workload also has a different UID. |
| 11 | Stage 2 | `fork()` (single-threaded, so this is safe) | — |
| 12a | Workload child | `setsid()` | No controlling terminal (and there is no TTY anyway, so `TIOCSTI` has nothing to target) |
| 12b | Workload child | Drop the bounding set with `PR_CAPBSET_DROP` for every cap up to `CAP_LAST_CAP` (read from `/proc/sys/kernel/cap_last_cap`) | Needs `CAP_SETPCAP`, so it must happen before the UID switch |
| 12c | Workload child | `setgroups(0, NULL)` | Drop supplementary groups (they could act as negative permissions) |
| 12d | Workload child | `setresgid(1000,1000,1000)` then `setresuid(1000,1000,1000)` | GID before UID, or the GID change would fail. With `SECBIT_KEEP_CAPS` unset, the UID change clears permitted/effective caps. |
| 12e | Workload child | Clear ambient (`PR_CAP_AMBIENT_CLEAR_ALL`) and inheritable caps; set `SECBIT_NOROOT\|NOROOT_LOCKED\|NO_SETUID_FIXUP\|NO_SETUID_FIXUP_LOCKED\|KEEP_CAPS_LOCKED\|NO_CAP_AMBIENT_RAISE\|…_LOCKED` | Setting securebits needs `CAP_SETPCAP`. **Open question (E4):** must they be set before 12d while the cap is still held? The order gets fixed in M0 with a test that reads `/proc/self/status` `CapEff/CapPrm/CapBnd/CapAmb/CapInh` = 0 and checks the securebits. |
| 12f | Workload child | `PR_SET_NO_NEW_PRIVS 1` | Required for Landlock and seccomp without caps |
| 12g | Workload child | `landlock_restrict_self` | Before seccomp, so the seccomp profile does not have to allow the Landlock syscalls |
| 12h | Workload child | `seccomp(SECCOMP_SET_MODE_FILTER, 0, prog)` | Last restriction. From here on every syscall is filtered, including `execve`. |
| 12i | Workload child | `execve` workload | The filter and Landlock domain are inherited across exec and cannot be removed |
| 13 | Init | Install the init seccomp profile (`wait4`/`waitid`, `kill`, `read`/`write`/`openat2` for artefacts, `exit_group`, …), then supervise | Narrows init's surface for the rest of its life |

Any failure in steps 6–12 makes stage 2 write a `SetupFailed{stage, errno}`
record to the status fd and `_exit` with a reserved code. The workload exec is
never reached. There is no "continue without X" path.

## Capability summary per phase

```text
          host caps   userns caps   NNP   Landlock  seccomp
idmap     SETUID,SETGID   n/a        no     no      own profile
supervisor   none         n/a        yes¹   no      own profile (M7)
stage2       none         full       yes¹   no      no
init         none         full²      yes¹   no      init profile
workload     none         none       yes    yes     workload profile
```
¹ The supervisor sets it at startup and it is inherited across `clone3` and
`execveat`. That is harmless: stage 2 gets its userns caps from creating the
namespace, not from a setuid exec.
² Init keeps userns caps because it needs `kill(-1)` across UIDs. Its seccomp
profile blocks everything else that would use them.
