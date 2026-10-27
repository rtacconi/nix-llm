# 02 — Architecture, trust boundaries and lifecycle

## Component diagram

```mermaid
flowchart LR
    subgraph Agent["LLM agent (untrusted requester)"]
        A[Agent tool call]
    end

    subgraph Orch["nsbx-orchestrator — Python asyncio<br/>host user: nsbx-orch, no caps"]
        API[HTTP API + schema validation]
        ADM[Admission control<br/>bounded queue + semaphore]
        JM[Job manager<br/>state, deadlines, cancel]
        SC[Supervisor client<br/>framed protocol, credits]
    end

    subgraph Sup["nsbx-supervisor — Rust/Tokio<br/>host user: nsbx, no caps, delegated cgroup"]
        PROTO[Protocol server<br/>SO_PEERCRED check]
        POL[Policy engine<br/>admin profiles, fail-closed]
        CG[cgroup manager]
        SPAWN[Spawner<br/>clone3 + execveat stage2]
        MON[Monitor<br/>pidfd, cgroup.events, output pumps]
    end

    subgraph Priv["nsbx-idmap — Rust, ~300 LOC<br/>CAP_SETUID + CAP_SETGID only"]
        IDM[Write uid_map/gid_map<br/>for verified child pidfd]
    end

    subgraph Box["Sandbox (per job): NEWUSER NEWPID NEWNS NEWNET NEWIPC NEWUTS NEWCGROUP"]
        S2[nsbx-stage2 → init (pid 1)<br/>ns-uid 0, own seccomp]
        W[Workload (pid 2+)<br/>ns-uid 1000, no caps,<br/>NNP + Landlock + seccomp]
    end

    K[(Linux kernel<br/>cgroup v2, namespaces,<br/>LSM Landlock, seccomp)]
    NIX[(/nix/store<br/>runtime closures, read-only)]

    A -- HTTPS/HTTP --> API --> ADM --> JM --> SC
    SC -- "Unix socket /run/nixsandbox/sup.sock<br/>(trust boundary TB2)" --> PROTO
    PROTO --> POL --> CG --> SPAWN
    SPAWN -- "socketpair (TB3)" --> IDM
    SPAWN -- "clone3 CLONE_INTO_CGROUP" --> S2
    S2 -- fork + exec --> W
    MON -. pidfd / pipes / status fd (TB4) .- S2
    W -. stdout/stderr pipes .-> MON
    Box --- K
    NIX -- "ro,nosuid,nodev binds" --> Box
```

## Trust boundaries

| ID | Boundary | Crossing data | Who validates |
|----|----------|---------------|---------------|
| TB1 | Agent → orchestrator | HTTP JSON requests | Orchestrator (schema, size, rate, auth) |
| TB2 | Orchestrator → supervisor | Framed protocol messages | Supervisor (peer creds, frame bounds, schema, **policy**). The supervisor never trusts the orchestrator's own validation. |
| TB3 | Supervisor → idmap helper | `(pidfd, slot)` via `SCM_RIGHTS` | idmap: pidfd liveness, parentage, cgroup path, slot range |
| TB4 | Sandbox → supervisor | Output bytes, status record, artefact stream | Supervisor: byte caps, fixed-size status struct, bounded artefact frames |
| TB5 | Workload → sandbox init | Signals (blocked by UID difference), exit status | Init does not parse any workload-controlled data except `waitid` results and, after all workload processes are dead, files it reads safely for artefacts |
| TB6 | Workload → kernel | Syscalls | Seccomp, Landlock, namespaces, cgroups, DAC |

## Component responsibilities

### A. Orchestrator (Python)

- Agent-facing HTTP API ([08](08-protocol-api.md)): validate, authenticate,
  rate-limit and queue requests.
- Owns job state as the API sees it, including results kept for retrieval.
- Bounded concurrency: `asyncio.Semaphore(max_running)` plus a bounded admission
  queue. It returns `429` with `Retry-After` when the queue is full.
- Streams output to clients over Server-Sent Events. It grants flow-control
  credits to the supervisor only as fast as it can forward or buffer bytes.
- Enforces request deadlines (the supervisor enforces them too, independently)
  and turns client disconnects into cancellations.
- **Never executes request content.** It has no `subprocess`, no `eval`, and
  only the deserialisers that JSON and pydantic provide. The CI lint rule
  `ruff` `S` (bandit) plus a banned-import check enforce this.

### B. Supervisor (Rust)

- The only component that turns a request into kernel objects.
- Loads admin policy at startup, validates it, and pins it by content hash.
  A request **selects** a profile and may only *narrow* its limits.
- Detects kernel features at startup ([03](03-kernel-primitives.md#feature-detection)).
  It refuses to start if a required feature is missing, and refuses individual
  profiles whose optional requirements are not met.
- Per job: creates the cgroup, spawns stage 2 into it, coordinates ID mapping,
  pumps output, enforces deadlines, kills, reaps, removes the cgroup and reports.
- Async (Tokio, multi-threaded) for I/O. **No code runs in a forked child except
  async-signal-safe syscalls up to `execveat`** (see [04](04-privilege-model.md#why-stage2-is-a-separate-exec)).

### C. Reproducible runtime (Nix)

- `mkRuntime { name; packages; profile; }` produces a runtime descriptor: the
  closure store-path list (from `closureInfo`), a skeleton `/etc`
  (passwd/group with the sandbox users, an empty `resolv.conf`, a minimal
  `nsswitch.conf`), a `PATH` view built with `buildEnv`, and the seccomp profile
  name. See [09](09-code-and-nix-layout.md#nix-layout).
- Runtimes are identified by output store path. Jobs report the runtime path
  and closure hash.
- **The Nix build sandbox is not the runtime sandbox.** Build-time isolation
  only makes derivations pure. It says nothing about what a runtime binary can
  do once it is running.

### D. Sandbox init (`nsbx-stage2`)

- One static Rust binary in two roles: first it is the setup stage (mounts,
  `pivot_root`, hostname, rlimits, fd closing), then it is PID 1 (reaper,
  signal forwarder, exit-status reporter, artefact collector).
- Runs as in-namespace UID 0 with capabilities **only within the sandbox user
  namespace**. Before it forks the workload it applies its own minimal seccomp
  filter for its post-setup role. It is non-dumpable.

### E. Backends

```rust
// nsbx-core::backend
pub trait Backend: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> BackendCaps;              // features this host supports
    async fn prepare(&self, spec: &ValidatedSpec) -> Result<Prepared, SetupError>;
    async fn start(&self, p: Prepared, io: JobIo) -> Result<Running, SetupError>;
    async fn signal(&self, r: &Running, s: Termination) -> Result<(), ControlError>;
    async fn wait(&self, r: Running) -> Outcome;        // never fails; carries cleanup result
}
```

| | Namespace backend | MicroVM backend (Cloud Hypervisor) |
|---|---|---|
| Boundary | Shared kernel; seccomp-reduced syscall surface | Hardware virtualisation; guest kernel; small VMM device model (virtio-blk/fs, vsock, optional virtio-net) |
| Host privilege | Unprivileged user namespaces + delegated cgroup + idmap helper | Access to `/dev/kvm`; VMM process itself jailed (namespaces + seccomp) |
| Rootfs | Read-only per-path bind mounts of the Nix closure | Read-only erofs or squashfs image built by Nix, or virtio-fs share of the closure (virtiofsd is a further host-side process to jail) |
| Control channel | Pipes + status fd | vsock to a guest agent, which is `nsbx-stage2` reused inside the guest |
| Startup | To be measured (expected to be dominated by mount count) | To be measured (expected to be dominated by guest kernel boot; snapshot/restore is a later optimisation) |
| Memory overhead | Per-sandbox kernel objects + page tables + tmpfs | Guest kernel + guest RAM reservation (balloon optional) |
| Operational complexity | Low: one host kernel, systemd unit | Higher: guest kernel builds, image pipeline, KVM availability (no nested virtualisation on many CI runners) |
| Residual risk | Host kernel bugs reachable from allowed syscalls | VMM/device-model bugs, KVM bugs, side channels |

The backend is selected per **profile**, not per request. A request can never
downgrade from the microVM backend to the namespace backend.

## Sandbox lifecycle

States: `Admitted → CgroupReady → Spawned → Mapped → Setup → Running →
Terminating → Reaped → Cleaned → Reported`. Every state has one cleanup action,
and cleanup runs in reverse order on any failure. See [12](12-failure-modes.md)
for the per-stage failure table.

### Creation sequence

```mermaid
sequenceDiagram
    autonumber
    participant O as Orchestrator
    participant S as Supervisor
    participant I as nsbx-idmap
    participant K as Kernel
    participant C as Child (→ stage2 → init)
    participant W as Workload

    O->>S: Submit{job_id, profile, spec}
    S->>S: validate frame + schema + policy (narrow-only limits)
    S->>K: mkdir jobs/job-<id>; write memory.max, memory.swap.max=0,<br/>memory.oom.group=1, pids.max, cpu.max; open dirfd
    S->>K: memfd_create(spec), write, F_ADD_SEALS(SEAL_WRITE|SHRINK|GROW|SEAL)
    S->>K: pipe2(O_CLOEXEC) for sync, status, stdout, stderr, stdin
    S->>K: clone3(NEWUSER|NEWPID|NEWNS|NEWNET|NEWIPC|NEWUTS|NEWCGROUP|<br/>INTO_CGROUP|PIDFD, exit_signal=SIGCHLD)
    Note over C: Child runs already inside job cgroup, in new namespaces,<br/>with no uid map yet (ns-uid = overflow)
    C->>K: dup2 fds to fixed numbers; execveat(stage2_fd, "", argv, envp=[], AT_EMPTY_PATH)
    Note over C: Fresh single-threaded image. Blocks reading sync pipe.
    S->>I: MapRequest{slot} + pidfd (SCM_RIGHTS)
    I->>K: verify pidfd alive, parent == supervisor, cgroup == job cgroup
    I->>K: write /proc/<pid>/{uid_map,gid_map} (ns 0 → base, ns 1000 → base+1000)
    I->>K: re-check pidfd alive (pid reuse guard)
    I-->>S: MapOk
    S->>C: sync byte "go"
    C->>C: read+verify sealed spec memfd
    C->>K: mount("", "/", MS_REC|MS_PRIVATE); build tmpfs root; ro binds of closure;<br/>tmpfs /workspace /tmp; proc(hidepid=invisible,subset=pid); minimal /dev
    C->>K: pivot_root(".", "."); umount2(".", MNT_DETACH); remount root ro
    C->>K: sethostname; setrlimit(CORE=0, NOFILE, FSIZE…); write ns max_user_namespaces=0
    C->>K: close_range(3, ~0, 0) except status/stdio
    C->>S: status: SetupOk{stage timings}
    C->>K: fork() → workload child
    W->>K: setsid; PR_CAPBSET_DROP all; setgroups(0); setresgid/setresuid(1000)
    W->>K: clear ambient/inheritable; securebits locked; PR_SET_NO_NEW_PRIVS
    W->>K: landlock_restrict_self(ruleset)
    W->>K: seccomp(SET_MODE_FILTER, profile)
    W->>K: execve(argv0 from runtime PATH, argv, env allowlist)
    C->>K: install init seccomp; PR_SET_DUMPABLE 0 (before fork); waitid loop
    S->>O: Started{job_id, setup_us}
```

### Teardown sequence (normal exit, deadline and cancel)

```mermaid
sequenceDiagram
    autonumber
    participant O as Orchestrator
    participant S as Supervisor
    participant K as Kernel
    participant C as Init (pid 1)
    participant W as Workload tree

    alt Normal exit
        W->>K: exit(n)
        K-->>C: SIGCHLD; waitid(P_PID workload)
        C->>K: kill(-1, SIGKILL) to every other process in the pid ns
        C->>K: waitid(P_ALL) until ECHILD
        C->>C: collect requested artefacts (openat2 RESOLVE_BENEATH|NO_SYMLINKS|NO_XDEV), bounded
        C->>S: status: Exited{code|signal} + artefact frames
        C->>K: exit(0) → pid ns torn down
    else Deadline or Cancel{grace_ms}
        O->>S: Cancel{job_id, grace_ms}
        S->>K: pidfd_send_signal(init_pidfd, SIGTERM)
        C->>K: kill(-1, SIGTERM) (forward to whole pid ns)
        S->>S: wait grace_ms or init exit
        S->>K: write "1" > cgroup.kill (SIGKILL every task in subtree, fork-safe)
    end
    S->>K: waitid(P_PIDFD, init_pidfd, WEXITED) → reap
    S->>K: wait (inotify) cgroup.events "populated 0", bounded by cleanup timeout
    S->>K: read memory.events/peak, pids.events, cpu.stat
    S->>K: rmdir jobs/job-<id>
    alt rmdir failed or timeout
        S->>S: mark cleanup_stuck, quarantine slot, emit event, retry in background
    end
    S->>O: Exited{reason, code/signal, usage, truncated flags}
```

Note: the PID namespace ends when its init exits. The kernel then sends SIGKILL
to every remaining process in it, which backs up `kill(-1)`. `cgroup.kill` is the
supervisor-side backstop that does not rely on init behaving correctly.
