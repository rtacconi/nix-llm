# 00 — Executive summary and system goals

## What this is

NixSandbox runs short-lived, possibly hostile programs written by LLM coding
agents (Python and Node scripts, compiler runs, CLI tools) on one Linux host. It
builds each sandbox directly from kernel primitives instead of wrapping a
container engine, so every security boundary is explicit, ordered and testable.

```
agent ──HTTP──▶ orchestrator (Python, asyncio, untrusted-input parser, no exec)
                    │  framed protocol over Unix socket (SO_PEERCRED-checked)
                    ▼
               nsbx-supervisor (Rust, unprivileged host user, delegated cgroup)
                    │  clone3(CLONE_INTO_CGROUP | NEW{USER,PID,NS,NET,IPC,UTS,CGROUP})
                    ├──▶ nsbx-idmap (Rust, tiny, CAP_SETUID+CAP_SETGID only)
                    ▼
               nsbx-stage2 → sandbox pid 1 (init) → workload (seccomp+Landlock, no caps)
```

## Goals

| ID | Goal | How it is measured |
|----|------|--------------------|
| G1 | A malicious unprivileged workload cannot read or write host files outside its assigned view, reach host network services, or affect other sandboxes, **unless it exploits a kernel bug**. | Security regression suite ([10](10-testing.md)), design review ([13](13-design-review.md)) |
| G2 | Resource limits apply **before the first workload instruction runs**, and the workload cannot leave them. | `CLONE_INTO_CGROUP` ordering test; cgroup migration probe |
| G3 | Every sandbox is torn down completely: no surviving processes, mounts, cgroups or fds, after any exit path including a supervisor crash. | Cleanup tests, crash-injection tests |
| G4 | The trusted computing base is small and auditable. Host privilege is limited to two capabilities in one ~300-line helper. | LOC budget, `cargo geiger` on unsafe code, review checklist |
| G5 | Configuration fails closed. A missing kernel feature or a failed restriction stops the job; the job never runs with weaker protection. | Feature-unavailability tests on older-kernel VMs |
| G6 | Runtimes are reproducible and pinned by Nix store path. | `nix build --check`, closure hash in every job result |
| G7 | Performance is measured. Startup, teardown and throughput get p50/p95/p99 baselines before any optimisation. | Benchmark plan ([11](11-benchmarks-observability.md)) |

## Non-goals (v1)

- Defending against kernel vulnerabilities on the namespace backend. That needs
  the microVM backend.
- Multi-host scheduling, Kubernetes, a cloud control plane, commercial sandbox
  services.
- Long-lived or interactive sandboxes (no TTY, no persistent sessions in v1).
- GPU access.

## Key decisions

| Decision | Choice | Main alternative | Why |
|----------|--------|------------------|-----|
| Isolation substrate | Kernel namespaces + cgroup v2 + Landlock + seccomp, assembled by our own code | Docker/podman/bubblewrap/nsjail | We need to control and test the ordering and the failure handling. bubblewrap and nsjail are good **references**, and nsjail is a useful differential-testing oracle. |
| Host privilege | Unprivileged supervisor + delegated cgroup + separate `CAP_SETUID/SETGID` id-mapping helper | Root daemon; setuid helper | Smallest privileged surface that still gives every sandbox its own host UID range |
| Process creation | `clone3` then an immediate `execveat` of a single-threaded stage-2 binary | Fork from inside the async supervisor | Forking a multi-threaded Tokio process is unsafe (allocator locks); runc follows the same rule |
| Resource attach | `CLONE_INTO_CGROUP` | Write PID to `cgroup.procs` after fork | No window in which the child runs outside its limits |
| Kill | pid-namespace init plus `cgroup.kill` plus pidfds | Signal by PID | Kills the whole tree atomically; no PID-reuse races |
| Runtime | Nix closure, bind-mounted read-only path by path | Whole `/nix/store` bind; image file | The mount namespace is the primary boundary; startup cost is measured, not guessed |
| Default network | Empty network namespace (loopback only) | Host network with filtering | Nothing to filter if nothing can be reached |

## When the shared-kernel backend is acceptable

See [01-threat-model.md](01-threat-model.md#shared-kernel-vs-microvm). In short,
it is acceptable for a single principal's agents on a host that holds no
higher-value secrets and is patched promptly. **MicroVM isolation is required**
for mutually distrusting tenants, hosts with credentials or sensitive network
reachability, or when kernel patch latency is long.
