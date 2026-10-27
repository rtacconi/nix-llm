# 16 — Design improvements: new mechanisms

This document adds eight new mechanisms to the design. Each one builds on a
finding in [15-literature-review](15-literature-review.md), cited here as [n],
and on something NixSandbox has that most other sandboxes in that literature do
not:

- content-addressed Nix runtimes;
- a kernel-object-centred lifecycle (cgroups and pidfds);
- a small Rust trusted computing base.

Every mechanism is stated with its mechanism, its costs and its open questions,
and each open question becomes an experiment in [14-roadmap](14-roadmap.md).

| ID | Mechanism | Problem it addresses | Source |
|----|-----------|----------------------|--------|
| N1 | Per-job warden processes | The supervisor parses sandbox-originated bytes in one shared process | [2], [18], [13] residual risk 3 |
| N2 | Co-built policy | Profiles and runtimes drift apart; policy-author error | [3] gap 4, [11] |
| N3 | Capability-shaped runtimes | Every tool in the closure is usable by the workload | [1], [17] |
| N4 | Kernel-exposure map | A kernel CVE lands; which profiles and jobs were exposed? | [2] §2.4, [1] |
| N5 | Pre-warmed single-use sandboxes | Startup latency is a usability barrier | [4], [6] |
| N6 | Crash-only supervisor | Recovery after a supervisor crash depends on in-memory state | [1] §6.2 |
| N7 | Reproducible forensic replay | Incidents cannot be re-examined after the job is gone | [3] RC4, [17] |
| N8 | Verified core | Narrowing and setup ordering are checked only by tests | [16], [3] gap 4 |

---

## N1. Per-job warden processes (privilege separation inside the supervisor)

**Problem.** The design review ([13](13-design-review.md), residual risk 3) names
the supervisor's parsing of sandbox-originated data as a residual risk: status
records, artefact frames and output streams. Today one multi-threaded Tokio
process parses those bytes for *every* job. A parser bug triggered by job A
therefore runs in the process that holds every other job's pipes and pidfds, the
orchestrator socket and the idmap channel. Chrome's site-isolation design and
IsolateGPT's hub-and-spoke model [18] answer the same question: give each
untrusted principal its own handler.

**Mechanism.**

1. For each job, the supervisor spawns `nsbx-warden`: a small, single-threaded,
   statically linked binary (fork plus immediate `execveat`, the same pattern as
   stage 2).
2. The warden receives the job's pipe read ends, the status fd and the init
   pidfd over a `SOCK_SEQPACKET` socketpair. These are the only fds it holds.
3. Before touching any job data it locks itself down:
   - `PR_SET_NO_NEW_PRIVS`;
   - an empty Landlock ruleset, so it has no filesystem access at all;
   - a seccomp allowlist of about 15 syscalls: `read`, `write`, `ppoll`,
     `recvmsg`, `sendmsg`, `waitid`, `pidfd_send_signal`, `close`,
     `exit_group`, `clock_gettime`, `mmap`/`munmap` for its arena, and similar.
4. The warden parses the status record and artefact frames. It enforces output
   byte caps and forwards *validated, length-prefixed* frames to the supervisor.
   The supervisor never parses a byte that came from the sandbox; it only
   relays opaque output chunks.
5. The supervisor keeps the authority: it owns the cgroup, does
   `cgroup.kill`, holds its own init pidfd for reaping, and enforces deadlines.
   A compromised warden can corrupt only its own job's *report*, not the
   enforcement. The deadline and `cgroup.kill` still fire.

**Costs.** One extra process per job, roughly a few hundred KiB RSS for a static
binary. That is to be measured in benchmark B10, not assumed. It adds one extra
hop of output-forwarding latency (B8).

**Open questions (E10).**
- Does the warden's seccomp allowlist cover Rust's static-musl allocator
  (`brk` vs `mmap`)?
- Does per-job warden CPU accounting belong in the job cgroup (cleaner billing,
  but the workload could starve its own warden) or in `supervisor/` (the
  proposed default)?

## N2. Co-built policy: profiles as Nix derivation outputs

**Problem.**
- Profiles live in `policy/` and runtimes live in `runtimes/`. They meet only at
  deploy time. Nothing stops a nixpkgs bump from adding a syscall the profile
  denies (a functional break) or a binary the profile never anticipated (a
  policy gap).
- ContainmentBench [11] traced 480 wrong blocks to a single label mismatch
  between two independently maintained vocabularies.
- The Balkanization SoK [3] (gap 4) notes that every mechanism it reviews
  assumes the policy author is correct.

**Mechanism.** `mkRuntime` ([09](09-code-and-nix-layout.md#mkruntime)) gains a
`policy` output. One derivation builds the runtime *and* its enforcement
artefacts:

| Artefact | Derived from |
|----------|--------------|
| Landlock read/exec rule set | `closureInfo` store paths. Mechanical, no hand-written paths |
| Mount list | the same store-path list |
| Seccomp BPF | the profile TOML, compiled with `nsbx-policy`. The BPF hash is a derivation output |
| Conformance trace | `passthru.tests` of the runtime, run inside an `nsbx` sandbox in a NixOS VM test with the profile in `SECCOMP_RET_LOG` mode. A syscall seen in the log but missing from the profile fails the build |
| `policy.json` | Ties together runtime store path, BPF hash, Landlock digest and profile version |

The supervisor accepts a `(runtime, policy)` pair only if `policy.json` names
that exact runtime store path. Editing one without rebuilding the other becomes
impossible rather than merely discouraged.

**Effect.** Policy drift becomes a build failure. The single-source requirement
[11] is enforced by the Nix dependency graph, not by review discipline. The
orchestrator's capability vocabulary (`GET /v1/profiles`) is generated from the
same `policy.json` files, so the API cannot advertise a capability the
supervisor does not enforce.

**Open question (E11).** Can the conformance-trace VM test run inside the Nix
build sandbox? It needs KVM via `requiredSystemFeatures = [ "kvm" ]`, so it
will run only on builders that have KVM. That matches CI tier T3.

## N3. Capability-shaped runtimes

**Problem.**
- After compromise, an attacker uses whatever tools the environment already
  provides.
- SandboxEscapeBench agents [1] relied on the standard tools present in the
  container.
- Five of the six failure classes ToolEmu reproduced on a real VM [17] needed a
  general-purpose shell and system utilities.
- Seccomp bounds which *syscalls* a workload can make, but a closure that ships
  a full userland still hands it ready-made tools.

**Mechanism.** Nix makes closure minimisation cheap, so runtimes are shaped to
the task class, not just the language:

| Runtime variant | Closure contains | Excluded on purpose |
|-----------------|------------------|---------------------|
| `python-compute` | `python3` (no `ensurepip`), stdlib | shell, coreutils, compilers, network clients |
| `python-tooling` | above + coreutils + git (read-only use) | compilers, network clients |
| `build-c` | gcc, make, binutils, coreutils, shell | network clients, package managers |
| `cli-text` | coreutils, grep, sed, jq | interpreters, compilers |

Concretely:
- A `python-compute` job literally has no `/bin/sh` to exec. `subprocess` calls
  fail with `ENOENT`, which is a clean, explainable denial.
- A CI check (`nsbx-policy closure-audit`) lists every executable in each
  runtime's closure and diffs it against a committed allowlist. Any new binary
  pulled in by a nixpkgs bump shows up in review.
- Smaller closures also mean fewer bind mounts, which feeds directly into
  startup latency (benchmark B3, decision D1).

**Trade-off.** More runtimes to maintain, though Nix shares store paths between
them, so the disk cost is small. Agents need to know which variant to request;
that is covered by the profile listing.

## N4. Kernel-exposure map

**Problem.** [2] counts about 3,500 kernel CVEs in 24 months, and stresses that
a kernel bug matters only through the surface a sandbox exposes. When a kernel
advisory lands, an operator needs answers in minutes:

- Which profiles allow the affected syscall or socket family?
- Which jobs actually *used* it in the last 30 days?
- Can we drop it from profiles that never use it?

**Mechanism.**

1. **Static side.** `nsbx-policy` emits, per profile, the set of allowed
   syscalls, argument constraints and socket families, as part of
   `policy.json` (N2).
2. **Dynamic side (opt-in).** A host-side eBPF program (bpftrace or Aya,
   loaded by an admin-run agent, never by the supervisor) counts
   `raw_syscalls:sys_enter` by syscall number. It aggregates per job cgroup and
   rolls up per profile. Only counts are kept: no arguments, no workload data.
3. **Join.** `nsbx exposure --syscall <name>` or `--family <AF>` prints every
   profile that allows it, its 30-day usage count, and the number of distinct
   jobs.
4. **Tightening suggestions.** Syscalls allowed by a profile but used by zero
   jobs over a long window become "candidates to drop" in a generated report.
   They are never dropped automatically. The change goes through the N2 build
   and the conformance trace.

**Why this is new.** Seccomp profiles are normally write-once. This turns them
into living, usage-informed artefacts, and it gives patch triage a data-driven
answer. That ties [2]'s exposure argument to day-to-day operations.

**Privacy and safety.** The collector runs host-side with its own privileges.
The workload gets no new capability or visibility. Counts are aggregated per
profile before storage.

## N5. Pre-warmed single-use sandboxes

**Problem.**
- Only 38.2% of SideKernel's survey respondents use a sandbox; slowness and
  setup friction are among the reported barriers [4].
- AgentBound's Docker sandbox adds hundreds of milliseconds of startup [6].
- Per-path bind mounts make NixSandbox's setup cost scale with closure size
  (decision D1).

**Mechanism.** The supervisor keeps a small pool of sandboxes per
`(runtime, policy)` pair. Each is fully constructed up to, but not including,
the workload fork:

- cgroup created, namespaces created, UID slot mapped;
- root view mounted, `pivot_root` done;
- an empty workspace tmpfs;
- stage 2 parked on its sync pipe.

On a request, the supervisor claims an entry:
1. It writes the job's cgroup limits. They can only be *raised* from the pool
   floor (the strictest values), and only up to the profile maximum.
2. It sends the job spec over the sealed memfd.
3. Stage 2 stages the input files and forks the workload, exactly as in the
   normal path.

**Security rules.**
- **Single use.** A pool entry is never returned to the pool. After the job it
  goes through the normal teardown. No state carries between jobs.
- **Nothing untrusted runs before the claim.** Everything done before the claim
  is setup by trusted code. The ordering guarantees in
  [04](04-privilege-model.md) are unchanged.
- **Limits are written before untrusted code runs.** The limits in effect while
  the entry is parked are the strictest possible, and the job's real limits are
  written before the fork.
- **Bounded idle cost.** Pool size and TTL are set per runtime, and idle entries
  count against the `jobs/` aggregate memory cap. Entries older than the TTL are
  torn down so they never run on stale host state.
- **Same receipts.** Pool entries go through the same feature and enforcement
  checks as on-demand sandboxes.

**Expected effect.** Startup latency becomes "claim and stage" instead of "build
the whole view". The improvement is measured as B1-warm vs B1-pool. No number is
claimed before measuring.

**Open question (E12).** Is lowering-then-raising `memory.max` on a parked cgroup
free of side effects? Expected yes, because nothing has been charged yet beyond
stage 2's small footprint. Verify, and check `memory.events` stays clean.

## N6. Crash-only supervisor

**Problem.**
- Today a supervisor crash kills every job (F22/F23 in
  [12](12-failure-modes.md)).
- [1] found that agents crash their own sandboxes frequently. A supervisor that
  can be disrupted by a parsing edge case, even one mitigated by N1, turns a
  local failure into a fleet-wide one.

**Mechanism.** The supervisor keeps **no durable state of its own**. Everything
it needs can be rebuilt from kernel objects:

| State | Source of truth |
|-------|-----------------|
| Which jobs exist | Directories under `jobs/` |
| Job identity, slot, profile, deadline, owner | A small record in an `O_TMPFILE`-backed memfd. The memfd is **held by systemd's fd store** (`FileDescriptorStoreMax=`, `sd_pid_notify_with_fds`) and handed back on restart |
| Process handles | `pidfd_open` on the PIDs in each job's `cgroup.procs`, cross-checked against the record's init PID and start time |
| Limits and usage | The cgroup files themselves |

On restart, the supervisor either *reattaches* to jobs whose deadline has not
passed or tears them down. Which one is a policy choice; the default stays
"tear down", which is fail-closed. The real gain is that teardown becomes exact
and fast, and the reattach option becomes possible.

Wardens (N1) die with the old supervisor, so reattaching means spawning fresh
wardens and re-passing the pipe fds. Those fds also go through the systemd fd
store.

**Open questions (E13).**
- Does the systemd fd store reliably hand back pipe and pidfd fds after a crash,
  rather than only after a clean restart?
- If not, fall back to tear-down-only. That is still crash-only in spirit: the
  supervisor has no state it cannot rebuild.

## N7. Reproducible forensic replay

**Problem.**
- When a job trips a seccomp kill or ends with `setup_failed{init}`, the
  sandbox is gone. Investigators have only the result record.
- [3] (RC4) criticises defences validated only against the authors' own
  scenarios. Real incidents are the best test cases, and they are usually lost.

**Mechanism.** Nix makes most of a job's inputs content-addressed already:

- runtime closure hash;
- `policy.json` hash (N2);
- request hash;
- input file digests;
- kernel release.

If the profile sets `retain_inputs: true`, the supervisor stores the request and
its input files in a content-addressed, size-capped, TTL-bound local store,
keyed by job ID.

`nsbx replay <job_id>` then:
1. builds the exact runtime by store path, with no network needed if it is cached;
2. starts it in the **microVM backend** inside a disposable VM with no network;
3. runs it with host-side tracing on: `strace -f` from outside the guest, plus
   cgroup and perf counters;
4. writes a replay report next to the original result.

**Scope.**
- Replays are best-effort deterministic. Timing, randomness and thread
  scheduling differ.
- Replay is for understanding, not for proving intent.
- It runs only on an operator workstation or a dedicated forensics host, never
  on the production supervisor host.

**Data handling.** `retain_inputs` is off by default, honouring the logging
policy in [11](11-benchmarks-observability.md#logging-policy). It is per
profile, with an explicit TTL. Retained inputs are untrusted data and are only
ever executed inside the microVM replay path.

**Bonus.** Every replayed incident can be reduced to a regression probe for
[10-testing](10-testing.md), with the content-safety rules applied to the
reduction. That turns production surprises into permanent tests.

## N8. Verified core

**Problem.**
- The two properties the whole design leans on are checked today only by tests
  and property tests:
  1. **narrow-only**: an accepted request never exceeds its profile;
  2. **setup ordering**: no workload instruction runs before every restriction
     is applied.
- Progent [16] shows the value of a machine-checked inclusion relation. It uses
  Z3 over its policy language. [3] (gap 4) shows how often policy authors get
  things wrong.

**Mechanism.**

1. **Narrowing proof.** The `nsbx-policy` capability types are kept decidable:
   intervals, finite sets, enums and literal path prefixes, with no regex. The
   `narrow(profile, principal, request) -> effective` function is written in
   plain Rust with no I/O.
   - Use [Kani](https://model-checking.github.io/kani/) (a bounded model checker
     for Rust) to prove, for all inputs within bounds, that
     `effective ⊆ profile`, `effective ⊆ principal`, and `effective ⊆ request`
     whenever the request is accepted.
   - The same proof covers the orchestrator only if the orchestrator *calls* the
     Rust function via a small PyO3 binding instead of reimplementing it in
     Python. Do that, so the API layer and the supervisor share one verified
     implementation.
2. **Frame decoder.** Kani harnesses prove that the `nsbx-proto` decoder never
   panics and never reads past `len` for any input up to the frame cap. They
   complement, rather than replace, fuzzing.
3. **Setup ordering as a typestate.** Stage 2's sequence is encoded in Rust's
   type system: each step consumes a token type and returns the next, and
   `exec_workload` only accepts `Restricted<SeccompApplied>`. A missing step then
   fails to compile; it cannot be "forgotten in a refactor". This turns the
   invariant from a lint ([12](12-failure-modes.md), invariant 3) into a
   compile-time guarantee.
4. **A small TLA+ model** of the job lifecycle checks liveness and safety under
   arbitrary interleavings of cancel, deadline, exit, supervisor crash and
   cleanup:
   - every admitted job reaches exactly one terminal state;
   - a slot is never reused before `rmdir`.

**Cost.** Proof harnesses are bounded and run in CI tier T1. The typestate costs
nothing at runtime. The TLA+ model is about a page and is checked with TLC in CI.

---

## How the mechanisms fit together

```text
   request ──▶ orchestrator ──(N8: shared verified narrow())──▶ supervisor
                                                              │
               N2 policy.json binds runtime ⇄ BPF ⇄ Landlock  │ N5 claim pre-warmed entry
                                                              ▼
           N3 minimal closure ──▶ sandbox (stage 2, typestate-ordered, N8)
                                                              │ raw bytes
                                                              ▼
                                       N1 warden (empty Landlock, ~15 syscalls)
                                                              │ validated frames
                                                              ▼
                     supervisor (N6: state rebuildable from cgroups + fd store)
                                                              │
                      N4 exposure map ◀── host eBPF counts    │ N7 retained inputs
                                                              ▼
                                                         result + replay
```

## Changes to the roadmap

| Milestone | Adds |
|-----------|------|
| M1 | N8 narrowing proof + decoder harnesses; PyO3 binding for `narrow()` |
| M3 | N3 runtime variants + `closure-audit` |
| M4 | N2 co-built policy (needs a KVM builder for the conformance trace) |
| M5 | N1 wardens; N8 stage-2 typestate |
| M6 | N6 crash-only state (E13) |
| M8 | N5 pool (E12), benchmarked against the non-pool baseline; N4 exposure map |
| M10 | N7 replay in the microVM backend |

New experiments: E10 (warden syscall set and accounting), E11 (KVM in Nix
builds), E12 (parked-cgroup limit raise), E13 (fd store across crashes).
