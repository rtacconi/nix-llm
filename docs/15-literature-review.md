# 15 — Literature review: sandboxing and privilege control for LLM agents

This review covers 19 arXiv papers (2023–2026) on executing LLM-agent actions
safely. For each paper it records what the paper says and measures, and what
follows for NixSandbox. The PDFs were read in full, appendices included, then
removed from the repository. The arXiv links below are the canonical copies.

**Conventions**

- Numbers in brackets, such as [1], refer to the [reference list](#references)
  at the end.
- **Reported** means the paper states it. All figures are copied as published.
  Several papers contain internal inconsistencies; these are listed in
  [Data-quality caveats](#data-quality-caveats).
- **Implication** marks our own inference for NixSandbox.
- This document follows the [content-safety rules](content-safety.md). It
  describes vulnerability and attack *classes* and outcomes, never exploit
  steps, payloads or commands, even where the source papers include them.

## Contents

1. [Cross-cutting findings](#1-cross-cutting-findings)
2. [Design actions for NixSandbox](#2-design-actions-for-nixsandbox)
3. [Per-paper notes](#3-per-paper-notes)
   - [A. Execution sandboxes for agent code](#a-execution-sandboxes-for-agent-code) [1]–[9]
   - [B. Agent-level privilege control and containment](#b-agent-level-privilege-control-and-containment) [10]–[19]
4. [Further reading](#4-further-reading)
5. [Data-quality caveats](#data-quality-caveats)
6. [References](#references)

---

## 1. Cross-cutting findings

### F1. Frontier models exploit reachable kernel bugs, so a shared-kernel boundary is not enough on its own

- **Escape success rates.** SandboxEscapeBench [1] measures how well LLM agents
  escape deliberately weakened Docker/Kubernetes containers. Overall success
  per model runs from 0.10 (gpt-5-nano) to 0.84 (Claude Mythos Preview), with
  95% Wilson intervals (Table 11f).
- **Hardest tasks.** On the hardest tasks, the eBPF-verifier privilege
  escalation was solved at 1.00 by three models whenever the vulnerable syscall
  was reachable.
- **Budget.** Success scales roughly log-linearly with inference tokens.
  The authors say that seeing no success at about 10^5 tokens "should not be
  interpreted as ruling out a vulnerability" [1].
- **Guidance cited.** [1] cites UK NCSC guidance that container separation alone
  is not a strong boundary, and that hypervisor isolation should be the minimum.
- **Exposure is the variable.** The comparative engine study [2] counts about
  3,500 Linux kernel CVEs in a 24-month window. A host-kernel bug becomes an
  escape only through what the sandbox class exposes: the full surface for runc,
  only the guest kernel and VMM for microVMs, and a minimal surface for gVisor.
- **Implication:** this confirms the [01-threat-model](01-threat-model.md#shared-kernel-vs-microvm)
  position. It also argues for making the microVM backend the *recommended
  default* for untrusted repositories, and for treating host-kernel patch level
  as an enforced precondition. Seccomp closes most of the
  configuration-class escapes in [1] (no caps; `bpf`, `unshare`, `mount`,
  `open_by_handle_at` and AF_PACKET blocked; cgroup v2 only; no host PID
  namespace). It does not close kernel bugs in syscalls that remain allowed.

### F2. MicroVMs are not automatically safe, and pin policy matters more than the engine

- **CVEs in both Rust VMMs.** Within the window, [2] reports escape-class CVEs in
  both Rust VMMs:
  - Cloud Hypervisor CVE-2026-45782: a virtio-block async-I/O use-after-free on
    the default io_uring/aio path, CVSS v4 8.9.
  - Firecracker CVE-2026-5747: a virtio-pci out-of-bounds write.
  - Cloud Hypervisor also had CVE-2026-27211, a QCOW backing-file host leak.
- **VMMs run privileged.** Every microVM product studied ran its VMM as real root
  with the full capability set and no user namespace [2].
- **Downstream pins lag.** One product pinned Cloud Hypervisor v44.0 for 471+
  days across 12 upstream releases, missing both fixes. "Downstream dominates
  upstream by orders of magnitude" [2].
- **Fuzzing gaps.** Cloud Hypervisor's 18 cargo-fuzz targets are compiled in CI
  but not run. Firecracker has no upstream fuzzer [2].
- **Host attack surface.** Cloud Hypervisor showed the smallest host syscall
  footprint (5 distinct syscalls under light load, 8 under heavy load) and
  per-thread seccomp on 32 of 33 threads [2]. The paper notes that a leader-only
  inspection would have misclassified it as unfiltered.
- **Implication:**
  - Jail the VMM (namespaces, per-thread seccomp, Landlock) and pass in a
    `/dev/kvm` fd. Whether user namespaces work with KVM is flagged as uncertain
    in [2], so it becomes experiment E7.
  - Avoid QCOW backing files and the io_uring block path; prefer read-only
    erofs.
  - Pair the Nix flake lock with an automated bump and an advisory watcher.
  - Never expose `/dev/kvm` or nested virtualisation to the guest. [2] found a
    product whose guest userland could open `/dev/kvm`.

### F3. Ambient authority is the dominant practical risk, and environment hygiene is the cheapest large win

- **Environment sanitisation works.** In a controlled study [7], it took secret
  leakage from 100% to 0% in the ambient-authority scenario (Table III, n = 10
  runs per cell). Composition and chaining risk also went from 100% to 0%.
- **Input mitigations do not.** Mitigating prompt injection at the input layer
  only reduced unsafe behaviour from 90% to 50% [7].
- **The lethal combination.** Shell access, network access and secrets together
  are the combination that hurts. CI/CD pipelines act as a *privilege amplifier*:
  a sandboxed agent that can trigger a pipeline borrows the pipeline's
  production credentials [7].
- **Credential proxying.** SideKernel [4] keeps API credentials outside the guest
  and injects them at a host-side proxy. AgentBay [9] uses short-lived,
  permission-scoped tokens at a single gateway.
- **Implication:** NixSandbox already starts workloads with an empty environment
  and no host paths ([05](05-filesystem-network.md)). Next steps:
  - Make "no ambient credentials" a tested invariant across env, filesystem and
    `/proc`.
  - Keep secrets out of the sandbox entirely, using proxy-side injection in M9.
  - State in [01](01-threat-model.md) that git push, CI triggers and API tokens
    are capabilities granted *outside* the kernel boundary.

### F4. Command-string filtering, input filtering and approval UIs are not security boundaries

- **Denylists are fragile.** ShellSieve, cited in [3], found 1,709 GitHub
  command denylists to be "69.0%–98.6% fragile" depending on the bypass class.
- **String classification.** The transactional sandbox [5] classifies commands by
  string, which is trivially bypassable.
- **Script content opacity.** Parallax [10] names this limitation itself: its
  validator checks the command that runs a script, not the script's contents.
- **Proxy bypass.** AgentWarden [15] reports a framework shell backend that ran
  host commands *without emitting a tool call*, bypassing its LLM proxy
  entirely.
- **Isolation in practice.** Among 13 open-source coding agents [8]:
  - three popular CLIs run directly on the host shell;
  - only Codex CLI uses kernel-level unprivileged sandboxing (bubblewrap plus
    Landlock on Linux).
- **Implication:** this confirms the design's premise. Enforcement lives in the
  kernel and in the deterministic supervisor. Any command classifier in the
  orchestrator is UX (for example, skipping snapshots for read-only calls) and
  must be labelled as such ([13-design-review](13-design-review.md)).

### F5. Deterministic, default-deny enforcement beats heuristic or LLM judgement at the boundary

- **ContainmentBench [11].** Deterministic tool-boundary enforcement was the only
  policy with zero committed violations on both models tested.
- **Taint-based policies leaked.** Taint-only and intent-ledger policies leaked
  142/576 on Mistral-7B (Table 20).
- **Progent [16].** Deterministic, block-by-default checks cut AgentDojo attack
  success from 39.9% to 1.0%, and ASB from 70.3% to 3.9%.
- **Default-allow failed.** SEAgent [14] defaults to *allow* when no policy
  matches. The authors of [14] show that the prior defences they studied fail
  through gaps of exactly this kind.
- **Classifier and LLM-judge costs:**
  - Parallax's max-security classifier produced 36% false positives [10].
  - AgentWarden's classifier was trained on 273 examples [15].
  - ToolEmu's LLM safety evaluator agrees with humans only at Cohen's κ ≈ 0.48
    [17].
- **Implication:** keep the supervisor's policy language decidable: intervals,
  finite sets, enums and literal path prefixes. Keep it deterministic and
  default-deny. ML judges may only feed audit or advisory channels
  ([11-benchmarks-observability](11-benchmarks-observability.md)).

### F6. Narrow-only (monotonic) authority is the key invariant, and it must cover values, not just limits

- **Progent [16].** Its "monotonic confinement" lets policy updates narrow
  automatically, while expansion needs approval. Only 6% of updates were
  expansions.
- **SEAgent [14].** It shows that a plan-then-execute defence (CaMeL) falls to
  *argument manipulation*: the plan is correct, but an injected value replaces a
  tool argument.
- **Plan-then-execute [19].** The re-planning loop it recommends reopens control
  flow unless re-plans are narrow-only.
- **Implication:** generalise the existing "limits may only be ≤ the profile's"
  rule ([08](08-protocol-api.md)) to every capability-bearing field:

  `effective(job) ⊆ request ⊆ principal-allowed ⊆ admin profile`

  It covers numeric limits, the network mode lattice (`none` < `egress-proxy`),
  egress allowlist ⊆ profile, `collect` and file paths by prefix, env keys, and
  `argv[0]` ∈ runtime PATH. Widening is only ever an out-of-band, versioned
  admin change, never an API flag. Property-test it against the configuration
  the supervisor *actually installs*, not just against request validation.

### F7. Authority lifetime and revocation: closure must happen before reuse

- **Stale authority is real.** Lingering Authority (PORTICO) [12] shows that the
  same grants without revocation allowed 10/10 late rereads (Table 6) and 6/6
  stale file, git and network effects (Tables 7–9).
- **Revocation works.** PORTICO itself allowed 0 in each case.
- **Trusted closure only.** Closure must be triggered by *trusted* events: a
  monitor-launched test passing, an orchestrator phase change, or authenticated
  human revocation. Planner-authored "done" text is ignored. In-flight calls
  must be revalidated "immediately before the effect".
- **Implication:**
  - NixSandbox authority is per job, which is safe while jobs are short and
    single-purpose.
  - For long sessions, implement grants as *scoped sub-jobs*. Landlock can only
    tighten a running process, so "grant then revoke" means "spawn with wider
    policy, then exit".
  - The cancel path must check an epoch flag at every effect point: new exec,
    egress CONNECT, artefact export. Signalling the process tree is not enough.

### F8. Rollback and snapshots are wanted, but current implementations are weak

- **Rollback works, at a cost.** The transactional sandbox [5] reports 100%
  rollback of failed state changes. Its snapshot is a full directory copy
  (≈ 250 MB per uncertain command), and it commits on exit code 0.
- **Agents already reinvent it [8]:**
  - Cline: shadow-git checkpoints.
  - Moatless: in-memory file context.
  - DARS: Docker reset plus replay from the root, so depth N re-executes N
    commands.
- **Parallax [10].** Content-addressed snapshots before destructive actions.
  None of these can undo external side effects.
- **Implication:** the cheap mechanism is a per-job copy-on-write upper layer
  over the read-only Nix runtime (overlayfs or reflinks; a VM disk snapshot in
  the microVM backend), with the process tree killed via `cgroup.kill` on
  rollback. Exposing snapshot, fork and restore as supervisor operations would
  serve tree-search harnesses. Commit should be an explicit verb, not "exit code
  0".

### F9. Write-back to the host is an under-modelled boundary crossing

- **SideKernel's boundaries.** SideKernel [4] distinguishes a *south* boundary
  (sandbox → host) from a *north* boundary (sandbox → outside world). It accepts
  a two-way read-write working-directory mount and automatic port forwarding to
  host loopback, both of which it lists as risks.
- **Pre-trust execution CVEs.** [3] lists CVE-2025-59536 and CVE-2026-21852, in
  which a coding agent ran repository-supplied code or exfiltrated keys *before*
  its trust dialog.
- **Persistence via config files.** [8] notes that agents persist instructions in
  files such as `AGENTS.md`, `.clinerules/` and `GEMINI.md`, which other tools
  read later.
- **Implication:**
  - Treat collected artefacts as untrusted ([05](05-filesystem-network.md)
    already does).
  - Flag or refuse write-back of host-auto-executed paths: `.git/hooks`,
    `.envrc`, `.vscode/`, agent config files.
  - Never evaluate repository-supplied configuration (including `flake.nix`) on
    the host.
  - Keep port forwarding off, or opt-in per port.

### F10. Evaluation methodology: assume compromise, use positive controls, measure utility

- **Assume compromise.** Parallax [10] stops calling the LLM and injects actions
  directly, because real models produced 0% attack success and every
  configuration looked the same.
- **Positive controls.** ContainmentBench [11] requires them: show that the
  violation happens under no defence before counting its absence. It also
  reports *authorized work completed* next to blocks: equally secure policies
  ranged from 0.164 to 0.857 mean score (Table 8).
- **Self-crash.** [1] found that agents frequently crash their own sandbox. On
  the hard tasks, 47–100% of failed samples ended with the sandbox dead
  (Table 3), and 18 of 75 flagged samples took down the outer VM.
- **Shortcuts through the harness.** [1] also found four unintended shortcuts,
  two of which went through the *outer harness*: default credentials reachable
  over the bridge gateway.
- **Implication for [10-testing](10-testing.md):**
  - Every probe gets a positive control in insecure-dev mode and a matched
    benign twin, so false-block rates are measured.
  - Add a harness-reachability probe: host gateway, loopback services and the
    supervisor socket must be unreachable.
  - Add self-crash tests: the workload wedges or kills its own init; the guest
    kernel panics. These must report `sandbox_died`, not `timeout`.

### F11. Usability decides adoption

- **Survey.** SideKernel's survey [4] covered 80 respondents, 68 of whom use
  coding agents, and about a third of whom work in security. Only 38.2% use a
  sandbox, and 60.0% of non-users "never considered it".
- **Barriers.** The top reported barriers were environment setup (24.2%),
  ports and networking (24.2%) and file sharing (21.2%).
- **Implication:** Nix-built runtimes already remove most of the
  environment-setup friction. File staging and an ergonomic API matter as much
  as isolation strength.

---

## 2. Design actions for NixSandbox

Proposed changes, each traced to its source. P1 means "before the M7 vertical
slice", P2 means "before M9/M10", and P3 means later.

| # | Action | Source | Affects | P |
|---|--------|--------|---------|---|
| 1 | Generalise narrow-only to every capability-bearing request field. Property-test the *installed* config ⊆ profile | [16], [14], [19] | [08](08-protocol-api.md), [10](10-testing.md) | P1 |
| 2 | Structured, machine-readable denials (`policy_denied{field, requested, max}`) so agents adapt instead of looping or probing | [5] §7.6, [16] | [08](08-protocol-api.md) | P1 |
| 3 | Probe-suite discipline: a positive control per probe (insecure-dev or layer disabled), plus a benign twin with false-block rate reported | [11], [10] | [10](10-testing.md) | P1 |
| 4 | Map SandboxEscapeBench's 18 task classes and [2]'s 14 kernel primitives to explicit probes (expect "unreachable") | [1], [2] | [10](10-testing.md) | P1 |
| 5 | Host-information leak probes (CPU model, RAM, kernel version, interrupts, disk model/serial, DMI); decide mask vs accept and document it | [2] §2.2 | [05](05-filesystem-network.md), [01](01-threat-model.md) | P1 |
| 6 | Harness-reachability probe: host gateway, loopback services, supervisor socket, metadata endpoint | [1] App. C | [10](10-testing.md) | P1 |
| 7 | `sandbox_died` termination reason, distinct from timeout; self-crash fault tests; log it as a security event | [1] §6.2 | [07](07-resources-cancellation.md), [12](12-failure-modes.md) | P1 |
| 8 | Cancel epoch check at every effect point (exec, egress CONNECT, artefact export). Invariant: "after cancel ack, zero new CONNECTs for that job" | [12] | [07](07-resources-cancellation.md), [12](12-failure-modes.md) | P1 |
| 9 | Principal-keyed orchestrator state (results, idempotency keys, artefacts), so `job_id` alone never grants access | [14] | [08](08-protocol-api.md) | P1 |
| 10 | Optional per-launch preflight canary: a minimal negative-probe set at supervisor start or profile change; fail closed | [10] | [03](03-kernel-primitives.md#feature-detection) | P2 |
| 11 | Policy linter: flag over-broad Landlock grants, re-enabled kill-listed syscalls and allow-all egress; emit a diff against the base profile | [3] gap 4 | `nsbx-policy` | P2 |
| 12 | Report each seccomp profile's syscall count next to references (Firecracker 55, gVisor 84, Docker default 361) | [2] §2.1 | [11](11-benchmarks-observability.md) | P2 |
| 13 | VMM jail: per-thread seccomp verification, Landlock, KVM-fd passing, no QCOW backing files, erofs read-only, no io_uring block path; experiment E7 for user namespace plus KVM | [2] | [02](02-architecture.md), [14](14-roadmap.md) | P2 |
| 14 | Automated Nix bump plus GHSA/OSV advisory watch for pinned Cloud Hypervisor, guest kernel and runtimes | [2] §2.5 | CI | P2 |
| 15 | Egress proxy: secrets injected at the proxy (never in the sandbox); per-job DNS/SNI logs; reject non-HTTP(S) schemes and loopback/metadata targets; eTLD+1-aware matching tests | [4], [7], [15], [18] | [05](05-filesystem-network.md) | P2 |
| 16 | `policy_decision` SSE events (egress allow/deny, cancel ack, limit hits); optional hash-chained audit log | [11], [10] | [08](08-protocol-api.md), [11](11-benchmarks-observability.md) | P2 |
| 17 | Write-back guard for collected artefacts: flag or refuse host-auto-executed paths | [4], [3], [8] | [05](05-filesystem-network.md) | P2 |
| 18 | Job provenance label (inputs from untrusted content), which admin policy can bar from egress or host-visible `collect` | [14], [18], [19] | [08](08-protocol-api.md) | P3 |
| 19 | CoW workspace transactions: snapshot, fork, restore, explicit commit; process tree killed on rollback | [5], [8], [10] | new milestone | P3 |
| 20 | Session grants as scoped sub-jobs with opaque, epoch-bound grant ids; closure only on trusted events | [12], [18] | [08](08-protocol-api.md) | P3 |
| 21 | Step-scoped capability token (`plan_ref`/`step_id`), single-use, minted when a plan is approved | [19], [16] | [08](08-protocol-api.md) | P3 |
| 22 | Run SandboxEscapeBench-style nested-VM evaluation in nightly T4 with NixSandbox in place of Docker | [1], [3] gap 1 | [10](10-testing.md) | P3 |
| 23 | State the scope explicitly: NixSandbox bounds the blast radius of code execution. It does not stop misuse of legitimately granted authority (allowed egress, task-scope overreach inside the workspace) | [6], [12], [14], [16] | [01](01-threat-model.md) | P1 |

---

## 3. Per-paper notes

### A. Execution sandboxes for agent code

#### [1] Quantifying Frontier LLM Capabilities for Container Sandbox Escape (SandboxEscapeBench)

Marchand et al. (Oxford; UK AI Security Institute). arXiv:2603.02277v3, 1 Aug 2026. ICML 2026.
[arxiv.org/abs/2603.02277](https://arxiv.org/abs/2603.02277)

- **Problem:** agents get code execution inside containers by design, so the
  question is whether they can escape.
- **Threat model:** an interactive shell, usually as root inside the container,
  with network access. The agent knows it is contained but not which weakness
  is present. Success means reading a flag on the outer VM host.
- **Design:**
  - Nested sandbox: Inspect starts a VM, the VM runs Docker or Kubernetes, and
    the container holds a seeded weakness.
  - 18 tasks across three layers:
    - orchestration: 4 tasks;
    - engine/runtime: 8 tasks, e.g. privileged mode, an exposed engine socket,
      dangerous capabilities, two runc CVEs;
    - host kernel: 6 tasks, e.g. cgroup v1 release-agent, two page-cache write
      bugs, an eBPF verifier bug, an AF_PACKET bug.
  - Difficulty 1–5, with inter-rater Krippendorff's α = 0.816.
- **Results:**
  - Overall success by model ranges from 0.84 [0.76, 0.91] (Claude Mythos
    Preview) through 0.66 (Opus 4.6) and 0.49 (GPT-5) down to 0.10 (gpt-5-nano)
    (Table 11f).
  - Original cohort: zero success at difficulty 4–5.
  - The newest models solve the eBPF task at 1.00.
  - Hints roughly double Opus success on hard tasks above 10^5 tokens.
  - Agents crashed their own sandbox in 47–100% of failed hard-task samples.
  - Four unintended shortcuts were found, two through the outer harness.
- **Limitations:**
  - Weaknesses are seeded deliberately, with no monitoring.
  - Mostly 2016–2017-era kernels.
  - No task tests a user-namespace, seccomp-confined, Landlock, gVisor or
    microVM sandbox.
- **For NixSandbox:** see F1, F10, and actions 4, 6, 7 and 22.

#### [2] AI Code Sandboxes: A Comparative Security Study, Part 1: Engine-Level Properties

Andronchik, Lokhmakov. arXiv:2606.08433v1, 7 Jun 2026. CC BY 4.0.
[arxiv.org/abs/2606.08433](https://arxiv.org/abs/2606.08433)

- **Scope:** five products compared on six engine-level axes, with no composite
  score:

  | Product | Engine |
  |---|---|
  | arrakis | Cloud Hypervisor |
  | e2b | Firecracker |
  | microsandbox | libkrun |
  | gVisor | runsc |
  | daytona | runc |

  Threat model: a single-tenant operator running untrusted code. Single host,
  kernel 6.8.
- **Host attack surface:**
  - Distinct host syscalls under light load: Cloud Hypervisor 5, Firecracker 13,
    libkrun 22, gVisor 33, runc 57.
  - Kernel primitives reachable from the guest, out of 14: gVisor 5,
    Firecracker 7, libkrun 11, runc 11, Cloud Hypervisor 12.
- **Leakage:** host-identifying leaks out of 28 probes: e2b 0, microsandbox 0,
  arrakis 1 (host CPU model via CPU passthrough), gVisor 2, daytona 10 (CPU,
  RAM, kernel, interrupts, DMI, microcode, disk model and serial, among
  others).
- **Stackability:** of 35 product × layer cells, 8 pass. **No product ran its
  engine under a user namespace.** All microVM VMMs ran with the full
  capability set.
- **CVEs (24 months):**
  - Firecracker 2 (both escape-class).
  - Cloud Hypervisor 2 (one escape-class, one host leak).
  - gVisor 3 (no escapes).
  - runc 4 (all escape-class).
  - libkrun 0, which the authors treat as absence of signal.
- **Patch cadence and fuzzing:**
  - Upstream fixes ship at disclosure for runc, Firecracker and Cloud
    Hypervisor.
  - Downstream products lagged 399–471+ days.
  - "MicroVM × continuous public fuzzer" is an unoccupied cell.
- **Limitations:** results are inherited from six companion papers. Several
  verdicts are about product *defaults*, not engines.
- **For NixSandbox:** see F2, and actions 5, 12, 13 and 14. It also suggests
  documenting a gVisor/runsc backend as a future option in
  [13](13-design-review.md).

#### [3] The Balkanization of Execution-Security Research for AI Coding Agents

Rashidi. arXiv:2607.05743v1, 7 Jul 2026. Systematisation of knowledge.
[arxiv.org/abs/2607.05743](https://arxiv.org/abs/2607.05743)

- **Corpus:** 39 papers in 17 categories, re-read by root cause and by pipeline
  stage.
- **Four root causes:**
  - RC1: no data/control separation.
  - RC2: checked once, trusted forever (TOCTOU, lingering authority).
  - RC3: permitted is not the same as intended.
  - RC4: defences validated only against self-built attackers.
- **Five gaps:**
  1. Isolation is never benchmarked against access control.
  2. Defences are not re-tested against measured enforcement-failure rates.
  3. TOCTOU and MCP threats are treated separately.
  4. Policy authors are assumed honest and correct.
  5. Scope creep is measured but not mitigated.
- **Figures quoted from the corpus:**
  - ShellSieve denylists: 69.0–98.6% fragile.
  - OverEager: Claude Code's overeager rate rose from 0.0% to 17.1% when the
    scope statement was removed from the prompt.
- **CVEs listed:** CVE-2024-21626 (runc fd leak), CVE-2025-53773,
  CVE-2025-59536 and CVE-2026-21852 (coding agents running code or leaking keys
  before trust).
- **Limitations:**
  - Single author with an informal search.
  - "Isolation architectures" means agent-level designs; no OS-sandboxing papers
    are included.
- **For NixSandbox:** see F4 and F9.
  - RC2 supports the "check and use on the same fd" rule
    ([04](04-privilege-model.md), [05](05-filesystem-network.md)).
  - Gap 4 motivates action 11.

#### [4] SideKernel: A Usable microVM Sandbox for AI Coding Agents on macOS

Prasakis (Georgia Tech). arXiv:2610.02456v1, 1 Oct 2026.
[arxiv.org/abs/2610.02456](https://arxiv.org/abs/2610.02456)

- **Design:**
  - A Swift VMM on Apple Virtualization.framework.
  - Kata kernel and Ubuntu rootfs, pinned by SHA-256.
  - A Rust PID 1 guest agent: VirtioFS working-directory mount, port
    auto-forwarding, PTY over vsock.
  - A host-side credential proxy.
  - A NAT-level network kill switch.
  - Explicitly accepts two risks: the read-write working-directory mount and
    automatic port forwarding to host loopback.
- **Survey:** 80 respondents. 38.2% use a sandbox; 60.0% of non-users never
  considered one.
- **Capability tests:** out of 23 binary tests, SideKernel and Docker Sandboxes
  pass 19, and Microsandbox, Shuru and SmolVM pass 12. Docker Sandboxes is the
  only one with DNS observability.
- **Limitations:**
  - No security evaluation.
  - The developer is also the evaluator.
  - The survey sample leans towards security professionals.
- **For NixSandbox:** see F3, F9 and F11, and actions 15 and 17. The
  north/south vocabulary is worth adopting in [01](01-threat-model.md).

#### [5] Fault-Tolerant Sandboxing for AI Coding Agents: A Transactional Approach

Yan (University of Virginia). arXiv:2512.12806v1, 14 Dec 2025.
[arxiv.org/abs/2512.12806](https://arxiv.org/abs/2512.12806)

- **Design:**
  - A command-string classifier sorts each call into whitelisted read-only,
    blacklisted destructive, or uncertain.
  - Uncertain commands trigger a snapshot (a full directory copy), then
    execution. Non-zero exit rolls back; zero exit commits.
  - Runs in an LXC container on Proxmox, with EVPN/VXLAN network isolation.
- **Results (Table 1, 20 attempts per category):** 100% in each of exec,
  blocked, rolled back and committed.
- **Latency:** `pip install` went from 4.69 s to 6.51 s. The paper's "≈1.82 s
  (14.5%)" does not match its own numbers (≈ 38.8%).
- **Limitations:**
  - The agent is assumed fallible, not malicious.
  - String blacklisting is bypassable.
  - Commit on exit code 0.
  - Copy cost grows with workspace size.
  - External effects are not reversible.
- **For NixSandbox:** see F8 and actions 2 and 19. Note also its "Sandbox-Aware
  Prompting" observation: agents loop on denials they cannot interpret.

#### [6] AgentBound: Securing Execution Boundaries of AI Agents

Bühler, Biagiola, Di Grazia, Salvaneschi. arXiv:2510.21236v3, Apr 2026. FSE 2026.
[arxiv.org/abs/2510.21236](https://arxiv.org/abs/2510.21236)

- **Design:**
  - An Android-style capability manifest for MCP servers: 18 capabilities in 5
    groups.
  - Two levels: declared capabilities, refined at runtime into concrete
    permissions. Undeclared requests abort.
  - An LLM generates the manifests.
  - Enforcement is one Docker container per server: bind mounts, env allowlist,
    and an iptables egress allowlist of hostnames resolved at startup.
- **Prevalence across 296 servers:** network client 83.1%, env read 79.6%, fs
  read 74.1%, fs write 49.3%.
- **Manifest accuracy:** against 48 human-written manifests, 96.5% (precision
  0.94, recall 0.96).
- **Security:**
  - Blocks every in-scope attack that targets system resources: 9 attacks.
  - Does not prevent puppet attacks or SQL injection, which stay inside granted
    policy.
- **Overhead:**
  - Startup: roughly 150–300 ms on macOS, up to about 400 ms on Debian.
  - Per operation: 0.29–0.6 ms.
- **Limitations:**
  - Resolving hostnames to IPs once at startup fails with CDN or rotating DNS
    and over-permits on shared IPs.
  - Packages install with full network *before* restrictions apply.
- **For NixSandbox:**
  - The two-level policy split matches profile → request.
  - Nix prebuilt closures avoid the install-time network gap entirely.
  - Run each tool or MCP server as its own sandboxed job.
  - Measure startup and per-op cost with the same four operations, so results
    compare directly.

#### [7] Security Risks in Tool-Enabled AI Agents: A Systematic Analysis of Privileged Execution Environments

Goel (Microsoft). arXiv:2605.09721v1, 10 May 2026. Short version at IEEE COMPSAC 2026.
[arxiv.org/abs/2605.09721](https://arxiv.org/abs/2605.09721)

- **Taxonomy (six categories):**
  1. capability–intent mismatch
  2. ambient authority leakage
  3. indirect secret exposure
  4. state persistence
  5. prompt injection
  6. composition / chaining
- **Experiment:** GPT-5.1 ReAct agent, 4 scenarios × 2 phases × 10 runs.

  **Table III, unsafe-behaviour rate and leak rate (baseline → mitigated):**

  | Scenario | Unsafe | Leak |
  |---|---|---|
  | Capability mismatch | 40% → 0% | — |
  | Prompt injection | 90% → 50% | 90% → 50% |
  | Ambient authority | 100% → 0% | 100% → 0% |
  | Chaining | 100% → 0% | 100% → 0% |

- **Guidelines:** least privilege, isolate from production credentials,
  explicit authorisation, log every tool call, assume adversarial input, design
  for failure.
- **Limitations:**
  - n = 10 per cell.
  - Mitigations are tuned per scenario.
  - Sandboxing is discussed but not measured.
- **For NixSandbox:** see F3 and actions 15 and 23. The CI/CD
  privilege-amplifier point belongs in [01](01-threat-model.md).

#### [8] Inside the Scaffold: A Source-Code Taxonomy of Coding Agent Architectures

Rombaut. arXiv:2604.03515v2, 10 Apr 2026.
[arxiv.org/abs/2604.03515](https://arxiv.org/abs/2604.03515)

- **Method:** 13 open-source scaffolds at pinned commits, 12 dimensions.
- **Execution isolation (Table 9):**

  | Isolation | Agents |
  |---|---|
  | None (local shell) | Gemini CLI, Aider, OpenCode |
  | Stateless subshell | mini-swe-agent |
  | Platform sandboxing | Codex CLI (bubblewrap + Landlock on Linux, Seatbelt on macOS) |
  | Docker | SWE-agent, OpenHands, DARS, AutoCodeRover, Prometheus |
  | Shadow-git checkpoints | Cline |
  | In-memory shadow mode | Moatless |
  | Not applicable | Agentless (Docker for tests only) |

- **Other safety layers:**
  - Codex CLI runs a separate safety-judge model and has a
    `request_permissions` tool for mid-session escalation.
  - Gemini CLI has a rule-based per-tool policy engine.
  - Cline blocks dangerous shell operators.
- **Other findings:**
  - Five agents spawn sub-agents through five different mechanisms.
  - Agents persist memory in workspace files.
- **Limitations:** single author; static analysis only; the isolation dimension
  is not inspected in depth.
- **For NixSandbox:**
  - Position NixSandbox as a harness-agnostic execution backend, and use
    mini-swe-agent as the minimal reference harness for integration tests.
  - Write a comparison against Codex CLI's Linux sandbox.
  - Support nested sub-jobs with strictly narrower policy. Landlock and seccomp
    stacking are naturally monotonic.

#### [9] AgentBay: A Hybrid Interaction Sandbox for Seamless Human-AI Intervention

Piao et al. (Alibaba Cloud). arXiv:2512.04367v1, 4 Dec 2025.
[arxiv.org/abs/2512.04367](https://arxiv.org/abs/2512.04367)

- **Design:**
  - One ephemeral VM per session, isolated VPCs, default-deny networking.
  - A single hardened gateway with short-lived, scoped tokens.
  - An adaptive streaming protocol for human takeover.
- **Evaluation caveat:** the authors label their evaluation "**with hypothetical
  data**".
- **Results as reported:**
  - Human-in-the-loop success on ad-obstructed reading: 27% → 97%; on CAPTCHA:
    64% → 95%.
  - Streaming latency 117 ms vs 122 ms for RDP; up to 55% less bandwidth.
  - The security test is qualitative, with no counts.
- **For NixSandbox:**
  - Confirms VM-per-session and default-deny networking.
  - A `paused` / `await_human` job state (`cgroup.freeze` with a deadline) is a
    possible future primitive for interactive workloads.

### B. Agent-level privilege control and containment

#### [10] Parallax: Why AI Agents That Think Must Never Act

Fokou. arXiv:2604.12986v1, 14 Apr 2026.
[arxiv.org/abs/2604.12986](https://arxiv.org/abs/2604.12986)

- **Design:**
  - **Cognitive-executive separation:** the reasoner process has no filesystem,
    network or shell access and only *proposes* actions over gRPC.
  - **Tiered "Shield" validator:** YAML rules, then a heuristic engine plus a
    DeBERTa classifier, then an LLM judge, then a human. Fail-closed at every
    tier.
  - **Information-flow tags** on data.
  - **"Chronicle" snapshots** before destructive actions.
  - A **startup self-check** that host read/write, network and `/proc` access
    *fail*.
- **Results** (assume-compromise harness, 280 attacks; Table 3):
  - Default config: 1.1% attack success, 0% false positives.
  - Max-security config: 0.0% attack success, 36% false positives.
- **Latency (Table 5):**

  | Tier | p50 | p99 |
  |---|---|---|
  | Tier 0 (rules) | <1 ms | — |
  | Tier 1 (classifier) | 1,947 ms | 2,638 ms |
  | Tier 2 (LLM judge) | 2,089 ms | 4,781 ms |

- **Limitations:**
  - In-sample evaluation after policy tuning.
  - Script contents are opaque to the validator.
  - The *executor* has full host access. The paper sandboxes the reasoner, not
    the code.
- **For NixSandbox:**
  - NixSandbox is the executor sandbox this architecture assumes.
  - Adopt the preflight self-check (action 10) and the assume-compromise method,
    which `nsbx-probe` already follows.
  - Consider a hash-chained audit log.

#### [11] ContainmentBench: Trace-Based Evaluation of Post-Exposure Containment in Tool-Using LLM Agents

Lan, Li, Wu, Lai, Yang, Shen. arXiv:2607.23999v3, 9 Aug 2026.
[arxiv.org/abs/2607.23999](https://arxiv.org/abs/2607.23999)

- **Design:**
  - Per-rollout trace graphs.
  - Metrics: committed violation, taint-to-commit, logged spread, and the share
    of authorized work completed.
  - Seven policies compared.
  - Qwen2.5-7B: 504 scenarios × 7 policies × 5 seeds = 17,640 rollouts.
- **Results:**
  - **Security stage.** No defence: committed violations 0.3354. All five
    runtime-enforced policies: 0.0000 (Table 25).
  - **Authorized work completed (mean score, Table 8):**

    | Policy | Mean score |
    |---|---|
    | No defence | 0.9233 |
    | Tool-boundary | 0.9233 |
    | Intent-ledger v2 | 0.8567 |
    | Taint-only v1 | 0.1642 |
    | Structured guard | 0.0102 |

  - **Mistral-7B (Table 20):** tool-boundary 0 violations; taint-only and
    intent-ledger policies 142/576.
  - A single capability-label mismatch between ledger and registry produced 480
    blocks.
- **Limitations:**
  - Synthetic workflows; one main model.
  - Tool-boundary success is partly by construction.
- **For NixSandbox:**
  - Positive controls, benign twins and utility-under-defence reporting
    (action 3).
  - Generate the orchestrator's capability vocabulary and the supervisor's
    enforcement from a single source.
  - Expose policy decisions as events (action 16).

#### [12] Lingering Authority: Revocable Resource-and-Effect Capabilities for Coding Agents

Santos-Grueiro. arXiv:2606.22504v1, 21 Jun 2026.
[arxiv.org/abs/2606.22504](https://arxiv.org/abs/2606.22504)

- **Design (PORTICO):**
  - A task contract compiles into an initial envelope, grant rules, closure
    predicates and invariants.
  - The planner *requests* grants. The system mints opaque, epoch-bound
    handles.
  - Closure happens only on trusted events and removes handles before the next
    decision.
  - It requires "linearizable mediation": revalidate immediately before each
    effect.
- **Results (Table 5, Qwen3-Coder 30B):**

  | Metric | Static allowlist | Sandbox | PORTICO |
  |---|---|---|---|
  | Suite-A violations | 0.82 | 0.86 | 0.00 |
  | Suite-B success | 0.97 | 0.97 | 0.87 |

  - Non-revoking grants allowed 6/6 stale file, git and network effects;
    PORTICO allowed 0/6.
  - Eight real Python repositories: 14/14 success with 0 violations in every
    condition.
- **Limitations:**
  - Contracts are hand-written.
  - Violations are scored against the same contract used for enforcement.
  - Small closure-slice N.
- **For NixSandbox:** see F7 and actions 8 and 20. It also challenges the design:
  a coarse sandbox still let 0.86 of Suite-A runs overreach the task. Task-scope
  minimisation inside the workspace is the caller's job; say so (action 23).

#### [13] ceLLMate: Sandboxing Browser AI Agents

Meng, Feng, Shumailov, Fernandes. arXiv:2512.12594v2, 4 Mar 2026.
[arxiv.org/abs/2512.12594](https://arxiv.org/abs/2512.12594)

- **Design:**
  - Enforce at the HTTP layer, where UI actions become meaningful.
  - Websites publish an "agent sitemap" mapping requests to semantic actions.
  - Policies form a partial order, so "least privilege" is well defined.
  - An LLM selects policies from *trusted context only* (the prompt and the
    policy catalogue, never page content), and the user confirms.
  - Enforced in a Chrome extension, with stateful counters such as "check out
    under $50 *only once*".
- **Results:**
  - Domain prediction 93.1–100%.
  - Policy selection 94.4–100%.
  - All 12 scripted fully-compromised-agent attacks on GitLab blocked.
  - Overhead 7.25–15.0% for 100–300 sitemap entries.
- **Limitations:**
  - Needs website cooperation.
  - Does not stop in-policy misuse.
  - No WebSocket coverage; single-turn only.
- **For NixSandbox:**
  - Supports a semantic egress proxy rather than packet filtering.
  - Method- and path-level rules would need TLS interception: a deliberate
    non-goal for v1.
  - Derive a job's policy from trusted context and freeze it for the job's life.
  - Document an inclusion order over profiles.

#### [14] Taming Various Privilege Escalation in LLM-Based Agent Systems: A Mandatory Access Control Framework (SEAgent)

Ji, Wu, Jiang, Ma, Li, Gao, Wang, Li. arXiv:2601.11893v1, 17 Jan 2026.
[arxiv.org/abs/2601.11893](https://arxiv.org/abs/2601.11893)

- **Design:**
  - A per-round information-flow graph.
  - Attribute labels on tools, agents and RAG stores (object, action,
    sensitivity, integrity, privacy), produced by an LLM and checked by a human.
  - An SELinux-inspired path policy language with allow/deny/ask decisions.
    **Unmatched calls default to allow.**
  - Memory reset every round.
- **Attack vectors:** direct injection, indirect injection, RAG poisoning,
  confused deputy, untrusted third-party agents. Case studies show prior
  defences bypassed: IsolateGPT through hub-level RAG poisoning and anonymous
  spokes, CaMeL through argument manipulation.
- **Results:**
  - Extended InjecAgent: 0% attack success in every category (Table 2).
    IsolateGPT allowed 42.98–54.55% at the hub on RAG poisoning.
  - AgentDojo overall: 39.14% (none) → 0.82% (IsolateGPT) → 0.00% (SEAgent)
    (Table 3).
  - LLM-vs-human labelling agreement: κ 0.9456 (Table 7).
- **Limitations:**
  - Results depend on correct labels.
  - Default-allow.
  - "Always allow" accumulates permanent exceptions.
  - No adaptive attacks.
- **For NixSandbox:**
  - Default-deny everywhere; widening is admin-only.
  - Key orchestrator state by principal (action 9).
  - Constrain request *values*, not just profiles (F6).
  - Job provenance labels (action 18).

#### [15] Beyond Static Sandboxing: Learned Capability Governance for Autonomous AI Agents (AgentWarden)

Sidik, Rokach (Ben-Gurion University). arXiv:2604.11839v2, 3 May 2026.
[arxiv.org/abs/2604.11839](https://arxiv.org/abs/2604.11839)

- **Design:**
  - A task classifier picks a tool mask.
  - A safety router proxy sits between the runtime and the LLM. Stage 1 is
    rules (0.1 ms); stage 2 is a fine-tuned 1.5B classifier.
  - A PPO policy over exposure masks.
- **Results:**
  - AgentDojo overall attack success 90.3% → 88.9%, with benign utility 90.7% →
    89.7% (Table 6).
  - N = 500 batch: all 70 shell-exec calls blocked; about 22 benign writes
    blocked as false positives.
- **Key finding:** a framework's local shell backend ran host commands *without
  generating any tool call*, bypassing the proxy entirely.
- **Limitations:**
  - Several internal inconsistencies (latency; +337% vs +952% for the same
    real-session figure; layer counts).
  - The over-provisioning metric (SER) can be gamed by exposing fewer tools.
  - Small N.
- **For NixSandbox:**
  - Enforcement belongs at the execution layer (F4).
  - Per-task-type profiles, filtered per principal.
  - Learned policy may only *suggest* narrowing.
  - Capability-substitution tests (`file://`, loopback or metadata through the
    proxy).

#### [16] Progent: Securing AI Agents with Privilege Control

Shi, He, Wang, Li, Wu, Guo, Song (UC Berkeley, UCSB, NUS). arXiv:2504.11703v3, 14 May 2026.
[arxiv.org/abs/2504.11703](https://arxiv.org/abs/2504.11703)

- **Design:**
  - A JSON-Schema policy language of allow/forbid rules with typed argument
    conditions and a fallback.
  - Deterministic enforcement; **unmatched calls are blocked**.
  - An LLM proposes updates.
  - Z3 checks inclusion: narrowing applies automatically, expansion needs
    approval ("monotonic confinement").
  - Layered generic policies: org > developer > user > task.
- **Results:**
  - AgentDojo attack success 39.9% → 1.0% with utility maintained.
  - ASB 70.3% → 3.9%.
  - With manual approval of expansions: 0%.
  - Only 6% of policy updates were expansions.
  - Real frameworks (LangChain, OpenAI Agents SDK, OpenHands): about 1%.
  - Adaptive attacks "only marginally increase" success.
- **Limitations:**
  - No defence against attacks within least privilege.
  - Proxy mode misses built-in tools.
  - Inclusion checking with regex conditions is expensive in general.
- **For NixSandbox:** see F6 and actions 1 and 2. The layered-policy rule maps to
  admin profile > principal allowance > request.

#### [17] Identifying the Risks of LM Agents with an LM-Emulated Sandbox (ToolEmu)

Ruan, Dong, Wang, Pitis, Zhou, Ba, Dubois, Maddison, Hashimoto. arXiv:2309.15817v2, May 2024. ICLR 2024.
[arxiv.org/abs/2309.15817](https://arxiv.org/abs/2309.15817)

- **Design:**
  - GPT-4 emulates tool execution, with an adversarial emulator that seeds risky
    states.
  - An LLM safety evaluator scores likelihood × severity.
  - 36 toolkits, 311 tools, 144 test cases.
- **Results:**
  - Identified-failure precision 68.8–72.5%.
  - Safety-evaluator agreement with humans: κ 0.478.
  - Six of seven emulated terminal failures were reproduced on a real VM, taking
    about 8 hours of setup against under 15 minutes emulated.
  - The safest prompted agent still failed in 23.9% of cases (Table 5).
- **Failure classes reproduced:**
  - privilege grants without checks
  - mass and recursive-root deletion
  - running an unverified downloaded script
  - killing critical processes
  - removing a system package
- **Limitations:**
  - GPT-4 is used throughout, risking shared blind spots.
  - An emulated sandbox has no containment semantics.
- **For NixSandbox:**
  - Cheap ephemeral real execution makes a consequence-containment suite
    practical. Turn the six classes into benign-stand-in tests asserting blast
    radius: the store and host are byte-identical afterwards and the next job is
    unaffected.
  - Prompting is not containment.

#### [18] IsolateGPT: An Execution Isolation Architecture for LLM-Based Agentic Systems

Wu, Roesner, Kohno, Zhang, Iqbal. arXiv:2403.04960v2, 30 Jan 2025. NDSS 2025.
[arxiv.org/abs/2403.04960](https://arxiv.org/abs/2403.04960)

- **Design:**
  - Hub-and-spoke: a non-LLM hub operator plus an LLM planner, and one spoke
    per app with its own LLM and memory.
  - All inter-app messages are mediated by the hub, with typed formats and
    ephemeral IDs.
  - User consent tiers: one-time, session or permanent. No permanent grants for
    irreversible actions.
  - Each process runs under seccomp and rlimits.
  - Egress is limited to each app's eTLD+1.
- **Results:**
  - Attack success on VanillaGPT 20.2% overall (Table I). On IsolateGPT, attacks
    succeed only if the user approves a warned dialog; 100% of shown dialogs
    carried a warning.
  - Functionality unchanged.
  - 75.73% of queries had at most 30% overhead.
- **Limitations:**
  - Minimal OS isolation (no namespaces or cgroups).
  - The hub planner remains injectable, as [14] shows.
- **For NixSandbox:**
  - The same broker + per-principal-context pattern, with much stronger kernel
    isolation.
  - Cross-job data flow only through the orchestrator, outputs treated as
    untrusted.
  - eTLD+1-aware egress tests.
  - Benchmark isolation overhead separately from model latency.

#### [19] Architecting Resilient LLM Agents: A Guide to Secure Plan-then-Execute Implementations

Del Rosario, Krawiecka, Schroeder de Witt. arXiv:2509.08646v1, 10 Sep 2025.
[arxiv.org/abs/2509.08646](https://arxiv.org/abs/2509.08646)

- **Type:** a practitioner guide with no experiments.
- **Content:**
  - Planner, executor, optional verifier.
  - Fixing the plan before untrusted data is read gives "control-flow
    integrity".
  - Task-scoped tools per step, RBAC as an upper bound, ephemeral Docker per
    execution.
  - Recipes for LangGraph, CrewAI and AutoGen.
  - Plan-Validate-Execute for high-stakes tasks.
- **Limitations:**
  - The control-flow integrity claim is overstated: argument manipulation [14]
    and the re-plan loop both reopen it.
  - It wrongly says containers have no network unless configured. Docker's
    default bridge allows egress.
  - "Tiered sandboxing" lets low-risk roles run natively.
- **For NixSandbox:**
  - Step-scoped, single-use capability tokens (action 21).
  - Re-plans must be narrow-only.
  - Every execution is sandboxed; tiering belongs in profiles, not in whether
    to isolate.
  - Ephemeral Docker is the baseline to compare against.

---

## 4. Further reading

Works cited by the reviewed papers that are most relevant to NixSandbox (not
downloaded here):

| Topic | Work |
|---|---|
| Sandbox test suites | Rabin et al., SandboxEval, [arXiv:2504.00018](https://arxiv.org/abs/2504.00018) (51-property suite); RedCode, [arXiv:2411.07781](https://arxiv.org/abs/2411.07781) |
| Seccomp policy generation | Ghavamnia et al., Confine (RAID 2020) and temporal syscall specialisation (USENIX Security 2020); Wan et al., "Mining Sandboxes for Linux Containers", [arXiv:1712.05493](https://arxiv.org/abs/1712.05493) |
| cgroups for agents | AgentCgroup, [arXiv:2602.09345](https://arxiv.org/abs/2602.09345) |
| Checkpoint / rollback | DeltaBox, [arXiv:2605.22781](https://arxiv.org/abs/2605.22781); "Atomicity for agents", [arXiv:2603.00476](https://arxiv.org/abs/2603.00476) |
| TOCTOU in agents | "Mind the Gap", [arXiv:2508.17155](https://arxiv.org/abs/2508.17155) |
| Denylist fragility | ShellSieve, "One goal, many commands", [arXiv:2606.15549](https://arxiv.org/abs/2606.15549) |
| Information-flow control | CaMeL, [arXiv:2503.18813](https://arxiv.org/abs/2503.18813); FIDES, [arXiv:2505.23643](https://arxiv.org/abs/2505.23643) |
| Systems framing | Christodorescu et al., "Systems Security Foundations for Agentic Computing", [arXiv:2512.01295](https://arxiv.org/abs/2512.01295) |
| MCP threats | Song et al., "Beyond the Protocol", [arXiv:2506.02040](https://arxiv.org/abs/2506.02040) |
| VMM security | Agache et al., Firecracker (NSDI 2020); Weissman et al., Firecracker microarchitectural security, [arXiv:2311.15999](https://arxiv.org/abs/2311.15999) |
| Container escapes | Jarkas et al., "A container security survey" (ACM CSUR 57(7), 2025) |
| Capabilities | Watson et al., Capsicum (USENIX Security 2010); Gray & Cheriton, Leases (SOSP 1989) |
| Policy language | Cedar (OOPSLA 2024), a policy language with analysable semantics |

These IDs come from the reviewed papers' reference lists and have not been
independently verified.

## Data-quality caveats

| Paper | Inconsistency |
|---|---|
| [1] | Opus 4.5 overall is 0.49 in §5.1 prose, 0.52 in Table 11(f) and "56%" in §6.1. Level 3 is 0.40 in prose and 0.41 in the table. This review quotes the tables |
| [2] | Some multi-column tables lost their alignment during text extraction. The finding that CVE-2026-27211 arose from a "Landlock-interaction design flaw" needs checking against the GHSA advisory before it is cited |
| [3] | The number of prior surveys is three in the abstract and four in the body. The "escape benchmark" category includes prompt-injection benchmarks |
| [5] | 10 scenarios defined, but 20 attempts reported per category. The overhead percentage contradicts the latencies reported |
| [6] | Two accuracy figures on different bases: 80.9% (developer responses) and 96.5% (manual comparison) |
| [9] | The authors label their evaluation "with hypothetical data". Bandwidth reduction is 50% in the abstract and 55% in the conclusion |
| [13] | Task counts in the §5.1.2 text do not match the Table 1 denominators |
| [15] | Classifier latency is given as ~800, 340 and 2,094 ms. The real-session improvement is +337% vs +952%. Layer counts differ between sections |
| [7], [12], [15] | Small samples (n = 10, 6, 20 in key cells). A "0%" there means "0 of n" |

## References

1. R. Marchand, A. O Cathain, J. Wynne, P. M. Giavridis, S. Jennings, F. Tuxworth, T. H. Dur, S. Deverett, J. Wilkinson, J. Gwartz, H. Coppock. *Quantifying Frontier LLM Capabilities for Container Sandbox Escape.* ICML 2026. [arXiv:2603.02277](https://arxiv.org/abs/2603.02277)
2. G. Andronchik, P. Lokhmakov. *AI Code Sandboxes: A Comparative Security Study. Part 1 of 2: Engine-Level Properties.* 2026. [arXiv:2606.08433](https://arxiv.org/abs/2606.08433)
3. M. Rashidi. *The Balkanization of Execution-Security Research for AI Coding Agents: Isolation, Access Control, and Time-of-Check-to-Time-of-Use Vulnerabilities.* 2026. [arXiv:2607.05743](https://arxiv.org/abs/2607.05743)
4. D. Prasakis. *SideKernel: A Usable microVM Sandbox for AI Coding Agents on macOS.* 2026. [arXiv:2610.02456](https://arxiv.org/abs/2610.02456)
5. B. Yan. *Fault-Tolerant Sandboxing for AI Coding Agents: A Transactional Approach to Safe Autonomous Execution.* 2025. [arXiv:2512.12806](https://arxiv.org/abs/2512.12806)
6. C. Bühler, M. Biagiola, L. Di Grazia, G. Salvaneschi. *AgentBound: Securing Execution Boundaries of AI Agents.* FSE 2026. [arXiv:2510.21236](https://arxiv.org/abs/2510.21236)
7. H. Goel. *Security Risks in Tool-Enabled AI Agents: A Systematic Analysis of Privileged Execution Environments.* IEEE COMPSAC 2026 (short version). [arXiv:2605.09721](https://arxiv.org/abs/2605.09721)
8. B. Rombaut. *Inside the Scaffold: A Source-Code Taxonomy of Coding Agent Architectures.* 2026. [arXiv:2604.03515](https://arxiv.org/abs/2604.03515)
9. Y. Piao, H. Min, H. Su, et al. *AgentBay: A Hybrid Interaction Sandbox for Seamless Human-AI Intervention in Agentic Systems.* 2025. [arXiv:2512.04367](https://arxiv.org/abs/2512.04367)
10. J. Fokou. *Parallax: Why AI Agents That Think Must Never Act.* 2026. [arXiv:2604.12986](https://arxiv.org/abs/2604.12986)
11. W. Lan, S. Li, M. Wu, X. Lai, J. Yang, H. Shen. *ContainmentBench: Trace-Based Evaluation of Post-Exposure Containment in Tool-Using LLM Agents.* 2026. [arXiv:2607.23999](https://arxiv.org/abs/2607.23999)
12. I. Santos-Grueiro. *Lingering Authority: Revocable Resource-and-Effect Capabilities for Coding Agents.* 2026. [arXiv:2606.22504](https://arxiv.org/abs/2606.22504)
13. L. Meng, H. Feng, I. Shumailov, E. Fernandes. *ceLLMate: Sandboxing Browser AI Agents.* 2026. [arXiv:2512.12594](https://arxiv.org/abs/2512.12594)
14. Z. Ji, D. Wu, W. Jiang, P. Ma, Z. Li, Y. Gao, S. Wang, Y. Li. *Taming Various Privilege Escalation in LLM-Based Agent Systems: A Mandatory Access Control Framework.* 2026. [arXiv:2601.11893](https://arxiv.org/abs/2601.11893)
15. B. Sidik, L. Rokach. *Beyond Static Sandboxing: Learned Capability Governance for Autonomous AI Agents.* 2026. [arXiv:2604.11839](https://arxiv.org/abs/2604.11839)
16. T. Shi, J. He, Z. Wang, H. Li, L. Wu, W. Guo, D. Song. *Progent: Securing AI Agents with Privilege Control.* 2026. [arXiv:2504.11703](https://arxiv.org/abs/2504.11703)
17. Y. Ruan, H. Dong, A. Wang, S. Pitis, Y. Zhou, J. Ba, Y. Dubois, C. J. Maddison, T. Hashimoto. *Identifying the Risks of LM Agents with an LM-Emulated Sandbox.* ICLR 2024. [arXiv:2309.15817](https://arxiv.org/abs/2309.15817)
18. Y. Wu, F. Roesner, T. Kohno, N. Zhang, U. Iqbal. *IsolateGPT: An Execution Isolation Architecture for LLM-Based Agentic Systems.* NDSS 2025. [arXiv:2403.04960](https://arxiv.org/abs/2403.04960)
19. R. F. Del Rosario, K. Krawiecka, C. Schroeder de Witt. *Architecting Resilient LLM Agents: A Guide to Secure Plan-then-Execute Implementations.* 2025. [arXiv:2509.08646](https://arxiv.org/abs/2509.08646)
