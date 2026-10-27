# 14 — Implementation roadmap (Phase 3) and open decisions

Each milestone is small and independently testable. A milestone is done when its
acceptance tests pass in CI on the stated tier. Stubs return an explicit
`unsupported_feature` error. Nothing ever falls back to a weaker mechanism.

## Milestones

| M | Scope | Acceptance criteria | Tier |
|---|-------|---------------------|------|
| **M0** | Flake skeleton, dev shell, CI `check` stage; `docs/verification.md` (every kernel and crate claim in [03](03-kernel-primitives.md) checked against primary sources); experiments E1–E6 | `nix flake check` green; each E-experiment has a written result; table rows marked verified or corrected | T0, VM |
| **M1** | `nsbx-proto` + `nsbx-policy` (no kernel): frame codec, schemas, profile validation, narrowing, seccomp TOML → BPF snapshot | Property tests (narrowing never widens; codec round-trip); fuzz targets build and run 5 min clean; BPF snapshot tests | T0/T1 |
| **M2** | `nsbx-sys` + `nsbx-cgroup` + minimal spawn: cgroup create/limit/kill/rmdir, `clone3` INTO_CGROUP + userns + pidns + execveat of a trivial stage 2 that exits | Test: child's `/proc/self/cgroup` is the job cgroup **at its first instruction** (stage 2 reads it before anything else); `cgroup.kill` leaves no tasks; no fd leak (fd census) | T2 |
| **M3** | Stage 2 filesystem: rprivate, tmpfs root, per-path closure binds, workspace/tmp/shm, proc subset, dev, pivot_root + detach; Nix `mkRuntime` for `cli` and `python` | `isolation_fs_*`, `isolation_proc_view`, `mountinfo` exact set; `python3 -c` runs | T2 |
| **M4** | Privilege drop + Landlock + seccomp (`base`, `python`, `cli`), ordering per [04](04-privilege-model.md); profile derivation tooling (log mode) | `isolation_caps`, `isolation_syscall_matrix`, `isolation_ns_create`, `isolation_socket_families`; Python conformance corpus passes in enforce mode | T2 |
| **M5** | Supervisor server: protocol, peer creds, job state machine, deadlines, escalation, credits, output caps, results, idempotency; init role (reaper, `kill(-1)`, status record) | `limits_*`, `lifecycle_*`; supervisor RSS bound under the slow-consumer test; malformed-protocol suite | T2 |
| **M6** | `nsbx-idmap` + NixOS module + VM tests (kernel matrix); production mode (per-slot UIDs) | All T2 tests rerun in T3 on 6.6 / 6.12 / latest; `isolation_signal_init`; crash-injection suite; feature-absence VMs refuse to start | T3 |
| **M7** | Python orchestrator: API, admission, SSE, cancel propagation, reconnect; supervisor self-seccomp | End-to-end tests through HTTP; cancel-on-disconnect; `mypy --strict` clean; banned-import check | T2/T3 |
| **M8** | Benchmarks B1–B10, baseline report; `node` and `build` profiles | Baseline JSON committed under `docs/baselines/` with hardware metadata (numbers come only from this run) | T4 |
| **M9** | Egress proxy network mode + nftables backstop | `isolation_net_*` in egress mode: allowlisted host reachable; private, link-local and metadata ranges denied even through the proxy with forced DNS answers (test resolver in VM) | T3 |
| **M10** | MicroVM backend prototype (Cloud Hypervisor, erofs closure image, vsock, stage 2 as guest agent) | Same probe suite passes through the `Backend` trait; B1/B4/B10 measured for both backends | T3/T4 |

The Phase 4 "minimal vertical slice" in the brief corresponds to **M0–M7** (with
the `node`/`build` profiles and networking stubbed).

## Experiments to resolve uncertainties (M0)

| E | Question | Experiment |
|---|----------|------------|
| E1 | Can `execveat(AT_EMPTY_PATH)` on an `O_PATH` fd exec a static binary from a freshly `clone3`d child with the expected credentials? | Minimal C-free Rust test in the VM |
| E2 | Exact per-path bind cost vs closure size (drives D1) | B3 micro-version |
| E3 | Is `/proc/sys/user/max_user_namespaces` per user namespace and writable by the ns owner with caps there, and does setting it to 0 block nested userns creation for descendants? | Write it in stage 2, then probe `clone(CLONE_NEWUSER)` without seccomp |
| E4 | Securebits-before-setuid ordering and the resulting cap sets | `/proc/self/status` assertions over the candidate orderings |
| E5 | Do Python 3.12, Node 22 and gcc run correctly with `clone3 → ENOSYS`, `proc subset=pid`, no `/sys`? | Conformance corpora |
| E6 | `landlock` crate: exact API for a hard-requirement compatibility level; `rustix` coverage of `mount_setattr`/`open_tree`/`move_mount` | Read the crate docs and source at the pinned versions |

## Prioritised open engineering decisions

| P | ID | Decision | Options | Leaning | Needed by |
|---|----|----------|---------|---------|-----------|
| 1 | D1 | Closure presentation | Per-path binds / whole-store bind + Landlock / erofs image via FUSE / overlay | Per-path binds unless E2 shows unacceptable cost for real closures | M3 |
| 2 | D2 | How `nsbx-idmap` is wired | Separate systemd unit + `SCM_RIGHTS` socket / supervisor-spawned child holding caps | Separate unit (cleaner cap scoping) | M6 |
| 3 | D3 | Seccomp compiler | `seccompiler` / `libseccomp` | `seccompiler` | M4 |
| 4 | D4 | Minimum kernel | 6.6 / 6.12 | 6.6 now, move to 6.12 when distros allow | M0 |
| 5 | D5 | Init privilege after setup | Keep userns caps / ns-UID 1 with `CAP_KILL` only / no caps (rely on pidns teardown) | Minimal caps (needs a design for `kill(-1)` across UIDs) | M5 |
| 6 | D6 | Disk-backed workspaces | None / XFS project quota (privileged helper) / loop image (privileged) / FUSE | None in v1 | Post-M8 |
| 7 | D7 | Python web stack | Starlette+uvicorn / aiohttp / stdlib-only | Starlette | M7 |
| 8 | D8 | Detached jobs surviving orchestrator restart | No (fail closed) / yes with TTL | No in v1 | M7 |
| 9 | D9 | Input file transfer | base64 in Submit / separate staged upload frames / memfd via `SCM_RIGHTS` (orchestrator → supervisor) | Frames (avoids a 64 KiB frame cap on JSON) | M5 |
| 10 | D10 | Agent-facing protocol | HTTP+SSE / MCP server façade / both | HTTP+SSE, MCP façade later | M7 |
| 11 | D11 | Policy signing | None / minisign | Later | Post-M8 |
