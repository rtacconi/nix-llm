# 09 — Rust crates, Python package and Nix flake layout

## Repository layout (recommended)

```text
nix-llm/
├── flake.nix  flake.lock
├── Cargo.toml  Cargo.lock  deny.toml  rust-toolchain.toml
├── crates/
│   ├── nsbx-proto/        # frame codec + message types; no_std-friendly, #![forbid(unsafe_code)]
│   ├── nsbx-policy/       # policy + seccomp TOML → validated structs → BPF; `nsbx-policy` CLI
│   ├── nsbx-sys/          # the ONLY crate with `unsafe`: clone3, pidfd, mount API, landlock/seccomp install, close_range
│   ├── nsbx-cgroup/       # delegated-subtree management on top of nsbx-sys
│   ├── nsbx-core/         # Backend trait, job state machine, slot allocator, results
│   ├── nsbx-supervisor/   # bin: Tokio server, namespace backend
│   ├── nsbx-stage2/       # bin: static, single-threaded setup + init
│   ├── nsbx-idmap/        # bin: id-mapping helper
│   ├── nsbx-probe/        # bin: security-test probes (see content-safety.md)
│   └── nsbx-bench/        # bin: benchmark driver
├── python/
│   └── nsbx_orchestrator/
│       ├── __init__.py
│       ├── app.py            # Starlette app factory, routes
│       ├── schemas.py        # pydantic models (JobRequest, JobView, ErrorView)
│       ├── admission.py      # bounded queue, semaphore, per-principal quotas
│       ├── jobs.py           # JobManager: state machine, deadlines, cancel
│       ├── supervisor.py     # asyncio Unix-socket client, framing, credits, reconnect
│       ├── streaming.py      # SSE fan-out with bounded per-subscriber buffers
│       ├── auth.py           # bearer tokens → principal → allowed profiles
│       └── config.py
│   └── tests/
├── runtimes/              # Nix: mkRuntime + runtime definitions
├── policy/
│   ├── profiles/*.toml     # admin job profiles (limits, runtime, seccomp, landlock, fs)
│   └── seccomp/*.toml      # syscall sets with per-syscall reasons
├── nix/
│   ├── module.nix          # NixOS module: users, systemd units, sysctls, nftables
│   └── tests/*.nix         # NixOS VM integration tests (kernel matrix)
├── tests/security/         # host-side regression suite (Rust integration tests)
└── docs/
```

### Rust crate rules

| Crate | `unsafe` | Depends on | Notes |
|-------|----------|-----------|-------|
| `nsbx-sys` | yes, every block has a `// SAFETY:` comment and a test | `libc`, `rustix` | Thin typed wrappers. **No policy logic.** `rustix` where it covers the call; raw `libc::syscall` for `clone3` and any gaps (M0 checks which mount-API calls `rustix` exposes) |
| `nsbx-proto` | forbidden | `serde`, `serde_json` | Shared with the fuzzer |
| `nsbx-policy` | forbidden | `serde`, `toml`, `seccompiler` | Validation is pure and property-tested |
| `nsbx-cgroup` | forbidden | `nsbx-sys` | Writes via dirfd + `openat`, never via string paths |
| `nsbx-core` | forbidden | above | |
| `nsbx-supervisor` | forbidden | `tokio`, `tracing`, `landlock` (to build rulesets), above | |
| `nsbx-stage2` | forbidden (uses `nsbx-sys`) | `nsbx-sys`, `nsbx-policy` (deserialise only), `landlock` | `panic = "abort"`, static musl build, no Tokio, no allocator-heavy dependencies |
| `nsbx-idmap` | forbidden | `nsbx-sys` | ~300 LOC budget enforced by a CI check |

Workspace lints: `clippy::pedantic` (selected), `unsafe_op_in_unsafe_fn`,
`missing_safety_doc`. `cargo deny` bans duplicate major versions and
non-allowlisted licences, and `cargo vet` or `cargo audit` runs in CI.

### Python package rules

- Python 3.12, `asyncio` only (no threads except uvicorn internals).
- Dependencies: `starlette`, `uvicorn`, `pydantic>=2`. Nothing else at runtime.
- `mypy --strict`, `ruff` with `S` (bandit), `B`, `ASYNC`. A custom check
  bans `subprocess`, `os.system`, `eval`, `exec`, `pickle` and `marshal`
  imports in `nsbx_orchestrator`.
- All per-job buffers are bounded (`asyncio.Queue(maxsize=…)`). A slow SSE
  subscriber is disconnected rather than buffered without limit.

## Nix layout

```nix
# flake.nix (shape, not final)
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";   # pinned via flake.lock
    crane.url = "github:ipetkov/crane";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };
  outputs = { self, nixpkgs, crane, rust-overlay }: let
    systems = [ "x86_64-linux" "aarch64-linux" ];
    devSystems = systems ++ [ "aarch64-darwin" ];    # edit + unit tests only
  in {
    packages.<linux> = {
      nsbx-supervisor = …;   # crane buildPackage
      nsbx-stage2     = …;   # pkgsStatic / musl target
      nsbx-idmap      = …;
      nsbx-probe      = …;
      nsbx-orchestrator = …; # python3Packages.buildPythonApplication
      runtime-python  = mkRuntime { name = "python"; packages = p: [ p.python312 ]; profile = "python"; };
      runtime-node    = mkRuntime { name = "node";   packages = p: [ p.nodejs_22 ]; profile = "node"; };
      runtime-build   = mkRuntime { name = "build";  packages = p: [ p.gcc p.gnumake p.coreutils ]; profile = "build"; };
      runtime-cli     = mkRuntime { name = "cli";    packages = p: [ p.coreutils p.gnugrep p.gnused p.jq ]; profile = "cli"; };
    };
    checks.<linux> = { fmt; clippy; cargo-test; cargo-deny; mypy; ruff; pytest;
                       vm-6_6; vm-6_12; vm-latest; vm-old-kernel-refuses; reproducible-runtimes; };
    devShells.<all>.default = …;   # rust toolchain, cargo-{nextest,deny,fuzz,audit}, python+mypy+ruff,
                                    # strace, perf, bpftrace, hyperfine (linux only)
    nixosModules.default = ./nix/module.nix;
    apps.<linux>.bench = …;
  };
}
```

Pinned versions (nixpkgs branch, crane, toolchain) are placeholders here. M0
picks them and records them in `flake.lock`.

### `mkRuntime`

```nix
mkRuntime = { name, packages, profile }: let
  env = pkgs.buildEnv { name = "nsbx-${name}-env"; paths = packages pkgs; };
  etc = pkgs.runCommand "nsbx-${name}-etc" {} ''
    mkdir -p $out
    printf 'root:x:0:0::/:/nonexistent\nsandbox:x:1000:1000::/workspace:/nonexistent\n' > $out/passwd
    printf 'root:x:0:\nsandbox:x:1000:\n' > $out/group
    printf 'hosts: files\npasswd: files\ngroup: files\n' > $out/nsswitch.conf
    printf '127.0.0.1 localhost\n::1 localhost\n' > $out/hosts
    : > $out/resolv.conf
  '';
  closure = pkgs.closureInfo { rootPaths = [ env etc ]; };
in pkgs.runCommand "nsbx-runtime-${name}" {} ''
  mkdir -p $out
  ln -s ${env} $out/env
  ln -s ${etc} $out/etc
  cp ${closure}/store-paths $out/store-paths
  cat > $out/runtime.json <<EOF
  {"name":"${name}","profile":"${profile}","env":"${env}","etc":"${etc}"}
  EOF
'';
```

- **Versioning:** the runtime's identity is its output store path. The
  supervisor policy references runtimes by store path. The NixOS module
  generates the policy file from flake outputs, so deploying a new runtime
  means a new policy hash.
- **Caching:** any Nix binary cache (`nix copy --to file://…`, a self-hosted
  attic, or `nix-serve`); no hosted service is required. The supervisor
  host only needs the closures in its local store.
- **Testing:** each runtime has a VM test that runs its conformance corpus
  inside the real sandbox (this also feeds seccomp profile derivation).
- **Reproducibility:** CI builds each runtime twice (`nix build --rebuild`) and
  fails on a mismatch.
- **Build vs runtime isolation:** derivations build in the Nix build sandbox.
  That is unrelated to, and gives no guarantee about, how the outputs behave
  inside `nsbx`.

### NixOS module (sketch)

Creates the users `nsbx`, `nsbx-orch`, `nsbx-idmap` and `nsbx-egress` and the
group `nsbx-clients`. Defines the units `nsbx-supervisor.service` (`Delegate=yes`,
`KillMode=control-group`, `NoNewPrivileges=yes`, `ProtectSystem=strict`,
`ProtectHome=yes`, `PrivateTmp=yes`, `RestrictAddressFamilies=AF_UNIX`,
`SystemCallArchitectures=native`, `CapabilityBoundingSet=`), plus
`nsbx-supervisor.socket`, `nsbx-idmap.service` (`AmbientCapabilities=CAP_SETUID CAP_SETGID`,
`CapabilityBoundingSet=CAP_SETUID CAP_SETGID`, connected to the supervisor by a
socketpair the supervisor creates; alternatively the supervisor starts it as a
child under systemd's `ExecStartPre` model, which is open decision D2) and
`nsbx-orchestrator.service`. It also sets the hardened sysctls and an
assertion that the kernel is ≥ 6.6.

Note: the `ProtectSystem`/`ProtectHome` options on the supervisor unit put the
supervisor itself in a mount namespace. Sandboxes inherit from it, which is
correct, but bind sources must be visible inside it. `/nix/store` is visible.
