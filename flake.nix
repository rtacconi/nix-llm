{
  description = "NixSandbox: a Linux execution sandbox for code written by LLM agents";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # Rust sources shared by the Rust workspace and the Python binding.
      rustSrc =
        pkgs:
        pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.unions [
            ./Cargo.toml
            ./Cargo.lock
            ./clippy.toml
            ./crates
            ./policy
          ];
        };

      # nsbx_policy: the Rust narrow() as a Python extension (maturin).
      nsbxPolicyPy =
        pkgs: ps:
        ps.buildPythonPackage {
          pname = "nsbx-policy";
          version = "0.1.0";
          pyproject = true;
          src = rustSrc pkgs;
          buildAndTestSubdir = "crates/nsbx-pyo3";
          cargoDeps = pkgs.rustPlatform.importCargoLock { lockFile = ./Cargo.lock; };
          nativeBuildInputs = [
            pkgs.rustPlatform.cargoSetupHook
            pkgs.rustPlatform.maturinBuildHook
          ];
          pythonImportsCheck = [ "nsbx_policy" ];
        };

      pythonFor =
        pkgs:
        pkgs.python312.withPackages (
          ps: with ps; [
            (nsbxPolicyPy pkgs ps)
            pydantic
            starlette
            uvicorn
            # test and type-check only
            httpx
            pytest
            anyio
            mypy
          ]
        );

      rustWorkspace =
        pkgs:
        pkgs.rustPlatform.buildRustPackage {
          pname = "nsbx";
          version = "0.1.0";
          src = rustSrc pkgs;
          cargoLock.lockFile = ./Cargo.lock;
          # Builds the default workspace members; the Python binding is built
          # separately by maturin (nsbxPolicyPy).
          doCheck = true;
        };

      # Design §9. One derivation pins the env, the etc skeleton, the executable
      # allowlist and the seccomp BPF hash.
      mkRuntime =
        pkgs: nsbx:
        {
          name,
          packages,
          profile,
          allowlist,
        }:
        let
          env = pkgs.buildEnv {
            name = "${name}-env";
            paths = packages;
            pathsToLink = [ "/bin" ];
          };
          etc = pkgs.runCommand "${name}-etc" { } ''
            mkdir -p $out
            cat > $out/passwd <<'EOF'
            root:x:0:0:root:/:/bin/false
            sandbox:x:1000:1000:sandbox:/workspace:/bin/false
            EOF
            cat > $out/group <<'EOF'
            root:x:0:
            sandbox:x:1000:
            EOF
            printf '127.0.0.1 localhost\n' > $out/hosts
            : > $out/resolv.conf
          '';
          info = pkgs.closureInfo { rootPaths = [ env etc ]; };
          policyScript =
            if pkgs.stdenv.isLinux then
              ''
                ${nsbx}/bin/nsbx-policy closure-audit --allowlist ${allowlist} --bin ${env}/bin
                ${nsbx}/bin/nsbx-policy policy-json \
                  --profile-toml ${profile} \
                  --seccomp-dir ${./policy/seccomp} \
                  --store-paths ${info}/store-paths \
                  --runtime "$out" \
                  --out $out/policy.json
              ''
            else
              ''
                cat > $out/policy.json <<EOF
                {"schema":1,"runtime":"$out","profile":"${name}"}
                EOF
              '';
        in
        pkgs.runCommand "${name}-runtime"
          {
            passthru = { inherit env etc; };
          }
          ''
            mkdir -p $out
            ln -s ${env} $out/env
            ln -s ${etc} $out/etc
            cp ${info}/store-paths $out/store-paths
            cp ${profile} $out/profile.toml
            ${policyScript}
            find ${env}/bin \( -type f -o -type l \) | sort > $out/executables
          '';
    in
    {
      packages = forAll (pkgs: {
        nsbx-rust = rustWorkspace pkgs;
        default = rustWorkspace pkgs;
        python-compute = mkRuntime pkgs (rustWorkspace pkgs) {
          name = "python-compute";
          packages = [ pkgs.python3Minimal ];
          profile = ./policy/profiles/python-compute.toml;
          allowlist = ./policy/allowlists/python-compute.txt;
        };
        cli-text = mkRuntime pkgs (rustWorkspace pkgs) {
          name = "cli-text";
          packages = [
            pkgs.coreutils
            pkgs.gnugrep
            pkgs.gnused
            pkgs.jq
          ];
          profile = ./policy/profiles/cli-text.toml;
          allowlist = ./policy/allowlists/cli-text.txt;
        };
      });

      checks = forAll (
        pkgs:
        let
          nsbx = rustWorkspace pkgs;
        in
        {
          rust = nsbx;

          python =
            pkgs.runCommand "nsbx-orchestrator-tests"
              {
                nativeBuildInputs = [
                  (pythonFor pkgs)
                  pkgs.ruff
                ];
              }
              ''
                cp -r ${./python} python && cp -r ${./policy} policy && chmod -R u+w python policy && cd python
                ruff check .
                mypy
                pytest -q
                touch $out
              '';
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          # M6: the same supervisor binary, three kernels, and one host whose
          # io_uring sysctl is left on. Strict mode must pass only on the three
          # hardened kernels.
          kernels = pkgs.testers.runNixOSTest {
            name = "nsbx-kernels";
            nodes = {
              k66 = {
                pkgs,
                ...
              }:
              {
                imports = [ ./nix/module.nix ];
                boot.kernelPackages = pkgs.linuxPackages_6_6;
                services.nsbx.enable = true;
                environment.systemPackages = [ nsbx ];
              };
              k612 = {
                pkgs,
                ...
              }:
              {
                imports = [ ./nix/module.nix ];
                boot.kernelPackages = pkgs.linuxPackages_6_12;
                services.nsbx.enable = true;
                environment.systemPackages = [ nsbx ];
              };
              latest = {
                pkgs,
                ...
              }:
              {
                imports = [ ./nix/module.nix ];
                boot.kernelPackages = pkgs.linuxPackages_latest;
                services.nsbx.enable = true;
                environment.systemPackages = [ nsbx ];
              };
              missing = {
                lib,
                ...
              }:
              {
                imports = [ ./nix/module.nix ];
                services.nsbx.enable = true;
                environment.systemPackages = [ nsbx ];
                boot.kernel.sysctl."kernel.io_uring_disabled" = lib.mkForce 0;
              };
            };
            testScript = ''
              k66.start()
              ver = k66.succeed("uname -r").strip()
              assert ver.startswith("6.6."), ver
              k66.succeed("nsbx-supervisor --check --strict")
              k66.succeed("nsbx-idmap --self-test")
              k66.shutdown()

              k612.start()
              ver = k612.succeed("uname -r").strip()
              assert ver.startswith("6.12."), ver
              k612.succeed("nsbx-supervisor --check --strict")
              k612.succeed("nsbx-idmap --self-test")
              k612.shutdown()

              latest.start()
              latest.succeed("nsbx-supervisor --check --strict")
              latest.succeed("nsbx-idmap --self-test")
              latest.shutdown()

              missing.start()
              missing.fail("nsbx-supervisor --check --strict")
              missing.shutdown()
            '';
          };
        }
      );

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages =
            [
              pkgs.cargo
              pkgs.rustc
              pkgs.clippy
              pkgs.rustfmt
              pkgs.cargo-deny
              (pythonFor pkgs)
              pkgs.ruff
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
              pkgs.strace
              pkgs.bpftrace
            ];
        };
      });
    };
}
