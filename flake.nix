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

      # Design §9. One derivation pins the env, the etc skeleton and the store
      # paths the supervisor is allowed to bind. The seccomp BPF hash is added
      # when the profile compiler lands (M4).
      mkRuntime =
        pkgs:
        { name, packages, profile }:
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
            cat > $out/policy.json <<EOF
            {"schema":1,"runtime":"$out","profile":"${name}"}
            EOF
            find ${env}/bin \( -type f -o -type l \) | sort > $out/executables
          '';
    in
    {
      packages = forAll (pkgs: {
        nsbx-rust = rustWorkspace pkgs;
        default = rustWorkspace pkgs;
        python-compute = mkRuntime pkgs {
          name = "python-compute";
          packages = [ pkgs.python3Minimal ];
          profile = ./policy/profiles/python-compute.toml;
        };
        cli-text = mkRuntime pkgs {
          name = "cli-text";
          packages = [
            pkgs.coreutils
            pkgs.gnugrep
            pkgs.gnused
            pkgs.jq
          ];
          profile = ./policy/profiles/cli-text.toml;
        };
      });

      checks = forAll (pkgs: {
        rust = rustWorkspace pkgs;

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
      });

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
