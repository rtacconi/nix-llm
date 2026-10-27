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
    in
    {
      packages = forAll (pkgs: {
        nsbx-rust = rustWorkspace pkgs;
        default = rustWorkspace pkgs;
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
