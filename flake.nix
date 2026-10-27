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

      pythonFor =
        pkgs:
        pkgs.python312.withPackages (
          ps: with ps; [
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
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./clippy.toml
              ./crates
              ./policy
            ];
          };
          cargoLock.lockFile = ./Cargo.lock;
          # Linux-only crates (supervisor, stage 2, idmap, warden) are not in the
          # workspace yet; everything here builds and tests on any platform.
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
              cp -r ${./python} python && chmod -R u+w python && cd python
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
