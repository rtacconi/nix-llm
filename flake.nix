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
          runtime = mkRuntime pkgs nsbx {
            name = "python-compute";
            packages = [ pkgs.python3Minimal ];
            profile = ./policy/profiles/python-compute.toml;
            allowlist = ./policy/allowlists/python-compute.txt;
          };
          registration = pkgs.closureInfo { rootPaths = [ runtime ]; };
          jobNode = extra: {
            imports = [
              ./nix/module.nix
              extra
            ];
            services.nsbx.enable = true;
            services.nsbx.package = nsbx;
            environment.systemPackages = [
              nsbx
              runtime
            ];
            environment.etc."nsbx/profiles".source = ./policy/profiles;
            environment.etc."nsbx/seccomp".source = ./policy/seccomp;
            environment.etc."nsbx/principals.json".text = ''
              [{"id":"agent-a","profiles":["python-compute"]}]
            '';
            environment.etc."nsbx/registration".source = "${registration}/registration";
          };
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
              k66 = { pkgs, ... }: jobNode {
                boot.kernelPackages = pkgs.linuxPackages_6_6;
              };
              k612 = { pkgs, ... }: jobNode {
                boot.kernelPackages = pkgs.linuxPackages_6_12;
              };
              latest = { pkgs, ... }: jobNode {
                boot.kernelPackages = pkgs.linuxPackages_latest;
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
              import json

              def exercise(node):
                  node.succeed("nix-store --load-db < /etc/nsbx/registration")
                  env = node.succeed("readlink -f ${runtime}/env").strip()
                  etc = node.succeed("readlink -f ${runtime}/etc").strip()
                  node.succeed(
                      "for i in $(seq 1 50); do test -S /run/nsbx-idmap.sock && exit 0; sleep 0.1; done; "
                      "echo 'idmap socket missing'; exit 1"
                  )
                  def start(unit, sock):
                      node.succeed(
                          "systemd-run --unit=" + unit
                          + " -p Delegate=yes -p KillMode=control-group -p User=nsbx -p Group=nsbx"
                          + " -p RuntimeDirectory=" + unit + " --collect "
                          "-- env PATH=/run/current-system/sw/bin NSBX_DELEGATED=1 nsbx-supervisor "
                          "--socket " + sock
                          + " --idmap /run/nsbx-idmap.sock"
                          + " --policy /etc/nsbx/profiles --seccomp /etc/nsbx/seccomp "
                          "--principals /etc/nsbx/principals.json "
                          "--etc " + etc + " --runtime python-compute=" + env
                      )
                  node.succeed("rm -rf /run/nsbx-live /run/nsbx-crash")
                  start("nsbx-live", "/run/nsbx-live/sock")
                  node.succeed("for i in $(seq 1 50); do test -S /run/nsbx-live/sock && exit 0; sleep 0.1; done; exit 1")
                  sup = node.succeed(
                      "awk '/^Uid:/ {print $2}' /proc/$(systemctl show -p MainPID --value nsbx-live.service)/status"
                  ).strip()
                  if sup != "2000000":
                      raise Exception("supervisor uid " + sup)
                  diag = node.succeed(
                      "set +e; runuser -u nsbx -- nsbx-run --socket /run/nsbx-live/sock --principal agent-a -- "
                      "python3 -c 'import os; open(\"/workspace/out/note\",\"w\").write(\"hi\"); open(\"/workspace/out/flake.nix\",\"w\").write(\"x\"); print(os.getuid())' "
                      "> /tmp/nsbx-job.out 2> /tmp/nsbx-job.err; "
                      "ec=$?; echo EXIT:$ec; echo STDOUT; cat /tmp/nsbx-job.out; "
                      "echo STDERR; cat /tmp/nsbx-job.err; "
                      "echo JOURNAL; journalctl -u nsbx-live.service -u nsbx-idmap.service --no-pager -n 80 -o cat; "
                      "exit 0"
                  )
                  stdout = diag.split("STDOUT\n", 1)[-1].split("\nSTDERR", 1)[0].strip()
                  stderr = diag.split("STDERR\n", 1)[-1].split("\nJOURNAL", 1)[0]
                  if stdout != "1000":
                      raise Exception(diag)
                  line = ""
                  for row in stderr.splitlines():
                      if row.startswith("["):
                          line = row
                  try:
                      parsed = json.loads(line)
                  except json.JSONDecodeError:
                      raise Exception(diag)
                  arts = {item["path"]: item for item in parsed}
                  note = "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4"
                  blob = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
                  if arts["out/note"]["sha256"] != note or arts["out/note"]["host_executable_risk"] is not False:
                      raise Exception(diag)
                  if arts["out/flake.nix"]["sha256"] != blob or arts["out/flake.nix"]["host_executable_risk"] is not True:
                      raise Exception(diag)
                  caps = node.succeed("cat /proc/$(pgrep -x nsbx-idmap)/status")
                  for name in ("CapEff:", "CapPrm:", "CapBnd:", "CapAmb:"):
                      got = [row.split()[-1] for row in caps.splitlines() if row.startswith(name)]
                      if got != ["00000000000000c0"]:
                          raise Exception(caps)
                  node.succeed("systemctl stop nsbx-live.service")

                  start("nsbx-crash", "/run/nsbx-crash/sock")
                  node.succeed("for i in $(seq 1 50); do test -S /run/nsbx-crash/sock && exit 0; sleep 0.1; done; exit 1")
                  node.execute(
                      "runuser -u nsbx -- nsbx-run --socket /run/nsbx-crash/sock --principal agent-a -- "
                      "python3 -c 'import time; time.sleep(60)' >/tmp/nsbx-crash.out 2>&1 &"
                  )
                  node.succeed(
                      "for i in $(seq 1 50); do pgrep -x nsbx-stage2 && exit 0; sleep 0.2; done; "
                      "echo 'stage2 did not start'; cat /tmp/nsbx-crash.out; journalctl -u nsbx-crash.service --no-pager -n 40 -o cat; exit 1"
                  )
                  mapped = node.succeed("cat /proc/$(pgrep -x nsbx-stage2)/uid_map")
                  rows = [tuple(line.split()) for line in mapped.splitlines() if line.strip()]
                  if ("0", "2000000", "1") not in rows or ("1000", "2001000", "1") not in rows:
                      raise Exception(mapped)
                  pid = node.succeed("systemctl show -p MainPID --value nsbx-crash.service").strip()
                  if not pid.isdigit() or int(pid) <= 1:
                      raise Exception("main pid " + pid)
                  node.succeed("kill -KILL " + pid)
                  node.succeed("sleep 2")
                  node.fail("pgrep -x nsbx-supervisor")
                  node.fail("pgrep -x nsbx-stage2")
                  node.fail("pgrep -x nsbx-warden")
                  node.succeed("pgrep -x nsbx-idmap")

              k66.start()
              ver = k66.succeed("uname -r").strip()
              assert ver.startswith("6.6."), ver
              k66.succeed("nsbx-supervisor --check --strict")
              k66.succeed("nsbx-idmap --self-test")
              exercise(k66)
              k66.shutdown()

              k612.start()
              ver = k612.succeed("uname -r").strip()
              assert ver.startswith("6.12."), ver
              k612.succeed("nsbx-supervisor --check --strict")
              k612.succeed("nsbx-idmap --self-test")
              exercise(k612)
              k612.shutdown()

              latest.start()
              latest.succeed("nsbx-supervisor --check --strict")
              latest.succeed("nsbx-idmap --self-test")
              exercise(latest)
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
