# Host requirements for NixSandbox (design §4). The supervisor's `--check --strict`
# reads these sysctls and refuses to start when any of them differ.
{
  config,
  lib,
  ...
}:
let
  cfg = config.services.nsbx;
in
{
  options.services.nsbx = {
    enable = lib.mkEnableOption "NixSandbox host sysctls";
    package = lib.mkOption {
      type = lib.types.nullOr lib.types.package;
      default = null;
      description = "nsbx package. When set, an idmap unit is installed and left stopped.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.versionAtLeast config.boot.kernelPackages.kernel.version "6.6";
        message = "NixSandbox needs Linux 6.6 or newer";
      }
    ];
    boot.kernel.sysctl = {
      "kernel.unprivileged_bpf_disabled" = 2;
      "kernel.perf_event_paranoid" = 2;
      "kernel.io_uring_disabled" = 2;
      "vm.unprivileged_userfaultfd" = 0;
      "fs.protected_symlinks" = 1;
      "fs.protected_hardlinks" = 1;
    };
    systemd.services.nsbx-idmap = lib.mkIf (cfg.package != null) {
      description = "NixSandbox uid and gid map helper";
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${cfg.package}/bin/nsbx-idmap --self-test";
        AmbientCapabilities = "CAP_SETUID CAP_SETGID";
        CapabilityBoundingSet = "CAP_SETUID CAP_SETGID";
        NoNewPrivileges = true;
      };
    };
  };
}
