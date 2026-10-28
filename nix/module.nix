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
      description = "nsbx package. When set, user nsbx and the idmap socket are installed.";
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
    users.users.nsbx = lib.mkIf (cfg.package != null) {
      isSystemUser = true;
      uid = 2000000;
      group = "nsbx";
      home = "/var/empty";
    };
    users.groups.nsbx = lib.mkIf (cfg.package != null) { gid = 2000000; };
    systemd.sockets.nsbx-idmap = lib.mkIf (cfg.package != null) {
      wantedBy = [ "sockets.target" ];
      listenStreams = [ "/run/nsbx-idmap.sock" ];
      socketConfig = {
        SocketUser = "nsbx";
        SocketGroup = "nsbx";
        SocketMode = "0600";
        Accept = false;
      };
    };
    systemd.services.nsbx-idmap = lib.mkIf (cfg.package != null) {
      description = "NixSandbox uid and gid map helper";
      requires = [ "nsbx-idmap.socket" ];
      after = [ "nsbx-idmap.socket" ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/nsbx-idmap --serve";
        User = "nsbx";
        Group = "nsbx";
        AmbientCapabilities = "CAP_SETUID CAP_SETGID";
        CapabilityBoundingSet = "CAP_SETUID CAP_SETGID";
        NoNewPrivileges = true;
      };
    };
  };
}
