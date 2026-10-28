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
  options.services.nsbx.enable = lib.mkEnableOption "NixSandbox host sysctls";

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
  };
}
