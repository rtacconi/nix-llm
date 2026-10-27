# Content safety rules for this repository

This repository is about isolating hostile code, so its tests have to try
forbidden actions. Endpoint antivirus (Microsoft Defender in particular) flags
files by pattern, and a sandbox test suite written carelessly looks a lot like a
malware toolkit. Every contributor and every code generator must follow the rules
below. Reviewers reject any change that breaks them.

## Rules

1. **No literal attack one-liners.** Do not put the classic shell process-bomb
   expression, shell redirections to network devices, or "spawn a shell over a
   socket" snippets in any file, comment or doc. Process-limit tests use the
   `nsbx-probe spawn --count N` probe, which is an ordinary bounded loop.
2. **No real credential paths in code or fixtures.** Do not read, list or
   mention by name SSH private keys, cloud credential files, browser profiles or
   shadow password databases. Host-leak tests use **synthetic canaries**: the
   test harness creates a temporary file with a random token at runtime and
   gives the probe its path. The test passes if the token never shows up.
3. **No embedded machine code, shellcode or encoded blobs.** No base64, hex or
   compressed payloads. Seccomp tests call syscalls through ordinary Rust code
   (`libc::syscall`) with named constants.
4. **No third-party exploit code.** Do not download, vendor or copy CVE
   proofs-of-concept. Regression tests for a kernel bug describe the *class* of
   behaviour and test that the sandbox blocks it (for example "user namespace
   creation is denied"). They never reproduce the exploit.
5. **No committed binaries.** Everything is built from source by Nix. Do not
   commit ELF, Mach-O, PE or archive files.
6. **Neutral naming.** Name tests and probes after the property they check
   (`isolation_fs_read_outside_root`, `limits_pids_max`), not after attack
   names. Do not use names like "exploit", "payload", "shellcode", "dropper",
   "keylog" or "stealer".
7. **No obfuscation.** No string splitting or encoding to hide what a test does.
   Tests must be readable at a glance.
8. **No network attack tooling.** Network-isolation tests open a TCP connection
   to an address the harness supplies (a local listener the harness starts) and
   report whether the connection succeeded. They do no scanning.
9. **Generated output stays out of the repo.** Benchmark results, traces and
   core files go to `./out/` (git-ignored). Core dumps are disabled
   (`RLIMIT_CORE=0`) in any case.

## Probe design

All "try something forbidden" behaviour lives in one small Rust binary,
`nsbx-probe`, with one subcommand per property. Each subcommand prints one
JSON result line (`{"probe":"fs-read","outcome":"denied","errno":"EACCES"}`),
so the host-side test asserts on structured data rather than scraping text. See
[10-testing.md](10-testing.md).
