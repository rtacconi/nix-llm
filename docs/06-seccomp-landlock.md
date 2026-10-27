# 06 — Seccomp and Landlock policy strategy

## Principles

1. **Default deny.** Each profile is an allowlist. The default action for an
   unlisted syscall is `SECCOMP_RET_ERRNO(ENOSYS)`. `ENOSYS` (rather than
   `EPERM`) makes libc and runtimes take their documented fallback for "syscall
   not implemented" (glibc's fallback from `clone3` to `clone` is the classic
   case), so new syscalls in future runtimes fail soft instead of crashing.
2. **Kill on red-flag syscalls.** A short explicit list returns
   `SECCOMP_RET_KILL_PROCESS`. These are syscalls no supported workload uses,
   and an attempt is a strong signal: `bpf`, `perf_event_open`, `kexec_*`,
   `init_module`, `finit_module`, `delete_module`, `open_by_handle_at`,
   `name_to_handle_at`, `userfaultfd`, `io_uring_setup`/`enter`/`register`,
   `keyctl`, `add_key`, `request_key`, `ptrace`, `process_vm_readv`/`writev`,
   `setns`, `unshare`, `mount`, `umount2`, `pivot_root`, `chroot`,
   `fsopen`/`fsconfig`/`fsmount`/`fspick`/`open_tree`/`move_mount`/`mount_setattr`,
   `swapon`/`swapoff`, `reboot`, `acct`, `quotactl`, `iopl`/`ioperm`,
   `lookup_dcookie`, `vm86`, `personality` (except the argument-filtered allow
   below), `syslog`, `settimeofday`/`clock_settime`/`adjtimex`.
   The kill shows up as `SIGSYS` with `termination_reason = seccomp_kill`, which
   is observable without host audit configuration.
3. **Architecture check first.** The first BPF instruction loads
   `seccomp_data.arch`. Anything other than the build's native audit arch
   (`AUDIT_ARCH_X86_64` / `AUDIT_ARCH_AARCH64`) → `KILL_PROCESS`. On x86_64,
   syscall numbers with `__X32_SYSCALL_BIT` (0x40000000) set → `KILL_PROCESS`.
   32-bit compat entry (`int 0x80`) reports `AUDIT_ARCH_I386` and is killed by
   the arch check.
4. **Argument filtering only for register arguments.** Seccomp sees only the six
   raw register values. It cannot dereference pointers, so it cannot inspect
   `clone3`'s `struct clone_args`, paths, or `sockaddr`. This drives several
   choices below.

## Syscalls that need specific treatment

| Syscall | Treatment | Reason / limitation |
|---------|-----------|---------------------|
| `clone` | Allow only if `(flags & (CLONE_NEWNS\|CLONE_NEWUSER\|CLONE_NEWPID\|CLONE_NEWNET\|CLONE_NEWIPC\|CLONE_NEWUTS\|CLONE_NEWCGROUP\|CLONE_NEWTIME)) == 0` (masked-equality on arg0, x86_64 and aarch64 layout) | Threads and `fork` still work. Namespace creation is blocked. |
| `clone3` | `ERRNO(ENOSYS)` | Flags live in user memory and cannot be checked. Returning `ENOSYS` makes glibc and musl fall back to `clone`. The same approach is used by mainstream container runtimes. M3 test: the Python, Node and gcc profiles pass with `clone3` disabled. |
| `unshare`, `setns` | `KILL_PROCESS` | The workload has no caps anyway; this removes the surface |
| `socket` | Allow `AF_UNIX`; `AF_INET`/`AF_INET6` only in profiles with `loopback_tcp: true`; everything else `ERRNO(EAFNOSUPPORT)` | `AF_NETLINK`, `AF_PACKET`, `AF_ALG`, `AF_VSOCK`, `AF_KEY` etc. are historically bug-prone kernel surfaces. `socketpair` is filtered the same way. |
| `ioctl` | Allowlist on arg1: `FIONREAD`, `FIONBIO`, `FIOCLEX`, `FIONCLEX`, `TCGETS` (answers `ENOTTY` because there is no TTY, which libraries expect), `TIOCGWINSZ`. Others → `ERRNO(ENOTTY)` | `TIOCSTI`/`TIOCLINUX` stay unreachable even if a TTY ever appears. Landlock ABI 5 `IOCTL_DEV` adds a check on device files. |
| `prctl` | Allow `PR_SET_NAME`, `PR_GET_NAME`, `PR_SET_PDEATHSIG`, `PR_GET_DUMPABLE`, `PR_SET_VMA` (Node), `PR_CAPBSET_READ`, `PR_GET_SECUREBITS`, `PR_SET_NO_NEW_PRIVS`; others `ERRNO(EPERM)` | Arg0 is the option, so it is filterable |
| `personality` | Allow only `0xffffffff` (query) and `PER_LINUX` | Blocks `ADDR_NO_RANDOMIZE` and `READ_IMPLIES_EXEC` |
| `mmap`/`mprotect` | Allow. W^X **not** enforced in the generic profile | JITs (V8, PCRE2, Python 3.13+ JIT if enabled) need RWX transitions. A stricter `python-nojit` profile could deny `PROT_EXEC\|PROT_WRITE` together. |
| `execve`/`execveat` | Allow | Needed by build and CLI workloads. Landlock `EXECUTE` limits what can be exec'd. |
| `kill`/`tgkill`/`pidfd_send_signal` | Allow | The PID namespace and the different init UID scope them. Landlock ABI 6 scoping blocks signals out of the domain where available. |
| `memfd_create` | Allow without `MFD_EXEC` flags check in v1 | V8 and others use it. Landlock does not cover memfd exec; noted as a residual risk. |
| `mbind`, `migrate_pages`, `move_pages`, `set_mempolicy` | `ERRNO(EPERM)` | Not needed; NUMA surface |
| `sched_setattr`, `sched_setscheduler` | `ERRNO(EPERM)` | Prevents attempts at RT-class abuse (also needs caps) |

## Workload profiles

Profiles are generated from TOML sources (`policy/seccomp/<name>.toml`) by
`nsbx-policy`. They share one base set and add deltas. Every profile has
`version` and `abi` fields and a content hash. Jobs report `profile@hash`.

| Profile | Base delta | Notes |
|---------|-----------|-------|
| `base` | File I/O, memory, time, signals, futex, epoll, `poll`/`ppoll`/`select`, `getrandom`, `rseq`, `sched_yield`/`getaffinity`, `clone` (filtered), `wait4`/`waitid`, `pipe2`, `dup*`, `fcntl`, `getdents64`, `statx`/`newfstatat`, `readlink(at)`, `getcwd`/`chdir`, `uname`, `set_tid_address`, `set_robust_list`, `exit(_group)`, `rt_sig*`, `sigaltstack`, `prlimit64` (get only: arg2 == NULL) | Never used directly |
| `python` | + `socket(AF_UNIX)`, `eventfd2`, `madvise`, `mremap`; `inotify_*` to be decided by the M4 trace | `asyncio`, `multiprocessing` (needs `/dev/shm`, `sem_open` → files in `/dev/shm`) |
| `node` | + `memfd_create`; `pkey_*` to be decided by the M4 trace (V8 may probe it); `io_uring_*` → **ENOSYS instead of KILL** so libuv falls back | libuv probes io_uring at start. Killing on it would break Node. This is a profile-specific downgrade from kill to ENOSYS, and it still blocks io_uring. |
| `build` | + `execve` heavy, `vfork`, `utimensat`, `fchmod*`, `fchown*` (own files only, DAC enforced), `link*`, `rename*`, `symlink*`, `flock`, `fallocate`, `copy_file_range` | gcc/clang/cargo/make. `/workspace` gets `exec`. |
| `cli` | Union of the above, minus `memfd_create` | Arbitrary CLI tools. The broadest profile, and the least trusted. |

### How profiles are derived (not guessed)

1. **Trace.** In a disposable VM, run the profile's conformance corpus (the
   Python test-suite subset, a Node script set, compiling a set of C/Rust
   projects, a CLI tool set) with
   `strace -f -c -qq` **and** with the profile in `SECCOMP_RET_LOG` mode. Collect
   syscall names and the argument values used for filtered calls.
2. **Review.** Every new syscall in a profile diff needs a written reason in the
   TOML (`reason = "..."`). The review checklist asks "does this add attack
   surface already blocked by a kill rule in another profile?"
3. **Enforce.** Switch to `ERRNO`/`KILL` mode and run the corpus again. It must
   pass.
4. **Regress.** The security suite verifies that every kill-listed syscall is
   killed in every profile (a generated test matrix).

### Versioning and updates

- Profile = `(name, semver, hash)`. Adding a syscall is a **minor** version;
  removing one is **major** (it can break workloads).
- A runtime pins a profile range in its descriptor. The supervisor refuses a
  `(runtime, profile)` pair outside the range.
- nixpkgs bumps run the trace corpus in CI. A new syscall seen in log mode
  fails the build until the profile is updated and reviewed.

### Implementation crate

`seccompiler` (from Firecracker, pure Rust) compiles the profile to classic BPF,
supports argument conditions (masked equality, comparisons) and the actions we
need, and generates the arch check. Alternative: `libseccomp` bindings (C
dependency, more mature syscall-name resolution across architectures, supports
`USER_NOTIF`). Choice: **seccompiler for v1**. Open decision D3 covers
revisiting this if aarch64 multiplexed-syscall handling or user notification is
needed. Each compiled BPF program is also dumped (`nsbx-policy dump`) and the
generated bytecode is snapshot-tested, so a crate upgrade cannot change a filter
silently.

### Limitations of seccomp (stated, not hidden)

- It filters syscall *entry*, not semantics. An allowed `openat` can still
  reach any path the mount namespace and Landlock allow.
- No pointer inspection (hence `clone3 → ENOSYS`, and no path or `sockaddr`
  filtering).
- io_uring would bypass syscall-level filtering entirely, which is why it is
  blocked outright.
- Filters are inherited and stack; they cannot be removed. Each extra filter adds
  a per-syscall cost (measured in M8).
- Allowed syscalls still contain kernel bugs. Seccomp shrinks the attack surface
  but does not remove it.

## Landlock

Landlock is **defence in depth behind the mount namespace**. It catches policy
mistakes such as a bind added to the view by error.

Ruleset (ABI ≥ 3 required; rights requested only up to the detected ABI, and a
profile that needs a higher ABI is disabled):

| Path (beneath) | Rights |
|----------------|--------|
| each closure store path | `READ_FILE`, `READ_DIR`, `EXECUTE` |
| `/etc` | `READ_FILE`, `READ_DIR` |
| `/workspace` | all FS rights except `MAKE_CHAR`, `MAKE_BLOCK`, `MAKE_SOCK` (Unix sockets are allowed only under `/tmp`), plus `REFER` within the same tree and `TRUNCATE`; `EXECUTE` only in `build`/`cli` |
| `/tmp`, `/dev/shm` | read/write/remove/make-reg/make-dir/make-sock/truncate; no execute |
| `/dev/null`, `/dev/zero`, `/dev/full`, `/dev/urandom`, `/dev/random` | `READ_FILE`, `WRITE_FILE` (null/full); ABI 5: no `IOCTL_DEV` |
| `/proc` | `READ_FILE`, `READ_DIR` |
| ABI 4 net | `handled_access_net = BIND_TCP\|CONNECT_TCP`; no rules in `network: none`, so TCP bind/connect is denied even on loopback unless the profile allows `loopback_tcp` ports |
| ABI 6 scope | `SCOPE_ABSTRACT_UNIX_SOCKET\|SCOPE_SIGNAL` |

The ruleset is built in stage 2 *before* `fork` (path fds are opened there) and
handed to the workload child, which calls `landlock_restrict_self`. That way the
child never has to resolve paths after dropping privileges.

Limitations: Landlock does not restrict `stat`, `chdir` or path traversal, so
names can be probed. It does not cover every filesystem operation (see
the "Current limitations" section of the kernel documentation for the pinned
version). It is only as complete as the ABI the kernel provides.
