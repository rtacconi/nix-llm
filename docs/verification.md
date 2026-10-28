# M0 verification

Checked on this host on 28 October 2026 (Europe/London): Linux 6.18.50
(`x86_64`), NixOS, cgroup v2 unified hierarchy, Landlock in the LSM list,
`/dev/kvm` present, unprivileged user namespaces usable (`unshare --user`
succeeds). There is no `kernel.unprivileged_userns_clone` sysctl and
AppArmor is not restricting user namespaces.

Sources are kernel `Documentation/` as published for the documented
interface, man-pages 6.19, the Landlock ABI table in `landlock(7)`, and the
crate sources resolved for this run (`rustix` 1.1.6, `landlock` 0.4.7,
`seccompiler` 0.5.0, `libc` 0.2.191). Experiments are
`experiments/m0` (`cargo run --manifest-path experiments/m0/Cargo.toml --release -- eN`).
That package is outside the workspace because its Linux-only dependencies do
not build on the Darwin flake outputs.

## Kernel claims (§4)

| Claim | Result | Source |
|-------|--------|--------|
| Minimum kernel 6.6; this host is newer | Verified | `uname -r` is 6.18.50 |
| `clone3` | Verified, Linux 5.3 | `clone(2)` / `clone3` history. E1 runs it |
| `CLONE_PIDFD` | Verified, Linux 5.2 | `clone(2)`. E1 requests it |
| `CLONE_INTO_CGROUP` | Verified, Linux 5.7 | `clone(2)` and the 5.7 merge notes. The flag is `0x200000000` and does not fit in a 32-bit `clone` flags word |
| User namespaces, unprivileged when allowed | Verified, Linux 3.8 | `user_namespaces(7)`. This host allows them |
| PID, mount, net, IPC, UTS, cgroup namespaces | Verified, cgroup ns in 4.6, the others older | `namespaces(7)`. E5 creates the set used by stage 2 |
| Time namespace, unused | Verified, Linux 5.6 | `time_namespaces(7)`. Not used |
| `open_tree`, `move_mount` | Verified, Linux 5.2 | `open_tree(2)`, `move_mount(2)`. E2 calls both |
| `mount_setattr` | Verified, Linux 5.12 | `mount_setattr(2)`. E2 calls it. Not wrapped by rustix 1.1.6 |
| `pivot_root` + `MNT_DETACH` | Verified | `pivot_root(2)`, `umount(2)`. E5 uses the `"."` / `"."` sequence from the manual |
| UID/GID maps; multi-range needs `CAP_SETUID`/`CAP_SETGID` | Verified | `user_namespaces(7)`. An unprivileged parent can write one line mapping its own ids, and only after `setgroups` is `deny`. E4 |
| `PR_SET_NO_NEW_PRIVS` | Verified, Linux 3.5 | `prctl(2)`. E4 reads `NoNewPrivs: 1` |
| seccomp-BPF; `SECCOMP_RET_KILL_PROCESS` | Verified, Linux 3.5 and 4.14 | `seccomp(2)`. seccompiler 0.5.0 exposes `SeccompAction::KillProcess` |
| Landlock ABI versions | Corrected | See below |
| cgroup v2 memory, cpu, pids, `memory.oom.group`, `memory.peak` | Verified present | `admin-guide/cgroup-v2.rst` documents both files. This host's unified hierarchy lists `memory` and `pids` in the worker cgroup and `cpu` in a delegated user scope. The current document does not restate introduction versions; the design's 4.5–5.19 span is not contradicted |
| `cgroup.kill` | Verified, Linux 5.14 | `cgroup-v2.rst` and the 5.14 merge |
| `cgroup.events` | Verified, Linux 4.5 | `cgroup-v2.rst` (`populated`) |
| `cgroup.freeze` | Verified, Linux 5.2 | `cgroup-v2.rst`. Optional, as designed |
| `pidfd_open`, `pidfd_send_signal`, `waitid(P_PIDFD)` | Verified, Linux 5.3 / 5.1 / 5.4 | `pidfd_open(2)`, `pidfd_send_signal(2)`, `waitid(2)`. rustix 1.1.6 wraps all three |
| `close_range` | Verified, Linux 5.9 | `close_range(2)`. Not wrapped by rustix 1.1.6 |
| `openat2` `RESOLVE_*` | Verified, Linux 5.6 | `openat2(2)`. rustix 1.1.6 wraps it |
| `proc` `hidepid=invisible,subset=pid` | Verified, `subset=pid` since Linux 5.8 | `proc(5)`. E3 mounts it inside a new PID namespace. `hidepid=invisible` is the named form of the historical `hidepid=2` value |
| overlayfs in a user namespace, unused | Verified, Linux 5.11 | `overlayfs` kernel documentation. Not used |
| `memfd_create` and seals | Verified, Linux 3.17 | `memfd_create(2)`, `fcntl(2)` `F_ADD_SEALS` |

### Landlock ABI correction

`landlock(7)` (man-pages 6.19) and the `landlock` 0.4.7 `ABI` enum:

| ABI | Kernel | New surface |
|-----|--------|-------------|
| 1 | 5.13 | filesystem access |
| 2 | 5.19 | `REFER` |
| 3 | 6.2 | `TRUNCATE` |
| 4 | 6.7 | TCP bind/connect |
| 5 | 6.10 | device ioctl |
| 6 | 6.12 | abstract-socket and signal scope |
| 7 | 6.15 | audit restrict-self flags |
| 8 | 7.0 | `LANDLOCK_RESTRICT_SELF_TSYNC` |
| 9 | 7.1 | `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` |

The original table stopped at ABI 6. This kernel's
`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` returns
**7** (E6). Detection keeps using that syscall. The crate's
`CompatLevel::HardRequirement` is a real method (`Compatible`) and
`AccessFs::from_all(ABI::V3)` is accepted on this kernel (E6). Rights are
still requested only up to the ABI the supervisor is prepared to name; ABI 7
adds audit flags, not filesystem rights the ruleset needs.

### Crate coverage (E6)

rustix 1.1.6, features `mount`, `fs`, `process`:

- Present: `open_tree`, `move_mount`, `mount`, `unmount`, `pivot_root`,
  `openat2`, `pidfd_open`, `pidfd_send_signal`, `waitid` with `P_PIDFD`,
  `execveat` (an `unsafe` function).
- Absent: `mount_setattr`, `clone3` (listed under `not_implemented`),
  `close_range`.

`nsbx-sys` calls rustix for the first list and `libc::syscall` for the second.
`open_tree` from an unprivileged process that is **not** in its own user and
mount namespace returns `EPERM` (E6). The same call succeeds after `clone3`
into those namespaces and the single-uid map (E2).

## Experiments

### E1 — `execveat(AT_EMPTY_PATH)` from a fresh `clone3` child

`execveat(2)` allows an empty path with `AT_EMPTY_PATH` on an `O_PATH` fd.
On this kernel the call works **before** the parent writes the uid map. The
child's euid is the overflow id 65534 and the exec'd image still runs. After
the map, the same fd and an `O_RDONLY` fd both run as euid 0. The design's
order (exec stage 2, then write the map, then the image blocks on the sync
pipe) holds.

### E2 — per-path bind cost

One run, not an M8 baseline. Closure of the host Python env: 159 store paths.
`open_tree(OPEN_TREE_CLONE)`, `mount_setattr` (`RDONLY|NOSUID|NODEV`),
`move_mount` onto a fresh tmpfs, inside a user and mount namespace:

| Paths | Wall time of the whole child, including namespace setup |
|-------|---------------------------------------------------------|
| 1 | 20.8 ms |
| 10 | 21.0 ms |
| 40 | 21.6 ms |
| 80 | 22.5 ms |

Every sample exited 0. Namespace setup dominates this sample, and the
per-path bind is not a reason to abandon decision D1. Numbers stay out of
`design.md`.

### E3 — `max_user_namespaces`

Inside a new user namespace the file reads `2147483647`, while the host reads
`254766`. Writing `0` succeeds inside and the host value is unchanged.
A nested `unshare(CLONE_NEWUSER)` then fails with `ENOSPC` (errno 28). The
limit is per user namespace, writable downwards from inside, and effective
for descendants.

`proc` mounted with `hidepid=invisible,subset=pid` succeeds only when the
caller is also in a new PID namespace. Without one, even a plain `proc` mount
returns `EPERM`. Under `subset=pid`, `/proc/self` is visible and
`/proc/sys/user/max_user_namespaces` is not. Stage 2 therefore writes the
sysctl through the inherited proc **before** mounting the subset proc. §5.4
and §6.3 say so.

### E4 — securebits and the uid switch

With the single-uid map an unprivileged parent can write:

- `setgroups(0)` returns `EPERM`, because the map write had to set
  `setgroups` to `deny`.
- `setresgid(1000)` returns `EINVAL`. Gid 1000 is not mapped. The only mapped
  ids are 0.

So dev mode cannot perform step 11d's production uid switch. The order that
does reach an empty capability state while staying at uid 0 is:

1. `PR_CAPBSET_DROP` for every capability (`EINVAL` stops the loop at the
   first unknown number).
2. Clear ambient and inheritable.
3. `PR_SET_SECUREBITS` with `NOROOT`, `NOROOT_LOCKED`,
   `NO_SETUID_FIXUP_LOCKED` (the bit itself **off**), `KEEP_CAPS_LOCKED`,
   `NO_CAP_AMBIENT_RAISE` and its lock. This still requires `CAP_SETPCAP`.
4. `capset` permitted, effective and inheritable to 0.
5. `PR_SET_NO_NEW_PRIVS`.

The resulting `Uid` line is `0`, every `Cap*` line is 0, and `NoNewPrivs`
is 1. Locking securebits after a uid change that dropped `CAP_SETPCAP` cannot
work, so §5.4 locks them before the credential change. Production, where
idmap installs the 0 and 1000 ranges and does not deny `setgroups`, still
uses `setgroups` / `setresgid` / `setresuid` for that change. The dev-mode
`capset` is the substitute, and only the dev-mode feature compiles it in.

### E5 — Python, Node and gcc

Each tool ran in a pivoted tmpfs with its Nix closure bind-mounted read-only,
`proc` mounted `hidepid=invisible,subset=pid`, no `/sys`, a new net/IPC/UTS
namespace, and a seccomp filter that returns `ENOSYS` for `clone3` and allows
every other syscall.

| Tool | Result |
|------|--------|
| `python3.13 -c 'print(1)'` | exit 0, stdout `1` |
| `node -e 'process.exit(0)'` | exit 0 |
| gcc wrapper compiling `int main(void){return 0;}` and running it | exit 0 |

All three work under those restrictions on this host.

### E6 — Landlock crate and rustix

Recorded above. Hard-requirement handling of ABI 3 rights succeeds.
`landlock` 0.4.7 knows ABIs 1 through 9.

### E7 — user namespace and `/dev/kvm`

`KVM_GET_API_VERSION` is 12 on the host and inside the user namespace.
`KVM_CREATE_VM` returns a new fd in both places. On this kernel a jailed VMM
can hold `/dev/kvm` inside a user namespace. This does not decide the
microVM backend; it answers the experiment.

## Host notes that are not design changes

- `kernel.io_uring_disabled` is 0. Strict mode refuses to start until it is 2,
  as §2 already requires. Seccomp still kills `io_uring_*`.
- The worker cgroup delegated to this process has `memory` and `pids` only.
  `systemd-run --user --scope -p Delegate=yes` gets `cpu io memory pids`.
  Integration tests that write `cpu.max` run in that scope. A missing required
  controller is a startup failure, not a silent downgrade.
- `kernel.unprivileged_bpf_disabled` is 2, `perf_event_paranoid` is 2,
  `vm.unprivileged_userfaultfd` is 0, and the symlink/hardlink protections
  are 1.
