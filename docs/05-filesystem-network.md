# 05 — Filesystem and network policy

## Exact filesystem view (namespace backend)

The new root is a fresh `tmpfs` (`size=1m,mode=0755,nr_inodes=4096`). Stage 2
populates it and remounts it read-only before the workload exists.

| Path in sandbox | Source | Type / flags | Notes |
|-----------------|--------|--------------|-------|
| `/` | new tmpfs | `ro,nosuid,nodev,noexec` after setup | Only mountpoint directories and symlinks |
| `/nix/store/<hash>-<name>` (one per closure path) | host `/nix/store/<…>` | bind, `ro,nosuid,nodev` (exec allowed) | Only paths listed in the runtime's `closureInfo` `store-paths`; `MS_REC` is **not** used |
| `/bin`, `/usr/bin/env` | symlinks into the runtime's `buildEnv` | — | For shebang compatibility |
| `/etc` | tmpfs populated from the runtime's skeleton | `ro,nosuid,nodev,noexec` | `passwd`/`group` list only `root(0)` and `sandbox(1000)`; empty `resolv.conf`; `hosts` with `localhost` only; no `ld.so.preload`; no `machine-id` |
| `/workspace` | tmpfs, `size=<policy>` | `rw,nosuid,nodev`, exec per profile (`exec` for build profiles, `noexec` otherwise) | Owned by 1000:1000; request files written here by stage 2 |
| `/tmp` | tmpfs, `size=<policy>` | `rw,nosuid,nodev,noexec` | mode 1777 |
| `/dev` | tmpfs `size=64k` | `ro,nosuid,noexec` after setup | Contains binds of host `null`, `zero`, `full`, `random`, `urandom` (device nodes cannot be created in a userns, so they must be bound), symlinks `fd → /proc/self/fd`, `stdin/stdout/stderr` |
| `/dev/shm` | tmpfs `size=<policy>` | `rw,nosuid,nodev,noexec` | Needed by Python `multiprocessing` and some Node addons |
| `/dev/pts` | **not mounted** | — | No TTY in v1 |
| `/proc` | new proc instance | `nosuid,nodev,noexec,hidepid=invisible,subset=pid` | Profiles may set `proc: full`. Then `subset` is dropped and runc-style masks are applied: `/dev/null` binds over `kcore`, `sysrq-trigger`, `timer_list`, `sched_debug`, `keys`, `kallsyms`, and `/proc/sys` remounted read-only |
| `/sys` | **not mounted** | — | Nothing in the target runtimes needs it. If a profile ever does, it needs a separate review |
| cgroupfs | **not mounted** | — | Part of the migration defence |

Not present by construction: host `/home`, `/root`, `/run` (and so no host Unix
sockets), `/var`, other store paths, any `/proc` entry for host processes.

### Mount propagation and flags policy

1. The first action after the maps are written is `mount(NULL, "/", NULL,
   MS_REC|MS_PRIVATE, NULL)`, so nothing propagates in either direction.
2. Every bind uses fd-based APIs: `open_tree(OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC)`
   on the source, `mount_setattr` for `MOUNT_ATTR_RDONLY|NOSUID|NODEV` (and
   `NOEXEC` where listed), then `move_mount` onto a target **dirfd** in the new
   tmpfs. Source paths are host store paths validated by the supervisor
   (regex `^/nix/store/[0-9a-z]{32}-[^/]+$`, opened with `openat2(RESOLVE_NO_SYMLINKS)`).
3. Locked mounts: flags inherited from the host mount (for example a `nosuid`
   store) cannot be cleared inside the userns. We rely on this as a bonus, not
   as the mechanism.
4. After `pivot_root(".", ".")`, `umount2(".", MNT_DETACH)` drops the old root.
   A test then checks `/proc/self/mountinfo` contains **only** the expected
   entries (an exact set comparison, not a subset check).

### Symlinks and boundaries

- Mount targets are created by stage 2 inside the fresh tmpfs before the workload
  exists, so there is no attacker-writable directory during setup.
- Request files for `/workspace` are written by stage 2 with
  `openat2(ws_dirfd, rel, RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV)`,
  `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0644, chowned to 1000. Paths are
  normalised and rejected if they have `..`, NUL, a leading `/`, or are
  longer than 4096 bytes or deeper than 32 components.
- Artefact collection after the run: init has already killed **every** workload
  process (`kill(-1)`, then `waitid` until `ECHILD`), so nothing can race it. It
  opens requested paths with the same `RESOLVE_*` flags, refuses non-regular
  files, and streams at most `artefact_bytes_max` bytes in total.
- Landlock adds a second check: workload write access is limited to
  `/workspace`, `/tmp`, `/dev/shm`, and the character devices `null`/`zero`/`full`.

### Bounded storage

All writable storage is tmpfs. Two independent bounds apply: the tmpfs `size=`
and `nr_inodes=`, and the job's `memory.max`, because tmpfs pages are charged
to the memory cgroup of the task that faults them in. The policy validator
enforces `workspace + tmp + shm ≤ memory.max − runtime_headroom`, so a full
disk shows up as `ENOSPC` and not as an OOM kill. Disk-backed workspaces (XFS
project quotas or loop images) need host privilege and are open decision **D6**.

## Network policy

### Default: `network: none`

The sandbox has a new network namespace containing only `lo`, which is down
until stage 2 brings it up (via an `ioctl(SIOCSIFFLAGS)` on a socket in the new
netns, using userns caps). There are no routes, no other interfaces, no DNS
resolver and an empty `resolv.conf`. Seccomp limits `socket()` to `AF_UNIX`
(and `AF_INET`/`AF_INET6` for loopback-only use in profiles that need local
test servers). `AF_NETLINK`, `AF_PACKET` and the rest are denied, so even with
the netns in place the workload cannot open netlink sockets.

Security comes from **there being nothing to reach**, not from filtering.
Cloud metadata, host loopback services and link-local addresses are unreachable
because no interface leads anywhere.

### Optional: `network: egress-proxy` (milestone M9, stubbed in v1)

The v1 supervisor rejects this profile setting with `unsupported_feature`. Design:

```text
workload ──TCP 127.0.0.1:3128──▶ in-sandbox forwarder (part of init; ns-uid 0)
         ──AF_UNIX (bind-mounted socket path)──▶ host nsbx-egress (own UID: nsbx-egress)
         ──TCP──▶ internet
```

1. Path-based Unix sockets work across network namespaces. Only one socket path
   is bound into `/run/nsbx/egress.sock`.
2. `nsbx-egress` speaks HTTP CONNECT. Per job it:
   - matches the requested host against the profile's domain allowlist
     (application-level, the first layer);
   - **resolves the name itself** and checks every resulting address against a
     deny list: `0.0.0.0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12,
     192.0.0/24, 192.168/16, 198.18/15, 224/4, 240/4, ::/128, ::1/128,
     ::ffff:0:0/96 (mapped addresses are unmapped and re-checked), fc00::/7,
     fe80::/10, ff00::/8`, plus any cloud metadata addresses configured;
   - connects to **that exact address**, with no second lookup, which closes
     the DNS-rebinding window;
   - enforces per-job byte and connection quotas.
3. **Kernel backstop:** host nftables rules match `meta skuid nsbx-egress` and
   drop every destination in the deny list, and allow only TCP to ports in the
   profile's set. A proxy bug therefore still cannot reach metadata or private
   ranges. This is what makes the policy more than hostname filtering.
4. DNS: the workload gets no resolver. Tools that honour `HTTPS_PROXY` resolve
   through CONNECT. Raw UDP/DNS is unavailable by design.

Alternatives considered: a veth + host bridge + nftables per sandbox (needs
`CAP_NET_ADMIN` on the host and a much larger host-side configuration surface);
`pasta`/`slirp4netns` userspace networking (unprivileged, but filtering would need
a dedicated UID per instance and gives full L4 egress rather than a reviewed
CONNECT surface). The proxy approach keeps the host privileged footprint at
"one nftables ruleset applied by NixOS".
