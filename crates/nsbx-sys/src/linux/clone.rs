//! `clone3` and the single-uid map an unprivileged parent is allowed to write.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::Error;

/// `include/uapi/linux/sched.h`. `CLONE_INTO_CGROUP` does not fit in 32 bits.
pub struct CloneFlags(pub u64);

impl CloneFlags {
    pub const PIDFD: u64 = 0x0000_1000;
    pub const NEWNS: u64 = 0x0002_0000;
    pub const NEWCGROUP: u64 = 0x0200_0000;
    pub const NEWUTS: u64 = 0x0400_0000;
    pub const NEWIPC: u64 = 0x0800_0000;
    pub const NEWUSER: u64 = 0x1000_0000;
    pub const NEWPID: u64 = 0x2000_0000;
    pub const NEWNET: u64 = 0x4000_0000;
    pub const INTO_CGROUP: u64 = 0x2_0000_0000;

    pub const SANDBOX: u64 = Self::NEWUSER
        | Self::NEWPID
        | Self::NEWNS
        | Self::NEWNET
        | Self::NEWIPC
        | Self::NEWUTS
        | Self::NEWCGROUP
        | Self::INTO_CGROUP
        | Self::PIDFD;
}

#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

pub struct Child {
    pub pid: i32,
    pub pidfd: OwnedFd,
}

/// Fork-like `clone3`. The child runs `child` and then `_exit`s if it returns.
///
/// `cgroup` is the directory fd passed with `CLONE_INTO_CGROUP`. It is ignored
/// unless that flag is set.
pub fn clone3<F>(flags: u64, cgroup: Option<RawFd>, child: F) -> Result<Child, Error>
where
    F: FnOnce(),
{
    let mut pidfd: RawFd = -1;
    let args = CloneArgs {
        flags: flags | CloneFlags::PIDFD,
        pidfd: std::ptr::from_mut(&mut pidfd) as u64,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: cgroup.unwrap_or(-1) as u64,
    };
    // SAFETY: `args` is a valid clone_args of the size we pass. The pidfd slot
    // points at `pidfd` on our stack, which stays live for the call. With
    // CLONE_VM unset the child has its own address space, so running `child`
    // after the syscall returns 0 is the same class of use as `fork`.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            std::ptr::from_ref(&args),
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if rc < 0 {
        return Err(Error::last("clone3"));
    }
    if rc == 0 {
        child();
        // SAFETY: `_exit` ends the child. We must not unwind into the parent.
        unsafe { libc::_exit(126) };
    }
    // SAFETY: the kernel stored a new pidfd in `pidfd`. We own it.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd) };
    Ok(Child {
        pid: rc as i32,
        pidfd,
    })
}

/// Map namespace uid/gid 0 to the calling process. Requires the parent's
/// `setgroups` write of `deny`, which an unprivileged process must do before
/// it can write `gid_map`.
pub fn map_caller(pid: i32) -> Result<(), Error> {
    let uid = {
        // SAFETY: geteuid cannot fail.
        unsafe { libc::geteuid() }
    };
    let gid = {
        // SAFETY: getegid cannot fail.
        unsafe { libc::getegid() }
    };
    let write = |name: &str, body: &str| -> Result<(), Error> {
        std::fs::write(format!("/proc/{pid}/{name}"), body).map_err(|e| {
            Error::from_io("uid map", io::Error::new(e.kind(), format!("{name}: {e}")))
        })
    };
    write("setgroups", "deny")?;
    write("uid_map", &format!("0 {uid} 1"))?;
    write("gid_map", &format!("0 {gid} 1"))?;
    Ok(())
}

/// Two-range map: ns 0 → `base`, ns 1000 → `base + 1000` (design §5.2).
/// The writer needs `CAP_SETUID` and `CAP_SETGID` in the parent namespace.
/// `base` must be the child's current host uid. A mismatch leaves the child
/// unmapped, and it loses every capability in the new namespace.
pub fn map_slot(pid: i32, base: u32) -> Result<(), Error> {
    let high = base
        .checked_add(1000)
        .ok_or_else(|| Error::from_io("uid map", io::Error::other("slot base overflows u32")))?;
    map_ranges(pid, base, high)
}

/// Namespace uid 0 → `ns0_host`, namespace uid 1000 → `workload_host`.
/// `ns0_host` has to be the child's current host uid (see [`map_slot`]).
pub fn map_ranges(pid: i32, ns0_host: u32, workload_host: u32) -> Result<(), Error> {
    if ns0_host == workload_host {
        return Err(Error::from_io(
            "uid map",
            io::Error::other("uid ranges overlap"),
        ));
    }
    let body = format!("0 {ns0_host} 1\n1000 {workload_host} 1\n");
    let write = |name: &str, text: &str| -> Result<(), Error> {
        std::fs::write(format!("/proc/{pid}/{name}"), text).map_err(|e| {
            Error::from_io("uid map", io::Error::new(e.kind(), format!("{name}: {e}")))
        })
    };
    write("setgroups", "deny")?;
    write("gid_map", &body)?;
    write("uid_map", &body)?;
    Ok(())
}

/// Root-only check that a two-range map is what the child observes.
pub fn prove_slot_map() -> Result<(), Error> {
    if crate::euid() != 0 {
        return Err(Error::from_io("uid map", io::Error::other("euid is not 0")));
    }
    let (out_r, out_w) = crate::pipe()?;
    let (sync_r, sync_w) = crate::pipe()?;
    let out_w_fd = out_w.as_raw_fd();
    let sync_r_fd = sync_r.as_raw_fd();
    let child = clone3(CloneFlags::NEWUSER | CloneFlags::PIDFD, None, move || {
        let mut byte = [0u8; 1];
        let _ = crate::read_fd(sync_r_fd, &mut byte);
        let text = std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
        let _ = crate::write_fd(out_w_fd, text.as_bytes());
    })?;
    let parent = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
    if ppid(child.pid)? != parent {
        return Err(Error::from_io(
            "ppid",
            io::Error::other("child is not our child"),
        ));
    }
    map_slot(child.pid, 2_000_000)?;
    crate::write_fd(sync_w.as_raw_fd(), b"x")?;
    drop(sync_w);
    drop(out_w);
    let waited = crate::wait_pidfd(child.pidfd.as_raw_fd())?;
    if !waited.exited() {
        return Err(Error::from_io(
            "uid map",
            io::Error::other("child did not exit"),
        ));
    }
    let mut buf = vec![0u8; 256];
    let n = crate::read_fd(out_r.as_raw_fd(), &mut buf)?;
    let text = String::from_utf8_lossy(&buf[..n]);
    if map_has_range(&text, 0, 2_000_000) && map_has_range(&text, 1000, 2_001_000) {
        Ok(())
    } else {
        Err(Error::from_io(
            "uid map",
            io::Error::other(format!("map was {text:?}")),
        ))
    }
}

fn map_has_range(text: &str, ns: u32, host: u32) -> bool {
    text.lines().any(|line| {
        let mut nums = line
            .split_whitespace()
            .filter_map(|s| s.parse::<u32>().ok());
        nums.next() == Some(ns) && nums.next() == Some(host) && nums.next() == Some(1)
    })
}

pub fn ppid(pid: i32) -> Result<i32, Error> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|e| Error::from_io("ppid", io::Error::new(e.kind(), format!("status: {e}"))))?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<i32>().map_err(|_| {
                Error::from_io("ppid", io::Error::other(format!("bad PPid line {line}")))
            });
        }
    }
    Err(Error::from_io("ppid", io::Error::other("PPid missing")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn clone3_child_is_waitable_by_pidfd() {
        let child = clone3(0, None, || {}).unwrap();
        let status = crate::wait_pidfd(child.pidfd.as_raw_fd()).unwrap();
        assert!(status.exited());
        assert_eq!(status.exit_code(), Some(126));
    }

    #[test]
    fn single_uid_map_makes_child_root() {
        let (read, write) = pipe().unwrap();
        let child = clone3(CloneFlags::NEWUSER, None, move || {
            let mut byte = [0u8; 1];
            // SAFETY: `read` is a live pipe end inherited across clone.
            unsafe { libc::read(read, byte.as_mut_ptr().cast(), 1) };
            let uid = unsafe { libc::geteuid() };
            // SAFETY: write end inherited from the parent.
            unsafe {
                let buf = uid.to_string();
                libc::write(write, buf.as_ptr().cast(), buf.len());
                libc::_exit(0);
            }
        })
        .unwrap();
        map_caller(child.pid).unwrap();
        // SAFETY: releasing the child, then reading its report.
        unsafe { libc::write(write, b"x".as_ptr().cast(), 1) };
        let status = crate::wait_pidfd(child.pidfd.as_raw_fd()).unwrap();
        assert_eq!(status.exit_code(), Some(0));
        let mut buf = [0u8; 16];
        let n = unsafe { libc::read(read, buf.as_mut_ptr().cast(), buf.len()) };
        assert!(n > 0);
        let text = std::str::from_utf8(&buf[..n as usize]).unwrap();
        assert_eq!(text, "0");
        unsafe {
            libc::close(read);
            libc::close(write);
        }
    }

    #[test]
    fn padded_uid_map_still_matches() {
        let text = "         0    2000000          1\n      1000    2001000          1\n";
        assert!(map_has_range(text, 0, 2_000_000));
        assert!(map_has_range(text, 1000, 2_001_000));
        assert!(!map_has_range(text, 0, 1));
    }

    #[test]
    fn slot_map_is_refused_without_host_caps() {
        let result = prove_slot_map();
        if crate::euid() == 0 {
            result.expect("slot map");
        } else {
            assert!(result.is_err(), "{result:?}");
        }
    }

    fn pipe() -> io::Result<(RawFd, RawFd)> {
        let mut fds = [0; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((fds[0], fds[1]))
    }
}
