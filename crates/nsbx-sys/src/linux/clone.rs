//! `clone3` and the single-uid map an unprivileged parent is allowed to write.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

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

    fn pipe() -> io::Result<(RawFd, RawFd)> {
        let mut fds = [0; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((fds[0], fds[1]))
    }
}
