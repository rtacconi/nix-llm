//! Dev-mode privilege drop. Production uid 1000 needs idmap (M6); this path
//! stays at namespace uid 0 and clears every capability set. Experiment E4.

use crate::Error;

const PR_CAP_AMBIENT: i32 = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: u64 = 4;
const NOROOT: u64 = 1;
const NOROOT_LOCKED: u64 = 2;
const NO_SETUID_FIXUP_LOCKED: u64 = 8;
const KEEP_CAPS_LOCKED: u64 = 0x20;
const NO_CAP_AMBIENT_RAISE: u64 = 0x40;
const NO_CAP_AMBIENT_RAISE_LOCKED: u64 = 0x80;
const CAP_VERSION: u32 = 0x2008_0522;

#[repr(C)]
struct Hdr {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Data {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Clear the bounding, ambient, inheritable, permitted and effective sets,
/// lock securebits, and set `NO_NEW_PRIVS`. The caller stays uid 0.
pub fn drop_dev_privileges() -> Result<(), Error> {
    for cap in 0..64 {
        // SAFETY: the capability index is a small integer. EINVAL ends the
        // walk once the kernel has no further defined capabilities.
        let rc = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINVAL) {
                return Err(Error::from_io("PR_CAPBSET_DROP", err));
            }
        }
    }
    // SAFETY: clear every ambient capability. The constants are the documented
    // prctl operation. This only affects the caller.
    let rc = unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
    if rc < 0 {
        return Err(Error::last("PR_CAP_AMBIENT"));
    }
    let hdr = Hdr {
        version: CAP_VERSION,
        pid: 0,
    };
    // Keep permitted and effective for the securebit lock, clear inheritable.
    let keep = [
        Data {
            effective: u32::MAX,
            permitted: u32::MAX,
            inheritable: 0,
        },
        Data {
            effective: u32::MAX,
            permitted: u32::MAX,
            inheritable: 0,
        },
    ];
    // SAFETY: `hdr` and `keep` match the capset ABI (version 3, two words).
    let rc = unsafe { libc::syscall(libc::SYS_capset, &hdr, keep.as_ptr()) };
    if rc < 0 {
        return Err(Error::last("capset"));
    }
    let bits = NOROOT
        | NOROOT_LOCKED
        | NO_SETUID_FIXUP_LOCKED
        | KEEP_CAPS_LOCKED
        | NO_CAP_AMBIENT_RAISE
        | NO_CAP_AMBIENT_RAISE_LOCKED;
    // SAFETY: the bit set is the locked securebits from E4. NO_SETUID_FIXUP
    // itself stays off so a later uid change would still clear permitted caps.
    let rc = unsafe { libc::prctl(libc::PR_SET_SECUREBITS, bits, 0, 0, 0) };
    if rc < 0 {
        return Err(Error::last("PR_SET_SECUREBITS"));
    }
    let zero = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: same capset ABI, now with every set zero. The caller stays uid 0.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &hdr, zero.as_ptr()) };
    if rc < 0 {
        return Err(Error::last("capset"));
    }
    crate::set_no_new_privs()
}

/// Invoke a syscall with six zero arguments. Used by the probe. A seccomp kill
/// never returns.
pub fn syscall0(nr: i64) -> Result<i64, Error> {
    // SAFETY: the number comes from the probe's name table. The arguments are
    // zeros, so the call cannot name a path, a buffer, or a command.
    let rc = unsafe { libc::syscall(nr, 0, 0, 0, 0, 0, 0) };
    if rc < 0 {
        Err(Error::last("syscall"))
    } else {
        Ok(rc)
    }
}

/// Effective uid of this process.
pub fn euid() -> u32 {
    // SAFETY: geteuid cannot fail and has no side effect.
    unsafe { libc::geteuid() }
}

pub fn peer_cred(fd: std::os::fd::RawFd) -> Result<(u32, u32, u32), Error> {
    #[repr(C)]
    struct Ucred {
        pid: u32,
        uid: u32,
        gid: u32,
    }
    let mut cred = Ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<Ucred>() as libc::socklen_t;
    // SAFETY: `fd` is a connected unix socket. `cred` is a ucred of the size
    // we pass. SO_PEERCRED does not install any passed descriptor.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut Ucred).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        Err(Error::last("SO_PEERCRED"))
    } else {
        Ok((cred.pid, cred.uid, cred.gid))
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;
    use crate::{CloneFlags, clone3, map_caller, pipe, read_fd, wait_pidfd, write_fd};

    #[test]
    fn dev_drop_clears_caps_and_sets_no_new_privs() {
        let (report_r, report_w) = pipe().unwrap();
        let (sync_r, sync_w) = pipe().unwrap();
        let report = report_w.as_raw_fd();
        let sync = sync_r.as_raw_fd();
        let child = clone3(CloneFlags::NEWUSER, None, move || {
            let mut byte = [0u8; 1];
            let _ = crate::read_fd(sync, &mut byte);
            drop_dev_privileges().expect("drop");
            let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            let _ = write_fd(report, status.as_bytes());
            std::process::exit(0);
        })
        .unwrap();
        drop(report_w);
        drop(sync_r);
        map_caller(child.pid).unwrap();
        write_fd(sync_w.as_raw_fd(), b"x").unwrap();
        let wait = wait_pidfd(child.pidfd.as_raw_fd()).unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = read_fd(report_r.as_raw_fd(), &mut tmp).unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        let text = String::from_utf8_lossy(&buf);
        assert!(wait.exited() && wait.exit_code() == Some(0), "{text}");
        for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            let line = text.lines().find(|l| l.starts_with(key)).unwrap_or("");
            assert!(line.ends_with("0000000000000000"), "{line}");
        }
        assert!(text.contains("NoNewPrivs:\t1"), "{text}");
    }
}
