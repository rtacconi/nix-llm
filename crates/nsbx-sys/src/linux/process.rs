//! pidfd signal and wait.

use std::os::fd::BorrowedFd;

use rustix::process::{WaitId, WaitIdOptions, WaitIdStatus};

use crate::Error;

pub fn pidfd_send_signal(pidfd: BorrowedFd<'_>, signal: i32) -> Result<(), Error> {
    let sig = rustix::process::Signal::from_named_raw(signal).ok_or_else(|| {
        Error::from_io(
            "pidfd_send_signal",
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad signal"),
        )
    })?;
    // Signal 0 is a liveness check. rustix rejects 0, so call the syscall.
    if signal == 0 {
        // SAFETY: `pidfd` is a valid pidfd borrowed from the caller. Signal 0
        // does not deliver a signal; the kernel only checks that the pid is live.
        let rc = unsafe { libc::syscall(libc::SYS_pidfd_send_signal, pidfd, 0, 0, 0) };
        return if rc < 0 {
            Err(Error::last("pidfd_send_signal"))
        } else {
            Ok(())
        };
    }
    rustix::process::pidfd_send_signal(pidfd, sig)
        .map_err(|e| Error::from_io("pidfd_send_signal", e.into()))
}

pub struct Wait {
    pub status: WaitIdStatus,
}

impl Wait {
    pub fn exited(&self) -> bool {
        self.status.exit_status().is_some()
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.status.exit_status()
    }
}

pub fn set_no_new_privs() -> Result<(), Error> {
    // SAFETY: the arguments are the documented prctl constants. This only
    // affects the calling process.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc < 0 {
        Err(Error::last("PR_SET_NO_NEW_PRIVS"))
    } else {
        Ok(())
    }
}

pub fn wait_pidfd(pidfd: std::os::fd::RawFd) -> Result<Wait, Error> {
    // SAFETY: the raw fd is borrowed for the duration of the wait and is not closed.
    let borrowed = unsafe { BorrowedFd::borrow_raw(pidfd) };
    let status = rustix::process::waitid(WaitId::PidFd(borrowed), WaitIdOptions::EXITED)
        .map_err(|e| Error::from_io("waitid", e.into()))?
        .ok_or_else(|| {
            Error::from_io("waitid", std::io::Error::other("child has no exit status"))
        })?;
    Ok(Wait { status })
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use super::*;
    use crate::{CloneFlags, clone3};

    #[test]
    fn no_new_privs_is_set_in_the_child() {
        let child = clone3(CloneFlags::NEWUSER, None, || {
            set_no_new_privs().expect("nnp");
            let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
            let ok = status.lines().any(|line| line == "NoNewPrivs:\t1");
            std::process::exit(if ok { 0 } else { 7 });
        })
        .expect("clone");
        let wait = wait_pidfd(child.pidfd.as_raw_fd()).expect("wait");
        assert_eq!(wait.exit_code(), Some(0));
    }
}
