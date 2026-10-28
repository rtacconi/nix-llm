//! inotify on a cgroup file. `cgroup.events` is watched for `populated`.

use std::ffi::CStr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

use crate::Error;

pub struct Watch {
    fd: OwnedFd,
}

impl Watch {
    pub fn modify(path: &CStr) -> Result<Self, Error> {
        // SAFETY: inotify_init1(IN_CLOEXEC) returns a new fd we own.
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(Error::last("inotify_init1"));
        }
        // SAFETY: `path` is NUL-terminated. IN_MODIFY matches cgroup.events updates.
        let wd = unsafe { libc::inotify_add_watch(fd, path.as_ptr(), libc::IN_MODIFY) };
        if wd < 0 {
            unsafe { libc::close(fd) };
            return Err(Error::last("inotify_add_watch"));
        }
        Ok(Self {
            // SAFETY: `fd` is the new inotify fd and is not aliased.
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Block until an event arrives or `timeout` elapses.
    pub fn wait(&self, timeout: Duration) -> Result<bool, Error> {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: `pfd` points at one live pollfd. A positive result means the
        // inotify fd is readable; we do not need the event payload to know the
        // file changed.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 {
            Err(Error::last("poll"))
        } else {
            Ok(rc > 0)
        }
    }
}
