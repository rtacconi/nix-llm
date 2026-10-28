//! `close_range`, `openat2` and `execveat(AT_EMPTY_PATH)`.

use std::ffi::CStr;
use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd, RawFd};

use rustix::fs::{Mode, OFlags, ResolveFlags};

use crate::Error;

pub fn chdir(path: &CStr) -> Result<(), Error> {
    // SAFETY: `path` is NUL-terminated and only changes this process's cwd.
    let rc = unsafe { libc::chdir(path.as_ptr()) };
    if rc < 0 {
        Err(Error::last("chdir"))
    } else {
        Ok(())
    }
}

pub fn execve(path: &CStr, argv: &[impl AsRef<CStr>], envp: &[impl AsRef<CStr>]) -> Error {
    let mut av: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ref().as_ptr()).collect();
    av.push(std::ptr::null());
    let mut ev: Vec<*const libc::c_char> = envp.iter().map(|s| s.as_ref().as_ptr()).collect();
    ev.push(std::ptr::null());
    // SAFETY: `path`, `argv` and `envp` are NUL-terminated and live for the call.
    // On success the process image is replaced.
    unsafe { libc::execve(path.as_ptr(), av.as_ptr(), ev.as_ptr()) };
    Error::last("execve")
}

pub fn open_opath(path: &CStr) -> Result<OwnedFd, Error> {
    rustix::fs::open(path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
        .map_err(|e| Error::from_io("open", e.into()))
}

pub fn pipe() -> Result<(OwnedFd, OwnedFd), Error> {
    let mut fds = [-1; 2];
    // SAFETY: pipe2 writes two new fds into `fds`. CLOEXEC keeps them out of exec
    // unless the caller dup2s them onto the keep-list.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc < 0 {
        return Err(Error::last("pipe"));
    }
    // SAFETY: both numbers are fresh fds from pipe2. We own them.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

pub fn dup2(from: RawFd, to: RawFd) -> Result<(), Error> {
    if from == to {
        // SAFETY: clear close-on-exec so the keep-list fd survives exec.
        let rc = unsafe { libc::fcntl(from, libc::F_SETFD, 0) };
        return if rc < 0 {
            Err(Error::last("fcntl"))
        } else {
            Ok(())
        };
    }
    // SAFETY: `from` is open. `to` is replaced and any previous occupant closed.
    let rc = unsafe { libc::dup2(from, to) };
    if rc < 0 {
        return Err(Error::last("dup2"));
    }
    // SAFETY: the duplicate is `to`; the original is no longer needed.
    unsafe { libc::close(from) };
    Ok(())
}

/// Install the keep-list and exec stage 2. Does not return on success.
pub fn stage2_exec(
    program: RawFd,
    argv: &[impl AsRef<CStr>],
    report: RawFd,
    sync: RawFd,
    spec: Option<RawFd>,
) -> Error {
    if let Err(e) = dup2(report, 3) {
        return e;
    }
    if let Err(e) = dup2(sync, 4) {
        return e;
    }
    if let Some(spec) = spec
        && let Err(e) = dup2(spec, 5)
    {
        return e;
    }
    let env: [&CStr; 0] = [];
    execveat_empty(program, argv, &env)
}

pub fn read_fd(fd: RawFd, buf: &mut [u8]) -> Result<usize, Error> {
    // SAFETY: `fd` is a caller-owned descriptor and `buf` is a valid writable slice.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(Error::last("read"))
    } else {
        Ok(n as usize)
    }
}

pub fn write_fd(fd: RawFd, buf: &[u8]) -> Result<usize, Error> {
    // SAFETY: `fd` is a caller-owned descriptor and `buf` is a valid readable slice.
    let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
    if n < 0 {
        Err(Error::last("write"))
    } else {
        Ok(n as usize)
    }
}

pub fn close_range(first: u32, last: u32) -> Result<(), Error> {
    // SAFETY: close_range only closes fds in the caller's table. The range is
    // the caller's keep-list decision; fds outside it stay open.
    let rc = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0u32) };
    if rc < 0 {
        Err(Error::last("close_range"))
    } else {
        Ok(())
    }
}

pub fn openat2(
    dir: BorrowedFd<'_>,
    path: &CStr,
    flags: OFlags,
    mode: Mode,
    resolve: ResolveFlags,
) -> Result<OwnedFd, Error> {
    rustix::fs::openat2(dir, path, flags, mode, resolve)
        .map_err(|e| Error::from_io("openat2", e.into()))
}

/// `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`. Does not return on success.
pub fn execveat_empty(fd: RawFd, argv: &[impl AsRef<CStr>], envp: &[impl AsRef<CStr>]) -> Error {
    let mut av: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ref().as_ptr()).collect();
    av.push(std::ptr::null());
    let mut ev: Vec<*const libc::c_char> = envp.iter().map(|s| s.as_ref().as_ptr()).collect();
    ev.push(std::ptr::null());
    // SAFETY: `fd` is an open file the caller owns. `argv` and `envp` are
    // NUL-terminated pointer arrays built above and live for the call. On
    // success the process image is replaced.
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            fd,
            c"".as_ptr(),
            av.as_ptr(),
            ev.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
    }
    Error::last("execveat")
}

/// `true` when `fd` is readable or hung up. `timeout_ms` of -1 blocks.
pub fn poll_in(fd: RawFd, timeout_ms: i32) -> Result<bool, Error> {
    let mut fds = [libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    // SAFETY: `fds` is one pollfd for a caller-owned descriptor.
    let rc = unsafe { libc::poll(fds.as_mut_ptr(), 1, timeout_ms) };
    if rc < 0 {
        return Err(Error::last("poll"));
    }
    let flags = fds[0].revents;
    Ok(flags & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::fd::{AsFd, AsRawFd};

    #[test]
    fn close_range_closes_one_fd() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let fd = file.as_raw_fd();
        std::mem::forget(file);
        close_range(fd as u32, fd as u32).unwrap();
        // SAFETY: the fd was closed; F_GETFD must fail with EBADF.
        let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_eq!(rc, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    #[test]
    fn pipe_round_trip() {
        let (read, write) = pipe().unwrap();
        write_fd(write.as_raw_fd(), b"ok").unwrap();
        drop(write);
        let mut buf = [0u8; 2];
        let n = read_fd(read.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(&buf[..n], b"ok");
    }

    #[test]
    fn dup2_moves_a_pipe_end() {
        let (read, write) = pipe().unwrap();
        let raw = write.as_raw_fd();
        // dup2 closes `raw`. Forget the owner so Drop does not close it again.
        std::mem::forget(write);
        dup2(raw, 50).unwrap();
        write_fd(50, b"z").unwrap();
        // SAFETY: fd 50 was installed by dup2 above and is not owned by an OwnedFd.
        unsafe { libc::close(50) };
        let mut buf = [0u8; 1];
        let n = read_fd(read.as_raw_fd(), &mut buf).unwrap();
        assert_eq!(&buf[..n], b"z");
    }

    #[test]
    fn chdir_round_trip_and_missing_exec_returns() {
        let before = std::env::current_dir().unwrap();
        chdir(c"/tmp").unwrap();
        assert_eq!(
            std::env::current_dir().unwrap(),
            std::path::PathBuf::from("/tmp")
        );
        let back = CString::new(before.to_str().unwrap()).unwrap();
        chdir(&back).unwrap();
        let env: [&CStr; 0] = [];
        let missing = execve(
            c"/no/such/nsbx-binary",
            &[CString::new("nsbx").unwrap()],
            &env,
        );
        assert_eq!(missing.raw_os_error(), Some(libc::ENOENT));
    }

    #[test]
    fn openat2_rejects_a_symlink_escape() {
        let dir = std::env::temp_dir().join(format!("nsbx-openat2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/inside"), b"in").unwrap();
        std::os::unix::fs::symlink("../sub/inside", dir.join("link")).unwrap();
        let root = std::fs::File::open(dir.join("sub")).unwrap();
        let err = openat2(
            root.as_fd(),
            c"../link",
            OFlags::RDONLY,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        );
        assert!(err.is_err(), "{err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
