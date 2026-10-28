//! Start `nsbx-warden` between the sandbox pipes and the supervisor.

use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};

use nsbx_sys::{clone3, dup2, execve, pipe};

pub struct Forwarder {
    pub stdout: OwnedFd,
    pub stderr: OwnedFd,
    pub pidfd: OwnedFd,
}

pub fn spawn(stdout_in: OwnedFd, stderr_in: OwnedFd, cap: u64) -> Result<Forwarder, String> {
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = me
        .parent()
        .ok_or_else(|| "supervisor path has no parent".to_string())?
        .join("nsbx-warden");
    if !path.exists() {
        return Err(format!(
            "warden is not next to the supervisor ({})",
            path.display()
        ));
    }
    let (out_r, out_w) = pipe().map_err(|e| e.to_string())?;
    let (err_r, err_w) = pipe().map_err(|e| e.to_string())?;
    blocking(&stdout_in)?;
    blocking(&stderr_in)?;
    let in_fd = stdout_in.as_raw_fd();
    let err_in = stderr_in.as_raw_fd();
    let out_fd = out_w.as_raw_fd();
    let err_fd = err_w.as_raw_fd();
    let bin = CString::new(path.to_string_lossy().as_bytes()).map_err(|_| "nul".to_string())?;
    let cap_arg = CString::new(cap.to_string()).map_err(|_| "nul".to_string())?;
    let child = clone3(0, None, move || {
        let _ = dup2(in_fd, 4);
        let _ = dup2(err_in, 5);
        let _ = dup2(out_fd, 6);
        let _ = dup2(err_fd, 7);
        let err = execve(
            bin.as_c_str(),
            &[bin.as_c_str(), cap_arg.as_c_str()],
            &[] as &[&std::ffi::CStr],
        );
        let _ = nsbx_sys::write_fd(2, err.to_string().as_bytes());
    })
    .map_err(|e| e.to_string())?;
    drop(stdout_in);
    drop(stderr_in);
    drop(out_w);
    drop(err_w);
    nonblock(&out_r)?;
    nonblock(&err_r)?;
    Ok(Forwarder {
        stdout: out_r,
        stderr: err_r,
        pidfd: child.pidfd,
    })
}

fn nonblock(fd: &OwnedFd) -> Result<(), String> {
    set_nonblock(fd, true)
}

fn blocking(fd: &OwnedFd) -> Result<(), String> {
    set_nonblock(fd, false)
}

fn set_nonblock(fd: &OwnedFd, on: bool) -> Result<(), String> {
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
    let flags = fcntl_getfl(fd).map_err(|e| e.to_string())?;
    let flags = if on {
        flags | OFlags::NONBLOCK
    } else {
        flags.difference(OFlags::NONBLOCK)
    };
    fcntl_setfl(fd, flags).map_err(|e| e.to_string())
}
