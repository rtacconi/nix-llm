//! Direct kernel calls for the M0 experiments. Production code uses `nsbx-sys`;
//! these probes stay outside the workspace so their dependencies are not built
//! on platforms that cannot run them.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::RawFd;

pub const CLONE_PIDFD: u64 = 0x0000_1000;
pub const CLONE_NEWNS: u64 = 0x0002_0000;
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const CLONE_NEWPID: u64 = 0x2000_0000;
pub const CLONE_NEWNET: u64 = 0x4000_0000;
/// `CLONE_INTO_CGROUP` from `include/uapi/linux/sched.h`. Does not fit in 32 bits.
pub const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

pub const OPEN_TREE_CLONE: u32 = 1;
pub const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x4;
pub const MOVE_MOUNT_T_EMPTY_PATH: u32 = 0x40;
pub const MOUNT_ATTR_RDONLY: u64 = 0x1;
pub const MOUNT_ATTR_NOSUID: u64 = 0x2;
pub const MOUNT_ATTR_NODEV: u64 = 0x4;
pub const MOUNT_ATTR_NOEXEC: u64 = 0x8;
pub const AT_RECURSIVE: i32 = 0x8000;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MountAttr {
    pub attr_set: u64,
    pub attr_clr: u64,
    pub propagation: u64,
    pub userns_fd: u64,
}

pub fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(0)
}

pub fn io_err(context: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("{context}: {e}"))
}

/// Fork-like `clone3`. The child runs `child` and must not return.
pub fn clone3<F>(flags: u64, cgroup: Option<RawFd>, child: F) -> io::Result<(i32, RawFd)>
where
    F: FnOnce(),
{
    let mut pidfd: RawFd = -1;
    let args = CloneArgs {
        flags: flags | CLONE_PIDFD,
        pidfd: std::ptr::from_mut(&mut pidfd) as u64,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: cgroup.map(|fd| fd as u64).unwrap_or(0),
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            std::ptr::from_ref(&args),
            std::mem::size_of::<CloneArgs>(),
        )
    };
    if rc < 0 {
        return Err(io_err("clone3"));
    }
    if rc == 0 {
        child();
        unsafe { libc::_exit(126) };
    }
    Ok((rc as i32, pidfd))
}

/// Single-uid map the calling user can write for a child user namespace.
pub fn map_self(pid: i32) -> io::Result<()> {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    std::fs::write(format!("/proc/{pid}/setgroups"), "deny").map_err(|e| {
        io::Error::new(e.kind(), format!("setgroups: {e}"))
    })?;
    std::fs::write(format!("/proc/{pid}/uid_map"), format!("0 {uid} 1"))?;
    std::fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1"))?;
    Ok(())
}

pub fn execveat_empty(fd: RawFd, argv: &[&CStr], envp: &[&CStr]) -> io::Error {
    let mut av: Vec<*const libc::c_char> = argv.iter().map(|s| s.as_ptr()).collect();
    av.push(std::ptr::null());
    let mut ev: Vec<*const libc::c_char> = envp.iter().map(|s| s.as_ptr()).collect();
    ev.push(std::ptr::null());
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
    io::Error::last_os_error()
}

pub fn cstring(s: &str) -> CString {
    CString::new(s).expect("interior nul")
}

pub fn mount(source: &CStr, target: &CStr, fstype: &CStr, flags: u64, data: Option<&CStr>) -> io::Result<()> {
    let data_ptr = data.map(|d| d.as_ptr()).unwrap_or(std::ptr::null());
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            data_ptr.cast(),
        )
    };
    if rc < 0 {
        Err(io_err("mount"))
    } else {
        Ok(())
    }
}

pub fn open_tree_clone(path: &CStr) -> io::Result<RawFd> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_open_tree,
            libc::AT_FDCWD,
            path.as_ptr(),
            OPEN_TREE_CLONE | libc::O_CLOEXEC as u32,
        )
    };
    if rc < 0 {
        Err(io_err("open_tree"))
    } else {
        Ok(rc as RawFd)
    }
}

pub fn move_mount_fd(from: RawFd, to_dir: RawFd) -> io::Result<()> {
    let rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            from,
            c"".as_ptr(),
            to_dir,
            c"".as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        )
    };
    if rc < 0 {
        Err(io_err("move_mount"))
    } else {
        Ok(())
    }
}

pub fn mount_setattr_fd(fd: RawFd, attr_set: u64, recursive: bool) -> io::Result<()> {
    let attr = MountAttr {
        attr_set,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    let mut flags = libc::AT_EMPTY_PATH;
    if recursive {
        flags |= AT_RECURSIVE;
    }
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            fd,
            c"".as_ptr(),
            flags,
            std::ptr::from_ref(&attr),
            std::mem::size_of::<MountAttr>(),
        )
    };
    if rc < 0 {
        Err(io_err("mount_setattr"))
    } else {
        Ok(())
    }
}

pub fn read_status_caps() -> String {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .filter(|l| {
            l.starts_with("Cap")
                || l.starts_with("Seccomp")
                || l.starts_with("NoNewPrivs")
                || l.starts_with("Uid")
                || l.starts_with("Gid")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn pipe2() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io_err("pipe"));
    }
    Ok((fds[0], fds[1]))
}

/// Run `child` in a new user namespace.
///
/// When `map` is true, the parent writes the single-uid map and only then
/// releases the child. The child's stdout and stderr are a pipe the parent
/// returns as a string.
pub fn run_child<F>(flags: u64, map: bool, child: F) -> io::Result<(i32, String)>
where
    F: FnOnce(),
{
    let (sync_r, sync_w) = pipe2()?;
    let (out_r, out_w) = pipe2()?;
    let (pid, pidfd) = clone3(flags | CLONE_NEWUSER, None, || {
        unsafe {
            libc::close(sync_w);
            libc::close(out_r);
            if map {
                let mut byte = [0u8; 1];
                while libc::read(sync_r, byte.as_mut_ptr().cast(), 1) < 0 {
                    if errno() != libc::EINTR {
                        break;
                    }
                }
            }
            libc::dup2(out_w, 1);
            libc::dup2(out_w, 2);
            libc::close(out_w);
        }
        child()
    })?;
    unsafe {
        libc::close(sync_r);
        libc::close(out_w);
    }
    if map {
        map_self(pid)?;
        unsafe {
            libc::write(sync_w, b"x".as_ptr().cast(), 1);
            libc::close(sync_w);
        }
    } else {
        unsafe { libc::close(sync_w) };
    }
    let watch = pid;
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(90));
        unsafe { libc::kill(watch, libc::SIGKILL) };
    });
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(out_r, tmp.as_mut_ptr().cast(), tmp.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            break;
        }
        buf.extend_from_slice(&tmp[..n as usize]);
    }
    unsafe { libc::close(out_r) };
    let mut status = 0;
    let start = std::time::Instant::now();
    loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == pid {
            break;
        }
        if start.elapsed() > std::time::Duration::from_secs(90) {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            unsafe { libc::waitpid(pid, &mut status, 0) };
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    unsafe { libc::close(pidfd) };
    let text = String::from_utf8_lossy(&buf).into_owned();
    Ok((status, text))
}
