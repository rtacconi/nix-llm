//! Non-Linux stubs. The functions exist so the workspace builds; calling them
//! is a hard error.

use std::ffi::CStr;
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};

use crate::Error;

pub struct CloneFlags;

impl CloneFlags {
    pub const PIDFD: u64 = 0;
    pub const NEWNS: u64 = 0;
    pub const NEWCGROUP: u64 = 0;
    pub const NEWUTS: u64 = 0;
    pub const NEWIPC: u64 = 0;
    pub const NEWUSER: u64 = 0;
    pub const NEWPID: u64 = 0;
    pub const NEWNET: u64 = 0;
    pub const INTO_CGROUP: u64 = 0;
    pub const SANDBOX: u64 = 0;
}

pub struct Child {
    pub pid: i32,
    pub pidfd: OwnedFd,
}

fn no<T>(name: &'static str) -> Result<T, Error> {
    Err(Error::Unsupported(name))
}

pub fn clone3<F>(_flags: u64, _cgroup: Option<RawFd>, _child: F) -> Result<Child, Error>
where
    F: FnOnce(),
{
    no("clone3")
}

pub fn map_caller(_pid: i32) -> Result<(), Error> {
    no("map_caller")
}

pub fn map_slot(_pid: i32, _base: u32) -> Result<(), Error> {
    no("map_slot")
}

pub fn ppid(_pid: i32) -> Result<i32, Error> {
    no("ppid")
}

pub fn prove_slot_map() -> Result<(), Error> {
    no("prove_slot_map")
}

pub fn close_range(_first: u32, _last: u32) -> Result<(), Error> {
    no("close_range")
}

pub fn chdir(_path: &CStr) -> Result<(), Error> {
    no("chdir")
}

pub fn execve(_path: &CStr, _argv: &[impl AsRef<CStr>], _envp: &[impl AsRef<CStr>]) -> Error {
    Error::Unsupported("execve")
}

pub fn open_opath(_path: &CStr) -> Result<OwnedFd, Error> {
    no("open")
}

pub fn pipe() -> Result<(OwnedFd, OwnedFd), Error> {
    no("pipe")
}

pub fn poll_in(_fd: RawFd, _timeout_ms: i32) -> Result<bool, Error> {
    no("poll")
}

pub fn dup2(_from: RawFd, _to: RawFd) -> Result<(), Error> {
    no("dup2")
}

pub fn stage2_exec(
    _program: RawFd,
    _argv: &[impl AsRef<CStr>],
    _report: RawFd,
    _sync: RawFd,
    _spec: Option<RawFd>,
) -> Error {
    Error::Unsupported("execveat")
}

pub fn bind_with(
    _src: &CStr,
    _dest: BorrowedFd<'_>,
    _readonly: bool,
    _nodev: bool,
    _noexec: bool,
) -> Result<(), Error> {
    no("bind")
}

pub fn mount_flags(
    _fd: RawFd,
    _readonly: bool,
    _nodev: bool,
    _noexec: bool,
    _recursive: bool,
) -> Result<(), Error> {
    no("mount_setattr")
}

#[derive(Clone, Copy)]
pub struct FilterInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

pub fn apply_seccomp_filter(_prog: &[FilterInsn]) -> Result<(), Error> {
    no("seccomp")
}

pub fn set_no_new_privs() -> Result<(), Error> {
    no("no_new_privs")
}

pub fn euid() -> u32 {
    0
}

pub fn drop_dev_privileges() -> Result<(), Error> {
    no("capset")
}

pub fn syscall0(_nr: i64) -> Result<i64, Error> {
    no("syscall")
}

pub fn peer_cred(_fd: RawFd) -> Result<(u32, u32, u32), Error> {
    no("SO_PEERCRED")
}

pub fn read_fd(_fd: RawFd, _buf: &mut [u8]) -> Result<usize, Error> {
    no("read")
}

pub fn write_fd(_fd: RawFd, _buf: &[u8]) -> Result<usize, Error> {
    no("write")
}

pub fn openat2(
    _dir: BorrowedFd<'_>,
    _path: &CStr,
    _flags: rustix::fs::OFlags,
    _mode: rustix::fs::Mode,
    _resolve: rustix::fs::ResolveFlags,
) -> Result<OwnedFd, Error> {
    no("openat2")
}

pub fn execveat_empty(_fd: RawFd, _argv: &[impl AsRef<CStr>], _envp: &[impl AsRef<CStr>]) -> Error {
    Error::Unsupported("execveat")
}

pub fn pidfd_send_signal(_pidfd: BorrowedFd<'_>, _signal: i32) -> Result<(), Error> {
    no("pidfd_send_signal")
}

pub struct Wait;

impl Wait {
    pub fn exited(&self) -> bool {
        false
    }
    pub fn exit_code(&self) -> Option<i32> {
        None
    }
}

pub fn wait_pidfd(_pidfd: RawFd) -> Result<Wait, Error> {
    no("waitid")
}

pub fn make_rprivate() -> Result<(), Error> {
    no("mount")
}
pub fn mount_tmpfs(_target: &CStr, _options: &CStr) -> Result<(), Error> {
    no("mount")
}
pub fn mount_proc_subset(_target: &CStr) -> Result<(), Error> {
    no("mount")
}
pub fn mount_proc_full(_target: &CStr) -> Result<(), Error> {
    no("mount")
}
pub fn open_tree_clone(_path: &CStr) -> Result<OwnedFd, Error> {
    no("open_tree")
}
pub fn mount_setattr_fd(_fd: RawFd, _readonly: bool, _noexec: bool) -> Result<(), Error> {
    no("mount_setattr")
}
pub fn bind_tree(_src: &CStr, _dest: BorrowedFd<'_>) -> Result<(), Error> {
    no("move_mount")
}
pub fn pivot_root_detach() -> Result<(), Error> {
    no("pivot_root")
}
pub fn landlock_abi() -> Result<i32, Error> {
    no("landlock")
}

pub struct Watch;
impl Watch {
    pub fn modify(_path: &CStr) -> Result<Self, Error> {
        no("inotify")
    }
    pub fn wait(&self, _timeout: std::time::Duration) -> Result<bool, Error> {
        no("inotify")
    }
}
