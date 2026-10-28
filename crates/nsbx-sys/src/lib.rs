//! Linux system calls used to build a sandbox.
//!
//! This is the only crate in the workspace that may contain `unsafe`. Other
//! crates call these wrappers. On non-Linux targets the same names exist and
//! return [`Error::Unsupported`], so the rest of the workspace still builds.

mod error;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(not(target_os = "linux"))]
mod stub;

pub use error::Error;

#[cfg(target_os = "linux")]
pub use linux::{
    Child, CloneFlags, Watch, bind_tree, clone3, close_range, dup2, execveat_empty, landlock_abi,
    make_rprivate, map_caller, mount_proc_subset, mount_setattr_fd, mount_tmpfs, open_opath,
    open_tree_clone, openat2, pidfd_send_signal, pipe, pivot_root_detach, read_fd, stage2_exec,
    wait_pidfd, write_fd,
};

#[cfg(not(target_os = "linux"))]
pub use stub::{
    Child, CloneFlags, Watch, bind_tree, clone3, close_range, dup2, execveat_empty, landlock_abi,
    make_rprivate, map_caller, mount_proc_subset, mount_setattr_fd, mount_tmpfs, open_opath,
    open_tree_clone, openat2, pidfd_send_signal, pipe, pivot_root_detach, read_fd, stage2_exec,
    wait_pidfd, write_fd,
};
