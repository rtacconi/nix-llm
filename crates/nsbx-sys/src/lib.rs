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
    Child, ChildExit, CloneFlags, FilterInsn, Watch, apply_seccomp_filter, assume_workload_uid,
    bind_tree, bind_with, chdir, chown_path, clone3, close_range, die_by_seccomp,
    drop_dev_privileges, dup2, euid, execve, execveat_empty, fd_is_open, fork_process,
    landlock_abi, make_rprivate, map_caller, map_ranges, map_slot, mount_flags, mount_proc_full,
    mount_proc_subset, mount_setattr_fd, mount_tmpfs, open_opath, open_tree_clone, openat2,
    peer_cred, pidfd_send_signal, pipe, pivot_root_detach, poll_in, ppid, prove_slot_map, read_fd,
    set_no_new_privs, stage2_exec, syscall0, unshare_mount_ns, wait_child, wait_pidfd, write_fd,
};

#[cfg(not(target_os = "linux"))]
pub use stub::{
    Child, ChildExit, CloneFlags, FilterInsn, Watch, apply_seccomp_filter, assume_workload_uid,
    bind_tree, bind_with, chdir, chown_path, clone3, close_range, die_by_seccomp,
    drop_dev_privileges, dup2, euid, execve, execveat_empty, fd_is_open, fork_process,
    landlock_abi, make_rprivate, map_caller, map_ranges, map_slot, mount_flags, mount_proc_full,
    mount_proc_subset, mount_setattr_fd, mount_tmpfs, open_opath, open_tree_clone, openat2,
    peer_cred, pidfd_send_signal, pipe, pivot_root_detach, poll_in, ppid, prove_slot_map, read_fd,
    set_no_new_privs, stage2_exec, syscall0, unshare_mount_ns, wait_child, wait_pidfd, write_fd,
};
