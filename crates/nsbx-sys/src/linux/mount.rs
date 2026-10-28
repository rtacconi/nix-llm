//! Mount helpers. `open_tree` and `move_mount` go through rustix.
//! `mount_setattr` does not exist in rustix 1.1.6, so it is a direct syscall.

use std::ffi::CStr;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};

use rustix::fs::{CWD, Mode, OFlags, ResolveFlags};
use rustix::mount::{MoveMountFlags, OpenTreeFlags};

use crate::Error;

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

const MOUNT_ATTR_RDONLY: u64 = 0x1;
const MOUNT_ATTR_NOSUID: u64 = 0x2;
const MOUNT_ATTR_NODEV: u64 = 0x4;
const MOUNT_ATTR_NOEXEC: u64 = 0x8;
const AT_RECURSIVE: i32 = 0x8000;

pub fn make_rprivate() -> Result<(), Error> {
    // SAFETY: the arguments are constant C strings. MS_REC|MS_PRIVATE only
    // changes this mount namespace's propagation.
    let rc = unsafe {
        libc::mount(
            c"none".as_ptr(),
            c"/".as_ptr(),
            c"none".as_ptr(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if rc < 0 {
        Err(Error::last("mount MS_PRIVATE"))
    } else {
        Ok(())
    }
}

pub fn mount_tmpfs(target: &CStr, options: &CStr) -> Result<(), Error> {
    // SAFETY: both pointers are NUL-terminated and live for the call.
    let rc = unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            target.as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            options.as_ptr().cast(),
        )
    };
    if rc < 0 {
        Err(Error::last("mount tmpfs"))
    } else {
        Ok(())
    }
}

pub fn mount_proc_full(target: &CStr) -> Result<(), Error> {
    // Full proc so stage 2 can replace meminfo and cpuinfo. `hidepid` still
    // hides other processes. Sensitive files are masked by the caller.
    mount_proc(target, c"hidepid=invisible")
}

pub fn mount_proc_subset(target: &CStr) -> Result<(), Error> {
    // SAFETY: `target` is a directory in this mount namespace. The option
    // string is a literal. This fails with EPERM unless the caller is in a
    // new PID namespace (E3).
    mount_proc(target, c"hidepid=invisible,subset=pid")
}

fn mount_proc(target: &CStr, options: &CStr) -> Result<(), Error> {
    // SAFETY: `target` is a directory in this mount namespace. `options` is a
    // literal. This fails with EPERM unless the caller is in a new PID namespace.
    let rc = unsafe {
        libc::mount(
            c"proc".as_ptr(),
            target.as_ptr(),
            c"proc".as_ptr(),
            (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
            options.as_ptr().cast(),
        )
    };
    if rc < 0 {
        Err(Error::last("mount proc"))
    } else {
        Ok(())
    }
}

pub fn open_tree_clone(path: &CStr) -> Result<OwnedFd, Error> {
    rustix::mount::open_tree(
        CWD,
        path,
        OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )
    .map_err(|e| Error::from_io("open_tree", e.into()))
}

pub fn mount_flags(
    fd: RawFd,
    readonly: bool,
    nodev: bool,
    noexec: bool,
    recursive: bool,
) -> Result<(), Error> {
    let mut attr_set = MOUNT_ATTR_NOSUID;
    if readonly {
        attr_set |= MOUNT_ATTR_RDONLY;
    }
    if nodev {
        attr_set |= MOUNT_ATTR_NODEV;
    }
    if noexec {
        attr_set |= MOUNT_ATTR_NOEXEC;
    }
    let attr = MountAttr {
        attr_set,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    let mut how = libc::AT_EMPTY_PATH;
    if recursive {
        how |= AT_RECURSIVE;
    }
    // SAFETY: `fd` is a mount fd from open_tree or an O_PATH dirfd. `attr` is
    // a mount_attr of the size we pass. AT_EMPTY_PATH applies the change to
    // the fd itself. AT_RECURSIVE is set only when the caller asked for it,
    // so a read-only root does not freeze writable children.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            fd,
            c"".as_ptr(),
            how,
            std::ptr::from_ref(&attr),
            std::mem::size_of::<MountAttr>(),
        )
    };
    if rc < 0 {
        Err(Error::last("mount_setattr"))
    } else {
        Ok(())
    }
}

pub fn mount_setattr_fd(fd: RawFd, readonly_nodev: bool, noexec: bool) -> Result<(), Error> {
    mount_flags(fd, readonly_nodev, true, noexec, true)
}

/// Attach `src` onto `dest` with the given flags. `nosuid` is always set.
pub fn bind_with(
    src: &CStr,
    dest: BorrowedFd<'_>,
    readonly: bool,
    nodev: bool,
    noexec: bool,
) -> Result<(), Error> {
    // A symlink source is rejected before the bind. Fail closed.
    let _checked = rustix::fs::openat2(
        CWD,
        src,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|e| Error::from_io("openat2", e.into()))?;
    let tree = open_tree_clone(src)?;
    mount_flags(tree.as_raw_fd(), readonly, nodev, noexec, true)?;
    rustix::mount::move_mount(
        tree,
        c"",
        dest,
        c"",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )
    .map_err(|e| Error::from_io("move_mount", e.into()))
}

/// Attach `src` onto `dest`, read-only, nosuid and nodev. Exec is allowed.
pub fn bind_tree(src: &CStr, dest: BorrowedFd<'_>) -> Result<(), Error> {
    bind_with(src, dest, true, true, false)
}

/// `pivot_root(".", ".")` then `umount2(".", MNT_DETACH)`. The caller has
/// already `chdir`'d into the new root.
pub fn pivot_root_detach() -> Result<(), Error> {
    // SAFETY: both paths are the constant ".". The caller is inside the new
    // root mount. On failure we return the errno and do not continue.
    let rc = unsafe { libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".".as_ptr()) };
    if rc < 0 {
        return Err(Error::last("pivot_root"));
    }
    // SAFETY: umount2 of "." detaches the old root that pivot_root stacked here.
    let rc = unsafe { libc::umount2(c".".as_ptr(), libc::MNT_DETACH) };
    if rc < 0 {
        Err(Error::last("umount2"))
    } else {
        Ok(())
    }
}

pub fn landlock_abi() -> Result<i32, Error> {
    // SAFETY: a NULL ruleset pointer with LANDLOCK_CREATE_RULESET_VERSION
    // returns the ABI and does not install a ruleset.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<()>(),
            0usize,
            1u32,
        )
    };
    if abi < 0 {
        Err(Error::last("landlock ABI"))
    } else {
        Ok(abi as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_flags_rejects_a_bad_fd() {
        // Outside a user namespace the kernel rejects the syscall before it
        // looks at the fd. The success path is the M3 pivot.
        let err = mount_flags(1_000_000, true, true, false, false).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn landlock_abi_is_at_least_3() {
        let abi = landlock_abi().unwrap();
        assert!(abi >= 3, "abi {abi}");
    }
}
