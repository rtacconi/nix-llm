//! Stage-2 filesystem, in the order of design §5.4 and §6.
//!
//! `exec_workload` is implemented only for [`Restricted<SeccompApplied>`].
//! The filter installed here allows every syscall except `clone3`, which
//! returns `ENOSYS`. M4 replaces it with the profile's kill list and allow
//! list. Landlock is inserted in front of this step in M4.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, AsRawFd};
use std::path::Path;

use nsbx_sys::Error;

pub struct Spec {
    pub runtime: String,
    pub etc: String,
    pub closure: Vec<String>,
    pub argv: Vec<CString>,
}

pub struct Private {
    _priv: (),
}

pub struct Rooted {
    _priv: (),
}

pub struct Pivoted {
    _priv: (),
}

pub struct SeccompApplied {
    _priv: (),
}

pub struct Restricted<T> {
    _mark: T,
}

const ROOT: &str = "/tmp/nsbx-root";

pub fn begin() -> Result<Private, Error> {
    nsbx_sys::make_rprivate()?;
    // subset=pid hides this file, so it is written through the inherited proc
    // before that mount (experiment E3).
    std::fs::write("/proc/sys/user/max_user_namespaces", "0")
        .map_err(|e| Error::from_io("max_user_namespaces", e))?;
    Ok(Private { _priv: () })
}

impl Private {
    pub fn mount_root(self, spec: &Spec) -> Result<Rooted, Error> {
        if !store_path(&spec.runtime) {
            return Err(Error::from_io(
                "runtime",
                std::io::Error::other("runtime is not a store path"),
            ));
        }
        let _ = std::fs::remove_dir_all(ROOT);
        std::fs::create_dir_all(ROOT).map_err(|e| Error::from_io("root", e))?;
        nsbx_sys::mount_tmpfs(&c_str(ROOT)?, c"size=1m,mode=755")?;
        for path in &spec.closure {
            if !store_path(path) {
                return Err(Error::from_io(
                    "closure",
                    std::io::Error::other("closure entry is not a store path"),
                ));
            }
            bind(path, &format!("{ROOT}{path}"), true, true, false)?;
        }
        mount_dir("/dev", c"size=1m,mode=755")?;
        for dev in ["null", "zero", "full", "random", "urandom"] {
            // Device nodes must not be NODEV, or opening them fails.
            bind(
                &format!("/dev/{dev}"),
                &format!("{ROOT}/dev/{dev}"),
                true,
                false,
                false,
            )?;
        }
        mount_dir("/dev/shm", c"size=64m,mode=1777")?;
        flag("/dev/shm", false, true, true)?;
        // After the shm mount, so the read-only flag does not cover it.
        flag("/dev", true, false, true)?;
        mount_dir("/tmp", c"size=64m,mode=1777")?;
        flag("/tmp", false, true, true)?;
        mount_dir("/workspace", c"size=64m,mode=755")?;
        flag("/workspace", false, true, true)?;
        if !safe_abs(&spec.etc) {
            return Err(Error::from_io(
                "etc",
                std::io::Error::other("etc path is not absolute"),
            ));
        }
        bind(&spec.etc, &format!("{ROOT}/etc"), true, true, true)?;
        let proc = format!("{ROOT}/proc");
        std::fs::create_dir_all(&proc).map_err(|e| Error::from_io("proc", e))?;
        nsbx_sys::mount_proc_subset(&c_str(&proc)?)?;
        let bin = format!("{}/bin", spec.runtime);
        std::os::unix::fs::symlink(&bin, format!("{ROOT}/bin"))
            .map_err(|e| Error::from_io("symlink", e))?;
        std::fs::create_dir_all(format!("{ROOT}/usr/bin")).map_err(|e| Error::from_io("usr", e))?;
        std::os::unix::fs::symlink(format!("{bin}/env"), format!("{ROOT}/usr/bin/env"))
            .map_err(|e| Error::from_io("symlink", e))?;
        Ok(Rooted { _priv: () })
    }
}

fn mount_dir(rel: &str, opts: &CStr) -> Result<(), Error> {
    let dest = format!("{ROOT}{rel}");
    std::fs::create_dir_all(&dest).map_err(|e| Error::from_io("mkdir", e))?;
    nsbx_sys::mount_tmpfs(&c_str(&dest)?, opts)
}

fn flag(rel: &str, readonly: bool, nodev: bool, noexec: bool) -> Result<(), Error> {
    let fd = nsbx_sys::open_opath(&c_str(&format!("{ROOT}{rel}"))?)?;
    nsbx_sys::mount_flags(fd.as_raw_fd(), readonly, nodev, noexec, false)
}

fn bind(src: &str, dest: &str, readonly: bool, nodev: bool, noexec: bool) -> Result<(), Error> {
    let meta = std::fs::metadata(src).map_err(|e| Error::from_io("stat", e))?;
    if meta.is_dir() {
        std::fs::create_dir_all(dest).map_err(|e| Error::from_io("mkdir", e))?;
    } else {
        if let Some(parent) = Path::new(dest).parent() {
            std::fs::create_dir_all(parent).map_err(|e| Error::from_io("mkdir", e))?;
        }
        std::fs::File::create(dest).map_err(|e| Error::from_io("create", e))?;
    }
    let dest_fd = nsbx_sys::open_opath(&c_str(dest)?)?;
    nsbx_sys::bind_with(&c_str(src)?, dest_fd.as_fd(), readonly, nodev, noexec)
}

impl Rooted {
    pub fn pivot(self) -> Result<Pivoted, Error> {
        nsbx_sys::chdir(&c_str(ROOT)?)?;
        nsbx_sys::pivot_root_detach()?;
        nsbx_sys::chdir(c"/")?;
        let root = nsbx_sys::open_opath(c"/")?;
        nsbx_sys::mount_flags(root.as_raw_fd(), true, true, false, false)?;
        Ok(Pivoted { _priv: () })
    }
}

impl Pivoted {
    pub fn mount_points(&self) -> Result<BTreeSet<String>, Error> {
        let text = std::fs::read_to_string("/proc/self/mountinfo")
            .map_err(|e| Error::from_io("mountinfo", e))?;
        let mut set = BTreeSet::new();
        for line in text.lines() {
            if let Some(point) = line.split_whitespace().nth(4) {
                set.insert(point.replace("\\040", " "));
            }
        }
        Ok(set)
    }

    /// `NO_NEW_PRIVS` plus a filter that returns `ENOSYS` for `clone3`.
    pub fn apply_baseline(self) -> Result<Restricted<SeccompApplied>, Error> {
        nsbx_sys::set_no_new_privs()?;
        let arch = seccompiler::TargetArch::try_from(std::env::consts::ARCH)
            .map_err(|e| Error::from_io("arch", std::io::Error::other(e.to_string())))?;
        let mut rules = BTreeMap::new();
        rules.insert(libc::SYS_clone3, Vec::new());
        let filter = seccompiler::SeccompFilter::new(
            rules,
            seccompiler::SeccompAction::Allow,
            seccompiler::SeccompAction::Errno(libc::ENOSYS as u32),
            arch,
        )
        .map_err(|e| Error::from_io("seccomp", std::io::Error::other(e.to_string())))?;
        let prog: seccompiler::BpfProgram =
            filter.try_into().map_err(|e: seccompiler::BackendError| {
                Error::from_io("seccomp", std::io::Error::other(e.to_string()))
            })?;
        seccompiler::apply_filter(&prog)
            .map_err(|e| Error::from_io("seccomp", std::io::Error::other(e.to_string())))?;
        Ok(Restricted {
            _mark: SeccompApplied { _priv: () },
        })
    }
}

impl Restricted<SeccompApplied> {
    /// Replace this process. The type is what makes an earlier call a compile error.
    pub fn exec_workload(self, argv: &[CString], env: &[CString]) -> Error {
        let _ = nsbx_sys::close_range(3, u32::MAX);
        let Some(path) = argv.first() else {
            return Error::from_io("exec", std::io::Error::other("empty argv"));
        };
        nsbx_sys::execve(path, argv, env)
    }
}

fn store_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/nix/store/") else {
        return false;
    };
    let Some((hash, name)) = rest.split_once('-') else {
        return false;
    };
    hash.len() == 32
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
        && !name.is_empty()
        && !name.contains('/')
}

fn safe_abs(path: &str) -> bool {
    path.starts_with('/') && !path.contains('\0') && !path.split('/').any(|p| p == "..")
}

fn c_str(s: &str) -> Result<CString, Error> {
    CString::new(s).map_err(|_| Error::from_io("cstr", std::io::Error::other("interior nul")))
}
