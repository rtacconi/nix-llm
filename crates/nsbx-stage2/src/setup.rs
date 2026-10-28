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
    pub profile: Option<String>,
    pub policy_dir: Option<String>,
    pub workspace_exec: bool,
    /// `true` means namespace uid 1000. `false` stays at uid 0 (dev mode).
    pub production: bool,
    pub collect: Vec<String>,
    /// Full `/proc` with synthetic `meminfo` and `cpuinfo`.
    pub proc_full: bool,
    pub memory_bytes: u64,
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

pub struct Dropped {
    _priv: (),
}

pub struct Landlocked {
    _priv: (),
}

pub struct Restricted<T> {
    _mark: T,
}

const ROOT: &str = "/tmp/nsbx-root";

pub fn begin() -> Result<Private, Error> {
    // The supervisor's clone already asked for a mount namespace. That copy
    // was made before the uid map existed, so its mounts are locked.
    // A second mount namespace, taken after the map, is one this process owns.
    nsbx_sys::unshare_mount_ns()?;
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
        if spec.proc_full {
            nsbx_sys::mount_proc_full(&c_str(&proc)?)?;
            synthetic_proc(spec)?;
        } else {
            nsbx_sys::mount_proc_subset(&c_str(&proc)?)?;
        }
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

    pub fn drop_privileges(self, production: bool) -> Result<Dropped, Error> {
        if production {
            nsbx_sys::assume_workload_uid()?;
        } else {
            nsbx_sys::drop_dev_privileges()?;
        }
        Ok(Dropped { _priv: () })
    }
}

impl Dropped {
    pub fn apply_landlock(self, spec: &Spec) -> Result<Landlocked, Error> {
        apply_landlock(spec)?;
        Ok(Landlocked { _priv: () })
    }
}

impl Landlocked {
    pub fn apply_profile(
        self,
        programs: &[seccompiler::BpfProgram],
    ) -> Result<Restricted<SeccompApplied>, Error> {
        for prog in programs {
            let insns: Vec<nsbx_sys::FilterInsn> = prog
                .iter()
                .map(|insn| nsbx_sys::FilterInsn {
                    code: insn.code,
                    jt: insn.jt,
                    jf: insn.jf,
                    k: insn.k,
                })
                .collect();
            nsbx_sys::apply_seccomp_filter(&insns)?;
        }
        Ok(Restricted {
            _mark: SeccompApplied { _priv: () },
        })
    }
}

impl Pivoted {
    /// `NO_NEW_PRIVS` plus a filter that returns `ENOSYS` for `clone3`.
    /// Used when the spec names no profile. A profile takes the drop,
    /// Landlock and compiled-filter path instead.
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

fn apply_landlock(spec: &Spec) -> Result<(), Error> {
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetStatus,
    };
    let detected = nsbx_sys::landlock_abi()?;
    if detected < 3 {
        return Err(Error::from_io(
            "landlock",
            std::io::Error::other(format!("ABI {detected} is below 3")),
        ));
    }
    let abi = if detected >= 6 {
        ABI::V6
    } else if detected >= 5 {
        ABI::V5
    } else if detected >= 4 {
        ABI::V4
    } else {
        ABI::V3
    };
    let fail = |e: &dyn std::fmt::Display| {
        Error::from_io("landlock", std::io::Error::other(e.to_string()))
    };
    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| fail(&e))?
        .create()
        .map_err(|e| fail(&e))?;
    let read_exec = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
    let read_only = AccessFs::ReadFile | AccessFs::ReadDir;
    let write = AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::Refer
        | AccessFs::Truncate;
    let mut workspace = write;
    if spec.workspace_exec {
        workspace |= AccessFs::Execute;
    }
    let scratch = write | AccessFs::MakeSock;
    let device = AccessFs::ReadFile | AccessFs::WriteFile;
    for path in &spec.closure {
        ruleset = add_rule(ruleset, path, read_exec)?;
    }
    ruleset = add_rule(ruleset, "/etc", read_only)?;
    ruleset = add_rule(ruleset, "/proc", read_only)?;
    ruleset = add_rule(ruleset, "/workspace", workspace)?;
    ruleset = add_rule(ruleset, "/tmp", scratch)?;
    ruleset = add_rule(ruleset, "/dev/shm", scratch)?;
    for dev in ["null", "zero", "full", "random", "urandom"] {
        ruleset = add_rule(ruleset, &format!("/dev/{dev}"), device)?;
    }
    let status = ruleset.restrict_self().map_err(|e| fail(&e))?;
    if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
        return Err(Error::from_io(
            "landlock",
            std::io::Error::other("ruleset was not fully enforced"),
        ));
    }
    Ok(())
}

fn add_rule(
    ruleset: landlock::RulesetCreated,
    path: &str,
    access: impl Into<landlock::BitFlags<landlock::AccessFs>>,
) -> Result<landlock::RulesetCreated, Error> {
    use landlock::RulesetCreatedAttr;
    let fd = landlock::PathFd::new(path)
        .map_err(|e| Error::from_io("landlock", std::io::Error::other(format!("{path}: {e}"))))?;
    let rule = landlock::PathBeneath::new(fd, access);
    ruleset
        .add_rule(rule)
        .map_err(|e| Error::from_io("landlock", std::io::Error::other(format!("{path}: {e}"))))
}

fn bind_existing(src: &str, dest: &str) -> Result<(), Error> {
    let dest_fd = nsbx_sys::open_opath(&c_str(dest)?)?;
    nsbx_sys::bind_with(&c_str(src)?, dest_fd.as_fd(), true, true, true)
}

fn synthetic_proc(spec: &Spec) -> Result<(), Error> {
    let kb = spec.memory_bytes / 1024;
    if kb == 0 {
        return Err(Error::from_io(
            "meminfo",
            std::io::Error::other("memory_bytes is zero"),
        ));
    }
    let dir = format!("{ROOT}/.nsbx");
    std::fs::create_dir_all(&dir).map_err(|e| Error::from_io("nsbx", e))?;
    let mem = format!("MemTotal: {kb} kB\nMemFree: {kb} kB\n");
    std::fs::write(format!("{dir}/meminfo"), mem).map_err(|e| Error::from_io("meminfo", e))?;
    let cpu = "processor\t: 0\nvendor_id\t: generic\nmodel name\t: generic\n";
    std::fs::write(format!("{dir}/cpuinfo"), cpu).map_err(|e| Error::from_io("cpuinfo", e))?;
    bind_existing(&format!("{dir}/meminfo"), &format!("{ROOT}/proc/meminfo"))?;
    bind_existing(&format!("{dir}/cpuinfo"), &format!("{ROOT}/proc/cpuinfo"))?;
    for name in ["cmdline", "version", "modules"] {
        let dest = format!("{ROOT}/proc/{name}");
        if Path::new(&dest).exists() {
            bind_existing("/dev/null", &dest)?;
        }
    }
    Ok(())
}

fn c_str(s: &str) -> Result<CString, Error> {
    CString::new(s).map_err(|_| Error::from_io("cstr", std::io::Error::other("interior nul")))
}
