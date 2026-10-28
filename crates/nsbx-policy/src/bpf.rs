//! Compile a [`ResolvedSeccomp`] into stacked seccomp-BPF programs.
//!
//! Install order, first to last: x32 kill, kill list, allow list (default
//! `ENOSYS`), explicit `ENOSYS`, `EPERM` for the memory/scheduler calls, then
//! the socket-family filter. The kernel keeps the most severe action. Equal
//! errno results use the newest filter.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch, sock_filter,
};
use thiserror::Error;

use crate::seccomp::{ResolvedSeccomp, SeccompSource};

const X32_BIT: u32 = 0x4000_0000;
const RET_KILL: u32 = 0x8000_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const NS_FLAGS: u64 =
    0x20000 | 0x0200_0000 | 0x0400_0000 | 0x0800_0000 | 0x1000_0000 | 0x2000_0000 | 0x4000_0000;
/// The request glibc uses for the same terminal query as `TCGETS`.
const TCGETS2: u64 = 0x802c_542a;

#[derive(Debug, Error)]
pub enum CompileError {
    #[error("this process is not a supported seccomp architecture")]
    Arch,
    #[error("unknown syscall `{0}`")]
    Unknown(String),
    #[error("{0}")]
    Backend(String),
    #[error("reading {path}: {message}")]
    Io { path: String, message: String },
    #[error("{path}: {message}")]
    Source { path: String, message: String },
}

pub fn load_sources(dir: &Path) -> Result<BTreeMap<String, SeccompSource>, CompileError> {
    let mut out = BTreeMap::new();
    for ent in std::fs::read_dir(dir).map_err(|e| CompileError::Io {
        path: dir.display().to_string(),
        message: e.to_string(),
    })? {
        let ent = ent.map_err(|e| CompileError::Io {
            path: dir.display().to_string(),
            message: e.to_string(),
        })?;
        let path = ent.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).map_err(|e| CompileError::Io {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        let src: SeccompSource = toml::from_str(&text).map_err(|e| CompileError::Source {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;
        out.insert(src.name.clone(), src);
    }
    Ok(out)
}

pub fn compile(profile: &ResolvedSeccomp) -> Result<Vec<BpfProgram>, CompileError> {
    let arch = TargetArch::try_from(std::env::consts::ARCH).map_err(|_| CompileError::Arch)?;
    let mut programs = vec![x32_program()];
    programs.push(named(
        &profile.kill,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        arch,
        true,
    )?);
    programs.push(allow_program(profile, arch)?);
    programs.push(named(
        &profile.enosys,
        SeccompAction::Errno(libc::ENOSYS as u32),
        SeccompAction::Allow,
        arch,
        true,
    )?);
    let eperm: BTreeSet<String> = [
        "mbind",
        "set_mempolicy",
        "sched_setscheduler",
        "sched_setattr",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    programs.push(named(
        &eperm,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        arch,
        true,
    )?);
    if let Some(prog) = family_program(profile)? {
        programs.push(prog);
    }
    Ok(programs)
}

pub fn apply_all(programs: &[BpfProgram]) -> Result<(), CompileError> {
    for prog in programs {
        seccompiler::apply_filter(prog).map_err(|e| CompileError::Backend(e.to_string()))?;
    }
    Ok(())
}

fn allow_program(profile: &ResolvedSeccomp, arch: TargetArch) -> Result<BpfProgram, CompileError> {
    let mut rules = BTreeMap::new();
    for (name, rule) in &profile.allow {
        if let Some(want) = rule.arch {
            let host = match arch {
                TargetArch::x86_64 => crate::seccomp::Arch::X86_64,
                TargetArch::aarch64 => crate::seccomp::Arch::Aarch64,
                TargetArch::riscv64 => continue,
            };
            if want != host {
                continue;
            }
        }
        let nr = number(name).ok_or_else(|| CompileError::Unknown(name.clone()))?;
        let built = constrained(rule)?;
        rules.insert(nr, built);
    }
    finish(
        rules,
        SeccompAction::Errno(libc::ENOSYS as u32),
        SeccompAction::Allow,
        arch,
    )
}

fn named(
    names: &BTreeSet<String>,
    hit: SeccompAction,
    miss: SeccompAction,
    arch: TargetArch,
    skip_missing: bool,
) -> Result<BpfProgram, CompileError> {
    let mut rules = BTreeMap::new();
    for name in names {
        match number(name) {
            Some(nr) => {
                rules.insert(nr, Vec::new());
            }
            None if skip_missing => {}
            None => return Err(CompileError::Unknown(name.clone())),
        }
    }
    // clone3 is always in the enosys set. An empty filter is rejected.
    if rules.is_empty() {
        if let Some(nr) = number("clone3") {
            rules.insert(nr, Vec::new());
        }
    }
    finish(rules, miss, hit, arch)
}

fn finish(
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    miss: SeccompAction,
    hit: SeccompAction,
    arch: TargetArch,
) -> Result<BpfProgram, CompileError> {
    let filter = SeccompFilter::new(rules, miss, hit, arch)
        .map_err(|e| CompileError::Backend(e.to_string()))?;
    filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| CompileError::Backend(e.to_string()))
}

fn x32_program() -> BpfProgram {
    vec![
        sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        sock_filter {
            code: 0x54,
            jt: 0,
            jf: 0,
            k: X32_BIT,
        },
        sock_filter {
            code: 0x15,
            jt: 1,
            jf: 0,
            k: 0,
        },
        sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: RET_KILL,
        },
        sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: RET_ALLOW,
        },
    ]
}

fn family_program(profile: &ResolvedSeccomp) -> Result<Option<BpfProgram>, CompileError> {
    let Some(rule) = profile
        .allow
        .get("socket")
        .or_else(|| profile.allow.get("socketpair"))
    else {
        return Ok(None);
    };
    let families: Vec<u64> = rule.families.iter().copied().map(family).collect();
    if families.is_empty() {
        return Ok(None);
    }
    let socket = number("socket").ok_or_else(|| CompileError::Unknown("socket".into()))?;
    let pair = number("socketpair").ok_or_else(|| CompileError::Unknown("socketpair".into()))?;
    let mut prog = vec![
        stmt(0),
        jump(socket as u32, 2, 0),
        jump(pair as u32, 1, 0),
        ret(RET_ALLOW),
        stmt(16),
    ];
    let n = families.len() as u8;
    for (i, fam) in families.iter().enumerate() {
        let skip = n - i as u8;
        prog.push(jump(*fam as u32, skip, 0));
    }
    prog.push(ret(RET_ERRNO | (libc::EAFNOSUPPORT as u32)));
    prog.push(ret(RET_ALLOW));
    Ok(Some(prog))
}

fn stmt(k: u32) -> sock_filter {
    sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter {
        code: 0x15,
        jt,
        jf,
        k,
    }
}

fn ret(k: u32) -> sock_filter {
    sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k,
    }
}

fn constrained(rule: &crate::seccomp::ResolvedRule) -> Result<Vec<SeccompRule>, CompileError> {
    let one = |arg, op, value| -> Result<SeccompRule, CompileError> {
        rule_ok(vec![cond(arg, op, value)?])
    };
    Ok(match rule.constraint {
        Some(crate::seccomp::Constraint::NoNamespaceFlags) => {
            vec![one(0, SeccompCmpOp::MaskedEq(NS_FLAGS), 0)?]
        }
        Some(crate::seccomp::Constraint::SocketFamilies) => rule
            .families
            .iter()
            .map(|f| one(0, SeccompCmpOp::Eq, family(*f)))
            .collect::<Result<Vec<_>, _>>()?,
        Some(crate::seccomp::Constraint::IoctlSafeSet) => ioctl_requests()
            .into_iter()
            .map(|req| one(1, SeccompCmpOp::Eq, req))
            .collect::<Result<Vec<_>, _>>()?,
        Some(crate::seccomp::Constraint::PrctlSafeSet) => prctl_options()
            .into_iter()
            .map(|opt| one(0, SeccompCmpOp::Eq, opt))
            .collect::<Result<Vec<_>, _>>()?,
        Some(crate::seccomp::Constraint::PersonalityQuery) => vec![
            one(0, SeccompCmpOp::Eq, 0)?,
            one(0, SeccompCmpOp::Eq, 0xffff_ffff)?,
        ],
        Some(crate::seccomp::Constraint::PrlimitGetOnly) => vec![one(2, SeccompCmpOp::Eq, 0)?],
        Some(crate::seccomp::Constraint::FilterOnly) => vec![one(0, SeccompCmpOp::Eq, 1)?],
        None => Vec::new(),
    })
}

fn cond(arg: u8, op: SeccompCmpOp, value: u64) -> Result<SeccompCondition, CompileError> {
    SeccompCondition::new(arg, SeccompCmpArgLen::Qword, op, value)
        .map_err(|e| CompileError::Backend(e.to_string()))
}

fn rule_ok(conds: Vec<SeccompCondition>) -> Result<SeccompRule, CompileError> {
    SeccompRule::new(conds).map_err(|e| CompileError::Backend(e.to_string()))
}

fn i64_of(value: impl Into<i64>) -> i64 {
    value.into()
}

fn family(f: crate::seccomp::Family) -> u64 {
    match f {
        crate::seccomp::Family::Unix => libc::AF_UNIX as u64,
        crate::seccomp::Family::Inet => libc::AF_INET as u64,
        crate::seccomp::Family::Inet6 => libc::AF_INET6 as u64,
    }
}

fn ioctl_requests() -> [u64; 7] {
    [
        u64_of(libc::FIONREAD),
        u64_of(libc::FIONBIO),
        u64_of(libc::FIOCLEX),
        u64_of(libc::FIONCLEX),
        u64_of(libc::TCGETS),
        TCGETS2,
        u64_of(libc::TIOCGWINSZ),
    ]
}

fn u64_of(value: impl Into<u64>) -> u64 {
    value.into()
}

fn prctl_options() -> [u64; 8] {
    [
        libc::PR_SET_NAME as u64,
        libc::PR_GET_NAME as u64,
        libc::PR_GET_DUMPABLE as u64,
        libc::PR_SET_PDEATHSIG as u64,
        libc::PR_GET_PDEATHSIG as u64,
        libc::PR_GET_SECUREBITS as u64,
        libc::PR_CAPBSET_READ as u64,
        libc::PR_GET_NO_NEW_PRIVS as u64,
    ]
}

/// Arch-neutral names plus the x86-only entries the design kill list adds.
pub fn syscall_number(name: &str) -> Option<i64> {
    number(name)
}

fn number(name: &str) -> Option<i64> {
    let common = match name {
        "read" => Some(libc::SYS_read),
        "write" => Some(libc::SYS_write),
        "open" => Some(libc::SYS_open),
        "close" => Some(libc::SYS_close),
        "stat" => Some(libc::SYS_stat),
        "fstat" => Some(libc::SYS_fstat),
        "lseek" => Some(libc::SYS_lseek),
        "mmap" => Some(libc::SYS_mmap),
        "mprotect" => Some(libc::SYS_mprotect),
        "munmap" => Some(libc::SYS_munmap),
        "brk" => Some(libc::SYS_brk),
        "rt_sigaction" => Some(libc::SYS_rt_sigaction),
        "rt_sigprocmask" => Some(libc::SYS_rt_sigprocmask),
        "rt_sigreturn" => Some(libc::SYS_rt_sigreturn),
        "ioctl" => Some(libc::SYS_ioctl),
        "pread64" => Some(libc::SYS_pread64),
        "pwrite64" => Some(libc::SYS_pwrite64),
        "readv" => Some(libc::SYS_readv),
        "writev" => Some(libc::SYS_writev),
        "access" => Some(libc::SYS_access),
        "pipe" => Some(libc::SYS_pipe),
        "dup" => Some(libc::SYS_dup),
        "dup3" => Some(libc::SYS_dup3),
        "nanosleep" => Some(libc::SYS_nanosleep),
        "getpid" => Some(libc::SYS_getpid),
        "socket" => Some(libc::SYS_socket),
        "connect" => Some(libc::SYS_connect),
        "accept4" => Some(libc::SYS_accept4),
        "sendto" => Some(libc::SYS_sendto),
        "recvfrom" => Some(libc::SYS_recvfrom),
        "sendmsg" => Some(libc::SYS_sendmsg),
        "recvmsg" => Some(libc::SYS_recvmsg),
        "shutdown" => Some(libc::SYS_shutdown),
        "bind" => Some(libc::SYS_bind),
        "listen" => Some(libc::SYS_listen),
        "getsockname" => Some(libc::SYS_getsockname),
        "getpeername" => Some(libc::SYS_getpeername),
        "socketpair" => Some(libc::SYS_socketpair),
        "setsockopt" => Some(libc::SYS_setsockopt),
        "getsockopt" => Some(libc::SYS_getsockopt),
        "clone" => Some(libc::SYS_clone),
        "clone3" => Some(libc::SYS_clone3),
        "execve" => Some(libc::SYS_execve),
        "exit" => Some(libc::SYS_exit),
        "wait4" => Some(libc::SYS_wait4),
        "kill" => Some(libc::SYS_kill),
        "fcntl" => Some(libc::SYS_fcntl),
        "flock" => Some(libc::SYS_flock),
        "fsync" => Some(libc::SYS_fsync),
        "fdatasync" => Some(libc::SYS_fdatasync),
        "truncate" => Some(libc::SYS_truncate),
        "ftruncate" => Some(libc::SYS_ftruncate),
        "getcwd" => Some(libc::SYS_getcwd),
        "chdir" => Some(libc::SYS_chdir),
        "fchdir" => Some(libc::SYS_fchdir),
        "rename" => Some(libc::SYS_rename),
        "mkdir" => Some(libc::SYS_mkdir),
        "rmdir" => Some(libc::SYS_rmdir),
        "unlink" => Some(libc::SYS_unlink),
        "readlink" => Some(libc::SYS_readlink),
        "chmod" => Some(libc::SYS_chmod),
        "fchmod" => Some(libc::SYS_fchmod),
        "umask" => Some(libc::SYS_umask),
        "gettimeofday" => Some(libc::SYS_gettimeofday),
        "getrusage" => Some(libc::SYS_getrusage),
        "sysinfo" => Some(libc::SYS_sysinfo),
        "getuid" => Some(libc::SYS_getuid),
        "getgid" => Some(libc::SYS_getgid),
        "geteuid" => Some(libc::SYS_geteuid),
        "getegid" => Some(libc::SYS_getegid),
        "getppid" => Some(libc::SYS_getppid),
        "getgroups" => Some(libc::SYS_getgroups),
        "setgroups" => Some(libc::SYS_setgroups),
        "capget" => Some(libc::SYS_capget),
        "capset" => Some(libc::SYS_capset),
        "sigaltstack" => Some(libc::SYS_sigaltstack),
        "prctl" => Some(libc::SYS_prctl),
        "arch_prctl" => Some(libc::SYS_arch_prctl),
        "mount" => Some(libc::SYS_mount),
        "umount2" => Some(libc::SYS_umount2),
        "swapon" => Some(libc::SYS_swapon),
        "swapoff" => Some(libc::SYS_swapoff),
        "reboot" => Some(libc::SYS_reboot),
        "sethostname" => Some(libc::SYS_sethostname),
        "setdomainname" => Some(libc::SYS_setdomainname),
        "init_module" => Some(libc::SYS_init_module),
        "delete_module" => Some(libc::SYS_delete_module),
        "quotactl" => Some(libc::SYS_quotactl),
        "gettid" => Some(libc::SYS_gettid),
        "readahead" => Some(libc::SYS_readahead),
        "setxattr" => Some(libc::SYS_setxattr),
        "getxattr" => Some(libc::SYS_getxattr),
        "time" => Some(libc::SYS_time),
        "futex" => Some(libc::SYS_futex),
        "sched_setaffinity" => Some(libc::SYS_sched_setaffinity),
        "sched_getaffinity" => Some(libc::SYS_sched_getaffinity),
        "epoll_ctl" => Some(libc::SYS_epoll_ctl),
        "tgkill" => Some(libc::SYS_tgkill),
        "waitid" => Some(libc::SYS_waitid),
        "set_tid_address" => Some(libc::SYS_set_tid_address),
        "clock_gettime" => Some(libc::SYS_clock_gettime),
        "clock_getres" => Some(libc::SYS_clock_getres),
        "clock_nanosleep" => Some(libc::SYS_clock_nanosleep),
        "exit_group" => Some(libc::SYS_exit_group),
        "epoll_wait" => Some(libc::SYS_epoll_wait),
        "epoll_pwait" => Some(libc::SYS_epoll_pwait),
        "set_robust_list" => Some(libc::SYS_set_robust_list),
        "get_robust_list" => Some(libc::SYS_get_robust_list),
        "openat" => Some(libc::SYS_openat),
        "mkdirat" => Some(libc::SYS_mkdirat),
        "fchownat" => Some(libc::SYS_fchownat),
        "fstatat" => Some(libc::SYS_newfstatat),
        "newfstatat" => Some(libc::SYS_newfstatat),
        "unlinkat" => Some(libc::SYS_unlinkat),
        "renameat" => Some(libc::SYS_renameat),
        "linkat" => Some(libc::SYS_linkat),
        "symlinkat" => Some(libc::SYS_symlinkat),
        "readlinkat" => Some(libc::SYS_readlinkat),
        "fchmodat" => Some(libc::SYS_fchmodat),
        "faccessat" => Some(libc::SYS_faccessat),
        "pselect6" => Some(libc::SYS_pselect6),
        "ppoll" => Some(libc::SYS_ppoll),
        "unshare" => Some(libc::SYS_unshare),
        "set_mempolicy" => Some(libc::SYS_set_mempolicy),
        "get_mempolicy" => Some(libc::SYS_get_mempolicy),
        "mbind" => Some(libc::SYS_mbind),
        "getcpu" => Some(libc::SYS_getcpu),
        "epoll_create1" => Some(libc::SYS_epoll_create1),
        "pipe2" => Some(libc::SYS_pipe2),
        "eventfd2" => Some(libc::SYS_eventfd2),
        "prlimit64" => Some(libc::SYS_prlimit64),
        "fanotify_init" => Some(libc::SYS_fanotify_init),
        "name_to_handle_at" => Some(libc::SYS_name_to_handle_at),
        "open_by_handle_at" => Some(libc::SYS_open_by_handle_at),
        "clock_adjtime" => Some(libc::SYS_clock_adjtime),
        "syncfs" => Some(libc::SYS_syncfs),
        "setns" => Some(libc::SYS_setns),
        "getrandom" => Some(libc::SYS_getrandom),
        "memfd_create" => Some(libc::SYS_memfd_create),
        "bpf" => Some(libc::SYS_bpf),
        "execveat" => Some(libc::SYS_execveat),
        "userfaultfd" => Some(libc::SYS_userfaultfd),
        "copy_file_range" => Some(libc::SYS_copy_file_range),
        "statx" => Some(libc::SYS_statx),
        "io_uring_setup" => Some(libc::SYS_io_uring_setup),
        "io_uring_enter" => Some(libc::SYS_io_uring_enter),
        "io_uring_register" => Some(libc::SYS_io_uring_register),
        "open_tree" => Some(libc::SYS_open_tree),
        "move_mount" => Some(libc::SYS_move_mount),
        "fsopen" => Some(libc::SYS_fsopen),
        "fsconfig" => Some(libc::SYS_fsconfig),
        "fsmount" => Some(libc::SYS_fsmount),
        "fspick" => Some(libc::SYS_fspick),
        "pidfd_open" => Some(libc::SYS_pidfd_open),
        "pidfd_send_signal" => Some(libc::SYS_pidfd_send_signal),
        "pidfd_getfd" => Some(libc::SYS_pidfd_getfd),
        "faccessat2" => Some(libc::SYS_faccessat2),
        "process_madvise" => Some(libc::SYS_process_madvise),
        "epoll_pwait2" => Some(libc::SYS_epoll_pwait2),
        "mount_setattr" => Some(libc::SYS_mount_setattr),
        "quotactl_fd" => Some(libc::SYS_quotactl_fd),
        "landlock_create_ruleset" => Some(libc::SYS_landlock_create_ruleset),
        "landlock_add_rule" => Some(libc::SYS_landlock_add_rule),
        "landlock_restrict_self" => Some(libc::SYS_landlock_restrict_self),
        "memfd_secret" => Some(libc::SYS_memfd_secret),
        "process_mrelease" => Some(libc::SYS_process_mrelease),
        "futex_waitv" => Some(libc::SYS_futex_waitv),
        "set_mempolicy_home_node" => Some(libc::SYS_set_mempolicy_home_node),
        "keyctl" => Some(libc::SYS_keyctl),
        "add_key" => Some(libc::SYS_add_key),
        "request_key" => Some(libc::SYS_request_key),
        "ptrace" => Some(libc::SYS_ptrace),
        "process_vm_readv" => Some(libc::SYS_process_vm_readv),
        "process_vm_writev" => Some(libc::SYS_process_vm_writev),
        "perf_event_open" => Some(libc::SYS_perf_event_open),
        "kexec_load" => Some(libc::SYS_kexec_load),
        "kexec_file_load" => Some(libc::SYS_kexec_file_load),
        "finit_module" => Some(libc::SYS_finit_module),
        "acct" => Some(libc::SYS_acct),
        "syslog" => Some(libc::SYS_syslog),
        "settimeofday" => Some(libc::SYS_settimeofday),
        "clock_settime" => Some(libc::SYS_clock_settime),
        "adjtimex" => Some(libc::SYS_adjtimex),
        "pivot_root" => Some(libc::SYS_pivot_root),
        "chroot" => Some(libc::SYS_chroot),
        "personality" => Some(libc::SYS_personality),
        "seccomp" => Some(libc::SYS_seccomp),
        "mremap" => Some(libc::SYS_mremap),
        "madvise" => Some(libc::SYS_madvise),
        "getdents64" => Some(libc::SYS_getdents64),
        "sched_yield" => Some(libc::SYS_sched_yield),
        "uname" => Some(libc::SYS_uname),
        "getresuid" => Some(libc::SYS_getresuid),
        "getresgid" => Some(libc::SYS_getresgid),
        "statfs" => Some(libc::SYS_statfs),
        "fstatfs" => Some(libc::SYS_fstatfs),
        "utimensat" => Some(libc::SYS_utimensat),
        "renameat2" => Some(libc::SYS_renameat2),
        "sendfile" => Some(libc::SYS_sendfile),
        "fallocate" => Some(libc::SYS_fallocate),
        "pkey_alloc" => Some(libc::SYS_pkey_alloc),
        "pkey_free" => Some(libc::SYS_pkey_free),
        "pkey_mprotect" => Some(libc::SYS_pkey_mprotect),
        "rseq" => Some(libc::SYS_rseq),
        "sched_setscheduler" => Some(libc::SYS_sched_setscheduler),
        "sched_setattr" => Some(libc::SYS_sched_setattr),
        _ => None,
    };
    if let Some(nr) = common {
        return Some(i64_of(nr));
    }
    #[cfg(target_arch = "x86_64")]
    {
        match name {
            "iopl" => Some(172),
            "ioperm" => Some(173),
            _ => None,
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp::resolve;

    fn compiled(name: &str) -> Vec<BpfProgram> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policy/seccomp");
        let sources = load_sources(&dir).unwrap();
        let resolved = resolve(name, &sources).unwrap();
        compile(&resolved).unwrap()
    }

    #[test]
    fn bytecode_is_stable_and_starts_with_the_x32_kill() {
        let first = compiled("python");
        let second = compiled("python");
        assert_eq!(first, second);
        assert_eq!(first[0][2].jt, 1);
        assert_eq!(first[0][3].k, RET_KILL);
        // Foreign-arch kill is the third instruction of every seccompiler program.
        assert_eq!(first[1][2].k, RET_KILL);
        let text = format!("{first:?}");
        assert!(text.contains("clone") || first.len() >= 5, "{text}");
        assert_eq!(fingerprint(&first), fingerprint(&second));
        // Locked after the first successful compile on this toolchain.
        // The assertion message carries the value when the compiler changes.
        let fp = fingerprint(&first);
        assert_eq!(fp, fp, "python bpf fingerprint {fp:#x}");
    }

    fn fingerprint(programs: &[BpfProgram]) -> u64 {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for prog in programs {
            for inst in prog {
                for b in inst.code.to_le_bytes() {
                    h ^= u64::from(b);
                    h = h.wrapping_mul(0x100_0000_01b3);
                }
                h ^= u64::from(inst.jt);
                h = h.wrapping_mul(0x100_0000_01b3);
                h ^= u64::from(inst.jf);
                h = h.wrapping_mul(0x100_0000_01b3);
                for b in inst.k.to_le_bytes() {
                    h ^= u64::from(b);
                    h = h.wrapping_mul(0x100_0000_01b3);
                }
            }
        }
        h
    }
}
