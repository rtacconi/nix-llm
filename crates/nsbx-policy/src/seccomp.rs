//! Seccomp profile sources (design §8).
//!
//! A source file lists allowed syscalls, each with a written reason, plus
//! optional named argument constraints. Profiles may extend one parent. This
//! module parses, resolves and validates sources on any platform; compiling to
//! BPF happens in the Linux-only build.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::profile::{valid_name, valid_version};

/// Syscalls that kill the process in every profile. A profile can neither
/// allow these nor drop them from the kill list; it may only downgrade the
/// entries in [`DOWNGRADABLE`] to `ENOSYS`.
pub const MANDATORY_KILL: &[&str] = &[
    "bpf",
    "perf_event_open",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "open_by_handle_at",
    "name_to_handle_at",
    "userfaultfd",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
    "keyctl",
    "add_key",
    "request_key",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "setns",
    "unshare",
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    "fsopen",
    "fsconfig",
    "fsmount",
    "fspick",
    "open_tree",
    "move_mount",
    "mount_setattr",
    "swapon",
    "swapoff",
    "reboot",
    "acct",
    "quotactl",
    "syslog",
    "settimeofday",
    "clock_settime",
    "clock_adjtime",
    "adjtimex",
];

/// Kill-list entries a profile may turn into `ENOSYS` because a runtime probes
/// them at startup and falls back (libuv and io_uring). Still blocked.
pub const DOWNGRADABLE: &[&str] = &["io_uring_setup", "io_uring_enter", "io_uring_register"];

/// Returns `ENOSYS` in every profile so libc falls back to an inspectable call.
pub const ALWAYS_ENOSYS: &[&str] = &["clone3"];

/// Named argument constraints, implemented by the BPF compiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Constraint {
    /// `clone`: no `CLONE_NEW*` flag set.
    NoNamespaceFlags,
    /// `socket`/`socketpair`: family in `families`.
    SocketFamilies,
    /// `ioctl`: request in the fixed safe set.
    IoctlSafeSet,
    /// `prctl`: option in the fixed safe set.
    PrctlSafeSet,
    /// `personality`: query or `PER_LINUX` only.
    PersonalityQuery,
    /// `prlimit64`: read only (new limit pointer is NULL).
    PrlimitGetOnly,
    /// `seccomp`: `SET_MODE_FILTER` without `NEW_LISTENER`.
    FilterOnly,
}

impl Constraint {
    fn applies_to(self, syscall: &str) -> bool {
        match self {
            Self::NoNamespaceFlags => syscall == "clone",
            Self::SocketFamilies => matches!(syscall, "socket" | "socketpair"),
            Self::IoctlSafeSet => syscall == "ioctl",
            Self::PrctlSafeSet => syscall == "prctl",
            Self::PersonalityQuery => syscall == "personality",
            Self::PrlimitGetOnly => syscall == "prlimit64",
            Self::FilterOnly => syscall == "seccomp",
        }
    }
}

/// Syscalls that must carry their constraint whenever they are allowed.
const MUST_CONSTRAIN: &[(&str, Constraint)] = &[
    ("clone", Constraint::NoNamespaceFlags),
    ("socket", Constraint::SocketFamilies),
    ("socketpair", Constraint::SocketFamilies),
    ("ioctl", Constraint::IoctlSafeSet),
    ("prctl", Constraint::PrctlSafeSet),
    ("personality", Constraint::PersonalityQuery),
    ("prlimit64", Constraint::PrlimitGetOnly),
    ("seccomp", Constraint::FilterOnly),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Unix,
    Inet,
    Inet6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRule {
    pub name: String,
    pub reason: String,
    #[serde(default)]
    pub constraint: Option<Constraint>,
    #[serde(default)]
    pub families: Vec<Family>,
    /// Restrict the rule to one architecture (e.g. `arch_prctl`).
    #[serde(default)]
    pub arch: Option<Arch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeccompSource {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub extends: Option<String>,
    #[serde(default)]
    pub allow: Vec<AllowRule>,
    /// Kill-list entries downgraded to `ENOSYS` (must be in `DOWNGRADABLE`).
    #[serde(default)]
    pub enosys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedRule {
    pub constraint: Option<Constraint>,
    pub families: BTreeSet<Family>,
    pub arch: Option<Arch>,
    pub reason: String,
}

/// A fully resolved profile, ready for the BPF compiler.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedSeccomp {
    pub name: String,
    pub version: String,
    /// Inheritance chain from root to this profile.
    pub chain: Vec<String>,
    pub allow: BTreeMap<String, ResolvedRule>,
    pub kill: BTreeSet<String>,
    pub enosys: BTreeSet<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SeccompError {
    #[error("{0}: invalid profile name or version")]
    BadHeader(String),
    #[error("{profile}: unknown parent `{parent}`")]
    UnknownParent { profile: String, parent: String },
    #[error("{0}: inheritance cycle or chain deeper than 4")]
    Chain(String),
    #[error("{profile}: `{syscall}` is not a valid syscall name")]
    BadName { profile: String, syscall: String },
    #[error("{profile}: `{syscall}` has no reason")]
    NoReason { profile: String, syscall: String },
    #[error("{profile}: `{syscall}` is listed twice")]
    Duplicate { profile: String, syscall: String },
    #[error("{profile}: `{syscall}` is on the mandatory kill list and cannot be allowed")]
    KillListed { profile: String, syscall: String },
    #[error("{profile}: `{syscall}` cannot be downgraded to ENOSYS")]
    NotDowngradable { profile: String, syscall: String },
    #[error("{profile}: `{syscall}` must be allowed with constraint {want:?}")]
    MissingConstraint {
        profile: String,
        syscall: String,
        want: Constraint,
    },
    #[error("{profile}: constraint {constraint:?} does not apply to `{syscall}`")]
    WrongConstraint {
        profile: String,
        syscall: String,
        constraint: Constraint,
    },
    #[error(
        "{profile}: `{syscall}` needs a non-empty families list (and only socket calls may have one)"
    )]
    Families { profile: String, syscall: String },
    #[error("{profile}: `{syscall}` always returns ENOSYS and cannot be allowed")]
    AlwaysEnosys { profile: String, syscall: String },
}

fn valid_syscall_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Resolve `name` against a set of sources (keyed by name).
pub fn resolve(
    name: &str,
    sources: &BTreeMap<String, SeccompSource>,
) -> Result<ResolvedSeccomp, SeccompError> {
    let mut chain = Vec::new();
    let mut cur = name.to_owned();
    loop {
        if chain.contains(&cur) || chain.len() >= 4 {
            return Err(SeccompError::Chain(name.to_owned()));
        }
        let src = sources
            .get(&cur)
            .ok_or_else(|| SeccompError::UnknownParent {
                profile: chain.last().cloned().unwrap_or_else(|| name.to_owned()),
                parent: cur.clone(),
            })?;
        chain.push(cur.clone());
        match &src.extends {
            Some(p) => cur = p.clone(),
            None => break,
        }
    }
    chain.reverse();

    let mut allow = BTreeMap::new();
    let mut enosys: BTreeSet<String> = ALWAYS_ENOSYS.iter().map(|s| (*s).to_owned()).collect();
    for pname in &chain {
        let src = &sources[pname];
        if !valid_name(&src.name) || !valid_version(&src.version) {
            return Err(SeccompError::BadHeader(src.name.clone()));
        }
        let mut own = BTreeSet::new();
        for r in &src.allow {
            check_rule(&src.name, r)?;
            if !own.insert(r.name.as_str()) {
                return Err(SeccompError::Duplicate {
                    profile: src.name.clone(),
                    syscall: r.name.clone(),
                });
            }
            allow.insert(
                r.name.clone(),
                ResolvedRule {
                    constraint: r.constraint,
                    families: r.families.iter().copied().collect(),
                    arch: r.arch,
                    reason: r.reason.clone(),
                },
            );
        }
        for e in &src.enosys {
            if !DOWNGRADABLE.contains(&e.as_str()) {
                return Err(SeccompError::NotDowngradable {
                    profile: src.name.clone(),
                    syscall: e.clone(),
                });
            }
            enosys.insert(e.clone());
        }
    }
    let kill = MANDATORY_KILL
        .iter()
        .map(|s| (*s).to_owned())
        .filter(|s| !enosys.contains(s))
        .collect();
    let me = &sources[name];
    Ok(ResolvedSeccomp {
        name: me.name.clone(),
        version: me.version.clone(),
        chain,
        allow,
        kill,
        enosys,
    })
}

fn check_rule(profile: &str, r: &AllowRule) -> Result<(), SeccompError> {
    let e = |syscall: &str| (profile.to_owned(), syscall.to_owned());
    if !valid_syscall_name(&r.name) {
        let (profile, syscall) = e(&r.name);
        return Err(SeccompError::BadName { profile, syscall });
    }
    if r.reason.trim().len() < 3 {
        let (profile, syscall) = e(&r.name);
        return Err(SeccompError::NoReason { profile, syscall });
    }
    if MANDATORY_KILL.contains(&r.name.as_str()) {
        let (profile, syscall) = e(&r.name);
        return Err(SeccompError::KillListed { profile, syscall });
    }
    if ALWAYS_ENOSYS.contains(&r.name.as_str()) {
        let (profile, syscall) = e(&r.name);
        return Err(SeccompError::AlwaysEnosys { profile, syscall });
    }
    if let Some((_, want)) = MUST_CONSTRAIN.iter().find(|(s, _)| *s == r.name) {
        if r.constraint != Some(*want) {
            let (profile, syscall) = e(&r.name);
            return Err(SeccompError::MissingConstraint {
                profile,
                syscall,
                want: *want,
            });
        }
    }
    if let Some(c) = r.constraint {
        if !c.applies_to(&r.name) {
            let (profile, syscall) = e(&r.name);
            return Err(SeccompError::WrongConstraint {
                profile,
                syscall,
                constraint: c,
            });
        }
    }
    let is_socket = r.constraint == Some(Constraint::SocketFamilies);
    if is_socket == r.families.is_empty() {
        let (profile, syscall) = e(&r.name);
        return Err(SeccompError::Families { profile, syscall });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(toml: &str) -> SeccompSource {
        toml::from_str(toml).unwrap()
    }

    fn set(list: &[SeccompSource]) -> BTreeMap<String, SeccompSource> {
        list.iter().map(|s| (s.name.clone(), s.clone())).collect()
    }

    const BASE: &str = r#"
        name = "base"
        version = "1.0.0"
        [[allow]]
        name = "read"
        reason = "file and pipe input"
        [[allow]]
        name = "clone"
        reason = "threads and fork"
        constraint = "no_namespace_flags"
    "#;

    #[test]
    fn resolves_inheritance_and_kill_list() {
        let child = src(r#"
            name = "node"
            version = "1.0.0"
            extends = "base"
            enosys = ["io_uring_setup", "io_uring_enter", "io_uring_register"]
            [[allow]]
            name = "socket"
            reason = "local IPC"
            constraint = "socket_families"
            families = ["unix"]
        "#);
        let r = resolve("node", &set(&[src(BASE), child])).unwrap();
        assert_eq!(r.chain, ["base", "node"]);
        assert!(r.allow.contains_key("read") && r.allow.contains_key("socket"));
        assert!(r.kill.contains("bpf") && !r.kill.contains("io_uring_setup"));
        assert!(r.enosys.contains("io_uring_setup") && r.enosys.contains("clone3"));
    }

    #[test]
    fn refuses_unsafe_sources() {
        let cases = [
            (
                "[[allow]]\nname = \"bpf\"\nreason = \"tracing\"",
                "mandatory kill",
            ),
            (
                "[[allow]]\nname = \"clone\"\nreason = \"threads\"",
                "must be allowed with constraint",
            ),
            ("[[allow]]\nname = \"read\"\nreason = \"\"", "has no reason"),
            (
                "[[allow]]\nname = \"clone3\"\nreason = \"threads\"",
                "always returns ENOSYS",
            ),
            ("enosys = [\"ptrace\"]", "cannot be downgraded"),
            (
                "[[allow]]\nname = \"read\"\nreason = \"x y z\"\nconstraint = \"ioctl_safe_set\"",
                "does not apply",
            ),
        ];
        for (body, want) in cases {
            let s = src(&format!("name = \"bad\"\nversion = \"1.0.0\"\n{body}"));
            let e = resolve("bad", &set(&[s])).unwrap_err().to_string();
            assert!(e.contains(want), "{body}: {e}");
        }
    }

    #[test]
    fn detects_cycles() {
        let a = src("name = \"a\"\nversion = \"1.0.0\"\nextends = \"b\"");
        let b = src("name = \"b\"\nversion = \"1.0.0\"\nextends = \"a\"");
        assert!(matches!(
            resolve("a", &set(&[a, b])),
            Err(SeccompError::Chain(_))
        ));
    }
}
