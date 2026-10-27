//! Admin-authored job profiles (design §8–§10). A profile is the upper bound
//! for every job that names it; `validate` rejects internally inconsistent
//! profiles before any job can use them.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::caps::{DomainSet, LimitCap, Limits, NetworkMode, valid_domain};
use crate::env;
use crate::path::RelPath;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    Namespace,
    Microvm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProcMode {
    /// `hidepid=invisible,subset=pid`
    Subset,
    /// Full `/proc` with masks and synthetic `meminfo`/`cpuinfo`.
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuMax {
    pub quota_us: u64,
    pub period_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Storage {
    pub workspace_bytes: u64,
    pub tmp_bytes: u64,
    pub shm_bytes: u64,
    /// Memory reserved for the runtime itself on top of tmpfs contents.
    pub headroom_bytes: u64,
}

impl Storage {
    /// Minimum `memory.max` for this storage layout: tmpfs pages are charged
    /// to the job's memory cgroup.
    pub fn storage_floor(&self) -> u64 {
        self.workspace_bytes
            .saturating_add(self.tmp_bytes)
            .saturating_add(self.shm_bytes)
            .saturating_add(self.headroom_bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub mode: NetworkMode,
    #[serde(default)]
    pub egress_domains: DomainSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Io {
    pub input_bytes_max: u64,
    pub artifact_bytes_max: u64,
    pub grace_max_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WriteBack {
    /// Collect risky paths but flag them in the result.
    #[default]
    Flag,
    /// Refuse to collect risky paths.
    Refuse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub version: String,
    pub backend: Backend,
    /// Bound by the co-built `policy.json`; absent in source profiles.
    #[serde(default)]
    pub runtime: Option<String>,
    pub seccomp: String,
    pub executables: BTreeSet<String>,
    pub proc: ProcMode,
    pub workspace_exec: bool,
    pub limits: Limits,
    #[serde(default)]
    pub defaults: LimitCap,
    pub cpu: CpuMax,
    pub storage: Storage,
    pub network: Network,
    #[serde(default)]
    pub env_allow: BTreeSet<String>,
    #[serde(default)]
    pub collect_prefixes: Vec<RelPath>,
    #[serde(default)]
    pub write_back: WriteBack,
    pub io: Io,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("profile `{profile}`: {field}: {problem}")]
pub struct ProfileError {
    pub profile: String,
    pub field: &'static str,
    pub problem: String,
}

impl Profile {
    pub fn from_toml(s: &str) -> Result<Self, String> {
        let p: Profile = toml::from_str(s).map_err(|e| e.to_string())?;
        p.validate().map_err(|e| e.to_string())?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<(), ProfileError> {
        let err = |field: &'static str, problem: String| {
            Err(ProfileError {
                profile: self.name.clone(),
                field,
                problem,
            })
        };

        if !valid_name(&self.name) {
            return err("name", "must match ^[a-z][a-z0-9-]{0,31}$".into());
        }
        if !valid_version(&self.version) {
            return err("version", "must be MAJOR.MINOR.PATCH".into());
        }
        if let Some(rt) = &self.runtime {
            if !valid_store_path(rt) {
                return err("runtime", format!("`{rt}` is not a /nix/store path"));
            }
        }
        if !valid_name(&self.seccomp) {
            return err("seccomp", "invalid seccomp profile name".into());
        }
        if self.executables.is_empty() {
            return err("executables", "must list at least one executable".into());
        }
        if let Some(bad) = self
            .executables
            .iter()
            .find(|e| e.is_empty() || e.contains(['/', '\0']))
        {
            return err("executables", format!("`{bad}` must be a bare file name"));
        }
        for (field, v) in self.limits.fields() {
            if v == 0 {
                return err("limits", format!("{field} must be greater than zero"));
            }
        }
        for ((field, default), (_, limit)) in
            self.defaults.fields().into_iter().zip(self.limits.fields())
        {
            match default {
                Some(0) => return err("defaults", format!("{field} must be greater than zero")),
                Some(d) if d > limit => {
                    return err("defaults", format!("{field} {d} exceeds its limit {limit}"));
                }
                _ => {}
            }
        }
        let CpuMax {
            quota_us,
            period_us,
        } = self.cpu;
        if !(1_000..=1_000_000).contains(&period_us) || quota_us < 1_000 {
            return err(
                "cpu",
                "period must be 1ms..1s and quota at least 1ms".into(),
            );
        }
        // A CPU budget the job could never reach within its wall clock is a
        // configuration error, not a limit.
        let reachable = (u128::from(self.limits.wall_ms) * u128::from(quota_us))
            .div_ceil(u128::from(period_us));
        if u128::from(self.limits.cpu_ms) > reachable {
            return err(
                "limits",
                format!(
                    "cpu_ms {} exceeds what cpu.max allows in wall_ms ({reachable})",
                    self.limits.cpu_ms
                ),
            );
        }
        let floor = self.storage.storage_floor();
        if floor > self.limits.memory_bytes {
            return err(
                "storage",
                "workspace + tmp + shm + headroom must not exceed limits.memory_bytes".into(),
            );
        }
        if self.defaults.memory_bytes.is_some_and(|d| d < floor) {
            return err(
                "defaults",
                format!("memory_bytes must be at least the storage floor {floor}"),
            );
        }
        match self.network.mode {
            NetworkMode::None if !self.network.egress_domains.is_empty() => {
                return err(
                    "network",
                    "egress_domains requires mode = egress-proxy".into(),
                );
            }
            _ => {}
        }
        if let Some(bad) = self
            .network
            .egress_domains
            .iter()
            .find(|d| !valid_domain(d))
        {
            return err(
                "network",
                format!("`{bad}` is not a valid lowercase domain name"),
            );
        }
        if let Some(bad) = self
            .env_allow
            .iter()
            .find(|k| !env::valid_key(k) || env::denied_key(k))
        {
            return err(
                "env_allow",
                format!("`{bad}` is invalid or runtime-controlled"),
            );
        }
        if u64::from(self.io.grace_max_ms) > self.limits.wall_ms {
            return err("io", "grace_max_ms must not exceed limits.wall_ms".into());
        }
        Ok(())
    }

    /// Profiles are partially ordered by inclusion; `self <= other` means every
    /// job valid under `self` is valid under `other`.
    pub fn is_narrower_or_equal(&self, other: &Profile) -> bool {
        self.backend == other.backend
            && self.executables.is_subset(&other.executables)
            && (!self.workspace_exec || other.workspace_exec)
            && self.limits.within(&other.limits)
            && self.network.mode <= other.network.mode
            && self
                .network
                .egress_domains
                .is_subset(&other.network.egress_domains)
            && self.env_allow.is_subset(&other.env_allow)
            && self
                .collect_prefixes
                .iter()
                .all(|p| other.collect_prefixes.iter().any(|o| p.starts_with(o)))
    }
}

pub(crate) fn valid_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

pub(crate) fn valid_version(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 9 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// `^/nix/store/[0-9a-z]{32}-[^/]+$`
pub fn valid_store_path(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("/nix/store/") else {
        return false;
    };
    let (hash, name) = rest.split_at_checked(32).unwrap_or(("", ""));
    hash.len() == 32
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
        && name.len() > 1
        && name.starts_with('-')
        && !name.contains(['/', '\0'])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_path_rules() {
        let h = "a".repeat(32);
        assert!(valid_store_path(&format!("/nix/store/{h}-python3")));
        assert!(!valid_store_path(&format!("/nix/store/{h}")));
        assert!(!valid_store_path(&format!("/nix/store/{h}-x/bin")));
        assert!(!valid_store_path(&format!(
            "/nix/store/{}-x",
            "A".repeat(32)
        )));
        assert!(!valid_store_path("/usr/bin/python3"));
    }

    #[test]
    fn name_and_version_rules() {
        assert!(valid_name("python-compute"));
        assert!(!valid_name("Python"));
        assert!(!valid_name("-x"));
        assert!(valid_version("1.2.3"));
        assert!(!valid_version("1.2"));
        assert!(!valid_version("1.2.x"));
    }
}
