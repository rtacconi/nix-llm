//! `narrow()`: the single function that turns a request into the effective
//! job configuration (design §12.1).
//!
//! Invariant: when it returns `Ok(e)`, then `e ⊆ request ⊆ principal ⊆ profile`
//! for every capability-bearing field. Widening is impossible through this
//! function; it only ever happens by an admin changing a profile.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::caps::{DomainSet, LimitCap, Limits, NetworkMode, valid_domain};
use crate::env;
use crate::path::RelPath;
use crate::profile::{Profile, WriteBack};

pub const MAX_ARGS: usize = 256;
pub const MAX_ARG_BYTES: usize = 4096;
pub const MAX_ENV: usize = 64;
pub const MAX_FILES: usize = 1024;
pub const MAX_COLLECT: usize = 64;
pub const DEFAULT_GRACE_MS: u32 = 2_000;

/// What a caller (agent principal) is allowed to use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub id: String,
    pub profiles: BTreeSet<String>,
    #[serde(default)]
    pub limits: LimitCap,
    #[serde(default)]
    pub network_max: NetworkMode,
    /// `None` = whatever the profile allows.
    #[serde(default)]
    pub egress_domains: Option<DomainSet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub profile: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub limits: LimitCap,
    #[serde(default)]
    pub network: Option<NetworkMode>,
    #[serde(default)]
    pub egress_domains: DomainSet,
    #[serde(default)]
    pub collect: Vec<String>,
    /// Paths of input files (contents travel separately).
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub input_bytes: u64,
    #[serde(default)]
    pub grace_ms: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effective {
    pub profile: String,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub limits: Limits,
    pub network: NetworkMode,
    pub egress_domains: DomainSet,
    pub collect: Vec<RelPath>,
    pub files: Vec<RelPath>,
    pub grace_ms: u32,
}

/// Why a request was refused. Mirrors `nsbx_proto::msg::ErrorV1` fields so a
/// denial can tell the agent exactly what to change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Denial {
    pub code: &'static str,
    pub field: String,
    pub requested: Option<String>,
    pub allowed: Option<String>,
    pub hint: String,
}

fn deny(
    code: &'static str,
    field: impl Into<String>,
    requested: Option<String>,
    allowed: Option<String>,
    hint: impl Into<String>,
) -> Denial {
    Denial {
        code,
        field: field.into(),
        requested,
        allowed,
        hint: hint.into(),
    }
}

pub fn narrow(
    profile: &Profile,
    principal: &Principal,
    req: &Request,
) -> Result<Effective, Denial> {
    if req.profile != profile.name {
        return Err(deny(
            "profile_mismatch",
            "profile",
            Some(req.profile.clone()),
            Some(profile.name.clone()),
            "internal: request evaluated against the wrong profile",
        ));
    }
    if !principal.profiles.contains(&profile.name) {
        let allowed = principal
            .profiles
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        return Err(deny(
            "profile_not_allowed",
            "profile",
            Some(profile.name.clone()),
            Some(allowed),
            "use one of the allowed profiles (GET /v1/profiles)",
        ));
    }

    // argv
    let Some(argv0) = req.argv.first() else {
        return Err(deny(
            "argv_empty",
            "argv",
            None,
            None,
            "argv must name an executable",
        ));
    };
    if req.argv.len() > MAX_ARGS {
        return Err(deny(
            "argv_too_long",
            "argv",
            Some(req.argv.len().to_string()),
            Some(MAX_ARGS.to_string()),
            "pass fewer arguments; put data in files",
        ));
    }
    if let Some((i, _)) = req
        .argv
        .iter()
        .enumerate()
        .find(|(_, a)| a.len() > MAX_ARG_BYTES || a.contains('\0'))
    {
        return Err(deny(
            "argv_invalid",
            format!("argv[{i}]"),
            None,
            Some(format!("<= {MAX_ARG_BYTES} bytes, no NUL")),
            "put large data in files",
        ));
    }
    if !profile.executables.contains(argv0) {
        let allowed = profile
            .executables
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        return Err(deny(
            "executable_not_in_runtime",
            "argv[0]",
            Some(argv0.clone()),
            Some(allowed),
            "use an executable provided by this profile's runtime",
        ));
    }

    // env
    if req.env.len() > MAX_ENV {
        return Err(deny(
            "env_too_large",
            "env",
            Some(req.env.len().to_string()),
            Some(MAX_ENV.to_string()),
            "set fewer variables",
        ));
    }
    for (k, v) in &req.env {
        if !env::valid_key(k) || env::denied_key(k) || !profile.env_allow.contains(k) {
            let allowed = profile
                .env_allow
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(",");
            return Err(deny(
                "env_key_not_allowed",
                format!("env.{k}"),
                Some(k.clone()),
                Some(allowed),
                "only the profile's env_allow keys may be set",
            ));
        }
        if v.len() > MAX_ARG_BYTES || v.contains('\0') {
            return Err(deny(
                "env_value_invalid",
                format!("env.{k}"),
                None,
                Some(format!("<= {MAX_ARG_BYTES} bytes, no NUL")),
                "shorten the value",
            ));
        }
    }

    // limits: allowed = profile ∧ principal; effective = request or default, never above allowed
    let allowed = profile.limits.meet(&principal.limits);
    let defaults = profile
        .limits
        .meet(&profile.defaults)
        .meet(&principal.limits);
    let pids = pick_limit(
        "pids",
        req.limits.pids.map(u64::from),
        u64::from(allowed.pids),
        u64::from(defaults.pids),
    )?;
    let limits = Limits {
        wall_ms: pick_limit(
            "wall_ms",
            req.limits.wall_ms,
            allowed.wall_ms,
            defaults.wall_ms,
        )?,
        cpu_ms: pick_limit("cpu_ms", req.limits.cpu_ms, allowed.cpu_ms, defaults.cpu_ms)?,
        memory_bytes: pick_limit(
            "memory_bytes",
            req.limits.memory_bytes,
            allowed.memory_bytes,
            defaults.memory_bytes,
        )?,
        pids: u32::try_from(pids).unwrap_or(allowed.pids),
        output_bytes: pick_limit(
            "output_bytes",
            req.limits.output_bytes,
            allowed.output_bytes,
            defaults.output_bytes,
        )?,
    };
    // tmpfs contents are charged to the job's memory cgroup, so a request may
    // not shrink memory below what the profile's storage needs.
    let s = profile.storage;
    let storage_floor = s.storage_floor();
    if limits.memory_bytes < storage_floor {
        return Err(deny(
            "memory_below_storage",
            "limits.memory_bytes",
            Some(limits.memory_bytes.to_string()),
            Some(format!(">= {storage_floor}")),
            "this profile's tmpfs sizes need at least this much memory",
        ));
    }

    // network: chain meet, default to the narrowest mode
    let net_allowed = profile.network.mode.min(principal.network_max);
    let network = req.network.unwrap_or_default();
    if network > net_allowed {
        return Err(deny(
            "network_not_allowed",
            "network",
            Some(format!("{network:?}")),
            Some(format!("{net_allowed:?}")),
            "this profile/principal does not allow network access",
        ));
    }
    let domains_allowed: DomainSet = match &principal.egress_domains {
        Some(p) => profile
            .network
            .egress_domains
            .intersection(p)
            .cloned()
            .collect(),
        None => profile.network.egress_domains.clone(),
    };
    let egress_domains = match network {
        NetworkMode::None => {
            if !req.egress_domains.is_empty() {
                return Err(deny(
                    "egress_without_network",
                    "egress_domains",
                    None,
                    None,
                    "set network = egress-proxy or drop egress_domains",
                ));
            }
            DomainSet::new()
        }
        NetworkMode::EgressProxy => {
            if let Some(d) = req
                .egress_domains
                .iter()
                .find(|d| !valid_domain(d) || !domains_allowed.contains(*d))
            {
                let allowed = domains_allowed
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",");
                return Err(deny(
                    "domain_not_allowed",
                    "egress_domains",
                    Some(d.clone()),
                    Some(allowed),
                    "request only allowlisted domains",
                ));
            }
            if req.egress_domains.is_empty() {
                domains_allowed
            } else {
                req.egress_domains.clone()
            }
        }
    };

    // files and collect paths
    if req.files.len() > MAX_FILES {
        return Err(deny(
            "too_many_files",
            "files",
            Some(req.files.len().to_string()),
            Some(MAX_FILES.to_string()),
            "bundle inputs into fewer files",
        ));
    }
    if req.input_bytes > profile.io.input_bytes_max {
        return Err(deny(
            "input_too_large",
            "files",
            Some(req.input_bytes.to_string()),
            Some(profile.io.input_bytes_max.to_string()),
            "send less input data",
        ));
    }
    let mut files = Vec::with_capacity(req.files.len());
    let mut seen = BTreeSet::new();
    for (i, f) in req.files.iter().enumerate() {
        let p = RelPath::parse(f).map_err(|e| {
            deny(
                "path_invalid",
                format!("files[{i}]"),
                Some(f.clone()),
                None,
                e.to_string(),
            )
        })?;
        if !seen.insert(p.clone()) {
            return Err(deny(
                "path_duplicate",
                format!("files[{i}]"),
                Some(f.clone()),
                None,
                "each input path may appear once",
            ));
        }
        files.push(p);
    }
    if req.collect.len() > MAX_COLLECT {
        return Err(deny(
            "too_many_collect",
            "collect",
            Some(req.collect.len().to_string()),
            Some(MAX_COLLECT.to_string()),
            "collect a directory prefix instead",
        ));
    }
    let mut collect = Vec::with_capacity(req.collect.len());
    for (i, c) in req.collect.iter().enumerate() {
        let p = RelPath::parse(c).map_err(|e| {
            deny(
                "path_invalid",
                format!("collect[{i}]"),
                Some(c.clone()),
                None,
                e.to_string(),
            )
        })?;
        if !profile
            .collect_prefixes
            .iter()
            .any(|pre| p.starts_with(pre))
        {
            let allowed = profile
                .collect_prefixes
                .iter()
                .map(RelPath::as_str)
                .collect::<Vec<_>>()
                .join(",");
            return Err(deny(
                "collect_outside_prefix",
                format!("collect[{i}]"),
                Some(c.clone()),
                Some(allowed),
                "collect only under the profile's collect prefixes",
            ));
        }
        if profile.write_back == WriteBack::Refuse && p.host_executable_risk() {
            return Err(deny(
                "collect_host_executable",
                format!("collect[{i}]"),
                Some(c.clone()),
                None,
                "this profile refuses to return files the host may execute automatically",
            ));
        }
        collect.push(p);
    }

    // grace
    let grace_max = profile.io.grace_max_ms;
    let grace_ms = match req.grace_ms {
        Some(g) if g > grace_max => {
            return Err(deny(
                "grace_exceeds_allowed",
                "grace_ms",
                Some(g.to_string()),
                Some(grace_max.to_string()),
                format!("request at most {grace_max}"),
            ));
        }
        Some(g) => g,
        None => DEFAULT_GRACE_MS.min(grace_max),
    };

    Ok(Effective {
        profile: profile.name.clone(),
        argv: req.argv.clone(),
        env: req.env.clone(),
        limits,
        network,
        egress_domains,
        collect,
        files,
        grace_ms,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LimitViolation {
    Zero,
    Exceeds,
}

/// One numeric limit, without allocation so it can be model-checked: the
/// requested value if it is within `allowed`, else `default` clamped to
/// `allowed`.
pub(crate) fn decide_limit(
    requested: Option<u64>,
    allowed: u64,
    default: u64,
) -> Result<u64, LimitViolation> {
    match requested {
        Some(0) => Err(LimitViolation::Zero),
        Some(r) if r > allowed => Err(LimitViolation::Exceeds),
        Some(r) => Ok(r),
        None => Ok(default.min(allowed)),
    }
}

/// `decide_limit` plus a structured denial for the agent.
pub(crate) fn pick_limit(
    field: &'static str,
    requested: Option<u64>,
    allowed: u64,
    default: u64,
) -> Result<u64, Denial> {
    decide_limit(requested, allowed, default).map_err(|v| match v {
        LimitViolation::Zero => deny(
            "limit_zero",
            format!("limits.{field}"),
            Some("0".into()),
            Some(allowed.to_string()),
            "limits must be greater than zero",
        ),
        LimitViolation::Exceeds => deny(
            "limit_exceeds_allowed",
            format!("limits.{field}"),
            requested.map(|r| r.to_string()),
            Some(allowed.to_string()),
            format!("request at most {allowed}"),
        ),
    })
}

impl Effective {
    /// `self ⊆ profile` for every capability-bearing field.
    pub fn within_profile(&self, p: &Profile) -> bool {
        self.profile == p.name
            && self.argv.first().is_some_and(|a| p.executables.contains(a))
            && self
                .env
                .keys()
                .all(|k| p.env_allow.contains(k) && !env::denied_key(k))
            && self.limits.within(&p.limits)
            && self.network <= p.network.mode
            && self.egress_domains.is_subset(&p.network.egress_domains)
            && self
                .collect
                .iter()
                .all(|c| p.collect_prefixes.iter().any(|pre| c.starts_with(pre)))
            && self.grace_ms <= p.io.grace_max_ms
    }

    /// `self ⊆ principal`
    pub fn within_principal(&self, pr: &Principal) -> bool {
        pr.profiles.contains(&self.profile)
            && self.limits.within_cap(&pr.limits)
            && self.network <= pr.network_max
            && pr
                .egress_domains
                .as_ref()
                .is_none_or(|d| self.egress_domains.is_subset(d))
    }

    /// `self ⊆ request`: every value the request pinned is kept exactly or
    /// narrowed, and nothing the request did not ask for is added.
    pub fn within_request(&self, r: &Request) -> bool {
        let lim = self.limits;
        let req = r.limits;
        self.argv == r.argv
            && self.env == r.env
            && req.wall_ms.is_none_or(|v| lim.wall_ms <= v)
            && req.cpu_ms.is_none_or(|v| lim.cpu_ms <= v)
            && req.memory_bytes.is_none_or(|v| lim.memory_bytes <= v)
            && req.pids.is_none_or(|v| lim.pids <= v)
            && req.output_bytes.is_none_or(|v| lim.output_bytes <= v)
            && self.network <= r.network.unwrap_or_default()
            && (r.egress_domains.is_empty() || self.egress_domains.is_subset(&r.egress_domains))
            && self.collect.len() == r.collect.len()
            && self.files.len() == r.files.len()
            && r.grace_ms.is_none_or(|g| self.grace_ms <= g)
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// For every profile limit, principal cap, profile default and requested
    /// value, an accepted limit is positive (when requested) and never exceeds
    /// the profile, the principal's cap or the request.
    #[kani::proof]
    fn decide_limit_is_narrow_only() {
        let profile: u64 = kani::any();
        let cap: Option<u64> = kani::any();
        let default: Option<u64> = kani::any();
        let requested: Option<u64> = kani::any();
        let allowed = cap.map_or(profile, |c| c.min(profile));
        let dflt = default.map_or(profile, |d| d.min(profile));
        if let Ok(v) = decide_limit(requested, allowed, dflt) {
            assert!(v <= profile);
            assert!(cap.is_none_or(|c| v <= c));
            assert!(requested.is_none_or(|r| v == r && r > 0));
        }
    }
}
