//! Capability values that are ordered, so narrowing is a lattice meet.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Resource limits. Every field is a maximum; smaller is narrower.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub wall_ms: u64,
    pub cpu_ms: u64,
    pub memory_bytes: u64,
    pub pids: u32,
    pub output_bytes: u64,
}

impl Limits {
    pub fn meet(&self, o: &LimitCap) -> Limits {
        Limits {
            wall_ms: o.wall_ms.map_or(self.wall_ms, |v| v.min(self.wall_ms)),
            cpu_ms: o.cpu_ms.map_or(self.cpu_ms, |v| v.min(self.cpu_ms)),
            memory_bytes: o
                .memory_bytes
                .map_or(self.memory_bytes, |v| v.min(self.memory_bytes)),
            pids: o.pids.map_or(self.pids, |v| v.min(self.pids)),
            output_bytes: o
                .output_bytes
                .map_or(self.output_bytes, |v| v.min(self.output_bytes)),
        }
    }

    pub fn within(&self, o: &Limits) -> bool {
        self.wall_ms <= o.wall_ms
            && self.cpu_ms <= o.cpu_ms
            && self.memory_bytes <= o.memory_bytes
            && self.pids <= o.pids
            && self.output_bytes <= o.output_bytes
    }

    pub fn within_cap(&self, o: &LimitCap) -> bool {
        o.wall_ms.is_none_or(|v| self.wall_ms <= v)
            && o.cpu_ms.is_none_or(|v| self.cpu_ms <= v)
            && o.memory_bytes.is_none_or(|v| self.memory_bytes <= v)
            && o.pids.is_none_or(|v| self.pids <= v)
            && o.output_bytes.is_none_or(|v| self.output_bytes <= v)
    }

    pub(crate) fn fields(&self) -> [(&'static str, u64); 5] {
        [
            ("wall_ms", self.wall_ms),
            ("cpu_ms", self.cpu_ms),
            ("memory_bytes", self.memory_bytes),
            ("pids", u64::from(self.pids)),
            ("output_bytes", self.output_bytes),
        ]
    }
}

/// A partial set of limits: a principal's cap or a request. `None` = no opinion.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitCap {
    pub wall_ms: Option<u64>,
    pub cpu_ms: Option<u64>,
    pub memory_bytes: Option<u64>,
    pub pids: Option<u32>,
    pub output_bytes: Option<u64>,
}

impl LimitCap {
    pub(crate) fn fields(&self) -> [(&'static str, Option<u64>); 5] {
        [
            ("wall_ms", self.wall_ms),
            ("cpu_ms", self.cpu_ms),
            ("memory_bytes", self.memory_bytes),
            ("pids", self.pids.map(u64::from)),
            ("output_bytes", self.output_bytes),
        ]
    }
}

/// Network modes form a chain: `None < EgressProxy`.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    #[default]
    None,
    EgressProxy,
}

/// A validated lowercase DNS name used in egress allowlists. IP literals are
/// rejected: egress policy is by name, and the proxy checks resolved addresses.
pub fn valid_domain(d: &str) -> bool {
    if d.is_empty() || d.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = d.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && !labels
            .last()
            .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
}

pub type DomainSet = BTreeSet<String>;
