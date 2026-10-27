//! Message payloads. JSON frames use `deny_unknown_fields` so a peer cannot
//! smuggle fields past an older reader; binary frames have fixed layouts.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::frame::FrameType;

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub proto: Vec<u16>,
    pub client: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloAck {
    pub proto: u16,
    pub supervisor: String,
    pub features: serde_json::Map<String, serde_json::Value>,
    pub profiles: Vec<String>,
}

/// An input file. v1 sends contents inline (base64) within the 64 KiB frame
/// cap; larger inputs need staged upload frames (open decision D9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputFile {
    pub path: String,
    pub content_b64: String,
    pub mode: u32,
}

/// `request` is the policy request (`nsbx_policy::Request` as JSON); the
/// supervisor re-validates it against admin policy whatever the client did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submit {
    pub job_id: Uuid,
    pub request_hash: String,
    pub principal: String,
    pub request: serde_json::Value,
    #[serde(default)]
    pub files: Vec<InputFile>,
    #[serde(default)]
    pub stdin_b64: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEventKind {
    EgressAllowed,
    EgressDenied,
    LimitHit,
    CancelAcknowledged,
}

/// Policy decisions streamed to callers so they can measure containment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvent {
    pub job_id: Uuid,
    pub kind: PolicyEventKind,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Accepted {
    pub job_id: Uuid,
    pub slot: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rejected {
    pub job_id: Uuid,
    pub error: ErrorV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Started {
    pub job_id: Uuid,
    pub setup_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cancel {
    pub job_id: Uuid,
    pub grace_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    Protocol,
    Policy,
    Admission,
    Resource,
    Setup,
    Internal,
}

/// Structured error. `field`/`requested`/`allowed`/`hint` let an agent adapt a
/// rejected request instead of retrying blindly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorV1 {
    pub category: ErrorCategory,
    pub code: String,
    pub message: String,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    Exited,
    Signaled,
    WallTimeout,
    CpuBudget,
    Oom,
    OutputLimit,
    SeccompKill,
    SandboxDied,
    Cancelled,
    SetupFailed,
    SupervisorShutdown,
    SupervisorUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cleanup {
    Ok,
    Stuck,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInfo {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub host_executable_risk: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultV1 {
    pub job_id: Uuid,
    pub reason: TerminationReason,
    #[serde(default)]
    pub stage: Option<String>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub wall_ms: u64,
    pub cpu_user_us: u64,
    pub cpu_sys_us: u64,
    pub memory_peak_bytes: u64,
    pub oom_kills: u32,
    pub pids_limit_hits: u32,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub output_truncated: bool,
    pub artifacts: Vec<ArtifactInfo>,
    pub cleanup: Cleanup,
    pub runtime: String,
    pub policy_hash: String,
    pub insecure_dev_mode: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Stream {
    Stdout = 1,
    Stderr = 2,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PayloadError {
    #[error("{ty:?} payload has {got} bytes, expected {want}")]
    Length {
        ty: FrameType,
        got: usize,
        want: &'static str,
    },
    #[error("unknown output stream {0}")]
    Stream(u8),
}

/// `job_id[16] | stream u8 | seq u64 BE | data`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output<'a> {
    pub job_id: Uuid,
    pub stream: Stream,
    pub seq: u64,
    pub data: &'a [u8],
}

impl<'a> Output<'a> {
    const FIXED: usize = 16 + 1 + 8;

    pub fn parse(p: &'a [u8]) -> Result<Self, PayloadError> {
        if p.len() < Self::FIXED {
            return Err(PayloadError::Length {
                ty: FrameType::Output,
                got: p.len(),
                want: ">= 25",
            });
        }
        let stream = match p[16] {
            1 => Stream::Stdout,
            2 => Stream::Stderr,
            s => return Err(PayloadError::Stream(s)),
        };
        Ok(Self {
            job_id: uuid_at(p, 0),
            stream,
            seq: u64_at(p, 17),
            data: &p[Self::FIXED..],
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.job_id.as_bytes());
        out.push(self.stream as u8);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(self.data);
    }
}

/// `job_id[16] | bytes u32 BE`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Credit {
    pub job_id: Uuid,
    pub bytes: u32,
}

impl Credit {
    pub fn parse(p: &[u8]) -> Result<Self, PayloadError> {
        if p.len() != 20 {
            return Err(PayloadError::Length {
                ty: FrameType::Credit,
                got: p.len(),
                want: "20",
            });
        }
        Ok(Self {
            job_id: uuid_at(p, 0),
            bytes: u32::from_be_bytes([p[16], p[17], p[18], p[19]]),
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.job_id.as_bytes());
        out.extend_from_slice(&self.bytes.to_be_bytes());
    }
}

/// `job_id[16] | index u16 BE | offset u64 BE | data`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact<'a> {
    pub job_id: Uuid,
    pub index: u16,
    pub offset: u64,
    pub data: &'a [u8],
}

impl<'a> Artifact<'a> {
    const FIXED: usize = 16 + 2 + 8;

    pub fn parse(p: &'a [u8]) -> Result<Self, PayloadError> {
        if p.len() < Self::FIXED {
            return Err(PayloadError::Length {
                ty: FrameType::Artifact,
                got: p.len(),
                want: ">= 26",
            });
        }
        Ok(Self {
            job_id: uuid_at(p, 0),
            index: u16::from_be_bytes([p[16], p[17]]),
            offset: u64_at(p, 18),
            data: &p[Self::FIXED..],
        })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.job_id.as_bytes());
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.extend_from_slice(self.data);
    }
}

/// Ping and Pong carry an 8-byte nonce.
pub fn parse_nonce(ty: FrameType, p: &[u8]) -> Result<[u8; 8], PayloadError> {
    p.try_into().map_err(|_| PayloadError::Length {
        ty,
        got: p.len(),
        want: "8",
    })
}

fn uuid_at(p: &[u8], at: usize) -> Uuid {
    let mut b = [0u8; 16];
    b.copy_from_slice(&p[at..at + 16]);
    Uuid::from_bytes(b)
}

fn u64_at(p: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&p[at..at + 8]);
    u64::from_be_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_round_trip() {
        let o = Output {
            job_id: Uuid::from_u128(7),
            stream: Stream::Stderr,
            seq: 42,
            data: b"hi",
        };
        let mut buf = Vec::new();
        o.write(&mut buf);
        assert_eq!(Output::parse(&buf).unwrap(), o);
        assert!(Output::parse(&buf[..24]).is_err());
        buf[16] = 9;
        assert_eq!(Output::parse(&buf), Err(PayloadError::Stream(9)));
    }

    #[test]
    fn credit_and_artifact_round_trip() {
        let c = Credit {
            job_id: Uuid::from_u128(1),
            bytes: 65_536,
        };
        let mut buf = Vec::new();
        c.write(&mut buf);
        assert_eq!(Credit::parse(&buf).unwrap(), c);
        buf.push(0);
        assert!(Credit::parse(&buf).is_err());

        let a = Artifact {
            job_id: Uuid::from_u128(2),
            index: 3,
            offset: 1 << 40,
            data: b"x",
        };
        let mut buf = Vec::new();
        a.write(&mut buf);
        assert_eq!(Artifact::parse(&buf).unwrap(), a);
    }

    #[test]
    fn json_rejects_unknown_fields() {
        let ok = r#"{"proto":[1],"client":"t"}"#;
        assert!(serde_json::from_str::<Hello>(ok).is_ok());
        let extra = r#"{"proto":[1],"client":"t","admin":true}"#;
        assert!(serde_json::from_str::<Hello>(extra).is_err());
    }

    #[test]
    fn reasons_serialise_snake_case() {
        let s = serde_json::to_string(&TerminationReason::SandboxDied).unwrap();
        assert_eq!(s, r#""sandbox_died""#);
    }
}
