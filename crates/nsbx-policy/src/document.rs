//! Co-built `policy.json` (design §9.1).

use serde::{Deserialize, Serialize};

use crate::hash::{self, mix};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub schema: u32,
    pub runtime: String,
    pub profile: String,
    #[serde(rename = "profileVersion")]
    pub profile_version: String,
    #[serde(rename = "bpfHash")]
    pub bpf_hash: String,
    #[serde(rename = "landlockDigest")]
    pub landlock_digest: String,
}

/// The supervisor accepts the pair only when `policy.json` names this runtime.
pub fn binds(doc: &PolicyDocument, runtime: &str) -> Result<(), String> {
    if doc.schema != 1 {
        return Err(format!("policy schema {} is not 1", doc.schema));
    }
    if doc.runtime != runtime {
        return Err(format!(
            "policy runtime {} does not match {runtime}",
            doc.runtime
        ));
    }
    if doc.bpf_hash.len() != 16 || doc.landlock_digest.len() != 16 {
        return Err("policy hashes must be 16 hex digits".into());
    }
    Ok(())
}

/// Digest of the closure paths plus the rights generation. Sorting makes the
/// order of `closureInfo` irrelevant.
pub fn landlock_digest(paths: &[String]) -> u64 {
    let mut sorted: Vec<&str> = paths.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let mut state = hash::new();
    mix(&mut state, b"landlock-rights-v1\n");
    for path in sorted {
        mix(&mut state, path.as_bytes());
        mix(&mut state, b"\n");
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(runtime: &str) -> PolicyDocument {
        PolicyDocument {
            schema: 1,
            runtime: runtime.into(),
            profile: "python-compute".into(),
            profile_version: "1.0.0".into(),
            bpf_hash: "0123456789abcdef".into(),
            landlock_digest: "fedcba9876543210".into(),
        }
    }

    #[test]
    fn binds_requires_the_same_runtime_path() {
        let runtime = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-python-compute-runtime";
        assert!(binds(&doc(runtime), runtime).is_ok());
        let err = binds(&doc("/nix/store/other"), runtime).expect_err("mismatch");
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn landlock_digest_ignores_order_and_sees_a_new_path() {
        let a = landlock_digest(&["/nix/store/b".into(), "/nix/store/a".into()]);
        let b = landlock_digest(&["/nix/store/a".into(), "/nix/store/b".into()]);
        assert_eq!(a, b);
        let c = landlock_digest(&["/nix/store/a".into(), "/nix/store/c".into()]);
        assert_ne!(a, c);
    }
}
