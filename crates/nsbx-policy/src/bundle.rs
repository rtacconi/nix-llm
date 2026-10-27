//! A loaded set of admin profiles with JSON entry points. Used by the
//! supervisor and, through the PyO3 binding, by the orchestrator, so both
//! narrow requests with exactly the same code.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde_json::{Value, json};
use thiserror::Error;

use crate::narrow::{Denial, Principal, Request, narrow};
use crate::profile::Profile;

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("{path}: {message}")]
    Profile { path: String, message: String },
    #[error("duplicate profile name `{0}`")]
    Duplicate(String),
    #[error("invalid {what} JSON: {message}")]
    Json { what: &'static str, message: String },
    #[error("request denied: {}", .0.code)]
    Denied(Denial),
}

#[derive(Debug, Clone, Default)]
pub struct PolicyBundle {
    profiles: BTreeMap<String, Profile>,
}

impl PolicyBundle {
    /// Load and validate every `*.toml` in `dir`.
    pub fn load_dir(dir: &Path) -> Result<Self, BundleError> {
        let io = |e| BundleError::Io {
            path: dir.display().to_string(),
            source: e,
        };
        let mut paths: Vec<_> = fs::read_dir(dir)
            .map_err(io)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        paths.sort();
        let mut texts = Vec::with_capacity(paths.len());
        for p in paths {
            let text = fs::read_to_string(&p).map_err(|e| BundleError::Io {
                path: p.display().to_string(),
                source: e,
            })?;
            texts.push((p.display().to_string(), text));
        }
        Self::from_tomls(texts)
    }

    /// Build from `(label, toml)` pairs; the label is only used in errors.
    pub fn from_tomls<I: IntoIterator<Item = (String, String)>>(
        items: I,
    ) -> Result<Self, BundleError> {
        let mut profiles = BTreeMap::new();
        for (path, text) in items {
            let p = Profile::from_toml(&text)
                .map_err(|message| BundleError::Profile { path, message })?;
            if profiles.contains_key(&p.name) {
                return Err(BundleError::Duplicate(p.name));
            }
            profiles.insert(p.name.clone(), p);
        }
        Ok(Self { profiles })
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.profiles.keys().map(String::as_str)
    }

    pub fn get(&self, name: &str) -> Option<&Profile> {
        self.profiles.get(name)
    }

    /// Narrow a JSON request for a JSON principal. Returns the effective job
    /// as JSON, or `BundleError::Denied` with a structured denial.
    pub fn narrow_json(&self, principal: &str, request: &str) -> Result<Value, BundleError> {
        let principal: Principal =
            serde_json::from_str(principal).map_err(|e| BundleError::Json {
                what: "principal",
                message: e.to_string(),
            })?;
        let request: Request = serde_json::from_str(request).map_err(|e| BundleError::Json {
            what: "request",
            message: e.to_string(),
        })?;
        let profile = self.profiles.get(&request.profile).ok_or_else(|| {
            BundleError::Denied(Denial {
                code: "unknown_profile",
                field: "profile".into(),
                requested: Some(request.profile.clone()),
                allowed: Some(self.names().collect::<Vec<_>>().join(",")),
                hint: "use GET /v1/profiles".into(),
            })
        })?;
        let effective = narrow(profile, &principal, &request).map_err(BundleError::Denied)?;
        serde_json::to_value(effective).map_err(|e| BundleError::Json {
            what: "effective",
            message: e.to_string(),
        })
    }

    /// A machine-readable description of what a job under `name` can and
    /// cannot do, for agents to read before acting (design §12.1).
    pub fn environment(&self, name: &str) -> Option<Value> {
        let p = self.profiles.get(name)?;
        Some(json!({
            "profile": p.name,
            "version": p.version,
            "backend": p.backend,
            "executables": p.executables,
            "network": {
                "mode": p.network.mode,
                "egress_domains": p.network.egress_domains,
            },
            "filesystem": {
                "workdir": "/workspace",
                "writable": ["/workspace", "/tmp", "/dev/shm"],
                "workspace_exec": p.workspace_exec,
                "workspace_bytes": p.storage.workspace_bytes,
                "tmp_bytes": p.storage.tmp_bytes,
                "collect_prefixes": p.collect_prefixes,
                "write_back": p.write_back,
            },
            "limits": { "max": p.limits, "defaults": p.defaults },
            "env_allow": p.env_allow,
            "proc": p.proc,
            "notes": [
                "No shell is available unless it is listed in executables.",
                "Writes outside the writable paths fail with EROFS or EACCES.",
                "With network mode none there is no DNS and no route; connections fail immediately.",
                "Exceeding a limit returns a structured denial naming the field and the allowed value."
            ],
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_bundle() -> PolicyBundle {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../policy/profiles");
        PolicyBundle::load_dir(&dir).unwrap()
    }

    const PRINCIPAL: &str = r#"{"id":"a","profiles":["python-compute"]}"#;

    #[test]
    fn narrows_json_requests() {
        let b = repo_bundle();
        let e = b
            .narrow_json(
                PRINCIPAL,
                r#"{"profile":"python-compute","argv":["python3","-c","1"]}"#,
            )
            .unwrap();
        assert_eq!(e["network"], "none");
        assert_eq!(e["limits"]["wall_ms"], 30_000);
    }

    #[test]
    fn denials_are_structured() {
        let b = repo_bundle();
        let req = r#"{"profile":"python-compute","argv":["python3"],"limits":{"pids":100000}}"#;
        match b.narrow_json(PRINCIPAL, req) {
            Err(BundleError::Denied(d)) => {
                assert_eq!(d.field, "limits.pids");
                assert_eq!(d.allowed.as_deref(), Some("128"));
            }
            other => panic!("{other:?}"),
        }
        let unknown = r#"{"profile":"nope","argv":["x"]}"#;
        assert!(
            matches!(b.narrow_json(PRINCIPAL, unknown), Err(BundleError::Denied(d)) if d.code == "unknown_profile")
        );
        assert!(matches!(
            b.narrow_json(PRINCIPAL, r#"{"profile":1}"#),
            Err(BundleError::Json { .. })
        ));
        let extra = r#"{"profile":"python-compute","argv":["python3"],"admin":true}"#;
        assert!(matches!(
            b.narrow_json(PRINCIPAL, extra),
            Err(BundleError::Json { .. })
        ));
    }

    #[test]
    fn environment_describes_the_profile() {
        let env = repo_bundle().environment("python-compute").unwrap();
        assert_eq!(env["executables"], json!(["python3"]));
        assert_eq!(env["network"]["mode"], "none");
        assert_eq!(env["filesystem"]["write_back"], "refuse");
        assert!(repo_bundle().environment("nope").is_none());
    }

    #[test]
    fn rejects_duplicate_names() {
        let text = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../policy/profiles/cli-text.toml"),
        )
        .unwrap();
        let r = PolicyBundle::from_tomls([("a".into(), text.clone()), ("b".into(), text)]);
        assert!(matches!(r, Err(BundleError::Duplicate(_))));
    }
}
