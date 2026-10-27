//! Relative paths inside the sandbox workspace.
//!
//! A `RelPath` can only be built through `RelPath::parse`, which rejects every
//! form that could resolve outside its base directory. The supervisor still
//! resolves paths with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | ...)`;
//! this is the first, purely lexical check (design §6.4).

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_COMPONENTS: usize = 32;
pub const MAX_COMPONENT_BYTES: usize = 255;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PathError {
    #[error("path is empty")]
    Empty,
    #[error("path is longer than {MAX_PATH_BYTES} bytes")]
    TooLong,
    #[error("path contains a NUL byte")]
    Nul,
    #[error("path is absolute")]
    Absolute,
    #[error("path has an empty component (`//` or trailing `/`)")]
    EmptyComponent,
    #[error("path contains a `.` or `..` component")]
    DotComponent,
    #[error("path has more than {MAX_COMPONENTS} components")]
    TooDeep,
    #[error("path component is longer than {MAX_COMPONENT_BYTES} bytes")]
    ComponentTooLong,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RelPath(String);

impl RelPath {
    pub fn parse(s: &str) -> Result<Self, PathError> {
        if s.is_empty() {
            return Err(PathError::Empty);
        }
        if s.len() > MAX_PATH_BYTES {
            return Err(PathError::TooLong);
        }
        if s.contains('\0') {
            return Err(PathError::Nul);
        }
        if s.starts_with('/') {
            return Err(PathError::Absolute);
        }
        let mut count = 0;
        for c in s.split('/') {
            count += 1;
            if count > MAX_COMPONENTS {
                return Err(PathError::TooDeep);
            }
            match c {
                "" => return Err(PathError::EmptyComponent),
                "." | ".." => return Err(PathError::DotComponent),
                c if c.len() > MAX_COMPONENT_BYTES => return Err(PathError::ComponentTooLong),
                _ => {}
            }
        }
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// Component-wise prefix: `out` contains `out` and `out/a`, not `outer`.
    pub fn starts_with(&self, prefix: &RelPath) -> bool {
        let mut mine = self.components();
        prefix.components().all(|p| mine.next() == Some(p))
    }

    /// True for paths that the host may execute automatically if this file is
    /// written back into a checkout (design §6.5): VCS hooks and config, direnv,
    /// editor task definitions, agent instruction files, Nix flakes and CI.
    pub fn host_executable_risk(&self) -> bool {
        const RISKY_COMPONENTS: &[&str] = &[
            ".git",
            ".envrc",
            ".vscode",
            ".idea",
            "AGENTS.md",
            "CLAUDE.md",
            "GEMINI.md",
            ".clinerules",
            ".cursorrules",
            ".windsurfrules",
            "flake.nix",
            ".gitlab-ci.yml",
        ];
        let parts: Vec<&str> = self.components().collect();
        parts.iter().any(|c| RISKY_COMPONENTS.contains(c))
            || parts.windows(2).any(|w| w == [".github", "workflows"])
    }
}

impl TryFrom<String> for RelPath {
    type Error = PathError;
    fn try_from(s: String) -> Result<Self, PathError> {
        Self::parse(&s)
    }
}

impl From<RelPath> for String {
    fn from(p: RelPath) -> String {
        p.0
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn accepts_plain_paths() {
        for p in ["a", "out/result.json", "a/b-c_d.e/f", "..hidden", "a/.b"] {
            assert!(RelPath::parse(p).is_ok(), "{p}");
        }
    }

    #[test]
    fn rejects_escaping_and_malformed_paths() {
        let cases = [
            ("", PathError::Empty),
            ("/etc/x", PathError::Absolute),
            ("a/../b", PathError::DotComponent),
            ("..", PathError::DotComponent),
            ("./a", PathError::DotComponent),
            ("a//b", PathError::EmptyComponent),
            ("a/", PathError::EmptyComponent),
            ("a\0b", PathError::Nul),
        ];
        for (p, e) in cases {
            assert_eq!(RelPath::parse(p), Err(e), "{p:?}");
        }
        let deep = vec!["d"; MAX_COMPONENTS + 1].join("/");
        assert_eq!(RelPath::parse(&deep), Err(PathError::TooDeep));
    }

    #[test]
    fn prefix_is_component_wise() {
        let out = RelPath::parse("out").unwrap();
        assert!(RelPath::parse("out").unwrap().starts_with(&out));
        assert!(RelPath::parse("out/a/b").unwrap().starts_with(&out));
        assert!(!RelPath::parse("outer/a").unwrap().starts_with(&out));
        assert!(!RelPath::parse("a/out").unwrap().starts_with(&out));
    }

    #[test]
    fn flags_host_executable_paths() {
        for p in [
            ".git/hooks/pre-commit",
            "sub/.envrc",
            ".github/workflows/ci.yml",
            "AGENTS.md",
            "x/flake.nix",
        ] {
            assert!(RelPath::parse(p).unwrap().host_executable_risk(), "{p}");
        }
        for p in ["src/main.rs", "github/workflows", "out/report.json"] {
            assert!(!RelPath::parse(p).unwrap().host_executable_risk(), "{p}");
        }
    }

    proptest! {
        #[test]
        fn accepted_paths_never_escape(s in "[a-z./]{0,40}") {
            if let Ok(p) = RelPath::parse(&s) {
                prop_assert!(!p.as_str().starts_with('/'));
                prop_assert!(p.components().all(|c| !c.is_empty() && c != "." && c != ".."));
            }
        }
    }
}
