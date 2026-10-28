//! `closure-audit`: the executables in a runtime must match a committed allowlist.

use std::collections::BTreeSet;
use std::path::Path;

pub fn names_in(dir: &Path) -> Result<BTreeSet<String>, String> {
    let mut names = BTreeSet::new();
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(format!("{} has a non-utf8 name", dir.display()));
        };
        names.insert(name.to_string());
    }
    Ok(names)
}

pub fn load_allowlist(path: &Path) -> Result<BTreeSet<String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(text
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect())
}

/// Equal sets. A nixpkgs bump that adds or drops a binary fails the build.
pub fn diff(allow: &BTreeSet<String>, found: &BTreeSet<String>) -> Result<(), String> {
    let extra: Vec<&str> = found.difference(allow).map(String::as_str).collect();
    let missing: Vec<&str> = allow.difference(found).map(String::as_str).collect();
    if extra.is_empty() && missing.is_empty() {
        return Ok(());
    }
    Err(format!(
        "closure-audit extra [{}] missing [{}]",
        extra.join(", "),
        missing.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_sets_pass_and_a_new_name_fails() {
        let allow = BTreeSet::from(["python3".into()]);
        let mut found = allow.clone();
        assert!(diff(&allow, &found).is_ok());
        found.insert("curl".into());
        let err = diff(&allow, &found).expect_err("extra");
        assert!(err.contains("curl"), "{err}");
    }
}
