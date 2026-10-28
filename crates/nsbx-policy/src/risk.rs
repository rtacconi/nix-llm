//! Paths the host might execute after a job writes them back (design §6.5).

pub fn host_executable_risk(path: &str) -> bool {
    let name = path.trim_start_matches('/');
    let base = match name.rsplit('/').next() {
        Some(base) => base,
        None => return false,
    };
    base == ".envrc"
        || base == "AGENTS.md"
        || base == "flake.nix"
        || name.contains(".git/hooks/")
        || name.ends_with(".git/config")
        || name.contains(".github/workflows/")
        || name.contains(".clinerules/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_host_executed_paths_and_leaves_ordinary_files() {
        assert!(host_executable_risk("out/.git/hooks/pre-commit"));
        assert!(host_executable_risk("flake.nix"));
        assert!(host_executable_risk("src/AGENTS.md"));
        assert!(!host_executable_risk("out/result.txt"));
    }
}
