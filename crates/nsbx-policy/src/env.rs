//! Environment-variable keys a job may set.

/// Keys that change how the dynamic loader or an interpreter starts. These are
/// controlled by the runtime, never by requests.
const DENIED_EXACT: &[&str] = &[
    "BASH_ENV",
    "ENV",
    "PYTHONSTARTUP",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PERL5OPT",
    "RUBYOPT",
    "GCONV_PATH",
    "HOSTALIASES",
    "PATH",
    "HOME",
];
const DENIED_PREFIX: &[&str] = &["LD_", "DYLD_", "NIX_", "NSBX_"];

/// `^[A-Z_][A-Z0-9_]{0,63}$`
pub fn valid_key(k: &str) -> bool {
    let b = k.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_uppercase() || b[0] == b'_')
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

pub fn denied_key(k: &str) -> bool {
    DENIED_EXACT.contains(&k) || DENIED_PREFIX.iter().any(|p| k.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_rules() {
        assert!(valid_key("PYTHONUNBUFFERED"));
        assert!(valid_key("_X1"));
        assert!(!valid_key("lower"));
        assert!(!valid_key("1ABC"));
        assert!(!valid_key("A-B"));
        assert!(!valid_key(&"A".repeat(65)));
        assert!(denied_key("LD_PRELOAD"));
        assert!(denied_key("NODE_OPTIONS"));
        assert!(!denied_key("PYTHONUNBUFFERED"));
    }
}
