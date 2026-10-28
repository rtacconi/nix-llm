//! Copy regular files from the workspace prefixes into a status record.
//! Symlinks are left out. Files larger than 64 KiB are left out.

use std::fs;
use std::path::Path;

use nsbx_policy::risk::host_executable_risk;
use nsbx_proto::status::{self, Item};

const MAX_BYTES: u64 = 65_536;
const MAX_FILES: usize = 32;

pub fn gather(prefixes: &[String]) -> Vec<Item> {
    let mut out = Vec::new();
    for prefix in prefixes {
        if out.len() >= MAX_FILES {
            break;
        }
        if !path_ok(prefix) {
            continue;
        }
        let root = Path::new("/workspace").join(prefix);
        walk(&root, prefix, &mut out, 0);
    }
    out
}

fn walk(dir: &Path, rel: &str, out: &mut Vec<Item>, depth: u32) {
    if depth > 8 || out.len() >= MAX_FILES {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for ent in entries.flatten() {
        if out.len() >= MAX_FILES {
            return;
        }
        let Some(name) = ent.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !path_ok(&name) {
            continue;
        }
        let rel_path = if rel.is_empty() {
            name
        } else {
            format!("{rel}/{name}")
        };
        let Ok(meta) = fs::symlink_metadata(ent.path()) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            walk(&ent.path(), &rel_path, out, depth + 1);
            continue;
        }
        if !meta.is_file() || meta.len() > MAX_BYTES {
            continue;
        }
        let Ok(data) = fs::read(ent.path()) else {
            continue;
        };
        if data.len() as u64 != meta.len() {
            continue;
        }
        out.push(Item {
            path: rel_path.clone(),
            size: data.len() as u64,
            sha256: status::digest(&data),
            risk: host_executable_risk(&rel_path),
            data,
        });
    }
}

fn path_ok(text: &str) -> bool {
    !text.is_empty()
        && text != "."
        && text != ".."
        && !text.contains('"')
        && !text.contains('\\')
        && !text.contains('\n')
        && !text.contains('\0')
}

#[cfg(test)]
mod tests {
    use super::path_ok;

    #[test]
    fn rejects_a_quote_in_a_collected_name() {
        assert!(!path_ok("a\"b"));
        assert!(path_ok("out/note"));
    }
}
