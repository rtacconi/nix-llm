//! Trivial stage 2 for milestone M2: report the fd table and wait to be killed.
//!
//! Fd 3 is the report pipe. Fd 4 is the sync pipe: `hold` blocks on it so the
//! parent can observe the cgroup before the process exits. The filesystem
//! typestate replaces this body in M3.

fn main() {
    let hold = std::env::args().nth(1).as_deref() == Some("hold");
    if hold {
        let mut byte = [0u8; 1];
        let _ = nsbx_sys::read_fd(4, &mut byte);
    }
    let _ = nsbx_sys::close_range(5, u32::MAX);
    let fds = fd_list();
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let report = format!(
        "{{\"fds\":{fds:?},\"cgroup\":{}}}\n",
        json_string(cgroup.trim())
    );
    let _ = nsbx_sys::write_fd(3, report.as_bytes());
}

fn fd_list() -> Vec<i32> {
    let mut ids = Vec::new();
    if let Ok(dir) = std::fs::read_dir("/proc/self/fd") {
        for ent in dir.flatten() {
            if let Ok(n) = ent.file_name().to_string_lossy().parse::<i32>() {
                ids.push(n);
            }
        }
    }
    ids.sort_unstable();
    ids
}

fn json_string(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
