//! Host-side checks of the probe's JSON line. Sandbox denial is covered by
//! the stage 2 tests.

#![cfg(target_os = "linux")]

use std::process::Command;

fn probe(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_nsbx-probe"))
        .args(args)
        .output()
        .expect("probe");
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf8")
}

#[test]
fn caps_and_spawn_print_one_json_line() {
    let caps = probe(&["caps"]);
    assert!(caps.contains(r#""probe":"caps""#), "{caps}");
    let spawned = probe(&["spawn", "--count", "2"]);
    assert!(spawned.contains(r#""outcome":"allowed""#), "{spawned}");
    let denied = probe(&["spawn", "--count", "65"]);
    assert!(denied.contains(r#""outcome":"denied""#), "{denied}");
}

#[test]
fn fs_read_of_a_temp_file_is_allowed() {
    let path = std::env::temp_dir().join("nsbx-probe-canary");
    std::fs::write(&path, b"token").expect("write");
    let line = probe(&["fs-read", path.to_str().expect("utf8")]);
    assert!(line.contains(r#""outcome":"allowed""#), "{line}");
    let _ = std::fs::remove_file(path);
}
