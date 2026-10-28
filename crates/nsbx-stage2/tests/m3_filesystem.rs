//! M3 acceptance: mountinfo equals the expected set, and `python3 -c` runs.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::Command;

use nsbx_cgroup::{Layout, Limits};
use nsbx_sys::{
    CloneFlags, clone3, dup2, map_caller, open_opath, pipe, read_fd, stage2_exec, write_fd,
};

#[test]
fn mountinfo_matches_and_python_prints() {
    // The Nix build sandbox has no user systemd session to delegate a cgroup.
    if std::env::var_os("NIX_BUILD_TOP").is_some() {
        return;
    }
    if std::env::var_os("NSBX_DELEGATED").is_none() {
        let exe = std::env::current_exe().expect("test exe");
        let out = Command::new("systemd-run")
            .args([
                "--user",
                "--scope",
                "-p",
                "Delegate=yes",
                "--setenv=NSBX_DELEGATED=1",
                "--",
            ])
            .arg(exe)
            .args(std::env::args().skip(1))
            .output()
            .expect("systemd-run");
        if !out.status.success() {
            panic!(
                "delegated rerun failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        return;
    }

    let python = real_path("python3");
    let runtime = store_root(&python);
    let closure = store_closure(&python);
    let etc = std::env::temp_dir().join("nsbx-m3-etc");
    let _ = std::fs::remove_dir_all(&etc);
    std::fs::create_dir_all(&etc).expect("etc");
    std::fs::write(
        etc.join("passwd"),
        "root:x:0:0:root:/:/bin/false\nsandbox:x:1000:1000:sandbox:/workspace:/bin/false\n",
    )
    .expect("passwd");
    std::fs::write(etc.join("group"), "root:x:0:\nsandbox:x:1000:\n").expect("group");
    std::fs::write(etc.join("hosts"), "127.0.0.1 localhost\n").expect("hosts");
    std::fs::write(etc.join("resolv.conf"), "").expect("resolv");

    let mut spec = String::new();
    spec.push_str("runtime\n");
    spec.push_str(&runtime);
    spec.push('\n');
    spec.push_str("etc\n");
    spec.push_str(&etc.display().to_string());
    spec.push_str("\nargv\n3\n");
    spec.push_str(&python);
    spec.push_str("\n-c\nprint(1)\nclosure\n");
    spec.push_str(&closure.len().to_string());
    spec.push('\n');
    for path in &closure {
        spec.push_str(path);
        spec.push('\n');
    }

    let layout = Layout::establish().expect("cgroup");
    let job = layout
        .create_job(
            "m3-python",
            Limits {
                memory_max: 512 * 1024 * 1024,
                pids_max: 64,
                cpu_quota_us: None,
                cpu_period_us: None,
            },
        )
        .expect("job");
    let program = open_stage2();
    let (report_r, report_w) = pipe().expect("pipe");
    let (sync_r, sync_w) = pipe().expect("pipe");
    let (spec_r, spec_w) = pipe().expect("pipe");
    let (out_r, out_w) = pipe().expect("pipe");
    let (err_r, err_w) = pipe().expect("pipe");
    write_fd(spec_w.as_raw_fd(), spec.as_bytes()).expect("spec");
    drop(spec_w);

    let argv0 = CString::new("nsbx-stage2").expect("argv");
    let argv1 = CString::new("setup").expect("argv");
    let program_fd = program.as_raw_fd();
    let report = report_w.as_raw_fd();
    let sync = sync_r.as_raw_fd();
    let spec_fd = spec_r.as_raw_fd();
    let stdout = out_w.as_raw_fd();
    let stderr = err_w.as_raw_fd();
    let child = clone3(
        CloneFlags::SANDBOX,
        Some(job.as_fd().as_raw_fd()),
        move || {
            let _ = dup2(stdout, 1);
            let _ = dup2(stderr, 2);
            let err = stage2_exec(
                program_fd,
                &[argv0.as_c_str(), argv1.as_c_str()],
                report,
                sync,
                Some(spec_fd),
            );
            let _ = write_fd(2, err.to_string().as_bytes());
        },
    )
    .expect("clone");
    drop(report_w);
    drop(sync_r);
    drop(spec_r);
    drop(out_w);
    drop(err_w);
    drop(program);
    map_caller(child.pid).expect("map");
    write_fd(sync_w.as_raw_fd(), b"x").expect("sync");
    drop(sync_w);

    let waited = nsbx_sys::wait_pidfd(child.pidfd.as_raw_fd()).expect("wait");
    let report = read_to_end(report_r.as_raw_fd());
    let stdout = read_to_end(out_r.as_raw_fd());
    let stderr = read_to_end(err_r.as_raw_fd());
    let report_text = String::from_utf8_lossy(&report);
    let stdout_text = String::from_utf8_lossy(&stdout);
    let stderr_text = String::from_utf8_lossy(&stderr);
    assert!(
        waited.exited() && waited.exit_code() == Some(0),
        "exit {:?} stdout {stdout_text:?} stderr {stderr_text:?} report {report_text}",
        waited.exit_code()
    );
    assert_eq!(stdout_text, "1\n", "stderr {stderr_text}");
    assert!(
        !report_text.starts_with("ERR"),
        "{report_text}\nstderr {stderr_text}"
    );

    let got: BTreeSet<String> = report_text.lines().map(str::to_string).collect();
    let mut expected = BTreeSet::new();
    expected.insert("/".to_string());
    for path in &closure {
        expected.insert(path.clone());
    }
    for path in [
        "/dev",
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/random",
        "/dev/urandom",
        "/dev/shm",
        "/etc",
        "/proc",
        "/tmp",
        "/workspace",
    ] {
        expected.insert(path.to_string());
    }
    assert_eq!(got, expected, "mountinfo mismatch");
    job.remove().expect("rmdir");
}

fn real_path(bin: &str) -> String {
    let which = Command::new("which").arg(bin).output().expect("which");
    let path = String::from_utf8(which.stdout).expect("utf8");
    let path = path.trim();
    let real = Command::new("readlink")
        .args(["-f", path])
        .output()
        .expect("readlink");
    String::from_utf8(real.stdout)
        .expect("utf8")
        .trim()
        .to_string()
}

fn store_root(path: &str) -> String {
    let rest = path.strip_prefix("/nix/store/").expect("store path");
    let name = rest.split('/').next().expect("name");
    format!("/nix/store/{name}")
}

fn store_closure(path: &str) -> Vec<String> {
    let out = Command::new("nix-store")
        .args(["-qR", path])
        .output()
        .expect("nix-store");
    String::from_utf8(out.stdout)
        .expect("utf8")
        .lines()
        .map(str::to_string)
        .filter(|l| !l.is_empty())
        .collect()
}

fn open_stage2() -> OwnedFd {
    let path = CString::new(env!("CARGO_BIN_EXE_nsbx-stage2")).expect("path");
    open_opath(path.as_c_str()).expect("opath")
}

fn read_to_end(fd: i32) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = read_fd(fd, &mut tmp).expect("read");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    buf
}
