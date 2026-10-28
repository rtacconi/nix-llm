//! Profile enforcement: capability sets are empty, Landlock is on, and every
//! profile's kill list is enforced. The benign twin is `python3 -c`.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::Command;

use nsbx_cgroup::{Layout, Limits};
use nsbx_policy::bpf::{load_sources, syscall_number};
use nsbx_policy::seccomp::resolve;
use nsbx_sys::{
    CloneFlags, clone3, dup2, map_caller, open_opath, pipe, read_fd, stage2_exec, write_fd,
};

const POLICY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../policy/seccomp");

#[test]
fn caps_are_clear_landlock_holds_and_python_runs() {
    if skip_or_delegate() {
        return;
    }
    let python = real_path("python3");
    let runtime = store_root(&python);
    let closure = store_closure(&python);
    let etc = std::env::temp_dir().join("nsbx-m4-etc");
    let _ = std::fs::remove_dir_all(&etc);
    std::fs::create_dir_all(&etc).expect("etc");
    std::fs::write(etc.join("passwd"), "root:x:0:0:root:/:/bin/false\n").expect("passwd");
    let script = r#"exec("s=open('/proc/self/status').read().splitlines()\ndef g(k):\n return next(l.split(':',1)[1].strip() for l in s if l.startswith(k+':'))\nw='ok'\ntry:\n open('/workspace/note','w').write('ok')\nexcept OSError as e:\n w=str(e.errno)\nd='wrote'\ntry:\n open('/etc/nsbx-note','w').write('no')\nexcept OSError as e:\n d=str(e.errno)\nprint(g('CapEff'),g('CapPrm'),g('CapBnd'),g('CapInh'),g('CapAmb'),g('NoNewPrivs'),g('Seccomp'),w,d)")"#;
    let got = run(&python, &runtime, &closure, &etc, "python", &[script]);
    assert!(
        got.exit == Some(0),
        "exit {:?} stdout {:?} stderr {:?} report {}",
        got.exit,
        got.stdout,
        got.stderr,
        got.report
    );
    let fields: Vec<&str> = got.stdout.split_whitespace().collect();
    assert_eq!(fields.len(), 9, "{:?}", got.stdout);
    for cap in &fields[..5] {
        assert!(cap.chars().all(|c| c == '0'), "{cap}");
    }
    assert_eq!(fields[5], "1");
    assert_eq!(fields[6], "2");
    assert_eq!(fields[7], "ok");
    assert_ne!(fields[8], "wrote");
    assert!(!etc.join("nsbx-note").exists());
}

#[test]
fn kill_list_holds_for_every_profile() {
    if skip_or_delegate() {
        return;
    }
    let python = real_path("python3");
    let runtime = store_root(&python);
    let closure = store_closure(&python);
    let etc = std::env::temp_dir().join("nsbx-m4-kill-etc");
    let _ = std::fs::remove_dir_all(&etc);
    std::fs::create_dir_all(&etc).expect("etc");
    std::fs::write(etc.join("passwd"), "root:x:0:0:root:/:/bin/false\n").expect("passwd");
    let sources = load_sources(std::path::Path::new(POLICY)).expect("sources");
    let script = "import ctypes,sys; libc=ctypes.CDLL(None,use_errno=True); rc=libc.syscall(int(sys.argv[1]),0,0,0,0,0,0); print(ctypes.get_errno())";
    // Positive control: the same call outside the sandbox returns, it is not killed.
    let host = Command::new(&python)
        .arg("-c")
        .arg(script)
        .arg(syscall_number("bpf").expect("bpf").to_string())
        .output()
        .expect("host");
    assert!(host.status.success(), "positive control died: {host:?}");

    for profile in ["python", "cli", "node"] {
        let resolved = resolve(profile, &sources).expect(profile);
        let benign = run(&python, &runtime, &closure, &etc, profile, &["print(1)"]);
        assert_eq!(
            benign.exit,
            Some(0),
            "{profile} benign twin failed stdout {:?} stderr {} report {}",
            benign.stdout,
            benign.stderr,
            benign.report
        );
        for name in &resolved.kill {
            let nr = syscall_number(name).unwrap_or_else(|| panic!("{name} has no number"));
            let got = run(
                &python,
                &runtime,
                &closure,
                &etc,
                profile,
                &[script, &nr.to_string()],
            );
            assert!(
                got.exit.is_none(),
                "{profile} {name} was not killed: exit {:?} stdout {:?} stderr {:?} report {}",
                got.exit,
                got.stdout,
                got.stderr,
                got.report
            );
        }
        for name in &resolved.enosys {
            let nr = syscall_number(name).unwrap_or_else(|| panic!("{name} has no number"));
            let got = run(
                &python,
                &runtime,
                &closure,
                &etc,
                profile,
                &[script, &nr.to_string()],
            );
            assert_eq!(got.exit, Some(0), "{profile} {name} stderr {}", got.stderr);
            assert_eq!(got.stdout.trim(), "38", "{profile} {name} {}", got.stdout);
        }
    }
}

static NEXT_JOB: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

struct Out {
    exit: Option<i32>,
    stdout: String,
    stderr: String,
    report: String,
}

fn run(
    python: &str,
    runtime: &str,
    closure: &[String],
    etc: &std::path::Path,
    profile: &str,
    code_and_args: &[&str],
) -> Out {
    // MS_PRIVATE inside a fresh user namespace sometimes returns EPERM. A later
    // identical sandbox succeeds. A filter miss still fails the assertion.
    let mut last = run_once(python, runtime, closure, etc, profile, code_and_args);
    for _ in 0..2 {
        if last.exit == Some(99) && last.report.contains("MS_PRIVATE") {
            last = run_once(python, runtime, closure, etc, profile, code_and_args);
        }
    }
    last
}

fn run_once(
    python: &str,
    runtime: &str,
    closure: &[String],
    etc: &std::path::Path,
    profile: &str,
    code_and_args: &[&str],
) -> Out {
    let mut spec = String::new();
    spec.push_str("runtime\n");
    spec.push_str(runtime);
    spec.push_str("\netc\n");
    spec.push_str(&etc.display().to_string());
    spec.push_str("\nargv\n");
    spec.push_str(&(2 + code_and_args.len()).to_string());
    spec.push('\n');
    spec.push_str(python);
    spec.push_str("\n-c\n");
    for arg in code_and_args {
        spec.push_str(arg);
        spec.push('\n');
    }
    spec.push_str("closure\n");
    spec.push_str(&closure.len().to_string());
    spec.push('\n');
    for path in closure {
        spec.push_str(path);
        spec.push('\n');
    }
    spec.push_str("profile\n");
    spec.push_str(profile);
    spec.push_str("\npolicy\n");
    spec.push_str(POLICY);
    spec.push_str("\nworkspace_exec\nfalse\n");

    let layout = Layout::establish().expect("cgroup");
    let seq = NEXT_JOB.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let job = layout
        .create_job(
            &format!("m4-{seq}"),
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
    let waited = nsbx_sys::wait_pidfd(child.pidfd.as_raw_fd());
    let stdout = String::from_utf8_lossy(&read_to_end(out_r.as_raw_fd())).into_owned();
    let stderr = String::from_utf8_lossy(&read_to_end(err_r.as_raw_fd())).into_owned();
    let report = String::from_utf8_lossy(&read_to_end(report_r.as_raw_fd())).into_owned();
    let _ = job.remove();
    let exit = waited.ok().and_then(|w| w.exit_code());
    let _ = layout;
    Out {
        exit,
        stdout,
        stderr,
        report,
    }
}

fn skip_or_delegate() -> bool {
    if std::env::var_os("NIX_BUILD_TOP").is_some() {
        return true;
    }
    if std::env::var_os("NSBX_DELEGATED").is_none() {
        let exe = std::env::current_exe().expect("test exe");
        // Re-exec this test alone. Forwarding the whole binary's arguments
        // starts both tests in one scope and they fight over the cgroup.
        let name = std::thread::current()
            .name()
            .expect("test thread name")
            .to_string();
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
            .arg(&name)
            .args(["--exact", "--test-threads=1", "--nocapture"])
            .output()
            .expect("systemd-run");
        if !out.status.success() {
            panic!(
                "delegated rerun failed\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        return true;
    }
    false
}

fn real_path(bin: &str) -> String {
    let which = Command::new("which").arg(bin).output().expect("which");
    let path = String::from_utf8(which.stdout).expect("utf8");
    let real = Command::new("readlink")
        .args(["-f", path.trim()])
        .output()
        .expect("readlink");
    String::from_utf8(real.stdout)
        .expect("utf8")
        .trim()
        .to_string()
}

fn store_root(path: &str) -> String {
    let rest = path.strip_prefix("/nix/store/").expect("store");
    format!("/nix/store/{}", rest.split('/').next().expect("name"))
}

fn store_closure(path: &str) -> Vec<String> {
    let out = Command::new("nix-store")
        .args(["-qR", path])
        .output()
        .expect("nix-store");
    String::from_utf8(out.stdout)
        .expect("utf8")
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
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
