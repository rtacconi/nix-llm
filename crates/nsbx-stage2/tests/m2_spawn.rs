//! M2 acceptance: the child is in the job cgroup before it runs, `cgroup.kill`
//! leaves that cgroup empty, and the fd census is the keep-list.

use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::Command;
use std::time::Duration;

use nsbx_cgroup::{Layout, Limits};
use nsbx_sys::{CloneFlags, clone3, map_caller, open_opath, pipe, read_fd, stage2_exec, write_fd};

#[test]
fn child_is_in_the_job_cgroup_and_kill_drains_it() {
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

    let layout = Layout::establish().expect("cgroup layout");
    let limits = Limits {
        memory_max: 128 * 1024 * 1024,
        pids_max: 32,
        cpu_quota_us: None,
        cpu_period_us: None,
    };

    let census = spawn(&layout, "m2-census", limits, true).expect("census spawn");
    assert!(
        census.fds.iter().all(|fd| *fd <= 4)
            || census.fds.iter().filter(|fd| **fd > 4).count() == 1,
        "fd census {:?}",
        census.fds
    );
    assert!(
        census.fds.contains(&3),
        "report fd missing: {:?}",
        census.fds
    );

    let killed = spawn(&layout, "m2-kill", limits, false).expect("kill spawn");
    assert!(
        killed.procs_at_start.contains(&killed.pid),
        "pid {} not in cgroup at start: {:?}",
        killed.pid,
        killed.procs_at_start
    );
    assert!(
        killed.procs_after_kill.is_empty(),
        "{:?}",
        killed.procs_after_kill
    );
}

struct Outcome {
    pid: i32,
    procs_at_start: Vec<i32>,
    procs_after_kill: Vec<i32>,
    fds: Vec<i32>,
}

fn spawn(layout: &Layout, name: &str, limits: Limits, release: bool) -> Result<Outcome, String> {
    let job = layout.create_job(name, limits).map_err(|e| e.to_string())?;
    let program = open_stage2()?;
    let (report_r, report_w) = pipe().map_err(|e| e.to_string())?;
    let (sync_r, sync_w) = pipe().map_err(|e| e.to_string())?;
    let argv0 = CString::new("nsbx-stage2").expect("argv");
    let argv1 = CString::new("hold").expect("argv");
    let report = report_w.as_raw_fd();
    let sync = sync_r.as_raw_fd();
    let program_fd = program.as_raw_fd();
    let child = clone3(
        CloneFlags::SANDBOX,
        Some(job.as_fd().as_raw_fd()),
        move || {
            let err = stage2_exec(
                program_fd,
                &[argv0.as_c_str(), argv1.as_c_str()],
                report,
                sync,
                None,
                None,
            );
            let _ = write_fd(2, err.to_string().as_bytes());
        },
    )
    .map_err(|e| e.to_string())?;
    // The pipe ends were copied into the child. Dropping the parent's copies
    // leaves the child's dup2 targets as the remaining owners.
    drop(report_w);
    drop(sync_r);
    drop(program);
    map_caller(child.pid).map_err(|e| e.to_string())?;
    let procs_at_start = job.procs().map_err(|e| e.to_string())?;
    let mut fds = Vec::new();
    if release {
        write_fd(sync_w.as_raw_fd(), b"x").map_err(|e| e.to_string())?;
        drop(sync_w);
        let mut buf = Vec::new();
        let mut tmp = [0u8; 256];
        loop {
            let n = read_fd(report_r.as_raw_fd(), &mut tmp).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        let text = String::from_utf8_lossy(&buf);
        fds = parse_fds(&text);
        nsbx_sys::wait_pidfd(child.pidfd.as_raw_fd()).map_err(|e| e.to_string())?;
        job.remove().map_err(|e| e.to_string())?;
        return Ok(Outcome {
            pid: child.pid,
            procs_at_start,
            procs_after_kill: Vec::new(),
            fds,
        });
    }
    job.kill().map_err(|e| e.to_string())?;
    nsbx_sys::wait_pidfd(child.pidfd.as_raw_fd()).map_err(|e| e.to_string())?;
    job.wait_empty(Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    let procs_after_kill = job.procs().map_err(|e| e.to_string())?;
    job.remove().map_err(|e| e.to_string())?;
    Ok(Outcome {
        pid: child.pid,
        procs_at_start,
        procs_after_kill,
        fds,
    })
}

fn open_stage2() -> Result<OwnedFd, String> {
    let path = CString::new(env!("CARGO_BIN_EXE_nsbx-stage2")).map_err(|e| e.to_string())?;
    open_opath(path.as_c_str()).map_err(|e| e.to_string())
}

fn parse_fds(text: &str) -> Vec<i32> {
    let Some(start) = text
        .find('[')
        .and_then(|i| text[i + 1..].find(']').map(|j| (i, i + 1 + j)))
    else {
        return Vec::new();
    };
    text[start.0 + 1..start.1]
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}
