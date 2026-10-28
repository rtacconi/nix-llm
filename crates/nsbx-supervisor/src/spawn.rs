//! Start one stage-2 sandbox in a delegated job cgroup.

use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;

use nsbx_cgroup::{Job, Layout, Limits};

pub struct Sandbox {
    pub stdout: OwnedFd,
    pub stderr: OwnedFd,
    pub report: OwnedFd,
    pub pidfd: OwnedFd,
    pub job: Job,
}

pub fn spawn(
    layout: &Layout,
    name: &str,
    spec: &str,
    memory_max: u64,
    pids_max: u32,
) -> Result<Sandbox, String> {
    let job = layout
        .create_job(
            name,
            Limits {
                memory_max,
                pids_max,
                cpu_quota_us: None,
                cpu_period_us: None,
            },
        )
        .map_err(|e| e.to_string())?;
    let program = open_stage2()?;
    let (report_r, report_w) = nsbx_sys::pipe().map_err(|e| e.to_string())?;
    let (sync_r, sync_w) = nsbx_sys::pipe().map_err(|e| e.to_string())?;
    let (spec_r, spec_w) = nsbx_sys::pipe().map_err(|e| e.to_string())?;
    let (out_r, out_w) = nsbx_sys::pipe().map_err(|e| e.to_string())?;
    let (err_r, err_w) = nsbx_sys::pipe().map_err(|e| e.to_string())?;
    write_all(spec_w.as_raw_fd(), spec.as_bytes())?;
    drop(spec_w);
    let argv0 = CString::new("nsbx-stage2").map_err(|_| "nul".to_string())?;
    let argv1 = CString::new("setup").map_err(|_| "nul".to_string())?;
    let program_fd = program.as_raw_fd();
    let report = report_w.as_raw_fd();
    let sync = sync_r.as_raw_fd();
    let spec_fd = spec_r.as_raw_fd();
    let stdout = out_w.as_raw_fd();
    let stderr = err_w.as_raw_fd();
    let child = nsbx_sys::clone3(
        nsbx_sys::CloneFlags::SANDBOX,
        Some(job.as_fd().as_raw_fd()),
        move || {
            let _ = nsbx_sys::dup2(stdout, 1);
            let _ = nsbx_sys::dup2(stderr, 2);
            let err = nsbx_sys::stage2_exec(
                program_fd,
                &[argv0.as_c_str(), argv1.as_c_str()],
                report,
                sync,
                Some(spec_fd),
            );
            let _ = nsbx_sys::write_fd(2, err.to_string().as_bytes());
        },
    )
    .map_err(|e| e.to_string())?;
    drop(report_w);
    drop(sync_r);
    drop(spec_r);
    drop(out_w);
    drop(err_w);
    drop(program);
    if let Err(err) = nsbx_sys::map_caller(child.pid) {
        let _ = job.kill();
        return Err(err.to_string());
    }
    write_all(sync_w.as_raw_fd(), b"x")?;
    drop(sync_w);
    nonblock(&out_r)?;
    nonblock(&err_r)?;
    nonblock(&report_r)?;
    Ok(Sandbox {
        stdout: out_r,
        stderr: err_r,
        report: report_r,
        pidfd: child.pidfd,
        job,
    })
}

fn open_stage2() -> Result<OwnedFd, String> {
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let path = me
        .parent()
        .ok_or_else(|| "supervisor path has no parent".to_string())?
        .join("nsbx-stage2");
    if !path.exists() {
        return Err(format!(
            "stage2 is not next to the supervisor ({})",
            path.display()
        ));
    }
    let text = path
        .to_str()
        .ok_or_else(|| "stage2 path is not utf-8".to_string())?;
    let c = CString::new(text).map_err(|_| "nul in stage2 path".to_string())?;
    nsbx_sys::open_opath(&c).map_err(|e| e.to_string())
}

fn nonblock(fd: &OwnedFd) -> Result<(), String> {
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
    let flags = fcntl_getfl(fd).map_err(|e| e.to_string())?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(|e| e.to_string())
}

fn write_all(fd: i32, mut buf: &[u8]) -> Result<(), String> {
    while !buf.is_empty() {
        let n = nsbx_sys::write_fd(fd, buf).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("short write".into());
        }
        buf = &buf[n..];
    }
    Ok(())
}

pub fn closure_of(path: &Path) -> Result<Vec<String>, String> {
    let out = std::process::Command::new("nix-store")
        .args(["-qR"])
        .arg(path)
        .output()
        .map_err(|e| format!("nix-store: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "nix-store -qR failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    let text = String::from_utf8(out.stdout).map_err(|_| "closure is not utf-8".to_string())?;
    let paths: Vec<String> = text
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    if paths.is_empty() {
        return Err("empty closure".into());
    }
    Ok(paths)
}

pub fn store_root(path: &str) -> Result<String, String> {
    let rest = path
        .strip_prefix("/nix/store/")
        .ok_or_else(|| format!("{path} is not a store path"))?;
    let name = rest
        .split('/')
        .next()
        .ok_or_else(|| format!("{path} is not a store path"))?;
    let root = format!("/nix/store/{name}");
    if !is_store_path(&root) {
        return Err(format!("{root} is not a store path"));
    }
    Ok(root)
}

pub fn is_store_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/nix/store/") else {
        return false;
    };
    let Some((hash, name)) = rest.split_once('-') else {
        return false;
    };
    hash.len() == 32
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase())
        && !name.is_empty()
        && !name.contains('/')
}
