//! Linux server. One connection, one job, `read(2)` only.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nsbx_core::epoch::{Epoch, Ticket};
use nsbx_policy::bundle::PolicyBundle;
use nsbx_policy::narrow::Principal;
use nsbx_policy::profile::{Backend, ProcMode};
use nsbx_proto::frame::{self, FrameType, HEADER_LEN, MAX_FRAME_LEN};
use nsbx_proto::msg::{
    self, Accepted, ArtifactInfo, Cleanup, ErrorCategory, ErrorV1, Hello, HelloAck, Rejected,
    ResultV1, Started, Stream, Submit, TerminationReason,
};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use serde::Serialize;

use crate::spawn::{self, Sandbox};

const INITIAL_WINDOW: u64 = 16 * 1024;

struct Config {
    socket: Option<PathBuf>,
    policy: Option<PathBuf>,
    seccomp: Option<PathBuf>,
    principals: Option<PathBuf>,
    etc: Option<PathBuf>,
    runtimes: BTreeMap<String, String>,
    check: bool,
    strict: bool,
}

pub fn run() -> Result<(), String> {
    let cfg = parse(std::env::args().skip(1))?;
    let gaps = sysctl_gaps();
    if cfg.check {
        return finish_check(&gaps, cfg.strict);
    }
    if cfg.strict && !gaps.is_empty() {
        return Err(gaps.join("; "));
    }
    if !dev_mode() && !gaps.is_empty() {
        return Err(gaps.join("; "));
    }
    ensure_delegated()?;
    let socket = cfg.socket.ok_or("missing --socket")?;
    let policy = PolicyBundle::load_dir(cfg.policy.as_deref().ok_or("missing --policy")?)
        .map_err(|e| e.to_string())?;
    let seccomp = cfg.seccomp.ok_or("missing --seccomp")?;
    let principals = load_principals(cfg.principals.as_deref().ok_or("missing --principals")?)?;
    let etc = cfg.etc.ok_or("missing --etc")?;
    if cfg.runtimes.is_empty() {
        return Err("missing --runtime NAME=/nix/store/...".into());
    }
    for path in cfg.runtimes.values() {
        if !spawn::is_store_path(path) {
            return Err(format!("{path} is not a store path"));
        }
    }
    let layout = nsbx_cgroup::Layout::establish().map_err(|e| e.to_string())?;
    if socket.exists() {
        std::fs::remove_file(&socket).map_err(|e| e.to_string())?;
    }
    let listener =
        UnixListener::bind(&socket).map_err(|e| format!("bind {}: {e}", socket.display()))?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| e.to_string())?;
    let pid_path = socket.with_extension("pid");
    std::fs::write(&pid_path, std::process::id().to_string()).map_err(|e| e.to_string())?;
    eprintln!("nsbx-supervisor listening {}", socket.display());
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(stream) => stream,
            Err(err) => return Err(err.to_string()),
        };
        let fd = stream.as_raw_fd();
        let (_pid, uid, _gid) = nsbx_sys::peer_cred(fd).map_err(|e| e.to_string())?;
        let me = nsbx_sys::euid();
        if uid != me {
            eprintln!("rejected uid {uid}");
            drop(stream);
            continue;
        }
        stream.set_nonblocking(true).map_err(|e| e.to_string())?;
        if let Err(err) = serve(
            &stream,
            &policy,
            &seccomp,
            &principals,
            &etc,
            &cfg.runtimes,
            &layout,
        ) {
            eprintln!("connection: {err}");
        }
    }
    Ok(())
}

fn finish_check(gaps: &[String], strict: bool) -> Result<(), String> {
    if gaps.is_empty() {
        return Ok(());
    }
    if strict || !dev_mode() {
        return Err(gaps.join("; "));
    }
    println!("insecure_dev_mode");
    Ok(())
}

fn dev_mode() -> bool {
    cfg!(feature = "insecure-dev-mode")
}

fn ensure_delegated() -> Result<(), String> {
    if std::env::var_os("NSBX_DELEGATED").is_some() || std::env::var_os("NIX_BUILD_TOP").is_some() {
        return Ok(());
    }
    let me = std::env::current_exe().map_err(|e| e.to_string())?;
    let status = std::process::Command::new("systemd-run")
        .args([
            "--user",
            "--scope",
            "-p",
            "Delegate=yes",
            "--setenv=NSBX_DELEGATED=1",
            "--",
        ])
        .arg(me)
        .args(std::env::args().skip(1))
        .status()
        .map_err(|e| format!("systemd-run: {e}"))?;
    std::process::exit(status.code().unwrap_or(1));
}

fn serve(
    stream: &UnixStream,
    policy: &PolicyBundle,
    seccomp: &Path,
    principals: &BTreeMap<String, Principal>,
    etc: &Path,
    runtimes: &BTreeMap<String, String>,
    layout: &nsbx_cgroup::Layout,
) -> Result<(), String> {
    let fd = stream.as_raw_fd();
    let mut buf = Vec::new();
    let mut hello = false;
    let mut live: Option<Live> = None;
    let mut done: BTreeMap<String, (String, Vec<u8>)> = BTreeMap::new();
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(job) = live.as_mut() {
            pump(fd, job)?;
            if job.finished {
                let payload = job.result.clone();
                let id = job.id.clone();
                let hash = job.hash.clone();
                done.insert(id, (hash, payload.clone()));
                send_raw(fd, &payload)?;
            }
        }
        if live.as_ref().is_some_and(|job| job.finished) {
            if let Some(job) = live.take() {
                let _ = job.box_.job.wait_empty(Duration::from_secs(2));
                let _ = job.box_.job.remove();
            }
        }
        let mut polls = vec![PollFd::new(stream, PollFlags::IN)];
        // A running job also has to notice cancel grace and pipe readability.
        if live.is_some() {
            let timeout = Timespec {
                tv_sec: 0,
                tv_nsec: 50_000_000,
            };
            let _ = poll(&mut polls, Some(&timeout)).map_err(|e| e.to_string())?;
        }
        let n = match nsbx_sys::read_fd(fd, &mut tmp) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(err) if would_block(&err) => {
                if live.is_none() {
                    let _ = poll(&mut polls, None).map_err(|e| e.to_string())?;
                }
                continue;
            }
            Err(err) => return Err(err.to_string()),
        };
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > HEADER_LEN + MAX_FRAME_LEN as usize {
            send_error(fd, "frame exceeds 65536 bytes")?;
            return Ok(());
        }
        loop {
            let decoded = frame::decode(&buf).map_err(|e| e.to_string())?;
            let Some((frame, used)) = decoded else { break };
            let ty = frame.ty;
            let payload = frame.payload.to_vec();
            buf.drain(..used);
            if !hello && ty != FrameType::Hello {
                send_error(fd, "Hello must be the first frame")?;
                return Ok(());
            }
            match ty {
                FrameType::Hello => {
                    let hello_msg: Hello =
                        serde_json::from_slice(&payload).map_err(|e| e.to_string())?;
                    if !hello_msg.proto.contains(&msg::PROTOCOL_VERSION) {
                        send_error(fd, "unsupported protocol")?;
                        return Ok(());
                    }
                    let ack = HelloAck {
                        proto: msg::PROTOCOL_VERSION,
                        supervisor: "nsbx-supervisor/0.1".into(),
                        features: serde_json::Map::new(),
                        profiles: policy.names().map(str::to_string).collect(),
                    };
                    send_json(fd, FrameType::HelloAck, &ack)?;
                    hello = true;
                }
                FrameType::Submit => {
                    if live.is_some() {
                        send_error(fd, "a job is already running")?;
                        return Ok(());
                    }
                    let submit: Submit =
                        serde_json::from_slice(&payload).map_err(|e| e.to_string())?;
                    if let Some((hash, exited)) = done.get(&submit.job_id.to_string()) {
                        if hash == &submit.request_hash {
                            send_raw(fd, exited)?;
                            continue;
                        }
                        send_error(fd, "job_id was already used with a different request")?;
                        return Ok(());
                    }
                    let host = Host {
                        policy,
                        seccomp,
                        principals,
                        etc,
                        runtimes,
                        layout,
                    };
                    live = Some(start_job(fd, &submit, &host)?);
                }
                FrameType::Credit => {
                    let credit = msg::Credit::parse(&payload).map_err(|e| e.to_string())?;
                    if let Some(job) = live.as_mut()
                        && job.id == credit.job_id.to_string()
                    {
                        job.credit = job.credit.saturating_add(u64::from(credit.bytes));
                    }
                }
                FrameType::Cancel => {
                    let cancel: msg::Cancel =
                        serde_json::from_slice(&payload).map_err(|e| e.to_string())?;
                    if let Some(job) = live.as_mut()
                        && job.id == cancel.job_id.to_string()
                    {
                        job.epoch.bump();
                        job.cancel = Some(
                            Instant::now() + Duration::from_millis(u64::from(cancel.grace_ms)),
                        );
                        let _ = nsbx_sys::pidfd_send_signal(job.box_.pidfd.as_fd(), 15);
                    }
                }
                FrameType::Ping => send_raw_type(fd, FrameType::Pong, &payload)?,
                _ => {
                    send_error(fd, "unsupported frame")?;
                    return Ok(());
                }
            }
        }
    }
}

struct Live {
    id: String,
    hash: String,
    box_: Sandbox,
    credit: u64,
    seq: u64,
    stdout_bytes: u64,
    stderr_bytes: u64,
    started: Instant,
    wall_at: Instant,
    wall_hit: bool,
    epoch: Epoch,
    ticket: Ticket,
    cancel: Option<Instant>,
    sandbox_done: bool,
    out_open: bool,
    err_open: bool,
    report: Vec<u8>,
    finished: bool,
    result: Vec<u8>,
    runtime: String,
    truncated: bool,
    warden: std::os::fd::OwnedFd,
}

struct Host<'a> {
    policy: &'a PolicyBundle,
    seccomp: &'a Path,
    principals: &'a BTreeMap<String, Principal>,
    etc: &'a Path,
    runtimes: &'a BTreeMap<String, String>,
    layout: &'a nsbx_cgroup::Layout,
}

fn start_job(fd: i32, submit: &Submit, host: &Host<'_>) -> Result<Live, String> {
    let Host {
        policy,
        seccomp,
        principals,
        etc,
        runtimes,
        layout,
    } = host;
    let Some(principal) = principals.get(&submit.principal) else {
        reject(
            fd,
            submit,
            "unknown_principal",
            "principal",
            &submit.principal,
        )?;
        return Err("unknown principal".into());
    };
    if !submit.files.is_empty() || submit.stdin_b64.is_some() {
        reject(fd, submit, "input_unsupported", "files", "inline input")?;
        return Err("inline input is not implemented".into());
    }
    let principal_json = serde_json::to_string(principal).map_err(|e| e.to_string())?;
    let request_json = serde_json::to_string(&submit.request).map_err(|e| e.to_string())?;
    let effective = match policy.narrow_json(&principal_json, &request_json) {
        Ok(value) => value,
        Err(nsbx_policy::bundle::BundleError::Denied(denial)) => {
            let rejected = Rejected {
                job_id: submit.job_id,
                error: ErrorV1 {
                    category: ErrorCategory::Policy,
                    code: denial.code.into(),
                    message: denial.hint.clone(),
                    retryable: false,
                    field: Some(denial.field),
                    requested: denial.requested,
                    allowed: denial.allowed,
                    hint: Some(denial.hint),
                },
            };
            send_json(fd, FrameType::Rejected, &rejected)?;
            return Err(format!("denied {}", denial.code));
        }
        Err(err) => {
            send_error(fd, &err.to_string())?;
            return Err(err.to_string());
        }
    };
    let profile_name = effective["profile"].as_str().unwrap_or("");
    let profile = policy
        .get(profile_name)
        .ok_or_else(|| format!("unknown profile {profile_name}"))?;
    if profile.backend != Backend::Namespace {
        reject(fd, submit, "unsupported_feature", "backend", "microvm")?;
        return Err("microvm backend is not implemented".into());
    }
    if effective["network"].as_str() == Some("egress-proxy") {
        reject(fd, submit, "unsupported_feature", "network", "egress-proxy")?;
        return Err("egress proxy is not implemented".into());
    }
    let runtime = runtimes
        .get(profile_name)
        .ok_or_else(|| format!("no --runtime for {profile_name}"))?;
    let argv0 = effective["argv"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| "effective argv is empty".to_string())?;
    let bin = Path::new(runtime).join("bin").join(argv0);
    let real = std::fs::canonicalize(&bin).map_err(|e| format!("{}: {e}", bin.display()))?;
    let real_s = real
        .to_str()
        .ok_or_else(|| "executable path is not utf-8".to_string())?;
    let root = spawn::store_root(real_s)?;
    let closure = spawn::closure_of(&real)?;
    let mut argv = Vec::new();
    let Some(items) = effective["argv"].as_array() else {
        return Err("effective argv is not a list".into());
    };
    for (i, item) in items.iter().enumerate() {
        let text = item
            .as_str()
            .ok_or_else(|| format!("argv[{i}] is not a string"))?;
        if text.contains('\n') {
            return Err("argv contains a newline".into());
        }
        if i == 0 {
            argv.push(real_s.to_string());
        } else {
            argv.push(text.to_string());
        }
    }
    let memory = effective["limits"]["memory_bytes"]
        .as_u64()
        .unwrap_or(512 * 1024 * 1024);
    let wall_ms = effective["limits"]["wall_ms"].as_u64().unwrap_or(60_000);
    let output_cap = effective["limits"]["output_bytes"]
        .as_u64()
        .unwrap_or(1024 * 1024);
    let pids = effective["limits"]["pids"].as_u64().unwrap_or(64);
    let pids = u32::try_from(pids).unwrap_or(64);
    let mut spec = render_spec(
        &root,
        &etc.display().to_string(),
        &argv,
        &closure,
        &profile.seccomp,
        seccomp,
        profile.workspace_exec,
    );
    append_identity(&mut spec, &profile.collect_prefixes)?;
    if profile.proc == ProcMode::Full {
        spec.push_str("proc\nfull\nmemory_bytes\n");
        spec.push_str(&memory.to_string());
        spec.push('\n');
    }
    send_json(
        fd,
        FrameType::Accepted,
        &Accepted {
            job_id: submit.job_id,
            slot: 0,
        },
    )?;
    let started = Instant::now();
    let idmap = if dev_mode() {
        spawn::IdMap::Caller
    } else {
        spawn::IdMap::Slot { base: 2_000_000 }
    };
    let started_box = spawn::spawn(layout, "job", &spec, memory, pids.max(1), idmap)?;
    let warden = match crate::warden::spawn(
        started_box.stdout,
        started_box.stderr,
        started_box.status,
        output_cap,
    ) {
        Ok(warden) => warden,
        Err(err) => {
            let _ = started_box.job.kill();
            return Err(err);
        }
    };
    let sandbox = Sandbox {
        stdout: warden.stdout,
        stderr: warden.stderr,
        report: started_box.report,
        status: warden.status,
        pidfd: started_box.pidfd,
        job: started_box.job,
    };
    let setup_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    send_json(
        fd,
        FrameType::Started,
        &Started {
            job_id: submit.job_id,
            setup_us,
        },
    )?;
    let epoch = Epoch::new();
    let ticket = epoch.ticket();
    Ok(Live {
        id: submit.job_id.to_string(),
        hash: submit.request_hash.clone(),
        box_: sandbox,
        credit: INITIAL_WINDOW,
        seq: 0,
        stdout_bytes: 0,
        stderr_bytes: 0,
        started,
        wall_at: started + Duration::from_millis(wall_ms),
        wall_hit: false,
        epoch,
        ticket,
        cancel: None,
        sandbox_done: false,
        out_open: true,
        err_open: true,
        report: Vec::new(),
        finished: false,
        result: Vec::new(),
        runtime: root,
        truncated: false,
        warden: warden.pidfd,
    })
}

fn pump(sock: i32, job: &mut Live) -> Result<(), String> {
    if Instant::now() >= job.wall_at {
        job.wall_hit = true;
        let _ = job.box_.job.kill();
    }
    if let Some(deadline) = job.cancel
        && Instant::now() >= deadline
    {
        let _ = job.box_.job.kill();
    }
    let mut polls = Vec::new();
    if job.credit > 0 && job.out_open {
        polls.push(PollFd::new(&job.box_.stdout, PollFlags::IN));
    }
    if job.credit > 0 && job.err_open {
        polls.push(PollFd::new(&job.box_.stderr, PollFlags::IN));
    }
    polls.push(PollFd::new(&job.box_.report, PollFlags::IN));
    polls.push(PollFd::new(&job.box_.pidfd, PollFlags::IN));
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let _ = poll(&mut polls, Some(&timeout)).map_err(|e| e.to_string())?;
    let ready_flags: Vec<bool> = polls.iter().map(ready).collect();
    drop(polls);
    let mut index = 0;
    if job.credit > 0 && job.out_open {
        if ready_flags[index] {
            job.out_open = drain(sock, job, true)?;
        }
        index += 1;
    }
    if job.credit > 0 && job.err_open {
        if ready_flags[index] {
            job.err_open = drain(sock, job, false)?;
        }
        index += 1;
    }
    if ready_flags[index] {
        let _ = read_some(job.box_.report.as_raw_fd(), &mut job.report)?;
    }
    index += 1;
    if ready_flags[index] {
        job.sandbox_done = true;
    }
    if job.sandbox_done && !job.out_open && !job.err_open && !job.finished {
        finish(sock, job)?;
    }
    Ok(())
}

fn ready(fd: &PollFd<'_>) -> bool {
    let flags = fd.revents();
    flags.contains(PollFlags::IN)
        || flags.contains(PollFlags::HUP)
        || flags.contains(PollFlags::ERR)
}

fn drain(sock: i32, job: &mut Live, stdout: bool) -> Result<bool, String> {
    let fd = if stdout {
        job.box_.stdout.as_raw_fd()
    } else {
        job.box_.stderr.as_raw_fd()
    };
    let mut buf = [0u8; 4096];
    loop {
        if job.credit == 0 {
            job.truncated = true;
            return Ok(true);
        }
        let want = usize::try_from(job.credit.min(buf.len() as u64)).unwrap_or(buf.len());
        match nsbx_sys::read_fd(fd, &mut buf[..want]) {
            Ok(0) => return Ok(false),
            Ok(n) => {
                if job.epoch.check(job.ticket).is_err() {
                    continue;
                }
                let stream = if stdout {
                    Stream::Stdout
                } else {
                    Stream::Stderr
                };
                send_output(sock, &job.id, stream, job.seq, &buf[..n])?;
                job.seq += 1;
                job.credit -= n as u64;
                if stdout {
                    job.stdout_bytes += n as u64;
                } else {
                    job.stderr_bytes += n as u64;
                }
            }
            Err(err) if would_block(&err) => return Ok(true),
            Err(err) => return Err(err.to_string()),
        }
    }
}

fn finish(sock: i32, job: &mut Live) -> Result<(), String> {
    let waited = nsbx_sys::wait_pidfd(job.box_.pidfd.as_raw_fd()).map_err(|e| e.to_string())?;
    let _ = nsbx_sys::wait_pidfd(job.warden.as_raw_fd());
    let mut status_buf = Vec::new();
    loop {
        let mut tmp = [0u8; 4096];
        match nsbx_sys::read_fd(job.box_.status.as_raw_fd(), &mut tmp) {
            Ok(0) => break,
            Ok(n) => status_buf.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
        if status_buf.len() > 1_048_576 {
            break;
        }
    }
    let artifacts = parse_artifacts(&status_buf);
    let _ = read_some(job.box_.report.as_raw_fd(), &mut job.report);
    let report = String::from_utf8_lossy(&job.report);
    let failure = setup_failure(&report);
    let (reason, exit_code) = termination(
        failure.is_some(),
        job.wall_hit,
        job.cancel.is_some(),
        waited.exit_code(),
    );
    let result = ResultV1 {
        job_id: job.id.parse().map_err(|_| "job id".to_string())?,
        reason,
        stage: failure,
        exit_code,
        signal: None,
        wall_ms: u64::try_from(job.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        cpu_user_us: 0,
        cpu_sys_us: 0,
        memory_peak_bytes: 0,
        oom_kills: 0,
        pids_limit_hits: 0,
        stdout_bytes: job.stdout_bytes,
        stderr_bytes: job.stderr_bytes,
        output_truncated: job.truncated,
        artifacts,
        cleanup: Cleanup::Ok,
        runtime: job.runtime.clone(),
        policy_hash: job.hash.clone(),
        insecure_dev_mode: dev_mode(),
    };
    let _ = sock;
    job.result = encode(
        FrameType::Exited,
        &serde_json::to_vec(&result).map_err(|e| e.to_string())?,
    )?;
    job.finished = true;
    let _ = job.box_.job.kill();
    Ok(())
}

/// The mount census is written before a later step can fail, so the error
/// line is not always the first line of the report.
fn setup_failure(report: &str) -> Option<String> {
    report
        .lines()
        .find(|line| line.starts_with("ERR "))
        .map(str::to_string)
}

fn termination(
    setup_failed: bool,
    wall: bool,
    cancel: bool,
    exit: Option<i32>,
) -> (TerminationReason, Option<i32>) {
    if setup_failed {
        (TerminationReason::SetupFailed, exit)
    } else if wall {
        (TerminationReason::WallTimeout, None)
    } else if cancel && exit.is_none() {
        (TerminationReason::Cancelled, None)
    } else if let Some(code) = exit {
        (TerminationReason::Exited, Some(code))
    } else {
        (TerminationReason::Signaled, None)
    }
}

fn render_spec(
    runtime: &str,
    etc: &str,
    argv: &[String],
    closure: &[String],
    seccomp_name: &str,
    policy: &Path,
    workspace_exec: bool,
) -> String {
    let mut spec = String::new();
    spec.push_str("runtime\n");
    spec.push_str(runtime);
    spec.push_str("\netc\n");
    spec.push_str(etc);
    spec.push_str("\nargv\n");
    spec.push_str(&argv.len().to_string());
    spec.push('\n');
    for arg in argv {
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
    spec.push_str(seccomp_name);
    spec.push_str("\npolicy\n");
    spec.push_str(&policy.display().to_string());
    spec.push_str("\nworkspace_exec\n");
    spec.push_str(if workspace_exec { "true\n" } else { "false\n" });
    spec
}

fn append_identity(
    spec: &mut String,
    prefixes: &[nsbx_policy::path::RelPath],
) -> Result<(), String> {
    spec.push_str("identity\n");
    spec.push_str(if dev_mode() { "dev\n" } else { "production\n" });
    spec.push_str("collect\n");
    spec.push_str(&prefixes.len().to_string());
    spec.push('\n');
    for prefix in prefixes {
        let text = prefix.to_string();
        if text.contains('\n') {
            return Err("collect prefix contains a newline".into());
        }
        spec.push_str(&text);
        spec.push('\n');
    }
    Ok(())
}

fn parse_artifacts(buf: &[u8]) -> Vec<ArtifactInfo> {
    let text = String::from_utf8_lossy(buf);
    let Some(line) = text.lines().next() else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return Vec::new();
    };
    let Some(list) = value.get("artifacts").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in list {
        let Some(path) = item.get("path").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(size) = item.get("size").and_then(|v| v.as_u64()) else {
            continue;
        };
        let Some(sha) = item.get("sha256").and_then(|v| v.as_str()) else {
            continue;
        };
        if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let risk = item
            .get("host_executable_risk")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        out.push(ArtifactInfo {
            path: path.to_string(),
            size,
            sha256: sha.to_string(),
            host_executable_risk: risk,
        });
    }
    out
}

fn reject(
    fd: i32,
    submit: &Submit,
    code: &str,
    field: &str,
    requested: &str,
) -> Result<(), String> {
    let rejected = Rejected {
        job_id: submit.job_id,
        error: ErrorV1 {
            category: ErrorCategory::Policy,
            code: code.into(),
            message: code.into(),
            retryable: false,
            field: Some(field.into()),
            requested: Some(requested.into()),
            allowed: None,
            hint: None,
        },
    };
    send_json(fd, FrameType::Rejected, &rejected)
}

fn send_output(fd: i32, id: &str, stream: Stream, seq: u64, data: &[u8]) -> Result<(), String> {
    let job_id = id.parse().map_err(|_| "job id".to_string())?;
    let mut payload = Vec::new();
    msg::Output {
        job_id,
        stream,
        seq,
        data,
    }
    .write(&mut payload);
    send_raw_type(fd, FrameType::Output, &payload)
}

fn send_json(fd: i32, ty: FrameType, value: &impl Serialize) -> Result<(), String> {
    let payload = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    send_raw_type(fd, ty, &payload)
}

fn send_error(fd: i32, message: &str) -> Result<(), String> {
    let payload =
        serde_json::to_vec(&serde_json::json!({"message": message})).map_err(|e| e.to_string())?;
    send_raw_type(fd, FrameType::Error, &payload)
}

fn send_raw(fd: i32, bytes: &[u8]) -> Result<(), String> {
    write_all(fd, bytes)
}

fn send_raw_type(fd: i32, ty: FrameType, payload: &[u8]) -> Result<(), String> {
    send_raw(fd, &encode(ty, payload)?)
}

fn encode(ty: FrameType, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    frame::encode(ty, payload, &mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
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

fn read_some(fd: i32, out: &mut Vec<u8>) -> Result<bool, String> {
    let mut tmp = [0u8; 4096];
    match nsbx_sys::read_fd(fd, &mut tmp) {
        Ok(0) => Ok(false),
        Ok(n) => {
            out.extend_from_slice(&tmp[..n]);
            Ok(true)
        }
        Err(err) if would_block(&err) => Ok(true),
        Err(err) => Err(err.to_string()),
    }
}

fn would_block(err: &nsbx_sys::Error) -> bool {
    match err {
        nsbx_sys::Error::Errno { source, .. } => source.kind() == ErrorKind::WouldBlock,
        nsbx_sys::Error::Unsupported(_) => false,
    }
}

fn load_principals(path: &Path) -> Result<BTreeMap<String, Principal>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let list: Vec<Principal> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let mut out = BTreeMap::new();
    for principal in list {
        if out.insert(principal.id.clone(), principal).is_some() {
            return Err("duplicate principal id".into());
        }
    }
    Ok(out)
}

fn parse(args: impl Iterator<Item = String>) -> Result<Config, String> {
    let args: Vec<String> = args.collect();
    let mut cfg = Config {
        socket: None,
        policy: None,
        seccomp: None,
        principals: None,
        etc: None,
        runtimes: BTreeMap::new(),
        check: false,
        strict: false,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let next = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value"))
        };
        match arg {
            "--check" => cfg.check = true,
            "--strict" => cfg.strict = true,
            "--socket" => cfg.socket = Some(PathBuf::from(next(&mut i)?)),
            "--policy" => cfg.policy = Some(PathBuf::from(next(&mut i)?)),
            "--seccomp" => cfg.seccomp = Some(PathBuf::from(next(&mut i)?)),
            "--principals" => cfg.principals = Some(PathBuf::from(next(&mut i)?)),
            "--etc" => cfg.etc = Some(PathBuf::from(next(&mut i)?)),
            "--runtime" => {
                let value = next(&mut i)?;
                let (name, path) = value
                    .split_once('=')
                    .ok_or("runtime must be NAME=/nix/store/...")?;
                cfg.runtimes.insert(name.to_string(), path.to_string());
            }
            "--help" => {
                println!(
                    "nsbx-supervisor --socket PATH --policy DIR --seccomp DIR --principals FILE --etc DIR --runtime NAME=STORE [--check] [--strict]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }
    Ok(cfg)
}

/// Host sysctls from design §4. Empty means strict mode may start.
fn sysctl_gaps() -> Vec<String> {
    let mut gaps = Vec::new();
    let eq = |path, want: i64, gaps: &mut Vec<String>| match read_sysctl(path) {
        Ok(got) if got == want => {}
        Ok(got) => gaps.push(format!("{path} is {got}, want {want}")),
        Err(err) => gaps.push(format!("{path}: {err}")),
    };
    let ge = |path, min: i64, gaps: &mut Vec<String>| match read_sysctl(path) {
        Ok(got) if got >= min => {}
        Ok(got) => gaps.push(format!("{path} is {got}, want >= {min}")),
        Err(err) => gaps.push(format!("{path}: {err}")),
    };
    ge("/proc/sys/kernel/unprivileged_bpf_disabled", 1, &mut gaps);
    ge("/proc/sys/kernel/perf_event_paranoid", 2, &mut gaps);
    eq("/proc/sys/kernel/io_uring_disabled", 2, &mut gaps);
    eq("/proc/sys/vm/unprivileged_userfaultfd", 0, &mut gaps);
    eq("/proc/sys/fs/protected_symlinks", 1, &mut gaps);
    eq("/proc/sys/fs/protected_hardlinks", 1, &mut gaps);
    gaps
}

fn read_sysctl(path: &str) -> Result<i64, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    text.trim()
        .parse()
        .map_err(|_| format!("not an integer: {text}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wall_timeout_outranks_a_signal() {
        let (reason, code) = termination(false, true, true, None);
        assert_eq!(reason, TerminationReason::WallTimeout);
        assert_eq!(code, None);
    }

    #[test]
    fn an_error_after_the_mount_census_is_setup_failure() {
        let report = "/\n/tmp\nERR chown: Operation not permitted (os error 1)\n";
        let failure = setup_failure(report);
        assert!(failure.is_some());
        let (reason, code) = termination(failure.is_some(), false, false, Some(99));
        assert_eq!(reason, TerminationReason::SetupFailed);
        assert_eq!(code, Some(99));
    }

    #[test]
    fn a_clean_exit_stays_exited() {
        let (reason, code) = termination(false, false, false, Some(0));
        assert_eq!(reason, TerminationReason::Exited);
        assert_eq!(code, Some(0));
    }
}
