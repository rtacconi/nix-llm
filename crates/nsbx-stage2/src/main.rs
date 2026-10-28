//! Stage 2. `hold` is the M2 census. `setup` builds the filesystem and execs.

mod collect;
mod setup;

use std::ffi::CString;

use setup::Spec;

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("setup") => setup_main(),
        Some("hold") => hold(),
        _ => hold(),
    }
}

fn hold() {
    if std::env::args().nth(1).as_deref() == Some("hold") {
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

fn setup_main() {
    let mut byte = [0u8; 1];
    let _ = nsbx_sys::read_fd(4, &mut byte);
    let spec = match read_spec() {
        Ok(spec) => spec,
        Err(err) => fail(&err),
    };
    // The policy files are on the host. Compile before the pivot hides them.
    let programs = match (&spec.profile, &spec.policy_dir) {
        (Some(profile), Some(dir)) => {
            let sources = match nsbx_policy::bpf::load_sources(std::path::Path::new(dir)) {
                Ok(sources) => sources,
                Err(err) => fail(&err.to_string()),
            };
            let resolved = match nsbx_policy::seccomp::resolve(profile, &sources) {
                Ok(resolved) => resolved,
                Err(err) => fail(&err.to_string()),
            };
            match nsbx_policy::bpf::compile(&resolved) {
                Ok(programs) => Some(programs),
                Err(err) => fail(&err.to_string()),
            }
        }
        _ => None,
    };
    let pivoted = match setup::begin().and_then(|private| private.mount_root(&spec)) {
        Ok(rooted) => match rooted.pivot() {
            Ok(pivoted) => pivoted,
            Err(err) => fail(&err.to_string()),
        },
        Err(err) => fail(&err.to_string()),
    };
    let points = match pivoted.mount_points() {
        Ok(points) => points,
        Err(err) => fail(&err.to_string()),
    };
    let mut report = String::new();
    for point in &points {
        report.push_str(point);
        report.push('\n');
    }
    let _ = nsbx_sys::write_fd(3, report.as_bytes());
    for prefix in &spec.collect {
        let path = format!("/workspace/{prefix}");
        if let Err(err) = std::fs::create_dir_all(&path) {
            fail(&err.to_string());
        }
    }
    if spec.production {
        let mut owned = vec![
            "/workspace".to_string(),
            "/tmp".to_string(),
            "/dev/shm".to_string(),
        ];
        for prefix in &spec.collect {
            owned.push(format!("/workspace/{prefix}"));
        }
        for path in owned {
            let c = CString::new(path).expect("path");
            if let Err(err) = nsbx_sys::chown_path(&c, 1000, 1000) {
                fail(&err.to_string());
            }
        }
    }
    let pid = match nsbx_sys::fork_process() {
        Ok(pid) => pid,
        Err(err) => fail(&err.to_string()),
    };
    if pid == 0 {
        let restricted = if let Some(programs) = programs {
            let dropped = match pivoted.drop_privileges(spec.production) {
                Ok(dropped) => dropped,
                Err(err) => fail(&err.to_string()),
            };
            let locked = match dropped.apply_landlock(&spec) {
                Ok(locked) => locked,
                Err(err) => fail(&err.to_string()),
            };
            match locked.apply_profile(&programs) {
                Ok(restricted) => restricted,
                Err(err) => fail(&err.to_string()),
            }
        } else {
            match pivoted.apply_baseline() {
                Ok(restricted) => restricted,
                Err(err) => fail(&err.to_string()),
            }
        };
        let env = [
            CString::new("PATH=/bin").expect("env"),
            CString::new("HOME=/tmp").expect("env"),
            CString::new("LANG=C").expect("env"),
        ];
        let err = restricted.exec_workload(&spec.argv, &env);
        fail(&err.to_string());
    }
    // The workload inherited stdout. Closing it here lets the pipe end when
    // the workload exits, while this process collects artefacts.
    let _ = nsbx_sys::close_range(1, 2);
    let waited = nsbx_sys::wait_child(pid).unwrap_or(nsbx_sys::ChildExit {
        code: None,
        signal: None,
    });
    let code = waited.code.unwrap_or(99);
    let items = collect::gather(&spec.collect);
    if let Ok(bytes) = nsbx_proto::status::encode(code, &items) {
        let _ = nsbx_sys::write_fd(8, &bytes);
    }
    if waited.signal.is_some() {
        let _ = nsbx_sys::die_by_seccomp();
    }
    std::process::exit(code);
}

fn fail(msg: &str) -> ! {
    let line = format!("ERR {msg}\n");
    let _ = nsbx_sys::write_fd(3, line.as_bytes());
    std::process::exit(99);
}

fn read_spec() -> Result<Spec, String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = nsbx_sys::read_fd(5, &mut tmp).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let text = String::from_utf8(buf).map_err(|_| "spec is not utf-8".to_string())?;
    parse_spec(&text)
}

fn parse_spec(text: &str) -> Result<Spec, String> {
    let mut lines = text.lines();
    let runtime = expect(&mut lines, "runtime")?;
    let etc = expect(&mut lines, "etc")?;
    let argv_n: usize = expect(&mut lines, "argv")?
        .parse()
        .map_err(|_| "argv count".to_string())?;
    let mut argv = Vec::with_capacity(argv_n);
    for _ in 0..argv_n {
        argv.push(CString::new(next_line(&mut lines)?).map_err(|_| "nul in argv".to_string())?);
    }
    let closure_n: usize = expect(&mut lines, "closure")?
        .parse()
        .map_err(|_| "closure count".to_string())?;
    let mut closure = Vec::with_capacity(closure_n);
    for _ in 0..closure_n {
        closure.push(next_line(&mut lines)?);
    }
    let mut profile = None;
    let mut policy_dir = None;
    let mut workspace_exec = false;
    let mut production = false;
    let mut collect = Vec::new();
    let mut proc_full = false;
    let mut memory_bytes = 0;
    if lines.next().is_some_and(|l| l == "profile") {
        profile = Some(next_line(&mut lines)?);
        if lines.next().is_some_and(|l| l == "policy") {
            policy_dir = Some(next_line(&mut lines)?);
        }
        if lines.next().is_some_and(|l| l == "workspace_exec") {
            workspace_exec = next_line(&mut lines)? == "true";
        }
        while let Some(label) = lines.next() {
            match label {
                "identity" => {
                    let value = next_line(&mut lines)?;
                    if value == "production" {
                        production = true;
                    } else if value != "dev" {
                        return Err("identity".into());
                    }
                }
                "collect" => {
                    let n: usize = next_line(&mut lines)?
                        .parse()
                        .map_err(|_| "collect count".to_string())?;
                    if n > 32 {
                        return Err("collect count".into());
                    }
                    for _ in 0..n {
                        collect.push(next_line(&mut lines)?);
                    }
                }
                "proc" => {
                    proc_full = next_line(&mut lines)? == "full";
                    if lines.next().is_some_and(|l| l == "memory_bytes") {
                        memory_bytes = next_line(&mut lines)?
                            .parse()
                            .map_err(|_| "memory_bytes".to_string())?;
                    }
                }
                other => return Err(format!("unexpected spec line {other}")),
            }
        }
    }
    Ok(Spec {
        runtime,
        etc,
        closure,
        argv,
        profile,
        policy_dir,
        workspace_exec,
        production,
        collect,
        proc_full,
        memory_bytes,
    })
}

fn expect(lines: &mut std::str::Lines<'_>, label: &str) -> Result<String, String> {
    let got = next_line(lines)?;
    if got != label {
        return Err(format!("expected {label}, got {got}"));
    }
    next_line(lines)
}

fn next_line(lines: &mut std::str::Lines<'_>) -> Result<String, String> {
    lines
        .next()
        .map(str::to_string)
        .ok_or_else(|| "truncated spec".to_string())
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
