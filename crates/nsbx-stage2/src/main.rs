//! Stage 2. `hold` is the M2 census. `setup` builds the filesystem and execs.

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
    let restricted = match pivoted.apply_baseline() {
        Ok(restricted) => restricted,
        Err(err) => fail(&err.to_string()),
    };
    let mut report = String::new();
    for point in &points {
        report.push_str(point);
        report.push('\n');
    }
    let _ = nsbx_sys::write_fd(3, report.as_bytes());
    let env = [
        CString::new("PATH=/bin").expect("env"),
        CString::new("HOME=/tmp").expect("env"),
        CString::new("LANG=C").expect("env"),
    ];
    let err = restricted.exec_workload(&spec.argv, &env);
    fail(&err.to_string());
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
    Ok(Spec {
        runtime,
        etc,
        closure,
        argv,
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
