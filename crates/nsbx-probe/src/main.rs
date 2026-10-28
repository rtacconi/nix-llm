//! One JSON line per property. The sandbox tests assert on the line.

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(cmd) = args.next() else {
        return usage();
    };
    let result = match cmd.as_str() {
        "caps" => caps(),
        "fs-read" => fs("fs-read", &args.next()),
        "fs-write" => fs("fs-write", &args.next()),
        "meminfo" => meminfo(),
        "cpuinfo" => cpuinfo(),
        "spawn" => spawn(&mut args),
        "net-connect" => connect(args.next().as_deref()),
        _ => return usage(),
    };
    match result {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            let _ = writeln!(std::io::stderr(), "{err}");
            ExitCode::from(1)
        }
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: nsbx-probe caps|fs-read PATH|fs-write PATH|meminfo|cpuinfo|spawn --count N|net-connect ADDR"
    );
    ExitCode::from(2)
}

fn line(probe: &str, outcome: &str, extra: &str) -> String {
    if extra.is_empty() {
        format!(r#"{{"probe":"{probe}","outcome":"{outcome}"}}"#)
    } else {
        format!(r#"{{"probe":"{probe}","outcome":"{outcome}",{extra}}}"#)
    }
}

fn caps() -> Result<String, String> {
    let text = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
    let mut fields = Vec::new();
    for key in ["CapEff", "NoNewPrivs", "Seccomp"] {
        let value = text
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{key}:")))
            .map(str::trim)
            .ok_or_else(|| format!("missing {key}"))?;
        fields.push(format!(r#""{key}":"{value}""#));
    }
    Ok(line("caps", "reported", &fields.join(",")))
}

fn fs(probe: &str, path: &Option<String>) -> Result<String, String> {
    let Some(path) = path else {
        return Err("missing path".into());
    };
    let result = if probe == "fs-write" {
        std::fs::write(path, b"x").map(|_| ())
    } else {
        std::fs::read(path).map(|_| ())
    };
    match result {
        Ok(()) => Ok(line(probe, "allowed", "")),
        Err(err) => {
            let errno = err.raw_os_error().unwrap_or(0);
            Ok(line(probe, "denied", &format!(r#""errno":{errno}"#)))
        }
    }
}

fn meminfo() -> Result<String, String> {
    let text = std::fs::read_to_string("/proc/meminfo").map_err(|e| e.to_string())?;
    let total = text
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .map(str::trim)
        .ok_or_else(|| "MemTotal missing".to_string())?;
    Ok(line(
        "meminfo",
        "reported",
        &format!(r#""mem_total":"{total}""#),
    ))
}

fn cpuinfo() -> Result<String, String> {
    let text = std::fs::read_to_string("/proc/cpuinfo").map_err(|e| e.to_string())?;
    let model = text
        .lines()
        .find_map(|l| l.strip_prefix("model name"))
        .map(|l| l.trim_start_matches(':').trim())
        .unwrap_or("absent");
    Ok(line(
        "cpuinfo",
        "reported",
        &format!(r#""model":"{model}""#),
    ))
}

fn spawn(args: &mut impl Iterator<Item = String>) -> Result<String, String> {
    if args.next().as_deref() != Some("--count") {
        return Err("usage: spawn --count N".into());
    }
    let Some(count) = args.next() else {
        return Err("usage: spawn --count N".into());
    };
    let n: u32 = count
        .parse()
        .map_err(|_| "count is not a number".to_string())?;
    if n > 64 {
        return Ok(line("spawn", "denied", r#""errno":"count""#));
    }
    for _ in 0..n {
        std::thread::scope(|scope| {
            scope.spawn(|| {});
        });
    }
    Ok(line("spawn", "allowed", &format!(r#""count":{n}"#)))
}

fn connect(addr: Option<&str>) -> Result<String, String> {
    let Some(addr) = addr else {
        return Err("missing address".into());
    };
    match std::net::TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|_| format!("{addr} is not host:port"))?,
        std::time::Duration::from_millis(200),
    ) {
        Ok(_) => Ok(line("net-connect", "connected", "")),
        Err(err) => {
            let errno = err.raw_os_error().unwrap_or(0);
            Ok(line(
                "net-connect",
                "denied",
                &format!(r#""errno":{errno}"#),
            ))
        }
    }
}
