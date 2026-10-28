//! idmap helper. Writes the two-range uid/gid map for one child (design §5.2).
//!
//! `--serve` is the production path: systemd socket activation hands it the
//! listening socket, and its capability bounding set is only `CAP_SETUID` and
//! `CAP_SETGID`. `--map` remains for a root supervisor that has not been given
//! that socket.

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::ExitCode;

/// Host uid of namespace uid 1000 when the supervisor itself is host uid 0.
const ROOT_SUPERVISOR_WORKLOAD: u32 = 2_001_000;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--self-test") => match nsbx_sys::prove_slot_map() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("{err}");
                ExitCode::from(1)
            }
        },
        Some("--map") => map_cli(args),
        Some("--serve") => serve(),
        _ => {
            eprintln!(
                "usage: nsbx-idmap --self-test | --serve | --map PID NS0_HOST WORKLOAD_HOST PARENT"
            );
            ExitCode::from(2)
        }
    }
}

fn map_cli(mut args: impl Iterator<Item = String>) -> ExitCode {
    let usage = "usage: nsbx-idmap --map PID NS0_HOST WORKLOAD_HOST PARENT";
    let Some(pid) = args.next().and_then(|s| s.parse::<i32>().ok()) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    let Some(ns0_host) = args.next().and_then(|s| s.parse::<u32>().ok()) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    let Some(workload_host) = args.next().and_then(|s| s.parse::<u32>().ok()) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    let Some(parent) = args.next().and_then(|s| s.parse::<i32>().ok()) else {
        eprintln!("{usage}");
        return ExitCode::from(2);
    };
    match nsbx_sys::ppid(pid) {
        Ok(got) if got == parent => {}
        Ok(got) => {
            eprintln!("child parent {got} is not {parent}");
            return ExitCode::from(1);
        }
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    }
    match nsbx_sys::map_ranges(pid, ns0_host, workload_host) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn serve() -> ExitCode {
    let fd = match nsbx_sys::systemd_listen_fd() {
        Ok(fd) => fd,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    let listener = UnixListener::from(fd);
    loop {
        let mut stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => {
                eprintln!("accept: {err}");
                return ExitCode::from(1);
            }
        };
        if let Err(err) = one_map(&mut stream) {
            let _ = writeln!(stream, "err {err}");
        }
    }
}

fn one_map(stream: &mut UnixStream) -> Result<(), String> {
    let mut buf = [0u8; 128];
    let mut filled = 0;
    let line = loop {
        if filled == buf.len() {
            return Err("request too long".into());
        }
        let n = stream
            .read(&mut buf[filled..])
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("short request".into());
        }
        filled += n;
        if let Some(end) = buf[..filled].iter().position(|b| *b == b'\n') {
            let text = std::str::from_utf8(&buf[..end]).map_err(|_| "request is not utf-8")?;
            break text.to_string();
        }
    };
    let (pid, ns0, workload) = parse_request(&line)?;
    if pid <= 1 || Some(pid) == i32::try_from(std::process::id()).ok() {
        return Err("refusing that pid".into());
    }
    let (peer_pid, peer_uid, _) =
        nsbx_sys::peer_cred(stream.as_raw_fd()).map_err(|e| e.to_string())?;
    if peer_uid != ns0 {
        return Err(format!("peer uid {peer_uid} is not {ns0}"));
    }
    let peer = i32::try_from(peer_pid).map_err(|_| "peer pid does not fit".to_string())?;
    let parent = nsbx_sys::ppid(pid).map_err(|e| e.to_string())?;
    if parent != peer {
        return Err(format!("child parent {parent} is not peer {peer}"));
    }
    check_workload(ns0, workload)?;
    nsbx_sys::map_ranges(pid, ns0, workload).map_err(|e| e.to_string())?;
    stream.write_all(b"ok\n").map_err(|e| e.to_string())?;
    Ok(())
}

fn parse_request(line: &str) -> Result<(i32, u32, u32), String> {
    let mut parts = line.split_whitespace();
    let pid = parts
        .next()
        .ok_or("missing pid")?
        .parse::<i32>()
        .map_err(|_| "bad pid")?;
    let ns0 = parts
        .next()
        .ok_or("missing ns0")?
        .parse::<u32>()
        .map_err(|_| "bad ns0")?;
    let workload = parts
        .next()
        .ok_or("missing workload")?
        .parse::<u32>()
        .map_err(|_| "bad workload")?;
    if parts.next().is_some() {
        return Err("trailing fields".into());
    }
    Ok((pid, ns0, workload))
}

/// Namespace uid 1000 is the slot next to the supervisor, or the fixed
/// production slot when the supervisor is host uid 0.
fn check_workload(ns0: u32, workload: u32) -> Result<(), String> {
    let expected = if ns0 == 0 {
        ROOT_SUPERVISOR_WORKLOAD
    } else {
        ns0.checked_add(1000)
            .ok_or_else(|| "uid overflows".to_string())?
    };
    if workload != expected {
        return Err(format!("workload {workload} is not {expected}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_request_names_three_ids() {
        assert_eq!(
            parse_request("12 2000000 2001000").unwrap(),
            (12, 2_000_000, 2_001_000)
        );
        assert!(parse_request("12 2000000").is_err());
        assert!(parse_request("12 2000000 2001000 extra").is_err());
    }

    #[test]
    fn the_workload_is_one_thousand_above_the_supervisor() {
        assert!(check_workload(2_000_000, 2_001_000).is_ok());
        assert!(check_workload(0, 2_001_000).is_ok());
        assert!(check_workload(2_000_000, 2_000_000).is_err());
        assert!(check_workload(0, 1000).is_err());
    }
}
