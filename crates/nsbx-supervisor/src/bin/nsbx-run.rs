//! One-shot nsbx/1 client. Prints the job's stdout and exits with its code.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use nsbx_proto::frame::{self, FrameType, MAX_FRAME_LEN};
use nsbx_proto::msg::{self, Cancel, Credit, Hello, ResultV1, Submit};
use uuid::Uuid;

fn main() {
    if let Err(err) = run() {
        eprintln!("nsbx-run: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut socket = None;
    let mut principal = None;
    let mut cancel_after = None;
    let mut argv = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => {
                i += 1;
                socket = Some(args.get(i).cloned().ok_or("missing --socket value")?);
            }
            "--principal" => {
                i += 1;
                principal = Some(args.get(i).cloned().ok_or("missing --principal value")?);
            }
            "--cancel-after" => {
                i += 1;
                let text = args.get(i).ok_or("missing --cancel-after value")?;
                let ms: u64 = text.parse().map_err(|_| "cancel-after is not a number")?;
                cancel_after = Some(ms);
            }
            "--" => {
                argv.extend(args[i + 1..].iter().cloned());
                break;
            }
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }
    let socket = socket.ok_or("missing --socket")?;
    let principal = principal.ok_or("missing --principal")?;
    if argv.is_empty() {
        return Err("missing argv after --".into());
    }
    let mut stream = UnixStream::connect(&socket).map_err(|e| format!("connect {socket}: {e}"))?;
    let first_wait = cancel_after.unwrap_or(120_000);
    stream
        .set_read_timeout(Some(Duration::from_millis(first_wait)))
        .map_err(|e| e.to_string())?;
    let hello = Hello {
        proto: vec![msg::PROTOCOL_VERSION],
        client: "nsbx-run".into(),
    };
    send(
        &mut stream,
        FrameType::Hello,
        &serde_json::to_vec(&hello).map_err(|e| e.to_string())?,
    )?;
    let job_id = job_id();
    match read_frame(&mut stream)? {
        (FrameType::HelloAck, _) => {}
        (other, payload) => {
            return Err(format!(
                "expected HelloAck, got {other:?} {}",
                show(&payload)
            ));
        }
    }
    let request = serde_json::json!({
        "profile": "python-compute",
        "argv": argv,
    });
    let submit = Submit {
        job_id,
        request_hash: "nsbx-run".into(),
        principal,
        request,
        files: Vec::new(),
        stdin_b64: None,
    };
    send(
        &mut stream,
        FrameType::Submit,
        &serde_json::to_vec(&submit).map_err(|e| e.to_string())?,
    )?;
    let mut credit = Vec::new();
    Credit {
        job_id,
        bytes: 65_536,
    }
    .write(&mut credit);
    send(&mut stream, FrameType::Credit, &credit)?;
    let mut cancelled = cancel_after.is_none();
    loop {
        let (ty, payload) = match read_frame(&mut stream) {
            Err(err) if err == "timeout" && !cancelled => {
                let cancel = Cancel {
                    job_id,
                    grace_ms: 0,
                };
                send(
                    &mut stream,
                    FrameType::Cancel,
                    &serde_json::to_vec(&cancel).map_err(|e| e.to_string())?,
                )?;
                cancelled = true;
                stream
                    .set_read_timeout(Some(Duration::from_secs(120)))
                    .map_err(|e| e.to_string())?;
                continue;
            }
            other => other?,
        };
        match ty {
            FrameType::Accepted | FrameType::Started | FrameType::PolicyEvent => {}
            FrameType::Output => {
                let output = msg::Output::parse(&payload).map_err(|e| e.to_string())?;
                let target: &mut dyn Write = if output.stream == msg::Stream::Stdout {
                    &mut std::io::stdout()
                } else {
                    &mut std::io::stderr()
                };
                target.write_all(output.data).map_err(|e| e.to_string())?;
            }
            FrameType::Rejected | FrameType::Error => {
                return Err(show(&payload));
            }
            FrameType::Exited => {
                let result: ResultV1 =
                    serde_json::from_slice(&payload).map_err(|e| e.to_string())?;
                let _ = std::io::stdout().flush();
                if let Some(stage) = &result.stage {
                    eprintln!("{stage}");
                }
                if !result.artifacts.is_empty() {
                    let line = serde_json::to_string(&result.artifacts).unwrap_or_default();
                    eprintln!("{line}");
                }
                let code = result.exit_code.unwrap_or(1);
                std::process::exit(code);
            }
            other => return Err(format!("unexpected frame {other:?}")),
        }
    }
}

fn job_id() -> Uuid {
    let mut bytes = [0u8; 16];
    let ticks = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    bytes[..8].copy_from_slice(&ticks.to_le_bytes()[..8]);
    bytes[8..12].copy_from_slice(&std::process::id().to_le_bytes());
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn send(stream: &mut UnixStream, ty: FrameType, payload: &[u8]) -> Result<(), String> {
    let mut out = Vec::new();
    frame::encode(ty, payload, &mut out).map_err(|e| e.to_string())?;
    stream.write_all(&out).map_err(|e| e.to_string())
}

fn read_frame(stream: &mut UnixStream) -> Result<(FrameType, Vec<u8>), String> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).map_err(|e| {
        if e.kind() == std::io::ErrorKind::TimedOut {
            "timeout".into()
        } else {
            format!("read: {e}")
        }
    })?;
    let len = u32::from_be_bytes(header);
    if len == 0 || len > MAX_FRAME_LEN {
        return Err("frame length".into());
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).map_err(|e| {
        if e.kind() == std::io::ErrorKind::TimedOut {
            "timeout".into()
        } else {
            format!("read: {e}")
        }
    })?;
    let ty = FrameType::from_u8(body[0]).ok_or_else(|| format!("unknown frame {}", body[0]))?;
    Ok((ty, body[1..].to_vec()))
}

fn show(payload: &[u8]) -> String {
    String::from_utf8_lossy(payload).trim().to_string()
}
