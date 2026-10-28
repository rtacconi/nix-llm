//! The nsbx/1 supervisor. It accepts one orchestrator connection, checks
//! `SO_PEERCRED`, and reads with `read(2)` so a passed file descriptor is
//! never installed.

fn main() {
    if let Err(err) = run() {
        eprintln!("nsbx-supervisor: {err}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    linux::run()
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<(), String> {
    Err("nsbx-supervisor requires Linux".into())
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod spawn;
