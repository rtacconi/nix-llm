//! idmap helper. Writes the two-range uid/gid map for one child (design §5.2).

use std::process::ExitCode;

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
        Some("--map") => {
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
        _ => {
            eprintln!("usage: nsbx-idmap --self-test | --map PID NS0_HOST WORKLOAD_HOST PARENT");
            ExitCode::from(2)
        }
    }
}
