//! Forwards a job's stdout and stderr. Confined to inherited fds (design §11.1).

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("nsbx-warden requires Linux");
        return ExitCode::from(1);
    }
    #[cfg(target_os = "linux")]
    match linux::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;

    const STDOUT_IN: i32 = 4;
    const STDERR_IN: i32 = 5;
    const STDOUT_OUT: i32 = 6;
    const STDERR_OUT: i32 = 7;

    pub fn run() -> Result<(), String> {
        let cap: u64 = std::env::args()
            .nth(1)
            .ok_or_else(|| "usage: nsbx-warden CAP".to_string())?
            .parse()
            .map_err(|_| "cap is not a number".to_string())?;
        confine()?;
        let mut left = cap;
        let mut out_open = true;
        let mut err_open = true;
        while out_open || err_open {
            if out_open && nsbx_sys::poll_in(STDOUT_IN, 50).map_err(|e| e.to_string())? {
                out_open = copy(STDOUT_IN, STDOUT_OUT, &mut left)?;
            }
            if err_open && nsbx_sys::poll_in(STDERR_IN, 0).map_err(|e| e.to_string())? {
                err_open = copy(STDERR_IN, STDERR_OUT, &mut left)?;
            }
        }
        Ok(())
    }

    fn copy(from: i32, to: i32, left: &mut u64) -> Result<bool, String> {
        if *left == 0 {
            return Ok(false);
        }
        let mut buf = [0u8; 4096];
        let want = usize::try_from((*left).min(buf.len() as u64)).unwrap_or(buf.len());
        match nsbx_sys::read_fd(from, &mut buf[..want]) {
            Ok(0) => Ok(false),
            Ok(n) => {
                write_all(to, &buf[..n])?;
                *left = left.saturating_sub(n as u64);
                Ok(true)
            }
            Err(err)
                if err.raw_os_error() == Some(libc::EAGAIN)
                    || err.raw_os_error() == Some(libc::EWOULDBLOCK) =>
            {
                Ok(true)
            }
            Err(err) => Err(err.to_string()),
        }
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

    fn confine() -> Result<(), String> {
        empty_landlock()?;
        allow_forwarding()
    }

    fn empty_landlock() -> Result<(), String> {
        use landlock::{
            ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetStatus,
        };
        let detected = nsbx_sys::landlock_abi().map_err(|e| e.to_string())?;
        if detected < 3 {
            return Err(format!("landlock ABI {detected} is below 3"));
        }
        let abi = if detected >= 6 {
            ABI::V6
        } else if detected >= 5 {
            ABI::V5
        } else if detected >= 4 {
            ABI::V4
        } else {
            ABI::V3
        };
        let ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(abi))
            .map_err(|e| e.to_string())?
            .create()
            .map_err(|e| e.to_string())?;
        let status = ruleset.restrict_self().map_err(|e| e.to_string())?;
        if status.ruleset != RulesetStatus::FullyEnforced {
            return Err("warden landlock was not fully enforced".into());
        }
        Ok(())
    }

    fn allow_forwarding() -> Result<(), String> {
        let arch =
            seccompiler::TargetArch::try_from(std::env::consts::ARCH).map_err(|e| e.to_string())?;
        let mut rules = BTreeMap::new();
        for nr in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_close,
            libc::SYS_poll,
            libc::SYS_ppoll,
            libc::SYS_exit,
            libc::SYS_exit_group,
            libc::SYS_futex,
            libc::SYS_mmap,
            libc::SYS_munmap,
            libc::SYS_mprotect,
            libc::SYS_brk,
            libc::SYS_madvise,
            libc::SYS_rt_sigreturn,
            libc::SYS_rt_sigprocmask,
            libc::SYS_clock_gettime,
            libc::SYS_getrandom,
            libc::SYS_restart_syscall,
            libc::SYS_nanosleep,
            libc::SYS_getpid,
            libc::SYS_fcntl,
            libc::SYS_lseek,
        ] {
            rules.insert(nr, Vec::new());
        }
        let filter = seccompiler::SeccompFilter::new(
            rules,
            seccompiler::SeccompAction::Errno(libc::ENOSYS as u32),
            seccompiler::SeccompAction::Allow,
            arch,
        )
        .map_err(|e| e.to_string())?;
        let prog: seccompiler::BpfProgram = filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| e.to_string())?;
        let insns: Vec<nsbx_sys::FilterInsn> = prog
            .iter()
            .map(|insn| nsbx_sys::FilterInsn {
                code: insn.code,
                jt: insn.jt,
                jf: insn.jf,
                k: insn.k,
            })
            .collect();
        // NNP is already set by Landlock. Install with seccomp(2), not prctl.
        nsbx_sys::apply_seccomp_filter(&insns).map_err(|e| e.to_string())
    }
}
