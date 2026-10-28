//! Dirfd-based management of a delegated cgroup v2 subtree.
//!
//! The layout respects the no-internal-processes rule:
//!
//! ```text
//! delegated/
//! ├── supervisor/    this process
//! └── jobs/          subtree_control enabled, no processes of its own
//!     └── job-<id>/  limits written before any clone
//! ```

use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{AtFlags, Mode, OFlags};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{op}: {source}")]
    Io {
        op: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Message(String),
}

impl Error {
    fn io(op: &'static str, source: std::io::Error) -> Self {
        Self::Io { op, source }
    }
}

fn c_name(op: &'static str, name: &str) -> Result<CString, Error> {
    CString::new(name).map_err(|_| Error::Message(format!("{op}: name contains NUL")))
}

fn open_dir(parent: impl AsFd, name: &str) -> Result<OwnedFd, Error> {
    rustix::fs::openat(
        parent,
        c_name("open", name)?,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| Error::io("openat", e.into()))
}

fn read_at(dir: impl AsFd, name: &str) -> Result<String, Error> {
    let fd = rustix::fs::openat(
        dir,
        c_name("read", name)?,
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| Error::io("openat", e.into()))?;
    let mut file = File::from(fd);
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .map_err(|e| Error::io("read", e))?;
    Ok(buf)
}

fn write_at(dir: impl AsFd, name: &str, body: &str) -> Result<(), Error> {
    let fd = rustix::fs::openat(
        dir,
        c_name("write", name)?,
        OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| Error::io("openat", e.into()))?;
    let mut file = File::from(fd);
    file.write_all(body.as_bytes())
        .map_err(|e| Error::io("write", e))?;
    Ok(())
}

fn current_cgroup() -> Result<PathBuf, Error> {
    let text = std::fs::read_to_string("/proc/self/cgroup").map_err(|e| Error::io("cgroup", e))?;
    let line = text.lines().next().unwrap_or("");
    let path = line.split("::").nth(1).unwrap_or("");
    Ok(Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')))
}

/// The delegated subtree after this process has moved into `supervisor/`.
pub struct Layout {
    jobs: OwnedFd,
    jobs_path: PathBuf,
    controllers: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub memory_max: u64,
    pub pids_max: u32,
    pub cpu_quota_us: Option<u64>,
    pub cpu_period_us: Option<u64>,
}

impl Layout {
    /// Create `supervisor/` and `jobs/` under the current cgroup and move this
    /// process into `supervisor/` so `jobs/` can enable controllers.
    pub fn establish() -> Result<Self, Error> {
        let here = current_cgroup()?;
        if here.file_name().and_then(|s| s.to_str()) == Some("supervisor") {
            let root = here
                .parent()
                .ok_or_else(|| Error::Message("supervisor has no parent".into()))?;
            return Self::open_existing(root);
        }
        let root = rustix::fs::open(
            c_name("cgroup", &here.display().to_string())?,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| Error::io("open cgroup", e.into()))?;
        mkdir(&root, "supervisor")?;
        mkdir(&root, "jobs")?;
        let supervisor = open_dir(&root, "supervisor")?;
        let pid = std::process::id().to_string();
        write_at(&supervisor, "cgroup.procs", &pid)?;
        let available = read_at(&root, "cgroup.controllers")?;
        let mut enable = String::new();
        let mut controllers = BTreeSet::new();
        for name in ["memory", "pids", "cpu"] {
            if available.split_whitespace().any(|c| c == name) {
                enable.push('+');
                enable.push_str(name);
                enable.push(' ');
                controllers.insert(name.to_owned());
            }
        }
        if !controllers.contains("memory") || !controllers.contains("pids") {
            return Err(Error::Message(format!(
                "delegated cgroup is missing memory or pids ({available})"
            )));
        }
        write_at(&root, "cgroup.subtree_control", enable.trim())?;
        let jobs = open_dir(&root, "jobs")?;
        write_at(&jobs, "cgroup.subtree_control", enable.trim())?;
        Ok(Self {
            jobs,
            jobs_path: here.join("jobs"),
            controllers,
        })
    }

    fn open_existing(root: &Path) -> Result<Self, Error> {
        let root_fd = rustix::fs::open(
            c_name("cgroup", &root.display().to_string())?,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| Error::io("open cgroup", e.into()))?;
        let text = read_at(&root_fd, "cgroup.subtree_control")?;
        let controllers = text.split_whitespace().map(str::to_owned).collect();
        Ok(Self {
            jobs: open_dir(&root_fd, "jobs")?,
            jobs_path: root.join("jobs"),
            controllers,
        })
    }

    pub fn controllers(&self) -> &BTreeSet<String> {
        &self.controllers
    }

    pub fn create_job(&self, name: &str, limits: Limits) -> Result<Job, Error> {
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(Error::Message(format!("bad job name {name}")));
        }
        mkdir(&self.jobs, name)?;
        let dir = open_dir(&self.jobs, name)?;
        write_at(&dir, "memory.max", &limits.memory_max.to_string())?;
        let high = limits.memory_max.saturating_mul(9) / 10;
        write_at(&dir, "memory.high", &high.to_string())?;
        write_at(&dir, "memory.swap.max", "0")?;
        write_at(&dir, "memory.oom.group", "1")?;
        write_at(&dir, "pids.max", &limits.pids_max.to_string())?;
        if let (Some(quota), Some(period)) = (limits.cpu_quota_us, limits.cpu_period_us) {
            if !self.controllers.contains("cpu") {
                return Err(Error::Message("cpu controller is not delegated".into()));
            }
            write_at(&dir, "cpu.max", &format!("{quota} {period}"))?;
        }
        Ok(Job {
            parent: rustix::fs::open(
                format!("/proc/self/fd/{}", self.jobs.as_raw_fd()),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| Error::io("dup jobs", e.into()))?,
            name: name.to_owned(),
            dir,
            path: self.jobs_path.join(name),
        })
    }
}

fn mkdir(parent: impl AsFd, name: &str) -> Result<(), Error> {
    match rustix::fs::mkdirat(parent, c_name("mkdir", name)?, Mode::from_raw_mode(0o755)) {
        Ok(()) => Ok(()),
        Err(e) if e == rustix::io::Errno::EXIST => Ok(()),
        Err(e) => Err(Error::io("mkdirat", e.into())),
    }
}

pub struct Job {
    parent: OwnedFd,
    name: String,
    dir: OwnedFd,
    path: PathBuf,
}

impl Job {
    pub fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.dir.as_fd()
    }

    pub fn procs(&self) -> Result<Vec<i32>, Error> {
        let text = read_at(&self.dir, "cgroup.procs")?;
        Ok(text
            .split_whitespace()
            .filter_map(|s| s.parse().ok())
            .collect())
    }

    pub fn kill(&self) -> Result<(), Error> {
        write_at(&self.dir, "cgroup.kill", "1")
    }

    /// Wait until `cgroup.events` says `populated 0`.
    pub fn wait_empty(&self, timeout: Duration) -> Result<(), Error> {
        if self.populated()? == 0 {
            return Ok(());
        }
        let events = self.path.join("cgroup.events");
        let watch = nsbx_sys::Watch::modify(&c_name("inotify", &events.display().to_string())?)
            .map_err(|e| Error::Message(e.to_string()))?;
        let deadline = Instant::now() + timeout;
        loop {
            if self.populated()? == 0 && self.procs()?.is_empty() {
                return Ok(());
            }
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return Err(Error::Message("cgroup did not drain".into()));
            };
            let _ = watch
                .wait(left)
                .map_err(|e| Error::Message(e.to_string()))?;
        }
    }

    fn populated(&self) -> Result<u32, Error> {
        let text = read_at(&self.dir, "cgroup.events")?;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("populated ") {
                return value
                    .trim()
                    .parse()
                    .map_err(|_| Error::Message(format!("bad cgroup.events {text}")));
            }
        }
        Err(Error::Message(format!("no populated line in {text}")))
    }

    pub fn remove(self) -> Result<(), Error> {
        rustix::fs::unlinkat(
            &self.parent,
            c_name("rmdir", &self.name)?,
            AtFlags::REMOVEDIR,
        )
        .map_err(|e| Error::io("rmdir", e.into()))
    }
}
