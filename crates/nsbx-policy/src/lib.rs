//! Policy for NixSandbox: admin profiles, request narrowing and seccomp
//! profile sources. Pure and platform-neutral; shared by the supervisor and
//! (through a binding) the orchestrator. See `docs/design.md` §8, §9 and §12.

pub mod audit;
#[cfg(target_os = "linux")]
pub mod bpf;
pub mod bundle;
pub mod caps;
pub mod document;
pub mod env;
pub mod hash;
pub mod narrow;
pub mod path;
pub mod profile;
pub mod risk;
pub mod seccomp;

pub use bundle::{BundleError, PolicyBundle};
pub use caps::{LimitCap, Limits, NetworkMode};
pub use narrow::{Denial, Effective, Principal, Request, narrow};
pub use path::RelPath;
pub use profile::Profile;
