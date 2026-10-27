//! Platform-neutral parts of the supervisor: the job lifecycle state machine,
//! UID slot allocation and effect epochs. See `docs/design.md` §3, §5 and §10.

pub mod epoch;
pub mod lifecycle;
pub mod slots;
