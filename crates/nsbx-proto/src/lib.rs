//! The `nsbx/1` protocol between the orchestrator and the supervisor.
//!
//! See `docs/design.md` §12.2. This crate has no I/O so the same code runs in
//! the supervisor, the warden, the fuzzers and the Kani proofs.

pub mod frame;
pub mod msg;
pub mod status;

pub use frame::{Frame, FrameError, FrameType, MAX_FRAME_LEN, decode, encode};
