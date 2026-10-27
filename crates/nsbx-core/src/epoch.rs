//! Effect epochs (design §10.4).
//!
//! Each job has an epoch. Cancel, deadline and revoke bump it. Code that is
//! about to produce an effect (exec during setup, egress CONNECT, artefact
//! export, output commit) takes a `Ticket` when it decides and calls
//! `check` immediately before acting; a stale ticket means "do nothing".

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

#[derive(Debug, Default, Clone)]
pub struct Epoch(Arc<AtomicU64>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket(u64);

#[derive(Debug, Error, PartialEq, Eq)]
#[error("effect refused: epoch moved from {issued} to {current}")]
pub struct Stale {
    pub issued: u64,
    pub current: u64,
}

impl Epoch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ticket(&self) -> Ticket {
        Ticket(self.0.load(Ordering::Acquire))
    }

    /// Invalidate every outstanding ticket. Returns the new epoch.
    pub fn bump(&self) -> u64 {
        self.0.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn check(&self, t: Ticket) -> Result<(), Stale> {
        let current = self.0.load(Ordering::Acquire);
        if current == t.0 {
            Ok(())
        } else {
            Err(Stale {
                issued: t.0,
                current,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_invalidates_outstanding_tickets() {
        let e = Epoch::new();
        let t = e.ticket();
        assert!(e.check(t).is_ok());
        e.bump();
        assert_eq!(
            e.check(t),
            Err(Stale {
                issued: 0,
                current: 1
            })
        );
        assert!(e.check(e.ticket()).is_ok());
    }

    #[test]
    fn clones_share_the_epoch() {
        let e = Epoch::new();
        let proxy_side = e.clone();
        let t = proxy_side.ticket();
        e.bump();
        assert!(proxy_side.check(t).is_err());
    }
}
