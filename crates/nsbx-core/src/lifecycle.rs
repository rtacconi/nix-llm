//! Job lifecycle state machine (design §3 "Lifecycle", §16 invariants).
//!
//! `step` is total: every (state, event) pair either moves to a defined state
//! or is rejected, and terminal states accept no events. The property tests
//! below drive random event sequences through it.

use nsbx_proto::msg::TerminationReason;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Admitted,
    CgroupReady,
    Spawned,
    Mapped,
    Setup,
    Running,
    /// Kill requested; waiting for the tree to die.
    Terminating(TerminationReason),
    /// Init reaped; cgroup may still be populated.
    Reaped(TerminationReason),
    /// Cgroup removed and slot released.
    Cleaned(TerminationReason),
    /// Cleanup timed out; slot quarantined.
    Stuck(TerminationReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    CgroupCreated,
    /// Pre-warmed pool entry claimed: skips straight to `Mapped`.
    PoolClaimed,
    Spawned,
    MapWritten,
    SetupStarted,
    WorkloadExecuted,
    /// Workload finished on its own (exit, signal, OOM, seccomp kill).
    Finished(TerminationReason),
    /// Supervisor-initiated termination (deadline, budget, cancel, output cap).
    Kill(TerminationReason),
    /// Any setup step failed.
    SetupFailed,
    InitReaped,
    CgroupRemoved,
    CleanupTimedOut,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("event {event:?} is not valid in state {state:?}")]
pub struct InvalidTransition {
    pub state: State,
    pub event: Event,
}

impl State {
    /// Terminal for the job's report: no further events are accepted.
    pub fn is_terminal(self) -> bool {
        matches!(self, State::Cleaned(_) | State::Stuck(_))
    }

    pub fn reason(self) -> Option<TerminationReason> {
        match self {
            State::Terminating(r) | State::Reaped(r) | State::Cleaned(r) | State::Stuck(r) => {
                Some(r)
            }
            _ => None,
        }
    }

    fn in_setup(self) -> bool {
        matches!(
            self,
            State::Admitted | State::CgroupReady | State::Spawned | State::Mapped | State::Setup
        )
    }
}

pub fn step(state: State, event: Event) -> Result<State, InvalidTransition> {
    use Event as E;
    use State as S;
    let next = match (state, event) {
        (S::Admitted, E::CgroupCreated) => S::CgroupReady,
        (S::Admitted, E::PoolClaimed) => S::Mapped,
        (S::CgroupReady, E::Spawned) => S::Spawned,
        (S::Spawned, E::MapWritten) => S::Mapped,
        (S::Mapped, E::SetupStarted) => S::Setup,
        (S::Setup, E::WorkloadExecuted) => S::Running,

        // Failure or cancellation during setup. A setup failure with nothing
        // spawned yet goes straight to cleanup.
        (S::Admitted | S::CgroupReady, E::SetupFailed) => S::Reaped(TerminationReason::SetupFailed),
        (s, E::SetupFailed) if s.in_setup() => S::Terminating(TerminationReason::SetupFailed),
        (S::Admitted | S::CgroupReady, E::Kill(r)) => S::Reaped(r),
        (s, E::Kill(r)) if s.in_setup() => S::Terminating(r),

        (S::Running, E::Finished(r)) => S::Terminating(r),
        (S::Running, E::Kill(r)) => S::Terminating(r),
        // First reason wins: a later deadline does not relabel a cancel.
        (S::Terminating(r), E::Kill(_) | E::Finished(_)) => S::Terminating(r),

        (S::Terminating(r), E::InitReaped) => S::Reaped(r),
        (S::Reaped(r), E::CgroupRemoved) => S::Cleaned(r),
        (S::Terminating(r) | S::Reaped(r), E::CleanupTimedOut) => S::Stuck(r),

        (state, event) => return Err(InvalidTransition { state, event }),
    };
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use TerminationReason as R;
    use proptest::prelude::*;

    fn run(events: &[Event]) -> Result<State, InvalidTransition> {
        events.iter().try_fold(State::Admitted, |s, e| step(s, *e))
    }

    #[test]
    fn happy_path() {
        let s = run(&[
            Event::CgroupCreated,
            Event::Spawned,
            Event::MapWritten,
            Event::SetupStarted,
            Event::WorkloadExecuted,
            Event::Finished(R::Exited),
            Event::InitReaped,
            Event::CgroupRemoved,
        ]);
        assert_eq!(s, Ok(State::Cleaned(R::Exited)));
    }

    #[test]
    fn pool_claim_skips_construction() {
        let s = run(&[
            Event::PoolClaimed,
            Event::SetupStarted,
            Event::WorkloadExecuted,
        ]);
        assert_eq!(s, Ok(State::Running));
    }

    #[test]
    fn first_reason_wins() {
        let s = run(&[
            Event::PoolClaimed,
            Event::SetupStarted,
            Event::WorkloadExecuted,
            Event::Kill(R::Cancelled),
            Event::Kill(R::WallTimeout),
            Event::InitReaped,
            Event::CgroupRemoved,
        ]);
        assert_eq!(s, Ok(State::Cleaned(R::Cancelled)));
    }

    #[test]
    fn terminal_states_accept_nothing() {
        for t in [State::Cleaned(R::Exited), State::Stuck(R::Oom)] {
            assert!(step(t, Event::Kill(R::Cancelled)).is_err());
            assert!(step(t, Event::CgroupRemoved).is_err());
        }
    }

    fn any_reason() -> impl Strategy<Value = TerminationReason> {
        prop_oneof![
            Just(R::Exited),
            Just(R::Signaled),
            Just(R::WallTimeout),
            Just(R::CpuBudget),
            Just(R::Oom),
            Just(R::OutputLimit),
            Just(R::SeccompKill),
            Just(R::SandboxDied),
            Just(R::Cancelled),
        ]
    }

    fn any_event() -> impl Strategy<Value = Event> {
        prop_oneof![
            Just(Event::CgroupCreated),
            Just(Event::PoolClaimed),
            Just(Event::Spawned),
            Just(Event::MapWritten),
            Just(Event::SetupStarted),
            Just(Event::WorkloadExecuted),
            any_reason().prop_map(Event::Finished),
            any_reason().prop_map(Event::Kill),
            Just(Event::SetupFailed),
            Just(Event::InitReaped),
            Just(Event::CgroupRemoved),
            Just(Event::CleanupTimedOut),
        ]
    }

    proptest! {
        /// Under any event sequence: once a reason is set it never changes, and
        /// nothing leaves a terminal state.
        #[test]
        fn reason_is_stable_and_terminal_is_absorbing(events in proptest::collection::vec(any_event(), 0..40)) {
            let mut s = State::Admitted;
            let mut reason = None;
            for e in events {
                if let Ok(n) = step(s, e) {
                    prop_assert!(!s.is_terminal(), "left terminal state {s:?}");
                    if let (Some(r0), Some(r1)) = (reason, n.reason()) {
                        prop_assert_eq!(r0, r1);
                    }
                    reason = reason.or(n.reason());
                    s = n;
                }
            }
        }

        /// From any reachable state, a kill followed by the cleanup events
        /// always ends in exactly one terminal state.
        #[test]
        fn every_job_can_reach_a_terminal_state(events in proptest::collection::vec(any_event(), 0..20)) {
            let mut s = State::Admitted;
            for e in events {
                s = step(s, e).unwrap_or(s);
            }
            if !s.is_terminal() {
                for e in [Event::Kill(R::Cancelled), Event::InitReaped, Event::CgroupRemoved] {
                    s = step(s, e).unwrap_or(s);
                }
            }
            prop_assert!(s.is_terminal(), "stuck in {s:?}");
        }
    }
}
