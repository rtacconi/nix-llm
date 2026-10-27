//! UID slot allocation (design §5.1). Each slot owns a disjoint host UID range;
//! a slot is reused only after its job's cgroup has been removed, and slots
//! whose cleanup got stuck stay quarantined until an operator releases them.

use thiserror::Error;

/// Width of each slot's host UID range.
pub const SLOT_WIDTH: u32 = 65_536;
/// In-namespace UID of the workload (maps to `base + 1000`).
pub const WORKLOAD_NS_UID: u32 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    Free,
    InUse,
    Quarantined,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SlotError {
    #[error("UID range starting at {start} with {slots} slots overflows u32")]
    Overflow { start: u32, slots: u16 },
    #[error("slot {0} is out of range")]
    OutOfRange(u16),
    #[error("slot {0} is not in use")]
    NotInUse(u16),
    #[error("slot {0} is not quarantined")]
    NotQuarantined(u16),
}

#[derive(Debug)]
pub struct SlotAllocator {
    range_start: u32,
    slots: Vec<Slot>,
    next: usize,
}

impl SlotAllocator {
    pub fn new(range_start: u32, count: u16) -> Result<Self, SlotError> {
        let end = u64::from(range_start) + u64::from(count) * u64::from(SLOT_WIDTH);
        if end > u64::from(u32::MAX) {
            return Err(SlotError::Overflow {
                start: range_start,
                slots: count,
            });
        }
        Ok(Self {
            range_start,
            slots: vec![Slot::Free; usize::from(count)],
            next: 0,
        })
    }

    /// Round-robin allocation, so a just-released slot is reused last.
    pub fn alloc(&mut self) -> Option<u16> {
        let n = self.slots.len();
        for i in 0..n {
            let idx = (self.next + i) % n;
            if self.slots[idx] == Slot::Free {
                self.slots[idx] = Slot::InUse;
                self.next = (idx + 1) % n;
                return u16::try_from(idx).ok();
            }
        }
        None
    }

    /// Call only after the job's cgroup has been removed.
    pub fn release(&mut self, slot: u16) -> Result<(), SlotError> {
        self.transition(slot, Slot::InUse, Slot::Free)
            .map_err(|()| SlotError::NotInUse(slot))
    }

    /// Cleanup got stuck: keep the UID range out of circulation.
    pub fn quarantine(&mut self, slot: u16) -> Result<(), SlotError> {
        self.transition(slot, Slot::InUse, Slot::Quarantined)
            .map_err(|()| SlotError::NotInUse(slot))
    }

    /// The stuck cgroup has finally gone.
    pub fn unquarantine(&mut self, slot: u16) -> Result<(), SlotError> {
        self.transition(slot, Slot::Quarantined, Slot::Free)
            .map_err(|()| SlotError::NotQuarantined(slot))
    }

    pub fn base_uid(&self, slot: u16) -> u32 {
        self.range_start + u32::from(slot) * SLOT_WIDTH
    }

    pub fn workload_uid(&self, slot: u16) -> u32 {
        self.base_uid(slot) + WORKLOAD_NS_UID
    }

    pub fn in_use(&self) -> usize {
        self.slots.iter().filter(|s| **s == Slot::InUse).count()
    }

    pub fn quarantined(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| **s == Slot::Quarantined)
            .count()
    }

    fn transition(&mut self, slot: u16, from: Slot, to: Slot) -> Result<(), ()> {
        match self.slots.get_mut(usize::from(slot)) {
            Some(s) if *s == from => {
                *s = to;
                Ok(())
            }
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn ranges_are_disjoint_and_in_bounds() {
        let a = SlotAllocator::new(2_000_000, 4).unwrap();
        assert_eq!(a.base_uid(0), 2_000_000);
        assert_eq!(a.base_uid(1), 2_000_000 + SLOT_WIDTH);
        assert_eq!(a.workload_uid(1), 2_000_000 + SLOT_WIDTH + 1000);
        assert!(SlotAllocator::new(u32::MAX - 10, 1).is_err());
    }

    #[test]
    fn released_slot_is_reused_last() {
        let mut a = SlotAllocator::new(0, 3).unwrap();
        let s0 = a.alloc().unwrap();
        a.release(s0).unwrap();
        assert_ne!(a.alloc(), Some(s0));
    }

    #[test]
    fn quarantine_blocks_reuse() {
        let mut a = SlotAllocator::new(0, 1).unwrap();
        let s = a.alloc().unwrap();
        a.quarantine(s).unwrap();
        assert_eq!(a.alloc(), None);
        assert_eq!(a.release(s), Err(SlotError::NotInUse(s)));
        a.unquarantine(s).unwrap();
        assert_eq!(a.alloc(), Some(s));
    }

    #[derive(Debug, Clone)]
    enum Op {
        Alloc,
        Release(usize),
        Quarantine(usize),
        Unquarantine(usize),
    }

    proptest! {
        /// No slot is ever handed out twice while in use or quarantined.
        #[test]
        fn never_double_allocates(ops in proptest::collection::vec(prop_oneof![
            Just(Op::Alloc),
            (0usize..8).prop_map(Op::Release),
            (0usize..8).prop_map(Op::Quarantine),
            (0usize..8).prop_map(Op::Unquarantine),
        ], 0..100)) {
            let mut a = SlotAllocator::new(0, 8).unwrap();
            let mut held: Vec<u16> = Vec::new();
            let mut quarantined: Vec<u16> = Vec::new();
            for op in ops {
                match op {
                    Op::Alloc => if let Some(s) = a.alloc() {
                        prop_assert!(!held.contains(&s) && !quarantined.contains(&s));
                        held.push(s);
                    },
                    Op::Release(i) if i < held.len() => { a.release(held.remove(i)).unwrap(); }
                    Op::Quarantine(i) if i < held.len() => { let s = held.remove(i); a.quarantine(s).unwrap(); quarantined.push(s); }
                    Op::Unquarantine(i) if i < quarantined.len() => { a.unquarantine(quarantined.remove(i)).unwrap(); }
                    _ => {}
                }
                prop_assert_eq!(a.in_use(), held.len());
                prop_assert_eq!(a.quarantined(), quarantined.len());
            }
        }
    }
}
