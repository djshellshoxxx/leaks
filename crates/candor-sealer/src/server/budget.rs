// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sealer-wide memory admission control for attachments (AUD-RM2-SEA-26).
//!
//! Staged parts (tmpfs) and the sealed bundle (memfd) are both charged to the
//! sealer's cgroup. Each session reserves, at every `PART_BEGIN`, the most its
//! attachments can occupy at once — the ciphertext of every declared part
//! plus the ciphertext of the bundle bucket for the declared total — against
//! one budget derived from the configuration (`Limits::memory_budget_bytes`,
//! set safely below the unit's `MemoryMax`). Uploads that do not fit get the
//! uniform `BUSY`; a seal never needs a reservation of its own, so sealing is
//! never refused for memory. The reservation is released when the session's
//! draft is dropped (submit, abort, zeroize, expiry).

use std::sync::{Arc, Mutex, PoisonError};

/// The budget (bytes).
#[derive(Debug)]
pub(crate) struct Budget {
    cap: u64,
    used: Mutex<u64>,
}

impl Budget {
    pub(crate) fn new(cap: u64) -> Arc<Self> {
        Arc::new(Self {
            cap,
            used: Mutex::new(0),
        })
    }

    /// Bytes reserved now.
    pub(crate) fn used(&self) -> u64 {
        *self.used.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn try_add(&self, n: u64) -> bool {
        let mut u = self.used.lock().unwrap_or_else(PoisonError::into_inner);
        match u.checked_add(n) {
            Some(t) if t <= self.cap => {
                *u = t;
                true
            }
            _ => false,
        }
    }

    fn sub(&self, n: u64) {
        let mut u = self.used.lock().unwrap_or_else(PoisonError::into_inner);
        *u = u.saturating_sub(n);
    }
}

/// One session's reservation; released on drop.
#[derive(Debug)]
pub(crate) struct Grant {
    budget: Arc<Budget>,
    held: u64,
}

impl Grant {
    /// An empty reservation.
    pub(crate) fn new(budget: &Arc<Budget>) -> Self {
        Self {
            budget: budget.clone(),
            held: 0,
        }
    }

    /// Raise the reservation to `total` bytes; `false` (nothing changes) if
    /// the budget cannot cover it.
    pub(crate) fn grow_to(&mut self, total: u64) -> bool {
        let Some(delta) = total.checked_sub(self.held) else {
            return true;
        };
        if delta == 0 || self.budget.try_add(delta) {
            self.held = total;
            true
        } else {
            false
        }
    }
}

impl Drop for Grant {
    fn drop(&mut self) {
        self.budget.sub(self.held);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn grants_never_exceed_the_cap_and_release_on_drop() {
        let b = Budget::new(100);
        let mut a = Grant::new(&b);
        let mut c = Grant::new(&b);
        assert!(a.grow_to(60));
        assert!(!c.grow_to(41));
        assert!(c.grow_to(40));
        assert_eq!(b.used(), 100);
        assert!(!a.grow_to(61));
        assert!(a.grow_to(10)); // never shrinks below what is held
        drop(a);
        assert_eq!(b.used(), 40);
        drop(c);
        assert_eq!(b.used(), 0);
    }
}
