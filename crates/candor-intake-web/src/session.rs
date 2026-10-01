// SPDX-License-Identifier: AGPL-3.0-or-later
//! Web session table (07 §5.1 "Sessions", 11 §5.6, ADR-034; ST-066).
//!
//! RAM only, keyed by `SHA-256(h)` (never `cs`, never the sealer handle).
//! One timer set: idle [`SESSION_IDLE`] (20 min) and absolute
//! [`SESSION_ABSOLUTE`] (2 h), on the monotonic clock. Expiry is checked on
//! every access and by [`Sessions::reap`]. At most [`MAX_SESSIONS`] entries;
//! when full, the entry idle the longest is evicted (07 §11). Drafts and
//! passphrases are not here: they live only in sealer RAM (ADR-034). An
//! entry holds the session's CSRF token, its piece key, the flow phase and
//! a few non-secret flow values.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use candor_intake_store::AccountId;
use zeroize::Zeroizing;

use crate::limits::{MAX_SESSIONS, SESSION_ABSOLUTE, SESSION_IDLE};
use crate::token::{RngError, hex, random};

/// Where the session is in the flow (11 §6 state machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Drafting a new report (S04b–S08).
    Drafting,
    /// S10 shown: passphrase generated in the sealer, not yet confirmed.
    Credential,
    /// S10c shown: waiting for the three words.
    Confirming,
    /// Sent (S10s); repeated `/submit` re-renders S10s (11 S10s).
    Submitted,
    /// Signed in after login (S11 inbox, S12).
    SignedIn,
    /// Signed in, S11r new passphrase shown.
    RotateCredential,
    /// Signed in, S11r confirmation shown.
    RotateConfirming,
}

/// The confirmation state of a pending passphrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Confirm {
    /// Positions to confirm (0-based, from the sealer).
    pub positions: [u8; 3],
    /// No attempts left (only "new passphrase" and "discard" remain).
    pub exhausted: bool,
    /// The last attempt failed (render the mismatch error).
    pub failed: bool,
}

/// One web session.
pub struct WebSession {
    created: Instant,
    last: Instant,
    /// Session CSRF token (hex), rotated at every change of authority.
    pub csrf: Zeroizing<String>,
    /// Key binding `piece` fields to stored values (AUD-RM1-SUI-11).
    pub piece_key: Zeroizing<[u8; 32]>,
    /// Flow phase.
    pub phase: Phase,
    /// Channel of the draft.
    pub channel: Option<[u8; 16]>,
    /// Mode chosen at S04 / S05b (banner and identity step).
    pub mode: candor_source_ui::Mode,
    /// Questionnaire step shown last (3..=6).
    pub step: u8,
    /// Delayed delivery chosen at S08 / S12 (ADR-038(4)).
    pub delayed: bool,
    /// Pending passphrase confirmation.
    pub confirm: Confirm,
    /// Signed-in account (intake-local id, never shown).
    pub account: Option<AccountId>,
    /// Signed-in account's lookup tag (to verify the passphrase re-entry at
    /// rotation in constant time).
    pub lookup_tag: Option<Zeroizing<[u8; 32]>>,
    /// Day of the successful send (S10s), and whether it was delayed.
    pub sent: Option<(u32, bool)>,
}

impl core::fmt::Debug for WebSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WebSession")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl WebSession {
    /// A new session in `phase`.
    pub fn new(phase: Phase, now: Instant) -> Result<Self, RngError> {
        let mut t = Zeroizing::new([0u8; 32]);
        random(t.as_mut())?;
        let mut pk = Zeroizing::new([0u8; 32]);
        random(pk.as_mut())?;
        Ok(Self {
            created: now,
            last: now,
            csrf: hex(t.as_ref()),
            piece_key: pk,
            phase,
            channel: None,
            mode: candor_source_ui::Mode::Anonymous,
            step: 3,
            delayed: false,
            confirm: Confirm::default(),
            account: None,
            lookup_tag: None,
            sent: None,
        })
    }

    /// Replace the CSRF token (after a change of authority).
    pub fn rotate_csrf(&mut self) -> Result<(), RngError> {
        let mut t = Zeroizing::new([0u8; 32]);
        random(t.as_mut())?;
        self.csrf = hex(t.as_ref());
        Ok(())
    }

    fn expired(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last) >= SESSION_IDLE
            || now.saturating_duration_since(self.created) >= SESSION_ABSOLUTE
    }

    /// Seconds left until `T_ABS` (for the CSS-only warning, 11 §5.6.1).
    #[must_use]
    pub fn abs_remaining_secs(&self, now: Instant) -> u32 {
        let left = SESSION_ABSOLUTE.saturating_sub(now.saturating_duration_since(self.created));
        u32::try_from(left.as_secs()).unwrap_or(u32::MAX)
    }

    /// The piece key for source-ui.
    #[must_use]
    pub fn piece_key(&self) -> candor_source_ui::PieceKey {
        candor_source_ui::PieceKey::new(*self.piece_key)
    }
}

/// Result of a lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// Live session (idle timer reset).
    Live,
    /// Unknown or expired (removed now).
    Gone,
}

/// The session table.
pub struct Sessions {
    map: Mutex<HashMap<[u8; 32], WebSession>>,
}

impl core::fmt::Debug for Sessions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sessions")
    }
}

impl Default for Sessions {
    fn default() -> Self {
        Self::new()
    }
}

impl Sessions {
    /// An empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<[u8; 32], WebSession>> {
        // Never held across an await and no code panics under it.
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Insert a new session, evicting the longest-idle one when full.
    pub fn insert(&self, key: [u8; 32], s: WebSession) {
        let mut m = self.lock();
        if m.len() >= MAX_SESSIONS && !m.contains_key(&key) {
            let oldest = m.iter().min_by_key(|(_, v)| v.last).map(|(k, _)| *k);
            if let Some(k) = oldest {
                m.remove(&k);
            }
        }
        m.insert(key, s);
    }

    /// Run `f` on a live session (resetting its idle timer when `touch`).
    /// Expired sessions are removed and reported as [`Lookup::Gone`].
    pub fn with<T>(
        &self,
        key: &[u8; 32],
        now: Instant,
        touch: bool,
        f: impl FnOnce(&mut WebSession) -> T,
    ) -> Result<T, Lookup> {
        let mut m = self.lock();
        let expired = match m.get(key) {
            None => return Err(Lookup::Gone),
            Some(s) => s.expired(now),
        };
        if expired {
            m.remove(key);
            return Err(Lookup::Gone);
        }
        let s = m.get_mut(key).ok_or(Lookup::Gone)?;
        if touch {
            s.last = now;
        }
        Ok(f(s))
    }

    /// Remove a session (logout, discard, leave).
    pub fn remove(&self, key: &[u8; 32]) {
        self.lock().remove(key);
    }

    /// Remove every expired session; returns how many were removed.
    pub fn reap(&self, now: Instant) -> usize {
        let mut m = self.lock();
        let before = m.len();
        m.retain(|_, s| !s.expired(now));
        before.saturating_sub(m.len())
    }

    /// Number of sessions (coarse health only).
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// No sessions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;
    use std::time::Duration;

    /// ST-066: 20 min idle, reset by activity; 2 h absolute, never extended.
    #[test]
    fn timers() {
        let t0 = Instant::now();
        let s = Sessions::new();
        s.insert([1; 32], WebSession::new(Phase::Drafting, t0).unwrap());
        let m = Duration::from_secs(60);
        // Activity every 19 minutes keeps it alive until the absolute limit.
        let mut t = t0;
        for _ in 0..6 {
            t += 19 * m;
            assert_eq!(s.with(&[1; 32], t, true, |_| ()), Ok(()));
        }
        // 114 min: still alive; 120 min: gone even with recent activity.
        t = t0 + 119 * m;
        assert_eq!(s.with(&[1; 32], t, true, |_| ()), Ok(()));
        assert_eq!(s.with(&[1; 32], t0 + 120 * m, true, |_| ()), Err(Lookup::Gone));
        // Idle: 20 minutes without activity ends it.
        s.insert([2; 32], WebSession::new(Phase::Drafting, t0).unwrap());
        assert_eq!(s.with(&[2; 32], t0 + 19 * m, false, |_| ()), Ok(()));
        assert_eq!(s.with(&[2; 32], t0 + 20 * m, true, |_| ()), Err(Lookup::Gone));
        // A peek without touch does not extend.
        s.insert([3; 32], WebSession::new(Phase::Drafting, t0).unwrap());
        assert_eq!(s.with(&[3; 32], t0 + 10 * m, false, |_| ()), Ok(()));
        assert_eq!(s.reap(t0 + 21 * m), 1);
        assert!(s.is_empty());
    }

    #[test]
    fn capacity_evicts_longest_idle() {
        let t0 = Instant::now();
        let s = Sessions::new();
        for i in 0..MAX_SESSIONS {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(i as u64).to_be_bytes());
            s.insert(k, WebSession::new(Phase::Drafting, t0 + Duration::from_millis(i as u64)).unwrap());
        }
        s.insert([9; 32], WebSession::new(Phase::Drafting, t0 + Duration::from_secs(100)).unwrap());
        assert_eq!(s.len(), MAX_SESSIONS);
        // Entry 0 (oldest) was evicted.
        assert!(s.with(&[0; 32], t0 + Duration::from_secs(101), false, |_| ()).is_err());
    }

    #[test]
    fn remaining_and_debug() {
        let t0 = Instant::now();
        let w = WebSession::new(Phase::SignedIn, t0).unwrap();
        assert_eq!(w.abs_remaining_secs(t0), 7200);
        assert_eq!(w.abs_remaining_secs(t0 + Duration::from_secs(8000)), 0);
        assert!(!format!("{w:?}").contains(w.csrf.as_str()));
    }
}
