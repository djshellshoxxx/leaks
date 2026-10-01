// SPDX-License-Identifier: AGPL-3.0-or-later
//! Per-circuit and global token buckets (07 §11, 08 §4, 16 §13 L4; NET-013,
//! NET-029, ADR-026, ADR-038(5), ADR-052(11); ST-079).
//!
//! The circuit identifier exported by tor (PROXY header) is never stored: it
//! is replaced at once by `CircuitToken = HMAC-SHA256(K_rl, circuit_id)`
//! truncated to 128 bits, with `K_rl` random per process. Entries live in RAM
//! only and are evicted after [`CIRCUIT_IDLE`] (10 min) without a request.
//! Nothing here is logged, exported or persisted. Every limit hit gives the
//! same byte-identical busy page.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::limits::{CIRCUIT_IDLE, MAX_CIRCUITS};
use crate::token::{RngError, random};

/// An opaque per-circuit token (keyed hash of the tor circuit id).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitToken([u8; 16]);

impl core::fmt::Debug for CircuitToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CircuitToken(<redacted>)")
    }
}

/// A rate class (per circuit unless noted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Every request: 60/min, burst 20 (08 §4 family default).
    Request,
    /// POST `/login`: 5 / 10 min (SW-10).
    Login,
    /// POST `/new` (session creation): 6 / 10 min (SW-03).
    NewSession,
    /// Uploads (SW-06, SW-13): 30 / h.
    Upload,
    /// POST `/review` (passphrase generation, SW-08): 10 / h.
    Review,
    /// POST `/submit` (SW-26): 10 / h.
    Submit,
    /// POST `/conversation` send (SW-12): 20 / h.
    Message,
    /// POST `/extend` (SW-21): 12 / h.
    Extend,
    /// Rotation (SW-22, SW-28): 3 / day.
    Rotate,
    /// POST `/end` (SW-15): 3 / h.
    End,
    /// `/newphrase` (SW-25): 5 per session, approximated per circuit.
    NewPhrase,
}

const CLASSES: usize = 11;

impl Class {
    fn index(self) -> usize {
        match self {
            Self::Request => 0,
            Self::Login => 1,
            Self::NewSession => 2,
            Self::Upload => 3,
            Self::Review => 4,
            Self::Submit => 5,
            Self::Message => 6,
            Self::Extend => 7,
            Self::Rotate => 8,
            Self::End => 9,
            Self::NewPhrase => 10,
        }
    }

    /// `(capacity, refill period of the whole capacity)`.
    fn limit(self) -> (u64, Duration) {
        let min = |m| Duration::from_secs(60 * m);
        match self {
            // 60 per minute with a burst of 20: refill 20 tokens in 20 s.
            Self::Request => (20, Duration::from_secs(20)),
            Self::Login => (5, min(10)),
            Self::NewSession => (6, min(10)),
            Self::Upload => (30, min(60)),
            Self::Review => (10, min(60)),
            Self::Submit => (10, min(60)),
            Self::Message => (20, min(60)),
            Self::Extend => (12, min(60)),
            Self::Rotate => (3, min(24 * 60)),
            Self::End => (3, min(60)),
            Self::NewPhrase => (5, min(120)),
        }
    }
}

/// Token bucket in milli-tokens.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    milli: u64,
    at: Instant,
}

impl Bucket {
    fn full(cap: u64, now: Instant) -> Self {
        Self {
            milli: cap.saturating_mul(1000),
            at: now,
        }
    }

    fn take(&mut self, cap: u64, period: Duration, now: Instant) -> bool {
        let max = cap.saturating_mul(1000);
        let el = u64::try_from(now.saturating_duration_since(self.at).as_millis()).unwrap_or(u64::MAX);
        let per = u64::try_from(period.as_millis()).unwrap_or(u64::MAX).max(1);
        // refill = elapsed_ms × cap × 1000 / period_ms (saturating).
        let refill = el
            .saturating_mul(max)
            .checked_div(per)
            .unwrap_or(max);
        self.milli = self.milli.saturating_add(refill).min(max);
        self.at = now;
        if self.milli >= 1000 {
            self.milli = self.milli.saturating_sub(1000);
            true
        } else {
            false
        }
    }
}

struct Entry {
    buckets: [Option<Bucket>; CLASSES],
    last: Instant,
}

/// Global limits (07 §11): requests 600/s, new sessions 600/h (sized at ≥
/// 10× design peak so single probes reveal nothing, ADR-038(5)).
#[derive(Debug, Clone, Copy)]
pub struct GlobalLimits {
    /// Requests per second.
    pub requests_per_sec: u64,
    /// New sessions per hour.
    pub sessions_per_hour: u64,
}

impl Default for GlobalLimits {
    fn default() -> Self {
        Self {
            requests_per_sec: 600,
            sessions_per_hour: 600,
        }
    }
}

struct Inner {
    circuits: HashMap<CircuitToken, Entry>,
    global_requests: Bucket,
    global_sessions: Bucket,
    last_sweep: Instant,
}

/// The limiter.
pub struct Limiter {
    key: Zeroizing<[u8; 32]>,
    global: GlobalLimits,
    inner: Mutex<Inner>,
}

impl core::fmt::Debug for Limiter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Limiter")
    }
}

impl Limiter {
    /// A limiter with a fresh random token key.
    pub fn new(global: GlobalLimits, now: Instant) -> Result<Self, RngError> {
        let mut key = Zeroizing::new([0u8; 32]);
        random(key.as_mut())?;
        Ok(Self {
            key,
            global,
            inner: Mutex::new(Inner {
                circuits: HashMap::new(),
                global_requests: Bucket::full(global.requests_per_sec, now),
                global_sessions: Bucket::full(global.sessions_per_hour, now),
                last_sweep: now,
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replace a raw circuit id by its token (the id is not kept).
    #[must_use]
    pub fn token(&self, circuit_id: u32) -> CircuitToken {
        let mut out = [0u8; 16];
        if let Ok(mut m) = <Hmac<Sha256> as KeyInit>::new_from_slice(self.key.as_ref()) {
            m.update(b"candor/web/circuit");
            m.update(&circuit_id.to_be_bytes());
            let tag: [u8; 32] = m.finalize().into_bytes().into();
            out.copy_from_slice(tag.get(..16).unwrap_or(&[0u8; 16]));
        }
        CircuitToken(out)
    }

    /// Take one token of `class` for `circuit` (and of the global request
    /// bucket for [`Class::Request`], the global session bucket for
    /// [`Class::NewSession`]). `false` → busy page.
    pub fn allow(&self, circuit: CircuitToken, class: Class, now: Instant) -> bool {
        let mut g = self.lock();
        if now.saturating_duration_since(g.last_sweep) >= Duration::from_secs(60) {
            g.circuits
                .retain(|_, e| now.saturating_duration_since(e.last) < CIRCUIT_IDLE);
            g.last_sweep = now;
        }
        match class {
            Class::Request => {
                let cap = self.global.requests_per_sec;
                if !g.global_requests.take(cap, Duration::from_secs(1), now) {
                    return false;
                }
            }
            Class::NewSession => {
                let cap = self.global.sessions_per_hour;
                if !g.global_sessions.take(cap, Duration::from_secs(3600), now) {
                    return false;
                }
            }
            _ => {}
        }
        if !g.circuits.contains_key(&circuit) {
            if g.circuits.len() >= MAX_CIRCUITS {
                g.circuits
                    .retain(|_, e| now.saturating_duration_since(e.last) < CIRCUIT_IDLE);
                if g.circuits.len() >= MAX_CIRCUITS {
                    return false;
                }
            }
            g.circuits.insert(
                circuit,
                Entry {
                    buckets: [None; CLASSES],
                    last: now,
                },
            );
        }
        let Some(e) = g.circuits.get_mut(&circuit) else {
            return false;
        };
        // An entry idle for the eviction period starts afresh (NET-013).
        if now.saturating_duration_since(e.last) >= CIRCUIT_IDLE {
            e.buckets = [None; CLASSES];
        }
        e.last = now;
        let (cap, period) = class.limit();
        let Some(slot) = e.buckets.get_mut(class.index()) else {
            return false;
        };
        let b = slot.get_or_insert_with(|| Bucket::full(cap, now));
        b.take(cap, period, now)
    }

    /// Circuits currently tracked (tests and coarse health).
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.lock().circuits.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;

    /// ST-079: per-circuit login limit 5 / 10 min, independent per circuit.
    #[test]
    fn login_limit_per_circuit() {
        let t0 = Instant::now();
        let l = Limiter::new(GlobalLimits::default(), t0).unwrap();
        let a = l.token(1);
        let b = l.token(2);
        for _ in 0..5 {
            assert!(l.allow(a, Class::Login, t0));
        }
        assert!(!l.allow(a, Class::Login, t0));
        assert!(l.allow(b, Class::Login, t0), "other circuits unaffected");
        // Two minutes refill one attempt.
        assert!(l.allow(a, Class::Login, t0 + Duration::from_secs(121)));
        assert!(!l.allow(a, Class::Login, t0 + Duration::from_secs(121)));
    }

    #[test]
    fn request_burst_and_rate() {
        let t0 = Instant::now();
        let l = Limiter::new(GlobalLimits::default(), t0).unwrap();
        let a = l.token(7);
        for _ in 0..20 {
            assert!(l.allow(a, Class::Request, t0));
        }
        assert!(!l.allow(a, Class::Request, t0));
        assert!(l.allow(a, Class::Request, t0 + Duration::from_secs(1)));
    }

    #[test]
    fn global_request_bucket() {
        let t0 = Instant::now();
        let l = Limiter::new(
            GlobalLimits {
                requests_per_sec: 3,
                sessions_per_hour: 1,
            },
            t0,
        )
        .unwrap();
        for i in 0..3 {
            assert!(l.allow(l.token(i), Class::Request, t0));
        }
        assert!(!l.allow(l.token(99), Class::Request, t0));
        assert!(l.allow(l.token(1), Class::NewSession, t0));
        assert!(!l.allow(l.token(2), Class::NewSession, t0));
    }

    /// NET-013: idle circuits are forgotten after 10 minutes.
    #[test]
    fn idle_eviction() {
        let t0 = Instant::now();
        let l = Limiter::new(GlobalLimits::default(), t0).unwrap();
        for i in 0..10 {
            assert!(l.allow(l.token(i), Class::Request, t0));
        }
        assert_eq!(l.tracked(), 10);
        assert!(l.allow(l.token(100), Class::Request, t0 + CIRCUIT_IDLE + Duration::from_secs(61)));
        assert_eq!(l.tracked(), 1);
    }

    #[test]
    fn tokens_are_keyed() {
        let t0 = Instant::now();
        let l1 = Limiter::new(GlobalLimits::default(), t0).unwrap();
        let l2 = Limiter::new(GlobalLimits::default(), t0).unwrap();
        assert_eq!(l1.token(5), l1.token(5));
        assert_ne!(l1.token(5), l2.token(5));
        assert_ne!(l1.token(5), l1.token(6));
        assert_eq!(format!("{:?}", l1.token(5)), "CircuitToken(<redacted>)");
    }
}
