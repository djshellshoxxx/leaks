// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use candor_log::chain::{AuditClock, ClockReading};
use candor_log::codes::HostRole;
use candor_log::ids::{TenantRef, UserRef, UtcMillis};
use candor_log::sink::MemorySink;
use candor_log::{AuditLog, CheckpointPolicy, SoftwareSigner};
use zeroize::Zeroizing;

/// 2026-10-01T13:37:42.123Z
pub const T0: u64 = 1_790_861_862_123;

#[derive(Clone, Debug)]
pub struct TestClock(pub Arc<AtomicU64>);

impl TestClock {
    pub fn new(ms: u64) -> Self {
        Self(Arc::new(AtomicU64::new(ms)))
    }
    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl AuditClock for TestClock {
    fn read(&self) -> ClockReading {
        ClockReading {
            now: UtcMillis(self.0.load(Ordering::SeqCst)),
            drift_exceeded: false,
        }
    }
}

pub fn tenant() -> TenantRef {
    TenantRef::from_bytes([0x11; 16])
}

pub fn user(n: u8) -> UserRef {
    UserRef::from_bytes([n; 16])
}

pub fn signer(seed: u8) -> SoftwareSigner {
    SoftwareSigner::from_seed(&Zeroizing::new([seed; 32]))
}

pub fn log_with(
    host: HostRole,
    policy: CheckpointPolicy,
) -> (AuditLog<SoftwareSigner, TestClock>, MemorySink, TestClock) {
    let clock = TestClock::new(T0);
    let mut log = AuditLog::new(tenant(), host, signer(7), clock.clone(), policy);
    let sink = MemorySink::new();
    log.add_sink(Box::new(sink.clone()));
    (log, sink, clock)
}
