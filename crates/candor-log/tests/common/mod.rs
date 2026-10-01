// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use candor_log::chain::{
    AuditClock, CaseCommitKey, CaseKeyStore, ClockReading, KeyUnavailable,
};
use candor_log::codes::HostRole;
use candor_log::ids::{AuditIdKey, CaseRef, TenantRef, UserRef, UtcMillis};
use candor_log::sink::MemorySink;
use candor_log::{AuditLog, CheckpointPolicy, SoftwareSigner};
use zeroize::Zeroizing;

/// 2026-10-01T13:37:42.123Z
pub const T0: u64 = 1_790_861_862_123;
pub const DAY: u64 = 86_400_000;

#[derive(Clone, Debug)]
pub struct TestClock(pub Arc<AtomicU64>);

impl TestClock {
    pub fn new(ms: u64) -> Self {
        Self(Arc::new(AtomicU64::new(ms)))
    }
    pub fn advance(&self, ms: u64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
    pub fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
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

pub fn idk() -> AuditIdKey {
    AuditIdKey::new([0x33; 32])
}

pub fn tenant() -> TenantRef {
    TenantRef::derive(&idk(), b"tenant-1")
}

pub fn user(n: u8) -> UserRef {
    UserRef::derive(&idk(), &[b'u', n])
}

pub fn case(n: u8) -> CaseRef {
    CaseRef::derive(&idk(), &[b'c', n])
}

pub fn signer(seed: u8) -> SoftwareSigner {
    SoftwareSigner::from_seed(&Zeroizing::new([seed; 32]))
}

/// Test key store: a deterministic key per case until destroyed. (A real
/// store holds random keys; deterministic keys are for tests only.)
#[derive(Clone, Debug, Default)]
pub struct TestKeys(pub Arc<Mutex<BTreeSet<CaseRef>>>);

impl TestKeys {
    pub fn destroy(&self, c: CaseRef) {
        self.0.lock().unwrap().insert(c);
    }
}

impl CaseKeyStore for TestKeys {
    fn commit_key(&mut self, c: CaseRef) -> Result<CaseCommitKey, KeyUnavailable> {
        if self.0.lock().unwrap().contains(&c) {
            return Err(KeyUnavailable);
        }
        let mut k = [0x77u8; 32];
        k[..16].copy_from_slice(c.as_bytes());
        Ok(CaseCommitKey::new(k))
    }
}

pub struct Rig {
    pub log: AuditLog<SoftwareSigner, TestClock>,
    pub sink: MemorySink,
    pub clock: TestClock,
    pub keys: TestKeys,
}

pub fn rig(host: HostRole, policy: CheckpointPolicy) -> Rig {
    rig_at(host, policy, T0)
}

pub fn rig_at(host: HostRole, policy: CheckpointPolicy, t: u64) -> Rig {
    let clock = TestClock::new(t);
    let mut log = AuditLog::new(tenant(), host, signer(7), clock.clone(), policy);
    let sink = MemorySink::new();
    log.set_primary_sink(Box::new(sink.clone()));
    let keys = TestKeys::default();
    log.set_case_keys(Box::new(keys.clone()));
    Rig {
        log,
        sink,
        clock,
        keys,
    }
}

pub fn log_with(
    host: HostRole,
    policy: CheckpointPolicy,
) -> (AuditLog<SoftwareSigner, TestClock>, MemorySink, TestClock) {
    let r = rig(host, policy);
    (r.log, r.sink, r.clock)
}
