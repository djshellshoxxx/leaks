// SPDX-License-Identifier: AGPL-3.0-or-later
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use candor_log::chain::{AuditClock, CaseCommitKey, CaseKeyStore, ClockReading, KeyUnavailable};
use candor_log::codes::HostRole;
use candor_log::disposal::{ApproverKeys, DisposalApprover, SoftwareApprover};
use candor_log::ids::{AuditIdKey, CaseRef, ChannelId, EvidRef, TenantRef, UserRef, UtcMillis};
use candor_log::sink::MemorySink;
use candor_log::{AuditLog, CheckpointPolicy, CheckpointSigner, SoftwareSigner};
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

/// Identifiers are only ever generated (AUD-RM1-LOG-17); tests draw a fixed
/// table once per process so `case(n)` is stable within a test binary.
fn table<T: Copy>(cell: &'static OnceLock<Vec<T>>, gen_one: fn() -> T) -> &'static [T] {
    cell.get_or_init(|| (0..=255).map(|_| gen_one()).collect())
}

pub fn tenant() -> TenantRef {
    static T: OnceLock<TenantRef> = OnceLock::new();
    *T.get_or_init(|| TenantRef::generate().unwrap())
}

pub fn user(n: u8) -> UserRef {
    static T: OnceLock<Vec<UserRef>> = OnceLock::new();
    table(&T, || UserRef::generate().unwrap())[usize::from(n)]
}

pub fn case(n: u8) -> CaseRef {
    static T: OnceLock<Vec<CaseRef>> = OnceLock::new();
    table(&T, || CaseRef::generate().unwrap())[usize::from(n)]
}

pub fn channel(n: u8) -> ChannelId {
    static T: OnceLock<Vec<ChannelId>> = OnceLock::new();
    table(&T, || ChannelId::generate().unwrap())[usize::from(n)]
}

pub fn evid(n: u8) -> EvidRef {
    static T: OnceLock<Vec<EvidRef>> = OnceLock::new();
    table(&T, || EvidRef::generate().unwrap())[usize::from(n)]
}

/// The two pinned disposal approvers (dedicated keys, AUD-RM1-LOG-16).
pub fn approvers() -> (SoftwareApprover, SoftwareApprover) {
    (
        SoftwareApprover::from_seed(&Zeroizing::new([21; 32])),
        SoftwareApprover::from_seed(&Zeroizing::new([22; 32])),
    )
}

/// Pinned approver keys for the test checkpoint key (`signer(7)`).
pub fn approver_keys() -> &'static ApproverKeys {
    static K: OnceLock<ApproverKeys> = OnceLock::new();
    K.get_or_init(|| {
        let (a, b) = approvers();
        ApproverKeys::new(
            vec![a.verifying_key(), b.verifying_key()],
            &signer(7).verifying_key(),
        )
        .unwrap()
    })
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
    log.set_approver_keys(approver_keys().clone());
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
