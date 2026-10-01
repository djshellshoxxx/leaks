// SPDX-License-Identifier: AGPL-3.0-or-later
//! ST-051 `fuzz_audit_log_verify`: a genuine signed stream (records,
//! redaction stubs and checkpoints written by `AuditLog`) is mutated by
//! fuzzer-chosen edits; the verifier must never panic and must reject every
//! mutation that changes what the witness-held checkpoint attests.
#![no_main]

use std::sync::OnceLock;

use candor_log::chain::{ChainRecord, ClockReading, AuditClock};
use candor_log::codes::{HostRole, StreamId};
use candor_log::ids::{AuditIdKey, CaseRef, ReceiptId, TenantRef, UserRef, UtcMillis};
use candor_log::sink::MemorySink;
use candor_log::verify::{VerifyParams, verify_stream};
use candor_log::{AuditEvent, AuditLog, CheckpointPolicy, EventContext, SignedCheckpoint, SoftwareSigner};
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

#[derive(Clone)]
struct Clock(std::rc::Rc<std::cell::Cell<u64>>);
impl AuditClock for Clock {
    fn read(&self) -> ClockReading {
        ClockReading { now: UtcMillis(self.0.get()), drift_exceeded: false }
    }
}

struct Keys;
impl candor_log::chain::CaseKeyStore for Keys {
    fn commit_key(&mut self, c: CaseRef) -> Result<candor_log::chain::CaseCommitKey, candor_log::chain::KeyUnavailable> {
        let mut k = [9u8; 32];
        k[..16].copy_from_slice(c.as_bytes());
        Ok(candor_log::chain::CaseCommitKey::new(k))
    }
}

struct Fixture {
    tenant: TenantRef,
    key: ed25519_dalek::VerifyingKey,
    records: Vec<ChainRecord>,
    checkpoints: Vec<SignedCheckpoint>,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let idk = AuditIdKey::new([1; 32]);
        let tenant = TenantRef::derive(&idk, b"t");
        let clock = Clock(std::rc::Rc::new(std::cell::Cell::new(1_790_812_800_000)));
        let mut log = AuditLog::new(
            tenant,
            HostRole::Core,
            SoftwareSigner::from_seed(&Zeroizing::new([7; 32])),
            clock.clone(),
            CheckpointPolicy::DEFAULT,
        );
        let sink = MemorySink::new();
        log.set_primary_sink(Box::new(sink.clone()));
        log.set_case_keys(Box::new(Keys));
        let user = UserRef::derive(&idk, b"u");
        for i in 0..12u8 {
            let case = CaseRef::derive(&idk, &[i % 3]);
            log.emit(EventContext::staff(user), AuditEvent::CaseOpened { case }).expect("emit");
        }
        let plan = sink.0.lock().expect("lock").plan_case_redaction(CaseRef::derive(&idk, &[1]));
        let tomb = log
            .emit(EventContext::staff(user), plan.tombstone(ReceiptId::derive(&idk, b"r")))
            .expect("emit")
            .record;
        sink.0.lock().expect("lock").apply_case_redaction(&plan, &tomb).expect("redact");
        clock.0.set(clock.0.get() + 86_400_000);
        log.tick().expect("tick");
        let st = sink.0.lock().expect("lock");
        Fixture {
            tenant,
            key: log.verifying_key(),
            records: st.chain(StreamId::Case),
            checkpoints: st.checkpoints(StreamId::Case),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let mut recs = f.records.clone();
    let mut cps = f.checkpoints.clone();
    let witness = cps.last().cloned();
    let mut changed = false;
    for op in data.chunks(4) {
        let [kind, a, b, c] = [op.first(), op.get(1), op.get(2), op.get(3)].map(|x| x.copied().unwrap_or(0));
        let n = recs.len().max(1);
        let i = usize::from(a) % n;
        match kind % 6 {
            0 if !recs.is_empty() => {
                recs.remove(i);
                changed = true;
            }
            1 if recs.len() > 1 => {
                let j = usize::from(b) % recs.len();
                if i != j && recs[i] != recs[j] {
                    recs.swap(i, j);
                    changed = true;
                }
            }
            2 => {
                if let Some(ChainRecord::Full { bytes, .. }) = recs.get_mut(i) {
                    if !bytes.is_empty() {
                        let k = usize::from(b) % bytes.len();
                        bytes[k] ^= c | 1;
                        changed = true;
                    }
                }
            }
            3 => {
                // Replace by a stub computed from the record (insider redaction).
                if let Some(ChainRecord::Full { bytes, salt, .. }) = recs.get(i) {
                    let commit = candor_log::chain::record_commit(salt, bytes);
                    let seq = i as u64;
                    recs[i] = ChainRecord::Redacted { seq, commit, tombstone_seq: u64::from(b) };
                    changed = true;
                }
            }
            4 if !cps.is_empty() => {
                cps.remove(usize::from(a) % cps.len());
                changed = true;
            }
            5 if !recs.is_empty() => {
                recs.truncate(i);
                changed = true;
            }
            _ => {}
        }
    }
    let p = VerifyParams {
        tenant: f.tenant,
        stream: StreamId::Case,
        key: &f.key,
        trusted_latest: witness.as_ref(),
        allow_pruned_prefix: data.first().is_some_and(|b| b & 0x80 != 0),
    };
    let res = verify_stream(&p, &recs, &cps);
    if !changed {
        assert!(res.is_ok(), "genuine stream rejected");
    } else if recs == f.records && cps == f.checkpoints {
        assert!(res.is_ok());
    } else {
        assert!(res.is_err(), "tampered stream accepted");
    }
});
