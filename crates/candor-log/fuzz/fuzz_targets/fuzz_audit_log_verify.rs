// SPDX-License-Identifier: AGPL-3.0-or-later
//! ST-051 `fuzz_audit_log_verify`: a genuine signed stream (records,
//! redaction stubs and checkpoints written by `AuditLog`) is mutated by
//! fuzzer-chosen edits; the verifier must never panic and must reject every
//! mutation that changes what the witness-held checkpoint attests.
#![no_main]

use std::sync::OnceLock;

use candor_log::chain::{ChainRecord, ClockReading, AuditClock};
use candor_log::codes::{HostRole, Service, StreamId};
use candor_log::disposal::{ApproverKeys, DisposalApprover, DisposalAuthorization, SoftwareApprover};
use candor_log::ids::{CaseRef, ChannelId, TenantRef, UtcMillis};
use candor_log::sink::MemorySink;
use candor_log::verify::{VerifyParams, verify_stream};
use candor_log::{AuditEvent, AuditLog, CheckpointPolicy, EventContext, SignedCheckpoint, SoftwareSigner};
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroizing;

#[path = "det.rs"]
mod det;

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
    approvers: ApproverKeys,
    /// `[CASE, CASE-SLOT]` streams: (records, checkpoints).
    streams: [(Vec<ChainRecord>, Vec<SignedCheckpoint>); 2],
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let tenant = det::tenant(b't');
        let clock = Clock(std::rc::Rc::new(std::cell::Cell::new(1_790_812_800_000)));
        let signer = SoftwareSigner::from_seed(&Zeroizing::new([7; 32]));
        let key = candor_log::CheckpointSigner::verifying_key(&signer);
        let (a, b) = (
            SoftwareApprover::from_seed(&Zeroizing::new([21; 32])),
            SoftwareApprover::from_seed(&Zeroizing::new([22; 32])),
        );
        let approvers =
            ApproverKeys::new(vec![a.verifying_key(), b.verifying_key()], &key).expect("keys");
        let mut log = AuditLog::new(tenant, HostRole::Core, signer, clock.clone(), CheckpointPolicy::DEFAULT);
        let sink = MemorySink::new();
        log.set_primary_sink(Box::new(sink.clone()));
        log.set_case_keys(Box::new(Keys));
        log.set_approver_keys(approvers.clone());
        let user = det::user(b'u');
        for i in 0..12u8 {
            let case = det::case(i % 3);
            log.emit(EventContext::staff(user), AuditEvent::CaseOpened { case }).expect("emit");
            log.emit(
                EventContext::system(Service::Relay),
                AuditEvent::CaseImported {
                    case,
                    channel_id: ChannelId::generate().expect("rng"),
                    received_day: UtcMillis(clock.0.get()).day(),
                    import_slot_date: UtcMillis(clock.0.get()).day(),
                },
            )
            .expect("emit");
        }
        // Flush the import slot (6 h), dispose case 1 in both streams.
        clock.0.set(clock.0.get() + 6 * 3_600_000);
        log.tick().expect("tick");
        let plan = sink.0.lock().expect("lock").plan_case_redaction(det::case(1));
        let req = plan.request(tenant, det::receipt(b'r')).expect("request");
        let auth = DisposalAuthorization::new(
            req.clone(),
            a.approve(&req).expect("approve"),
            b.approve(&req).expect("approve"),
            &approvers,
        )
        .expect("auth");
        log.emit_case_disposal(EventContext::staff(user), &plan, &auth).expect("dispose");
        clock.0.set(clock.0.get() + 6 * 3_600_000);
        log.tick().expect("tick");
        for s in [StreamId::Case, StreamId::CaseSlot] {
            sink.0.lock().expect("lock").apply_case_redaction(&plan, s).expect("redact");
        }
        clock.0.set(clock.0.get() + 86_400_000);
        log.tick().expect("tick");
        let st = sink.0.lock().expect("lock");
        let part = |s| (st.chain(s), st.checkpoints(s));
        Fixture {
            tenant,
            key,
            approvers,
            streams: [part(StreamId::Case), part(StreamId::CaseSlot)],
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let f = fixture();
    let si = usize::from(data.last().is_some_and(|b| b & 1 == 1));
    let stream = [StreamId::Case, StreamId::CaseSlot][si];
    let (orig_recs, orig_cps) = &f.streams[si];
    let mut recs = orig_recs.clone();
    let mut cps = orig_cps.clone();
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
                // Replace by a stub computed from the record (insider
                // redaction), naming a fuzzer-chosen case.
                if let Some(ChainRecord::Full { bytes, salt, .. }) = recs.get(i) {
                    let inner = candor_log::chain::record_inner(salt, bytes);
                    let seq = i as u64;
                    let case: CaseRef = det::case(c % 4);
                    recs[i] = ChainRecord::Redacted { seq, case, inner, tombstone_seq: u64::from(b) };
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
        stream,
        key: &f.key,
        approver_keys: &f.approvers,
        trusted_latest: witness.as_ref(),
        allow_pruned_prefix: data.first().is_some_and(|b| b & 0x80 != 0),
        min_retention_days: None,
    };
    let res = verify_stream(&p, &recs, &cps);
    if !changed {
        assert!(res.is_ok(), "genuine stream rejected");
    } else if &recs == orig_recs && &cps == orig_cps {
        assert!(res.is_ok());
    } else {
        assert!(res.is_err(), "tampered stream accepted");
    }
});
