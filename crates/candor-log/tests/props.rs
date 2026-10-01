// SPDX-License-Identifier: AGPL-3.0-or-later
//! Property tests: canonical CBOR determinism and chain verification under
//! random tampering (AUD-001, AUD-004).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use candor_log::cbor::{self, Value};
use candor_log::chain::ChainRecord;
use candor_log::codes::{HostRole, StreamId};
use candor_log::ids::CaseRef;
use candor_log::verify::{VerifyParams, verify_stream};
use candor_log::{AuditEvent, CheckpointPolicy, EventContext};
use common::*;
use proptest::prelude::*;

fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<u64>().prop_map(Value::Uint),
        any::<u64>().prop_map(Value::Nint),
        proptest::collection::vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        "[a-z_]{0,12}".prop_map(Value::Text),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            proptest::collection::btree_map("[a-z]{1,6}", inner, 0..6).prop_map(|m| {
                Value::Map(m.into_iter().map(|(k, v)| (Value::Text(k), v)).collect())
            }),
        ]
    })
}

/// Reverse every map's entry order recursively (same logical value).
fn permute(v: &Value) -> Value {
    match v {
        Value::Array(a) => Value::Array(a.iter().map(permute).collect()),
        Value::Map(m) => Value::Map(m.iter().rev().map(|(k, v)| (permute(k), permute(v))).collect()),
        other => other.clone(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    // Encoding is a function of the logical value only.
    #[test]
    fn canonical_encoding_is_deterministic(v in arb_value()) {
        let a = cbor::encode(&v).unwrap();
        let b = cbor::encode(&permute(&v)).unwrap();
        prop_assert_eq!(&a, &b);
        let d = cbor::decode(&a).unwrap();
        prop_assert_eq!(cbor::encode(&d).unwrap(), a);
    }

    // A byte string is accepted iff it is the canonical encoding of its value.
    #[test]
    fn decoder_accepts_only_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        if let Ok(v) = cbor::decode(&bytes) {
            prop_assert_eq!(cbor::encode(&v).unwrap(), bytes);
        }
    }
}

#[derive(Debug, Clone)]
enum Tamper {
    FlipBit { rec: usize, byte: usize, bit: u8 },
    Delete(usize),
    Swap(usize, usize),
    Duplicate(usize),
    Truncate(usize),
    DropCheckpoint(usize),
    SpliceForeign(usize),
}

fn arb_tamper() -> impl Strategy<Value = Tamper> {
    prop_oneof![
        (any::<usize>(), any::<usize>(), 0u8..8).prop_map(|(rec, byte, bit)| Tamper::FlipBit { rec, byte, bit }),
        any::<usize>().prop_map(Tamper::Delete),
        (any::<usize>(), any::<usize>()).prop_map(|(a, b)| Tamper::Swap(a, b)),
        any::<usize>().prop_map(Tamper::Duplicate),
        any::<usize>().prop_map(Tamper::Truncate),
        any::<usize>().prop_map(Tamper::DropCheckpoint),
        any::<usize>().prop_map(Tamper::SpliceForeign),
    ]
}

fn build(n: u8, every: u64, seed: u8) -> (Vec<ChainRecord>, Vec<candor_log::SignedCheckpoint>, ed25519_dalek::VerifyingKey) {
    let (mut log, sink, _c) = log_with(HostRole::Core, CheckpointPolicy::new(every, 300_000).unwrap());
    for i in 0..n {
        log.emit(
            EventContext::staff(user(seed)),
            AuditEvent::CaseOpened { case: CaseRef::from_bytes([i; 16]) },
        )
        .unwrap();
    }
    // Attest the tail so every record is covered by a signed checkpoint.
    log.checkpoint_now(StreamId::Case).unwrap();
    let st = sink.0.lock().unwrap();
    (st.chain(StreamId::Case), st.checkpoints(StreamId::Case), log.verifying_key())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]

    // Any tampering of a fully attested stream is detected.
    #[test]
    fn chain_verification_detects_random_tampering(
        n in 2u8..30,
        every in 1u64..8,
        t in arb_tamper(),
    ) {
        let (mut recs, mut cps, key) = build(n, every, 1);
        // The external witness holds the latest checkpoint (truncation defence, 20 §8).
        let witness = cps.last().cloned().unwrap();
        let p = VerifyParams {
            tenant: tenant(),
            stream: StreamId::Case,
            key: &key,
            trusted_latest: Some(&witness),
            allow_pruned_prefix: false,
        };
        prop_assert!(verify_stream(&p, &recs, &cps).is_ok());
        let len = recs.len();
        match t {
            Tamper::FlipBit { rec, byte, bit } => {
                let r = rec % len;
                let ChainRecord::Full { bytes, .. } = &mut recs[r] else { unreachable!() };
                let b = byte % bytes.len();
                bytes[b] ^= 1 << bit;
            }
            Tamper::Delete(i) => {
                recs.remove(i % len);
            }
            Tamper::Swap(a, b) => {
                let (a, b) = (a % len, b % len);
                let b = if a == b { (b + 1) % len } else { b };
                recs.swap(a, b);
            }
            Tamper::Duplicate(i) => {
                let i = i % len;
                let r = recs[i].clone();
                recs.insert(i, r);
            }
            Tamper::Truncate(k) => recs.truncate(k % len),
            Tamper::DropCheckpoint(i) => {
                cps.remove(i % cps.len());
            }
            Tamper::SpliceForeign(i) => {
                // Same position from an independently written chain (other actor).
                let (other, _, _) = build(n, every, 2);
                let i = i % len;
                recs[i] = other[i].clone();
            }
        }
        prop_assert!(verify_stream(&p, &recs, &cps).is_err());
    }
}
