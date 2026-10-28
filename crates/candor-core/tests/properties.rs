// SPDX-License-Identifier: Apache-2.0 OR MIT
//! ST-024 / ST-025 property tests over the public sealed-object API: round trip for
//! random sizes; any single-bit flip of the blob, truncation or extension is rejected.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use candor_core::Suite;
use candor_core::hash::{KeyKind, key_id};
use candor_core::header::ObjectType;
use candor_core::kem::KemKeyPair;
use candor_core::object::{SealRequest, parse, seal, seal_bytes};
use candor_core::padding::pad;
use candor_core::slots::SlotContext;
use proptest::prelude::*;
use std::sync::OnceLock;

fn reply_req(pt: &[u8]) -> SealRequest<'_> {
    SealRequest {
        suite: Suite::CandorStd1,
        object_type: ObjectType::Reply,
        tenant_id: [1; 16],
        channel_id: [0; 16],
        epoch_id: 0,
        day_stamp: 0,
        recipients: None,
        padded_len: pt.len() as u64,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn reply_roundtrip_and_any_bitflip_rejected(content in proptest::collection::vec(any::<u8>(), 0..20_000), bit in any::<usize>()) {
        let pt = pad(ObjectType::Reply, &content).unwrap();
        let (ck, obj) = seal_bytes(&reply_req(&pt), &pt).unwrap();
        let back = parse(&obj.bytes).unwrap().open(&ck).unwrap();
        prop_assert_eq!(&back[..content.len()], content.as_slice());
        let mut bad = obj.bytes.clone();
        let b = bit % (bad.len() * 8);
        bad[b / 8] ^= 1 << (b % 8);
        // Either the structural parse or authentication must fail.
        let r = parse(&bad).and_then(|p| p.open(&ck).map(|_| ()));
        prop_assert!(r.is_err());
    }

    #[test]
    fn truncation_and_extension_rejected(cut in 1usize..200, ext in proptest::collection::vec(any::<u8>(), 1..20)) {
        let pt = pad(ObjectType::Reply, b"x").unwrap();
        let (_ck, obj) = seal_bytes(&reply_req(&pt), &pt).unwrap();
        let cut = cut.min(obj.bytes.len());
        prop_assert!(parse(&obj.bytes[..obj.bytes.len() - cut]).is_err());
        let mut long = obj.bytes.clone();
        long.extend_from_slice(&ext);
        prop_assert!(parse(&long).is_err());
    }

    /// Arbitrary bytes never parse into an openable object and never panic.
    #[test]
    fn arbitrary_blob(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        let _ = parse(&bytes);
    }
}

fn member() -> &'static KemKeyPair {
    static M: OnceLock<KemKeyPair> = OnceLock::new();
    M.get_or_init(|| KemKeyPair::generate(Suite::CandorStd1).unwrap())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    /// ST-025 context binding: an intake object opened with a different tenant,
    /// channel or epoch in the slot context fails.
    #[test]
    fn intake_context_binding(epoch in 0u32..1000, which in 0usize..3) {
        let ctx = SlotContext::MemberEpoch { tenant_id: [1; 16], channel_id: [2; 16], epoch_id: epoch };
        let pt = pad(ObjectType::SourceMessage, b"msg").unwrap();
        let pks = [member().public.clone()];
        let req = SealRequest {
            suite: Suite::CandorStd1,
            object_type: ObjectType::SourceMessage,
            tenant_id: [1; 16],
            channel_id: [2; 16],
            epoch_id: epoch,
            day_stamp: 0,
            recipients: Some((ctx.clone(), &pks)),
            padded_len: pt.len() as u64,
        };
        prop_assert!(seal_bytes(&req, &pt).is_err(), "intake objects must use seal()");
        let (secrets, obj) = seal(&req, |_| Ok(pt.clone())).unwrap();
        let list = secrets.recipient_list();
        let p = parse(&obj.bytes).unwrap();
        let blk = obj.slot_block.unwrap();
        let (ck, pos) = blk.trial_open(&member().private, &p.slot_binding(ctx.clone())).unwrap();
        prop_assert_eq!(usize::from(list.as_slice()[0].slot_index()), pos);
        let dir = |kid: &[u8; 32]| {
            (key_id(Suite::CandorStd1, KeyKind::Mek, &member().public.to_bytes()) == *kid)
                .then(|| member().public.clone())
        };
        prop_assert_eq!(p.slot_binding_from_header().unwrap(), p.slot_binding(ctx.clone()));
        blk.verify_slot_block(&ck, &p.slot_binding(ctx.clone()), list.as_slice(), dir)
            .unwrap();
        let wrong = match which {
            0 => SlotContext::MemberEpoch { tenant_id: [9; 16], channel_id: [2; 16], epoch_id: epoch },
            1 => SlotContext::MemberEpoch { tenant_id: [1; 16], channel_id: [9; 16], epoch_id: epoch },
            _ => SlotContext::MemberEpoch { tenant_id: [1; 16], channel_id: [2; 16], epoch_id: epoch.wrapping_add(1) },
        };
        prop_assert!(blk.trial_open(&member().private, &p.slot_binding(wrong)).is_err());
    }
}
