// SPDX-License-Identifier: AGPL-3.0-or-later
//! AUD-RM2-SEA-01 / SEA-02 regression (the auditor's PoC, ADR-052(1)/(2)): real
//! envelope groups — maximal message, maximal identity block (CONFIDENTIAL),
//! follow-ups with and without attachments — are indistinguishable from chaff
//! by object count, object types and order, per-object size, total size,
//! account-record shape and the sequence of store operations. 04 §12.7,
//! ST-168, AT-087, IMPL-RM2 A12.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::collections::BTreeSet;

use candor_core::header::{CoreHeader, ObjectType};
use candor_core::{padding, stream};
use candor_sealer::proto::*;
use candor_sealer::server::{ChaffBuckets, ChaffConfig, Limits};
use common::*;

/// `(type, padded_plaintext_len, byte length)` of every object, in order.
fn shape(env: &StoredEnvelope) -> Vec<(ObjectType, u64, usize)> {
    env.objects
        .iter()
        .map(|o| {
            let h = CoreHeader::decode(&o.bytes[..128]).unwrap();
            assert_eq!(
                o.bytes.len() as u64,
                160 + stream::ciphertext_len(h.padded_plaintext_len).unwrap()
            );
            (h.object_type, h.padded_plaintext_len, o.bytes.len())
        })
        .collect()
}

fn total(env: &StoredEnvelope) -> usize {
    env.objects
        .iter()
        .map(|o| o.bytes.len() + o.slot_block.len())
        .sum()
}

async fn add_part(f: &Fixture, s: SessionHandle, data: &[u8]) {
    let Response::Part { part } = ok(
        &f.sealer,
        Request::PartBegin {
            sess: s,
            declared_len: data.len() as u64,
            display_name: SecretText::new("evidence.pdf"),
            media_type: SecretText::new("application/pdf"),
        },
    )
    .await
    else {
        panic!()
    };
    ok(
        &f.sealer,
        Request::PartChunk {
            sess: s,
            part,
            data: SecretBytes::from_slice(data),
            last: true,
        },
    )
    .await;
}

async fn seal(f: &Fixture, s: SessionHandle) {
    let r = f
        .sealer
        .handle(Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        })
        .await;
    assert!(matches!(r, Response::Sealed { .. }), "{r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_and_chaff_groups_are_indistinguishable_by_shape() {
    let f = fixture_with(
        ChaffConfig {
            enabled: false,
            followup_share_permille: 500,
            ..ChaffConfig::default()
        },
        Limits::default(),
    );
    let s = sess(1);
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: s,
            channel_id: CHANNEL,
        },
    )
    .await;
    // Maximal inputs: a 40 KiB message and a 4,090-byte identity block (the
    // PoC: 30,000 B → 32 KiB SUBMISSION, 4,090 B → 8 KiB IDENTITY before).
    ok(
        &f.sealer,
        Request::DraftSet(DraftSet {
            sess: s,
            mode: Mode::Confidential,
            message: SecretText::new(&"m".repeat(MAX_DRAFT_TEXT)),
            fields: vec![],
            identity: Some(SecretText::new(&"i".repeat(4090))),
            coi: None,
        }),
    )
    .await;
    let Response::Words {
        words,
        confirm_positions,
    } = ok(&f.sealer, Request::GenAccount { sess: s }).await
    else {
        panic!()
    };
    ok(
        &f.sealer,
        Request::ConfirmPassphrase {
            sess: s,
            words: confirm_words(&words, confirm_positions),
        },
    )
    .await;
    seal(&f, s).await;
    // Follow-up with an attachment (the PoC: 2 objects before) …
    let followup = |msg: &str| {
        Request::DraftSet(DraftSet {
            sess: s,
            mode: Mode::Anonymous,
            message: SecretText::new(msg),
            fields: vec![],
            identity: None,
            coi: None,
        })
    };
    ok(&f.sealer, followup(&"f".repeat(MAX_DRAFT_TEXT))).await;
    add_part(&f, s, &[7u8; 10_000]).await;
    seal(&f, s).await;
    // … and one without.
    ok(&f.sealer, followup("short")).await;
    seal(&f, s).await;
    let real_ops = f.sink.ops();
    assert_eq!(real_ops, "AGGG", "real: account, then one group each");
    let real = f.sink.envelopes();
    assert_eq!(real.len(), 3);

    // Chaff: enough events for both shapes.
    for _ in 0..40 {
        f.sealer.chaff_event(CHANNEL).await.unwrap();
    }
    let all = f.sink.envelopes();
    let chaff = &all[3..];
    let buckets = ChaffBuckets::default();

    let mut chaff_shapes = BTreeSet::new();
    let mut chaff_main_types = BTreeSet::new();
    for c in chaff {
        let sh = shape(c);
        assert_eq!(sh.len(), 3);
        assert!(buckets.supports(sh[1].1));
        chaff_main_types.insert(format!("{:?}", sh[0].0));
        chaff_shapes.insert(format!("{:?}", (sh[0], sh[2])));
    }
    assert_eq!(chaff_main_types.len(), 2, "both chaff shapes drawn");

    for r in &real {
        let sh = shape(r);
        // Object count and order.
        assert_eq!(
            sh.iter().map(|o| o.0).collect::<Vec<_>>()[1..],
            [ObjectType::AttachmentBundle, ObjectType::Identity]
        );
        // Main and identity objects: one fixed size each, as in chaff.
        assert_eq!(sh[0].1, padding::MESSAGE_MAX);
        assert_eq!(sh[2].1, padding::IDENTITY_MAX);
        assert!(
            chaff_shapes.contains(&format!("{:?}", (sh[0], sh[2]))),
            "real main/identity shape outside the chaff support"
        );
        // Bundle bucket in the chaff support.
        assert!(buckets.supports(sh[1].1), "bundle {} not in chaff support", sh[1].1);
        // Total size equals that of a chaff group with the same bundle bucket.
        let twin = chaff
            .iter()
            .find(|c| {
                let cs = shape(c);
                cs[0].0 == sh[0].0 && cs[1].1 == sh[1].1
            })
            .map(total);
        if let Some(t) = twin {
            assert_eq!(total(r), t);
        }
        let expected: usize = sh.iter().map(|o| o.2 + 18_692).sum();
        assert_eq!(total(r), expected);
    }

    // Account records: real and dummy are the same shape.
    let accts = f.sink.accounts();
    let real_acct = &accts[0];
    assert!(accts.len() > 1, "initial-shaped chaff writes dummy accounts");
    for a in &accts[1..] {
        assert_eq!(a.account.prefs_ct.len(), real_acct.account.prefs_ct.len());
        assert_eq!(a.account.mailbox_ids.len(), real_acct.account.mailbox_ids.len());
        assert!(a.replaces.is_none());
    }
    // Op sequence: chaff 'A' precedes exactly the SUBMISSION-shaped groups.
    let ops: Vec<char> = f.sink.ops().chars().skip(real_ops.len()).collect();
    let mut i = 0;
    for c in chaff {
        if shape(c)[0].0 == ObjectType::Submission {
            assert_eq!(ops[i], 'A');
            i += 1;
        }
        assert_eq!(ops[i], 'G');
        i += 1;
    }
    assert_eq!(i, ops.len());
}
