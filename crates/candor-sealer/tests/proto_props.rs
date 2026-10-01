// SPDX-License-Identifier: AGPL-3.0-or-later
//! Property tests for the IPC decoder (07 BE-006; 27 ST-040/041 style): no
//! panics on arbitrary or mutated input, strict canonicity (anything that
//! decodes re-encodes to the identical bytes), and round trips.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use candor_sealer::proto::*;
use proptest::prelude::*;
use zeroize::Zeroizing;

const OPS: [Op; 21] = [
    Op::Hello,
    Op::SessionOpen,
    Op::DraftSet,
    Op::DraftGet,
    Op::GenAccount,
    Op::LoginDerive,
    Op::LoginSign,
    Op::LoadPrefs,
    Op::ConfirmPassphrase,
    Op::RotatePassphrase,
    Op::RotateFinish,
    Op::PartBegin,
    Op::PartChunk,
    Op::SealFinish,
    Op::SealAbort,
    Op::PartDrop,
    Op::NoteReal,
    Op::OpenReply,
    Op::Zeroize,
    Op::Touch,
    Op::Status,
];

fn arb_sess() -> impl Strategy<Value = SessionHandle> {
    any::<[u8; 16]>().prop_map(SessionHandle)
}

fn arb_text(max: usize) -> impl Strategy<Value = SecretText> {
    proptest::string::string_regex(&format!(".{{0,{max}}}"))
        .unwrap()
        .prop_filter("byte bound", move |s| s.len() <= max)
        .prop_map(|s| SecretText::new(&s))
}

fn sorted_unique(v: Vec<u16>, max: usize) -> Zeroizing<Vec<u16>> {
    let mut v = v;
    v.sort_unstable();
    v.dedup();
    v.truncate(max);
    Zeroizing::new(v)
}

fn arb_request() -> impl Strategy<Value = Request> {
    prop_oneof![
        any::<u64>().prop_map(|proto| Request::Hello { proto }),
        (arb_sess(), any::<[u8; 16]>())
            .prop_map(|(sess, channel_id)| Request::SessionOpen { sess, channel_id }),
        (
            arb_sess(),
            0u8..3,
            arb_text(200),
            proptest::collection::btree_map(any::<u16>(), arb_text(40), 0..8),
            proptest::option::of(arb_text(100)),
            proptest::option::of((
                proptest::collection::vec(any::<u16>(), 0..20),
                proptest::collection::vec(any::<u16>(), 0..10)
            )),
        )
            .prop_map(|(sess, mode, message, fields, identity, coi)| {
                Request::DraftSet(DraftSet {
                    sess,
                    mode: [Mode::Anonymous, Mode::Confidential, Mode::Identified]
                        [usize::from(mode)],
                    message,
                    fields: fields.into_iter().collect(),
                    identity,
                    coi: coi.map(|(l, c)| Coi {
                        excluded_labels: sorted_unique(l, MAX_COI_LABELS),
                        categories: sorted_unique(c, MAX_COI_CATEGORIES),
                    }),
                })
            }),
        (arb_sess(), proptest::collection::vec(any::<u8>(), 0..300)).prop_map(|(sess, p)| {
            Request::LoginDerive {
                sess,
                passphrase: SecretBytes::from_slice(&p[..p.len().min(256)]),
            }
        }),
        (arb_sess(), any::<[u8; 32]>())
            .prop_map(|(sess, challenge)| Request::LoginSign { sess, challenge }),
        (arb_sess(), proptest::collection::vec(any::<u16>(), 3)).prop_map(|(sess, w)| {
            Request::ConfirmPassphrase {
                sess,
                words: SecretWords(Zeroizing::new(w)),
            }
        }),
        (
            arb_sess(),
            proptest::collection::vec(
                (
                    any::<[u8; 32]>(),
                    proptest::collection::vec(any::<u8>(), 0..100)
                ),
                0..4
            )
        )
            .prop_map(|(sess, r)| Request::RotateFinish {
                sess,
                replies: r
                    .into_iter()
                    .map(|(object_hash, stanza)| PendingReply {
                        object_hash,
                        stanza
                    })
                    .collect(),
            }),
        (arb_sess(), any::<u64>(), arb_text(255), arb_text(127)).prop_map(
            |(sess, declared_len, display_name, media_type)| {
                Request::PartBegin {
                    sess,
                    declared_len,
                    display_name,
                    media_type,
                }
            }
        ),
        (
            arb_sess(),
            any::<[u8; 16]>(),
            proptest::collection::vec(any::<u8>(), 0..2000),
            any::<bool>()
        )
            .prop_map(|(sess, part, d, last)| Request::PartChunk {
                sess,
                part,
                data: SecretBytes::from_slice(&d),
                last
            }),
        (arb_sess(), any::<bool>()).prop_map(|(sess, delayed_delivery)| Request::SealFinish {
            sess,
            delayed_delivery
        }),
        (any::<[u8; 16]>(), any::<[u8; 32]>()).prop_map(|(channel_id, first_object_hash)| {
            Request::NoteReal {
                channel_id,
                first_object_hash,
            }
        }),
        (arb_sess(), proptest::collection::vec(any::<u8>(), 0..500))
            .prop_map(|(sess, entry)| Request::OpenReply { sess, entry }),
        arb_sess().prop_map(|sess| Request::Zeroize { sess }),
        Just(Request::Status),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn arbitrary_bytes_never_panic(b in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = decode_request(&b);
        for op in OPS {
            let _ = decode_response(op, &b);
        }
    }

    #[test]
    fn requests_round_trip(req in arb_request(), rid in any::<u32>()) {
        let b = encode_request(rid, &req).unwrap();
        let (r2, back) = decode_request(&b).unwrap();
        prop_assert_eq!(r2, rid);
        prop_assert_eq!(&back, &req);
    }

    /// Mutations either fail or decode to something whose canonical encoding is
    /// exactly the mutated input (no two encodings of one message are accepted).
    #[test]
    fn mutations_are_rejected_or_canonical(
        req in arb_request(),
        pos in any::<prop::sample::Index>(),
        byte in any::<u8>(),
        cut in any::<prop::sample::Index>(),
        mode in 0u8..3,
    ) {
        let mut b = encode_request(9, &req).unwrap().to_vec();
        match mode {
            0 => { let i = pos.index(b.len()); b[i] = byte; }
            1 => { let n = cut.index(b.len()); b.truncate(n); }
            _ => { let i = pos.index(b.len()); b.insert(i, byte); }
        }
        if let Ok((rid, decoded)) = decode_request(&b) {
            let again = encode_request(rid, &decoded).unwrap();
            prop_assert_eq!(&again[..], &b[..]);
        }
    }

    #[test]
    fn frame_length_bounds(n in any::<u32>()) {
        let r = frame_len(n.to_be_bytes());
        prop_assert_eq!(r.is_ok(), n >= 1 && n as usize <= MAX_FRAME_LEN);
    }
}

#[test]
fn responses_round_trip() {
    let cases = [
        (
            Op::Hello,
            Response::Hello {
                proto: 2,
                snapshot_version: 9,
            },
        ),
        (Op::Touch, Response::Empty),
        (
            Op::GenAccount,
            Response::Words {
                words: SecretWords(Zeroizing::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10])),
                confirm_positions: [0, 4, 9],
            },
        ),
        (
            Op::LoginDerive,
            Response::Locator {
                lookup_tag: [3; 32],
            },
        ),
        (Op::LoginSign, Response::Signature { sig: [4; 64] }),
        (
            Op::ConfirmPassphrase,
            Response::Confirm {
                ok: false,
                confirm_positions: Some([1, 2, 3]),
            },
        ),
        (
            Op::ConfirmPassphrase,
            Response::Confirm {
                ok: true,
                confirm_positions: None,
            },
        ),
        (Op::PartBegin, Response::Part { part: [5; 16] }),
        (
            Op::SealFinish,
            Response::Sealed {
                release_offset_days: 2,
            },
        ),
        (
            Op::NoteReal,
            Response::Disposition {
                disposition_ct: vec![6; 1168],
            },
        ),
        (Op::OpenReply, Response::Reply(None)),
        (
            Op::OpenReply,
            Response::Reply(Some(ReplyView {
                reply_seq: 3,
                day: 20_000,
                role_label: SecretText::new("Ombudsperson"),
                body: SecretText::new("hello"),
            })),
        ),
        (
            Op::Status,
            Response::Status {
                sessions_band: 1,
                argon_queue_band: 0,
                pool_free_band: 4,
            },
        ),
        (
            Op::SealFinish,
            Response::Error {
                code: ErrorCode::NoEligibleTriage,
                alternative_channel_id: Some([7; 16]),
            },
        ),
        (Op::DraftGet, Response::error(ErrorCode::UnknownSession)),
    ];
    for (op, resp) in cases {
        let b = encode_response(op, 77, &resp).unwrap();
        let (rid, back) = decode_response(op, &b).unwrap();
        assert_eq!(rid, 77);
        assert_eq!(back, resp);
    }
    // A response for another op is rejected.
    let b = encode_response(Op::Touch, 1, &Response::Empty).unwrap();
    assert_eq!(decode_response(Op::Status, &b), Err(ProtoError::Mismatch));
}

#[test]
fn draft_text_bound_is_enforced() {
    let s = SessionHandle([1; 16]);
    let big = "x".repeat(MAX_DRAFT_TEXT / 2 + 1);
    let req = Request::DraftSet(DraftSet {
        sess: s,
        mode: Mode::Anonymous,
        message: SecretText::new(&big),
        fields: vec![(1, SecretText::new(&big))],
        identity: None,
        coi: None,
    });
    let b = encode_request(1, &req).unwrap();
    assert!(decode_request(&b).is_err());
}
