// SPDX-License-Identifier: AGPL-3.0-or-later
//! Seed corpus for `fuzz_sealer_ipc` (AUD-RM2-SEA-23): canonical encodings of
//! every request type (decoder mode), a framed Tier W flow (raw-frame mode)
//! and deterministic byte strings for the structure-aware modes. Run from
//! `crates/candor-sealer/fuzz`; writes `seeds/fuzz_sealer_ipc/`.

use candor_sealer::proto::{
    Coi, DraftSet, Mode, PendingReply, Request, SecretBytes, SecretText, SecretWords,
    SessionHandle, encode_request, frame,
};

fn requests() -> Vec<Request> {
    let s = SessionHandle([1; 16]);
    vec![
        Request::Hello { proto: 1 },
        Request::SessionOpen { sess: s, channel_id: [0x22; 16] },
        Request::DraftSet(DraftSet {
            sess: s,
            mode: Mode::Confidential,
            message: SecretText::new("report \u{0958}e\u{0301}"),
            fields: vec![(1, SecretText::new("answer"))],
            identity: Some(SecretText::new("name")),
            coi: Some(Coi {
                excluded_labels: zeroize::Zeroizing::new(vec![3]),
                categories: zeroize::Zeroizing::new(vec![7]),
            }),
        }),
        Request::DraftGet { sess: s },
        Request::GenAccount { sess: s },
        Request::ConfirmPassphrase { sess: s, words: SecretWords(zeroize::Zeroizing::new(vec![1, 2, 3])) },
        Request::PartBegin {
            sess: s,
            declared_len: 10,
            display_name: SecretText::new("a.txt"),
            media_type: SecretText::new("text/plain"),
        },
        Request::PartChunk { sess: s, part: [9; 16], data: SecretBytes::from_slice(b"0123456789"), last: true },
        Request::PartDrop { sess: s, part: [9; 16] },
        Request::SealFinish { sess: s, delayed_delivery: true },
        Request::SealAbort { sess: s },
        Request::LoginDerive { sess: s, passphrase: SecretBytes::from_slice(b"alpha beta gamma") },
        Request::LoginSign { sess: s, challenge: [7; 32] },
        Request::LoadPrefs { sess: s, prefs_ct: vec![0; 48] },
        Request::RotatePassphrase { sess: s },
        Request::RotateFinish { sess: s, replies: vec![PendingReply { object_hash: [5; 32], stanza: vec![1, 2, 3] }] },
        Request::OpenReply { sess: s, entry: vec![0, 0, 0, 4, 1, 2, 3, 4] },
        Request::NoteReal { channel_id: [0x22; 16], first_object_hash: [6; 32] },
        Request::Zeroize { sess: s },
        Request::Touch { sess: s },
        Request::Status,
    ]
}

#[allow(clippy::disallowed_methods)] // safefs-lint: allow(fuzz seed generator writes its own corpus dir)
fn main() {
    let dir = std::path::Path::new("seeds/fuzz_sealer_ipc");
    std::fs::create_dir_all(dir).unwrap();
    let mut n = 0u32;
    let mut put = |bytes: Vec<u8>| {
        std::fs::write(dir.join(format!("seed-{n:03}")), bytes).unwrap();
        n += 1;
    };
    let reqs = requests();
    // Mode 0: one canonical request each.
    for (i, r) in reqs.iter().enumerate() {
        let mut v = vec![0u8];
        v.extend_from_slice(&encode_request(i as u32, r).unwrap());
        put(v);
    }
    // Mode 1: the whole flow as length-prefixed frames, and per-prefix flows.
    for upto in [3usize, 6, 9, reqs.len()] {
        let mut v = vec![1u8];
        for (i, r) in reqs.iter().take(upto).enumerate() {
            v.extend_from_slice(&frame(&encode_request(i as u32, r).unwrap()).unwrap());
        }
        put(v);
    }
    // Modes 2 and 3: deterministic pseudo-random driver bytes.
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for k in 0..48u32 {
        let len = 16 + (k as usize * 37) % 600;
        let mut v = vec![if k % 3 == 0 { 3u8 } else { 2u8 }];
        for _ in 0..len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            v.push((x >> 24) as u8);
        }
        put(v);
    }
}
