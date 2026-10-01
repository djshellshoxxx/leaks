// SPDX-License-Identifier: AGPL-3.0-or-later
//! Session expiry and zeroization (ADR-034: 20 min idle / 2 h absolute; 07
//! BE-005, BE-055) and the no-disk-plaintext property (04 §9.13, 07 BE-055,
//! 08 API-039).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::path::Path;
use std::time::{Duration, SystemTime};

use candor_sealer::proto::*;
use common::*;

async fn stage(f: &Fixture, s: SessionHandle, data: &[u8], name: &str) {
    let Response::Part { part } = ok(
        &f.sealer,
        Request::PartBegin {
            sess: s,
            declared_len: data.len() as u64,
            display_name: SecretText::new(name),
            media_type: SecretText::new("text/plain"),
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

#[tokio::test(start_paused = true)]
async fn idle_and_absolute_expiry_zeroize_and_unlink() {
    let f = fixture();
    let s = sess(1);
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: s,
            channel_id: CHANNEL,
        },
    )
    .await;
    stage(&f, s, b"secret attachment", "a.txt").await;
    assert_eq!(read_all_files(&f.staging_path).len(), 1);
    // Activity resets the idle timer (SW-21).
    tokio::time::advance(Duration::from_secs(19 * 60)).await;
    ok(&f.sealer, Request::Touch { sess: s }).await;
    tokio::time::advance(Duration::from_secs(19 * 60)).await;
    ok(&f.sealer, Request::DraftGet { sess: s }).await;
    // 20 minutes idle: the reaper drops the session; Drop zeroizes K36 and the
    // draft and unlinks the staged ciphertext.
    tokio::time::advance(Duration::from_secs(20 * 60 + 1)).await;
    f.sealer.reap_expired();
    assert_eq!(f.sealer.session_count(), 0);
    assert!(read_all_files(&f.staging_path).is_empty());
    let r = f.sealer.handle(Request::DraftGet { sess: s }).await;
    assert_eq!(r, Response::error(ErrorCode::UnknownSession));

    // Absolute limit: 2 h even with continuous activity.
    let s2 = sess(2);
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: s2,
            channel_id: CHANNEL,
        },
    )
    .await;
    stage(&f, s2, b"x", "b.txt").await;
    for _ in 0..7 {
        tokio::time::advance(Duration::from_secs(15 * 60)).await;
        ok(&f.sealer, Request::Touch { sess: s2 }).await;
    }
    tokio::time::advance(Duration::from_secs(15 * 60)).await; // 2 h
    let r = f.sealer.handle(Request::Touch { sess: s2 }).await;
    assert_eq!(r, Response::error(ErrorCode::UnknownSession));
    assert!(read_all_files(&f.staging_path).is_empty());
}

#[tokio::test]
async fn zeroize_and_abort_drop_staged_parts() {
    let f = fixture();
    let s = sess(1);
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: s,
            channel_id: CHANNEL,
        },
    )
    .await;
    stage(&f, s, b"one", "1").await;
    stage(&f, s, b"two", "2").await;
    let Response::Draft(v) = ok(&f.sealer, Request::DraftGet { sess: s }).await else {
        panic!()
    };
    assert_eq!(v.parts.len(), 2);
    assert!(
        v.parts.iter().all(|p| p.size_bucket == 262_144),
        "bucket, not exact size"
    );
    ok(
        &f.sealer,
        Request::PartDrop {
            sess: s,
            part: v.parts[0].part,
        },
    )
    .await;
    assert_eq!(read_all_files(&f.staging_path).len(), 1);
    ok(&f.sealer, Request::SealAbort { sess: s }).await;
    assert!(read_all_files(&f.staging_path).is_empty());
    stage(&f, s, b"three", "3").await;
    ok(&f.sealer, Request::Zeroize { sess: s }).await;
    ok(&f.sealer, Request::Zeroize { sess: s }).await; // idempotent
    assert!(read_all_files(&f.staging_path).is_empty());
    assert_eq!(f.sealer.session_count(), 0);
}

fn scan_for(dir: &Path, needle: &[u8], since: SystemTime, all: bool) -> Vec<String> {
    let mut hits = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let listing = std::fs::read_dir(&d); // safefs-lint: allow(test scans tempdirs)
        let Ok(rd) = listing else { continue };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                if all {
                    stack.push(e.path());
                }
            } else if ft.is_file() {
                let fresh = e
                    .metadata()
                    .map(|m| m.len() < (64 << 20) && m.modified().is_ok_and(|t| t >= since))
                    .unwrap_or(false);
                // Staging files carry a day-start mtime, so the fixture's own
                // tempdir is scanned in full.
                let read = (fresh || all).then(|| std::fs::read(e.path())); // safefs-lint: allow(test scans tempdirs)
                if let Some(Ok(b)) = read
                    && contains(&b, needle)
                {
                    hits.push(e.path().display().to_string());
                }
            }
        }
    }
    hits
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_plaintext_reaches_disk() {
    let since = SystemTime::now() - Duration::from_secs(1);
    // A run-unique marker that occurs in no binary or source file.
    let mut r = [0u8; 12];
    candor_core::fill_random(&mut r).unwrap();
    let marker: String = r.iter().map(|b| format!("{b:02x}")).collect();
    let f = fixture();
    let s = sess(1);
    ok(
        &f.sealer,
        Request::SessionOpen {
            sess: s,
            channel_id: CHANNEL,
        },
    )
    .await;
    ok(
        &f.sealer,
        Request::DraftSet(DraftSet {
            sess: s,
            mode: Mode::Identified,
            message: SecretText::new(&marker),
            fields: vec![(1, SecretText::new(&marker))],
            identity: Some(SecretText::new(&marker)),
            coi: None,
        }),
    )
    .await;
    let big: Vec<u8> = marker.bytes().cycle().take(200_000).collect();
    stage(&f, s, &big, &marker).await;
    let check = |stage_name: &str| {
        let mut hits = scan_for(f.dir.path(), marker.as_bytes(), since, true);
        hits.extend(scan_for(
            &std::env::temp_dir(),
            marker.as_bytes(),
            since,
            false,
        ));
        assert!(
            hits.is_empty(),
            "plaintext on disk after {stage_name}: {hits:?}"
        );
    };
    check("draft and staging");
    let Response::Words {
        words,
        confirm_positions,
    } = ok(&f.sealer, Request::GenAccount { sess: s }).await
    else {
        panic!()
    };
    let phrase = words_to_phrase(&words);
    ok(
        &f.sealer,
        Request::ConfirmPassphrase {
            sess: s,
            words: confirm_words(&words, confirm_positions),
        },
    )
    .await;
    ok(
        &f.sealer,
        Request::SealFinish {
            sess: s,
            delayed_delivery: false,
        },
    )
    .await;
    check("seal");
    // Neither the marker nor the passphrase is in anything the store received.
    for env in f.sink.envelopes() {
        for o in &env.objects {
            assert!(!contains(&o.bytes, marker.as_bytes()));
            assert!(!contains(&o.bytes, phrase.as_bytes()));
        }
        let a = env.account.unwrap();
        assert!(!contains(&a.prefs_ct, marker.as_bytes()));
    }
    let hits = scan_for(f.dir.path(), phrase.as_bytes(), since, true);
    assert!(hits.is_empty(), "passphrase on disk: {hits:?}");
}
