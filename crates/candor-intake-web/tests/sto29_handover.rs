// SPDX-License-Identifier: AGPL-3.0-or-later
//! C-5 / AUD-RM2-STO-29: the sealer's `handover::StoreConnection::hand_over`
//! reaching the store's `StagedReceiver` over a real `SOCK_SEQPACKET` pair
//! (`SCM_RIGHTS`), both crates' production code on both ends:
//! copy → `0x02 ‖ h` → envelope commit → `0x01 ‖ h`; a refused commit fails
//! the hand-over; both sides share one bundle-size cap.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    // Test fixture only: a private 0700 temp root for candor-safefs.
    clippy::disallowed_methods
)]

use std::os::fd::{AsFd, OwnedFd};
use std::time::Duration;

use candor_intake_store::staged::{STAGED_BUNDLE_INDEX, STAGED_MAX_BUNDLE_LEN, StagedReceiver};
use candor_intake_store::*;
use candor_safefs::{RootPolicy, SafeRoot, SlotTime};
use candor_sealer::server::handover::{MAX_BUNDLE_LEN, StoreConnection, VERSION};
use candor_sealer::server::sink::{SinkError, StagedBundle};
use rustix::net::{AddressFamily, SocketFlags, SocketType};

fn pair() -> (OwnedFd, OwnedFd) {
    rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap()
}

fn my_uid() -> u32 {
    let (a, _b) = pair();
    rustix::net::sockopt::socket_peercred(&a)
        .unwrap()
        .uid
        .as_raw()
}

fn receiver(tmp: &tempfile::TempDir) -> StagedReceiver {
    use std::os::unix::fs::DirBuilderExt;
    let base = std::fs::canonicalize(tmp.path()).unwrap(); // safefs-lint: allow(test blob root in own tempdir)
    let p = base.join("blobs"); // safefs-lint: allow(test blob root in own tempdir)
    std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap(); // safefs-lint: allow(test blob root in own tempdir)
    let root = SafeRoot::open(&p, RootPolicy::BlobStore).unwrap();
    StagedReceiver::new(root, my_uid(), u64::MAX)
        .unwrap()
        .with_timeout(Duration::from_secs(5))
}

fn object(size: u64, tag: u8) -> GroupObject {
    let mut blob = [tag; 16];
    blob[0] = 0x42;
    GroupObject {
        object_hash: [tag; 32],
        slot_block: vec![0x5b; SLOT_BLOCK_LEN_STD],
        blob: PartRef {
            blob_id: BlobId(blob),
            padded_size: size,
        },
    }
}

fn envelope(blob_id: BlobId, len: u64, tag: u8) -> CommitEnvelope {
    let mut objects = [
        object(65_536, tag),
        object(len, tag ^ 1),
        object(65_536, tag ^ 2),
    ];
    objects[STAGED_BUNDLE_INDEX].blob = PartRef {
        blob_id,
        padded_size: len,
    };
    CommitEnvelope {
        channel_id: ChannelId([0xc1; 16]),
        objects,
        disposition_ct: vec![0xd0; DISPOSITION_CT_LEN_STD],
        epoch_index: 2963,
        received_date: Day(20_741),
        release_offset_days: 0,
    }
}

async fn store() -> MemoryStore {
    let s = MemoryStore::new().unwrap();
    s.init(TenantId([0x11; 16]), [0x5a; 32]).await.unwrap();
    s
}

fn slot() -> SlotTime {
    SlotTime::from_unix_secs(1_790_000_100).unwrap()
}

/// The full seal-path hand-over: Ok only after the store committed the
/// envelope that references exactly the copied bundle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sealer_hand_over_reaches_the_store() {
    let tmp = tempfile::tempdir().unwrap();
    let rx = receiver(&tmp);
    let s = store().await;
    let data: Vec<u8> = (0..262_144u32).map(|i| (i % 253) as u8).collect();
    let bundle = StagedBundle::from_bytes(&data).unwrap();
    assert_eq!(VERSION, 2);
    let (sealer_end, store_end) = pair();
    let sealer = std::thread::spawn(move || {
        let mut conn = StoreConnection::new(sealer_end);
        let r = conn.hand_over(&bundle);
        (r, conn.is_open())
    });
    let blob = rx.receive(store_end.as_fd(), slot()).unwrap();
    assert_eq!(blob.len(), data.len() as u64);
    let env = envelope(blob.blob_id(), blob.len(), 7);
    let c = rx.commit_staged(&s, env, blob).await.unwrap();
    rx.acknowledge(store_end.as_fd(), c).unwrap();
    let (r, open) = sealer.join().unwrap();
    assert_eq!(r, Ok(()));
    assert!(open);
    assert_eq!(s.pending_count().await.unwrap(), 1);
}

/// A commit refused after the copy (a different bundle claiming an already
/// committed group): the store answers `0x00`, the sealer reports failure
/// and closes the connection; the orphan copy is swept at the next slot.
/// (Re-sending the *same* bundle is an idempotent success, see
/// `late_commit_then_retry_is_one_envelope_and_success`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_commit_fails_the_hand_over() {
    let tmp = tempfile::tempdir().unwrap();
    let rx = receiver(&tmp);
    let s = store().await;
    // First, a committed group.
    let data = vec![1u8; 262_144];
    let (a, b) = pair();
    let bundle = StagedBundle::from_bytes(&data).unwrap();
    let t = std::thread::spawn(move || StoreConnection::new(a).hand_over(&bundle));
    let blob = rx.receive(b.as_fd(), slot()).unwrap();
    let env = envelope(blob.blob_id(), blob.len(), 9);
    let c = rx.commit_staged(&s, env.clone(), blob).await.unwrap();
    rx.acknowledge(b.as_fd(), c).unwrap();
    assert_eq!(t.join().unwrap(), Ok(()));
    // The same group with different bundle bytes: refused.
    let (a, b) = pair();
    let bundle = StagedBundle::from_bytes(&vec![2u8; 262_144]).unwrap();
    let t = std::thread::spawn(move || {
        let mut conn = StoreConnection::new(a);
        let r = conn.hand_over(&bundle);
        (r, conn.is_open())
    });
    let blob = rx.receive(b.as_fd(), slot()).unwrap();
    let mut env2 = env;
    env2.objects[STAGED_BUNDLE_INDEX].blob = PartRef {
        blob_id: blob.blob_id(),
        padded_size: blob.len(),
    };
    assert!(rx.commit_staged(&s, env2, blob).await.is_err());
    rx.refuse(b.as_fd()).unwrap();
    let (r, open) = t.join().unwrap();
    assert_eq!(r, Err(SinkError));
    assert!(!open, "closed after a refusal");
    let next = SlotTime::from_unix_secs(1_790_000_100 + 3600).unwrap();
    assert_eq!(rx.sweep(&s, next).await.unwrap(), 1, "orphan copy swept");
}

/// STO-29: one bundle-size cap for both sides.
#[test]
fn one_cap_on_both_sides() {
    assert_eq!(MAX_BUNDLE_LEN, STAGED_MAX_BUNDLE_LEN);
    assert!(StagedBundle::from_bytes(&[]).is_err());
}

/// AUD-RM2-SEA-01: the store commits after the sealer gave up (the commit
/// lands just past the sealer's deadline). The sealer's retry on a fresh
/// connection hands the same bundle over again; the store recognises the
/// committed group and answers `0x02 ‖ h`, `0x01 ‖ h`. Result: exactly one
/// envelope, and success; the duplicate copy is swept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_commit_then_retry_is_one_envelope_and_success() {
    let tmp = tempfile::tempdir().unwrap();
    let rx = receiver(&tmp);
    let s = store().await;
    let data: Vec<u8> = (0..131_072u32).map(|i| (i % 251) as u8).collect();
    let bundle = StagedBundle::from_bytes(&data).unwrap();
    let (a1, b1) = pair();
    let (a2, b2) = pair();
    let deadline = Duration::from_millis(300);
    let sealer = std::thread::spawn(move || {
        let mut conn = StoreConnection::with_ack_timeout(a1, deadline);
        conn.hand_over_with_retry(&bundle, move || Ok(a2))
    });
    // First hand-over: copied (0x02), then the commit is slow.
    let blob = rx.receive(b1.as_fd(), slot()).unwrap();
    let env = envelope(blob.blob_id(), blob.len(), 21);
    tokio::time::sleep(deadline * 2).await;
    // The commit lands after the sealer's deadline; its ack finds the
    // sealer gone (an error or a write into a dead socket).
    let c = rx.commit_staged(&s, env.clone(), blob).await.unwrap();
    let _ = rx.acknowledge(b1.as_fd(), c);
    assert_eq!(s.pending_count().await.unwrap(), 1);
    // The retry: same bundle, fresh connection.
    let blob2 = rx.receive(b2.as_fd(), slot()).unwrap();
    let mut env2 = env;
    env2.objects[STAGED_BUNDLE_INDEX].blob = PartRef {
        blob_id: blob2.blob_id(),
        padded_size: blob2.len(),
    };
    let c2 = rx.commit_staged(&s, env2, blob2).await.unwrap();
    assert!(c2.replayed(), "recognised as the committed group");
    rx.acknowledge(b2.as_fd(), c2).unwrap();
    assert_eq!(sealer.join().unwrap(), Ok(()), "reported as success");
    assert_eq!(s.pending_count().await.unwrap(), 1, "no double commit");
    let next = SlotTime::from_unix_secs(1_790_000_100 + 3600).unwrap();
    assert_eq!(
        rx.sweep(&s, next).await.unwrap(),
        1,
        "the retry's copy is swept"
    );
}
