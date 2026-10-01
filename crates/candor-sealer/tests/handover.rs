// SPDX-License-Identifier: AGPL-3.0-or-later
//! Staged-bundle hand-over to the Intake Store (deploy D-33, AUD-RM2-SEA-16):
//! the sealed bundle is an immutable anonymous file passed as a descriptor
//! over a SEQPACKET socketpair (`SCM_RIGHTS`, safe rustix API), with the
//! 41-byte header of `candor-intake-store::staged`; `Ok` only on the store's
//! two acknowledgements `0x02 ‖ h` (copied, length-scaled deadline) and
//! `0x01 ‖ h` (committed, 60 s), both echoing the bundle hash
//! (AUD-RM2-STO-29). The "store" here is a minimal receiver that checks what
//! the real one checks.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};

use candor_core::header::ObjectType;
use candor_sealer::server::handover::{
    ACK_COMMITTED, ACK_COPIED, ACK_LEN, ACK_REFUSED, MAX_BUNDLE_LEN, MSG_LEN, StoreConnection,
    VERSION, copy_deadline, encode_ack,
};
use candor_sealer::server::sink::{Blob, EnvelopeGroup, EnvelopeObject, SinkError, StagedBundle};
use candor_sealer::server::{ChaffConfig, Limits};
use common::*;
use rustix::fs::SealFlags; // safefs-lint: allow(memfd seal flags)
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendFlags, SocketFlags, SocketType,
};

fn pair() -> (OwnedFd, OwnedFd) {
    rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap()
}

/// A sealed bundle produced by the sealer (one chaff event).
async fn bundle() -> (Fixture, StagedBundle) {
    let f = fixture_with(
        ChaffConfig {
            enabled: false,
            followup_share_permille: 0,
            dummy_rotation_permille: 0,
            ..ChaffConfig::default()
        },
        Limits::default(),
    );
    f.sealer.chaff_event(CHANNEL).await.unwrap();
    let b = f.sink.bundles.lock().unwrap()[0].clone();
    (f, b)
}

/// The store side: receive one message, check it like
/// `candor-intake-store::staged::receive_staged_bundle`, return the bytes.
fn receive(sock: &OwnedFd) -> ([u8; MSG_LEN], usize, Vec<OwnedFd>) {
    let mut data = [0u8; MSG_LEN + 1];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(4))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = rustix::net::recvmsg(
        sock,
        &mut [IoSliceMut::new(&mut data)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    )
    .unwrap();
    let mut fds = Vec::new();
    for m in control.drain() {
        if let RecvAncillaryMessage::ScmRights(it) = m {
            fds.extend(it);
        }
    }
    let mut hdr = [0u8; MSG_LEN];
    hdr.copy_from_slice(&data[..MSG_LEN]);
    (hdr, msg.bytes, fds)
}

fn reply(sock: &OwnedFd, b: &[u8], with_fd: Option<&OwnedFd>) {
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let fds;
    if let Some(fd) = with_fd {
        fds = [fd.as_fd()];
        assert!(control.push(rustix::net::SendAncillaryMessage::ScmRights(&fds)));
    }
    rustix::net::sendmsg(sock, &[IoSlice::new(b)], &mut control, SendFlags::NOSIGNAL).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bundle_is_handed_over_as_a_sealed_descriptor() {
    let (_f, b) = bundle().await;
    let (sealer_end, store_end) = pair();
    let expect_len = b.len();
    let expect_hash = b.sha256();
    let store = std::thread::spawn(move || {
        let (hdr, n, mut fds) = receive(&store_end);
        assert_eq!(n, MSG_LEN);
        assert_eq!(hdr[0], VERSION);
        assert_eq!(
            u64::from_be_bytes(hdr[1..9].try_into().unwrap()),
            expect_len
        );
        assert_eq!(&hdr[9..], &expect_hash);
        assert_eq!(fds.len(), 1, "exactly one descriptor");
        let fd = fds.pop().unwrap();
        // A regular file of exactly the announced size…
        let st = rustix::fs::fstat(&fd).unwrap(); // safefs-lint: allow(fstat of a passed fd)
        use rustix::fs::FileType; // safefs-lint: allow(file type of a passed fd)
        let regular = FileType::from_raw_mode(st.st_mode) == FileType::RegularFile;
        assert!(regular);
        assert_eq!(st.st_size as u64, expect_len);
        // …sealed against any change by either side…
        let seals = rustix::fs::fcntl_get_seals(&fd).unwrap(); // safefs-lint: allow(fd seals)
        let all = SealFlags::WRITE
            | SealFlags::GROW
            | SealFlags::SHRINK
            | SealFlags::EXEC
            | SealFlags::SEAL;
        assert!(seals.contains(all));
        // DEP-29: not executable, and it cannot be made executable.
        assert_eq!(st.st_mode & 0o111, 0, "memfd has exec bits");
        let chmod = rustix::fs::fchmod(&fd, rustix::fs::Mode::RWXU); // safefs-lint: allow(fd-only probe)
        assert!(chmod.is_err(), "exec seal must refuse chmod +x");
        assert!(rustix::io::pwrite(&fd, b"x", 0).is_err());
        let trunc = rustix::fs::ftruncate(&fd, 0); // safefs-lint: allow(fd-only probe)
        assert!(trunc.is_err());
        // …whose bytes hash to the header value.
        let mut buf = vec![0u8; expect_len as usize];
        let mut off = 0;
        while off < buf.len() {
            let k = rustix::io::pread(&fd, &mut buf[off..], off as u64).unwrap();
            assert!(k > 0);
            off += k;
        }
        assert_eq!(candor_core::hash::sha256(&[&buf]), expect_hash);
        reply(&store_end, &encode_ack(ACK_COPIED, &expect_hash), None);
        reply(&store_end, &encode_ack(ACK_COMMITTED, &expect_hash), None);
        buf
    });
    let mut conn = StoreConnection::new(sealer_end);
    conn.hand_over(&b).unwrap();
    assert!(conn.is_open());
    let bytes = store.join().unwrap();
    assert_eq!(bytes, b.read_to_vec().unwrap());
    // The bundle starts with a CoreHeader of an ATTACHMENT_BUNDLE.
    assert_eq!(bytes.len() as u64, b.len());
}

/// Run one hand-over against a scripted store that answers `answers` (each a
/// separate SEQPACKET message) after receiving the bundle.
fn scripted(b: &StagedBundle, answers: Vec<Vec<u8>>) -> Result<(), SinkError> {
    let (s, st) = pair();
    let t = std::thread::spawn(move || {
        let _ = receive(&st);
        for a in answers {
            reply(&st, &a, None);
        }
        // Keep the socket open until the sealer side is done.
        let mut b = [0u8; 1];
        let _ = rustix::net::recv(&st, &mut b, rustix::net::RecvFlags::empty());
    });
    let mut conn = StoreConnection::with_ack_timeout(s, std::time::Duration::from_millis(300));
    let r = conn.hand_over(b);
    if r.is_err() {
        assert!(!conn.is_open(), "closed after a failure");
    }
    drop(conn);
    t.join().unwrap();
    r
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hand_over_fails_closed_without_a_commit_ack() {
    let (_f, b) = bundle().await;
    let h = b.sha256();
    let copied = encode_ack(ACK_COPIED, &h).to_vec();
    let committed = encode_ack(ACK_COMMITTED, &h).to_vec();
    // The well-formed exchange succeeds.
    assert_eq!(
        scripted(&b, vec![copied.clone(), committed.clone()]),
        Ok(())
    );
    // Refused, before or after the copy.
    let refused = encode_ack(ACK_REFUSED, &h).to_vec();
    assert_eq!(scripted(&b, vec![refused.clone()]), Err(SinkError));
    assert_eq!(scripted(&b, vec![copied.clone(), refused]), Err(SinkError));
    // STO-29: the commit ack without the copied ack first.
    assert_eq!(scripted(&b, vec![committed.clone()]), Err(SinkError));
    // STO-29: the copied ack twice (no commit).
    assert_eq!(
        scripted(&b, vec![copied.clone(), copied.clone()]),
        Err(SinkError)
    );
    // STO-29 hash echo: an ack for another bundle is refused in either phase.
    let mut other = h;
    other[0] ^= 1;
    assert_eq!(
        scripted(
            &b,
            vec![encode_ack(ACK_COPIED, &other).to_vec(), committed.clone()]
        ),
        Err(SinkError)
    );
    assert_eq!(
        scripted(
            &b,
            vec![copied.clone(), encode_ack(ACK_COMMITTED, &other).to_vec()]
        ),
        Err(SinkError)
    );
    // Old one-byte acks (protocol 1), an unknown code, short and long acks.
    assert_eq!(scripted(&b, vec![vec![ACK_COMMITTED]]), Err(SinkError));
    assert_eq!(
        scripted(&b, vec![encode_ack(0x03, &h).to_vec()]),
        Err(SinkError)
    );
    assert_eq!(
        scripted(&b, vec![copied[..ACK_LEN - 1].to_vec()]),
        Err(SinkError)
    );
    let mut long = committed.clone();
    long.push(0);
    assert_eq!(scripted(&b, vec![copied.clone(), long]), Err(SinkError));
    // A descriptor sent back with an ack is refused (and closed).
    let (s, st) = pair();
    let (c2, k2) = (copied.clone(), committed.clone());
    let t = std::thread::spawn(move || {
        let (_, _, fds) = receive(&st);
        reply(&st, &c2, fds.first());
        reply(&st, &k2, None);
    });
    let mut conn = StoreConnection::new(s);
    assert_eq!(conn.hand_over(&b), Err(SinkError));
    assert!(!conn.is_open());
    assert_eq!(
        conn.hand_over(&b),
        Err(SinkError),
        "closed connection refuses"
    );
    t.join().unwrap();
    // The store goes away without answering.
    let (s, st) = pair();
    let t = std::thread::spawn(move || {
        let _ = receive(&st);
        drop(st);
    });
    assert_eq!(StoreConnection::new(s).hand_over(&b), Err(SinkError));
    t.join().unwrap();
    // A store that never reports the copy: bounded by the copy deadline
    // (base 200 ms + the length term of a small bundle, 1 s), then closed —
    // a late ack can never be credited to the next bundle.
    let (s, st) = pair();
    let t = std::thread::spawn(move || {
        let _ = receive(&st);
        std::thread::sleep(std::time::Duration::from_millis(1_600));
        let late = rustix::net::send(&st, &copied, SendFlags::NOSIGNAL);
        assert!(late.is_err(), "late ack must not reach an open socket");
    });
    let mut conn = StoreConnection::with_ack_timeout(s, std::time::Duration::from_millis(200));
    let start = std::time::Instant::now();
    assert_eq!(conn.hand_over(&b), Err(SinkError));
    assert!(start.elapsed() < std::time::Duration::from_millis(1_500));
    assert!(!conn.is_open());
    t.join().unwrap();
    // A store that copies but never commits: bounded by the commit deadline.
    let (s, st) = pair();
    let c3 = encode_ack(ACK_COPIED, &h).to_vec();
    let t = std::thread::spawn(move || {
        let _ = receive(&st);
        reply(&st, &c3, None);
        std::thread::sleep(std::time::Duration::from_millis(2_000));
        let late = rustix::net::send(&st, &committed, SendFlags::NOSIGNAL);
        assert!(
            late.is_err(),
            "late commit ack must not reach an open socket"
        );
    });
    let mut conn = StoreConnection::with_ack_timeout(s, std::time::Duration::from_millis(200));
    let start = std::time::Instant::now();
    assert_eq!(conn.hand_over(&b), Err(SinkError));
    // copy phase answered at once; commit phase bounded by 200 ms.
    assert!(start.elapsed() < std::time::Duration::from_millis(1_500));
    t.join().unwrap();
    // Peer already closed: the send itself fails (no SIGPIPE).
    let (s, st) = pair();
    drop(st);
    assert_eq!(StoreConnection::new(s).hand_over(&b), Err(SinkError));
}

/// AUD-RM2-STO-29: the copy deadline is length-scaled (a 1 GiB bundle gets
/// 22 s of copy time on top of the base) and the cap is shared with the
/// store; an oversize bundle is refused without sending anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn copy_deadline_and_bundle_cap() {
    assert_eq!(
        copy_deadline(1 << 30),
        std::time::Duration::from_secs(10 + 22)
    );
    assert_eq!(MAX_BUNDLE_LEN, 4 << 30);
    let (_f, b) = bundle().await;
    assert!(b.len() <= MAX_BUNDLE_LEN);
    // The group helper hands over exactly the bundle object.
    let (s, st) = pair();
    let h = b.sha256();
    let t = std::thread::spawn(move || {
        let (hdr, n, fds) = receive(&st);
        assert_eq!((n, fds.len(), hdr[0]), (MSG_LEN, 1, VERSION));
        assert_eq!(&hdr[9..], &h);
        reply(&st, &encode_ack(ACK_COPIED, &h), None);
        reply(&st, &encode_ack(ACK_COMMITTED, &h), None);
    });
    let obj = |object_type, blob| EnvelopeObject {
        object_type,
        object_hash: [0; 32],
        slot_block: Vec::new(),
        blob,
    };
    let group = EnvelopeGroup {
        channel_id: CHANNEL,
        main: obj(ObjectType::Submission, Blob::Inline(vec![1])),
        bundle: obj(ObjectType::AttachmentBundle, Blob::Staged(b.clone())),
        identity: obj(ObjectType::Identity, Blob::Inline(vec![3])),
        disposition_ct: Vec::new(),
    };
    let mut conn = StoreConnection::new(s);
    conn.hand_over_group_bundle(&group).unwrap();
    t.join().unwrap();
    assert!(conn.is_open());
    // An inline bundle cannot be handed over: fail closed, connection closed.
    let (s, _st) = pair();
    let mut bad = group.clone();
    bad.bundle.blob = Blob::Inline(vec![2]);
    let mut conn = StoreConnection::new(s);
    assert_eq!(conn.hand_over_group_bundle(&bad), Err(SinkError));
    assert!(!conn.is_open());
}
