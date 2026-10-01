// SPDX-License-Identifier: AGPL-3.0-or-later
//! Staged-bundle hand-over to the Intake Store (deploy D-33, AUD-RM2-SEA-16):
//! the sealed bundle is an immutable anonymous file passed as a descriptor
//! over a SEQPACKET socketpair (`SCM_RIGHTS`, safe rustix API), with the
//! 41-byte header of `candor-intake-store::staged`; `Ok` only on the store's
//! commit acknowledgement. The "store" here is a minimal receiver that checks
//! what the real one checks.
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

use candor_sealer::server::handover::{self, ACK_COMMITTED, ACK_REFUSED, MSG_LEN, VERSION};
use candor_sealer::server::sink::{SinkError, StagedBundle};
use candor_sealer::server::{ChaffConfig, Limits};
use common::*;
use rustix::fs::SealFlags;
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
        assert_eq!(u64::from_be_bytes(hdr[1..9].try_into().unwrap()), expect_len);
        assert_eq!(&hdr[9..], &expect_hash);
        assert_eq!(fds.len(), 1, "exactly one descriptor");
        let fd = fds.pop().unwrap();
        // A regular file of exactly the announced size…
        let st = rustix::fs::fstat(&fd).unwrap();
        assert_eq!(
            rustix::fs::FileType::from_raw_mode(st.st_mode),
            rustix::fs::FileType::RegularFile
        );
        assert_eq!(st.st_size as u64, expect_len);
        // …sealed against any change by either side…
        let seals = rustix::fs::fcntl_get_seals(&fd).unwrap();
        assert!(seals.contains(SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL));
        assert!(rustix::io::pwrite(&fd, b"x", 0).is_err());
        assert!(rustix::fs::ftruncate(&fd, 0).is_err());
        // …whose bytes hash to the header value.
        let mut buf = vec![0u8; expect_len as usize];
        let mut off = 0;
        while off < buf.len() {
            let k = rustix::io::pread(&fd, &mut buf[off..], off as u64).unwrap();
            assert!(k > 0);
            off += k;
        }
        assert_eq!(candor_core::hash::sha256(&[&buf]), expect_hash);
        reply(&store_end, &[ACK_COMMITTED], None);
        buf
    });
    handover::hand_over(&sealer_end, &b).unwrap();
    let bytes = store.join().unwrap();
    assert_eq!(bytes, b.read_to_vec().unwrap());
    // The bundle starts with a CoreHeader of an ATTACHMENT_BUNDLE.
    assert_eq!(bytes.len() as u64, b.len());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hand_over_fails_closed_without_a_commit_ack() {
    let (_f, b) = bundle().await;
    // Refused.
    let (s, st) = pair();
    let t = std::thread::spawn(move || {
        let _ = receive(&st);
        reply(&st, &[ACK_REFUSED], None);
    });
    assert_eq!(handover::hand_over(&s, &b), Err(SinkError));
    t.join().unwrap();
    // An unknown byte, or more than one byte.
    for answer in [&[0x02u8][..], &[ACK_COMMITTED, 0][..]] {
        let (s, st) = pair();
        let a = answer.to_vec();
        let t = std::thread::spawn(move || {
            let _ = receive(&st);
            reply(&st, &a, None);
        });
        assert_eq!(handover::hand_over(&s, &b), Err(SinkError));
        t.join().unwrap();
    }
    // A descriptor sent back with the ack is refused (and closed).
    let (s, st) = pair();
    let t = std::thread::spawn(move || {
        let (_, _, fds) = receive(&st);
        reply(&st, &[ACK_COMMITTED], fds.first());
    });
    assert_eq!(handover::hand_over(&s, &b), Err(SinkError));
    t.join().unwrap();
    // The store goes away without answering.
    let (s, st) = pair();
    let t = std::thread::spawn(move || {
        let _ = receive(&st);
        drop(st);
    });
    assert_eq!(handover::hand_over(&s, &b), Err(SinkError));
    t.join().unwrap();
    // Peer already closed: the send itself fails (no SIGPIPE).
    let (s, st) = pair();
    drop(st);
    assert_eq!(handover::send(&s, &b), Err(SinkError));
}
