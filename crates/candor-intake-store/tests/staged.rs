// SPDX-License-Identifier: AGPL-3.0-or-later
//! Staged-bundle hand-over over a `SOCK_SEQPACKET` socketpair with
//! `SCM_RIGHTS` (deploy D-33): the store copies the passed file into its own
//! `candor-safefs` blob root and acknowledges only after the envelope commit;
//! every hostile variant is refused with nothing committed and every received
//! descriptor closed.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    // Test fixture only: a private 0700 temp root for candor-safefs.
    clippy::disallowed_methods
)]

mod common;

use std::io::{IoSlice, IoSliceMut, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};

use candor_intake_store::staged::{
    STAGED_ACK_COMMITTED, STAGED_ACK_REFUSED, StagedHeader, acknowledge_committed,
    receive_staged_bundle, refuse, send_staged_bundle,
};
use candor_intake_store::*;
use candor_safefs::{ObjectId, RootPolicy, SafeRoot, SlotTime};
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage,
    SendFlags, SocketFlags, SocketType,
};
use sha2::{Digest, Sha256};

const MAX: u64 = 8 << 20;

struct Env {
    _tmp: tempfile::TempDir,
    root: SafeRoot,
}

fn env() -> Env {
    use std::os::unix::fs::DirBuilderExt;
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let p = base.join("blobs");
    std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
    let root = SafeRoot::open(&p, RootPolicy::BlobStore).unwrap();
    Env { _tmp: tmp, root }
}

fn slot() -> SlotTime {
    SlotTime::from_unix_secs(1_790_000_100).unwrap()
}

fn pair() -> (OwnedFd, OwnedFd) {
    rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap()
}

/// An anonymous file (no path) holding `data`, as the sealer's staged file.
fn memfile(data: &[u8]) -> OwnedFd {
    memfile_named("staged", data)
}

fn memfile_named(name: &str, data: &[u8]) -> OwnedFd {
    let fd = rustix::fs::memfd_create(name, rustix::fs::MemfdFlags::CLOEXEC).unwrap();
    let mut f = std::fs::File::from(fd);
    f.write_all(data).unwrap();
    f.into()
}

fn bundle(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    getrandom::fill(&mut v).unwrap();
    v
}

fn header(data: &[u8]) -> StagedHeader {
    StagedHeader {
        len: data.len() as u64,
        sha256: Sha256::digest(data).into(),
    }
}

fn recv_byte(sock: &OwnedFd) -> u8 {
    let mut b = [0u8; 4];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let m = rustix::net::recvmsg(
        sock,
        &mut [IoSliceMut::new(&mut b)],
        &mut control,
        RecvFlags::empty(),
    )
    .unwrap();
    assert_eq!(m.bytes, 1);
    b[0]
}

/// Send raw bytes with the given descriptors (hostile sealer).
fn send_raw(sock: &OwnedFd, data: &[u8], fds: &[std::os::fd::BorrowedFd<'_>]) {
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(8))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() {
        assert!(control.push(SendAncillaryMessage::ScmRights(fds)));
    }
    rustix::net::sendmsg(
        sock,
        &[IoSlice::new(data)],
        &mut control,
        SendFlags::empty(),
    )
    .unwrap();
}

/// D-33: a staged bundle passed as a descriptor is copied into the store's
/// blob root (content and length exact), referenced by a durably committed
/// envelope, and only then acknowledged; the sealer's file is untouched.
#[tokio::test]
async fn staged_bundle_handover_roundtrip() {
    let e = env();
    let (sealer, store_sock) = pair();
    let data = bundle(300_000 + 17);
    let file = memfile(&data);
    send_staged_bundle(&sealer, &header(&data), file.as_fd()).unwrap();
    let blob = receive_staged_bundle(store_sock.as_fd(), &e.root, slot(), MAX).unwrap();
    assert_eq!(blob.len, data.len() as u64);
    let id = ObjectId::from_bytes(blob.blob_id.0);
    assert_eq!(e.root.read_to_vec(&id, MAX).unwrap(), data);
    // The envelope referencing the blob is committed first (durable on
    // return), then the sealer gets the acknowledgement.
    let s = MemoryStore::with_config(common::TEST_DEADDROP, Box::new(RandomDummyReplies)).unwrap();
    s.init(common::TENANT, common::SALT).await.unwrap();
    let mut env_in = common::envelope(0);
    env_in.objects[1].blob.blob_id = blob.blob_id;
    let r = s.commit_envelope(env_in).await.unwrap();
    acknowledge_committed(store_sock.as_fd(), blob, &r).unwrap();
    assert_eq!(recv_byte(&sealer), STAGED_ACK_COMMITTED);
    // The sealer's file is unchanged (read-only use with pread).
    let mut back = vec![0u8; data.len()];
    std::os::unix::fs::FileExt::read_exact_at(&std::fs::File::from(file), &mut back, 0).unwrap();
    assert_eq!(back, data);
    assert_eq!(e.root.list().unwrap().len(), 1);
}

/// Hostile hand-overs are refused before anything is committed: no
/// descriptor, two descriptors, short/long/unknown-version messages, size
/// mismatch, hash mismatch, a non-regular descriptor (a socket), and a
/// length above the bound. The blob root stays empty and the store can
/// still receive a good bundle afterwards; a refusal is signalled with 0x00.
#[test]
fn staged_bundle_hostile_variants_refused() {
    let e = env();
    let (sealer, store_sock) = pair();
    let data = bundle(70_000);
    let good = header(&data);
    let file = memfile(&data);
    let other = memfile(&data);
    let mut bad_hash = good;
    bad_hash.sha256[0] ^= 1;
    let mut bad_len = good;
    bad_len.len += 1;
    let mut short = good;
    short.len -= 1;
    let mut v2 = good.encode();
    v2[0] = 2;
    let (sock_a, _sock_b) = pair();
    let cases: Vec<(&str, Vec<u8>, Vec<std::os::fd::BorrowedFd<'_>>)> = vec![
        ("no descriptor", good.encode().to_vec(), vec![]),
        (
            "two descriptors",
            good.encode().to_vec(),
            vec![file.as_fd(), other.as_fd()],
        ),
        (
            "short message",
            good.encode()[..40].to_vec(),
            vec![file.as_fd()],
        ),
        (
            "trailing byte",
            [good.encode().as_slice(), &[0]].concat(),
            vec![file.as_fd()],
        ),
        ("unknown version", v2.to_vec(), vec![file.as_fd()]),
        (
            "size larger than file",
            bad_len.encode().to_vec(),
            vec![file.as_fd()],
        ),
        (
            "size smaller than file",
            short.encode().to_vec(),
            vec![file.as_fd()],
        ),
        (
            "hash mismatch",
            bad_hash.encode().to_vec(),
            vec![file.as_fd()],
        ),
        (
            "not a regular file",
            good.encode().to_vec(),
            vec![sock_a.as_fd()],
        ),
    ];
    for (why, msg, fds) in cases {
        send_raw(&sealer, &msg, &fds);
        assert!(
            matches!(
                receive_staged_bundle(store_sock.as_fd(), &e.root, slot(), MAX),
                Err(StoreError::InvalidInput(_))
            ),
            "{why}"
        );
        refuse(store_sock.as_fd()).unwrap();
        assert_eq!(recv_byte(&sealer), STAGED_ACK_REFUSED, "{why}");
        assert!(
            e.root.list().unwrap().is_empty(),
            "{why}: nothing committed"
        );
    }
    // Above the caller's bound.
    send_staged_bundle(&sealer, &good, file.as_fd()).unwrap();
    assert!(receive_staged_bundle(store_sock.as_fd(), &e.root, slot(), 69_999).is_err());
    assert!(e.root.list().unwrap().is_empty());
    // A good hand-over still works on the same socket.
    send_staged_bundle(&sealer, &good, file.as_fd()).unwrap();
    let blob = receive_staged_bundle(store_sock.as_fd(), &e.root, slot(), MAX).unwrap();
    assert_eq!(
        e.root
            .read_to_vec(&ObjectId::from_bytes(blob.blob_id.0), MAX)
            .unwrap(),
        data
    );
    let _ = refuse(store_sock.as_fd());
    drop(blob);
}

/// Surplus descriptors are closed by the store, not leaked: after the
/// refused two-descriptor message, only the sender's own two descriptors of
/// the uniquely named files remain open in this process.
#[test]
fn staged_surplus_descriptors_closed() {
    let e = env();
    let (sealer, store_sock) = pair();
    let data = bundle(4096);
    let a = memfile_named("candor-surplus-probe", &data);
    let b = memfile_named("candor-surplus-probe", &data);
    send_raw(&sealer, &header(&data).encode(), &[a.as_fd(), b.as_fd()]);
    assert_eq!(probe_fds(), 2);
    assert!(receive_staged_bundle(store_sock.as_fd(), &e.root, slot(), MAX).is_err());
    assert_eq!(probe_fds(), 2, "received descriptors must be closed");
    drop((a, b));
}

/// Open descriptors of this process that refer to the probe memfds.
fn probe_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|d| std::fs::read_link(d.ok()?.path()).ok())
        .filter(|t| t.to_string_lossy().contains("candor-surplus-probe"))
        .count()
}
