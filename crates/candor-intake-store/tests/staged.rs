// SPDX-License-Identifier: AGPL-3.0-or-later
//! Staged-bundle hand-over over a `SOCK_SEQPACKET` socketpair with
//! `SCM_RIGHTS` (deploy D-33, ADR-055(1), AUD-RM2-STO-27): the store copies a
//! sealed memfd into its own `candor-safefs` blob root, acknowledges only with
//! the token of a committed envelope, refuses every hostile variant with
//! nothing committed and every received descriptor closed, and sweeps orphan
//! blobs at the slot boundary.
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
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::Duration;

use candor_intake_store::staged::{
    STAGED_ACK_COMMITTED, STAGED_ACK_REFUSED, STAGED_BUNDLE_INDEX, STAGED_MAX_IN_FLIGHT,
    StagedBlob, StagedCommit, StagedHeader, StagedReceiver, send_staged_bundle,
};
use candor_intake_store::*;
use candor_safefs::{ObjectId, RootPolicy, SafeRoot, SlotTime};
use rustix::fs::SealFlags;
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvFlags, SendAncillaryBuffer, SendAncillaryMessage,
    SendFlags, SocketFlags, SocketType,
};
use sha2::{Digest, Sha256};

const MAX: u64 = 8 << 20;
const ALL_SEALS: SealFlags = SealFlags::WRITE
    .union(SealFlags::GROW)
    .union(SealFlags::SHRINK)
    .union(SealFlags::SEAL);

struct Env {
    tmp: tempfile::TempDir,
    rx: StagedReceiver,
}

fn env_with(max: u64) -> Env {
    env_uid(max, my_uid())
}

fn env_uid(max: u64, uid: u32) -> Env {
    use std::os::unix::fs::DirBuilderExt;
    let tmp = tempfile::tempdir().unwrap();
    let base = std::fs::canonicalize(tmp.path()).unwrap();
    let p = base.join("blobs");
    std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
    let root = SafeRoot::open(&p, RootPolicy::BlobStore).unwrap();
    let rx = StagedReceiver::new(root, uid, max)
        .unwrap()
        .with_timeout(Duration::from_millis(200));
    Env { tmp, rx }
}

fn env() -> Env {
    env_with(MAX)
}

/// This process's uid as seen through `SO_PEERCRED` of a socketpair.
fn my_uid() -> u32 {
    let (a, _b) = pair();
    rustix::net::sockopt::socket_peercred(&a)
        .unwrap()
        .uid
        .as_raw()
}

fn slot() -> SlotTime {
    SlotTime::from_unix_secs(1_790_000_100).unwrap()
}

fn next_slot() -> SlotTime {
    SlotTime::from_unix_secs(1_790_000_100 + 3600).unwrap()
}

fn pair_of(t: SocketType) -> (OwnedFd, OwnedFd) {
    rustix::net::socketpair(AddressFamily::UNIX, t, SocketFlags::CLOEXEC, None).unwrap()
}

fn pair() -> (OwnedFd, OwnedFd) {
    pair_of(SocketType::SEQPACKET)
}

/// An anonymous file holding `data`, sealed with `seals` (the sealer's form
/// with all four seals).
fn memfile_sealed(name: &str, data: &[u8], seals: SealFlags) -> OwnedFd {
    let fd = rustix::fs::memfd_create(
        name,
        rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
    )
    .unwrap();
    let mut f = std::fs::File::from(fd);
    f.write_all(data).unwrap();
    let fd: OwnedFd = f.into();
    if !seals.is_empty() {
        rustix::fs::fcntl_add_seals(&fd, seals).unwrap();
    }
    fd
}

fn memfile(data: &[u8]) -> OwnedFd {
    memfile_sealed("staged", data, ALL_SEALS)
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

/// The next reply byte, or `None` if nothing is queued.
fn try_recv_byte(sock: &OwnedFd) -> Option<u8> {
    let mut b = [0u8; 4];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    match rustix::net::recvmsg(
        sock,
        &mut [IoSliceMut::new(&mut b)],
        &mut control,
        RecvFlags::DONTWAIT,
    ) {
        Ok(m) => {
            assert_eq!(m.bytes, 1);
            Some(b[0])
        }
        Err(e) => {
            assert_eq!(e, rustix::io::Errno::AGAIN);
            None
        }
    }
}

/// Send raw bytes with the given descriptors, one control message per entry
/// of `groups` (hostile sealer).
fn send_groups(sock: &OwnedFd, data: &[u8], groups: &[&[BorrowedFd<'_>]]) {
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(8))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    for g in groups {
        if !g.is_empty() {
            assert!(control.push(SendAncillaryMessage::ScmRights(g)));
        }
    }
    rustix::net::sendmsg(
        sock,
        &[IoSlice::new(data)],
        &mut control,
        SendFlags::empty(),
    )
    .unwrap();
}

fn send_raw(sock: &OwnedFd, data: &[u8], fds: &[BorrowedFd<'_>]) {
    send_groups(sock, data, &[fds]);
}

async fn mem_store() -> MemoryStore {
    let s = MemoryStore::with_config(common::TEST_DEADDROP, Box::new(RandomDummyReplies)).unwrap();
    s.init(common::TENANT, common::SALT).await.unwrap();
    s
}

fn envelope_for(blob: &StagedBlob) -> CommitEnvelope {
    let mut e = common::envelope(0);
    e.objects[STAGED_BUNDLE_INDEX].blob = PartRef {
        blob_id: blob.blob_id(),
        padded_size: blob.len(),
    };
    e
}

fn assert_clean(e: &Env, why: &str) {
    assert!(
        e.rx.blobs().list().unwrap().is_empty(),
        "{why}: nothing kept"
    );
    assert_eq!(e.rx.in_flight(), 0, "{why}: nothing in flight");
}

/// D-33 / STO-27(3): a sealed bundle passed as a descriptor is copied
/// exactly, referenced by a committed envelope, and only then acknowledged
/// with `0x01` (the token exists only after `commit_envelope` returned).
#[tokio::test]
async fn staged_bundle_handover_roundtrip() {
    let e = env();
    let (sealer, store_sock) = pair();
    let data = bundle(300_000 + 17);
    let file = memfile(&data);
    send_staged_bundle(&sealer, &header(&data), file.as_fd()).unwrap();
    let blob = e.rx.receive(store_sock.as_fd(), slot()).unwrap();
    assert_eq!(blob.len(), data.len() as u64);
    let id = ObjectId::from_bytes(blob.blob_id().0);
    assert_eq!(e.rx.blobs().read_to_vec(&id, MAX).unwrap(), data);
    // Nothing is acknowledged before the commit.
    assert_eq!(try_recv_byte(&sealer), None);
    let s = mem_store().await;
    let env_in = envelope_for(&blob);
    let c = e.rx.commit_staged(&s, env_in, blob).await.unwrap();
    assert_eq!(s.pending_count().await.unwrap(), 1);
    e.rx.acknowledge(store_sock.as_fd(), c).unwrap();
    assert_eq!(try_recv_byte(&sealer), Some(STAGED_ACK_COMMITTED));
    // Committed blobs are never swept.
    assert_eq!(e.rx.in_flight(), 0);
    assert_eq!(e.rx.sweep(&s, next_slot()).await.unwrap(), 0);
    assert!(e.rx.blobs().exists(&id).unwrap());
    // The sealer's file is unchanged (read-only use with pread).
    let mut back = vec![0u8; data.len()];
    std::os::unix::fs::FileExt::read_exact_at(&std::fs::File::from(file), &mut back, 0).unwrap();
    assert_eq!(back, data);
}

/// STO-27(1): a peer whose `SO_PEERCRED` uid is not the configured sealer
/// uid is refused before its message is read; a receiver configured for the
/// right uid then gets the queued message.
#[test]
fn staged_wrong_peer_uid_refused() {
    let e = env();
    let other = env_uid(MAX, my_uid().wrapping_add(1)).rx;
    let (sealer, store_sock) = pair();
    let data = bundle(1000);
    let file = memfile(&data);
    send_staged_bundle(&sealer, &header(&data), file.as_fd()).unwrap();
    assert_eq!(
        other.receive(store_sock.as_fd(), slot()).unwrap_err(),
        StoreError::InvalidInput("staged peer")
    );
    assert_eq!(try_recv_byte(&sealer), None, "no answer to a foreign peer");
    assert_clean(&e, "wrong uid");
    let blob = e.rx.receive(store_sock.as_fd(), slot()).unwrap();
    drop(blob);
}

/// A stream socket (no message boundaries) is refused.
#[test]
fn staged_stream_socket_refused() {
    let e = env();
    let (sealer, store_sock) = pair_of(SocketType::STREAM);
    let data = bundle(1000);
    let file = memfile(&data);
    send_staged_bundle(&sealer, &header(&data), file.as_fd()).unwrap();
    assert_eq!(
        e.rx.receive(store_sock.as_fd(), slot()).unwrap_err(),
        StoreError::InvalidInput("staged socket type")
    );
    assert_clean(&e, "stream");
}

/// STO-27(2): a peer that sends nothing cannot hold the receiver: the
/// receive returns after the socket deadline.
#[test]
fn staged_stalled_peer_times_out() {
    let e = env();
    let (_sealer, store_sock) = pair();
    let h = std::thread::spawn(move || {
        let r = e.rx.receive(store_sock.as_fd(), slot());
        (r.map(drop), e)
    });
    // Generous bound: 200 ms deadline, finishes well within 10 s.
    for _ in 0..100 {
        if h.is_finished() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(h.is_finished(), "receive must not block past its deadline");
    let (r, e) = h.join().unwrap();
    assert_eq!(
        r.unwrap_err(),
        StoreError::InvalidInput("staged receive deadline")
    );
    assert_clean(&e, "timeout");
}

/// A hostile message: label, bytes, descriptors per control message.
type Case<'a> = (&'static str, Vec<u8>, Vec<Vec<BorrowedFd<'a>>>);

/// STO-27(3)/ADR-055(1): hostile hand-overs are refused before anything is
/// committed and answered with `0x00`; the receiver still accepts a good
/// bundle afterwards.
#[test]
fn staged_bundle_hostile_variants_refused() {
    let e = env();
    let (sealer, store_sock) = pair();
    let data = bundle(70_000);
    let good = header(&data);
    let file = memfile(&data);
    let other = memfile(&data);
    let unsealed = memfile_sealed("staged", &data, SealFlags::empty());
    let missing: Vec<OwnedFd> = [
        SealFlags::WRITE,
        SealFlags::GROW,
        SealFlags::SHRINK,
        SealFlags::SEAL,
    ]
    .iter()
    .map(|s| memfile_sealed("staged", &data, ALL_SEALS.difference(*s)))
    .collect();
    let disk = {
        let mut f = tempfile::tempfile_in(e.tmp.path()).unwrap();
        f.write_all(&data).unwrap();
        OwnedFd::from(f)
    };
    let mut bad_hash = good;
    bad_hash.sha256[0] ^= 1;
    let mut bad_len = good;
    bad_len.len += 1;
    let mut short = good;
    short.len -= 1;
    let mut v2 = good.encode();
    v2[0] = 2;
    let zero_len = StagedHeader {
        len: 0,
        sha256: good.sha256,
    };
    let (sock_a, _sock_b) = pair();
    let g = good.encode().to_vec();
    let mut cases: Vec<Case<'_>> = vec![
        ("no descriptor", g.clone(), vec![vec![]]),
        (
            "two descriptors",
            g.clone(),
            vec![vec![file.as_fd(), other.as_fd()]],
        ),
        (
            "two control messages",
            g.clone(),
            vec![vec![file.as_fd()], vec![other.as_fd()]],
        ),
        ("short message", g[..40].to_vec(), vec![vec![file.as_fd()]]),
        ("empty message", vec![0], vec![vec![file.as_fd()]]),
        (
            "trailing byte",
            [g.as_slice(), &[0]].concat(),
            vec![vec![file.as_fd()]],
        ),
        ("unknown version", v2.to_vec(), vec![vec![file.as_fd()]]),
        (
            "zero length",
            zero_len.encode().to_vec(),
            vec![vec![file.as_fd()]],
        ),
        (
            "size larger than file",
            bad_len.encode().to_vec(),
            vec![vec![file.as_fd()]],
        ),
        (
            "size smaller than file",
            short.encode().to_vec(),
            vec![vec![file.as_fd()]],
        ),
        (
            "hash mismatch",
            bad_hash.encode().to_vec(),
            vec![vec![file.as_fd()]],
        ),
        ("not a regular file", g.clone(), vec![vec![sock_a.as_fd()]]),
        ("unsealed memfd", g.clone(), vec![vec![unsealed.as_fd()]]),
        (
            "disk file (unsealable)",
            g.clone(),
            vec![vec![disk.as_fd()]],
        ),
    ];
    for (i, m) in missing.iter().enumerate() {
        let why = [
            "no SEAL_WRITE",
            "no SEAL_GROW",
            "no SEAL_SHRINK",
            "no SEAL_SEAL",
        ][i];
        cases.push((why, g.clone(), vec![vec![m.as_fd()]]));
    }
    for (why, msg, groups) in &cases {
        let gs: Vec<&[BorrowedFd<'_>]> = groups.iter().map(Vec::as_slice).collect();
        send_groups(&sealer, msg, &gs);
        assert!(
            matches!(
                e.rx.receive(store_sock.as_fd(), slot()),
                Err(StoreError::InvalidInput(_))
            ),
            "{why}"
        );
        assert_eq!(try_recv_byte(&sealer), Some(STAGED_ACK_REFUSED), "{why}");
        assert_eq!(try_recv_byte(&sealer), None, "{why}: one answer");
        assert_clean(&e, why);
    }
    // Above the receiver's bound.
    let small = env_with(69_999);
    send_staged_bundle(&sealer, &good, file.as_fd()).unwrap();
    assert!(small.rx.receive(store_sock.as_fd(), slot()).is_err());
    assert_eq!(try_recv_byte(&sealer), Some(STAGED_ACK_REFUSED));
    assert_clean(&small, "above bound");
    // A good hand-over still works on the same socket.
    send_staged_bundle(&sealer, &good, file.as_fd()).unwrap();
    let blob = e.rx.receive(store_sock.as_fd(), slot()).unwrap();
    assert_eq!(
        e.rx.blobs()
            .read_to_vec(&ObjectId::from_bytes(blob.blob_id().0), MAX)
            .unwrap(),
        data
    );
}

/// Surplus descriptors are closed by the store, not leaked: two in one
/// message, and more than the control buffer holds (`MSG_CTRUNC`).
#[test]
fn staged_surplus_descriptors_closed() {
    let e = env();
    let (sealer, store_sock) = pair();
    let data = bundle(4096);
    let fds: Vec<OwnedFd> = (0..6)
        .map(|_| memfile_sealed("candor-surplus-probe", &data, ALL_SEALS))
        .collect();
    for n in [2usize, 6] {
        let b: Vec<BorrowedFd<'_>> = fds[..n].iter().map(AsFd::as_fd).collect();
        send_raw(&sealer, &header(&data).encode(), &b);
        assert_eq!(probe_fds(), 6, "in flight descriptors are not in the table");
        assert!(e.rx.receive(store_sock.as_fd(), slot()).is_err());
        assert_eq!(probe_fds(), 6, "received descriptors must be closed ({n})");
        assert_eq!(try_recv_byte(&sealer), Some(STAGED_ACK_REFUSED));
        assert_clean(&e, "surplus");
    }
}

/// Open descriptors of this process that refer to the probe memfds.
fn probe_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|d| std::fs::read_link(d.ok()?.path()).ok())
        .filter(|t| t.to_string_lossy().contains("candor-surplus-probe"))
        .count()
}

/// STO-27(3)/(4): a failed envelope commit yields no token (so no `0x01`);
/// the copied blob is an orphan and the slot-boundary sweep removes it.
#[tokio::test]
async fn staged_commit_failure_refused_and_swept() {
    let e = env();
    let (sealer, store_sock) = pair();
    let data = bundle(5000);
    let file = memfile(&data);
    // Not initialised: commit_envelope fails before any transaction.
    let s = MemoryStore::with_config(common::TEST_DEADDROP, Box::new(RandomDummyReplies)).unwrap();
    send_staged_bundle(&sealer, &header(&data), file.as_fd()).unwrap();
    let blob = e.rx.receive(store_sock.as_fd(), slot()).unwrap();
    let env_in = envelope_for(&blob);
    assert!(e.rx.commit_staged(&s, env_in, blob).await.is_err());
    e.rx.refuse(store_sock.as_fd()).unwrap();
    assert_eq!(try_recv_byte(&sealer), Some(STAGED_ACK_REFUSED));
    assert_eq!(e.rx.blobs().list().unwrap().len(), 1);
    assert_eq!(e.rx.sweep(&s, next_slot()).await.unwrap(), 1);
    assert_clean(&e, "commit failure");
}

/// STO-27(4): a duplicate group commits nothing for the second copy, which
/// is swept; the first, committed copy stays.
#[tokio::test]
async fn staged_duplicate_envelope_orphan_swept() {
    let e = env();
    let (sealer, store_sock) = pair();
    let data = bundle(5000);
    let file = memfile(&data);
    let s = mem_store().await;
    send_staged_bundle(&sealer, &header(&data), file.as_fd()).unwrap();
    let b1 = e.rx.receive(store_sock.as_fd(), slot()).unwrap();
    let keep = ObjectId::from_bytes(b1.blob_id().0);
    let env1 = envelope_for(&b1);
    let c = e.rx.commit_staged(&s, env1.clone(), b1).await.unwrap();
    e.rx.acknowledge(store_sock.as_fd(), c).unwrap();
    assert_eq!(try_recv_byte(&sealer), Some(STAGED_ACK_COMMITTED));
    send_staged_bundle(&sealer, &header(&data), file.as_fd()).unwrap();
    let b2 = e.rx.receive(store_sock.as_fd(), slot()).unwrap();
    let mut env2 = env1;
    env2.objects[STAGED_BUNDLE_INDEX].blob.blob_id = b2.blob_id();
    assert_eq!(
        e.rx.commit_staged(&s, env2, b2).await.unwrap_err(),
        StoreError::DuplicateEnvelope
    );
    assert_eq!(e.rx.sweep(&s, next_slot()).await.unwrap(), 1);
    assert_eq!(e.rx.blobs().list().unwrap(), vec![keep]);
    assert_eq!(e.rx.in_flight(), 0);
}

/// STO-27(4): a received blob dropped without a commit attempt (e.g. the
/// envelope could not be built) is swept at the next slot boundary; the
/// sweep does nothing when there are no orphans.
#[tokio::test]
async fn staged_dropped_blob_swept() {
    let e = env();
    let m = mem_store().await;
    let (sealer, store_sock) = pair();
    let data = bundle(5000);
    let file = memfile(&data);
    assert_eq!(e.rx.sweep(&m, slot()).await.unwrap(), 0);
    send_staged_bundle(&sealer, &header(&data), file.as_fd()).unwrap();
    let blob = e.rx.receive(store_sock.as_fd(), slot()).unwrap();
    assert_eq!(e.rx.in_flight(), 1);
    drop(blob);
    assert_eq!(e.rx.blobs().list().unwrap().len(), 1);
    assert_eq!(e.rx.sweep(&m, next_slot()).await.unwrap(), 1);
    assert_clean(&e, "dropped");
    assert_eq!(e.rx.startup(&m, next_slot()).await.unwrap(), 0);
}

/// Bounded in-flight blobs: beyond the limit a hand-over is refused with
/// `Capacity` and nothing is written; after the sweep it works again.
#[tokio::test]
async fn staged_in_flight_bounded() {
    let e = env();
    let m = mem_store().await;
    let (sealer, store_sock) = pair();
    let data = bundle(64);
    let file = memfile(&data);
    let mut held = Vec::new();
    for _ in 0..STAGED_MAX_IN_FLIGHT {
        send_staged_bundle(&sealer, &header(&data), file.as_fd()).unwrap();
        held.push(e.rx.receive(store_sock.as_fd(), slot()).unwrap());
    }
    send_staged_bundle(&sealer, &header(&data), file.as_fd()).unwrap();
    assert_eq!(
        e.rx.receive(store_sock.as_fd(), slot()).unwrap_err(),
        StoreError::Capacity
    );
    assert_eq!(try_recv_byte(&sealer), Some(STAGED_ACK_REFUSED));
    assert_eq!(e.rx.blobs().list().unwrap().len(), STAGED_MAX_IN_FLIGHT);
    drop(held);
    assert_eq!(
        e.rx.sweep(&m, next_slot()).await.unwrap(),
        STAGED_MAX_IN_FLIGHT
    );
    assert_clean(&e, "capacity");
    send_staged_bundle(&sealer, &header(&data), file.as_fd()).unwrap();
    drop(e.rx.receive(store_sock.as_fd(), slot()).unwrap());
}

/// A commit seam with scripted outcomes (backend errors and cancellation
/// cannot be produced by the real stores on demand). `None` never completes.
struct Scripted {
    outcomes: std::sync::Mutex<Vec<Option<Result<EnvelopeRef>>>>,
    calls: std::sync::atomic::AtomicUsize,
}

impl Scripted {
    fn new(mut v: Vec<Option<Result<EnvelopeRef>>>) -> Self {
        v.reverse();
        Self {
            outcomes: std::sync::Mutex::new(v),
            calls: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl StagedCommit for Scripted {
    fn commit_staged_envelope(
        &self,
        _env: CommitEnvelope,
    ) -> impl std::future::Future<Output = Result<EnvelopeRef>> + Send {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let next = self.outcomes.lock().unwrap().pop().unwrap();
        async move {
            match next {
                Some(r) => r,
                None => std::future::pending().await,
            }
        }
    }
}

/// Receive one small bundle (the sealer end is dropped: no answers needed).
fn received(e: &Env) -> StagedBlob {
    let (sealer, store_sock) = pair();
    let data = bundle(100);
    let file = memfile(&data);
    send_staged_bundle(&sealer, &header(&data), file.as_fd()).unwrap();
    e.rx.receive(store_sock.as_fd(), slot()).unwrap()
}

/// STO-27(3): a backend error has an unknown outcome; the commit is retried
/// once and a success then yields the token; nothing is kept as an orphan.
#[tokio::test]
async fn staged_backend_error_retry_commits() {
    let e = env();
    let b = received(&e);
    let env_in = envelope_for(&b);
    let s = Scripted::new(vec![
        Some(Err(StoreError::Backend)),
        Some(Ok(EnvelopeRef([9; 16]))),
    ]);
    let c = e.rx.commit_staged(&s, env_in, b).await.unwrap();
    assert_eq!(c.envelope_ref(), EnvelopeRef([9; 16]));
    assert_eq!(s.calls(), 2);
    assert_eq!(e.rx.in_flight(), 0);
    assert_eq!(e.rx.uncertain_count(), 0);
    assert_eq!(e.rx.blobs().list().unwrap().len(), 1);
}

/// STO-27(4): when the outcome stays unknown (backend error twice, or a
/// duplicate/any error on the retry, meaning the first attempt may have
/// committed), no token is issued; the blob is protected for one sweep and
/// then kept only if a committed envelope references it.
#[tokio::test]
async fn staged_unknown_outcome_keeps_blob() {
    for second in [
        StoreError::Backend,
        StoreError::DuplicateEnvelope,
        StoreError::InvalidInput("duplicate blob id"),
    ] {
        let e = env();
        let b = received(&e);
        let id = ObjectId::from_bytes(b.blob_id().0);
        let env_in = envelope_for(&b);
        // The duplicate case: the first attempt did commit.
        let m = mem_store().await;
        let committed = second == StoreError::DuplicateEnvelope;
        if committed {
            m.commit_envelope(env_in.clone()).await.unwrap();
        }
        let s = Scripted::new(vec![Some(Err(StoreError::Backend)), Some(Err(second))]);
        assert_eq!(
            e.rx.commit_staged(&s, env_in, b).await.unwrap_err(),
            StoreError::Backend
        );
        assert_eq!(e.rx.uncertain_count(), 1);
        assert_eq!(e.rx.in_flight(), 1, "registered until resolved");
        // Protected for one sweep even though unreferenced.
        assert_eq!(e.rx.sweep(&m, slot()).await.unwrap(), 0);
        assert!(e.rx.blobs().exists(&id).unwrap());
        // Then the database decides.
        let n = e.rx.sweep(&m, next_slot()).await.unwrap();
        assert_eq!(n, usize::from(!committed));
        assert_eq!(e.rx.blobs().exists(&id).unwrap(), committed);
    }
}

/// A definite rejection is not retried; the blob is an orphan for the sweep.
#[tokio::test]
async fn staged_definite_rejection_not_retried() {
    let e = env();
    let b = received(&e);
    let env_in = envelope_for(&b);
    let s = Scripted::new(vec![Some(Err(StoreError::RestorePending))]);
    assert_eq!(
        e.rx.commit_staged(&s, env_in, b).await.unwrap_err(),
        StoreError::RestorePending
    );
    assert_eq!(s.calls(), 1);
    let m = mem_store().await;
    assert_eq!(e.rx.sweep(&m, next_slot()).await.unwrap(), 1);
    assert_clean(&e, "definite rejection");
}

/// A commit future dropped mid-await (cancelled): the outcome is unknown,
/// so the blob is protected for one sweep, then removed if unreferenced.
#[tokio::test]
async fn staged_cancelled_commit_keeps_blob() {
    let e = env();
    let b = received(&e);
    let env_in = envelope_for(&b);
    let s = Scripted::new(vec![None]);
    let fut = e.rx.commit_staged(&s, env_in, b);
    let cancelled = tokio::select! {
        biased;
        _ = fut => false,
        () = std::future::ready(()) => true,
    };
    assert!(cancelled);
    assert_eq!(s.calls(), 1);
    assert_eq!(e.rx.uncertain_count(), 1);
    let m = mem_store().await;
    assert_eq!(e.rx.sweep(&m, slot()).await.unwrap(), 0);
    assert_eq!(e.rx.blobs().list().unwrap().len(), 1);
    assert_eq!(e.rx.sweep(&m, next_slot()).await.unwrap(), 1);
    assert_clean(&e, "cancelled");
}

/// STO-27(3): the envelope must reference the blob exactly once, in the
/// bundle position, with its exact size; otherwise the store is not called
/// and the blob is swept.
#[tokio::test]
async fn staged_envelope_must_reference_blob() {
    let e = env();
    let mutate: [fn(&mut CommitEnvelope, BlobId); 4] = [
        |v, _| v.objects[STAGED_BUNDLE_INDEX].blob.blob_id = BlobId([7; 16]),
        |v, _| v.objects[STAGED_BUNDLE_INDEX].blob.padded_size += 1,
        |v, id| v.objects[0].blob.blob_id = id,
        |v, id| {
            v.objects[STAGED_BUNDLE_INDEX].blob.blob_id = BlobId([7; 16]);
            v.objects[2].blob.blob_id = id;
        },
    ];
    for m in mutate {
        let b = received(&e);
        let mut v = envelope_for(&b);
        m(&mut v, b.blob_id());
        let s = Scripted::new(vec![Some(Ok(EnvelopeRef([1; 16])))]);
        assert!(matches!(
            e.rx.commit_staged(&s, v, b).await,
            Err(StoreError::InvalidInput(_))
        ));
        assert_eq!(s.calls(), 0);
    }
    let m = mem_store().await;
    assert_eq!(e.rx.sweep(&m, next_slot()).await.unwrap(), 4);
    assert_clean(&e, "unreferenced");
}

/// Reopen the receiver's directory as a restarted process would.
fn restart(e: &Env) -> StagedReceiver {
    let p = std::fs::canonicalize(e.tmp.path()).unwrap().join("blobs");
    StagedReceiver::new(
        SafeRoot::open(&p, RootPolicy::BlobStore).unwrap(),
        my_uid(),
        MAX,
    )
    .unwrap()
}

/// STO-27(4), crash between copy and commit: the copied blob is not in the
/// restarted receiver's memory; the start-up sweep removes it because no
/// committed envelope names it, and keeps the committed blob.
#[tokio::test]
async fn staged_crash_leftover_swept_at_startup() {
    let e = env();
    let m = mem_store().await;
    let kept = received(&e);
    let keep = ObjectId::from_bytes(kept.blob_id().0);
    let c =
        e.rx.commit_staged(&m, envelope_for(&kept), kept)
            .await
            .unwrap();
    drop(c);
    // "Crash": the blob is never committed and its handle never dropped.
    std::mem::forget(received(&e));
    assert_eq!(e.rx.blobs().list().unwrap().len(), 2);
    let rx2 = restart(&e);
    assert_eq!(rx2.startup(&m, next_slot()).await.unwrap(), 1);
    assert_eq!(rx2.blobs().list().unwrap(), vec![keep]);
}

/// The sweep never removes a blob that is in flight in this receiver, even
/// though no envelope references it yet.
#[tokio::test]
async fn staged_sweep_spares_in_flight() {
    let e = env();
    let m = mem_store().await;
    let b = received(&e);
    assert_eq!(e.rx.sweep(&m, next_slot()).await.unwrap(), 0);
    assert!(
        e.rx.blobs()
            .exists(&ObjectId::from_bytes(b.blob_id().0))
            .unwrap()
    );
    drop(b);
    assert_eq!(e.rx.sweep(&m, next_slot()).await.unwrap(), 1);
}

/// Removals per sweep are bounded; the rest go at later slot boundaries.
#[tokio::test]
async fn staged_sweep_bounded_per_slot() {
    use candor_intake_store::staged::STAGED_SWEEP_MAX_REMOVALS;
    let e = env();
    let m = mem_store().await;
    for _ in 0..STAGED_SWEEP_MAX_REMOVALS + 6 {
        std::mem::forget(received(&e));
    }
    let rx2 = restart(&e);
    assert_eq!(
        rx2.startup(&m, slot()).await.unwrap(),
        STAGED_SWEEP_MAX_REMOVALS
    );
    assert_eq!(rx2.blobs().list().unwrap().len(), 6);
    assert_eq!(rx2.sweep(&m, next_slot()).await.unwrap(), 6);
    assert!(rx2.blobs().list().unwrap().is_empty());
}

/// A reference check that fails is "referenced": nothing is removed.
#[tokio::test]
async fn staged_sweep_fails_closed() {
    struct Broken;
    impl IntakeMaintenance for Broken {
        async fn prune_deletion_list(&self, _today: Day) -> Result<u64> {
            Err(StoreError::Backend)
        }
        async fn blob_referenced(&self, _blob: BlobId) -> Result<bool> {
            Err(StoreError::Backend)
        }
    }
    let e = env();
    drop(received(&e));
    assert_eq!(
        e.rx.sweep(&Broken, next_slot()).await.unwrap_err(),
        StoreError::Backend
    );
    assert_eq!(e.rx.blobs().list().unwrap().len(), 1);
}
