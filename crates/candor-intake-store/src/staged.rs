// SPDX-License-Identifier: AGPL-3.0-or-later
//! Receive side of the staged-bundle hand-over (deploy D-33, ADR-055(1),
//! AUD-RM2-STO-27).
//!
//! The sealer seals each ATTACHMENT_BUNDLE into an anonymous `memfd` sealed
//! `F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL` and passes it to
//! the store as an open descriptor over `istore.sock` (`AF_UNIX`,
//! `SOCK_SEQPACKET`, `SCM_RIGHTS`), never as a path. A [`StagedReceiver`]
//! copies the bytes into the store's blob root through `candor-safefs`
//! (atomic create + fsync + no-replace rename, times normalised to the
//! caller's slot). The acknowledgement `0x01` can only be sent with a
//! [`CommittedStaged`] token, which only [`StagedReceiver::commit_staged`]
//! creates, and only after [`crate::IntakeStore::commit_envelope`] returned
//! (it returns after the database `COMMIT`, ADR-046(1)) for an envelope whose
//! ATTACHMENT_BUNDLE object references exactly this blob with its exact size.
//!
//! Wire format, protocol version 2 (AUD-RM2-STO-29, C-5): one SEQPACKET
//! message, exactly one descriptor:
//! `u8 version (= 2) ‖ u64be len ‖ sha256(file bytes)(32)` = 41 bytes. The
//! replies are 33-byte acknowledgements `u8 code ‖ sha256(file bytes)` that
//! echo the bundle hash: `0x02` ("copied") as soon as the copy is durable in
//! the blob root (sent by [`StagedReceiver::receive`]), then `0x01`
//! ("committed", [`StagedReceiver::acknowledge`], only with a
//! [`CommittedStaged`] token) or `0x00` (refused; the hash field is zero).
//! The sealer waits for `0x02` with a deadline scaled by the length and for
//! `0x01` with a fixed 60 s, so a large copy cannot eat the commit budget.
//! Both sides enforce one bundle-size cap, [`STAGED_MAX_BUNDLE_LEN`]
//! (`candor_sealer::server::handover::MAX_BUNDLE_LEN`).
//!
//! Hostile-peer discipline (all refused before anything is committed, every
//! received descriptor closed): a peer whose `SO_PEERCRED` uid is not the
//! configured sealer uid, a socket that is not `SOCK_SEQPACKET`, no message
//! within the receive timeout (`SO_RCVTIMEO`), truncated data or control
//! (`MSG_TRUNC`/`MSG_CTRUNC`), any length other than 41, an unknown version,
//! `len = 0` or above the bound, credentials or a second control message, zero
//! or more than one descriptor, a non-regular file, a file without all four
//! seals plus `F_SEAL_EXEC` (this also excludes FUSE/NFS/disk files, which cannot be sealed, so
//! the copy reads RAM only and cannot stall), `fstat` size ≠ `len`, a file that
//! shrinks or grows during the copy, and a hash mismatch.
//!
//! Orphans: [`StagedReceiver::sweep`] (at start-up via
//! [`StagedReceiver::startup`] and at every slot boundary, with that slot)
//! removes a blob only if it is not in flight in this receiver and no
//! committed envelope references it ([`crate::IntakeMaintenance::blob_referenced`]),
//! in shuffled order and a bounded number per slot. This covers failed
//! commits, unknown outcomes and crashes between copy and commit. In-flight
//! state is kept in memory only (never on disk).
//! No path, size, name or identifier is logged or put into an error.
//!
//! Receive, acknowledge, refuse and sweep block (run them on a blocking
//! thread); [`StagedReceiver::commit_staged`] is async.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::{IoSlice, IoSliceMut, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use candor_safefs::{ObjectId, SafeRoot, SlotTime};
use rustix::fs::{FileType, SealFlags, fcntl_get_seals, fstat}; // safefs-lint: allow(fd-only calls on the SCM_RIGHTS-received descriptor: fstat and F_GET_SEALS; no path access)
use rustix::net::sockopt::{Timeout, set_socket_timeout, socket_peercred, socket_type};
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendFlags, SocketType,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Result, StoreError};
use crate::types::{BlobId, CommitEnvelope, EnvelopeRef, GROUP_OBJECTS};
use crate::{IntakeMaintenance, IntakeStore};

const _: () = assert!(STAGED_BUNDLE_INDEX < GROUP_OBJECTS);

/// Protocol version of the hand-over message (2: two-phase acknowledgements
/// with hash echo, AUD-RM2-STO-29).
pub const STAGED_VERSION: u8 = 2;
/// Exact length of the hand-over message.
pub const STAGED_MSG_LEN: usize = 1 + 8 + 32;
/// Exact length of an acknowledgement: `u8 code ‖ sha256`.
pub const STAGED_ACK_LEN: usize = 1 + 32;
/// Acknowledgement code: the envelope referencing the blob is committed.
pub const STAGED_ACK_COMMITTED: u8 = 0x01;
/// Acknowledgement code: refused (nothing committed).
pub const STAGED_ACK_REFUSED: u8 = 0x00;
/// Acknowledgement code: the copy is durable in the blob root; the envelope
/// commit follows (AUD-RM2-STO-29).
pub const STAGED_ACK_COPIED: u8 = 0x02;
/// Largest bundle accepted (bytes), whatever `max_len` a receiver is built
/// with. The sealer enforces the same cap
/// (`candor_sealer::server::handover::MAX_BUNDLE_LEN`; AUD-RM2-STO-29).
pub const STAGED_MAX_BUNDLE_LEN: u64 = 4 << 30;
/// Index of the ATTACHMENT_BUNDLE object in a group (ADR-052(1)).
pub const STAGED_BUNDLE_INDEX: usize = 1;
/// Default per-call socket deadline (`SO_RCVTIMEO` / `SO_SNDTIMEO`).
pub const STAGED_DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// Smallest accepted socket deadline (zero would mean "block forever").
pub const STAGED_MIN_TIMEOUT: Duration = Duration::from_millis(10);
/// Largest accepted socket deadline.
pub const STAGED_MAX_TIMEOUT: Duration = Duration::from_secs(60);
/// Blobs received but not yet committed or swept, per receiver; more are
/// refused with [`StoreError::Capacity`] (bounded memory and disk).
pub const STAGED_MAX_IN_FLIGHT: usize = 64;
/// Required seals (ADR-055(1), plus `F_SEAL_EXEC`: the sealer creates its
/// memfds with `MFD_NOEXEC_SEAL`).
const REQUIRED_SEALS: SealFlags = SealFlags::WRITE
    .union(SealFlags::GROW)
    .union(SealFlags::EXEC)
    .union(SealFlags::SHRINK)
    .union(SealFlags::SEAL);
/// Reference lookups per sweep.
pub const STAGED_SWEEP_MAX_CHECKS: usize = 1024;
/// Removals per sweep.
pub const STAGED_SWEEP_MAX_REMOVALS: usize = 64;
/// Copy buffer size.
const CHUNK: usize = 64 * 1024;
const CHUNK_U64: u64 = 64 * 1024;
/// Descriptors accepted into the control buffer per message (more are
/// received only to be closed; the kernel truncates beyond this, which is
/// refused via `MSG_CTRUNC`).
const MAX_FDS: usize = 4;

/// The hand-over header.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StagedHeader {
    /// Exact file length in bytes (1 ..= the receiver's bound).
    pub len: u64,
    /// SHA-256 of the file bytes.
    pub sha256: [u8; 32],
}

impl core::fmt::Debug for StagedHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // No size (metadata) in debug output.
        f.write_str("StagedHeader")
    }
}

impl StagedHeader {
    /// Encode the 41-byte message (sealer side and tests).
    #[must_use]
    pub fn encode(&self) -> [u8; STAGED_MSG_LEN] {
        let mut m = [0u8; STAGED_MSG_LEN];
        let (v, rest) = m.split_at_mut(1);
        let (l, h) = rest.split_at_mut(8);
        v.copy_from_slice(&[STAGED_VERSION]);
        l.copy_from_slice(&self.len.to_be_bytes());
        h.copy_from_slice(&self.sha256);
        m
    }

    /// Strict decoding: exact length, known version, `len ≥ 1`.
    pub fn decode(m: &[u8]) -> Result<Self> {
        let m: &[u8; STAGED_MSG_LEN] = m
            .try_into()
            .map_err(|_| StoreError::InvalidInput("staged message length"))?;
        let (v, rest) = m.split_at(1);
        let (l, h) = rest.split_at(8);
        if v != [STAGED_VERSION] {
            return Err(StoreError::InvalidInput("staged message version"));
        }
        let len = u64::from_be_bytes(
            l.try_into()
                .map_err(|_| StoreError::InvalidInput("staged message"))?,
        );
        if len == 0 {
            return Err(StoreError::InvalidInput("staged length"));
        }
        Ok(Self {
            len,
            sha256: h
                .try_into()
                .map_err(|_| StoreError::InvalidInput("staged message"))?,
        })
    }
}

/// Registry state of a blob this receiver wrote.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// Being copied (no committed file yet).
    Receiving,
    /// Committed to the blob root; a [`StagedBlob`] is alive.
    Live,
    /// Its envelope commit is in progress.
    Committing,
    /// Definitely not referenced: removed by the next sweep.
    Orphan,
    /// Commit outcome unknown. `false`: protected until the next sweep (a
    /// late `COMMIT` has a full slot to land; statement timeouts are far
    /// shorter); `true`: then decided by the database reference check.
    Uncertain(bool),
}

impl State {
    /// Protected from the sweep regardless of the database.
    fn in_flight(self) -> bool {
        matches!(
            self,
            Self::Receiving | Self::Live | Self::Committing | Self::Uncertain(false)
        )
    }
}

#[derive(Default)]
struct Registry {
    map: Mutex<HashMap<BlobId, State>>,
    /// Blobs whose envelope commit outcome was unknown (health counter).
    uncertain: AtomicU64,
}

impl Registry {
    fn lock(&self) -> MutexGuard<'_, HashMap<BlobId, State>> {
        // No code panics while holding the lock; recovering a poisoned map
        // keeps the bookkeeping instead of failing every later call.
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn set(&self, id: BlobId, s: State) {
        self.lock().insert(id, s);
    }

    fn forget(&self, id: BlobId) {
        self.lock().remove(&id);
    }

    fn uncertain(&self, id: BlobId) {
        self.set(id, State::Uncertain(false));
        self.uncertain.fetch_add(1, Ordering::Relaxed);
    }
}

/// Removes a `Receiving` entry unless the copy committed (`done`), and marks
/// it `Orphan` if the safefs commit may have left a file behind.
struct ReceiveGuard<'a> {
    reg: &'a Registry,
    id: BlobId,
    outcome: Option<State>,
}

impl Drop for ReceiveGuard<'_> {
    fn drop(&mut self) {
        match self.outcome {
            Some(s) => self.reg.set(self.id, s),
            None => self.reg.forget(self.id),
        }
    }
}

/// Marks a blob `Uncertain` if the commit future is dropped mid-await (the
/// database may or may not have committed: only the reference check may
/// remove the blob).
struct CommitGuard<'a> {
    reg: &'a Registry,
    id: BlobId,
    armed: bool,
}

impl Drop for CommitGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.reg.uncertain(self.id);
        }
    }
}

/// A staged bundle copied into the blob root, not yet referenced by a
/// committed envelope. Pass it to [`StagedReceiver::commit_staged`]; if it is
/// dropped instead, the blob is an orphan and is removed by the next sweep.
#[must_use = "commit the envelope with commit_staged, or the blob is swept as an orphan"]
pub struct StagedBlob {
    blob_id: BlobId,
    len: u64,
    sha256: [u8; 32],
    reg: Arc<Registry>,
    armed: bool,
}

impl StagedBlob {
    /// Blob id in the store's blob root (put it in the ATTACHMENT_BUNDLE
    /// object's [`crate::PartRef`]).
    #[must_use]
    pub fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    /// Copied length (the object's `padded_size`).
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Never empty (`len ≥ 1` is enforced on receive).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn disarm(mut self) -> (BlobId, u64, [u8; 32], Arc<Registry>) {
        self.armed = false;
        (self.blob_id, self.len, self.sha256, Arc::clone(&self.reg))
    }
}

impl Drop for StagedBlob {
    fn drop(&mut self) {
        if self.armed {
            self.reg.set(self.blob_id, State::Orphan);
        }
    }
}

impl core::fmt::Debug for StagedBlob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StagedBlob")
    }
}

/// Proof that the envelope referencing a received blob is durably committed.
/// Not constructible outside this module, not `Clone`; consumed by
/// [`StagedReceiver::acknowledge`].
#[must_use = "acknowledge the hand-over"]
pub struct CommittedStaged {
    blob_id: BlobId,
    envelope_ref: EnvelopeRef,
    sha256: [u8; 32],
}

impl CommittedStaged {
    /// The committed blob.
    #[must_use]
    pub fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    /// The committed envelope.
    #[must_use]
    pub fn envelope_ref(&self) -> EnvelopeRef {
        self.envelope_ref
    }
}

impl core::fmt::Debug for CommittedStaged {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CommittedStaged")
    }
}

/// The envelope commit used by [`StagedReceiver::commit_staged`]:
/// implemented for every [`IntakeStore`] as
/// [`IntakeStore::commit_envelope`], which returns only after the database
/// `COMMIT` (ADR-046(1)). A separate seam so that commit outcomes the real
/// stores cannot produce on demand (backend errors, cancellation) are
/// testable; production code passes the store.
pub trait StagedCommit: Send + Sync {
    /// `COMMIT_ENVELOPE`; `Ok` only once the envelope is durably committed.
    fn commit_staged_envelope(
        &self,
        env: CommitEnvelope,
    ) -> impl Future<Output = Result<EnvelopeRef>> + Send;
}

impl<S: IntakeStore> StagedCommit for S {
    fn commit_staged_envelope(
        &self,
        env: CommitEnvelope,
    ) -> impl Future<Output = Result<EnvelopeRef>> + Send {
        self.commit_envelope(env)
    }
}

/// The store's end of `istore.sock` hand-overs. Share it (`&self` methods)
/// between the receiving threads and the slot-boundary sweep.
pub struct StagedReceiver {
    blobs: SafeRoot,
    sealer_uid: u32,
    max_len: u64,
    timeout: Duration,
    reg: Arc<Registry>,
}

impl core::fmt::Debug for StagedReceiver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StagedReceiver")
    }
}

impl StagedReceiver {
    /// A receiver writing into `blobs`, accepting hand-overs only from a peer
    /// whose `SO_PEERCRED` uid is `sealer_uid` (the sealer's dedicated system
    /// user; there is no default) and bundles of at most
    /// `min(max_len, STAGED_MAX_BUNDLE_LEN)` bytes (`max_len ≥ 1`).
    pub fn new(blobs: SafeRoot, sealer_uid: u32, max_len: u64) -> Result<Self> {
        if max_len == 0 {
            return Err(StoreError::InvalidInput("staged bound"));
        }
        Ok(Self {
            blobs,
            sealer_uid,
            max_len: max_len.min(STAGED_MAX_BUNDLE_LEN),
            timeout: STAGED_DEFAULT_TIMEOUT,
            reg: Arc::new(Registry::default()),
        })
    }

    /// Per-call socket deadline, clamped to
    /// [`STAGED_MIN_TIMEOUT`]..=[`STAGED_MAX_TIMEOUT`].
    #[must_use]
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t.clamp(STAGED_MIN_TIMEOUT, STAGED_MAX_TIMEOUT);
        self
    }

    /// The blob root.
    #[must_use]
    pub fn blobs(&self) -> &SafeRoot {
        &self.blobs
    }

    /// Blobs received and not yet committed or swept.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.reg.lock().len()
    }

    /// Blobs kept because their envelope commit outcome was unknown (health
    /// counter; content-free).
    #[must_use]
    pub fn uncertain_count(&self) -> u64 {
        self.reg.uncertain.load(Ordering::Relaxed)
    }

    /// Start-up: remove temp files of copies interrupted by a crash, then
    /// [`Self::sweep`] (crash leftovers: copied, never committed).
    pub async fn startup<M: IntakeMaintenance + ?Sized>(
        &self,
        refs: &M,
        slot: SlotTime,
    ) -> Result<usize> {
        self.blobs.purge_incomplete(slot).map_err(io_err)?;
        self.sweep(refs, slot).await
    }

    /// Receive one hand-over from `sock`, copy the passed file into the
    /// blob root (times normalised to `slot`) and, once the copy is durable,
    /// send `0x02 ‖ sha256` ("copied", AUD-RM2-STO-29). The total time is
    /// bounded: one `recvmsg` under `SO_RCVTIMEO`, then a copy of at most the
    /// bound from a sealed RAM-backed file, and one `send` under
    /// `SO_SNDTIMEO`. If a message was consumed and refused, `0x00` is sent
    /// (best effort). On any error the caller should close the connection.
    pub fn receive(&self, sock: BorrowedFd<'_>, slot: SlotTime) -> Result<StagedBlob> {
        let mut consumed = false;
        let r = self.receive_inner(sock, slot, &mut consumed);
        if r.is_err() && consumed {
            let _ = self.refuse(sock);
        }
        r
    }

    fn receive_inner(
        &self,
        sock: BorrowedFd<'_>,
        slot: SlotTime,
        consumed: &mut bool,
    ) -> Result<StagedBlob> {
        self.check_socket(sock)?;
        set_socket_timeout(sock, Timeout::Recv, Some(self.timeout)).map_err(io_err)?;
        let (header, fd) = receive_message(sock, consumed)?;
        if header.len > self.max_len {
            return Err(StoreError::InvalidInput("staged bundle too large"));
        }
        check_descriptor(&fd, header.len)?;
        // Reserve a registry entry before writing anything (bounded in-flight).
        let id = ObjectId::random().map_err(io_err)?;
        let blob_id = BlobId(*id.as_bytes());
        {
            let mut m = self.reg.lock();
            if m.len() >= STAGED_MAX_IN_FLIGHT {
                return Err(StoreError::Capacity);
            }
            if m.insert(blob_id, State::Receiving).is_some() {
                return Err(StoreError::Integrity("staged blob id reuse"));
            }
        }
        let mut guard = ReceiveGuard {
            reg: &self.reg,
            id: blob_id,
            outcome: None,
        };
        // An uncommitted safefs object is removed on drop.
        let mut pending = self.blobs.create_new(&id).map_err(io_err)?;
        copy_verified(&fd, &header, &mut pending)?;
        drop(fd);
        // From here a file may exist even if `commit` reports an error.
        guard.outcome = Some(State::Orphan);
        let got = pending.commit(slot).map_err(io_err)?;
        if got != id {
            return Err(StoreError::Integrity("staged blob id"));
        }
        guard.outcome = Some(State::Live);
        drop(guard);
        let blob = StagedBlob {
            blob_id,
            len: header.len,
            sha256: header.sha256,
            reg: Arc::clone(&self.reg),
            armed: true,
        };
        // STO-29: the copy is durable; tell the sealer, which now switches
        // from its length-scaled copy deadline to the fixed commit deadline.
        // If this fails the blob is dropped (orphan, swept) and refused.
        self.send_ack(sock, STAGED_ACK_COPIED, &header.sha256)?;
        Ok(blob)
    }

    /// `SO_PEERCRED` uid = the configured sealer uid, and `SOCK_SEQPACKET`.
    fn check_socket(&self, sock: BorrowedFd<'_>) -> Result<()> {
        let cred = socket_peercred(sock).map_err(|_| StoreError::InvalidInput("staged peer"))?;
        if cred.uid.as_raw() != self.sealer_uid {
            return Err(StoreError::InvalidInput("staged peer"));
        }
        if socket_type(sock).map_err(io_err)? != SocketType::SEQPACKET {
            return Err(StoreError::InvalidInput("staged socket type"));
        }
        Ok(())
    }

    /// Commit `env`, whose ATTACHMENT_BUNDLE object must reference exactly
    /// `blob` (id and size; no other object may name it), through
    /// `store.commit_envelope`, which returns after the database `COMMIT`.
    ///
    /// Outcomes: `Ok` → the token for [`Self::acknowledge`]. A rejection
    /// before the transaction or a capped wait that expired (validation,
    /// duplicate, not initialised, [`StoreError::Timeout`], …) →
    /// the blob is an orphan (swept). A backend error has an unknown outcome:
    /// the commit is retried once (a group that did commit is then reported
    /// as a duplicate); if that does not succeed, or the future is dropped
    /// mid-commit, no token is issued, the blob is counted in
    /// [`Self::uncertain_count`] and protected for one sweep, after which the
    /// database reference check decides. On `Err` call [`Self::refuse`].
    pub async fn commit_staged<C: StagedCommit + ?Sized>(
        &self,
        store: &C,
        env: CommitEnvelope,
        blob: StagedBlob,
    ) -> Result<CommittedStaged> {
        let (blob_id, len, sha256, reg) = blob.disarm();
        if !references_exactly(&env, blob_id, len) {
            reg.set(blob_id, State::Orphan);
            return Err(StoreError::InvalidInput("staged blob not referenced"));
        }
        reg.set(blob_id, State::Committing);
        let mut guard = CommitGuard {
            reg: &reg,
            id: blob_id,
            armed: true,
        };
        let first = store.commit_staged_envelope(env.clone()).await;
        let r = match first {
            Ok(r) => Ok(r),
            Err(StoreError::Backend) => match store.commit_staged_envelope(env).await {
                Ok(r) => Ok(r),
                // Unknown outcome (possibly committed): keep the blob.
                Err(_) => {
                    guard.armed = false;
                    reg.uncertain(blob_id);
                    return Err(StoreError::Backend);
                }
            },
            Err(e) => Err(e),
        };
        guard.armed = false;
        match r {
            Ok(envelope_ref) => {
                reg.forget(blob_id);
                Ok(CommittedStaged {
                    blob_id,
                    envelope_ref,
                    sha256,
                })
            }
            Err(e) => {
                reg.set(blob_id, State::Orphan);
                Err(e)
            }
        }
    }

    /// Send `0x01 ‖ sha256` (the hash of the committed bundle); possible only
    /// with the token of a committed envelope.
    pub fn acknowledge(&self, sock: BorrowedFd<'_>, committed: CommittedStaged) -> Result<()> {
        let CommittedStaged { sha256, .. } = committed;
        self.send_ack(sock, STAGED_ACK_COMMITTED, &sha256)
    }

    /// Send `0x00 ‖ 0³²` (nothing referencing the hand-over was committed).
    pub fn refuse(&self, sock: BorrowedFd<'_>) -> Result<()> {
        self.send_ack(sock, STAGED_ACK_REFUSED, &[0u8; 32])
    }

    fn send_ack(&self, sock: BorrowedFd<'_>, code: u8, sha256: &[u8; 32]) -> Result<()> {
        set_socket_timeout(sock, Timeout::Send, Some(self.timeout)).map_err(io_err)?;
        let msg = encode_staged_ack(code, sha256);
        let mut control = SendAncillaryBuffer::default();
        let n = rustix::net::sendmsg(
            sock,
            &[IoSlice::new(&msg)],
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .map_err(io_err)?;
        if n != STAGED_ACK_LEN {
            return Err(StoreError::Backend);
        }
        Ok(())
    }

    /// Sweep the staged blob directory: at start-up ([`Self::startup`]) and
    /// at every slot boundary, with that slot. A blob is removed only if it is
    /// not in flight in this receiver (being received, held as a
    /// [`StagedBlob`], being committed, or of unknown outcome for less than
    /// one sweep) **and** `refs.blob_referenced` says no committed envelope
    /// names it; any error counts as "referenced" (fail closed: the sweep stops
    /// without removing anything unchecked). Known orphans are checked first,
    /// then the other unregistered blobs (crash leftovers) in random order;
    /// at most [`STAGED_SWEEP_MAX_CHECKS`] lookups and
    /// [`STAGED_SWEEP_MAX_REMOVALS`] removals per call (the rest waits for
    /// the next slot). Removals run in shuffled order through safefs, which
    /// normalises directory times to `slot`; nothing is logged or recorded.
    ///
    /// The directory must be used by this receiver only (deploy rule): any
    /// other unreferenced object in it would be removed. Filesystem calls
    /// block briefly (one listing, bounded removals).
    pub async fn sweep<M: IntakeMaintenance + ?Sized>(
        &self,
        refs: &M,
        slot: SlotTime,
    ) -> Result<usize> {
        // List first, then snapshot the registry: a listed blob was
        // registered before its file existed, so if it is in flight it is in
        // the snapshot; one that has left the registry is committed (the
        // database says so) or was orphaned.
        let listed: Vec<BlobId> = self
            .blobs
            .list()
            .map_err(io_err)?
            .iter()
            .map(|o| BlobId(*o.as_bytes()))
            .collect();
        let listed_set: HashSet<BlobId> = listed.iter().copied().collect();
        let mut known = Vec::new();
        let mut others = Vec::new();
        {
            let mut m = self.reg.lock();
            // Orphans and aged uncertain entries whose file is gone are
            // dropped; the rest of them are candidates. Fresh uncertain
            // entries age now and become candidates at the next sweep.
            m.retain(|id, st| match *st {
                State::Orphan | State::Uncertain(true) => listed_set.contains(id),
                _ => true,
            });
            for id in &listed {
                match m.get_mut(id) {
                    None => others.push(*id),
                    Some(st @ State::Uncertain(false)) => *st = State::Uncertain(true),
                    Some(st) if !st.in_flight() => known.push(*id),
                    Some(_) => {}
                }
            }
            // Uncertain entries whose file is not listed age too.
            for st in m.values_mut() {
                if *st == State::Uncertain(false) {
                    *st = State::Uncertain(true);
                }
            }
        }
        shuffle(&mut known)?;
        shuffle(&mut others)?;
        let mut doomed = Vec::new();
        for id in known
            .into_iter()
            .chain(others)
            .take(STAGED_SWEEP_MAX_CHECKS)
        {
            if doomed.len() >= STAGED_SWEEP_MAX_REMOVALS {
                break;
            }
            if !refs.blob_referenced(id).await? {
                doomed.push(id);
            }
        }
        shuffle(&mut doomed)?;
        let mut removed = 0usize;
        let mut failed = false;
        for id in doomed {
            // Re-check under the lock: never remove a blob that became in
            // flight (it cannot, ids are fresh, but fail safe).
            if self.reg.lock().get(&id).is_some_and(|st| st.in_flight()) {
                continue;
            }
            let oid = ObjectId::from_bytes(id.0);
            match self.blobs.remove(&oid, slot) {
                Ok(()) => {
                    self.reg.forget(id);
                    removed = removed.saturating_add(1);
                }
                Err(_) => failed = true,
            }
        }
        if failed {
            return Err(StoreError::Backend);
        }
        Ok(removed)
    }
}

/// Unbiased Fisher–Yates shuffle from the OS CSPRNG (fail closed).
fn shuffle<T>(v: &mut [T]) -> Result<()> {
    let mut i = v.len();
    while i > 1 {
        let bound = u64::try_from(i).map_err(|_| StoreError::Capacity)?;
        // Rejection sampling: accept only below the largest multiple of `bound`.
        let rem = u64::MAX.checked_rem(bound).ok_or(StoreError::Capacity)?;
        let zone = u64::MAX.saturating_sub(rem);
        let r = loop {
            let mut b = [0u8; 8];
            crate::rng::fill(&mut b)?;
            let x = u64::from_le_bytes(b);
            if x < zone {
                break x.checked_rem(bound).ok_or(StoreError::Capacity)?;
            }
        };
        i = i.saturating_sub(1);
        v.swap(i, usize::try_from(r).map_err(|_| StoreError::Capacity)?);
    }
    Ok(())
}

/// The bundle object (and only it) names `id`, with size `len`.
fn references_exactly(env: &CommitEnvelope, id: BlobId, len: u64) -> bool {
    let mut hits = 0usize;
    for (i, o) in env.objects.iter().enumerate() {
        if o.blob.blob_id == id {
            if i != STAGED_BUNDLE_INDEX || o.blob.padded_size != len {
                return false;
            }
            hits = hits.saturating_add(1);
        }
    }
    hits == 1
}

fn io_err<E>(_e: E) -> StoreError {
    StoreError::Backend
}

/// Regular file, all five seals, `fstat` size = `len`.
fn check_descriptor(fd: &OwnedFd, len: u64) -> Result<()> {
    let st = fstat(fd).map_err(io_err)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(StoreError::InvalidInput(
            "staged descriptor not a regular file",
        ));
    }
    // F_GET_SEALS fails (EINVAL) on files that cannot be sealed.
    let seals = fcntl_get_seals(fd)
        .map_err(|_| StoreError::InvalidInput("staged descriptor not sealed"))?;
    if !seals.contains(REQUIRED_SEALS) {
        return Err(StoreError::InvalidInput("staged descriptor not sealed"));
    }
    if u64::try_from(st.st_size).ok() != Some(len) {
        return Err(StoreError::InvalidInput("staged size mismatch"));
    }
    Ok(())
}

/// Copy `header.len` bytes with `pread` from offset 0, then require EOF and
/// the header hash.
fn copy_verified(fd: &OwnedFd, header: &StagedHeader, out: &mut impl Write) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    let mut off: u64 = 0;
    while off < header.len {
        let want = usize::try_from(header.len.saturating_sub(off).min(CHUNK_U64))
            .map_err(|_| StoreError::InvalidInput("staged length"))?;
        let chunk = buf
            .get_mut(..want)
            .ok_or(StoreError::InvalidInput("staged length"))?;
        let n = rustix::io::pread(fd, &mut *chunk, off).map_err(io_err)?;
        if n == 0 {
            return Err(StoreError::InvalidInput("staged file shrank"));
        }
        let got = chunk
            .get(..n)
            .ok_or(StoreError::InvalidInput("staged length"))?;
        hasher.update(got);
        out.write_all(got).map_err(io_err)?;
        off = off
            .checked_add(u64::try_from(n).map_err(|_| StoreError::Capacity)?)
            .ok_or(StoreError::Capacity)?;
    }
    // The file must not have grown (impossible with the seals; kept as a
    // second line of defence).
    let mut probe = [0u8; 1];
    if rustix::io::pread(fd, &mut probe, header.len).map_err(io_err)? != 0 {
        return Err(StoreError::InvalidInput("staged file grew"));
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if !bool::from(digest.ct_eq(&header.sha256)) {
        return Err(StoreError::InvalidInput("staged hash mismatch"));
    }
    Ok(())
}

/// `recvmsg` one message with exactly one control message carrying exactly
/// one descriptor; every descriptor received is owned (closed on drop), so
/// surplus ones never leak. `consumed` is set once a message was dequeued.
fn receive_message(sock: BorrowedFd<'_>, consumed: &mut bool) -> Result<(StagedHeader, OwnedFd)> {
    let mut data = [0u8; STAGED_MSG_LEN + 1];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = rustix::net::recvmsg(
        sock,
        &mut [IoSliceMut::new(&mut data)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|e| {
        if e == rustix::io::Errno::AGAIN {
            StoreError::InvalidInput("staged receive deadline")
        } else {
            StoreError::Backend
        }
    })?;
    *consumed = true;
    let mut fds: Vec<OwnedFd> = Vec::new();
    let mut cmsgs = 0usize;
    let mut extra = false;
    for m in control.drain() {
        cmsgs = cmsgs.saturating_add(1);
        match m {
            RecvAncillaryMessage::ScmRights(it) => fds.extend(it),
            _ => extra = true,
        }
    }
    if msg
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(StoreError::InvalidInput("staged message truncated"));
    }
    if extra || cmsgs > 1 {
        return Err(StoreError::InvalidInput("staged ancillary data"));
    }
    let header = StagedHeader::decode(
        data.get(..msg.bytes)
            .ok_or(StoreError::InvalidInput("staged message length"))?,
    )?;
    if fds.len() != 1 {
        return Err(StoreError::InvalidInput("staged descriptor count"));
    }
    let fd = fds
        .pop()
        .ok_or(StoreError::InvalidInput("staged descriptor count"))?;
    Ok((header, fd))
}

/// Encode a 33-byte acknowledgement `code ‖ sha256` (AUD-RM2-STO-29).
#[must_use]
pub fn encode_staged_ack(code: u8, sha256: &[u8; 32]) -> [u8; STAGED_ACK_LEN] {
    let mut m = [0u8; STAGED_ACK_LEN];
    let (c, h) = m.split_at_mut(1);
    c.copy_from_slice(&[code]);
    h.copy_from_slice(sha256);
    m
}

/// Send a hand-over message with one descriptor (sealer side and tests).
pub fn send_staged_bundle(
    sock: impl AsFd,
    header: &StagedHeader,
    file: BorrowedFd<'_>,
) -> Result<()> {
    let msg = header.encode();
    let fds = [file];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !control.push(rustix::net::SendAncillaryMessage::ScmRights(&fds)) {
        return Err(StoreError::Backend);
    }
    let n = rustix::net::sendmsg(
        sock,
        &[IoSlice::new(&msg)],
        &mut control,
        SendFlags::NOSIGNAL,
    )
    .map_err(io_err)?;
    if n != STAGED_MSG_LEN {
        return Err(StoreError::Backend);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn header_strict_decoding() {
        let h = StagedHeader {
            len: 300_000,
            sha256: [7; 32],
        };
        let m = h.encode();
        assert_eq!(StagedHeader::decode(&m).unwrap(), h);
        assert!(StagedHeader::decode(&m[..40]).is_err());
        let mut long = m.to_vec();
        long.push(0);
        assert!(StagedHeader::decode(&long).is_err());
        // Unknown versions, including the retired version 1 (STO-29).
        for ver in [0u8, 1, 3, 0xff] {
            let mut v = m;
            v[0] = ver;
            assert!(StagedHeader::decode(&v).is_err());
        }
        assert_eq!(m[0], STAGED_VERSION);
        let zero = StagedHeader {
            len: 0,
            sha256: [0; 32],
        };
        assert!(StagedHeader::decode(&zero.encode()).is_err());
    }

    /// AUD-RM2-STO-29: acknowledgements are `code ‖ sha256`, 33 bytes.
    #[test]
    fn ack_encoding() {
        let a = encode_staged_ack(STAGED_ACK_COPIED, &[9; 32]);
        assert_eq!(a.len(), STAGED_ACK_LEN);
        assert_eq!(a[0], STAGED_ACK_COPIED);
        assert_eq!(&a[1..], &[9u8; 32]);
    }

    proptest::proptest! {
        /// Decoding arbitrary bytes never panics; valid messages round-trip.
        #[test]
        fn decode_total(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64)) {
            if let Ok(h) = StagedHeader::decode(&data) {
                proptest::prop_assert_eq!(h.encode().to_vec(), data);
            }
        }
    }
}
