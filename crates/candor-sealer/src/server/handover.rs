// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sealed ATTACHMENT_BUNDLE files and their hand-over to the Intake Store
//! (deploy D-33, AUD-RM2-SEA-16).
//!
//! The store has no access to the sealer's staging directory, so a sealed
//! bundle reaches it as an **open file descriptor** over `istore.sock`
//! (`AF_UNIX`, `SOCK_SEQPACKET`) with `SCM_RIGHTS`, never as a path. The
//! sealer writes each sealed bundle into an anonymous `memfd` (no name in any
//! directory, RAM-backed like the staging tmpfs, charged to the sealer's
//! cgroup with `MemorySwapMax=0`), created `MFD_NOEXEC_SEAL` (never
//! executable, DEP-29), and seals it read-only and size-fixed
//! (`F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_EXEC | F_SEAL_SEAL`) before it is
//! handed over: neither side can change the ciphertext while the store copies
//! it, and it disappears when the last descriptor is closed — nothing has to
//! be deleted after the store's acknowledgement, and nothing is left behind by
//! a crash. (`candor-safefs` exposes no descriptor of a staged object, so the
//! staging directory itself keeps only the STREAM-encrypted upload parts.)
//!
//! Wire format (matches `candor-intake-store::staged`, protocol version 2,
//! AUD-RM2-STO-29 / C-5): one SEQPACKET message
//! `u8 version (= 2) ‖ u64be len ‖ SHA-256(file bytes)` (41 bytes) carrying
//! exactly one descriptor. The store answers with 33-byte acknowledgements
//! `u8 code ‖ SHA-256(file bytes)` that echo the bundle hash, so an
//! acknowledgement is bound to the bundle it acknowledges:
//! 1. `0x02 ‖ h` ("copied") once its copy is durable in the blob root; the
//!    sealer waits for it at most [`copy_deadline`]`(len)` = [`COPY_DEADLINE_BASE`]
//!    + `len / `[`MIN_COPY_RATE`] (length-scaled);
//! 2. `0x01 ‖ h` ("committed") once the envelope referencing the copy is
//!    durably committed, within the fixed [`ACK_TIMEOUT`] (60 s) after `0x02`.
//!
//! `0x00` (refused), a wrong hash, a missing `0x02`, any other code or
//! length, a descriptor sent back, a short read, EOF, a timeout or an error
//! is a failure (fail closed) and closes the connection. Both sides enforce
//! the same bundle-size cap ([`MAX_BUNDLE_LEN`] here, `STAGED_MAX_BUNDLE_LEN`
//! in the store): an oversize bundle is refused before anything is sent.
//!
//! All calls block; [`crate::server::EnvelopeSink`] implementations run on a
//! blocking thread.

use std::io::{IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::Arc;

use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, fstat, memfd_create}; // safefs-lint: allow(fd-only memfd API, no path)
use rustix::net::{
    RecvAncillaryBuffer, RecvFlags, ReturnFlags, SendAncillaryBuffer, SendAncillaryMessage,
    SendFlags,
};
use sha2::{Digest, Sha256};

use super::sink::SinkError;

/// Protocol version of the hand-over message (2: two-phase acknowledgements
/// with hash echo, AUD-RM2-STO-29).
pub const VERSION: u8 = 2;
/// Exact length of the hand-over message.
pub const MSG_LEN: usize = 1 + 8 + 32;
/// Exact length of an acknowledgement: `u8 code ‖ SHA-256(bundle)`.
pub const ACK_LEN: usize = 1 + 32;
/// Acknowledgement code: the envelope referencing the copy is committed.
pub const ACK_COMMITTED: u8 = 0x01;
/// Acknowledgement code: refused (nothing committed).
pub const ACK_REFUSED: u8 = 0x00;
/// Acknowledgement code: the store's copy is durable; the commit follows.
pub const ACK_COPIED: u8 = 0x02;
/// Largest bundle handed over (bytes). The store enforces the same cap
/// (`candor_intake_store::staged::STAGED_MAX_BUNDLE_LEN`); one value for both
/// sides (AUD-RM2-STO-29). 4 GiB = the Tier W per-file maximum of 07 §11.
pub const MAX_BUNDLE_LEN: u64 = 4 << 30;
/// Fixed part of the copy deadline.
pub const COPY_DEADLINE_BASE: std::time::Duration = std::time::Duration::from_secs(10);
/// Copy-rate floor (bytes per second) the copy deadline is scaled with. The
/// store's blob volume must sustain it (deploy requirement, checked by
/// `config-check`; recorded in SPEC-NOTES).
pub const MIN_COPY_RATE: u64 = 50_000_000;

/// A sealed bundle: an immutable anonymous file (sealed `memfd`) with its
/// exact length and SHA-256. Cloning shares the descriptor.
#[derive(Clone)]
pub struct StagedBundle {
    fd: Arc<OwnedFd>,
    len: u64,
    sha256: [u8; 32],
}

impl core::fmt::Debug for StagedBundle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // No size (metadata) and no descriptor number in debug output.
        f.write_str("StagedBundle(<redacted>)")
    }
}

impl PartialEq for StagedBundle {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && candor_core::kdf::ct_eq(&self.sha256, &other.sha256)
    }
}

impl Eq for StagedBundle {}

impl StagedBundle {
    /// Exact length in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Never empty (a bundle always has a header).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// SHA-256 of the bytes.
    #[must_use]
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    /// The (sealed, read-only) descriptor, for [`send`].
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Read the whole file (`pread` from offset 0), for in-process sinks and
    /// tests. Bounded by the recorded length.
    pub fn read_to_vec(&self) -> Result<Vec<u8>, SinkError> {
        let n = usize::try_from(self.len).map_err(|_| SinkError)?;
        let mut v = vec![0u8; n];
        let mut off = 0usize;
        while off < n {
            let buf = v.get_mut(off..).ok_or(SinkError)?;
            let pos = u64::try_from(off).map_err(|_| SinkError)?;
            let got = rustix::io::pread(&*self.fd, buf, pos).map_err(|_| SinkError)?;
            if got == 0 {
                return Err(SinkError);
            }
            off = off.checked_add(got).ok_or(SinkError)?;
        }
        Ok(v)
    }
}

/// Writer for a new sealed bundle (sealed by [`BundleWriter::finish`]).
pub(crate) struct BundleWriter {
    fd: OwnedFd,
    hasher: Sha256,
    len: u64,
}

impl BundleWriter {
    /// A new anonymous file (`MFD_CLOEXEC | MFD_ALLOW_SEALING`; the name is a
    /// constant and carries no metadata).
    pub(crate) fn new() -> std::io::Result<Self> {
        // Anonymous memory file: no path, no directory entry; created
        // non-executable with the exec seal already set (MFD_NOEXEC_SEAL,
        // DEP-29; implies MFD_ALLOW_SEALING).
        let flags = MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING | MemfdFlags::NOEXEC_SEAL;
        let fd = memfd_create("candor-bundle", flags)?;
        Ok(Self {
            fd,
            hasher: Sha256::new(),
            len: 0,
        })
    }

    /// Make the file immutable and return it.
    pub(crate) fn finish(self) -> std::io::Result<StagedBundle> {
        let seals = SealFlags::WRITE
            | SealFlags::GROW
            | SealFlags::SHRINK
            | SealFlags::EXEC
            | SealFlags::SEAL;
        fcntl_add_seals(&self.fd, seals)?;
        let st = fstat(&self.fd)?;
        if u64::try_from(st.st_size).ok() != Some(self.len) {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
        }
        Ok(StagedBundle {
            fd: Arc::new(self.fd),
            len: self.len,
            sha256: self.hasher.finalize().into(),
        })
    }
}

impl std::io::Write for BundleWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = rustix::io::write(&self.fd, buf)?;
        let done = buf.get(..n).ok_or(std::io::ErrorKind::InvalidData)?;
        self.hasher.update(done);
        self.len = self
            .len
            .checked_add(u64::try_from(n).map_err(|_| std::io::ErrorKind::InvalidData)?)
            .ok_or(std::io::ErrorKind::InvalidData)?;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Start-up check (DEP-29): the kernel supports `MFD_NOEXEC_SEAL` (Linux ≥
/// 6.3). There is no fallback: the sealer refuses to start without it.
pub(crate) fn check_memfd_support() -> std::io::Result<()> {
    let w = BundleWriter::new()?;
    drop(w);
    Ok(())
}

/// Encode the 41-byte hand-over header.
#[must_use]
pub fn encode_header(b: &StagedBundle) -> [u8; MSG_LEN] {
    let mut m = [0u8; MSG_LEN];
    let (v, rest) = m.split_at_mut(1);
    let (l, h) = rest.split_at_mut(8);
    v.copy_from_slice(&[VERSION]);
    l.copy_from_slice(&b.len.to_be_bytes());
    h.copy_from_slice(&b.sha256);
    m
}

/// Send the hand-over message with the bundle's descriptor over `sock`.
pub(crate) fn send(sock: impl AsFd, b: &StagedBundle) -> Result<(), SinkError> {
    let msg = encode_header(b);
    let fds = [b.as_fd()];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(SinkError);
    }
    let n = rustix::net::sendmsg(
        sock,
        &[IoSlice::new(&msg)],
        &mut control,
        SendFlags::NOSIGNAL,
    )
    .map_err(|_| SinkError)?;
    if n == MSG_LEN { Ok(()) } else { Err(SinkError) }
}

/// Longest wait for the store's commit acknowledgement after its `0x02`
/// (its commit includes an `fsync`); a hung store fails the commit instead of
/// pinning a thread.
pub const ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Length-scaled wait for the store's `0x02` ("copied"):
/// `base + ceil(len / MIN_COPY_RATE)` seconds, saturating.
#[must_use]
pub fn copy_deadline_with(base: std::time::Duration, len: u64) -> std::time::Duration {
    let secs = len.div_ceil(MIN_COPY_RATE);
    base.saturating_add(std::time::Duration::from_secs(secs))
}

/// [`copy_deadline_with`] with [`COPY_DEADLINE_BASE`].
#[must_use]
pub fn copy_deadline(len: u64) -> std::time::Duration {
    copy_deadline_with(COPY_DEADLINE_BASE, len)
}

/// Encode a 33-byte acknowledgement (store side and tests).
#[must_use]
pub fn encode_ack(code: u8, sha256: &[u8; 32]) -> [u8; ACK_LEN] {
    let mut m = [0u8; ACK_LEN];
    let (c, h) = m.split_at_mut(1);
    c.copy_from_slice(&[code]);
    h.copy_from_slice(sha256);
    m
}

/// Wait for one acknowledgement `code ‖ sha256`, at most `timeout`
/// (`SO_RCVTIMEO`). `Ok` only for exactly [`ACK_LEN`] bytes with the expected
/// code and the bundle's hash (constant-time compare); a refusal, another
/// code, a wrong hash, a timeout, EOF, a longer or shorter message or any
/// descriptor sent back is an error (received descriptors are closed).
pub(crate) fn await_ack_within(
    sock: impl AsFd,
    timeout: std::time::Duration,
    want: u8,
    sha256: &[u8; 32],
) -> Result<(), SinkError> {
    if timeout.is_zero() {
        return Err(SinkError);
    }
    rustix::net::sockopt::set_socket_timeout(
        &sock,
        rustix::net::sockopt::Timeout::Recv,
        Some(timeout),
    )
    .map_err(|_| SinkError)?;
    let mut data = [0u8; ACK_LEN + 1];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = rustix::net::recvmsg(
        sock,
        &mut [IoSliceMut::new(&mut data)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(|_| SinkError)?;
    let mut unexpected_fds = false;
    for m in control.drain() {
        unexpected_fds = true;
        if let rustix::net::RecvAncillaryMessage::ScmRights(fds) = m {
            // Close anything the peer sent.
            fds.for_each(drop);
        }
    }
    if unexpected_fds
        || msg.bytes != ACK_LEN
        || msg
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(SinkError);
    }
    let (code, echo) = data.split_first().ok_or(SinkError)?;
    let echo = echo.get(..32).ok_or(SinkError)?;
    let hash_ok = candor_core::kdf::ct_eq(echo, sha256);
    if *code == want && hash_ok {
        Ok(())
    } else {
        Err(SinkError)
    }
}

/// The sealer's connection to `istore.sock` for bundle hand-overs. Any error
/// or timeout **closes** the socket, so a late acknowledgement of a failed
/// hand-over can never be read as the acknowledgement of the next bundle; in
/// addition every acknowledgement echoes the bundle hash (AUD-RM2-STO-29).
/// After a failure the integrator reconnects and builds a new
/// `StoreConnection`.
pub struct StoreConnection {
    sock: Option<OwnedFd>,
    copy_base: std::time::Duration,
    ack_timeout: std::time::Duration,
}

impl core::fmt::Debug for StoreConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StoreConnection")
            .field("open", &self.sock.is_some())
            .finish_non_exhaustive()
    }
}

impl StoreConnection {
    /// Wrap a connected `istore.sock` descriptor (deadlines
    /// [`copy_deadline`] and [`ACK_TIMEOUT`]).
    #[must_use]
    pub fn new(sock: OwnedFd) -> Self {
        Self {
            sock: Some(sock),
            copy_base: COPY_DEADLINE_BASE,
            ack_timeout: ACK_TIMEOUT,
        }
    }

    /// As [`StoreConnection::new`] with `t` as both the fixed part of the copy
    /// deadline and the commit deadline (tests and integration tuning; the
    /// copy deadline still grows with the bundle length).
    #[must_use]
    pub fn with_ack_timeout(sock: OwnedFd, t: std::time::Duration) -> Self {
        Self {
            sock: Some(sock),
            copy_base: t,
            ack_timeout: t,
        }
    }

    /// The connection is usable (no failure so far).
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.sock.is_some()
    }

    /// Hand `b` over and wait for the store's `0x02` within the length-scaled
    /// copy deadline, then for its `0x01` within the commit deadline, both
    /// echoing `b`'s hash. A bundle above [`MAX_BUNDLE_LEN`] is refused before
    /// anything is sent. On any error the socket is closed and every later
    /// call fails.
    pub fn hand_over(&mut self, b: &StagedBundle) -> Result<(), SinkError> {
        let Some(sock) = self.sock.as_ref() else {
            return Err(SinkError);
        };
        let r = if b.len() > MAX_BUNDLE_LEN || b.is_empty() {
            Err(SinkError)
        } else {
            let hash = b.sha256();
            send(sock, b)
                .and_then(|()| {
                    await_ack_within(
                        sock,
                        copy_deadline_with(self.copy_base, b.len()),
                        ACK_COPIED,
                        &hash,
                    )
                })
                .and_then(|()| await_ack_within(sock, self.ack_timeout, ACK_COMMITTED, &hash))
        };
        if r.is_err() {
            self.sock = None;
        }
        r
    }

    /// C-5 seal-path wiring: hand over the ATTACHMENT_BUNDLE of `group`
    /// (ADR-052(1): every group has exactly one, real or chaff). Only a
    /// [`super::sink::Blob::Staged`] bundle can be handed over; an inline
    /// bundle is a programming error and fails closed. Returns after the
    /// store's commit acknowledgement for this bundle.
    pub fn hand_over_group_bundle(
        &mut self,
        group: &super::sink::EnvelopeGroup,
    ) -> Result<(), SinkError> {
        match &group.bundle.blob {
            super::sink::Blob::Staged(b) => self.hand_over(b),
            super::sink::Blob::Inline(_) => {
                self.sock = None;
                Err(SinkError)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AUD-RM2-STO-29: the copy deadline grows with the length (base + len /
    /// floor rate, rounded up) and saturates instead of overflowing.
    #[test]
    fn copy_deadline_scales_with_length() {
        let s = std::time::Duration::from_secs;
        assert_eq!(copy_deadline(1), s(11));
        assert_eq!(copy_deadline(MIN_COPY_RATE), s(11));
        assert_eq!(copy_deadline(MIN_COPY_RATE + 1), s(12));
        // 1 GiB at 50 MB/s: 22 s of copy time.
        assert_eq!(copy_deadline(1 << 30), s(10 + 22));
        // The cap (4 GiB): 86 s of copy time plus the base.
        assert_eq!(copy_deadline(MAX_BUNDLE_LEN), s(10 + 86));
        assert!(copy_deadline(u64::MAX) >= s(u64::MAX / MIN_COPY_RATE));
    }

    #[test]
    fn ack_encoding_is_code_then_hash() {
        let a = encode_ack(ACK_COPIED, &[7; 32]);
        assert_eq!(a.len(), ACK_LEN);
        assert_eq!(a.first(), Some(&ACK_COPIED));
        assert!(a.iter().skip(1).all(|b| *b == 7));
    }
}
