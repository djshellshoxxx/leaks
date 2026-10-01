// SPDX-License-Identifier: AGPL-3.0-or-later
//! Sealed ATTACHMENT_BUNDLE files and their hand-over to the Intake Store
//! (deploy D-33, AUD-RM2-SEA-16).
//!
//! The store has no access to the sealer's staging directory, so a sealed
//! bundle reaches it as an **open file descriptor** over `istore.sock`
//! (`AF_UNIX`, `SOCK_SEQPACKET`) with `SCM_RIGHTS`, never as a path. The
//! sealer writes each sealed bundle into an anonymous `memfd` (no name in any
//! directory, RAM-backed like the staging tmpfs, charged to the sealer's
//! cgroup with `MemorySwapMax=0`) and seals it read-only and size-fixed
//! (`F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL`) before it is
//! handed over: neither side can change the ciphertext while the store copies
//! it, and it disappears when the last descriptor is closed — nothing has to
//! be deleted after the store's acknowledgement, and nothing is left behind by
//! a crash. (`candor-safefs` exposes no descriptor of a staged object, so the
//! staging directory itself keeps only the STREAM-encrypted upload parts.)
//!
//! Wire format (matches `candor-intake-store::staged`): one SEQPACKET message
//! `u8 version (= 1) ‖ u64be len ‖ SHA-256(file bytes)` (41 bytes) carrying
//! exactly one descriptor; the store answers one byte, `0x01` once the
//! envelope referencing the copy is durably committed, `0x00` if refused. Any
//! other answer, a short read, EOF or an error is a failure (fail closed).
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

/// Protocol version of the hand-over message.
pub const VERSION: u8 = 1;
/// Exact length of the hand-over message.
pub const MSG_LEN: usize = 1 + 8 + 32;
/// Acknowledgement: the envelope referencing the copy is committed.
pub const ACK_COMMITTED: u8 = 0x01;
/// Acknowledgement: refused (nothing committed).
pub const ACK_REFUSED: u8 = 0x00;

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
        // Anonymous memory file: no path, no directory entry.
        let flags = MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING;
        let fd = memfd_create("candor-bundle", flags)?;
        Ok(Self {
            fd,
            hasher: Sha256::new(),
            len: 0,
        })
    }

    /// Make the file immutable and return it.
    pub(crate) fn finish(self) -> std::io::Result<StagedBundle> {
        let seals = SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL;
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
pub fn send(sock: impl AsFd, b: &StagedBundle) -> Result<(), SinkError> {
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

/// Longest wait for the store's acknowledgement (its commit includes an
/// `fsync`); a hung store fails the commit instead of pinning a thread.
pub const ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Wait for the store's acknowledgement, at most [`ACK_TIMEOUT`]. `Ok` only
/// for [`ACK_COMMITTED`]; a refusal, a timeout, EOF, a longer message or any
/// descriptor sent back is an error (received descriptors are closed).
pub fn await_ack(sock: impl AsFd) -> Result<(), SinkError> {
    await_ack_within(sock, ACK_TIMEOUT)
}

/// [`await_ack`] with an explicit bound (`SO_RCVTIMEO` on the socket).
pub fn await_ack_within(sock: impl AsFd, timeout: std::time::Duration) -> Result<(), SinkError> {
    if timeout.is_zero() {
        return Err(SinkError);
    }
    rustix::net::sockopt::set_socket_timeout(
        &sock,
        rustix::net::sockopt::Timeout::Recv,
        Some(timeout),
    )
    .map_err(|_| SinkError)?;
    let mut data = [0u8; 2];
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
        || msg.bytes != 1
        || msg
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(SinkError);
    }
    match data.first() {
        Some(&ACK_COMMITTED) => Ok(()),
        _ => Err(SinkError),
    }
}

/// [`send`] then [`await_ack`]: returns `Ok` only once the store has durably
/// committed the envelope referencing its copy of the bundle.
pub fn hand_over(sock: impl AsFd, b: &StagedBundle) -> Result<(), SinkError> {
    send(&sock, b)?;
    await_ack(&sock)
}
