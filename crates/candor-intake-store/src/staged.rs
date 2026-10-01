// SPDX-License-Identifier: AGPL-3.0-or-later
//! Receive side of the staged-bundle hand-over (deploy D-33; integration item
//! for the sealer and store owners).
//!
//! The sealer writes a sealed ATTACHMENT_BUNDLE into its own tmpfs staging
//! root; the store has **no** access to that directory. The sealer passes the
//! staged file to the store as an open file descriptor over `istore.sock`
//! (`AF_UNIX`, `SOCK_SEQPACKET`) with `SCM_RIGHTS`, never as a path. The store
//! copies the bytes into its own blob store through `candor-safefs` (atomic
//! create + fsync + no-replace rename, timestamps normalised to the caller's
//! slot), and acknowledges to the sealer only after the envelope that
//! references the blob has been durably committed
//! ([`crate::IntakeStore::commit_envelope`] returns after `COMMIT`).
//!
//! Wire format (one SEQPACKET message, exactly one descriptor):
//! `u8 version (= 1) ‖ u64be len ‖ sha256(file bytes)(32)` = 41 bytes; the
//! reply is one byte, `0x01` (committed; the sealer may delete its file) or
//! `0x00` (refused; the sealer deletes its file and fails the seal).
//!
//! Hostile-peer discipline: truncated data or control messages, a wrong
//! message length, a missing descriptor or more than one (every received
//! descriptor is closed), a non-regular file, a size that differs from the
//! header, a file that changes during the copy, a length above the caller's
//! bound and a hash mismatch are all refused before anything is committed (an
//! uncommitted safefs object is removed on drop). The descriptor is read with
//! `pread` from offset 0 (its file offset is ignored) and never written.
//! No path, size or name is logged or put into an error.
//!
//! All calls block; run them on a blocking thread.

use std::fs::File;
use std::io::{IoSlice, IoSliceMut, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt;

use candor_safefs::{SafeRoot, SlotTime};
use rustix::fs::FileType;
use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendFlags,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{Result, StoreError};
use crate::types::{BlobId, EnvelopeRef, MAX_PART_PADDED_SIZE};

/// Protocol version of the hand-over message.
pub const STAGED_VERSION: u8 = 1;
/// Exact length of the hand-over message.
pub const STAGED_MSG_LEN: usize = 1 + 8 + 32;
/// Acknowledgement byte: the envelope referencing the blob is committed.
pub const STAGED_ACK_COMMITTED: u8 = 0x01;
/// Acknowledgement byte: refused (nothing committed).
pub const STAGED_ACK_REFUSED: u8 = 0x00;
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
    /// Exact file length in bytes (1 ..= the caller's bound).
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

/// A staged bundle copied into the blob store, not yet acknowledged. Commit
/// the envelope referencing [`Self::blob_id`], then call
/// [`acknowledge_committed`]; on failure call [`refuse`] and remove the blob.
#[must_use = "acknowledge after the envelope commit, or refuse and remove the blob"]
pub struct StagedBlob {
    /// Blob id in the store's blob root.
    pub blob_id: BlobId,
    /// Copied length.
    pub len: u64,
}

impl core::fmt::Debug for StagedBlob {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StagedBlob")
    }
}

fn io_err<E>(_e: E) -> StoreError {
    StoreError::Backend
}

/// Receive one hand-over message from `sock` and copy the passed file into
/// `blobs` (a `candor-safefs` blob root), with timestamps normalised to `slot`.
/// `max_len` bounds the accepted size (also capped at
/// [`MAX_PART_PADDED_SIZE`]). Nothing is committed unless every check passes;
/// every received descriptor is closed before return.
pub fn receive_staged_bundle(
    sock: BorrowedFd<'_>,
    blobs: &SafeRoot,
    slot: SlotTime,
    max_len: u64,
) -> Result<StagedBlob> {
    let (header, fd) = receive_message(sock)?;
    if header.len > max_len.min(MAX_PART_PADDED_SIZE) {
        return Err(StoreError::InvalidInput("staged bundle too large"));
    }
    let st = rustix::fs::fstat(&fd).map_err(io_err)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
        return Err(StoreError::InvalidInput(
            "staged descriptor not a regular file",
        ));
    }
    if u64::try_from(st.st_size).ok() != Some(header.len) {
        return Err(StoreError::InvalidInput("staged size mismatch"));
    }
    let file = File::from(fd);
    let mut pending = blobs.create_random().map_err(io_err)?;
    let mut hasher = Sha256::new();
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    let mut off: u64 = 0;
    while off < header.len {
        let want = usize::try_from(header.len.saturating_sub(off).min(CHUNK_U64))
            .map_err(|_| StoreError::InvalidInput("staged length"))?;
        let chunk = buf
            .get_mut(..want)
            .ok_or(StoreError::InvalidInput("staged length"))?;
        let n = file.read_at(chunk, off).map_err(io_err)?;
        if n == 0 {
            return Err(StoreError::InvalidInput("staged file shrank"));
        }
        let got = chunk
            .get(..n)
            .ok_or(StoreError::InvalidInput("staged length"))?;
        hasher.update(got);
        pending.write_all(got).map_err(io_err)?;
        off = off
            .checked_add(u64::try_from(n).map_err(|_| StoreError::Capacity)?)
            .ok_or(StoreError::Capacity)?;
    }
    // The file must not have grown while it was copied.
    let mut probe = [0u8; 1];
    if file.read_at(&mut probe, header.len).map_err(io_err)? != 0 {
        return Err(StoreError::InvalidInput("staged file grew"));
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if !bool::from(digest.ct_eq(&header.sha256)) {
        return Err(StoreError::InvalidInput("staged hash mismatch"));
    }
    let id = pending.commit(slot).map_err(io_err)?;
    Ok(StagedBlob {
        blob_id: BlobId(*id.as_bytes()),
        len: header.len,
    })
}

/// `recvmsg` one message with exactly one descriptor; every descriptor
/// received is owned (closed on drop), so surplus ones never leak.
fn receive_message(sock: BorrowedFd<'_>) -> Result<(StagedHeader, OwnedFd)> {
    let mut data = [0u8; STAGED_MSG_LEN + 1];
    let mut space = [MaybeUninit::<u8>::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let msg = rustix::net::recvmsg(
        sock,
        &mut [IoSliceMut::new(&mut data)],
        &mut control,
        RecvFlags::CMSG_CLOEXEC,
    )
    .map_err(io_err)?;
    let mut fds: Vec<OwnedFd> = Vec::new();
    for m in control.drain() {
        if let RecvAncillaryMessage::ScmRights(it) = m {
            fds.extend(it);
        }
    }
    if msg
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    {
        return Err(StoreError::InvalidInput("staged message truncated"));
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

fn send_byte(sock: BorrowedFd<'_>, b: u8) -> Result<()> {
    let mut control = SendAncillaryBuffer::default();
    let n = rustix::net::sendmsg(
        sock,
        &[IoSlice::new(&[b])],
        &mut control,
        SendFlags::NOSIGNAL,
    )
    .map_err(io_err)?;
    if n != 1 {
        return Err(StoreError::Backend);
    }
    Ok(())
}

/// Acknowledge a received bundle after the envelope referencing it was
/// committed: `committed` is the [`EnvelopeRef`] returned by
/// [`crate::IntakeStore::commit_envelope`], which returns only after the
/// database `COMMIT` (durable, ADR-046(1)); the blob itself was fsynced by
/// `candor-safefs` before. The sealer deletes its staged file on this byte.
pub fn acknowledge_committed(
    sock: BorrowedFd<'_>,
    blob: StagedBlob,
    committed: &EnvelopeRef,
) -> Result<()> {
    let _ = (blob, committed);
    send_byte(sock, STAGED_ACK_COMMITTED)
}

/// Refuse a hand-over (nothing referencing it was committed).
pub fn refuse(sock: BorrowedFd<'_>) -> Result<()> {
    send_byte(sock, STAGED_ACK_REFUSED)
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
        let mut v = m;
        v[0] = 2;
        assert!(StagedHeader::decode(&v).is_err());
        let zero = StagedHeader {
            len: 0,
            sha256: [0; 32],
        };
        assert!(StagedHeader::decode(&zero.encode()).is_err());
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
