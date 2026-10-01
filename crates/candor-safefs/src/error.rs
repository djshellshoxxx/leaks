// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Error type. Messages never contain paths, names or content (EVID-008).

use std::fmt;
use std::io;

/// Errors from the safe-path store.
#[derive(Debug)]
#[non_exhaustive]
pub enum SafeFsError {
    /// The root directory fails its policy (symlinked component, not a
    /// directory, wrong owner or mode).
    RootPolicy(&'static str),
    /// A string is not a canonical object id.
    InvalidObjectId,
    /// A slot time is not normalized (see [`crate::SlotTime`]).
    InvalidSlotTime,
    /// The object does not exist.
    NotFound,
    /// An object with this id already exists (random-id collision or reuse).
    AlreadyExists,
    /// The object on disk is not a plain, singly-linked regular file inside
    /// the root (symlink, hardlink, FIFO, device, directory, other device).
    UnsafeObject(&'static str),
    /// The object exceeds the root's size limit.
    TooLarge,
    /// Underlying I/O error (errno only; never a path).
    Io(io::ErrorKind),
}

impl fmt::Display for SafeFsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootPolicy(r) => write!(f, "storage root rejected: {r}"),
            Self::InvalidObjectId => f.write_str("invalid object id"),
            Self::InvalidSlotTime => f.write_str("slot time not normalized"),
            Self::NotFound => f.write_str("object not found"),
            Self::AlreadyExists => f.write_str("object already exists"),
            Self::UnsafeObject(r) => write!(f, "unsafe object refused: {r}"),
            Self::TooLarge => f.write_str("object exceeds size limit"),
            Self::Io(k) => write!(f, "i/o error: {k}"),
        }
    }
}

impl std::error::Error for SafeFsError {}

impl From<io::Error> for SafeFsError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::AlreadyExists => Self::AlreadyExists,
            k => {
                // ELOOP (symlink with O_NOFOLLOW) and ENOTDIR surface as
                // generic kinds; map them to an explicit refusal.
                match e.raw_os_error() {
                    Some(c) if c == rustix::io::Errno::LOOP.raw_os_error() => {
                        Self::UnsafeObject("symlink")
                    }
                    Some(c) if c == rustix::io::Errno::XDEV.raw_os_error() => {
                        Self::UnsafeObject("cross-device")
                    }
                    _ => Self::Io(k),
                }
            }
        }
    }
}

impl From<SafeFsError> for io::Error {
    fn from(e: SafeFsError) -> Self {
        let kind = match e {
            SafeFsError::NotFound => io::ErrorKind::NotFound,
            SafeFsError::AlreadyExists => io::ErrorKind::AlreadyExists,
            SafeFsError::Io(k) => k,
            _ => io::ErrorKind::InvalidData,
        };
        io::Error::new(kind, e.to_string())
    }
}
