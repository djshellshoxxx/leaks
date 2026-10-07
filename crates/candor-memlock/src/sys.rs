// SPDX-License-Identifier: AGPL-3.0-or-later
//! The crate's entire `unsafe` surface: two operations the standard library cannot express
//! safely. Each is a single `unsafe` block with its invariant stated above it, and each is
//! reachable only from [`crate::systemd_unix_listener`], which establishes the invariants
//! (main thread, first adoption) before calling here. Nothing in this module reads input.

use std::os::fd::{BorrowedFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{AdoptError, SD_LISTEN_FDS_START};

/// Set once the descriptor has been adopted; a second adoption would create a second owner
/// of the same file descriptor (double close), so it is refused before the `unsafe` block.
static ADOPTED: AtomicBool = AtomicBool::new(false);

/// The environment variables systemd sets for socket activation (`sd_listen_fds(3)`).
const LISTEN_VARS: [&str; 3] = ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"];

/// True when the calling thread is the process's main thread (`gettid() == getpid()`).
pub(crate) fn on_main_thread() -> bool {
    rustix::thread::gettid().as_raw_nonzero() == rustix::process::getpid().as_raw_nonzero()
}

/// Removes `LISTEN_PID`, `LISTEN_FDS` and `LISTEN_FDNAMES` from the process environment, so
/// that neither a child process nor a later call can adopt the descriptor again.
///
/// Precondition (checked by the caller): the process is still single-threaded. Daemons call
/// [`crate::systemd_unix_listener`] first thing in `main`, before any runtime starts.
pub(crate) fn clear_listen_env() {
    for name in LISTEN_VARS {
        // SAFETY: `remove_var` is unsound only if another thread reads or writes the
        // environment concurrently (glibc's `environ` is not synchronised). The caller
        // guarantees a single-threaded process at this point (main thread, start of `main`,
        // no runtime, no thread spawned), so no concurrent access exists.
        unsafe { std::env::remove_var(name) };
    }
}

/// Takes ownership of file descriptor `SD_LISTEN_FDS_START` (3), exactly once per process.
///
/// Returns `Err(AdoptError::AlreadyAdopted)` on any later call and `Err(AdoptError::BadFd)`
/// when fd 3 is not open (an `OwnedFd` of a closed descriptor would abort the process on
/// drop: the standard library treats `close == EBADF` as an I/O-safety violation).
pub(crate) fn adopt_fd3() -> Result<OwnedFd, AdoptError> {
    if ADOPTED.swap(true, Ordering::SeqCst) {
        return Err(AdoptError::AlreadyAdopted);
    }
    // SAFETY: `borrow_raw` requires the descriptor to stay valid for the borrow's lifetime.
    // The borrow lives for one `fcntl(F_GETFD)` in a single-threaded process (caller's
    // precondition: main thread, start of `main`), so nothing can close fd 3 meanwhile; if
    // fd 3 is not open at all, `fcntl` reports `EBADF` and the borrow is never used again.
    let probe = unsafe { BorrowedFd::borrow_raw(SD_LISTEN_FDS_START) };
    if rustix::io::fcntl_getfd(probe).is_err() {
        ADOPTED.store(false, Ordering::SeqCst);
        return Err(AdoptError::BadFd);
    }
    // SAFETY: `from_raw_fd` requires that the descriptor is open and that no other owner will
    // close it. It is open (probe above). systemd passes the activated socket as fd 3
    // (`sd_listen_fds(3)`) and nothing else in the process has adopted it: this function runs
    // at most once (the `ADOPTED` swap above), before any other descriptor-owning code, and
    // the caller has verified `LISTEN_PID == getpid()` and `LISTEN_FDS == 1`.
    Ok(unsafe { OwnedFd::from_raw_fd(SD_LISTEN_FDS_START) })
}

/// Re-arms [`adopt_fd3`] after an adoption whose descriptor failed validation and has been
/// closed by dropping its `OwnedFd`. Sound because at that point no object owns fd 3 any
/// more; a successful adoption never re-arms (the caller holds the descriptor for life).
pub(crate) fn release_failed_adoption() {
    ADOPTED.store(false, Ordering::SeqCst);
}
