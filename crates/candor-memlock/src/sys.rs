// SPDX-License-Identifier: AGPL-3.0-or-later
//! The crate's entire `unsafe` surface: two operations the standard library cannot express
//! safely. Each is a single `unsafe` block with its invariant stated above it, and each is
//! reachable only from [`crate::systemd_unix_listener`], which establishes the invariants
//! (single thread, main thread, first adoption) before calling here. The two `/proc/self`
//! reads here are existence/count probes of this process's own tables, never content.

use std::os::fd::{FromRawFd, OwnedFd};

use rustix::fs::{AtFlags, CWD, Dir, Mode, OFlags, openat, statat}; // safefs-lint: allow(two constant /proc/self probes of this process's own tables: fd-3 existence, thread count; no content, reviewed AUD-RM2-MEM-01/02)
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
/// Precondition (checked by the caller through [`thread_count`] == 1 and the main-thread
/// test): the process is single-threaded. Daemons call [`crate::systemd_unix_listener`] first
/// thing in `main`, before any runtime starts.
pub(crate) fn clear_listen_env() {
    for name in LISTEN_VARS {
        // SAFETY: `remove_var` is unsound only if another thread reads or writes the
        // environment concurrently (glibc's `environ` is not synchronised). The caller has
        // just verified that this process has exactly one thread (`/proc/self/task`) and that
        // it is the main thread, and no code between that check and this call spawns a thread,
        // so no concurrent access exists.
        unsafe { std::env::remove_var(name) };
    }
}

/// True when fd `SD_LISTEN_FDS_START` is open in this process: `/proc/self/fd/3` exists as a
/// symlink exactly then (`fstatat` with `AT_SYMLINK_NOFOLLOW` never follows it). No borrow of
/// the descriptor is constructed (AUD-RM2-MEM-02). Unreadable `/proc` reads as "not open".
#[allow(
    clippy::disallowed_methods,
    reason = "constant /proc/self path, existence probe of our own descriptor table (AUD-RM2-MEM-02); reviewed"
)]
fn fd3_is_open() -> bool {
    statat(CWD, "/proc/self/fd/3", AtFlags::SYMLINK_NOFOLLOW).is_ok()
}

/// Number of threads of this process: the entries of `/proc/self/task` (one per thread).
/// `None` when `/proc` is unreadable; the caller fails closed.
#[allow(
    clippy::disallowed_methods,
    reason = "constant /proc/self path, counts this process's own threads (AUD-RM2-MEM-01); reviewed"
)]
pub(crate) fn thread_count() -> Option<usize> {
    let dir = openat(
        CWD,
        "/proc/self/task",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .ok()?;
    let mut n = 0usize;
    for entry in Dir::read_from(&dir).ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            n = n.checked_add(1)?;
        }
    }
    Some(n)
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
    if !fd3_is_open() {
        ADOPTED.store(false, Ordering::SeqCst);
        return Err(AdoptError::BadFd);
    }
    // SAFETY: `from_raw_fd` requires that the descriptor is open and that no other owner will
    // close it. It is open (`fd3_is_open` above, in a single-threaded process: nothing can
    // close it in between). systemd passes the activated socket as fd 3 (`sd_listen_fds(3)`)
    // and nothing else in the process has adopted it: this function runs at most once (the
    // `ADOPTED` swap above), before any other descriptor-owning code, and the caller has
    // verified `LISTEN_PID == getpid()` and `LISTEN_FDS == 1`.
    Ok(unsafe { OwnedFd::from_raw_fd(SD_LISTEN_FDS_START) })
}

/// Re-arms [`adopt_fd3`] after an adoption whose descriptor failed validation and has been
/// closed by dropping its `OwnedFd`. Sound because at that point no object owns fd 3 any
/// more; a successful adoption never re-arms (the caller holds the descriptor for life).
pub(crate) fn release_failed_adoption() {
    ADOPTED.store(false, Ordering::SeqCst);
}
