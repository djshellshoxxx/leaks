// SPDX-License-Identifier: AGPL-3.0-or-later
//! `candor-memlock`: the allow-listed OS shim of the Candor workspace (IMPL-00 §4.5, SI-A-04;
//! WAVE-BRIEF §3). It is the only crate whose lints permit `unsafe`, and it keeps that surface
//! to the minimum the standard library cannot express safely (see `src/sys.rs`: adopting a raw
//! descriptor, removing environment variables in a single-threaded process).
//!
//! This slice provides one facility for the three intake daemons (C-06 web, C-07 sealer,
//! C-08 store; `deploy/intake/systemd/*.socket`): [`systemd_unix_listener`] adopts exactly one
//! pre-opened Unix listening socket from systemd socket activation (`sd_listen_fds(3)`), after
//! checking everything a hostile or mistaken environment could get wrong, and scrubs the
//! `LISTEN_*` variables. Any deviation is a typed [`AdoptError`]; nothing panics.
//!
//! Memory locking is **not** provided here: the daemons lock their whole address space with
//! `rustix::mm::mlockall(CURRENT | FUTURE)` (safe wrapper; `candor-sealer::server::hardening`,
//! `candor-intake-web::hardening`), so a separate `unsafe` `mlock` buffer would duplicate a
//! control that already exists without `unsafe` (SPEC-NOTES decision 3).

use std::fmt;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixListener;

use rustix::io::FdFlags;
use rustix::net::{AddressFamily, SocketType, sockopt};

#[allow(
    unsafe_code,
    reason = "IMPL-00 §4.5 allow-list: this module holds the crate's whole unsafe surface, reviewed as T0 (SPEC-NOTES decision 1)"
)]
mod sys;

/// The first descriptor systemd passes (`SD_LISTEN_FDS_START` in `sd-daemon(3)`).
pub const SD_LISTEN_FDS_START: i32 = 3;

/// Longest accepted value of any `LISTEN_*` variable (decimal pid: 10 digits; a name: the
/// `FileDescriptorName=` limit is 255 bytes). Longer values are refused unread.
const MAX_VALUE_LEN: usize = 255;

/// Why an activated socket was not adopted. Every variant is a refusal; the daemon must exit.
/// Values from the environment never appear in the message (ADR-016: no metadata in errors).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdoptError {
    /// Called from a thread other than the main thread (the environment may only be edited
    /// while the process is single-threaded; daemons call this first in `main`).
    NotMainThread,
    /// `LISTEN_PID` is absent: the process was not socket-activated.
    NotActivated,
    /// `LISTEN_PID` is not this process (a descriptor meant for a parent or another process).
    PidMismatch,
    /// `LISTEN_FDS` is absent or not exactly `1`.
    FdCount,
    /// `LISTEN_FDNAMES` is absent or not exactly the expected `FileDescriptorName=`.
    NameMismatch,
    /// A `LISTEN_*` value is malformed (non-decimal, leading zero, too long, non-UTF-8).
    InvalidValue,
    /// The descriptor was already adopted by an earlier call in this process.
    AlreadyAdopted,
    /// File descriptor 3 is not open.
    BadFd,
    /// File descriptor 3 is not a socket.
    NotSocket,
    /// The socket is not `AF_UNIX`.
    WrongFamily,
    /// The socket is neither `SOCK_STREAM` nor `SOCK_SEQPACKET`.
    WrongType,
    /// The socket is not in the listening state (`SO_ACCEPTCONN == 0`).
    NotListening,
    /// `fcntl(F_SETFD, FD_CLOEXEC)` failed.
    Fcntl,
}

impl fmt::Display for AdoptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotMainThread => "socket activation must be adopted on the main thread",
            Self::NotActivated => "not socket-activated (LISTEN_PID absent)",
            Self::PidMismatch => "LISTEN_PID is not this process",
            Self::FdCount => "LISTEN_FDS is not exactly 1",
            Self::NameMismatch => "LISTEN_FDNAMES is not the expected descriptor name",
            Self::InvalidValue => "malformed LISTEN_* value",
            Self::AlreadyAdopted => "the activated socket was already adopted",
            Self::BadFd => "descriptor 3 is not open",
            Self::NotSocket => "descriptor 3 is not a socket",
            Self::WrongFamily => "activated socket is not AF_UNIX",
            Self::WrongType => "activated socket is neither SOCK_STREAM nor SOCK_SEQPACKET",
            Self::NotListening => "activated socket is not listening",
            Self::Fcntl => "could not set FD_CLOEXEC on the activated socket",
        })
    }
}

impl std::error::Error for AdoptError {}

/// Socket type of an adopted listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    /// `SOCK_STREAM` (`ListenStream=`: `http` for C-06, `seal` for C-07).
    Stream,
    /// `SOCK_SEQPACKET` (`ListenSequentialPacket=`: `istore` for C-08).
    SeqPacket,
}

/// A validated, `FD_CLOEXEC` Unix listening socket adopted from systemd.
#[derive(Debug)]
pub struct AdoptedListener {
    fd: OwnedFd,
    kind: SocketKind,
}

impl AdoptedListener {
    /// The socket type systemd created.
    #[must_use]
    pub fn kind(&self) -> SocketKind {
        self.kind
    }

    /// The owned descriptor (for `SOCK_SEQPACKET` consumers that `accept4` through `rustix`).
    #[must_use]
    pub fn into_fd(self) -> OwnedFd {
        self.fd
    }

    /// The descriptor as a standard `UnixListener`; refused for a `SOCK_SEQPACKET` socket,
    /// which `std` cannot represent. The listener is still blocking: a tokio consumer calls
    /// `set_nonblocking(true)` before `tokio::net::UnixListener::from_std`.
    pub fn into_stream_listener(self) -> Result<UnixListener, AdoptError> {
        match self.kind {
            SocketKind::Stream => Ok(UnixListener::from(self.fd)),
            SocketKind::SeqPacket => Err(AdoptError::WrongType),
        }
    }
}

impl AsFd for AdoptedListener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Adopts the one Unix listening socket systemd passed to this process.
///
/// Checks, in order: main thread; `LISTEN_PID == getpid()`; `LISTEN_FDS == 1`;
/// `LISTEN_FDNAMES == expected_name`; fd 3 open, `FD_CLOEXEC` set; `AF_UNIX`; `SOCK_STREAM`
/// or `SOCK_SEQPACKET`; listening. The three `LISTEN_*` variables are removed from the
/// environment as soon as the main-thread check passes, on every path, so a child process or
/// a retry never sees them.
///
/// Call it first thing in `main`, before any thread or async runtime exists (the environment
/// edit is only sound in a single-threaded process). It succeeds at most once per process.
pub fn systemd_unix_listener(expected_name: &str) -> Result<AdoptedListener, AdoptError> {
    if !sys::on_main_thread() {
        return Err(AdoptError::NotMainThread);
    }
    let pid = std::env::var_os("LISTEN_PID");
    let fds = std::env::var_os("LISTEN_FDS");
    let names = std::env::var_os("LISTEN_FDNAMES");
    sys::clear_listen_env();
    let own_pid = rustix::process::getpid().as_raw_nonzero().get();
    check_listen_env(
        pid.as_deref().map(|v| v.as_encoded_bytes()),
        fds.as_deref().map(|v| v.as_encoded_bytes()),
        names.as_deref().map(|v| v.as_encoded_bytes()),
        own_pid,
        expected_name,
    )?;
    let fd = sys::adopt_fd3()?;
    match check_listener_fd(fd.as_fd()) {
        Ok(kind) => Ok(AdoptedListener { fd, kind }),
        Err(e) => {
            drop(fd);
            sys::release_failed_adoption();
            Err(e)
        }
    }
}

/// Validates the `sd_listen_fds(3)` environment against this process (pure; unit-tested
/// under Miri). `own_pid` is the caller's pid; `expected_name` the unit's
/// `FileDescriptorName=`.
pub fn check_listen_env(
    listen_pid: Option<&[u8]>,
    listen_fds: Option<&[u8]>,
    listen_fdnames: Option<&[u8]>,
    own_pid: u32,
    expected_name: &str,
) -> Result<(), AdoptError> {
    let pid = listen_pid.ok_or(AdoptError::NotActivated)?;
    if parse_decimal(pid)? != own_pid {
        return Err(AdoptError::PidMismatch);
    }
    let fds = listen_fds.ok_or(AdoptError::FdCount)?;
    if parse_decimal(fds)? != 1 {
        return Err(AdoptError::FdCount);
    }
    let names = listen_fdnames.ok_or(AdoptError::NameMismatch)?;
    if names.len() > MAX_VALUE_LEN {
        return Err(AdoptError::InvalidValue);
    }
    // One descriptor, so exactly one name: no ':' separator may be present.
    if names.is_empty() || names.contains(&b':') {
        return Err(AdoptError::InvalidValue);
    }
    if expected_name.is_empty() || names != expected_name.as_bytes() {
        return Err(AdoptError::NameMismatch);
    }
    Ok(())
}

/// Strict decimal `u32`: 1–10 ASCII digits, no sign, no leading zero, no overflow.
fn parse_decimal(v: &[u8]) -> Result<u32, AdoptError> {
    if v.is_empty() || v.len() > 10 || (v.len() > 1 && v.first() == Some(&b'0')) {
        return Err(AdoptError::InvalidValue);
    }
    let mut n: u32 = 0;
    for &c in v {
        let d = c
            .checked_sub(b'0')
            .filter(|d| *d <= 9)
            .ok_or(AdoptError::InvalidValue)?;
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(u32::from(d)))
            .ok_or(AdoptError::InvalidValue)?;
    }
    Ok(n)
}

/// Validates an already-owned descriptor as a Unix listening socket and sets `FD_CLOEXEC`.
/// Safe code only (rustix wrappers); used by [`systemd_unix_listener`] and directly testable.
pub fn check_listener_fd(fd: BorrowedFd<'_>) -> Result<SocketKind, AdoptError> {
    let flags = rustix::io::fcntl_getfd(fd).map_err(|e| {
        if e == rustix::io::Errno::BADF {
            AdoptError::BadFd
        } else {
            AdoptError::Fcntl
        }
    })?;
    if !flags.contains(FdFlags::CLOEXEC) {
        rustix::io::fcntl_setfd(fd, flags | FdFlags::CLOEXEC).map_err(|_| AdoptError::Fcntl)?;
    }
    let family = sockopt::socket_domain(fd).map_err(|_| AdoptError::NotSocket)?;
    if family != AddressFamily::UNIX {
        return Err(AdoptError::WrongFamily);
    }
    let kind = match sockopt::socket_type(fd).map_err(|_| AdoptError::NotSocket)? {
        SocketType::STREAM => SocketKind::Stream,
        SocketType::SEQPACKET => SocketKind::SeqPacket,
        _ => return Err(AdoptError::WrongType),
    };
    if !sockopt::socket_acceptconn(fd).map_err(|_| AdoptError::NotSocket)? {
        return Err(AdoptError::NotListening);
    }
    Ok(kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::net::{SocketAddrUnix, SocketFlags, bind, listen, socket_with, socketpair};

    const OK_PID: u32 = 4242;

    fn env(pid: Option<&str>, fds: Option<&str>, names: Option<&str>) -> Result<(), AdoptError> {
        check_listen_env(
            pid.map(str::as_bytes),
            fds.map(str::as_bytes),
            names.map(str::as_bytes),
            OK_PID,
            "http",
        )
    }

    // Miri-friendly (no syscalls): the environment contract, 07 §4.2 / deploy README
    // "Socket activation".
    #[test]
    fn env_accepts_exactly_one_named_descriptor_for_this_pid() {
        assert_eq!(env(Some("4242"), Some("1"), Some("http")), Ok(()));
    }

    #[test]
    fn env_misuse_is_refused_with_a_typed_error() {
        use AdoptError as E;
        assert_eq!(env(None, Some("1"), Some("http")), Err(E::NotActivated));
        assert_eq!(
            env(Some("4241"), Some("1"), Some("http")),
            Err(E::PidMismatch)
        );
        assert_eq!(env(Some("4242"), None, Some("http")), Err(E::FdCount));
        assert_eq!(env(Some("4242"), Some("2"), Some("http")), Err(E::FdCount));
        assert_eq!(env(Some("4242"), Some("0"), Some("http")), Err(E::FdCount));
        assert_eq!(env(Some("4242"), Some("1"), None), Err(E::NameMismatch));
        assert_eq!(
            env(Some("4242"), Some("1"), Some("seal")),
            Err(E::NameMismatch)
        );
        assert_eq!(
            env(Some("4242"), Some("1"), Some("http:seal")),
            Err(E::InvalidValue)
        );
        assert_eq!(env(Some("4242"), Some("1"), Some("")), Err(E::InvalidValue));
        assert_eq!(
            env(Some("04242"), Some("1"), Some("http")),
            Err(E::InvalidValue)
        );
        assert_eq!(
            env(Some("+4242"), Some("1"), Some("http")),
            Err(E::InvalidValue)
        );
        assert_eq!(
            env(Some("4242 "), Some("1"), Some("http")),
            Err(E::InvalidValue)
        );
        assert_eq!(env(Some(""), Some("1"), Some("http")), Err(E::InvalidValue));
        assert_eq!(
            env(Some("99999999999"), Some("1"), Some("http")),
            Err(E::InvalidValue)
        );
        assert_eq!(
            env(Some("4242"), Some("01"), Some("http")),
            Err(E::InvalidValue)
        );
        assert_eq!(
            env(Some("4242"), Some("1\n"), Some("http")),
            Err(E::InvalidValue)
        );
        let long = "x".repeat(MAX_VALUE_LEN.saturating_add(1));
        assert_eq!(
            env(Some("4242"), Some("1"), Some(&long)),
            Err(E::InvalidValue)
        );
        // An empty expected name can never match (a caller bug must not open the check).
        assert_eq!(
            check_listen_env(Some(b"4242"), Some(b"1"), Some(b""), OK_PID, ""),
            Err(E::InvalidValue)
        );
    }

    #[test]
    fn decimal_parser_is_strict_and_overflow_safe() {
        assert_eq!(parse_decimal(b"0"), Ok(0));
        assert_eq!(parse_decimal(b"4294967295"), Ok(u32::MAX));
        assert_eq!(parse_decimal(b"4294967296"), Err(AdoptError::InvalidValue));
        assert_eq!(parse_decimal(b"00"), Err(AdoptError::InvalidValue));
        assert_eq!(parse_decimal(b"1a"), Err(AdoptError::InvalidValue));
        assert_eq!(parse_decimal(b"-1"), Err(AdoptError::InvalidValue));
        assert_eq!(parse_decimal("٤".as_bytes()), Err(AdoptError::InvalidValue));
    }

    fn abstract_listener(kind: SocketType, tag: &str) -> OwnedFd {
        let fd = socket_with(AddressFamily::UNIX, kind, SocketFlags::CLOEXEC, None).unwrap();
        let name = format!("candor-memlock-test-{}-{tag}", std::process::id());
        bind(
            &fd,
            &SocketAddrUnix::new_abstract_name(name.as_bytes()).unwrap(),
        )
        .unwrap();
        listen(&fd, 1).unwrap();
        fd
    }

    #[test]
    fn listening_unix_sockets_of_both_types_pass_and_get_cloexec() {
        let s = abstract_listener(SocketType::STREAM, "stream");
        assert_eq!(check_listener_fd(s.as_fd()), Ok(SocketKind::Stream));
        let q = abstract_listener(SocketType::SEQPACKET, "seqpacket");
        assert_eq!(check_listener_fd(q.as_fd()), Ok(SocketKind::SeqPacket));
        // A descriptor created without CLOEXEC gets the flag set by the check.
        let plain = socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::empty(),
            None,
        )
        .unwrap();
        bind(
            &plain,
            &SocketAddrUnix::new_abstract_name(
                format!("candor-memlock-test-{}-plain", std::process::id()).as_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
        listen(&plain, 1).unwrap();
        assert!(
            !rustix::io::fcntl_getfd(&plain)
                .unwrap()
                .contains(FdFlags::CLOEXEC)
        );
        assert_eq!(check_listener_fd(plain.as_fd()), Ok(SocketKind::Stream));
        assert!(
            rustix::io::fcntl_getfd(&plain)
                .unwrap()
                .contains(FdFlags::CLOEXEC)
        );
    }

    #[test]
    fn wrong_descriptors_are_refused() {
        // Connected (not listening) pair.
        let (a, _b) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        assert_eq!(check_listener_fd(a.as_fd()), Err(AdoptError::NotListening));
        // Datagram socket: wrong type (checked before the listening state).
        let d = socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        assert_eq!(check_listener_fd(d.as_fd()), Err(AdoptError::WrongType));
        // AF_INET listener on the loopback: wrong family. No packet leaves the host.
        let inet = socket_with(
            AddressFamily::INET,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        assert_eq!(
            check_listener_fd(inet.as_fd()),
            Err(AdoptError::WrongFamily)
        );
        // Not a socket at all (the test process's stdin, whatever it is), or not open.
        let r = check_listener_fd(std::io::stdin().as_fd());
        assert!(
            matches!(r, Err(AdoptError::NotSocket | AdoptError::BadFd)),
            "{r:?}"
        );
    }

    #[test]
    fn adoption_off_the_main_thread_is_refused_without_touching_the_environment() {
        // libtest runs this on a worker thread, so the main-thread guard fires first and the
        // environment is left alone (this must not race other tests reading env vars).
        assert_eq!(
            systemd_unix_listener("http").err(),
            Some(AdoptError::NotMainThread)
        );
    }

    #[test]
    fn errors_carry_no_values() {
        for e in [
            AdoptError::PidMismatch,
            AdoptError::NameMismatch,
            AdoptError::InvalidValue,
        ] {
            let s = e.to_string();
            assert!(!s.contains(char::is_numeric), "{s}");
        }
    }
}
