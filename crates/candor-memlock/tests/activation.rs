// SPDX-License-Identifier: AGPL-3.0-or-later
//! End-to-end adoption on the main thread of a single-threaded process (`harness = false`):
//! the real `systemd_unix_listener` with the `LISTEN_*` environment systemd would set and a
//! listening socket at fd 3. Negative cases first (each failed adoption closes fd 3 and
//! re-arms), then the one success, then the "already adopted" refusal.
//!
//! `unsafe` here is only `std::env::set_var` (unsafe in edition 2024), run while this process
//! has exactly one thread.

#![allow(
    unsafe_code,
    reason = "test sets LISTEN_* in a single-threaded process"
)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use candor_memlock::{AdoptError, SD_LISTEN_FDS_START, SocketKind, systemd_unix_listener};
use rustix::net::{
    AddressFamily, SocketAddrUnix, SocketFlags, SocketType, bind, listen, socket_with,
};

fn set(name: &str, value: Option<&str>) {
    match value {
        // SAFETY: this test binary is single-threaded (no harness, no runtime, no spawned
        // thread), so nothing reads the environment concurrently.
        Some(v) => unsafe { std::env::set_var(name, v) },
        // SAFETY: as above.
        None => unsafe { std::env::remove_var(name) },
    }
}

fn set_env(pid: Option<&str>, fds: Option<&str>, names: Option<&str>) {
    set("LISTEN_PID", pid);
    set("LISTEN_FDS", fds);
    set("LISTEN_FDNAMES", names);
}

fn env_is_clear() -> bool {
    ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"]
        .iter()
        .all(|k| std::env::var_os(k).is_none())
}

/// Places `fd` at descriptor 3 (which must be free, or be `fd` itself: every earlier
/// adoption closed it, so the next descriptor the kernel hands out is 3).
fn at_fd3(fd: OwnedFd) -> OwnedFd {
    if fd.as_raw_fd() == SD_LISTEN_FDS_START {
        return fd;
    }
    let moved = rustix::io::fcntl_dupfd_cloexec(&fd, SD_LISTEN_FDS_START).unwrap();
    assert_eq!(
        moved.as_raw_fd(),
        SD_LISTEN_FDS_START,
        "fd 3 is not free in this test process"
    );
    drop(fd);
    moved
}

fn abstract_listener(kind: SocketType, tag: &str) -> OwnedFd {
    let fd = socket_with(AddressFamily::UNIX, kind, SocketFlags::empty(), None).unwrap();
    let name = format!("candor-memlock-activation-{}-{tag}", std::process::id());
    bind(
        &fd,
        &SocketAddrUnix::new_abstract_name(name.as_bytes()).unwrap(),
    )
    .unwrap();
    listen(&fd, 4).unwrap();
    fd
}

fn expect_err(what: &str, fd3: Option<OwnedFd>, name: &str, want: AdoptError) {
    // `fd3` is handed to the adoption, which closes it on failure; the duplicate we hold is
    // released without a second close by leaking the handle into the adoption's ownership.
    let keep = fd3.map(at_fd3);
    let got = systemd_unix_listener(name);
    assert!(env_is_clear(), "{what}: LISTEN_* not scrubbed");
    match got {
        Err(e) if e == want => {}
        other => panic!("{what}: expected {want:?}, got {other:?}"),
    }
    if let Some(k) = keep {
        // The adoption only reached fd 3 for the descriptor cases; there it already closed
        // fd 3 and our handle would double-close it, so the handle is detached. For the
        // environment cases the adoption never touched fd 3 and we close it here.
        match want {
            AdoptError::BadFd
            | AdoptError::NotSocket
            | AdoptError::WrongFamily
            | AdoptError::WrongType
            | AdoptError::NotListening
            | AdoptError::Fcntl => {
                let _ = std::os::fd::IntoRawFd::into_raw_fd(k);
            }
            _ => drop(k),
        }
    }
}

/// Closes an fd 3 inherited from whoever started this binary (a shell may leave one open),
/// so the kernel hands out 3 next. Under `cargo test` nothing is there.
fn free_fd3() {
    // SAFETY: the borrow lives for one `fcntl` in this single-threaded process; nothing can
    // close fd 3 meanwhile.
    let probe = unsafe { std::os::fd::BorrowedFd::borrow_raw(SD_LISTEN_FDS_START) };
    if rustix::io::fcntl_getfd(probe).is_ok() {
        // SAFETY: fd 3 is open (probe above) and no Rust object in this process owns it (it
        // was inherited at exec); taking ownership here closes it exactly once.
        let inherited: OwnedFd =
            unsafe { std::os::fd::FromRawFd::from_raw_fd(SD_LISTEN_FDS_START) };
        drop(inherited);
    }
}

fn main() {
    free_fd3();
    let pid = std::process::id().to_string();
    let good = |n: &'static str| (Some(pid.as_str()), Some("1"), Some(n));
    assert_eq!(
        rustix::thread::gettid().as_raw_nonzero(),
        rustix::process::getpid().as_raw_nonzero()
    );

    // Environment misuse (fd 3 untouched, nothing adopted).
    set_env(None, None, None);
    expect_err("no activation", None, "http", AdoptError::NotActivated);
    set_env(Some("1"), Some("1"), Some("http"));
    expect_err("foreign pid", None, "http", AdoptError::PidMismatch);
    set_env(Some(&pid), Some("2"), Some("http:seal"));
    expect_err("two descriptors", None, "http", AdoptError::FdCount);
    set_env(Some(&pid), Some("1"), Some("seal"));
    expect_err("other name", None, "http", AdoptError::NameMismatch);
    set_env(Some(&pid), Some("1"), None);
    expect_err("unnamed", None, "http", AdoptError::NameMismatch);
    set_env(Some(&pid), Some("x"), Some("http"));
    expect_err("garbage count", None, "http", AdoptError::InvalidValue);

    // Descriptor misuse with a correct environment.
    let (p, f, n) = good("http");
    set_env(p, f, n);
    expect_err("fd 3 closed", None, "http", AdoptError::BadFd);
    let (sa, _sb) = rustix::net::socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::empty(),
        None,
    )
    .unwrap();
    set_env(p, f, n);
    expect_err(
        "connected, not listening",
        Some(sa),
        "http",
        AdoptError::NotListening,
    );
    let inet = socket_with(
        AddressFamily::INET,
        SocketType::STREAM,
        SocketFlags::empty(),
        None,
    )
    .unwrap();
    set_env(p, f, n);
    expect_err("AF_INET", Some(inet), "http", AdoptError::WrongFamily);
    let dgram = socket_with(
        AddressFamily::UNIX,
        SocketType::DGRAM,
        SocketFlags::empty(),
        None,
    )
    .unwrap();
    set_env(p, f, n);
    expect_err("SOCK_DGRAM", Some(dgram), "http", AdoptError::WrongType);
    // A non-socket: the read end of a pipe.
    let (notsock, _wr) = rustix::pipe::pipe().unwrap();
    set_env(p, f, n);
    expect_err("not a socket", Some(notsock), "http", AdoptError::NotSocket);

    // Success: a listening SOCK_STREAM at fd 3, environment scrubbed, CLOEXEC set, usable.
    let lst = at_fd3(abstract_listener(SocketType::STREAM, "ok"));
    let _ = std::os::fd::IntoRawFd::into_raw_fd(lst); // ownership passes to the adoption
    set_env(p, f, n);
    let adopted = systemd_unix_listener("http").expect("adoption");
    assert!(env_is_clear());
    assert_eq!(adopted.kind(), SocketKind::Stream);
    assert_eq!(adopted.as_fd().as_raw_fd(), SD_LISTEN_FDS_START);
    assert!(
        rustix::io::fcntl_getfd(adopted.as_fd())
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC)
    );

    // Second adoption in the same process is refused even with a fresh valid environment.
    set_env(p, f, n);
    assert_eq!(
        systemd_unix_listener("http").err(),
        Some(AdoptError::AlreadyAdopted)
    );
    assert!(env_is_clear());

    // The adopted listener accepts a connection and carries bytes.
    let listener = adopted.into_stream_listener().expect("stream");
    let name = format!("candor-memlock-activation-{}-ok", std::process::id());
    let addr = SocketAddrUnix::new_abstract_name(name.as_bytes()).unwrap();
    let client = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    rustix::net::connect(&client, &addr).unwrap();
    let mut client = UnixStream::from(client);
    let (mut server, _) = listener.accept().unwrap();
    client.write_all(b"ping").unwrap();
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping");
}
