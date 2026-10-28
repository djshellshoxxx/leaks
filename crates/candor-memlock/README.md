<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-memlock — the allow-listed OS shim

`candor-memlock` is the only crate in the Candor workspace whose lints permit `unsafe`
(IMPL-00 §4.5, SI-A-04; WAVE-BRIEF §3). It exists so that every other crate can keep
`unsafe_code = forbid` while the intake daemons still get the two operations the standard
library cannot express safely: taking ownership of a raw file descriptor, and editing the
process environment. Both live in `src/sys.rs` (two `unsafe` blocks, each with a `SAFETY:`
invariant and a runtime-checked precondition); the rest of the crate is safe code over
`rustix` wrappers.

## API

| Item | Purpose |
|---|---|
| `systemd_unix_listener(expected_name) -> Result<AdoptedListener, AdoptError>` | Adopts exactly one pre-opened Unix listening socket from systemd socket activation (`sd_listen_fds(3)`): main thread; exactly one thread in `/proc/self/task`; `LISTEN_PID == getpid()`; `LISTEN_FDS == 1`; `LISTEN_FDNAMES == expected_name` (one name, no `:`); fd 3 open; `FD_CLOEXEC` set; `AF_UNIX`; `SOCK_STREAM` or `SOCK_SEQPACKET`; listening (`SO_ACCEPTCONN`). The three `LISTEN_*` variables are removed from the environment on every path. Succeeds at most once per process. |
| `AdoptedListener` | `kind()` (`Stream` / `SeqPacket`), `into_fd()` (`OwnedFd`, for `rustix` `accept4` consumers such as the store's `istore` SEQPACKET socket), `into_stream_listener()` (`std::os::unix::net::UnixListener`; the caller sets non-blocking before `tokio::net::UnixListener::from_std`). |
| `AdoptError` | Typed refusals, `Display` without any environment value (ADR-016). Any variant means "exit". |
| `check_listen_env(...)`, `check_listener_fd(fd)` | The two validation steps as pure/safe functions, for tests and for callers that already own a descriptor. |
| `SD_LISTEN_FDS_START` | 3. |

Expected names: `http` (C-06 `candor-intake-web.socket`), `seal` (C-07 `candor-sealer.socket`),
`istore` (C-08 `candor-intake-store.socket`). The store's second listener (`relay`, TCP from
PID 1) is not adopted by this function: it demands exactly one descriptor, and the relay
socket is wave-2 work (store SPEC-NOTES).

Use it first thing in `main`, before any thread or async runtime starts:

```rust
fn main() -> std::process::ExitCode {
    let listener = match candor_memlock::systemd_unix_listener("http") {
        Ok(l) => l,
        Err(_) => return std::process::ExitCode::FAILURE, // typed; nothing is logged here
    };
    // ... hardening (mlockall, dumpable=0, rlimits), then the runtime
    let std_listener = listener.into_stream_listener().ok();
    // std_listener.set_nonblocking(true); tokio::net::UnixListener::from_std(..)
    std::process::ExitCode::SUCCESS
}
```

## What is deliberately not here

* **No `mlock` buffer type.** The sealer and the web service already lock their whole address
  space with `rustix::mm::mlockall(CURRENT | FUTURE)` (safe wrapper) under `LimitMEMLOCK=`,
  and zeroize secrets with `zeroize`. A per-buffer `mlock` helper would add `unsafe` for a
  control that exists without it (SPEC-NOTES decision 3).
* **No seccomp/Landlock glue yet.** IMPL-00 §4.5 names this crate as their future home; the
  daemon binaries (wave 2) decide what they need.

## Tests

`cargo test -p candor-memlock`: 8 unit tests (environment contract and strict decimal
parser, Miri-clean; descriptor checks on abstract Unix sockets, a socket pair, a datagram
socket, an `AF_INET` socket and a pipe; thread count; off-main-thread refusal), the
harness-less `tests/activation.rs`, which runs the real adoption on the main thread of its own
process (six environment misuses, five descriptor misuses, refusal while a second thread
exists, the success path with environment scrubbed, `FD_CLOEXEC` and a working `accept`, the
second-adoption refusal), and `tests/seccomp_runtime.rs`, which starts a tokio multi-thread
runtime (with the `signal` feature) under each daemon's deploy syscall allow-set applied as an
in-process seccomp filter. `cargo +nightly-2026-09-28 miri test -p candor-memlock --lib` runs
the pure tests.
