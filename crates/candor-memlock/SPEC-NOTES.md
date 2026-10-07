<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-memlock — SPEC-NOTES

Sources: IMPL-00 §4.2 (lint set), §4.5 (`unsafe` allow-list), IMPL-RM2-INTAKE §2.2,
07 §4 (units, socket activation), deploy/README "Requirements on the Candor binaries",
WAVE-BRIEF §3.

## Implementation decisions

1. **Lints.** `[workspace.lints]` sets `unsafe_code = "forbid"`, which no crate can relax, and
   the root `Cargo.toml` may not be edited (BUILD-BRIEF rule 3). This crate therefore carries
   its own `[lints]` table that re-declares every workspace lint (`missing_debug_implementations`,
   `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`) with
   `unsafe_code = "deny"` instead of `forbid`, plus `unsafe_op_in_unsafe_fn`,
   `clippy::undocumented_unsafe_blocks` and `clippy::multiple_unsafe_ops_per_block` at `deny`
   (IMPL-00 §4.2 "allow-listed crates" row). `unsafe` is then allowed on exactly one module
   (`#[allow(unsafe_code)] mod sys;`) and in `tests/activation.rs` (`std::env::set_var`, which is
   `unsafe` in edition 2024). `lib.rs` itself has no `unsafe`. *Lead request:* when the root
   manifest is next edited, `IMPL-00 §4.2` suggests `security/unsafe-allowlist.toml` naming this
   crate; a `[lints] workspace = true` cannot express the exception, so the crate-local table
   must stay.
2. **Unsafe surface = three blocks.** `BorrowedFd::borrow_raw(3)` for one `fcntl(F_GETFD)` probe
   (an `OwnedFd` of a closed descriptor would abort the process on drop: `close == EBADF` is an
   I/O-safety violation in the standard library), `OwnedFd::from_raw_fd(3)` once per process
   (guarded by an `AtomicBool`; re-armed only after a failed validation has closed fd 3), and
   `std::env::remove_var` for the three `LISTEN_*` names. The environment edit is sound only in a
   single-threaded process; the crate cannot prove single-threadedness without reading
   `/proc`, so it checks `gettid() == getpid()` (main thread) and documents "call first in
   `main`". Reading `/proc/self/task` would need a filesystem path outside candor-safefs and was
   not added.
3. **No `LockedBuf`.** `candor-sealer::server::hardening` and `candor-intake-web::hardening` call
   `rustix::mm::mlockall(CURRENT | FUTURE)` and `set_dumpable_behavior(NotDumpable)` through safe
   wrappers; `candor-intake-store` holds its keys the same way once its binary exists
   (deploy D-36 gives it `LimitMEMLOCK=512M`). A buffer-level `mlock` would be a second mechanism
   with `unsafe` and no additional protection, so it is not provided.
4. **Strictness beyond `sd_listen_fds(3)`.** libsystemd tolerates a missing `LISTEN_FDNAMES`
   and several descriptors; here `LISTEN_FDS` must be exactly `1` and `LISTEN_FDNAMES` exactly the
   expected name (one name, no `:`), because every intake socket unit sets `FileDescriptorName=`
   and a daemon that receives a second descriptor is misconfigured (fail closed). Decimal values
   are parsed strictly (1–10 ASCII digits, no sign, no leading zero, checked arithmetic); any
   value longer than 255 bytes is refused. Non-UTF-8 values are compared as bytes and refused.
5. **No `O_NONBLOCK`.** The kind of runtime is the consumer's choice; the function returns a
   blocking listener and the README shows the tokio step.
6. **Errors carry no values.** `AdoptError` is `Copy`, has no payload, and its `Display` strings
   contain no digits or names (ADR-016; the `errors_carry_no_values` test).

## Dependencies

| Crate | Why |
|---|---|
| `rustix =1.1.2` (`std`, `net`, `process`, `thread`; dev: `pipe`) | Safe `getpid`/`gettid`, `fcntl_getfd/setfd`, `SO_DOMAIN`/`SO_TYPE`/`SO_ACCEPTCONN` getters. Already in `Cargo.lock` for five crates; no new transitive dependency. |

## Security self-review (OWASP ASVS 5.0 L3 mindset)

- *Hostile environment.* Every `LISTEN_*` value is bounded and parsed strictly; a value from a
  parent that was meant for another pid, two descriptors, a renamed descriptor or a non-socket
  at fd 3 each map to a distinct typed error and nothing is adopted. The variables are removed
  before the checks, so an error path never leaves them for a child or a retry.
- *Descriptor ownership.* fd 3 is probed before it is owned, owned at most once, and closed by
  the validation path on failure. `FD_CLOEXEC` is set before any other check so that a later
  `execve` (denied by the unit filters anyway) cannot inherit it.
- *Memory safety.* Three `unsafe` blocks, each one operation, each with its invariant; Miri
  runs the pure tests (see "Open items" for the toolchain gap); no `unsafe` in `lib.rs`.
- *No metadata.* No logging, no `Debug` of environment values (the error type has none), no
  paths. Abstract socket names in tests contain only the test pid.
- *Residual risk.* Single-threadedness at call time is a documented precondition, checked only
  as "main thread". A daemon that spawns a thread before calling this function and reads the
  environment on that thread concurrently would race `remove_var`; the daemon code review must
  keep the call first in `main`.

## Verification run (2026-10-07)

`cargo fmt -p candor-memlock`; `cargo clippy -p candor-memlock --all-targets -- -D warnings`
(clean); `cargo test -p candor-memlock` (7 unit tests + `activation` harness-less test, all
pass; the binary also passes when started with an inherited fd 3, which it closes first).

## Open items

- **Miri / Kani.** The pinned toolchain (`1.94.1`, `profile = "minimal"`) has no `miri`
  component and `kani-verifier` is not installed in this container; IMPL-00 §4.5 asks for Miri
  runs and a Kani harness per unsafe precondition. The pure tests (`check_listen_env`,
  `parse_decimal`) are Miri-ready (no syscalls); the descriptor tests need a real kernel. Lead
  to run `cargo +nightly-2026-09-28 miri test -p candor-memlock --lib` in CI.
- **Adoption by the daemon binaries** (wave 2): web `http`, sealer `seal`, store `istore`;
  the store's `relay` TCP listener needs a two-descriptor variant or a separate function when
  that path is built.
- **`cargo geiger`** evidence for the gate (IMPL-00 §4.5) is not generated here.
