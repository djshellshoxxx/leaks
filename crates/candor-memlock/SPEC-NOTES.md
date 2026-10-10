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
2. **Unsafe surface = two blocks** (after AUD-RM2-MEM-01/02). `OwnedFd::from_raw_fd(3)` once per
   process (guarded by an `AtomicBool`; re-armed only after a failed validation has closed fd 3),
   and `std::env::remove_var` for the three `LISTEN_*` names. Whether fd 3 is open is probed
   **without** constructing a borrow: `fstatat(AT_SYMLINK_NOFOLLOW)` of `/proc/self/fd/3`
   succeeds exactly when the descriptor exists (the earlier `BorrowedFd::borrow_raw(3)` probe
   violated the borrow's contract on the closed-fd path; removed). The environment edit is
   sound only in a single-threaded process, which is now **checked**: `/proc/self/task` is
   opened (`O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`) and its entries counted; anything but exactly one,
   or an unreadable `/proc`, is `AdoptError::NotSingleThreaded` before any environment access
   (fail closed; the units keep `/proc/self` visible under `ProtectProc=invisible`). The main-thread
   test (`gettid() == getpid()`) stays as the first check. Both `/proc` reads carry a
   `safefs-lint: allow` marker and a scoped `clippy::disallowed_methods` allowance: constant
   paths, this process's own tables, no content.
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
| `rustix =1.1.2` (`std`, `fs`, `net`, `process`, `thread`; dev: `pipe`, `rand`) | Safe `getpid`/`gettid`, `fcntl_getfd/setfd`, `SO_DOMAIN`/`SO_TYPE`/`SO_ACCEPTCONN` getters, the two `/proc/self` probes. Already in `Cargo.lock` for five crates; no new transitive dependency. |
| dev: `tokio =1.48.0` (`rt`, `rt-multi-thread`, `net`, `signal`, `time`), `seccompiler =0.5.0` (new; depends on `libc` only; Firecracker's seccomp builder, no `unsafe` in our use), `libc =0.2.189` (`SYS_*` numbers) | `tests/seccomp_runtime.rs` only (AUD-RM2-DEP-33). |

## Security self-review (OWASP ASVS 5.0 L3 mindset)

- *Hostile environment.* Every `LISTEN_*` value is bounded and parsed strictly; a value from a
  parent that was meant for another pid, two descriptors, a renamed descriptor or a non-socket
  at fd 3 each map to a distinct typed error and nothing is adopted. The variables are removed
  before the checks, so an error path never leaves them for a child or a retry.
- *Descriptor ownership.* fd 3 is probed before it is owned, owned at most once, and closed by
  the validation path on failure. `FD_CLOEXEC` is set before any other check so that a later
  `execve` (denied by the unit filters anyway) cannot inherit it.
- *Memory safety.* Two `unsafe` blocks, each one operation, each with its invariant, each
  precondition checked at runtime (fd open, single thread); Miri runs the pure tests; no
  `unsafe` in `lib.rs`.
- *No metadata.* No logging, no `Debug` of environment values (the error type has none), no
  paths. Abstract socket names in tests contain only the test pid.
- *Residual risk.* The thread count is read, then the environment edited; a thread spawned by
  a signal handler or a constructor in between is the only gap, and no such code exists in the
  daemons (the call is first in `main`). A just-joined thread can still be listed for a moment,
  which makes the function refuse (never unsound); the activation test retries.

## Verification run (2026-10-07, after the audit fixes)

`cargo fmt -p candor-memlock`; `cargo clippy -p candor-memlock --all-targets -- -D warnings`
(clean); `cargo test -p candor-memlock` (8 unit tests, `activation` harness-less test with the
new multi-thread refusal, `seccomp_runtime` 3 tests; all pass, three consecutive runs);
`cargo +nightly-2026-09-28 miri test -p candor-memlock --lib`: 5 passed, 3 ignored
(`#[cfg_attr(miri, ignore)]` on the socket and `/proc` tests). `cargo careful` could not run in
this container ("failed to run rustc to learn about target-specific information"; its
sysroot build needs the nightly `rust-src`, not installed). `strace -f` of the runtime start
in `seccomp_runtime` (54 distinct syscalls) shows nothing outside the deploy sets.

## Audit fixes (AUD-RM2-memlock-deploy, 2026-10-07)

| Finding | Fix |
|---|---|
| MEM-01 | `thread_count()` over `/proc/self/task`; `AdoptError::NotSingleThreaded` before any env access; activation test spawns a parked thread, expects the error with `LISTEN_*` untouched and fd 3 still open, joins, then succeeds. |
| MEM-02 | fd-3 probe by `fstatat` of `/proc/self/fd/3`; the `borrow_raw` block is gone (two `unsafe` blocks remain); SAFETY comments restated. |
| MEM-03 | `#[cfg_attr(miri, ignore)]` on the socket and `/proc` tests; Miri run recorded above; stale "no miri component" text removed. *Lead request:* add the Miri invocation to the crate's CI job. |
| MEM-04 | Abstract socket names carry 8 random bytes from `getrandom` (unit and activation tests). |
| MEM-05 | The off-main-thread test returns early if it ever runs on the main thread. |
| DEP-33 | `tests/seccomp_runtime.rs` (dev-deps `tokio` with `signal`, `seccompiler =0.5.0`, `libc =0.2.189`; vet exemption appended): each of `scf`, `scf-web`, `scf-store` from the release baseline applied as an in-process filter, runtime built and driven; start-up syscalls asserted present and off `scf-never`; control without `socketpair` → `EPERM`. |

## Open items

- **Kani.** `kani-verifier` is not installed in this container; IMPL-00 §4.5 asks for a Kani
  harness per unsafe precondition (the two preconditions are now runtime-checked; a harness for
  `check_listen_env`/`parse_decimal` is straightforward once Kani is available). Miri runs
  (see the verification run); it belongs in the crate's CI job.
- **Adoption by the daemon binaries** (wave 2): web `http`, sealer `seal`, store `istore`;
  the store's `relay` TCP listener needs a two-descriptor variant or a separate function when
  that path is built.
- **`cargo geiger`** evidence for the gate (IMPL-00 §4.5) is not generated here.
