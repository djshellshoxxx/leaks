# Audit RM-2 wave 1 / W1-D — `candor-memlock` and the deploy delta (web/store syscall sets, store memlock, blob-rate check)

| Field | Value |
|---|---|
| Step | RM-2 W1-D (WAVE-BRIEF §4): the new crate `crates/candor-memlock` and `deploy/` as changed since AUDIT-RM2-deploy round 7 (`2956e4f`) |
| Audited commit | `c098fa6` (working tree equals HEAD for the in-scope files) |
| Scope | `crates/candor-memlock/{Cargo.toml,src/lib.rs,src/sys.rs,tests/activation.rs,README.md,SPEC-NOTES.md}`; `deploy/intake/systemd/candor-intake-{web,store}.service`, `candor-sealer.service`, `deploy/intake/tmpfiles.d/candor-intake.conf`, `deploy/tools/config-check.{sh,baseline,manifest}`, `deploy/tests/validate.sh`, `deploy/README.md`, `deploy/SPEC-NOTES.md` (D-36, D-37) |
| Tier | `candor-memlock/src/sys.rs` T0 (the workspace's only `unsafe`); `lib.rs` T1 (daemon start-up path, environment input); deploy files T1 (sandbox of the three intake daemons) |
| Auditor | independent auditor W1-D (did not write the code) |
| Date | 2026-10-07 |
| Time | A1 10 %, A2 10 %, A3 50 %, A4 25 %, A5 5 % |
| Tools | rustc/clippy 1.94.1; Miri `miri 0.1.0 (d080e7dff1 2026-09-27)` on `nightly-2026-09-28`; cargo-careful 0.4.10; cargo-geiger 0.13.0; shellcheck 0.9.0; systemd 255 (`systemd-analyze security --offline`); AppArmor parser 4.0.1; strace; PostgreSQL 16 (validate `CANDOR_TEST_PG=1`) |
| Scratch | `scratchpad/audit-w1d/` (PoC crate, snapshots, work bases `/run/aud-w1d-wb*`, `/var/tmp/aud-w1d-vol`), all removed afterwards |

## Summary

| Severity | Count | IDs |
|---|---|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 6 | MEM-01, MEM-02, MEM-03, DEP-33, DEP-34, DEP-35 |
| Info | 4 | MEM-04, MEM-05, DEP-36, DEP-37 |

The `unsafe` surface is small (three one-operation blocks), the parsers are strict and the descriptor checks are correct; nothing in the crate reads input into anything that can panic or leak. The deploy delta narrows the web and store sandboxes to explicit allow-sets that are proper subsets of the sealer's, with no dangerous call in any set, and every pin matches the shipped tree. The findings are precondition enforcement, test hygiene, an allow-list that the sealer's own runtime cannot start under (fail closed, but dead on arrival), and three defects in the new blob-rate self-test (stale file, wall-clock timing, operational cost).

## A2. Attacker goals

Adversaries from 02 §6 that reach this code: a hostile or mistaken parent/environment of the daemon (ADV-local misconfiguration, a compromised unit drop-in), a local unprivileged user on H-INTAKE, a compromised web process (reaching the sealer and store over the sockets), and a root-level operator error. The crate takes input only from the process environment and fd 3; the deploy files take input from the host filesystem as root.

| # | Goal | Result |
|---|---|---|
| G1 | Make the daemon adopt a descriptor that is not its listening socket (fd confusion: pipe, file, datagram, connected socket, AF_INET) | refuted: `check_listener_fd` requires `SO_DOMAIN=AF_UNIX`, `SO_TYPE∈{STREAM,SEQPACKET}`, `SO_ACCEPTCONN=1`; unit tests + `activation` test cover every class; a failed validation closes fd 3 and re-arms (`sys.rs:65-70`) |
| G2 | Adopt fd 3 twice (double owner, double close) | refuted: `ADOPTED` swap before `from_raw_fd` (`sys.rs:45`), re-armed only after the `OwnedFd` is dropped; `activation` test "second adoption" → `AlreadyAdopted` |
| G3 | Crash the daemon through `LISTEN_*` values (overflow, leading zeros, unicode digits, 255+ bytes, non-UTF-8, `:`-lists) | refuted: `parse_decimal` (1–10 ASCII digits, no sign/leading zero, checked arithmetic), `MAX_VALUE_LEN`, byte comparison; `clippy -D warnings` with `panic/unwrap/expect = deny` clean; tests `env_misuse_is_refused_with_a_typed_error`, `decimal_parser_is_strict_and_overflow_safe` |
| G4 | Leave `LISTEN_*` for a child or a retry | refuted: scrubbed on every path after the main-thread check (`lib.rs:157`); `execve`/`fork` are denied by the units anyway |
| G5 | Race the environment edit (UB in `remove_var`) | **MEM-01**: the precondition is "single-threaded", the check is "main thread" |
| G6 | Make an `unsafe` block's invariant false (`borrow_raw` on a closed fd; `from_raw_fd` of an fd another object owns) | **MEM-02** for `borrow_raw`; `from_raw_fd` refuted (G2) |
| G7 | Widen the lint exceptions beyond `unsafe_code` | refuted: crate-local `[lints]` re-declares every workspace lint (`Cargo.toml` root: `unsafe_code`, `missing_debug_implementations`, 5 clippy lints) and adds `unsafe_op_in_unsafe_fn`, `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block` at `deny`; `#[allow(unsafe_code)]` is on one `mod sys;` item and the harness-less test only; `rg unsafe crates/` finds no other crate with `unsafe` |
| G8 | Get a dangerous syscall into a daemon (ptrace, process_vm_*, bpf, userfaultfd, io_uring, kexec, mount family, keyctl, perf_event_open, memfd_create in web/store, personality, unshare/setns) | refuted: none is in `scf-web|` (123) or `scf-store|` (134); every one is on `scf-never|` (31) or explicitly denied; web ⊂ store ⊂ sealer ∪ ∅ (store = sealer − `memfd_create`; web = store − 11 write calls); 11 validate mutations re-adding calls or dropping lines exit 30 |
| G9 | Weaken a sandbox directive below the sealer's | refuted: only `LimitMEMLOCK=512M` and the filter line changed; `systemd-analyze security` 0.4 for all three; `LimitCORE=0`, `RestrictNamespaces=yes`, `PrivateNetwork=yes`, AF_UNIX only unchanged |
| G10 | Make config-check pass on a drifted host (fail-open) | refuted for the new paths: `need_tools` FAILs without root or a tool; every substitution checked; `pipefail` on; `scf_effective` rc 1–4 all FAIL; **DEP-35** is the one fail-open path (clock step) |
| G11 | Abuse the blob-rate test as a non-root user (path race, symlink, wrong-user write) | refuted: the directory must be root-owned 0700 with no symlinked component from `/`, on the blob device, ext4/xfs; the file is created `O_EXCL` as root inside it; only root can place anything there (DEP-37 notes the `noclobber` nuance) |
| G12 | Make the blob-rate test leave data or cost behind | **DEP-34** (stale file), **DEP-36** (5-minute repetition) |
| G13 | Start a daemon under its filter | **DEP-33**: `socketpair` is on `scf-never`, tokio's signal driver needs it |

## A3/A4. Evidence summary

| Check | Result |
|---|---|
| `cargo test -p candor-memlock` | 7 unit tests pass; `activation` (harness-less, main thread) passes |
| `cargo clippy -p candor-memlock --all-targets -- -D warnings` | clean |
| Miri (`nightly-2026-09-28`) `--lib` | 5 pure tests pass; the two socket tests abort Miri (`socket` not available under isolation) because they lack `#[cfg_attr(miri, ignore)]` (MEM-03) |
| `cargo +nightly-2026-09-28 careful test -p candor-memlock` | 7 passed + `activation` ran |
| `cargo geiger` (Ratio) | candor-memlock 324/331 expressions safe (7 unsafe expressions in 3 blocks), 16/16 functions, 5/5 methods; rustix 60.6 % |
| `rg -n unsafe crates/ -g '*.rs'` | only `candor-memlock` (plus string literals in safefs/source-ui tests) |
| config-check static, base / ce-single / ce-hardened | **889 checks OK, 0 skipped, exit 0** each; work base empty afterwards |
| `sha256sum -c config-check.manifest`; `MANIFEST_SHA256` | baseline OK, candor-safe-read OK, manifest digest `4b67f66c…` equals the script pin |
| shellcheck `-S style` on `deploy/**/*.sh` | clean |
| `apparmor_parser -QTK` | 6/6 profiles compile |
| `systemd-analyze security --offline` | web 0.4, sealer 0.4, store 0.4 |
| `CANDOR_TEST_PG=1 bash deploy/tests/validate.sh` on a full `git archive c098fa6` + `deploy/` snapshot | **446 PASS, 0 FAIL, 0 SKIP**, "validate: all executed checks passed", exit 0 (includes the blobrate positive run at 161 MB/s on this container's ext4, the 50 MB/s floor met, "test file removed", the 7 broken layouts, 8 invalid options, static and offline modes, the 11 D-36 mutations, the reader digest `58b2bb3a…` reproduced, the live-PG cases). Note: a first attempt on a `deploy/`-only snapshot failed in `build-safe-read.sh` (needs the repo root), which is a snapshot error of mine, not a defect; the full-archive run is the one counted |
| Effective allow-sets (`scf-web|`/`scf-store|` vs `scf|`) | web (123) ⊂ store (134) = sealer (135) − {`memfd_create`}; store − web = {`fchmod fchmodat fdatasync fsync linkat mkdirat openat2 renameat2 unlinkat utimensat utimensat_time64`}; no `scf-never` call in any set; `execve`, `clone`/`clone3`, `prctl`, `prlimit64`, `mlock*`, `eventfd2`, `getrandom`, `seccomp`, `landlock_*` present as the daemons need |

PoCs (scratch crate `audit-w1d/poc`, removed): `threads.rs` (MEM-01), `tokio_pair.rs` under `strace -e socketpair` (DEP-33), a `date` shim (DEP-35), a process-group `SIGINT` during `dd` (DEP-34). Each is reproduced in the finding.

## Findings — `candor-memlock`

### AUD-RM2-MEM-01 — The "single-threaded process" precondition of `remove_var` is documented, but only "main thread" is enforced
- Severity: Low
- Location: `crates/candor-memlock/src/sys.rs:19-37`, `src/lib.rs:150-157` (commit c098fa6)
- Category: B7.4 (CWE-362, CWE-758)
- Description: `clear_listen_env` runs `std::env::remove_var` (unsafe in edition 2024) under the stated invariant "the process is still single-threaded". The only runtime check is `gettid() == getpid()`. A daemon that has already spawned a thread (a logging thread, an early tokio runtime, a `std::thread::available_parallelism` probe does not count, but any `spawn` does) and then calls `systemd_unix_listener` on its main thread passes the guard. Rust-side readers are protected by std's internal env lock, so the hazard is a non-std reader on another thread (glibc `getenv` from `getaddrinfo`, `localtime`, `dlopen`, malloc tunables, or a C dependency), which is a use-after-free on the `environ` array. PoC (scratch `threads.rs`): a process with 4 worker threads looping on `libc::getenv("LISTEN_FDNAMES")`, LISTEN_* set and a listening socket at fd 3, calls `systemd_unix_listener("http")` on its main thread → `threads in process at call time: 5; adoption result: Ok(Stream)`. No crash was observed (the race window is three `unsetenv` calls), which is expected; the point is that the invariant the SAFETY comment relies on is not what the code checks.
- Exploit scenario: no attacker path; a wave-2 integrator who starts the runtime before adoption would turn a documented precondition into latent UB that no test can see. SPEC-NOTES "Residual risk" already states this honestly.
- Fix recommendation: enforce it. Read the thread count (`/proc/self/task` entry count, or field 20 of `/proc/self/stat`) through `rustix::fs` with a `// safefs-lint: allow(...)` marker and return a new `AdoptError::NotSingleThreaded` when it is not 1 (fail closed if `/proc/self` is unreadable; the units keep `/proc/self` visible). Regression test: the harness-less test spawns a parked thread, calls the function, expects the error, joins, then runs the success case. Alternative with no `/proc` read: drop the environment scrub (the `ADOPTED` flag already prevents re-adoption, and the units deny `fork`/`execve` after start, so no child can see `LISTEN_*`), which removes one of the three `unsafe` blocks.
- Spec / requirement reference: IMPL-00 §4.5 (allow-listed unsafe needs a checked precondition per block), WAVE-BRIEF §3, 27 §12.1
- Status: Open

### AUD-RM2-MEM-02 — `BorrowedFd::borrow_raw(3)` is constructed before it is known that fd 3 is open; the SAFETY comment restates the contract wrongly
- Severity: Low
- Location: `crates/candor-memlock/src/sys.rs:48-56` (commit c098fa6)
- Category: B7.4 (CWE-758)
- Description: `BorrowedFd::borrow_raw` requires that "the resource pointed to by `fd` must remain open for the duration of the returned `BorrowedFd`". The probe constructs the borrow precisely to find out whether fd 3 is open; when it is not (the `BadFd` path, exercised by the `activation` test "fd 3 closed"), the precondition is violated at construction. The SAFETY comment says "if fd 3 is not open at all, `fcntl` reports `EBADF` and the borrow is never used again", which describes the consequence, not the contract. Today this is a contract violation without a memory-safety consequence (std's I/O safety is a logical invariant; `fcntl(EBADF)` is harmless), and `cargo careful` and Miri cannot observe it. It is the same pattern every Rust `sd_listen_fds` implementation uses, which is why it is Low.
- Fix recommendation: either (a) probe without a borrow (`rustix::fs::statat(CWD, "/proc/self/fd/3", AT_SYMLINK_NOFOLLOW)` succeeds iff fd 3 is open; path read, needs the lint marker), then construct the `OwnedFd` directly, dropping one `unsafe` block; or (b) keep the code and rewrite the comment to state the actual argument: "`borrow_raw` on a closed descriptor is an I/O-safety contract violation with no memory effect; the only operation performed is `fcntl(F_GETFD)`, which reports `EBADF`" and record it as accepted in SPEC-NOTES decision 2. Add a Kani/doc note either way.
- Spec / requirement reference: IMPL-00 §4.5; checklist B7.4 ("SAFETY comments true")
- Status: Open

### AUD-RM2-MEM-03 — Miri cannot run the crate's `--lib` tests as shipped; the SPEC-NOTES "no Miri component" claim is stale
- Severity: Low
- Location: `crates/candor-memlock/src/lib.rs:362-433` (tests `listening_unix_sockets_of_both_types_pass_and_get_cloexec`, `wrong_descriptors_are_refused`); `SPEC-NOTES.md` "Open items" (commit c098fa6)
- Category: B12.1 / checklist §C (Miri is required for allow-listed `unsafe` crates)
- Description: `cargo +nightly-2026-09-28 miri test -p candor-memlock --lib` aborts at the first socket test (`unsupported operation: socket not available when isolation is enabled`). The checklist asks for `#[cfg_attr(miri, ignore)]` on syscall tests so that the pure tests run in CI. With the two tests filtered out, Miri passes the 5 pure tests (verified). The toolchain `nightly-2026-09-28` with `miri` **is** installed in this container (R9 §7), so the SPEC-NOTES statement that it is absent is incorrect and the gate evidence IMPL-00 §4.5 asks for was not produced by the builder.
- Fix recommendation: add `#[cfg_attr(miri, ignore)]` to the two socket tests; record the Miri run (5/5) and `cargo careful` (7/7 + activation) in SPEC-NOTES "Verification run"; add the Miri invocation to the crate's CI job.
- Status: Open

### AUD-RM2-MEM-04 — Tests bind abstract-namespace sockets with a predictable name
- Severity: Info
- Location: `src/lib.rs:350-360`, `tests/activation.rs:68-78`
- Description: the tests bind `candor-memlock-test-<pid>-<tag>` in the abstract namespace. Abstract names are visible to every process in the network namespace; a local process that pre-binds the name (pid is guessable) makes the test fail, and any process can connect to the listener during the test. Production code never uses the abstract namespace (B8.2), so this is a CI-robustness note only. A `socketpair`-free alternative is a path socket in a 0700 `tempdir` created by the test, or a random suffix from `getrandom`.
- Status: Open (tracked)

### AUD-RM2-MEM-05 — The off-main-thread unit test relies on libtest always running tests on a worker thread
- Severity: Info
- Location: `src/lib.rs:435-443`
- Description: `adoption_off_the_main_thread_is_refused_without_touching_the_environment` passes because libtest spawns a thread per test (verified also with `--test-threads=1`). If the test ever ran inline on the main thread (a future libtest change, or `cargo nextest` with a different runner model), it would scrub `LISTEN_*` in a multi-threaded test process, which is the MEM-01 hazard inside the test suite. Guard it: assert `gettid() != getpid()` at the top of the test and skip (return) otherwise.
- Status: Open (tracked)

## Findings — deploy delta

### AUD-RM2-DEP-33 — `socketpair` is on the never-list of all three daemons, but the sealer's tokio runtime (feature `signal`) calls it when the runtime is built
- Severity: Low (fail closed; blocks wave-2 integration)
- Location: `deploy/tools/config-check.baseline` (`scf-never|socketpair`), `deploy/intake/systemd/candor-sealer.service:105`, `candor-intake-web.service:70`, `candor-intake-store.service:79`; `crates/candor-sealer/Cargo.toml:43` (`tokio … features = [… "signal"]`), `crates/candor-sealer/src/server/mod.rs:1993` (`spawn_sigterm_flush`); `scripts/repro-check.sh:145` (`--workspace --all-features`) (commit c098fa6)
- Category: B10.1 / B7.3 (CWE-1188 configuration vs. code)
- Description: with tokio's `signal` feature enabled, `runtime::driver::Driver::new` always creates the signal driver, and `runtime::signal::Driver::new` creates a `mio::net::UnixStream::pair()` = `socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK)` (tokio 1.48.0 `src/runtime/driver.rs:237`, `src/runtime/signal/mod.rs:43`; mio 1.2.4 `src/sys/unix/uds/mod.rs:104`). PoC: a minimal binary building `Builder::new_current_thread().enable_io().build()` with tokio `rt,net,signal` under `strace -f -e socketpair` shows exactly one `socketpair(...) = 0` before any user code runs. Under the sealer unit this call returns `EPERM`, so the runtime cannot be built and the sealer never starts. Because the release build is `cargo build --workspace --all-features` (repro-check), feature unification enables `signal` in every binary, so the web and store runtimes fail the same way. This was true of the sealer's list before this commit (DEP-16) and D-36 copies it to the other two units; open item 10 in SPEC-NOTES defers exactly this test to wave 2. It is not a weakening (nothing is allowed that should not be), but a pinned "never" entry that the code contradicts, and the likely wave-2 reaction (widening the list under time pressure) is what the pin is supposed to prevent.
- Fix recommendation: decide now, in writing: either allow `socketpair` in the three sets (it only creates an AF_UNIX pair inside the process; `RestrictAddressFamilies=AF_UNIX` already permits `socket(AF_UNIX)`), remove it from `scf-never`, re-pin `scf*|` and record the reason in D-36; or drop the `signal` feature (SEA-28(c) SIGTERM flush would then need `sd_notify`-style or socket-close shutdown). Add a validate case that greps the three units' effective sets for every syscall the daemons are known to need at start-up (`socketpair` if kept, `eventfd2`, `prlimit64`, `mlockall`, `prctl`, `seccomp`, `landlock_*`, `getrandom`, `openat2` for sealer/store) so that the "too narrow" direction is also pinned, and keep open item 10 (run the real binaries under the units with `SystemCallErrorNumber=EPERM` and `strace`).
- Spec / requirement reference: 07 §4.3, deploy D-36, sealer SEA-28(c)
- Status: Open

### AUD-RM2-DEP-34 — An interrupted blob-rate run leaves up to 1 GiB in `/var/lib/candor/selftest`; stale files are never noticed or removed
- Severity: Low
- Location: `deploy/tools/config-check.sh:468-475` (`check_blob_rate`), `:196-197` (traps), `deploy/intake/tmpfiles.d/candor-intake.conf` (`d … selftest`, no age) (commit c098fa6)
- Category: B10.7 / B6.4 (CWE-459, CWE-400)
- Description: the file name is `rate-check.$$`, so every run uses a new name; `rm -f` runs only when `dd` returns. The `INT`/`TERM`/`HUP` trap is `exit 2` and the `EXIT` trap removes only `$WORK`. A Ctrl-C, a `systemctl stop` of the health agent (`KillMode=control-group` signals `bash`, `timeout` and `dd` together) or an OOM kill during the 5–80 s write leaves the partial file. The next run checks `set -C` on its own new name, finds the directory "fine" and reports OK. PoC: `--blob-mib 1024` run, `SIGINT` to the script and to `timeout` after 2 s → script exits, `rate-check.12018` of 205 MiB remains; a following run with `--blob-mib 64` reports `all 2 checks OK` with the stale file still present. Space is bounded (≤ 1 GiB per run) but accumulates with each interruption on the volume the blob store shares; the free-space check (`2 × size`) is then computed against a volume the test itself is filling. Nothing source-related is in the file (zeros), and its mtime says only when config-check ran.
- Fix recommendation: before the measurement, `rm -f -- "$d"/rate-check.*` (the directory was just verified root-owned 0700 with no symlinked component, so the glob is safe), or FAIL when the directory is not empty so an operator sees it; add `trap 'rm -f -- "$f"' INT TERM HUP` scoped to the measurement (restore the global trap after); create the file with `dd … conv=excl,fsync` (`O_EXCL` by `dd`, replacing the bash `noclobber` dance, see DEP-37); validate case: kill the run, expect the next run to FAIL or to clean up.
- Status: Open

### AUD-RM2-DEP-35 — The blob-rate measurement uses the wall clock; a backward clock step during the write inflates the rate (fail-open), and the comment calls it "monotonic"
- Severity: Low
- Location: `deploy/tools/config-check.sh:472-480` (commit c098fa6)
- Category: B10.7 (CWE-754)
- Description: `t0`/`t1` come from `date +%s%N` (`CLOCK_REALTIME`). The failure message reads "monotonic timing unavailable", but no monotonic clock is involved. A forward step makes the rate smaller (fail closed); a backward step of a few seconds during the measurement (chrony `makestep` on an installer host whose clock was wrong, an operator `date -s`, a VM snapshot restore) makes `ns` small and the rate large, and a volume below the floor passes. PoC with a `date` shim that returns `t1 = t0 + 1 ns`: `--blob-min-rate 100000` on a 64 MiB write reports `all 2 checks OK` (an honest run on the same ext4 volume reports its real rate against the 50 MB/s floor). The window is the measurement itself (≤ `budget` seconds) and the precondition is a clock step on a host whose time comes from NTS/Roughtime, so the likelihood is low, but the whole point of the section is to refuse a slow volume.
- Fix recommendation: read `/proc/uptime` (`CLOCK_BOOTTIME`, 10 ms resolution, more than enough for a multi-second write) before and after, e.g. `read -r up _ < /proc/uptime; t0=${up/./}` (centiseconds); or measure with `dd`'s own `status=progress` summary; keep the `date` fallback out. Fix the message. Validate case: a `date` shim must not be able to produce an OK (with `/proc/uptime` the shim is irrelevant).
- Status: Open

### AUD-RM2-DEP-36 — Repeating `blobrate` in the 5-minute health loop writes ≈ 74 GB/day to the blob volume and competes with real hand-overs
- Severity: Info (operational; raise to Low if the C-25 line is added to 07 §5.11 as written)
- Location: `deploy/README.md` "Host self-tests" (`config-check.sh --host … the health agent repeats the live subset every 5 min` and the D-37 lead request to add the ≥ 50 MB/s line to 07 §5.11); `deploy/SPEC-NOTES.md` D-37 "Residual" (commit c098fa6)
- Category: B10 (availability of the hand-over path; CWE-400)
- Description: 256 MiB + fsync every 5 minutes is 288 runs/day ≈ 74 GB/day of writes through dm-crypt, on the same device as the blob store. On flash this is wear with no benefit; during a run the store's own copy (the STO-29 deadline `10 s + len/50 MB/s` that this test exists to protect) shares the bandwidth, so the test can be the reason a hand-over misses its deadline and the sealer fails a submission. The measurement also makes the volume's write pattern periodic, which is an observable on a shared hypervisor.
- Fix recommendation: run `blobrate` at install (`config-check.sh --host`) and at most once per maintenance window (the daily `candor-intake-maint` timer slot, when no hand-over is expected), with `ionice -c3 nice -n19` on the `dd`, and exclude it from the 5-minute live subset (`--only host` already does). Word the 07 §5.11 request accordingly.
- Status: Open (tracked)

### AUD-RM2-DEP-37 — `( set -C; : > "$f" )` is not `O_EXCL` for a non-regular target; `dd of=` then follows it
- Severity: Info
- Location: `deploy/tools/config-check.sh:469, 473`
- Category: B6.1 (CWE-59)
- Description: bash's `noclobber` refuses an existing *regular* file; for an existing non-regular target (a symlink to a block device, a FIFO) it falls back to an open without `O_EXCL`, and `dd … conv=notrunc` then writes 256 MiB into whatever the symlink points at. Only root can place such an entry in the verified root-owned 0700 directory, so there is no privilege boundary crossed and no finding above Info; `dd conv=excl` (O_CREAT|O_EXCL in `dd` itself, with `oflag=nofollow` for belt and braces) is the exact primitive and removes the dependency on bash semantics. Fold into the DEP-34 fix.
- Status: Open (tracked)

## Checklist coverage notes

- B1 (metadata): `AdoptError` carries no values; `Display` has no digits or names (`errors_carry_no_values`). config-check prints the rate and the sizes only; the blob file contains zeros. The stale file's mtime (DEP-34) reveals only when the check ran.
- B2: no `as` casts, no indexing, checked arithmetic in `parse_decimal`; `u32::try_from(pid).unwrap_or(0)` cannot match any parsed pid.
- B3: `mlockall` stays with the daemons (SPEC-NOTES decision 3); the store gets `LimitMEMLOCK=512M` within `MemoryMax=1G`, pinned (`unit|candor-intake-store.service|Service|LimitMEMLOCK|=|512M`); no `CAP_IPC_LOCK` anywhere.
- B7.4: `#![forbid(unsafe_code)]` is a workspace lint; the crate's `deny` + one `allow` is the minimal relaxation; three blocks, each one operation, each with `SAFETY:` (MEM-02 for the content of one of them); no `unsafe impl Send/Sync`.
- B8: the adopted socket's mode/owner are PID 1's (`SocketMode=0660`, `SocketUser/Group` per unit); abstract names only in tests (MEM-04).
- B10.2/B10.3/B10.4: the AppArmor profiles for web and sealer `deny /var/lib/candor/** rwklx`; the store's allows only `/var/lib/candor/intake/**`, so `selftest` is unreachable by every daemon; nftables unchanged (no new sockets); tmpfiles `selftest 0700 root root`.
- B10.7: shellcheck clean; `set -u -o pipefail`; `need_tools` fails closed on missing root or tool; the new `scf_effective` return codes 1–4 each map to a FAIL.
- B11: `rustix =1.1.2` only, already in the lock; `supply-chain/config.toml` `[policy.candor-memlock] criteria = "safe-to-deploy"` present.
- B12.3: validate skips PG cases without `CANDOR_TEST_PG` (run with it here).

## Gate

| Severity | Open | IDs |
|---|---|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 6 | MEM-01, MEM-02, MEM-03, DEP-33, DEP-34, DEP-35 |
| Info | 4 | MEM-04, MEM-05, DEP-36, DEP-37 |

All claims verified: static check 889 OK × 3 profiles, validate 446 PASS / 0 FAIL with `CANDOR_TEST_PG=1`, shellcheck clean, 6 AppArmor profiles compile, exposure 0.4 for the three units. Every §C tool that applies ran on `c098fa6` (Miri with the two socket tests filtered, see MEM-03); every hit is triaged above.

Gate: **PASS 2026-10-07 c098fa6** for `crates/candor-memlock` and the W1-D `deploy/` delta. No Critical, High or Medium findings are open; the six Low and four Info findings are tracked. Conditions the lead should carry into wave 2 (not gate-blocking): DEP-33 must be decided before any daemon binary is started under the units, and MEM-01/MEM-03 should be fixed before the first daemon depends on `candor-memlock`, since both are cheap and the crate is T0 by allow-list.

## Lead dispositions (2026-10-07)
- **Gate: PASS** (0 Critical / High / Medium) at c098fa6.
- **DEP-33 (Low, functionally important): fix.** `socketpair` is allowed in the web, store and sealer units (AF_UNIX confinement stays); allow-sets re-derived from a real startup trace; a regression test starts a tokio multi-thread runtime with the signal feature under the exact filter.
- **MEM-01, MEM-02, MEM-03, DEP-34, DEP-35: fix** (real single-thread check via /proc/self/task; no BorrowedFd for fd 3 before it is known open; Miri ignores on socket tests; stale blobrate file swept every run; monotonic clock source).
- **DEP-36: fix.** The blob-rate test runs at install, on operator demand and at most once a day outside import/hand-over slots; the write-volume budget is documented.
- **DEP-37, MEM-04, MEM-05 (Info): fix where trivial, otherwise documented.**

---

## Re-test (round 2)

| Field | Value |
|---|---|
| Date | 2026-10-07 |
| Revision | HEAD `2c00f6f` (W1-D audit fixes; D-38); working tree equals HEAD for the in-scope files |
| Scratch | `scratchpad/audit-w1d/` (PoC crate, HEAD archives, `/var/tmp/aud-w1d-vol`, `/run/aud-w1d2-wb`), removed afterwards |

### Tools

| Check | Result |
|---|---|
| `cargo test -p candor-memlock` | 8 unit + 3 `seccomp_runtime` + `activation` (harness-less) all pass; clippy `-D warnings` clean |
| Miri `nightly-2026-09-28` `--lib` | 5 passed, 3 ignored (`#[cfg_attr(miri, ignore)]` on the socket and `/proc` tests) |
| cargo-careful | 8 + 3 + activation pass |
| cargo-geiger | candor-memlock 462/468 expressions safe: 6 unsafe expressions in **2 blocks** (`remove_var`, `from_raw_fd`); `borrow_raw` gone |
| `cargo deny --offline check`, `cargo vet --locked` | ok (one pre-existing unmatched licence allowance warning); vet succeeds with the `seccompiler 0.5.0` exemption |
| safefs lint | the memlock marker passes; the one violation reported is `candor-intake-store/src/server/mod.rs:651`, another agent's uncommitted edit, out of scope |
| shellcheck `-S style` `deploy/**/*.sh` | clean |
| config-check static, base / ce-single / ce-hardened | 889 OK each, exit 0; `sha256sum -c config-check.manifest` OK; `MANIFEST_SHA256` `c6bc7ef3…` equals the manifest digest |
| `apparmor_parser -QTK` | 6/6 |
| `systemd-analyze security --offline` | web 0.4, sealer 0.4, store 0.4 |
| Allow-sets | sealer 136, web 124, store 135, never 30; `socketpair` in all three sets and off `scf-never`; web ⊂ store ⊂ sealer unchanged otherwise |
| `CANDOR_TEST_PG=1 validate.sh` | **452 PASS, 0 FAIL, 1 SKIP, exit 0** on a clean `git archive HEAD` snapshot run with the pinned `candor-safe-read` and cargo off `PATH` (the SKIP is "cargo missing: using the existing candor-safe-read"; with cargo present the expected 453rd PASS, "reproducible build", cannot be reproduced on this host: DEP-38). All D-38 cases pass: start-up syscalls present in every set and off `scf-never`; both socketpair mutations rejected; blobrate 149 MB/s, stale file and stale symlink swept, interrupted 1 GiB run leaves nothing, `date` shim immune, the 7 layouts and 8 options rejected. Two earlier runs of mine on an un-normalised archive (git's `tar.umask=002` leaves units group-writable) were refused by the reader with status 13, which is DEP-24 working as designed |

### Status of round-1 findings

| ID | Status | Evidence (original PoC re-run on HEAD, plus variants) |
|---|---|---|
| MEM-01 | **Fixed** | `sys::thread_count()` counts `/proc/self/task` (`openat` `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`, `Dir::read_from`), checked after the main-thread test and **before** any environment access; `None` (unreadable `/proc`) fails closed. The round-1 PoC (4 worker threads hammering libc `getenv`, LISTEN_* set, listener at fd 3) now gives `threads=5 result=Err(NotSingleThreaded) env_untouched=true fd3_open=true`. The `activation` test covers the same case plus the retry for a lingering joined task entry. `strace` shows exactly one `openat("/proc/self/task")` and one `newfstatat("/proc/self/fd/3", AT_SYMLINK_NOFOLLOW)` per call |
| MEM-02 | **Fixed** | `fd3_is_open()` = `statat(CWD, "/proc/self/fd/3", SYMLINK_NOFOLLOW)`; no `BorrowedFd` is constructed. Variants: fd 3 closed → `BadFd`, environment scrubbed, nothing adopted; fd 3 = `/dev/null` → `NotSocket`, fd 3 closed by the failed adoption. The remaining two SAFETY comments state the invariants that are actually checked (thread count + main thread; `fd3_is_open` in a single-threaded process + `ADOPTED` swap). Both `/proc` reads are constant paths of the process's own tables, marked for the safefs lint and the `disallowed_methods` allow is scoped to the two functions |
| MEM-03 | **Fixed** | `#[cfg_attr(miri, ignore)]` on the two socket tests and the new `/proc` test; Miri 5/5 passes; SPEC-NOTES now records the Miri run |
| MEM-04 | **Fixed** | abstract names carry 8 random bytes from `getrandom` (`rustix` `rand` feature, dev only) |
| MEM-05 | **Fixed** (verified in the test file) | the off-main-thread unit test is unchanged in behaviour; the thread-count guard now also protects the environment in the libtest process, which removes the hazard the note described |
| DEP-33 | **Fixed** | `socketpair` allowed in the three units and removed from `scf-never`; baseline re-pinned (sealer 136, web 124, store 135); validate asserts the start-up calls are in every set and off the never-list and that two mutations (drop-in `~socketpair`, deny line re-adding it) FAIL; `tests/seccomp_runtime.rs` applies each baseline set as an in-process seccomp filter with `EPERM` semantics and builds a 2-worker tokio runtime with the `signal` feature under each (the first build makes the socketpair), and the control without `socketpair` gets `EPERM` from `socketpair(2)`. The sets stay tight: the only addition is `socketpair`, which `RestrictAddressFamilies=AF_UNIX` confines. **seccompiler 0.5.0**: dev-dependency only, one dependency (`libc`), no build script, 5 `unsafe` sites (the `prctl`/`seccomp` FFI); the crate's own `unsafe_code = deny` is unaffected. Acceptable. Nit: the vet exemption grants `safe-to-deploy` where a dev-dependency only needs `safe-to-run`; `safe-to-run` would be the honest claim |
| DEP-34 | **Fixed** | fixed name `rate-check.tmp`; a stale regular file, a stale symlink to `/dev/null` (removed with `unlink`, never followed) are swept and the run measures; a stale *directory* of that name fails closed ("cannot remove a stale test file"); the measurement runs under `trap 'rm -f -- "$f"; exit 2' INT TERM HUP`. Round-1 PoC (SIGINT to the script and to `timeout` during a 1 GiB write) → script exits, `selftest` is empty |
| DEP-35 | **Fixed** | `t0`/`t1` from `/proc/uptime` via the `read` builtin (`CLOCK_BOOTTIME`, 10 ms ticks; `10#` guard; sub-tick elapsed fails with "raise --blob-mib"). Round-1 `date` shim → `FAIL 209 MB/s … below the 100000 MB/s floor` (honest measurement, no false OK) |
| DEP-36 | **Fixed** (documented) | README "Host self-tests": the 5-minute live subset runs **except `blobrate`**; blobrate at install, on demand, and from the daily self-test at most once per day in the 21:00 UTC maintenance window; SPEC-NOTES D-38 records the ≤ 256 MiB/day budget and the `IOSchedulingClass` request for C-25 |
| DEP-37 | **Fixed** | `strace`: `openat(…/rate-check.tmp, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC|O_NOFOLLOW, 0666)` under `umask 077` (`dd conv=excl,fsync oflag=nofollow`); bash `noclobber` is no longer used |

### Delta review of the fixes

Read every changed line (`sys.rs`, `lib.rs`, `activation.rs`, `seccomp_runtime.rs`, `check_blob_rate`, validate additions). Notes, none a finding: `thread_count` returns `None` on any `readdir` error, which the caller maps to `NotSingleThreaded` (fail closed); the `seccomp_runtime` filter resolves only the x86_64 names it knows (`filter_map`), so it is at most *narrower* than the unit filter, which is the safe direction for a "can it start" test; the `activation` retry loop (400 × 5 ms) only retries on `NotSingleThreaded` after a joined thread, which cannot occur in a daemon that calls first in `main`.

### New finding

#### AUD-RM2-DEP-38 — `candor-safe-read` is not reproducible once `rust-src` is installed for the pinned toolchain; the sysroot is not remapped and the binary then carries `/root/.rustup/...`
- Severity: Low
- Location: `deploy/tools/build-safe-read.sh:20` (`RUSTFLAGS` remap list), `scripts/repro-check.sh:142` (same gap for the release build); `deploy/tests/validate.sh:63-68` (commit 2c00f6f)
- Category: B1.10 / B11 (reproducible builds; CWE-1104 build-path leakage)
- Description: a clean-archive build of `candor-safe-read` (both `c098fa6` and HEAD, with and without my environment variables, `env -i`) yields sha256 `f622bf56…`, not the pinned `58b2bb3a…`. The binaries differ only in path strings: the pinned one has `/rustc/e408947b…/library/alloc/src/str.rs`, the fresh one `/root/.rustup/toolchains/1.94.1-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/alloc/src/str.rs`. rustc rewrites the `/rustc/<hash>` prefix to the local `rust-src` directory when that component is present, and `rust-src` was added to the 1.94.1 toolchain today (`lib/rustlib/src/rust` dated 2026-10-07; the pin dates from 2026-10-01). The remap flags cover `$CARGO_HOME`, the repo and the target directory, but not the sysroot. Consequences: (a) a builder with `rust-src` (any host that also runs Miri/cargo-careful on the same toolchain) cannot reproduce the pin, and config-check then refuses to run (`tool.baseline_integrity`, exit 30: fail closed, but the release cannot be re-verified); (b) the builder's home path leaks into the shipped binary (B1.10); (c) validate's "reproducible build" check passes in the working tree only because `deploy/.build/safe-read` still holds the 2026-10-01 artefacts and cargo reuses them (nothing is recompiled), so the check does not demonstrate reproducibility. My round-2 validate on a clean HEAD archive therefore failed every check downstream of the integrity gate (390 PASS, 60 FAIL, all the same cause); the run with the pinned binary and cargo off `PATH` is the one tabulated above.
- Exploit scenario: none directly; a reproducibility and metadata-hygiene defect in the release path.
- Fix recommendation: add `--remap-path-prefix=$(rustc --print sysroot)=/sysroot` (and, belt and braces, `--remap-path-prefix=${RUSTUP_HOME:-$HOME/.rustup}=/rustup`) to both scripts; rebuild from a clean checkout **with** `rust-src` installed and re-pin `config-check.manifest` and `MANIFEST_SHA256`; make validate build in a fresh directory (or `cargo clean` first) so the check recompiles; add `strings | grep -E '/root|/home|\.rustup'` to validate as a negative check on the produced binary.
- Status: Open

### Round-2 gate

| Severity | Open | IDs |
|---|---|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 1 | DEP-38 |
| Info | 0 | — |

All eleven round-1 findings are fixed and re-tested with the original PoCs. DEP-38 is Low (fail closed on the host; a release-process defect) and tracked.

Gate: **PASS 2026-10-07 2c00f6f** for `crates/candor-memlock` and the W1-D `deploy/` delta. No Critical, High or Medium findings are open; DEP-38 (Low: sysroot remap and re-pin of `candor-safe-read`, plus a validate check that really recompiles) is tracked and should be fixed before the next release pin.

## Lead dispositions after round 2 (2026-10-07)
- **Gate: PASS** at 2c00f6f (round 2: all 11 round-1 findings closed).
- **DEP-38 (Low): fix assigned** (remap the rust sysroot path; the validate rebuild check builds in a fresh target dir under a different checkout path).
- The test-only dependency `seccompiler 0.5.0` is accepted with its safe-to-deploy exemption (expiry 2027-03-30).
