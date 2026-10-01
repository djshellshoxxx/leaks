# R7 — Secure Implementation Practices for Candor (Rust services, Linux hardening, no-JS web, onion ops, PostgreSQL, desktop client, document sandboxing)

*Research note, as of 2026-10-01. Scope: **how** to build Candor's components (DECISIONS §4: C-05…C-17, C-19, C-21…C-24) securely. Each item is laid out as **Practice → Why → Candor rule → Verify**. Rule IDs (`SI-x-nn`) are proposals that 27-SECURE-DEVELOPMENT / 17-INFRASTRUCTURE / 29-SECURITY-TESTING can adopt.*

**Method and caveats.** The egress proxy blocked many primary web hosts (docs.rs, freedesktop.org, cheatsheetseries.owasp.org, postgresql.org, man7.org, kernel.org docs, community.torproject.org, riseup.net, onionservices.torproject.org, gitlab.torproject.org). Where possible I read the **same primary text from source repositories**: shallow clones of ANSSI-FR/rust-guide (commit 2026-05-18), RustCrypto/utils (zeroize 1.9.0), dalek-cryptography/subtle (2.6.x), iqlusioninc/crates (secrecy 0.10.3), OWASP/CheatSheetSeries (2026-09-30), systemd/systemd man pages (main, "263 in spe"), postgres/postgres docs (master), torvalds/linux Documentation (Yama, Landlock), torproject/community GitHub mirror (2026-09-29), tauri-apps/tauri-docs (2026-09-29), electron/electron docs, freedomofpress/dangerzone, securedrop-client and securedrop-workstation (all late Sept 2026), firecracker-microvm/firecracker docs, and the RustSec advisory-db (2026-09-30). I read Arti 2.6.0 and tor-hsservice 0.46.0 from the published crate tarballs on static.crates.io, and took crate versions from the crates.io API on 2026-10-01. Items I did not read in a primary source this session are marked **UNVERIFIED**.

**Current versions (crates.io, 2026-10-01):** hyper 1.11.1 · axum 0.8.9 · tower-http 0.7.1 · sqlx 0.9.0 · zeroize 1.9.0 · secrecy 0.10.3 · subtle 2.6.1 · landlock 0.4.7 · seccompiler 0.5.0 · rustix 1.1.5 · nix 0.31.3 · region 4.0.1 · memsec 0.7.0 · cargo-deny 0.20.2 · cargo-vet 0.10.2 · cargo-audit 0.22.2 · cargo-geiger 0.13.0 · cargo-fuzz 0.13.2 · libfuzzer-sys 0.4.13 · bolero 0.13.6 · proptest 1.11.0 · kani-verifier 0.68.0 · dudect-bencher 0.7.0 · tauri 2.12.1 · tauri-plugin-updater 2.13.1 · arti 2.6.0 (2026-09-02).

---

## Top 15 rules (executive summary)

1. **Use C tor (0.4.8+/0.4.9, GPL build with `pow: yes`) for the server-side onion service, not Arti.** The Arti 2.6.0 example config still says "*Some of the security features needed for onion service privacy are not yet implemented*", and its service-side PoW (`hs-pow-full`) is behind an `__is_experimental` feature. Arti is fine for the C-03 *client* [B-SI-30][B-SI-31].
2. **Fail closed on panic.** Set `panic = "abort"` and `overflow-checks = true` in `[profile.release]`. Forbid `unwrap`/`expect`/`panic`/indexing in trust-path crates through clippy restriction lints. Use explicit `checked_*`/`saturating_*` arithmetic (ANSSI LANG-ARITH) [B-SI-01].
3. **Keep `unsafe` out of the trust path.** Put `#![forbid(unsafe_code)]` in every crate except a small `candor-sys` crate (mlock, prctl, Landlock/seccomp glue). That crate gets `clippy::undocumented_unsafe_blocks`, Miri, and Kani harnesses [B-SI-01][B-SI-09][B-SI-10].
4. **Treat zeroization as hygiene, not a guarantee.** zeroize states that moves, stack spills and `Vec` reallocation can leave copies. Hold secrets in `secrecy::SecretBox` with heap allocation pre-sized and never grown. Add `mlock` + `MADV_DONTDUMP` + `PR_SET_DUMPABLE=0` + `LimitCORE=0` + no swap or encrypted swap [B-SI-04][B-SI-05].
5. **Use `subtle` for secret-dependent comparisons and selection.** It is "best-effort", so add dudect-style statistical timing tests in CI for the comparison, decoding, and KEM paths [B-SI-06][B-SI-12].
6. **Supply chain gates on every PR:** `cargo deny check` (advisories, bans, licenses, sources), `cargo vet` (fail on unaudited), `cargo audit` on a schedule, and a `cargo geiger` report diffed per release. This already applies to sqlx < 0.8.1: RUSTSEC-2024-0363 is protocol-level SQL smuggling via truncating casts [B-SI-13..16][B-SI-17].
7. **Give every service a systemd unit with `systemd-analyze security` exposure ≤ 2.0** (intake ≤ 1.5). The baseline is `ProtectSystem=strict`, `PrivateNetwork=yes` (except the tor/IPC edge), `RestrictAddressFamilies=AF_UNIX`, `SystemCallFilter=@system-service` minus `@privileged @resources`, `MemoryDenyWriteExecute=yes`, `PrivatePIDs=yes` (v257+), and `CapabilityBoundingSet=` empty [B-SI-18][B-SI-19].
8. **Add in-process Landlock and seccomp after init.** Landlock is self-applied, unprivileged, and stackable. Request ABI ≥ 6 for scoping and ABI ≥ 4 for TCP. Apply it in best-effort mode and fail startup if the kernel is below the minimum the profile declares. Add a seccompiler allow-list per process role [B-SI-20][B-SI-21].
9. **Use privilege separation in the OpenSSH style.** C-06 (parses HTTP) and C-07 (holds plaintext and keys) are separate processes. They talk over a `SOCK_SEQPACKET` socketpair or a unix socket, authenticated with `SO_PEERCRED`/`SO_PEERPIDFD`, and exchange a fixed, length-prefixed, versioned binary schema with no serde-flexible formats [B-SI-23][B-SI-24].
10. **No-JS web: protect forms with a synchronizer CSRF token plus a `Sec-Fetch-Site` check.** Use `__Host-` cookies with `Secure; HttpOnly; SameSite=Strict; Path=/`; Tor Browser treats `.onion` over HTTP as a secure context. Send a strict CSP with `script-src 'none'` in no-JS mode [B-SI-25][B-SI-26][B-SI-27][B-SI-28].
11. **Use hyper 1.x HTTP/1.1 only on the intake listener, behind tor.** There is no reverse proxy, which means no front-end/back-end parser disagreement and therefore no smuggling surface. Set header-read timeout, total request deadline, body caps, and connection caps. Disable HTTP/2 on intake (repeated h2 DoS advisories, the latest is RUSTSEC-2026-0258) [B-SI-17].
12. **Use PostgreSQL over unix sockets with `peer` auth only.** The application role is not the table owner and has no `BYPASSRLS`. Set `FORCE ROW LEVEL SECURITY` on tenant tables. Remember that unique/FK checks bypass RLS (covert channel), so key uniqueness on `(tenant_id, …)` [B-SI-35].
13. **Onion ops:** service on a host with no clearnet route, and the backend bound to a unix socket. Enable `HiddenServicePoWDefensesEnabled 1`, `HiddenServiceEnableIntroDoSDefense 1`, and `HiddenServiceMaxStreams` with `MaxStreamsCloseCircuit 1`. Use vanguards (built-in vanguards-lite, plus full vanguards where available). Send no `Server`/version strings, run no NTP or DNS on clearnet from intake, and do no update checks except through Tor [B-SI-29][B-SI-30].
14. **Candor Desk (Tauri 2):** bundled assets only, no remote capabilities, one capability file per window with minimal permissions, Isolation pattern on, strict CSP. Render **no** hostile content in the main WebView: evidence goes only to C-17. Updater signatures are mandatory but single-key minisign, so wrap them in TUF (ADR-022) [B-SI-38..41].
15. **Evidence handling:** copy Dangerzone's settings: gVisor inside an unprivileged container, `--network=none`, `--cap-drop all`, `no-new-privileges`, `--userns nomap`, logging off, a custom seccomp profile, and a signed, independently updatable sandbox image. For higher assurance, use Firecracker+jailer microVMs or a Qubes DispVM over qrexec with a strict policy [B-SI-42..46].

---

## A. Rust secure coding

### A1. Toolchain and profiles (ANSSI DENV-*)
- **Practice:** Build with the stable toolchain on tier-1 targets only. Commit `Cargo.lock`. Do not override `debug-assertions`/`overflow-checks` in the dev/test profiles. Keep compiler flags in `Cargo.toml` rather than in environment variables. Run rustfmt and clippy, and review every autofix by hand (ANSSI DENV-STABLE, DENV-TIERS, DENV-CARGO-LOCK, DENV-CARGO-OPTS, DENV-CARGO-ENVVARS, DENV-LINTER, DENV-AUTOFIX) [B-SI-01].
- **Why:** Reproducible builds (ADR-022) and consistent overflow semantics.
- **Rule SI-A-01:** Pin `rust-toolchain.toml` to a specific stable version and bump it deliberately. In `[profile.release]`, set `overflow-checks = true`, `panic = "abort"`, `lto = "fat"`, `codegen-units = 1`, `debug = false`, `strip = "symbols"`. Builds run in CI with `--locked`, and `RUSTFLAGS` are set only in the checked-in `.cargo/config.toml`. Targets are `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` (both tier 1).
- **Verify:** A CI job greps the profile keys. The reproducible-build diff (ADR-022) fails on any env-flag drift.

### A2. Integer overflow (ANSSI LANG-ARITH)
- **Practice:** "When an arithmetic operation can produce an overflow, the usual operators MUST NOT be used directly." Use `checked_`/`overflowing_`/`wrapping_`/`saturating_` or `Wrapping`/`Saturating` [B-SI-01].
- **Why:** The behaviour must not depend on the build profile. RUSTSEC-2024-0363 (sqlx) is the canonical case: a length prefix truncated past 4 GiB let bound values be read as protocol commands [B-SI-17].
- **Rule SI-A-02:** In `candor-core`, intake, the relay and all parsers, enable `clippy::arithmetic_side_effects`, `clippy::cast_possible_truncation`, `clippy::cast_sign_loss`, `clippy::cast_possible_wrap` and `clippy::as_conversions` at deny. Lengths are `u64` and convert with `try_from`. Every wire length field has an explicit maximum, checked before allocation.
- **Verify:** clippy in CI. Proptest/fuzz harnesses with boundary values (0, max, max+1, 2^32). Kani proofs of no overflow for the framing and padding code.

### A3. Panics and error handling (ANSSI LANG-LIMIT-PANIC, LANG-ERRWRAP, LANG-ARRINDEXING, LANG-DROP-NO-PANIC)
- **Practice:** Limit panics and panicking functions. Test indexing or use `get`. Never panic in `Drop`. Wrap all errors in a custom `Error` type. ANSSI notes that `panic = 'abort'` in `[profile.release]` makes sense where it stops corrupted state from propagating [B-SI-01].
- **Why:** Under tokio, a panic inside a task is caught and the process carries on, possibly with half-updated state, poisoned mutexes, or a key left in memory. Panic messages and `Debug` output can carry secrets or paths into logs.
- **Rule SI-A-03:** `panic = "abort"` in release for every server binary. For C-06 this means a client-triggerable panic is a DoS, so it is treated as a P1 bug, and fuzzing must reach zero panics. Trust-path crates set `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::todo, clippy::unimplemented, clippy::unreachable)]`, and tests may allow them. Each crate has one `thiserror` error enum, mapped at the HTTP boundary to a fixed set of **generic, constant-size** error pages that carry an opaque random correlation ID. The internal error detail goes only to the class-separated audit/ops log (ADR-016), and secret-bearing types are excluded from it by their `Debug` impls. Install a panic hook that writes only a static string plus the correlation ID: no payload, no backtrace in release (`RUST_BACKTRACE` unset in units).
- **Verify:** clippy; a fuzz "no panic" oracle; integration tests that send malformed input and assert the response body hashes to one of N known error templates.

### A4. `unsafe` policy (ANSSI LANG-UNSAFE, LANG-UNSAFE-ENCP, UNSAFE-NOUB, FFI-*, MEM-*)
- **Practice:** "Don't use unsafe blocks" unless encapsulated behind a safe API. No UB. No `mem::forget`/`leak`. FFI uses only C-compatible types and checks foreign pointers, and panics must not cross FFI [B-SI-01]. The Rust Secure Code WG and the "safety-dance" effort push the same minimisation [B-SI-02].
- **Rule SI-A-04:** Set `#![forbid(unsafe_code)]` workspace-wide through `[workspace.lints.rust] unsafe_code = "forbid"`. Two crates are exceptions. **`candor-sys`** holds the mlock, madvise, prctl, Landlock and seccomp shims, preferably through `rustix`, which wraps most of these safely. **`candor-ffi`**, if HSM/PKCS#11 is needed (C-29), holds the FFI code. Both deny `clippy::undocumented_unsafe_blocks`, `clippy::multiple_unsafe_ops_per_block` and `unsafe_op_in_unsafe_fn` (warn-by-default in edition 2024; Candor sets it to deny), and need two reviewers per change. `clippy::mem_forget` is denied everywhere.
- **Verify:** `cargo geiger` report per release, with any increase in unsafe count in dependencies flagged in review (ANSSI LIBS-UNSAFE). `cargo +nightly miri test` on `candor-sys` and `candor-core` (pure parts). Kani harnesses for each `unsafe` function's preconditions [B-SI-09][B-SI-10][B-SI-16].

### A5. Secret memory: `zeroize`, `secrecy`, and their limits
- **Facts (from source):** zeroize 1.9.0 guarantees only that "*the zeroing operation can't be 'optimized away'*" (volatile writes). It says moves can copy, that "*stack spilling and other optimizations may leave temporary copies of data from the heap on the stack*", that `Vec`/`String` zeroize their capacity but "*cannot guarantee copies of the data were not previously made by buffer reallocation*", and that register clearing, `mlock()` and `mprotect()` are out of scope. It makes no claims about microarchitectural leaks. It provides `zeroize_stack` and suggests `Pin` [B-SI-04]. secrecy 0.10.3 offers `SecretBox`/`SecretString` and `ExposeSecret` for auditable access, redacted `Debug`, and no `Serialize` unless opted in. It is `forbid(unsafe_code)` with no mlock, and it points to the `secrets` crate for that [B-SI-05].
- **Rule SI-A-05:**
  1. All key material and plaintext buffers in C-07, C-15 and candor-core are `SecretBox<…>` or `Zeroizing<…>`. Types holding secrets derive `ZeroizeOnDrop`, do **not** implement `Clone`/`Copy`/`Debug`/`Serialize`, and are passed by reference.
  2. Allocate secret buffers at their final capacity (`Vec::with_capacity(max)`) and forbid growth: wrap them in a newtype with no `push`/`extend`. Decrypt streaming chunks into one reused, pre-allocated buffer.
  3. Each process holding secrets calls `prctl(PR_SET_DUMPABLE, 0)` at start, which also blocks same-uid ptrace and `/proc/pid/mem`. It runs with `LimitCORE=0`, `madvise(MADV_DONTDUMP)` and `mlock` on the secret arena (one locked arena from a small allocator in `candor-sys`, using `region`/`memsec` or `rustix::mm`) and with `LimitMEMLOCK` sized for it. The host has no swap, or encrypted swap with a random key per boot.
  4. Document the residual risk in 40-SECURITY-ASSUMPTIONS. Compiler copies, registers and the kernel socket buffers that carried TLS/onion plaintext are not controllable, so short process lifetime (respawn C-07 workers after N requests) is the real mitigation.
- **Verify:** A test that core-dumps a debug build with a known canary secret and greps the dump and `/proc/pid/mem` access (it must be denied). A `gcore` attempt against the production unit must fail. `systemd-analyze security` shows `LimitCORE`. The `secrecy` `Debug` redaction is tested by asserting `format!("{:?}")` contains no canary.

### A6. Constant time
- **Facts:** subtle 2.6.x describes itself as "*a best-effort attempt*" because "*side-channel resistance is not a property of software alone*" [B-SI-06]. Compilers have re-introduced branches into "constant-time" code (for example the 2024 "clangover" finding in ML-KEM reference code), and KyberSlash showed secret-dependent division timing in deployed Kyber code [B-SI-07][B-SI-08] (**UNVERIFIED** this session: not re-fetched).
- **Rule SI-A-06:** Every comparison of MACs, tokens, CSRF values, codename-derived lookup keys and password-verifier outputs uses `subtle::ConstantTimeEq`. `==` on `[u8]`/`String` for secrets is banned through a clippy `disallowed_methods`/`disallowed_types` config plus a newtype without `PartialEq`. Do not write your own primitives. Use the RustCrypto/`aws-lc-rs` implementations behind candor-core (ADR-019) and track their advisories. Codename lookup uses a keyed hash (HMAC of the codename-derived ID) indexed in the DB, so DB B-tree timing does not leak the codename.
- **Verify:** dudect-style tests (`dudect-bencher` 0.7.0, or a Welch t-test harness) on token compare, codename login, decapsulation failure vs success, and AEAD tag failure. CI flags |t| > 4.5 on a pinned bare-metal runner. Spot-check release assembly of hot paths for branches on secret data, for example with `cargo asm` review or a binary-analysis tool such as `timecop`/valgrind-memcheck taint (**UNVERIFIED** tool currency).

### A7. Testing and verification tools
- **cargo-fuzz (libFuzzer)** for every parser: HTTP form/multipart decoder, envelope framing, the relay batch format, the key-directory log parser, and the export package. Use structure-aware fuzzing with `arbitrary`. Apply to OSS-Fuzz once public. Seed corpora live in the repo. Use **bolero** to run the same harness under libFuzzer, AFL and Kani [B-SI-11].
- **proptest** for round-trip properties: encrypt/decrypt, pad/unpad, serialize/parse, and the authorization engine. Property: deny unless an explicit grant exists, and COI exclusion always wins.
- **Kani** (0.68) for bounded proofs of arithmetic and framing, and of `unsafe` preconditions in `candor-sys`. **Miri** for UB in unsafe code and in tests of pure crates [B-SI-09][B-SI-10].
- **Prusti/Creusot:** these are research-grade, so use them only for small, stable cores such as the padding-bucket function or the authorization decision function. Creusot fits pure functional specs best. This is optional, not a gate (**UNVERIFIED** current maturity).
- **Rule SI-A-07:** Every PR runs the fuzz targets for ≥ 60 s each (regression corpus); nightly runs for ≥ 1 h each. Kani and Miri run on every PR touching `candor-sys`/`candor-core`. Coverage is reported with `cargo llvm-cov`.

### A8. Clippy restriction lints worth enabling (workspace `[lints.clippy]`)
`unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `arithmetic_side_effects`, `as_conversions`, `cast_possible_truncation`, `mem_forget`, `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block`, `dbg_macro`, `print_stdout`, `print_stderr` (logging only through the scrubbed logger), `todo`, `unimplemented`, `exit` (only in main), `string_slice` (UTF-8 boundary panics), `float_arithmetic` in core, `missing_asserts_for_indexing`, `large_stack_arrays`/`large_stack_frames` (secrets on the stack), `disallowed_methods` (bans `std::env::var` outside config, `format!` into SQL, `std::process::Command` outside the sandbox launcher, and `rand::thread_rng` in favour of `OsRng`/`getrandom`), and `lossy_float_literal`. Set them all to deny in trust-path crates. Lint names follow the current clippy lint list [B-SI-03].

### A9. Dependency/advisory practice (ANSSI LIBS-*)
- **Rule SI-A-09:** Every dependency is vetted (`cargo vet`, importing audits from Mozilla, Google, Bytecode Alliance and others, plus Candor's own `safe-to-deploy` audits for trust-path crates). `cargo deny` bans duplicate crypto crates, git sources, yanked crates and copyleft-incompatible licenses (ADR-031). `cargo audit` runs daily against advisory-db with alerts. `cargo outdated` runs monthly (ANSSI LIBS-OUTDATED). Pins must be at or above the advisory fixes that matter: `sqlx ≥ 0.8.1` (RUSTSEC-2024-0363), `h2 ≥ 0.4.16` (RUSTSEC-2026-0258, unbounded empty DATA frames), and `rustls ≥ 0.23.45` (RUSTSEC-2026-0285, TLS 1.3 messages accepted across encryption levels) [B-SI-13..17].

---

## B. Linux service hardening

### B1. systemd sandboxing (systemd.exec, main ≈ v262/263; Debian 13 ships v257 (**UNVERIFIED** exact package version))
- **Practice:** Directives verified in the current man page include `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`, `PrivateDevices=`, `PrivateNetwork=`, `PrivateUsers=`, `PrivateIPC=`, `PrivatePIDs=` (v257), `PrivateBPF=` (v258), `ProtectKernelTunables/Modules/Logs=`, `ProtectClock=`, `ProtectHostname=`, `ProtectControlGroups=`, `ProtectProc=` (`noaccess|invisible|ptraceable`), `ProcSubset=`, `RestrictAddressFamilies=`, `RestrictNamespaces=`, `RestrictRealtime=`, `RestrictSUIDSGID=`, `RestrictFileSystems=`, `LockPersonality=`, `MemoryDenyWriteExecute=`, `SystemCallFilter=`, `SystemCallArchitectures=`, `CapabilityBoundingSet=`, `NoNewPrivileges=`, `NoExecPaths=`/`ExecPaths=`, `KeyringMode=`, `RemoveIPC=`, `UMask=`, `LoadCredential(Encrypted)=`, `LimitCORE=`, `CoredumpFilter=`, `MemoryKSM=`. `MemoryDenyWriteExecute=` blocks W+X mmap and mprotect→X, and is incompatible with JITs [B-SI-18]. `systemd-analyze security` scores exposure from 0.0 to 10.0, and `--threshold=` fails CI above a level [B-SI-19].
- **Rule SI-B-01 (baseline drop-in for every Candor daemon):**
  ```ini
  [Service]
  User=candor-<role>   # static system user per role; DynamicUser only for stateless helpers
  NoNewPrivileges=yes
  CapabilityBoundingSet=
  AmbientCapabilities=
  ProtectSystem=strict
  ProtectHome=yes
  PrivateTmp=yes
  PrivateDevices=yes
  PrivateIPC=yes
  PrivatePIDs=yes            # v257+
  PrivateUsers=yes           # where compatible with socket ownership
  ProtectKernelTunables=yes
  ProtectKernelModules=yes
  ProtectKernelLogs=yes
  ProtectControlGroups=yes
  ProtectClock=yes
  ProtectHostname=yes
  ProtectProc=invisible
  ProcSubset=pid
  RestrictNamespaces=yes
  RestrictRealtime=yes
  RestrictSUIDSGID=yes
  LockPersonality=yes
  MemoryDenyWriteExecute=yes
  RemoveIPC=yes
  KeyringMode=private
  UMask=0077
  SystemCallArchitectures=native
  SystemCallFilter=@system-service
  SystemCallFilter=~@privileged @resources @mount @debug @cpu-emulation @obsolete @raw-io @reboot @swap @module @clock
  SystemCallErrorNumber=EPERM
  RestrictAddressFamilies=AF_UNIX          # C-06/C-07/C-08; add AF_INET only where strictly needed
  PrivateNetwork=yes                        # for C-07 Sealer and C-17 helpers
  IPAddressDeny=any                         # plus explicit IPAddressAllow only where needed
  LimitCORE=0
  LimitMEMLOCK=<sized>
  ReadWritePaths=/var/lib/candor/<role>
  NoExecPaths=/
  ExecPaths=/usr/lib/candor/bin /usr/lib/x86_64-linux-gnu  # adjust; keeps tmp/state non-executable
  LoadCredentialEncrypted=<name>:/etc/credstore.encrypted/<name>   # TPM2-bound secrets (ADR-028)
  ```
  Secrets reach the service through `LoadCredentialEncrypted=` (TPM-sealed), never through environment variables.
- **Verify:** `systemd-analyze security --offline=yes --threshold=20 <unit>` in CI on the packaged unit files. The thresholds are on the tool's 0–100 internal scale, and the displayed value is /10, so check exact semantics against the man page. CI also runs `systemd-analyze verify`. A runtime self-test (C-25) reads `/proc/self/status` (`Seccomp: 2`, `NoNewPrivs: 1`, `CapEff: 0`) and reports drift.

### B2. seccomp in-process (seccompiler)
- **Practice:** systemd's filter is coarse, so add a per-process-role BPF allow-list compiled at build time. seccompiler 0.5.0 is Firecracker's library and supports JSON → BPF and thread-sync install [B-SI-21][B-SI-45].
- **Rule SI-B-02:** After init (sockets opened, keys loaded, Landlock applied), each binary installs a role-specific allow-list (`read, write, recvmsg, sendmsg, epoll_*, futex, clock_gettime, mmap/munmap (no PROT_EXEC), madvise, close, exit_group, …`) with default action `KillProcess`, applied to all threads (TSYNC). Kept in `candor-sys/seccomp/<role>.json`.
- **Verify:** An integration test runs each binary under the filter through the full functional test suite. A negative test executes `execve`/`socket(AF_INET)`/`ptrace` from inside and expects SIGSYS. `/proc/<pid>/status` shows `Seccomp_filters ≥ 2`.

### B3. Landlock
- **Facts:** Landlock is an unprivileged, stackable LSM sandbox applied by the process itself. Network rules exist since ABI v4 (TCP) and v10 (UDP). `LANDLOCK_SCOPE_*` (abstract unix sockets, signals) arrived in ABI v6. The kernel docs show the best-effort downgrade pattern by ABI [B-SI-20]. The `landlock` crate (0.4.7) implements a `CompatLevel` (BestEffort / SoftRequirement / HardRequirement). The mapping 6.7→ABI4, 6.10→ABI5, 6.12→ABI6 (Debian 13 kernel 6.12) is **UNVERIFIED** against kernel changelogs.
- **Rule SI-B-03:** Each daemon restricts itself to its state directory (RW) and its read-only config/binary paths, with no `REFER`/`MAKE_*` outside state. On ABI ≥ 4 it denies all TCP bind/connect except declared ones. On ABI ≥ 6 it scopes abstract-unix-socket and signal access. The minimum ABI is declared per profile: production requires 6 (`HardRequirement`), dev allows best-effort with a loud warning.
- **Verify:** Tests try `open("/etc/shadow")`, `open("/home")`, connect to 127.0.0.1:22 and signals to other processes, expecting EACCES/EPERM. The C-25 self-test reports the effective ABI.

### B4. AppArmor / namespaces
- **Rule SI-B-04:** Ship enforce-mode AppArmor profiles for `tor`, the Candor daemons and PostgreSQL. Debian enables AppArmor by default, and SecureDrop shipped enforce-mode profiles for apache/tor for years (**UNVERIFIED** current SecureDrop state; securedrop-proxy ships `usr.bin.securedrop-proxy` [B-SI-46]). The profiles act as defense-in-depth beside Landlock, because AppArmor holds even if the process is compromised before it applies its own sandbox. Namespaces come from systemd (`PrivateNetwork`, `PrivatePIDs`, `PrivateUsers`). Candor does not roll its own clone/unshare code.
- **Verify:** `aa-status` in the self-test. CI runs the functional suite with profiles in enforce mode and fails on `audit: apparmor="DENIED"` lines.

### B5. Privilege separation and IPC authentication (OpenSSH privsep lessons; SO_PEERCRED)
- **Practice:** OpenSSH split a privileged monitor from an unprivileged, chrooted network-facing child that talks over a narrow, validated message interface, so bugs in pre-auth parsing don't yield root [B-SI-23]. For local IPC, `SO_PEERCRED` returns the peer's pid/uid/gid captured at `connect()`/`socketpair()` time. Linux ≥ 6.5 adds `SO_PEERPIDFD` to avoid PID-reuse races (**UNVERIFIED**: man7 blocked; from memory) [B-SI-24].
- **Rule SI-B-05:** The split is C-06 (HTTP parse, unprivileged, no keys) ⇄ C-07 Sealer (keys, no network, `PrivateNetwork=yes`) ⇄ C-08 Store writer. The IPC is unix `SOCK_SEQPACKET` in a `0700` RuntimeDirectory. On accept, check `SO_PEERCRED.uid == expected_uid`, and use `SO_PEERPIDFD` where available. Messages use a fixed binary schema with explicit length limits, a version byte and no optional/unknown fields, and are rejected on any parse error. Do not use serde's self-describing formats, which allow unknown or duplicate fields. The Sealer exposes only `seal(plaintext_stream) → envelope_id` and `derive_source_key(codename) → session handle`. It never returns plaintext or keys. Each request is handled by a fresh or recycled worker with a bounded lifetime.
- **Verify:** Fuzz the IPC decoder. Integration test: connect as the wrong uid and expect rejection. Test that the C-06 process has no read access to key files (Landlock and DAC).

### B6. File descriptor hygiene, tmpfs, core dumps, ptrace
- **Rule SI-B-06:**
  - Rust std opens with `O_CLOEXEC` by default. Never pass inherited FDs to helpers except explicitly; use `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)` before any exec.
  - Uploads stream to `memfd_create(MFD_CLOEXEC | MFD_NOEXEC_SEAL)` or straight into encryption. Plaintext never touches disk, and there is no tmp file for no-JS uploads.
  - `/tmp` and `/var/tmp` are private tmpfs with `nosuid,nodev,noexec`.
  - Host settings: `kernel.yama.ptrace_scope=3` on intake and core hosts. Yama: "*no processes may use ptrace … Once set, this sysctl value cannot be changed*" [B-SI-22]. `fs.suid_dumpable=0`, `kernel.core_pattern=|/bin/false`, and `systemd-coredump` disabled (`Storage=none`, `ProcessSizeMax=0`). Also `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `kernel.unprivileged_bpf_disabled=1`, `kernel.kexec_load_disabled=1`, `user.max_user_namespaces=0` on intake if nothing needs it, `vm.swappiness` irrelevant if swap is off.
- **Verify:** The C-25 self-test checks the sysctls. `ls -l /proc/<pid>/fd` audit test. Lynis or `kernel-hardening-checker` in an image CI job (**UNVERIFIED** tool versions).

---

## C. Web / no-JS security (C-06 source web service; C-19 admin endpoints)

### C1. Sessions and cookies (OWASP Session Management, 2026-09)
- **Facts:** Session IDs need ≥ 64 bits of entropy. `__Host-` requires `Secure`, no `Domain` and `Path=/`, and is "**Recommended for session IDs**". The example is `Set-Cookie: __Host-SessionID=<value>; Secure; HttpOnly; SameSite=Strict; Path=/`. Idle timeouts of "*2-5 minutes for high-value applications*". Every session needs an absolute timeout. Regenerate the ID on privilege change [B-SI-25].
- **Tor-specific:** Tor Browser treats `http://*.onion` as a secure context and accepts `Secure` cookies there (EOTK advisory 001 criticises this for a different reason) [B-SI-28]. So `__Host-` works on plain-HTTP onions. **Verify empirically** in the current Tor Browser in CI (Selenium/marionette with tbselenium).
- **Rule SI-C-01:** Source session token is 256-bit random, stored server-side only as `HMAC(server_key, token)`, sent in a `__Host-candor_s` cookie with `Secure; HttpOnly; SameSite=Strict; Path=/`, **no `Max-Age`/`Expires`** (session cookie only, so nothing persists on the source's disk past browser close). Idle timeout 15 min (form-filling needs more than 2–5 minutes; show a warning), absolute timeout 2 h. New token on login, logout and codename-derived key unlock. Logout deletes the server row and clears the cookie. Pre-login, use a separate anti-CSRF pre-session cookie. Never put the codename or any identifier in URLs.
- **Verify:** A test suite asserts every `Set-Cookie` header. A test asserts there are no cookies without `__Host-`. Timeout tests.

### C2. CSRF without JS (OWASP CSRF, 2026-09)
- **Facts:** The synchronizer token pattern is recommended for stateful apps. The signed double-submit cookie must be session-bound with HMAC. Fetch Metadata (`Sec-Fetch-Site`) is now a primary option for modern browsers, but needs an Origin/Referer fallback. Also implement at least one defense-in-depth item [B-SI-26].
- **Rule SI-C-02:** Every POST form carries a hidden synchronizer token (`HMAC(session_key, form_id‖session_id)`, compared with `subtle`). The server also rejects `Sec-Fetch-Site` values other than `same-origin`/`none` on state-changing routes. If the header is absent, require `Origin` to equal the exact onion origin, and treat `null` as reject. `SameSite=Strict` acts as defense in depth. GET is never state-changing (ADR-029 deny-by-default routes).
- **Verify:** Tests send cross-site POSTs (missing token, wrong token, `Sec-Fetch-Site: cross-site`, `Origin: null`) and expect 403 with the generic page.

### C3. Security headers and CSP without JS (OWASP HTTP Headers)
- **Rule SI-C-03:** Every response carries:
  ```
  Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; sandbox allow-forms allow-same-origin
  ```
  In no-JS mode, add `script-src 'none'`. In the optional WEBCAT/WASM mode, use `script-src 'self' 'wasm-unsafe-eval'` with hashes. Also send `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Cross-Origin-Embedder-Policy: require-corp`, `Permissions-Policy` denying every feature, `Cache-Control: no-store` on all dynamic pages, `X-Frame-Options: DENY` (legacy), **no `Server`, `X-Powered-By` or `Date`-revealing build info**, and no HSTS on the onion. No inline styles, no external fonts, no favicon fetches from elsewhere. The CSP sandbox and directives are as recommended by OWASP [B-SI-27]. Exact header lists were not re-quoted from the file, so the line-level recommended values are **UNVERIFIED**.
- **Verify:** An integration test asserts the header set on every route (route-table driven). Response bodies are scanned for `<script` and `style=` in no-JS templates. Mozilla Observatory-style checks don't work on onion, so use a local checker.

### C4. Input validation, uploads, errors, logging
- **Rule SI-C-04:**
  - Use an allow-list per field (length in bytes and in grapheme clusters, UTF-8 validity, NFC normalisation, control characters stripped). Reject rather than sanitise. Templates auto-escape (askama/maud), and `|safe`/`PreEscaped` is banned via grep in CI.
  - Uploads use `multipart` streaming with a per-part and total cap. The filename is **never used on disk**: store it encrypted as metadata, then discard. The server does **not** sniff or parse content (ADR-012). Stream into the Sealer, which encrypts it. Reject nested multipart.
  - Error pages are a fixed set of static templates of identical size (see C6). No stack traces, versions, SQL errors or paths.
  - Logging follows the OWASP Logging cheat sheet's "do not log" list (session IDs, tokens, PII, codenames), extended by ADR-016 for Candor: **no IP (always 127.0.0.1 behind tor anyway), no User-Agent, no timestamps finer than the coarse bucket, no URL paths with IDs**. Use a typed log-event enum, not free-form strings [B-SI-25].
- **Verify:** A log-scrub test feeds canary values through every route and greps all log sinks. The upload fuzzer.

### C5. Request smuggling and slowloris with hyper/axum
- **Facts:** hyper has a history of smuggling-class bugs: body in GET (RUSTSEC-2020-0008), multiple `Transfer-Encoding` (RUSTSEC-2021-0020), lenient `Content-Length` (RUSTSEC-2021-0078) and TE integer overflow (RUSTSEC-2021-0079), all fixed. h2 has recurring DoS issues: RUSTSEC-2023-0034, RUSTSEC-2024-0003, RUSTSEC-2024-0332 (CONTINUATION flood) and RUSTSEC-2026-0258 [B-SI-17].
- **Rule SI-C-05:** Tor connects to C-06 directly over a unix socket (`HiddenServicePort 80 unix:/run/candor/web.sock`). There is **no intermediary HTTP proxy**, which eliminates front/back parsing disagreement. Use hyper `http1` only, with `http1_header_read_timeout` ≈ 10 s, `max_buf_size` 16–64 KiB, and no `http1_allow_obsolete_multiline_headers`. Reject requests that have both `Content-Length` and `Transfer-Encoding`, and reject `TE` other than `chunked`. tower-http layers: `TimeoutLayer` (total ≈ 30–120 s scaled to the upload cap), `RequestBodyLimitLayer`, and a `ConcurrencyLimitLayer` global and per circuit. Get the per-circuit ID through `HiddenServiceExportCircuitID haproxy` (PROXY protocol v2) on a separate TCP or unix port, and kill abusive circuits. Read bodies with a minimum data rate (abort if < X bytes/s over 30 s) to stop slow-POST.
- **Verify:** The smuggling test corpus (e.g. PortSwigger http-request-smuggling payloads, `smuggler.py`) runs against the listener. A slowloris/slow-POST test with `slowhttptest` against the unix socket through `socat` shows bounded resource use.

### C6. Constant-size responses (ADR-011)
- **Rule SI-C-06:** All source-facing responses are padded to a fixed set of size buckets (e.g. 16/32/64/128 KiB) **after** compression. Simplest: disable compression entirely on intake, which also avoids BREACH-style compression oracles. Pad with an HTML comment or a fixed-length hidden element. Responses are sent at fixed-time boundaries where cheap: delay to the next 250 ms tick on login/submit outcomes so the success/failure paths are indistinguishable. Success and failure pages for codename login are the same bucket.
- **Verify:** A test enumerates every route × outcome and asserts the body length ∈ the bucket set. A timing test asserts the login success/failure response-time distributions are indistinguishable (t-test).

---

## D. Onion service operation (C-05)

### D1. Tor daemon choice and DoS defenses
- **Facts (Tor community docs, 2026-09 mirror):** The Proposal 305 intro-point limits are `HiddenServiceEnableIntroDoSDefense`, `HiddenServiceEnableIntroDoSRatePerSec` and `HiddenServiceEnableIntroDoSBurstPerSec` (0 = infinite). The PoW options are `HiddenServicePoWDefensesEnabled`, `HiddenServicePoWQueueRate` and `HiddenServicePoWQueueBurst`, plus the global `CompiledProofOfWorkHash`. PoW is "*enabled by default on C Tor versions 0.4.8.1-alpha onwards*" but the Equi-X/HashX puzzle libraries are LGPL and "*enabled only if tor is compiled with `--enable-gpl`*". Check with `tor --list-modules` (`pow: yes`). Stream limits are `HiddenServiceMaxStreams` (≤ 65535) and `HiddenServiceMaxStreamsCloseCircuit 1`. Circuit-based rate-limiting uses `HiddenServiceExportCircuitID`. Onionbalance provides HA. The docs say to avoid too many onion addresses because of the extra guards [B-SI-29].
- **Arti status:** Arti 2.6.0 (2026-09-02) has `onion-service-service` and `vanguards` (default) features. Its example config warns that "*some of the security features needed for onion service privacy are not yet implemented*". Service-side `hs-pow-full` is still `__is_experimental` in tor-hsservice 0.46.0, and `restricted-discovery` is "will become non-experimental once #1795 is closed" [B-SI-30][B-SI-31]. Arti's own README also still says Tor Browser on Arti can't reach onion services yet.
- **Rule SI-D-01:** C-05 runs **C tor ≥ 0.4.8 stable built with `--enable-gpl`**, from Debian or deb.torproject.org, checking `pow: yes`. torrc:
  ```
  HiddenServiceDir /var/lib/tor/candor_src/
  HiddenServiceVersion 3
  HiddenServicePort 80 unix:/run/candor/web.sock
  HiddenServicePoWDefensesEnabled 1
  HiddenServicePoWQueueRate 50        # tune via load test
  HiddenServicePoWQueueBurst 100
  HiddenServiceEnableIntroDoSDefense 1
  HiddenServiceEnableIntroDoSRatePerSec 25
  HiddenServiceEnableIntroDoSBurstPerSec 200
  HiddenServiceMaxStreams 20
  HiddenServiceMaxStreamsCloseCircuit 1
  HiddenServiceExportCircuitID haproxy   # only on a second, rate-limit-aware listener
  SocksPort 0
  ControlPort 0     # or unix socket, cookie-auth, if vanguards addon/monitoring needed
  ClientUseIPv6 0   # match host network policy
  Sandbox 1         # tor's own seccomp sandbox on Linux
  ```
  Arti is used for the **C-03 client** (with `vanguards` enabled) and re-evaluated for C-05 once its OnionService.md lists the missing privacy features as done and PoW is non-experimental. The staff/journalist interface onions use restricted discovery (client auth) [B-SI-29].
- **Verify:** `tor --verify-config` in CI and `tor --list-modules | grep 'pow: yes'` in the self-test. Load test with PoW-solving clients (`tor` 0.4.8+ clients) and a non-solving flood to confirm the queue prioritises solvers.

### D2. Vanguards
- **Rule SI-D-02:** C tor ≥ 0.4.7 has **vanguards-lite** built in (**UNVERIFIED** version boundary). For full vanguards (the Tor docs recommend the Vanguards addon for "advanced attacks" [B-SI-29]), run the `vanguards` addon over a unix control port with cookie auth until C tor or Arti full vanguards is the norm. Its maintenance status is **UNVERIFIED**, so check before adopting. Its bandwidth/circuit checks also detect some attacks.
- **Verify:** The self-test checks that the addon process is alive and that its logs show no `WARN` about attacks.

### D3. Avoiding clearnet leaks (Riseup/Tor opsec; OnionScan lessons)
- **Facts:** The Tor opsec page warns that the web server can reveal OS and server software, that availability profiles and uptime correlation (and induced traffic patterns) deanonymise, and that services should run on a Tor client, not a relay. It points to the Riseup best-practices page and the Vanguards addon [B-SI-29][B-SI-32]. OnionScan (2016) found leaks via Apache `mod_status`, open directories, EXIF in images, shared SSH host keys and co-hosted clearnet sites (from memory, **UNVERIFIED** this session) [B-SI-33].
- **Rule SI-D-03:**
  - Intake hosts have **no default route to the internet except tor's own egress**. nftables allows outbound only for the `debian-tor` uid. DNS goes through tor's `DNSPort` or isn't present (`/etc/resolv.conf` → 127.0.0.1 with tor `DNSPort`). Time sync uses an onion-reachable source or `tlsdate`-like time from Tor consensus. Do not run NTP to public pools from intake (**UNVERIFIED** best tool; at minimum, NTP only via Tor or from the core zone over the relay link). APT updates go through `apt-transport-tor`/`tor+https` sources. Candor itself makes no update, telemetry or crash-report calls from intake.
  - There is no SSH reachable on the clearnet. Admin access goes through a separate restricted-discovery onion or out-of-band management, with distinct host keys per host and no SSH keys shared with any clearnet host.
  - The web app emits no version strings, build IDs, `Server`/`Date` skew or framework error pages, and no absolute URLs or clearnet links that auto-load. Static assets are stripped of metadata at build time (exiftool/mat2 in CI).
  - Do not co-host clearnet services on the same IP or host as C-05. The Clearnet Information Site (C-37) lives on different infrastructure.
  - Uptime patterns: the service runs continuously, with maintenance windows randomised and not tied to the organisation's working hours.
- **Verify:** On a test intake host, a network-namespace capture (`tcpdump` on the uplink) during the full test suite and during apt upgrade must show only tor ORPort traffic. An OnionScan-style self-scan (or a maintained fork) runs against staging. Static assets are checked with `exiftool -all` for an empty result.

### D4. Onion key custody
- **Facts:** C tor's `--keygen` and `OfflineMasterKey` apply to **relay** ed25519 identity keys, not onion services. C tor keeps the onion identity key (`hs_ed25519_secret_key`) online. Arti's design separates an identity key "which can be offline" from per-period signing keys, and its keymgr CLI exists, but offline HS identity support status is **UNVERIFIED**/not production [B-SI-31][B-SI-34].
- **Rule SI-D-04:** The onion secret key exists only on C-05 intake hosts (ADR-032 for HA) in `/var/lib/tor` (0700, tor-owned, on an encrypted volume, unlocked by TPM + measured boot). Back it up offline encrypted to the backup quorum key. Have a documented **rotation/compromise procedure**: publish the new onion via C-37 and the signed key directory C-14, revoke the old one. Track Arti offline-identity support as a roadmap item (38-IMPLEMENTATION-ROADMAP).
- **Verify:** The self-test checks permissions. A backup-restore drill (19-BACKUPS-DR) checks the key matches the published address.

---

## E. Database (C-08 Intake Store, C-12 Case DB)

- **Facts (PostgreSQL docs, master):** With RLS enabled and no policy, "*a default-deny policy is used*". "*Superusers and roles with the BYPASSRLS attribute always bypass the row security system*". Table owners bypass unless `FORCE ROW LEVEL SECURITY`. "*Referential integrity checks, such as unique or primary key constraints and foreign key references, always bypass row security … Care must be taken … to avoid covert channel leaks*". Leakproof functions may run before RLS quals [B-SI-35].
- **Rule SI-E-01 (connection and auth):** Use a unix socket only: `listen_addresses = ''`. `pg_hba.conf` contains only `local <db> <role> peer map=candor` lines, with `pg_ident` mapping OS user `candor-case` → DB role `case_app`, and a final `local all all reject`. There are no `host` lines. Core-zone replicas use `hostssl … scram-sha-256` with `clientcert=verify-full` only on the replication network. `password_encryption = scram-sha-256`. Restrict the socket directory to group `candor-db`.
- **Rule SI-E-02 (roles):** `schema_owner` (NOLOGIN, owns tables, used only by the migration tool), `case_app` (LOGIN, DML only, `NOBYPASSRLS`, `NOSUPERUSER`, `NOCREATEDB`, `NOCREATEROLE`) and `audit_writer` (INSERT-only on audit tables). `REVOKE ALL ON SCHEMA public FROM PUBLIC`, `REVOKE CREATE`. Set `search_path` explicitly in the role config and on every `SECURITY DEFINER` function (`SET search_path = pg_catalog, candor`). Avoid `SECURITY DEFINER` where possible.
- **Rule SI-E-03 (RLS):** Tenant tables use `ENABLE` + `FORCE ROW LEVEL SECURITY` and a policy `USING (tenant_id = current_setting('candor.tenant_id')::uuid)` with matching `WITH CHECK`. The app sets `SET LOCAL candor.tenant_id` **inside each transaction** (never session-level, because pooled connections leak tenant context). Uniqueness constraints include `tenant_id` so cross-tenant existence can't be probed. Views use `security_invoker = true` (PG ≥ 15). Mark no custom functions LEAKPROOF. RLS is defense-in-depth. The C-22 authorization engine remains the primary control, and case-level ACL/COI must also be enforced cryptographically (ADR-030).
- **Rule SI-E-04 (logging):** `log_statement = 'none'` (or `'ddl'`), `log_min_duration_statement = -1`, `log_parameter_max_length = 0`, `log_parameter_max_length_on_error = 0` (bind values never logged), `log_min_error_statement = panic` on intake (so failing SQL text isn't logged with context), `log_connections = on` is fine over a unix socket (no IP), and `log_line_prefix` without `%h`/`%r`. Turn off `track_activity_query_size` exposure via `pg_stat_activity` to non-owners (default restricts other roles' query text). Disable `pg_stat_statements` on intake. These setting names are from the config docs. The exact defaults are **UNVERIFIED** line-by-line.
- **Rule SI-E-05 (sqlx):** Use only `sqlx::query!`/`query_as!` (compile-time checked against the offline `.sqlx` metadata committed in-repo) or `QueryBuilder::push_bind`. A `disallowed_methods` lint plus a grep bans `format!`/string concatenation into `query()`. Pin `sqlx ≥ 0.8.1` (RUSTSEC-2024-0363); Candor is on 0.9.0. Cap every bound value's size at the application layer, well below 1 GiB.
- **Rule SI-E-06 (migrations):** Migrations are forward-only, reviewed, signed in release, and run by `schema_owner` through `candorctl migrate`, never automatically at app start. Each migration runs in a transaction with `lock_timeout`/`statement_timeout`, using an expand → backfill → contract pattern. A CI test applies all migrations to an empty DB and to a previous-release snapshot, then runs an RLS regression suite.
- **Verify:** `pg_hba` lint in CI. An RLS test suite connects as `case_app` with tenant A and asserts zero rows, and an error on insert, for tenant B data, including FK/unique probe attempts. `SELECT rolbypassrls, rolsuper FROM pg_roles` is checked by the self-test. The CIS PostgreSQL Benchmark items (logging, auth, file permissions) are checked with an automated scanner. CIS text was not accessible, so the item mapping is **UNVERIFIED** [B-SI-36].

---

## F. Desktop app (C-15 Candor Desk, Tauri 2) — later milestone

- **Facts (tauri-docs, 2026-09):** Capabilities define which permissions apply to which windows and webviews. "*Windows and WebViews which are part of more than one capability effectively merge the security boundaries*". All capability files in `src-tauri/capabilities` are enabled by default. Command scopes: "*deny always supersedes the allow scope*", and "*Command developers need to ensure that there are no scope bypasses*". The Runtime Authority checks origin, capability and scope before any command runs. The CSP is only enabled if set in config, and Tauri hashes and nonces bundled assets at compile time. Isolation pattern: "*Tauri highly recommends using the isolation pattern whenever it can be used*". It intercepts all IPC in a sandboxed iframe and encrypts messages with AES-GCM using a runtime-generated key [B-SI-38][B-SI-39]. Updater: "*needs a signature … This cannot be disabled*", single private key via `TAURI_SIGNING_PRIVATE_KEY` [B-SI-40]. RustSec has past Tauri FS-scope bypasses (RUSTSEC-2022-0088/0091) [B-SI-17].
- **Electron checklist lessons (20 items) [B-SI-41]:** load only local, secure content; no Node integration for remote content; context isolation; process sandbox; deny permission requests; keep `webSecurity`; CSP; limit navigation and new windows; no `shell.openExternal` on untrusted input; validate IPC `sender`; avoid `file://` and prefer custom protocols; fuses. These map one-to-one to Tauri rules below.
- **Rule SI-F-01:** `frontendDist` is bundled static assets only, with **no `remote` capability and no `devUrl` in release**. One capability file per window, listing only that window's commands. There is no FS/shell/http plugin exposure to the WebView: file I/O happens in Rust commands with hard-coded directories. Turn on the Isolation pattern with a minimal validator. The CSP is `default-src 'self'; script-src 'self'; connect-src ipc: http://ipc.localhost; img-src 'self' asset: blob:; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'`. Navigation and new windows are blocked with `on_navigation` → false except the app origin. No `open` of URLs except through an allow-list with user confirmation (no Tor-less clearnet opens).
- **Rule SI-F-02 (hostile content):** The Desk WebView **never renders evidence or source-supplied HTML/markdown/SVG/images**. Source messages are shown as plain text: escape everything, show no links, and render them inert. Show source-supplied text through a text-only component with bidi and confusable controls visible. Evidence is opened only in C-17 (Dangerzone-style pixels-to-PDF). Even the sanitised PDF is opened in C-17's viewer, not in the Desk's WebView. Dangerzone itself removed in-app markdown→HTML rendering of release notes to cut attack surface [B-SI-42].
- **Rule SI-F-03 (updates):** Tauri's updater signature is necessary but not sufficient: it is a single minisign key, with no threshold, rollback or freeze protection. Wrap it per ADR-022: the updater fetches a TUF-verified target (threshold-signed, from a transparency log) and *then* the Tauri signature is checked as a second factor. Alternatively, ship Desk only through signed .deb/APT with TUF-backed metadata and disable the in-app updater.
- **SecureDrop Workstation lessons [B-SI-46][B-SI-47]:** Its compartments are `sd-app` (no network, holds decrypted submissions), `sd-proxy` (the only networked VM; a **Rust** proxy translating qrexec JSON ↔ HTTP to a single configured onion origin), `sd-gpg` (split-GPG: keys never in the app VM), `sd-viewer` disposable VMs for every opened file, and `sd-log`. The proxy's stated properties are isolation ("*The proxy … talks only to the (onion) origin it's configured with*") and sanitisation. FPF's own rationale: the air-gapped SVS workflow was slow and error-prone. The Qubes approach "*stands and falls with the security of Qubes OS*", and SecureDrop Workstation is still "open beta" on Qubes 4.3. **Candor rule:** Candor Desk's EE "Qubes profile" should mirror this split: keys in a non-networked key VM reached over qrexec, a network proxy VM, and DispVM viewers. Candor's non-Qubes profile should approximate it with separate OS users and processes, with the key-holding process having no network (systemd/Landlock), and C-17 microVMs.
- **Verify:** The `tauri-cli` build checks capability schemas. A CI test asserts that no `remote` key appears and that the CSP is set. A Playwright/WebDriver test injects a malicious message (HTML, `javascript:` link, RTL override) and asserts it renders as inert text. An IPC fuzz test calls every command with fuzzed args from an untrusted-window identity and expects denial.

---

## G. Sandboxed document handling (C-17)

- **Dangerzone facts (2026-09):** The outer container runs with `--log-driver none`, `--security-opt no-new-privileges`, `--userns nomap` (Podman ≥ 4.1), a custom seccomp profile (Podman's default plus the ptrace gVisor needs), `--cap-drop all` (except `CAP_SYS_CHROOT` for gVisor), SELinux `container_engine_t` and `--network=none`. The document is converted **inside gVisor (`runsc`) inside the container**. The sandbox image updates independently of the app and is **Cosign-signed** and verified (`dangerzone-image verify-local`). It accepts stdin/stdout pipes. v0.11.0 dropped the bundled `container.tar` from slim packages [B-SI-42][B-SI-43].
- **Firecracker facts:** The jailer sets up a chroot, uid/gid drop, cgroups (v1/v2), netns, and a new PID namespace before exec'ing Firecracker. Firecracker installs its own seccomp filters. The production host guide covers seccomp, serial-device limits, disk/memory/vCPU limits, egress filtering with nft, **disabling swap or using secure swap**, disabling SMT and KSM, and Rowhammer-mitigated memory [B-SI-44][B-SI-45].
- **Qubes qrexec:** RPC between VMs is mediated by dom0 policy (`/etc/qubes/policy.d/*.policy`) with explicit allow/deny/ask per service, source and target. DispVMs are destroyed after use. SecureDrop Workstation relies on it for split-GPG and the proxy [B-SI-46][B-SI-48] (qrexec docs not re-fetched: **UNVERIFIED** current syntax details).
- **Rule SI-G-01 (CE/default C-17):** Use a two-layer sandbox. The outer layer is a rootless Podman container with Dangerzone's exact flags. The inner layer is gVisor `runsc` with `--network=none`, a read-only rootfs, a tmpfs work dir with a size cap, and a CPU/memory/pids/time limit per document. The input is passed as a byte stream on stdin. The output is **raw RGB pixel pages** with width, height and count validated by the host, and the host (outside the sandbox) rebuilds the PDF and optionally OCRs in a *second* sandbox. This is Dangerzone's two-phase design. The sandbox image is reproducibly built, signed (Cosign or TUF target), digest-pinned, and auto-updated independently.
- **Rule SI-G-02 (EE/high-assurance C-17):** Use a Firecracker microVM per document through the jailer: no network device, a single virtio-block read-only rootfs plus a virtio-vsock or block device for I/O, no serial console in production, a memory/vCPU cap, and destruction after each document. The host runs with SMT off where the threat model needs it, KSM off (`MemoryKSM=no`), swap off, and `ptrace_scope=3`. On Qubes, use a `sd-viewer`-style DispVM template with `netvm=""`, qrexec policy `candor.Convert * candor-desk @dispvm:candor-viewer allow` and everything else `deny`.
- **Rule SI-G-03 (minimal device config):** Expose no USB, audio, GPU or clipboard to viewer VMs or containers. Use a fixed locale/timezone (UTC) so metadata can't be correlated. Time limit per page. Keep no logs of document content. Return only pixels and a status code.
- **Verify:** A malicious-document corpus (polyglots, zip bombs, decompression bombs, CVE PoCs for LibreOffice/poppler/ImageMagick) asserts bounded resources and no network attempts (eBPF/`tcpdump` on host shows nothing). Escape canaries: a sandbox test tries to read a host canary file and open a socket, and must fail. Image signature verification is tested with a tampered image, which must be refused.

---

## Bibliography

| ID | Title | URL | Date (version read) | Relevance |
|---|---|---|---|---|
| B-SI-01 | ANSSI, *Secure Rust Guidelines* (rust-guide), rules DENV-*, LANG-*, MEM-*, FFI-*, LIBS-* | https://anssi-fr.github.io/rust-guide/ (source: https://github.com/ANSSI-FR/rust-guide) | commit 2026-05-18 | Core Rust coding rules (A1–A4, A9) |
| B-SI-02 | Rust Secure Code Working Group | https://github.com/rust-secure-code/wg | not re-fetched (**UNVERIFIED** current activity) | unsafe minimisation, safety-dance |
| B-SI-03 | Clippy lint list | https://rust-lang.github.io/rust-clippy/master/ | not fetched (**UNVERIFIED** each lint name against the current list) | A8 lint set |
| B-SI-04 | zeroize crate docs (src/lib.rs) | https://github.com/RustCrypto/utils/tree/master/zeroize | v1.9.0, 2026-06-12 | Zeroization guarantees/limits |
| B-SI-05 | secrecy crate docs | https://github.com/iqlusioninc/crates/tree/main/secrecy | v0.10.3 | Secret wrapper semantics |
| B-SI-06 | subtle crate README | https://github.com/dalek-cryptography/subtle | v2.6.x (crates.io 2.6.1) | Constant-time primitives, best-effort caveat |
| B-SI-07 | "clangover": compiler-induced timing leak in ML-KEM reference | https://github.com/antoonpurnal/clangover | 2024 (**UNVERIFIED**, not fetched) | Compiler CT pitfalls |
| B-SI-08 | KyberSlash | https://kyberslash.cr.yp.to/ | 2024 (**UNVERIFIED**, not fetched) | Secret-dependent division timing |
| B-SI-09 | Kani Rust Verifier | https://github.com/model-checking/kani | kani-verifier 0.68.0 (2026-09-16, crates.io) | Bounded proofs |
| B-SI-10 | Miri | https://github.com/rust-lang/miri | not fetched | UB detection |
| B-SI-11 | cargo-fuzz / libfuzzer-sys / bolero / proptest | https://github.com/rust-fuzz/cargo-fuzz ; https://github.com/camshaft/bolero ; https://github.com/proptest-rs/proptest | 0.13.2 / 0.4.13 / 0.13.6 / 1.11.0 (crates.io) | Fuzz/property testing |
| B-SI-12 | dudect-bencher; Reparaz et al., "Dude, is my code constant time?" (DATE 2017) | https://github.com/rozbb/dudect-bencher ; https://eprint.iacr.org/2016/1123 | 0.7.0 (2026-03-23) | Statistical CT testing |
| B-SI-13 | cargo-deny | https://github.com/EmbarkStudios/cargo-deny | 0.20.2 (2026-07-09) | Policy gate |
| B-SI-14 | cargo-vet | https://github.com/mozilla/cargo-vet | 0.10.2 (2026-01-13) | Audit gate |
| B-SI-15 | cargo-audit / RustSec | https://github.com/rustsec/rustsec | 0.22.2 (2026-06-05) | Advisory scanning |
| B-SI-16 | cargo-geiger | https://github.com/geiger-rs/cargo-geiger | 0.13.0 (2025-08-31) | unsafe inventory |
| B-SI-17 | RustSec advisory-db (hyper RUSTSEC-2020-0008, -2021-0020/0078/0079; h2 -2023-0034, -2024-0003, -2024-0332, -2026-0258; sqlx -2024-0363; rustls -2026-0285; tauri -2022-0088/0091) | https://github.com/rustsec/advisory-db | snapshot 2026-09-30 | Concrete pins and bug classes |
| B-SI-18 | systemd.exec(5) man page (source) | https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html (src: https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml) | main, 2026-09-29 (v263 in development) | Sandboxing directives |
| B-SI-19 | systemd-analyze(1) `security` verb | https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html | main, 2026-09-29 | Exposure scoring/threshold |
| B-SI-20 | Linux kernel Landlock userspace API doc | https://docs.kernel.org/userspace-api/landlock.html (src: torvalds/linux Documentation/userspace-api/landlock.rst) | mainline 2026-09 (ABI up to v10) | Landlock ABI, best-effort pattern |
| B-SI-21 | landlock crate; seccompiler crate | https://github.com/landlock-lsm/rust-landlock ; https://github.com/rust-vmm/seccompiler | 0.4.7 (2026-07-27); 0.5.0 (2025-03-07) | In-process sandboxing |
| B-SI-22 | Linux Yama LSM doc | https://docs.kernel.org/admin-guide/LSM/Yama.html (src: Documentation/admin-guide/LSM/Yama.rst) | mainline 2026-09 | ptrace_scope semantics |
| B-SI-23 | Provos, Friedl, Honeyman, "Preventing Privilege Escalation" (USENIX Security 2003) | https://www.usenix.org/conference/12th-usenix-security-symposium/preventing-privilege-escalation | 2003 (**UNVERIFIED**, not fetched) | Privsep design |
| B-SI-24 | unix(7) man page: SO_PEERCRED / SO_PEERPIDFD | https://man7.org/linux/man-pages/man7/unix.7.html | not fetched (**UNVERIFIED**) | IPC peer auth |
| B-SI-25 | OWASP Session Management Cheat Sheet (+ Logging, Error Handling, Input Validation, File Upload cheat sheets) | https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html (src: github.com/OWASP/CheatSheetSeries) | repo 2026-09-30 | Cookies, timeouts, logging |
| B-SI-26 | OWASP CSRF Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html | repo 2026-09-30 | Synchronizer token, Fetch Metadata |
| B-SI-27 | OWASP HTTP Headers / CSP Cheat Sheets | https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html | repo 2026-09-30 (values partly **UNVERIFIED**) | Header set |
| B-SI-28 | EOTK/Onionspray security advisory 001 (Tor Browser secure-context/Secure cookies on .onion) | https://github.com/alecmuffett/eotk/blob/master/docs.d/security-advisories.d/001-torbrowser.md | v1.2, 2020-07-27 | `__Host-` viability on HTTP onions |
| B-SI-29 | Tor Project, Onion Services: Advanced → DoS, OpSec, Client auth | https://community.torproject.org/onion-services/advanced/dos/ ; …/opsec/ (src: github.com/torproject/community) | mirror 2026-09-29 | torrc DoS/PoW options, opsec |
| B-SI-30 | Arti 2.6.0 crate (README, arti-example-config.toml) | https://crates.io/crates/arti ; https://gitlab.torproject.org/tpo/core/arti/-/blob/main/doc/OnionService.md | 2026-09-02 | Arti onion-service readiness |
| B-SI-31 | tor-hsservice 0.46.0 (Cargo features: hs-pow-full experimental) | https://crates.io/crates/tor-hsservice | 2026 | Arti service-side PoW status |
| B-SI-32 | Riseup, "Tor Onion Services Best Practices" | https://riseup.net/en/security/network-security/tor/onionservices-best-practices | not fetched (blocked; **UNVERIFIED** content) | Onion opsec |
| B-SI-33 | OnionScan (s-rah) and reports | https://github.com/s-rah/onionscan | 2016 (**UNVERIFIED**, not fetched) | Leak classes |
| B-SI-34 | tor(1) manual: OfflineMasterKey / --keygen (relay keys) | https://2019.www.torproject.org/docs/tor-manual.html.en | not fetched (**UNVERIFIED**) | Offline keys apply to relays |
| B-SI-35 | PostgreSQL docs: Row Security Policies (ddl.sgml), Client Authentication, Server Configuration | https://www.postgresql.org/docs/current/ddl-rowsecurity.html (src: github.com/postgres/postgres doc/src/sgml) | master 2026-09 | RLS bypass/covert channels, pg_hba, logging |
| B-SI-36 | CIS PostgreSQL Benchmark | https://www.cisecurity.org/benchmark/postgresql | not fetched (**UNVERIFIED**) | Hardening checklist |
| B-SI-37 | sqlx | https://github.com/launchbadge/sqlx | 0.9.0 (2026-05-21) | Query macros, RUSTSEC-2024-0363 |
| B-SI-38 | Tauri 2 docs: Security overview, Capabilities, Permissions, Scopes, Runtime Authority, CSP | https://v2.tauri.app/security/ (src: github.com/tauri-apps/tauri-docs) | 2026-09-29; tauri 2.12.1 | Desk security model |
| B-SI-39 | Tauri 2 docs: Isolation Pattern | https://v2.tauri.app/concept/inter-process-communication/isolation/ | 2026-09-29 | IPC interception |
| B-SI-40 | Tauri updater plugin docs | https://v2.tauri.app/plugin/updater/ | 2026-09-29; plugin 2.13.1 | Update signatures |
| B-SI-41 | Electron Security Checklist | https://www.electronjs.org/docs/latest/tutorial/security | repo 2026-09 | Desktop webview lessons (20 items) |
| B-SI-42 | Dangerzone source (isolation_provider/container.py, CHANGELOG) | https://github.com/freedomofpress/dangerzone | 2026-09-15 (post-0.11.0) | Sandbox flags, gVisor |
| B-SI-43 | Dangerzone "Independent Container Updates" (Cosign-signed sandbox) | https://github.com/freedomofpress/dangerzone/blob/main/docs/developer/independent-container-updates.md | since 0.10.0 (2025-12-02) | Sandbox update trust |
| B-SI-44 | Firecracker jailer.md | https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md | main 2026-09 | microVM jail |
| B-SI-45 | Firecracker Production Host Setup | https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md | main 2026-09 | Host hardening (swap, SMT, KSM, egress) |
| B-SI-46 | SecureDrop Workstation README; securedrop-client/proxy README | https://github.com/freedomofpress/securedrop-workstation ; https://github.com/freedomofpress/securedrop-client/tree/main/proxy | 2026-09-30 / 2026-09-29 | VM split, Rust qrexec proxy |
| B-SI-47 | SecureDrop Workstation docs | https://workstation.securedrop.org | not fetched (**UNVERIFIED**) | Operator guidance |
| B-SI-48 | Qubes OS qrexec documentation | https://www.qubes-os.org/doc/qrexec/ | not fetched (**UNVERIFIED**) | Inter-VM RPC policy |
| B-SI-49 | gVisor documentation (runsc security model) | https://gvisor.dev/docs/architecture_guide/security/ | not fetched (**UNVERIFIED**) | User-space kernel sandbox |
