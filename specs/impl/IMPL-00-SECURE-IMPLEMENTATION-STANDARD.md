# IMPL-00 — Secure Implementation Standard

Status: Draft v1.0 · Edition applicability: both (CE trust path; EE inherits) · Owner: Security Lead (with Lead Architect) · Applies to: every build step RM-0..RM-12 (`38-IMPLEMENTATION-ROADMAP.md`)

## 1. Purpose and scope

This document says **how** every Candor change is built. The step documents `IMPL-RM0`..`IMPL-RM4` say **what** is built in which order. This standard brings together:

- the normative SDL (`27-SECURE-DEVELOPMENT.md`), supply chain (`28`), testing (`29`, `30`), audit (`37`) and roadmap (`38`);
- the implementation research `research/R7-secure-implementation.md` (rules `SI-x-nn`), `research/R8-secure-dev-lifecycle.md` (rules `SL-R-nnn`, incidents `INC-SL-nn`) and `research/R9-secure-code-audit.md` (audit procedure);
- the owner's build instructions in `process/BUILD-BRIEF.md`: the Security and OPSEC bar, and the independent audit gate.

Out of scope: product behaviour (owned by specs 01–26) and release ceremonies with production keys (33, RM-7).

## 2. Normative sources and precedence

| Rank | Source | Rule |
|---|---|---|
| 1 | `specs/DECISIONS.md` ADR-001..ADR-051 | Binding. An implementation that contradicts an ADR is a defect. |
| 2 | Owning spec (DECISIONS §3 prefix owner) and `tools/constants.json` | Canonical values. Code takes constants from `candor-limits`, which is generated from the registry. Literals are never restated in code. |
| 3 | `27`/`28`/`29`/`30` | Process, gates (SG-01..SG-29) and test IDs (ST-/AT-) |
| 4 | This standard (`IMP-STD-*`) and the step docs (`IMP-RMn-*`) | How the work is done. These may only **tighten** ranks 1–3. |
| 5 | R7/R8/R9 rules | Adopted through this standard. Where a research rule conflicts with a spec, the spec wins (table below). |

**Conflict resolutions** (research vs. spec; the spec or the stricter value applies):

| Topic | Research says | Binding value | Source |
|---|---|---|---|
| Dependency cooldown | 7 days (SL-R-009) | **14 days**, security fixes fast-tracked with a diff review | 28 SCM-012 |
| Tier W session idle timeout | 15 min (SI-C-01) | **20 min idle / 2 h absolute** (`tierw_session_idle`, `tierw_session_absolute`) | 11 §5.6, ADR-034 |
| Sealer/store IPC encoding | fixed binary, no serde (SI-B-05) | **Deterministic CBOR (RFC 8949 §4.2) with a strict hand-written decoder**: reject unknown/duplicate keys, indefinite lengths, non-canonical ints and trailing bytes. No serde self-describing formats. | 07 §5.2 |
| Name of the `unsafe` OS-shim crate | `candor-sys` (SI-A-04) | **`candor-memlock`**, the only allow-listed OS crate. It also hosts the Landlock/seccomp glue. | 27 §12.1 |
| Source-UI header set | SI-C-03 list | **11 §5.3** header list. SI-C-03 adds only checks, never different values. | 11 §5.3 |
| Panic handling in C-06/C-10 | `panic = "abort"` everywhere (SI-A-03) | Release `panic = "abort"` for all binaries. C-06/C-10 also map handler errors to fixed pages, and a reachable panic counts as a **High** finding (R9 §8.3) | 27 §12.2, R9 |

## 3. Per-change workflow

Every change to T0/T1 code follows all eight stages in order. A T2 change may skip stages 1, 6 and 7.

| # | Stage | Artefact (path) | Done when | Owner | Gate / tool |
|---|---|---|---|---|---|
| 1 | Threat-model delta | `threat-model/features/<feature-id>.md` (27 §10.2: DFD, STRIDE, LINDDUN, THR mapping, drill delta, item 5a inferential analysis, canary sinks, abuse cases, tests, residuals) **or** `Threat-Model: N/A (<reason>)` in the PR | Security Lead approves, plus the Anonymity Reviewer if 27 §11.4 triggers. Approval comes **before** the implementation PR merges | Builder | `tm-link` lint (ST-004) |
| 2 | Design note | `crates/<c>/SPEC-NOTES.md` §Design: interfaces (traits/types), invariants, input limits (named constants), privileges required (OS user, files, sockets, syscalls), failure modes (fail-closed table), secrets held and their lifetime | Reviewer agrees the design before code review starts | Builder | PR description links it |
| 3 | Code | Crate source under the §4–§10 rules | `make check` green locally | Builder | fmt, clippy deny set, lints ST-004..ST-008, ST-013 |
| 4 | Tests | Unit, negative, hostile, property, KAT, fuzz and integration tests per §11, each mapped to ST-/AT-/IMP- IDs in a comment | Required tests in the step's test plan exist and pass. Fuzz targets are registered in CI | Builder | `cargo test`, fuzz smoke run |
| 5 | Self-review | `SPEC-NOTES.md` §Security self-review (template in §14.2): an attacker read of the diff against the BUILD-BRIEF bar and the step's §4 checklist | Every checklist line answered, residuals listed | Builder | Reviewer checks it is present |
| 6 | Independent audit gate | `process/audits/AUDIT-<step>.md`, written by an auditor who did not build the code, using `process/AUDIT-CHECKLIST.md` and R9 | 0 open Critical/High. Each Medium is fixed or has the lead's written acceptance. Each finding has a red→green regression test (SL-R-014) and a variant scan | Independent auditor | §13 |
| 7 | Two-person review | Forge approvals per §12 | Required approvals on the final commit (stale approvals dismissed) | Reviewers | SG-02, `bp-verify` |
| 8 | Integration | Merge to the protected branch with a signed commit; gate evidence appended to the milestone report | All required CI checks green, including `anon-marker-scan` from RM-1 | Lead / Release Manager | SG gates; RM-005 |

## 4. Rust coding rules

### 4.1 Toolchain and build profile (SI-A-01; ANSSI DENV-*)

- `rust-toolchain.toml` pins one stable version (currently 1.94.1). Bumps go through a reviewed PR.
- `Cargo.lock` is committed, and every build runs with `--locked`. Release builds also use `--frozen` against a vendored tree (SCM-016).
- Flags live only in the checked-in `.cargo/config.toml`: `--remap-path-prefix` for the source, `$CARGO_HOME` and target dirs (ADR-051(5)). Ambient `RUSTFLAGS` are never used.
- `[profile.release]`: `overflow-checks = true`, `panic = "abort"`, `lto = "fat"`, `codegen-units = 1`, `debug = false`, `strip = "symbols"`, `incremental = false`. Test and dev profiles keep `overflow-checks = true`.
- Targets: `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` (tier 1). Crypto CI runs on both natively (SL-R-004).

### 4.2 Lint set

Every lint below is `deny` in T0/T1 crates through `[workspace.lints]` plus a per-crate `[lints]` override. `clippy.toml` sets `allow-*-in-tests = true`.

| Lint(s) | Why | Source |
|---|---|---|
| `unsafe_code = forbid` (all crates except `security/unsafe-allowlist.toml`) | Memory safety | SI-A-04; 27 §12.1 |
| `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `unreachable`, `indexing_slicing`, `string_slice`, `missing_asserts_for_indexing` | No panics on hostile input. With `panic = "abort"` a panic is a remote kill switch | SI-A-03; 27 §12.2; R9 §1.2 |
| `arithmetic_side_effects`, `as_conversions`, `cast_possible_truncation`, `cast_sign_loss`, `cast_possible_wrap` | Length smuggling (RUSTSEC-2024-0363) | SI-A-02 |
| `mem_forget`, `large_stack_arrays`, `large_stack_frames` | Secrets left on the stack or never zeroized | SI-A-05 |
| `dbg_macro`, `print_stdout`, `print_stderr`; `disallowed-macros`: `println`, `eprintln`, `print`, `eprint`, `dbg`, `log::*`, `tracing::*` | candor-log is the only output | 27 §12.5 Logging; ADR-016 |
| `exit` (except in `main`), `float_arithmetic` (T0), `lossy_float_literal` | Determinism | SI-A-08 |
| `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block`, `unsafe_op_in_unsafe_fn` (allow-listed crates) | Reviewable `unsafe` | SI-A-04 |
| `disallowed-methods`: `std::env::var*` outside the config crate; `std::process::Command` outside the C-17 launcher; `rand::thread_rng`, `rand::random`; `SystemTime::now`, `chrono::Utc::now` outside `candor-time`; `std::fs::*` with non-constant paths outside `candor-safefs`; `Path::join`; `tar::Archive::unpack`; `zip::ZipArchive::extract`; `sqlx::query` / `query_as` (non-macro); `Nonce::from*` outside `candor-core::aead` | Banned APIs | SI-A-06, SI-A-08, SI-E-05; 27 §12.5; ADR-027 |
| `disallowed-types`: `std::collections::HashMap` in T0 deterministic encoders (use `BTreeMap`); `flate2::*`, `zstd::*` in T0/T1 except the padded export path | Canonical encoding; compression oracle | SL-R-005 |

Lints that clippy cannot express (for example "no `|safe` in templates", "no `format!` into SQL", "no compression before encryption", "no exact time on a source-linked type") are enforced as Semgrep rules vendored under `security/semgrep/` (ST-008) and as `tests/lint*.rs` in-crate tests. Both are required checks.

### 4.3 Arithmetic, lengths and casting (SI-A-02)

- Wire lengths are decoded as `u64` and converted with `usize::try_from`. Arithmetic on them uses `checked_*`, and an overflow becomes an error.
- Every length field is checked against a **named constant** from `candor-limits` **before** allocation (27 §12.2).
- `Vec::with_capacity(n)` takes only a bounded `n`. Collection sizes are not trusted from the wire.
- Kani harnesses prove that framing, padding-bucket and chunk-index arithmetic cannot overflow (SI-A-07).

### 4.4 Panics, errors and error text (SI-A-03; 27 §12.5 Errors)

- Each crate has one error enum (`thiserror` or hand-written). Variants carry **codes and bounded enums only**: no input bytes, paths, names, sizes or secret-derived values. Errors never echo input (AT-018).
- At the HTTP boundary, errors map to a fixed set of static error templates, each in its response size class (§7), plus an opaque random correlation ID. The internal detail goes only to a SYSTEM-class candor-log event that carries the code.
- Panic hook (all binaries): writes a static string and the correlation ID to the candor-log SYSTEM sink, with no payload, location or backtrace. `RUST_BACKTRACE` is unset in units. `Drop` never panics.
- Async: a panic inside a tokio task must never leave half-updated state. With `panic = "abort"` the process dies. Supervisors (07 §4.5) restart it, and the restart path zeroizes everything because memory is gone.

### 4.5 `unsafe` (SI-A-04; 27 §12.1)

- Allow-list: `candor-memlock` (mlock, madvise, prctl, Landlock and seccomp glue, through `rustix` where it offers a safe wrapper), the FIPS FFI shim, and platform keystore bindings (C-15/C-03). Changes to these are T0.
- Each block carries a `// SAFETY:` invariant. Tests run under Miri where Miri supports the operations; otherwise ASan/UBSan fuzzing applies. Each unsafe precondition has a Kani harness.
- `cargo geiger` output is gate evidence. Any increase in T0/T1, dependencies included, needs Security Lead approval.
- Chromium Rule of 2 (R8 §5.2): a component may combine at most two of {untrusted input, memory-unsafe code, high privilege}. `security/rule-of-2.toml` records this per component. C-07 links no C/C++ parser, and CI checks this with `ldd`/`nm` (only libc allowed).

### 4.6 Misuse-resistant APIs (R8 §2.2; SL-R-003, SL-R-011)

| Pattern | Rule | Test |
|---|---|---|
| Typestate | `Envelope<Sealed>` → `Envelope<Opened>`. Only `open()` builds `Opened`, and only `Opened` exposes plaintext | `trybuild` compile-fail |
| Newtype per key role | `IntakeKemPk`, `CaseWrapKey`, `DirectorySigningKey`, … with no `From`/`AsRef<[u8]>` between roles. Labels are an `enum Label` with `const fn bytes()` | Label uniqueness and prefix-freeness test (`tests/label_registry.rs`) |
| `Verified<T>` | Trust decisions (`sign`, `trust`, `seal_to`) accept only `Verified<…>`, which holds the exact key bytes. IDs are never re-resolved after verification (INC-SL-04) | Harness case: same ID, different key → hard failure |
| Keypair-only signing | `SigningKeyPair::sign(&self, msg)`. Never `sign(sk, pk, msg)` | API review; trybuild |
| Validated public keys | `from_bytes` checks length, canonical encoding, low-order/zero shared secret (X25519) and the FIPS 203 modulus check (ML-KEM ek) | Wycheproof low-order and invalid-ek vectors |
| Hidden nonces | No public API takes a nonce. STREAM nonces are counter ‖ last-flag under a per-message key | Property test: 10⁵ seals of the same plaintext give distinct ciphertexts |
| Release after authentication | A chunk is yielded only after its tag verifies. A missing final flag is an error. No partial plaintext reaches any parser | Truncation and reorder corpus |
| Uniform errors | `open()` returns one `DecryptError::Invalid` across the API boundary | Error-class size and timing equality (AT-042 style) |
| Authorization token types | Repositories returning protected rows require `Authorized<T>` (07 §5.6) | trybuild |

### 4.7 Randomness, time and identifiers (27 §12.5)

- Randomness: only `candor_core::rng` (OS `getrandom`). RNG failure is an error, never a fallback (ST-013, INC-50/51).
- Time: only `candor-time`. Source-linked values are `EpochDay`. Intake hosts have no wall clock finer than a day except `Monotonic` (07 §12, ADR-010). Staff timestamps appear only in the tables allow-listed in 09 §8.
- IDs: random 128-bit. UUIDv7, ULID and other time-ordered IDs are banned in source-linked tables (AT-041). No sequential IDs ever leave a process.

### 4.8 Filesystem (ADR-027; SL-R-001)

- Every externally influenced name goes through `candor-safefs`: `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, `O_CREAT|O_EXCL`, content-addressed or random names, fixed mtimes.
- **Validate, then write:** no byte from an untrusted peer reaches a path until its name and size have been validated. Data lands in an anonymous `O_TMPFILE`/`memfd` and is linked in only after validation (INC-SL-01 / INC-101).
- Archives are read only through the safefs allow-list extractor. It rejects absolute paths, `..`, symlinks, hardlinks and device nodes, and members over the limits, **before** any write (INC-SL-03 / INC-102).

### 4.9 Serialization

- External DTOs: `#[serde(deny_unknown_fields)]`, one DTO per role and mutation, no generic "set attribute" (INC-112).
- Internal IPC and signed or hashed objects: deterministic CBOR via a strict decoder (§2 table). Every hashed or signed structure has exactly one canonical encoding, and parse→serialize is the identity (property test).
- No compression of secret-bearing data before encryption unless the output is padded to a fixed size class (SL-R-005, INC-SL-05).

## 5. Secrets handling

| Lifecycle point | Rule | Verify |
|---|---|---|
| Type | Key material, passphrases, seeds and plaintext buffers are wrapped in `secrecy::SecretBox` or `zeroize::Zeroizing`, derive `ZeroizeOnDrop`, and implement **none** of `Clone`, `Copy`, `Debug` (a redacted impl is allowed), `Display`, `Serialize` or `PartialEq`. They are passed by reference | trybuild not-impl assertions; `format!("{:?}")` canary test |
| Allocation | Secret buffers are allocated at final capacity and never grown (a newtype without `push`/`extend`). Streaming decrypt reuses one pre-allocated buffer (SI-A-05.2) | Unit test that capacity is unchanged |
| Process | Every secret-holding process calls `prctl(PR_SET_DUMPABLE, 0)` at start, runs with `LimitCORE=0` and `MADV_DONTDUMP`, and either `mlock`s its secret arena or `mlockall`s (C-07). The host has no swap (intake), or encrypted swap with a random per-boot key | ST-110, ST-027; `gcore` must fail |
| Comparison | `subtle::ConstantTimeEq` for MACs, tokens, CSRF values, verifiers and codename-derived lookups. `==` on secrets is banned through newtypes without `PartialEq` (SI-A-06) | dudect (ST-026) |
| Transport | Secrets never go in env vars, argv, temp files, URLs, logs, errors, metrics or panics. Service secrets come via `LoadCredentialEncrypted=` (TPM-sealed; ADR-028) | ST-121 secret-placement scan; AT-001 canaries |
| Lifetime | Secrets are kept as briefly as possible. C-07 workers respawn after a bounded number of sessions. Zeroization runs on every exit path, error paths included | Crypto checklist item 6; ST-027 memory scan |
| Residual | zeroize cannot clear compiler copies, registers or kernel socket buffers (SI-A-05.4). This is documented in `40-SECURITY-ASSUMPTIONS.md` | INSP |

## 6. Error and log discipline (candor-log only)

1. Output goes only through the typed `candor-log` API (`AuditField`, sealed event catalog; 20 §7). `println!`, `eprintln!`, `log`, `tracing` and free-form strings are banned in all shipped code (27 §12.5; ST-006).
2. Never log, emit or persist, in any sink (logs, errors, panics, metrics, `Debug`, temp files, fixtures, crash paths, HTML comments, headers): source IP, User-Agent, Accept-Language, exact source-event time, filenames, sizes, MIME guesses, codenames/passphrases, request bodies, Tor circuit IDs, or URL paths containing IDs (20 §6.1; BUILD-BRIEF; R9 §6.6).
3. SOURCE-SENSITIVE data is only ever a counter (20 §5.4) and leaves a host only as a global daily band (BE-073).
4. A new event or field requires a schema entry, an anonymity classification and Anonymity Reviewer approval (27 §11.4).
5. CI canary: each test suite injects unique marker strings into every external input, then scans every sink (AT-001 family, `anon-marker-scan`). Any hit blocks the merge (RM-002, SG-10).

## 7. Input bounds

| Input class | Rule | Default limits (canonical source) |
|---|---|---|
| HTTP request (C-06) | hyper `http1` only. Header read 10 s, `max_buf_size` ≤ 64 KiB, body idle 60 s. Reject `Content-Length` together with `Transfer-Encoding`. Reject `TE` other than chunked. No obsolete multiline headers. No HTTP/2 on intake (SI-C-05) | 07 §11; 112 KiB form body; 64 KiB message |
| Form fields | Allow-list per field: byte length **and** grapheme count, UTF-8 validity, NFC, control characters rejected. Inputs are rejected, not sanitised (SI-C-04) | 11 §5.7 |
| Uploads | Streamed multipart with per-part and total caps. Nested multipart rejected. The filename is never used on disk; it is encrypted metadata only. No content sniffing (ADR-012) | `upload_per_file_cap`, files/envelope 20 (max 32) |
| IPC message | Max datagram size, then per-op field limits, then the decode. Unknown op or extra key → `BAD_FRAME` and the connection closes | 07 §5.2 (128 KiB) |
| Crypto objects | Header ≤ `MAX_HEADER`, recipients = 16 slots, chunk = `stream_chunk`, parts ≤ 32 | 04; `candor-limits` |
| Relay batch | Strict validation of the intake-supplied fields (07 §5.4). Anything else is rejected and quarantined after 3 slots | 07 §5.4 |
| Archives | Member count, depth, ratio and total size checked before writing | 10 §10 (`LP-DEFAULT`) |
| Recursion | No recursion on attacker-controlled depth. Iterative parsers with an explicit depth limit | R9 §4 |
| Resource ceilings | Global and per-circuit concurrency, rate and staging limits, each with a byte-identical "busy" page | 07 §11 |

Every input in this table has a fuzz or proptest harness. Boundary values are 0, max, max+1 and 2³² (SI-A-02).

## 8. IPC rules

| # | Rule | Source |
|---|---|---|
| 1 | Only `AF_UNIX` `SOCK_SEQPACKET` (one datagram = one message) in a `RuntimeDirectory` with mode `0750`, owned by the server user, and with the group set to the single permitted client user | 07 §4.1, §5.2 |
| 2 | On accept, check `SO_PEERCRED.uid` against the expected uid, and use `SO_PEERPIDFD` where available (Linux ≥ 6.5). The peer is identified from the transport only, never from a message field | SI-B-05; 27 §12.5 Identity; INC-103 |
| 3 | Versioned frame `{v, op, rid, body}`. The first message is `HELLO`. Version mismatch closes the connection. No negotiation down to an older protocol | 07 §5.2 |
| 4 | A strict canonical CBOR decoder (§4.9). Any parse error, unknown op or extra key → error code and close. No partial processing | 07 §5.2 |
| 5 | Error responses carry a code only (`BAD_FRAME`, `BUSY`, …). No echo | 07 §5.2 |
| 6 | Operations that hold keys **never return keys**. They return plaintext only where the spec defines it (for example `OPEN_REPLIES` for immediate rendering) | SI-B-05 |
| 7 | Per-connection and global concurrency bounds. Session state machines are explicit enums, and each invalid transition has a test | 07 §5.2 state machine |
| 8 | Every IPC decoder has a cargo-fuzz target. Integration tests cover a wrong-uid connect (rejected, ST-097), an oversize datagram and a truncated datagram | ST-097 |

## 9. Process and host confinement (per daemon)

| Layer | Rule | Target / verify |
|---|---|---|
| systemd | SI-B-01 baseline drop-in, as consolidated in 07 §4.2 | `systemd-analyze security --offline=true` exposure ≤ 2.0 (intake units ≤ 1.5). `systemd-analyze verify` in CI |
| seccomp | Per-role allow-list (seccompiler JSON → BPF), installed after init with TSYNC and default `KillProcess` (SI-B-02; 07 §4.3) | Negative test: `execve`, `socket(AF_INET)` and `ptrace` → SIGSYS |
| Landlock | Self-restrict to the state dir (rw) and config/binaries (ro). TCP deny on ABI ≥ 4. Scoping on ABI ≥ 6. Production uses `HardRequirement` ABI 6 (SI-B-03) | Tests: `/etc/shadow` → EACCES; connect to 127.0.0.1:22 → EPERM |
| AppArmor | Enforce-mode profiles for each daemon, tor and PostgreSQL (SI-B-04) | Functional suite runs in enforce mode; 0 `DENIED` |
| Host | `ptrace_scope=3`, `suid_dumpable=0`, `core_pattern=|/bin/false`, coredump `Storage=none`, `kptr_restrict=2`, `dmesg_restrict=1`, `unprivileged_bpf_disabled=1`, private tmpfs `noexec` (SI-B-06) | C-25 self-test; ST-110 |
| FDs | `O_CLOEXEC` everywhere. `close_range` before any exec. Uploads go to `memfd_create(MFD_CLOEXEC\|MFD_NOEXEC_SEAL)` or straight into encryption | `/proc/<pid>/fd` audit test |

## 10. Dependency rules (28; SI-A-09; SL-R-009)

1. A new direct dependency in T0/T1 needs a one-line justification in `SPEC-NOTES.md` §Dependencies (function, alternatives, maintainer health, `unsafe` count, transitive fan-out, licence) and two approvals (SCM-011).
2. Exact pins `"=x.y.z"`, `default-features = false`, a minimal feature set, `[lints] workspace = true`.
3. **Cooldown:** a version is eligible ≥ 14 days after publication, unless it is a security fix with a diff review (SCM-012). Trust in imported cargo-vet audits and trusted publishers expires after 6 months and must be renewed (SL-R-009).
4. cargo-vet: crypto-set crates meet `candor-crypto-reviewed` (SCM-010). Exemptions carry an expiry. Candor's own audits default to `safe-to-run`, and `safe-to-deploy` is used only with real expertise.
5. cargo-deny: no git sources, no yanked crates, no duplicate crypto crates (time-boxed exceptions only, for example ADR-051(1)), no `openssl` outside the FIPS feature, `unmaintained = all` (crypto: deny), and licences per ADR-031.
6. Advisory floors: `sqlx ≥ 0.8.1`, `h2 ≥ 0.4.16`, `rustls ≥ 0.23.45`. Daily `cargo audit` (SI-A-09). SBOM advisory matching within 24 h (SCM-044).
7. No build script that fetches anything or runs network tools. `links`/`build.rs` in new dependencies are flagged for review.
8. Banned in shipped code: `reqwest` and other HTTP clients except the `candor-http` wrapper (redirects off, proxy-from-env off, cookie store off; INC-104), any telemetry or crash-report SDK (ST-014), table-based software AES/GHASH backends (SL-R-012), and abandoned crypto libraries.
9. `cargo geiger` and `cargo tree -d` diffs are attached to every lockfile PR.

## 11. Test pyramid

| Level | Tool (pinned) | Scope | When | Pass criterion |
|---|---|---|---|---|
| Unit + negative | `cargo test` | Every module. Positive, negative and hostile paths (27 §11.2) | PR | 100 % pass |
| Compile-fail | `trybuild` | Typestates, `Verified<T>`, not-impl on secret types, `Authorized<T>` | PR | Expected errors match |
| Property | `proptest =1.11.0` | Round-trips, parsers, padding, authz ("deny unless explicit grant"; COI always wins). Collections with **N ≥ 2 heterogeneous** elements where only element k fails (INC-SL-08) | PR | No failure; regressions committed |
| KAT / conformance | in-repo vectors (hash-pinned), Wycheproof (pinned commit), C2SP CCTV | Every primitive and Candor format (ST-020..025, SL-R-015) | PR touching T0; release | 100 % |
| Differential | second implementation (e.g. RustCrypto `hpke` vs `aws-lc-rs`; portable vs SIMD backend) | ST-029. 10⁶ random inputs per release | Nightly; release | Equal outputs |
| Multi-arch | native x86_64-v1, x86_64-v3, aarch64 (±SHA3 ext), forced-portable | Crypto suites (SL-R-004, INC-SL-07) | PR touching T0 or crypto deps | All green |
| Fuzz | `cargo-fuzz =0.13.2` (libFuzzer); `bolero` optional | Every parser and decoder (ST-040..054) | PR: ≥ 60 s per target (regression corpus). Nightly: ≥ 1 h per target. Release: 24 CPU-h (patch) / 72 CPU-h (minor/major), SG-07 | 0 crashes, panics, OOM > 2 GiB or > 10 s inputs. Coverage drop ≤ 2 pp |
| Miri | `nightly-2026-09-28` | Allow-listed `unsafe` crates; pure-logic tests of T0 crates | PR touching those crates | 0 UB |
| Kani | `kani-verifier =0.68.0` | Framing, padding, chunk arithmetic, `unsafe` preconditions | PR touching T0 | All harnesses verified |
| Constant time | `dudect-bencher =0.7.0` or Welch t-test harness on a pinned bare-metal runner | Token compare, codename/locator verify, KEM decapsulation success vs failure, AEAD tag failure, per backend (ST-026, SL-R-012) | Nightly; release | \|t\| < 4.5 |
| Mutation | `cargo-mutants` (pin on adoption) | `check_*`, `verify_*` and authz functions in T0/T1 (ST-015, SL-R-006) | PR touching them | 0 surviving mutants in changed functions |
| Integration | candor-lab over unix sockets and localhost only. PostgreSQL tests gated by `CANDOR_TEST_PG` (skip with a message when unset) | Cross-process flows, IPC, DB, RLS | PR | 100 % |
| Malicious-server harness | ST-090..097 (ADR-027) | Every client (C-15, C-03, C-17 bridge, relay → intake) | PR touching clients | 100 % |
| Anonymity | AT-001 canary scan; AT-040..058 timing, size and fingerprint; drills AT-020..032 | Every flow that touches source data | PR (canary), nightly (timing), release | 0 hits; answers ⊆ oracle |
| Formal | Tamarin / ProVerif models in `protocol/` (ST-030) | Wire-protocol changes | PR touching `protocol/` or `candor-core/src/proto*` | No lemma changes status |

Canonical commands, all run with `--locked`:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo +nightly-2026-09-28 fuzz run <target> -- -max_total_time=60 -rss_limit_mb=2048 -timeout=10
cargo +nightly-2026-09-28 miri test -p <crate>
cargo kani -p <crate>
cargo mutants -p <crate> --in-diff <(git diff origin/main)
cargo deny --locked check && cargo vet --locked && cargo audit
cargo geiger -p <crate> --output-format Json > evidence/geiger-<crate>.json
semgrep --config security/semgrep/ --error --metrics=off
make docs-lint   # traceability + SG-25 constants lint
```

Test rules: no network except localhost and unix sockets, no DNS, no real data, no fixtures containing anything that looks like a real IP, UA or name (use canaries). Tests map to IDs in a comment: `// ST-043, IMP-RM2-012`.

## 12. Review roles

| Change | Approvals (excl. author) | Required roles | Notes |
|---|---|---|---|
| T0 | 2 | ≥ 1 Crypto Reviewer; ≥ 1 from another team or organisation | Crypto checklist 27 §11.3 signed. Diff ≤ 400 lines. AI-assisted T0: the reviewer re-derives the argument independently |
| T1 | 2 | ≥ 1 Trust-Path Maintainer (CODEOWNER) | Anonymity Reviewer when 27 §11.4 triggers |
| `unsafe` allow-listed crate | 2 | as T0 | Miri/Kani evidence attached |
| Dependency / lockfile | 2 (T0/T1) | Reviewer checks the cargo-vet record | Cooldown evidence |
| CI / workflows / build | 2 | Release/Supply-chain owner | zizmor clean |
| Classification, CODEOWNERS, branch protection | 2 | Security Lead | No admin override |
| Independent audit (stage 6) | — | Auditor ≠ builder ≠ approving reviewer for the same change | BUILD-BRIEF audit gate |

Separation of duties: nobody approves their own change, audits their own code, or signs off a gate on a release that contains their own T0 change (27 §3.1). Release signing requires signer ≠ author ≠ builder-B operator (SL-R-010).

## 13. Independent audit gate (per build step)

1. **Inputs:** the step doc (§3 build sequence, §4 checklist), the diff, SPEC-NOTES (§Design, §Security self-review), test results and fuzz stats.
2. **Procedure** (R9 §8): threat model first → manual line review of T0/T1 → targeted greps for metadata and crypto misuse (clippy cannot see them) → tools (clippy restriction set, Semgrep, cargo-deny/vet/audit/geiger, Miri, fuzz smoke, `systemd-analyze security`, zizmor, shellcheck).
3. **Severity** (R9 §8.2–3): any deanonymisation or plaintext exposure reachable by a 02 adversary is **Critical**. A remotely triggerable panic, abort or unbounded allocation in an onion- or network-facing process is **High**. Crypto misuse with no demonstrated exploit is at least **High** in T0.
4. **Output:** `process/audits/AUDIT-<step>.md`: scope (commit range), method, findings table (`ID | Severity | CWE | Location | Description | Fix | Regression test | Status`), variant-scan notes, tool outputs, verdict.
5. **Closure:** 0 open Critical/High. Each Medium is fixed or has the lead's written acceptance with an expiry. Each fix has a red→green regression test (SL-R-014; ST-012) plus a variant scan. The auditor re-tests and signs the closure.
6. **Pre-external-audit:** an LLM-assisted adversarial sweep (ST-142, SL-R-013) runs before A1–A4, with its findings closed first.

## 14. Evidence each step must leave

### 14.1 Evidence inventory

| Evidence | Location | Required content |
|---|---|---|
| README | `crates/<c>/README.md` | Purpose, public API, guarantees and non-guarantees, how to test |
| SPEC-NOTES | `crates/<c>/SPEC-NOTES.md` | Sections: **Design**; **Implementation decisions** (safest reading, never a silent weakening); **Spec feedback**; **Dependencies** (one line each); **Test map** (ID → test); **Required privileges** (user, paths, sockets, syscalls); **Security self-review** (§14.2); **Residual risks**; **Open items** |
| Threat-model delta | `threat-model/features/<id>.md` | 27 §10.2 |
| Test results | `evidence/<step>/test-report.txt` | Exact commands, toolchain, commit, pass/fail counts. Fuzz CPU-hours and coverage. Miri/Kani/dudect outputs |
| Audit report | `process/audits/AUDIT-<step>.md` | §13 |
| Gate evidence | `evidence/<step>/gates.json` | SG results relevant to the step; signed milestone report (RM-005) |
| Traceability | step doc §8 tables + test comments | Every IMP- requirement maps to ≥ 1 test or inspection |

### 14.2 Security self-review template (SPEC-NOTES)

```
## Security self-review (<commit>, <date>)
- Metadata: sinks checked (logs/errors/panics/metrics/Debug/temp/fixtures/crash) → result
- Network: runtime connections = <list>; none outside spec → result
- Fail-closed: error paths enumerated → each refuses / degrades how
- Input bounds: inputs → limit constant → test ID
- Secrets: types, zeroize, no Clone/Debug, CT compares, lifetime
- Privileges: OS user, files, sockets, syscalls (matches unit file?)
- Side channels: timing/size/existence oracles considered → mitigation/test
- Dependencies: added/changed, cooldown, vet criteria
- Step §4 checklist: item → answer
- Residual risks: honest list
```

## 15. Definition of done (every T0/T1 change)

- [ ] Threat-model delta approved, or N/A justified and acknowledged (27 §10)
- [ ] Design note present. Interfaces are traits/types owned by the right crate (BUILD-BRIEF RM-2 addendum)
- [ ] fmt and the clippy deny set are clean. Semgrep and the ST-004..008/013 lints are clean
- [ ] Every external input bounded by a named constant, strictly parsed, and fuzz- or proptest-covered. No panic, unbounded allocation or recursion on attacker data
- [ ] No unvalidated write, exec or OS handoff on untrusted names (SL-R-001/008). safefs only
- [ ] Trust decisions use `Verified<T>`. New keys and labels are in the registry and the uniqueness test passes (SL-R-003/011)
- [ ] Secrets: zeroizing types, no Clone/Debug/Display/Serialize/PartialEq, CT compares, no env/argv/tmp
- [ ] candor-log only. No prohibited field. Canary scan green (SG-10)
- [ ] No exact source-linked timestamp. Random 128-bit IDs. Padding and size classes are as specified
- [ ] Fail-closed on every privacy-relevant error. No clearnet fallback, no unsealed storage, no partial plaintext
- [ ] No compression on secret-bearing paths, or padded (SL-R-005)
- [ ] Mutation: 0 surviving mutants in changed `check_*`/`verify_*`/authz functions (SL-R-006)
- [ ] Multi-arch crypto CI green if T0 or crypto deps changed (SL-R-004)
- [ ] Dependencies justified, pinned, cooled, vetted. deny/vet/audit green. geiger diff reviewed
- [ ] Bug fix: regression test red before the fix, green after (SL-R-014)
- [ ] SPEC-NOTES sections complete, including Security self-review
- [ ] Independent audit report shows 0 open Critical/High; Mediums dispositioned
- [ ] Required approvals per §12 on the final commit; `AI-Assisted` field set
- [ ] `cargo fmt`, `clippy -D warnings`, `cargo test` and `make docs-lint` pass. Exact commands and results recorded

## 16. Traceability of implementation requirements (prefix `IMP-`)

- **IDs:** `IMP-STD-NNN` (this standard) and `IMP-RMn-NNN` (step doc for milestone RM-n). Once published, IDs are never reused or renumbered. A withdrawn requirement keeps its row, marked WITHDRAWN.
- **Format:** the repository's 6 columns `| ID | Requirement | Evidence | Threats | Component | Verification |`. Evidence cites `B-SI-`, `B-SL-`, `B-AU-`, `INC-`/`INC-SL-` and `ADR-` IDs. Threats cite `THR-` (02). Components cite `C-nn` (DECISIONS §4). Verification uses `TST:`/`INSP:`/`AUD:` followed by the ST-/AT- ID or the CI job name.
- **Links:** each IMP- requirement restates no spec value. It cites the owning requirement (for example `BE-`, `API-`, `SUI-`) in the requirement text where one exists. Tests reference IMP- IDs in comments, and `tools/traceability.py` is extended to scan `specs/impl/*.md` (open issue OI-IMPL-1).
- **Prefix registration:** `IMP-` must be added to DECISIONS §3 (owner: this directory). Until then, `tools/traceability.py` (non-recursive `specs/*.md` glob) does not parse these tables.

## 17. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| IMP-STD-001 | Every T0/T1 change SHALL pass the eight workflow stages of §3 in order. Implementation PRs SHALL NOT merge before their threat-model delta is approved. | B-SL-01; B-SL-02; ADR-016 | THR-012; THR-016; THR-024 | C-30 | TST: `tm-link` (ST-004); INSP: PR sample |
| IMP-STD-002 | T0/T1 crates SHALL compile with the §4.2 lint set at deny, with `unsafe_code = forbid` outside `security/unsafe-allowlist.toml`. | B-SI-01; B-SI-03; B-AU-04 | THR-012; THR-032 | C-31 | TST: clippy CI job; ST-007 |
| IMP-STD-003 | Release profiles SHALL set `overflow-checks = true`, `panic = "abort"`, `codegen-units = 1`, `lto = "fat"`, `strip = "symbols"`, and builds SHALL use `--locked` with flags only from the checked-in `.cargo/config.toml`. | B-SI-01; ADR-022; ADR-051 | THR-024; THR-014 | C-31 | TST: profile-key grep job; ST-131 |
| IMP-STD-004 | Every wire or user length SHALL be checked against a named `candor-limits` constant before allocation, with checked arithmetic and `try_from` conversions. | B-SI-17; B-AU-04 | THR-032; THR-012 | C-11; C-06; C-07 | TST: fuzz ST-040..054; Kani harnesses |
| IMP-STD-005 | Error values SHALL carry codes only. User-facing errors SHALL be fixed templates within their size class. The panic hook SHALL emit only a static string and a correlation ID. | B-SI-25; INC-60 | THR-016; THR-011 | C-06; C-10 | TST: AT-017; AT-018; error-template hash test |
| IMP-STD-006 | Secret-bearing types SHALL be zeroizing, non-Clone, non-Debug (redacted), non-Display, non-Serialize and non-PartialEq, and SHALL be compared only with `subtle`. | B-SI-04; B-SI-05; B-SI-06 | THR-013; THR-014 | C-11; C-07; C-15 | TST: trybuild not-impl; ST-026; ST-027 |
| IMP-STD-007 | Secret-holding processes SHALL set `PR_SET_DUMPABLE=0`, `LimitCORE=0` and `MADV_DONTDUMP`, and lock their secret memory. | B-SI-04; B-SI-22; INC-58 | THR-014; THR-016 | C-07; C-21; C-24; C-15 | TST: ST-110; `gcore` negative test |
| IMP-STD-008 | Output SHALL go only through `candor-log` typed events, and no sink SHALL contain any §6 item 2 datum. | INC-60; ADR-016; B-SI-25 | THR-016; THR-001; THR-011 | C-06; C-07; C-08; C-24 | TST: ST-006; AT-001..019 |
| IMP-STD-009 | Local IPC SHALL follow §8 (SEQPACKET, transport-derived peer identity, versioned strict canonical CBOR, code-only errors, no key-returning ops). | B-SI-23; B-SI-24; INC-103 | THR-014; THR-018 | C-06; C-07; C-08 | TST: ST-097; IPC fuzz targets |
| IMP-STD-010 | Every externally influenced filesystem name SHALL go through `candor-safefs`, validated before any byte is written. | INC-101; INC-102; INC-108; ADR-027 | THR-023; THR-037 | C-08; C-13; C-15; C-17 | TST: ST-005; ST-080; ST-086; ST-090 |
| IMP-STD-011 | Trust decisions SHALL accept only `Verified<T>` values carrying exact key bytes, and key roles SHALL be distinct newtypes with registry-unique labels. | B-SL-29; B-SL-30; INC-62; INC-63 | THR-046; THR-012 | C-11; C-14; C-15 | TST: trybuild; label-registry test; ST-093 |
| IMP-STD-012 | No secret-bearing data SHALL be compressed before encryption unless it is padded to a fixed size class. | B-SL-30; INC-63 | THR-012; THR-013 | C-11; C-27 | TST: Semgrep rule; size-independence test |
| IMP-STD-013 | Daemons SHALL ship systemd units meeting §9 exposure targets and SHALL self-apply seccomp and Landlock after init. | B-SI-18; B-SI-19; B-SI-20; B-SI-21 | THR-014; THR-030 | C-05..C-10; C-21..C-24 | TST: `systemd-analyze security` CI; SIGSYS/EACCES negative tests |
| IMP-STD-014 | Dependencies SHALL follow §10 (justified, exact-pinned, 14-day cooldown, vetted with 6-month import expiry, advisory floors, no fetching build scripts). | B-SI-13; B-SI-14; B-SL-04; INC-37; INC-40 | THR-024 | C-30; C-31 | TST: cargo deny/vet/audit; cooldown checker |
| IMP-STD-015 | Each step SHALL implement the §11 test levels relevant to its components, with the stated pass criteria and fuzz durations. | B-SI-09; B-SI-11; B-SI-12; B-SL-23 | THR-012; THR-032 | C-31 | TST: CI required statuses; SG-06; SG-07 |
| IMP-STD-016 | Crypto suites SHALL pass KAT, Wycheproof and differential tests natively on every shipped architecture and on forced-portable backends. | B-SL-14; INC-SL-07 | THR-012 | C-11 | TST: multi-arch matrix; ST-029 |
| IMP-STD-017 | Check and verify loops over collections SHALL have N ≥ 2 heterogeneous property tests and 0 surviving mutants in changed functions. | B-SL-16 | THR-021; THR-046 | C-11; C-22 | TST: ST-015 `cargo mutants` |
| IMP-STD-018 | Review SHALL follow §12. The independent auditor SHALL NOT be the builder or an approving reviewer of the same change. | B-SL-02; B-SL-45; INC-37 | THR-024 | C-30 | TST: SG-02 forge-API audit; INSP: audit report authorship |
| IMP-STD-019 | No build step SHALL integrate with an open Critical or High audit finding. Each fix SHALL carry a red→green regression test and a variant scan. | B-SL-09; INC-109 | THR-024; THR-012 | C-30 | AUD: `process/audits/AUDIT-<step>.md`; TST: ST-012 |
| IMP-STD-020 | Each crate SHALL maintain the §14.1 README and SPEC-NOTES sections, including a dated Security self-review. | B-SL-02 | THR-024 | C-30 | INSP: doc-section lint in CI |
| IMP-STD-021 | Tests SHALL use no network beyond localhost and unix sockets, and no real personal data. PostgreSQL tests SHALL skip cleanly without `CANDOR_TEST_PG`. | ADR-023; INC-53 | THR-036; THR-016 | C-31 | TST: CI egress allow-list (SCM-027); fixture canary scan |
| IMP-STD-022 | Shipped code SHALL NOT make runtime network calls other than those its spec defines, and SHALL NOT include telemetry or crash-report SDKs. | INC-53; INC-46; ADR-023 | THR-036; THR-001 | C-03; C-06; C-15 | TST: ST-014; AT-052; AT-063 |
| IMP-STD-023 | Random values SHALL come only from `candor_core::rng`, time only from `candor-time` (EpochDay on source-linked data), and stored object IDs SHALL be random 128-bit. | INC-50; INC-51; ADR-010 | THR-011; THR-012 | C-06..C-13 | TST: ST-013; AT-040; AT-041 |
| IMP-STD-024 | A component SHALL NOT combine untrusted input, memory-unsafe code and high privilege. `security/rule-of-2.toml` SHALL record each component and be checked by linking analysis. | B-SL-45 | THR-023; THR-014 | C-07; C-15; C-17 | TST: `ldd`/`nm` check for C-07; INSP |

## 18. Residual risks and limitations

- zeroize, `subtle` and mlock are best-effort. Compiler copies, register state and kernel buffers are outside their control (SI-A-05.4, SI-A-06). The real mitigation is short process lifetime.
- Lints and Semgrep find known patterns only. Logic and metadata bugs need the human audit gate, which is only as good as the auditor's time and the checklist.
- Fuzzing and property tests show that bugs were not found in the explored space, not that none exist. dudect results depend on the runner hardware.
- The independent auditor is currently a helper role inside the same project. True independence comes only with the external audits A1–A4 at RM-6.
- Several R7 facts are marked UNVERIFIED in the research (for example the Landlock ABI ↔ kernel mapping and full-vanguards maintenance). Steps that rely on them must re-verify them first.

## 19. Open issues

| ID | Issue |
|---|---|
| OI-IMPL-1 | Register the `IMP-` prefix in DECISIONS §3 and extend `tools/traceability.py` to scan `specs/impl/*.md`. |
| OI-IMPL-2 | Create `process/AUDIT-CHECKLIST.md` from R9 (referenced by BUILD-BRIEF but not yet present) and the `process/audits/` directory. |
| OI-IMPL-3 | Create the `security/` scaffolding (classification, unsafe allow-list, rule-of-2, proof-tcb, asvs-map, semgrep rules), which 27 references but which does not exist in the repository yet. |
| OI-IMPL-4 | Adopt the R7/R8 rules formally into 27/28/29 (R8 §6 gap list: SL-R-001 ordering, proof-TCB checklist item, mutation testing in SG-06/08, signer ≠ author ≠ builder-B in 33, Desk opener ban). |
