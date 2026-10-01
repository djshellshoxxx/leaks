# R9 — Secure-Code Audit: What to Look For, and With What Tools

*Research note for the Candor implementation audit programme. As of 2026-10-01.*
*Consumer: `process/AUDIT-CHECKLIST.md` (the reusable per-step audit procedure). Related specs: 27 §11–§12 (review rules, coding standards), 29 (security testing), 37 (audit plan), BUILD-BRIEF "Security and OPSEC bar".*

**Method and caveats.** I used web search plus primary sources I could read directly. I made a shallow clone of the RustSec advisory database (`RustSec/advisory-db`, HEAD commit dated 2026-09-30) and tallied categories and keywords myself. I also cloned the ANSSI Rust guide (`ANSSI-FR/rust-guide`, HEAD 2026-05-18) and read the advisory files listed below. I installed and ran the tools in §7 in this container. The egress proxy blocked cwe.mitre.org, arxiv.org, securityweek.com, infosecurity-magazine.com and docs.zizmor.sh. For the CWE Top 25 ranks I relied on search-engine extracts of the MITRE page. The ranks of items 1, 4, 5 and 21–25 come from those extracts; the others are from memory of the published list and are marked **UNVERIFIED-RANK**. Citations use the form [B-AU-xx].

---

## 1. Executive summary

1. **For this codebase the dominant risks are logic, metadata and resource bugs, not memory corruption.** The workspace has `unsafe_code = "forbid"`, so memory-safety bugs come in through dependencies (RustSec "memory-corruption" is still the largest category, 284 of 1,257 advisories [B-AU-02]). Candor's own code is more likely to fail through: (a) panics or unbounded allocation on hostile input (DoS; with `panic = "abort"` one panic kills the process), (b) secret or metadata leaks through `Debug`, errors, logs, timing and sizes, (c) authorization and role confusion (CWE-862/863/639 are all in the 2025 Top 25 [B-AU-01]), (d) crypto API misuse (nonce, domain separation, unauthenticated release), and (e) filesystem TOCTOU/symlink issues.
2. **`overflow-checks = true` + `panic = "abort"` turns every unchecked arithmetic on attacker data into a remote kill switch.** This is a deliberate fail-closed choice, but it means `arithmetic_side_effects` and `as`-cast findings on input paths are DoS findings, not style findings. Precedent: RUSTSEC-2025-0009 (ring AES panics when overflow checking is enabled) [B-AU-11].
3. **Truncating `as` casts on lengths are a protocol-smuggling class**, not only a correctness one. Precedent: RUSTSEC-2024-0363, where sqlx's truncating/overflowing casts allowed SQL protocol-level query smuggling [B-AU-04].
4. **Crypto-failure advisories in Rust are mostly misuse and side channels in otherwise memory-safe code.** Examples: a non-constant-time tag check (libcrux-aesgcm), unauthenticated nonce increment (snow), a counter overflow repeating keystream (chacha20), a low-level GCM that ignores the operation nonce (dcrypt), timing in curve25519-dalek `Scalar::sub` (RUSTSEC-2024-0344), and the Ed25519 "double public key" signing oracle (RUSTSEC-2022-0093, a key/role-confusion API) [B-AU-05, B-AU-06, B-AU-12].
5. **Archive and path handling is still a live bug class in 2025–2026.** Examples: `zip` path canonicalization leading to arbitrary write (RUSTSEC-2025-0168), `tar` `unpack_in` chmod through symlinks, and a tar PAX-size parser differential (RUSTSEC-2026-0067/0068). In std itself, `remove_dir_all` had a TOCTOU (CVE-2022-21658) [B-AU-03, B-AU-07, B-AU-08]. This validates ADR-027 / `candor-safefs`, and the audit must check that nothing bypasses it.
6. **The HTTP layer's DoS and smuggling history is in hyper/h2.** Examples: Transfer-Encoding smuggling (RUSTSEC-2021-0020), HTTP/2 rapid reset (CVE-2023-44487), and h2 unbounded empty DATA frames (RUSTSEC-2026-0258, 2026-08-17) [B-AU-09, B-AU-10]. Candor must set explicit header/body/time limits and not rely on defaults.
7. **Tooling that runs here today** (verified 2026-10-01): clippy 0.1.94 (incl. restriction lints), cargo-deny 0.20.2, cargo-vet 0.10.2, zizmor 1.26.1 (incl. `--persona=auditor`), Miri (nightly-2026-09-28, `miri 0.1.0 d080e7dff1`), shellcheck 0.9.0, systemd-analyze 255 (`security --offline=true`), lynis 3.0.9 (apt), and also cargo-audit, cargo-geiger, cargo-careful, cargo-fuzz and semgrep if the §7 table marks them verified. See the §7 table for pins and status.

---

## 2. Weakness taxonomy: CWE Top 25 (2025) mapped to Candor

The MITRE/CISA 2025 list [B-AU-01] is dominated by web, authorization and memory classes. Each entry below has a Candor-relevance verdict.

| Rank | CWE | Name | Candor relevance |
|---|---|---|---|
| 1 | 79 | XSS | High: source UI (askama), recipient Desk webview. Check for raw/`safe` filters and inline script (27 §12.5). |
| 2* | 89 | SQL injection | Medium: `sqlx::query!` only; check for `format!` into SQL and dynamic `ORDER BY`. |
| 3* | 352 | CSRF | High: the source UI uses cookies over an onion; check SameSite, token binding, POST-only state changes. |
| 4 | 862 | Missing authorization | High: every route has `authz=`/`audience=` (ADR-029); check the registry and its default-deny. |
| 5 | 787 | OOB write | Low in safe Rust; dependencies and `unsafe` allowlist only. |
| 6* | 22 | Path traversal | High: anything bypassing `candor-safefs`. |
| 7*/8* | 416/125 | UAF / OOB read | Dependencies; Miri on allowlisted `unsafe`. |
| 9*/23 | 78/77 | OS command injection | Low: check `std::process::Command` with external args (sanitiser workers). |
| 10* | 94 | Code injection | Low: templates, build scripts. |
| 12* | 434 | Unrestricted upload | High: the upload pipeline (10): size, type, count, storage location, never served back. |
| 15* | 502 | Deserialization of untrusted data | High: serde DTOs, `deny_unknown_fields`, depth/size limits, untrusted key material parsing. |
| 17* | 863 | Incorrect authorization | High: tenant/role checks, RLS (`SET LOCAL app.tenant_id`). |
| 18* | 20 | Improper input validation | High: strict parsing, trailing bytes. |
| 19*/20* | 284/200 | Access control / exposure of sensitive info | Critical for anonymity: CWE-200 covers metadata leaks. |
| 21 | 306 | Missing auth for critical function | High: admin/IPC sockets. |
| 22 | 918 | SSRF | Low: no outbound HTTP except Tor/defined (BUILD-BRIEF "no network surprises"). |
| 24 | 639 | Authz bypass via user-controlled key | High: case/submission IDs in URLs; IDOR. |
| 25 | 770 | Allocation without limits | High: all parsers, uploads, channels. |

\* rank UNVERIFIED-RANK (the CWE ID is on the 2025 list; the exact position comes from memory, because the primary page was blocked).

**Off-list CWEs that matter more for Candor than their global rank suggests:** CWE-190/191 (integer overflow/underflow), CWE-681/197 (numeric conversion/truncation), CWE-129 (unchecked index), CWE-367 (TOCTOU), CWE-59/61 (link following), CWE-208 (observable timing discrepancy), CWE-203/204 (observable discrepancy / response discrepancy, i.e. account-existence oracles), CWE-209 (error messages with sensitive info), CWE-532 (sensitive info in logs), CWE-226/244 (sensitive info not cleared before reuse/release, i.e. zeroization), CWE-323 (nonce reuse), CWE-330/338 (weak randomness), CWE-347 (improper signature verification), CWE-354 (improper integrity check), CWE-400/674 (resource exhaustion / uncontrolled recursion), CWE-1333 (ReDoS), CWE-444 (request smuggling), CWE-113 (header injection), CWE-614/1004 (cookie flags), CWE-525 (cacheable sensitive responses), CWE-288/290 (auth bypass via alternate path / spoofing, e.g. IPC identity from message fields), and CWE-1395 (vulnerable third-party component).

---

## 3. What actually goes wrong in Rust: RustSec evidence

Own tally of `RustSec/advisory-db` @ 2026-09-30 (1,257 advisory files, 945 crates) [B-AU-02]:

| Category | Count | Notes for Candor |
|---|---|---|
| memory-corruption | 284 | Almost all in `unsafe`/FFI crates. Candor forbids `unsafe` (allowlist only), so the exposure is via dependencies. Hence cargo-deny/vet/audit plus geiger. |
| denial-of-service | 129 | Top keywords: **panic** (20), http/http2/h2, parsing, **stack-overflow** (5), **oom** (5), x509, untrusted-input. Matches §1 item 2. |
| memory-exposure | 90 | Use-after-free, OOB read, uninitialized memory. |
| crypto-failure | 85 | mitm, signature-verification, side-channel, bypass, and nonce issues (examples in §1 item 4). |
| malicious | 75 | Typosquats and malicious crates. Hence cargo-vet and exact pins. |
| thread-safety | 64 | `Send`/`Sync` impls that are wrong. Check any manual `unsafe impl` (none allowed outside the allowlist). |
| code-execution / privilege-escalation / file-disclosure / format-injection | 40 / 19 / 19 / 21 | File-disclosure keywords: directory traversal, tar, symlink, chmod. Format-injection keywords: xss, html, **request smuggling**, **parser-differential**, sql, truncation. |
| informational | unmaintained 275, unsound 212, notice 6 | `deny.toml` already sets `unmaintained = "all"`, `unsound = "all"`. |

Std-library advisories in the same DB include `remove_dir_all` TOCTOU (CVE-2022-21658), several panic-safety bugs (`BinaryHeap`, `String::retain`, `Vec::from_iter` double free when drop panics), and `std::net` octal-literal IP parsing (CVE-2021-29922) [B-AU-03]. Lesson: even std path and FS helpers are not race-free. Use `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` via `candor-safefs`.

The academic baseline is Xu et al., "Memory-Safety Challenge Considered Solved? An In-Depth Study with All Rust CVEs" [B-AU-14]. Its main patterns are panic-safety bugs (unsafe code observing a half-updated state after unwinding), lifetime/aliasing violations in unsafe APIs, uninitialized memory exposure, and incorrect `Send`/`Sync` bounds. The fetch was blocked; this summary comes from the abstract via search and my prior knowledge.

---

## 4. Rust-specific pitfalls (audit-relevant)

Sources: ANSSI Rust guide rule IDs [B-AU-13], Clippy lint catalogue [B-AU-27], zeroize docs [B-AU-16], tokio docs and Arti issue #479 [B-AU-15], Rust Reference on casts [B-AU-35].

| Pitfall | Why it matters here | ANSSI / lint |
|---|---|---|
| **Panics as DoS**: `unwrap/expect/panic!/unreachable!/todo!`, slice indexing `a[i]`, `a[x..y]`, `&s[..n]` on `str` (UTF-8 boundary), integer overflow with checks on, division by zero, `RefCell` borrow panics, `.split_at()`, `Vec::with_capacity(huge)` abort, `Duration`/`Instant` arithmetic panics | `panic = "abort"`: one request kills the process for everyone. In the sealer, that is a correct fail-closed outcome, but an attacker can still trigger it at will. | LANG-LIMIT-PANIC, LANG-ARRINDEXING; clippy `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `string_slice`, `arithmetic_side_effects`, `unreachable`, `integer_division`, `get_unwrap` |
| **`as` casts** silently truncate (int→smaller int), wrap sign, or saturate (float→int) | Length-prefix truncation leads to parser differentials and smuggling [B-AU-04]. | clippy `as_conversions`, `cast_possible_truncation`, `cast_sign_loss`, `cast_possible_wrap`, `cast_lossless` |
| **Allocation from untrusted lengths** (`vec![0; n]`, `with_capacity(n)`, `read_to_end` without `take`) | CWE-770; OOM abort. | 27 §12.2 `candor-limits` |
| **Recursion on attacker data** (serde nested structures, recursive descent, `Drop` of deep linked structures) | Stack overflow is an abort, not a catchable panic. | serde_json `recursion_limit` stays on (never `unbounded_depth`) |
| **Zeroization gaps**: moves/copies leave stale copies (`let k2 = k;` is a memcpy), `Vec` reallocation leaves old buffers, `mem::forget`/`ManuallyDrop`/`Box::leak`/`Rc` cycles skip `Drop`, `panic = "abort"` skips all `Drop`, `String` from `format!` of a secret, `Clone` | Stale plaintext or key bytes in the heap, core dumps (disabled), swap. | LANG-DROP-SEC, MEM-FORGET, MEM-LEAK; clippy `mem_forget` |
| **`#[derive(Debug)]` / `Display` / `Serialize` on secret-bearing or metadata-bearing types**, and `{:?}` in error `From` impls | Secrets or filenames in logs and panic messages. | 27 §12.3; grep |
| **Non-constant-time `==`** on MACs, tokens, hashes, seeds; secret-dependent early return; `HashMap` lookups keyed by secrets | CWE-208. | 27 §12.4, `subtle` |
| **`PartialEq`/`Ord` derive** on types with secret or identity semantics | Accidental variable-time compares. | LANG-CMP-DERIVE |
| **Async cancellation**: a future dropped at `.await` inside `tokio::select!`/timeout leaves state torn (half-written file, half-sent frame, lock-queue loss) | Partial writes produce unsealed or partial records. Contrary to fail-closed. | Arti #479 [B-AU-15] |
| **Blocking in async** (`std::fs`, Argon2, sealing crypto, `std::sync::Mutex` held across `.await`) | Executor starvation. Timing becomes correlated across users. DoS. | clippy `await_holding_lock` |
| **Unbounded channels/queues** (`mpsc::unbounded_channel`, `Vec` buffers fed by the network) | CWE-770. | grep |
| **`std::fs` with dynamic paths**, `Path::join` on input (an absolute input replaces the base), `canonicalize` then open (TOCTOU), `create_dir_all`, `set_permissions` after create, `std::env::temp_dir` | CWE-22/59/367/377. | 27 §12.5 (ST-005); semgrep `rust.lang.security.temp-dir` [B-AU-19] |
| **`unsafe` soundness** (allowlist crates only): missing `// SAFETY:`, `unsafe impl Send/Sync`, `set_len`, `from_raw_parts`, `transmute`, `MaybeUninit::assume_init` | Classic memory corruption. | `undocumented_unsafe_blocks`, Miri, cargo-careful |
| **Env/args/time leakage**: `std::env::var` for secrets, `SystemTime::now()` in source paths, UUIDv7/ULID | ADR-010; 27 §12.5. | grep |
| **Panic payloads and backtraces**: `RUST_BACKTRACE=1` in services; panic messages include `Debug` of values | Leaks to the journal. | grep, unit files |

---

## 5. Crypto-misuse patterns

These are drawn from RustSec crypto-failure advisories [B-AU-05, B-AU-06, B-AU-12], R5 (spec 04 basis), and standard misuse literature.

- **Nonce reuse or nonce control.** Check that nonces come from the RNG or a monotonic counter that cannot wrap (chacha20 counter-overflow advisory), and that an API cannot accept a caller nonce for a different key. For STREAM/chunked AEAD, check the chunk counter and the last-chunk flag (truncation and reorder).
- **Unauthenticated plaintext release.** Streaming decryption must not emit plaintext before the chunk tag (and, for whole-file semantics, the final chunk) is verified. Errors after partial release must purge what was released (BUILD-BRIEF "no partial plaintext release").
- **Non-constant-time comparison** of tags, verifiers and tokens (libcrux-aesgcm advisory); `==` on `[u8; 32]` is not constant-time.
- **Key/role confusion.** The same key is used for two purposes (signing vs KEM, epoch vs case key); signing APIs take a separately supplied public key (ed25519-dalek double-pubkey oracle). HPKE `info`/`aad` must bind role, tenant, recipient and version.
- **Missing domain separation.** Every HKDF `info`, signature context and hash input carries a unique, versioned label; check against the constant table in spec 04 / `tools/constants.json`.
- **Missing key commitment** in multi-recipient AEAD ("invisible salamanders"; R5).
- **Randomness misuse.** Only `candor_core::rng`. Flag `rand::thread_rng`, `SmallRng`, seeded RNGs, `fastrand`, `uuid` v1/v6/v7, and timestamps used as IDs.
- **Deserializing untrusted keys.** Check point validation and the small-order/identity rejection for X25519 (all-zero shared secret), ML-KEM encapsulation-key checks (FIPS 203 modulus check), canonical encoding of signatures (malleability), and length checks before `try_into`.
- **KEM/AEAD API misuse.** Ciphertext or encapsulation is not bound into the transcript; decapsulation failure is distinguishable from AEAD failure (an oracle); AAD is omitted.
- **Error oracles.** Distinct error codes or timings for "bad MAC" vs "bad padding" vs "unknown key id".
- **Side-channel regressions in dependencies** (curve25519-dalek `Scalar::sub`, ml-dsa decomposition, rsa Marvin). Check RustSec on every lockfile change.

---

## 6. Web/HTTP, IPC, SQL, deployment, CI/CD and OPSEC

### 6.1 HTTP (source UI over onion, recipient API)
- **Request smuggling / parser differential** (CWE-444): conflicting `Content-Length`/`Transfer-Encoding`, obs-fold, duplicate headers; hyper RUSTSEC-2021-0020 [B-AU-09]. Relevant wherever a reverse proxy sits in front.
- **Resource limits**: header count and size, body size per route (`DefaultBodyLimit`/`RequestBodyLimitLayer`), multipart part count, slowloris (header read timeout), slow body (minimum rate / total timeout), HTTP/2 stream limits (rapid reset CVE-2023-44487; h2 empty DATA frames RUSTSEC-2026-0258) [B-AU-10, B-AU-37, B-AU-38], concurrency limits per circuit-less listener. Over Tor there is no client IP to rate-limit on, so limits must be global or per-session and must not create a fingerprint.
- **CSRF**: `SameSite=Strict` cookies, a synchronizer token bound to the session, and state change only via POST. The onion origin removes CORS from consideration, but cross-site form POSTs remain a risk.
- **Header injection** (CWE-113): never build headers from input (filenames in `Content-Disposition`).
- **Cache**: `Cache-Control: no-store` on every source-facing response; no ETag/Last-Modified that encodes time or size.
- **Cookie flags**: `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`; `Secure` per onion policy (spec 11); `__Host-` prefix if applicable; no persistent `Expires` for source sessions.
- **Security headers**: CSP with no inline script and no third-party origins, `Referrer-Policy: no-referrer`, `X-Content-Type-Options`, frame-ancestors `'none'`, no `Server`/`Date`-derived fingerprint beyond the spec.
- **Uniform responses**: fixed error bodies; padding to size classes where the spec requires (ADR-047 chaff).

### 6.2 IPC / unix sockets
- Peer identity comes from `SO_PEERCRED`/`getsockopt(SO_PEERCRED)`, never from message fields (CVE-2025-24889 lesson, 27 §12.5) [B-AU-32].
- Socket file mode and owner are set atomically: bind inside a 0700 directory, or `umask` before `bind` (the chmod-after-bind race).
- Abstract-namespace sockets (`\0` names) bypass filesystem permissions and must not be used.
- Framed protocol with a length cap, a read timeout and a per-connection message limit; versioned; `deny_unknown_fields`.

### 6.3 SQL / PostgreSQL
- Injection: `format!`/`push_str` into SQL, `QueryBuilder::push` with input, dynamic identifiers.
- RLS bypass: table owner or `BYPASSRLS` role used by the app, missing `FORCE ROW LEVEL SECURITY`, `SET` instead of `SET LOCAL` (it leaks across pooled connections), `SECURITY DEFINER` functions without a pinned `search_path`.
- Privilege: the app role holds DDL, `TRUNCATE`, `superuser` or `pg_read_server_files`.
- Logging leaks [B-AU-21]: PostgreSQL re-attaches bind parameters in DETAIL lines when a statement is logged. Required settings: `log_statement = none`, `log_min_duration_statement = -1`, `log_parameter_max_length = 0`, `log_parameter_max_length_on_error = 0`, `log_error_verbosity = terse`, `log_connections/log_disconnections = off` (or no host field), `log_line_prefix` without `%h`/`%r`, `log_min_error_statement = panic` (otherwise failing statements, and their literals, are logged).
- Timestamps: `now()`/`DEFAULT CURRENT_TIMESTAMP` on source-linked tables (ADR-010).

### 6.4 Deployment config
- **systemd**: score with `systemd-analyze security --offline=true <unit>` [B-AU-22]. Expect `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `PrivateNetwork` (sealer), `RestrictAddressFamilies=AF_UNIX` (no AF_INET for non-Tor processes), `SystemCallFilter=@system-service` minus extras, `MemoryDenyWriteExecute`, `LimitCORE=0`, `CapabilityBoundingSet=` empty, `IPAddressDeny=any`, `UMask=0077`, and no `Environment=` secrets. Also `LogLevelMax` and `StandardOutput` routing.
- **AppArmor**: profile in enforce mode, no `/** rw`, no `ptrace`, no network for the sealer.
- **nftables**: default-drop output policy; only Tor's user may egress; no DNS (port 53) egress.
- **Tor**: `SafeLogging 1`, `Log notice` (not `info`/`debug`), `HiddenServiceNonAnonymousMode 0`, Unix-socket `HiddenServicePort`, `DisableDebuggerAttachment 1`, and no ControlPort over TCP without auth.
- **Journald / logrotate**: retention limits, and no forwarding of journal entries that carry service stdout.

### 6.5 CI/CD (GitHub Actions) [B-AU-17, B-AU-18]
Template injection (`${{ github.event.* }}` in `run:`), `pull_request_target` / `workflow_run` with checkout of PR head, excessive `permissions:`, unpinned `uses:` (tag instead of SHA; impostor commits from forks), `persist-credentials` (artipacked), cache poisoning from PR-written caches, `GITHUB_ENV`/`GITHUB_PATH` writes from untrusted data, `secrets: inherit`, self-hosted runners on public repos, artifacts consumed across trust boundaries, and Dependabot auto-merge. zizmor covers most of these; `scripts/check-actions-pinned.sh` duplicates the pin check.

### 6.6 OPSEC / metadata leak classes (the Candor-specific top priority)
Anything that records or emits: IP, User-Agent, Accept-Language, exact time, sizes, filenames, MIME guesses, codenames/passphrases, request bodies, Tor circuit IDs. Places to check: logs, error text, panic messages, metrics labels, `Debug`, temp files, test fixtures, crash paths, DB defaults, file mtimes (safefs should set fixed mtimes), response headers, HTML comments, and the build environment (paths in binaries; `strip = "symbols"` is set, but `file!()`/`panic` locations still embed source paths; use `--remap-path-prefix`).
**Oracles to check**: account existence (login vs unknown codename), submission existence (ID guessing → 404 vs 403), timing of the KDF only on the "known" path, response size by branch, and error-code granularity.

---

## 7. Audit tooling: status in this environment (verified 2026-10-01)

"Verified" means the tool was installed (or found) and run against this repo or a test input in this container.

| Tool | Purpose | Pinned version | Install route (offline/pinned) | Status here |
|---|---|---|---|---|
| clippy (+ restriction lints) | Panic/cast/arith/unsafe/secret lints | toolchain 1.94.1 (`clippy 0.1.94`) | rustup component; already pinned in `rust-toolchain.toml` | **Verified**: ran `-W clippy::as_conversions -W clippy::cast_possible_truncation -W clippy::string_slice` workspace-wide |
| cargo-deny | Advisories, bans, licences, sources | `=0.20.2` | `cargo install --locked`; DB mirror for offline use (`--offline` uses cached DB) | **Verified**: `cargo deny --offline check advisories bans sources` OK |
| cargo-vet | Supply-chain audits | `=0.10.2` | `cargo install --locked` | **Verified**: `cargo vet --locked` succeeded |
| cargo-audit | RustSec scan of Cargo.lock (second opinion to deny) | `=0.22.2` (latest 2026-06-05) | `cargo install --locked` | see §7.1 |
| cargo-geiger | `unsafe` counts incl. deps (27 §12.1 gate evidence) | `=0.13.0` (2025-08-31) | `cargo install --locked` | see §7.1 |
| Miri | UB detection in `unsafe`/allowlist crates and their tests | `nightly-2026-09-28` (`miri 0.1.0 d080e7dff1`) | `rustup toolchain install nightly-2026-09-28 --profile minimal --component miri,rust-src` | **Verified**: `cargo +nightly-2026-09-28 miri test -p candor-log --lib` passed 17/17 |
| cargo-careful | Runs tests with a debug-assertion std (catches UB preconditions cheaply) | `=0.4.10` (2026-04-01) | `cargo install --locked`; needs the same nightly + rust-src | see §7.1 |
| cargo-fuzz (libFuzzer) | Parser/decoder fuzzing (ST-040..ST-056) | `=0.13.2` (2026-06-09) | `cargo install --locked`; needs nightly | see §7.1 |
| proptest | Property tests | `=1.11.0` | already a pinned dev-dep | present in all crates |
| semgrep | Pattern rules (custom Candor rules + `p/rust`) | `semgrep==1.178.0` (PyPI) | `pip install --require-hashes` into a venv; **registry rules need network**, so vendor rules as local YAML for offline use | see §7.1 |
| zizmor | GitHub Actions audit | `=1.26.1` (CI pin; 1.30.1 is latest 2026-09-09, so a bump is due via the 14-day cooling process) | `cargo install --locked` | **Verified**: `zizmor --offline .github/` and `--persona=auditor`, both run |
| shellcheck | Shell scripts / installers (ST-121) | `0.9.0` (Ubuntu noble) | apt / pinned static binary | **Verified**: ran on `scripts/*.sh` |
| systemd-analyze security | Unit sandbox exposure score | systemd 255 | OS package | **Verified**: `--offline=true` on a test unit |
| lynis | Host hardening audit (deployment images) | `3.0.9` (Ubuntu noble) | apt | **Verified**: installed and `--version` ran (host audit applies to deployment images, not this container) |
| valgrind / ASan | `unsafe`/FFI memory checks | valgrind present; ASan via `-Zsanitizer=address` on nightly | OS / nightly | valgrind present (not exercised) |
| dudect-style timing tests | Constant-time checks (ST-026) | `dudect-bencher` (pin when adopted) | cargo | not installed (adopt with ST-026) |

### 7.1 Install results for the late-installed tools
(Filled in at the end of this research session; see the checklist's tool table for the authoritative status.)

---

## 8. Implications for the audit procedure

1. Audit **per build step** against that step's requirements (spec sections + ADRs + BUILD-BRIEF bar), threat-model first, then a manual line review of trust-path code, then tools. Tools are evidence, not the audit.
2. Severity must be tied to **source anonymity and confidentiality**: any deanonymisation or plaintext exposure is Critical regardless of exploit difficulty, if it is reachable by the Adversaries in spec 02.
3. A remotely triggerable panic or abort counts as **High** for internet/onion-facing processes, because `panic = "abort"` makes it a full-service DoS and a timing correlation primitive.
4. Grep patterns are needed because clippy cannot see metadata semantics (filenames, IPs, timestamps) or crypto misuse.
5. Re-test must include a regression test per finding (27 SG-21, 29 ST-012) and a scan for variants of the same bug class elsewhere. The SecureDrop lesson is that the same bug class recurred after audit fixes (R1/37 §2).

---

## Bibliography

| ID | Title | URL | Date | Relevance |
|---|---|---|---|---|
| B-AU-01 | 2025 CWE Top 25 Most Dangerous Software Weaknesses (MITRE/CISA) | https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html | 2025-12 (exact day UNVERIFIED; page blocked, ranks via search extracts) | Weakness taxonomy, §2 |
| B-AU-02 | RustSec Advisory Database (own category/keyword tally) | https://github.com/RustSec/advisory-db | HEAD 2026-09-30 | Rust bug-class evidence, §3 |
| B-AU-03 | RustSec std advisories incl. CVE-2022-21658 `remove_dir_all` TOCTOU, CVE-2021-29922 | https://github.com/RustSec/advisory-db/tree/main/rust/std | 2022-01 / 2021 | FS TOCTOU, input validation |
| B-AU-04 | RUSTSEC-2024-0363 sqlx: Binary protocol misinterpretation caused by truncating or overflowing casts | https://rustsec.org/advisories/RUSTSEC-2024-0363 | 2024-08-15 | `as` casts → smuggling |
| B-AU-05 | RUSTSEC-2024-0344 curve25519-dalek: timing variability in `Scalar29::sub`/`Scalar52::sub` | https://rustsec.org/advisories/RUSTSEC-2024-0344 | 2024-06-18 | CT regressions in deps |
| B-AU-06 | RUSTSEC-2022-0093 ed25519-dalek: double public key signing function oracle | https://rustsec.org/advisories/RUSTSEC-2022-0093 | 2022-06-11 | Key/role-confusion APIs |
| B-AU-07 | RUSTSEC-2026-0067 / -0068 tar: `unpack_in` chmod via symlinks; PAX size headers ignored | https://rustsec.org/advisories/RUSTSEC-2026-0067 | 2026-03-19 | Archive/symlink/parser differential |
| B-AU-08 | RUSTSEC-2025-0168 zip: incorrect path canonicalization → arbitrary file write | https://rustsec.org/advisories/RUSTSEC-2025-0168 | 2025-03-16 | Path traversal |
| B-AU-09 | RUSTSEC-2021-0020 hyper: multiple Transfer-Encoding headers → request smuggling | https://rustsec.org/advisories/RUSTSEC-2021-0020 | 2021-02 | CWE-444 |
| B-AU-10 | RUSTSEC-2026-0258 h2: unbounded empty DATA frames; RUSTSEC-2023-0034 h2 resource exhaustion | https://rustsec.org/advisories/RUSTSEC-2026-0258 | 2026-08-17 | HTTP/2 DoS |
| B-AU-11 | RUSTSEC-2025-0009 ring: some AES functions may panic when overflow checking is enabled | https://rustsec.org/advisories/RUSTSEC-2025-0009 | 2025-03-06 | overflow-checks + abort = DoS |
| B-AU-12 | RustSec crypto-failure advisories: libcrux-aesgcm non-CT tag check; snow unauthenticated nonce increment; chacha20 counter overflow; dcrypt GCM ignores nonce; ml-dsa timing; rsa Marvin | https://github.com/RustSec/advisory-db/tree/main/crates | 2023–2026 | Crypto misuse patterns, §5 |
| B-AU-13 | ANSSI, "Secure Rust Guidelines" (rule IDs LANG-*, MEM-*, FFI-*, DENV-*, LIBS-*) | https://github.com/ANSSI-FR/rust-guide | HEAD 2026-05-18 | Rust coding rules |
| B-AU-14 | Xu et al., "Memory-Safety Challenge Considered Solved? An In-Depth Study with All Rust CVEs" (ACM TOSEM) | https://arxiv.org/abs/2003.03296 | v6, 2021 (fetch blocked) | Rust bug patterns |
| B-AU-15 | Tor Project Arti issue #479 "async cancellation hazards – consider select_safe!"; tokio `select!` cancellation-safety docs | https://gitlab.torproject.org/tpo/core/arti/-/issues/479 ; https://docs.rs/tokio/latest/tokio/macro.select.html | 2022– / current | Async cancellation |
| B-AU-16 | `zeroize` crate documentation (moves/copies, `mem::forget`, not a guarantee) | https://docs.rs/zeroize | current | Zeroization pitfalls |
| B-AU-17 | zizmor — static analysis for GitHub Actions | https://github.com/zizmorcore/zizmor | v1.26.1 local; 1.30.1 latest (2026-09-09) | CI/CD audit |
| B-AU-18 | GitHub Docs, "Security hardening for GitHub Actions" | https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions | current | CI/CD |
| B-AU-19 | Semgrep rule `rust.lang.security.temp-dir.temp-dir`; Semgrep Rust support announcement | https://registry.semgrep.dev/rule/rust.lang.security.temp-dir.temp-dir ; https://semgrep.dev/blog/2023/announcing-semgrep-s-beta-support-for-rust/ | 2023– | SAST |
| B-AU-20 | Kudelski Security, "Advancing Rust support in Semgrep" | https://kudelskisecurity.com/research/advancing-rust-support-in-semgrep | 2024 (approx.) | Custom Rust rules |
| B-AU-21 | PostgreSQL 16 docs, Error Reporting and Logging; C. Pettus, "log_parameter_max_length…" | https://www.postgresql.org/docs/16/runtime-config-logging.html ; https://thebuild.com/blog/all-your-gucs-in-a-row-log_parameter_max_length-and-log_parameter_max_length_on_error/ | current | DB log leaks |
| B-AU-22 | systemd-analyze(1) `security` verb | https://www.freedesktop.org/software/systemd/man/latest/systemd-analyze.html | systemd 255 | Unit hardening |
| B-AU-23 | cargo-careful (R. Jung) | https://github.com/RalfJung/cargo-careful | 0.4.10, 2026-04-01 | UB precondition checks |
| B-AU-24 | cargo-geiger | https://github.com/geiger-rs/cargo-geiger | 0.13.0, 2025-08-31 | unsafe inventory |
| B-AU-25 | cargo-fuzz / Rust Fuzz Book | https://github.com/rust-fuzz/cargo-fuzz | 0.13.2, 2026-06-09 | Fuzzing |
| B-AU-26 | Miri | https://github.com/rust-lang/miri | nightly-2026-09-28 | UB detection |
| B-AU-27 | Clippy lint list (restriction group) | https://rust-lang.github.io/rust-clippy/master/index.html | 1.94 | Lints |
| B-AU-28 | cargo-deny / cargo-vet / cargo-audit | https://github.com/EmbarkStudios/cargo-deny ; https://github.com/mozilla/cargo-vet ; https://github.com/rustsec/rustsec | 0.20.2 / 0.10.2 / 0.22.2 | Supply chain |
| B-AU-29 | OWASP ASVS 5.0.0 | https://github.com/OWASP/ASVS | 2025-05 | Verification targets (27 §6) |
| B-AU-30 | RFC 9112 HTTP/1.1 §6.3 Message Body Length | https://www.rfc-editor.org/rfc/rfc9112#section-6.3 | 2022-06 | Smuggling rules |
| B-AU-31 | RFC 6265bis Cookies (SameSite, `__Host-`) | https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/ | draft, 2025– | Cookie flags |
| B-AU-32 | unix(7) / socket(7) — `SO_PEERCRED` | https://man7.org/linux/man-pages/man7/unix.7.html | current | IPC peer auth |
| B-AU-33 | Lynis | https://github.com/CISOfy/lynis | 3.0.9 (Ubuntu noble) | Host audit |
| B-AU-34 | ShellCheck | https://github.com/koalaman/shellcheck | 0.9.0 | Shell lint |
| B-AU-35 | The Rust Reference, "Type cast expressions" (numeric cast semantics) | https://doc.rust-lang.org/reference/expressions/operator-expr.html#type-cast-expressions | current | `as` truncation/saturation |
| B-AU-36 | Reparaz, Balasch, Verbauwhede, "Dude, is my code constant time?" (dudect) | https://eprint.iacr.org/2016/1123 | 2017 | Timing tests |
| B-AU-37 | CVE-2023-44487 HTTP/2 Rapid Reset; S. McArthur, "hyper HTTP/2 Rapid Reset unaffected" | https://seanmonstar.com/blog/hyper-http2-rapid-reset-unaffected/ | 2023-10-10 | HTTP/2 DoS |
| B-AU-38 | Invicti, "Slowloris attack" | https://www.invicti.com/learn/slowloris-attack | current | Slow-client DoS |
| B-AU-39 | Tor manual (`SafeLogging`, `HiddenServicePort unix:`) | https://2019.www.torproject.org/docs/tor-manual.html.en | current | Tor config leaks |
