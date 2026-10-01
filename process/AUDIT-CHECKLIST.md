# Candor Secure-Code Audit Checklist (per build step)

Status: v1.0, 2026-10-01 · Owner: lead security auditor · Research basis: `research/R9-secure-code-audit.md` [B-AU-xx]
Applies to: every build step (RM-n / crate / PR series) before it is integrated. It works alongside `process/BUILD-BRIEF.md` ("Security and OPSEC bar"), 27 §11–§13 (review rules, coding standards, gates), 29 (security tests) and 37 (external audit plan). This checklist is the **internal** gate. It does not replace the external audits in 37.

---

## A. Method

The audit is threat-model-driven, the manual review comes first, and tools serve as evidence. Do the phases in order and record time spent per phase in the report.

**A1. Scope and inputs (≈10 %)**
1. Pin the audited revision: `git rev-parse HEAD`. List the files in scope: `git diff --stat <base>..HEAD -- crates/<step crates>`.
2. Read, for the step's components: the owning spec sections (component ID C-xx in 06), the relevant ADRs in `specs/DECISIONS.md`, the REQ/ST/AT IDs in `specs/39-REQUIREMENTS-TRACEABILITY.md`, the BUILD-BRIEF bar and addenda, and each crate's `README.md`, `SPEC-NOTES.md` and its "Security self-review".
3. Classify each file by tier (27 §4: T0 crypto/sealer, T1 trust path/source-facing, T2 other). The review depth scales with tier.

**A2. Threat model for the step (≈15 %)**
1. Draw the step's trust boundaries: who supplies each input (source over Tor, recipient, admin, another process over IPC, filesystem, DB, config) and which adversaries from 02 §6 (ADV-01..ADV-20) reach it.
2. For each input, list the assets at risk: source identity/metadata, plaintext, keys, availability, integrity of the record.
3. Write 5–15 attacker goals ("learn whether codename X exists", "make the sealer write plaintext", "kill intake with one request", "correlate submission time"). Each goal must later be marked *refuted (evidence)* or *finding*.

**A3. Manual line review of trust-path code (≈50 %)**
1. Read every line of T0/T1 code in scope; for T2 code, read entry points and anything reached from an untrusted input.
2. Follow each untrusted input **from source to sink**: parse → validate → authorize → process → store/log/respond. At each hop, apply the checklist categories in §B.
3. Re-read the diff as an attacker (ASVS 5.0 L3 mindset). For each `?`/error path, ask: what is emitted, what is left behind on disk or in memory, and does it fail closed?
4. Check the tests: do they assert the security property (negative tests, limits, oracles), or only the happy path?

**A4. Tools (≈20 %)**
Run the commands in §C. Treat tool output as leads: every hit is triaged to *finding*, *false positive (reason)* or *accepted (ref)*. A tool's silence proves nothing.

**A5. Report (≈5 %)**
Write findings in the §D format to `process/audits/AUDIT-<step>.md`, along with the attacker-goal table from A2, the tool versions and the outputs summary.

---

## B. Checklist by category

Pattern notation: `rg` = ripgrep run on the in-scope paths, `$S` = `crates/<step-crates>/src`. Grep hits are leads only; confirm each by reading the code. The **Sev** column gives the *default* severity when an item is violated on a reachable path; adjust it per §E.

### B1. Metadata and OPSEC leaks (highest priority; spec 03, 20, ADR-010/016, BUILD-BRIEF)
| # | Check | How to detect | Sev |
|---|---|---|---|
| B1.1 | No IP, User-Agent, Accept-Language, Tor circuit or stream data read or stored | `rg -n -i 'remote_addr\|peer_addr\|ConnectInfo\|x-forwarded\|forwarded\|user-agent\|USER_AGENT\|accept-language\|circuit' $S` | Crit |
| B1.2 | No exact source-event timestamps (only `EpochDay`/candor-time) in source-linked records, files or responses | `rg -n 'SystemTime::now\|Instant::now\|Utc::now\|Local::now\|chrono::\|time::OffsetDateTime::now\|now\(\)\|CURRENT_TIMESTAMP\|DEFAULT now' $S migrations/` ; check file mtimes set by safefs | Crit/High |
| B1.3 | No filenames, sizes, MIME, codenames, passphrases or bodies in logs, errors, panics, metrics, `Debug` or fixtures | `rg -n 'println!\|eprintln!\|print!\|dbg!\|log::\|tracing::\|panic!\(.*\{\|format!\(.*(name\|size\|len\|path)' $S`; review every `impl Display/Debug for *Error` and every `#[error("...{}")]` | Crit/High |
| B1.4 | Logging only through typed `candor-log` events with no free-form string fields | `rg -n 'candor_log::' $S`, then inspect the event field types (no `String`/`&str` carrying input) | High |
| B1.5 | Errors carry codes, never input values; user-facing errors are fixed strings | `rg -n '#\[error\(' $S`, `rg -n 'thiserror\|anyhow' $S`; `anyhow` with `.context(format!(..input..))` is a lead | High |
| B1.6 | Existence oracles: unknown codename vs wrong passphrase, unknown vs forbidden ID, are indistinguishable in body, status, size class and timing (27 §12.4) | Read the auth/lookup branches; check that the KDF runs on both paths; look for `NotFound` vs `Forbidden` divergence; AT-042 test present | Crit |
| B1.7 | Response size/timing do not reveal secret state; padding/chaff applied where the spec requires (ADR-047, 04 §12.7) | Read the response builders; look for content-length variance per branch | High |
| B1.8 | No telemetry, DNS or unspecified network calls; tests use localhost/unix sockets only | `rg -n 'TcpStream\|UdpSocket\|ToSocketAddrs\|lookup_host\|reqwest\|ureq\|hyper::Client\|std::net::' $S`; `cargo tree -e normal -i <net crates>` | Crit |
| B1.9 | Random IDs only (UUIDv4/128-bit); no UUIDv1/6/7, ULID or sequential IDs in source-linked tables | `rg -n 'Uuid::now_v7\|new_v7\|new_v1\|new_v6\|ulid\|SERIAL\|BIGSERIAL\|IDENTITY' $S migrations/` | High |
| B1.10 | Build-path / environment leakage in binaries (`file!()` and panic locations embed paths) | `strings target/release/<bin> \| rg '/home/\|/root/\|\.cargo/registry'`; check `--remap-path-prefix` in the release build | Low/Med |
| B1.11 | Temp files: none for plaintext; any others via safefs, 0600, no predictable names, never `std::env::temp_dir` | `rg -n 'temp_dir\|tempfile\|NamedTempFile\|/tmp' $S` | High |
| B1.12 | Panic/abort crash paths: `RUST_BACKTRACE` unset in services, core dumps off (`RLIMIT_CORE=0`, `PR_SET_DUMPABLE 0`, `LimitCORE=0`) | Check units and `main()` init; `rg -n 'RUST_BACKTRACE\|set_hook\|PR_SET_DUMPABLE\|RLIMIT_CORE' -g '!target'` | High |

### B2. Input handling, panics and resource exhaustion (CWE-20/129/190/400/674/770; 27 §12.2)
| # | Check | How to detect | Sev |
|---|---|---|---|
| B2.1 | No panicking constructs on input paths | `cargo clippy --workspace --all-targets -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -W clippy::indexing_slicing -W clippy::string_slice -W clippy::arithmetic_side_effects -W clippy::unreachable -W clippy::todo -W clippy::unimplemented -W clippy::integer_division -W clippy::get_unwrap`; also `rg -n '\[[^\]]*\.\.[^\]]*\]\|\.split_at\(\|\.remove\(0\)\|\.swap_remove\(' $S` | High (remote) / Med (local) |
| B2.2 | Truncating/wrapping `as` casts, especially on lengths, counts and offsets | `cargo clippy -- -W clippy::as_conversions -W clippy::cast_possible_truncation -W clippy::cast_sign_loss -W clippy::cast_possible_wrap`; `rg -n ' as (u8\|u16\|u32\|i32\|usize\|i64)\b' $S`. Precedent: RUSTSEC-2024-0363 [B-AU-04] | High (on wire lengths) |
| B2.3 | Every external input has a named max size checked **before** allocation (`candor-limits` / spec constants) | `rg -n 'with_capacity\|vec!\[.*;\|reserve\(\|read_to_end\|read_to_string\|to_vec\(\)\|collect::<Vec' $S`; confirm a bound or `.take(MAX)` upstream; compare constants with `tools/constants.json` | High |
| B2.4 | Strict parsing: `#[serde(deny_unknown_fields)]` on every external DTO; trailing bytes rejected; no `#[serde(flatten)]` with deny (they conflict); no untagged enums on attacker data | `rg -n 'derive\(.*Deserialize' $S` vs `rg -n 'deny_unknown_fields' $S`; `rg -n 'serde\(flatten\|serde\(untagged\|from_slice\|from_reader\|from_str' $S` | High |
| B2.5 | No recursion on attacker-controlled depth; serde_json recursion limit not disabled | `rg -n 'unbounded_depth\|disable_recursion_limit' $S`; read recursive fns on parsed data | High |
| B2.6 | Bounded queues/channels/caches; per-connection and global concurrency limits | `rg -n 'unbounded_channel\|unbounded\(\)\|HashMap::new\(\)\|VecDeque' $S`; check eviction for state keyed by input | High |
| B2.7 | Regex only on bounded input; `regex` crate (linear time), no `fancy-regex` / backtracking on input | `rg -n 'Regex::new\|fancy_regex' $S` | Med |
| B2.8 | Decompression/archive bombs: ratio and absolute limits; archive entries never extracted with `unpack`/`extract` (ADR-027) | `rg -n 'flate2\|zstd\|brotli\|GzDecoder\|unpack\(\|unpack_in\|extract\(' $S` | High |
| B2.9 | Fuzz/proptest coverage for every parser and decoder (BUILD-BRIEF) | `ls crates/*/fuzz/fuzz_targets`; `rg -n 'proptest!' crates/<c>/tests`; map each parser to a target | Med (missing) |
| B2.10 | Unicode handling: normalization/confusables in codenames; `char` vs byte length in limits | Read the validators | Med |

### B3. Secrets and memory hygiene (27 §12.3)
| # | Check | How to detect | Sev |
|---|---|---|---|
| B3.1 | Secret types wrap `Zeroizing`/`SecretBox` and do **not** derive/impl `Clone, Debug, Display, Serialize, PartialEq` | `rg -n -B3 'struct .*(Key\|Secret\|Seed\|Passphrase\|Plaintext\|Token\|Shared)' $S` then inspect the derives; `rg -n 'impl.*Debug for' $S` must redact | High (Crit if keys are printed) |
| B3.2 | No stale copies: no `.clone()`/`to_vec()`/`to_owned()` on secrets; no `Vec` growth after secret write (realloc leaves copies); no `String` from `format!` of secrets | `rg -n 'expose_secret\(\)\.(clone\|to_vec\|to_owned)\|\.clone\(\)' $S` around secret vars | Med/High |
| B3.3 | No `mem::forget`, `ManuallyDrop`, `Box::leak`, or `Rc`/`Arc` cycles on secret holders | `rg -n 'mem::forget\|ManuallyDrop\|Box::leak\|Rc::new\|Arc::new' $S`; clippy `-W clippy::mem_forget` | Med |
| B3.4 | `panic = "abort"` means `Drop` does not run on panic, so long-lived plaintext must be in `mlock`ed/`DONTDUMP` memory and the core dump disabled | Read process init (`candor-memlock`) | High (sealer) |
| B3.5 | No secrets in env vars, argv, temp files or config read into `String` without zeroize | `rg -n 'env::var\|env::args\|std::env' $S` | High |
| B3.6 | Constant-time comparison for MACs, tokens, verifiers and derived seeds | `rg -n '==\|!=\|\.eq\(\|cmp\(' ` near `tag\|mac\|token\|hash\|digest\|verifier\|seed`; require `subtle::ConstantTimeEq`; flag `HashMap<secret,…>` lookups | High |
| B3.7 | No secret-dependent branches, early returns or table lookups in T0 code | Manual read of T0 functions | High |

### B4. Cryptography (spec 04, ADRs; R5; [B-AU-05/06/12])
| # | Check | How to detect | Sev |
|---|---|---|---|
| B4.1 | Algorithms, parameters, labels and versions exactly as in spec 04 / `tools/constants.json` | `python3 tools/constants_lint.py`; diff the literal labels: `rg -n 'b"candor\|"candor[-/.]' crates/` | High |
| B4.2 | Nonces: random (XChaCha) or a non-wrapping counter; never caller-reused across keys; STREAM chunk counter + last-chunk flag; checked overflow | `rg -n 'nonce\|Nonce::\|counter' $S`; read the increment code for `checked_add` | Crit |
| B4.3 | Domain separation: unique, versioned HKDF `info` / HPKE `info`/`aad` / signature context per purpose; role, recipient, tenant and version bound | Read each KDF/seal/sign call site; table of labels must be injective | High |
| B4.4 | No key/role confusion: distinct types per key role (newtypes); signing API cannot take a mismatched pubkey | Inspect types; `rg -n 'from_bytes\|try_from' ` on key types | High |
| B4.5 | Decryption releases no plaintext before authentication (whole-chunk/whole-stream as the spec says); partial output purged on error | Read the decrypt/stream loop and the error path | Crit |
| B4.6 | Key commitment present for multi-recipient AEAD (R5) | Read the header format | High |
| B4.7 | Untrusted key material validated: length, canonical encoding, small-order/all-zero X25519 output rejected, ML-KEM ek check, signature canonicality | Read the parse functions; tests with bad keys | High |
| B4.8 | Randomness only from `candor_core::rng` | `rg -n 'rand::\|thread_rng\|SmallRng\|StdRng\|seed_from_u64\|fastrand\|getrandom::' crates/ -g '!*/tests/*' -g '!candor-core/src/rng*'` | High |
| B4.9 | No distinguishable decapsulation/AEAD/format error codes reaching an attacker (oracles) | Read the error mapping at the boundary | Med/High |
| B4.10 | Passphrase KDF parameters per spec; verification on the derived seed, never word-by-word | Read the KDF call sites | High |
| B4.11 | Crypto dependencies: exact pins, no `default-features`, RustSec clean, vetted | `cargo deny check`; `cargo vet`; `rg -n 'default-features' crates/*/Cargo.toml` | High |

### B5. Authorization, sessions and web (CWE-862/863/639/352/79/113/444/525/614)
| # | Check | How to detect | Sev |
|---|---|---|---|
| B5.1 | Every route registered via the registry with `authz=` and `audience=`; default-deny | `rg -n 'route\(\|Router::new\|\.nest\(' $S`; each must go through the registry (ADR-029, ST-004) | Crit/High |
| B5.2 | Object-level authz on every ID from the request (IDOR); tenant bound from session, not request | Read the handlers; `rg -n 'Path<\|Query<\|Json<' $S` | Crit/High |
| B5.3 | CSRF: state-changing routes are POST with a session-bound token; cookies `SameSite=Strict` | Read the cookie builder and form handlers | High |
| B5.4 | Cookie flags: `HttpOnly`, `SameSite=Strict`, no `Domain`, session-only, `Secure`/`__Host-` per spec 11 | `rg -n 'Set-Cookie\|Cookie::build\|cookie' $S` | Med/High |
| B5.5 | Templates auto-escape; no `|safe`, raw HTML, inline script, third-party URLs | `rg -n '\|safe\|\|e\(\"none\"\)\|escape = "none"\|<script\|https?://' crates/*/templates`; CSP header check | High |
| B5.6 | Response headers: `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, CSP, `X-Content-Type-Options: nosniff`, `frame-ancestors 'none'`; no ETag/Last-Modified; no `Server`/version | Read the middleware; curl a test server: `curl -sI --unix-socket ...` | Med |
| B5.7 | No header values built from input (CRLF, `Content-Disposition` filenames) | `rg -n 'HeaderValue::from_str\|HeaderValue::from_bytes\|header::CONTENT_DISPOSITION' $S` | Med/High |
| B5.8 | HTTP limits: header size/count, body limit per route, request/header-read timeout, HTTP/2 stream caps, total connections | `rg -n 'DefaultBodyLimit\|RequestBodyLimit\|max_header\|http1_header_read_timeout\|TimeoutLayer\|ConcurrencyLimit\|max_concurrent_streams' $S` | High |
| B5.9 | Smuggling: no hand-rolled HTTP parsing; proxy/upstream agree on framing; reject `TE`+`CL` | Read any custom framing; hyper version is RustSec-clean | High |
| B5.10 | Panic isolation: catch-panic layer returns a fixed body (C-06/C-10) | `rg -n 'CatchPanic' $S` | Med |
| B5.11 | Session timers: 20 min idle / 2 h absolute; logout invalidates server-side; session ID rotated on auth | Read the session store | High |
| B5.12 | Upload (spec 10, 08 canonical): size/count caps, stored by content address via safefs, never served back with a sniffable type, no filename trust | Read the upload handler | High |

### B6. Filesystem (ADR-027; CWE-22/59/367/377)
| # | Check | How to detect | Sev |
|---|---|---|---|
| B6.1 | All writes and externally influenced names go through `candor-safefs` (openat2 `RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`) | `rg -n 'std::fs::\|fs::(write\|File::create\|OpenOptions\|create_dir\|remove\|rename\|copy\|set_permissions\|canonicalize)\|tokio::fs' crates/ -g '!candor-safefs/**'` | High/Crit |
| B6.2 | No `Path::join`/`PathBuf::push` on external input; no `canonicalize`-then-open (TOCTOU) | `rg -n '\.join\(\|\.push\(\|canonicalize' $S` | High |
| B6.3 | Permissions set at creation (mode via `OpenOptionsExt::mode`/umask), not afterwards | `rg -n 'set_permissions\|chmod\|PermissionsExt' $S` | Med |
| B6.4 | Atomic write (temp in same dir + `fsync` + `renameat2(RENAME_NOREPLACE)` + dir fsync); no partial plaintext left on error/cancel | Read safefs call sites | High |
| B6.5 | Secure deletion semantics per spec 35 (no claims of overwrite on SSD; crypto-erasure) | Read deletion paths | Med |

### B7. Async, concurrency and process model
| # | Check | How to detect | Sev |
|---|---|---|---|
| B7.1 | Cancellation safety: no partially applied state when a future is dropped in `select!`/`timeout`/client disconnect | `rg -n 'select!\|timeout\(\|abort\(\)\|JoinHandle' $S`; read each arm for side effects before an `.await` [B-AU-15] | High (if plaintext/partial write) |
| B7.2 | No blocking in async (std::fs, KDF, sealing, `std::sync::Mutex` across `.await`) | `rg -n 'std::sync::Mutex\|std::fs::\|argon2\|block_on' $S` within `async fn`; clippy `-W clippy::await_holding_lock -W clippy::await_holding_refcell_ref` | Med |
| B7.3 | Least privilege: each process holds only its keys; key-holding code is not linked into network-facing binaries | `cargo tree -p <bin> -e normal \| rg 'sealer\|core'`; read `main.rs` | High |
| B7.4 | `unsafe` only in allowlisted crates, each block with `// SAFETY:`; no `unsafe impl Send/Sync` | `rg -n 'unsafe' crates/ -g '*.rs'`; `#![forbid(unsafe_code)]` in each crate root; `cargo geiger` | High/Crit |
| B7.5 | `Command` spawning: no shell, args not from input without validation, env cleared, fds closed | `rg -n 'Command::new\|process::' $S` | High |

### B8. IPC / unix sockets
| # | Check | How to detect | Sev |
|---|---|---|---|
| B8.1 | Peer identity from `SO_PEERCRED` (uid/gid/pid), never from message fields (CVE-2025-24889 lesson) | `rg -n 'peer_cred\|SO_PEERCRED\|UCred\|getsockopt' $S` | Crit |
| B8.2 | Socket created in a 0700 dir or with umask before `bind`; no abstract namespace | `rg -n 'UnixListener::bind\|from_abstract\|\\\\0' $S` | High |
| B8.3 | Framed messages: length cap before alloc, read/write timeouts, versioned, `deny_unknown_fields`, max messages per connection | Read the proto module (`candor-sealer::proto`) | High |
| B8.4 | Fail closed: sealer unavailable → refuse intake (never store unsealed) | Read the client error path | Crit |

### B9. SQL / PostgreSQL (spec 09; 27 §12.5)
| # | Check | How to detect | Sev |
|---|---|---|---|
| B9.1 | Only `sqlx::query!`/`query_as!`; no string-built SQL | `rg -n 'sqlx::query\(\|query_as\(\|QueryBuilder\|format!\(.*(SELECT\|INSERT\|UPDATE\|DELETE\|WHERE)' $S` | Crit/High |
| B9.2 | Tenant context: every connection via the wrapper running `SET LOCAL app.tenant_id` inside a transaction; never plain `SET` | `rg -n 'SET (LOCAL )?app\.\|set_config' $S migrations/` | Crit |
| B9.3 | RLS `ENABLE` + `FORCE` on tenant tables; app role is not owner/superuser/`BYPASSRLS`; `SECURITY DEFINER` functions pin `search_path` | `rg -n -i 'ROW LEVEL SECURITY\|BYPASSRLS\|SECURITY DEFINER\|GRANT\|OWNER TO' migrations/` | Crit/High |
| B9.4 | No `now()`/timestamp defaults on source-linked columns; no IP/inet columns | `rg -n -i 'timestamptz\|timestamp\|now\(\)\|inet\|cidr' migrations/` | High |
| B9.5 | PostgreSQL logging cannot leak: `log_statement=none`, `log_min_duration_statement=-1`, `log_min_error_statement=panic`, `log_parameter_max_length=0`, `log_parameter_max_length_on_error=0`, `log_error_verbosity=terse`, `log_connections=off`, `log_line_prefix` without `%h %r` [B-AU-21] | `rg -n 'log_' deploy/ **/postgresql*.conf` | High |
| B9.6 | Integer widths: Rust↔SQL types match (i32/i64), no truncating casts on bind (RUSTSEC-2024-0363) | Read the binds; see B2.2 | Med |

### B10. Deployment configuration (spec 17, 18)
| # | Check | How to detect | Sev |
|---|---|---|---|
| B10.1 | systemd units hardened; exposure ≤ the threshold set in spec 17 (if unset, ≤ 2.0 for the sealer and ≤ 3.0 for others) | `systemd-analyze security --offline=true --threshold=<n> deploy/systemd/*.service` | High |
| B10.2 | Non-Tor services: `RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`, `PrivateNetwork=yes` (sealer); `LimitCORE=0`; `UMask=0077`; no `Environment=` secrets | `rg -n 'RestrictAddressFamilies\|IPAddressDeny\|PrivateNetwork\|LimitCORE\|Environment=' deploy/` | High |
| B10.3 | AppArmor profiles enforce; no broad `/** rw`, `ptrace`, network for the sealer | `apparmor_parser -QTK <profile>` (syntax) + manual read | Med |
| B10.4 | nftables: output default drop; only the tor uid may egress; no udp/53 | Read the ruleset; `nft -c -f <file>` | High |
| B10.5 | torrc: `SafeLogging 1`, `Log notice`, unix-socket `HiddenServicePort`, no `HiddenServiceNonAnonymousMode`, `DisableDebuggerAttachment 1`, no TCP ControlPort without auth | `rg -n '^(Log\|SafeLogging\|HiddenService\|ControlPort\|DisableDebugger)' deploy/**/torrc*` | High |
| B10.6 | Journald/log retention limits; no stdout of services carrying input | Read the unit `StandardOutput`/journald conf | Med |
| B10.7 | Shell/installer: `set -euo pipefail`, shellcheck clean, explicit file lists for secrets | `shellcheck -S style scripts/*.sh deploy/**/*.sh` | Med |
| B10.8 | Host image audit (deployment images only, not dev containers) | `lynis audit system --quick --no-colors` on the built image | Info/Low |

### B11. Supply chain and CI/CD (spec 28; ST-010/011/133)
| # | Check | How to detect | Sev |
|---|---|---|---|
| B11.1 | New deps justified, exact `=` pins, `default-features = false`, no build scripts that fetch, licence OK | `git diff <base> -- '**/Cargo.toml' Cargo.lock`; `cargo deny check`; `rg -n 'build = \|\[build-dependencies\]' crates/*/Cargo.toml`; read any `build.rs` | High |
| B11.2 | RustSec: no vulnerable/unsound/unmaintained crates without a dated exception | `cargo deny check advisories`; `cargo audit` (second DB reader) | High (vuln reachable) |
| B11.3 | cargo-vet: every new crate audited or explicitly exempted with a reason | `cargo vet --locked` | Med |
| B11.4 | `unsafe` inventory did not grow in T0/T1 (deps included) without Security Lead approval | `cargo geiger -p <crate> --output-format Ratio` vs the previous baseline | Med |
| B11.5 | Workflows: no template injection, no `pull_request_target`, SHA-pinned uses, minimal permissions, no persisted credentials, no caches in release | `zizmor --offline --persona=auditor .github/`; `scripts/check-actions-pinned.sh` | High |
| B11.6 | No secrets committed | `git log -p <base>..HEAD \| rg -i 'BEGIN .*PRIVATE KEY\|AGE-SECRET-KEY\|password\s*=\|token\s*='` | Crit |

### B12. Tests as security evidence
| # | Check | How to detect | Sev |
|---|---|---|---|
| B12.1 | Negative tests for each limit, oracle and authz rule; regression test per previous finding (27 SG-21) | Map findings → tests in the report | Med |
| B12.2 | Tests contain no real-looking metadata (IPs, real names, timestamps) in fixtures | `rg -n '\b\d{1,3}(\.\d{1,3}){3}\b' crates/*/tests crates/*/fuzz` | Low |
| B12.3 | PostgreSQL integration tests skip cleanly when `CANDOR_TEST_PG` is unset | Run without the env var | Low |

---

## C. Tool runs (pinned; record exact output summary in the report)

Run from the repo root on the audited commit. Status was verified in this environment on 2026-10-01 (see R9 §7).

| Tool | Pin | Command | Verified here |
|---|---|---|---|
| clippy (deny set + audit extras) | toolchain `1.94.1` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` then the audit run: `cargo clippy --workspace --all-features -- -W clippy::as_conversions -W clippy::cast_possible_truncation -W clippy::cast_sign_loss -W clippy::cast_possible_wrap -W clippy::string_slice -W clippy::indexing_slicing -W clippy::arithmetic_side_effects -W clippy::integer_division -W clippy::mem_forget -W clippy::await_holding_lock -W clippy::undocumented_unsafe_blocks -W clippy::dbg_macro -W clippy::print_stdout -W clippy::print_stderr -W clippy::unreachable -W clippy::todo` | yes |
| tests | — | `cargo test --workspace --locked` (+ `CANDOR_TEST_PG=… ` for PG suites) | yes (toolchain present) |
| cargo-deny | `=0.20.2` | `cargo deny --offline check` (refresh the DB first: `cargo deny fetch`) | yes |
| cargo-audit | `=0.22.1` installed (latest `0.22.2`; bump via reviewed PR) | `cargo audit --db <mirrored advisory-db> --no-fetch --deny warnings` | yes |
| cargo-vet | `=0.10.2` | `cargo vet --locked` | yes |
| cargo-geiger | `=0.13.0` | `cargo geiger -p <crate> --all-features --output-format Ratio` | see R9 §7.1 |
| Miri | `nightly-2026-09-28` + `miri,rust-src` | `cargo +nightly-2026-09-28 miri setup && cargo +nightly-2026-09-28 miri test -p <crate> --lib` (required for allowlisted `unsafe` crates; optional elsewhere; FS/syscall tests may be unsupported, so mark them `#[cfg_attr(miri, ignore)]`) | yes (candor-log 17/17) |
| cargo-careful | `=0.4.10` | `cargo +nightly-2026-09-28 careful test -p <crate>` | see R9 §7.1 |
| cargo-fuzz | `=0.13.2` | `cargo +nightly-2026-09-28 fuzz run <target> -- -max_total_time=600 -rss_limit_mb=2048 -timeout=10` per parser (ST-040.. thresholds) | see R9 §7.1 |
| semgrep | `semgrep==1.178.0` (venv, `--require-hashes`) | `semgrep scan --metrics=off --config p/rust --error crates/` plus Candor custom rules once added under `process/semgrep/` (not yet created; ST-008). `p/rust` needs network; vendor it for offline runs | see R9 §7.1 |
| zizmor | `=1.26.1` (CI pin) | `zizmor --offline --persona=auditor .github/` | yes |
| shellcheck | `0.9.0` | `shellcheck -S style $(git ls-files '*.sh')` | yes |
| systemd-analyze | systemd 255 | `systemd-analyze security --offline=true --threshold=<n> <unit files>` | yes |
| lynis | `3.0.9` | `lynis audit system --quick` (deployment image only) | yes (installed) |
| repo lints | in-repo | `python3 tools/constants_lint.py`; `scripts/check-actions-pinned.sh`; the ST-005/006/013 lints once they exist | yes (python present) |

Tool runs must not make network calls during the audit except the explicit DB refresh steps. Record the advisory DB commit used.

---

## D. Finding report format

File: `process/audits/AUDIT-<step>.md`. Header: step ID, audited commit, scope (files), auditor, dates, tool versions, attacker-goal table (A2), summary counts by severity. Then one block per finding:

```
### AUD-<step>-NN — <short title>
- Severity: Critical | High | Medium | Low | Info
- Location: crates/<crate>/src/<file>.rs:<line>[-<line>] (commit <sha>)
- Category: B<x>.<y> (+ CWE-<id>)
- Description: what is wrong, in plain words; quote the minimal code.
- Exploit scenario: which adversary (ADV-xx), what they control, the steps, and the impact on
  source anonymity / confidentiality / integrity / availability. State preconditions honestly.
- Fix recommendation: concrete change; the regression test or static rule to add (SG-21).
- Spec / requirement reference: spec §, ADR-nnn, REQ-/ST-/AT- IDs, BUILD-BRIEF bar item.
- Status: Open | Fixed (commit <sha>, test <name>) | Accepted (by <lead>, <date>, expiry <date>,
  risk statement) | False positive (reason) | Duplicate of AUD-…
```

Numbering: `<step>` is the build-step ID (for example `RM2`); `NN` is sequential within the step and is never reused. Findings are written so they can be published later (37), so they contain no real data or secrets.

---

## E. Severity definitions (anonymity- and confidentiality-anchored)

Rate by **impact if exploited** by an adversary in 02 §6 who can reach the code path. Then adjust by at most one level for preconditions (for example, it needs admin + sealer-host root). Never lower an anonymity or plaintext impact below High because of difficulty alone.

| Severity | Definition | Typical examples |
|---|---|---|
| **Critical** | Can deanonymise or link a source; can expose submission plaintext or keys; can defeat authorization across tenants/cases; or the system silently degrades a protection (stores unsealed, clearnet fallback, partial plaintext release) | IP/UA/exact time persisted; codename-existence oracle; nonce reuse; plaintext released before auth; peer identity from message field; RLS bypass; secret key in logs |
| **High** | Weakens a privacy or crypto guarantee with realistic conditions; remotely triggerable crash/abort or unbounded resource use on a source-facing or IPC path; authz gap within one tenant; leak of metadata that narrows the anonymity set (size, filename, coarse timing); missing fail-closed on an error path | panic on hostile input; `as`-truncated length; missing body limit; missing CSRF; non-CT token compare; `std::fs` with external path; unhardened sealer unit |
| **Medium** | Defence-in-depth gap with no direct exploit path today, or one needing privileged/local position; a hygiene violation of a mandatory rule (27 §12) without a reachable exploit | missing zeroize on short-lived copy; blocking call in async; missing fuzz target; weak cache headers on non-source pages; vet exemption without reason |
| **Low** | Minor hardening or consistency issue; requires an unlikely chain | path strings in binary; test fixture realism; overly broad lint allow |
| **Info** | Observation, recommendation or documentation gap; no security impact on its own | naming, comments, suggested refactor for auditability |

---

## F. Gate rule

A build step may be **integrated** only when all of the following hold:

1. **Zero open Critical and zero open High** findings in that step's report. A Critical/High cannot be "accepted"; it must be fixed and re-tested (§G), or the feature removed from the step.
2. Every **Medium** is either fixed and re-tested, or **accepted in writing by the lead auditor**. The acceptance records the risk statement in honest language, compensating controls, an expiry of ≤ 90 days (27 §13.2) and the tracking issue. Expired acceptances reopen the finding.
3. Low/Info are tracked; they do not block.
4. All §C tools ran on the final commit with no untriaged output. Every tool hit is triaged in the report.
5. The attacker-goal table from A2 has every goal marked *refuted (evidence)* or linked to a finding.

The lead auditor signs the report line `Gate: PASS <date> <commit>`. Any later change to in-scope files voids the PASS for those files (delta re-audit per §G).

---

## G. Re-test procedure after fixes

1. **Verify the fix commit.** Read the diff for the finding and confirm it fixes the root cause, not only the reported instance. Record the commit SHA.
2. **Regression test.** A test or static rule that fails on the vulnerable commit and passes on the fix (27 SG-21, 29 ST-012). Demonstrate it: `git stash`/checkout the old commit, run the test, show the failure; then show the pass on the fix.
3. **Variant hunt.** Search the whole workspace (not just the step) for the same pattern using the §B detection for that item, plus a pattern derived from the bug. Each variant becomes a new finding or is noted "none found (pattern …)". The same bug class recurred at SecureDrop after audit fixes.
4. **Delta review.** Do a manual review of all lines changed by the fix (fixes introduce bugs), with the same tier depth as A3.
5. **Re-run tools.** Run the full §C set on the fixed commit, with the same pins.
6. **Update status.** Set `Status: Fixed (commit, test)`. Re-compute the gate (§F). If the fix changed an interface or spec-visible behaviour, flag it for a spec/ADR update by the owners (the auditor does not edit specs).
7. **Re-audit trigger.** If more than 30 % of the step's in-scope lines changed since the audited commit, or any T0 file changed, re-run phases A2–A4 on the changed files.
