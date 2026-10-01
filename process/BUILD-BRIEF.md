# Build Brief — Community Edition implementation (RM-0 / RM-1 / early RM-2)

You are implementing part of Candor Community Edition in `/home/user/leaks` (Rust workspace; root `Cargo.toml` already exists with `members = ["crates/*"]`, edition 2024, pinned toolchain 1.94.1 in `rust-toolchain.toml`, workspace lints: `unsafe_code = forbid`, clippy `unwrap_used/expect_used/panic = deny`).

## Rules
0. **Token efficiency (owner instruction):** be as token-efficient as possible without compromising quality — read only the spec sections you need (grep, targeted line ranges), avoid re-reading files, keep reports terse, no redundant tool calls; never cut tests, checks or correctness to save tokens.
1. **The specs are the source of truth.** Read the spec sections named in your assignment (in `specs/`) and `specs/DECISIONS.md` ADRs referenced. Implement exactly; where the spec is ambiguous or underspecified, choose the safest reasonable option, document it in your crate's `SPEC-NOTES.md` as "Implementation decision" and NEVER silently weaken a protection.
2. **Never invent cryptography.** Use vetted crates (RustCrypto, `hpke` 0.14.1 which implements X-Wing KEM 0x647a, `ed25519-dalek`, `argon2`, `blake3`). No custom primitives.
3. **Only edit files inside your assigned directories.** Do not edit the root `Cargo.toml`, `Cargo.lock` conflicts are expected — if `cargo` rewrites `Cargo.lock`, that is fine. Do not edit `specs/` (put spec feedback in your `SPEC-NOTES.md`).
4. **Dependencies:** declare in your crate's `Cargo.toml` with exact versions (`"=x.y.z"`), `default-features = false` where sensible, minimal feature sets. Use `[lints] workspace = true`. Every new dependency must be justified in `SPEC-NOTES.md` (one line).
5. **Hostile-input discipline:** no panics on untrusted input (no `unwrap`/`expect`/indexing on attacker data; use `get`, checked arithmetic). Zeroize secrets (`zeroize`). Constant-time comparisons for MACs/tags (`subtle`). Secrets never in `Debug` output or error messages.
6. **Tests are mandatory:** unit tests, known-answer tests where a standard defines vectors, property tests (`proptest`) for parsers/round-trips, negative tests (tampering, truncation, wrong lengths, reserved bits). Map tests to spec test IDs (ST-xxx / requirement IDs) in comments.
7. **Run before finishing:** `cargo fmt --all`, `cargo clippy -p <your crate> --all-targets -- -D warnings`, `cargo test -p <your crate>`. All must pass. Report exact commands and results.
8. **Commits:** do NOT commit or push; the lead integrates.
9. Licence headers: `// SPDX-License-Identifier: <licence>` at the top of every source file.

## Final message (≤250 words)
Crate(s) built, public API summary, test count and results, spec ambiguities/decisions logged, anything blocked.

## Security and OPSEC bar (owner instruction — applies to every line of code)
Every change must be as OPSEC-sound and securely coded as possible. Treat each item as a review gate:
- **Metadata:** never record or emit source IP, User-Agent, exact source-event time, filenames, sizes, codenames/passphrases, request bodies or Tor circuit data — not in logs, errors, panics, metrics, debug output, temp files, test fixtures or crash paths. Use candor-log typed events only.
- **No network surprises:** no runtime network calls except those the spec defines (unix sockets, Tor); no telemetry; no DNS; tests use only localhost/unix sockets.
- **Fail closed:** on any error in a privacy-relevant path, refuse rather than degrade (no clearnet fallback, no unsealed storage, no partial plaintext release).
- **Input handling:** every external input has an explicit maximum size, is parsed strictly (reject unknown fields/trailing bytes), and is fuzz/proptest covered; no panics, no unbounded allocation, no recursion on attacker data.
- **Secrets:** zeroize on drop; never Clone secret types without need; constant-time comparisons; no secrets in Debug/Display/errors; minimise lifetime in memory; no swap/disk for plaintext.
- **Least privilege:** each process does one job, holds only the keys it needs, and can be confined by systemd/AppArmor; document the required privileges.
- **Timing/size side channels:** uniform responses and padding where the spec requires; avoid branches that reveal secret-dependent existence (e.g., account exists vs not) through timing or error text.
- **Dependencies:** minimum set, exact pins, default-features off, no build scripts that fetch anything; justify each.
- **Self-review before finishing:** re-read your diff as an attacker (OWASP ASVS 5.0 L3 mindset) and list in SPEC-NOTES.md under "Security self-review" what you checked and any residual risk.

## RM-2 addendum (intake zone)
- Existing crates you may depend on (path deps): `candor-core` (crypto/formats; read its README + SPEC-NOTES first), `candor-safefs` (all filesystem writes), `candor-log` (all logging/audit: typed events only, no println/tracing), `candor-source-ui` (HTML rendering).
- Canonical decisions: specs/DECISIONS.md ADR-001..051. Upload protocol: 08 is canonical. Exact-timestamp rules: 09. Timers: 20 min idle / 2 h absolute. Chaff: ADR-047(3), 04 §12.7. No exact source timestamps, no IP/UA anywhere (ADR-010/016).
- Interfaces between intake crates are defined by their owners as Rust traits + types in the owner crate; consumers depend on the trait, never on internals. Owners: `candor-intake-store` owns `IntakeStore` trait; `candor-sealer` owns the sealer IPC protocol types (in its `proto` module, usable without the server feature).
- PostgreSQL 16 server binaries are at /usr/lib/postgresql/16/bin (we run as root; initdb needs a non-root OS user — create one for tests, e.g. `pgtest`). Integration tests needing PostgreSQL must skip cleanly with a message when `CANDOR_TEST_PG` is unset, and run when it is set.
