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
