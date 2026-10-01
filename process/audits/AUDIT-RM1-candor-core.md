# AUDIT-RM1-candor-core — Independent secure-code audit of `crates/candor-core`

| Field | Value |
|---|---|
| Step | RM-1 (IMPL-RM1 §1.2 primitives/RNG, §1.3 wire formats), component C-11 |
| Audited commit | `60e732f9dab712cf23c1335321edac15b9ba6fc9` (`crates/candor-core` clean in the working tree at audit time) |
| Scope | `crates/candor-core/{Cargo.toml, src/*.rs (21 files, 5,463 lines), tests/*.rs, tests/vectors/**, fuzz/Cargo.toml, fuzz/fuzz_targets/*.rs, data/eff_large_wordlist.txt}` |
| Auditor | Independent auditor helper (did not write this code) |
| Date | 2026-10-01 |
| Method | `process/AUDIT-CHECKLIST.md` v1.0 (A1–A5, B1–B12, C, D, E), `research/R9-secure-code-audit.md`, BUILD-BRIEF "Security and OPSEC bar", IMPL-RM1 §4 (A1–A15) |
| Spec basis | 04 §4, §8, §10, §11.1–11.5, §13.1–13.9, §23; ADR-005/006/011/030/033/046(7)/047(6)/050/051(1) |

## Summary

| Severity | Count | Open |
|---|---|---|
| Critical | 0 | 0 |
| High | 0 | 0 |
| Medium | 6 | 6 |
| Low | 6 | 6 |
| Info | 4 | 4 |

**Gate status: NOT YET PASS.** There are no Critical or High findings. The six Medium findings must be fixed and re-tested, or accepted in writing by the lead auditor (§F.2). Low and Info findings are tracked and do not block.

The core is well built. Every decoder is bounds-checked, rejects trailing data and checks lengths before allocating. The header MAC is verified in constant time before any payload decryption. STREAM enforces the final flag, truncation and trailing-data rules. Slot verification re-derives all 16 slots (ADR-050(3)). Error strings are static, and there is no `unsafe` code, no I/O, no logging and no clock use. The Medium findings are about secret-material hygiene: CK-equivalent `enc_rand`, Argon2 working memory and passphrase reallocation copies. They also cover one nonce-misuse hazard in the public STREAM API and fuzz coverage that does not reach the deep parsers.

## Time per phase (approximate)

A1 scope/inputs 10 % · A2 threat model 10 % · A3 manual line review 50 % · A4 tools 25 % · A5 report 5 %.

## A1. Tier classification

| File | Tier | Depth |
|---|---|---|
| `aead.rs`, `kdf.rs`, `kem.rs`, `sig.rs`, `rand.rs`, `secret.rs`, `hash.rs`, `labels.rs`, `passphrase.rs`, `stream.rs`, `header.rs`, `slots.rs`, `stanza.rs`, `record.rs`, `object.rs`, `padding.rs`, `bytes.rs`, `suite.rs`, `selftest.rs`, `error.rs` | T0 | every line read |
| `vectors.rs` (cfg(test)), `tests/*.rs`, `fuzz/fuzz_targets/*.rs` | T2 (evidence) | read in full for assertion quality |

## A2. Threat model

**Trust boundaries and inputs.** `candor-core` is a library with no I/O. Hostile bytes reach it through its callers:
- Sealed objects, slot blocks and stanzas: from a source over Tor via C-06/C-07, from the intake store (C-08, ADV compromise of Z-INTAKE), or replayed by a malicious server to a Desk.
- Records: from the PostgreSQL server (ADV-insider/DB compromise).
- Passphrases: typed by a source; in Tier W they arrive at C-07 over a Unix socket.
- Public keys: from the Key Directory.
- Recipient List entries: from inside an authenticated payload produced by a possibly malicious sealer or client release (THR-046).

**Assets.** Source passphrase and seed (deanonymisation, reply access). CK/case keys/EK (plaintext). Slot block integrity (hidden recipients). Availability of the sealer and Desk (panic = abort).

| # | Attacker goal | Result |
|---|---|---|
| G1 | Crash sealer/Desk with a malformed header, slot block, stanza, record or STREAM (panic/overflow/OOM) | **Refuted.** All decoders use `Reader` (`split_at_checked`); clippy `indexing_slicing`/`arithmetic_side_effects` are clean on lib code; exact-length checks run before `to_vec`/`with_capacity`; 6 fuzz targets ran clean and proptests passed. The fuzz *coverage* gap is AUD-RM1-CORE-06 |
| G2 | Obtain plaintext before authentication (Efail class) | **Refuted.** `ParsedObject::open`/`open_stream` call `verify_header_mac` (constant time) first; buffered `stream::decrypt` returns nothing unless every chunk including the final-flagged one verifies; the chunk API is documented and poisons on error (Info AUD-RM1-CORE-13) |
| G3 | Make one ciphertext decrypt to different content for different recipients (invisible salamanders) | **Refuted.** `header_mac = HMAC(HKDF(CK, object_id, header-mac‖suite), header)` commits to CK; payload key derives from CK and the authenticated `payload_nonce` |
| G4 | Hide an extra recipient, or swap a listed recipient for an attacker key, in the slot block | **Refuted** for the core check: all 16 slots are re-derived and compared without short-circuit, and duplicate or out-of-range indices are rejected. Edge-case hardening is in AUD-RM1-CORE-09 |
| G5 | Keystream/nonce reuse | **Finding** (API hazard): AUD-RM1-CORE-04 |
| G6 | Recover CK or source keys from residual memory (swap, freed heap, crash) | **Finding:** AUD-RM1-CORE-01, -02, -03, -07 |
| G7 | Timing oracle on secret comparisons (MAC, tag, bound hash, slot) | **Refuted** for MAC/tag/bound-hash/slot comparisons (`subtle`); **finding** for `Wordlist::check` (AUD-RM1-CORE-08) |
| G8 | Downgrade or confuse suite/version/type | **Refuted.** `Suite::from_id` rejects unknown values, FIPS is rejected by `require_supported` everywhere, unknown `object_type`/`stanza_type`/reserved bits are rejected, and there is no negotiation |
| G9 | Cross-protocol/domain confusion of HKDF/HPKE/AAD/signature inputs | **Refuted** today (labels unique; fixed-width suffixes). The missing prefix-freeness argument and test are in AUD-RM1-CORE-10 |
| G10 | Learn secrets from error messages/Debug | **Refuted** for keys (redacted `Debug`, static errors). Metadata-bearing `Debug` is in AUD-RM1-CORE-11 |
| G11 | Bias passphrase generation / weaken derivation | **Refuted.** Rejection sampling (`uniform_below`), exact `ceil(128/log2 N)`, Argon2id m=65536 t=3 p=1 v0x13 32 B fixed (`derive_with_params` is `pub(crate)`), normalization matches 04 §11.3 / ADR-047(6). The stuck-RNG hang is in AUD-RM1-CORE-12 |
| G12 | Use derandomized encapsulation as a public primitive | **Refuted.** `seal_base_with_randomness` and `dummy_slot` are `pub(crate)`. `verify_slot_block` uses caller `enc_rand` but returns only pass/fail |

## A3. Spec-conformance notes (verified, no finding)

- **§13.1 CoreHeader.** The layout and offsets match; decode is strict and decode∘encode is the identity (proptest + fuzz). Bucket legality, `chunk_size_log2 = 16`, reserved fields, zero channel for CASE_*/EXPORT/REPLY, `day_stamp = 0` for source objects and REPLY (CRYPTO-016) and the exact payload length are all checked before the MAC.
- **§13.3 STREAM.** `nonce = u88be(i) ‖ last` (`chunk_nonce`); `n = max(1, ceil(len/65536))`; the empty plaintext is one final chunk; checked arithmetic throughout.
- **§13.2 / ADR-050.** The dummy derivation is `HKDF(CK, object_id, "candor/v1/dummy-slot"‖u8 pos, 64)`, then `DeriveKeyPair(kp_seed)`, with ChaCha20 expansion of `r` (`chacha_expansion_matches_raw_chacha20`). Real slots use CSPRNG `enc_rand` returned as `{slot_index, key_id, enc_rand}`. The info/AAD strings match §13.2.
- **§11.3.** `salt = SHA-256("candor/v1/source-salt" ‖ deployment_salt ‖ tenant_id)`; `PRK = Extract("candor/v1/source", seed)`; the lookup-id/auth/sign/kem-seed‖suite/mailbox‖u32be/prefs labels match; `lookup_tag` matches §11.4. NFKC → `to_lowercase` → separator runs (`char::is_whitespace` = White_Space, U+002D, U+2010..2015, U+002C) → single space, trimmed.
- **ADR-050(2).** The wordlist SHA-256 is pinned and checked at load; the 4 hyphenated words are excluded; N = 7,772 → 10 words.
- **Key validation.** X-Wing pk length is checked, and the ML-KEM-768 ek passes the FIPS 203 modulus check (`ml-kem 0.3.2` `EncryptionKey::from_bytes`). Ed25519 uses `verify_strict`, and signing is keypair-only (no double-pubkey oracle).
- **Self-test.** SHA-256, BLAKE3, HMAC, HKDF, ChaCha20-Poly1305, XChaCha20-Poly1305, Ed25519, X-Wing, Argon2id and RNG distinctness.

## C. Tool runs

Toolchain `1.94.1` (cargo 1.94.1, clippy 0.1.94); nightly `nightly-2026-09-28`. The advisory DB is `advisory-db` @ `9b3a3b73a7f4` (2026-09-30), mirrored locally with no fetch. Isolated `CARGO_TARGET_DIR`s were used; no repository files were modified.

| Tool | Command (abridged) | Result | Triage |
|---|---|---|---|
| clippy deny set | `cargo clippy -p candor-core --all-targets --all-features -- -D warnings` | 0 warnings, exit 0 | — |
| clippy audit extras | `cargo clippy -p candor-core --all-features -- -W as_conversions … -W get_unwrap` (full §C list + `unimplemented`, `get_unwrap`) | 4 warnings, all `as_conversions` | FP: all four are fieldless `#[repr]` enum → discriminant casts (`hash.rs:41`, `header.rs:146`, `stanza.rs:269`, `suite.rs:22`) — lossless by construction. No `indexing_slicing`, `arithmetic_side_effects`, `cast_*`, `string_slice`, `integer_division` or `print_*` hits in lib code |
| tests | `cargo test -p candor-core --locked` | 89 passed (73 unit, 4 KAT, 2 label-registry, 4 properties, 6 vectors), 0 failed | — |
| cargo-careful 0.4.10 | `cargo +nightly-2026-09-28 careful test -p candor-core` | 89 passed, 0 failed | — |
| Miri | `MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=4 cargo +nightly-2026-09-28 miri test -p candor-core --lib -- bytes:: rand:: stream:: header:: padding:: labels:: secret:: suite:: record:: stanza::tests::case_aead` | No Undefined Behaviour reported. At least 26 of the 37 selected tests completed `ok`, among them all of `bytes`, `rand`, `header`, `padding`, `labels`, `secret`, `suite` and `record`, and `stream::nonce_layout`/`poisoning_and_random_access`. The run hit the 3,000 s `timeout` (exit 124) inside the 64 KiB-chunk proptest `stream::tests::roundtrip_and_bitflip`, so the remaining stream/stanza tests did not finish under Miri. The shared scratch log was partly overwritten by a concurrent session, so the exact per-test count is a lower bound | The first run with isolation failed on proptest's `getcwd` (tool limitation, not a finding). Argon2/X-Wing-heavy tests were excluded as infeasible under Miri; the crate has no `unsafe` (`forbid`), so Miri is optional here (§C) |
| cargo-fuzz 0.13.1 | `cargo +nightly-2026-09-28 fuzz run <t> <scratch corpus> -- -max_total_time=120 -rss_limit_mb=2048 -timeout=10` for all 6 targets | All 6 targets exit 0, 120 s each, no crash/OOM/timeout. Execs / coverage: header 31.7 M / cov 170; slot_block 47.2 M / cov 40; stanza 47.5 M / cov 64; record 5.1 M / cov 535; envelope_parse 30.7 M / cov 126; stream_decrypt 4.7 M / cov 586 | No crash, OOM or timeout. Coverage is shallow for `fuzz_slot_block`, `fuzz_stanza` and `fuzz_envelope_parse` → AUD-RM1-CORE-06. Corpora and artifacts were written to scratch only |
| cargo-deny 0.20.2 | `cargo deny --offline check` | advisories ok, licenses ok, sources ok; **bans FAILED** (duplicate `sha2` 0.10.9 via `sqlx` → `candor-intake-store`) | Not in candor-core's tree; belongs to the RM-2 audit. The `sha3` 0.11/0.12 duplicate in candor-core's tree is the ADR-051(1) dated exception (expires 2026-12-30) |
| cargo-audit 0.22.1 | `cargo audit --db <mirror> --no-fetch --deny warnings` | 0 vulnerabilities, 0 warnings (300 crates, 1,277 advisories) | — |
| cargo-vet 0.10.2 | `cargo vet --locked` | Workspace fails: 101 unvetted crates | None of the 66 crates in `cargo tree -p candor-core -e normal,build` is unvetted (set intersection is empty) |
| cargo-geiger 0.13.0 | `cargo geiger --manifest-path $PWD/crates/candor-core/Cargo.toml --all-features --output-format Ratio` | candor-core: 0 unsafe (`?` = forbids unsafe); deps with unsafe: curve25519-dalek, sha2, keccak, zerocopy/ppv-lite86 (rand_chacha), getrandom, hybrid-array, zeroize, unicode-normalization, subtle | Baseline recorded for B11.4. All are RustCrypto/dalek/rand crates already in the reviewed set; `rand_chacha` (zerocopy/ppv-lite86) is used only for the ADR-050(1) expansion |
| grep set B1–B7 | `rg` patterns of §B on `src/` | No clock, network, env (except cfg(test) `CANDOR_REGEN_VECTORS`), fs (cfg(test)/tests only, safefs-lint annotated), print/log, `unsafe`, `mem::forget`/`Rc`/`Arc`, or foreign RNG outside `rand.rs`/`slots.rs` dummy expansion | — |
| constants / semgrep / zizmor / shellcheck / systemd / lynis | — | Not applicable to this crate-only scope (no workflows, scripts, units or images in scope) | — |

## D. Findings

### AUD-RM1-CORE-01 — `enc_rand` is CK-equivalent but handled as non-secret data
- Severity: Medium
- Location: crates/candor-core/src/slots.rs:140-196, 271-298; crates/candor-core/src/object.rs:54-69 (commit 60e732f)
- Category: B3.1, B3.2 (+ CWE-316, CWE-200)
- Description: X-Wing encapsulation is deterministic given its 64-byte randomness. Anyone who holds a Recipient List entry's `enc_rand` and the listed member's public key (which is public in the Key Directory) can recompute the ML-KEM `m` and the X25519 ephemeral scalar. From these they get the shared secret, the HPKE key schedule and the slot plaintext, which is CK. So `enc_rand` is exactly as sensitive as CK to anyone who does not hold CK. The code treats it as ordinary data:
  - `RecipientListEntry` has `pub enc_rand`, derives `Clone` and derives a non-constant-time `PartialEq`.
  - `to_bytes()` returns a plain `[u8; 97]` that is not zeroized.
  - `build_with` moves entries through `sort_by_key` and `into_iter().map().collect()`. This leaves stale, unzeroized copies in the freed `Vec` buffer, because `Drop` runs only on the final location.
  - `SealedObject` (derives `Clone`) bundles `recipient_list` with the public `bytes`/`slot_block`.

  The doc comment "`enc_rand` gives a CK holder nothing beyond CK" (slots.rs:141-142, SPEC-NOTES §5) is true for recipients. It is dangerously misleading for integrators, because it invites them to treat the entries as public metadata.
- Exploit scenario: an integrator (sealer, intake store, test harness) persists or logs `SealedObject` as a unit, or writes `entry.to_bytes()` to a debug file, next to the stored ciphertext. ADV-Z-INTAKE compromise or a log reader then obtains `enc_rand` plus the public MEK and recovers CK, and so the submission plaintext. This bypasses ADR-033's sealing to MEKs. Precondition: caller misuse or a memory disclosure. There is no leak inside candor-core itself today.
- Fix recommendation:
  - Make `enc_rand` private, behind a `Zeroizing` wrapper.
  - Remove `Clone`/`PartialEq`, or replace `PartialEq` with a constant-time `ct_eq`.
  - Have `to_bytes` return `Zeroizing<[u8; 97]>`.
  - Build entries in a pre-sized `Vec` indexed by recipient, with no sort/collect moves.
  - Split `SealedObject` into the public blob and a `SealSecrets { ck, recipient_list }` that zeroizes on drop.
  - Correct the doc comment to state that `enc_rand` is CK-equivalent for anyone without CK.
  - Regression: a compile-fail test that `RecipientListEntry: !Clone`, and a test that `SealedObject` does not expose entries.
- Spec / requirement reference: ADR-050(3); 04 §23.2; IMPL-RM1 §4 A1; BUILD-BRIEF "Secrets"; 27 §12.3.
- Status: Open

### AUD-RM1-CORE-02 — Argon2id working memory (64 MiB) is never zeroized and cannot be mlocked; the seed is recoverable from it
- Severity: Medium
- Location: crates/candor-core/src/passphrase.rs:239-248 (`argon2id` → `argon2 0.6.0` `hash_password_into`) (commit 60e732f)
- Category: B3.2, B3.4 (+ CWE-226, CWE-316)
- Description: `hash_password_into` allocates `block::Blocks` internally. Its `Drop` only calls `dealloc`, and the crate's `zeroize` feature clears only `initial_hash` and `blockhash`, not the 64 MiB memory. With p = 1 the final memory block *is* the input to the final `H'`, so the seed can be recomputed from freed or swapped memory. That seed yields `lookup_id`, the auth/sign keys, `src_sk` and `K_prefs`. SPEC-NOTES implies zeroization because the `zeroize` feature is enabled. 04 §11.5 requires Tier W to "run Argon2id in an mlocked buffer", and the API gives the caller no way to supply one.
- Exploit scenario: ADV with a later memory or swap image of the C-07 host gets the seed. The precondition is swap enabled against 17 INFRA-013, a non-glibc allocator that keeps the freed region mapped, or a memory-disclosure bug. A second case is the Source App (C-03) on a source device, where swap and hibernation are explicitly in scope (17 §device forensics). The attacker then gets every key derived from that source's passphrase: they can read replies, link the source to the account via `lookup_tag`, and impersonate the source.
- Fix recommendation:
  - Call `Argon2::hash_password_into_with_memory` with a caller-provided block arena: `Zeroizing<Vec<argon2::Block>>`, or a `candor-memlock` mlocked/`MADV_DONTDUMP` region.
  - Zeroize the arena after use.
  - Expose a `SourceKeys::derive_in(arena, …)` variant for C-07.
  - Regression: a unit test with a custom arena that asserts it is zeroed after `derive`.
- Spec / requirement reference: 04 §11.5, §23.2; SL-R rules on mlocked secrets; IMPL-RM1 §4 A1; BUILD-BRIEF "Secrets … no swap/disk for plaintext".
- Status: Open

### AUD-RM1-CORE-03 — Passphrase text is copied into freed heap by `String` reallocation
- Severity: Medium
- Location: crates/candor-core/src/passphrase.rs:193-204 (`generate_with`), 214-231 (`normalize`) (commit 60e732f)
- Category: B3.2 (+ CWE-226)
- Description:
  - `generate_with` starts from `Zeroizing::new(String::new())` and grows it with `push`/`push_str` across about 10 words. Each reallocation frees the previous buffer, which holds a passphrase prefix, without zeroizing it. `Zeroizing` only clears the final buffer.
  - `normalize` collects `p.nfkc()` into a `String`, which grows by reallocation from the iterator's lower size hint.
  - `to_lowercase()` can also reallocate when the lowercase form expands.

  These are the most sensitive bytes the source has (04 §11.1: "never stored anywhere").
- Exploit scenario: same memory/forensic adversaries as AUD-RM1-CORE-02. In particular, Tier W C-07 holds the passphrase "in RAM until confirmation". Fragments of up to 9 of 10 words in freed heap reduce the remaining entropy, for example to 12.9 bits for one unknown word (04 §11.2 table).
- Fix recommendation:
  - Pre-compute the exact capacity: for `generate`, the sum of the chosen word lengths plus separators, or the list's maximum word length × `word_count` + `word_count`.
  - For `normalize`, use a two-pass or bounded-expansion capacity (NFKC ≤ 18× per code point; `to_lowercase` ≤ 3×), or a zeroizing growable buffer that zeroizes the old allocation on growth.
  - Regression: a test that asserts no capacity change during `generate`/`normalize` for worst-case inputs.
- Spec / requirement reference: 04 §11.1, §11.5, §23.2; 27 §12.3; R9 §4 "Zeroization gaps".
- Status: Open

### AUD-RM1-CORE-04 — STREAM nonce uniqueness depends on callers never reusing a derived key; the public API cannot enforce it
- Severity: Medium
- Location: crates/candor-core/src/stream.rs:86-138 (`StreamEncryptor::new`, `encrypt`); crates/candor-core/src/kdf.rs:74 (`derive_payload_key`, caller-supplied `payload_nonce`), kdf.rs:139 (`derive_stage_part_key`, caller-supplied `part_id`); crates/candor-core/src/secret.rs:141-152 (`AeadKey::from_bytes`) (commit 60e732f)
- Category: B4.2 (+ CWE-323)
- Description: STREAM chunk nonces are the counter `0,1,2…` with a last flag. They are unique only if each `AeadKey` encrypts exactly one stream. The public API accepts any `AeadKey`, including raw bytes and keys derived from caller-chosen `payload_nonce`/`part_id`. Nothing prevents two `StreamEncryptor`s under the same key. Inside the crate, `object::seal` is correct because it draws a fresh `payload_nonce`. But candor-sealer already bypasses it: `candor-sealer/src/server/seal.rs:246,254` and `server/mod.rs:890-904` build `StreamEncryptor`s from `derive_payload_key(…, &payload_nonce)` and `derive_stage_part_key(k36, part_id)`. SPEC-NOTES has no nonce-uniqueness argument (IMPL-RM1 §4 A3).
- Exploit scenario: a caller bug reuses `part_id` under one K36 (for example a retried upload part), or reuses a `payload_nonce`. Two plaintexts are then encrypted with the same ChaCha20 keystream and Poly1305 key. An ADV who can read the staging tmpfs or intake store gets the XOR of the plaintexts and can forge chunks. Impact on a reachable path would be Critical (nonce reuse). It is rated Medium because no reuse exists inside candor-core; the hazard is the API shape.
- Fix recommendation:
  - Introduce an encrypt-only `StreamKey` that can be created only together with a freshly drawn nonce, for example `StreamKey::fresh_payload(ck) -> (StreamKey, payload_nonce)` and `StreamKey::fresh_stage_part(k36) -> (StreamKey, part_id)`.
  - Have `StreamEncryptor::new` consume it.
  - Keep `derive_payload_key` for the decryption side only, returning a decrypt-only type.
  - Document the uniqueness argument in SPEC-NOTES.
  - Variant hunt in candor-sealer (RM-2 audit).
- Spec / requirement reference: 04 §8 "Nonce policy", §13.3; CRYPTO-007; IMPL-RM1 §4 A3; R9 §5 "Nonce reuse or nonce control".
- Status: Open

### AUD-RM1-CORE-05 — Missing security test evidence required by IMPL-RM1 §1.2/§1.3
- Severity: Medium
- Location: crates/candor-core/fuzz/fuzz_targets/ (6 targets); crates/candor-core/tests/; crates/candor-core/src/slots.rs tests (commit 60e732f)
- Category: B2.9, B12.1
- Description: The following are missing:
  - (a) `fuzz_hpke_open` (ST-042). There is no fuzz target for `kem::open_base`, `RecipientSlotBlock::trial_open`, `WrapStanza::open_hpke*`, `RecipientListEntry::from_bytes`, `verify_slot_block` or `passphrase::normalize`/`Wordlist::check`.
  - (b) Wycheproof/CCTV vectors (ST-023): X25519 low-order, ChaCha20-Poly1305 and XChaCha edge cases, Ed25519 malleability, ML-KEM invalid ek.
  - (c) The INC-SL-08 property "only slot k of 16 is substituted → rejected for every k". Current tests swap slots 0↔15 and 1↔14 only.
  - (d) dudect (ST-026) on tag verification and decapsulation.
  - (e) A zeroization scan (ST-027).

  IMPL-RM1 §9.1 already lists some of these, but they remain open gate evidence.
- Exploit scenario: a regression in HPKE-open error handling or in slot comparison (for example a short-circuit reintroduced) would not be caught before release. The impact depends on the regression. This is an evidence gap, not a known bug.
- Fix recommendation:
  - Add `fuzz_hpke_open`, `fuzz_recipient_entry`, `fuzz_normalize`.
  - Add the per-k substitution proptest (16 cases × real/dummy).
  - Import the Wycheproof JSON with pinned hashes.
  - Add the dudect harness.
  - Map each new test to its ST ID.
- Spec / requirement reference: IMPL-RM1 §1.2 Verify, §1.3 Verify, §4 A14; 04 §22.2–22.3; ST-023/026/027/042; BUILD-BRIEF "fuzz/proptest covered".
- Status: Open

### AUD-RM1-CORE-06 — Three fuzz targets cannot reach the parsers they claim to cover
- Severity: Medium
- Location: crates/candor-core/fuzz/fuzz_targets/fuzz_slot_block.rs, fuzz_envelope_parse.rs, fuzz_stanza.rs; crates/candor-core/fuzz/corpus/ (seed corpus only for `fuzz_header`) (commit 60e732f)
- Category: B2.9
- Description: libFuzzer's default `-max_len` is 4096. A valid slot block is exactly 18,692 bytes, and the smallest valid sealed object is 128 + 32 + 4112 = 4,272 bytes. With no seed corpus, the slot-block decoder never gets past the length check, and `parse` never reaches `ParsedObject::open`, `check_slot_block` or `object_hash` on a structurally valid object. In the audit run, `fuzz_slot_block` plateaued at cov 40 after 47 M executions. `fuzz_stanza` also stayed at cov 64 after 47 M executions: it never synthesised a structurally valid 1,210-byte HPKE_BASE stanza, so `encode` round-trip and `open_casekey_ek` went unexercised. So ST-040/041 evidence for these targets is mostly vacuous.
- Exploit scenario: a future change in the slot-block or open path could introduce a panic or overflow reachable by a source-supplied envelope (ADV over Tor, remote abort with `panic = "abort"`) that fuzzing would not find.
- Fix recommendation:
  - Commit seed corpora generated from `tests/vectors/*.json`: a valid slot block, valid SUBMISSION/REPLY objects, and stanzas.
  - Set `-max_len` (for example 70,000) in the README/CI command, or use a `[profile]`/`.options` file per target.
  - Make `fuzz_envelope_parse` structure-aware: mutate fields of a valid object and also run `open` with the right CK.
  - Record coverage numbers in CI.
- Spec / requirement reference: ST-040/041; 04 §22.3; IMPL-RM1 §4 A14.
- Status: Open

### AUD-RM1-CORE-07 — Unzeroized intermediate copies of key material and plaintext-derived state
- Severity: Low
- Location: crates/candor-core/src/kdf.rs:24-31 (`hkdf_extract`: the `prk` array returned by `Hkdf::extract` is not zeroized); crates/candor-core/src/aead.rs:17,28,40,51 (`(*key.expose()).into()` temporary key arrays); crates/candor-core/src/kem.rs:73-75 (`KemPrivateKey::to_bytes` intermediate `Array`); crates/candor-core/src/passphrase.rs:308,320 (`*buf` copies); crates/candor-core/src/slots.rs:224-238 (`eseed` not zeroized if the second `hkdf` returns early); crates/candor-core/src/hash.rs:72-76 (`EvidenceHasher` buffers of file plaintext not zeroized on drop) (commit 60e732f)
- Category: B3.2 (+ CWE-226)
- Description: These are short-lived stack and heap copies of PRKs, AEAD keys, private seeds and plaintext-hash state that are not cleared. Each one is individually minor. Note that `digest/zeroize` is enabled by feature unification through x-wing/sha3, so HMAC/HKDF internal state is covered.
- Exploit scenario: needs a memory-disclosure primitive. Swap and core dumps are disabled by deployment (04 §23.2, 17).
- Fix recommendation:
  - Wrap these values in `Zeroizing` (for example `let (mut prk, _) = …; … prk.zeroize()`).
  - Pass `GenericArray::from_slice(key.expose())` instead of copying.
  - Zeroize `eseed` with a guard.
  - Use `Zeroizing` hasher wrappers, or document the residual.
- Spec / requirement reference: 04 §23.2; IMPL-RM1 §4 A1.
- Status: Open

### AUD-RM1-CORE-08 — `Wordlist::check` has secret-dependent timing
- Severity: Low
- Location: crates/candor-core/src/passphrase.rs:149-153 (commit 60e732f)
- Category: B3.7, B3.6 (+ CWE-208)
- Description: `toks.len() == self.word_count && toks.iter().all(|t| self.words.iter().any(|w| w == t))` short-circuits on the token count, on the first unknown token and inside a linear scan. Its runtime reveals the list positions of the passphrase words and which token is wrong. Today it is used only client-side and in tests. 04 §11.3 calls it a client usability check, and C-07 does not call it. It is still a public T0 API that a Tier W implementer could reasonably call server-side.
- Exploit scenario: a co-resident attacker on the C-07 host who measures the timing of the check learns word indices. Remote measurement over Tor is unrealistic. Precondition: the API is used server-side.
- Fix recommendation:
  - Implement a constant-time membership check that scans every word for every token, compares with `subtle` on fixed-width padded words and does not short-circuit.
  - Alternatively, mark it `#[doc = "client-side only"]` and gate it behind a `client` feature.
- Spec / requirement reference: 04 §11.3, §23.1; 27 §12.4.
- Status: Open

### AUD-RM1-CORE-09 — Slot-binding and recipient-list edge cases are left to callers
- Severity: Low
- Location: crates/candor-core/src/slots.rs:388-438 (`verify_slot_block`); crates/candor-core/src/object.rs:124-141 (`seal_with_ck_rng`), 223-230 (`ParsedObject::slot_binding`) (commit 60e732f)
- Category: B4.3, B4.4
- Description:
  - (a) `verify_slot_block` accepts several entries with the same `key_id`, so one member can occupy two slots. It does not limit `Custodian` contexts to at most one real slot (04 §13.2: IDENTITY has one real slot to K13 and 15 dummies).
  - (b) `seal` does not check that the `SlotContext` kind matches `object_type` (IDENTITY ⇔ `Custodian`), or that the context's tenant/channel/epoch equal the header fields. An IDENTITY object can be sealed with `MemberEpoch` context to MEKs.
  - (c) Callers pass the context to `slot_binding` instead of deriving it from the authenticated header.
- Exploit scenario: a caller bug, or a malicious client release whose output a Desk accepts, seals the IDENTITY CK under a `MemberEpoch` context. The recipient-side checks then depend on the caller's context. If the Desk builds the context from the header in the same wrong way, the identity block reaches all channel members instead of the custodian (THR-046 class). The recipient list (signed, inside the payload) is the remaining control.
- Fix recommendation:
  - Reject duplicate `key_id`s, and more than one real slot for `Custodian`.
  - In `seal`, require context-kind/type consistency and header equality.
  - Add `ParsedObject::slot_binding_from_header()`, which derives the context from the header for intake types.
  - Add negative tests.
- Spec / requirement reference: 04 §13.2, §12.1; ADR-033(1); ADR-050(3); IMPL-RM1 §4 A6.
- Status: Open

### AUD-RM1-CORE-10 — No written injectivity argument or test for labels that prefix other labels
- Severity: Low
- Location: crates/candor-core/src/labels.rs:199-311, tests 319-360; crates/candor-core/tests/label_registry.rs (commit 60e732f)
- Category: B4.1, B4.3
- Description: IMPL-RM1 §4 A5 requires labels to be "unique and prefix-free". The registry is unique but not prefix-free, and no test checks this. The overlapping pairs are:
  - `dummy-slot`/`dummy-slot-pt`
  - `desk/keystore`/`desk/keystore-slot`
  - `wrap/custodian`/`wrap/custodian-group`
  - `wrap/case`/`wrap/casekey`
  - `candor/v1/source` vs `source/*` and `source-salt`
  - `candor/v1/case` vs `case/record/` and `casekey`

  Manual analysis found **no actual collision today**. Suffixes are fixed-width, and in each same-primitive pair the byte after the shorter label differs: the suite high byte is `0x00` against `-` (0x2D), or the pair is used under different keys or primitives (salt vs info vs AAD). Injectivity therefore rests on an undocumented argument that a future suite id ≥ 0x2D00 or a variable-length suffix would break.
- Exploit scenario: none today. A future label or suite addition could create cross-context key or AAD collisions (INC-63 cross-protocol).
- Fix recommendation:
  - Add a registry test that, per (primitive, key domain), enumerates every label with its fixed suffix width and asserts that no full input is a prefix of another of different length.
  - Document the argument in SPEC-NOTES.
  - Raise the "prefix-free" wording with the spec owners, since 04 §10 itself defines prefixing labels.
- Spec / requirement reference: 04 §10; CRYPTO-012; IMPL-RM1 §4 A5.
- Status: Open

### AUD-RM1-CORE-11 — `Debug` on metadata-bearing types
- Severity: Low
- Location: crates/candor-core/src/hash.rs:63 (`EvidenceHashes` derives `Debug`); crates/candor-core/src/stanza.rs:55-65 (`HpkeWrapContext::Reply` prints `mailbox_id`); crates/candor-core/src/record.rs:21-48 (`RecordAad::SourcePrefs` prints `lookup_tag`); crates/candor-core/src/object.rs:188-195 (`ParsedObject` `Debug` dumps the whole payload slice) (commit 60e732f)
- Category: B1.3 (+ CWE-532)
- Description: These types derive `Debug` and print values that identify a document (evidence hashes are content identifiers that can be matched against a leaked file) or link a source (`mailbox_id`, `lookup_tag`). If a caller logs or panics with `{:?}`, these values leave the trust boundary.
- Exploit scenario: a log reader (ADV-insider) correlates `lookup_tag` or `mailbox_id` across events, or matches an evidence hash to a known document. Precondition: caller misuse, since candor-log typed events should prevent it.
- Fix recommendation:
  - Give these fields a redacting `Debug`, as already done for `Slot`/`WrapStanza`.
  - Give `ParsedObject` a `Debug` that prints the header type and lengths only.
  - Add a redacted-`Debug` test (CRYPTO-057).
- Spec / requirement reference: BUILD-BRIEF "Metadata"; 27 §12.3; CRYPTO-057.
- Status: Open

### AUD-RM1-CORE-12 — `uniform_below` can hang on a stuck RNG instead of failing closed
- Severity: Low
- Location: crates/candor-core/src/rand.rs:39-58; health check at rand.rs:30-36 (commit 60e732f)
- Category: B4.8 (+ CWE-835)
- Description: The rejection loop has no retry bound. The all-zero health check applies only to draws of 16 bytes or more, but this loop draws 4 bytes. An RNG stuck at `0xFFFFFFFF` (≥ `limit` whenever 2^32 mod n ≠ 0, for example n = 7,772) spins forever in passphrase generation instead of returning `Error::Rng`. A stuck `0x00000000` is accepted and always yields index 0.
- Exploit scenario: needs a broken or compromised OS RNG. The result is a hang of C-03/C-07, or degenerate passphrases. The second case is caught by neither the self-test (it checks two 32-byte draws) nor generation.
- Fix recommendation:
  - Bound retries (for example 128) and fail with `Error::Rng`.
  - Draw 16-byte blocks so the health check applies, or run the self-test's distinctness check on every passphrase generation.
- Spec / requirement reference: 04 §23.4; CRYPTO-033; ST-028.
- Status: Open

### AUD-RM1-CORE-13 — Plaintext-release and typestate design notes
- Severity: Info
- Location: crates/candor-core/src/stream.rs:140-287; crates/candor-core/src/object.rs:187-265 (commit 60e732f)
- Category: B4.5
- Description:
  - `StreamDecryptor`/`ChunkReader` yield per-chunk-authenticated plaintext before the final flag is checked. This is allowed by 04 §13.3 and documented, but easy to misuse.
  - `ParsedObject::open` buffers file-type objects of up to about 16 GiB in memory.
  - `ParsedObject.header` is `pub` while still unauthenticated.
  - The `Sealed`/`Opened`/`Verified<T>` typestate named in IMPL-RM1 §1.3 is not implemented.
- Fix recommendation:
  - Have `open_stream` return a type whose chunks are usable only through a closure that is rolled back unless `finish()` succeeds, or require consumers to go through an encrypted-scratch sink.
  - Refuse `open` for file types above a configurable cap.
  - Add `Verified<CoreHeader>`.
- Spec / requirement reference: 04 §8, §13.3; IMPL-RM1 §1.3 (INC-62/INC-65).
- Status: Open

### AUD-RM1-CORE-14 — X-Wing public keys: X25519 component not checked for low order
- Severity: Info
- Location: crates/candor-core/src/kem.rs:31-41 (commit 60e732f)
- Category: B4.7
- Description: `KemPublicKey::from_bytes` checks length, and the ML-KEM ek passes the FIPS 203 modulus check. The 32-byte X25519 part is accepted as-is (low-order or non-canonical). X-Wing's IND-CCA security does not depend on the X25519 part, and the combiner hashes `pk_X`/`ct_X`, so this is not exploitable. It does deviate from the IMPL-RM1 §4 A8 wording ("rejects low-order").
- Fix recommendation: either reject the 8 low-order points and non-canonical encodings in `from_bytes` (cheap; defence in depth if ML-KEM is ever broken), or record the rationale in SPEC-NOTES and amend A8.
- Spec / requirement reference: 04 §23.3; IMPL-RM1 §4 A8.
- Status: Open

### AUD-RM1-CORE-15 — Record header fields outside the AAD
- Severity: Info
- Location: crates/candor-core/src/record.rs:91-157, 197-222 (commit 60e732f)
- Category: B4.3
- Description: The record `version`/`suite` bytes are not in the AAD. For non-`Case` AAD forms, `key_version` is not authenticated either (documented decision). This is harmless while only STD exists and keys differ per version. Once FIPS is implemented, a ciphertext could be presented under the other suite id without detection by the AAD.
- Fix recommendation: before enabling a second suite, bind `version ‖ suite ‖ key_version` into every AAD form (format v2), or reject the record when its suite differs from the tenant's suite.
- Spec / requirement reference: 04 §13.8, §13.9.
- Status: Open

### AUD-RM1-CORE-16 — Spec items not implemented in this crate
- Severity: Info
- Location: crates/candor-core (crate-wide) (commit 60e732f)
- Category: B2.4, B4.1
- Description:
  - (a) There is no strict deterministic-CBOR decoder for the §13.4/§13.5 inner formats (indefinite lengths, duplicate keys, non-canonical integers, unknown keys < 1000). Downstream crates currently encode CBOR themselves, and no decoder exists for Desk/C-03 to use.
  - (b) The start-up self-test covers the X-Wing KEM but not the HPKE key schedule/open (an hpke-pq vector), and has no weak-key check (IMPL-RM1 §1.2, INC-61).
  - (c) The dev-dependencies `serde`/`serde_json`/`hex` keep default features (test-only).
- Fix recommendation:
  - Add a `cbor` module with a strict decoder, plus `non_canonical`/`dup_key` negative vectors (SPEC-NOTES already lists them as not covered).
  - Add one HPKE-PQ 0x647a base-mode open KAT to `self_test`.
- Spec / requirement reference: 04 §13 preamble, §22.2; IMPL-RM1 §1.2.
- Status: Open

## Variant leads for other steps (not findings of this report)

- candor-sealer `server/seal.rs:246,254` and `server/mod.rs:890-904` construct `StreamEncryptor` directly (see AUD-RM1-CORE-04). The RM-2 audit must verify that `payload_nonce` and `part_id` are fresh CSPRNG values that are never reused under one key.
- Workspace `cargo deny` bans failure (`sha2` 0.10.9 via `sqlx`) and 101 unvetted crates belong to the RM-2 (intake-store) audit.

## Gate

Not signed. Gate is blocked by six open Medium findings (AUD-RM1-CORE-01..06), which need a fix and re-test (§G) or written acceptance by the lead auditor (§F.2). No Critical or High findings.

---

## Re-test (round 2) — 2026-10-01

| Field | Value |
|---|---|
| Re-tested commit | `0d486a91c11bce682facdf62a8b9babeb5337d17` (candor-core code identical to `92028a9` + the `SPEC-NOTES.md` working-tree edits reviewed; only `SPEC-NOTES.md` changed in between) |
| Delta | `git diff 60e732f..0d486a9 -- crates/candor-core`: 61 files, +26,144/−278 (src 13 files; new `src/wycheproof.rs`, `tests/ct_timing.rs`, 3 fuzz targets, `fuzz/seeds/`, Wycheproof JSON) |
| Procedure | §G steps 1–6. Every fix diff was read (T0 depth). Variant hunt covered the remaining raw-key and nonce paths, `SealSecrets`/`RecipientList` flows, runtime `PartId` reuse, and sealer call sites. All §C tools were re-run with isolated target dirs and scratch fuzz corpora (seeds copied from `fuzz/seeds/`; nothing written to the repo) |

### Tool re-runs (round 2)

| Tool | Result | Triage |
|---|---|---|
| `cargo test -p candor-core --locked` | 113 passed, 0 failed (95 unit, 1 ct_timing, 4 KAT, 3 label-registry, 4 properties, 6 vectors) | — |
| `cargo +nightly-2026-09-28 careful test -p candor-core` | 113 passed | — |
| clippy deny set `--all-targets --all-features -D warnings` | **FAILS**: 8 errors, all `disallowed_methods`/`disallowed_macros` from the workspace `clippy.toml` (added after round 1 by `ba3cdfd`) in test-only code: `tests/label_registry.rs:29,39` (`std::fs`), `tests/ct_timing.rs:108,122,138` (`println!`), `src/vectors.rs:616-619` (`std::fs`, cfg(test)) | → AUD-RM1-CORE-18 |
| clippy audit extras (lib) | 4 `as_conversions` (the same fieldless-enum discriminant FPs as round 1); no indexing, arithmetic or cast hits | FP (unchanged) |
| `ct_timing` (debug, as shipped) | control 1090; ct_eq 1.63, header MAC 1.12, STREAM tag 1.39, X-Wing 1.67, `Wordlist::check` 1.42 | — |
| `ct_timing --release` (×6) | control 1277; ct_eq 1.2–2.1; header MAC 0.95; **STREAM tag 6.9–9.4** (threshold 10); X-Wing 2.30; `Wordlist::check` 1.24 | A controlled experiment (`t0` vs `t0`-copy ≤ 2.0, `t15` vs `t15`-copy ≤ 3.5, `t0` vs `t15` sign flips with seed and order) shows environment drift on this shared 4-core host, not a leak. The tag compare is `subtle` (`universal-hash 0.6.1` `verify` → `ct_eq`). Test validity → AUD-RM1-CORE-19 |
| cargo-fuzz, 9 targets × 150 s, seeds + README `-max_len` | No crash, leak, OOM or timeout. cov/execs: envelope_parse 2,464/141 k; header 170/34.1 M; hpke_open 1,332/49.5 k; normalize 617/300 k; recipient_entry 212/20.6 M; record 571/3.1 M; slot_block 1,876/2.2 k; stanza 1,987/834 k; stream_decrypt 704/526 k | Deep paths are now reached: slot_block cov 40 → 1,876, stanza 64 → 1,987, envelope 126 → 2,464. `fuzz_slot_block` runs ≈ 15 exec/s (16 decapsulations per input), so it needs long CI runs (ST-040 threshold) |
| Wycheproof provenance | All 6 full files byte-identical to `C2SP/wycheproof@3fa63dd0` `testvectors_v1/` (SHA-256 recomputed from upstream). The ML-KEM subset: all 136 tests occur verbatim upstream, and all 132 upstream invalid tests are included | Verified |
| cargo-audit 0.22.1 | 0 vulnerabilities (1,278 advisories) | — |
| cargo-deny 0.20.2 | advisories ok, **bans ok**, licenses ok, sources ok | Round-1 workspace `sha2` failure resolved |
| cargo-vet | Workspace still has unvetted crates; none of the 66 crates in candor-core's normal/build tree is among them | — |
| cargo-geiger | candor-core 0 unsafe (forbid); dependency set unchanged (`x25519-dalek` is dev-only) | — |
| Miri | Not re-run by the auditor (round-1 attempt hit the timeout under Miri on this host). The builder records 37 parser tests clean in SPEC-NOTES; accepted as builder evidence only | Optional for a forbid-unsafe crate (§C) |
| `cargo check -p candor-sealer` | Compiles against the new API | Variant hunt below |

### Per-finding status

| ID | Sev. | Round-2 status | Verification notes |
|---|---|---|---|
| CORE-01 | M | **Fixed** (60e732f→0d486a9; tests `recipient_entries_are_secret`, `submission_end_to_end`) | `RecipientListEntry` has private fields, no `enc_rand` accessor, `Zeroize + ZeroizeOnDrop`, no `Clone`/`PartialEq` (constant-time `ct_eq`), redacted `Debug` and `to_bytes() -> Zeroizing<[u8;97]>`. Entries are filled in place in a pre-sized `Vec` (no sort/collect). `SealedObject` no longer carries entries. `SealSecrets`/`RecipientList` are not `Clone` and have redacted `Debug`. `seal_base_with_randomness` takes `&[u8;64]`. `from_bytes` errors drop a zeroizing value. Variant: the sealer copies `to_bytes()` output into its CBOR encoder (`candor-sealer/src/server/seal.rs:428-445`). Whether that buffer is zeroizing belongs to the sealer audit |
| CORE-02 | M | **Fixed, residual accepted by design** (test `argon2_arena_is_wiped`) | `Argon2Arena` (`Zeroizing<Vec<Block>>`, `try_reserve_exact`, no growth) goes to `hash_password_into_with_memory`, is wiped after success or error and zeroized on drop. `derive_in` allows a long-lived mlocked arena. The mlock residual is moved to the process (`mlockall`/`LimitMEMLOCK`, swap off), which matches 04 §11.5 and 17 INFRA-013. The sealer and Source App audits must confirm it |
| CORE-03 | M | **Fixed** (tests `generate_never_reallocates`, `lowercase_fixed_never_reallocates`, `normalize_rejects_overlong`, proptest `normalize_matches_reference`) | Fixed-capacity buffers with bounded pushes that fail closed. The 18× byte bound is safe: the worst NFKC byte expansion is U+FDFA, 3 → 33 bytes. `lowercase_fixed` was reviewed. The KELVIN-SIGN shrink padding keeps every prefix ≤ capacity (needs max growth ≤ 2·pads; it is), and Final_Sigma is unaffected because U+0020 is neither cased nor case-ignorable. It relies on `str::to_lowercase` reserving `len` (std implementation detail; the capacity test catches a change) → Info AUD-RM1-CORE-20. Residual: `unicode-normalization` spill buffer (> 4 combining marks; unreachable for wordlist passphrases) |
| CORE-04 | M | **Fixed** (tests `payload_encryptor_fresh_nonce_roundtrip`, `staged_part_id_is_single_use`, `encryptor_enforces_lengths`) | No public encrypt constructor takes a key or nonce. `derive_payload_key`/`derive_stage_part_key` are `pub(crate)`; raw `encrypt` is cfg(test). `for_payload` draws the nonce internally. `PartId` is CSPRNG-only, not `Clone`, cannot be built from bytes, and `for_staged_part` single use is enforced by `AtomicBool::swap` (fails closed). Variant hunt: the remaining public AEAD-encrypt APIs (`record::seal_record`, stanzas, HPKE) all use fresh random nonces or encapsulations; `StreamDecryptor::new(AeadKey)` is decrypt-only; the chaff `seal_with_ck` path still draws a fresh `payload_nonce`; the sealer uses `for_payload`/`for_staged_part` (seal.rs:71-84, 271). Runtime `PartId` reuse is impossible without the same object, and a retry on the same object errors. Uniqueness argument documented |
| CORE-05 | M | **Fixed (a–d); (e) residual** | (a) `fuzz_hpke_open`, `fuzz_recipient_entry`, `fuzz_normalize` added; HPKE open, trial-open and `verify_slot_block` are reached (see coverage). (b) Wycheproof verified against upstream (above). (c) `single_slot_substitution_rejected_for_every_k` covers 16 positions × 3 replacement kinds. (d) `ct_timing` added; validity limits → AUD-RM1-CORE-19. (e) ST-027 zeroization scan is not automated; type-level guarantees and arena/capacity tests partly substitute → tracked in AUD-RM1-CORE-19 |
| CORE-06 | M | **Fixed** (seeds + `vectors::fuzz_seeds_are_current`; coverage above) | Structure-aware harnesses with fixed keys (`common.rs`), committed seeds, per-target `-max_len`. The envelope target checks MAC-before-release and buffered/chunked agreement |
| CORE-07 | L | **Fixed** (residual: compiler stack temporaries) | PRK array wiped; AEAD keys via `new_from_slice`; `KemPrivateKey::to_bytes` intermediate wiped; dummy-slot `r`/`eseed` are guards; `EvidenceHasher` zeroizes its BLAKE3 state, and SHA-256 via `sha2/zeroize`. The `rand_chacha` state holding `r` is not wiped → Info AUD-RM1-CORE-20 |
| CORE-08 | L | **Fixed** (`check_constant_time_semantics`; ct_timing \|t\| ≈ 1.2–1.4) | Every token is compared with every 33-byte slot via `subtle`, with no early exit; only the token count (public) branches |
| CORE-09 | L | **Fixed** | Duplicate `key_id` and > 1 custodian entry are rejected in `verify_slot_block` and `build`; `check_context` enforces IDENTITY ⇔ custodian and tenant/channel/epoch equality; `slot_binding_from_header()` added |
| CORE-10 | L | **Fixed** (`prefix_pairs_are_injective`) | The test enumerates shared-use prefix pairs (4), asserting different total lengths and a non-colliding next byte; new pairs fail until argued |
| CORE-11 | L | **Fixed** | Redacted `Debug` for `EvidenceHashes`, `HpkeWrapContext`, `RecordAad`, `ParsedObject`, `SealedObject` (type and lengths only) |
| CORE-12 | L | **Fixed** (`stuck_high_rng_fails_closed`, `stuck_rng_fails_closed`) | 128-rejection bound → `Error::Rng`; an all-same-index passphrase → `Error::Rng` |
| CORE-13 | I | **Partially fixed; deferral acceptable** | `open_bounded` added. The `Verified<T>` typestate and closure-scoped chunk API are deferred to the RM-2 API review. Chunk release is spec-allowed and documented. Tracked; non-blocking |
| CORE-14 | I | **Fixed** (`wycheproof_x25519_and_xwing_pk_validation`) | Rejects top-bit-set, ≥ p, and the 5 canonical low-order u-coordinates (0, 1, two order-8 points, p−1). List checked against RFC 7748 / libsodium |
| CORE-15 | I | **Deferred; acceptable with a hard precondition** | Only STD exists, and `open_record` rejects non-STD suites. Binding `version‖suite‖key_version` (format v2) must land **before** any second suite is enabled. Track as a release blocker for FIPS |
| CORE-16 | I | **(b) Fixed** (HPKE-PQ open KAT + tamper check in `self_test`); **(a) deferred; acceptable**; (c) n/a | A strict deterministic-CBOR decoder belongs with the consumer schemas. The sealer already has `proto/cbor.rs`; Desk/C-03 need one before they parse §13.4/13.5 (track in RM-2/RM-3) |

### New findings (round 2)

### AUD-RM1-CORE-17 — §11.3 `normalize` is not idempotent; wordlists are not checked for fixed points
- Severity: Low
- Location: crates/candor-core/src/passphrase.rs (`normalize`, `Wordlist::from_words`) (commit 0d486a9)
- Category: B2.10 (+ CWE-176)
- Description: confirmed. `normalize("\u{0130}\u{031F}") = "i\u{0307}\u{031F}"`, and a second pass reorders the marks to `"i\u{031F}\u{0307}"`. NFKC runs before full lowercasing, and U+0130's lowercase (`i U+0307`) followed by a mark of lower canonical class is not in NFKC order. `normalize∘normalize` is stable (a third pass changes nothing). Only U+0130 has an unconditional multi-code-point lowercase mapping, so the non-idempotent set is narrow: U+0130 followed by a combining mark with 0 < ccc < 230. Examples in the passphrase alphabet are U+0130+U+0323 (which NFKC composes first, so it is idempotent) and Turkish input such as `KİWİ` (idempotent, but normalizes to `ki̇wi̇`, not `kiwi`).
- **Security impact (answer to the coordinator's question).** Derivation is a pure function of the raw input bytes: the same keystrokes always derive the same keys. Non-idempotence never merges two different passphrases (no collision, no entropy loss), so confidentiality and anonymity are unaffected. What it can do is *split* one passphrase: two entries derive different keys, and so different `lookup_tag`s and accounts, only if some layer normalizes twice. Examples: a client pre-normalizes before sending to C-07; the Source App stores or displays `normalize(p)` and later derives from it; two implementations (Rust C-07, WASM C-03) differ in Unicode version or normalization order. The result is a source lockout (availability), and only for passphrases containing U+0130 + marks. The EFF list is ASCII and every ASCII output is a fixed point (fuzzed), so the shipped default is unaffected. A localized list could contain a non-fixed-point word, which `from_words` does not reject. Such a word would make `Wordlist::check` fail for generated passphrases, although derivation would stay self-consistent.
- Exploit scenario: no adversarial gain. The risk is an integration bug causing lockout of a source using a future localized list.
- Fix recommendation:
  - `Wordlist::from_words` must reject any word `w` with `normalize(normalize(w)) != normalize(w)`, and any list where two words are equal after double normalization.
  - Document the contract "normalize exactly once, on the raw input, in every component; never derive from or transmit a normalized form that will be normalized again".
  - Pin the Unicode version used by both `unicode-normalization` and std lowercasing, and add a cross-implementation vector containing U+0130/U+031F.
  - The proposed spec amendment (`separators ∘ NFKC ∘ lowercase ∘ NFKC`, or `toNFKC_Casefold`) is endorsed. It changes derived keys only for non-fixed-point inputs, none of which are reachable from the shipped list, so it should be decided before the first localized list ships.
- Spec / requirement reference: 04 §11.1(a), §11.3; ADR-047(6); ST-053.
- Status: Open

### AUD-RM1-CORE-18 — Clippy deny run fails on test code under the workspace `clippy.toml`
- Severity: Low
- Location: crates/candor-core/tests/label_registry.rs:29,39; crates/candor-core/tests/ct_timing.rs:108,122,138; crates/candor-core/src/vectors.rs:616-619 (cfg(test)) (commit 0d486a9)
- Category: B1.3/B6.1 tooling; §F.4 (all tools clean)
- Description: `cargo clippy -p candor-core --all-targets --all-features -- -D warnings` fails with 8 `disallowed_methods` (`std::fs::*`) and `disallowed_macros` (`println!`) errors. The workspace `clippy.toml` (ADR-027 / LOG-001) now applies to test targets. The `// safefs-lint: allow` comments satisfy the repo lint but not clippy. All hits are test-only: there is no production impact, but the §C gate run is not clean.
- Fix recommendation: add scoped `#[allow(clippy::disallowed_methods)]` / `#[allow(clippy::disallowed_macros)]` with a justification comment on these test functions (or print via `eprintln!` behind the same allow), and re-run the deny set.
- Spec / requirement reference: AUDIT-CHECKLIST §C, §F.4; BUILD-BRIEF rule 7.
- Status: Open

### AUD-RM1-CORE-19 — Constant-time and zeroization evidence is weaker than the gate needs (ST-026/ST-027)
- Severity: Low
- Location: crates/candor-core/tests/ct_timing.rs (whole file); SPEC-NOTES CORE-05(e) (commit 0d486a9)
- Category: B12.1, B3.6, B3.2
- Description:
  - (a) `ct_timing` runs in the debug profile under plain `cargo test`. Constant-time behaviour must be measured on optimized code: the release profile changes the results, for example STREAM tag 1.4 → 6.9–9.4.
  - (b) Classes are fixed-vs-fixed with a fixed class schedule seed and small sample counts (150–2,000). In release, the STREAM tag check sits at |t| 7–9 against a pass threshold of 10 on code that is constant-time by inspection (`subtle` in `universal-hash`). My control experiment attributes this to host drift. So the test has low power for real small leaks and is close to flaky for constant-time code.
  - (c) The test can be silently skipped with `CANDOR_SKIP_CT_TIMING=1`.
  - (d) ST-027 (zeroization scan) is not automated (CORE-05(e)).
- Fix recommendation:
  - Run ct_timing in a dedicated release-profile CI job on a pinned, quiet runner.
  - Use dudect's fixed-vs-random classes with ≥ 10^5–10^6 measurements and repeated runs, and report the max |t| over runs as an artifact (advisory), not as a flaky unit-test gate.
  - Fail CI if the job is skipped on the release branch.
  - For ST-027, add an out-of-crate harness (allow-listed `unsafe` crate or Miri-based heap inspection) that seals/derives and scans freed allocations for known secret patterns, or record a written acceptance with its expiry.
- Spec / requirement reference: ST-026, ST-027; IMPL-RM1 §1.2 Verify; 04 §23.1–23.2.
- Status: Open

### AUD-RM1-CORE-20 — Minor residuals in the fixes
- Severity: Info
- Location: crates/candor-core/src/slots.rs (`dummy_slot`: `rand_chacha::ChaCha20Rng::from_seed(*r32)`); crates/candor-core/src/passphrase.rs (`lowercase_fixed`) (commit 0d486a9)
- Category: B3.2
- Description:
  - (a) The ChaCha20Rng state, keyed by the CK-derived `r`, is dropped without zeroization (`rand_chacha` has no zeroize). It yields only dummy-slot randomness, and anyone holding CK can recompute it, so the impact is negligible.
  - (b) `lowercase_fixed` depends on `str::to_lowercase` allocating exactly `len` and growing only past it. This is a std implementation detail, guarded by the capacity test; re-check the test on every toolchain bump.
  - (c) `fuzz_slot_block` runs at about 15 exec/s, so meaningful ST-040 coverage needs long CI fuzz budgets for this target.
- Fix recommendation:
  - Generate the ChaCha20 keystream with `chacha20::ChaCha20` (zeroize feature) instead of `rand_chacha`, which also removes rand_chacha from production.
  - Keep the capacity tests mandatory.
  - Give `fuzz_slot_block` a long nightly budget.
- Status: Open

### Gate verdict (round 2)

All six Medium findings (AUD-RM1-CORE-01..06) are **Fixed** and verified, with the CORE-02 mlock residual assigned to the process per 04 §11.5. All round-1 Lows are Fixed. The Info deferrals (CORE-13 typestate, CORE-15 AAD v2, CORE-16(a) CBOR decoder) are acceptable as tracked items, with CORE-15 a hard precondition for enabling any second suite. Round 2 adds three Lows (CORE-17, -18, -19) and one Info (CORE-20). There are **no open Critical, High or Medium findings**.

§F.4 is **not yet met**: the clippy deny run fails (AUD-RM1-CORE-18, test-only). Once CORE-18 is fixed and the deny run is clean, the step meets §F.1–F.5 for candor-core.

**Gate: CONDITIONAL — PASS on re-run of `cargo clippy -p candor-core --all-targets --all-features -- -D warnings` clean (CORE-18); no other blocker. 2026-10-01 0d486a9.**

## Lead dispositions (2026-10-01)
- **AUD-RM1-CORE-18 — FIXED (lead):** justified `#[allow(clippy::disallowed_methods/macros)]` on test-only vector/seed regeneration, label-registry scan and the ct_timing harness; `cargo clippy -p candor-core --all-targets --all-features -- -D warnings` clean.
- **CORE-13, CORE-15, CORE-16(a) — deferrals ACCEPTED as tracked items** with the auditor's conditions (CORE-15 before any second suite; CORE-16(a) before Desk/C-03 parse §13.4/13.5).
- **CORE-17 (Low) — scheduled:** wordlist loader rejects words that change under a second normalization; spec 04 §11.3 amendment (normalize must be applied exactly once by every component). Tracked for RM-3 entry.
- **CORE-19 (Low) — ACCEPTED for now:** optimized-build timing runs moved to a dedicated quiet CI runner before RM-6; constant-time comparison verified by code review.
- **CORE-02 residual / CORE-05(e) ST-027:** process-level memory locking is enforced by the sealer/systemd hardening (ADR-052(5)); ST-027 zeroization scan tracked for RM-1 exit.
- **Gate: PASS (candor-core).**
