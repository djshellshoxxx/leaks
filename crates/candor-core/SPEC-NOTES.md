<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# candor-core — spec notes

Scope: `specs/04-CRYPTOGRAPHY.md` §4, §8, §10, §11.1–11.3, §13.1–13.3, §13.6, §13.8; ADR-005/006/011/012/031/033/046(7)/047(6).
CANDOR-STD-1 is implemented in full. CANDOR-FIPS-1 (`0x0002`) is recognised on the wire and every operation returns `Error::UnsupportedSuite`. Any other suite id (including the reserved `0x0003`) returns `Error::UnknownSuite` (CRYPTO-003/056).

## Spec findings that need an amendment

1. **Dummy-slot encapsulation randomness (§13.2): 32 bytes given, but X-Wing needs 64.**
   §13.2 derives `(kp_seed ‖ r) = HKDF(CK, object_id, "candor/v1/dummy-slot" ‖ u8 i, 64)`, so `r` is 32 bytes. An X-Wing encapsulation consumes 64 bytes (`eseed`: 32 for ML-KEM-768 plus 32 for the X25519 ephemeral key; see draft-connolly-cfrg-xwing-kem and the `hpke` 0.14.1 `XWING_ENCAP_RANDOMNESS_SIZE`).
   **What is implemented** (as the build brief instructs):
   `eseed = the first 64 output bytes of rand_chacha 0.10.0 ChaCha20Rng::from_seed(r)`. That equals ChaCha20 keystream block 0 (RFC 8439 block function, 20 rounds) with key `r`, an all-zero 96-bit nonce and block counter 0. The unit test `slots::tests::chacha_expansion_matches_raw_chacha20` checks this equality against the `chacha20` crate, so other implementations can reproduce it without rand_chacha.
   `kp_seed` goes through HPKE `DeriveKeyPair(kp_seed)` for KEM 0x647a: `SHAKE256.LabeledDerive(ikm, "DeriveKeyPair", "", 32)` per draft-ietf-hpke-pq. It is not used as the raw X-Wing seed.
   The 64 bytes are fed to the encapsulation through an exact-consumption adaptor (`rand::ExactBytesRng`). If the KEM consumes anything other than exactly 64 bytes, the output is discarded and the call fails.
   **Proposed amendment:** either adopt this ChaCha20 expansion verbatim, or (simpler, with no extra primitive) change the HKDF output to `L = 96` and use `kp_seed (32) ‖ eseed (64)` directly.
   The dummy-slot KAT is published in `tests/vectors/sealed_object.json` → `dummy_slot_kat`.
2. **The EFF large wordlist violates §11.1(b).** Four official entries contain a hyphen: `drop-down`, `felt-tip`, `t-shirt`, `yo-yo`. A hyphen is a separator after §11.3 normalization, so these words break the token-count usability check and make tokenization ambiguous.
   **Implementation decision:** keep `data/eff_large_wordlist.txt` byte-identical to the official file (hash below) and leave those four entries out of the in-memory list. That gives N = 7,772 and still 10 words, with 10 × log2(7772) ≈ 129.24 bits (≥ 128; the §11.2 table changes by < 0.01 bit). KeePassXC ships the same 7,772-word list.
   §11.1 and §11.2 ("7,776 words, 129.25 bits") should be amended.
3. **Source KEM seed (§10 / §11.3) is ambiguous.** The table says "X-Wing seed / DeriveKeyPair ikm".
   **Implementation decision:** `(src_sk, src_pk) = HPKE DeriveKeyPair(kem_seed)` for KEM 0x647a, matching the FIPS wording and the dummy-slot keys, as the build brief directs. Published in `tests/vectors/passphrase.json`.
4. **Dummy slot index `i`.** §13.2 does not say whether `i` is the slot position or a dummy counter.
   **Implementation decision:** `i` = the slot's position (0..15) in the final permuted block. This makes dummies position-bound: a verifier recomputes one dummy per position and compares in constant time.
5. **Full recipient-set verification: resolved by ADR-050(3).**
   The first version verified slots only by counting, which caught extra recipients but not a listed recipient swapped for an attacker key. This is now replaced.
   - Every real slot is encapsulated with 64 bytes of `enc_rand` drawn from the CSPRNG at sealing time.
   - The builder returns one `RecipientListEntry {slot_index (u8), key_id (32), enc_rand (64)}` per real slot. The wire form is 97 bytes: `u8 ‖ key_id ‖ enc_rand`.
   - `object::seal` hands these entries, together with the final header, to a payload-builder closure. That way they can be embedded in the signed, AEAD-protected Recipient List. `seal_bytes`, which takes no builder, is refused for intake types.
   - **The entries are secret (AUD-RM1-CORE-01).** X-Wing encapsulation is deterministic given its randomness, so `enc_rand` plus the recipient's *public* key recomputes the slot's shared secret and therefore CK. For anyone without CK an entry is CK-equivalent. See "Fixes for AUD-RM1-CORE".
   - `RecipientSlotBlock::verify_slot_block(ck, binding, list, resolve_pk)` re-derives **all 16 slots** and requires byte equality for each one. Listed slots are re-derived by HPKE SealBase of CK to the resolved key with `enc_rand`. The resolved key's `key_id` must equal the entry's. Every other slot is re-derived as the dummy for its position.
   - These cases are all rejected: a duplicate or out-of-range `slot_index`, a key that cannot be resolved, or any mismatch.

   **Implementation decisions:**
   - `key_id` uses kind 1 (MEK) for the member-epoch context and kind 3 (custodian) for IDENTITY slots.
   - The binding (`object_id`, `payload_nonce`, context, suite) is passed as a `SlotBinding`.
   - Entries are returned in the order of the input recipient list.
   - The old count-based `verify` was removed so that no weaker check remains in the API.

   **Tests:**
   - `slots::tests::swapped_recipient_detected`
   - `hidden_recipient_detected`
   - `build_open_verify` (honest envelope)
   - the vectors `hidden_recipient` and `swapped_recipient` in `sealed_object.json`

## Implementation decisions (safest reasonable reading)

- **CoreHeader validation (§13.1)** goes beyond the explicit list:
  - `chunk_size_log2` must be 16;
  - both reserved fields must be zero;
  - `slot_block_hash` must be non-zero exactly for intake-sealed types (SUBMISSION, ATTACHMENT_BUNDLE, IDENTITY, SOURCE_MESSAGE) and all-zero otherwise;
  - `channel_id` must be zero for CASE_*, EXPORT_PACKAGE and REPLY;
  - `day_stamp` must be 0 for source objects and REPLY (CRYPTO-016);
  - `epoch_id` must be 0 for every type not sealed to Member Epoch Keys (IDENTITY, REPLY, staff objects).

  The encoder runs the same validation, so an invalid header is never emitted.
- **The sealed-object opening order is enforced by the API** (`object::parse` → `ParsedObject::open`): validate the header, check the exact total length, verify `header_mac` in constant time, and only then decrypt the payload.
- **Two STREAM decryption APIs (§8, §13.3):**
  - `stream::decrypt` is buffered and releases nothing unless every chunk, including the final-flagged one, verifies.
  - `StreamDecryptor` / `ChunkReader` yield chunks that have each passed their own tag check. The stream is authentic only after `finish()` returns `Ok`, which checks the final flag, truncation and trailing data. Any error poisons the decryptor.

  C-17 and exports must buffer and discard unless `finish()` succeeds. The plaintext length always comes from the authenticated CoreHeader.
- **The largest file bucket (§13.6)** is the first bucket ≥ 16 GiB (`FILE_CONTENT_MAX`, the EE maximum in 10). Profiles enforce their lower limits before sealing.
- **Wrap Stanzas (§13.2):**
  - the decoder requires the exact `enc_len` per type (1120 / 24 / 24) and `16 ≤ ct_len ≤ 65,536` (resource bound, CRYPTO-053), and rejects trailing data;
  - CASE_AEAD requires `ct_len = 48` and zero `recipient_ref` padding;
  - HPKE_BASE stanzas with a Reply context must have `recipient_ref = 0`;
  - every open function takes the *expected* `bound_hash` and compares it in constant time first ("stanza bound to another object" negative vector).
- **CASEKEY_EK:**
  - The outer `recipient_ref` is the inner recipient key id, and the outer `bound_hash` is `H("candor/v1/casekey" ‖ case_id ‖ u32 v)`.
  - Sealing accepts only an HPKE_BASE stanza whose bound hash is that value. No API layers a raw case key (§9.10).
  - Opening rejects any inner plaintext that is not such a stanza with a matching recipient and suite (`ek_direct_wrap`).
- **Fixed-length context fields:** `job_id` (viewer job) and `connector_id` are taken as 16-byte UUIDs. Every §9.9 `info` field used here is fixed-length, so no u16 length prefixes appear.
- **Record format (§13.8):**
  - `key_version` is authenticated through the AAD for case records (the spec AAD). For the other §9.9 AAD forms (prefs, keystore, keystore slot, case-key cache, ek-meta), the header `key_version` only selects the key; a wrong value fails authentication.
  - `case/record/ ‖ table_id` uses `u16be(table_id)`, consistent with §13.8.
  - The FIPS 2^31 counter (CRYPTO-010) is not applicable to STD.
- **Normalization (§11.3):**
  - NFKC via `unicode-normalization`, then `str::to_lowercase`: Unicode default full lowercase mapping, locale-independent, including the Final_Sigma context rule.
  - Separators are `char::is_whitespace` (= Unicode White_Space), U+002D, U+2010..=U+2015 and U+002C.
  - Input longer than `MAX_PASSPHRASE_INPUT_LEN` (1,024 bytes) is refused with `Error::Length` before any allocation; every intermediate lives in a fixed-capacity zeroizing buffer (AUD-RM1-CORE-03). `normalize` therefore returns `Result`.
- **Argon2id** parameters are fixed constants. The parameterised derivation is `pub(crate)`, so callers cannot lower them (CRYPTO-043). Memory-allocation failure returns `Error::PasswordHash` (fail closed). The 64 MiB working memory is a caller-visible `Argon2Arena`, wiped after every derivation (AUD-RM1-CORE-02).
- **Randomness (§23.4, CRYPTO-033):**
  - All randomness comes from `getrandom::fill`, with any error propagated. A draw of ≥ 16 bytes that is all-zero is treated as an RNG failure.
  - HPKE encapsulation randomness (64 bytes) is pre-drawn from `getrandom` and fed through `ExactBytesRng`, so `hpke`'s infallible RNG interface never panics or invents bytes.
  - `rand_chacha` is used only as the deterministic expansion inside `slots::dummy_slot` and as `TestRng` under `cfg(test)`. The CI `rng-ban` rule must allow-list those two sites.
- **Secrets:**
  - `ContentKey`, `CaseKey`, `ErasureKey`, `AeadKey`, `MacKey`, `Secret32`, `SessionKey`, `KemPrivateKey`, `SigningKey`, `SourceKeys`, `Passphrase`, `RecipientListEntry`, `RecipientList`, `SealSecrets` and `Argon2Arena` zeroize on drop. They have no `Clone`, a redacted `Debug` and no `Display`.
  - `lookup_id` is treated as secret.
  - Error messages are static.
- **Key generation and self-test:**
  - `KemKeyPair::generate` runs a pairwise-consistency test (encapsulate, decapsulate, compare; CRYPTO-036).
  - `selftest::self_test()` runs these KATs: SHA-256, BLAKE3, HMAC, HKDF, ChaCha20-Poly1305, XChaCha20-Poly1305, Ed25519, X-Wing, HPKE-PQ 0x647a base-mode open (hpke-pq vector, AUD-RM1-CORE-16(b)), Argon2id (RFC 9106). It also runs an RNG health check.
- **Ed25519** uses `verify_strict` only.

## Wordlist provenance (`data/eff_large_wordlist.txt`)

- **SHA-256:** `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`. Size: 7,776 lines (`DDDDD\tword\n`). It is also embedded in `passphrase::EFF_LARGE_WORDLIST_SHA256` and checked at load.
- **Where it came from:** the official URL `https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt` was blocked from this environment (proxy 403, Wayback too). The file was taken from the GitHub mirror `ulif/diceware` (`diceware/wordlists/wordlist_en_eff.txt`).
- **Byte-identical SHA-256 in four further independent repositories:** `commonsguy/cw-omnibus`, `curveball/a12n-server`, `ctsrc/Pgen` and `protonpass/proton-pass-common`.
- **Word column:** matches `micahflee/passphraseme` and `redacted/XKCD-password-generator` (words-only SHA-256 `6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522`).
- **Dice-number column:** verified to be the base-6 enumeration 11111..66666.
- **Before release:** re-check the hash against eff.org from an unrestricted network.

## Known-answer test sources (`tests/vectors/kat/`, hashes pinned in `tests/kat.rs`)

| File | Source | SHA-256 |
|---|---|---|
| `xwing-draft.json` | `x-wing` 0.1.0 crate `tests/test-vectors.json` (static.crates.io); byte-identical vectors to github.com/dconnolly/draft-connolly-cfrg-xwing-kem `spec/test-vectors.json` | `a8726596…4f00` |
| `hpke-pq-xwing.json` | `hpke` 0.14.1 `test-vectors/pq-6433c8f.json`, filtered to KEM 0x647a; the HKDF-SHA256/ChaCha20-Poly1305 entry matches github.com/hpkewg/hpke-pq `test-vectors.json` | `52bc66ad…afc9` |
| `rfc9180-x25519-base.json` | `hpke` 0.14.1 `test-vectors/origrfc-5f503c5.json` (RFC 9180 App. A), filtered to DHKEM(X25519)/HKDF-SHA256 base mode | `1b3422b2…34ab` |

The tests run:
- X-Wing draft vectors through `hpke`'s KEM (keypair, encapsulation, decapsulation);
- hpke-pq 0x647a (DeriveKeyPair, `enc`, all 10 sequential encryptions, exports, and a `candor_core::kem::open_base` open);
- RFC 9180 A.2.1 (X25519 / ChaCha20-Poly1305).

These HPKE/KEM KATs (ST-020) are in `tests/kat.rs`. The other primitive KATs are unit tests: RFC 5869 (HKDF), RFC 4231 (HMAC), RFC 8439 (ChaCha20-Poly1305), the XChaCha20-Poly1305 draft vector, RFC 8032 (Ed25519), RFC 9106 (Argon2id), FIPS 180 (SHA-256), and the BLAKE3 empty-input vector (ST-021/022).

## Candor test vectors (`tests/vectors/*.json`, CRYPTO-038)

The files are generated deterministically by `src/vectors.rs` (cfg(test), seeded `TestRng`). Regenerate them with `CANDOR_REGEN_VECTORS=1 cargo test -p candor-core --lib vectors`. Without that variable, the same test fails if a committed file is stale. `tests/vectors.rs` verifies them through the public API only.

| File | Contents |
|---|---|
| `passphrase.json` | full-parameter derivations |
| `stream.json` | positive cases, plus `truncated`, `no_final`, `reordered`, `duplicated`, `trailing`, `bitflip_last` |
| `sealed_object.json` | SUBMISSION with 2 of 3 members, plus Recipient List entries; dummy-slot KAT; `header_tamper`, `wrong_suite` (unknown and FIPS), `tampered_slot_block_hash`, salamander/other-CK, `hidden_recipient`, `swapped_recipient` |
| `stanza.json` | HPKE_BASE reply, CASE_AEAD, CASEKEY_EK and inner; `ek_direct_wrap`, bound to another object |
| `record.json` | case record, stale `row_version` |
| `misc.json` | buckets, `key_id`, `lookup_tag`, evidence hashes |

**Not yet covered (out of this crate's assignment):** CBOR inner formats (§13.4/13.5: `non_canonical`, `dup_key`, `forged Recipient List`), KD entries and checkpoints.

## Test-ID mapping (selection)

| ID | Tests |
|---|---|
| ST-020 | `tests/kat.rs` |
| ST-023 | `wycheproof::*` (ChaCha20-Poly1305, XChaCha20-Poly1305, X25519 + X-Wing pk validation, Ed25519, HKDF-SHA256, HMAC-SHA256, ML-KEM-768 invalid ek) |
| ST-026 | `tests/ct_timing.rs` (dudect-style, separate test target) |
| ST-042 | `fuzz/fuzz_targets/fuzz_hpke_open.rs` |
| INC-SL-08 | `slots::tests::single_slot_substitution_rejected_for_every_k` |
| ST-021/022 | unit KATs (`kdf`, `aead`, `sig`, `hash`, `passphrase::argon2id_rfc9106`) |
| ST-024 | `stream` proptests, `tests/properties.rs` |
| ST-025 | `object::tests`, `slots::tests`, `tests/properties.rs::intake_context_binding` |
| ST-028 | `selftest`, `rand::tests::rng_failure_propagates` |
| ST-040/041 | proptests and `fuzz/` |
| ST-053 | `passphrase::normalize_idempotent` |
| CRYPTO-003/056 | `suite::tests` |
| CRYPTO-007 | `stream::tests::negative_vectors`, `tests/vectors.rs::stream_vectors` |
| CRYPTO-008 | `header::tests::mac_verifies_and_binds`, salamander vectors |
| CRYPTO-009 | `stream::tests::tampered_final_chunk_releases_nothing` |
| CRYPTO-011/054 | `record::tests`, `stanza::tests::case_aead_roundtrip_and_binding` |
| CRYPTO-012 | `labels::tests`, `tests/label_registry.rs` |
| CRYPTO-013/014 | `padding::tests` |
| CRYPTO-018/047 | `header::tests::rejects_bad_fields` |
| CRYPTO-034 | `selftest` |
| CRYPTO-036 | `KemKeyPair::generate` |
| CRYPTO-057 | redacted-`Debug` tests |
| CRYPTO-058/059/060 | `slots::tests` |
| CRYPTO-072 | `passphrase::tests::normalization_rules` |

## Dependencies (one-line justifications)

| Crate | Version | Why |
|---|---|---|
| `hpke` | =0.14.1 (`alloc`, `mlkem`, `x25519`, `hkdfsha2`, `chacha`) | RFC 9180 HPKE with X-Wing KEM 0x647a. `x25519` is required because `hpke` gates `XWing` behind both `mlkem` and `x25519`. |
| `chacha20poly1305` | =0.11.0 | ChaCha20-Poly1305 (STREAM) and XChaCha20-Poly1305 (records, wraps); same version `hpke` uses. |
| `hkdf` | =0.13.0 | HKDF-SHA256 (§10). |
| `hmac` | =0.13.0 | HMAC-SHA-256 `header_mac` (§13.1). |
| `sha2` | =0.11.0 (`zeroize`) | SHA-256 content ids, `key_id`, salts, evidence hash; `zeroize` wipes hasher state on drop (no new crate). |
| `blake3` | =1.8.2 (`zeroize`) | BLAKE3 evidence hash (ADR-012); pinned to match `candor-safefs`; `zeroize` lets `EvidenceHasher` wipe buffered plaintext (no new crate). |
| `ed25519-dalek` | =3.0.0 | Ed25519 source keys and strict verification. |
| `argon2` | =0.6.0 (`alloc`, `zeroize`) | Argon2id passphrase stretching (ADR-046(7)). |
| `getrandom` | =0.4.3 | The sole OS CSPRNG (§23.4); same major as `hpke`. |
| `rand_chacha` | =0.10.0 | Deterministic dummy-slot randomness expansion (brief-mandated; see finding 1). |
| `subtle` | =2.6.1 | Constant-time comparisons. |
| `zeroize` | =1.8.2 | Secret zeroization; workspace-aligned pin. |
| `unicode-normalization` | =0.1.24 | NFKC for §11.3; workspace-aligned pin. |
| `proptest` | =1.11.0 (dev) | Property tests (lead-mandated workspace pin). |
| `x25519-dalek` | =3.0.0 (dev, no default features) | Wycheproof X25519 vectors against the exact X25519 implementation `hpke` uses inside X-Wing (already in the lockfile; no new crate). |
| `serde`, `serde_json`, `hex` | dev | Read and write the JSON vector files. |
| `chacha20` | =0.10.2 (dev) | Proves the ChaCha20 expansion equals the raw keystream. |
| `libfuzzer-sys` | =0.4.10 | Fuzz harness only, in the separate `fuzz/` workspace. |

## Fixes for AUD-RM1-CORE

Audit: `process/audits/AUDIT-RM1-candor-core.md` (commit `60e732f`). Lead decisions for CORE-01..06 were applied as given; deviations are marked **Deviation**.

| ID | Sev. | Fix | Regression evidence |
|---|---|---|---|
| CORE-01 | M | `RecipientListEntry` is a secret type: private fields (`slot_index()`, `key_id()` accessors; no `enc_rand` accessor), `Zeroize + ZeroizeOnDrop`, not `Clone`/`Copy`, no `PartialEq` (constant-time `ct_eq`), redacted `Debug`, `to_bytes() -> Zeroizing<[u8; 97]>`. `RecipientSlotBlock::build` returns a `RecipientList` (not `Clone`, redacted `Debug`) whose vector is allocated once at its final size and filled in place (no sort/collect moves). `SealedObject` no longer contains entries (and its `Debug` prints type/length only); `object::seal` returns `(SealSecrets { ck, recipient_list }, SealedObject)`, `seal_with_ck` returns `(RecipientList, SealedObject)`. The only path for the bytes is `PayloadContext::recipient_list` → `to_bytes()` → the caller's encrypted Recipient List encoder. Doc comments now state that an entry is CK-equivalent for anyone without CK. `seal_base_with_randomness` takes the randomness by reference, so no by-value copies of `enc_rand` are made. | `slots::tests::recipient_entries_are_secret` (compile-time `!Clone` probe for both types, redacted `Debug`), `object::tests::submission_end_to_end` (object `Debug` carries no entry) |
| CORE-02 | M | Argon2id runs in a caller-visible `passphrase::Argon2Arena` (`Zeroizing<Vec<argon2::Block>>`, allocated once with `try_reserve_exact`, failure → `Error::PasswordHash`) via `argon2::Argon2::hash_password_into_with_memory`; the arena is wiped after every derivation (success or error) and again on drop. `SourceKeys::derive_in(&mut arena, …)` lets a long-lived process reuse one arena. **Residual (documented, by decision):** this crate is `forbid(unsafe_code)` and cannot `mlock`; keeping the 64 MiB out of swap/core dumps is the process's job: the sealer (C-07) and Source App must `mlockall(MCL_CURRENT\|MCL_FUTURE)` or run under systemd `LimitMEMLOCK=` ≥ 96 MiB with swap off and `LimitCORE=0` (04 §11.5, 17 INFRA-013). `argon2`'s own `initial_hash`/`blockhash` are zeroized by its `zeroize` feature; its stack temporaries are not (residual). | `passphrase::tests::argon2_arena_is_wiped` (arena zero after success and after a failing too-small arena; derivation result unchanged) |
| CORE-03 | M | `normalize` rejects input > `MAX_PASSPHRASE_INPUT_LEN` (1,024 B) before allocating and returns `Result`. NFKC output goes into a buffer pre-sized to `input × 18` (max NFKC expansion) with bounded pushes that fail closed instead of growing. Lowercasing (`lowercase_fixed`) keeps `str::to_lowercase` (exact Unicode semantics incl. Final_Sigma) but guarantees its internal buffer never reallocates: it computes the exact maximum prefix growth and, if positive, appends `' '` + ⌈g/2⌉ KELVIN SIGNs (3 B → 1 B each) as shrink-padding, then truncates; the space is neither cased nor case-ignorable so Final_Sigma is unaffected. The separator pass writes into a buffer of the exact lowercase length. `generate` reserves `(max_word_len + 1) × word_count` before the first word. All intermediates are `Zeroizing` (wiping full capacity). **Residual:** `unicode-normalization`'s internal decomposition buffer (`TinyVec`, inline 4 entries) spills to the heap only for runs of > 4 combining marks; it is not zeroized (not reachable for wordlist passphrases). | `lowercase_fixed_never_reallocates` (capacity unchanged for İ/Ⱥ/Ⱦ/Σ worst cases), `generate_never_reallocates`, `normalize_rejects_overlong` (incl. 341 × U+FDFA), proptest `normalize_matches_reference` (byte-identical to the previous implementation), unchanged `passphrase.json` vectors |
| CORE-04 | M | No public STREAM constructor takes a key or nonce. Encryption: `StreamEncryptor::for_payload(suite, &ck, len) -> (StreamEncryptor, payload_nonce)` draws the 16-byte nonce from the CSPRNG and derives `K_pay`; `StreamEncryptor::for_staged_part(&SessionKey, &PartId, len)` derives `HKDF(K36, part_id, "candor/v1/stage/part")` (registered label). `PartId` is only created by `PartId::generate()` (CSPRNG), is not `Clone`, and is accepted by `for_staged_part` once (an `AtomicBool` flips on first use; reuse → `Error::Stream("part id already used")`). **Deviation:** the lead's signature `for_staged_part(k36, part_id)` gains the required `plaintext_len` argument, and because `&PartId` cannot be consumed, single use is enforced by that flag (fail closed) rather than by the type system. `StreamEncryptor` is not `Clone`; `finish`/`encrypt_all` consume it. `kdf::derive_payload_key`/`derive_stage_part_key` and raw-key `stream::encrypt` are crate-private (the latter `cfg(test)`). Decryption keeps `StreamDecryptor::new(AeadKey, len)` (cannot reuse a nonce) and adds `for_payload`/`for_staged_part`. New `secret::SessionKey` for K36. **Nonce-uniqueness argument:** each encryptor's key is HKDF of (CK or K36) with a fresh 128-bit CSPRNG salt (`payload_nonce` / `part_id`), so two encryptors share a key only on a 2^-128-scale collision (or `PartId` reuse, which is refused); within one encryptor, chunk nonces `u88be(i) ‖ last` are distinct because `i` strictly increases and the encryptor refuses chunks after the last. Migration table for candor-sealer: README "API changes". | `stream::tests::payload_encryptor_fresh_nonce_roundtrip`, `staged_part_id_is_single_use`, `encryptor_enforces_lengths` |
| CORE-05 | M | (a) New fuzz targets `fuzz_hpke_open` (ST-042: `open_base` on `enc ‖ ct`, X-Wing pk validation on 1,216-byte inputs), `fuzz_recipient_entry`, `fuzz_normalize`; trial-open/`open_hpke*`/`verify_slot_block` are now reached by `fuzz_slot_block`, `fuzz_stanza`, `fuzz_envelope_parse`. (b) Wycheproof (ST-023) from github.com/C2SP/wycheproof `testvectors_v1/` at commit `3fa63dd0344abb611f1fb1d77e119938603ea230`, committed under `tests/vectors/wycheproof/`, SHA-256 pinned and checked in `src/wycheproof.rs`: ChaCha20-Poly1305 `fe61d25f…d53d`, XChaCha20-Poly1305 `a79de072…36a9`, X25519 `35c3f523…be7d`, Ed25519 `752d2ea7…5536`, HKDF-SHA256 `bb2b462a…5f1e`, HMAC-SHA256 `2d201cfa…743f` (all byte-identical to upstream), plus `mlkem_768_encaps_subset.json` `63bb3557…3733` = upstream `mlkem_768_encaps_test.json` (`9d4381f9…b713`) filtered to the first 4 valid and all invalid (ModulusOverflow) tests per group. All vectors pass through this crate's wrappers (`aead`, `kdf`, `sig::verify_strict`, `KemPublicKey::from_bytes`) and `x25519-dalek` (the version `hpke` uses); wrong-size nonces/keys/signatures are unrepresentable in the typed API and counted. (c) Per-slot substitution: for every k in 0..15 (3 real, 13 dummy positions) and three replacement kinds (same-position slot of another honest block, a slot sealed to an attacker key, random bytes) `verify_slot_block` fails. (d) dudect-style timing test as the separate target `tests/ct_timing.rs`: Welch t over cropped distributions, random class interleaving, |t| < 10 required, positive control (`==` on 4 KiB) must exceed 4.5; covers `kdf::ct_eq`, `verify_header_mac`, STREAM tag check, X-Wing decapsulation with implicit rejection, `Wordlist::check`. Measured here: control 453.7; others 0.74, 0.89, 1.92, 2.05, 0.74. `CANDOR_SKIP_CT_TIMING=1` skips on noisy runners. (e) The zeroization scan (ST-027) is **not** automated: it needs a memory-inspection harness outside a `forbid(unsafe)` crate; covered by the type-level guarantees above and the arena/capacity tests. | `wycheproof::*` (7 tests), `slots::tests::single_slot_substitution_rejected_for_every_k`, `ct_timing::constant_time_comparisons`, fuzz runs below |
| CORE-06 | M | Seed corpora are generated deterministically by `vectors::fuzz_seeds` and committed in `fuzz/seeds/<target>/` (the stale-check test `vectors::fuzz_seeds_are_current` fails if they drift; regenerate with `CANDOR_REGEN_VECTORS=1`). Seeds are valid under fixed keys shared through `fuzz/fuzz_targets/common.rs`, so targets are structure-aware: `fuzz_envelope_parse` takes `[slot block ‖] object`, opens with the fixed CK, checks the commitment, trial-opens with the fuzz member, parses the Recipient List from the plaintext and runs full slot verification, and asserts that buffered and chunked opening agree and that plaintext is released only after the MAC verifies; `fuzz_slot_block` takes `block ‖ entries`; `fuzz_stanza` opens every stanza type with the fixed keys; `fuzz_stream_decrypt` asserts buffered/chunked agreement. Per-target `-max_len` in README. | Fuzz table below |
| CORE-07 | L | `hkdf_extract` wipes the returned PRK array; AEAD keys are passed by reference (`new_from_slice`, no stack copy); `KemPrivateKey::to_bytes` wipes its intermediate; dummy-slot `r`/`eseed` are `Zeroizing` guards (wiped on every exit path); `EvidenceHasher` wipes BLAKE3 state on drop and SHA-256 state via `sha2/zeroize`; `uniform_below` wipes its draw. **Residual:** `*buf` copies in `SourceKeys::from_seed` are moved directly into zeroize-on-drop containers; compiler-made stack temporaries cannot be controlled from safe Rust. | — (code review) |
| CORE-08 | L | `Wordlist::check` compares every token against every word on fixed-width 33-byte slots with `subtle`, no early exit; only the token count (a length property) affects timing. Words > 32 bytes are refused in `from_words`. | `check_constant_time_semantics`, `ct_timing` (`Wordlist::check` t = 0.74) |
| CORE-09 | L | (a) `verify_slot_block` rejects duplicate `key_id`s and > 1 entry for a custodian context; `build` rejects duplicate recipients and > 1 custodian recipient. (b) `seal*` require IDENTITY ⇔ custodian context and context tenant/channel/epoch equal to the header. (c) `ParsedObject::slot_binding_from_header()` derives the context from the header. | `hidden_recipient_detected`, `all_dummy_block_and_custodian`, `recipient_entries_are_secret`, `submission_end_to_end`, `properties::intake_context_binding` |
| CORE-10 | L | Injectivity argument recorded and tested (`tests/label_registry.rs::prefix_pairs_are_injective`): the 4 prefix pairs that share a use (`dummy-slot`/`-pt`, `desk/keystore`/`-slot` as info and AAD, `wrap/custodian`/`-group`) have fixed-width suffixes, different total input lengths, and (where the suffix cannot start with every byte) a distinguishing byte (`-` = 0x2D vs suite high byte 0x00 / slot index ≤ 0x0F). Other prefix pairs are used in different positions (salt vs info vs hash domain). New shared-use prefix pairs fail the test until argued. Spec feedback: 04 §10 / IMPL-RM1 §4 A5 should say "injective per use" rather than "prefix-free". | `prefix_pairs_are_injective` |
| CORE-11 | L | Redacted `Debug`: `EvidenceHashes`, `HpkeWrapContext` and `RecordAad` (variant name only), `ParsedObject` and `SealedObject` (type and lengths only). | `context_debug_is_redacted`, `aad_debug_is_redacted`, `hash::tests::evidence_kats`, `submission_end_to_end` |
| CORE-12 | L | Rejection sampling stops after 128 rejections with `Error::Rng` (< 2^-128 for a working RNG); `generate` fails with `Error::Rng` if every word has the same index (stuck-low RNG; ≈ 2^-116 false-positive rate). Chosen over 16-byte draws so the published vectors stay unchanged. | `rand::tests::stuck_high_rng_fails_closed`, `passphrase::tests::stuck_rng_fails_closed` |
| CORE-13 | I | Added `ParsedObject::open_bounded(ck, max)` (refuses before decrypting/allocating) and documented the buffering of `open`. **Not done:** the `Verified<T>` typestate and a closure-scoped chunk API; they change every consumer's API and the chunk semantics are spec-allowed and documented; left for the RM-2 API review. | `submission_end_to_end` |
| CORE-14 | I | `KemPublicKey::from_bytes` rejects an X25519 component with the top bit set, a value ≥ p, or one of the 5 canonical low-order points. | `wycheproof_x25519_and_xwing_pk_validation` (all LowOrderPublic/ZeroSharedSecret/NonCanonicalPublic rejected; accepted keys never give a zero shared secret) |
| CORE-15 | I | **Deferred (format change):** binding `version ‖ suite ‖ key_version` into every AAD changes the record format and invalidates stored records and vectors; only STD exists and `open_record` rejects non-STD suites. Must be done (format v2) before a second suite is enabled. | — |
| CORE-16 | I | (b) Start-up self-test now includes an HPKE-PQ 0x647a base-mode open KAT (hpke-pq vector, encryption 0) with a tamper check. (a) **Deferred:** a strict deterministic-CBOR decoder for §13.4/§13.5 is a new component (owned with the consumers' schemas), not a fix. Weak-key check: X-Wing/Ed25519 keys are derived from 32-byte seeds and the PCT already runs on generation; nothing further identified. (c) Dev-dependency defaults (`serde`, `serde_json`, `hex`) are only `std`; test-only. | `selftest::tests::self_test_passes` |

### Fuzzing evidence (AUD-RM1-CORE-05/06)

`cargo-fuzz 0.13.1`, `nightly-2026-09-28`, libFuzzer via `libfuzzer-sys =0.4.10`; each target ran 70 s (3 in parallel on 4 cores) from the committed seeds with the README `-max_len`, `-rss_limit_mb=2048 -timeout=20`. Corpora/artifacts were written to a scratch directory. No crash, leak, OOM or timeout, except one invariant failure in the new `fuzz_normalize` (see the spec finding below): it was a wrong assertion in the harness, the target was corrected and re-run clean. "cov" is libFuzzer's edge coverage; the audit's numbers (no seeds, 120 s) are given for comparison.

| Target | Audit cov | cov at start (seeds) | cov at end | Executions |
|---|---|---|---|---|
| `fuzz_header` | 170 | 124 | 170 | 10,874,656 |
| `fuzz_slot_block` | 40 | 1,859 | 1,870 | 1,038 (≈ 14/s: every input runs 16 X-Wing decapsulations and, when trial-open succeeds, 16 re-encapsulations) |
| `fuzz_envelope_parse` | 126 | 2,322 | 2,462 | 91,474 |
| `fuzz_stanza` | 64 | 1,926 | 1,987 | 267,979 |
| `fuzz_record` | 535 | 518 | 571 | 410,940 |
| `fuzz_stream_decrypt` | 586 | 636 | 701 | 146,879 |
| `fuzz_hpke_open` (new) | — | 1,276 | 1,288 | 7,746 |
| `fuzz_recipient_entry` (new) | — | 205 | 212 | 2,604,585 |
| `fuzz_normalize` (new) | — | 504 | 623 | 247,019 |

### Spec finding: §11.3 normalization is not idempotent for some non-ASCII input

`fuzz_normalize` found that `normalize(normalize(p)) ≠ normalize(p)` for inputs such as `U+0130 U+031F`: NFKC runs before lowercasing, and the full lowercase mapping of U+0130 (`i U+0307`) followed by a combining mark of lower canonical class (U+031F, ccc 220) is not in NFKC order, so a second pass reorders it. The previous implementation behaves identically (the fixed-buffer version is byte-identical to it, proven by `normalize_matches_reference`). Derivation is unaffected for wordlist passphrases (ASCII after normalization, where idempotence holds and is fuzzed), and the implementation keeps the spec's definition so that keys stay reproducible. **Proposed amendment** (04 §11.3, ST-053): define `normalize = separators ∘ NFKC ∘ lowercase ∘ NFKC` (or Unicode `toNFKC_Casefold`), which is idempotent; ST-053 should state idempotence only for that definition.

### Security self-review (AUD-RM1-CORE fixes)

Reviewed the diff as an attacker (OWASP ASVS 5.0 L3 mindset):
- **Secrets:** every new type holding CK-equivalent or seed-equivalent bytes (`RecipientListEntry`, `RecipientList`, `SealSecrets`, `SessionKey`, `Argon2Arena`, passphrase intermediates) zeroizes on drop, has no `Clone` and a redacted `Debug`; no new `Display`; error strings stay static. The new `Debug` of `SealedObject`/`ParsedObject` prints only the object type and lengths.
- **Nonce reuse:** no public API can choose a STREAM key or nonce; a `PartId` yields one encryptor. Sealer variant hunt remains for the RM-2 audit (its current code no longer compiles against this API and must migrate per README).
- **Hostile input:** new parsers (`RecipientListEntry::from_bytes`, slot-block entry tails in fuzzers) use `Reader`/checked lengths; `normalize` refuses > 1,024 bytes before allocating and never grows a buffer; `Wordlist::check` work is bounded by `word_count × N`.
- **Fail closed:** stuck RNG → `Error::Rng`; Argon2 allocation failure → `Error::PasswordHash`; over-capacity normalization → `Error::Length`; slot context mismatch → refuse to seal.
- **Timing:** comparisons on secrets use `subtle`; measured by `ct_timing` (|t| ≤ 2.05). `verify_slot_block`'s new duplicate-`key_id` check runs on the (CK-holder-visible) list and is not secret-dependent.
- **Dependencies:** no new crates; `sha2`/`blake3` gain their `zeroize` features; `x25519-dalek` is a dev-dependency already in the lockfile.
- **Residual risk:** memory locking is the process's job (CORE-02); compiler stack temporaries and `unicode-normalization`'s spill buffer are not wiped (CORE-03/07); CORE-13 typestate, CORE-15 AAD v2 and CORE-16(a) CBOR decoder are deferred as recorded above; ST-027 zeroization scan is not automated.

Miri (`nightly-2026-09-28`, `MIRIFLAGS=-Zmiri-disable-isolation PROPTEST_CASES=4`): 37 decoder/parser tests (`bytes`, `header`, `labels`, `padding`, `rand`, `record`, `secret`, `suite`, `stream` incl. `arbitrary_ct`/`staged_part_id_is_single_use`, `passphrase` normalization/lowercase/over-long) passed with no UB reported (2,284 s). X-Wing/Argon2-heavy tests were excluded as infeasible under Miri.
