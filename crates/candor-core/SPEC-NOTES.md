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
  - The output is zeroized on drop.
- **Argon2id** parameters are fixed constants. The parameterised derivation is `pub(crate)`, so callers cannot lower them (CRYPTO-043). Memory-allocation failure returns `Error::PasswordHash` (fail closed).
- **Randomness (§23.4, CRYPTO-033):**
  - All randomness comes from `getrandom::fill`, with any error propagated. A draw of ≥ 16 bytes that is all-zero is treated as an RNG failure.
  - HPKE encapsulation randomness (64 bytes) is pre-drawn from `getrandom` and fed through `ExactBytesRng`, so `hpke`'s infallible RNG interface never panics or invents bytes.
  - `rand_chacha` is used only as the deterministic expansion inside `slots::dummy_slot` and as `TestRng` under `cfg(test)`. The CI `rng-ban` rule must allow-list those two sites.
- **Secrets:**
  - `ContentKey`, `CaseKey`, `ErasureKey`, `AeadKey`, `MacKey`, `Secret32`, `KemPrivateKey`, `SigningKey`, `SourceKeys` and `Passphrase` zeroize on drop. They have no `Clone`, a redacted `Debug` and no `Display`.
  - `lookup_id` is treated as secret.
  - Error messages are static.
- **Key generation and self-test:**
  - `KemKeyPair::generate` runs a pairwise-consistency test (encapsulate, decapsulate, compare; CRYPTO-036).
  - `selftest::self_test()` runs these KATs: SHA-256, BLAKE3, HMAC, HKDF, ChaCha20-Poly1305, XChaCha20-Poly1305, Ed25519, X-Wing, Argon2id (RFC 9106). It also runs an RNG health check.
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
| `sha2` | =0.11.0 | SHA-256 content ids, `key_id`, salts, evidence hash. |
| `blake3` | =1.8.2 | BLAKE3 evidence hash (ADR-012); pinned to match `candor-safefs`. |
| `ed25519-dalek` | =3.0.0 | Ed25519 source keys and strict verification. |
| `argon2` | =0.6.0 (`alloc`, `zeroize`) | Argon2id passphrase stretching (ADR-046(7)). |
| `getrandom` | =0.4.3 | The sole OS CSPRNG (§23.4); same major as `hpke`. |
| `rand_chacha` | =0.10.0 | Deterministic dummy-slot randomness expansion (brief-mandated; see finding 1). |
| `subtle` | =2.6.1 | Constant-time comparisons. |
| `zeroize` | =1.8.2 | Secret zeroization; workspace-aligned pin. |
| `unicode-normalization` | =0.1.24 | NFKC for §11.3; workspace-aligned pin. |
| `proptest` | =1.11.0 (dev) | Property tests (lead-mandated workspace pin). |
| `serde`, `serde_json`, `hex` | dev | Read and write the JSON vector files. |
| `chacha20` | =0.10.2 (dev) | Proves the ChaCha20 expansion equals the raw keystream. |
| `libfuzzer-sys` | =0.4.10 | Fuzz harness only, in the separate `fuzz/` workspace. |
