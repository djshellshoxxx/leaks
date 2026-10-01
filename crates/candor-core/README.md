<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
# candor-core

`candor-core` is Candor's shared cryptographic library (component C-11). It implements suite **CANDOR-STD-1** from `specs/04-CRYPTOGRAPHY.md`:
- HPKE RFC 9180 base mode with X-Wing (KEM `0x647a`) / HKDF-SHA256 / ChaCha20-Poly1305;
- 64 KiB ChaCha20-Poly1305 STREAM payloads;
- XChaCha20-Poly1305 encrypted records;
- HMAC-SHA-256 key commitment;
- Ed25519 signatures;
- Argon2id source passphrases.

`CANDOR-FIPS-1` is recognised and rejected with `Error::UnsupportedSuite`.

Licence: Apache-2.0 OR MIT (ADR-031). No `unsafe`. Secrets zeroize on drop and are never printed. MAC and tag checks are constant-time. Parsers never panic on hostile input.

## Modules

| Module | Spec | Provides |
|---|---|---|
| `suite` | §4 | `Suite` ids, sizes |
| `labels` | §10 | the registry of every `candor/...` label (tests reject duplicates and unregistered literals) |
| `passphrase` | §11.1–11.3 | EFF wordlist, `generate`, `normalize` (NFKC/lowercase/separators; fixed buffers, ≤ 1,024-byte input), constant-time `Wordlist::check`, `SourceKeys::derive` / `derive_in(&mut Argon2Arena, …)`: Argon2id m=64 MiB t=3 p=1 → `lookup_id`/`lookup_tag`, Ed25519 auth/sign keys, X-Wing `src_sk`/`src_pk`, `mailbox_id(i)`, `K_prefs` |
| `header` | §13.1 | `CoreHeader` 128-byte encode/decode/validate, `header_mac`, `object_hash` |
| `slots` | §13.2, ADR-050 | `RecipientSlotBlock`: 16 anonymous slots, verifiable dummies, secret `RecipientListEntry` / `RecipientList` (CK-equivalent; serialize only into the encrypted Recipient List), `trial_open`, `verify_slot_block` (re-derives all 16 slots) |
| `stanza` | §13.2 | `WrapStanza`: HPKE_BASE (all §9.9 contexts), CASE_AEAD, CASEKEY_EK |
| `stream` | §13.3 | `StreamEncryptor::for_payload` / `for_staged_part` (no raw-key or caller-nonce constructor), buffered `decrypt`/`decrypt_with`, `StreamDecryptor` (`new`, `for_payload`, `for_staged_part`)/`ChunkReader` with explicit `finish()` |
| `padding` | §13.6 | buckets, `pad` |
| `record` | §13.8 | `seal_record` / `open_record` with the §9.9 AAD forms |
| `hash` | §13.2, ADR-012 | `key_id`, `lookup_tag`, bound hashes, `EvidenceHasher` (SHA-256 + BLAKE3) |
| `kdf` | §10 | named derivations (payload, header-mac, case record/wrap, EK layer/meta, COI, stage part) |
| `kem`, `sig` | §4 | X-Wing keys, `seal_base`/`open_base`, Ed25519 strict |
| `object` | §13.1–13.3 | `seal` → `(SealSecrets, SealedObject)` (payload builder receives header and Recipient List) / `seal_with_ck` / `seal_bytes` (non-intake) / `parse` → `slot_binding_from_header` / `open` / `open_bounded` / `open_stream` (validate → length → MAC → payload) |
| `selftest` | §22.2 | `self_test()`: start-up KATs; call it at process start and refuse to start on error |

## Example

```rust
use candor_core::{Suite, header::ObjectType, kem::KemKeyPair, object, padding, slots::SlotContext};

let member = KemKeyPair::generate(Suite::CandorStd1)?;
let ctx = SlotContext::MemberEpoch { tenant_id: [1; 16], channel_id: [2; 16], epoch_id: 7 };
let pks = [member.public.clone()];
let req = object::SealRequest {
    suite: Suite::CandorStd1, object_type: ObjectType::Submission,
    tenant_id: [1; 16], channel_id: [2; 16], epoch_id: 7, day_stamp: 0,
    recipients: Some((ctx.clone(), &pks)), padded_len: 4096,
};
// The builder sees the final header and the Recipient List entries (ADR-050(3))
// and returns the padded inner plaintext that embeds the signed Recipient List.
// The entries are CK-equivalent secrets: encode them (entry.to_bytes()) only into the
// signed, encrypted Recipient List; never log or store them elsewhere.
let (secrets, sealed) = object::seal(&req, |pc| {
    let inner = build_inner_cbor(pc.header, pc.recipient_list); // caller's §13.4 encoder
    padding::pad(ObjectType::Submission, &inner)
})?;
// Recipient side:
let parsed = object::parse(&sealed.bytes)?;
let block = sealed.slot_block.as_ref().unwrap();
parsed.check_slot_block(block)?;
let binding = parsed.slot_binding_from_header()?; // context derived from the header
let (ck, _pos) = block.trial_open(&member.private, &binding)?;
let plaintext = parsed.open(&ck)?;
let list = /* RecipientListEntry::from_bytes(..) for each entry of the verified plaintext */;
block.verify_slot_block(&ck, &binding, &list, |key_id| key_directory.lookup(key_id))?;
```

## Tests and vectors

```
cargo test -p candor-core                                            # unit, KAT, Wycheproof, vectors, properties, ct_timing
cargo test -p candor-core --test ct_timing -- --nocapture            # dudect-style timing test alone (CANDOR_SKIP_CT_TIMING=1 skips it)
CANDOR_REGEN_VECTORS=1 cargo test -p candor-core --lib vectors       # regenerate tests/vectors/*.json and fuzz/seeds/
cd crates/candor-core
t=fuzz_envelope_parse
mkdir -p fuzz/corpus/$t && cp fuzz/seeds/$t/* fuzz/corpus/$t/     # seed the (gitignored) corpus
cargo +nightly fuzz run $t -- -max_len=70000 -max_total_time=60
```

The committed seeds in `fuzz/seeds/<target>/` are valid inputs under the fixed keys in `fuzz/fuzz_targets/common.rs` (generated by `vectors::fuzz_seeds`); `fuzz/corpus/` and `fuzz/artifacts/` are gitignored, so copy the seeds into the corpus before every run (CI must do the same). `-max_len` per target: `fuzz_header` 256, `fuzz_slot_block` 20500, `fuzz_envelope_parse` 70000, `fuzz_stanza` 70000, `fuzz_record` 4096, `fuzz_stream_decrypt` 140000, `fuzz_hpke_open` 4096, `fuzz_recipient_entry` 128, `fuzz_normalize` 4096.

- `tests/vectors/kat/` holds the X-Wing draft, hpke-pq 0x647a and RFC 9180 vectors.
- `tests/vectors/*.json` holds the deterministic Candor format vectors for other implementations (positive and negative).
- `tests/vectors/wycheproof/` holds pinned Wycheproof vectors (ST-023).
- Fuzz targets: `fuzz_header`, `fuzz_slot_block`, `fuzz_stanza`, `fuzz_record`, `fuzz_envelope_parse`, `fuzz_stream_decrypt`, `fuzz_hpke_open`, `fuzz_recipient_entry` and `fuzz_normalize`.

## API changes from the AUD-RM1-CORE fixes (migration for candor-sealer and other callers)

| Before | Now |
|---|---|
| `StreamEncryptor::new(key, len)`, `stream::encrypt(key, pt)`, `kdf::derive_payload_key`, `kdf::derive_stage_part_key` (public) | Removed / crate-private. Encrypt with `let (enc, payload_nonce) = StreamEncryptor::for_payload(suite, &ck, padded_len)?;` (nonce drawn internally; put it in the CoreHeader and `SlotBinding`), or `let part_id = PartId::generate()?; let enc = StreamEncryptor::for_staged_part(&k36, &part_id, padded_len)?;` (`k36: SessionKey`; each `PartId` works once; send/store `part_id.as_bytes()`). Then `encrypt_chunk` … `finish()`, or `encrypt_all(pt)`. |
| `StreamDecryptor::new(derive_payload_key(..), len)` / `new(derive_stage_part_key(k36, id), len)` | `StreamDecryptor::for_payload(suite, &ck, &payload_nonce, len)?` / `StreamDecryptor::for_staged_part(&k36, &part_id_bytes, len)?` (`new(AeadKey, len)` stays for decryption). |
| `k36: Secret32` | `secret::SessionKey` (`SessionKey::generate()`). |
| `object::seal` → `(ContentKey, SealedObject)`; `SealedObject.recipient_list` | `seal` → `(SealSecrets, SealedObject)`; `secrets.ck()`, `secrets.recipient_list().as_slice()`, `secrets.into_parts()`. `seal_with_ck` → `(RecipientList, SealedObject)`. `SealedObject` has no entries and no `Debug` content. |
| `RecipientSlotBlock::build` → `Vec<RecipientListEntry>` | → `RecipientList` (`as_slice()`); recipients must be distinct; a custodian context takes at most one recipient. |
| `RecipientListEntry` public fields, `Clone`, `PartialEq`, `to_bytes() -> [u8; 97]` | Private fields; `slot_index()`, `key_id()`, `ct_eq()`, `to_bytes() -> Zeroizing<[u8; 97]>`; not `Clone`. |
| `object::seal*` with any slot context | The context must match the object type (IDENTITY ⇔ custodian) and the header tenant/channel/epoch. Recipients can use `ParsedObject::slot_binding_from_header()`. |
| `passphrase::normalize(p) -> Zeroizing<String>` | `-> Result<Zeroizing<String>>` (`Error::Length` above 1,024 bytes); `SourceKeys::derive` fails the same way. Long-lived processes: `SourceKeys::derive_in(&mut Argon2Arena::new()?, …)` with a reused arena. |
| `KemPublicKey::from_bytes` | Also rejects X25519 components that are non-canonical or of low order (`Error::InvalidKey`). |
| `Debug` of `EvidenceHashes`, `HpkeWrapContext`, `RecordAad`, `ParsedObject`, `SealedObject` | Redacted. |

Read `SPEC-NOTES.md` before relying on anything. It covers the spec findings, notably the dummy-slot randomness expansion and the 4 hyphenated EFF words. It also covers the implementation decisions, the wordlist and KAT provenance, and the dependency justifications.
