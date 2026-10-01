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
| `passphrase` | §11.1–11.3 | EFF wordlist, `generate`, `normalize` (NFKC/lowercase/separators), `SourceKeys::derive`: Argon2id m=64 MiB t=3 p=1 → `lookup_id`/`lookup_tag`, Ed25519 auth/sign keys, X-Wing `src_sk`/`src_pk`, `mailbox_id(i)`, `K_prefs` |
| `header` | §13.1 | `CoreHeader` 128-byte encode/decode/validate, `header_mac`, `object_hash` |
| `slots` | §13.2 | `RecipientSlotBlock`: 16 anonymous slots, verifiable dummies, `trial_open`, `verify` |
| `stanza` | §13.2 | `WrapStanza`: HPKE_BASE (all §9.9 contexts), CASE_AEAD, CASEKEY_EK |
| `stream` | §13.3 | `encrypt`, buffered `decrypt`, `StreamDecryptor`/`ChunkReader` with explicit `finish()` |
| `padding` | §13.6 | buckets, `pad` |
| `record` | §13.8 | `seal_record` / `open_record` with the §9.9 AAD forms |
| `hash` | §13.2, ADR-012 | `key_id`, `lookup_tag`, bound hashes, `EvidenceHasher` (SHA-256 + BLAKE3) |
| `kdf` | §10 | named derivations (payload, header-mac, case record/wrap, EK layer/meta, COI, stage part) |
| `kem`, `sig` | §4 | X-Wing keys, `seal_base`/`open_base`, Ed25519 strict |
| `object` | §13.1–13.3 | `seal` / `parse` → `open` / `open_stream` (validate → length → MAC → payload) |
| `selftest` | §22.2 | `self_test()`: start-up KATs; call it at process start and refuse to start on error |

## Example

```rust
use candor_core::{Suite, header::ObjectType, kem::KemKeyPair, object, padding, slots::SlotContext};

let member = KemKeyPair::generate(Suite::CandorStd1)?;
let ctx = SlotContext::MemberEpoch { tenant_id: [1; 16], channel_id: [2; 16], epoch_id: 7 };
let pt = padding::pad(ObjectType::Submission, b"...inner CBOR with u32 length prefix...")?;
let pks = [member.public.clone()];
let (_ck, sealed) = object::seal(&object::SealRequest {
    suite: Suite::CandorStd1, object_type: ObjectType::Submission,
    tenant_id: [1; 16], channel_id: [2; 16], epoch_id: 7, day_stamp: 0,
    recipients: Some((ctx.clone(), &pks)), padded_plaintext: &pt,
})?;
// Recipient side:
let parsed = object::parse(&sealed.bytes)?;
let block = sealed.slot_block.as_ref().unwrap();
parsed.check_slot_block(block)?;
let (ck, pos) = block.trial_open(&member.private, &parsed.slot_binding(ctx.clone()))?;
block.verify(&ck, &parsed.slot_binding(ctx), /* Recipient List length */ 1, Some(pos))?;
let plaintext = parsed.open(&ck)?;
```

## Tests and vectors

```
cargo test -p candor-core                                            # unit, KAT, vectors, properties
CANDOR_REGEN_VECTORS=1 cargo test -p candor-core --lib vectors       # regenerate tests/vectors/*.json
cd crates/candor-core && cargo +nightly fuzz run fuzz_envelope_parse # fuzz targets in fuzz/
```

- `tests/vectors/kat/` holds the X-Wing draft, hpke-pq 0x647a and RFC 9180 vectors.
- `tests/vectors/*.json` holds the deterministic Candor format vectors for other implementations (positive and negative).
- Fuzz targets: `fuzz_header`, `fuzz_slot_block`, `fuzz_stanza`, `fuzz_record`, `fuzz_envelope_parse` and `fuzz_stream_decrypt`.

Read `SPEC-NOTES.md` before relying on anything. It covers the spec findings, notably the dummy-slot randomness expansion and the 4 hyphenated EFF words. It also covers the implementation decisions, the wordlist and KAT provenance, and the dependency justifications.
