# 04 — Cryptographic Design Specification
Status: Draft v1.1 (round-2 revision: ADR-034..046) · Edition applicability: both (CE and EE identical in all trust-path cryptography; EE adds HSM/PKCS#11 options and the FIPS profile) · Owner: Cryptography & Protocols team

## 1. Purpose and scope

This document fixes every cryptographic primitive, parameter, key, wire format and key-lifecycle procedure used by Candor, so that the crypto library (C-11), the intake services (C-06/C-07/C-08), the core services (C-09..C-14, C-24), Candor Desk (C-15), the Candor Source App (C-03), backups (C-27), recovery (C-28) and HSM integration (C-29) can be built by separate teams without inventing cryptographic decisions.

In scope: primitive selection and suites (ADR-006); transport encryption (onion, internal TLS/mTLS); application-layer envelope encryption; at-rest encryption and its limits; AEAD and key commitment; the key hierarchy (ADR-005, ADR-007, ADR-008, ADR-013, ADR-014); KDFs and password hashing; source passphrase scheme; rotation, forward secrecy, recovery, backup encryption, cryptographic erasure (ADR-025); compromise analysis; HSM/TPM; threshold schemes; byte-level wire formats (envelope, STREAM, message, reply, key directory and transparency log); the server-delivered-code problem (ADR-004); sequence diagrams; formal verification, KATs, constant-time, zeroization and RNG requirements.

Out of scope (referenced): authentication protocols and session tokens (15-AUTHENTICATION-AUTHORIZATION.md), Tor configuration (16-TOR-I2P.md), release signing and TUF (33-RELEASE-UPDATE-SECURITY.md), file parsing/sanitization (10-FILE-EVIDENCE-PIPELINE.md), backup operations (19-BACKUPS-DR.md), retention clocks (35-DATA-RETENTION-DELETION.md).

**Protection statement form (DECISIONS §0).** Every claim below names what is protected, from whom, under which assumptions, and the residual risk. Local assumption labels `CA-n` (§3.4) are to be registered as `ASM-*` in 40-SECURITY-ASSUMPTIONS.md.

## 2. Context and dependencies

| Document | Dependency |
|---|---|
| DECISIONS.md | ADR-004/005/006/007/008/009/010/011/013/014/020/022/025/028/030/031/032/033 are binding inputs (ADR-030 per-member epoch keys; ADR-033 anonymous recipient slots, import-gated epoch retirement, Erasure Key vault, viewer-only attachment decryption). Round 2: ADR-034 (Tier W session key, RAM-only drafts), ADR-035 (sealer attestation, running manifest, operator statement, incident notice), ADR-036 (directory governance, time-locks, witnesses, high-water mark, independent time, follow-up sealing rule), ADR-037 (triage-first wrapping, blinded COI tags), ADR-038 (fixed import schedule, delayed delivery, undecryptable-envelope handling), ADR-039 (fetch-all reply retrieval), ADR-043 (device custody), ADR-044 (wrap-deletion cooling, ≥ 2 authenticators, GOV recovery default, EKV DR), ADR-046 (KDF parameters, FIPS PBKDF2, passphrase rotation, PQ transport residual, Intake Routing Key, Connector Key) supersede conflicting v1.0 text |
| 02-THREAT-MODEL.md | THR-007, 012, 013, 014, 015, 017, 018, 026, 030, 031, 034, 043, 044, 046 are the primary threats addressed |
| 03-PRIVACY-ANONYMITY.md | Timing (ADR-010) and size (ADR-011) metadata rules that the formats implement |
| 06-SYSTEM-ARCHITECTURE.md | Zones, Intake/Core separation (ADR-009), Transport Adapter |
| 07-BACKEND.md, 08-API.md, 09-DATABASE.md | Carry the byte formats defined here as opaque blobs; `key_wraps`, `kd_entries` tables |
| 10-FILE-EVIDENCE-PIPELINE.md | Consumes STREAM decryption output inside C-17 only |
| 11-FRONTEND-SOURCE.md | Tier W / Tier V flows, passphrase display, roster display |
| 12-FRONTEND-RECIPIENT.md | Candor Desk key store, import, re-wrap UI, log-monitor alerts |
| 14-CASE-MANAGEMENT.md | Case lifecycle events that trigger key operations |
| 15-AUTHENTICATION-AUTHORIZATION.md | Staff authentication, WebAuthn PRF, COI exclusion before wrapping (ADR-015) |
| 16-TOR-I2P.md | Onion-service key custody (THR-044) |
| 19-BACKUPS-DR.md | Erasure Key Vault own backup (≤ 14 days), backup encryption to K25 |
| 20-LOGGING-AUDITING.md | Audit checkpoint signing key; key-event audit records |
| 29-SECURITY-TESTING.md / 30-ANONYMITY-TESTING.md | Malicious-server harness, crypto test jobs |
| 33-RELEASE-UPDATE-SECURITY.md | Release keys, TUF, WEBCAT manifest keys (K26/K27 below) |
| 35-DATA-RETENTION-DELETION.md | Triggers for cryptographic erasure |

## 3. Design principles and assumptions

### 3.1 Principles
1. **Servers are not trusted with content.** No key that decrypts report content exists on any server in usable form (ADR-007, ADR-008). Tier W is the single, explicitly disclosed exception: plaintext exists transiently in C-07 RAM (ADR-004).
2. **Standard constructions only.** HPKE (RFC 9180) with hybrid PQ KEMs, age-style STREAM, HKDF, Argon2id, Ed25519, ML-DSA. The composition (envelope, directory, roster continuity) is new and is therefore formally modelled and externally reviewed before 1.0 (§22; INC-63).
3. **Hybrid post-quantum confidentiality now.** Leak material is a harvest-now-decrypt-later target (B-CR-03, B-CR-04). PQ authentication is added first for long-lived roots (B-CR-10).
4. **Everything bound to context.** Every encryption binds tenant, channel, epoch, object identity and purpose through HPKE `info`, AEAD AAD and HKDF `info` labels (INC-66, B-CR-24).
5. **Key commitment everywhere.** Every sealed object carries an HMAC commitment to its content key (B-CR-16, B-CR-17).
6. **Crypto-agility without negotiation.** Suites are identified in every header; allowed suites are pinned per tenant in the key directory; there is no in-band negotiation, so no downgrade path.
7. **Fail closed.** Missing, expired or unverifiable keys stop the operation; they never cause fallback to weaker keys, to plaintext or to server-side decryption (INC-06 lesson in R2 Hush Line: server-side fallback created a downgrade path).

### 3.2 Profiles
| Profile | Where | Primitive suite | Module |
|---|---|---|---|
| STD (default) | CE and EE | CANDOR-STD-1 (§4.1) | RustCrypto + `aws-lc-rs` (non-FIPS build) behind C-11 |
| FIPS | EE/GOV opt-in | CANDOR-FIPS-1 (§4.1) | AWS-LC FIPS 3 (CMVP #5314, ML-KEM inside boundary; B-CR-11) via `aws-lc-rs` FIPS feature |
| CNSA-2.0 (reserved) | GOV archive tier, future | CANDOR-CNSA-1 (reserved, not shipped in v1) | TBD |

A tenant's suite is fixed at tenant creation and recorded in the ORG_ROOT directory entry. Mixed-suite tenants are not supported in v1 (migration procedure §15.6).

### 3.3 CNSA 2.0 note
Candor is not a National Security System. CNSA 2.0 (B-CR-10) requires ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/512 and LMS/XMSS for firmware signing, with software/firmware signing "exclusive" by 2030. CANDOR-FIPS-1 already uses ML-KEM-1024 (hybrid with P-384), AES-256 and SHA-384. Gaps to full CNSA 2.0: (a) hybrid rather than pure ML-KEM-1024 key establishment (CNSA permits hybrids during transition — Knowledge (unverified)); (b) Ed25519/ECDSA rather than ML-DSA-87 for message/log signatures; (c) release signing uses Ed25519+ML-DSA-65 (ADR-006), not ML-DSA-87 or LMS. Suite ID `0x0003` CANDOR-CNSA-1 is reserved (ML-KEM-1024 pure or MLKEM1024-P384, AES-256-GCM, HKDF-SHA384, ML-DSA-87 for all signatures, LMS for release roots) for a later ADR.

### 3.4 Cryptographic assumptions (to be registered as ASM-* in 40)
| Label | Assumption |
|---|---|
| CA-1 | At least one of ML-KEM (FIPS 203) and X25519 (resp. ECDH P-384) is IND-CCA-secure as used in the hybrid combiner (B-CR-05, B-CR-06). |
| CA-2 | ChaCha20-Poly1305, XChaCha20-Poly1305, AES-256-GCM are secure AEADs under unique nonces; HMAC-SHA-256/384 is a PRF and collision-resistant as a commitment. |
| CA-3 | Ed25519 (RFC 8032 strict verification) and ML-DSA-65 are EUF-CMA; a hybrid signature is secure if either component is. |
| CA-4 | The OS CSPRNG (`getrandom(2)`) or the FIPS module DRBG produces unpredictable output after boot seeding, including after VM snapshot restore (mitigated §23.4). |
| CA-5 | Recipient endpoints (C-15 on C-16) are not compromised at the time they unwrap keys; hardware wrapping keys (FIDO2/PIV/TPM) resist extraction. |
| CA-6 | C-07 Intake Sealer is not live-compromised during a Tier W submission or login session (Tier W only). In the optional Confidential-VM profile (ADR-035(3)) this is weakened to "the TEE vendor and the TEE's isolation are not broken"; TEEs have a record of side-channel breaks, so this is defence in depth, never a source-facing guarantee. |
| CA-7 | For Tier V, at least one external witness (outside the operating organisation, ADR-036(5)) that cosigned the checkpoint the client accepts is honest, so a split view of the key directory is detected before sealing; in CE without external witnesses, detection falls back to Desk monitors and VR-9 at import. |
| CA-8 | Source passphrases are generated by the specified CSPRNG path and not chosen or modified by the source. |
| CA-9 | **KEM key privacy (anonymity):** an X-Wing / MLKEM1024-P384 encapsulation and the HPKE ciphertext reveal nothing about which public key they were produced for (ANO-CCA-style); required so that the 16 anonymous recipient slots do not reveal which members received an envelope (ADR-033 item 1). Knowledge (unverified): the formal key-privacy status of the hybrid combiners — including MLKEM1024-P384 used by the FIPS suite (RVW-C-15) — must be confirmed by the external review (§22); if it cannot be confirmed for MLKEM1024-P384, FIPS tenants are told that recipient anonymity of slots is unproven for their suite (OI-15). |
| CA-10 | **Independent time:** the Tor directory-authority consensus signature scheme is sound and a majority of directory authorities is not controlled by the adversary, so the signed consensus `valid-after` is a trustworthy lower bound on current time; Roughtime servers of ≥ 2 independent operators do not collude (ADR-036(6)). |

## 4. Primitive selection (ADR-006)

### 4.1 Suites
| Function | CANDOR-STD-1 (`0x0001`) | CANDOR-FIPS-1 (`0x0002`) | Rationale / evidence |
|---|---|---|---|
| Public-key encryption | HPKE RFC 9180 `mode_base`, KEM `0x647a` MLKEM768-X25519 (X-Wing) | HPKE `mode_base`, KEM `0x0051` MLKEM1024-P384 | Hybrid PQ; codepoints from draft-ietf-hpke-pq-05 (B-CR-05, B-CR-06, B-CR-07); AWS-LC FIPS 3 has ML-KEM inside boundary (B-CR-11) |
| HPKE KDF | HKDF-SHA256 (`0x0001`) | HKDF-SHA384 (`0x0002`) | RFC 9180 |
| HPKE AEAD | ChaCha20-Poly1305 (`0x0003`) | AES-256-GCM (`0x0002`) | RFC 9180 |
| Payload STREAM AEAD | ChaCha20-Poly1305, 64 KiB chunks (age-style) | AES-256-GCM, 64 KiB chunks, same nonce layout | B-CR-14; per-object derived key makes counter nonces safe |
| Record AEAD (DB fields, wraps) | XChaCha20-Poly1305, random 192-bit nonce | AES-256-GCM, random 96-bit nonce, ≤2^31 encryptions per derived key (counter-enforced) | B-CR-15, B-CR-27; SP 800-38D limit (R5 §A.3) |
| Key commitment / MAC | HMAC-SHA-256 | HMAC-SHA-384 | B-CR-16, B-CR-17 |
| KDF | HKDF-SHA256 (RFC 5869) | HKDF-SHA384 (SP 800-56C r2) | R5 §A.6 |
| Signatures (messages, directory entries, checkpoints, audit) | Ed25519 (RFC 8032, strict) | Ed25519 (FIPS 186-5) if inside the validated boundary of the deployed module, else ECDSA P-384 (UNVERIFIED which applies to AWS-LC FIPS 3; decided at build per certificate) | B-CR-01 context, R5 §A.2 |
| Long-lived root signatures (ORG_ROOT, release roots) | Ed25519 + ML-DSA-65, both REQUIRED | ECDSA P-384 or Ed25519 + ML-DSA-65 (ML-DSA-87 when CNSA profile ships) | ADR-006; B-CR-10 |
| Hash (content IDs, Merkle trees) | SHA-256; evidence hashes SHA-256 + BLAKE3 (ADR-012) | SHA-384 for Merkle trees; evidence SHA-256 + SHA-384 (BLAKE3 recorded but not relied on for FIPS claims) | ADR-012 |
| Source passphrase stretching | Argon2id m=64 MiB (65536 KiB), t=3, p=1, 32-byte output (ADR-046(7)) | PBKDF2-HMAC-SHA-512, 210,000 iterations, 32-byte output (ADR-046(7)) | ADR-005/006/046; B-CR-19, B-CR-20, B-CR-27. Security rests on ≈ 129-bit passphrase entropy (§11.2); stretching is defence in depth |
| Staff software-fallback passphrase (CE only) | Argon2id m=256 MiB, t=3, p=4 | PBKDF2-HMAC-SHA-512 ≥600,000 | B-CR-19 |
| Staff server-side password verifier (if passwords used at all, 15) | Argon2id m=64 MiB, t=3, p=4 + HMAC pepper in C-29 | PBKDF2-HMAC-SHA-512 ≥600,000 + HMAC pepper | B-CR-19, B-CR-20; OPAQUE RFC 9807 optional (B-CR-21) |
| Key wrap (symmetric) | XChaCha20-Poly1305 AEAD wrap (not RFC 3394) | AES-256-GCM AEAD wrap (AES-KW RFC 3394 accepted only inside HSM PKCS#11 `CKM_AES_KEY_WRAP_KWP`) | AEAD wrap allows AAD binding (INC-66) |
| Threshold | Shamir over GF(2^8) (offline, reconstruct-on-air-gap); explicit k-of-n multi-signatures; FROST(Ed25519, SHA-512) RFC 9591 optional | Same; FROST not used in FIPS profile | B-CR-29, R5 §A.9 |
| Transport (internal) | TLS 1.3; groups X25519MLKEM768, then X25519 | TLS 1.3; SecP384r1MLKEM1024 (if supported) then SecP256r1MLKEM768 then secp384r1 | B-CR-08 (RFC number UNVERIFIED) |
| RNG | `getrandom(2)` via `rand_core::OsRng` | Module DRBG (SP 800-90A) seeded from OS | INC-50, INC-51 |

### 4.2 Parameter sizes (C-11 constants; verified by KATs)
| Item | STD | FIPS |
|---|---|---|
| HPKE `Nenc` (encapsulated key) | 1120 B | 1665 B (1568 ML-KEM-1024 ct + 97 B uncompressed P-384 point) |
| HPKE `Npk` | 1216 B | 1665 B (1568 + 97) |
| HPKE `Nsk` (stored private seed) | 32 B | 32 B seed (per concrete-hybrid-kems draft; UNVERIFIED — C-11 SHALL take sizes from the KAT-validated implementation, not from this table) |
| AEAD key / tag | 32 B / 16 B | 32 B / 16 B |
| HMAC output | 32 B | 48 B |
| Ed25519 pk / sig | 32 B / 64 B | same (or P-384: 97 B / 96 B raw r‖s) |
| ML-DSA-65 pk / sig | 1952 B / 3309 B | same |
| Content key (CK), Case Key | 32 B | 32 B |

### 4.3 Rejected options
| Option | Reason |
|---|---|
| OpenPGP (SecureDrop classic) | Server-side encryption of plaintext, per-source server-held keys, no PQ in deployed profiles, complex parser surface (R1 §5 item 1; INC-65 Efail) |
| libsodium sealed boxes (GlobaLeaks, CoverDrop) | No PQ, no key commitment in multi-recipient box (B-CR-27; R2 §1.3) |
| HPKE `mode_auth` / `mode_auth_psk` for source→recipient | Would require a source static key visible in the key schedule; KCI noted for AuthPSK (B-CR-24). Source authentication is done by a signature inside the ciphertext instead (§13.4) |
| AES-GCM-SIV | Not key-committing; not FIPS-approved mode (R5 §A.3) |
| Pure ML-KEM | Loses classical security if ML-KEM implementation or analysis fails; hybrid preferred (B-CR-06) |
| Server-side KMS-held content keys | Violates ADR-007; compellable (INC-02 Lavabit, INC-01 Hushmail) |
| Custom AEAD/KDF/stream constructions | INC-63, INC-64 |

## 5. Encryption in transit

### 5.1 Source ↔ Intake Gateway (C-02/C-03 → C-05)
- **Layer 1 — Tor v3 onion service** (details 16-TOR-I2P.md). Client and service authenticate via the self-authenticating ed25519 onion address; the rendezvous circuit gives end-to-end encryption between the Tor client and the tor daemon on C-05. Protects: source IP from Candor and hosting provider (THR-001), content confidentiality against relays. Assumption: Tor circuit cryptography. **Residual (ADR-046(8), RVW-A-11): Tor's circuit and onion-service handshakes are classical (X25519-based; Knowledge (unverified) that no PQ handshake is deployed network-wide as of 2026-09), so a recorded Tier W session — report plaintext, attachments and, at login, the passphrase — is exposed to a harvest-now-decrypt-later adversary with a future quantum computer who also breaks each onion layer. Because a captured passphrase gives access to replies still stored and to impersonation, the exposure outlives the session; passphrase rotation (§11.7) and the 30-day reply window (ADR-039) bound it. Tier V content and Tier V credentials never cross the network outside end-to-end hybrid-PQ HPKE and are not exposed this way; HIGH-risk guidance (05, 11) therefore recommends Tier V. Candor adopts PQ onion handshakes when Tor ships them (16 §9.4).**
- **Layer 2 — Optional onion HTTPS** (profile setting `onion_tls`, default OFF in CE; default ON for HIGH/GOV profiles whenever a CA-issued `.onion` certificate is obtainable, RVW-A-11): TLS 1.3 terminated in C-06 with PQ hybrid group `X25519MLKEM768` offered first. Purpose: adds PQ confidentiality to Tier W transit when the source's Tor Browser supports the hybrid group (Knowledge (unverified): Firefox ESR-based Tor Browser supports `X25519MLKEM768`). Costs: CA issuance publicly links the organisation to the onion address in CT logs (usually already public for an intake address); CA dependency; certificate renewal. The onion address remains the identity anchor; TLS failure never causes fallback to plain HTTP when `onion_tls` is ON (HSTS on the onion origin).
- **Layer 3 — Application encryption.** Tier V: HPKE to the eligible Triage Set members' Member Epoch Keys before upload (§9.5, ADR-037). Tier W: C-07 holds the draft in RAM and staged parts under the session key K36 and seals to the final recipient set only at Submit (§12.3, ADR-034).

### 5.2 Internal links (TLS 1.3 / mTLS)
| Link | Initiator → listener | Protocol | Authentication | Notes |
|---|---|---|---|---|
| Intake Relay pull/push | C-09 (Z-CORE) → C-08 export endpoint (Z-INTAKE, internal NIC only) | TLS 1.3, mTLS | Relay client cert (SPKI pinned in C-08 config); C-08 server cert (SPKI pinned in C-09 config) | ADR-009: Z-INTAKE never initiates; C-08 listener accepts only the pinned relay SPKI and only from the relay host address |
| Z-CORE service mesh | C-10, C-14, C-21, C-23, C-24 ↔ each other and C-12/C-13 | TLS 1.3, mTLS | Internal CA (K18) leaf certs, 7-day lifetime | PostgreSQL `sslmode=verify-full` with client certs; S3-compatible blob store over TLS 1.3 with mTLS or SigV4 over TLS |
| Candor Desk ↔ Z-CORE API | C-15 → C-10 (desk-api) | TLS 1.3 (or over staff onion with client auth, 16) | Server SPKI pinned at Desk enrollment; staff auth per 15 (WebAuthn) | No WebPKI dependency; pin rotation via signed KD entry |
| Admin console ↔ Z-CORE admin API | C-19 → C-10/C-21 | TLS 1.3 | SPKI pin + admin auth (15) | |
| Monitor | C-25 ← metrics pull from hosts | TLS 1.3 mTLS | Internal CA | Pull only; allow-listed counters (20) |
| Backup | C-27 agent → backup store | TLS 1.3 mTLS | Internal CA | Payload already encrypted (§17) |
| SIEM export (EE) | C-26 → customer SIEM | TLS 1.3 | Customer CA | Scrubbed events only (ADR-016) |

TLS parameters (all internal links): TLS 1.3 only; cipher suites `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` (STD) / `TLS_AES_256_GCM_SHA384` (FIPS); key-exchange groups per §4.1; no PSK resumption across hosts (0-RTT disabled); certificates Ed25519 (STD) or ECDSA P-384 (FIPS); OCSP not used — short lifetimes instead; SNI and ALPN (`h2`, `http/1.1`) fixed. Libraries: `rustls` with `aws-lc-rs` provider.

## 6. Application-layer encryption overview

```
Source (Tier V client or C-07 for Tier W)
  └─ per object: random Content Key CK (256-bit)
       ├─ payload  = STREAM_AEAD(K_pay = HKDF(CK, payload_nonce, "candor/v1/payload"), padded plaintext)
       ├─ slots    = 16 anonymous HPKE slots: one per eligible **Triage Set** member (after the source's COI ticks
       │             and the CIK-signed COI_POLICY, ADR-030/037) sealed to that member's current Member Epoch Key (MEK);
       │             follow-ups: only members of the original report's eligible set that are still members (ADR-036(4));
       │             remaining slots are verifiable dummies; random order
       ├─ commit   = HMAC(K_mac = HKDF(CK, object_id, "candor/v1/header-mac"), CoreHeader incl. H(slot block))
       └─ inside payload: signed Recipient List (real recipient MEK key IDs + directory checkpoint) (ADR-033)
Triage Set member's Candor Desk on import (trial-decrypts the 16 slots with its MEK private key)
  └─ CK re-wrapped: AEAD(Case Key v, CK, aad = case/object context)   [blob unchanged]
Case Key v ── HPKE-wrapped first to the importing Triage Set members, later by the Triage Set to further investigators
              after COI assessment (ADR-037(2)) and optionally to the Recovery Quorum Key; every such HPKE wrap is then
              encrypted under the per-case Erasure Key (EK) held in the Erasure Key Vault — EK is an OUTER layer only;
              no direct wrap of a case key under EK exists (§9.10)
COI exclusions ── stored server-side only as blinded tags HMAC(K_case_excl, user_id), K_case_excl from the Case Key (§9.11)
User Encryption Key / MEK private ── only on the member's endpoint, sealed by a hardware wrapping key (FIDO2 PRF / PIV / TPM)
Attachments: payload decrypted only inside C-17 with a single-use per-job key (ADR-033 item 5)
Replies: new CK, payload as above, wrap₁ = HPKE to Source X-Wing key, wrap₂ = AEAD under Case Key; routing to the
         source's mailbox via routing_ct sealed to the Intake Routing Key K37 (§9.12); Tier V sources fetch ALL
         replies of the last 30 days and trial-decrypt locally (ADR-039, §11.5)
```

Only the key wraps change over an object's lifetime; ciphertext blobs are immutable (enables cheap membership changes, rotation and erasure).

## 7. Encryption at rest — and why it is not the content layer

| Layer | Mechanism | Protects | Against | Does NOT protect against |
|---|---|---|---|---|
| L0 Content | Envelope encryption §9 (keys only on endpoints) | Report content, messages, files, case notes, identity data | Server compromise, DB/blob theft, backups, admins, hosting provider, compelled operator (THR-013/014/015/018/026/030) | Compromised recipient endpoint; Tier W live sealer compromise |
| L1 Media | LUKS2 on every server volume (`aes-xts-plain64`, 512-bit key, `--pbkdf argon2id`), unattended unlock via TPM2-sealed keyslot (PCR policy per 17) or Clevis/Tang NBDE; recovery passphrase keyslot held offline | Plaintext infra metadata (workflow fields, account records, logs), onion keys at rest, TLS keys, swap (if any) | Theft of powered-off disks, decommissioned drives (THR-031) | A running/compromised host (keys in kernel memory), hypervisor snapshots of a running VM (THR-030), compelled operator, backups (separate) |
| L2 DB | PostgreSQL TDE or column encryption (optional, EE) keyed from C-29 | Same as L1 for DB files | Storage-array or DB-file theft | Anything with DB credentials |
| L3 Intake Store | Sealed envelopes (L0) + source account records containing only `lookup_tag`, `auth_pk`, mailbox IDs | — | — | — |

**Why disk encryption is not the content layer:** a server that boots unattended must be able to unlock its disks, so the unlock key is available to anyone who controls the running server, its hypervisor, its TPM-measured boot chain or its operator under compulsion (INC-02 Lavabit: the compelled key was a server key). SecureDrop's audit found servers without FDE for exactly this reason (R1 7ASecurity SEC-01-017). Candor therefore treats L1/L2 as defence-in-depth for media and infrastructure metadata only, and no requirement may claim content confidentiality from L1/L2.

## 8. AEAD, nonces and key commitment

- **Nonce policy.** STREAM: per-object key derived from CK and a fresh 16-byte `payload_nonce`, chunk nonce = 11-byte big-endian counter ‖ 1-byte final flag (age, B-CR-14) — counter never repeats under one derived key. Records: XChaCha20-Poly1305 with random 24-byte nonces (safe for random nonces); FIPS AES-256-GCM random 12-byte nonces with a persisted per-derived-key usage counter capped at 2^31 (forces case-key version rotation long before the SP 800-38D 2^32 bound).
- **Key commitment.** Every sealed object has `header_mac = HMAC(K_mac, core_header)` where `K_mac` is derived from CK; the payload key is derived from CK. A ciphertext therefore decrypts under at most one CK (invisible-salamander resistance, B-CR-16/17). Every key-wrap record uses AEAD with AAD including the wrapped object's `object_hash`; after unwrapping, the recipient MUST verify `header_mac` before any payload decryption.
- **Why it matters here:** a malicious source or insider could otherwise craft one submission that shows different content to different recipients, to a malware scanner and to a reviewer, or that yields different evidence hashes (THR-037).
- **Release of plaintext.** No plaintext chunk is released to a consumer before its tag verifies; for files, the consumer (C-17) receives a stream whose final chunk verification failure aborts and discards all output (INC-65 Efail lesson).

## 9. Key hierarchy

### 9.1 Overview
```mermaid
flowchart TD
  ORG["K01 Org Root (Ed25519+ML-DSA-65)\noffline: Shamir 3-of-5 or HSM"] --> LOG["K02 Log Signing Key"]
  ORG --> KA["K15 Key-Admin Authorization Keys (hardware tokens)"]
  ORG --> CUST["K13 Identity Custodian Group Key"]
  ORG --> RQ["K14 Recovery Quorum Key (optional, Shamir k-of-n)"]
  ORG --> ONION["K16 onion address statement"]
  ORG --> GOV["GOVERNANCE_ROLES: OVERSIGHT, independent roles,\noperator-statement signers (K01-signed)"]
  KA -->|co-sign| CIK["K03 Channel Identity Key (Ed25519)\nheld by Triage Set + OVERSIGHT only; signs channel metadata"]
  GOV -->|certifies role labels; co-approves additions| ROSTER
  KA -->|co-sign| UK["K08/K09 User Identity + Encryption Keys"]
  CIK --> ROSTER["Channel Roster + COI policy entries"]
  UK -->|K08 signs| MEK["K04 Member Epoch Keys (X-Wing, 7-day, per member per channel)"]
  MEK -->|16 anonymous HPKE slots (Triage Set MEKs only)| CK["K05 Content Keys (per object)"]
  SESS["K36 Tier W draft session key (sealer RAM only)"] -.->|staged parts until Submit| CK
  CK -->|re-wrap on import| CASE["K06 Case Key (versioned)"]
  CASE -->|HPKE wrap inside EK layer| UK
  CASE -->|HPKE wrap inside EK layer, optional| RQ
  EK["K32 Erasure Key (per case, Erasure Key Vault)"] -.->|outer layer on member/quorum wraps| CASE
  SRC["K12 Source seed (Argon2id(passphrase))"] --> SRCK["source auth / sign / X-Wing keys"]
  SRCK -->|HPKE wrap| RCK["Reply content keys"]
  UK -->|sealed by| HW["K10 hardware wrapping key (FIDO2 PRF/PIV/TPM)"]
  CK -->|per-job HPKE to viewer VM| VJ["K34 Viewer job key (C-17, single use)"]
  CASE -->|HKDF| EXCL["K40 COI exclusion tag key (derived)"]
  RK["K37 Intake Routing Key (X-Wing, intake host)"] -.->|opens routing_ct → mailbox| RCK
  CONN["K38 Connector Key (X-Wing, integration)"] -.->|receives| EXP["Export Package CK"]
  SEAL["K35 Intake Sealer key (TEE-bound in CVM profile)"] -.->|signs Recipient Lists + running manifest| CK
```

### 9.2 Per-report / per-object keys (K05)
- Every sealed object (submission object, attachment bundle, reply, identity section, case attachment, export package) has its own CK = 32 bytes from the CSPRNG, generated where the plaintext originates (C-03, C-07 or C-15).
- CKs are never stored unwrapped outside RAM; never logged; never sent to any server unwrapped.
- A **submission** = exactly two objects: `SUBMISSION` (manifest + form answers + message; ≤64 KiB padded to 4 KiB buckets) and `ATTACHMENT_BUNDLE` (all files concatenated in one STREAM; minimum bucket 256 KiB; an empty bundle is still sent) so that the stored object count does not reveal whether or how many files were attached (ADR-011). Optional `IDENTITY` object (Confidential mode, ADR-014) is a third object, whose slot block contains one slot for K13 instead of member epoch keys; to avoid revealing mode by object count, Tier V and Tier W always send exactly one `IDENTITY` object with every initial submission — a dummy of the same bucket when no identity is given (dummy content = random bytes under a CK that is wrapped to K13 and flagged `dummy` inside the ciphertext). The importing Desk verifies this invariant (VR-9(f); RVW-A-26). Follow-up SOURCE_MESSAGEs never carry an IDENTITY object.
- The file list (display names, claimed types, sizes, hashes) travels inside the SUBMISSION object, so Candor Desk can list attachments without decrypting the ATTACHMENT_BUNDLE, whose payload is decrypted only inside C-17 (ADR-033 item 5).

### 9.3 Per-case keys (K06)
- Symmetric 256-bit, generated on Candor Desk at case creation/import. Versioned (`case_key_version` u32, starts at 1).
- **Triage-first (ADR-037(2)):** at import the Case Key is wrapped via HPKE (`CASEKEY` stanza, §13.2) only to the eligible Triage Set members of the envelope (and K14 when enabled). After the Triage Set has assessed conflicts of interest (including manager-chain checks with HR data held outside Candor), a Triage Set member's Desk wraps the Case Key to further investigators; each such grant is an audited CASE event and is refused by C-22 if the grantee's blinded tag is in the case's exclusion set (§9.11). Every wrap is stored encrypted under the case's **Erasure Key** (K32, §9.10) as an outer layer, so that destroying K32 makes every stored and backed-up wrap of the case key unreadable (ADR-033 item 3).
- **Minimum holders (ADR-044(2)):** a case SHALL have ≥ 2 key holders (`min_recipients` default 2); Desk refuses any removal or rotation that would leave fewer than 2 wraps until a replacement wrap exists (RVW-C-03).
- **Removal of wraps (ADR-044(1)):** IdP/SCIM/HR changes only **suspend** server-side delivery of a member's wraps (C-22). Deleting a member's wraps (including the old-version wraps after a rotation that excludes the member) requires dual control, a 7-day cooling-off and a content-free OVERSIGHT notice, except for source-requested erasure and retention expiry (§18). A case-key rotation to v+1 that excludes the member MAY take effect immediately (new records and CK re-wraps use v+1); the old version and the member's old wraps are destroyed only after the cooling-off.
- Used to: re-wrap object CKs (K05) on import; derive record keys for encrypted case fields: `K_rec(table) = HKDF-Expand(HKDF-Extract(salt="candor/v1/case", CaseKey_v), "candor/v1/case/record/" ‖ table_id, 32)`.
- No forward secrecy (§15.3): a case key must decrypt the whole case for its lifetime.
- Rotation to version v+1 on: member removal from case, suspected member-device compromise, 2^31 FIPS record-nonce budget, or annually for cases open >12 months. Old-version object wraps are re-wrapped to v+1 by the rotating Desk (small records only; blobs unchanged); old version is then destroyed (§18).

### 9.4 Per-user keys (K08, K09, K10, K11)
- **User Identity Key** (Ed25519, per staff user): signs the user's KD entries, roster co-signatures, case ACL grants, export approvals.
- **User Encryption Key** (X-Wing / MLKEM1024-P384 per suite): recipient of case-key wraps, CIK wraps and (for custodians) K13 wraps. Member Epoch Keys are separate keys (§9.5).
- Generated on C-15 at enrollment; private parts sealed in the Desk keystore by K11 = `HKDF(K10 output, "candor/v1/desk/keystore")` where K10 is (preference order) FIDO2 `hmac-secret`/WebAuthn PRF, PIV/smartcard decrypt of a keystore key, TPM 2.0 sealed object with PIN and PCR policy; CE software fallback: Argon2id passphrase (§4.1) with a persistent warning banner (ADR-007).
- **Authenticators and devices (ADR-044(2), RVW-C-03, RVW-C-19):** each member enrols ≥ 2 hardware authenticators (primary + stored backup). The keystore key K11 is sealed in one slot per authenticator (`K11` wrapped under `HKDF(K10_i output, "candor/v1/desk/keystore-slot")` for each authenticator i), so either token unlocks it. Up to **2 active devices** per user (primary + optional spare, e.g., an AIRGAP-RCP workstation or a spare kept by the member at a different site). Additional device = **device-link ceremony**: new Desk generates an ephemeral X-Wing key, shows its fingerprint as a 6-word SAS; old Desk verifies SAS and HPKE-seals K08/K09 and current MEK private keys to it; new Desk seals under its own K10 slots. Logged as a KD `USER_KEYS` update (device count changes are visible to all channel members).
- **Offline keystore backup (ADR-044(2)):** at enrolment and after every K09/MEK change the Desk writes an encrypted keystore backup file sealed **only** to the backup authenticator's K10 slot (Record AEAD, aad `"candor/v1/desk/keystore-backup"` ‖ user_id ‖ backup_seq); the member stores it on removable media kept with the backup authenticator. Restoring it on a new device (after reimage or loss of all devices) needs the backup authenticator plus the file, and is logged as a USER_KEYS update. MEK private keys in a backup older than their retirement are zeroized on restore; the backup file is itself a key copy and therefore an endpoint-custody residual (§27).
- **Device custody attribute (ADR-043):** USER_KEYS carries `device_custody ∈ {independent, org_managed, unknown}` and the hashes of the authenticators' attestation statements; for Triage Set members of channels of type INDEPENDENT, `org_managed`/`unknown` is shown to members, OVERSIGHT and Tier V sources, and enabling such a channel without independent custody is a DANGEROUS configuration (13/32).
- Rotation: K09 every 12 months and on suspicion: new keypair, the user's Desk re-wraps all case-key and CIK wraps addressed to the old key, old private key destroyed after re-wrap completes.

### 9.5 Channel identity keys, Triage Set and Member Epoch Keys (K03, K04; ADR-008 as amended by ADR-030/033/036/037)
- **Triage Set (ADR-037(1)):** each channel's CHANNEL_ROSTER designates a Triage Set of ≥ 2 members whose role labels are certified independent-body labels (ombudsman, audit committee, external counsel, IG, ethics officer; or channel owner + OVERSIGHT where none exist; §14.2 ROLE_LABEL_CERT). Only Triage Set members hold the `read_intake` capability; C-14 rejects a roster with fewer than 2 or more than 16 `read_intake` members, or with a `read_intake` member whose label lacks a current `independent` certification.
- **Channel Identity Key (CIK)**: Ed25519 per channel. Private key HPKE-wrapped **only** to Triage Set members and OVERSIGHT members holding `channel_admin` (ADR-036(1)); C-14 rejects a roster granting `channel_admin` to anyone else, and to any role label that appears in the channel's COI_POLICY for any category (RVW-A-05). Signs **channel metadata only**: CHANNEL_ROSTER, COI_POLICY and channel configuration entries (ADR-030). It does not sign epoch keys or replies. Certified at creation by 2 Key-Admin Authorization signatures (K15) plus the creating member's K08 and an OVERSIGHT K08; rotations additionally require a signature by the **previous** CIK (continuity rule, §14.4).
- **Member Epoch Key (MEK)**: X-Wing (STD) / MLKEM1024-P384 (FIPS) keypair **per Triage Set member, per channel, per epoch** (ADR-030, ADR-037).
  - Epoch length `E = 7 days`; epoch `n` is valid for encryption in `[start_n, start_n + 7d)`, `start_n` a UTC midnight. Decrypt window `W = 14 days` after encryption validity ends.
  - Generated on the member's own Desk; the private key **never leaves that Desk's keystore** (sealed by K11; copied only by the device-link ceremony and into the offline keystore backup, §9.4). No server holds MEK private keys in any form, and none are in server backups.
  - Published as a MEMBER_EPOCH directory entry signed by the member's K08, listed under the member's role label for that channel. Each Desk pre-publishes **4 future epochs** (ADR-030); C-14 appends submitted MEMBER_EPOCH entries only in the fixed weekly publication slot (ADR-036(7), §14.3), so publication time does not reveal when a member was online. C-25 alerts when a member has < 2 future epochs appended.
  - A MEK is usable for sealing only while its owner is in the channel's latest **active** roster (§14.4 rule 7) with the `read_intake` capability.
  - **Retirement gated on import (ADR-033 item 2, as amended by ADR-038(6)):** a MEK private key is destroyed only after BOTH `valid_until + 14 d` has passed AND every envelope stored under that epoch for the channel has been imported by some Triage Set member or rejected. Envelopes un-imported for more than 7 days raise an escalation to OVERSIGHT, the channel's independent route and C-25, rate-limited to one content-free escalation per channel per day. Envelopes that remain undecryptable or unimportable 14 days after their arrival slot MAY be rejected with dual approval (two Triage Set members, or one Triage Set member + OVERSIGHT) and are then deleted, so the epoch can retire. There is no automatic destruction without that approval (prevents suppression-by-waiting). Destruction = the Desk zeroizes the private key in its keystore (all linked devices) and publishes a content-free `MEK_RETIRED` audit record.
- A new Triage Set member publishes its own MEKs; it has no slot in, and cannot decrypt, envelopes sealed before it joined (no retroactive intake access; case access is via case keys granted by the Triage Set, ADR-015/037). Members outside the Triage Set never hold MEKs, never list pending envelopes, never receive intake notifications and never trial-decrypt (ADR-037(2)).
- **COI filter (ADR-030/037):** before sealing, the sealer (Tier V client locally; Tier W C-07 in RAM) removes from the Triage Set (1) members whose role labels the source flagged ("my report concerns: …") and (2) members listed in the channel's active COI_POLICY entry for the chosen category. If no eligible Triage Set MEK remains, the sealer does not seal and the source is directed to the channel's configured alternative independent channel (`independent_route`, §14.2), or shown "temporarily unavailable" if none is configured (fail closed).
- **Follow-up sealing rule (ADR-036(4)):** a SOURCE_MESSAGE (follow-up) is sealed only to members who were in the eligible set of the report's initial SUBMISSION **and** are still in the channel's active roster with `read_intake` and a valid current MEK. The original eligible set (user IDs) is kept in the source's `prefs_ct` (§11.4) and in the encrypted case record. Members added later obtain access only through case-key wrapping by the Triage Set (audited). If the intersection is empty, the follow-up is not sealed; the source is told that the people who received the report are no longer available and is offered a new report (which goes through normal triage). The reviewer proposal (RVW-A-06) of letting the source opt in to newly added members is not adopted, because ADR-036(4) routes later access only through the Triage Set.
- **Slot limit:** each intake envelope has exactly 16 slots (tenant-fixed; 16 default, ADR-030). C-14 rejects a roster whose `read_intake` (Triage Set) member count exceeds 16.

### 9.6 Source keys (K12; ADR-005) — see §11.

### 9.7 Identity Custodian Group Key (K13; ADR-014)
X-Wing keypair per tenant, private key HPKE-wrapped to each Identity Custodian's K09; certified by K01 (offline) and logged. `IDENTITY` objects are wrapped to K13, never to epoch or case keys, and never shown in the case view. Unsealing: custodian Desk unwraps, records legal basis + second approver signature (15/14) before decrypting; the unseal event is an audit record and, where law requires, generates a source-visible notice. Rotation: 24 months or on custodian change (re-wrap of stored identity CK wraps by a remaining custodian).

### 9.8 Recovery Quorum Key (K14; ADR-013) — see §16.

### 9.9 Envelope encryption summary
| Wrapped key | Wrapping key | Wrap construction | AAD / info binding |
|---|---|---|---|
| CK (intake) | Each eligible member's MEK (K04) public — anonymous slot | HPKE base | info = `"candor/v1/wrap/member-epoch"` ‖ suite ‖ tenant ‖ channel ‖ u32 epoch; aad = `"candor/v1/slot"` ‖ object_id ‖ payload_nonce (no recipient key ID anywhere in cleartext) |
| CK (identity) | K13 public — anonymous slot | HPKE base | info = `"candor/v1/wrap/custodian"` ‖ suite ‖ tenant; aad as above |
| CK (in case) | Case Key v | Record AEAD | aad = `"candor/v1/wrap/case"` ‖ tenant ‖ case_id ‖ v ‖ object_hash |
| CK (reply to source) | Source X-Wing public | HPKE base | info = `"candor/v1/wrap/reply"` ‖ suite ‖ tenant ‖ channel ‖ mailbox_id; aad = object_hash |
| CK (viewer job) | Viewer VM ephemeral X-Wing public (K34) | HPKE base | info = `"candor/v1/wrap/viewer-job"` ‖ suite ‖ job_id; aad = object_hash |
| Case Key v | K09 public / K14 public, then outer AEAD under Erasure Key K32 | HPKE base inside Record AEAD | inner info = `"candor/v1/wrap/casekey"` ‖ suite ‖ tenant ‖ case_id ‖ v ‖ recipient_key_id; outer aad = `"candor/v1/ek-layer"` ‖ tenant ‖ case_id ‖ v ‖ recipient_key_id |
| CIK private | K09 public | HPKE base | info = `"candor/v1/wrap/channel"` ‖ suite ‖ tenant ‖ channel ‖ key_id_of_wrapped ‖ recipient_key_id |
| K13 private | Custodian K09 | HPKE base | info = `"candor/v1/wrap/custodian-group"` ‖ suite ‖ tenant ‖ recipient_key_id |
| K08/K09/MEK private (on device) | K11 | Record AEAD | aad = `"candor/v1/desk/keystore"` ‖ user_id ‖ device_id ‖ key_id |
| K11 (keystore key) | Each enrolled authenticator's K10 output (slot i) | Record AEAD | aad = `"candor/v1/desk/keystore-slot"` ‖ user_id ‖ device_id ‖ u8 i |
| Staged Tier W part (ciphertext on tmpfs) | K36 draft session key | STREAM (§13.3) under `HKDF(K36, part_id, "candor/v1/stage/part")` | part_id (random 16 B) in the STREAM key derivation; parts never carry recipient slots |
| `{mailbox_id, reply_seq}` (routing_ct) | K37 Intake Routing Key public | HPKE base | info = `"candor/v1/wrap/routing"` ‖ suite ‖ tenant; aad = object_hash of the REPLY |
| Export Package CK | K38 Connector Key public (EE integrations) or K30 recipient key | HPKE base | info = `"candor/v1/wrap/connector"` ‖ suite ‖ tenant ‖ connector_id; aad = object_hash |
| Source prefs (`prefs_ct`) | `K_prefs = HKDF(PRK_source, "candor/v1/source/prefs")` | Record AEAD | aad = `"candor/v1/source/prefs"` ‖ tenant_id ‖ lookup_tag ‖ u32 prefs_version |

`‖` denotes concatenation of fixed-length fields (UUIDs 16 B, epoch u32 BE, key IDs 32 B, suite u16 BE); variable-length fields are prefixed with u16 BE length. Stored case-key wraps may carry `recipient_key_id` in the DB because case ACLs are already known to the authorization engine (C-22); intake slots never do.

### 9.10 Erasure Key and Erasure Key Vault (K32, K33; ADR-033 item 3, ADR-044(4))
- **Construction — strictly an outer layer (clarifies ADR-033(3); RVW-B-21(c), RVW-C-08):** the Erasure Key (EK) never wraps a case key directly. The only object ever encrypted under an EK is an **HPKE_BASE stanza that already wraps the case key to a member's K09 or to K14** (`CASEKEY_EK`, §13.2). Removing the EK layer yields an HPKE ciphertext that still requires K09/K14; therefore EK (and the EKV) give the server no content access (ADR-007 preserved). C-11 exposes no API that AEAD-encrypts a raw case key under an EK, and CI rejects any `CASEKEY_EK` whose inner plaintext is not a parseable HPKE_BASE stanza (§22.2 negative vector `ek_direct_wrap`). The same construction applies to the Recovery Quorum wrap.
- **Erasure Key (EK)**: 256-bit symmetric key per case, generated by C-10 at case creation and stored only in the **Erasure Key Vault (EKV)** — a host-local vault store on the C-12 host on its own volume (09 §5.6; not a PostgreSQL schema, so it never appears in WAL, streaming replicas or routine backups; RVW-C-08) — encrypted at rest under the EKV master key K33 (TPM-sealed in CE; HSM in EE/GOV; in HIGH/GOV profiles a **physical** host TPM or HSM, never a vTPM, ADR-044(4)).
- Every case-key wrap (to members' K09 and to K14) is stored as `AEAD(EK, nonce, HPKE-wrap, aad = ek-layer context)`.
- **Backups and erasure log:** the EKV is **excluded from routine backups**; it has its own backup with **≤ 14-day retention**. EKV backup exports contain EKs re-encrypted to the Backup Master public key K25 (STREAM + HPKE, §17.2), **not** VMK/TPM-sealed records, so a vault backup is restorable on replacement hardware (RVW-C-07). C-10 appends every EK destruction to a signed, append-only **erasure log** (`{case_id, day}` entries hash-chained and signed by K24); any vault or database restore applies the erasure log (destroying listed EKs and wraps) **before** the restored core serves requests (ADR-044(4)). Destroying a case's EK (and its entries in EKV backups ageing out within ≤ 14 days) renders every backed-up copy of that case's key wraps unreadable — the documented upper bound of "delete" for backups (§18).
- **Replication (ADR-044(4)):** in EE-HA the vault is replicated to the standby core host and to the DR site within the HA RPO, each replica under its own K33 (HSM at the DR site in EE/GOV); replicas obey the same erasure log.
- **Infrastructure backups (ADR-044(4), RVW-C-06):** hypervisor-, SAN- or image-level backups and snapshots of core hosts MUST exclude the vault volume and the K33 sealing state; the config checker records an operator attestation; where it is absent, 35/11 source-facing text SHALL NOT claim the 14-day bound.
- Desk fetches EK-layered wraps through C-10, which removes the EK layer only for an authenticated, authorized member's request (C-22); DB-only thieves without EKV see only doubly wrapped blobs.
- **Vault-loss recovery by Desk re-wrap (RVW-C-07):** member Desks cache the case keys they hold in their keystore (sealed by K11, §9.4). If the EKV is lost with no usable vault backup, C-10 creates a new EK per affected case and any current holder's Desk re-uploads HPKE wraps of its cached case key to every ACL member's K09 (and K14 when enabled), which C-10 layers under the new EK; the operation is dual-approved and audited. Cases none of whose holders retain a cached key are lost (as for loss of all holders' devices). Caching case keys on endpoints lengthens their exposure there (§27 #3).

### 9.11 Blinded COI exclusion tags (K40, derived; ADR-037(3))
- Per case and case-key version v: `K_case_excl_v = HKDF-Expand(HKDF-Extract(salt = case_id, IKM = CaseKey_v), "candor/coi-excl/v1", 32)` (label fixed by ADR-037; registered in §10 as the one label outside the `candor/v1/` namespace).
- Tag for staff user U: `excl_tag = HMAC(K_case_excl_v, "candor/coi-excl/tag" ‖ tenant_id ‖ user_id_U)` (32 B; FIPS HMAC-SHA-384 truncated to 32 B).
- The server stores for each (case_id, v) a set of exactly 8·⌈max(1, x)/8⌉ tags, where x is the number of real exclusions; padding tags are 32 random bytes; order random. No cleartext user ID, count of real exclusions or exclusion source (source tick vs COI map vs triage decision) is stored server-side; the exclusion source lives only in the encrypted case record.
- **Blind check:** a Desk proposing a case grant to user U sends `excl_tag(U)`; C-22 refuses the grant if the tag is in the set (a check against honest-but-mistaken Desks; it does not constrain a malicious Desk).
- **Desk verification on sync:** every holder's Desk recomputes `excl_tag` for each user that holds a case-key wrap (wrap recipients are known to C-22) and raises a SECURITY alert (content-free server event, detailed local notice) if any matches the set.
- On case-key rotation to v+1 the rotating Desk recomputes all real tags under `K_case_excl_{v+1}`, adds fresh padding and replaces the set atomically with the new version's wraps.
- Audit reason codes SHALL NOT distinguish COI removals from other removals; no event, table or export associates a user identity with a COI exclusion for a specific case (ADR-037(3); enforced in 09/14/20).
- Residual: a live Z-CORE attacker who also controls a case member's Desk can compute tags; case members legitimately know who is excluded.

### 9.12 Intake Routing Key and Connector Key (K37, K38; ADR-046(12))
- **Intake Routing Key (K37):** X-Wing (STD) / MLKEM1024-P384 (FIPS) keypair generated on the intake host at install; private half only on H-INTAKE (TPM-sealed where available; inside the sealer TEE in the Confidential-VM profile, ADR-035(3)); public half published as a `ROUTING_KEY` KD entry (0x18) signed by K01. The replying Desk encrypts `{mailbox_id, reply_seq}` to K37 (`routing_ct`, §9.9), so the Case DB never stores a cleartext mailbox or source account identifier (06 ARCH-009). C-08 opens `routing_ct` only in the reply-apply step. Joint compromise of the Case DB and the intake host links cases to pseudonymous mailboxes (nothing identifying; 03). Rotation: 24 months or on intake compromise (new `ROUTING_KEY` entry; the intake keeps the old private half until every `routing_ct` sealed to it has been applied, then destroys it). Backup: BS-SECRETS (19).
- **Connector Key (K38, EE):** X-Wing / MLKEM1024-P384 keypair generated inside the receiving integration (C-40 connector host or the external system), registered as a `CONNECTOR_KEY` KD entry (0x19) signed by K01 + 1 K15 with `connector_id`, allowed export kinds and expiry (≤ 12 months). Export Package CKs are HPKE-wrapped to it (§9.9); the connector host decrypts outside Candor's trust boundary (the integration is a data recipient, ADR-018). A Connector Key never receives intake, case or MEK wraps (KEY-046).

### 9.13 Tier W draft session key (K36; ADR-034)
- 256-bit key generated by C-07 from the CSPRNG when a Tier W draft session starts; exists only in mlocked, non-dumpable C-07 RAM, keyed by the opaque session handle; never persisted, logged or derived from any client value (no cookie-derived keys).
- Draft text (answers, message, identity block, file names) is held in C-07 RAM in plaintext arenas (no disk, no tmpfs). Uploaded attachment parts are first padded to the ADR-011 bucket (§13.6; ADR-038(5)) and then STREAM-encrypted under `K_stage = HKDF(K36, part_id, "candor/v1/stage/part")` before being written to the tmpfs staging area (non-swappable host, §23.2).
- **No member wrap before Submit (RVW-A-07):** no Content Key is HPKE-sealed to any MEK while the draft is open. At Submit, after the recipient set is fixed (§12.1), C-07 generates the objects' CKs, streams each staged part (decrypt under K_stage → STREAM-encrypt into the ATTACHMENT_BUNDLE under the bundle CK) and only then builds the slot blocks. If the category, COI ticks, roster or epoch changed during the draft, no re-work is needed because nothing was sealed earlier.
- Single timer set (ADR-034): 20 min idle, 2 h absolute; on expiry, discard, successful Submit or sealer restart, C-07 zeroizes K36 and all draft arenas and unlinks the staged files (whose content is unreadable without K36). No per-draft time value is written anywhere.
- The same session memory holds a Tier W login's derived seed and keys (§11.5) for the session lifetime; the passphrase itself is zeroized immediately after derivation.

### 9.14 Intake integrity evidence keys (ADR-035)
- **Intake Sealer key K35:** signs Tier W Recipient Lists (`sealer_sig`) and the **running manifest** (below). Default profiles: generated on the intake host, TPM-sealed; this proves only "the intake host signed" and gives no protection against a root-level or compelled modification (RVW-A-01). **Confidential-VM profile (optional, HIGH/GOV; ADR-035(3)):** K35 is generated inside the SEV-SNP/TDX guest; the hardware attestation report's report-data field carries `H("candor/v1/sealer-attest" ‖ K35_pk ‖ running_manifest_hash)`; a `SEALER_ATTESTATION` KD entry (0x15) with the report is appended at least in every weekly publication slot and on every restart. Desks and External Watchers verify the report chain to the TEE vendor root, that the measurement equals the reproducibly built, TUF-logged sealer image (33), and that `sealer_sig` keys match. In this profile Desk VR-9 rejects Tier W envelopes whose `sealer_sig` key is not bound to a current, release-matching attestation.
- **Running manifest:** a fixed-size signed document `{format, tenant_id, release_version, TUF targets hashes of installed trust-path packages, Platform Manifest hash (33 §4.1), static source-UI asset digest set hash, CSP header string hash, day}` signed by K35, served by C-06 at `/.well-known/candor/running-manifest` and re-signed daily. External Watchers fetch it over Tor and compare with the release transparency log (ADR-035(1), 33 §7.1). It is self-reported and forgeable by a root-level attacker outside the Confidential-VM profile (honest limit).
- **Operator Statement (ADR-035(2)):** an `OPERATOR_STATEMENT` KD entry (0x13) with fixed text ("no compelled modification, no instrumentation of intake memory, no targeted update" plus `reduced_separation_of_duties` flag, ADR-045), `issued_day` and `valid_until_day = issued_day + 30`, signed by k-of-n **statement signers** (their K08 keys) listed in the K01-signed `GOVERNANCE_ROLES` entry (0x11), where the signature set SHALL include ≥ 1 signer whose role is flagged independent. Tier V clients, Tier W pages (via C-06) and Desks show a warning when no valid statement exists. Honest limit: canaries are legally uncertain and can be coerced; they are a signal, not a guarantee.
- **Incident notice (ADR-035(4)):** when intake memory or packet capture is authorized, an `INCIDENT_NOTICE` KD entry (0x17) `{day, scope: intake-memory | intake-network, window_days}` is appended, signed by the approving independent-role member's K08 and the IR lead's K08; capture tooling refuses to start without the entry's inclusion proof. Capture output is encrypted to a one-time key split between independent custodians (31).
- **External Witness / Watcher keys (K39):** Ed25519 keys of witness and watcher organisations, held by those organisations (never by the operator), listed in ORG_ROOT with their roles (witness, watcher) and whether they are outside the operating organisation/jurisdiction; they cosign checkpoints (§14.3) and sign watcher reports.

## 10. KDFs and HKDF label registry

All HKDF uses: `HKDF-Extract(salt, IKM)` then `HKDF-Expand(PRK, info, L)`. Labels are ASCII, versioned `candor/v1/...`, registered in `candor-core/src/labels.rs`; CI rejects duplicates and unregistered literals.

| Label (`info`) | IKM | Salt | L | Output |
|---|---|---|---|---|
| `candor/v1/payload` ‖ suite | CK | payload_nonce (16 B) | 32 | STREAM key |
| `candor/v1/header-mac` ‖ suite | CK | object_id (16 B) | 32/48 | header MAC key |
| `candor/v1/dummy-slot` ‖ u8 i | CK | object_id | 64 | seed (32 B throwaway KEM key seed ‖ 32 B encapsulation randomness) for dummy slot i |
| `candor/v1/dummy-slot-pt` ‖ u8 i | CK | object_id | 32 | plaintext sealed in dummy slot i |
| `candor/v1/ek-layer` | K32 (EK) | case_id | 32 | AEAD key for the Erasure-Key layer |
| `candor/v1/ekv/master` | K33 output | host_id | 32 | EKV at-rest key |
| `candor/v1/case/record/` ‖ table_id | Case Key v | `"candor/v1/case"` | 32 | record key per table |
| `candor/v1/desk/keystore` | K10 output | device_id | 32 | K11 |
| `candor/v1/source/lookup-id` | seed | `"candor/v1/source"` | 32 | source lookup id |
| `candor/v1/source/auth-ed25519` | seed | same | 32 | auth key seed |
| `candor/v1/source/sign-ed25519` | seed | same | 32 | signing key seed |
| `candor/v1/source/kem-seed` ‖ suite | seed | same | 32 (STD) / 64 (FIPS) | X-Wing seed / DeriveKeyPair ikm |
| `candor/v1/source/mailbox/` ‖ u32 report_index | seed | same | 32 | mailbox id per report |
| `candor/v1/backup/object` | Backup Generation Key | backup_set_id | 32 | per backup archive key |
| `candor/v1/export/package` | export CK | export_id | 32 | export payload key |
| `candor/v1/session/source-web` | K28 | — | 32 | session MAC key (15 owns semantics) |
| `candor/v1/source/prefs` | seed-derived PRK | `"candor/v1/source"` | 32 | K_prefs (AEAD key for `prefs_ct`, §11.4) |
| `candor/v1/stage/part` | K36 | part_id (16 B) | 32 | STREAM key for one staged Tier W part (§9.13) |
| `candor/coi-excl/v1` | Case Key v | case_id | 32 | K_case_excl_v (ADR-037(3); only label outside `candor/v1/`, fixed by the ADR) |
| `candor/v1/desk/keystore-slot` | K10_i output | device_id | 32 | per-authenticator slot key wrapping K11 (§9.4) |
| `candor/v1/sealer-attest` | — | — | — | domain separator for TEE report-data binding (§9.14) |
| `candor/v1/audit/chain` | — | — | — | domain separator for audit hash chain (20) |

## 11. Source passphrase scheme (ADR-005)

### 11.1 Generation
- 10 words drawn uniformly and independently from the EFF large wordlist (7,776 words; B-GL-27 uses the same list), using rejection sampling on `getrandom` output (no modulo bias). Tier V: generated in C-03 (or WASM bundle). Tier W: generated in C-07.
- Localized lists (11/26) MUST have exactly 7,776 unique entries after NFKC + lowercase normalization, no word a prefix of another is NOT required (entropy is unaffected), and pass the offensive-word filter (R1 notes SecureDrop's list purges).
- **Never stored anywhere by the platform** (ADR-034, ADR-005). Tier W: the passphrase is displayed on the Recovery Credential screen **before** the submission is finalized; the source must re-type 3 randomly chosen words (positions chosen by C-07's CSPRNG); only then does C-07 seal and commit. Until confirmation it exists only in the session's C-07 RAM (≤ session timers, §9.13). If the confirmation response is lost, the submission was not finalized; the source restarts. No re-display after finalization. Tier V: same confirmation step in C-03, locally. The UI offers no "copy to clipboard" in Tier W no-JS mode and warns about writing it down (THR-048; 05-SOURCE-OPSEC.md).

### 11.2 Entropy calculation and cost table
`H = 10 × log2(7776) = 10 × 12.925 = 129.25 bits`. The security of `lookup_tag` against offline guessing rests on this entropy; Argon2id (m = 64 MiB, t = 3, p = 1; ADR-046(7)) is defence in depth against generation or transcription faults (e.g., a source who writes down only some words). Offline cost at ~2^-3 s and 64 MiB per guess on commodity hardware (Knowledge (unverified) timing):

| Words known to be correct / unknown | Remaining entropy | Expected Argon2id evaluations | Assessment |
|---|---|---|---|
| 0 known (full passphrase unknown) | 129.25 bits | 2^128 | infeasible, including with Grover-style speed-up (≥ 2^64 sequential memory-hard evaluations) |
| 3 unknown words (e.g., 7 of 10 leaked) | 38.8 bits | 2^37.8 | feasible for a funded adversary in days–weeks; hence "write down all words or none" guidance (05) |
| 5 unknown words | 64.6 bits | 2^63.6 | beyond commodity budgets (comparable to CoverDrop's full passphrase) |
| 7 unknown words | 90.5 bits | 2^89.5 | infeasible |

The FIPS profile (PBKDF2-HMAC-SHA-512, 210,000 iterations) is not memory-hard; its safety depends on the full 129-bit entropy (§27 #16). Comparison: GlobaLeaks 16-digit receipt ≈ 53.2 bits (R2 §1.3), SecureDrop 7 words ≈ 89.8 bits (R1 B-SD-18), SecureDrop Protocol BIP39-12 = 128 bits (B-SD-11), CoverDrop 5 EFF words + Argon2 ≈ 64.6 bits (B-GL-27). The RVW-B-27 proposal to reduce the default to 7 words is not adopted: ADR-046(7) keeps ≈ 129-bit entropy and reduces the stretching cost instead; recall is supported by the confirmation step (§11.1) and guidance (05).

### 11.3 Normalization and derivation
```
normalize(p) = NFKC(lowercase(p)), split on any whitespace/hyphen/comma, require exactly 10 tokens each in the wordlist, join with 0x20
deployment_salt  = 32 random bytes generated at tenant creation, published in ORG_ROOT KD entry
salt             = SHA-256("candor/v1/source-salt" ‖ deployment_salt ‖ tenant_id)          (32 B)
seed             = Argon2id(password = normalize(p), salt, m = 65536 KiB, t = 3, p = 1, len = 32, version 0x13)
                   [FIPS: seed = PBKDF2-HMAC-SHA-512(normalize(p), salt, 210000, 32)]
PRK              = HKDF-Extract(salt = "candor/v1/source", IKM = seed)
lookup_id        = HKDF-Expand(PRK, "candor/v1/source/lookup-id", 32)
auth_sk_seed     = HKDF-Expand(PRK, "candor/v1/source/auth-ed25519", 32)   → Ed25519 keypair (auth_sk, auth_pk)
sign_sk_seed     = HKDF-Expand(PRK, "candor/v1/source/sign-ed25519", 32)   → Ed25519 keypair (sign_sk, sign_pk)
kem_seed         = HKDF-Expand(PRK, "candor/v1/source/kem-seed" ‖ suite, 32|64) → X-Wing keypair (src_sk, src_pk) [FIPS: DeriveKeyPair]
mailbox_id[i]    = HKDF-Expand(PRK, "candor/v1/source/mailbox/" ‖ u32be(i), 32)  for report index i = 0,1,… (reports created under this passphrase)
K_prefs          = HKDF-Expand(PRK, "candor/v1/source/prefs", 32)
```
Rationale for a per-deployment (not per-source) salt: login must derive the lookup identifier before any account is found, so a per-source salt would need an extra round trip that reveals account existence. Multi-target amortization is irrelevant at 129 bits (compare GlobaLeaks' per-tenant salt at 53 bits, R2 §1.3); ADR-046(7) accepts the per-deployment salt for this reason. The salt is tenant-bound so a passphrase is not portable across deployments. **Parameter change (ADR-046(7)):** v1.0 drafts used m = 256 MiB and PBKDF2 600,000; no deployment existed, so no migration of stored `lookup_tag`s is needed; any later change of these parameters requires a new `kdf_version` in ORG_ROOT and is applied only to new passphrases (existing sources keep their version, recorded in the account's `kdf_version`).

### 11.4 What each party stores
| Datum | Intake Store (C-08) | Core (C-12) | Source | Candor Desk |
|---|---|---|---|---|
| Passphrase | never (Tier W: C-07 RAM until confirmation / derivation only) | never | memory (source's) | never |
| seed / private keys | never (Tier W: C-07 RAM only for the session, §9.13) | never | derived on demand | never |
| `lookup_tag = SHA-256("candor/v1/lookup-tag" ‖ lookup_id)` | yes (index) | no | — | no |
| `auth_pk` | yes | no | — | no |
| `sign_pk`, `src_pk` | **no** (delivered only inside the encrypted SUBMISSION object or a KEY_ROTATION SOURCE_MESSAGE) | inside case (encrypted) | — | yes (case data) |
| `mailbox_id[i]` | yes (reply routing for Tier W lookup; never served with dead-drop pages) | only inside `routing_ct` and the encrypted case record | — | yes |
| `prefs_ct` = AEAD(K_prefs) of `{1: format, 2: kdf_version, 3: [{report_index, mailbox_id, original_eligible_user_ids, roster_version}], 4: ui_prefs}` | yes (opaque) | no | decrypts after login | no |

Storing `src_pk` only inside ciphertext minimizes what a Z-INTAKE compromise reveals (stricter than, and conformant with, ADR-005). `prefs_ct` stores the original eligible set needed for the follow-up sealing rule (ADR-036(4)); it does **not** store the source's COI ticks (RVW-A-03 item 4). Residual: whoever obtains the passphrase can read the eligible set and so infer which Triage Set members were excluded.

### 11.5 Login and reply access
- **Tier V — fetch-all reply retrieval (ADR-039):** reading replies needs **no authentication and no account identifier**. The intake publishes every stored reply of the last 30 days as **dead-drop entries** in fixed-size pages (page transport, page size and paging in 08; entry format §13.5). The client downloads **all** pages over Arti in one session, in a fixed order, and trial-decrypts every entry's stanza with `src_sk` for each of its `mailbox_id[i]` (the stanza's HPKE `info` binds mailbox_id; a mismatching mailbox simply fails to open). Cost: one X-Wing decapsulation per entry per mailbox (Knowledge (unverified): < 0.2 ms each on a laptop), so 10,000 entries ≈ 2 s. The server cannot tell which mailbox was checked; entries carry no cleartext mailbox_id, reply count or timestamp. Authenticated Tier V operations remain only for mailbox deletion and passphrase rotation: C-03 sends `lookup_tag`; server returns a 32-byte challenge bound to audience `source-app`, tenant and a 5-minute expiry; client returns `Ed25519.Sign(auth_sk, "candor/v1/source-auth" ‖ challenge ‖ tenant_id ‖ audience)`. **Tier V follow-ups are uploaded as envelopes without account authentication** (linkage to the case is proven inside the ciphertext by `mailbox_id` and `source_sig`; per-circuit and global rate limits and PoW apply, 08/16), so follow-up upload does not reveal which account is active.
- **Tier W:** passphrase POSTed over the onion to C-06, streamed to C-07 via a local Unix socket; C-07 normalizes, runs Argon2id in an mlocked buffer, zeroizes the passphrase, derives keys, verifies `lookup_tag`/`auth_pk`, looks up and decrypts pending replies for server-side rendering. The derived seed and keys stay in the session's mlocked memory for the session lifetime (20 min idle / 2 h absolute, ADR-034) to render the inbox and sign follow-ups, and are zeroized on logout, expiry or restart. **Tier W necessarily performs a server-side lookup, so a compromised intake learns which account is active and when (documented residual, ADR-039).** C-07 limits concurrent Argon2id derivations with a semaphore of `ARGON2_MAX_CONCURRENT = 4` (4 × 64 MiB = 256 MiB) plus Tor PoW and C-06 per-circuit limits (ADR-046(7)); waiting requests queue (FIFO, depth 64, ≤ 30 s) and are answered in the normal size class and a fixed minimum latency; only queue overflow (sized to ≥ 10× design peak, 34) yields the busy page, and no response exposes queue length or position (ADR-038(5); RVW-A-27).
- Wrong passphrases are indistinguishable from unknown accounts (same response body/size class and same C-07 work).

### 11.6 Multiple reports under one passphrase
Default: one passphrase per report (ADR-005). If the source chooses to add a report, report index `i+1` yields a new `mailbox_id` and the new SUBMISSION object carries the same `sign_pk` and `src_pk` (recipients can see both reports come from the same source — shown explicitly to the source before confirming).

### 11.7 Passphrase rotation (ADR-046(7); RVW-A-03, RVW-A-11)
A logged-in source may rotate the passphrase from the inbox (default offered at every Tier W login in HIGH profile):
1. The client (C-03 locally; Tier W: C-07 in session RAM) generates a new passphrase (§11.1, including confirmation) and derives `seed'`, `lookup_tag'`, `auth_pk'`, `sign_pk'`, `src_pk'`, `K_prefs'`.
2. It builds a `KEY_ROTATION` SOURCE_MESSAGE per report (§13.4: `sign_pk'`, `src_pk'`, signed by the **old** `sign_sk` and by `sign_sk'`), sealed per the follow-up sealing rule; Desks update the case's source keys only if both signatures verify.
3. It re-wraps every pending reply of the source's mailboxes: opens stanza(1) with the old `src_sk` and HPKE-wraps the same CK to `src_pk'` (reply bodies unchanged). Tier V uploads the new stanzas authenticated with the old `auth_sk`.
4. The intake atomically replaces `lookup_tag`, `auth_pk` and `prefs_ct` (now under `K_prefs'`, carrying the existing mailbox IDs, which are no longer derivable from `seed'`), and deletes the old values.
Effect: a passphrase captured earlier (past Tier W compromise window, recorded transit) stops opening new replies and cannot authenticate. Limit: a sealer that is compromised **during** the rotation sees both passphrases; rotation bounds past captures, not a live one.

## 12. Intake sealing and member-epoch operations

### 12.1 Recipient selection (C-03, C-07)
1. Obtain the latest key-directory snapshot (pushed by C-09 to C-06, ADR-009; Tier V: fetched from the intake **and** the latest cosigned checkpoint from ≥ 1 external witness endpoint over Tor, not via the tenant onion, §14.5 VR-3) and verify it (§14.5).
2. **High-water mark (ADR-036(6)):** C-07 persists a monotonic high-water mark `(tree_size, checkpoint issued hour)` of the newest verified checkpoint (09 owns the storage row). A snapshot whose tree size or `issued` is below the high-water mark is rejected (rollback). Tier V: the Source App pins the last seen tree head per tenant (persistent pin, §14.5 VR-3) and rejects older or inconsistent heads.
3. **Independent time (ADR-036(6)):** `now` is taken from the host clock only if it passes the independent-time check of 16 §14.3: not earlier than the `valid-after` of the latest signed Tor consensus held by C-05 (floor), not later than that `valid-after` + 27 h, and within ± 10 min of the Roughtime median when Roughtime is reachable. Otherwise, or if skew to Roughtime exceeds 2 h, fail closed (THR-043). The clock is **never** cross-checked only against a Z-CORE-supplied value (checkpoint time or C-09 timestamp; RVW-A-04). `today` = UTC day of `now`; the checkpoint must satisfy VR-5.
4. Candidate set = Triage Set members (capability `read_intake`) of the channel's latest **active** CHANNEL_ROSTER (§14.4 rule 7: time-locked additions are not yet active; removals are active immediately).
5. **COI filter (ADR-030/037):** remove members whose role labels the source flagged, and members mapped to the selected report category in the latest **active** COI_POLICY entry. The flags and category are recorded inside the encrypted SUBMISSION (§13.4 keys 14, 17). For a follow-up, additionally intersect with the report's original eligible set (§9.5 follow-up rule).
6. For each remaining member select the MEMBER_EPOCH entry with `valid_from_day ≤ today < valid_until_day`, signed by that member's current K08, not revoked, with valid public key (§23.3). Members without a valid current MEK are skipped and counted.
7. If the eligible set is empty, do not seal; direct the source to the channel's `independent_route` channel, or show "temporarily unavailable" (fail closed, ADR-030/037). If members were skipped for missing MEKs, the Tier V client shows "N recipients currently unreachable" and lets the source proceed or wait; Tier W proceeds and records the count inside the ciphertext.
8. The eligible set has ≤ 16 members (C-14 invariant); the remaining slots are dummies.
9. **Tier V source-facing checks (ADR-036(3), RVW-A-05):** VR-8 shows, per recipient role label, "member since YYYY-MM-DD" (day of the member's first active roster entry for the channel) and warns when a recipient's user or MEK key is < 7 days old or when the roster changed in the last 30 days.

### 12.2 Tier V sealing (C-03 / WEBCAT bundle)
Client generates CKs, builds the three objects (§9.2), seals payloads (§13.3), builds the anonymous slot block (§13.2), commits (§13.1), and signs the SUBMISSION inner map — including the Recipient List (key IDs of the MEKs actually used + checkpoint) — with `sign_sk`. Plaintext never leaves the client. Optional delayed delivery (ADR-038(4)): the client includes `release_day` (1–3 days after upload, uniform) as upload metadata; the intake holds the sealed envelope until that day (the value is not inside the ciphertext and is deleted at release).

### 12.3 Tier W sealing (C-07)
C-06 parses the HTML form and streams fields and file parts to C-07 over a Unix socket without buffering request bodies to disk (C-06 never writes request bodies to disk or tmpfs — in-memory pipes only). During the draft, C-07 keeps text in RAM and staged attachment parts on tmpfs only as ciphertext under the session key K36 (§9.13; ADR-034). At **Submit** — after the passphrase confirmation (§11.1) and after the recipient set is fixed (§12.1) — C-07 runs the same sealing code as C-03 (same C-11 functions, same KATs), applies the COI filter in RAM, re-encrypts the staged parts into the ATTACHMENT_BUNDLE under a fresh CK, builds the slot blocks, and writes only sealed objects and slot blocks to C-08 (at the fixed commit slots of 09/ADR-038(1)). The Recipient List is signed with the derived `sign_sk` and additionally with the Intake Sealer key K35 (§9.14). Plaintext buffers are mlocked and zeroized after sealing (§23.2). No member wrap of any CK exists before Submit (RVW-A-07). Optional delayed delivery as in §12.2 (the source chooses on the review screen).

### 12.4 MEK pre-publication (every Triage Set member's Desk)
On each sync, for every channel where the member has `read_intake`: ensure MEKs for the current and next 4 epochs exist; generate missing ones from the CSPRNG; pairwise-consistency and KAT self-test; seal private keys in the keystore; submit MEMBER_EPOCH entries signed by K08. C-14 queues them and appends them in the next weekly publication slot (ADR-036(7); §14.3), accepting only if the signer is in the latest active roster with `read_intake` and no MEK exists for (channel, member, epoch). Because 4 future epochs are pre-published, the weekly slot never delays sealing.

### 12.5 MEK retirement (ADR-033 item 2, ADR-038(6))
For each held MEK past `valid_until + 14 d`, the Desk asks C-10 whether any envelope of that channel and epoch is neither imported nor rejected. Only when none remains does the Desk zeroize the private key (on all linked devices; offline keystore backups are refreshed so that they no longer contain it), compact the keystore file (best-effort on SSD, §18.4) and emit `MEK_RETIRED`. C-10 escalates envelopes un-imported for > 7 days to OVERSIGHT, the channel's independent route and C-25 (content-free, at most one escalation per channel per day). After 14 days pending, an undecryptable or unimportable envelope may be rejected with dual approval and is then deleted (§9.5).

### 12.6 Fail-closed conditions for intake
Intake (C-06/C-07) SHALL refuse new submissions for a channel and show the outage page (no alternative anonymous path, ADR-002) when: the eligible recipient set is empty (with the independent-route pointer of §12.1 step 7); the checkpoint is older than VR-5 allows; checkpoint signature, witness cosignature policy or consistency fails; the snapshot is below the high-water mark; the independent-time check fails; roster or COI_POLICY verification fails; suite mismatch; self-test failure of C-11; the running release is below the signed security floor after its effective day (33 §8.1). Source logins and reply display continue if only the recipient condition fails.

## 13. Wire formats

All integers big-endian. `H` = SHA-256 (STD) / SHA-384 (FIPS); wherever a format field is 32 bytes, FIPS values are SHA-384 truncated to 256 bits (SP 800-107 truncation — Knowledge (unverified)). Structured inner data uses deterministic CBOR (RFC 8949 §4.2.1 core deterministic encoding) with integer map keys; decoders reject indefinite lengths, duplicate keys, non-canonical integers, floats, tags, and unknown keys unless the key number is ≥ 1000 (reserved for forward-compatible optional fields). No inner structure is parsed before AEAD verification succeeds.

### 13.1 Sealed Object (immutable blob)
```
SealedObject = CoreHeader (128 B) ‖ header_mac (32 B STD / 48 B FIPS) ‖ Payload (STREAM ciphertext)

CoreHeader:
 off len field
   0  4  magic = 0x43 0x4E 0x44 0x52 ("CNDR")
   4  1  format_version = 0x01
   5  1  object_type   0x01 SUBMISSION | 0x02 ATTACHMENT_BUNDLE | 0x03 IDENTITY | 0x04 REPLY
                       0x05 SOURCE_MESSAGE | 0x06 CASE_ATTACHMENT | 0x07 EXPORT_PACKAGE | 0x08 CASE_DOCUMENT
   6  2  suite_id      0x0001 CANDOR-STD-1 | 0x0002 CANDOR-FIPS-1   (others rejected in v1)
   8  2  flags         MUST be 0x0000 in v1
  10  2  reserved      MUST be 0x0000
  12 16  tenant_id
  28 16  channel_id    (all-zero for CASE_*, EXPORT_PACKAGE and REPLY)
  44  4  epoch_id      (0 unless sealed to Member Epoch Keys)
  48 32  slot_block_hash  (H(RecipientSlotBlock) for intake-sealed objects; all-zero for REPLY and staff objects)
  80 16  object_id     (random 128-bit, CSPRNG)
  96  4  day_stamp     (0 for source-originated objects and REPLY — ADR-010/039; UTC day number for other staff-originated objects)
 100  1  chunk_size_log2 = 16
 101  3  reserved = 0
 104  8  padded_plaintext_len
 112 16  payload_nonce (CSPRNG)
header_mac  = HMAC(K_mac, CoreHeader),  K_mac = HKDF(IKM=CK, salt=object_id, info="candor/v1/header-mac" ‖ suite)
(the header MAC therefore also commits to the slot block through slot_block_hash)
object_hash = H(CoreHeader ‖ header_mac)
```
Readers MUST: check magic/version/suite/flags/reserved; check `padded_plaintext_len` is a legal bucket for `object_type` (§13.6); compute expected payload length and reject any mismatch before decryption; verify `header_mac` in constant time before decrypting payload.

### 13.2 Recipient Slot Block (intake) and Wrap Stanzas (stored)

**RecipientSlotBlock** — immutable, travels with every intake-sealed object (SUBMISSION, ATTACHMENT_BUNDLE, IDENTITY, SOURCE_MESSAGE); no recipient key IDs in cleartext (ADR-033 item 1):
```
 off len field
   0  1  block_version = 0x01
   1  1  slot_count = 16            (tenant-fixed; readers reject any other value for the tenant)
   2  2  suite_id
   4  …  16 × Slot, Slot = enc (Nenc: 1120 B STD / 1665 B FIPS) ‖ ct (48 B)
Size: 4 + 16 × 1168 = 18,692 B (STD); 4 + 16 × 1713 = 27,412 B (FIPS)

Real slot for member m:  (enc, ct) = HPKE.SealBase(pk = MEK_m, info = "candor/v1/wrap/member-epoch" ‖ suite ‖ tenant ‖ channel ‖ u32 epoch,
                                                  aad = "candor/v1/slot" ‖ object_id ‖ payload_nonce, pt = CK)
IDENTITY object: one real slot to K13 (info "candor/v1/wrap/custodian" ‖ suite ‖ tenant), 15 dummies.
Dummy slot i:  (kp_seed ‖ r) = HKDF(CK, object_id, "candor/v1/dummy-slot" ‖ u8 i, 64);  pk_d = KEM.DeriveKeyPair(kp_seed).pk
               (enc, ct) = HPKE.SealBase with encapsulation randomness r to pk_d, same info/aad, pt = HKDF(CK, object_id, "candor/v1/dummy-slot-pt" ‖ u8 i, 32)
Order: real and dummy slots are placed in a uniformly random permutation (CSPRNG).
slot_block_hash (CoreHeader offset 48) = H(RecipientSlotBlock)
```
- Recipients trial-decrypt: a Desk runs HPKE.OpenBase with each of its MEK private keys for the envelope's epoch against all 16 slots (≤ 16 decapsulations per held key; constant work regardless of success).
- Dummy slots are real HPKE encryptions to throwaway keys, so they are indistinguishable from real slots to anyone without a MEK private key (CA-9), yet any holder of CK can recompute and **verify** them. The importing Desk verifies that every slot is either a verifiable dummy or corresponds to an entry of the signed Recipient List (count of non-dummy slots = list length), detecting hidden extra recipients produced by a malicious sealer or client release (THR-046).
- C-11 exposes derandomized encapsulation only through the internal dummy-slot function (not a public API) and it is covered by KATs.

**Wrap Stanza** — mutable, stored separately in `key_wraps` (09); used for case copies, replies, case-key and CIK wraps:
```
 off len field
   0  1  stanza_type   0x01 HPKE_BASE | 0x02 CASE_AEAD | 0x03 CASEKEY_EK (HPKE_BASE of a case key inside an Erasure-Key AEAD layer)
   1  1  reserved = 0
   2  2  suite_id
   4 32  recipient_ref (HPKE_BASE: key_id of recipient pk, or all-zero for REPLY; CASE_AEAD: case_id(16) ‖ u32 v ‖ 12 zero bytes;
                        CASEKEY_EK: key_id of the member/K14 key)
  36 32  bound_hash    (object_hash, or H("candor/v1/casekey" ‖ case_id ‖ u32 v), or H("candor/v1/chankey" ‖ channel_id ‖ wrapped_key_id))
  68  2  enc_len       (HPKE: Nenc; CASE_AEAD: 24 STD / 12 FIPS nonce; CASEKEY_EK: nonce length)
  70  …  enc
   …  4  ct_len
   …  …  ct
HPKE_BASE:  ct = HPKE.SealBase(pkR, info = label ‖ context (§9.9), aad = bound_hash, pt = key)
CASE_AEAD:  ct = AEAD(K = HKDF(CaseKey_v, salt="candor/v1/case", info="candor/v1/wrap/case"), nonce = enc,
                      aad = "candor/v1/wrap/case" ‖ tenant_id ‖ case_id ‖ u32 v ‖ object_hash, pt = CK)
CASEKEY_EK: ct = AEAD(K = HKDF(EK_case, salt=case_id, info="candor/v1/ek-layer"), nonce = enc,
                      aad = "candor/v1/ek-layer" ‖ tenant_id ‖ case_id ‖ u32 v ‖ recipient_ref, pt = HPKE_BASE stanza bytes of the case key)
key_id(pk)  = SHA-256("candor/v1/key-id" ‖ u16 suite ‖ u8 key_kind ‖ pk)    key_kind: 1 MEK, 2 user-enc, 3 custodian, 4 quorum, 5 source, 6 viewer-job
```
After import, the intake slot block is retained with the sealed object only until the MEK retirement condition (§12.5) is met, then deleted; thereafter only CASE_AEAD stanzas give access.

### 13.3 Payload STREAM
```
K_pay  = HKDF(IKM=CK, salt=payload_nonce, info="candor/v1/payload" ‖ suite)
chunk i (plaintext P_i, 65536 B except the last, which is 1..65536 B; a zero-length plaintext is one empty final chunk)
nonce_i = u88be(i) ‖ (0x01 if last else 0x00)        (12 B)
C_i     = AEAD_Encrypt(K_pay, nonce_i, P_i, aad = empty)     STD ChaCha20-Poly1305 / FIPS AES-256-GCM
Payload = C_0 ‖ C_1 ‖ … ‖ C_{n-1};  n = max(1, ceil(padded_plaintext_len / 65536))
```
Decryptors verify each chunk; a missing final flag, extra data after the final chunk, or any tag failure aborts with no further output; consumers that must not act on partial data (C-17 viewers, export) buffer to an encrypted scratch area and release only after the final chunk verifies. Random access: chunk i is independently decryptable (seek = i × 65552).

### 13.4 SUBMISSION and SOURCE_MESSAGE inner format (message format)
```
padded_plaintext = u32be(cbor_len) ‖ cbor ‖ 0x00 padding   (length = bucket, §13.6)
SUBMISSION cbor map:
  1: format (=1)                2: report_index (uint)            3: mailbox_id (bstr 32)
  4: src_pk (bstr Npk)          5: sign_pk (bstr 32)              6: roster_entry_hash seen (bstr 32)
  7: checkpoint seen [tree_size uint, root_hash bstr]             8: tier (0 = W, 1 = V-app, 2 = V-web)
  9: mode (0 ANONYMOUS, 1 CONFIDENTIAL, 2 IDENTIFIED)             10: bundle_object_hash (bstr)
 11: identity_object_hash (bstr) 12: form_answers [[field_id uint, value tstr|uint|bool], …]
 13: message (tstr, UTF-8, NFC)  14: concerns_roles [role_label_id…] (source COI flags, ADR-030)
 16: recipient_list = { 1: epoch_id, 2: [MEK key_id …] (real recipients, sorted), 3: skipped_count (members without a current MEK),
                        4: coi_policy_entry_hash, 5: checkpoint [tree_size, root_hash] }   (ADR-033 item 1)
 17: category_id (uint)          18: bundle_manifest = { 1: format, 2: files [{1: display_name tstr ≤ 255 B (metadata only — never a path, ADR-027),
                                     2: claimed_media_type, 3: size u64, 4: sha256, 5: blake3 (STD) / sha384 (FIPS), 6: offset u64}], 3: total_len u64 }
 15: source_sig (bstr 64) = Ed25519(sign_sk, "candor/v1/submission-sig" ‖ H(CoreHeader) ‖ H(cbor of all keys except 15 and 19))
 19: sealer_sig (Tier W only) = Ed25519(K35, "candor/v1/sealer-sig" ‖ H(CoreHeader) ‖ H(cbor of all keys except 15 and 19))
SOURCE_MESSAGE cbor map (v1.1): 1: format (=2), 2: report_index, 3: mailbox_id, 4: in_reply_to (reply_seq | null), 5: message (tstr; empty for KEY_ROTATION),
  7: kind (0 MESSAGE, 1 KEY_ROTATION), 8: recipient_list (same structure as SUBMISSION key 16; follow-up rule §9.5),
  9: original_submission_object_hash (bstr), 10: new_keys (KEY_ROTATION only: {1: sign_pk', 2: src_pk'}),
  11: bundle_object_hash (follow-up attachments, optional),
  6: source_sig = Ed25519(sign_sk, "candor/v1/source-message-sig" ‖ H(CoreHeader) ‖ H(cbor of all keys except 6, 12, 13)),
 12: sealer_sig (Tier W only; K35, label "candor/v1/sealer-sig"),  13: new_key_sig (KEY_ROTATION only; Ed25519(sign_sk', same message))
```
Signing `H(CoreHeader)` binds the signature to the object and, through `slot_block_hash`, to the slot block. The same Recipient List covers the ATTACHMENT_BUNDLE and IDENTITY objects of the submission via keys 10/11 (their slot blocks are verified with the CKs obtained from them). Desk verifies `source_sig` against `sign_pk` of the first SUBMISSION in the report; a mismatch is shown as "message not from the same source key" and quarantined. Desk additionally verifies that a SOURCE_MESSAGE's recipient list is a subset of the report's original eligible set intersected with the roster active at its checkpoint (VR-9(c)), and applies a KEY_ROTATION only if both `source_sig` (old key) and `new_key_sig` verify.

### 13.5 REPLY format (staff → source)
```
SealedObject with object_type = 0x04, channel_id = all-zero, epoch_id = 0, slot_block_hash = 0, day_stamp = 0
  (v1.1: REPLY headers are served publicly in dead-drop pages, so channel and day live only inside the ciphertext, key 4 and the stanza info; ADR-038(3), ADR-039)
Wrap stanzas: (1) HPKE_BASE to src_pk, recipient_key_id = 0 (hidden), info = "candor/v1/wrap/reply" ‖ suite ‖ tenant ‖ channel ‖ mailbox_id
              (2) CASE_AEAD under current Case Key (staff copy)
Inner cbor: 1: format, 2: mailbox_id, 3: reply_seq (uint, per mailbox monotonic), 4: day (uint), 5: body (tstr ≤ 60 KiB),
            6: sender_user_keys_entry_hash (bstr 32), 7: role_label (tstr, as in roster),
            8: sender_sig = Ed25519(K08 of the replying member, "candor/v1/reply-sig" ‖ H(CoreHeader) ‖ H(cbor keys 1–7))
Relay reply record (pushed by C-09 to C-08): { routing_ct = HPKE(K37_pk, {mailbox_id, reply_seq}), SealedObject, stanza (1) }  (§9.12)
Dead-drop entry (served to anyone in fetch-all pages, ADR-039; 08 owns paging):
  u32 entry_len ‖ SealedObject (REPLY) ‖ stanza (1)          — no mailbox_id, no reply_seq, no day outside the ciphertext;
  entries of a page are in random order; pages are rebuilt at each reply-apply slot and contain every reply of the last 30 days
```
Replies are signed by the replying member's User Identity Key (the CIK signs channel metadata only, ADR-030); the source sees the member's roster role label, never a name unless the channel's policy publishes names. v1 replies are text-only (no attachments to sources, reducing THR-048 residue). Source client (or C-07 for Tier W) verifies that the signer is in the channel roster valid on the reply's `day`, the signature, and `reply_seq` monotonicity; failures show "reply could not be verified" and do not render the body.

### 13.6 Padding buckets (ADR-011)
| Object type | Legal `padded_plaintext_len` values |
|---|---|
| SUBMISSION, SOURCE_MESSAGE, REPLY | 4096 × k, k = 1..16 (max 65536) |
| IDENTITY | 4096 × k, k = 1..4 (dummy uses the most common bucket, k = 1) |
| ATTACHMENT_BUNDLE, CASE_ATTACHMENT, CASE_DOCUMENT, EXPORT_PACKAGE | b_0 = 262144; b_{j+1} = 65536 × ceil(1.25 × b_j / 65536); max per 10-FILE-EVIDENCE-PIPELINE.md |

Padding bytes are zero and lie inside the AEAD; the real length is inside the encrypted inner structure. Maximum size overhead for files: 25% + 64 KiB.

### 13.7 ATTACHMENT_BUNDLE inner format and viewer jobs
```
padded_plaintext = u32 magic "CBDL" ‖ u32 file_count ‖ file_0 bytes ‖ file_1 bytes ‖ … ‖ zero padding to bucket
(offsets, sizes, names and hashes are in the SUBMISSION bundle_manifest, key 18)
```
**Viewer-only decryption (ADR-033 item 5).** Candor Desk's main process never decrypts ATTACHMENT_BUNDLE, CASE_ATTACHMENT or CASE_DOCUMENT payloads:
1. C-17 starts a disposable VM/DispVM per job; inside it, the viewer agent generates an ephemeral X-Wing keypair (K34) and returns its public key over the VM control channel.
2. Desk unwraps the object's CK and sends `HPKE.SealBase(K34_pk, info = "candor/v1/wrap/viewer-job" ‖ suite ‖ job_id, aad = object_hash, pt = CK ‖ file_index ‖ expected sha256)` plus the ciphertext blob (streamed).
3. The viewer decrypts the STREAM, verifies all chunks and the file hash from the manifest, performs the job (hash-at-import, render, sanitize — 10), and returns only the job output (hashes, sanitized PDF pixels-to-PDF output re-encrypted to the case per 10).
4. The VM and K34 are destroyed at job end; one K34 per job.
Evidence hashes (ADR-012) are computed by a C-17 **import-hash job** and recorded in the encrypted case record; mismatch with the manifest marks the file "integrity failure" (10).

### 13.8 Encrypted record format (case fields, Desk keystore)
```
0x01 (version) ‖ u16 suite ‖ u32 key_version ‖ nonce (24 B STD / 12 B FIPS) ‖ ciphertext ‖ tag
AAD = "candor/v1/rec" ‖ tenant_id ‖ case_id ‖ u16 table_id ‖ u16 column_id ‖ record_id (16) ‖ u32 key_version ‖ u64 row_version
```
`row_version` is also committed in the case event hash chain (14) so a server replaying an older ciphertext for a row is detected by Desk.

### 13.9 Versioning rules
- `format_version` increments only for incompatible layout changes; readers support N and N−1 for ≥ 24 months.
- New suites require an ADR, KATs and a formal-model update before any tenant may select them.
- Unknown `object_type`, `stanza_type`, `suite_id` or non-zero reserved bits → reject (no "best effort" parsing).

## 14. Key Directory and Transparency Log (C-14)

### 14.1 Purpose
C-14 is a per-tenant append-only Merkle log of every public key, roster and policy statement that determines who can decrypt what, plus accepted client release hashes and onion address statements. It prevents silent key substitution and hidden-recipient insertion (THR-046; INC-14 Anom, INC-62 Matrix, INC-67 Nextcloud) by making every change signed, attributable, continuous and visible to members, monitors and Tier V sources.

### 14.2 Entry format
```
KDEntry (deterministic CBOR map):
  1: entry_type    2: format_version (=1)   3: tenant_id (bstr 16)   4: subject_id (bstr 16 or 32)
  5: subject_seq (uint, 1,2,3… per subject)  6: prev_subject_entry_hash (bstr 32 | null when seq = 1)
  7: not_before_day (uint)  8: not_after_day (uint | null)  9: suite_id (uint)  10: body (map, per type)
SignedKDEntry: { 1: entry_bytes (bstr = canonical encoding of KDEntry), 2: [ {1: signer_key_id, 2: alg (1 Ed25519, 2 ML-DSA-65, 3 ECDSA-P384), 3: sig}, … ] }
Signed message: "candor/v1/kd-entry\x00" ‖ entry_bytes
Leaf hash: H(0x00 ‖ SignedKDEntry bytes)       Interior node: H(0x01 ‖ left ‖ right)   (RFC 6962/9162 tree; Knowledge (unverified) RFC 9162 as algorithm reference)
```

| entry_type | Subject | Body fields | Required signatures |
|---|---|---|---|
| 0x01 ORG_ROOT | tenant | Ed25519 pk, ML-DSA-65 pk, allowed suites, deployment_salt, `kdf_version`, witness/watcher list [{name, K39 pk, role ∈ {witness, watcher}, external_org: bool, external_jurisdiction: bool, endpoint (onion)}] + cosignature policy `w_total`, `w_external`, policy flags | self (both algs); pinned out-of-band (§14.5 VR-1) |
| 0x02 LOG_KEY | log | Ed25519 pk, log origin string | K01 (both algs) |
| 0x03 KEY_ADMIN | admin user | Ed25519 pk (on token), role label | K01 (both algs) |
| 0x04 USER_KEYS | staff user | K08 pk, K09 pk, key_ids, pseudonymous label, device_count, authenticator_count (≥ 2), authenticator attestation hashes, `device_custody` (§9.4), `oob_verified_by` (user_id of the second approver who verified `person_ref` out of band, ADR-036(2)) | K08 (self) + 1 K15 + K08 of the out-of-band verifier (≠ the K15 holder) |
| 0x05 CHANNEL_IDENTITY | channel | CIK pk, `orphan` flag, `activation_day` | seq 1: creator K08 + 2 distinct K15 + 1 OVERSIGHT K08; seq > 1: previous CIK + 1 K15; orphan: K01 + 2 K15 + 1 OVERSIGHT K08, time-locked 7 days in all profiles (§14.4 rule 7) |
| 0x06 CHANNEL_ROSTER | channel | roster_version, `activation_day`, `change_class ∈ {tightening, loosening}`, members [{user_id, user_keys_entry_hash, role_label, role_label_cert_hash, caps ⊆ {read_intake, channel_admin, investigate}, member_since_day}] (`read_intake` = Triage Set, 2..16 members), channel_type ∈ {STANDARD, INDEPENDENT}, independent_route (channel for escalations and COI-exhausted sources), recovery {enabled, quorum_entry_hash, holder_labels}, custodian_entry_hash, names_published flag | current CIK + 1 K15; **loosening** (any addition, any `read_intake`/`channel_admin` grant, any role-label change) additionally + K08 of 1 approver from an independent role (OVERSIGHT or an independent-labelled Triage Set member) who is not the CIK signer (ADR-036(2)) |
| 0x07 MEMBER_EPOCH | (channel, member, epoch) | channel_id, user_id, role_label, epoch_id, pk, key_id, valid_from_day, valid_until_day, user_keys_entry_hash | the member's K08 (ADR-030) |
| 0x0F COI_POLICY | channel | policy_version, `activation_day`, `change_class`, categories [{category_id, label, excluded_role_label_ids}], source-selectable role list | current CIK + 1 K15; loosening (any category's excluded set not a superset of the previous version's, or a source-selectable role removed) + 1 independent-role K08 as for rosters |
| 0x08 CUSTODIAN_GROUP | tenant | pk, key_id, custodian labels, custodian count | K01 (both algs) |
| 0x09 RECOVERY_QUORUM | tenant | enabled flag, pk, key_id, k, n, holder role labels (GOV default enabled with independent-role holders, ADR-044(3)), ceremony date | K01 (both algs) + 2 K15 (DANGEROUS CFG outside GOV, ADR-013) |
| 0x0A ONION_ADDRESS | tenant | active onion addresses, standby addresses (optional), revoked addresses | K01 (both algs); + ≥ 1 external witness cosignature in EE/GOV/MANAGED (16 §11.1) |
| 0x0B CLIENT_RELEASE | product | product (source-app, web-bundle, desk), version, artifact hash / WEBCAT manifest hash, TUF targets version | 1 K15 (records the tenant's acceptance; release authenticity is by 33) |
| 0x0C REVOCATION | key_id | revoked key_id, reason code (never distinguishing COI from other reasons), effective_day | signer authorized for the subject type |
| 0x0D SERVER_PIN | service | Z-CORE API SPKI hashes (current, next) for Desk pinning | K01 or 2 K15 |
| 0x0E RECOVERY_PERFORMED | tenant | day, case_count (content-free, §16) | K14-ceremony output signed by 2 K15 |
| 0x10 ROLE_LABEL_CERT | (channel, role label) | role_label, `independent` flag and body type (ombudsman, audit committee, external counsel, IG, ethics officer, channel owner), valid_until_day (≤ 12 months) | K08 of an OVERSIGHT member listed in GOVERNANCE_ROLES (ADR-036(3)) |
| 0x11 GOVERNANCE_ROLES | tenant | OVERSIGHT members [user_keys_entry_hash], independent-role members, statement signers {k, n, [user_keys_entry_hash, independent flag]}, `small_org_mode` + external party label (ADR-045), time-lock durations (72 h / 7 d by profile) | K01 (both algs) |
| 0x12 OBJECTION | (channel, pending entry hash) | objected entry hash, reason code | K08 of any current channel member or OVERSIGHT member; resolution = a second OBJECTION_RESOLVED body signed by 2 OVERSIGHT K08 |
| 0x13 OPERATOR_STATEMENT | tenant | fixed statement text version, `reduced_separation_of_duties`, issued_day, valid_until_day (= issued + 30) | k-of-n statement signers' K08, ≥ 1 independent (§9.14) |
| 0x14 (reserved) | — | — | — |
| 0x15 SEALER_ATTESTATION | intake host | K35 pk, TEE type, attestation report, measurement, running_manifest_hash, day | K35 (inside TEE) — verified against the TEE vendor chain, not a Candor key |
| 0x16 RUNNING_MANIFEST | intake host | running manifest bytes (§9.14) — appended weekly; the daily copy is served on the onion | K35 |
| 0x17 INCIDENT_NOTICE | tenant | day, scope, window_days | IR lead K08 + independent-role approver K08 (ADR-035(4)) |
| 0x18 ROUTING_KEY | intake | K37 pk, key_id, suite | K01 (both algs) |
| 0x19 CONNECTOR_KEY | connector | K38 pk, key_id, connector_id, allowed export kinds, expiry_day | K01 + 1 K15 |

Role labels are pseudonymous by default (e.g., "Compliance officer A"); real names only if the tenant opts in (13-FRONTEND-ADMIN.md); publishing names on a channel that accepts ANONYMOUS reports is a DANGEROUS configuration (RVW-B-32). Role labels used for sealing SHALL carry a current ROLE_LABEL_CERT (ADR-036(3)).

### 14.3 Checkpoints (signed tree heads)
Signed-note text (C2SP tlog-checkpoint style; Knowledge (unverified) — exact spec version pinned at implementation):
```
candor-kd/<tenant_id as 32 hex>/v1
<tree_size decimal>
<base64(root_hash)>
issued <YYYY-MM-DDTHH>Z

— candor-log-<tenant short> <base64(key_hash[0..4] ‖ Ed25519 signature)>
— <witness name> <base64(key_hash[0..4] ‖ timestamp u64 ‖ cosignature)>   (0..n lines)
```
- **Fixed cadence (RVW-A-29):** C-14 issues exactly one checkpoint per hour at hh:00 UTC, whether or not entries were appended (hour-granularity `issued` line; no finer time). Checkpoint issuance therefore reveals nothing about append times within the hour.
- **Publication slots (ADR-036(7)):** MEMBER_EPOCH entries, roster/COI loosening entries, ROLE_LABEL_CERT, RUNNING_MANIFEST and SEALER_ATTESTATION entries are queued by C-14 and appended only in the **weekly publication slot** (Monday 00:00 UTC checkpoint). **Tightening** entries (removals, REVOCATION, COI tightening, INCIDENT_NOTICE, OBJECTION) are appended immediately and appear in the next hourly checkpoint, because ADR-036(2) makes removals effective immediately; the hour of a removal is therefore visible to directory readers (residual, §27).
- **Witnesses (ADR-036(5); RVW-A-08):** ORG_ROOT lists witnesses and the cosignature policy. EE, GOV and MANAGED tenants SHALL require ≥ 2 witness cosignatures on every checkpoint, of which ≥ 1 is from a witness outside the operating organisation (`w_external ≥ 1`; C-14 refuses an ORG_ROOT that violates this for these editions); CE tenants SHOULD configure the same and otherwise run with the fallback of CA-7. Witnesses cosign only checkpoints consistent with the last one they cosigned. Witness candidates: the channel's independent-route host (ombudsman/audit committee), the vendor's witness (EE), civil-society witness networks (36). A witness learns only tree size and root hash (no key material). Witnesses that publish an onion endpoint serve their latest cosigned checkpoint for the tenant there (VR-3).
- C-09 pushes to C-06, with each snapshot: latest checkpoint + cosignatures, all entries (tenant logs are small: O(10^4) entries), and consistency proofs from the last 16 checkpoints and from the intake's high-water mark.

### 14.4 Continuity rules (enforced by C-14 on append and re-verified by every verifier)
1. `subject_seq` increments by exactly 1; `prev_subject_entry_hash` equals the hash of the previous entry for the subject.
2. CHANNEL_IDENTITY seq > 1 is signed by the CIK of seq − 1 (key continuity) and one K15; `orphan = true` entries require K01, 2 K15 and an OVERSIGHT K08, trigger a mandatory alert to every tenant user and are displayed to sources.
3. CHANNEL_ROSTER is signed by the CIK current at append time and by one K15 whose KEY_ADMIN entry is unrevoked; additions reference a USER_KEYS entry signed by the added user, one K15 and the out-of-band verifier. The same K15 MUST NOT approve both the USER_KEYS entry and the roster addition of the same user, and the independent-role approver of a loosening entry MUST differ from the CIK signer and from both K15 holders (no single person satisfies two roles; `person_ref` distinctness per 15).
4. MEMBER_EPOCH is accepted only if signed by the K08 of a member who is in the latest active roster with `read_intake`; it is usable for sealing only while that remains true (a later roster removing the member implicitly retires it for sealing; an explicit REVOCATION is also appended in the same append batch).
5. At most one unrevoked MEMBER_EPOCH per (channel, member, epoch_id); 2..16 `read_intake` members per roster, each with a current independent ROLE_LABEL_CERT; `channel_admin` only for `read_intake` members and OVERSIGHT members, never for a role label that appears in the channel's COI_POLICY (ADR-036(1)).
6. RECOVERY_QUORUM and CUSTODIAN_GROUP changes are also reflected in every subsequent roster of affected channels.
7. **Time-lock (ADR-036(2)):** a CHANNEL_ROSTER or COI_POLICY entry with `change_class = loosening`, and every CHANNEL_IDENTITY `orphan` entry, has `activation_day ≥ inclusion_day + D`, where D = 3 days (72 h) by default and 7 days for GOV and HIGH profiles and for all orphan re-keys (stricter than ADR-036's minimum for the orphan case, RVW-C-05). An entry becomes **active** at `activation_day` only if no unresolved OBJECTION references it. Until then sealers keep using the previous active entry. A `tightening` entry (a removal, a capability reduction, an exclusion addition) is active on inclusion. A single entry that both adds and removes is split by the proposing Desk into a tightening entry and a loosening entry. C-14 notifies all current members and OVERSIGHT content-free at inclusion ("a change to channel <label> becomes active on <day>").
8. **Objections:** during a time-lock any current channel member or OVERSIGHT member may append an OBJECTION; activation is blocked until two OVERSIGHT members sign a resolution. Objections and resolutions are visible to members and Tier V sources.

### 14.5 Client verification rules (C-03, WEBCAT bundle, C-07, C-15, C-25)
| Rule | Check |
|---|---|
| VR-1 | ORG_ROOT keys are pinned out-of-band: Tier V source app — from the signed onion address statement obtained with the app (externally witness-cosigned in EE/GOV/MANAGED), or entered/scanned fingerprint from the clearnet info site / printed material; Desk — at enrollment ceremony; C-07 — at install. Any ORG_ROOT change other than a K01-signed rotation (old K01 signs new K01) is fatal. |
| VR-2 | Checkpoint signature by the LOG_KEY (itself signed by K01) verifies, and cosignatures satisfy the ORG_ROOT policy (EE/GOV/MANAGED: ≥ 2 valid cosignatures including ≥ 1 external witness, ADR-036(5)). |
| VR-3 | Consistency and pinning: **Tier V Source App** — keeps a persistent pin of the last seen tree head per tenant (`tenant_id, tree_size, root_hash`, stored in the app's data directory, ADR-036(5); a device trace, THR-048, disclosed in 05); on each session fetches the latest cosigned checkpoint from ≥ 1 external witness endpoint over Arti (not via the tenant onion; endpoints and K39 keys come from ORG_ROOT and from the witness key set embedded in the app release, 33 §15.2) and requires consistency among the pin, the witness checkpoint and the tenant-served checkpoint before sealing (RVW-A-08). **Tier V web bundle** — cannot persist state; it shows the tree head as a short fingerprint (first 8 base32 characters of `H(tenant_id ‖ tree_size ‖ root_hash)`) that the source may note and compare next time. Desk, C-07 and C-25 — from their last stored checkpoint / high-water mark. Inconsistency = fatal alert ("directory fork"). |
| VR-4 | Every entry used is included (inclusion proof or full-tree recomputation) and satisfies §14.4. |
| VR-5 | Freshness: checkpoint `issued` ≤ 24 h old for sources, intake and Desk (RVW-A-04; v1.0 allowed 72 h for sources/intake), judged against the independent-time check (§12.1 step 3), and not below the verifier's high-water mark; otherwise fail closed with a user-visible reason. |
| VR-6 | Recipient selection per §12.1 (active roster, active COI_POLICY, MEMBER_EPOCH validity, Triage Set only, follow-up rule); suite matches ORG_ROOT allowed suites. |
| VR-7 | Reply signatures verify against the K08 of a member in the roster valid on the reply's `day`. |
| VR-8 | Tier V displays the roster summary before the source confirms: Triage Set role labels with certification and "member since", which roles the COI filter will exclude for the chosen category and flags, pending (time-locked) changes and changes in the last 30 days, device-custody status for INDEPENDENT channels, recovery escrow ENABLED/DISABLED + holder labels, custodians, and whether a valid Operator Statement exists; the roster hash and the Recipient List are included in the SUBMISSION (§13.4 keys 6, 16). |
| VR-9 | Desk, on import: (a) verifies `source_sig` (and `sealer_sig` for Tier W; in the Confidential-VM profile, that the K35 key is bound to a current release-matching SEALER_ATTESTATION) over the Recipient List; (b) checks every listed key_id is a valid MEMBER_EPOCH of a `read_intake` member in the directory at the stated checkpoint; (c) recomputes the expected recipient set from active roster, active COI_POLICY, `concerns_roles`, `category_id` and — for SOURCE_MESSAGEs — the report's original eligible set, and compares; (d) verifies that each non-listed slot is a valid dummy and that the number of non-dummy slots equals the list length; (e) checks the stated checkpoint was issued no earlier than `received_date − 4 days` (3-day maximum delayed delivery + 1 day, ADR-038(4)) and raises "sealed to superseded roster" if any listed recipient had been removed by an entry included before that bound (RVW-A-04); (f) for initial submissions, checks there is exactly one IDENTITY object. Any mismatch = alert "intake presented a different directory or recipient set" (possible Z-INTAKE compromise or malicious client). Recipient key IDs are taken only from the authenticated Recipient List, never from any cleartext header (ADR-046(10)). |
| VR-10 | CLIENT_RELEASE: C-25 and Desks fetch the served web bundle manifest hash from the onion and alert if it is not the latest accepted CLIENT_RELEASE (REQ-H-28 pattern). |
| VR-11 | Revoked keys are never used for encryption and signatures by revoked keys dated after `effective_day` are rejected. |
| VR-12 | Parsing of entries is bounded (entry ≤ 64 KiB, log ≤ 10^6 entries per snapshot) to prevent resource exhaustion. |
| VR-13 | **Tier W honesty (ADR-036 Tier W limit; RVW-A-17):** Tier W pages SHALL NOT present fingerprints, witness status or directory checks as protection for a web submission; where directory data is shown it carries the fixed sentence "Checking these values does not protect a report sent from this website; only the Candor app checks them before encrypting." Verification for Tier W is performed by Desk at import (VR-9) and by External Watchers. |
| VR-14 | Operator Statement: Tier V clients and Desks verify the latest OPERATOR_STATEMENT (signers per GOVERNANCE_ROLES, ≥ 1 independent, `valid_until_day ≥ today`) and show a warning when absent or expired; C-06 renders the same warning banner on Tier W pages (ADR-035(2)). |

### 14.6 Hidden-recipient detection and COI confidentiality (THR-046, THR-020)
| Attack | Detection / prevention |
|---|---|
| Server substitutes its own epoch key for a member | Tier V: key not a valid MEMBER_EPOCH (K08 of a roster member) → refused (VR-4/VR-6). Tier W: C-07 is the server; the importing Desk detects the foreign key_id in the Recipient List (VR-9b) or a non-dummy slot not covered by the list (VR-9d). |
| Sealer omits a member it should have included | VR-9c recomputes the expected set; mismatch alerts. |
| Sealer adds a hidden extra slot | VR-9d: every slot must be a verifiable dummy or a listed recipient. |
| Sealer copies Tier W plaintext out (adds no slot) | Not detectable by VR-9 (RVW-A-01). Evidence only: External Watchers (running manifest, static-asset digests), Operator Statement, Confidential-VM attestation where deployed (§9.14). Residual, disclosed to sources (ADR-035(5)). |
| Server freezes or rolls back the directory / clock | High-water mark and independent time at the intake (§12.1); VR-5 24 h; Tier V pin + witness-fetched checkpoint (VR-3); Desk VR-9(e) "sealed to superseded roster". |
| Server shows a forked log to one source | ≥ 2 witness cosignatures incl. ≥ 1 external (VR-2) + persistent pin and witness-fetched checkpoint (VR-3); in CE without external witnesses, detection relies on VR-9 at import — residual (§27). |
| Admin or accused member adds a member, relabels itself or loosens COI_POLICY | Needs the CIK (held only by the Triage Set and OVERSIGHT) + 1 K15 + an independent-role approver; certified labels; 72 h / 7-day time-lock with objections; visible to all members, OVERSIGHT and Tier V sources ("pending change", "member since") (ADR-036). A three-party collusion including an independent-role holder remains possible (§27). |
| Orphan re-key by K01 + 2 K15 (governance capture, RVW-C-05) | Additionally needs an OVERSIGHT K08; 7-day time-lock; alert to every user; shown to sources. K01 share distribution per §21.3. |
| A roster member exfiltrates its own MEK private keys | Not cryptographically detectable (insider); bounded to envelopes where that member was eligible; audit (20). Residual. |
| Recovery quorum silently enabled | RECOVERY_QUORUM entry requires K01 + 2 K15 and propagates to every roster; sources see "Recovery escrow: ENABLED". |
| Vendor-pushed client that adds a recipient (Anom) | Client code integrity (§24, 33); VR-9d at import. |
| **DB thief, admin or server learns which members were excluded** (THR-020) | Slots carry no key IDs and dummies are indistinguishable (CA-9); the Recipient List and COI flags are inside the AEAD payload; only Triage Set members list pending envelopes; after import, exclusions are stored only as padded blinded tags (§9.11). **This holds until import** (RVW-A-18): after import, the case ACL visible to C-22 reveals who has access, and non-membership of a Triage Set member in a case ACL is visible to C-22 and to that member. |
| **Excluded member learns that an exclusion happened** (THR-020) | **Not fully preventable with per-member keys.** Triage-first (ADR-037) confines the signal to Triage Set members: members outside the Triage Set never list, receive notifications for or trial-decrypt envelopes, and their dashboards show no intake counts. A Triage Set member ticked by the source can still observe a pending envelope it cannot open, which reveals that some exclusion (source tick, COI map, missing MEK) applied — not the content or flags. Chaff envelopes (RVW-A-18/B-04) are not adopted by the ADRs; residual (§27 #5). |

### 14.7 Monitoring
- Every Desk validates the full tenant log on each sync and raises non-dismissable notifications for changes affecting channels the user belongs to (roster, pending time-locked changes, objections, CIK, epoch wrap counts, quorum, custodians, orphan re-key, ORG_ROOT, GOVERNANCE_ROLES, missing Operator Statement, INCIDENT_NOTICE).
- C-25 validates all invariants every 15 min and alerts SOC on any violation (content-free alert).
- External witnesses and watchers (≥ 2 organisations, ≥ 1 outside the operator's jurisdiction for EE/GOV/MANAGED; ADR-035(1)) receive checkpoints and entries read-only, fetch them over Tor, and publish mismatches.

## 15. Key rotation and forward secrecy

### 15.1 Rotation schedule
| Key | Scheduled rotation | Event-driven rotation | Mechanism |
|---|---|---|---|
| K01 Org Root | 5 years | Suspected compromise; ≥ k share holders replaced | Offline ceremony; new ORG_ROOT entry signed by old and new K01 |
| K02 Log Signing Key | 2 years | Host compromise | New LOG_KEY entry; last checkpoint under old key cosigned by new key |
| K03 Channel Identity Key | 24 months | Removal of a member holding it; member device compromise | §25.6 (continuity-signed) |
| K04 Member Epoch Key | 7 days (automatic, per member) | Member removal (member's MEKs revoked); suspected device compromise (member's future MEKs revoked and regenerated) | §25.7 |
| K05 Content Key | never (immutable object) | — | Re-wrapped, never re-keyed; re-encryption only for suite migration |
| K06 Case Key | 12 months for cases open > 12 months | Member removed from case ACL; member device compromise; FIPS nonce budget | New version, re-wrap of CK stanzas and record re-encryption on write (lazy) + background re-encryption of records within 30 days |
| K08 User Identity Key | 36 months | Device loss/compromise; departure | New USER_KEYS entry (K15-approved) |
| K09 User Encryption Key | 12 months | Device loss/compromise | Re-wrap all wraps addressed to old key, then destroy old key |
| K10 hardware wrap key | Token replacement (≤ 5 years) | Token loss | Re-seal keystore under new token |
| K12 Source keys | none scheduled | Source-initiated rotation from the inbox (§11.7; offered at each Tier W login in HIGH) or abandonment | §11.7 KEY_ROTATION (continuity-signed, same case); abandonment = new identity (unlinkable by design) |
| K13 Custodian Group | 24 months | Custodian change | New group key; remaining custodian re-wraps identity CKs |
| K14 Recovery Quorum | 36 months | Holder change; suspected share loss | New key, Desks re-wrap case keys; old shares destroyed in a recorded ceremony |
| K15 Key-Admin keys | 36 months | Role change, token loss | REVOCATION + new KEY_ADMIN entry (K01) |
| K16 Onion service key | none scheduled (address stability) | Compromise (THR-044) | 16-TOR-I2P.md §onion key custody |
| K18 Internal CA | root 5 years (offline), intermediate 12 months, leaves 7 days | Host compromise | Automated leaf renewal; intermediate via ceremony |
| K21 Disk (LUKS) | Keyslot passphrases 12 months | Hardware re-provision | `cryptsetup luksChangeKey`; volume key only on reinstall |
| K24 Audit checkpoint key | 2 years | Host compromise | 20-LOGGING-AUDITING.md |
| K25 Backup keys | generation key monthly; master 3 years | Compromise | §17 |
| K28 Session MAC keys | 24 hours | Compromise | 15 |
| K35 Intake Sealer key | 12 months; every sealer restart in the Confidential-VM profile | Intake compromise | New key; SEALER_ATTESTATION (CVM) or pin update |
| K36 Tier W draft session key | Per session (≤ 2 h) | — | Zeroized at expiry/submit/discard/restart |
| K37 Intake Routing Key | 24 months | Intake compromise | New ROUTING_KEY entry (§9.12) |
| K38 Connector Key | ≤ 12 months (entry expiry) | Connector host compromise | New CONNECTOR_KEY entry; REVOCATION of old |

### 15.2 Forward secrecy provided
| Where | Mechanism | FS window | Conditions |
|---|---|---|---|
| Source ↔ onion service transport | Tor circuit ephemeral keys | Circuit lifetime | Tor assumptions |
| Internal TLS 1.3 | Ephemeral (EC)DHE / hybrid KEM, no resumption across hosts | Connection | — |
| Intake envelopes (both tiers) | Member Epoch Keys retired after window AND import (ADR-030, ADR-033, ADR-038(6)) | ≥ 7 + 14 days; extends until every envelope of the epoch is imported or rejected; undecryptable envelopes can be dual-approved-rejected and deleted after 14 days pending, so an unopenable envelope cannot pin MEKs beyond the approvers' reaction time (RVW-A-20) | MEK private keys exist only in members' Desk keystores (never on servers or in backups), so retirement on every holding Desk (including linked devices) completes FS for the intake slots; imported content is thereafter protected by case keys (no FS, §15.3) |
| Tier V source device | Nothing retained after submission (no local state) | Immediate | Source device not compromised during use |

### 15.3 Where forward secrecy is NOT provided (explicit)
| Where | Why | Consequence | Mitigation |
|---|---|---|---|
| Case keys (K06) | A case must remain readable by its members for its lifetime | Theft of a member's unlocked device or K09 exposes every case the member can access, including history | Least privilege (ADR-015), hardware-bound K10, K09 rotation, case-key rotation on removal, crypto-erase at retention end |
| Replies to sources | Source keys derive from a long-lived passphrase; sources are stateless (B-CR-24 notes the same asymmetry for SecureDrop Protocol) | Passphrase disclosure (THR-034) exposes all replies still stored at intake (≤ 30 days, ADR-039) | 30-day reply window, passphrase rotation (§11.7), source-initiated mailbox deletion, no reply attachments |
| Identity sections (K13) | Must be unsealable later under legal process | Custodian key theft exposes all identity sections | Custodian hardware keys, dual approval, rotation |
| Staff keys (K08/K09) | Long-lived identities | — | Hardware binding, rotation |
| Recovery quorum (K14) | Escrow by definition | k shares expose all wrapped cases | Off by default (ADR-013) |

### 15.4 Suite migration
To move a tenant from STD to FIPS (or to a future suite): (1) K01 signs ORG_ROOT allowing both suites; (2) users publish new-suite K09 keys; (3) members publish new-suite MEKs (intake switches at the next epoch); (4) case keys re-wrapped to new-suite K09 keys; (5) optional re-encryption of blobs into new-suite objects by Desk (new object_id, `derived_from` record for evidence; originals kept until verified); (6) ORG_ROOT removes the old suite. Objects are never partially migrated.

## 16. Recovery and escrow (ADR-013)

- **Default: no escrow in CE/EE; enabled in GOV (ADR-044(3)).** GOV deployments default to an Organization Recovery Quorum with custodians from independent roles, disclosed to sources on the landing page and in VR-8, because records law may prohibit unrecoverable loss (RVW-C-14). Desk refuses to finalize a case ACL or channel roster with fewer than 2 key holders (ADR-044(2)); a tenant with fewer than 2 staff users cannot enable ANONYMOUS channels without small-organisation mode's external party (ADR-045). Loss of all holders' devices **and** their offline keystore backups (§9.4) = permanent loss of the affected cases/unimported intake; this is stated in admin onboarding.
- **Optional Recovery Quorum (C-28).** K14 generated on an air-gapped ceremony machine (§21.3), Shamir-split (default 3-of-5, minimum 2-of-3, over GF(2^8), per-share integrity tag) onto hardware tokens held by independent roles; K14 public key logged (RECOVERY_QUORUM); roster displays "Recovery escrow: ENABLED, held by: …" to sources. When enabled, every case-key version is also wrapped to K14 (inside the EK layer, §9.10) by the Desk that creates it; Member Epoch Keys are never wrapped to K14 (preserves intake FS and COI exclusion).
- **Recovery ceremony:** (1) dual-approved recovery request listing case_ids (15/14); (2) C-10 removes the EK layer and exports the relevant K14 wraps as a signed request bundle; (3) k holders assemble at the ceremony machine; shares combined in RAM; (4) machine unwraps only the listed case keys and HPKE-wraps them to the target member's K09; (5) K14 private key zeroized, machine powered off; (6) output bundle imported by C-10; (7) audit record and a content-free KD entry `0x0E RECOVERY_PERFORMED` {day, case_count} (visible to members; sources see the count on the roster page).
- **Implications:** an enabled quorum is a standing ability to decrypt every quorum-wrapped case (historical and current, including copies in backups) by k colluding, coerced or compromised holders (THR-018, THR-026). It does not reach unimported intake, identity sections (K13) or cases created while disabled. Disabling: holders destroy shares in a recorded ceremony, Desks delete K14 stanzas; wraps in backups persist until backup expiry (§18.3).
- **Contrast:** GlobaLeaks' admin escrow lets an administrator read everything and was wiped cross-tenant by CVE-2026-46648 (R2 INC-2); CoverDrop uses k-of-n social recovery for journalist vault backups (B-GL-29).

## 17. Backup encryption

### 17.1 Contents
| Included (C-27) | Excluded |
|---|---|
| C-12 database (workflow metadata, encrypted case records, `key_wraps` for CKs and EK-layered case-key wraps, audit tables) | Erasure Key Vault (own backup, ≤ 14-day retention, §9.10); MEK private keys (endpoint-only, never on servers) |
| C-13 sealed objects | Desk keystores (endpoint-only; users re-enroll or use device link) |
| C-08 intake store (sealed envelopes, lookup tags, `auth_pk`, mailbox routing) | Session keys, K28; TLS leaf keys (re-issued) |
| C-14 KD log (public data) | Onion service keys (separate offline escrow, 16-TOR-I2P.md) |
| Configuration (secrets per ADR-028 manifest classified; secrets excluded unless listed) | Swap, temp, caches |

### 17.2 Format
- Each backup archive: STREAM-encrypted (§13.3 construction) with a random 256-bit Archive Key `AK`; `AK` HPKE-wrapped to the **Backup Master public key** (K25-pub). The backup agent holds only public keys, so a compromised backup host or store cannot read archives.
- Archive manifest (object list, sizes, hashes) signed by the Backup Agent signing key (Ed25519, TPM-sealed on the backup host); manifests hash-chained (19).
- **Backup Master private key**: generated offline; Shamir 2-of-3 (CE) or HSM with dual-control policy (EE/GOV). Restores require its use (§21).
- Report content inside is already end-to-end encrypted; backup encryption protects infrastructure metadata, lookup tags and wrap tables.

### 17.3 Erasure Key Vault backups (ADR-033 item 3)
The Erasure Key Vault (§9.10) is excluded from routine backups. It has its own backup job: daily, STREAM-encrypted to K25 like other archives, stored separately, **retention ≤ 14 days** with verified deletion of expired EKV backup archives. Restoring a routine backup therefore also requires an EKV backup no older than 14 days; case keys of cases erased before that EKV backup's date cannot be recovered from any backup. EKV backup archives contain EKs re-encrypted to K25, never records sealed under K33 or a TPM, so they restore on replacement hardware (RVW-C-07). Every restore applies the signed erasure log (§9.10) before the core serves requests (ADR-044(4)). If the newest usable EKV backup predates a ransomware or disaster time T0, restore uses the latest EKV backup whose AEAD records verify against the database rows, with dual approval, and the Desk re-wrap procedure (§9.10) recovers cases created after it.

## 18. Deletion and cryptographic erasure (ADR-025)

| Operation | Steps | Effective against |
|---|---|---|
| 18.1 Object erase | Delete all stanzas (HPKE and CASE_AEAD) for `object_hash` in C-12 and C-08; delete blob in C-13/C-08; Desks purge caches; audit tombstone (object pseudonym, day) | Live systems immediately |
| 18.2 Case erase | Dual-approved (35); C-10 appends `{case_id, day}` to the signed erasure log, then destroys the case's Erasure Key K32 in the EKV and its replicas (overwrite + vault compaction; HSM object destroy in EE/GOV); deletes all EK-layered case-key wraps (all versions, all members, K14) and all CK stanzas; deletes blobs; Desks purge case keys and local caches on next sync (Desk refuses to open an erased case); signed deletion receipt `Ed25519(K08 of each approver, "candor/v1/erase" ‖ case_pseudonym ‖ day ‖ counts)` stored in audit (20) | Live systems immediately |
| 18.3 Backups | Routine backups still contain the case's EK-layered wraps, but no copy of K32 exists outside EKV backups, which expire within ≤ 14 days | All backed-up copies unreadable after ≤ 14 days (documented upper bound of "delete" for backups, ADR-033) — even for an adversary holding a member K09 or k quorum shares |
| 18.4 Media | LUKS volume-key destruction on decommission (`cryptsetup erase`) + physical destruction per NIST SP 800-88r2 CE preconditions (B-CR-33) | Disk theft after decommission |
| 18.5 Source mailbox deletion | Source deletes replies: stanza(1) + delivery record deleted in C-08 | Intake only; the organisation's case copy remains (source is told) |

**Not reachable by erasure:** Export Packages and anything a recipient copied, printed or photographed (THR-041); data under legal hold (erase blocked, 35); plaintext that touched swap or journals on a compromised endpoint; epoch-window envelopes already imported (their CKs live on under the case key until case erase).

NIST SP 800-88r2 preconditions (B-CR-33): keys generated in validated modules (FIPS profile), no plaintext stored before encryption (true for content: servers never store content plaintext; Tier W plaintext exists only in C-07 RAM), all key copies destroyed (K32 and its EKV backups within ≤ 14 days).

## 19. Key table (authoritative inventory)

"Recovery" = what happens if the key is **lost** (not stolen). Rotation details §15.1. Placement is enforced by the Secret Placement Manifest (ADR-028): any key found outside its listed location fails deployment.

| ID | Key (alg) | Who possesses | Where stored | Decrypts / signs | Lifetime | Rotation | If stolen | Recovery if lost |
|---|---|---|---|---|---|---|---|---|
| K01 | Org Root (Ed25519 + ML-DSA-65) | No single person; k-of-n share holders (3-of-5) or HSM with dual control | Offline: Shamir shares on smartcards, or offline HSM (C-29) | Signs ORG_ROOT, LOG_KEY, KEY_ADMIN, CUSTODIAN_GROUP, RECOVERY_QUORUM, ONION_ADDRESS, orphan re-keys | 5 y | Ceremony | Cannot decrypt anything. Enables forged KEY_ADMIN/LOG_KEY/ONION_ADDRESS entries → with 2 forged K15 can orphan re-key a channel to attacker keys; all such entries are logged and alert every Desk; Tier V sources see orphan re-key. | Re-establish trust via new root pinned out-of-band at all Desks and source-facing channels (heavy; avoid by 3-of-5 shares in ≥ 2 locations) |
| K02 | Log Signing Key (Ed25519) | C-14 service | C-14 host, TPM-sealed (CE) / HSM (EE) | Signs checkpoints | 2 y | Planned handover | Can sign forked checkpoints (split view) → detected by witnesses (VR-2) and Desk monitors; cannot forge entries (entries carry their own signatures) | Rotate; no data loss |
| K03 | Channel Identity Key (Ed25519) | Triage Set members and OVERSIGHT members with `channel_admin` only (ADR-036(1)) | Wrapped to those members' K09 in C-14; Desk keystore | Signs channel metadata only: roster, COI_POLICY, channel config (ADR-030) | ≤ 24 months | On removal/compromise, continuity-signed | With one colluding K15 and an independent-role approver: rogue loosening entries, time-locked 72 h/7 d with objections, visible to all members and Tier V sources. Cannot decrypt; cannot sign replies or epoch keys. | Any other holder; if all lost → orphan re-key (K01 + 2 K15 + OVERSIGHT, 7-day time-lock) |
| K04 | Member Epoch Key (X-Wing / MLKEM1024-P384), per Triage Set member per channel per epoch (ADR-030/037) | One Triage Set member | Private: only that member's Desk keystore (sealed by K11; linked devices; offline keystore backup); public: MEMBER_EPOCH entry | Opens that member's slot in envelopes sealed during its epoch | 7 d encrypt + ≥ 14 d decrypt, retained until import or rejection (ADR-033, ADR-038(6)) | Automatic weekly | Opens that epoch's un-imported envelopes in which that member was eligible — not envelopes excluding the member, not other epochs | Other eligible members' slots; the member's offline keystore backup; if all eligible members lose their keys before import, those envelopes are lost |
| K05 | Content Key (256-bit) | Nobody at rest; transiently C-03/C-07/C-15 | Only as wraps (stanzas) | Decrypts one object | Object lifetime | Never (re-wrapped) | Exposes one object | Via any valid wrap |
| K06 | Case Key v (256-bit) | Importing Triage Set members, then investigators granted by the Triage Set (after COI assessment, ADR-037); optional K14 | EK-layered HPKE wraps in C-12 `key_wraps`; Desk keystore cache | Unwraps CKs of the case; derives record keys and K40 | Case lifetime | Version bump on removal/12 months (old wraps destroyed after 7-day cooling, ADR-044(1)) | Exposes entire case (all versions it wraps) | Any other ACL member (≥ 2 holders enforced); Desk re-wrap after EKV loss (§9.10); else K14 if enabled; else lost |
| K07 | Case record subkeys (derived) | Same as K06 | Not stored (derived) | Case fields per table | = K06 | With K06 | = K06 for that table | Re-derive |
| K08 | User Identity Key (Ed25519) | One staff user | Desk keystore sealed by K11 | Signs user's KD entries (incl. MEMBER_EPOCH), replies to sources, ACL grants, approvals, erase receipts | 36 months | New USER_KEYS entry | Impersonate the user's approvals (still needs second approver for dual-control ops); cannot decrypt | New key via K15-approved enrollment |
| K09 | User Encryption Key (X-Wing / MLKEM1024-P384) | One staff user | Desk keystore sealed by K11 | Unwraps case keys (after C-10 removes the EK layer), CIK, (custodian K13) addressed to the user | 12 months | Re-wrap then destroy | Everything the user can access now, and (with EKV/backups ≤ 14 days old) wraps of cases the user held — bounded by ACL (THR-013) | Other members re-grant access; K14 if enabled |
| K10 | Hardware wrapping key (FIDO2 PRF / PIV / TPM) | User's token/device | Hardware (non-exportable) | Unseals Desk keystore (via K11) | Token life | Token replacement | Needs the Desk keystore file too; with both → as K08+K09 | New token + device link / re-enrollment |
| K11 | Desk keystore key (derived) | Desk process in RAM while unlocked | Not stored | Seals K08/K09/cached keys | Session | Per unlock | Same as K08+K09 | Re-derive from K10 |
| K12 | Source seed + derived keys (lookup, auth, sign, X-Wing, K_prefs) | The source only (passphrase in memory); C-07 RAM transiently (Tier W session ≤ 2 h) | Nowhere persistent; server stores `lookup_tag`, `auth_pk`, `prefs_ct` | Decrypts replies; signs source messages; authenticates deletion/rotation; opens `prefs_ct` | Until rotated or abandoned | Source-initiated (§11.7) | Read stored replies (≤ 30 days) to that source, impersonate the source in the conversation (THR-034) until the source rotates | None by design (no recovery, ADR-005) |
| K13 | Identity Custodian Group Key (X-Wing) | Identity Custodians | Wrapped to custodians' K09 in C-14; custodian Desks | Unwraps IDENTITY objects (ADR-014) | 24 months | On custodian change | Exposes identities of all CONFIDENTIAL sources who provided them | Other custodians; else identities unrecoverable |
| K14 | Recovery Quorum Key (X-Wing) — optional | k-of-n holders jointly | Offline: Shamir shares on tokens | Unwraps every case key wrapped while enabled | 36 months | Ceremony | **Exposes all quorum-wrapped cases, historical and current, including in backups** | Lost shares < k: re-share at next ceremony; ≥ n−k+1 lost: quorum unusable, cases still accessible to members |
| K15 | Key-Admin Authorization Keys (Ed25519 on FIDO2/PIV) | Designated key-admins (not sysadmins by default) | Hardware token | Co-signs USER_KEYS, rosters, CIK rotations | 36 months | REVOCATION + K01 | One K15 alone cannot add a member (needs CIK) or re-key a channel (needs previous CIK, or K01 + 2 K15) | Revoke, new token via K01 |
| K16 | Onion service identity key (ed25519, tor v3) + standby key | C-05 tor daemon (≤ 2 intake hosts, active/passive, in EE-HA/GOV-ONPREM per ADR-032); standby offline | C-05 `HiddenServiceDir` (LUKS, mode 0700); standby: offline escrow | Proves onion address; decrypts intro/rendezvous handshakes | Long-lived | Only on compromise (16) | Impersonation/phishing of sources via the same address (THR-044); does not decrypt stored content; Tier W live traffic could be intercepted if attacker also routes descriptors (MITM) | Restore from offline escrow or switch to standby address |
| K17 | Staff onion client-auth keys (x25519) — if staff onion used | Each Desk; service holds public parts | Desk keystore / staff onion host `authorized_clients/` | Restricted discovery of staff onion | 12 months | Re-issue | Discovery of the staff onion descriptor only; staff auth still required | Re-issue |
| K18 | Internal CA (root offline, intermediate) + K19 leaf keys | Ops (ceremony) / each service | Root: offline; intermediate: Z-CORE HSM/TPM; leaves: service hosts, TPM-sealed where possible | Authenticates internal TLS/mTLS | root 5 y, int 1 y, leaf 7 d | Automatic leaves | MITM internal links → sees sealed objects, workflow metadata, KD traffic; cannot decrypt content (L0) | Re-issue |
| K20 | Clearnet info site TLS key (WebPKI) | C-37 host | C-37 host | TLS for info site | 90 d (ACME) | Automatic | Impersonate info site → publish a false onion address (mitigated by K01-signed address statement, 16) | Re-issue |
| K21 | Disk volume keys (LUKS2) | Each host (kernel), TPM/Tang, offline recovery passphrase | TPM-sealed keyslot / Tang; recovery passphrase offline | Decrypts media | Host life | Keyslot rotation | With powered-off media: infra metadata, sealed objects (still L0-encrypted) | Recovery passphrase keyslot |
| K22 | DB TDE/column keys (optional EE) | DB host | HSM / KMS | DB files | 1 y | Re-key | Same as K21 for DB | HSM backup |
| K24 | Audit checkpoint signing key (Ed25519) | C-24 | TPM/HSM | Signs audit checkpoints | 2 y | Planned | Forge future audit checkpoints (detected by external anchoring/witness, 20) | Rotate |
| K25 | Backup Master Key (X-Wing; private offline) + Backup Agent signing key | Backup custodians (2-of-3) / HSM; agent key on backup host | Offline shares or HSM; agent key TPM-sealed | Decrypts backup archives (infra metadata, EK-layered wrap tables, EKV backups) | 3 y (master) | Ceremony | Infra metadata and wrap tables of all backups and EKV backups ≤ 14 days old; content still needs member K09/K14 | Lost master = backups unrestorable (hence 2-of-3) |
| K26 | Release signing keys (TUF root/targets/snapshot/timestamp; Ed25519 + ML-DSA-65) | Release signers (vendor/project) | Offline tokens/HSM (33) | Sign updates | per 33 | per 33 | Could sign a malicious update (THR-025) — needs threshold + reproducible-build match + transparency log (33) | per 33 |
| K27 | WEBCAT manifest signing keys | Release signers | Hardware tokens / Sigsum keys | Signs web bundle manifest | per 33 | per 33 | Malicious web bundle to Tier V-web sources (needs threshold, logged) | per 33 |
| K28 | Session MAC/encryption keys (source-web, desk-api) | C-06 / C-21 | RAM only (regenerated on restart) | Session tokens | 24 h | Automatic | Session forgery for ≤ 24 h (sources re-login cheaply) | Regenerate (sessions invalidated) |
| K29 | Staff password pepper (if passwords used) | C-21 | HSM/TPM | Keys HMAC before Argon2id storage | long | 3 y with re-hash on login | Offline guessing of staff password hashes becomes possible (still Argon2id-bound) | Regenerate; force password reset |
| K30 | Export Package key (per export) | Exporting Desk; the external recipient | Wrapped to recipient key or passphrase (age-compatible) | One Export Package | Export life | — | Exposes that package | Re-export |
| K32 | Erasure Key (256-bit, per case; ADR-033) | C-10 service (server-held by design) | Erasure Key Vault (host-local store on its own volume on the C-12 host, 09 §5.6; HSM objects in EE/GOV), encrypted under K33; replicas at standby/DR; own backup ≤ 14 days re-encrypted to K25 | Outer AEAD layer on HPKE stanzas that wrap the case key to members/K14 — never a direct wrap of the case key (§9.10) | Case lifetime | None (destroyed on erase; recorded in the erasure log) | Alone: nothing (inner wraps still need K09/K14). Enables backup-copy recovery of wraps for ≤ 14 days after erase only in combination with K09/K14 | Loss = case keys unrecoverable from DB; recovery by vault backup, DR replica or Desk re-wrap from cached case keys (§9.10) |
| K33 | EKV master key | C-12 host | TPM-sealed (CE; physical TPM, never vTPM, in HIGH/GOV) / HSM (EE/GOV) | Encrypts EKV at rest | Host life / 12 months | Re-encrypt vault | EKV readable → as K32 | Rebuild from EKV backup (K25) or DR replica |
| K34 | Viewer job key (X-Wing, ephemeral) | One disposable C-17 VM | VM RAM only | Receives one object's CK for one job (ADR-033 item 5) | One job | Per job | That one object (viewer compromise already sees its plaintext) | Re-run job |
| K35 | Intake Sealer signing key (Ed25519) | C-07 | Intake host, TPM-sealed; in the Confidential-VM profile generated inside the TEE and bound to its measurement (§9.14) | Signs Tier W Recipient Lists (`sealer_sig`) and the running manifest | 12 months (CVM: per restart) | Planned; on intake compromise | Forge Tier W recipient attestations and running manifests (detected by VR-9c recomputation; outside CVM a root attacker can use it); cannot decrypt | Re-issue; SEALER_ATTESTATION (CVM) |
| K36 | Tier W draft session key (256-bit, ADR-034) | C-07, one per Tier W session | mlocked C-07 RAM only | Staged attachment parts on tmpfs (§9.13) | ≤ 2 h (20 min idle) | Per session | Staged parts of that live session only (plaintext already in the same RAM) | None needed: session restarts (draft lost, stated in UI) |
| K37 | Intake Routing Key (X-Wing / MLKEM1024-P384; ADR-046(12)) | C-08 on the intake host | TPM-sealed where available / inside TEE (CVM profile); public in ROUTING_KEY entry | Opens `routing_ct` → mailbox for reply apply | 24 months | New ROUTING_KEY entry | With the Case DB: links cases to pseudonymous mailboxes (nothing identifying) | BS-SECRETS restore (19); else replies pause until a new key is published and Desks re-queue |
| K38 | Connector Key (X-Wing / MLKEM1024-P384; ADR-046(12), EE) | The integration (C-40 connector host or external system) | Integration's own key store; public in CONNECTOR_KEY entry | Receives Export Package CKs for that connector | ≤ 12 months | New entry + REVOCATION | Exposes packages exported to that connector (already outside Candor's trust boundary) | New key; re-export |
| K39 | External witness / watcher keys (Ed25519) | Witness and watcher organisations (never the operator) | Their own infrastructure | Cosign checkpoints; sign watcher reports | Per operator | Per operator (ORG_ROOT update) | Forged cosignature alone cannot fork the log without the other required witnesses and K02 | Replace via ORG_ROOT update |
| K40 | COI exclusion tag key (derived from K06, ADR-037(3)) | Case key holders | Not stored (derived) | Computes blinded `excl_tag` values | = K06 version | With K06 | Lets the holder test which users are excluded from that case | Re-derive |
| K31 | Intake batch signing key (Ed25519) | C-08 | Intake host, TPM-sealed | Signs batch manifests pulled by C-09 (origin/integrity; low trust) | 12 months | Planned | Forge batches (ciphertext injection = spam class, THR-033); cannot decrypt | Re-issue via C-09 pin update |

(K23 intentionally unused.)

## 20. "If the master key is stolen today, can historical reports be decrypted?"

There is no single server-side master key for content (ADR-008). Every key that could be called "master" is answered explicitly (assumptions: CA-1..CA-5; "historical" = reports received before the theft).

| "Master" candidate | Answer | Explanation |
|---|---|---|
| K01 Org Root | **No.** | Signing only. Future risk: forged directory entries, all logged and alerting; orphan re-key additionally needs 2 K15. |
| K02 Log Signing Key | **No.** | Signs checkpoints only; split views detectable (VR-2/VR-3). |
| K03 Channel Identity Key | **No.** | Signs channel metadata only. Future risk (with a colluding K15): rogue roster/COI entries, logged and visible. |
| K04 a member's current Member Epoch Key | **Only un-imported envelopes of that epoch in which that member was eligible.** | Not envelopes that excluded the member (COI), not retired epochs (§15.2). Imported content needs case keys. |
| K32 Erasure Key / K33 EKV master | **No.** | Outer layer only; inner case-key wraps still need K09/K14 (§9.10). |
| K37 Intake Routing Key | **No.** | Reply routing only; with the Case DB it links cases to pseudonymous mailboxes. |
| K36 Tier W session key | **No (historical).** | Exists only during one live session. |
| K09 a member's User Encryption Key (+ device unlock) | **Yes, within that member's scope.** | All cases the member can access (and older case-key wraps in backups until K09 rotation), plus live epoch keys. Not cases outside the member's ACL (ADR-015). |
| K13 Identity Custodian Group Key | **Yes, for identity sections only.** | All stored IDENTITY objects of CONFIDENTIAL reports; not report content. |
| K14 Recovery Quorum Key (if enabled; needs k shares) | **Yes.** | Every case wrapped while the quorum was enabled, historical and current, including copies in backups. Not unimported intake, not identities, not cases from disabled periods. This is why it is off by default and shown to sources. |
| K25 Backup Master Key | **No (content).** | Exposes infrastructure metadata, EK-layered wrap tables and EKV backups ≤ 14 days old; content still requires K09/K14. Combined with a member K09 → as K09 row, limited to cases not erased more than 14 days earlier. |
| K21 Disk / K22 TDE keys | **No.** | Media layer only (§7). |
| K18 Internal CA | **No.** | Enables internal MITM of ciphertext and metadata; Tier W plaintext never crosses TLS links (C-06→C-07 is a local Unix socket). |
| K16 Onion service key | **No.** | Transport identity. Future risk: impersonation of the intake address (THR-044), which could capture future Tier W plaintext from deceived sources. |
| HSM master/wrapping key (EE) | **No.** | HSMs hold signing/infra keys only; recipient private keys never enter server HSMs (ADR-007). |
| K26 Release root keys | **No (directly).** | Future risk: malicious update (THR-025), mitigated by thresholds, reproducible-build matching and transparency (33). |
| A source's passphrase | **Only that source's replies.** | The source cannot decrypt its own submissions (sealed to epoch keys). |

### 20.1 Compromise scenario analysis
| Scenario (adversary) | Content exposed | Metadata exposed | Detection | Response |
|---|---|---|---|---|
| Live root on Z-INTAKE (attacker, THR-014) | Tier W plaintext submitted **and passphrases of Tier W sources who log in** during compromise — hence their stored replies (≤ 30 days), `prefs_ct` and the ability to impersonate them until they rotate (RVW-A-03); COI flags of those submissions; Tier V: none (unless attacker also has a malicious client release) | Lookup tags, `auth_pk`, `routing_ct` openings via K37, day-granularity receipt, size buckets, onion key (K16), K35; Tier W login times of targeted accounts (Tier V reads are fetch-all, ADR-039) | VR-9 at import (roster/checkpoint mismatch); External Watchers (static assets, running manifest), C-25; CLIENT_RELEASE mismatch; CVM attestation where deployed. Plaintext copying by the sealer is **not** detectable by VR-9 | 31: rebuild intake, rotate K16 (standby), K35, K37; INCIDENT_NOTICE; advise affected Tier W sources to rotate passphrases (§11.7) |
| Live root on Z-CORE (THR-014/018) | None directly (no content keys); can withhold/replay ciphertext, attempt rogue KD entries (need CIK/K15) | Workflow metadata, ACL graph, audit | KD monitors, audit chain, VR rules | 31 |
| Theft of DB + blobs (THR-015) | None | Workflow metadata (L1 if media stolen powered-off: nothing) | — | — |
| Theft of backups (THR-017) | None (needs K25 and K09/K14; erased cases need an EKV backup ≤ 14 days old) | With K25: metadata | — | Rotate K25 |
| Stolen locked Desk laptop (THR-031) | None without K10 token + PIN/biometric | Local encrypted cache | User report | Revoke USER_KEYS, rotate case keys the user held |
| Stolen/compromised unlocked Desk (THR-013/041) | Member's scope (§20 K09 row) + un-imported envelopes where the member was eligible (MEKs); attachment plaintext only if the attacker also drives C-17 jobs | Member's case metadata | EDR, anomalous access audit | Revoke USER_KEYS and MEKs, rotate CIK (if held) and affected case keys |
| Malicious sysadmin (THR-018) | None (no case keys; ADR-015) | Infra metadata | Audit | — |
| Malicious key-admin + colluding CIK holder + colluding independent-role approver (THR-046) | Future intake of the channel after the 72 h / 7-day time-lock (adds a member) | — | Pending change visible to all members, OVERSIGHT and Tier V sources during the time-lock; objections block activation | Object, remove, rotate |
| Compelled operator (THR-026) | Future Tier W plaintext and login passphrases if compelled to modify C-07 (Hushmail/Lavabit class); none historical | As above | External Watchers (only if the modification is visible in served assets or the running manifest), Operator Statement not renewed, CVM attestation (HIGH/GOV option); Tier V unaffected | Honest disclosure (ADR-004, ADR-035(5)) |
| Future quantum adversary with recorded traffic | Tier W transit (Tor classical handshakes, §5.1) unless onion HTTPS with PQ group; stored objects protected by ML-KEM hybrid (CA-1) | — | — | Prefer Tier V; onion TLS for HIGH profile |

## 21. HSM / PKCS#11 / TPM, offline roots, split knowledge, thresholds

### 21.1 Placement options
| Key | CE default | EE option | GOV (FIPS) |
|---|---|---|---|
| K01 Org Root | Shamir 3-of-5 on smartcards, offline ceremony machine | Offline HSM (FIPS 140-3 L3) + Shamir backup | Offline HSM L3; ML-DSA component on ceremony machine if HSM lacks ML-DSA |
| K02 Log, K24 Audit, K31 Batch | TPM 2.0 sealed blob (unsealed to RAM at start) | Network HSM via PKCS#11 (`CKM_EDDSA`, PKCS#11 v3.0) | HSM L3 |
| K18 intermediate CA | TPM-sealed | HSM | HSM |
| K22 TDE, K29 pepper, K33 EKV master, K35 sealer, K37 routing | TPM-sealed (K33: physical TPM, not vTPM, in HIGH profiles) | HSM/KMS on-prem; K35/K37 inside the sealer TEE in the Confidential-VM profile | HSM (K33 on physical TPM or HSM, ADR-044(4)) |
| K32 Erasure Keys | EKV file/schema under K33 | HSM objects (destroy = `C_DestroyObject`) | HSM |
| K25 Backup Master | Shamir 2-of-3 offline | HSM with dual-control (M-of-N card) policy | HSM |
| K10 staff wrap | FIDO2 PRF / TPM / passphrase fallback | FIDO2 / PIV | PIV (FIPS 201-3) / FIPS-validated FIDO2 |
| K16 onion key | LUKS + file mode 0700 (C-tor cannot use HSM/offline identity keys for onion services — Knowledge (unverified)) | Same | Same |

Rules: recipient/case/epoch private keys never enter server HSMs (ADR-007). TPM "sealed" keys exist in host RAM while in use — HSM residency is required where the threat model includes live-host key extraction (EE/GOV). PKCS#11 integration is via `cryptoki` behind C-11's `Signer` trait; ML-KEM/ML-DSA PKCS#11 mechanisms (v3.2) used only if the HSM's validation covers them (UNVERIFIED availability per vendor, B-CR-30).

### 21.2 Offline master/root keys
K01, K14, K25-private, K18-root and release roots (33) are generated and used only on an **air-gapped ceremony machine**: booted from a reproducibly built, signed, read-only live image (hash verified by two participants), no storage persisting after power-off, no network hardware enabled, RNG health check before key generation, ≥ 2 witnesses plus the required share holders, printed ceremony script, signed ceremony transcript (hashes of outputs) appended to audit (20) and, for public keys, to C-14.

### 21.3 Split knowledge
- Shamir secret sharing (k-of-n over GF(2^8), each share with a 32-byte HMAC tag keyed by a hash of the secret for share-corruption detection) for K01 (3-of-5), K14 (default 3-of-5), K25 (2-of-3).
- Shares stored encrypted on PIN-protected hardware tokens; holders in distinct roles and, for EE/GOV, in ≥ 2 sites/jurisdictions; no person holds ≥ k shares. **K01 share distribution (RVW-C-05):** in tenants with any INDEPENDENT channel, at least n − k + 1 K01 shares (3 of 5 at 3-of-5) SHALL be held by OVERSIGHT or external parties listed in GOVERNANCE_ROLES, so that no coalition of management-line holders alone reaches k; holder role labels are listed in ORG_ROOT and shown in VR-8. Share inventory audited annually (holder attests possession with a signature over a challenge using a token-bound key, without revealing the share).
- Reconstruction only on the ceremony machine; the reconstructed key is zeroized before power-off.

### 21.4 Threshold signatures
- **Default: explicit k-of-n multi-signatures** (TUF roles, KD entries with multiple signer entries, WEBCAT `threshold`) because each signer is attributable and individually logged (B-CR-40, B-CR-45; R5 §A.9).
- **FROST (RFC 9591, Ed25519-SHA512 ciphersuite)** MAY be used in EE for the Ed25519 component of K01 when an external verifier requires a single ordinary signature and the organisation wants no reconstruction ceremony. There is no standardized threshold ML-DSA; the ML-DSA-65 component of K01 remains Shamir-reconstructed at ceremony. FROST is not used in the FIPS profile.
- Threshold decryption of K14 without reconstruction is not available for ML-KEM; reconstruction on the ceremony machine is the accepted design.

## 22. Formal verification plan, test vectors and KATs

### 22.1 Models (Tamarin primary; ProVerif for equivalence properties)
| Model | Scope | Properties | Tool |
|---|---|---|---|
| FM-1 Intake Tier V | Source client, intake (adversarial), C-14 log abstraction, per-member epoch keys, COI filter, 16 anonymous slots, members | Secrecy of CK/content vs server, network and COI-excluded members; secrecy after MEK retirement (FS) even if long-term keys later leak; Recipient List/roster binding (VR-8/VR-9) | Tamarin |
| FM-2 Replies | Desk, CIK, source keys, intake | Reply confidentiality to the source; reply authenticity (channel) incl. KCI analysis; replay/reorder rejection (`reply_seq`) | Tamarin |
| FM-3 Import / re-wrap / case membership | Desk, case keys, ACL changes, K14 | Only ACL members (and K14 if enabled) can obtain CK; removed members cannot obtain keys for objects created after removal | Tamarin |
| FM-4 Directory & roster continuity | KD entries, K01, K15, CIK continuity, witnesses | No encryption to a key outside the logged roster without either a valid logged entry or a detectable fork; dual-control properties | Tamarin |
| FM-5 Source unlinkability and recipient anonymity | Two sources / two passphrases through intake; envelopes with different recipient sets | Observational equivalence: server cannot link submissions made with different passphrases, and cannot distinguish envelopes differing only in which members are recipients (relies on CA-9) | ProVerif (diff-equivalence) + computational note on KEM key privacy |
| FM-6 Key commitment | Envelope format | No object decrypts under two CKs (computational argument, reviewed by external cryptographer; salamander test vectors) | Pen-and-paper proof + tests |

Schedule: FM-1..FM-4 complete and externally reviewed before 1.0 (ADR-006; INC-63 lesson); FM-5/FM-6 before 1.0 GA. Models live in `formal/` and are re-run in CI job `formal-models` on every change to `candor-core/src/protocol/**` or this document's formats.

### 22.2 Test vectors and KATs
| Set | Source | CI job |
|---|---|---|
| HPKE base mode | RFC 9180 Appendix A; hpke-pq draft vectors for 0x647a / 0x0051 (B-CR-06) | `crypto-kat` |
| X-Wing | draft-connolly-cfrg-xwing-kem vectors (B-CR-05) | `crypto-kat` |
| ML-KEM / ML-DSA | FIPS 203/204 ACVP vectors | `crypto-kat` |
| Ed25519 | RFC 8032 §7.1; Wycheproof EdDSA (Knowledge (unverified): Wycheproof suite names) | `crypto-kat` |
| AEAD, HKDF, HMAC, ECDSA | Wycheproof; NIST CAVP | `crypto-kat` |
| Argon2id | RFC 9106 §5.3 | `crypto-kat` |
| PBKDF2-HMAC-SHA-512 | NIST CAVP | `crypto-kat-fips` |
| STREAM behaviour | age/C2SP test vectors adapted (B-CR-14) | `crypto-kat` |
| Candor formats | `test-vectors/v1/{sealed_object,stanza,stream,submission,reply,passphrase,kd_entry,checkpoint}.json` incl. negative vectors: truncated stream, reordered chunks, missing final flag, trailing data, header tamper, stanza bound to another object, wrong suite, non-canonical CBOR, duplicate keys, oversized manifest, salamander attempt, slot block with an unlisted non-dummy slot, forged Recipient List, tampered slot_block_hash | `crypto-vectors` (native, WASM, FIPS builds must agree) |
| Startup self-tests | C-11 runs KATs for every primitive at process start (C-03, C-06, C-07, C-14, C-15); failure = refuse to start | `crypto-selftest` |

### 22.3 Fuzzing and external review
`cargo-fuzz` targets for every parser (CoreHeader, stanza, CBOR inner maps, KD entries, checkpoints, bundle manifest), ≥ 24 CPU-hours per release and continuous (OSS-Fuzz style); malicious-server harness (ADR-027, 29) replays hostile KD snapshots and objects against C-03 and C-15. External cryptographic review of this document and C-11 before 1.0 (37).

## 23. Implementation requirements

### 23.1 Constant-time
- No secret-dependent branches, memory indices or early exits in C-11 code paths handling keys, CKs, MAC verification, passphrase verification or padding removal of unverified data.
- MAC/tag/verifier comparisons via `subtle::ConstantTimeEq`; secret encodings via constant-time codecs (`base64ct`).
- Tier W login work is identical for unknown and known accounts (Argon2id always runs; lookup performed after derivation).
- dudect-style statistical timing tests (CI job `ct-tests`) for HMAC verify, AEAD open failure path, stanza unwrap failure path, login verification.

### 23.2 Zeroization and memory hygiene
- All key and plaintext buffers use `zeroize`/`secrecy` wrapper types; `Drop` zeroizes; no `Clone`/`Debug`/`Display` for secret types (lint `secret-types`).
- Key-holding and plaintext-holding processes (C-03 core, C-06 request handlers, C-07, C-14, C-15 core): `prctl(PR_SET_DUMPABLE, 0)`, `RLIMIT_CORE = 0`, `mlock` on secret arenas, `MADV_DONTDUMP`, no swap on Z-INTAKE/Z-CORE hosts (or swap encrypted with an ephemeral random key), no off-host crash reporting (INC-58).
- C-07 processes each Tier W session in a fresh arena (§9.13); plaintext never written to disk, tmpfs or pipes other than the C-06→C-07 socket; the only tmpfs content is staged-part ciphertext under K36; arenas zeroized on submit, error, discard, sealer restart and the session timers (20 min idle / 2 h absolute, ADR-034).
- Candor Desk: keys and plaintext handled only in the Rust core; the WebView receives rendered, sanitized text or handles, never key bytes (12).

### 23.3 Key and input validation
- X25519: reject all-zero shared secrets (RFC 7748 §6.1). ML-KEM: encapsulation-key modulus check and decapsulation-key hash check (FIPS 203 input validation). P-384: full point validation. Ed25519: strict RFC 8032 verification (canonical S, reject small-order points).
- Pairwise-consistency test for every generated key pair; weak-key blocklist checks (REQ-H-51; INC-51, INC-61). RSA is not accepted anywhere.
- All lengths checked against §4.2 before use.

### 23.4 Randomness
- Sole source: `getrandom(2)` (blocking until initialized) via `OsRng`; FIPS: module DRBG. No other RNG crate or constant-seeded generator in trust-path code (CI code search; INC-50).
- Startup health check (KAT/DRBG self-test; consecutive outputs non-equal and non-zero).
- VM snapshot/restore hazard: Z-INTAKE and Z-CORE VMs MUST NOT be live-snapshotted or cloned while running (17); hosts use kernels with VM-generation-ID reseeding (Knowledge (unverified)); after any resume event services regenerate cached randomness (nonce pools, session keys).

### 23.5 Library policy
Only C-11 calls cryptographic primitives; all other crates use C-11 APIs. C-11 (`candor-core`) is dual-licensed Apache-2.0 OR MIT for independent reuse (ADR-031) and remains Trust Path code: public, reproducibly built and in audit scope (37). Dependencies pinned and `cargo-vet`-audited (ADR-019; B-CR-27); no `unsafe` in C-11 outside audited dependencies; the same C-11 source builds for native, WASM (Tier V web) and FIPS targets, verified identical by `crypto-vectors`. WASM clients MUST NOT silently lower Argon2id parameters; if 256 MiB cannot be allocated, the client stops and points the source to the Source App or Tier W.

## 24. Server-delivered code analysis (Hushmail class, THR-007; ADR-004)

**Question: can a compromised or compelled server deliver malicious code to sources?** **Yes** for every web path:
- **Tier W (no-JS):** the server does not need malicious code — by design it sees plaintext in C-07 RAM while sealing. A compromised or compelled operator (INC-01 Hushmail, INC-02 Lavabit) can capture submissions and passphrases made during the compromise, and could serve altered HTML (phishing text, fake roster/escrow statements). If a source has JavaScript enabled, a seized server can also serve exploit code (INC-27, INC-28 NIT class).
- **Tier V-web / JS-enabled path without WEBCAT:** the server can serve JavaScript/WASM that exfiltrates the passphrase and plaintext, to one source at one time, undetectably (B-CR-35). SRI does not help because the root HTML is itself server-controlled (R5 §B.1). **Therefore Candor serves no JavaScript at all to sources unless the bundle is WEBCAT-enforced** (CSP `script-src 'none'` otherwise).

### 24.1 Mitigations ranked
| Rank | Mitigation | Strength | Feasibility 2026 | What it achieves / residual | Evidence |
|---|---|---|---|---|---|
| 1 | **Candor Source App (C-03)**: reproducible, threshold-signed, transparency-logged, TUF-updated, pins K01 and verifies the directory (§14.5); embeds Arti | ★★★★★ | Medium (install is a device trace and a signal of intent, THR-048) | Server cannot alter client code per user; content never visible to server; residual: malicious *global* release (mitigated by 33), source endpoint compromise | R5 §B.3 row 1; B-CR-42, B-CR-43; REQ-H-01, REQ-H-15 |
| 2 | **WEBCAT-enforced JS/WASM bundle** in Tor Browser: k-of-n signed manifest, enrollment consensus, transparency, blocking enforcement | ★★★★ | Low today (alpha; Tor Browser integration in progress, B-CR-37/38) → Medium later | Targeted code substitution blocked; split views detectable; residual: WEBCAT alpha maturity, browser exploits | B-CR-37, B-CR-38, B-CR-40 |
| 3 | **No-JS Tier W** (Tor Browser Safest) with isolated, memory-locked sealer (C-07) | ★★★ | High | Removes client code delivery risk and NIT exploit surface via JS; residual: live-compromised sealer reads plaintext (disclosed) | R5 §B.2 (SecureDrop classic); INC-27 |
| 4 | **Transparency of accepted client/web releases + external monitors** (CLIENT_RELEASE entries, VR-10) and reproducible server builds (33) | ★★ | High | Detects broad (non-targeted) substitution; not targeted delivery to one source | INC-28 |
| 5 | Strict CSP, no third-party resources, SRI | ★ | High | Blocks injection by third parties; not the operator | INC-46 (Polyfill.io); R5 §B.3 row 1(e) |
| — | Rejected: server-delivered JS crypto without WEBCAT; browser extension verification (fingerprinting, R5 §B.3 1(d)) | — | — | — | ADR-004 |

Honest source-facing statements (11, 05): Tier W — the text fixed by ADR-035(5): "If the intake server is compromised or legally compelled while you use the website (no-JavaScript) version, what you type, and your passphrase when you log in, can be captured. For the highest risk, use the Candor Source App." Recommended additional sentence (RVW-A-03): "Anyone who obtains your passphrase can read replies still stored for you and write as you; you can change your passphrase from your inbox." Tier V — "Your report is encrypted on your device to keys you can verify; the server cannot read it."

## 25. Sequence diagrams

### 25.1 Submit — Tier W (no-JS; ADR-034)
```mermaid
sequenceDiagram
  autonumber
  participant S as Source (Tor Browser, Safest)
  participant T as C-05 tor daemon (onion)
  participant W as C-06 Source Web Service
  participant X as C-07 Intake Sealer
  participant I as C-08 Intake Store
  S->>T: HTTP over onion circuit (optionally onion TLS)
  T->>W: request via Unix socket (no IP; CircuitToken only)
  W->>X: open session → K36 + RAM arena (20 min idle / 2 h absolute)
  W-->>S: form incl. category + optional "my report concerns: [Triage Set role labels]" checklist
  S->>W: POST form fields (draft text kept in C-07 RAM only)
  S->>W: POST file parts (multipart, streamed)
  W->>X: stream parts over Unix socket (no disk)
  X->>X: pad part to bucket; STREAM-encrypt under HKDF(K36, part_id) → tmpfs staging
  X-->>W: Recovery Credential screen: new passphrase (10 words)
  S->>W: re-type 3 random words + Submit
  X->>X: verify confirmation; verify KD snapshot (VR-1..VR-6, high-water mark, independent time)
  X->>X: Triage Set ∩ active roster; COI filter in RAM; none → independent-route pointer / fail closed
  X->>X: passphrase → Argon2id(64 MiB) → seed → keys (§11.3); zeroize passphrase
  X->>X: CKs; SUBMISSION (incl. Recipient List, bundle manifest) / BUNDLE (re-encrypt staged parts) / IDENTITY(dummy)
  X->>X: 16-slot blocks (real slots to eligible Triage Set MEKs, verifiable dummies, random order); header MAC
  X->>X: sign SUBMISSION with sign_sk and K35; prefs_ct (original eligible set)
  X->>I: sealed objects + slot blocks + lookup_tag, auth_pk, mailbox_id, prefs_ct (committed at the fixed commit slot; optional release_day)
  X->>X: zeroize plaintext, K36, seed, keys, COI flags; unlink staged files
  W-->>S: "sent" page (fixed size class); no passphrase re-display
```

### 25.2 Submit — Tier V (Source App or WEBCAT bundle)
```mermaid
sequenceDiagram
  autonumber
  participant A as C-03 Source App (Arti)
  participant WT as External witness endpoint (onion)
  participant W as C-06/C-08 Intake (untrusted)
  A->>A: verify own release/update state (33); pinned K01 from address statement; load pinned tree head
  A->>W: GET KD snapshot (checkpoint + cosigs + entries + proofs)
  A->>WT: GET latest cosigned checkpoint for tenant (not via tenant onion)
  A->>A: VR-1..VR-8, VR-14; consistency pin ↔ witness ↔ served; show Triage Set, member-since, pending changes, COI checklist, escrow, operator statement
  A->>A: COI filter locally → eligible Triage Set MEKs (none → independent-route pointer)
  A->>A: generate passphrase (10 EFF words); source confirms 3 random words; Argon2id → keys; generate CKs
  A->>A: build + seal 3 objects; 16-slot blocks; sign SUBMISSION incl. Recipient List + roster hash + checkpoint; prefs_ct
  A->>W: register {lookup_tag, auth_pk, mailbox_id, prefs_ct}; upload sealed objects + slot blocks (padded; optional release_day)
  W-->>A: ack (no timestamps)
  A->>A: update pinned tree head; zeroize; no other local state kept
```

### 25.3 Reply (staff → source) and source retrieval (ADR-039)
```mermaid
sequenceDiagram
  autonumber
  participant D as C-15 Candor Desk (case member)
  participant C as C-10 Case Service / C-12
  participant R as C-09 Intake Relay
  participant I as C-08 Intake Store
  participant S as Source (C-03 or Tier W via C-07)
  D->>D: compose text; CK; REPLY object (header: channel 0, day 0); sign inner with own K08
  D->>D: stanza1 = HPKE(src_pk, info binds mailbox_id); stanza2 = CASE_AEAD(Case Key v); routing_ct = HPKE(K37, {mailbox_id, reply_seq})
  D->>C: store object + stanza2 (case copy); queue {routing_ct, object, stanza1}
  R->>C: pull outbound queue at the fixed relay slot
  R->>I: push {routing_ct, SealedObject, stanza1} (mTLS, core-initiated)
  I->>I: open routing_ct with K37 → store under mailbox; rebuild dead-drop pages (last 30 days, random order)
  alt Tier V (fetch-all)
    S->>I: GET all dead-drop pages (no auth, no identifier)
    S->>S: trial-decrypt every entry per own mailbox_id; verify sender_sig (VR-7), reply_seq
  else Tier W
    S->>I: login (passphrase → C-07 derives in RAM; server-side lookup by mailbox)
    I-->>S: C-07 decrypts, verifies sender K08 ∈ roster, renders; keys held for session only
  end
```

### 25.4 Case import and re-wrap (ADR-037, ADR-038)
```mermaid
sequenceDiagram
  autonumber
  participant R as C-09 Intake Relay
  participant I as C-08 Intake Store
  participant C as C-10/C-12/C-13 Core (+ EKV)
  participant D as C-15 Desk (Triage Set member)
  participant V as C-17 Viewer VM
  R->>I: pull sealed batch at the fixed import slot (4×/day; HIGH/GOV 1×/day), verify K31 batch signature
  R->>C: store blobs (C-13, object times normalized to slot) + slot blocks; record received date only (ADR-033 item 4, ADR-038(1))
  D->>C: list pending envelopes (only Triage Set members of the channel can list; identical list for each)
  D->>D: trial-decrypt 16 slots with own MEK_n → CK (or no slot → not surfaced)
  D->>D: verify header_mac, sizes, source_sig/sealer_sig, Recipient List vs directory (VR-9 a–f)
  D->>C: create case → Case Key v1 wrapped to importing Triage Set members (+K14); CASE_AEAD stanza per CK
  C->>C: generate Erasure Key K32 in EKV; store case-key wraps inside EK layer (CASEKEY_EK)
  D->>C: blinded exclusion tag set (8·k tags, §9.11) derived from Case Key v1
  D->>V: import-hash job: CK sealed to per-job key K34 + bundle ciphertext
  V-->>D: per-file SHA-256 + BLAKE3, manifest match result (no plaintext to Desk)
  D->>C: evidence hashes into encrypted case record; mark imported (date only in audit)
  Note over D,C: after COI assessment the Triage Set wraps Case Key v to investigators (C-22 blind tag check; audited)
  Note over C: slot blocks deleted once §12.5 retirement condition holds
```

### 25.5 Member add (channel; ADR-036)
```mermaid
sequenceDiagram
  autonumber
  participant N as New member Desk
  participant K as Key-Admin (K15 token)
  participant O as Independent-role approver (OVERSIGHT) Desk
  participant M as CIK holder Desk (Triage Set / OVERSIGHT)
  participant L as C-14 Key Directory
  N->>N: generate K08, K09 on device; seal with ≥ 2 K10 slots; offline keystore backup
  N->>L: USER_KEYS entry signed by K08
  K->>L: co-sign USER_KEYS (key-admin A)
  O->>L: co-sign USER_KEYS after out-of-band person_ref check
  M->>M: verify USER_KEYS; propose roster v+1 adding N (certified role label, caps) — change_class loosening
  M->>L: CHANNEL_ROSTER v+1 signed by CIK; K (key-admin B ≠ A) and O co-sign
  L->>L: continuity checks; queue to weekly slot; append with activation_day = inclusion + 72 h (GOV/HIGH 7 d)
  L-->>M: all members + OVERSIGHT notified (content-free, non-dismissable); sources see "pending change"
  opt objection during time-lock
    M->>L: OBJECTION → activation blocked until 2 OVERSIGHT resolve
  end
  N->>L: (if read_intake) MEMBER_EPOCH entries for next epochs (weekly slot)
  opt N gets channel_admin (Triage Set / OVERSIGHT only)
    M->>L: CIK wrap to N's K09
  end
  Note over N: roster active on activation_day; no slots in earlier envelopes; case access only via Triage Set grants
```

### 25.6 Member remove (channel and cases; ADR-036(2), ADR-044(1))
```mermaid
sequenceDiagram
  autonumber
  participant M as Remaining CIK holder Desk
  participant K as Key-Admin (K15)
  participant L as C-14
  participant C as C-10/C-12 (+ EKV)
  participant O as OVERSIGHT
  M->>L: CHANNEL_ROSTER v+1 (without removed member; change_class tightening) signed by CIK + K15 — active immediately
  M->>L: REVOCATION of the removed member's future MEMBER_EPOCH entries (same append)
  opt removed member held the CIK
    M->>M: generate CIK'; CHANNEL_IDENTITY seq+1 signed by old CIK
    K->>L: co-sign CIK rotation; wraps of CIK' to remaining channel_admins
  end
  Note over L: sealers stop including the member at the next hourly checkpoint (VR-6)
  M->>C: for each case the member was on: Case Key v+1 (≥ 2 holders kept), re-wrap CK stanzas, wrap v+1 to remaining ACL (+K14) inside EK layer, new exclusion-tag set
  C->>O: content-free notice; 7-day cooling-off starts (suspension of the member's wraps is immediate)
  C->>C: after cooling-off + dual approval: delete the member's old-version wraps and old version; audit record
  Note over M,C: Removed member keeps what it already decrypted, and its MEKs still open un-imported envelopes where it was eligible (residual)
```

### 25.7 Member epoch key rotation (scheduled, per member)
```mermaid
sequenceDiagram
  autonumber
  participant D as Member Desk
  participant L as C-14
  participant C as C-10
  participant X as C-07/C-06 Intake
  D->>L: check own published MEKs for channel (< current + 4?)
  D->>D: generate MEK_{n+4}; validate; seal private in keystore
  D->>L: MEMBER_EPOCH entry signed by K08
  L->>L: verify (member in roster with read_intake), append, checkpoint
  L-->>X: KD snapshot pushed via C-09
  X->>X: at 00:00 UTC of epoch start use MEK_{n+1} of each eligible member
  D->>C: for MEK_{n-3}: any envelope of that epoch not imported / not rejected?
  alt none remaining and window passed
    D->>D: zeroize MEK_{n-3} private; MEK_RETIRED audit record
  else pending > 7 days
    C->>C: escalate to OVERSIGHT + independent route + C-25 (content-free, ≤ 1/channel/day)
  end
```

### 25.8 Cryptographic erasure of a case
```mermaid
sequenceDiagram
  autonumber
  participant A as Approver 1 Desk
  participant B as Approver 2 Desk
  participant C as C-10 / C-12 / C-13
  participant E as Erasure Key Vault (K32 under K33)
  participant O as Other member Desks
  A->>C: erase request (case, legal-hold check, retention basis) signed K08
  B->>C: approval signed K08 (dual control)
  C->>C: verify no legal hold (35)
  C->>C: append {case_id, day} to the signed erasure log (applied before serving after any restore)
  C->>E: destroy K32(case) in vault and replicas (overwrite + compaction / HSM C_DestroyObject)
  C->>C: delete EK-layered case-key wraps (all versions, members, K14), CK stanzas, blobs, slot blocks
  C->>O: erase notice on next sync
  O->>O: purge cached case keys + local caches; refuse reopen
  C->>C: store deletion receipt (approver signatures, counts, day) in audit
  Note over E: EKV backups containing K32 expire ≤ 14 days → all backup copies unreadable (ADR-033)
```

## 26. Requirements

### 26.1 Primitives, formats and implementation (CRYPTO-)
| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| CRYPTO-001 | The system SHALL implement suite CANDOR-STD-1 exactly as specified in §4.1 (HPKE base mode, KEM 0x647a X-Wing, HKDF-SHA256, ChaCha20-Poly1305; STREAM ChaCha20-Poly1305; records XChaCha20-Poly1305; HMAC-SHA-256; Ed25519) as the default for every tenant. | ADR-006; B-CR-05; B-CR-06; B-CR-07 | THR-012 | C-11 | TST: `crypto-kat` (RFC 9180 App. A, X-Wing draft vectors); AUD: crypto review |
| CRYPTO-002 | The FIPS profile SHALL implement CANDOR-FIPS-1 (MLKEM1024-P384, HKDF-SHA384, AES-256-GCM, HMAC-SHA-384, PBKDF2-HMAC-SHA-512) using only a FIPS 140-3 validated module operated in its approved mode; the build SHALL record the CMVP certificate number and fail if the module's FIPS self-test fails. | ADR-006; B-CR-11; B-CR-13 | THR-012 | C-11, C-29 | TST: `crypto-kat-fips`; INSP: CMVP certificate check in release checklist |
| CRYPTO-003 | Suites SHALL NOT be negotiated in-band; each tenant's allowed suite(s) SHALL be pinned in the ORG_ROOT entry, and any object, stanza or key with an unlisted `suite_id` SHALL be rejected. | ADR-006; INC-64 | THR-012 | C-11, C-14 | TST: negative vectors `wrong_suite` in `crypto-vectors` |
| CRYPTO-004 | Only the candor-core library (C-11) SHALL invoke cryptographic primitives; no trust-path crate SHALL implement or directly call a primitive, and no home-grown primitive SHALL exist. | ADR-006; INC-63; INC-64 | THR-012 | C-11 | TST: CI dependency/lint rule `crypto-boundary`; INSP: code review |
| CRYPTO-005 | All public-key encryption of content keys and private-key wraps SHALL use a hybrid PQ KEM (X-Wing or MLKEM1024-P384); classical-only KEMs SHALL NOT be accepted. | ADR-006; B-CR-03; B-CR-04 | THR-012 | C-11 | TST: `crypto-vectors` rejects DHKEM-only stanzas |
| CRYPTO-006 | Every HPKE seal SHALL bind the context (label, suite, tenant, channel/case, epoch or version, and the recipient key_id except in anonymous intake slots) in `info` and the object or key-wrap context in `aad` exactly as §9.9/§13.2. | B-CR-24; INC-66 | THR-012; THR-046 | C-11 | TST: vectors with swapped tenant/channel/epoch fail to open; FM-1 model |
| CRYPTO-007 | Payload encryption SHALL use the STREAM construction of §13.3 (64 KiB chunks, 11-byte counter + final flag nonces, per-object derived key) and SHALL reject truncation, reordering, duplication, trailing data and missing final chunk. | B-CR-14; B-CR-15 | THR-012; THR-037 | C-11 | TST: negative vectors `truncated`, `reordered`, `no_final`, `trailing` |
| CRYPTO-008 | Every Sealed Object SHALL carry `header_mac = HMAC(K_mac(CK), CoreHeader)`; readers SHALL verify it in constant time after unwrapping CK and before any payload decryption. | B-CR-16; B-CR-17 | THR-012; THR-037; THR-023 | C-11, C-15 | TST: salamander vector (two CKs) rejected; `ct-tests` |
| CRYPTO-009 | No decrypted plaintext SHALL be released to a consumer before its AEAD tag verifies; consumers that act on whole files SHALL receive output only after the final chunk verifies, and SHALL discard all output on failure. | INC-65 | THR-012; THR-023 | C-11, C-15, C-17 | TST: tampered last chunk yields zero bytes delivered to C-17 |
| CRYPTO-010 | Encrypted records SHALL use the format of §13.8; STD SHALL use XChaCha20-Poly1305 with random 192-bit nonces; FIPS SHALL use AES-256-GCM with random 96-bit nonces and a persisted per-derived-key counter that forces case-key version rotation at 2^31 encryptions. | B-CR-15 | THR-012 | C-11, C-15 | TST: counter-exhaustion test triggers rotation |
| CRYPTO-011 | Every record and wrap AEAD SHALL bind tenant_id, case/channel id, table/column/record ids, key version and row_version in AAD as in §13.8/§13.2. | INC-66 | THR-012; THR-021 | C-11, C-12, C-15 | TST: row moved between cases/tenants fails to decrypt |
| CRYPTO-012 | All HKDF `info` labels SHALL be taken from the registry in §10 (`candor/v1/...`); CI SHALL reject duplicate or unregistered label literals. | ADR-006 | THR-012 | C-11 | TST: CI job `label-registry` |
| CRYPTO-013 | SUBMISSION, SOURCE_MESSAGE and REPLY plaintexts SHALL be padded to 4096-byte multiples up to 65536 bytes; larger content SHALL be rejected (split into further messages). | ADR-011; B-CR-24 | THR-011; THR-015 | C-11, C-03, C-07, C-15 | TST: size-class property test (all ciphertext lengths in allowed set) |
| CRYPTO-014 | File-bearing objects SHALL be padded to the geometric bucket series of §13.6 (b0 = 256 KiB, ratio 1.25, 64 KiB aligned). | ADR-011 | THR-015; THR-039 | C-11 | TST: bucket computation vectors |
| CRYPTO-015 | Every submission SHALL consist of exactly one SUBMISSION, one ATTACHMENT_BUNDLE (empty if no files) and one IDENTITY object (dummy if no identity supplied), in both tiers. | ADR-011; ADR-014 | THR-015; THR-040 | C-03, C-07 | TST: object-count invariance test across submission variants; TST: mode-inference test (30-ANONYMITY-TESTING.md) |
| CRYPTO-016 | Source-originated objects and REPLY objects SHALL carry `day_stamp = 0` (REPLY also `channel_id = 0`) and no timestamp of any granularity in any cleartext field; other staff-originated objects SHALL carry at most a UTC day. | ADR-010; ADR-039 | THR-011 | C-11, C-07, C-03, C-15 | TST: format lint; INSP: schema review |
| CRYPTO-017 | Inner structures SHALL be deterministic CBOR decoded by a strict decoder (no indefinite lengths, duplicates, floats, tags, unknown keys < 1000) and SHALL be parsed only after authentication succeeds. | INC-65; B-SD-33 | THR-012; THR-023 | C-11, C-15 | TST: `cargo-fuzz` targets; negative vectors `dup_key`, `noncanonical` |
| CRYPTO-018 | Readers SHALL validate CoreHeader magic, version, suite, zero flags/reserved, legal bucket and exact payload length before decrypting. | INC-66 | THR-012; THR-032 | C-11 | TST: negative vectors per field |
| CRYPTO-019 | Replies SHALL be text-only in v1, SHALL be signed with the replying member's User Identity Key over the core header and inner fields, and source clients (C-03, and C-07 for Tier W) SHALL NOT render a reply whose signer is not in the roster valid on its day, whose signature fails, or whose `reply_seq` is not monotonic. | ADR-030; INC-62; INC-64 | THR-019; THR-007 | C-11, C-03, C-07, C-15 | TST: forged/replayed reply rejected; malicious-server suite (29-SECURITY-TESTING.md) |
| CRYPTO-020 | Candor Desk SHALL verify `source_sig` on every SUBMISSION/SOURCE_MESSAGE against the report's `sign_pk` and quarantine mismatches with a visible warning. | INC-62 | THR-033; THR-037 | C-15 | TST: mismatched signature quarantined |
| CRYPTO-021 | In Tier V, all content SHALL be encrypted on the source device before upload; no API SHALL accept plaintext content from a Tier V client. | ADR-004; INC-02 | THR-007; THR-014 | C-03, C-06 | TST: API schema rejects non-SealedObject bodies; TST: intercept test (29-SECURITY-TESTING.md) |
| CRYPTO-022 | C-07 SHALL process Tier W plaintext only in mlocked memory arenas, never write plaintext to disk/tmpfs/logs (staged parts reach tmpfs only as ciphertext under K36), zeroize arenas after sealing, on error, discard, sealer restart and at the ADR-034 session timers (20 min idle / 2 h absolute), and run as a separate process with no network access except its local sockets. | ADR-004; ADR-034; INC-58; INC-60; RVW-A-02 | THR-014; THR-016 | C-07 | TST: canary plaintext never found on disk/swap/logs/tmpfs after draft, abandon, error and submit flows; INSP: seccomp/systemd unit review |
| CRYPTO-023 | C-06 SHALL stream request bodies to C-07 without buffering them to disk or tmpfs. | ADR-004; B-OS-02 | THR-014; THR-017 | C-06 | TST: filesystem watcher during upload shows no body writes |
| CRYPTO-024 | The source web service SHALL serve no JavaScript or WASM (CSP `script-src 'none'`) unless the bundle is WEBCAT-enforced for the onion origin; JS SHALL never be required for any source function. | ADR-004; B-CR-35; B-CR-37; INC-27 | THR-007; THR-008 | C-06 | TST: CSP scanner; DEMO: full flow at Tor Browser Safest |
| CRYPTO-025 | Source UI SHALL display the tier-specific honest protection statement of §24 (Tier W: the ADR-035(5) text) before submission and on the Tier W login page. | ADR-004; ADR-035; B-GL-33; RVW-A-03 | THR-040 | C-06, C-03 | INSP: copy review (11); DEMO: usability test |
| CRYPTO-026 | All internal links SHALL use TLS 1.3 only with the groups and cipher suites of §5.2, mutual authentication by the internal CA, no 0-RTT and no cross-host resumption. | B-CR-08 | THR-030; THR-014 | C-09, C-10, C-12, C-13, C-14, C-21, C-24, C-25, C-27 | TST: TLS scanner in CI deployment test; INSP: config review |
| CRYPTO-027 | The Intake Relay connection SHALL be initiated only by C-09, use mTLS with SPKI pins on both ends, and C-08's listener SHALL accept only the pinned relay certificate from the relay host address. | ADR-009; INC-33 | THR-014 | C-09, C-08 | TST: connection from any other cert/address refused; TST: intake→core initiation blocked (29-SECURITY-TESTING.md) |
| CRYPTO-028 | Candor Desk SHALL pin the Z-CORE API SPKI from the enrollment bundle and SERVER_PIN directory entries and SHALL NOT fall back to WebPKI validation. | INC-02 | THR-022; THR-030 | C-15 | TST: MITM with CA-valid cert rejected |
| CRYPTO-029 | When `onion_tls` is enabled, C-06 SHALL offer `X25519MLKEM768` first, serve HSTS on the onion origin, and SHALL NOT serve plain HTTP content on that onion; `onion_tls` SHALL default to ON in HIGH and GOV profiles whenever a CA-issued `.onion` certificate is obtainable. | B-CR-08; ADR-046(8); RVW-A-11 | THR-003; THR-012 | C-06, C-05 | TST: TLS scan of onion via Tor; INSP: profile defaults |
| CRYPTO-030 | Server volumes SHALL use LUKS2 (`aes-xts-plain64`, 512-bit key, argon2id keyslot KDF) with TPM2 or Tang unattended unlock and an offline recovery keyslot; no document or UI SHALL claim content confidentiality from disk encryption. | B-SD-13; B-CR-33 | THR-031 | C-39, C-05, C-08, C-12, C-13 | INSP: deployment check (18); TST: `cryptsetup luksDump` compliance script |
| CRYPTO-031 | Secret-dependent operations in C-11 SHALL be constant-time; tag/MAC/verifier comparisons SHALL use constant-time equality; CI SHALL run statistical timing tests on MAC verify, AEAD failure, stanza unwrap failure and login verification. | INC-64 | THR-012 | C-11, C-07 | TST: `ct-tests` (dudect-style) |
| CRYPTO-032 | Key- and plaintext-holding processes SHALL disable core dumps (`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`), mlock secret memory with `MADV_DONTDUMP`, zeroize on drop, run without swap (or with ephemeral-key encrypted swap), and never send crash reports off-host. | INC-58 | THR-013; THR-016 | C-03, C-06, C-07, C-14, C-15 | TST: SIGSEGV test yields no core; INSP: host config |
| CRYPTO-033 | The only randomness sources SHALL be `getrandom(2)` (STD) or the FIPS module DRBG; any other RNG crate or constant-seeded generator in trust-path code SHALL fail CI. | INC-50; INC-51 | THR-012 | C-11 | TST: CI code search `rng-ban` |
| CRYPTO-034 | Every process using C-11 SHALL run primitive KAT self-tests at startup and refuse to start on failure. | INC-51 | THR-012 | C-11 | TST: fault-injected build fails closed (`crypto-selftest`) |
| CRYPTO-035 | C-11 SHALL perform the input and key validation of §23.3 (X25519 zero-secret check, ML-KEM key checks, point validation, strict Ed25519) and SHALL NOT accept RSA keys anywhere. | INC-61; Knowledge (unverified): RFC 7748 §6.1 | THR-012 | C-11 | TST: invalid-key vectors (Wycheproof) |
| CRYPTO-036 | Generated key pairs SHALL pass a pairwise-consistency test and weak-key blocklist checks before use or publication. | INC-51; INC-61 | THR-012 | C-11, C-14 | TST: seeded-RNG test build detected |
| CRYPTO-037 | CI job `crypto-kat` SHALL run the vector sets of §22.2 on every commit touching C-11, for native, WASM and FIPS builds. | ADR-006 | THR-012 | C-11, C-31 | TST: CI job presence and pass gate |
| CRYPTO-038 | The project SHALL publish Candor format test vectors (positive and negative, §22.2) and all builds SHALL produce identical outputs for deterministic parts. | INC-63 | THR-012 | C-11 | TST: `crypto-vectors` cross-build diff |
| CRYPTO-039 | Every parser of Candor formats SHALL have a fuzz target executed ≥ 24 CPU-hours per release with zero open crashes. | B-SD-28; INC-66 | THR-012; THR-023 | C-11 | TST: fuzz report attached to release (33) |
| CRYPTO-040 | Tamarin models FM-1..FM-4 SHALL be completed, pass, and be externally reviewed before 1.0; CI job `formal-models` SHALL re-run them on protocol changes. | ADR-006; INC-63; B-CR-25; B-SD-38 | THR-012; THR-046 | C-11 | TST: `formal-models`; AUD: external crypto review (37) |
| CRYPTO-041 | ProVerif model FM-5 (source unlinkability) and the key-commitment argument FM-6 SHALL be completed before 1.0 GA. | B-CR-16; B-CR-24 | THR-012 | C-11 | TST: `formal-models`; AUD |
| CRYPTO-042 | C-03 and C-15 SHALL be tested against the malicious-server harness with hostile objects, stanzas, directory snapshots and replies. | ADR-027; INC-66; INC-67 | THR-007; THR-046 | C-03, C-15 | TST: malicious-server suite (29-SECURITY-TESTING.md) |
| CRYPTO-043 | WASM and app clients SHALL NOT lower Argon2id parameters (m = 64 MiB, t = 3, p = 1); if memory allocation fails they SHALL stop and direct the source to another tier. | ADR-005; ADR-046(7); B-GL-27 | THR-034 | C-03, C-06 | TST: low-memory simulation |
| CRYPTO-044 | C-07 SHALL limit concurrent Argon2id derivations with a semaphore of 4 (ADR-046(7)), queue waiting requests (FIFO, depth 64, ≤ 30 s) answered in the normal size class, and serve the busy page only on queue overflow; no response SHALL expose queue length or position. | ADR-026; ADR-038(5); ADR-046(7); RVW-A-27 | THR-032; THR-011 | C-07 | TST: load test (34); TST: response size/latency identical below overflow |
| CRYPTO-045 | Tier W login SHALL perform identical work and return identical response size classes for unknown accounts and wrong passphrases as for valid ones. | B-GL-08 | THR-034; THR-011 | C-07, C-06 | TST: timing/size comparison test |
| CRYPTO-046 | Z-INTAKE and Z-CORE VMs SHALL NOT be live-snapshotted or cloned while running; after any resume, services SHALL regenerate cached randomness. | Knowledge (unverified) | THR-030; THR-012 | C-39, C-07, C-14 | INSP: hypervisor policy (17); TST: resume hook test |
| CRYPTO-047 | Readers SHALL support format versions N and N−1 for ≥ 24 months and SHALL reject unknown object types, stanza types and non-zero reserved bits. | — | THR-012 | C-11 | TST: version-matrix tests |
| CRYPTO-048 | Suite migration SHALL follow §15.4 and SHALL never leave an object encrypted under mixed suites. | ADR-006 | THR-012 | C-15, C-14 | TST: migration integration test |
| CRYPTO-049 | Intake SHALL fail closed on every condition in §12.6 (including high-water-mark, independent-time and security-floor failures) and SHALL NOT fall back to any other key, plaintext storage or path. | ADR-002; ADR-036(6); ADR-040; B-GL-33; B-GL-39 | THR-012; THR-046; THR-043 | C-06, C-07 | TST: each condition injected → outage page, no stored object |
| CRYPTO-050 | Evidence hashes (SHA-256 + BLAKE3; FIPS: SHA-256 + SHA-384) SHALL be computed over decrypted file bytes by a C-17 import-hash job, compared with the SUBMISSION bundle manifest, and recorded in the encrypted case record. | ADR-012; ADR-033 | THR-037 | C-17, C-15 | TST: manifest-mismatch vector flagged |
| CRYPTO-051 | Export Packages SHALL be Sealed Objects (type EXPORT_PACKAGE) or age-compatible files wrapped to the external recipient's key, never plaintext archives. | ADR-018; B-GL-11 | THR-029; THR-041 | C-15, C-40 | TST: export produces only ciphertext; INSP |
| CRYPTO-052 | Candor Desk SHALL keep keys and decrypted content inside the Rust core; the WebView SHALL receive only sanitized render output or opaque handles. | ADR-007; B-SD-06 | THR-023; THR-013 | C-15 | TST: IPC schema test; TST: renderer compromise test (29-SECURITY-TESTING.md) |
| CRYPTO-053 | Resource bounds of VR-12 and header-declared lengths SHALL be enforced before allocation. | B-CR-52 | THR-032 | C-11 | TST: oversize vectors |
| CRYPTO-054 | Encrypted case records SHALL include `row_version` in AAD and the case event hash chain so that Desk detects server replay of stale ciphertext. | INC-66; INC-64 | THR-037; THR-018 | C-15, C-10 | TST: stale row replay detected |
| CRYPTO-055 | Epoch selection SHALL use `now` only if it passes the independent-time check (Tor consensus floor, Roughtime cross-check; §12.1 step 3, 16 §14.3) and SHALL NOT validate time solely against Z-CORE-supplied values; failure SHALL fail closed. | ADR-036(6); RVW-A-04 | THR-043 | C-07, C-03 | TST: clock-skew injection with a consistent stale Z-CORE snapshot + clock fails closed |
| CRYPTO-056 | Suite 0x0003 (CNSA-1) and any other suite SHALL NOT be enabled without an ADR, KATs and an updated formal model. | B-CR-10 | THR-012 | C-11 | INSP: release checklist |
| CRYPTO-057 | Source passphrases, seeds, CKs, case keys and private keys SHALL never appear in logs, metrics, traces, crash data or error messages; secret types SHALL NOT implement Debug/Display. | INC-60; ADR-016 | THR-016 | C-11, C-03, C-06, C-07, C-10, C-14, C-15 | TST: `secret-types` lint; canary grep of all log sinks |
| CRYPTO-058 | Every intake-sealed object SHALL carry a RecipientSlotBlock of exactly 16 fixed-size HPKE slots (§13.2) in uniformly random order, with no recipient key IDs or other recipient identifiers in any cleartext field, and SHALL commit to it via `slot_block_hash` in the CoreHeader. | ADR-030; ADR-033 | THR-020; THR-015; THR-046 | C-11, C-03, C-07 | TST: format vectors; statistical test that slot bytes do not reveal recipients; FM-5 |
| CRYPTO-059 | Dummy slots SHALL be real HPKE encryptions to throwaway keys derived from CK per §13.2, so that holders of CK can verify them and others cannot distinguish them from real slots. | ADR-033 | THR-046; THR-020 | C-11 | TST: dummy verification vectors; distinguisher test |
| CRYPTO-060 | Desk trial decryption SHALL attempt all 16 slots with each applicable MEK and perform constant work regardless of success. | ADR-033 | THR-020; THR-012 | C-15, C-11 | TST: `ct-tests` on slot trial path |
| CRYPTO-061 | Every SUBMISSION and SOURCE_MESSAGE SHALL contain the signed Recipient List (MEK key IDs, skipped count, COI policy hash, checkpoint) inside the AEAD payload, signed by the source signing key and, in Tier W, also by the Intake Sealer key K35. | ADR-033; ADR-036(4) | THR-046 | C-03, C-07, C-11 | TST: unsigned/altered list rejected at import |
| CRYPTO-062 | Candor Desk's main process SHALL NOT decrypt ATTACHMENT_BUNDLE, CASE_ATTACHMENT or CASE_DOCUMENT payloads; it SHALL deliver the object's CK to C-17 only HPKE-sealed to a per-job ephemeral key (K34) generated inside the disposable viewer, and C-17 SHALL destroy K34 with the VM at job end. | ADR-033; ADR-012; INC-65 | THR-023; THR-013 | C-15, C-17 | TST: Desk process memory scan shows no attachment plaintext; job-key single-use test |

### 26.2 Keys and key management (KEY-)
| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| KEY-001 | The key inventory of §19 SHALL be authoritative; each host's Secret Placement Manifest SHALL list exactly the keys permitted there, and post-deploy self-test SHALL fail the deployment if any other key material is found. | ADR-028; B-SD-22 | THR-013; THR-035 | C-25, C-05, C-08, C-12, C-14, C-27 | TST: placement self-test with planted key |
| KEY-002 | No server component (C-05..C-14, C-21..C-24) SHALL hold, in any form it can use, a private key or symmetric key that decrypts report content, case records or identity sections. | ADR-007; ADR-008; INC-01; INC-02 | THR-014; THR-018; THR-026 | C-06, C-07, C-08, C-09, C-10, C-12, C-13, C-14 | AUD: key-flow review; TST: "full server keys + traffic → no plaintext" drill (REQ-H-02) |
| KEY-003 | Content keys SHALL be 256-bit CSPRNG values generated per object at the point of plaintext origin and SHALL exist unwrapped only in RAM. | B-CR-33 | THR-013 | C-03, C-07, C-15 | TST: memory/disk canary scan |
| KEY-004 | Case keys SHALL be generated on Candor Desk and wrapped at import only to the eligible Triage Set members of the envelope (plus K14 only when the quorum is enabled); further wraps SHALL be created only by a Triage Set member's Desk after COI assessment and SHALL be refused by C-22 when the grantee's blinded tag is in the case's exclusion set; each wrap SHALL be stored inside the case's Erasure-Key layer. | ADR-015; ADR-030; ADR-033; ADR-037 | THR-020; THR-018 | C-15, C-22, C-10 | TST: excluded user has no wrap; non-triage member has no wrap before grant; FM-3 |
| KEY-005 | Case keys SHALL be rotated to a new version on member removal, member device compromise, FIPS nonce budget exhaustion and annually for cases open > 12 months, with CK stanzas re-wrapped and old-version wraps destroyed. | ADR-008 | THR-019; THR-013 | C-15, C-10 | TST: removal triggers v+1; old wraps absent |
| KEY-006 | Desk SHALL refuse to finalize a case ACL or channel roster, or to perform a removal or rotation, that leaves fewer than 2 key holders (`min_recipients` default 2); single-staff tenants cannot enable ANONYMOUS channels without the small-organisation external party (ADR-045). | ADR-013; ADR-044(2); ADR-045; RVW-C-03 | THR-042; THR-020 | C-15 | TST: removal leaving 1 holder blocked; DEMO: admin onboarding |
| KEY-007 | User Identity and Encryption keys SHALL be generated on C-15 and sealed by a hardware wrapping key (FIDO2 PRF/hmac-secret, PIV or TPM); the CE software-passphrase fallback SHALL use §4.1 parameters and display a persistent warning. | ADR-007 | THR-013; THR-031 | C-15, C-16 | TST: keystore unreadable without token; INSP |
| KEY-008 | User Encryption Keys SHALL be rotated at most every 12 months, with all wraps re-addressed before the old private key is destroyed. | ADR-008 | THR-013; THR-017 | C-15 | TST: rotation job; old key absent from keystore |
| KEY-009 | Additional devices (at most 2 active per user) SHALL be linked only by the SAS-verified device-link ceremony of §9.4 and the resulting device and authenticator counts SHALL be logged in USER_KEYS. | INC-62; ADR-044(2) | THR-046; THR-022 | C-15, C-14 | TST: link without SAS confirmation fails; third device refused |
| KEY-010 | Each channel SHALL have a Channel Identity Key that signs channel metadata only (roster, COI policy, configuration), whose rotations are signed by the previous CIK and one Key-Admin, except K01-signed orphan re-keys which SHALL alert all users and be shown to sources. | ADR-008; ADR-030; INC-62 | THR-046 | C-14, C-15 | TST: rotation without old-CIK signature rejected; CIK-signed epoch or reply rejected; FM-4 |
| KEY-011 | Each Triage Set member (`read_intake`) SHALL have its own Member Epoch Key per channel per 7-day epoch (14-day decrypt window), generated on its Desk, published as a K08-signed MEMBER_EPOCH entry for the current and next 4 epochs and appended by C-14 only in the weekly publication slot; C-25 SHALL alert when a member has fewer than 2 future epochs appended; members outside the Triage Set SHALL hold no MEK. | ADR-030; ADR-036(7); ADR-037; B-GL-26 | THR-020; THR-013 | C-15, C-14, C-25 | TST: scheduler tests; append only at slot; alert test |
| KEY-012 | A MEK private key SHALL be destroyed only after its decrypt window has passed AND every envelope of that channel and epoch has been imported or rejected; envelopes un-imported for more than 7 days SHALL be escalated to OVERSIGHT, the independent route and C-25 at most once per channel per day; envelopes pending 14 days MAY be rejected only with dual approval and are then deleted. | ADR-033; ADR-038(6); B-CR-33; RVW-A-20 | THR-013; THR-020 | C-15, C-10, C-25 | TST: retirement blocked while pending; escalation rate-limit test; dual-approved rejection unblocks retirement |
| KEY-013 | MEK private keys SHALL exist only in the owning member's Desk keystore, its linked devices and its offline keystore backup (sealed to the member's backup authenticator), and SHALL never be sent to, wrapped for, or stored on any server, server backup or other member. | ADR-030; ADR-044(2) | THR-013; THR-017 | C-15 | TST: server/backup inventory scan; code review of keystore export paths |
| KEY-014 | Sealers SHALL use a MEK only while its owner is a Triage Set member of the channel's latest **active** roster (time-locked additions excluded, removals effective immediately) and the MEK is valid for the current day and not revoked. | ADR-030; ADR-036(2); ADR-037 | THR-019; THR-046 | C-03, C-07 | TST: removed member's MEK not used; pending-addition member's MEK not used before activation_day |
| KEY-015 | Removing a roster member SHALL publish a tightening roster without the member (active on inclusion), revoke its future MEMBER_EPOCH entries in the same append, rotate the CIK if the member held it, and rotate case keys of every case the member held; deletion of the member's old wraps SHALL follow the 7-day cooling-off with dual control and OVERSIGHT notice (ADR-044(1)). | INC-62; ADR-030; ADR-036(2); ADR-044(1) | THR-019; THR-046; THR-020 | C-15, C-14, C-10 | TST: removed member receives no new slots or case keys; old wraps retained until cooling-off; FM-3 |
| KEY-016 | Source passphrases SHALL be 10 words sampled uniformly (rejection sampling on CSPRNG output) from a 7,776-word list, generated by C-03 or C-07 only, confirmed by the source re-typing 3 randomly chosen words before the submission is finalized, never re-displayed after finalization and never stored. | ADR-005; ADR-034; INC-32; B-SD-17; RVW-B-13 | THR-034 | C-03, C-07 | TST: distribution test; finalization blocked without confirmation; code review no persistence |
| KEY-017 | Source key derivation SHALL follow §11.3 exactly (normalization, tenant-bound salt, Argon2id m=65536 KiB t=3 p=1, HKDF labels); FIPS SHALL use PBKDF2-HMAC-SHA-512 with 210,000 iterations. | ADR-005; ADR-006; ADR-046(7); B-CR-19; B-CR-27 | THR-034 | C-11, C-03, C-07 | TST: passphrase KAT vectors |
| KEY-018 | Intake SHALL store only `lookup_tag`, `auth_pk` and mailbox routing ids per source; `src_pk` and `sign_pk` SHALL be transmitted only inside encrypted SUBMISSION objects. | ADR-005; B-SD-16 | THR-015; THR-014 | C-08, C-07 | INSP: schema (09); TST: DB dump contains no source public keys |
| KEY-019 | No recovery, reset or alternative credential SHALL exist for source passphrases; the only credential change SHALL be the authenticated, continuity-signed rotation of §11.7. | ADR-005; ADR-046(7); INC-05 | THR-034; THR-026 | C-06, C-07 | INSP; TST: no reset endpoint in route registry |
| KEY-020 | IDENTITY objects SHALL be wrapped only to the Identity Custodian Group Key; unsealing SHALL require recorded legal basis and a second approver signature before decryption. | ADR-014 | THR-018; THR-019 | C-15, C-14 | TST: case member without custodian key cannot unwrap; audit record present |
| KEY-021 | The Recovery Quorum SHALL be disabled by default in CE/EE and enabled by default in GOV with custodians from independent roles (ADR-044(3)); enabling it SHALL require a RECOVERY_QUORUM entry signed by K01 and two Key-Admins and SHALL be reflected in every roster and shown to sources. | ADR-013; ADR-044(3) | THR-018; THR-026 | C-28, C-14, C-06 | TST: enable without signatures rejected; DEMO: source sees status |
| KEY-022 | Member Epoch Keys SHALL never be wrapped to the Recovery Quorum Key or any other key. | ADR-030; ADR-013 | THR-013; THR-020 | C-15 | TST: stanza audit |
| KEY-023 | Recovery SHALL follow the ceremony of §16 and append a content-free RECOVERY_PERFORMED entry. | ADR-013; B-GL-29 | THR-018 | C-28, C-14 | DEMO: recovery drill; INSP: ceremony transcript |
| KEY-024 | C-14 SHALL implement the entry types, fields and signature requirements of §14.2 and reject any entry that does not satisfy them. | INC-67; INC-14 | THR-046 | C-14 | TST: per-type signature matrix tests |
| KEY-025 | C-14 and every verifier SHALL enforce the continuity rules of §14.4. | INC-62; INC-67 | THR-046 | C-14, C-03, C-07, C-15, C-25 | TST: rule-violation vectors; FM-4 |
| KEY-026 | C-14 SHALL issue exactly one checkpoint per hour at hh:00 UTC in the format of §14.3, SHALL append queued MEMBER_EPOCH, loosening, ROLE_LABEL_CERT, RUNNING_MANIFEST and SEALER_ATTESTATION entries only in the weekly publication slot, and SHALL obtain witness cosignatures per the ORG_ROOT policy. | B-CR-42; ADR-036(7); RVW-A-29 | THR-046; THR-011 | C-14 | TST: checkpoint cadence independent of appends; slot batching test; witness integration test |
| KEY-027 | Source App, Tier W sealer, Desk and C-25 SHALL apply verification rules VR-1..VR-14 and fail closed on any failure. | INC-67; INC-14; ADR-036 | THR-046; THR-007 | C-03, C-07, C-15, C-25 | TST: hostile snapshots in malicious-server harness |
| KEY-028 | Every Desk SHALL validate the full tenant log on sync and raise non-dismissable notifications for changes to rosters, CIKs, epoch wrap counts, quorum, custodians, orphan re-keys and ORG_ROOT. | INC-62 | THR-046; THR-018 | C-15 | TST: injected roster change produces notification |
| KEY-029 | C-25 SHALL validate all directory invariants every 15 minutes and emit a content-free alert on violation. | INC-67 | THR-046 | C-25 | TST |
| KEY-030 | Tier V clients SHALL display the roster summary of VR-8 (Triage Set labels with certification and member-since, pending and recent changes, escrow status and holders, custodians, device custody for INDEPENDENT channels, operator-statement status) before submission and include the verified roster hash and checkpoint in the SUBMISSION. | INC-14; INC-21; ADR-036(3); ADR-043 | THR-046; THR-040 | C-03 | DEMO; TST |
| KEY-031 | On import, Desk SHALL perform VR-9 (a)–(f): verify Recipient List signatures (and CVM sealer attestation where deployed), directory validity of listed MEKs, recomputed expected recipient set (active roster, COI policy, flags, category, follow-up rule), slot accounting, checkpoint age relative to `received_date`, and the single-IDENTITY invariant, and alert on any mismatch. | ADR-033; ADR-035(3); ADR-036(4); INC-28; RVW-A-04; RVW-A-26 | THR-046; THR-014 | C-15 | TST: forged list / extra slot / omitted member / stale checkpoint / follow-up to new member / missing IDENTITY each raise alert |
| KEY-032 | Desks and C-25 SHALL compare the web bundle served on the onion with the latest CLIENT_RELEASE entry and alert on mismatch. | INC-28 | THR-007; THR-025 | C-25, C-15 | TST: unsigned bundle on staging detected |
| KEY-033 | Backup archives SHALL be encrypted per §17.2 to the Backup Master public key; backup agents SHALL NOT hold any backup decryption key. | B-GL-11; INC-55 | THR-017 | C-27 | TST: restore without K25 fails; INSP |
| KEY-034 | Each case SHALL have an Erasure Key in the Erasure Key Vault that encrypts, as an outer layer only, the HPKE stanzas wrapping the case key (no direct EK wrap of a case key SHALL exist); the EKV SHALL be excluded from routine and infrastructure-level backups and have its own backup (EKs re-encrypted to K25) with ≤ 14-day retention; every restore SHALL apply the signed erasure log before serving. | ADR-033; ADR-044(4); INC-55; RVW-B-21; RVW-C-06; RVW-C-07 | THR-017 | C-10, C-12, C-27, C-29 | TST: erase then restore routine backup + EKV backup older than erase → case keys unrecoverable; restore re-applies erasure log; negative vector `ek_direct_wrap`; retention job test |
| KEY-035 | Case erasure SHALL follow §18.2 including dual approval, destruction of the case's Erasure Key, deletion of all wraps, stanzas, slot blocks and blobs, and a signed deletion receipt. | ADR-025; ADR-033; B-CR-33 | THR-017; THR-015 | C-10, C-15, C-24 | TST: post-erase search of DB/EKV/blobs finds no key material for the case |
| KEY-036 | Desks SHALL purge cached keys and decrypted caches for erased cases and refuse to reopen them. | ADR-025 | THR-017 | C-15 | TST |
| KEY-037 | Offline keys (K01, K14, K25-private, K18-root, release roots) SHALL be generated and used only on the air-gapped ceremony machine of §21.2 with a signed ceremony transcript. | B-CR-30; INC-58 | THR-013; THR-024 | C-28, C-29 | INSP: ceremony transcripts; AUD |
| KEY-038 | Shamir-split keys SHALL use the thresholds of §21.3, shares on PIN-protected tokens held by distinct roles, no person holding ≥ k shares, and annual possession attestation. | B-CR-29 | THR-018; THR-031 | C-28 | INSP: share inventory audit |
| KEY-039 | Multi-party authorization SHALL use explicit k-of-n multi-signatures by default; FROST MAY be used only for the Ed25519 component of K01 in EE. | B-CR-29; B-CR-40; B-CR-45 | THR-024 | C-14, C-32 | INSP |
| KEY-040 | In EE/GOV, K02, K18-intermediate, K24, K25 and K29 SHALL reside in an HSM (FIPS 140-3 Level 3 for GOV) accessed via PKCS#11; in CE they SHALL be TPM-sealed. | B-CR-30; INC-58 | THR-013; THR-031 | C-29 | INSP: HSM configuration; TST: key non-exportable |
| KEY-041 | Recipient, case and epoch private keys SHALL never be imported into server-side HSMs or KMS. | ADR-007 | THR-026; THR-014 | C-29 | INSP |
| KEY-042 | Onion service keys SHALL be protected, backed up and rotated per 16-TOR-I2P.md, present on at most 2 intake hosts in EE-HA/GOV-ONPREM (ADR-032) and on exactly one otherwise, and no onion key SHALL exist on hosts outside its placement manifest. | ADR-028; ADR-032; B-SD-22 | THR-044 | C-05 | TST: placement self-test |
| KEY-043 | Scheduled rotations of §15.1 SHALL be tracked by C-25 with alerts when overdue. | — | THR-013 | C-25 | TST |
| KEY-044 | Revoked keys SHALL never be used for encryption and signatures by revoked keys dated after their effective day SHALL be rejected. | INC-67 | THR-046 | C-11, C-14 | TST: revocation vectors |
| KEY-045 | ORG_ROOT keys SHALL be pinned out-of-band at Desk enrollment and delivered to Source App users via the signed onion address statement (16); any non-continuity ORG_ROOT change SHALL be fatal. | INC-52 | THR-046; THR-044 | C-03, C-15 | TST: substituted root rejected |
| KEY-046 | Each key SHALL have exactly one purpose (§19); no key SHALL be used for both signing and encryption or across tenants. | INC-63 | THR-012; THR-045 | C-11 | INSP: key-usage matrix review |
| KEY-047 | Session keys (K28) SHALL exist only in RAM and rotate every 24 hours. | INC-58 | THR-022 | C-06, C-21 | TST |
| KEY-048 | Directory entries SHALL use pseudonymous role labels by default; real names only by explicit tenant opt-in, which SHALL be a DANGEROUS configuration on channels accepting ANONYMOUS reports. | ADR-015; ADR-046(6); RVW-B-32 | THR-019 | C-14 | INSP; TST: default label format; config label check |
| KEY-049 | Before sealing, the sealer (Tier V client locally, C-07 in RAM for Tier W) SHALL restrict recipients to the Triage Set, remove members flagged by the source and members mapped to the chosen category in the active CIK-signed COI_POLICY, and, if no eligible MEK remains, SHALL NOT seal and SHALL direct the source to the independent-route channel (or show "temporarily unavailable"). | ADR-030; ADR-037; INC-22 | THR-020 | C-03, C-07 | TST: flagged role receives no slot; non-triage member receives no slot; empty set fails closed with pointer; FM-1 |
| KEY-050 | C-10 SHALL list pending envelopes only to Triage Set members of the channel and identically to each of them; Desk SHALL NOT surface envelopes it cannot open; non-triage roles SHALL see no intake counts; pending-list fetches SHALL be audited. | ADR-033; ADR-037(2); RVW-B-04 | THR-020 | C-10, C-15 | TST: non-triage member gets 403/empty; responses identical across triage members; UI test |
| KEY-051 | C-14 SHALL reject rosters with fewer than 2 or more than 16 `read_intake` members, `read_intake` members without a current independent ROLE_LABEL_CERT, `channel_admin` outside the Triage Set/OVERSIGHT or on a COI-mapped label, and MEMBER_EPOCH entries not signed by the K08 of a current `read_intake` member. | ADR-030; ADR-036(1); ADR-037(1) | THR-046 | C-14 | TST: rule-violation vectors |
| KEY-052 | The EKV master key K33 SHALL be TPM-sealed (CE; physical TPM, never vTPM, in HIGH and GOV) or HSM-resident (EE/GOV), Erasure Keys SHALL be HSM objects in EE/GOV, and the vault SHALL be a host-local store on its own volume (never a PostgreSQL schema), replicated to the DR site within the HA RPO. | ADR-033; ADR-044(4); INC-58; RVW-C-06; RVW-C-08 | THR-017; THR-031 | C-12, C-29 | INSP; TST: key non-exportable; vault absent from WAL/replicas; DR replica test |

## 27. Residual risks and limitations (honest)

1. **Tier W plaintext exposure.** A live-compromised or compelled intake host (C-06/C-07) reads Tier W submissions (including COI flags) and Tier W reply views during the compromise (ADR-004). Mitigation is isolation and honest disclosure, not prevention.
2. **Harvest-now-decrypt-later on Tor transit** for Tier W, because Tor circuit handshakes are classical (§5.1), unless onion TLS with a PQ group is enabled and supported by the source's browser.
3. **Recipient endpoint compromise** exposes everything in that member's scope (no FS for case keys) plus un-imported envelopes where the member was eligible. Hardware binding reduces key theft but not a live-compromised unlocked Desk.
4. **Insider with legitimate keys** (eligible member) can exfiltrate MEK or case keys undetectably; only audit and least privilege limit this.
5. **Excluded members can learn that an exclusion happened** (they cannot open a pending envelope) — not who reported, the category or the content (§14.6). Inherent to per-member keys (ADR-030).
6. **Removed members** keep their MEK private keys; until those envelopes are imported and the epoch retires, a removed member who was eligible can still open un-imported envelopes of epochs before removal.
7. **Recipient anonymity of slots relies on KEM key privacy (CA-9)**, which must be confirmed for the hybrid combiners by external review.
8. **Admin + member collusion** can add a recipient; visible in the log and to Tier V sources, but Tier W sources and inattentive members may not notice.
9. **Split-view detection needs witnesses.** Without an independent witness, a Z-CORE compromise holding K02 could present a forked directory to a targeted Tier V source; detection then depends on VR-9 at import (which a compromised core could also suppress).
10. **Backup erasure bound.** Erased cases remain recoverable for up to 14 days from EKV backups by an adversary who also holds routine backups, K25 and a member K09 or k quorum shares (ADR-033).
11. **Erasure Key loss** (EKV destroyed with no valid EKV backup) makes case keys unrecoverable from the DB; EKV availability is therefore safety-critical (HA replica, 19/21).
12. **Reply metadata.** The intake server knows which mailbox received replies and how many (no private fetch in v1; SecureDrop Protocol's challenge-based fetch is future work, B-SD-11).
13. **Size/count leakage remains coarse:** bucket sizes, per-report message counts, upload volume on the network.
14. **Draft standards.** X-Wing and HPKE-PQ codepoints are drafts (B-CR-05, B-CR-06); a codepoint or combiner change requires a new suite ID and migration.
15. **Source passphrase compromise** (THR-034): exposes stored replies and allows impersonation; not submissions.
16. **FIPS profile** relies on PBKDF2 (not memory-hard); safe only because passphrase entropy is 129 bits.
17. **Implementation risk** in young PQ libraries (ML-KEM crate audit status UNVERIFIED, R5 §A.5).

## 28. Open issues

| # | Issue | Proposed resolution |
|---|---|---|
| OI-1 | **Open Issue for ADR revision — ADR-030 vs ADR-033.** ADR-030 still says the envelope header lists recipient key IDs; ADR-033 item 1 supersedes this (anonymous slots). This document follows ADR-033. | Edit ADR-030 text to reference ADR-033 to avoid implementers following the superseded sentence. |
| OI-2 | **Open Issue for ADR revision — missing ADR for the key directory.** The task referenced "ADR-046"; no such ADR exists in DECISIONS.md. This document uses THR-046 and defines continuity/dual-control rules (§14.4), COI_POLICY and MEMBER_EPOCH entry semantics, which are major architectural decisions. | Add an ADR "Key Directory continuity, dual control and witness policy". |
| OI-3 | **Open Issue for ADR revision — ADR-006 FIPS source KDF.** ADR-006 names Argon2id for the source passphrase without a FIPS alternative; Argon2id is not FIPS-approved. This document uses PBKDF2-HMAC-SHA-512 (600,000 iterations) in CANDOR-FIPS-1. | Amend ADR-006. |
| OI-4 | **Open Issue for ADR revision — ADR-005/006 Argon2id at 256 MiB server-side (Tier W).** Each Tier W login/submission costs 256 MiB × ~0.5 s on C-07: DoS amplification (bounded here by concurrency limits) and possible OOM on small CE hosts; Tor Browser WASM on mobile may not allocate 256 MiB. | Consider a lower Tier W server-side cost with unchanged 129-bit entropy, or size C-07 RAM ≥ 4 GiB (34). |
| OI-5 | **Open Issue for ADR revision — ADR-033 item 3 wording.** "Each case key is additionally wrapped under a per-case Erasure Key" could be read as a server-decryptable wrap of the case key, which would violate ADR-007. This document implements EK strictly as an outer layer around member/quorum wraps (§9.10). | Clarify ADR-033 wording. |
| OI-6 | **Open Issue for ADR revision — exclusion observability (ADR-030).** Per-member keys let an excluded member observe that some envelope excludes it (§14.6); ADR-030's privacy effect does not mention this. | Add to ADR-030 privacy effect; guidance in 14/21 to route executive-related categories to independent channels. |
| OI-7 | Channel Identity Key holders: ADR-008 gives the CIK to all members; this document introduces a `channel_admin` capability (default all members, conformant) so tenants can restrict it. | Confirm in 14/15. |
| OI-8 | Ed25519 inside the AWS-LC FIPS 3 validated boundary is UNVERIFIED. | Confirm; otherwise ECDSA P-384 in FIPS profile. |
| OI-9 | HPKE-PQ and X-Wing codepoints are drafts; derandomized encapsulation for dummy slots and KEM key privacy of the hybrids need explicit external review. | Pin draft versions + KATs; include in 37 audit scope and FM-5. |
| OI-10 | Tier V via web depends on WEBCAT in Tor Browser (not yet available). | Launch Tier V with the Source App only; web Tier V behind a feature flag. |
| OI-11 | Metadata-private reply fetch (ristretto255 challenge, SecureDrop Protocol) not in v1. | Evaluate for v2; requires fixed-size mailbox model. |
| OI-12 | Onion TLS default (`onion_tls`) for HIGH profile depends on CA `.onion` issuance and Tor Browser PQ-group support (Knowledge (unverified)). | Validate in 30; decide default per profile in 18. |
| OI-13 | Witness availability and privacy for per-tenant logs. | Define witness operators (internal independent role; optional third-party) in 21/22. |
| OI-14 | C-tor cannot keep onion identity keys offline. | Track Arti (16). |
