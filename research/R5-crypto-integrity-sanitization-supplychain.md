# R5 — Cryptographic Building Blocks, Client-Code Integrity, Secure Development & File Sanitization

*Research note for the design of a high-assurance whistleblowing platform. As of 2026-09-30.*

**Method and caveats.** This note is based on web searches and on primary sources I read directly: shallow git clones of the SecureDrop Protocol spec (`freedomofpress/securedrop-protocol`, commit dated 2026-09-28), CoverDrop (`guardian/coverdrop`, 2026-09-25), age / C2SP age spec, `hpkewg/hpke-pq` (2026-07-06), the X-Wing draft repo (2026-09-23), WEBCAT and `webcat-spec`, Dangerzone (tags v0.7.0–v0.11.0, advisories), mat2 (CHANGELOG/threat model), and the libsodium docs. The egress proxy blocked direct fetches from several primary hosts: csrc.nist.gov, ietf.org/datatracker, eprint.iacr.org, freedom.press/securedrop.org, blog.cloudflare.com, hacks.mozilla.org, go.dev, and slsa.dev. For those sources, the facts here come from search-engine extracts of the primary pages, and I note that where it matters. Items I could not confirm are marked **UNVERIFIED**. Citations use the form [B-CR-xx] (bibliography at the end).

---

## Executive summary (decisions)

| Area | Primary choice (non-FIPS / "best crypto") | FIPS-mode alternative | Rationale |
|---|---|---|---|
| Public-key encryption to journalists/newsroom | HPKE (RFC 9180) with **X-Wing = MLKEM768-X25519 (HPKE KEM 0x647a)**, HKDF-SHA256, ChaCha20-Poly1305 | HPKE with **MLKEM1024-P384 (0x0051)** or MLKEM768-P256 (0x0050), HKDF-SHA256/384, AES-256-GCM, from a FIPS 140-3 module that includes ML-KEM (e.g., AWS-LC 3, cert #5314) | Protects against harvest-now-decrypt-later. The hybrid holds if either ML-KEM or ECDH holds. The IETF HPKE-PQ codepoints follow the X-Wing construction [B-CR-05][B-CR-06][B-CR-07] |
| Signatures (messages, key bundles) | Ed25519 (RFC 8032; FIPS 186-5 approved) | Ed25519 or ECDSA P-384 in a validated module; add ML-DSA-65/87 when tooling allows | PQ authentication is not yet urgent for ephemeral messaging, but it is urgent for long-lived trust anchors |
| Release/code-signing roots (long-lived) | Hybrid: Ed25519 plus **ML-DSA-65** or a hash-based **SLH-DSA-SHA2-128s** offline root; threshold t-of-n signers | ML-DSA-87 or LMS/XMSS (SP 800-208) per CNSA 2.0 | CNSA 2.0 sets software/firmware signing as the earliest category to switch ("exclusively" by 2030) [B-CR-10] |
| Symmetric AEAD (records/messages) | XChaCha20-Poly1305 (random 192-bit nonces) | AES-256-GCM with deterministic/counter nonces, or random 96-bit nonces capped well below 2^32 messages per key | Nonce-misuse safety versus FIPS approval |
| Large files | **age v1 STREAM** (ChaCha20-Poly1305, 64 KiB chunks) or libsodium `secretstream_xchacha20poly1305` | Tink **AES-GCM-HKDF streaming** (AES256_GCM_HKDF_1MB) built on a FIPS module | Chunked AEAD resists truncation and reordering and bounds memory use [B-CR-14][B-CR-15] |
| Key commitment | Always add a commitment (HMAC-SHA256 over the header/key-ID with a key derived from the DEK, as age does) | Same (HMAC-SHA-256 is approved) | GCM, ChaCha20-Poly1305 and GCM-SIV are **not** key-committing ("invisible salamanders") [B-CR-16][B-CR-17] |
| KDF | HKDF-SHA256 (RFC 5869) with distinct `info` labels | HKDF per SP 800-56C r2 (approved) | Standard, and matches HPKE/age |
| Password hashing (staff logins) | Argon2id, at least m=64 MiB, t=3, p=4 (RFC 9106 second recommended option); never below OWASP's minimum of m=19 MiB, t=2, p=1 | PBKDF2-HMAC-SHA256 with ≥600k iterations (OWASP), per SP 800-132 | [B-CR-19][B-CR-20] |
| Password-derived *keys* (sources) | Generated high-entropy secret: ≥128-bit (12-word BIP39, as the SecureDrop Protocol uses) or ≥8 diceware words, stretched with Argon2id m≥256 MiB, t≥3 where the client allows it | Same entropy; PBKDF2 as the stretcher | Entropy matters more than the stretching function. CoverDrop uses 5 EFF words + Argon2 256 MiB, t=3 on devices without a secure element [B-CR-27] |
| Staff authentication | FIDO2/WebAuthn hardware keys + **OPAQUE** (RFC 9807, CFRG Informational, July 2025) for passwords | WebAuthn with a FIPS-validated authenticator; PBKDF2-verified password over TLS | The server never sees the password [B-CR-21] |
| Group messaging among staff | MLS (RFC 9420) | MLS ciphersuite 0x0002/0x0007 (P-256/P-384, AES-GCM) | FS and PCS for groups [B-CR-22] |
| Source↔journalist protocol | Adopt or track the **SecureDrop Protocol** design (HPKE AuthPSK + ML-KEM-768; X-Wing metadata; stateless sources; ristretto255 fetch) | n/a (ristretto255/X25519 are not FIPS) | Formally analysed with Tamarin plus game-based proofs; ACM CCS 2026 [B-CR-24][B-CR-25] |
| Key custody | Org root in an HSM (PKCS#11, FIPS 140-3 L3), Shamir 3-of-5 offline backup; t-of-n multi-signature for releases | Same | [B-CR-29][B-CR-30] |
| Deletion | Per-object DEKs wrapped by KEKs; **cryptographic erase** by destroying the DEK/KEK (NIST SP 800-88 r2, Sept 2025) | CE with FIPS-validated modules is required for federal CE claims | [B-CR-33] |

---

## A. Cryptographic building blocks — best practice 2025-2026

### A.1 Standards landscape (status as of 2026-09-30)

- **FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)** were finalised on 13 Aug 2024 [B-CR-01]. ML-KEM parameter sets are 512/768/1024 (NIST categories 1/3/5). The HPKE-PQ draft advises implementers to "generally prefer ML-KEM-768 or ML-KEM-1024 … as a hedge against cryptanalysis" over ML-KEM-512 [B-CR-06].
- **NIST SP 800-227**, *Recommendations for Key-Encapsulation Mechanisms*, was finalised on **18 Sep 2025** after the Feb 2025 KEM workshop [B-CR-02]. It gives definitions, security properties and implementation/usage guidance for KEMs, including how to combine a KEM with other key-establishment schemes. It could not be fetched directly (csrc blocked), so the detailed combiner wording is **UNVERIFIED** here. My understanding, from the IPD, is that hybrid combiners are acceptable under FIPS when an approved KDF/combiner (SP 800-56C) mixes an approved shared secret (ML-KEM) with the other secret.
- **NIST IR 8547** (IPD, Nov 2024) proposes that quantum-vulnerable RSA/ECC (ECDH, ECDSA, EdDSA, RSA, FFDH) be **deprecated after 2030 and disallowed after 2035**. Secondary sources say it was *still a draft as of mid-2026* [B-CR-03]. **OMB M-26-15**, *Execution of the Migration to Post-Quantum Cryptography* (24 Jun 2026, following EO 14412), treats those dates as the federal planning baseline. It sets a five-phase migration schedule for 2026-2035 and requires agency PQC plans by October 2026 [B-CR-04]. These are secondary-source summaries; I did not read the memorandum's text directly. For the platform, **ship hybrid PQ key establishment now**. Stored leak material is the textbook harvest-now-decrypt-later target.
- **CNSA 2.0** (NSA; National Security Systems): ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/512, plus LMS/XMSS for firmware signing. Software/firmware signing is to be "support and prefer" from 2025 and exclusive by 2030. Web browsers/servers and cloud services are exclusive by 2033 [B-CR-10]. The platform is not an NSS. Use CNSA 2.0 as the "maximum assurance" profile, e.g., for the offline archive tier.
- **Hybrid KEMs.** **X-Wing** (draft-connolly-cfrg-xwing-kem; -10 Mar 2026, -11 Sep 2026; Informational/CFRG) is X25519 + ML-KEM-768 with a SHA3-256 combiner. The combiner omits the ML-KEM ciphertext because ML-KEM is ciphertext-binding, which makes it simple and fast [B-CR-05]. **draft-ietf-hpke-pq-05** (6 Jul 2026, Standards Track, HPKE WG) defines HPKE KEM codepoints. I read them from the WG repository [B-CR-06]:
  - `0x0040/0x0041/0x0042` ML-KEM-512/768/1024 (pure PQ)
  - `0x0050` MLKEM768-P256, `0x0051` MLKEM1024-P384, **`0x647a` MLKEM768-X25519**. The X-Wing draft requests the same memorable codepoint (25519+203 = 0x647a), so MLKEM768-X25519 *is* X-Wing via draft-irtf-cfrg-concrete-hybrid-kems.
  - New single-stage KDFs: SHAKE128 `0x0010`, SHAKE256 `0x0011`, TurboSHAKE128/256 `0x0012/0x0013`. `DeriveKeyPair` uses SHAKE256.
  - TLS equivalent: X25519MLKEM768 is widely deployed. Search results show it published as **RFC 10024** (PQ/T hybrid key agreement for TLS 1.3) [B-CR-08]. The RFC number came from search only and is **UNVERIFIED** against rfc-editor.
- **HQC** was selected in March 2025 as a backup (code-based) KEM. A draft standard is expected, but its status is **UNVERIFIED**. **FN-DSA (FIPS 206, Falcon)** is draft/final status **UNVERIFIED**. Do not depend on it.

### A.2 HPKE, X25519/Ed25519

- **HPKE (RFC 9180, Feb 2022)** [B-CR-07] is the right KEM-DEM abstraction. Use **single-shot `Seal/Open` in `mode_base`** for anonymous-sender encryption (source → journalist). Consider **`mode_auth_psk`** only when you need sender authentication without signatures. The SecureDrop Protocol uses AuthPSK to inject ML-KEM into the key schedule, following Alwen et al. 2023, *The Pre-Shared Key Modes of HPKE*. Note its documented limitation: HPKE's implicit DH authentication is **vulnerable to key-compromise impersonation (KCI)** (RFC 9180 §9.1.1), and it offers "quantum-resistant message encryption, but not quantum-resistant message authentication" [B-CR-24].
- Always bind context into `info` (protocol label, version, recipient key ID, submission ID). The SecureDrop Protocol binds `c2 ‖ pkS ‖ pkR_fetch` into `info` to stop key-swapping, forged-sender, relay and re-encapsulation attacks. `info` is never transmitted because the public keys are identifying [B-CR-24].
- **X25519/Ed25519** remain the default classical primitives. Ed25519 is FIPS 186-5 approved. X25519 is **not** an approved key-agreement scheme in FIPS mode (SP 800-56A covers P-curves). In FIPS deployments, use P-256/P-384 hybrids (0x0050/0x0051).

### A.3 AEAD choice and key commitment

| AEAD | Nonce | FIPS | Committing? | Use |
|---|---|---|---|---|
| AES-256-GCM | 96-bit; random nonces limit ≈2^32 msgs/key (SP 800-38D) | Yes | No | FIPS profile; counter nonces for DB records |
| ChaCha20-Poly1305 (RFC 8439) | 96-bit | No | No | age payload, HPKE, TLS |
| XChaCha20-Poly1305 | 192-bit random-safe | No | No | Default for stored records (CoverDrop uses it) [B-CR-27] |
| AES-GCM-SIV (RFC 8452) | 96-bit, misuse-resistant | No (not an SP 800-38 mode) | No | Only if deterministic/nonce-reuse risk dominates |

- **Invisible salamanders.** For GCM, GCM-SIV and any Poly1305-based scheme, one can craft a ciphertext that decrypts validly under two keys (Dodis–Grubbs–Ristenpart–Woodage CRYPTO 2018; Grubbs, Black Hat 2020) [B-CR-16]. Follow-up work generalised this into practical attacks on multi-recipient encryption, key-rotation systems and password-based encryption [B-CR-17].
- **Relevance here.** A malicious "source" or insider could craft one submission that shows different plaintext to different journalists or reviewers, or that bypasses a malware scanner which sees a benign decryption. Moderation, audit-log hashes and "what did the source send" disputes all depend on commitment.
- **Fix.** Derive `commit_key = HKDF(DEK, "commit")` and store `HMAC-SHA256(commit_key, header)` (age's approach). Alternatively use a committing construction such as CTX, or the "padding fix" of prepending zero blocks and checking them, per Albertini et al. [B-CR-17]. **age** is robust in practice: its header MAC is HMAC-SHA-256 under a key derived from the file key, and the payload key is derived from the file key [B-CR-14]. **CoverDrop's "Multi Anonymous Box"** encrypts one XSalsa20-Poly1305 payload under a random key wrapped per recipient with sealed boxes, and its doc does not describe a key commitment [B-CR-27]. If you reuse a similar pattern, add one.

### A.4 Streaming encryption for large files

- **age v1 (C2SP spec)** [B-CR-14]:
  - Header `age-encryption.org/v1` with recipient stanzas that wrap a 128-bit file key.
  - Header MAC is HMAC-SHA-256 with `HKDF(file_key, "", "header")`.
  - Payload key is `HKDF-SHA-256(file_key, nonce16, "payload")`.
  - STREAM: 64 KiB chunks, 12-byte nonce = 11-byte big-endian counter + final flag byte, ChaCha20-Poly1305. The final flag prevents truncation.
  - Recipient types include X25519, scrypt (must be the only stanza), and a **hybrid PQ `MLKEM768-X25519` recipient using HPKE with X-Wing** (keys `age1pq1…`), plus tag types for hardware keys.
  - Releases (from git tags): **v1.3.0 (2025-12-27) added native PQ recipients**. **v1.3.2 (2026-08-29)** added hardening: it rejects headers >2 MiB or >1024 recipients, malformed SSH keys, and non-UTF-8 terminal output [B-CR-14].
  - A third-party audit of age's Go implementation is **UNVERIFIED** (no audit report located). Treat age as well-reviewed but not formally audited unless a report is found.
- **libsodium `crypto_secretstream_xchacha20poly1305`** [B-CR-15] detects truncation, removal, reordering, duplication and modification. It has no practical stream length limit and ~256 GB per message. Its tags (`PUSH`, `REKEY`, `FINAL`) are encrypted, and explicit `REKEY` provides forward secrecy within a stream.
- **Tink streaming AEAD** (AES-GCM-HKDF and AES-CTR-HMAC segment-based, with random access) is the FIPS-friendlier option on AWS-LC/BoringCrypto. Parameters are **UNVERIFIED** here because developers.google.com was blocked. Use `AES256_GCM_HKDF_1MB`.
- **Recommendation.** Store each submission file as `age`-format ciphertext to the newsroom's hybrid PQ recipient(s), or as an age-like envelope of your own. Keep a per-file random DEK, wrap the DEK under the KEK hierarchy (A.9), and keep a commitment tag.

### A.5 Libraries and audits

- **libsodium.** Mature; used by CoverDrop (X25519, Ed25519, XChaCha20-Poly1305, sealed boxes = X25519 + XSalsa20-Poly1305) [B-CR-27]. No PQ KEM in libsodium core at time of writing (**UNVERIFIED** for 1.0.20+).
- **RustCrypto.** The `aes-gcm`/`chacha20poly1305` crates had an NCC Group audit (2020, funded by MobileCoin); cite as **UNVERIFIED** since the report was not re-fetched. The `ml-kem` crate audit status is **UNVERIFIED**. CoverDrop pins its Rust dependency tree with `cargo-vet` (`supply-chain/audits.toml`, `imports.lock`) — a good pattern [B-CR-27].
- **Tink.** Misuse-resistant APIs and key management via keysets. Recommended for the server side in Java, Go or C++.
- **FIPS 140-3 validated modules**:
  - **AWS-LC 3**: CMVP **#5314**, FIPS 140-3 L1, validated 2026-06-05 (per sec-certs), sunset 2031. It is **the first open-source module with ML-KEM inside the FIPS boundary** [B-CR-11].
  - **OpenSSL 3.1.2 FIPS provider**: **#4985**, active to 10 Mar 2030, no PQC. **OpenSSL 3.5.4** (with ML-KEM/ML-DSA/SLH-DSA) was *submitted* to CMVP in Oct 2025. Certificate issuance by 2026-09 is **UNVERIFIED** [B-CR-12].
  - **Go Cryptographic Module v1.0.0** (Go 1.24+): **CMVP #5247**, CAVP A6650. v1.26.0 was "Pending Review" as of 2026-04-28. Go+BoringCrypto is deprecated and incompatible with native FIPS mode [B-CR-13]. Whether ML-KEM is inside the #5247 boundary is **UNVERIFIED**.
  - **BoringCrypto** (BoringSSL FIPS module) has FIPS 140-3 validations. The current certificate number is **UNVERIFIED**.

### A.6 Password hashing, PAKE, KDF

- **Argon2id (RFC 9106).** RFC 9106's first recommended option is t=1, p=4, m=2 GiB. The second option, for memory-constrained settings, is t=3, p=4, m=64 MiB [B-CR-19]. OWASP's floor is m=19 MiB (19456 KiB), t=2, p=1, with equivalent trade-offs [B-CR-20]. For interactive staff login, use at least m=64 MiB, t=3, p=1-4, tuned to ≈0.5 s. Add a server-side pepper held in the HSM/KMS (HMAC before storage).
- **Browser/WASM clients** (source side) may not afford 256 MiB+. Push entropy up instead: generated 12-word BIP39 (128 bits) in the SecureDrop Protocol, which derives keys with HKDF-SHA256 from the BIP39 entropy [B-CR-24]. CoverDrop's calculation shows that with Argon2 at 256 MiB/t=3, 5 EFF words (~64.6 bits) hold up, whereas 3 words (~38.8 bits) suffice only with secure-element rate limiting [B-CR-27].
- **OPAQUE, RFC 9807 (July 2025)**, is a CFRG *Informational* aPAKE with a 3DH instantiation. The password is hidden from the server even at registration, it resists pre-computation after server compromise, and it provides forward secrecy [B-CR-21]. Use it for journalist/admin passwords as a second factor alongside WebAuthn, not as the only factor.
- **HKDF (RFC 5869)** is the universal KDF. Use unique `info` strings per purpose, e.g., `"leaks/v1/dek-wrap"`, `"leaks/v1/commit"`, `"leaks/v1/search-index"`.

### A.7 Forward secrecy in messaging

- **MLS (RFC 9420, Jul 2023)** [B-CR-22] provides group key agreement with FS and PCS. It suits internal newsroom/case-team chat. Choose ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` or a PQ/hybrid suite once standardised (an MLS PQ ciphersuite draft exists; its status is **UNVERIFIED**).
- **Signal.** PQXDH (2023) added ML-KEM (originally Kyber) to the initial handshake. **SPQR (Sparse Post-Quantum Ratchet), announced Oct 2025**, adds an ML-KEM-768 ratchet mixed with the Double Ratchet (the "Triple Ratchet"). It uses chunking/erasure coding to spread large KEM messages, provides authenticated downgrade protection, and was built with PQShield, NYU and AIST contributors [B-CR-23]. It shows that **PQ FS and PCS are practical**.
- **Source-side constraints.** A whistleblower source is intentionally **stateless** (no local state, for deniability). Full double-ratchet FS is therefore impossible on the source side. The SecureDrop Protocol gives journalist-side inbound FS through **one-time ephemeral key bundles** (APKE_E, PKE_E) that the server serves once (no "last-resort key"). Sources' keys are permanent and derived from the passphrase [B-CR-24]. Accept this asymmetry explicitly in the threat model.

### A.8 SecureDrop Protocol and CoverDrop (domain-specific prior art)

**SecureDrop Protocol** (FPF + ETH Zürich; spec v0.4, PoC v0.4, Tamarin models v0.3) [B-CR-24][B-CR-25]:
- **Paper and status.** Berra, Linker, Maier, Myers, Paterson, Shane, Veitch, *"The SecureDrop Protocol: End-to-End Encrypted Whistleblowing for All"*, IACR ePrint 2026/1484, forthcoming at **ACM CCS 2026**. Prior milestones: Maier's formal analysis (Jan 2025, ETH, leading to spec v0.2) and a preliminary crypto audit by Michele Orrù (Dec 2023). Integration begins in 2026. The PoC is explicitly "not intended for production use".
- **Key hierarchy.** FPF Ed25519 signs the newsroom Ed25519 key, which signs journalist Ed25519 keys. Journalists hold long-term APKE keys (DHKEM(X25519) + ML-KEM-768), one-time APKE_E and PKE_E keys (X-Wing), and ristretto255 fetch keys. Sources derive all keys from the passphrase.
- **Primitives.** Messages use SD-APKE = HPKE `SealAuthPSK` with DHKEM(X25519, HKDF-SHA256) and PSK = ML-KEM-768 shared secret, KS HKDF-SHA256, AEAD ChaCha20-Poly1305. Metadata uses SD-PKE = HPKE base mode with **X-Wing**.
- **Anonymous fetching.** A challenge-based, identity-hiding fetch over ristretto255 lets the server pad replies to a fixed number of messages/challenges.
- **Fixed sizes.** Journalists must produce the same ciphertext sizes as sources. Messages are padded to a fixed size (envelope = fixed size + 3552 bytes).
- **Known limitations** (verbatim themes): no attachment transfer spec yet, no journalist key replenishment spec, no newsroom key rotation spec, not designed for scalability (bounded by per-request challenges over Tor), KCI, and no PQ authentication or PQ fetching [B-CR-24].
- **Design takeaway.** Reuse its structure (HPKE + hybrid PQ, fixed-size padding, one-time recipient keys, unauthenticated stateless API, signed roster). Design **attachments** separately: chunked, padded to size buckets, per-file DEK.

**CoverDrop** (Guardian + Cambridge; deployed in the Guardian app April 2025; UCAM-CL-TR-999) [B-CR-26][B-CR-27]:
- **Primitives.** libsodium X25519, Ed25519, XChaCha20-Poly1305, sealed boxes and "Multi Anonymous Box".
- **Traffic analysis resistance.** Every app user sends constant-rate cover traffic. A hardened on-prem **CoverNode** mixes and decrypts the outer layer, behind an untrusted AWS API. Messages use a GZip Padded Compressed String of fixed length.
- **Deniable client storage.** Local storage is plausibly deniable, keyed by an EFF-wordlist passphrase and Argon2 at 256 MiB/t=3.
- **Takeaways.** (1) Cover traffic from a large user base is the strongest defence against network-level source discovery. (2) Fixed-size everything. (3) `cargo-vet` for dependencies. (4) Add key commitment to multi-recipient boxes.

### A.9 Key hierarchy, envelope encryption, HSMs, thresholds, erasure

**Hierarchy:**

```
Offline Org Root (HSM, FIPS 140-3 L3; Shamir 3-of-5 backup on smartcards in separate custody)
 ├─ Newsroom signing key (Ed25519 [+ML-DSA-65]) — signs roster, key bundles, config
 ├─ Journalist device keys (hybrid KEM, on hardware tokens / TPM-sealed where possible)
 └─ Storage KEKs (per-tenant/per-case, HSM/KMS resident, rotated yearly)
       └─ per-submission DEK (random 256-bit) → wraps per-file DEKs → age/STREAM ciphertext
```

- **Envelope encryption.** DEKs never leave memory unwrapped. Wrap them with AES-256-KW (RFC 3394/SP 800-38F) or HPKE to the journalist's public key, so that **server-side KEKs cannot decrypt content (E2EE)**. Server KEKs then protect only server-held metadata.
- **HSM/PKCS#11.** Use HSMs (FIPS 140-3 Level 3) for org root/signing keys, and PKCS#11 v3.x (OASIS). Specific HSM vendors' PQC support and certificates are **UNVERIFIED**.
- **Threshold schemes.**
  - **Shamir secret sharing** for backup of offline roots, with t-of-n custody across jurisdictions.
  - **FROST (RFC 9591, Jun 2024)** [B-CR-29] produces a single Ed25519/ristretto255 signature from a t-of-n group. It suits cases where the verifier must see one ordinary signature.
  - **For releases, prefer explicit multi-signature thresholds** (TUF/WEBCAT-style, `threshold: k` of listed signers). Each signer's key and signature is then individually logged and attributable. WEBCAT's `server.md` defines `signers` + `threshold` [B-CR-40]. TUF role thresholds work the same way [B-CR-45].
- **Cryptographic erasure.** **NIST SP 800-88 Rev. 2 (final, 26 Sep 2025)** [B-CR-33] retains Cryptographic Erase (CE) as a *Purge* technique. Its preconditions (per summaries) are:
  - Keys must be generated and held in validated modules (federal: current FIPS 140).
  - No sensitive data may have been stored in plaintext on the media before the keys were established.
  - All copies of the key must be destroyed.

  Design for CE from day one:
  - Per-submission DEKs, and key-wrapped backups only.
  - Never log plaintext.
  - Separate retention clocks for DEKs versus ciphertext blobs.
  - A "destroy case" operation that zeroises KEK versions in the HSM and records a signed deletion receipt.
  - Caveat: CE cannot reach copies that journalists exported, or plaintext that ever touched swap or journals. Disable swap on processing VMs and use encrypted, tmpfs-only disposables.

---

## B. The server-delivered client code problem

### B.1 The problem

**Hushmail, 2007.** Hushmail's Java applet did client-side encryption, yet a Canadian court order obtained through an MLAT (U.S. DEA case) led to **12 CDs of decrypted mail**. The server could serve a *targeted, modified* applet that captured the passphrase [B-CR-35]. Any browser-delivered E2EE, including a WASM/JS SecureDrop-like source interface, inherits this issue. The server (or whoever coerces or compromises it, including a CDN/TLS MITM) can serve different code **to one user at one time**, and without integrity, consistency and transparency this is undetectable. Web Crypto only prevents key extraction for non-extractable keys. It does nothing about malicious page code. Subresource Integrity (SRI) protects sub-resources only when the (unprotected) HTML that declares the hashes is trustworthy, so it does not solve the root-document problem.

### B.2 Mitigation landscape (2024-2026)

- **Meta Code Verify** (2022; WhatsApp Web, later Messenger/Instagram) [B-CR-36]. A browser extension compares the page's JS hashes against a hash manifest published via Cloudflare as a third party. It is site-specific and depends on the extension. The later WAICT effort is its generalisation.
- **WEBCAT** (FPF) [B-CR-37][B-CR-38][B-CR-40]:
  - **What it enforces.** Blocking code signing, integrity and transparency for single-page apps. Developers sign a manifest covering all HTML/JS/CSS/WASM with Sigstore (OIDC identities) and/or Sigsum keys, with a **k-of-n `threshold`**. Site owners enroll domains into a list maintained by a **CometBFT-based enrollment consensus**, so no single community member can censor enrollment. A Firefox (MV2) extension verifies using only Web Crypto and enforces a strict CSP.
  - **Transport and Tor.** WEBCAT is TLS-independent, so it works for **onion services**. Tor Browser integration is in progress with the Tor Project.
  - **Status.** Alpha: the README warns that it "might not yet provide the intended security guarantees". Git tag **v3.0.0 on 2026-09-29**. An independent evaluation is reported, but its details were not fetched (**UNVERIFIED**). There is an Ethereum Foundation 1TS grant (Aug 2026). The origin is Giulio Berra's master thesis (ePrint 2025/797).
- **WAICT (Web Application Integrity, Consistency and Transparency)** [B-CR-39]:
  - **Who.** A W3C-community effort with Cloudflare, Mozilla, FPF and Meta, introduced by Cloudflare in Oct 2025 and in a Mozilla Hacks post in May 2026.
  - **Mechanism.** Sites bind their code to a manifest committed to a public transparency log. If an **opted-in site serves unlogged code, the browser rejects it**, so targeted attacks become observable and attributable.
  - **Status.** A prototype sits **behind a pref in Firefox Nightly**, with a demo at waict.dev.
  - **Outlook.** This is the most promising long-term, extension-free fix. It is not deployable to general users in 2026.
- **Isolated Web Apps / Signed Web Bundles** (Chromium) [B-CR-41]. The app is packaged as a signed bundle (Integrity Block v2 adds key rotation) and installed rather than fetched live. Initially this was enterprise-policy install only, on ChromeOS first (shipping around Chrome 128). It is useful for **journalist workstations on managed ChromeOS**, not for anonymous sources on Tor Browser.
- **Native/installed clients plus binary transparency.** Ship signed, reproducible binaries and log every release in a transparency log. Options include **Sigstore Rekor**, whose v2 "rekor-tiles" is a tile-based log sharded roughly every 6 months under a 99.5% SLO [B-CR-42]. **Sigsum** (minimal, witness-cosigned) and the Go-style checksum DB (sum.golang.org) are alternatives. Clients refuse artifacts lacking an inclusion proof, and witnesses/monitors detect split views.
- **Reproducible builds.**
  - Useful references: reproducible-builds.org, Debian's reproducibility effort, and Tor Browser's `rbm`-based reproducible builds [B-CR-43].
  - Dangerzone publishes **reproducible** sandbox images with a documented verification process (`docs/developer/reproducibility.md`) [B-CR-44].
  - Reproducibility turns "trust the builder" into "trust any one of N independent rebuilders".
- **SLSA.** v1.0 (2023), v1.1 (Apr 2025), and **v1.2 (Nov 2025)**, which adds the **Source Track** [B-CR-46]:
  - Source L1: version control.
  - Source L2: immutable history + source provenance.
  - Source L3: enforced technical controls.
  - Source L4: mandatory two-party review.

  Build L3 means a hardened, isolated build platform with non-forgeable provenance.
- **in-toto** attestations (layout/link, and the attestation framework used by SLSA provenance). **TUF** handles update-metadata roles, thresholds, expiry, freeze/rollback/mix-and-match protection. **Uptane** is TUF for automotive [B-CR-45].
- **Sigstore/cosign** signs containers and artifacts with keyless OIDC or keys. Example: Dangerzone's "independent container updates" (since v0.10.0) sign the sandbox image with **cosign** against a public key shipped in the app and signed by the PGP release key. Nightly images carry **GitHub-CI provenance attestations** that users can verify [B-CR-44].
- **Minimal-JS / no-JS forms.** SecureDrop's classic source interface works in Tor Browser at "Safest" (no JS): submission is a plain HTML form and encryption happens **server-side on receipt** (OpenPGP to the journalist key). Only the server and transport are then trusted, and there is no client-code risk beyond HTML. The trade-off is that the server sees plaintext momentarily, so this is not E2EE.

### B.3 Risk table — server-delivered code and mitigations (ranked)

Strength: ★★★★★ strongest. Feasibility (2026, for anonymous Tor-using sources): H/M/L.

| # | Risk | Mitigation (ranked by strength) | Strength | Feasibility | Notes |
|---|---|---|---|---|---|
| 1 | **Targeted malicious JS to one source** (coerced or compromised server, Hushmail pattern) | (a) Installed, signed, reproducible native/mobile client with binary transparency (CoverDrop-in-news-app model) | ★★★★★ | M (install is a signal of intent unless bundled in a popular app) | CoverDrop hides inside the Guardian app, with cover traffic from all users |
| | | (b) WEBCAT/WAICT enforcement + transparency log + k-of-n signers | ★★★★ | M→H as Tor Browser integration lands; alpha today | Blocks unlogged code; split views detectable by monitors |
| | | (c) No-JS form, server-side encryption on receipt (SecureDrop classic) | ★★★ | H | Removes client-code risk but trusts server RAM at submission |
| | | (d) Code Verify-style extension | ★★ | L (Tor users should not install extensions) | Fingerprinting risk |
| | | (e) SRI alone | ★ | H | Root HTML not covered |
| 2 | **Global malicious update** (all users) | Transparency log + public monitors + reproducible builds + TUF/WEBCAT thresholds + release delay/“cooling” window | ★★★★ | H | Detectable after the fact; delay allows veto |
| 3 | **Build-system / CI compromise** (SolarWinds-class) | SLSA Build L3 provenance, hermetic builds, ≥2 independent rebuilders verifying bit-for-bit | ★★★★ | M | Dangerzone/Tor Browser practice |
| 4 | **Maintainer key/account compromise** | Threshold signing (k-of-n, HSM/FIDO-bound), SLSA Source L4 two-party review, signed commits, short-lived Sigstore identities | ★★★★ | H | |
| 5 | **Dependency compromise** (npm/crates, xz-style) | Lockfiles + vendoring + `cargo-vet`/manual audit, Scorecard gates, minimal deps, no install scripts, S2C2F practices | ★★★ | H | CoverDrop uses cargo-vet |
| 6 | **CDN/TLS MITM or clearnet interception** | Onion service only for sources; no third-party CDN; HSTS/preload for clearnet landing page | ★★★★ | H | WEBCAT is TLS-independent |
| 7 | **Browser/extension/endpoint compromise of the source** | Out of scope for code integrity; guidance: Tails, Tor Browser "Safest" | ★★ | M | |
| 8 | **Rollback to old vulnerable signed version** | TUF-style expiry + version monotonicity; WEBCAT manifest versioning | ★★★ | H | |
| 9 | **Update-fingerprinting / split-view via distinct manifests** | Transparency logs with witness cosigning (Sigsum), gossip/monitors | ★★★ | M | |

**Recommended posture.**
1. Launch sources on a **no-JS-capable onion form** with server-side hybrid-PQ encryption on receipt. This is the baseline, compatible with Tor Browser "Safest".
2. Offer an **E2EE WASM client only behind WEBCAT enrollment**, and later WAICT, with a k-of-n (e.g., 2-of-3) Sigsum/Sigstore signer threshold and reproducible builds.
3. Ship journalist tools as **signed, reproducible native apps** (or IWAs on managed ChromeOS) with TUF-style updates and Rekor/Sigsum inclusion proofs.
4. Publish a **transparency monitor** and invite third-party monitors.

---

## C. Secure development standards (what applies, 2025-2027)

- **NIST SSDF, SP 800-218 v1.1 (Feb 2022)** is the baseline practice set (PO/PS/PW/RV). **SP 800-218 Rev. 1 (SSDF v1.2) initial public draft, 17 Dec 2025**, was mandated by **EO 14306**. Comments closed 30 Jan 2026. It adds new practice **PO.6** and expanded examples. The final version's status is **UNVERIFIED** [B-CR-47]. **SP 800-218A** (Jul 2024) is the SSDF community profile for generative-AI/dual-use foundation models. Apply it if ML triage of submissions is used.
- **OMB M-22-18 / M-23-16** required federal self-attestation to SSDF via the CISA Common Form. They were **rescinded by OMB M-26-05 on 23 Jan 2026** in favour of agency risk-based approaches. The Common Form and SBOMs remain optional tools [B-CR-48]. This matters only if the platform sells to U.S. agencies. Still, keep an SSDF mapping, because it is the lingua franca.
- **OWASP ASVS 5.0.0** (30 May 2025): 17 chapters, ~350 requirements, L1-L3, requirement IDs like `v5.0.0-3.2.1`, and new chapters on tokens, OAuth and WebRTC. Chapters open with "documented security decisions" [B-CR-49]. **Target ASVS L3 for the source interface and journalist API.**
- **OWASP SAMM v2**: maturity model for program governance. Use it for a yearly self-assessment.
- **OpenSSF Scorecard**: automated repo-hygiene checks (branch protection, pinned deps, token permissions, signed releases, fuzzing, SAST). Gate CI on a minimum score and on no regressions.
- **S2C2F** (Secure Supply Chain Consumption Framework, contributed by Microsoft to OpenSSF): levels 1-4 for *consuming* OSS (ingest via internal mirror, scan, inventory, update, audit, rebuild from source at L4).
- **CISA Secure by Design** (principles 2023; pledge May 2024): memory-safe languages roadmap, MFA by default, eliminate vulnerability classes, publish CVEs with CWE, vulnerability disclosure policy. Implementation choice: **Rust for crypto and parsing components**, and parsers inside sandboxes.
- **SBOM**: CycloneDX 1.6 (Apr 2024; also Ecma-424, with CBOM/cryptography-asset support that is useful for PQC inventory) and SPDX 3.0 (Apr 2024). CycloneDX 1.7's existence and date are **UNVERIFIED**. Produce SBOMs per release, sign them, and log them next to the artifact.
- **EU Cyber Resilience Act (Reg. (EU) 2024/2847)**:
  - **Reporting obligations** (Art. 14: actively exploited vulnerabilities and severe incidents, via the ENISA Single Reporting Platform) **apply from 11 Sep 2026**, i.e., already in force now. Main obligations apply from **11 Dec 2027** [B-CR-50].
  - **Open-source software stewards** have a light-touch regime: a documented cybersecurity policy, vulnerability handling, cooperation with market-surveillance authorities, no CE marking and no administrative fines [B-CR-50][B-CR-51]. A non-profit publishing the platform as FOSS is plausibly a *steward*. An entity that monetises hosted or supported versions is plausibly a *manufacturer*. **Legal review required.**
  - Secondary sources differ on whether stewards' reporting duties start in Sep 2026 or Dec 2027. Treat Sep 2026 as the conservative date.
  - Build the CRA technical file now: SBOM, vulnerability handling process, support period, and secure-by-default configuration.

**Practical mapping.** SSDF (process) + SLSA Build L3/Source L3-L4 (integrity) + ASVS L3 (verification) + Scorecard/S2C2F (dependencies) + CycloneDX SBOM/CBOM (inventory) + CRA/ENISA reporting runbook.

---

## D. File sanitisation and malware containment

### D.1 Threats in submitted files

1. **Exploits against the viewer or parser.** Examples:
   - ExifTool **CVE-2021-22204**: DjVu annotation parsed with Perl `eval`, giving RCE on metadata extraction; fixed in 12.24, and exploited in the wild through GitLab CVE-2021-22205.
   - ImageMagick **"ImageTragick" CVE-2016-3714** (delegate command injection).
   - Ghostscript: **CVE-2023-36664** (pipe/`%pipe%` handling), **CVE-2023-43115** (the reason for a Dangerzone advisory, 2023-12-07), **CVE-2024-29510** (uniprint format string → SAFER bypass).
   - GStreamer gst-plugins-base **CVE-2024-47538/47607/47615** (Dangerzone advisory 2024-12-24) [B-CR-44].
   - LibreOffice macro/link-execution issues: CVE-2023-2255, CVE-2024-3044, CVE-2025-1080. These IDs are from memory, and exact descriptions are **UNVERIFIED** in this session.
2. **Resource exhaustion.** Zip bombs, especially Fifield's non-recursive overlapping-file "better zip bomb" (USENIX WOOT 2019: e.g., 46 MB → 4.5 PB), decompression bombs in PNG/PDF/XML (billion laughs) [B-CR-52].
3. **Polyglots and parser differentials.** A file valid as several formats (PDF+ZIP+HTML, etc.), which defeats extension- or MIME-based routing.
4. **De-anonymisation of the source** through what the file carries:
   - EXIF GPS, device serials, thumbnails.
   - Office `docProps`, rsids, tracked changes, comments, custom XML, embedded fonts/printers, and PDF `/Info`/XMP/incremental updates.
   - **Printer tracking dots (MIC)** in scans.
   - **Content watermarks/canary traps**: per-recipient wording, spacing, kerning, invisible Unicode, image micro-perturbations.
   - Failed redactions (black box drawn over text that is still selectable).

### D.2 Tools — capabilities, limits, status

- **Dangerzone** (FPF) [B-CR-44]:
  - **Pipeline.** Any document is converted to PDF (LibreOffice, etc.), then rasterised to RGB pixels inside the sandbox. A new PDF is rebuilt **outside** the sandbox from pixels only, with optional OCR.
  - **Sandbox.** Podman container + **gVisor** since v0.7.0 (2024-07-08), no network, custom seccomp.
  - **Supply chain and updates.** Reproducible Debian-based images since v0.9.0 (2025-04-08). **Independent, cosign-signed sandbox updates with CI provenance** since v0.10.0 (2025-12-01). v0.11.0 (2026-07-01) brought parallel OCR, "strongly advised" updates, and Linux packages now fetch the image via `dangerzone-image upgrade`.
  - **Audit.** Include Security, Dec 2023: no high-risk findings, 3 low, 7 informational.
  - **Qubes.** Supported with a hardened disposable VM (advisory 2023-10-25: set `default_dispvm ''`).
  - **Limits.** Loses text layers, hyperlinks and vector fidelity, and does **not** remove visible content watermarks or tracking dots. Formats: PDF, Office/ODF, EPUB, common images, HWP (not on Qubes).
- **mat2** [B-CR-53]:
  - **Formats.** Metadata removal for images, audio/video, PDF, Office/ODF, EPUB, archives and more. Adds WebP (0.14.0), AVIF and JPEG XL (0.15.0, 2026-08-04).
  - **Maintenance.** Active: 0.13.5 (2025-01-09), 0.14.0 (2025-10-23), 0.15.0 (2026-08-04).
  - **Sandboxing warning.** **0.14.0 removed bubblewrap sandboxing.** You must run mat2 inside your own disposable VM or gVisor container.
  - **Threat model (explicit).** mat2 does **not** anonymise content, handle watermarking, steganography, homoglyphs, stylometry, non-standard metadata, or filesystem metadata. It cannot defend against an adversary who created the document for the specific user. "No metadata shown ≠ clean".
  - **Behaviour.** The default mode may re-compress media and make PDF text unselectable. `-L` (lightweight) preserves data but removes less.
- **PDF normalisation.** Use qpdf/pikepdf to linearise, drop incremental updates, strip `/Info`/XMP, JavaScript, `/OpenAction`, `/AA`, embedded files and forms. Keep Ghostscript only inside sandboxes and patched (repeated SAFER bypasses). **Verified redaction = rasterise (Dangerzone), or true content removal then text-extraction check**. Never rely on overlays.
- **CDR (content disarm & reconstruction).** Dangerzone is a pixel-level CDR. Commercial structural CDR (rebuild the file from a whitelist of elements) keeps editability but has a larger parser attack surface. For a newsroom, pixel-CDR for viewing plus a sealed original kept for forensics is the safer pairing.
- **Isolation substrates:**
  - **Qubes OS disposables.** The **SecureDrop Workstation** is Qubes-based: `sd-viewer` opens files in networkless disposable VMs, export goes through a dedicated VM, and it is at 1.x.
    - An X41 D-Sec review of SecureDrop Workstation was published 2026-04-21. Its findings were not retrievable, so they are **UNVERIFIED**.
  - **gVisor** (user-space kernel in Go; used by Dangerzone).
  - **Firecracker** microVMs (KVM, minimal device model; AWS Lambda/Fargate). Use them for server-side batch processing such as thumbnailing or OCR, where needed.
- **DEDA** (TU Dresden) extracts, decodes and **anonymises** yellow tracking dots in scanned colour-laser prints. Use lossless 300 dpi scans. Monochrome or inkjet prints may contain none. Reference: Richter et al., IH&MMSec 2018 [B-CR-54]. Rasterising and converting to greyscale/thresholding also destroys most dot patterns, at a fidelity cost.
- **Invisible watermarks and canary traps.** No tool reliably removes content-level fingerprints. Newsroom procedure should:
  - Obtain and compare multiple copies if possible.
  - Retype or paraphrase text for publication.
  - Publish re-rendered excerpts rather than originals.
  - Normalise whitespace and Unicode (strip zero-width, homoglyph-normalise).
  - Downscale or re-encode images, and crop margins.

### D.3 Recommended sanitisation pipeline

1. **Server (intake).**
   - Never parse submissions server-side. Store only ciphertext (age/STREAM to journalist keys).
   - Enforce size limits pre-encryption on the client, and chunk-count limits server-side.
   - Pad sizes to buckets.
2. **Air-gapped / Qubes journalist workstation.**
   - Decrypt in `sd-svs`-like vault VM.
   - **Never open in the vault**: open only in networkless disposables (Qubes) or gVisor/Firecracker sandboxes.
3. **Triage in the disposable.**
   - Identify the type by magic plus full parse (reject polyglots or flag them).
   - Enforce decompression ratio/size/entry-count/nesting limits (Fifield overlap check: reject ZIPs whose local headers overlap).
   - Run AV/YARA if desired, knowing it offers no guarantee.
4. **Viewing copy.** Dangerzone (pixels→PDF, OCR in the sandbox).
5. **Publication/sharing copy.**
   - Dangerzone output → mat2 (in its own sandbox) → qpdf linearise.
   - For images: re-encode, strip EXIF, check for DEDA dots on scans.
   - Manual review for redaction, watermarks and stylometry.
6. **Retain the sealed original** (encrypted, access-logged) for authentication work. Destroy it via crypto-erase at the retention deadline.
7. **Patch cadence.** Subscribe to Dangerzone independent container updates, the Ghostscript/LibreOffice/ImageMagick/ExifTool advisories, and Qubes Security Bulletins. Keep the tool versions in the SBOM.

---

## Bibliography

| ID | Title | URL | Date | Relevance |
|---|---|---|---|---|
| B-CR-01 | FIPS 203 / 204 / 205 (ML-KEM, ML-DSA, SLH-DSA) | https://csrc.nist.gov/pubs/fips/203/final (and /204, /205) | 2024-08-13 | PQ primitives |
| B-CR-02 | NIST SP 800-227 Recommendations for KEMs (final) | https://csrc.nist.gov/pubs/sp/800/227/final ; news: https://csrc.nist.gov/News/2025/nist-publishes-sp-800-227 | 2025-09-18 | KEM usage & hybrid guidance (body not fetched) |
| B-CR-03 | NIST IR 8547 ipd Transition to PQC Standards (+ secondary summary) | https://csrc.nist.gov/pubs/ir/8547/ipd ; https://detectors.xygeni.io/xydocs/compliance/nist_pqc_transition.html | 2024-11-12 (draft) | 2030/2035 deprecation dates |
| B-CR-04 | OMB M-26-15 Execution of the Migration to PQC | https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf | 2026-06-24 | Federal PQC timeline (secondary summaries read) |
| B-CR-05 | draft-connolly-cfrg-xwing-kem-11 (X-Wing) + repo | https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.html ; https://github.com/dconnolly/draft-connolly-cfrg-xwing-kem | 2026-09 | Hybrid KEM |
| B-CR-06 | draft-ietf-hpke-pq-05 PQ & PQ/T hybrid HPKE (WG repo read) | https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/ ; https://github.com/hpkewg/hpke-pq | 2026-07-06 | HPKE codepoints 0x0040-42, 0x0050/51, 0x647a |
| B-CR-07 | RFC 9180 Hybrid Public Key Encryption | https://www.rfc-editor.org/rfc/rfc9180 | 2022-02 | Core PKE |
| B-CR-08 | RFC 10024 PQ/T hybrid key agreement for TLS 1.3 (X25519MLKEM768) | https://rfc-editor.org/info/rfc10024/ | 2026 (UNVERIFIED number/date) | Transport PQ |
| B-CR-10 | NSA CNSA 2.0 (summaries) | https://www.encryptionconsulting.com/education-center/what-is-cnsa-2-0/ ; https://postquantum.com/security-pqc/nsa-cnsa-2-0-faq-v2-1-update/ | 2022-09, updates | High-assurance profile/timeline |
| B-CR-11 | AWS-LC FIPS 3.0: first library with ML-KEM in FIPS 140-3 validation; sec-certs #5314 | https://aws.amazon.com/blogs/security/aws-lc-fips-3-0-first-cryptographic-library-to-include-ml-kem-in-fips-140-3-validation ; https://sec-certs.org/fips/1e0b605fa2f516ae/ | 2025 / cert 2026-06-05 | FIPS-mode PQ |
| B-CR-12 | OpenSSL FIPS provider 3.1.2 (#4985); OpenSSL 3.5.4 FIPS submission | https://openssl-library.org/news/fips-cve/index.html ; https://mirror.openssl-library.org/post/2025-10-09-ossl3.5.4-fips-submission/ | 2025-10-09 | FIPS modules |
| B-CR-13 | Go FIPS 140-3 Compliance (Go Cryptographic Module, CMVP #5247) | https://go.dev/doc/security/fips140 | 2025-2026 | FIPS module in Go |
| B-CR-14 | age format spec (C2SP) and age releases v1.3.0/v1.3.2 | https://github.com/C2SP/C2SP/blob/main/age.md ; https://github.com/FiloSottile/age/releases | 2025-12-27 / 2026-08-29 | File encryption, STREAM, PQ recipients |
| B-CR-15 | libsodium docs: secretstream (XChaCha20-Poly1305) | https://libsodium.gitbook.io/doc/secret-key_cryptography/secretstream (read via github.com/jedisct1/libsodium-doc) | 2026 | Streaming AEAD |
| B-CR-16 | Grubbs et al., Hunting Invisible Salamanders (Black Hat USA 2020); Dodis et al., Fast Message Franking (CRYPTO 2018) | https://i.blackhat.com/USA-20/Thursday/us-20-Grubbs-Hunting-Invisible-Salamanders-Cryptographic-Insecurity-With-Attacker-Controlled-Keys.pdf | 2018/2020 | Key commitment |
| B-CR-17 | Albertini, Duong, Gueron, Kölbl, Luykx, Schmieg, How to Abuse and Fix Authenticated Encryption Without Key Commitment (USENIX Security 2022) | https://www.usenix.org/conference/usenixsecurity22/presentation/albertini (URL UNVERIFIED) | 2022 | Committing AEAD fixes |
| B-CR-19 | RFC 9106 Argon2 | https://www.rfc-editor.org/rfc/rfc9106 | 2021-09 | Password hashing params |
| B-CR-20 | OWASP Password Storage Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html | living | Argon2id/PBKDF2 minimums |
| B-CR-21 | RFC 9807 OPAQUE aPAKE | https://www.rfc-editor.org/rfc/rfc9807.html | 2025-07 | Staff password auth |
| B-CR-22 | RFC 9420 Messaging Layer Security | https://www.rfc-editor.org/rfc/rfc9420 | 2023-07 | Group E2EE |
| B-CR-23 | Signal: Signal Protocol and Post-Quantum Ratchets (SPQR) | https://signal.org/blog/spqr/ | 2025-10 | PQ FS/PCS |
| B-CR-24 | SecureDrop Protocol spec v0.4 & README (repo read) | https://github.com/freedomofpress/securedrop-protocol (docs/protocol.md) | 2026-09-28 commit | Whistleblowing E2EE design |
| B-CR-25 | Berra, Linker, Maier, Myers, Paterson, Shane, Veitch: The SecureDrop Protocol: E2EE Whistleblowing for All (ACM CCS 2026) ; FPF IETF 124 post | https://eprint.iacr.org/2026/1484 ; https://freedom.press/tech/news/security-analysis-of-securedrop-protocol-presented-at-ietf-124/ | 2026-07 / 2025-11 | Formal analysis (Tamarin + game-based) |
| B-CR-26 | CoverDrop tech report UCAM-CL-TR-999; Cambridge/Guardian launch news | https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-999.html ; https://www.cam.ac.uk/research/news/whistleblowing-tech-based-on-cambridge-research-launched-by-the-guardian | 2025 | Cover-traffic design |
| B-CR-27 | CoverDrop repo docs (cryptography.md, client_passphrase_configurations.md, supply-chain/) | https://github.com/guardian/coverdrop | 2026-09-25 commit | Primitives, Argon2 params, cargo-vet |
| B-CR-29 | RFC 9591 FROST threshold Schnorr signatures | https://www.rfc-editor.org/rfc/rfc9591 | 2024-06 | Threshold signing |
| B-CR-30 | OASIS PKCS#11 v3.x | https://docs.oasis-open.org/pkcs11/ (UNVERIFIED path) | 2020-2024 | HSM interface |
| B-CR-33 | NIST SP 800-88 Rev. 2 Guidelines for Media Sanitization | https://csrc.nist.gov/pubs/sp/800/88/r2/final | 2025-09-26 | Cryptographic erase |
| B-CR-35 | Hushmail court orders (The Register; Schneier) | https://www.theregister.com/2007/11/08/hushmail_court_orders/ ; https://www.schneier.com/blog/archives/2007/11/hushmail.html | 2007-11 | Server-delivered code lesson |
| B-CR-36 | Meta Code Verify; Cloudflare verifies WhatsApp Web code | https://engineering.fb.com/2022/03/10/security/code-verify/ ; https://blog.cloudflare.com/cloudflare-verifies-code-whatsapp-web-serves-users/ | 2022-03 | Web code verification |
| B-CR-37 | WEBCAT repo (README, v3.0.0 tag) | https://github.com/freedomofpress/webcat | 2026-09-29 | Web integrity for onions |
| B-CR-38 | FPF/SecureDrop WEBCAT posts (Introducing; Alpha; Tamper-evident seal; Update incl. independent evaluation & WAICT) | https://securedrop.org/news/webcat-alpha/ ; https://freedom.press/tech/news/webcat-a-tamper-evident-seal-for-the-open-web/ ; https://securedrop.org/news/webcat-update-independent-evaluation-waict-and-a-growing-team/ | 2025-2026 | Status (bodies not fetched) |
| B-CR-39 | WAICT: Cloudflare "Improving the trustworthiness of JavaScript on the Web"; Mozilla Hacks "Trustworthy JavaScript for the Open Web"; waict.dev | https://blog.cloudflare.com/improving-the-trustworthiness-of-javascript-on-the-web/ ; https://hacks.mozilla.org/2026/05/trustworthy-javascript-for-the-open-web/ ; https://waict.dev/ | 2025-10 / 2026-05 | Browser-native transparency |
| B-CR-40 | WEBCAT spec (server.md threshold/signers; manifest.md; csp.md) | https://github.com/freedomofpress/webcat-spec | 2026 | k-of-n signing |
| B-CR-41 | Chrome Isolated Web Apps docs; Intent to Ship | https://developer.chrome.com/docs/iwa/introduction ; https://groups.google.com/a/chromium.org/g/blink-dev/c/iMfYonTs414/m/tgT7z51CBAAJ | 2024-2026 | Signed web bundles |
| B-CR-42 | Sigstore rekor-tiles (Rekor v2) | https://github.com/sigstore/rekor-tiles | 2025-10+ | Binary transparency |
| B-CR-43 | Reproducible Builds project; Tor Browser rbm | https://reproducible-builds.org/ ; https://gitlab.torproject.org/tpo/applications/tor-browser-build (UNVERIFIED path) | living | Reproducibility |
| B-CR-44 | Dangerzone repo: README (audit), advisories 2023-10-25/2023-12-07/2024-12-24, independent-container-updates.md, reproducibility.md; tags v0.7.0-v0.11.0 | https://github.com/freedomofpress/dangerzone | 2024-07 → 2026-07-01 | CDR, sandboxing, signed updates |
| B-CR-45 | The Update Framework spec; in-toto; Uptane | https://theupdateframework.github.io/specification/latest/ ; https://in-toto.io/ ; https://uptane.org/ | living | Update security |
| B-CR-46 | SLSA v1.1 (Apr 2025) and v1.2 announcement (Source Track) | https://slsa.dev/blog/2025/04/slsa-v1.1 ; https://slsa.dev/blog/2025/11/announce-slsa-v1.2 | 2025-04 / 2025-11 | Build/Source levels |
| B-CR-47 | NIST SP 800-218r1 ipd (SSDF v1.2); SP 800-218 v1.1; SP 800-218A | https://csrc.nist.gov/pubs/sp/800/218/r1/ipd ; https://csrc.nist.gov/News/2025/draft-ssdf-version-1-2 | 2025-12-17 | Secure dev framework |
| B-CR-48 | OMB M-26-05 rescinds M-22-18/M-23-16 (Mayer Brown; DWT; Inside Gov Contracts) | https://www.insidegovernmentcontracts.com/2026/02/omb-rescinds-the-common-form-secure-software-attestation-requirement/ ; https://www.dwt.com/blogs/privacy--security-law-blog/2026/02/omb-changes-course-on-software-security | 2026-01-23 | Attestation status |
| B-CR-49 | OWASP ASVS project (5.0.0) | https://owasp.org/www-project-application-security-verification-standard/ | 2025-05-30 | Verification standard |
| B-CR-50 | CRA guidance: Linux Foundation/OpenSSF CRA Stewards one-pager & playbook; Goodwin alert | https://policy.openssf.org/CRA/stewards-one-pager.html ; https://www.goodwinlaw.com/en/insights/publications/2026/09/alerts-lifesciences-technology-preparing-for-eu-cyber-resilience-act | 2026 | CRA dates/steward duties |
| B-CR-51 | ENISA CRA Single Reporting Platform terms v1.0 | https://www.enisa.europa.eu/sites/default/files/2026-09/Terms%20and%20conditions%20CRA%20SRP%20v1.0%2020260910.pdf | 2026-09-10 | CRA reporting |
| B-CR-52 | Fifield, A better zip bomb (USENIX WOOT 2019) | https://www.bamsoftware.com/hacks/zipbomb/ (UNVERIFIED fetch) | 2019 | Decompression limits |
| B-CR-53 | mat2 repo (CHANGELOG, README, doc/threat_model.md) | https://github.com/jvoisin/mat2 | 0.15.0, 2026-08-04 | Metadata removal limits |
| B-CR-54 | DEDA repo; Richter et al., Forensic Analysis and Anonymisation of Printed Documents (IH&MMSec 2018, doi:10.1145/3206004.3206019) | https://github.com/dfd-tud/deda | 2018 | Printer dots |
| B-CR-55 | X41 D-Sec Review of SecureDrop Workstation 2026 | https://x41-dsec.de/security/research/job/news/2026/04/21/securedrop-review-2026/ | 2026-04-21 | Workstation audit (content UNVERIFIED) |
| B-CR-56 | CVE records: CVE-2021-22204 (ExifTool), CVE-2016-3714 (ImageMagick), CVE-2023-36664, CVE-2023-43115, CVE-2024-29510 (Ghostscript), CVE-2024-47538/47607/47615 (GStreamer) | https://www.cve.org/ (per-ID) | various | Parser exploit history |

*(IDs B-CR-09, -18, -28, -31, -32, -34 intentionally unused.)*
