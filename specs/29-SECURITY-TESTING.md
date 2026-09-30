# 29 — Security Verification Specification (Security Testing)
Status: Draft v1.2 (final consistency pass: ADR-047) · previously v1.1 (revision round 2: ADR-034..046, REVIEW-A/B/C) · Edition applicability: both (EE-only components tested in the EE matrix rows) · Owner: Security Engineering — Verification

## 1. Purpose and scope

This document is the **Security Verification Specification** for Candor. It defines:

- the test environments and rules for test data (§3);
- the **CI gating matrix**: which tests run when, and which block merges or releases (§4);
- the catalogue of security tests **ST-001…ST-178** in tables (ID, name, what it proves, method, frequency, gating) (§5–§13), covering: unit and integration tests; cryptographic tests (KAT, property-based, Wycheproof, constant-time, formal-model regression); fuzzing (parsers, envelope, API; list of cargo-fuzz targets); API authorization, IDOR and cross-tenant tests; CSRF, XSS and injection; path traversal, archive and upload attacks; SSRF; authentication/session attacks; rate limits and DoS; DB corruption, power loss, network interruption, storage failure, clock problems and upgrade failure; backup restore; the **malicious-server harness** for clients (ADR-027); config-checker tests; secret-placement tests (ADR-028); supply-chain tests; the pre-release pentest; tests for every revision control of ADR-034..ADR-046 (§14A: RAM-only drafts, passphrase non-persistence, triage-first routing, blinded COI, directory governance, platform manifest and security floor, operator statement, external watchers, Erasure Key Vault restore, backup-exclusion checker, Desk hostile-string rendering, platform-tier viewer enforcement, fetch-all reply retrieval); and the **spec-constant consistency lint** (ST-167);
- requirements on the testing programme itself (**SECT-** IDs, §15).

Anonymity-specific tests (canaries across all log sinks, compromise drills, timing/size/fingerprinting, usability-security studies) are in `30-ANONYMITY-TESTING.md` (AT-). External audits are in `37-SECURITY-AUDIT-PLAN.md`.

Honest language: passing this suite shows the absence of the *tested* failure modes under the *tested* conditions. It does not show the absence of vulnerabilities.

## 2. Context and dependencies

| Document | Relationship |
|---|---|
| `DECISIONS.md` | ADR-009 (intake/core separation), ADR-010/011 (timing/size), ADR-012 (no server parsing; viewer containment), ADR-021 (multi-tenancy/RLS), ADR-022 (TUF), ADR-026 (abuse resistance), ADR-027 (safe-path + malicious-server harness), ADR-028 (secret placement manifests), ADR-029 (audience-bound tokens, deny-by-default routes), ADR-030/033 (member epoch keys, anonymous slots, retirement gated on import, Erasure Key Vault), **ADR-034..ADR-046** (revision controls; binding, supersede earlier text) |
| `39-REQUIREMENTS-TRACEABILITY.md` | Owns the machine-readable constants registry consumed by ST-167 (cross-document request, see `process/DISP-G8.md`) |
| `24-LICENSING-BUSINESS-MODEL.md` §TEL | Canonical metrics regime (ADR-046(5)); referenced, not restated |
| `11-FRONTEND-SOURCE.md` | Canonical page size classes and session cookie (ST-066, ST-074) |
| `27-SECURE-DEVELOPMENT.md` | Coding rules enforced by lints ST-004..ST-015; release gates SG-01..SG-24 reference these IDs |
| `28-SUPPLY-CHAIN.md` | Pipeline placement of SAST/DAST/fuzzing/secret scanning; supply-chain tests ST-130..ST-135 |
| `30-ANONYMITY-TESTING.md` | AT- tests; shares the lab (§3) |
| `04-CRYPTOGRAPHY.md` | Suites and vectors under test |
| `08-API.md`, `15-AUTHENTICATION-AUTHORIZATION.md` | Route registry, roles, policy model under test |
| `10-FILE-EVIDENCE-PIPELINE.md` | Viewer containment and sanitizer behaviour under test |
| `19-BACKUPS-DR.md`, `34-PERFORMANCE-SCALABILITY.md` | Restore and failure-behaviour (FAIL-) expectations |
| `32-OPERATIONS.md` | CFG classification checked by the config checker |
| `33-RELEASE-UPDATE-SECURITY.md` | Update client behaviour under test |
| `37-SECURITY-AUDIT-PLAN.md` | Pentest scope and findings flow |

Research basis: R1 (malicious-server lessons CVE-2025-24888, CVE-2026-35465, CVE-2026-49996, CVE-2025-24889, TOB-SDW-012/016, CVE-2026-54706/54707, CVE-2026-50000, GHSA-rqwh) [B-SD-20, B-SD-22, B-SD-28, B-SD-33..B-SD-36, B-OS-01..B-OS-04]; R2 (GlobaLeaks CVE-2026-45020/46647/46648, GHSA-9vhh, Twisted CVE-2024-41671; Hush Line CVE-2024-38521/55888/38523) [B-GL-37, B-GL-39, B-GL-40]; R5 (Wycheproof-style vectors, key commitment, zip bombs, parser CVEs) [B-CR-07, B-CR-14, B-CR-16, B-CR-17, B-CR-44, B-CR-52, B-CR-56]; R3 REQ-H-51/58/60 [B-INC-80, B-INC-90, B-INC-93].

## 3. Test environments and data rules

| Env | Name | Composition | Used for |
|---|---|---|---|
| E1 | unit | `cargo test`, `vitest` for Desk UI; Miri; no network | ST-001, ST-020..ST-029, lints |
| E2 | **candor-lab** | One VM per zone per ADR-009/024 (C-05/06/07/08 intake host(s), C-09..C-14/C-21..C-24 core host(s), C-25 monitor, C-27 backup, C-15 Desk client VMs Linux/Windows/macOS, C-17 viewer microVM), a **private Tor network via chutney** (deterministic, instrumented), lab CA, lab TUF repo, mailpit SMTP sink, lab SIEM (C-26 target) | ST-002/003, ST-060..ST-124; shared with 30 (AT-) |
| E3 | **hostile-lab** | Isolated network; malicious-server harness `candor-hostile` (§11); weaponized document corpus; malicious package registry fixture; rogue TUF repo | ST-080..ST-097, ST-130..ST-135 |
| E4 | staging-live-tor | E2 topology reachable as a real onion service on the public Tor network (non-production keys) | Smoke of NET/PoW behaviour, ST-100 subset |
| E5 | profile-matrix | Automated deployment of all 8 profiles (ADR-024) × feature-flag combinations (pairwise + all DANGEROUS flags individually) | ST-120, ST-121, ST-122, ST-123, ST-124 |

Data rules:
- No real submissions, real source passphrases, real staff credentials or production backups are ever used in any environment (SECT-003).
- Synthetic corpora are generated by `candor-synth` with deterministic seeds.
- Lab keys are marked `TEST-ONLY` in their key IDs, and production builds refuse them (ST-028).

## 4. CI gating matrix

Legend: **B** = runs and blocks on failure; **R** = runs, reports, creates a ticket (non-blocking at that stage); — = not run. "RC" = release candidate pipeline, which must be green for signing (27 §13).

| Test group | IDs | PR | Merge queue | Nightly (main) | Weekly | RC / Release | Quarterly / per major |
|---|---|---|---|---|---|---|---|
| Unit + lints + SAST | ST-001, ST-004..ST-011, ST-013, ST-014 | B | B | B | — | B | — |
| Audit regression mapping | ST-012 | B (if touching `security/findings/`) | B | — | — | B | — |
| Mutation testing (authz, crypto wrappers) | ST-015 | — | — | R | B (score threshold) | B | — |
| Integration / E2E | ST-002, ST-003 | B (fast subset ≤15 min) | B (full) | B | — | B | — |
| Crypto KAT / Wycheproof / property | ST-020..ST-025, ST-028, ST-029, ST-031..ST-034 | B | B | B | — | B | — |
| Constant-time statistical | ST-026 | — | — | R | B | B | — |
| Zeroization | ST-027 | B (if T0 touched) | B | B | — | B | — |
| Formal models | ST-030 | B (if model/protocol files touched) | B | — | B | B | — |
| Fuzzing smoke | ST-040..ST-054 | B (5 min per changed target) | — | — | — | — | — |
| Fuzzing long-run | ST-040..ST-054, ST-056 | — | — | R (4 h/target) | R (24 h/target) | B (SG-07 CPU-hours) | — |
| API stateful fuzzing | ST-055 | — | — | R | B | B | — |
| AuthZ / tenancy / session / web | ST-060..ST-079 | B (affected routes) | B (all) | B | — | B | — |
| File / archive / upload | ST-080..ST-087 | B (if touching C-06/C-15/C-17/safefs) | B | B | — | B | — |
| Malicious-server harness | ST-090..ST-097 | B (fast profile) | B | B (full field coverage) | — | B | — |
| DoS / rate limits | ST-079, ST-100, ST-101 | — | — | R | B | B | — |
| Resilience (DB, power, net, storage, clock, OOM) | ST-102..ST-106, ST-109..ST-111 | — | — | R | B | B | — |
| Upgrade / rollback | ST-107 | — | — | R | B | B | — |
| Backup / restore | ST-108 | — | — | — | B | B | B (full drill) |
| Core dumps | ST-110 | B (if touching service units) | B | B | — | B | — |
| Config checker / secret placement / network zoning | ST-120..ST-124 | B (if touching config/installer) | B | B (E5 pairwise) | B (E5 full) | B | — |
| Update client / repro / CI lint / packages | ST-130..ST-135 | B (ST-133..ST-135) | B | B (ST-130) | — | B (ST-131, ST-132) | — |
| Pentest / red team / LLM sweep | ST-140..ST-142 | — | — | — | — | B (major; conditional minor) | B |
| Tier W draft/passphrase/seal ordering (ADR-034) | ST-143..ST-145 | B (if C-06/C-07 touched) | B | B | — | B | — |
| Routing, COI, directory governance (ADR-036/037) | ST-146..ST-152 | B (affected crates) | B | B | B (clock-manipulation variants) | B | — |
| Platform/integrity evidence (ADR-035/040) | ST-153..ST-157 | B (ST-153 if packaging touched) | B | B | B (ST-155 watcher soak) | B | — |
| Erasure vault / backup exclusion (ADR-044) | ST-158, ST-159 | — | — | R | B | B | B (manual drill with ST-108) |
| Desk rendering / viewer tiers / custody (ADR-042/043) | ST-160..ST-162 | B (Desk UI/viewer touched; 5-min fuzz smoke) | B | B (4 h fuzz) | B (24 h fuzz) | B | — |
| Continuity, org-as-adversary, envelope rejection, fetch-all (ADR-038/039/044/045) | ST-163..ST-166 | B (affected) | B | B | — | B | — |
| Spec-constant consistency lint | ST-167 | B (any change under `specs/`, config schema, `candor-limits`, test fixtures) | B | B | — | B | — |
| ADR-047 controls (chaff, freshness, vault, metadata erasure, deletion list, Desk re-wrap, audit key, wordlists, IDENTIFIED over onion) | ST-168..ST-178 | B (affected crates; ST-171 if C-03 touched; ST-177 if a wordlist changes) | B | B | B (ST-168 rate soak; ST-174/ST-175 DR lab) | B | B (ST-174/ST-175 in the RT-1/RT-5 drills of 19) |

Any **B** failure on `main` nightly opens a P1 ticket and marks `main` "not releasable" until green.

## 5. Unit, integration, static and policy tests (ST-001..ST-015)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-001 | Unit test suite | Functional correctness of all crates incl. negative and hostile-input paths; line coverage ≥ 85% for T0, ≥ 75% for T1 crates, no decrease > 1 pp per PR | `cargo test --workspace --locked`, `cargo llvm-cov`; `vitest` for Desk UI | PR, nightly | Yes (PR) |
| ST-002 | Integration suite (candor-lab) | Components interoperate across zones per ADR-009 (core pulls, intake never initiates) | Docker/VM stack; scenario tests over chutney Tor | PR subset, merge, nightly | Yes |
| ST-003 | E2E source→case→reply flows | Tier W and Tier V submissions import into cases, replies reach source on next login, deletions propagate | Headless Tor Browser (tbselenium) at Safest; Source App driver; Desk driver | Merge, nightly, RC | Yes |
| ST-004 | Architecture policy lints | Every route declares audience + authz (ADR-029); every path classified T0/T1/T2; T0/T1 PRs link a threat model | `candor-policy-lint` over route registry, `classification.toml`, PR metadata | PR | Yes |
| ST-005 | safefs lint | No filesystem sink with external data outside `candor-safefs`; no `Path::join` on external input; no `unpack`/`extract` archive APIs (ADR-027) | Semgrep taint rules + clippy `disallowed_methods` | PR | Yes |
| ST-006 | Typed-logging lint | No free-text logging in T0/T1; error types carry no input values (ADR-016) | clippy `disallowed_macros`, Semgrep | PR | Yes |
| ST-007 | Rust safety lints | `forbid(unsafe_code)` except allowlist; SAFETY comments; panic lint set; release profile (`overflow-checks`, sealer `panic=abort`); geiger delta; Miri on allowlisted crates | clippy deny set (27 §12.2), `cargo geiger`, `cargo miri test` | PR | Yes |
| ST-008 | SAST | No High/Critical SAST findings; Candor rule packs: `anon-time` (no `SystemTime::now` / UUIDv7 in source-linked code), `http-client` (redirects off), `templates` (no raw filters), `secret-traits`, `sql` (no dynamic SQL) | Semgrep, CodeQL (Rust, TS) → SARIF | PR, nightly | Yes (High/Crit) |
| ST-009 | Secret scanning | No verified secrets in diffs, history, build logs, artefacts, image layers; CI masking works (canary secret never appears unmasked) | gitleaks + trufflehog verified mode; log canary | PR, weekly full history, release | Yes |
| ST-010 | Dependency vulnerability scan | No unfixed High/Critical advisory in shipped SBOM without reviewed VEX | cargo-audit, osv-scanner on CycloneDX SBOM | PR, daily on released SBOMs | Yes (release) |
| ST-011 | License & bans policy | cargo-deny advisories/bans/sources/licenses pass; npm license allow-list | cargo-deny, license-checker | PR | Yes |
| ST-012 | Audit-finding regression mapping | Every closed finding (audit, pentest, bounty, internal) maps to ≥1 test or static rule that fails on the vulnerable code (R1 R-AUDIT-1) | `security/findings/*.toml` → test IDs; CI runs each mapped test against a stored vulnerable fixture where feasible | PR (on change), release | Yes |
| ST-013 | RNG lint | Only `candor_core::rng` used in non-test code (INC-50/51) | clippy `disallowed_types/methods`; `cargo tree` ban on RNG crates outside allowlist | PR | Yes |
| ST-014 | Prohibited SDK / egress scan for source clients | No analytics/crash/push/ads SDKs; no network endpoints except onion/Arti in C-03 and none in source web assets (REQ-H-13, REQ-H-57) | Dependency denylist; binary string scan for hostnames; manifest entitlements check (no push) | PR, release | Yes |
| ST-015 | Mutation testing | Authorization engine and crypto wrapper tests detect injected faults (mutation score ≥ 90% for C-22 policy crate, ≥ 85% for `candor-core` API layer) | `cargo-mutants` | Weekly, RC | Yes (weekly/RC) |

## 6. Cryptographic tests (ST-020..ST-034)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-020 | HPKE & X-Wing KATs | HPKE implementation matches RFC 9180 App. A vectors for used modes; X-Wing matches draft test vectors; hpke-pq codepoint 0x647a behaviour matches WG vectors | Vector files pinned by hash in `tests/vectors/`; CI job `crypto-kat` | PR, release | Yes |
| ST-021 | PQ & signature KATs | ML-KEM-768/1024 (FIPS 203), ML-DSA-65 (FIPS 204), Ed25519 (RFC 8032), P-384 ECDH (FIPS profile) match official/ACVP-format vectors | Same harness | PR, release | Yes |
| ST-022 | Symmetric & KDF KATs | XChaCha20-Poly1305, ChaCha20-Poly1305 (RFC 8439), AES-256-GCM, HKDF (RFC 5869), Argon2id (RFC 9106), SHA-256/BLAKE3, age STREAM (C2SP age spec vectors) | Same harness | PR, release | Yes |
| ST-023 | Wycheproof vectors | Edge-case rejection: invalid tags, truncated nonces, low-order X25519 points, non-canonical Ed25519 encodings, malleable signatures, invalid P-384 points, ML-KEM/ML-DSA vectors where published | Project Wycheproof JSON (pinned commit) over `candor-core` API | PR, release | Yes |
| ST-024 | Property-based envelope/STREAM tests | seal→open round-trip for random sizes (0..16 MiB, chunk boundaries ±1); any single-bit flip, truncation, chunk reorder, duplication, final-flag removal, or header change ⇒ authentication failure; no plaintext released before full-chunk authentication (REQ-H-65) | `proptest` with ≥10,000 cases per property (nightly 1,000,000) | PR, nightly | Yes |
| ST-025 | Key commitment & context binding | An "invisible salamander" ciphertext constructed to open under two keys is rejected by header commitment; swapping the recipient list inside the AEAD-protected payload (ADR-033(1); never in cleartext), `info` labels, submission IDs or AAD fields ⇒ failure; cross-suite confusion (STD vs FIPS) rejected | Constructed multi-key ciphertexts per Albertini et al.; mutation of context fields | PR, release | Yes |
| ST-026 | Constant-time statistical tests | No detectable timing difference (Welch t-test, absolute t < 4.5 after 10^7 measurements) for MAC/tag comparison, token comparison, source-auth verifier, X25519/ML-KEM decapsulation failure paths | dudect-style harness on pinned hardware runner; valgrind-based secret-taint checker (ctgrind approach) on T0 functions | Weekly, RC | Yes (RC) |
| ST-027 | Zeroization | After drop of secret types and after C-07 seal completion, no copy of the test secret remains in process memory | Test build with sentinel secrets; `/proc/self/mem` scan after drop; heap scan in C-07 test harness | PR (T0), nightly, RC | Yes |
| ST-028 | Startup self-test & weak-key checks | Startup KATs run; deterministic/stuck RNG injection ⇒ fail closed; generated keys checked against weak-key lists (Debian weak keys, ROCA fingerprint for any RSA accepted); `TEST-ONLY` keys rejected by production builds | Fault-injection build flag `rng-fault`; seeded test keys | PR, release | Yes |
| ST-029 | Differential/interop tests | `candor-core` STREAM/age-format files decrypt with reference age implementation and vice versa (for age-compatible modes); HPKE interop with a second independent implementation | Cross-implementation test vectors generated nightly | Nightly, RC | Yes (RC) |
| ST-030 | Formal model regression | Tamarin/ProVerif models of submission, reply, key directory and epoch rotation still prove secrecy, authentication and forward-secrecy lemmas after changes (ADR-006, REQ-H-63) | Model files in repo; CI runs provers with timeouts; lemma list must be unchanged or extended | PR (if touched), weekly, RC | Yes |
| ST-031 | FIPS profile enforcement | CANDOR-FIPS-1 build uses only the validated AWS-LC module for all primitives; any STD-only algorithm call in FIPS build ⇒ compile or runtime error | Build-time feature check; runtime algorithm-provider assertion | PR, release | Yes |
| ST-032 | Padding conformance | Message ciphertexts are exactly on 4 KiB buckets (max 64 KiB); attachment totals follow the ratio-1.25 geometric buckets (min 256 KiB) (ADR-011) | Property tests over sizes 0..2 GiB (sampled) | PR, release | Yes |
| ST-033 | Key directory / transparency verification | Client-side verification rejects: missing inclusion proof, inconsistent consistency proof, signature by unknown key, rollback of tree size, split view between two clients (C-14) | Rogue log server fixture; two-client split-view scenario | PR, release | Yes |
| ST-034 | Epoch key lifecycle | Member Epoch Keys rotate at 7 days, decrypt window 14 days, pre-published 4 epochs ahead (ADR-030); a private epoch key is destroyed only after BOTH its window has passed AND every envelope under that epoch is imported or dual-approval-rejected (ADR-033(2)); envelopes to destroyed epochs become undecryptable (ADR-008); undecryptable envelopes follow ST-165 | Lab clock acceleration; key-store inspection; decrypt attempt after destruction | Nightly, RC | Yes |

## 7. Fuzzing (ST-040..ST-056)

Each cargo-fuzz target runs with libFuzzer + ASan (and UBSan for `unsafe`/FFI crates), `-rss_limit_mb=2048`, `-timeout=10`, and dictionaries and seed corpora committed under `fuzz/corpus/<target>/`. Crashes are minimized, stored as regression inputs and replayed in ST-001 forever (SECT-011). A panic counts as a failure (27 SDL-022). Coverage per target is tracked; SG-07 blocks on a coverage drop of more than 2 pp.

| ID | Name (cargo-fuzz target, component) | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-040 | `fuzz_envelope_parse` (C-11) | Envelope header/framing parser never panics, never over-allocates; parse(serialize(x)) == x for valid inputs | libFuzzer+ASan; structure-aware (arbitrary) | PR smoke 5 min (changed targets); nightly 4 h; weekly 24 h; release per SG-07 | Yes (PR smoke, release) |
| ST-041 | `fuzz_stream_decrypt` (C-11) | Any malformed STREAM chunk sequence/nonce/final-flag yields auth failure with zero plaintext output | libFuzzer+ASan; plaintext-release oracle | PR smoke 5 min (changed targets); nightly 4 h; weekly 24 h; release per SG-07 | Yes (PR smoke, release) |
| ST-042 | `fuzz_hpke_open` (C-11) | Malformed encapsulations, wrong-length keys, unknown suite IDs are rejected; results agree with a second implementation | Differential fuzzing | PR smoke 5 min (changed targets); nightly 4 h; weekly 24 h; release per SG-07 | Yes (PR smoke, release) |
| ST-043 | `fuzz_multipart_intake` (C-06/C-07) | Hostile multipart bodies (boundaries, nesting, huge headers) cause no writes before policy and no panic | libFuzzer + fanotify oracle in harness | PR smoke 5 min (changed targets); nightly 4 h; weekly 24 h; release per SG-07 | Yes (PR smoke, release) |
| ST-044 | `fuzz_http_request` (C-06, C-10) | Raw HTTP/1.1 edge cases (CL/TE conflicts, pipelining) never mis-map responses to requests (CVE-2024-41671 class) | Request-sequence fuzzing with response-ID oracle | PR smoke 5 min (changed targets); nightly 4 h; weekly 24 h; release per SG-07 | Yes (PR smoke, release) |
| ST-045 | `fuzz_api_json` (C-10, C-21) | desk-api/admin-api DTO deserialization rejects unknown fields and never panics | libFuzzer JSON dictionary | PR smoke 5 min (changed targets); nightly 4 h; weekly 24 h; release per SG-07 | Yes (PR smoke, release) |
| ST-046 | `fuzz_key_directory` (C-14, C-15, C-03) | Verifier never accepts invalid log entries, tree heads or proofs | Differential vs reference verifier | PR smoke 5 min (changed targets); nightly 4 h; weekly 24 h; release per SG-07 | Yes (PR smoke, release) |
| ST-047 | `fuzz_tuf_metadata` (update client, 33) | No acceptance of under-threshold, expired or malformed metadata/delegations | libFuzzer + acceptance oracle | PR smoke 5 min (changed targets); nightly 4 h; weekly 24 h; release per SG-07 | Yes (PR smoke, release) |
| ST-048 | `fuzz_safefs_names` (`candor-safefs`) | Arbitrary byte names, Unicode forms and reserved names never resolve outside the root | `openat2` containment oracle | PR smoke 5 min (changed targets); nightly 4 h; weekly 24 h; release per SG-07 | Yes (PR smoke, release) |
| ST-049 | `fuzz_archive` (C-15 export, C-17 bridge) | tar/zip/gzip headers (absolute, `..`, symlink/hardlink/device members, FNAME) never escape containment; ratio/entry limits hold | libFuzzer + containment oracle | PR smoke 5 min (changed targets); nightly 4 h; weekly 24 h; release per SG-07 | Yes (PR smoke, release) |
| ST-050 | `fuzz_config` (config loader/checker, 32) | Invalid config never loads partially; checker verdict deterministic | libFuzzer TOML grammar | PR smoke 5 min (changed targets); nightly 4 h; weekly 24 h; release per SG-07 | Yes (PR smoke, release) |
| ST-051 | `fuzz_audit_log_verify` (C-24) | Tampered hash chains/checkpoints never verify | Mutation of valid chains | PR smoke 5 min (changed targets); nightly 4 h; weekly 24 h; release per SG-07 | Yes (PR smoke, release) |
| ST-052 | `fuzz_relay_batch` (C-09) | Hostile sealed batches from Z-INTAKE cannot write outside import staging or panic | libFuzzer + fanotify oracle | PR smoke 5 min (changed targets); nightly 4 h; weekly 24 h; release per SG-07 | Yes (PR smoke, release) |
| ST-053 | `fuzz_passphrase_input` (C-07, C-03) | Passphrase normalization is idempotent; invalid words rejected uniformly | Property oracle | PR smoke 5 min (changed targets); nightly 4 h; weekly 24 h; release per SG-07 | Yes (PR smoke, release) |
| ST-054 | `fuzz_form_urlencoded` (C-06) | Form bodies and CSRF fields never panic; limits enforced | libFuzzer | PR smoke 5 min (changed targets); nightly 4 h; weekly 24 h; release per SG-07 | Yes (PR smoke, release) |
| ST-055 | API stateful fuzzing (C-10, C-21, C-06) | Sequences of API calls generated from OpenAPI (08) never violate authz invariants (§8) or produce undocumented 5xx | Schemathesis/RESTler-style stateful fuzzing in candor-lab | Nightly, weekly, RC | Yes (weekly/RC) |
| ST-056 | Continuous fuzzing service (all targets) | All targets run continuously; new crashes triaged ≤ 2 business days | ClusterFuzzLite; OSS-Fuzz when accepted | Continuous | Yes (SLA; crashes block release via SG-07) |

Frequencies and gating for ST-040..ST-056 follow §4 (PR smoke 5 min; nightly 4 h; weekly 24 h; release per SG-07). The additional target `fuzz_desk_string_render` (C-15, ADR-042) is catalogued as ST-160 (§14A) and follows the same schedule and SG-07 rules.

## 8. API authorization, tenancy, session and web tests (ST-060..ST-079)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-060 | AuthZ matrix | For every route × audience × role × tenant × case-ACL state × COI state, the response equals the policy oracle (allow/deny, field set); 0 undeclared routes | Generated matrix from route registry + policy model (15); executed in candor-lab; expected results from an independently written oracle | PR (affected), merge, RC | Yes |
| ST-061 | IDOR enumeration | Swapping any object ID (case, evidence, message, export, user, channel, key) for another tenant's/case's/user's ID yields deny with identical response to "not found" | Automated ID substitution across all ID-bearing parameters | Merge, nightly, RC | Yes |
| ST-062 | Cross-tenant isolation snapshot | Running every admin/recipient action in tenant A leaves tenant B byte-identical (DB snapshot diff, blob store listing, key directory) (CVE-2026-46648) | Two-tenant EE lab; `pg_dump` per tenant schema/RLS view before/after | Merge, RC (EE) | Yes |
| ST-063 | RLS fail-closed | Raw SQL without `app.tenant_id` context errors; connection wrapper cannot be bypassed from application code | Direct SQL via test role; code-path test | PR, RC | Yes |
| ST-064 | Mass-assignment / field allow-list | For every mutation endpoint and role, attempting to set every model attribute changes only allow-listed fields; source-credential material immutable except by source's own rotation (CVE-2026-45020) | Property-based field enumeration | PR (affected), RC | Yes |
| ST-065 | Token audience replay matrix | Tokens/cookies from each audience (source-web, source-app, desk-api, admin-api) are rejected on every other audience; tokens after logout, revocation, key reset, role change are rejected across N=8 workers (CVE-2026-50000, ADR-029) | Replay matrix with concurrency | PR (auth code), merge, RC | Yes |
| ST-066 | Session lifecycle | Session fixation impossible (new ID after auth); staff idle/absolute timeouts per 15; source web sessions use the single ADR-034 timer set (20 min idle, 2 h absolute) and the one cookie name/attribute set owned by 11 (values read from the ST-167 registry, never literals in the test); logout synchronous; concurrent-session limits; source sessions hold no data after logout or expiry (Tier W keys and draft state zeroized, see ST-027, ST-143) | Scripted flows; server state inspection | Merge, RC | Yes |
| ST-067 | Authentication attacks | WebAuthn: assertion replay, wrong RP ID/origin, counter regression flagged; PIV path; OIDC (EE): `state`/`nonce`/PKCE/issuer mix-up, `alg=none`, key confusion; staff lockout/backoff; OTP single-use if any OTP exists (CVE-2024-38523); step-up enforced for key and security-setting changes; source passphrase: online guessing throttled per ADR-026 without identity | Attack scripts; OIDC test IdP with malicious modes | Merge, RC | Yes |
| ST-068 | Admin ≠ case access | Admin roles cannot obtain case content via any API, export, backup, support bundle or DB access; admin hosts hold no case keys (ADR-015) | Admin-role crawl + key-store inspection | RC | Yes |
| ST-069 | COI exclusion | Users excluded by COI map or source "report concerns" flag never receive key wrappings and cannot be granted access without the break-glass path (break-glass itself requires an independent-role approver, ST-164); envelope wrapping is triage-first (ST-146) and exclusions are stored only as blinded tags (ST-147) | Scenario tests with key-wrap inspection | Merge, RC | Yes |
| ST-070 | Break-glass & dual authorization | Break-glass requires two distinct authorized humans, is time-bounded, and emits CASE/SECURITY audit events; single approver cannot complete; approver ≠ requester | Scenario tests | RC | Yes |
| ST-071 | CSRF | All state-changing source-web forms require a per-session token bound to the session; SameSite=Strict cookies; desk/admin APIs reject requests lacking bearer + audience; no CORS allowances | Cross-origin form posts from lab origin; token removal/mismatch | Merge, RC | Yes |
| ST-072 | XSS polyglot corpus | Source-supplied text (message bodies, filenames as display metadata, form answers) rendered in source UI, Desk and exports never executes script or triggers network requests; including "pre-encrypted" claims (CVE-2024-38521) | Polyglot corpus through every input; headless render with network capture and JS execution hooks; Desk webview automation | Merge, RC | Yes |
| ST-073 | Injection suite | SQL (none possible via sqlx; fuzzed string params), command injection (no shell invocations with external data), header/CRLF, template injection, CSV/formula injection in exports (`=`,`+`,`-`,`@` prefixes neutralized), log injection (typed logging) | Payload corpus per sink | Merge, RC | Yes |
| ST-074 | Security header golden test | Deployed artefacts (not dev servers) return the golden header set: CSP (no inline, no third-party), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on dynamic pages, frame-ancestors none, `Permissions-Policy` restrictive; no `Server`/version headers (CVE-2024-55888; GL01-002/004) | External probe over Tor (onion) and clearnet (C-37/C-38) against candor-lab and E4 | Nightly, RC; production probes per 32 | Yes |
| ST-075 | HTTP conformance / smuggling | No request smuggling or response mix-up with pipelined/HTTP/1.1 edge cases through tor → C-06 (CVE-2024-41671 class) | Smuggling test corpus; pipelining with interleaved slow bodies | Nightly, RC | Yes |
| ST-076 | SSRF | Admin-configurable outbound URLs (webhook/Matrix/SMTP relay, OIDC discovery, SIEM endpoint, update mirror) reject internal/link-local/metadata/loopback/onion-of-self targets, DNS rebinding, and redirects; outbound only via declared egress proxy per zone | SSRF payload corpus; rebinding DNS fixture | Merge, RC | Yes |
| ST-077 | AuthZ independent of encryption | With every user given all key material (simulated leak), policy still denies unauthorized API access (GHSA-9vhh) | Key-leak simulation + ST-060 matrix subset | RC | Yes |
| ST-078 | Dangerous config requires two persons | Changing any DANGEROUS/anonymity-affecting config (32 CFG) by one admin remains pending until a second admin approves; notifications emitted; missing role check impossible (CVE-2026-46647) | Scenario tests over every DANGEROUS key | Merge, RC | Yes |
| ST-079 | Rate limits & quotas | Per-circuit and global limits (in-memory, circuit IDs never persisted), per-source-account upload quotas (current counters only, reset daily, no history, ADR-038(3)), Tier W passphrase-derivation concurrency semaphore (default 4) plus PoW (ADR-046(7)), staff login throttles, admin API limits behave per 15/16; limits reset without persistence; no response or dashboard exposes global rate-limit/queue state beyond the coarse daily health band (ADR-038(5)) | Load scripts over chutney with controlled circuits | Nightly, weekly, RC | Yes (weekly/RC) |

## 9. File, upload, archive and path tests (ST-080..ST-087)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-080 | Path traversal corpus | Names `../../.config/autostart/x.desktop`, `/abs/path`, `..\\x`, `C:\\x`, NUL, overlong (>4096), NFC/NFD/NFKC variants, RTL overrides, reserved device names never create/modify files outside the storage root in C-15/C-17/C-03 (CVE-2025-24888, CVE-2026-35465, TOB-SDW-012) | Corpus through every API returning names; fanotify/inotify audit of the whole client FS | PR (affected), nightly, RC | Yes |
| ST-081 | Archive attacks | Zip-slip, symlink/hardlink/device members, absolute names, gzip FNAME injection, zip bombs incl. overlapping-entry bombs (Fifield), nested depth >3, entry count >10,000, ratio >100:1 rejected; containment for export bundles (TOB-SDW-016) | Crafted archives; resource monitors | PR (affected), RC | Yes |
| ST-082 | Upload attacks | Extra/unexpected file parts, oversized parts, too many parts, nested multipart, missing boundaries, chunked-resumable abuse (chunk replays, out-of-range offsets, cross-session chunk IDs per THR-047) are rejected **before** any byte persists; the canonical 08 upload protocol holds (per-upload tokens, 8 MiB chunks, no cross-session resume, resume only within one Tier V session ≤ 24 h, **no resume in Tier W**, per-file cap 4 GiB standard / 16 GiB only in EE profiles; ADR-046(4)); Tier W parts are padded to ADR-011 buckets before staging (ADR-038(5)); disabled features truly disabled at the stream layer (CVE-2026-54707) | Crafted requests; fanotify on intake host | Merge, RC | Yes |
| ST-083 | No plaintext at rest in intake | During Tier W submissions (text + files up to max size), no plaintext byte sequence of the canary content appears on any disk, swap (must be absent), tmpfs outside the sealer's locked memory, or page cache dump of other processes | Canary content + fanotify + post-run raw block device scan of intake VM | Nightly, RC | Yes |
| ST-084 | Weaponized document containment | Known-CVE PoC documents (ExifTool CVE-2021-22204, Ghostscript CVE-2023-36664/-43115/CVE-2024-29510, ImageMagick CVE-2016-3714, GStreamer CVE-2024-47538 family, LibreOffice macro/link cases) opened in C-17 cannot reach network, key material, the Desk process or persistent storage; the viewer VM is destroyed on close | Red-team corpus; in-VM instrumentation; network tap (must be silent); post-close VM inventory | Weekly, RC | Yes |
| ST-085 | Sanitizer & redaction verification | Sanitized working copies contain none of the seeded metadata (EXIF GPS, Office docProps/rsids/comments/tracked changes, PDF /Info/XMP/incremental updates); redaction verifier finds no redacted string via text layer, OCR or history (REQ-H-17/18/19) | Seeded corpus; text extraction + OCR checks | Nightly, RC | Yes |
| ST-086 | Symlink containment on served/exported trees | Symlinks/hardlinks to `/etc/passwd` or sibling dirs inside export trees are not followed (CVE-2026-54706) | Crafted trees | PR (affected), RC | Yes |
| ST-087 | Polyglot handling | PDF+ZIP+HTML polyglots are identified and routed to the most restrictive handler or flagged; never rendered as HTML anywhere | Polyglot corpus through C-17 triage | Weekly, RC | Yes |

## 10. Malicious-server harness (ADR-027) (ST-090..ST-097)

### 10.1 Harness design (`candor-hostile`)
- **Principle:** clients treat every byte from a server as hostile. This covers names, sizes, counts, ordering, redirects, timing and keys, not only payloads (R1 principle 6).
- **Architecture:** `candor-hostile` implements the full server side of every client-facing protocol, generated from the OpenAPI/protocol schemas in 08: desk-api, admin-api, relay endpoints as seen by C-15, the Source App API as seen by C-03, the key directory (incl. witness cosignatures and OPERATOR_STATEMENT entries), the TUF repo (incl. Platform Manifest and security floor), the Tier V fetch-all reply pages (ADR-039), and the C-15↔C-17 bridge.
- **Mutation strategies:** each response is produced by a scenario that applies one or more strategies to a valid response:
  - `name-attack`: traversal/absolute/NUL/Unicode names.
  - `size-lie`: declared vs actual length mismatches, 0, 2^63.
  - `count-bomb`: 10^6 items.
  - `deep-nest`: nesting depth 10^4.
  - `reorder`/`duplicate`.
  - `type-confuse`.
  - `redirect`: 301/302/307/308 to other origins, `file://`, Alt-Svc.
  - `slowloris`: 1 byte per 30 s.
  - `truncate`.
  - `key-substitute`: unlogged or extra recipient keys.
  - `split-view`: different log views to two clients.
  - `rollback`: older signed metadata.
  - `replay`: old valid responses.
  - `error-injection`: HTML error pages with script, huge error bodies.
  - `hostile-string`: HTML/SVG/Markdown/link payloads, bidi and control characters, confusables, oversized and invalid-UTF-8 strings in every displayed string field (ADR-042; ST-160).
- **Client under test** runs in a VM with:
  - fanotify watching the entire filesystem (any write outside `<storage_root>` and the documented config/cache paths = failure);
  - a network namespace with packet capture (any connection other than the pinned endpoint = failure);
  - process accounting (any unexpected child process or exec = failure);
  - memory cap (RSS > 1.5 GiB = failure);
  - UI automation to trigger every user-visible flow;
  - crash detection.
- **Coverage requirement:** the nightly full run applies every applicable strategy to **every field of every response type** at least once. A generated coverage report fails the run if field×strategy coverage is below 100% of the applicable pairs (SECT-015).

### 10.2 Tests

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-090 | Hostile names to Desk | No server-supplied string reaches a filesystem path in C-15; storage names are client-generated (ADR-027; CVE-2025-24888, CVE-2026-35465) | `name-attack` on every field in all desk-api responses and in encrypted payload metadata after decryption | PR (fast profile), nightly (full), RC | Yes |
| ST-091 | Hostile sizes/counts/nesting/ordering | Clients bound memory/CPU/disk use; no panics; UI remains responsive; limits from `candor-limits` enforced | `size-lie`, `count-bomb`, `deep-nest`, `reorder`, `slowloris`, `truncate` | Nightly, RC | Yes |
| ST-092 | Redirects & origin pinning | No second connection to any endpoint other than the pinned one; no redirects followed; no proxy-from-env (CVE-2026-49996) | `redirect` scenarios + packet capture | PR (fast), nightly, RC | Yes |
| ST-093 | Key substitution / hidden recipient | Desk and Source App refuse to encrypt to keys not present in the verified key directory with valid inclusion proof; extra recipients are rejected and displayed (THR-046; INC-14; REQ-H-14, REQ-H-62) | `key-substitute` on key bundles and channel rosters | Nightly, RC | Yes |
| ST-094 | Split view & rollback | Clients detect split-view (via witness/consistency proofs) and rollback of key directory or TUF metadata; they stop and warn | `split-view`, `rollback`, `replay` with two client instances | Nightly, RC | Yes |
| ST-095 | Source App under hostile server | C-03 applies ST-090..ST-094 equivalents; additionally no local persistence beyond documented state; no plaintext written to disk | Harness in Source App profile (Android emulator + desktop) | Nightly, RC | Yes |
| ST-096 | Hostile intake batch to core (Z-INTAKE compromised) | C-09 import rejects malformed/oversized/replayed/duplicate batches; a compromised Z-INTAKE cannot cause writes outside import staging, cannot inject staff-visible active content, cannot forge staff audit events, and cannot trigger outbound connections from Z-CORE | Hostile relay endpoint in E3 + ST-052 corpus | Nightly, RC | Yes |
| ST-097 | Transport-derived identity for IPC | C-15↔C-17, C-24 ingest and C-25 agents take peer identity from the transport (SO_PEERCRED, vsock CID, mTLS SAN) and ignore claimed identities in payloads (CVE-2025-24889) | Messages claiming other identities from each compartment | PR (affected), RC | Yes |

## 11. Resilience and failure tests (ST-100..ST-111)

Expected failure behaviour (FAIL-) is owned by `34-PERFORMANCE-SCALABILITY.md`. These tests verify the **security** outcome, which is always fail closed with no plaintext and no metadata leak.

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-100 | Intake DoS | With Tor onion PoW enabled (ADR-026), under ≥1,000 parallel anonymous upload attempts a legitimate uploader completes within the SLO in 34; no name collisions over 10^7 simulated inserts (OnionShare OTF-012 lesson) | chutney + real-Tor E4 smoke; load generator | Weekly, RC | Yes |
| ST-101 | Slow and large request abuse | Slowloris, slow-read, oversized headers/bodies, decompression bombs in request encodings are cut off at documented limits without resource exhaustion | Load scripts | Weekly, RC | Yes |
| ST-102 | DB corruption | PostgreSQL data checksums detect page corruption; services fail closed (no partial case rendering, no fallback to unsafe state); restore path documented works | Flip bytes in PGDATA/WAL on lab VM; start services | Weekly, RC | Yes |
| ST-103 | Power loss | Hard power-off (VM kill) at 50 random points during: Tier W sealing, relay import, case-key rewrap, epoch rotation, deletion, backup, upgrade ⇒ after reboot: no plaintext on disk, no orphaned unwrapped keys, no duplicate or lost envelopes (idempotent import), audit chain verifies or reports a detectable gap | Fault-injection scheduler | Weekly, RC | Yes |
| ST-104 | Network interruption / partition | Relay pulls interrupted at every protocol step resume correctly with no duplicate imports; Z-CORE↔Z-INTAKE partition causes queueing, not data loss; clients handle drops without corrupting local stores | tc/netem, iptables partition | Weekly, RC | Yes |
| ST-105 | Storage failure | Disk full, read-only remount, EIO (dm-flakey/dm-error), blob store unavailable ⇒ fail closed with content-free errors; no fallback to temp dirs; no plaintext spill | Device-mapper fault targets | Weekly, RC | Yes |
| ST-106 | Clock issues | Clock skew ±24 h, backward jump, forward jump of 30 days, NTP spoofing: TUF expiry handling (no acceptance of expired metadata; no permanent brick), epoch key selection (no encryption to expired epoch), token lifetimes, SLA engine, audit timestamps (monotonic ordering preserved via sequence numbers) (THR-043) | libfaketime + NTP fixture | Weekly, RC | Yes |
| ST-107 | Upgrade failure & rollback | From each supported prior version (N-2 minors, previous major's last minor): interrupted upgrade (power loss mid-migration) recovers or rolls back cleanly; failed DB migration leaves the system on the prior version; no downgrade to a vulnerable version via rollback; config and secret placement preserved | Upgrade matrix in E5 with fault injection | Weekly, RC | Yes |
| ST-108 | Backup & restore | Full restore to clean hosts reproduces a working instance with keys held by recipients; a backup restored **without** recipient/quorum keys yields no readable content; a case crypto-erased before restore remains unreadable after restore, including when the Erasure Key Vault is restored from an older vault backup (erasure log applied first, ST-158) (ADR-025, ADR-044(4)); backup contains no source-linked plaintext metadata (see AT-012, AT-077) | Scripted drill; content inspection | Weekly (automated), RC, quarterly full manual drill | Yes |
| ST-109 | Memory pressure / OOM | Under memory pressure C-07 and key-handling processes are OOM-killed rather than swapping (swap absent), and no core/partial state persists | cgroup memory limits; swap presence check | Weekly, RC | Yes |
| ST-110 | Core dump prohibition | SIGSEGV/SIGABRT of any key- or plaintext-handling process produces no core file, no systemd-coredump entry, no crash upload (REQ-H-58; INC-58); includes the Candor Desk main and webview/renderer processes on every supported Desk platform: OS and webview crash reporting disabled (WER LocalDumps/upload, WebView2/Crashpad, macOS ReportCrash), no minidump containing canary case text leaves the host (RVW-C-11) | Signal injection; filesystem and journal inspection; Desk crash with canary content + egress capture on Windows/macOS/Linux lab clients | PR (service units), RC | Yes |
| ST-111 | Audit-log dependency failure | If C-24 is unavailable, staff actions that require audit fail closed (no unaudited case access); source intake continues (no source-visible dependency on staff audit) | Stop C-24 during scenarios | Nightly, RC | Yes |

## 12. Configuration, secret placement and zoning (ST-120..ST-124)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-120 | Config checker | Every DANGEROUS/anonymity-affecting option (32 CFG) is detected and reported with its class; secure defaults apply when keys are absent; known placeholder secrets are rejected; checker verdicts are deterministic and cover 100% of options in the schema (coverage check) | Schema-driven property tests over generated configs; E5 pairwise flags | PR (config), nightly, RC | Yes |
| ST-121 | Secret placement manifest scan | On every host of every profile × feature-flag combination, the set of secret-bearing files (patterns: PEM, OpenSSH, onion `hs_ed25519_secret_key`, client-auth `.auth_private`, age/X-Wing/Candor key formats, PKCS#12, TUF keys) equals the host role's manifest; violation fails deployment (ADR-028; GHSA-rqwh) | Post-deploy scanner (installer + C-25 self-test) with content-pattern and path checks | Nightly (pairwise), weekly (full), RC | Yes |
| ST-122 | Host network baseline | Z-INTAKE has no clearnet listener; backends bind only loopback/Unix sockets; egress default-deny except via tor; no debug/status endpoints; error pages carry no hostnames/IPs (REQ-H-33/34; INC-34) | `ss`/nmap from inside and outside; config inspection | Nightly, RC | Yes |
| ST-123 | Zone direction enforcement | No connection can be initiated from Z-INTAKE to Z-CORE; only C-09 pulls (ADR-009) | Connection attempts from compromised-intake simulation | Nightly, RC | Yes |
| ST-124 | Installer idempotence & drift | Re-running installer/upgrades produces no drift; manual drift in hardening settings is detected by C-25 self-test | Repeat installs; injected drift | Weekly, RC | Yes |

## 13. Update and supply-chain tests (ST-130..ST-135)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-130 | Update client rejection suite | Update client rejects unsigned, under-threshold, expired, rolled-back, freeze-attacked, mix-and-match, unlogged (no inclusion proof) metadata and mismatched target hashes; replacing repository contents on the mirror yields only DoS (INC-49, REQ-H-15) | Rogue TUF repository fixture in E3 | Nightly, RC | Yes |
| ST-131 | Reproducible build verification | Builders A and B produce bit-identical artefacts and source tarballs; mismatch triggers diffoscope report (28) | Comparator job | Every release build; nightly on main | Yes |
| ST-132 | Artefact+hash swap detection | Replacing both a download and its published hash on one channel is detected by signature/TUF verification and by the ≥2-channel hash check (INC-52) | Simulated site compromise in E3 | RC | Yes |
| ST-133 | CI configuration policy | All actions SHA-pinned to mirrored forks; no `pull_request_target`; minimal permissions; no curl-piped-to-shell; no template injection; cache policy; Scorecard threshold (28) | zizmor, actionlint, custom policy checks, OpenSSF Scorecard | PR (CI changes), weekly | Yes |
| ST-134 | Malicious install-script canary | A fixture npm package with a `postinstall` that writes a marker is added in a test branch: the marker is never created in builds; lockfile integrity enforcement rejects tampered tarballs (INC-42) | Fixture registry in E3 | Weekly, RC | Yes |
| ST-135 | Typosquat allow-list | Adding an unapproved name (e.g. `serde_jsom`, `reqeusts`) fails resolution with "not on allow-list" (INC-43) | Fixture manifests | Weekly | Yes |

## 14. Pentest, red team and audit-driven tests (ST-140..ST-142)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-140 | Pre-release external pentest | Independent testers find no open Critical/High issues in the release candidate; scope: source web over Tor, Source App, Desk + desk/admin APIs, relay, key directory and its governance (time-locks, witness cosignatures, high-water mark), fetch-all reply endpoint, operator statement and watcher-facing endpoints, viewer containment on each platform tier (ADR-042), Confidential-VM sealer where offered, installer and host hardening for CE-HARDENED and EE-ONPREM profiles; malicious-server, malicious-insider and organisation-as-adversary perspectives included (details in 37) | Grey-box, source code access, candor-lab + E4, ≥4 person-weeks for major | Each major; minor with new attack surface (37) | Yes (SG-22) |
| ST-141 | Internal red-team exercise | End-to-end objectives: "identify a source", "read a case without assignment", "ship a malicious update", "exfiltrate a key", "learn who a report concerns", "re-roster a channel so the next report reaches the accused", "suppress a case by destroying key access" (organisation-as-adversary, RVW-C-01/03/05) against a full lab deployment with realistic operators | Objective-based exercise, 2 weeks | Each major, yearly | Findings gated via ST-012 |
| ST-142 | LLM-assisted source audit sweep | Automated adversarial code review across trust-path repos surfaces candidate authorization/logic bugs; each candidate is triaged by a human (GlobaLeaks 2026 LLM-adversary audit lesson [B-GL-19]) | Tooling run on RC; triage records | Each minor, RC | Yes (triage complete) |

Findings from ST-140..ST-142, audits and the bounty feed ST-012. No finding closes without a regression test or rule.

## 14A. Revision controls ADR-034..ADR-047 (ST-143..ST-178)

These tests verify the controls introduced by the round-2 revision ADRs. Leakage and inference aspects of the same controls (what an adversary *learns*) are tested in 30 (AT-069, AT-076..AT-085); the tests here verify that the control is *enforced* and fails closed. All parameter values (timers, slot times, k, time-lock durations, retention windows, slot counts) are read from the constants registry checked by ST-167, never hard-coded in the test.

### 14A.1 Tier W draft and credential state (ADR-034)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-143 | RAM-only drafts and tmpfs staging cleanup | Draft text, identity block, questionnaire answers, file display names and timers exist only in C-07 mlocked RAM keyed by an opaque session handle; attachment parts exist only in the tmpfs staging area, encrypted under a per-session key held only in C-07 RAM; on Submit, abandon, 20-min idle expiry, 2-h absolute expiry, sealer restart, OOM kill and power loss, the per-session key is zeroized and staging files are removed (for crash/power loss: at the next sealer start, before any new session is accepted); no draft byte, staging name or timer value reaches C-08 (incl. WAL), any non-tmpfs filesystem, journald or swap (absent) (RVW-A-02, RVW-B-12) | Canary drafts (M-MSG, M-FNAME, identity canary) through journeys J7, J10 (draft → idle expiry), J11 (draft → `kill -9` sealer), J12 (draft → VM power-off); fanotify on all non-tmpfs mounts (any write by C-06/C-07 during the draft phase fails the test); `/proc/<sealer>/status` VmLck covers draft buffers and VmSwap = 0; tmpfs listing after each journey and after restart; raw block scan of the intake VM; heap scan per ST-027 after expiry | PR (C-06/C-07 touched), nightly, RC | Yes |
| ST-144 | Seal only after recipient set is fixed | The HPKE seal of the content key happens only at Submit, after COI ticks are final; back-navigating after uploads and changing COI ticks yields an envelope in which no object (text, attachments, identity) has a slot openable by a member removed by the final ticks (RVW-A-07) | Scripted flow: upload 3 files → tick role R → back → change ticks → submit; the Desk of every channel member and triage member trial-decrypts every object | PR (C-07), nightly, RC | Yes |
| ST-145 | Passphrase never persisted; confirm-before-finalize | The generated passphrase is held only in C-07 RAM until confirmation or session expiry, then zeroized; it is never written to any store (C-08 incl. WAL, tmpfs staging, logs, crash output); the submission is finalized only after the source re-types 3 randomly chosen words correctly; wrong words, a dropped confirmation response, or expiry before confirmation leave no envelope, no `source_account` row and no staged file | M-PASS canary + DB/tmpfs diff; fault injection dropping the confirmation response at the onion service; heap scan of C-06/C-07 after response (ST-027) | PR (C-06/C-07), nightly, RC | Yes |

### 14A.2 Routing, COI and Key Directory governance (ADR-036, ADR-037)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-146 | Triage-first routing | Envelopes are wrapped **only** to Member Epoch Keys of eligible Triage Set members (≥ 2 independent-body role labels, or channel owner + OVERSIGHT) after removal of source-ticked roles; if fewer than 1 eligible triage member remains the source is directed to the alternative independent channel and nothing is sealed; a non-triage member cannot list, trial-decrypt (holds no wrap), or receive notifications for intake envelopes, and non-triage dashboards show no intake counts; wider access arises only from Case Key wraps made by the Triage Set, each audited (RVW-B-02, RVW-A-18) | Scenario matrix: channel with 2 triage + 5 non-triage members; submissions with 0/1/2 triage roles ticked; non-triage member Desk with debug build attempting list/trial-decrypt via desk-api; notification sink capture; dashboard API crawl per role; key-wrap inspection | Merge, nightly, RC | Yes |
| ST-147 | Blinded COI enforcement | Exclusions are stored only as `HMAC(K_case_excl, user_id)` tags with `K_case_excl = HKDF(case_key, "candor/coi-excl/v1")`, padded to exactly 8 tags per case; C-22 denies adding a user whose Desk-computed tag is in the set without learning the user; every member Desk on sync detects a wrap for an excluded user and raises a SECURITY alert; `case.member_removed` and `authz.denied` reason codes are identical for COI and non-COI removals/denials (RVW-B-01) | Schema/row inspection (tag count = 8 for 0..8 exclusions; tags indistinguishable from random without case key); planted wrap for excluded user via compromised-core fixture → alert within one sync; event diff COI vs non-COI removal (byte-identical apart from IDs) | Merge, nightly, RC | Yes |
| ST-148 | Follow-up sealing rule | A source follow-up is sealed only to members who were in the eligible set of the original report AND are still members; a member added after the original report never receives a follow-up slot and gains access only via an audited Case Key wrap by the Triage Set (RVW-A-06) | Add member M after report; source sends follow-up; M trial-decrypts; audit inspection | Merge, RC | Yes |
| ST-149 | Directory rollback/freeze rejection and independent time | The intake enforces the snapshot high-water mark: any snapshot with smaller tree size or earlier time than the last accepted one is rejected and sealing continues on the last accepted snapshot; a snapshot older than the freshness bound (7 days, ADR-047(4); boundary cases in ST-172) causes fail-closed ("temporarily unavailable"), not sealing to a stale roster; the intake clock floor comes from the signed Tor consensus `valid-after` plus Roughtime, so a Z-CORE-supplied time cannot move sealing time backwards or forwards (RVW-A-04) | Hostile core fixture pushes (a) older signed snapshot, (b) same size with earlier time, (c) withheld updates beyond freshness bound, (d) Z-CORE NTP skewed ±7 days; lab consensus/Roughtime fixture; sealer decision log (lab-only instrumentation) | Nightly, weekly (clock variants), RC | Yes |
| ST-150 | Governance time-lock enforcement | Roster additions, role-label changes and COI-policy loosening stay pending for 72 h (GOV/HIGH: 7 days), trigger content-free notification to all current members and OVERSIGHT, and need dual approval with ≥ 1 approver from an independent role; the second approver's out-of-band `person_ref` verification is recorded; pending entries are never used for sealing; removals and tightening apply immediately; clock manipulation (ST-149 fixture) cannot shorten the lock (RVW-A-05, RVW-C-05) | Scenario tests per change type × profile; approver-set permutations (same-role pair, accused member as approver, missing independent role); accelerated clock with forward jump on Z-CORE only | Merge, weekly, RC | Yes |
| ST-151 | Witness cosignature enforcement | In EE/GOV/MANAGED, Tier V clients, Desks and the intake reject checkpoints with < 2 witness cosignatures or with no cosignature from outside the operating organisation; in CE the same condition produces a visible warning; the Source App's persistent tree-head pin detects rollback/fork across sessions; the web-bundle pin fingerprint changes on fork (RVW-A-08) | Rogue witness fixtures (1 witness, 2 same-org witnesses, forged cosignature, valid pair); split-view between two Source App instances; restart with pinned head | Nightly, RC | Yes |
| ST-152 | Role-label certification, new-key warning, publication slot | Role labels not signed by OVERSIGHT are rejected by clients; Tier V clients warn when a member key is < 7 days old; epoch-key and roster publications appear only at the fixed weekly publication slot (ADR-036(7)); Tier W pages present no verification affordance they cannot deliver (RVW-A-17, RVW-A-29) | Unsigned/mis-signed label fixtures; fresh-key fixture; 8-week accelerated directory trace (publication times ∈ slot set); Tier W page crawl for fingerprint/verify UI | Nightly, RC | Yes |

### 14A.3 Platform integrity evidence (ADR-035, ADR-040)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-153 | Platform Manifest and security floor | The C-25 self-test and installer fail when any installed OS/tor/PostgreSQL package on Z-INTAKE/Z-CORE differs from the TUF-signed Platform Manifest (name, version, hash; extra or missing package), or when tor is not from the pinned Tor Project key/version; every trust-path component refuses to start below the signed security floor; Fleet Manager ring policy cannot hold an instance below the floor; Z-INTAKE fetches updates only via the project onion mirror over Tor, Z-CORE only via the egress-restricted HTTPS mirror (ADR-046(3)); emergency releases are refused by the update client unless ≥ 2 signers from ≥ 2 organisations signed and the 2-hour cooling period elapsed (RVW-A-12, RVW-A-16, RVW-C-17) | Rogue snapshot mirror in E3 (swapped `.deb`, extra package, downgraded tor); floor fixture (N-1 below floor); Fleet policy attempting hold; egress capture per zone; rogue TUF emergency metadata (1 org, 0-h cooling) | PR (packaging), nightly, RC | Yes |
| ST-154 | Operator statement expiry banner | A quorum-signed (k-of-n, ≥ 1 independent role) OPERATOR_STATEMENT is accepted only with a valid quorum; when the newest valid statement is older than 30 days, or its signature/quorum is invalid, the Tier W landing and inbox pages, the Source App and Desk show the warning banner in every locale; renewal removes it; the statement includes "reduced separation of duties" when small-organisation mode is on (ADR-045) (RVW-A-01) | Accelerated clock across day 29/30/31; forged and under-quorum statements; DOM assertions (Tier W, no JS), Source App and Desk UI automation | Nightly, RC | Yes |
| ST-155 | External watcher mismatch detection | The reference watcher (fetching over Tor) detects and publishes, within one watcher cycle, any divergence between served static source-UI assets/templates, CSP headers or the Sealer's signed running manifest and the transparency-logged release digests; zero false positives over a 7-day clean soak; watcher requests carry no per-instance or per-watcher identifiers beyond what 16 permits (RVW-A-01, RVW-A-13) | Lab intake with injected divergence: modified template, weakened CSP, unlogged sealer manifest, divergence served only to 1 of N circuits (selective serving, sampled); publication endpoint capture | Nightly (injection set), weekly (soak), RC | Yes |
| ST-156 | Confidential-VM attestation verification (optional profile) | Where the Sealer runs in an SEV-SNP/TDX confidential VM, Desk and watchers accept the attestation only if the measurement equals a transparency-logged release, the report is fresh (nonce bound; age ≤ 24 h, ADR-047(4); boundary cases in ST-173) and the guest policy disallows debug/migration; replayed, stale, debug-enabled or unlogged-measurement reports are rejected and shown as failed, never as "verified" to sources | Attestation fixtures (valid, replayed, debug policy, wrong measurement); TEE-capable lab runner where available, else signed-fixture mode (recorded as reduced coverage) | Weekly, RC (TEE profile only) | Yes (TEE profile) |
| ST-157 | IR memory/packet capture approval | Intake memory or packet capture tooling (`candorctl ir capture`) refuses to run without approval by an independent role (channel OVERSIGHT or external ombudsman) in addition to the IR lead; captures are encrypted to independent custodians before touching disk; an INCIDENT_NOTICE directory entry is published (RVW-C-04) | Approval permutations (IR lead only, IR lead + legal, IR lead + OVERSIGHT); disk inspection during capture; directory inspection | Merge (IR tooling), RC | Yes |

### 14A.4 Erasure and backup boundaries (ADR-044)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-158 | Erasure Key Vault restore applies erasure log | Restoring the vault (from its own backup, ≤ 14-day retention, or from the DR replica) applies the signed append-only erasure log **before** serving any key; cases erased after the vault backup was taken remain unreadable after restore; a truncated, reordered or unsigned erasure log is rejected and the vault stays closed (fail closed, content-free error); a vault backup ≥ 15 days old restores without resurrecting any erased case (RVW-C-07 RT-5); DR replica lags ≤ HA RPO (RVW-C-06, RVW-C-07) | Erase cases after vault backup → restore → attempt decrypt with all member devices; log tampering fixtures; DR failover in EE-HA lab; replica lag measurement | Weekly, RC; quarterly manual drill with ST-108 | Yes |
| ST-159 | Infrastructure backup exclusion checker | The config checker requires a signed attestation that hypervisor/SAN/image-level backups of core hosts exclude the vault volume; missing or expired attestation is reported as DANGEROUS, shown in the configuration digest, and switches the source-facing deletion statement to the text stating that the 14-day bound does not hold; HIGH/GOV profiles fail when the vault is sealed by a vTPM instead of a physical host TPM (RVW-C-06) | E5 profile matrix with attestation present/absent/expired; TPM type fixture (swtpm vs physical in lab hardware runner); source landing page text assertion | PR (config), nightly (E5), RC | Yes |

### 14A.5 Desk rendering, viewer tiers and custody (ADR-042, ADR-043)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-160 | Desk plain-text rendering fuzz | Every string originating from a source, the viewer VM (Stage 0/metadata report, OCR text) or the server (names, labels, error texts) is rendered in the Desk webview only as text nodes: no HTML/Markdown interpretation, no link auto-detection, bidi/control characters visualised, per-field length bounds enforced after schema validation; zero CSP/Trusted Types violations; no IPC command is invoked as a side effect of rendering (RVW-A-15) | cargo-fuzz target `fuzz_desk_string_render` (schema validation + text-node renderer) and a hostile-string corpus (HTML/SVG/MathML polyglots, Markdown/link payloads, `javascript:` URLs, bidi overrides, zero-width/confusables, 1 MiB strings, invalid UTF-8) injected via `candor-hostile` into every string field (SECT-015) and via decrypted payload metadata; webview automation with CSP-report sink and IPC call log | PR smoke 5 min (Desk UI/renderer touched), nightly 4 h, weekly 24 h, RC | Yes |
| ST-161 | Platform-tier viewer enforcement | On Tier 1 (Linux KVM microVM, Qubes) and Tier 2 (Windows Hyper-V isolated VM, macOS Virtualization.framework VM) the viewer VM has no NIC, no shared folders and no clipboard; where no hardware-isolated viewer is available (virtualisation disabled, unsupported OS), Desk permits only CL-0 (metadata-free text preview of sanitized text) and refuses to open originals; pixel-rendered copies carry the "rendering — not evidence" label with converter output hash and converter release digest recorded; the Desk host never decodes image formats from the viewer (RVW-A-15, RVW-A-30) | Desk on each platform with virtualisation on/off; in-VM network/share/clipboard probes; attempt to open original with viewer unavailable; label and record inspection | Nightly (Linux), RC (all platforms) | Yes |
| ST-162 | Independent-custody device enforcement | Enabling an INDEPENDENT channel whose Triage Set members lack recorded independent-custody attestations is a DANGEROUS change (two-person, ST-078) and is surfaced in the Admin UI; Desk reports its own release digest and a mismatch with the transparency log is shown (non-authoritative; RVW-C-01) | Admin flow scenarios; Desk digest fixture (modified build) | Merge, RC | Yes |

### 14A.6 Continuity, organisation-as-adversary, envelope rejection, reply retrieval (ADR-038, ADR-039, ADR-044, ADR-045)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-163 | Key-access continuity | SCIM/HR/IdP deprovisioning only suspends server-side authorization; deleting a member's key wraps requires dual control, a 7-day cooling-off and OVERSIGHT notice (except source-requested erasure or retention expiry); `min_recipients` per case defaults to 2; enrolment requires ≥ 2 hardware authenticators (RVW-C-03) | SCIM deprovision fixture; wrap-deletion attempts within cooling period and single approver; enrolment with 1 authenticator | Merge, RC | Yes |
| ST-164 | Organisation-as-adversary controls | Break-glass cannot complete without one approver from an independent role outside the legal/management chain; Fleet Manager commands cannot disable intake, lower security floors or change routing, and logging/retention changes from Fleet Manager are tighten-only; availability-affecting actions require the customer's independent role; small-organisation mode requires an external OVERSIGHT party before activation (RVW-C-09, RVW-C-10, RVW-C-13) | Approver-set permutations; Fleet command fuzzing against policy (ST-055 style); small-org setup flow | Merge, RC | Yes |
| ST-165 | Undecryptable-envelope handling | An envelope that no eligible member can import is escalated per ADR-033(2) with per-channel rate limiting; after 14 days pending and a dual-approved rejection it is deleted so its epoch keys can retire (ST-034); no single actor can reject; escalation flooding (1,000 garbage envelopes) produces at most the rate-limited number of escalations (RVW-A-20) | Hostile intake injecting garbage envelopes (ST-096 fixture); accelerated clock; epoch-key retirement check | Nightly, RC | Yes |
| ST-166 | Fetch-all reply retrieval under hostile server | Tier V clients retrieve replies only by downloading the complete set of fixed-size pages covering the last 30 days and trial-decrypting locally; the request sequence is byte-identical across different mailboxes and never contains a mailbox identifier; clients remain bounded and correct under `size-lie`, `count-bomb`, `truncate`, `reorder` and `replay` on the page set; header digests on the intake are purged after ≤ 24 h (RVW-A-10) | `candor-hostile` fetch-all profile; request capture diff across 3 mailboxes; intake row age inspection | Nightly, RC | Yes |

### 14A.7 Spec-constant consistency lint (RVW-B-07, RVW-B-29)

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-167 | Spec-constant consistency lint (`spec-constants`) | Every canonical constant has exactly one value across (a) the machine-readable constants registry, (b) its owning document section, (c) every other spec that mentions it, (d) the shipped configuration schema defaults and CFG classes (32), (e) code constants in `candor-limits` and service crates, and (f) the fixtures of ST-/AT- tests; no spec contains a known superseded variant (e.g. "idle 30 min", "15 ± 10 min" import, "k ≥ 5", "hourly digest", "recipient key IDs" in cleartext header text) | Registry `tools/constants.json` (owned by 39; entries: name, value, unit, owner doc §, ADR, profile overrides, `superseded_variants`); the lint (1) extracts tagged values `⟦const:NAME⟧` and anchored phrases from `specs/*.md`, (2) compares config schema defaults and generated `candor-limits` constants (build fails if the generated file is stale), (3) fails on any superseded variant or on an untagged numeric literal within 8 words of a registered keyword in a new/changed line; initial registry below | PR (any change to `specs/`, config schema, `candor-limits`, test fixtures), merge, nightly, RC | Yes |

Initial registry content for ST-167 (values from DECISIONS; owner documents are canonical where named in the revision brief):

| Constant | Value | Owner / ADR |
|---|---|---|
| Tier W session idle / absolute | 20 min / 2 h (single timer set) | ADR-034; 11 |
| Source session cookie name and attributes | value in 11 | 11 |
| Relay import schedule | 4×/day fixed times (default); 1×/day fixed time (HIGH/GOV); never event-driven | ADR-038(1); 07/09 |
| Staff notification schedule | one content-free daily digest at a fixed time, sent whether or not anything is pending; disabled by default in HIGH | ADR-038(2); 07 |
| Staff date display | day (standard), ISO week (HIGH) | ADR-038(3); 12 |
| Delayed-delivery option | random 1–3 days | ADR-038(4) |
| Undecryptable envelope rejection | 14 days pending + dual approval | ADR-038(6) |
| Metrics regime | k = 10; minimum period 1 calendar month; complementary suppression; no medians/ratios/percentiles for cells < k; no per-channel metrics for channels < 3 cases/month; SOC global daily health bands only | ADR-046(5); 24 §TEL |
| Message padding | 4 KiB buckets, max 64 KiB | ADR-011; 04 |
| Attachment padding | geometric ratio 1.25, min 256 KiB | ADR-011; 04 |
| Page size classes | values in 11 §5.4 | 11 |
| Upload protocol | 8 MiB chunks; Tier V resume ≤ 24 h within one session; Tier W no resume; 4 GiB/file (16 GiB EE only) | ADR-046(4); 08 |
| Envelope recipient slots | 16 fixed-size anonymous slots | ADR-033(1); 04 |
| COI tag padding | 8 tags per case | ADR-037(3); 09 |
| Triage Set minimum | ≥ 2 members | ADR-037(1); 14 |
| Member epoch | 7-day epoch, 14-day decrypt window, 4 epochs pre-published | ADR-030; 04 |
| Directory time-lock | 72 h (GOV/HIGH 7 days) | ADR-036(2); 04/15 |
| Witness cosignatures | ≥ 2, ≥ 1 outside operating organisation (EE/GOV/MANAGED) | ADR-036(5) |
| Directory publication | fixed weekly slot | ADR-036(7) |
| New member key warning | < 7 days | ADR-036(3) |
| Operator statement cadence | 30 days | ADR-035(2) |
| Reply retrieval window | 30 days, fixed-size pages; header digests ≤ 24 h | ADR-039 |
| Erasure Key Vault backup retention | ≤ 14 days | ADR-033(3), ADR-044(4); 19 |
| Key-wrap deletion cooling-off | 7 days | ADR-044(1) |
| `min_recipients` | 2 | ADR-044(2) |
| Emergency release cooling | ≥ 2 h, ≥ 2 signers from ≥ 2 organisations | ADR-040 |
| Source passphrase KDF | Argon2id m = 64 MiB, t = 3, p = 1; FIPS PBKDF2-HMAC-SHA-512 210,000 iterations; derivation semaphore 4 | ADR-046(7); 04 |
| Source passphrase | 10 EFF large-list words; per-locale lists: `ceil(128 / log2(list_size))` words (≥ 128 bits), NFKC + lowercase + single spaces before derivation | ADR-005; ADR-047(6) |
| Chaff envelopes | Poisson, mean 1 per 2 h per channel; real envelope replaces a slot with delay ≤ 2 h (immediate for the source-visible confirmation) | ADR-047(3); 32 CFG |
| Key Directory snapshot freshness | ≤ 7 days (sealer and Tier V clients; fail closed) | ADR-047(4) |
| Confidential-VM attestation refresh | ≤ 24 h | ADR-047(4) |
| Intake deletion list | replicated to Z-CORE every import slot; applied before any restored intake opens | ADR-047(9); 19 |

### 14A.8 Final-round controls (ADR-047) (ST-168..ST-178)

Inference aspects (what an observer learns from chaff, restored deletions, seized Source App devices, mode display) are tested in 30 (AT-086..AT-092).

| ID | Name | What it proves | Method | Frequency | Gating? |
|---|---|---|---|---|---|
| ST-168 | Chaff generation and format identity (ADR-047(3)) | For every channel the Intake Sealer writes chaff envelopes on a Poisson schedule with the configured mean (default 1 per 2 h per channel, `intake.chaff.mean_interval`); chaff is byte-format identical to real envelopes (same header layout, 16 slots, padded size classes drawn from the real-size distribution, same store path, same row fields); a real envelope replaces a scheduled chaff slot with delay ≤ 2 h, or is written immediately for the source-visible confirmation with the next chaff draw adjusted so the long-run rate stays constant; no member key opens any chaff slot | Sealer run with a fake clock over 30 simulated days, with and without real submissions; χ² goodness-of-fit of inter-write gaps against the exponential distribution (p ≥ 0.01) per channel; structural diff of real vs chaff rows/files (only ciphertext bytes differ); trial decryption of every chaff slot by every lab member key fails; replacement-delay histogram max ≤ 2 h | Nightly (1-day sim), weekly (30-day soak), RC | Yes |
| ST-169 | Chaff discarded at import without residue | Chaff never becomes a case: after an import slot no C-12 row, C-13 blob, key wrap, CASE/SECURITY audit event, counter increment, notification or ADR-033(2)/ADR-038(6) escalation/rejection exists for any chaff envelope; chaff does not delay member epoch-key retirement; intake deletes chaff after the slot like acknowledged envelopes | Lab with only chaff for 14 days, then a mix; DB/blob/audit/counter diff before/after each slot; epoch-key retirement log; escalation queue inspection | Nightly, RC | Yes |
| ST-170 | Per-case metadata erasure (ADR-047(8)) | Category, title and custom-field values are stored in C-12 only as AEAD ciphertext under the metadata key derived from the case's Erasure Key (label per 04); destroying the Erasure Key makes them undecryptable in production, replicas and every BS-CORE set once the matching BS-ERASURE sets have expired; no cleartext copy exists in any other column, index, audit event, export or search index | Canary strings in all three field types; column/WAL/backup byte scan for canaries; erase case → restore BS-CORE older than the erasure with BS-ERASURE ≥ 15 days old → fields fail AEAD; negative: attempt to read fields with a case key only (not EK) fails | Nightly (scan), weekly (restore), RC | Yes |
| ST-171 | Source App encrypted vault (ADR-047(1)) | At install the Source App creates a fixed-size encrypted vault whose size and file structure are identical whether it is never used, used for one organisation, or used for several; Key Directory pins, the onion address and passphrase-derived material exist only inside it; no plaintext organisation identifier (onion address, organisation name, directory tree head, channel label) exists anywhere in app storage, preferences, caches, logs, OS keychain entries, crash data or temp files; wrong-passphrase unlock is indistinguishable in time and error from an empty vault | Forensic imaging (Android, iOS where feasible, Linux/Windows/macOS desktop) at install, after a submission and after a reply check; grep for canary onion address/org name/tree head in raw images incl. unallocated space; vault size comparison; timing of wrong-passphrase vs empty-vault unlock (≤ 5% difference) | Weekly, RC (all C-03 platforms) | Yes |
| ST-172 | Key Directory snapshot freshness bound (ADR-047(4)) | The sealer (Tier W) and Tier V clients seal to a snapshot aged 7 d − 1 h by the independent time floor and refuse one aged 7 d + 1 h with the fail-closed "channel temporarily unavailable" state; a Z-CORE clock skew cannot extend the bound (time from Tor consensus + Roughtime) | Hostile-core fixture withholds snapshots; fake consensus/Roughtime fixtures; Source App against a frozen directory mirror | Nightly, RC | Yes |
| ST-173 | Confidential-VM attestation freshness (ADR-047(4)) | Attestation evidence older than 24 h is treated as absent by Desk import (WARN, envelopes not shown as TEE-verified) and by the reference watcher (stale finding published); the guest refreshes at least every 24 h and at every sealer start | Signed-fixture mode (or TEE runner) with evidence aged 23 h / 25 h; sealer restart | Weekly, RC (TEE profile) | Yes (TEE profile) |
| ST-174 | Intake deletion list across DR and failover (ADR-047(9)) | Deleting a mailbox writes a signed, hash-chained deletion-list entry; C-09 replicates the full list to Z-CORE at every import slot as a fixed-size padded blob; after intake restore (DR-P1) and after EE-HA failover the intake refuses to open until it has verified and applied the merged list; no listed account or reply is served; C-09 skips re-push of listed replies; a truncated, re-ordered or wrongly signed list is rejected | Lab: delete mailbox after last BS-INTAKE → destroy intake → DR-P1; variants: tampered replica, missing replica (open refused), EE-HA failover; replica size constant for 0, 1 and 10,000 entries | Weekly (DR lab), RC; quarterly with RT-1 | Yes |
| ST-175 | Desk re-wrap after vault loss (ADR-047(7)) | After a vault loss, `ekv rewrap` requires dual approval; new Erasure Keys are generated; a holder's Desk re-creates inner wraps only to the restored ACL (keys verified against the Key Directory, blinded COI tags respected) and re-uploads `K_meta` fields; C-10 rejects wraps to non-ACL keys; other holders detect any deviation on sync; a case in the erasure log is purged from every Desk cache and never re-wrapped; the Desk cache is hardware-sealed and has no export API | 19 RT-5 in the lab plus negative cases (rogue Desk adds a key; excluded user; erased case in cache; approval by one admin only); keystore inspection | Weekly (DR lab), RC; yearly RT-5 | Yes |
| ST-176 | MANAGED customer-held audit export key (ADR-047(10)) | In MANAGED every audit export (CASE and all exported classes) is encrypted to the customer-held audit export key before leaving Z-CORE; no vendor host, backup or support bundle holds its private key; the vendor-side store contains only ciphertext; a vendor-initiated export cannot be re-targeted to a vendor key without customer OVERSIGHT approval | MANAGED lab profile; secret-placement scan (ST-121) for the private key; vendor-side decrypt attempt; config change attempt from vendor admin | Weekly, RC (MANAGED) | Yes (MANAGED) |
| ST-177 | Per-locale passphrase wordlists (ADR-047(6)) | Every shipped wordlist has a signed review record, no duplicates after normalization, and a word count per passphrase of `ceil(128 / log2(list_size))` (EFF large list: 10); generation draws uniformly (CSPRNG) from the selected list; passphrases are NFKC-normalized, lowercased and single-spaced before derivation on every client and the sealer (identical KDF input across platforms); the wordlist language is not transmitted or stored server-side | Static check of each list (size, duplicates, normalization collisions); χ² uniformity over 10⁶ generations; cross-platform normalization vectors (combining characters, full-width, mixed case, multiple spaces); request and DB capture show no locale indicator tied to the passphrase | PR (if a list changes), nightly, RC | Yes |
| ST-178 | IDENTIFIED over onion: identity sealing (ADR-047(5)) | When a source chooses IDENTIFIED mode over the onion service, identity details are sealed only as the IDENTITY object to the Identity Custodian key (Sealed Identity Store, ADR-014), never to epoch or case keys, never shown in the case view, and the case mode is recorded as IDENTIFIED; switching back before submission removes the identity block from sealer RAM | Tier W and Tier V submissions in each mode; envelope/object inspection with lab custodian and member keys; case-view render test; sealer RAM inspection (lab instrumentation) after mode switch | Nightly, RC | Yes |

## 15. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| SECT-001 | The project SHALL maintain the ST catalogue in this document as the authoritative list of security tests; each test SHALL have an owner, an executable job name and a gating classification. | B-CR-47 | THR-024 | C-31 | INSP: catalogue vs CI job inventory (`st-inventory` job fails on unmapped IDs) |
| SECT-002 | The CI gating matrix in §4 SHALL be implemented as code, and any change to gating SHALL require Security Lead approval. | B-CR-47 | THR-024 | C-31 | TST: `gating-policy` check comparing pipeline config with matrix; INSP |
| SECT-003 | No test environment SHALL contain real submissions, real source passphrases, real staff credentials or production backups; lab keys SHALL be marked TEST-ONLY and rejected by production builds. | INC-56; INC-60 | THR-015; THR-016; THR-013 | C-31 | TST: ST-028 TEST-ONLY rejection; INSP: environment data inventory |
| SECT-004 | The candor-lab environment SHALL model all zones of ADR-009 with separate VMs and SHALL use a private chutney Tor network for deterministic onion tests. | ADR-009; B-AN-26 | THR-001; THR-014 | C-05; C-09 | INSP: lab topology definition; DEMO |
| SECT-005 | Cryptographic KAT, Wycheproof and property tests (ST-020..ST-025, ST-028, ST-029, ST-031..ST-034) SHALL pass on every PR and release. | B-CR-07; B-CR-14; INC-51; REQ-H-51 | THR-012 | C-11 | TST: ST-020..ST-025, ST-028, ST-029, ST-031..ST-034 |
| SECT-006 | Key commitment and context binding SHALL be tested with constructed multi-key ("invisible salamander") ciphertexts. | B-CR-16; B-CR-17 | THR-012; THR-037 | C-11 | TST: ST-025 |
| SECT-007 | Constant-time behaviour of T0 secret-dependent operations SHALL be tested statistically on pinned hardware before each release. | INC-64; REQ-H-64 | THR-012 | C-11; C-07 | TST: ST-026 |
| SECT-008 | Formal protocol models SHALL be re-verified in CI whenever protocol code or model files change and before each release. | ADR-006; REQ-H-63; B-CR-25 | THR-012 | C-11 | TST: ST-030 |
| SECT-009 | Every parser of externally influenced data in T0/T1 SHALL have a cargo-fuzz target listed in §7; a new parser without a target SHALL fail review. | B-SD-35; B-OS-02 | THR-023; THR-032; THR-014 | C-06; C-07; C-09; C-10; C-11; C-14; C-15; C-17 | TST: `fuzz-coverage-map` job maps parsing modules to targets; INSP |
| SECT-010 | Fuzz targets SHALL run continuously (ClusterFuzzLite, OSS-Fuzz when accepted), and new crashes SHALL be triaged within 2 business days. | B-CR-52 | THR-023; THR-032 | C-31 | TST: ST-056 dashboard SLA report; INSP |
| SECT-011 | Every fuzz crash and every security bug SHALL add a permanent regression input or test executed in ST-001. | B-SD-28 | THR-023 | C-31 | TST: ST-012 mapping; corpus replay job |
| SECT-012 | The authorization matrix test SHALL cover every route × audience × role × tenant × ACL × COI state using an independently written oracle. | B-GL-37; B-SD-20; ADR-029 | THR-021; THR-020; THR-018 | C-10; C-22; C-21 | TST: ST-060; coverage report must list 100% of routes |
| SECT-013 | Cross-tenant isolation SHALL be tested by byte-level snapshot comparison of an untouched tenant after all actions in another tenant. | B-GL-37; ADR-021 | THR-045; THR-021 | C-10; C-12 | TST: ST-062 |
| SECT-014 | Token audience and revocation SHALL be tested with a cross-context replay matrix under multi-worker concurrency. | B-SD-20; ADR-029 | THR-021; THR-022 | C-06; C-10; C-21 | TST: ST-065 |
| SECT-015 | The malicious-server harness SHALL exercise every applicable mutation strategy against every field of every server response consumed by C-15, C-03, C-09 and the C-15↔C-17 bridge, with 100% field×strategy coverage nightly. | ADR-027; B-SD-28; B-SD-33; B-SD-35; B-SD-36 | THR-014; THR-023; THR-046; THR-007 | C-15; C-03; C-09; C-17 | TST: ST-090..ST-097 coverage report |
| SECT-016 | Harness runs SHALL monitor the whole client filesystem, network and process tree, and SHALL fail on any write outside documented paths, any non-pinned connection, or any unexpected exec. | B-SD-33; B-SD-36 | THR-023; THR-014 | C-15; C-03 | TST: ST-090; ST-092; harness self-test with planted violation |
| SECT-017 | Upload and multipart policy SHALL be verified at the stream layer with filesystem monitoring proving no bytes persist before policy checks. | B-OS-02 | THR-032; THR-023; THR-047 | C-06; C-07 | TST: ST-082; ST-043 |
| SECT-018 | Weaponized-document containment SHALL be tested each release with a maintained corpus of known parser-exploit PoCs, updated within 30 days of new relevant CVEs in C-17 components. | B-CR-44; B-CR-56 | THR-023 | C-17 | TST: ST-084; INSP: corpus changelog |
| SECT-019 | Resilience tests (DB corruption, power loss, network interruption, storage failure, clock manipulation, OOM, upgrade failure) SHALL verify fail-closed outcomes with no plaintext or metadata spill. | THR-043; ADR-025 | THR-042; THR-043; THR-014; THR-017 | C-07; C-08; C-09; C-10; C-12; C-13 | TST: ST-102..ST-107, ST-109, ST-111 |
| SECT-020 | Backup restore SHALL be tested weekly (automated) and quarterly (full manual drill), including restore-without-keys and crypto-erased-case checks. | INC-55; ADR-025 | THR-017; THR-015; THR-042 | C-27 | TST: ST-108; DEMO: quarterly drill report |
| SECT-021 | Core-dump prohibition SHALL be tested for every key- or plaintext-handling service unit. | REQ-H-58; INC-58 | THR-013; THR-016 | C-07; C-10; C-15; C-03 | TST: ST-110 |
| SECT-022 | The config checker SHALL be tested for 100% coverage of the configuration schema, including every DANGEROUS option. | B-GL-37; ADR-013 | THR-035 | C-19; C-25 | TST: ST-120 coverage check |
| SECT-023 | Secret placement SHALL be tested on every deployment profile and on all DANGEROUS flags plus pairwise feature-flag combinations each night, and the full cross-product weekly. | ADR-028; B-SD-22 | THR-013; THR-035 | C-05; C-25; C-27 | TST: ST-121 |
| SECT-024 | Security headers and transport configuration SHALL be tested against deployed artefacts (not development servers), including over the onion service. | B-GL-39 | THR-008; THR-036 | C-06; C-37; C-38 | TST: ST-074 |
| SECT-025 | SSRF defences SHALL be tested for every admin-configurable outbound URL, including DNS rebinding and redirects. | B-GL-16; B-SD-36 | THR-021; THR-030 | C-23; C-21; C-26; C-10 | TST: ST-076 |
| SECT-026 | Update-client rejection behaviour SHALL be tested against a rogue repository covering unsigned, under-threshold, expired, rollback, freeze, mix-and-match and unlogged metadata. | INC-49; ADR-022; B-CR-45 | THR-025 | C-32; C-33 | TST: ST-130 |
| SECT-027 | A pre-release external pentest SHALL be completed on each major release candidate (and on minors adding attack surface per 37) with no open Critical/High findings at signing. | B-SD-28; B-SD-40; B-GL-18 | THR-021; THR-023; THR-014; THR-001 | C-06; C-10; C-15; C-03; C-17 | AUD: pentest report (37); TST: ST-140 status in SG-22 |
| SECT-028 | Mutation testing SHALL maintain mutation scores ≥90% for the authorization policy crate and ≥85% for the `candor-core` API layer. | B-GL-37 | THR-021; THR-012 | C-22; C-11 | TST: ST-015 |
| SECT-029 | Test results for every release SHALL be archived in the signed gate-evidence bundle, and a public summary (pass/fail per ST group, exceptions) SHALL be published. | B-CR-47 | THR-024 | C-32 | INSP: release page; TST: bundle signature verification |
| SECT-030 | Every test in this catalogue that is marked gating SHALL block the corresponding stage; a test SHALL NOT be disabled or marked flaky-skip on `main` for more than 7 days without Security Lead approval recorded in the exception register. | B-CR-47 | THR-024 | C-31 | TST: `quarantine-age` job; INSP: exception register |
| SECT-031 | (amended r3) Every control introduced by ADR-034..ADR-047 SHALL have at least one gating enforcement test in §14A (ST-143..ST-166, ST-168..ST-178) that fails closed on violation; a later ADR that adds a control SHALL add its test in the same change. | ADR-034; ADR-035; ADR-036; ADR-037; ADR-038; ADR-039; ADR-040; ADR-042; ADR-043; ADR-044; ADR-045; RVW-B-29 | THR-014; THR-018; THR-020; THR-025; THR-046 | C-07; C-10; C-14; C-15; C-22; C-25 | TST: ST-143..ST-166; INSP: `st-inventory` maps each ADR-034..046 decision item to ≥ 1 ST/AT ID |
| SECT-032 | Tier W draft state, attachment staging and the source passphrase SHALL be verified never to reach persistent storage, including after sealer crash, OOM kill and power loss, and tmpfs staging SHALL be verified empty after each session end and before the sealer accepts sessions after restart. | ADR-034; RVW-A-02; RVW-B-12 | THR-014; THR-015; THR-034 | C-06; C-07; C-08 | TST: ST-143; ST-145; AT-076 |
| SECT-033 | Key Directory governance (high-water mark, independent time floor, time-locks, dual approval with an independent role, witness cosignatures, role-label certification, weekly publication slot) SHALL be tested against a hostile Z-CORE including clock manipulation of Z-CORE only. | ADR-036; RVW-A-04; RVW-A-05; RVW-A-08; RVW-C-05 | THR-046; THR-043; THR-020 | C-07; C-14; C-03; C-15 | TST: ST-149..ST-152 |
| SECT-034 | Triage-first routing and blinded COI storage SHALL be tested so that a non-triage member can neither list, decrypt nor be notified of intake envelopes, and so that no stored row or event distinguishes a COI exclusion from other removals. | ADR-037; RVW-B-01; RVW-B-02 | THR-020; THR-018; THR-038 | C-07; C-10; C-12; C-22; C-23; C-24 | TST: ST-146; ST-147; AT-069; AT-084 |
| SECT-035 | The Platform Manifest, security floor, operator-statement expiry banner and external-watcher mismatch detection SHALL be tested with injected divergence on every release candidate; the Confidential-VM attestation verifier SHALL be tested on every release that offers the TEE profile. | ADR-035; ADR-040; RVW-A-01; RVW-A-12; RVW-A-13 | THR-007; THR-014; THR-025; THR-026 | C-06; C-07; C-25; C-32; C-33; C-34 | TST: ST-153..ST-156 |
| SECT-036 | Erasure Key Vault restore SHALL be tested to apply the signed erasure log before serving keys, including restore from a vault backup older than the most recent erasure and from a backup ≥ 15 days old, and the backup-exclusion attestation checker SHALL be tested in every profile. | ADR-044(4); RVW-C-06; RVW-C-07 | THR-017; THR-042 | C-12; C-25; C-27; C-39 | TST: ST-158; ST-159; ST-108 |
| SECT-037 | The malicious-server harness SHALL include a hostile-string corpus for every string rendered in the Desk webview, and a cargo-fuzz target for Desk string validation/rendering SHALL be listed with the §7 targets. | ADR-042; RVW-A-15 | THR-023; THR-014 | C-15; C-17 | TST: ST-160; ST-090 coverage report |
| SECT-038 | Viewer containment SHALL be tested on every supported Desk platform tier, and Desk SHALL be verified to refuse originals where no hardware-isolated viewer is available. | ADR-042; RVW-A-15 | THR-023; THR-041 | C-15; C-17 | TST: ST-161; ST-084 |
| SECT-039 | A spec-constant consistency lint SHALL block any change that introduces a divergent value, in any spec, configuration default, code constant or test fixture, for a constant held in the canonical registry, or that reintroduces a superseded variant. | RVW-B-07; RVW-B-29; RVW-A-21; ADR-046 | THR-011; THR-035; THR-039 | C-30; C-31 | TST: ST-167; AT-083 |
| SECT-040 | Crash reporting of the Candor Desk main and webview processes SHALL be verified disabled on every supported Desk platform, with no dump containing case content leaving the host. | RVW-C-11; REQ-H-58; INC-58 | THR-016; THR-013 | C-15; C-16 | TST: ST-110 |
| SECT-041 | The ADR-047 controls SHALL be tested as specified in §14A.8: chaff generation, format identity and discard at import (ST-168, ST-169); per-case metadata erasure (ST-170); Source App vault (ST-171); Key Directory and attestation freshness (ST-172, ST-173); intake deletion list after DR and failover (ST-174); Desk re-wrap after vault loss (ST-175); MANAGED customer-held audit key (ST-176); per-locale wordlists (ST-177); IDENTIFIED-over-onion identity sealing (ST-178). | ADR-047; RVW-B-04; RVW-A-28; RVW-B-21; RVW-C-07 | THR-020, THR-017, THR-048, THR-046, THR-027, THR-034, THR-040 | C-03, C-07, C-08, C-09, C-10, C-12, C-15, C-24 | TST: ST-168..ST-178 |

## 16. Residual risks and limitations

- **Oracle quality.** The authorization-matrix oracle (ST-060) is written from the policy specification. If 15 is wrong, the tests encode the error. Independent pentests (ST-140) and red teams (ST-141) are the counter-check.
- **Coverage ≠ correctness.** 100% field×strategy harness coverage does not cover combinations of mutations or stateful sequences beyond the scenario library.
- **Constant-time tests are statistical** and hardware-specific. Results on the CI runner may not hold on all customer CPUs.
- **Formal models abstract the implementation.** Gaps between model and code are closed only partially, by KATs and review. Verified implementations (hax/F*) are future work (37).
- **Weaponized corpus** covers only known exploit classes. Zero-days in C-17 parsers are contained by isolation, not detected by tests.
- **Lab ≠ production.** chutney does not reproduce real Tor network conditions. E4 smoke tests are limited. Production-only misconfigurations are caught by the C-25 self-test and external probes (32), not by this suite.
- **Model-bound revision tests.** ST-155 proves the reference watcher detects divergence it can observe; a compelled operator serving modified content only to a targeted circuit is caught only probabilistically (sampling) and only for static assets, headers and the signed running manifest, not for a modified binary that reports the correct manifest without a TEE. ST-156 verifies attestation *verification logic*; it cannot test for TEE side-channel breaks, which remain a residual recorded in 40.
- **Governance tests assume honest independent roles.** ST-150/ST-164 prove that the software requires an independent approver; they cannot detect an independent role that colludes or is itself captured (RVW-C-05 residual).
- **ST-159 checks an attestation, not the hypervisor.** Infrastructure backups outside the guest cannot be observed by Candor; a false attestation defeats the 14-day deletion bound (ADR-044(4) honest limit).
- **Tier 2 viewer platforms.** Hyper-V and Virtualization.framework isolation is tested for the absence of NIC/shares/clipboard, not for hypervisor escape.
- **ST-167 catches only registered constants.** A new parameter that nobody registers can still diverge; review (27) must add it to the registry.
- **Performance of the full suite**: the RC pipeline is expected to take about 24–36 hours, dominated by fuzzing and resilience tests. Emergency releases may use the reduced set allowed by 27 §13.2. Non-waivable gates always run.

## 17. Open issues

1. Choose the independent oracle implementation language and team for ST-060, which must differ from C-22 implementers.
2. Check the availability of Wycheproof-style vectors for ML-KEM/ML-DSA/X-Wing (2026). Until they exist, rely on ACVP-format and draft vectors.
3. Decide whether macOS and Windows Desk builds can run the full fanotify-equivalent harness monitoring. Candidate substitutes: Endpoint Security framework on macOS, ETW on Windows.
4. Budget and hardware for ST-026 pinned-hardware runners, and the number of CPU families to cover.
5. Define E4 staging onion key handling so that lab onion addresses are never confused with production (naming and TUF channel separation).
6. TEE-capable CI runners (SEV-SNP/TDX) for ST-156; until available, fixture-mode results are reported as reduced coverage.
7. **Closed (ADR-047(4)):** snapshot freshness 7 days and attestation refresh 24 h are registry constants (ST-172, ST-173).
8. Watcher sampling rate for selective-serving detection (ST-155) needs a statistical target agreed with 16/32.
9. The chaff discard mechanism at import (how chaff is recognised without weakening indistinguishability) is owned by `04-CRYPTOGRAPHY.md`/`07-BACKEND.md`; ST-169 tests the observable outcome and must be refined when the mechanism is final.

### Open Issues for ADR revision
- None blocking; conforms to DECISIONS.md incl. ADR-034..047. The snapshot freshness bound is now fixed by ADR-047(4).
