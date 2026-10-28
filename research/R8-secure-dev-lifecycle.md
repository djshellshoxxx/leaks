# R8 — Secure Development Lifecycle: How High-Assurance Privacy Projects Build and Ship

*Research note for Candor (Rust services, Tor onion intake, Tauri "Candor Desk", PostgreSQL). As of 2026-10-01.*

**Method and caveats.** I used primary sources where the egress proxy allowed. I read a shallow clone of `freedomofpress/securedrop-dev-docs` (last commit 2026-09-28): release management, reproducible builds, dependency updates (including the cargo-vet policy) and the contributor guidelines. I also used web-search extracts of primary pages: Chromium `rule-of-2.md`, NIST CSRC, the Tails release-process and reproducibility pages, Qubes code-signing docs, the Tauri v2 ACL docs, Cryspen posts, GitHub/NVD/MITRE advisory text, and the ETH Zurich Threema paper page. The proxy blocked sonarsource.com, nvd.nist.gov, osv.dev, advisories.gitlab.com, globaleaks.org and the GitHub advisory API for repos not attached to this session. For those, the facts come from search-engine extracts of the primary page, and I flag this where it matters. Anything I could not confirm against a primary source this session is marked **UNVERIFIED**. Citations use the form [B-SL-xx] (bibliography at the end).

**How to read this note.** Each topic follows the pattern **lesson → concrete rule for Candor (`SL-R-nnn`) → verification**. The rules are written as deltas against `specs/27-SECURE-DEVELOPMENT.md`, `28-SUPPLY-CHAIN.md`, `29-SECURITY-TESTING.md` and `33-RELEASE-UPDATE-SECURITY.md`. Spec 27 already covers most baseline practice: tiers, a review matrix, the crypto checklist, the `unsafe` policy, gates SG-01..SG-29 and the safefs/HTTP/identity rules. This note does not restate it. Where a lesson is already covered, the note says **"covered: 27 §x"** and adds only what is missing. The milestone column refers to RM-0..RM-12 in `38-IMPLEMENTATION-ROADMAP.md`.

---

## 0. Executive summary: new rules this research adds

| ID | Rule (short) | Driven by | Milestone |
|---|---|---|---|
| SL-R-001 | **Validate-then-write.** No byte from an untrusted peer touches a filesystem path until the name/size has been validated. Downloads land in an anonymous `O_TMPFILE`/memfd and are linked into place only after validation. | SecureDrop CVE-2025-24888 | RM-1 (safefs), RM-4 |
| SL-R-002 | **Sanitize last, render inert.** No DOM/HTML mutation after sanitization. Untrusted content in the Desk is rendered as text nodes, or as images produced by the Viewer, never as HTML. | Proton 2022, Signal-Desktop 2018, Wire 2021-22 | RM-4 |
| SL-R-003 | **Sign the bytes you verified.** Trust decisions bind to full key bytes/fingerprints carried in a `Verified<T>` typestate, never to an identifier looked up again later. | Matrix CVE-2022-39250 | RM-1, RM-4 |
| SL-R-004 | **Proof TCB inventory.** Every claim that something is "formally verified" lists its admitted modules, assumed specs and unverified fallbacks, per target architecture. CI runs KATs and cross-backend equality on every shipped arch (x86_64, aarch64). | libcrux GHSA-2cgv-28vr-rv6j and the 2026 spec-mismatch critique | RM-1 |
| SL-R-005 | **No compression of secret-bearing data before encryption** unless the output is padded to a fixed size class. | Threema backup side channel | RM-1, RM-5 (backups) |
| SL-R-006 | **Mutation testing on T0/T1 validation and authz code** (`cargo-mutants`). Surviving mutants in loops over sets/recipients/slots block merge. | Let's Encrypt CAA 2020 | RM-1 → |
| SL-R-007 | **Strict CSP that is tested, not just declared.** CSP is evaluated in CI and a known-bypass corpus is run against it. Security-setting changes require step-up auth. | Hush Line CVE-2024-38522/-38523/-55888 | RM-2, RM-4 |
| SL-R-008 | **No OS-handoff surface in the Desk.** No custom URI scheme handler, no `shell:open`/`opener` capability, no "open externally" for any attacker-influenced string. | Element-Desktop CVE-2022-23597, Tutanota 2022 | RM-4 |
| SL-R-009 | **Dependency cooldown.** Non-security dependency upgrades wait 7 days after upstream publication. Trusted cargo-vet imports and trusted publishers expire every 6 months. | SecureDrop dependency policy 2025-26 | RM-0 |
| SL-R-010 | **Two-party release ceremony with an independent reviewer.** The tag is signed offline. A *different* person verifies the build logs and signs the repository metadata (TUF targets/snapshot). Reproduction by the second builder happens *before* signing. | SecureDrop and Tails release processes | RM-0, RM-7 |
| SL-R-011 | **Key-type separation in the type system.** A key for one sub-protocol cannot be passed where another is expected (newtype per role and per label). One HPKE/HKDF `info` registry, unique per role. | Threema cross-protocol attack, Ed25519 double-pubkey oracle | RM-1 |
| SL-R-012 | **No table-based software AES/GHASH, and no secret-indexed tables, in any backend.** dudect on every backend. | libolm CVE-2024-45191 | RM-1 |
| SL-R-013 | **LLM-adversary audit pass before each external audit.** Run an internal LLM-assisted code audit and close its findings before A1–A4, so that paid auditors spend their time on design. | GlobaLeaks/ISGroup 2026 | RM-6 |
| SL-R-014 | **Regression test per advisory, written before the fix** (red→green evidence in the PR). | SecureDrop R-AUDIT practice (extends SG-21) | all |
| SL-R-015 | **Interop/conformance suites, not only own tests.** HPKE/X-Wing/ML-KEM run against Wycheproof plus C2SP CCTV vectors plus a second implementation (differential). | rustls BoGo, Wycheproof | RM-1 |

---

## 1. Engineering process at comparable projects

### 1.1 SecureDrop (Freedom of the Press Foundation)

Observed practice, from the dev docs clone, commit 2026-09-28 [B-SL-01..05]:
- **Code review:** every change in any repository goes through a PR. "There must not be any unreviewed changes in the pull request at the time of approval." A component reviewed outside a PR must have a review record in an issue titled "code review" [B-SL-02].
- **Release:** an RC is cut first; QA and signing ceremonies never start before an RC exists. Each release gets a **test plan** focused on new functionality, published in the wiki, plus a **QA matrix** copied from the previous release. QA runs on production VMs and hardware [B-SL-01].
- **Signing ceremony:** release commits are GPG-signed (`git commit --amend --gpg-sign`). The final tag is prepared unpushed, and the tag file goes through an offline **signing ceremony**. The detached signature is appended (`cat x.tag.sig >> x.tag`) before the signed tag is made, verified and pushed [B-SL-01].
- **Packages:** a packaging PR uploads to `apt-qa.freedom.press`. **"A reviewer must verify the build logs, obtain and sign the generated `Release` file, and append the detached signature to the PR."** A reviewer, not the author, merges the PR, which publishes to the production apt repo [B-SL-01].
- **Reproducible builds:** containerized, minimal build environments. Build metadata is published. Wheels are built at a fixed path. **diffoscope** is used, and reprotest is being phased out in favour of "repeating builds twice, in parallel, and diffoscoping the result". The docs openly list what is *not* reproducible (`securedrop-app-code`, kernel) [B-SL-03].
- **Dependencies:** a review is required before adding a dependency. Upgrades are risk-ranked; "highest scrutiny" packages get a **manual diff review with diffoscope**, posted publicly. **7-day cooldown** for non-security upgrades. Rust uses **cargo-vet**: own audits default to `safe-to-run`, and `safe-to-deploy` is used only with real expertise. Imported audits from other organisations are discussed case by case. Trusted publishers (Rust Project, Sequoia-PGP members) are trusted for **6 months**, then the trust must be renewed [B-SL-04].
- **Pre-release audits:** OTF-funded whitebox audit by 7ASecurity (May–June 2024) covering server, source, docs, **supply chain and package repositories** [B-SL-06].

| Lesson | Candor rule | Verification |
|---|---|---|
| The person who builds is not the person who signs repo metadata | **SL-R-010**: the TUF `targets` and `snapshot` roles are signed by a reviewer ≠ the release author, after reading the build logs and the second builder's diffoscope-clean attestation | 33 ceremony script refuses when signer identity = author identity; ceremony transcript in the transparency log |
| A written per-release QA plan focused on new functionality | Every minor/major release has `qa/<ver>/test-plan.md` generated from the PR labels `feature/*`, plus a QA matrix (profiles × platforms: CE-SINGLE, CE-HARDENED, Desk Linux/macOS/Windows) | SG gate addition "SG-QA": matrix 100% filled and signed off by the release manager |
| Admit what is not reproducible | `REPRODUCIBILITY.md` lists each artefact's status, with no hidden exceptions | SG-13 report enumerates every artefact in the SBOM |
| Cooldown and time-boxed trust | **SL-R-009** | `cargo vet` config: `[imports.*]` has an expiry; CI rejects a crate version published less than 7 days ago unless the PR is labelled `security-fix` (check via crates.io `created_at`) |

### 1.2 GlobaLeaks

- **Mandatory peer review** for all PRs. **CI on every commit** (GitHub Actions; Codacy for coverage and quality). Unit tests use Twisted trial and E2E tests use Cypress. The project publishes its **OpenSSF Best Practices** badge and **Scorecard** score [B-SL-07].
- **Audit cadence about every 2 years**, with all reports published: Cure53 2013, Least Authority 2014, Subgraph 2018, ROS 2019/2022, ISGroup 2024 and 2026 [B-SL-07][B-SL-08].
- **2026:** ISGroup ran a *source code audit under an "LLM-equipped adversary model"* (June 2026). It found 29 confirmed vulnerabilities (2 High, 0 Critical) and 12 DoS observations. Remediation started in v5.0.96 [B-SL-09] (secondary news source; the globaleaks.org post was blocked, so details are partly **UNVERIFIED**).

Lesson: attackers now have cheap LLM-assisted code review, so a project's own review must at least match it. → **SL-R-013**. Verification: an LLM-audit report attached to the RM-6 entry gate; every finding is closed or accepted before A1–A4 begin.

### 1.3 Tor Project / Arti

- Tor tarballs are signed by release managers and the hashes are published. Security issues use **TROVE** identifiers and a documented security policy. Arti is Rust and leans on `cargo-audit` and crate-level `forbid(unsafe_code)` where possible (**UNVERIFIED** for current per-crate coverage) [B-SL-10].
- Lesson for Candor: C-tor is an external dependency on the Trust Path. Pin the minimum version (PoW/vanguards) and follow TROVE advisories. → covered: 16/28. Add: subscribe CI to the Tor security advisory feed, and make "Tor version below floor" fail the config checker (ST-120).

### 1.4 Signal

- **libsignal** is Rust. Test vectors are kept in the repo, and the code is fuzzed. PQXDH had a formal analysis (ProVerif/CryptoVerif, Bhargavan et al. 2023/24) that found issues in the draft spec, which were fixed before deployment (**UNVERIFIED** details this session) [B-SL-11].
- **SPQR / Triple Ratchet (Oct 2025):** Cryspen built ProVerif models during design, because the engineers found ProVerif easy to read and write and the tool gives fast automatic feedback. The Rust code is verified with **hax → F\***. Models are **re-verified in CI on every change** [B-SL-12].
- **Reproducible Android builds:** Signal-Android ships a Docker-based reproducible build and an `apkdiff` comparison (**UNVERIFIED** current status) [B-SL-13].
- **Caution, same ecosystem:** libcrux (the ML-KEM used by SPQR) shipped **GHSA-2cgv-28vr-rv6j**. An *unverified* fallback for the aarch64 `vxarq_u64` intrinsic in `libcrux-intrinsics` 0.0.3 passed `b` instead of `a_xor_b`. That corrupted SHA-3, so ML-KEM produced wrong shared secrets and ML-DSA produced invalid signatures (CVSS v4 8.8, fixed in 0.0.4) [B-SL-14]. A 2026 public critique also says some "verified" modules were admitted, and that part of the F\* spec did not match FIPS 203 (third-party claims, contested by Cryspen; **UNVERIFIED**) [B-SL-15].

| Lesson | Candor rule | Verification |
|---|---|---|
| Write the formal model *before* the code and re-check it in CI | covered: 38 RM-003, 27 ST-030. Add: the model check runs on every PR touching `protocol/` or `candor-core/src/proto*`, and fails if any lemma changes status | CI job `formal-models` (Tamarin/ProVerif) as a required status |
| "Verified" ≠ verified on *your* platform | **SL-R-004**: `security/proof-tcb.toml` lists, per crate: verified functions, admitted lemmas, spec provenance, arch-specific fallbacks. A fallback with no proof needs a KAT + Wycheproof run *on that arch* | CI matrix runs the crypto test suites on x86_64 **and** aarch64 (native runners), plus a forced-portable-backend build; cross-backend differential test (`portable == avx2 == neon` output for 10⁶ random inputs) |

### 1.5 Let's Encrypt / Boulder

- **Incident (2020):** see INC-SL-08. Boulder took a reference to a Go loop iterator variable, so it re-checked one domain N times instead of N domains once. About 3M certificates were affected, and roughly 1.7M had to be revoked within days [B-SL-16].
- Boulder practice: service split by privilege (RA/VA/CA/SA). Pre-issuance linting (zlint). Public incident reports on Bugzilla. Many small Go services talking over gRPC with mTLS (**UNVERIFIED** current detail) [B-SL-17].

Lesson: bugs where a check is "applied to the wrong element" survive ordinary unit tests that use N=1. Rust removes the Go aliasing variant but not the logic class (for example, `iter().any()` vs `all()`, or checking `slots[0]` for every slot). → **SL-R-006**, plus property tests with N≥2 heterogeneous elements for every loop over recipients, slots, domains or authz subjects.

### 1.6 Tails

- The release process includes "verify that Jenkins reproduced the images" **and** the IUKs (incremental upgrade kits). The Git tag is verified against the Tails signing key. A separate reproducibility page lets anyone verify an image [B-SL-18].

Lesson: reproduce **every** shipped artefact, delta updates included, before publishing. → Candor: SG-13 applies to TUF delta/patch targets and to installer bundles, not only to full packages. Verification: the SG-13 report lists every TUF target hash, and each one is reproduced by builder B.

### 1.7 Qubes OS

- A **code-signing policy** requires every commit or tag to be signed. A bot (`policy/qubesos/code-signing`) reports "No signature found" or "Unable to verify". Signed tags can cover a range of unsigned history [B-SL-19]. qubes-builder verifies signed tags before it builds.

Lesson: the build system verifies the signature on its input, not just the forge UI. → Candor: builder A and builder B both run `git verify-tag` against a pinned maintainers keyring (and Sigstore gitsign, if used) **inside** the hermetic build, and record the result in the provenance. Covered in part by SG-02. Add the "builder verifies input" step to 28.

### 1.8 WireGuard

- About 4k lines of kernel code and deliberately no cipher agility. The protocol was verified symbolically (Tamarin, Donenfeld & Milner) and computationally (CryptoVerif, Lipp–Blanchet–Bhargavan, IEEE EuroS&P 2019). The kernel Curve25519 is formally verified code (HACL\*/fiat-crypto) (**UNVERIFIED** this session; widely documented) [B-SL-20].

Lesson: minimal code and a single suite make verification feasible. → Candor: CANDOR-STD-1 is the **only** suite on the CE path. CANDOR-FIPS-1 is a separate build feature, never negotiated at runtime (covered: 04/27 §11.3 item 9). Add a **LoC budget**: `candor-core` protocol logic (excluding primitives) stays ≤ 5k SLOC, and any increase needs a Crypto Reviewer note. Verification: a `tokei` check in CI.

---

## 2. Crypto implementation practice

### 2.1 How the reference libraries structure code

| Library | Pattern | Candor adoption |
|---|---|---|
| **age** (Go, and rage in Rust) | No options or agility. The header is MACed with a key derived from the file key, which gives key commitment over the header. 64 KiB STREAM chunks with a last-chunk flag. Spec at C2SP. Shared test vectors (CCTV `age` testkit) are used across implementations [B-SL-21] | Candor envelope v1 runs the CCTV-style testkit pattern: a corpus of *invalid* envelopes (bad MAC, truncated, reordered, extra chunk, wrong last-flag, non-canonical encodings), each with an expected error class. Shared by the Rust core and any second implementation |
| **libsignal** | Rust core with thin language bindings. Protocol state is held in typed records. Errors are explicit enums (**UNVERIFIED** detail) [B-SL-11] | All bindings (Desk TS via Tauri commands) expose only high-level operations (`seal_reply`, `open_submission`). No raw-key APIs cross the IPC boundary |
| **rustls** | Small state machine with typed states. Crypto is behind a `CryptoProvider` trait (aws-lc-rs/ring). Runs Google's **BoGo** TLS conformance suite plus OpenSSL interop. The Cure53 2020 audit of rustls/ring/webpki found only 4 minor issues [B-SL-22] | **SL-R-015**: an external conformance corpus for every primitive, plus a differential test against a second independent implementation (for example RustCrypto `hpke` vs aws-lc-rs HPKE, or `ml-kem` vs libcrux) |
| **Wycheproof** (now under C2SP) | Edge-case and known-attack vectors, now including ML-KEM/ML-DSA; Go's `crypto/mlkem` consumes them [B-SL-23] | covered: ST-020..025. Add: pin the Wycheproof commit in `supply-chain/` and refresh it each release. A new vector failure blocks the release |
| **hax / libcrux / Tamarin / ProVerif** | Models are checked in CI. Rust is extracted to F\*. Lesson from §1.4: the proof TCB must be audited | SL-R-004 |

### 2.2 API misuse resistance in Rust: concrete patterns

1. **Typestate for protocol phases.** `Envelope<Sealed>` → `Envelope<Opened>`. Only `Opened` exposes plaintext, and only `open()` constructs it. Pattern from rustls and libsignal. Test: `trybuild` compile-fail tests showing that, for example, `Envelope<Sealed>::plaintext()` does not compile.
2. **Newtypes per key role** (SL-R-011): `IntakeKemPk`, `CaseWrapKey`, `DirectorySigningKey`, `ReplyKemPk`, … with no `From`/`AsRef<[u8]>` between them. HKDF labels are an `enum Label` with `const fn bytes()`, and a unit test asserts all labels are unique and prefix-free.
3. **Keypair-only signing API.** `sign(&self: &SigningKeyPair, msg)`. Never `sign(sk, pk, msg)`, because accepting a caller-supplied public key enabled private-key recovery in about 40 Ed25519 libraries (the 2022 "double public key" oracle; **UNVERIFIED** count) [B-SL-24].
4. **Validated public-key deserialization.** `IntakeKemPk::from_bytes` performs length, canonical-encoding and (for X25519/X-Wing) non-zero-shared-secret checks per HPKE/RFC 7748 §6.1. ML-KEM ek runs the FIPS 203 modulus check. Invalid keys are unrepresentable afterwards. Test: Wycheproof `x25519` low-order vectors, and ML-KEM invalid-ek vectors.
5. **Nonces not exposed.** STREAM nonces are derived internally (counter ‖ last-flag) from a per-message random key. The public API takes no nonce parameter. Test: property test that 10⁵ seals of identical plaintext give distinct ciphertexts; grep lint banning `Nonce::from` outside `candor-core::aead`.
6. **No plaintext before authentication.** STREAM `open` yields a chunk only after its tag verifies, and the final chunk must carry the last-flag (truncation). Desk/Viewer never stream unauthenticated bytes to a parser. Test: truncation and reorder corpus.
7. **Uniform errors.** `open()` returns one `DecryptError::Invalid` with no sub-cause across the boundary. Internal diagnostics go only to a debug build. This prevents padding- or format-oracle distinctions. Test: AT/ST timing-and-size equality on error classes.

### 2.3 Common implementation bugs → Candor control

| Bug class | Known instance | Control | Test |
|---|---|---|---|
| Nonce reuse (GCM forbidden attack) | 184 HTTPS hosts repeating GCM nonces (Böck et al., WOOT 2016; **UNVERIFIED** count) [B-SL-25] | Pattern 5; XChaCha/derived nonces; FIPS profile uses counter nonces with a per-key message cap | Nonce-uniqueness property test; FIPS cap test |
| Key/ID confusion | Matrix CVE-2022-39250 (INC-SL-04) | SL-R-003, pattern 2 | Malicious-server harness case: same ID, different key |
| Missing key separation | Threema cross-protocol attack (INC-SL-05) | SL-R-011 | Label-uniqueness test; Tamarin lemma for cross-protocol |
| Compression oracle | Threema backup (INC-SL-05) | SL-R-005 | Lint banning `flate2`/`zstd` in T0 crates except the padded-export path |
| Cache-timing | libolm AES (INC-SL-06) | SL-R-012 | dudect per backend (ST-026 extended) |
| Unverified fallback | libcrux (INC-SL-07) | SL-R-004 | Multi-arch CI, differential |
| Padding/format oracle | Classic Vaudenay/Lucky13 | Pattern 7; AEAD only, no CBC anywhere | Error-uniformity test |
| Untrusted key deserialization | Invalid-curve / low-order points | Pattern 4 | Wycheproof low-order vectors |

---

## 3. Incident catalogue: implementation-level failures in privacy tools

Each block lists the INCIDENT, the ROOT CAUSE, the CODING PRACTICE THAT PREVENTS IT and the TEST.

**INC-SL-01 — SecureDrop Client CVE-2025-24888 (malicious server → code execution in `sd-app`)** [B-SL-26]
- ROOT CAUSE: `download_reply()` took the filename from the server's `Content-Disposition` header and **wrote the file first**. `safe_move()` later detected the traversal and failed, but the file stayed where the attacker chose (for example `~/.config/autostart/`). It was a check-after-use problem.
- PRACTICE: **SL-R-001.** Untrusted names are never used for any write. Content goes to `memfd`/`O_TMPFILE` in a private dir. The final name is Candor-generated (content-addressed), and the server-supplied name is metadata only.
- TEST: in the malicious-server harness (ST-090..097), the server returns `Content-Disposition: filename="../../.config/autostart/x.desktop"` and variants (absolute path, NUL, overlong, Unicode dot). Assert that no new inode appears anywhere outside the store (inotify on `$HOME`), not only that the move failed.

**INC-SL-02 — SecureDrop sd-log CVE-2025-24889 (VM → sd-log code execution via a log path)** [B-SL-27]
- ROOT CAUSE: the destination path used the VM name *as reported by the sending VM*, not the Qubes-provided `QREXEC_REMOTE_DOMAIN`.
- PRACTICE: identity from the transport (covered: 27 §12.5 Identity row).
- TEST: ST-097 as specified, plus a fuzzed "self-reported identity" field that must be ignored.

**INC-SL-03 — SecureDrop proxy CVE-2026-49996 (cross-origin redirects bypass origin restriction), and a gzip-extraction absolute-path bug (≤0.17.4; CVE ID UNVERIFIED)** [B-SL-28]
- ROOT CAUSE: the HTTP client followed redirects by default. The archive extractor accepted absolute member paths.
- PRACTICE: covered: 27 §12.5 HTTP-client and Filesystem rows. Add: the archive reader is a Candor-owned allow-list extractor that rejects members with absolute paths, `..`, symlinks, hardlinks or device nodes, and members over the limits *before* writing.
- TEST: a corpus of malicious tar/gzip/zip archives (zip-slip set) in ST-04x fuzz seeds; assert zero writes outside the target.

**INC-SL-04 — Matrix "Nebuchadnezzar" CVE-2022-39250 (matrix-js-sdk)** [B-SL-29]
- ROOT CAUSE: the SDK checked a device or identity and then signed it in **two steps that referenced the key by ID**. A malicious homeserver could swap in its own cross-signing identity in between. A protocol design choice (identities stored as devices whose ID equals the key) made the IDs ambiguous.
- PRACTICE: **SL-R-003.** `verify()` returns `Verified<DirectoryEntry>` that holds the exact key bytes. `sign()` and `trust()` accept only `Verified<…>`. IDs are never re-resolved after verification. ID namespaces are disjoint by construction.
- TEST: malicious-server harness case where the key-directory response changes the key behind an unchanged ID between two calls; assert hard failure. A `trybuild` test shows that `trust()` will not compile with an unverified entry.

**INC-SL-05 — Threema (ETH Zurich, USENIX Security 2023): 7 attacks** [B-SL-30]
- ROOT CAUSE: (a) no key separation between sub-protocols, which enabled a cross-protocol authentication break; (b) **compression before encryption** in backups, which let the backup size leak the long-term private key.
- PRACTICE: SL-R-011 and SL-R-005. Also: export packages and backups pad to size classes (covered: padding in 04/19). There is no user-controlled data adjacent to secrets inside a compressed stream.
- TEST: a Tamarin lemma that no message of sub-protocol A is accepted as B. A unit test that backup ciphertext size is independent of secret-key bytes (vary the key, keep the payload fixed; sizes must be equal).

**INC-SL-06 — libolm AES cache-timing CVE-2024-45191 (and related CVE-2024-45192/45193), libolm deprecated in favour of vodozemac (Aug 2024)** [B-SL-31]
- ROOT CAUSE: software AES using S-box lookup tables (SubWord), in an unmaintained C library.
- PRACTICE: SL-R-012. Only constant-time backends: hardware AES-NI/ARMv8-CE, or bitsliced. ChaCha20 as the default suite. Abandoned crypto libraries are banned (cargo-deny `unmaintained = deny` for crypto crates).
- TEST: dudect on every compiled backend, including forced-software builds. A `cargo deny` advisories gate.

**INC-SL-07 — libcrux GHSA-2cgv-28vr-rv6j (wrong SHA-3 on aarch64 fallback → wrong ML-KEM secrets / invalid ML-DSA signatures)** [B-SL-14]
- ROOT CAUSE: a hand-written fallback for a missing intrinsic was **outside the verified boundary**, and it passed the wrong operand. CI evidently did not exercise that path with KATs.
- PRACTICE: SL-R-004. Every `cfg(target_arch)`/`cfg(target_feature)` branch in crypto dependencies is enumerated, and each one runs the KATs.
- TEST: build-matrix runs of ST-020..025 for `x86_64-v1` (no AVX2), `x86_64-v3`, `aarch64` (with and without NEON SHA-3 extensions, via `-C target-feature=-sha3`), and a forced-portable build. Differential equality across all of them.

**INC-SL-08 — Let's Encrypt CAA re-check bug (2020)** [B-SL-16]
- ROOT CAUSE: the Go loop iterator variable was captured by reference, so one domain was checked N times. Tests evidently did not include heterogeneous multi-element inputs whose expected outcomes differ per element.
- PRACTICE: SL-R-006 (mutation testing). Property tests with heterogeneous collections for any "check each" loop (recipient slots, COI checks, export approvals).
- TEST: `cargo mutants` on `candor-authz`, `candor-core::envelope`, `candor-export`, with zero surviving mutants in the `check_*`/`verify_*` fns. A proptest where only element k of N fails and the operation must be rejected for each k.

**INC-SL-09 — Signal Desktop CVE-2018-10994 / CVE-2018-11101 (HTML injection → RCE)** [B-SL-32]
- ROOT CAUSE: React `dangerouslySetInnerHTML` used to render quoted replies and links, combined with a permissive CSP and Electron Node exposure.
- PRACTICE: covered: 27 §12.5 Desk UI row (bans `innerHTML`/`dangerouslySetInnerHTML`, Trusted Types). Add **SL-R-002**: attacker-controlled message text reaches the DOM only through `textContent`. Attachments are only ever shown as Viewer-rendered bitmaps.
- TEST: ESLint `no-unsanitized` + `react/no-danger` = error. Run a Playwright/WebDriver XSS corpus (PortSwigger cheat-sheet payloads) through every message, filename and case-field render path. Assert that no script runs (a CSP violation report endpoint counts hits; it must be 0).

**INC-SL-10 — Proton Mail XSS (Sonar, disclosed June 2022)** [B-SL-33]
- ROOT CAUSE: DOMPurify output was **processed again** by application code; the SVG/namespace handling ran after sanitization. This parser differential re-enabled script, and a CSP bypass was needed and found. (Detail from the Sonar post via search extract; the primary was blocked, **UNVERIFIED** detail.)
- PRACTICE: SL-R-002. Sanitization (if any HTML is ever shown) is the **last** transform before insertion. No serialize→parse round trips. Prefer not rendering HTML at all: the Desk shows rich submissions only as Viewer bitmaps.
- TEST: a lint that the sanitizer call site is the direct argument to the sink. A mutation-XSS corpus (mXSS vectors: SVG/MathML namespace confusion) run in CI.

**INC-SL-11 — Tutanota Desktop XSS → RCE (Sonar, June 2022)** [B-SL-34]
- ROOT CAUSE: XSS in email rendering, escalated through Electron renderer access to privileged functionality after two clicks (precise API **UNVERIFIED**; primary blocked).
- PRACTICE: SL-R-008. Tauri capabilities give the case-view window **no** IPC commands except read-only view-model fetch. The Tauri isolation pattern is mandatory. No `shell`/`opener` plugin, no custom protocol handler, no `dialog` write access from renderer-initiated flows. If a window matches no capability, it has no IPC access at all [B-SL-35].
- TEST: a capability-manifest snapshot test (any added permission fails CI unless the PR carries `security/desk-capability` approval). A red-team harness injects JS into the case-view webview (test build hook) and asserts that every IPC call except the allow-listed read is denied.

**INC-SL-12 — Element Desktop CVE-2022-23597 (link → execution of a local binary)** [B-SL-36]
- ROOT CAUSE: clicking a crafted link led the app to execute a local path, or to hand a URI to OS handlers (CWE details **UNVERIFIED**).
- PRACTICE: SL-R-008. Links in submissions are never clickable. They show as text plus a "copy" action that copies the defanged string.
- TEST: grep/AST lint for `open(`, `openPath`, `shell.open`, and `tauri-plugin-opener` in `desk/`. E2E test that a submission containing `file:///`, `smb://`, custom-scheme and `javascript:` links produces no navigation and no OS handoff.

**INC-SL-13 — Wire webapp XSS CVE-2021-32683, CVE-2022-24799, CVE-2022-29168** [B-SL-37]
- ROOT CAUSE: same-origin `createObjectURL` of attacker images, insufficient escaping in code-highlighting markdown, and insufficient escaping in `@mention` rendering. These are all *secondary renderers* bolted onto message text.
- PRACTICE: one rendering path for untrusted text, with no markdown, mentions or highlighting extensions in the Desk (source text is plain). Blobs open only in the Viewer microVM, never as same-origin blob URLs.
- TEST: CSP `blob:` not allowed in `script-src`/`frame-src`. The XSS corpus is run per renderer, and the renderer count is asserted to be 1.

**INC-SL-14 — Hush Line CVE-2024-38522 (trivially bypassable CSP), CVE-2024-38523 (TOTP flow weaknesses; no 2FA re-prompt for security settings), CVE-2024-55888 (missing security headers on prod)** [B-SL-38]
- ROOT CAUSE: a security header policy that was declared but never tested, and a production config that drifted from dev. Sensitive settings changes did not require step-up auth.
- PRACTICE: SL-R-007. The CSP is generated from code, the same in every profile, and served by the app, not by an optional reverse-proxy file. Changing an auth factor, recovery settings, routing or export policy requires a FIDO2 step-up within the last 5 min.
- TEST: CI runs Google `csp-evaluator` (or equivalent) and fails on any finding ≥ Medium. An integration test fetches every route in each deployment profile and asserts the exact header set. ST authz suite: a settings change without a fresh step-up returns 403.

**INC-SL-15 — GlobaLeaks CVE-2026-33284 (support API embeds arbitrary URLs in admin emails; low) and the 2026 LLM-adversary audit (29 findings)** [B-SL-39][B-SL-09]
- ROOT CAUSE: a free-text field from an unauthenticated user flowed into a privileged channel (admin email) unvalidated.
- PRACTICE: covered: content-free notifications (14/20). Add: no unauthenticated free text is ever forwarded to staff channels; staff see it only inside the Desk. SL-R-013 for the audit lesson.
- TEST: AT marker scan already covers notifications. Add a canary URL in every unauthenticated input and assert it is absent from all outbound mail/webhook bodies.

---

## 4. Secure-by-design frameworks: concrete implementation

### 4.1 NIST SSDF
- SP 800-218 v1.1 is the mapped baseline (27 §5). **SP 800-218r1 (SSDF v1.2)** initial public draft came out 2025-12-17, with comments closing 2026-01-30. It adds practice **PO.6** and expands delivery and configuration-management examples. EO 14306 set a final-publication deadline of 2026-03-31 [B-SL-40]. **Final publication is UNVERIFIED this session.** Action: re-map 27 §5 to v1.2 when it is final, and add a PO.6 row (it is about organisational/delivery practice; the exact text is **UNVERIFIED**).
- Practice-level evidence Candor can produce automatically: PO.3 (toolchains: pinned `rust-toolchain.toml` + container digests), PS.1/PS.2 (signed commits, SLSA provenance), PS.3 (SBOM + archived source), PW.4 (cargo-vet), PW.7/PW.8 (SAST/fuzz SARIF), RV.1–RV.3 (advisories + SG-21 mapping). → Generate the SSDF attestation (the CISA Secure Software Development Attestation Form) from the gate-evidence bundle at RM-7.

### 4.2 OWASP ASVS 5.0 / WSTG
- ASVS 5.0.0 (released May 2025) is the target (covered: 27 §6). WSTG v4.2 is the stable testing guide; v5 is in development (**UNVERIFIED** status).
- Concrete: keep `asvs-map.csv` with requirement → test ID → evidence link. Each L3 item gets either an automated ST test or a manual WSTG procedure with a recorded result per release. A2 pentest scoping (37) references WSTG test IDs so that findings map back.

### 4.3 OpenSSF
- **Concise Guide for Developing More Secure Software** (OpenSSF Best Practices WG): 2FA, signed commits, minimal dependencies, SAST/fuzzing, secrets out of repo, the Scorecard and Best Practices badge [B-SL-41].
- **Scorecard** checks include Pinned-Dependencies, Token-Permissions, Dangerous-Workflow, Signed-Releases, Fuzzing, SAST, Branch-Protection, Code-Review, Maintained, Vulnerabilities, SECURITY.md, CII-Best-Practices and Binary-Artifacts. Weights: Critical 10 / High 7.5 / Medium 5 / Low 2.5 [B-SL-42].
- Candor rule: Scorecard runs weekly and on every PR to `.github/`. **Gate: Dangerous-Workflow, Token-Permissions, Pinned-Dependencies, Branch-Protection, Code-Review, Signed-Releases = 10/10** at RM-0 exit. Aggregate ≥ 9 at RM-7. Get the OpenSSF Best Practices **Gold** badge by RM-7 (GlobaLeaks precedent).

### 4.4 SLSA Build L3 for Rust (concrete setup)
- `slsa-framework/slsa-github-generator` generic generator (since v1.2.0) produces non-forgeable SLSA3 provenance for arbitrary artefacts. The project itself notes that the reusable workflows alone do **not** satisfy L3; provenance distribution and verification must be handled separately [B-SL-43]. GitHub `actions/attest-build-provenance` (Sigstore-backed) is the lighter option.
- Recommended Candor pipeline (RM-0):
  1. `cargo build --locked --frozen --release` inside a digest-pinned container. Set `SOURCE_DATE_EPOCH`, `--remap-path-prefix`, `CARGO_INCREMENTAL=0`, `codegen-units=1`, and strip.
  2. **`cargo auditable build`** embeds the dependency list in each binary, so deployed binaries can be scanned with `cargo audit bin` or osv-scanner.
  3. `cargo cyclonedx` + `syft` → SBOMs.
  4. Generic generator → `*.intoto.jsonl`. `slsa-verifier` runs in the TUF publishing step **and** in the Candor self-test agent.
  5. Builder B (a different organisation, non-GitHub infrastructure) rebuilds. Release proceeds only if the hashes are equal (SG-13). Provenance from both builders is logged in the Candor transparency log.
- Verification: `slsa-verifier verify-artifact --source-uri … --source-tag …` in CI. A negative test feeds tampered provenance and expects rejection.

### 4.5 Sigstore and TUF
- Sigstore/cosign keyless signing binds artefacts to CI OIDC identity and records them in Rekor. That is useful as an **additional** transparency signal, but trust in it rests on the OIDC issuer and the forge. Candor's release authority stays with the offline threshold keys (33). Use cosign for container images and the SBOM, and verify with `--certificate-identity` and `--certificate-oidc-issuer` pinned.
- TUF in Rust: **`tough`** (AWS Labs; used by Bottlerocket) or `rust-tuf` (UNVERIFIED maintenance status of each, this session) [B-SL-44]. Rules: root rotation tested (N→N+1→N+2 chain), freeze/rollback/mix-and-match/endless-data attacks tested using the TUF conformance suite where available. Covered by RM-5 exit tests. Add: "client fails closed on expired timestamp > 7 days and shows an operator alert" (freeze-attack UX).

---

## 5. Definition of done and review checklists from high-assurance teams

### 5.1 Sources
- **Chromium Rule of 2:** pick no more than 2 of {untrustworthy input, unsafe language, high privilege}. The security team generally will not approve all 3. Fixes: safe language, privilege reduction (sandbox), or a trustworthy source [B-SL-45].
- **Mozilla:** Rapid Risk Assessment for new services, plus mandatory security review for new features touching sensitive surface (**UNVERIFIED** current form). Mozilla built **cargo-vet** [B-SL-46].
- **Rust `unsafe` review practice** (Rust std, Android, Chromium Rust): `// SAFETY:` comments, clippy `undocumented_unsafe_blocks`, Miri, a small audited set of `unsafe` crates (covered: 27 §12.1).
- **SecureDrop:** no unreviewed changes at approval time; separate signer and reviewer at release (§1.1).

### 5.2 Rule of 2 applied to Candor components

| Component | Untrusted input | Unsafe lang | High privilege | Status / action |
|---|---|---|---|---|
| Source Web Service (C-06) | yes | no (Rust, `forbid(unsafe)`) | low (no keys) | OK |
| Intake Sealer (C-07) | yes (submissions) | no | **high** (holds encryption pipeline) | OK only if T0 is Rust with no C parsers. **Rule:** no C/C++ parser (libmagic, image libs) may be linked into C-07 |
| Viewer microVM | yes (hostile files) | **yes** (LibreOffice, poppler, etc.) | must be **low** | Required: microVM, no network, pixels-out only (covered 12/10) |
| Desk (Tauri) | yes (case text) | WebView = C++ | medium (holds keys via hardware) | Untrusted bytes never parsed in the WebView beyond plain text; keys handled in the Rust core; SL-R-002/008 |
| PostgreSQL | semi (app-validated) | C | high | Only parameterized `sqlx::query!`; RLS; no extensions that parse untrusted data |
| C-tor | yes (network) | C | medium | Separate user/namespace; Arti migration (RM-12) |

Verification: `security/rule-of-2.toml` per component, checked in CI by linking analysis (`cargo tree` + `ldd`/`nm` for C deps in C-07, which must be empty except libc).

### 5.3 Candor PR Definition of Done (T0/T1)

The PR template is mandatory and reviewers tick each item. This complements 27 §11.2.

1. [ ] Feature threat-model delta (27 §10) linked, or "no new trust boundary" justified.
2. [ ] Hostile-input test added, and **a regression test that was red before the fix** (SL-R-014) for bug fixes.
3. [ ] No write, exec or OS-handoff on untrusted names (SL-R-001/008).
4. [ ] Trust decisions use `Verified<T>`; no re-lookup by ID (SL-R-003).
5. [ ] New key or label: added to the label registry; uniqueness test passes (SL-R-011).
6. [ ] No compression on secret-bearing paths, or justification plus padding (SL-R-005).
7. [ ] Mutation score: zero surviving mutants in changed `check_*`/`verify_*`/authz fns (SL-R-006).
8. [ ] New dependency: cargo-vet audit at the right criteria, cooldown respected, Rule-of-2 table updated if it parses input (SL-R-009).
9. [ ] Multi-arch crypto CI green (SL-R-004) if `candor-core` or a crypto dep changed.
10. [ ] Desk: capability manifest unchanged, or approved; XSS corpus green (SL-R-002/007/008).
11. [ ] Anonymity marker scan green (covered: SG-10).
12. [ ] `AI-Assisted` field set (covered: 27 §11.5).

### 5.4 Milestone mapping

| Milestone | Rules entering force |
|---|---|
| RM-0 | SL-R-009, SL-R-010 (test keys), Scorecard 10/10 subset, SLSA pipeline §4.4, builder-verifies-input (§1.7) |
| RM-1 | SL-R-001 (safefs), SL-R-003, SL-R-004, SL-R-005, SL-R-006, SL-R-011, SL-R-012, SL-R-015, LoC budget (§1.8) |
| RM-2 | SL-R-007 (source UI CSP/headers), INC-SL-15 canary |
| RM-3 | SL-R-006 on authz/COI, SL-R-014 |
| RM-4 | SL-R-002, SL-R-008, Desk capability snapshot, archive extractor (INC-SL-03) |
| RM-5 | TUF freeze UX (§4.5), SG-13 extended to delta targets (§1.6) |
| RM-6 | SL-R-013 before A1–A4; QA matrix and test plan (§1.1) |
| RM-7 | Two-party ceremony with production keys; SSDF attestation; Best Practices Gold |
| RM-8..RM-12 | Re-run SL-R-004 for new targets (Windows/macOS aarch64 Source App, Arti); Rule-of-2 table refresh |

---

## 6. Gaps found in the current specs (feedback)

1. 27 §12.5 Filesystem covers *paths* but not **write-before-validate** ordering → add SL-R-001 explicitly, citing CVE-2025-24888.
2. 27 §11.3 crypto checklist has no **proof-TCB / multi-arch** item → add SL-R-004 as checklist item 10.
3. 27 §12.2 has no **mutation testing** → add SL-R-006 to SG-06/SG-08 evidence.
4. 28 should record the **7-day cooldown** and **6-month trust expiry** (SL-R-009), following SecureDrop's own cargo-vet policy.
5. 33 ceremony should require **signer ≠ author ≠ builder-B operator** (SL-R-010).
6. 12/27 Desk rows should explicitly ban `tauri-plugin-shell` open and `tauri-plugin-opener`, plus custom URI schemes (SL-R-008).
7. 27 §5 needs re-mapping to **SSDF v1.2** once final (PO.6).

---

## Bibliography

| ID | Title | URL | Date | Relevance |
|---|---|---|---|---|
| B-SL-01 | SecureDrop dev docs — Release Management (`release_management.rst`) | https://github.com/freedomofpress/securedrop-dev-docs/blob/main/docs/release_management.rst | read at commit 2026-09-28 | RC → test plan → QA matrix → signing ceremony → reviewer-signed apt Release |
| B-SL-02 | SecureDrop dev docs — Contributor Guidelines (Code Review) | https://github.com/freedomofpress/securedrop-dev-docs/blob/main/docs/contributor_guidelines.rst | 2026-09-28 | "No unreviewed changes at approval" |
| B-SL-03 | SecureDrop dev docs — Reproducible builds | https://github.com/freedomofpress/securedrop-dev-docs/blob/main/docs/reproducible_builds.rst | 2026-09-28 | Containerized builds, diffoscope, double-build |
| B-SL-04 | SecureDrop dev docs — Dependency updates (cargo-vet policy, 7-day cooldown) | https://github.com/freedomofpress/securedrop-dev-docs/blob/main/docs/dependency_updates.rst | 2026-09-28 | SL-R-009 |
| B-SL-05 | SecureDrop Workstation Release Management | https://docs.securedrop.org/en/0.8.0/development/workstation_release_management.html | n.d. | Workstation release process (search extract) |
| B-SL-06 | 7ASecurity — SecureDrop Security Audit | https://7asecurity.com/blog/2024/10/securedrop-security-audit/ | 2024-10 | Pre-release whitebox and supply-chain audit (search extract) |
| B-SL-07 | GlobaLeaks docs — Security audits / Continuous integration / QA | https://docs.globaleaks.org/en/stable/security/PenetrationTests.html ; https://docs.globaleaks.org/en/stable/technical/development/continuous-integration.html | n.d. | Audit cadence, CI, OpenSSF badges (search extract) |
| B-SL-08 | OTF — GlobaLeaks Penetration Test 2022 (ROS) | https://www.opentech.fund/security-safety-audits/globaleaks-penetration-test-2022/ | 2022 | 0 critical/high (search extract) |
| B-SL-09 | "GlobaLeaks Remediates 29 Findings From AI-Assisted Audit" (secondary); primary: globaleaks.org 2026-07-30 post | https://letsdatascience.com/news/globaleaks-remediates-29-findings-from-ai-assisted-audit-3545df8c | 2026-07/08 | LLM-adversary audit; v5.0.96 (primary blocked; partly UNVERIFIED) |
| B-SL-10 | Tor Project security policy / TROVE; Arti repo | https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/SecurityPolicy | n.d. | UNVERIFIED (not fetched) |
| B-SL-11 | libsignal repository; PQXDH formal analysis (Bhargavan, Jacomme, Kiefer, Schmidt, USENIX Sec 2024) | https://github.com/signalapp/libsignal | — | UNVERIFIED this session |
| B-SL-12 | Cryspen — "Helping Secure Signal's Post-Quantum Transition" (SPQR verification) | https://cryspen.com/post/signal-spqr-verification/ | 2025-10 | ProVerif + hax/F\*, CI re-verification (search extract) |
| B-SL-13 | Signal-Android reproducible builds | https://github.com/signalapp/Signal-Android/tree/main/reproducible-builds | — | UNVERIFIED |
| B-SL-14 | GHSA-2cgv-28vr-rv6j — libcrux-intrinsics aarch64 fallback (also RUSTSEC) | https://osv.dev/vulnerability/GHSA-2cgv-28vr-rv6j | 2025 | INC-SL-07 (search extract; osv blocked) |
| B-SL-15 | Symbolic Software — "On the Promises of 'High-Assurance' Cryptography" and Cryspen response | https://www.symbolic.software/blog/2026-02-05-cryspen ; https://www.symbolic.software/blog/2026-02-12-cryspen-response | 2026-02 | Proof-TCB critique; contested, UNVERIFIED |
| B-SL-16 | Let's Encrypt — 2020-02-29 CAA Rechecking Bug (community incident report) and press coverage | https://community.letsencrypt.org/t/2020-02-29-caa-rechecking-bug/114591 ; https://www.theregister.com/2020/03/03/lets_encrypt_cert_revocation | 2020-03 | INC-SL-08 |
| B-SL-17 | Boulder repository | https://github.com/letsencrypt/boulder | — | Service architecture (UNVERIFIED details) |
| B-SL-18 | Tails — Release process; Reproducibility | https://tails.net/contribute/release_process ; https://tails.net/contribute/release_process/reproducibility | n.d. | Jenkins reproduces images and IUKs before release |
| B-SL-19 | Qubes OS — Code signing | https://www.qubes-os.org/doc/code-signing/ | n.d. | Signed commits/tags; signature-checker bot |
| B-SL-20 | WireGuard formal verification (Tamarin; CryptoVerif Lipp–Blanchet–Bhargavan 2019) | https://www.wireguard.com/formal-verification/ | 2017-2019 | UNVERIFIED this session |
| B-SL-21 | C2SP age specification; CCTV test vectors | https://c2sp.org/age ; https://c2sp.org/CCTV | — | Header MAC, STREAM, shared testkit |
| B-SL-22 | Cure53 — rustls/ring/webpki pentest report; jbp.io audit post; rustls BoGo | https://cure53.de/pentest-report_rustls.pdf ; https://jbp.io/2020/06/14/rustls-audit/ | 2020-06 | Conformance suites, audit outcome |
| B-SL-23 | C2SP Wycheproof | https://github.com/C2SP/wycheproof | updated 2026-07 | Edge-case vectors incl. ML-KEM/ML-DSA |
| B-SL-24 | Ed25519 "double public key" signing-oracle disclosures (MystenLabs/Chalkias) | https://github.com/MystenLabs/ed25519-unsafe-libs | 2022 | API misuse; UNVERIFIED this session |
| B-SL-25 | Böck et al., "Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS" (WOOT 2016) | https://eprint.iacr.org/2016/475 | 2016 | Nonce reuse; UNVERIFIED this session |
| B-SL-26 | CVE-2025-24888 — SecureDrop Client path traversal in `download_reply()` | https://nvd.nist.gov/vuln/detail/CVE-2025-24888 | 2025 | INC-SL-01 (search extract) |
| B-SL-27 | CVE-2025-24889 / GHSA-933q-fx9h-5g46 — sd-log path traversal | https://github.com/freedomofpress/securedrop-client/security/advisories/GHSA-933q-fx9h-5g46 | 2025 | INC-SL-02 |
| B-SL-28 | CVE-2026-49996 / GHSA-6qxc-pcfg-v6qv — securedrop-proxy redirect origin bypass; gzip absolute-path bug (ID UNVERIFIED) | https://osv.dev/vulnerability/CVE-2026-49996 | 2026 | INC-SL-03 (search extract) |
| B-SL-29 | CVE-2022-39250 — matrix-js-sdk key/device identifier confusion in SAS | https://nvd.nist.gov/vuln/detail/CVE-2022-39250 | 2022-09 | INC-SL-04 |
| B-SL-30 | Paterson, Scarlata, Truong — "Three Lessons From Threema" (USENIX Sec 2023) | https://breakingthe3ma.app/ ; https://www.usenix.org/conference/usenixsecurity23/presentation/paterson | 2023 | INC-SL-05 |
| B-SL-31 | Matrix.org — libolm deprecation; CVE-2024-45191 | https://matrix.org/blog/2024/08/libolm-deprecation/ | 2024-08 | INC-SL-06 |
| B-SL-32 | thehackerblog — "Accidentally Finding RCE in Signal Desktop via HTML Injection in Quoted Replies" (CVE-2018-11101; also CVE-2018-10994) | https://thehackerblog.com/i-too-like-to-live-dangerously-accidentally-finding-rce-in-signal-desktop-via-html-injection-in-quoted-replies/ | 2018-05 | INC-SL-09 |
| B-SL-33 | Sonar — "Code Vulnerabilities Leak Emails in Proton Mail" | https://www.sonarsource.com/blog/code-vulnerabilities-leak-emails-in-proton-mail/ | 2022 | INC-SL-10 (blocked; search extract) |
| B-SL-34 | Sonar — "Remote Code Execution in Tutanota Desktop due to Code Flaw"; Tuta "vulnerability fixed" | https://www.sonarsource.com/blog/remote-code-execution-in-tutanota-desktop-due-to-code-flaw/ ; https://tuta.com/blog/vulnerability-fixed | 2022 | INC-SL-11 (blocked; search extract) |
| B-SL-35 | Tauri v2 — Capabilities / ACL reference; isolation pattern | https://v2.tauri.app/reference/acl/capability | — | SL-R-008 |
| B-SL-36 | CVE-2022-23597 — Element Desktop remote program execution | https://advisories.gitlab.com/pkg/npm/desktop/CVE-2022-23597/ | 2022-02 | INC-SL-12 (root-cause detail UNVERIFIED) |
| B-SL-37 | Wire webapp advisories CVE-2021-32683, CVE-2022-24799, CVE-2022-29168 (GHSA-5568-rfh8-vmhq) | https://github.com/wireapp/wire-webapp/security/advisories/GHSA-5568-rfh8-vmhq | 2021-2022 | INC-SL-13 |
| B-SL-38 | Hush Line CVE-2024-38522, CVE-2024-38523, CVE-2024-55888 | https://nvd.nist.gov/vuln/detail/CVE-2024-38522 ; https://nvd.nist.gov/vuln/detail/CVE-2024-38523 ; https://osv.dev/vulnerability/CVE-2024-55888 | 2024 | INC-SL-14 |
| B-SL-39 | CVE-2026-33284 / GHSA-84wr-q36q-wqhv — GlobaLeaks `/api/support` URL injection | https://nvd.nist.gov/vuln/detail/CVE-2026-33284 | 2026 | INC-SL-15 |
| B-SL-40 | NIST — Draft SP 800-218r1 (SSDF v1.2) | https://csrc.nist.gov/pubs/sp/800/218/r1/ipd | 2025-12-17 | PO.6; final status UNVERIFIED |
| B-SL-41 | OpenSSF — Concise Guide for Developing More Secure Software | https://best.openssf.org/Concise-Guide-for-Developing-More-Secure-Software | 2023+ | Baseline practices (not fetched; UNVERIFIED current text) |
| B-SL-42 | OpenSSF Scorecard (checks and risk weights) | https://github.com/ossf/scorecard | — | §4.3 |
| B-SL-43 | slsa-framework/slsa-github-generator | https://github.com/slsa-framework/slsa-github-generator | — | Generic generator SLSA3; L3 caveat |
| B-SL-44 | awslabs/tough (TUF in Rust); theupdateframework/rust-tuf | https://github.com/awslabs/tough ; https://github.com/theupdateframework/rust-tuf | — | Update client options (maintenance status UNVERIFIED) |
| B-SL-45 | Chromium — The Rule Of 2 | https://chromium.googlesource.com/chromium/src/+/main/docs/security/rule-of-2.md | current | §5.2 |
| B-SL-46 | Mozilla cargo-vet | https://mozilla.github.io/cargo-vet/ | — | Audit criteria, imports |
