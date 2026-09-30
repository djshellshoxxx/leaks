# DECISIONS.md — Architecture Decision Baseline (ADR Register)

Status: BASELINE v1.0 (binding on all specification documents 00–40)
Project codename: **Candor** (working name; replaceable)
Date: 2026-09-30

This document fixes the architectural decisions, identifiers and conventions that every specification in `specs/` MUST follow so that independent teams do not invent conflicting major decisions. Any specification that needs to deviate MUST add a new ADR here (ADR-NNN) rather than silently diverge.

Research inputs: `research/R1..R6` (bibliography IDs `B-SD-*`, `B-GL-*`, `B-INC-*`, `B-AN-*`, `B-CR-*`, `B-CO-*`; incident-derived requirements `REQ-H-*` / incidents `INC-*` in R3). Consolidated in `00-RESEARCH.md`.

---

## 0. Language rules (apply to every document)

- Never describe Candor as unhackable, perfectly anonymous, untraceable, airtight or 100% secure. Use "designed to", "reduces", "protects against X under assumptions A".
- Every protection statement names: WHAT is protected, FROM WHOM, UNDER WHICH ASSUMPTIONS (reference `40-SECURITY-ASSUMPTIONS.md` IDs `ASM-*`), and RESIDUAL RISK.
- RFC 2119 keywords (SHALL/MUST, SHOULD, MAY) in requirement text.

## 1. Requirement format (machine-parsed by `39-REQUIREMENTS-TRACEABILITY.md`)

Every requirement is a row in a Markdown table with EXACTLY these columns:

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| CRYPTO-001 | The system SHALL … | B-CR-05; INC-01 | THR-012 | C-11 | TST: KAT vectors (RFC 9180 App. A) in CI job `crypto-kat`; AUD: crypto review |

- **ID**: `PREFIX-NNN` (3 digits), unique project-wide. Prefixes are owned by documents (§3).
- **Evidence**: bibliography IDs, incident IDs (`INC-nn` from R3), finding IDs (`F-nnn` from 00-RESEARCH) or ADR IDs. "Design" allowed only for non-security product requirements.
- **Threats**: `THR-nnn` IDs from §5 (or new IDs added in 02-THREAT-MODEL) or `—` for purely functional requirements.
- **Component**: `C-nn` IDs from §4.
- **Verification**: one or more of `TST:` (automated test, name the test ID or describe concretely), `AT-nnn` (anonymity test, 30), `ST-nnn` (security test, 29), `INSP:` (inspection/review), `AUD:` (independent audit scope, 37), `DEMO:` (usability/operational demonstration). **No security requirement may have an empty Verification cell.**

## 2. Editions (binding)

- **Community Edition (CE)**: AGPL-3.0-or-later, self-hosted, single organization (multiple channels), full anonymity/crypto/security protections identical to EE.
- **Enterprise/Government Edition (EE)**: CE core + commercial modules + support. Commercial modules are **never in the source trust path** (see ADR-020).
- **Trust Path** (defined): all code that (a) handles source-facing requests, (b) handles plaintext report content, (c) generates, stores, wraps or uses cryptographic keys, (d) builds/signs/updates any of the above, or (e) enforces anonymity-related logging suppression. Trust-path code is AGPL, reproducibly built, and publicly auditable in both editions.

## 3. Document ownership of requirement prefixes

| Doc | Prefixes |
|---|---|
| 00-RESEARCH | F- (findings) |
| 01-PRODUCT-REQUIREMENTS | PRD- |
| 02-THREAT-MODEL | THR- (threats), ADV- (adversaries) |
| 03-PRIVACY-ANONYMITY | ANON-, META-, PRIV- |
| 04-CRYPTOGRAPHY | CRYPTO-, KEY- |
| 05-SOURCE-OPSEC | SOPS- |
| 06-SYSTEM-ARCHITECTURE | ARCH- |
| 07-BACKEND | BE- |
| 08-API | API- |
| 09-DATABASE | DB- |
| 10-FILE-EVIDENCE-PIPELINE | FILE-, EVID- |
| 11-FRONTEND-SOURCE | SUI- |
| 12-FRONTEND-RECIPIENT | RUI- |
| 13-FRONTEND-ADMIN | AUI-, SOCUI-, EMUI- |
| 14-CASE-MANAGEMENT | CASE-, ROUTE- |
| 15-AUTHENTICATION-AUTHORIZATION | AUTH-, AUTHZ- |
| 16-TOR-I2P | NET- |
| 17-INFRASTRUCTURE | INFRA-, PHYS- |
| 18-DEPLOYMENT | DEP- |
| 19-BACKUPS-DR | BAK-, DR- |
| 20-LOGGING-AUDITING | LOG-, AUD- |
| 21-ENTERPRISE | ENT-, HA-, TEN- |
| 22-GOVERNMENT | GOV- |
| 23-COMMUNITY-EDITION | CE- , SMB- |
| 24-LICENSING-BUSINESS-MODEL | BIZ-, TEL- |
| 25-COMPLIANCE | COMP- |
| 26-ACCESSIBILITY | A11Y-, I18N- |
| 27-SECURE-DEVELOPMENT | SDL- |
| 28-SUPPLY-CHAIN | SCM- |
| 29-SECURITY-TESTING | ST- (tests), SECT- (requirements on testing) |
| 30-ANONYMITY-TESTING | AT- (tests), ANT- (requirements on testing) |
| 31-INCIDENT-RESPONSE | IR- |
| 32-OPERATIONS | OPS-, HUM- (human-factor controls), CFG- (config classification) |
| 33-RELEASE-UPDATE-SECURITY | REL-, UPD- |
| 34-PERFORMANCE-SCALABILITY | PERF-, FAIL- (failure behavior) |
| 35-DATA-RETENTION-DELETION | RET-, DEL- |
| 36-OPEN-SOURCE-GOVERNANCE | OSG- |
| 37-SECURITY-AUDIT-PLAN | SAP- |
| 38-IMPLEMENTATION-ROADMAP | RM- (milestones) |
| 40-SECURITY-ASSUMPTIONS | ASM- |
| REVIEW-REPORT | RVW- (weaknesses) |

## 4. Component catalog (fixed IDs)

Zones: **Z-SRC** source device · **Z-NET** anonymity network · **Z-INTAKE** internet-facing intake zone (onion only) · **Z-CORE** internal case zone · **Z-RCP** recipient endpoints · **Z-VIEW** evidence viewing/containment · **Z-ADM** administration · **Z-SOC** monitoring · **Z-BAK** backups · **Z-SUPPLY** build/release · **Z-VENDOR** vendor-operated services.

| ID | Component | Zone | Notes |
|---|---|---|---|
| C-01 | Source device + OS | Z-SRC | untrusted by us, trusted by source |
| C-02 | Source browser (Tor Browser) | Z-SRC | primary client |
| C-03 | Candor Source App (optional, signed, reproducible desktop/mobile client; embeds Arti) | Z-SRC | E2E path |
| C-04 | Tor network / onion-service transport | Z-NET | |
| C-05 | Intake Gateway host (tor daemon, onion service, PoW, vanguards; no clearnet listener) | Z-INTAKE | |
| C-06 | Source Web Service (server-rendered HTML, no-JS capable, optional WEBCAT-signed JS/WASM bundle) | Z-INTAKE | |
| C-07 | Intake Sealer (isolated process: encrypts no-JS submissions in RAM to channel epoch keys; derives source keys in RAM at login) | Z-INTAKE | holds plaintext transiently in no-JS mode |
| C-08 | Intake Store (sealed envelopes + minimal source-account records; PostgreSQL + ciphertext blob dir) | Z-INTAKE | |
| C-09 | Intake Relay (Z-CORE-initiated pull connector; one-way: core pulls sealed batches, pushes sealed replies; no inbound from Z-INTAKE to Z-CORE) | Z-CORE | |
| C-10 | Case Service (case workflow API, authorization engine, SLA engine) | Z-CORE | |
| C-11 | candor-core crypto library (Rust; HPKE/X-Wing, AEAD, STREAM, KDF, signing) | all | shared by C-03, C-06/07, C-10, C-15 |
| C-12 | Case Database (PostgreSQL, RLS per tenant) | Z-CORE | |
| C-13 | Case Blob Store (filesystem or S3-compatible on-prem; ciphertext only) | Z-CORE | |
| C-14 | Key Directory & Transparency Log (append-only signed log of recipient/channel public keys and client release hashes) | Z-CORE (published via C-06) | |
| C-15 | Candor Desk (recipient/investigator desktop client; holds private keys; decrypts locally) | Z-RCP | |
| C-16 | Recipient workstation OS | Z-RCP | |
| C-17 | Evidence Viewer / Containment (disposable microVM or Qubes DispVM; pixels-to-PDF; sanitizer) | Z-VIEW | |
| C-18 | Air-gapped Viewing Station (optional) | Z-VIEW | |
| C-19 | Admin Console (admin mode of Candor Desk + `candorctl` CLI) | Z-ADM | |
| C-20 | Admin workstation | Z-ADM | |
| C-21 | Authentication Service (WebAuthn/FIDO2, PIV, OIDC/SAML bridge for EE; OPAQUE optional) | Z-CORE | |
| C-22 | Authorization Engine (policy: RBAC+ABAC+case ACL+COI) | Z-CORE | part of C-10, separately testable |
| C-23 | Notification Service (content-free notifications) | Z-CORE | |
| C-24 | Audit Log Service (hash-chained, signed checkpoints, class-separated streams) | Z-CORE | |
| C-25 | Health/Self-test Agent + Monitor host | Z-SOC | |
| C-26 | Event export gateway to SIEM (allow-list scrubbed events) | Z-SOC | EE |
| C-27 | Backup Agent + Backup Store | Z-BAK | |
| C-28 | Organization Recovery Quorum (optional k-of-n escrow; offline) | Z-ADM | off by default |
| C-29 | HSM / PKCS#11 / TPM | Z-CORE/Z-ADM | EE optional; CE via TPM/soft |
| C-30 | Source repository & review (Git forge) | Z-SUPPLY | |
| C-31 | CI + isolated reproducible builders (≥2 independent) | Z-SUPPLY | |
| C-32 | Release signing (offline threshold keys) + TUF repository + transparency log | Z-SUPPLY | |
| C-33 | Package/update mirror (APT repo, OCI registry) | Z-SUPPLY | |
| C-34 | Enterprise Fleet Manager (EE; manages instances without holding onion addresses in cleartext, content, or keys) | Z-VENDOR / customer | |
| C-35 | Licensing service (EE; offline license files; no phone-home required) | Z-VENDOR | |
| C-36 | Vendor support infrastructure (ticketing; support bundles) | Z-VENDOR | |
| C-37 | Clearnet Information Site (static; publishes onion address, Onion-Location, guidance; no submission form for anonymous mode) | Internet | |
| C-38 | Confidential Clearnet Intake (optional, EE/CE, separately branded CONFIDENTIAL/IDENTIFIED only) | Z-INTAKE-CLEAR | off by default |
| C-39 | Hypervisor / physical servers / storage hardware | infra | |
| C-40 | Integration Connectors (records mgmt, ticketing, HR, legal; export only via explicit redacted Export Package) | Z-CORE→external | EE |

## 5. Core threat catalog (02 MUST retain these IDs; may add THR-100+)

| ID | Threat |
|---|---|
| THR-001 | Source IP/network identity observed or logged by platform component |
| THR-002 | Source network activity correlated by employer/ISP/local network (Tor usage visible, timing) |
| THR-003 | End-to-end traffic/timing correlation by network adversary |
| THR-004 | Website/onion fingerprinting of source visit |
| THR-005 | Guard discovery / malicious relays against onion service |
| THR-006 | Browser fingerprinting / tracking identifiers (cookies, storage) |
| THR-007 | Malicious or compelled server delivers altered client code (Hushmail class) |
| THR-008 | Browser exploit delivered to source (NIT class) |
| THR-009 | Document metadata identifies source (EXIF, Office, PDF, revision history) |
| THR-010 | Content/stylometry/canary-trap/printer-dots identify source |
| THR-011 | Timing metadata (exact timestamps, activity patterns) identifies source |
| THR-012 | Cryptographic design/implementation failure exposes content |
| THR-013 | Key theft (server, recipient, backup, HSM) exposes content |
| THR-014 | Server compromise exposes plaintext in memory or future submissions |
| THR-015 | Database/storage theft exposes content or metadata |
| THR-016 | Log/SIEM/metrics/tracing/crash-dump leakage of source-sensitive data |
| THR-017 | Backup/snapshot/replica retains data beyond deletion |
| THR-018 | Malicious/curious administrator reads reports or identifies source |
| THR-019 | Malicious investigator/recipient identifies or retaliates against source |
| THR-020 | Accused person (incl. executives/admins) accesses, suppresses or learns of report |
| THR-021 | Authorization bypass / IDOR / cross-tenant access |
| THR-022 | Authentication compromise of recipient/admin (phishing, credential theft) |
| THR-023 | Hostile uploaded file exploits recipient/viewer (malware, parser exploit) |
| THR-024 | Supply-chain compromise (dependency, build, CI, signing, repository) |
| THR-025 | Malicious or compromised update delivered to instances (targeted or broad) |
| THR-026 | Legal compulsion of operator or vendor to disclose or modify |
| THR-027 | Vendor/support personnel access to customer data or deployment metadata |
| THR-028 | Notification content/metadata leakage (email, SMS, push) |
| THR-029 | Enterprise integration exfiltrates report content to general systems |
| THR-030 | Cloud/hosting provider observes metadata, snapshots memory/disks |
| THR-031 | Physical seizure/theft of servers, workstations, backups, HSM |
| THR-032 | Denial of service / resource exhaustion against intake |
| THR-033 | Spam/abuse/flooding of intake; malicious false reports |
| THR-034 | Source credential loss or theft (codename disclosure, device seizure) |
| THR-035 | Misconfiguration or dangerous option enables metadata collection |
| THR-036 | Telemetry/analytics/third-party resources expose users |
| THR-037 | Evidence tampering / chain-of-custody break |
| THR-038 | Audit records themselves become source-identifying |
| THR-039 | Aggregate reports/metrics enable inference of source identity (small cells) |
| THR-040 | Mode confusion: user believes they are anonymous when confidential/identified |
| THR-041 | Recipient/investigator operational mistake (forwarding originals, printing, cloud upload) |
| THR-042 | Ransomware / destructive attack on case data |
| THR-043 | Clock manipulation / wrong time affects SLA, crypto epochs, logs |
| THR-044 | Onion service private key compromise (impersonation/phishing of sources) |
| THR-045 | Multi-tenant co-residency leakage |
| THR-046 | Hidden recipient insertion / key substitution (Anom class) |
| THR-047 | Resumable/chunked upload metadata correlates sessions |
| THR-048 | Source device forensic residue (history, downloads, codename written down) |

## 6. Architecture Decision Records

Each ADR: CONTEXT / OPTIONS / DECISION / SECURITY EFFECT / PRIVACY EFFECT / USABILITY EFFECT / OPERATIONAL EFFECT / ALTERNATIVES REJECTED / EVIDENCE.

### ADR-001 Anonymous transport: Tor v3 onion services only, behind a transport abstraction
- CONTEXT: Anonymous submissions need a network layer that hides source IP from the platform and hosting provider.
- OPTIONS: Tor only; I2P only; Tor+I2P; clearnet+policy; transport abstraction.
- DECISION: Anonymous mode is reachable **only** via a Tor v3 onion service (C-05). C-tor ≥0.4.8 with PoW DoS defense (`HiddenServicePoWDefensesEnabled 1`) and Vanguards (vanguards-lite built-in; full vanguards add-on for HIGH profile) until Arti onion services are declared production-ready, then Arti. A `Transport Adapter` interface (ARCH) with admission criteria (independent analysis, anonymity-set size, hardened client, maintenance) allows future transports (e.g., cover-traffic mixnet). I2P is **not** shipped in v1.
- SECURITY EFFECT: Platform never learns source IP (THR-001 mitigated by construction). Does not stop THR-002/003/004.
- PRIVACY EFFECT: Removes IP metadata entirely from intake. Tor use itself is visible to local network observer (documented).
- USABILITY EFFECT: Requires Tor Browser or Candor Source App; mitigated by clear landing guidance.
- OPERATIONAL EFFECT: Tor daemon upgrades, PoW tuning, onion key custody.
- REJECTED: I2P-only (small anonymity set ~15–30k routers, practical netDb/floodfill deanonymization NDSS 2026, repeated Sybil floods 2023–2026, no hardened browser); Tor+I2P (doubles attack surface, gives I2P users weaker anonymity under same label); clearnet with "no-log" policy (policy-only, compellable — Proton 2021).
- EVIDENCE: R4 (B-AN-*), INC ProtonMail 2021, GlobaLeaks Tor-only mode, SecureDrop.

### ADR-002 No clearnet fallback; three honest modes
- DECISION: Modes are **ANONYMOUS** (onion only; no identity collected), **CONFIDENTIAL** (source identity or network identity knowable to the operator's designated identity custodians/hosting path, protected by access controls), **IDENTIFIED** (named reporter). Anonymous mode never falls back to clearnet; if onion unavailable the source sees an outage page with no alternative "anonymous" path. Optional Confidential Clearnet Intake (C-38) is off by default, separately branded, and every page states "NOT ANONYMOUS". A source may *voluntarily* disclose identity inside an onion submission, which converts the report to CONFIDENTIAL and places identity into the Sealed Identity Store (ADR-014).
- REJECTED: "anonymous" clearnet form (GlobaLeaks default clearnet, commercial SaaS); silent fallback.
- EVIDENCE: R2 GlobaLeaks defaults; R4; INC Proton; THR-040.

### ADR-003 Tor is required for Anonymous mode; no Tor Browser fingerprinting
- DECISION: Onion-only access proves Tor transport without fingerprinting. The server does not fingerprint the browser to check "is Tor Browser". The Clearnet Information Site (C-37) may check the connecting IP against the public Tor exit list in memory (no logging) to show a warning/Onion-Location. Source UI works fully at Tor Browser "Safest" (no JS).
- EVIDENCE: R4, INC Freedom Hosting NIT, INC TorMoil.

### ADR-004 Two source client tiers with honest disclosure
- CONTEXT: Server-delivered JS crypto gives no protection against a compromised/compelled server (Hushmail, Hush Line threat model).
- DECISION:
  - **Tier W (Web, no-JS, default)**: server-rendered HTML forms. Submission plaintext arrives over the onion connection into C-06, is streamed directly into C-07 Intake Sealer (separate process, memory-locked, no swap, no core dumps), encrypted to channel epoch keys (ADR-008) and discarded. Honest statement: "A live-compromised intake server could read what you submit while it is being encrypted."
  - **Tier V (Verified client)**: Candor Source App (C-03, reproducible, threshold-signed, transparency-logged, embeds Arti) **or** Tor Browser with the WEBCAT-verified JS/WASM bundle (when WEBCAT is available in Tor Browser). Client encrypts before upload; server never sees plaintext; client verifies channel keys against Key Directory (C-14).
  - JS on the web path is optional progressive enhancement and SHALL NOT be required.
- SECURITY EFFECT: Tier V removes THR-007/THR-014 plaintext exposure; Tier W bounds it to transient RAM of an isolated sealer.
- REJECTED: mandatory server-delivered JS crypto (no real gain, breaks Safest mode); native-app-only (usability, installation leaves device traces, threatens THR-048).
- EVIDENCE: R5 ranked mitigations; INC Hushmail; R2 Hush Line; WEBCAT (B-CR-37/38).

### ADR-005 Source return credential: generated high-entropy codename, no conventional identity
- DECISION: A **Source Passphrase** of 10 words from the EFF large wordlist (≈129 bits) generated by the client (Tier V) or by C-07 using OS CSPRNG (Tier W), shown once. Argon2id(passphrase, per-deployment salt) → seed → HKDF → {source auth key, source X-Wing keypair, source Ed25519 key}. Server stores only the source public keys and an auth verifier derived from the seed (not the passphrase). No email/phone/SMS/IdP/security questions in Anonymous mode. Separate **Report Receipt** is not needed; the passphrase is the only credential. Optional: source may choose to add a second report under the same passphrase (default: one passphrase per report to minimize linkability).
- Tier W login: C-07 derives keys in RAM to decrypt replies for rendering, then zeroizes.
- REJECTED: 16-digit receipts (~53 bits, GlobaLeaks); user-chosen passwords; email recovery (Proton 2024).
- EVIDENCE: R2, R5 (B-CR-24, CoverDrop), INC Proton 2024, INC Ulbricht.

### ADR-006 Hybrid post-quantum public-key encryption via HPKE
- DECISION: HPKE (RFC 9180) with KEM **X-Wing (ML-KEM-768+X25519)**, KDF HKDF-SHA256, AEAD ChaCha20-Poly1305 (default suite "CANDOR-STD-1"). FIPS profile "CANDOR-FIPS-1": KEM MLKEM1024-P384 hybrid, HKDF-SHA384, AES-256-GCM, via AWS-LC FIPS module. Signatures: Ed25519 (messages/log entries); release roots: Ed25519 + ML-DSA-65 dual signatures. Record encryption: XChaCha20-Poly1305 (STD) / AES-256-GCM (FIPS). Files: age-style STREAM with 64 KiB chunks and header HMAC key commitment. Password hashing (staff local secrets): Argon2id m=256 MiB,t=3,p=1 for source passphrase KDF; staff PINs protected by hardware. No home-grown primitives; protocol composition reviewed and formally modelled (Tamarin/ProVerif) before 1.0.
- EVIDENCE: R5 (B-CR-02..16, 19, 24), SecureDrop Protocol, age.

### ADR-007 Recipient private keys live only on recipient endpoints
- DECISION: Each staff user has an identity key (Ed25519) and encryption key (X-Wing) generated on C-15, private keys sealed by a hardware-bound wrapping key (FIDO2 `hmac-secret`/WebAuthn PRF, PIV/smartcard, or TPM; software-passphrase fallback in CE with warning). Servers (C-06..C-13) never hold recipient private keys. Candor Desk is a signed reproducible desktop app (Tauri/Rust); **no browser-based recipient UI** is served by the server.
- REJECTED: GlobaLeaks-style server-side unwrapping (server compromise = total), web recipient UI (Hushmail class for recipients).
- EVIDENCE: R2 GlobaLeaks analysis, R5, INC Lavabit.

### ADR-008 Channel epoch keys for forward secrecy of intake; case keys for case lifetime
- DECISION: Key hierarchy:
  - **Channel Identity Key** (signing, long-term) per intake channel, held by channel members' clients (wrapped to each member).
  - **Channel Epoch Keys** (X-Wing, default 7-day epoch, 14-day decrypt window) pre-generated by a channel member client, signed by Channel Identity Key, published in C-14. Intake encrypts to the current epoch key. Private epoch keys wrapped to channel members; **destroyed** after window + import.
  - On import, Candor Desk re-wraps envelope content keys into a **Case Key** (per case, symmetric 256-bit) wrapped to each authorized case member's X-Wing key (and optionally the Recovery Quorum key).
  - **Source Keys** (ADR-005) for replies.
  - **Storage/DB at-rest keys** (LUKS/TPM, DB TDE optional) protect infrastructure media only — they are NOT the content protection layer.
- Master-key answer: there is no single server-side master key that decrypts reports. Stealing today's channel identity key does not decrypt envelopes whose epoch keys were destroyed; stealing a member's device+unlock yields that member's current case keys (bounded by their ACL). With Recovery Quorum enabled (ADR-013), theft of k shares exposes cases wrapped to it.
- EVIDENCE: R2 CoverDrop (daily rotation, 7-day), R5, INC Lavabit.

### ADR-009 Intake/Core separation with core-initiated pull
- DECISION: Z-INTAKE (C-05..C-08) and Z-CORE (C-09..C-14, C-21..C-24) run on separate hosts (Community Hardened and above) or separate VMs (Community Single-Node with documented reduced isolation). No connection may be initiated from Z-INTAKE to Z-CORE. C-09 in Z-CORE periodically (randomized, default every 15±10 min) pulls sealed envelope batches and pushes sealed replies and signed key-directory snapshots. Z-INTAKE compromise yields: ciphertext, source public keys, coarse metadata, and — for Tier W — plaintext of submissions made during the compromise window.
- EVIDENCE: R2 CoverDrop (no inbound to on-prem), SecureDrop app/monitor split, INC Silk Road IP leak.

### ADR-010 Timing metadata minimization
- DECISION: Intake Store records only `received_epoch_day` (UTC date) and a monotonic batch number; no exact timestamps for source actions. Case import records batch time. Recipients see "received on YYYY-MM-DD". Source UI shows message dates at day granularity. Replies become visible to source on next login (no push). No read receipts, typing, or presence indicators in either direction. Source "last seen" never stored. Exact timestamps exist only for staff actions in audit logs.
- EVIDENCE: R3 (INC Reality Winner, Strava, Ricochet timing), R4.

### ADR-011 Size/shape padding
- DECISION: Messages padded to 4 KiB buckets (max 64 KiB text). Attachments encrypted in 64 KiB STREAM chunks; total stored size padded to the next bucket of a geometric series (ratio 1.25, min 256 KiB) — "Padmé-like". Source web responses padded to fixed size classes where feasible.
- EVIDENCE: R2 (GlobaLeaks 5% padding), R5 SecureDrop Protocol fixed-size, R4 packet-size analysis.

### ADR-012 Evidence never parsed on servers; original + sanitized derivative
- DECISION: Servers treat attachments as opaque ciphertext. Decryption and parsing only in C-17 (disposable, network-less microVM/Qubes DispVM, Dangerzone-style pixels-to-PDF, mat2 inside sandbox, qpdf normalization). ORIGINAL EVIDENCE is immutable (content hash SHA-256 + BLAKE3 recorded at import inside encrypted case record); SANITIZED WORKING COPY is a new evidence object linked by `derived_from` with transformation record. Originals exportable only with dual approval (AUTHZ).
- EVIDENCE: R5 (Dangerzone, mat2 0.14 sandbox removal, CVE-2021-22204), R1 SecureDrop Workstation, INC Reality Winner, INC Efail.

### ADR-013 Recovery: no escrow by default; optional k-of-n Recovery Quorum
- DECISION: CE and EE default: no escrow; case keys wrapped to ≥2 case members (loss of all members' devices = loss of access; warned). Optional Organization Recovery Quorum (C-28): X-Wing keypair generated offline, private key Shamir-split k-of-n (default 3-of-5) on hardware tokens held by independent roles (e.g., audit committee, ombudsman, external counsel). Enabling it is a DANGEROUS config (CFG) requiring dual approval, published in key directory (visible to sources as "Recovery escrow: ENABLED, held by: …").
- EVIDENCE: R2 (GlobaLeaks escrow risks, CVE-2026-46648; CoverDrop k-of-n), R3 insider incidents.

### ADR-014 Sealed Identity Store for Confidential mode
- DECISION: Identity details a source chooses to provide are encrypted to a separate **Identity Custodian** key set (not the case key), never shown in case view; unsealing requires recorded legal basis, dual approval, and generates a source-visible notice where law requires (EU Directive Art 16(3)).
- EVIDENCE: R6 (EU Art 16, 5 USC 407(b), PSDPA s.11), R2 GlobaLeaks custodian role.

### ADR-015 Authorization: admin ≠ case access; COI-aware routing
- DECISION: Policy engine = RBAC (roles) + ABAC (tenant, department, channel, case attributes) + per-case ACL + Conflict-of-Interest exclusion lists + time-bounded grants + break-glass requiring dual authorization and post-hoc independent review. System administrators have zero case-content capability (cryptographically: they hold no case keys). Routing: source picks a channel; channels can route to independent bodies (ombudsman, audit committee, external counsel); sources may flag "report concerns: [role list]" and a pre-configured COI map excludes those roles before any access; exclusions applied before key wrapping so excluded users never receive keys.
- EVIDENCE: R3 INC Barclays/Staley, R6 SOX §301, ISO 37002.

### ADR-016 Privacy-preserving audit with four event classes
- DECISION: Classes: SECURITY (auth, admin), CASE (staff actions on cases, pseudonymous case IDs), SYSTEM (health), SOURCE-SENSITIVE (never emitted as events; only counters with k-anonymity thresholds). Prohibited fields list enforced by typed logging API (allow-list schema); free-text logging banned in trust-path code. Hash-chained, periodically checkpointed and signed, optionally anchored to an external witness. Tor daemon and web server access logs disabled.
- EVIDENCE: R3 INC Facebook plaintext logs, Okta HAR; R2 GlobaLeaks logs staff IPs by default.

### ADR-017 Content-free notifications
- DECISION: Notifications (email/Teams/SMTP/Matrix webhooks) contain only: "Candor: secure case-management action requires attention" + instance label; no case ID, no count, no time of submission; delivery time jittered/batched (default hourly digest). No push to sources ever.
- EVIDENCE: R3 INC push notification demands, AP phone records.

### ADR-018 Integrations via explicit Export Packages only
- DECISION: No automatic flow of report content to SIEM/HR/ticketing/records systems. Integrations receive either (a) scrubbed SECURITY/SYSTEM events via C-26 allow-list, or (b) an **Export Package** created by a human with case access, redaction review, dual approval for originals, recorded in CASE audit.
- EVIDENCE: THR-029; R3 Okta support system.

### ADR-019 Technology stack
- DECISION: Rust for all trust-path server/crypto code (axum/hyper, tokio, sqlx), RustCrypto/`aws-lc-rs` behind candor-core abstraction; PostgreSQL ≥16; filesystem or S3-compatible on-prem blob store; job queue in PostgreSQL (`SKIP LOCKED`) — no separate broker in CE; Candor Desk = Tauri 2 (Rust + bundled static UI, no remote content); source web UI = server-rendered HTML + CSS, optional WASM; Debian stable (currently Debian 13) as reference OS; packaging: signed .deb (primary), OCI images (EE/K8s optional), appliance VM image. cargo-vet + cargo-deny, pinned lockfiles.
- EVIDENCE: R2 (GlobaLeaks Twisted CVE-2024-41671), R5 (CoverDrop cargo-vet), memory safety guidance (CISA).

### ADR-020 Open-core boundary
- DECISION: AGPL-3.0-or-later for all Trust Path code (both editions). EE commercial modules (source-available to customers/auditors under commercial license): Fleet Manager, SSO/SCIM connector, HA orchestration/cluster operator, compliance/report packs, SIEM exporter, records/ticketing connectors, advanced workflow designer, DR automation. EE modules run only in Z-CORE/Z-ADM/Z-VENDOR, interact only via documented APIs, never receive plaintext except through human-created Export Packages, never hold private keys. Security fixes for shared code released to CE and EE simultaneously. Public "Edition Charter" forbids moving protections to EE.
- EVIDENCE: R6 licensing analysis (HashiCorp/OpenTofu, Elastic, Redis, Signal server gap, Threema).

### ADR-021 Multi-tenancy
- DECISION: CE: single tenant. EE shared-instance multi-tenancy is allowed only for low/moderate-risk tenants within one customer group (subsidiaries/departments) with PostgreSQL RLS + per-tenant channel keys + per-tenant onion services. High-risk customers (government IG, law-enforcement internal affairs, intelligence-adjacent, customers whose adversary is the parent org) SHALL get dedicated instances. Managed service: one dedicated intake gateway + onion key per customer; no cross-customer shared Z-INTAKE.
- EVIDENCE: R2 GlobaLeaks CVE-2026-46648 cross-site escrow wipe.

### ADR-022 Updates: TUF + threshold signing + transparency; no targeted updates
- DECISION: Updates delivered via TUF metadata (root keys offline, threshold 3-of-5 for root, 2-of-3 for targets), artifacts reproducibly built by ≥2 independent builders whose outputs must match before signing, logged in a public transparency log (Sigsum/Rekor), and identical for all customers (no per-customer builds of trust-path code). Update client does not report onion addresses or instance identity; EE Fleet Manager uses opaque instance IDs.
- EVIDENCE: R3 (SolarWinds, NotPetya, xz, 3CX, CCleaner, Anom), R5 (TUF, SLSA v1.2).

### ADR-023 Telemetry: none source-side; opt-in, schema-fixed admin telemetry
- DECISION: Zero telemetry from source clients/interfaces. Instance telemetry OFF by default in CE and EE; if enabled, only fields in TEL schema (24), sent to self-hostable collector or vendor, inspectable locally before sending.
- EVIDENCE: R3 (Meta Pixel), R6 (Go telemetry design).

### ADR-024 Deployment profiles
- DECISION: Eight profiles: CE-SINGLE (one host, VMs/containers split intake/core), CE-HARDENED (≥2 hosts + monitor + air-gapped option), EE-ONPREM, EE-HA, GOV-ONPREM, AIRGAP-RCP (air-gapped recipient environment), PRIVATE-CLOUD (with documented provider-observer risks), MANAGED (vendor-operated; dedicated intake per customer; vendor cannot decrypt content). Kubernetes supported only for Z-CORE in EE-HA/PRIVATE-CLOUD; Z-INTAKE on dedicated VMs/hosts (not shared clusters).

### ADR-025 Deletion semantics
- DECISION: Deletion = cryptographic erasure (destroy all wrappings of the object key / case key) + best-effort physical deletion; backups contain only ciphertext whose keys are not in backups (case keys wrapped only to member keys and quorum), so key destruction propagates to backups. Documented where "delete" ≠ immediate physical erasure (SSDs, snapshots, legal hold).
- EVIDENCE: R5 (NIST SP 800-88r2), R3 (LastPass backups).

### ADR-026 Abuse resistance without third-party CAPTCHA
- DECISION: Tor onion PoW (Equi-X), app-level per-circuit and global rate limits (in-memory, circuit IDs never persisted), optional app-level PoW for no-JS via tiered queue, upload quotas per source account, submission size caps, triage queue for spam. No third-party CAPTCHA.
- EVIDENCE: R4 (Tor 0.4.8 PoW), R2 (GlobaLeaks PoW).

### ADR-027 Single audited safe-path/archive API and malicious-server harness
- CONTEXT: SecureDrop Workstation/Client suffered server-controlled path traversal / archive-header injection repeatedly (TOB-SDW-012 2020, CVE-2025-24888, CVE-2026-35465); OnionShare CVE-2026-54706 symlink escape.
- DECISION: All filesystem writes of server- or source-influenced names in C-15/C-17/C-03 go through one audited `candor-safefs` API (content-addressed storage names, never source-provided names; display names are metadata only). CI lint bans direct path joins, `tar`/`zip` extraction outside the API. A **malicious-server test harness** (29) drives every client against a hostile server.
- EVIDENCE: R1 (B-SD-28, B-SD-33..36, B-OS-01..04).

### ADR-028 Verified secret placement per host
- CONTEXT: SecureDrop GHSA-rqwh: installer copied onion client-auth keys to the Monitor server.
- DECISION: Each host role has a machine-readable **Secret Placement Manifest**; the self-test (C-25) and installer verify after every deploy that no secret exists outside its permitted hosts; violation = deployment failure.
- EVIDENCE: R1 (B-SD-22).

### ADR-029 Audience-bound tokens and deny-by-default routes
- DECISION: Every session/token is bound to one audience (source-web, source-app, desk-api, admin-api) and one tenant; route registry is deny-by-default with explicit authorization declaration per route checked in CI.
- EVIDENCE: R1 CVE-2026-50000 (API token reused on web UI); R2 GlobaLeaks CVE-2026-46647 (missing admin check), CVE-2026-45020.
