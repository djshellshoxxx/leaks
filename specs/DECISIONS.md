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
| 02-THREAT-MODEL | THR- (threats), ADV- (adversaries), TM- (threat-model obligations) |
| 03-PRIVACY-ANONYMITY | ANON-, META-, PRIV- |
| 04-CRYPTOGRAPHY | CRYPTO-, KEY- |
| 05-SOURCE-OPSEC | SOPS- |
| 06-SYSTEM-ARCHITECTURE | ARCH- |
| 07-BACKEND | BE- |
| 08-API | API- |
| 09-DATABASE | DB- |
| 10-FILE-EVIDENCE-PIPELINE | FILE-, EVID- |
| 11-FRONTEND-SOURCE | SUI- |
| 11a-SOURCE-SAFETY-TIPS | TIP- |
| impl/IMPL-* (secure implementation specs) | IMP- (IMP-STD-, IMP-RMn-) |
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
- EVIDENCE: R2 (GlobaLeaks escrow risks, CVE-2026-46648 [CVE record unconfirmed]; CoverDrop k-of-n), R3 insider incidents.

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
- EVIDENCE: R2 GlobaLeaks CVE-2026-46648 [CVE record unconfirmed] cross-site escrow wipe.

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
- EVIDENCE: R1 CVE-2026-50000 [CVE record unconfirmed] (API token reused on web UI); R2 GlobaLeaks CVE-2026-46647 [CVE record unconfirmed] (missing admin check), CVE-2026-45020 [CVE record unconfirmed].

### ADR-030 Per-member epoch keys so conflict-of-interest exclusion is cryptographic (amends ADR-008, ADR-015)
- CONTEXT: With a single channel-wide epoch key (ADR-008 as first written), every channel member holds a key that decrypts every envelope, so excluding an accused member "before key wrapping" (ADR-015) is only policy. Raised by 21-ENTERPRISE author.
- OPTIONS: (a) channel-wide key + policy exclusion; (b) per-role-group epoch keys within a channel; (c) per-member epoch keys, envelope content key wrapped individually to each eligible member.
- DECISION: (c). Each channel member's Candor Desk publishes signed **Member Epoch Keys** (X-Wing, 7-day epoch, 14-day decrypt window) in the Key Directory (C-14), listed under the member's **role label** (e.g., "Audit Committee Chair", "HR Investigations Lead"; names optional per channel policy). The envelope content key is wrapped separately to each *eligible* member's current epoch key. Before wrapping, the COI filter removes (1) members the source flags ("my report concerns: …" role list shown in the UI) and (2) members listed in the tenant's pre-configured COI map for the chosen category. Tier V clients apply the filter locally; Tier W the Intake Sealer applies it in RAM. Envelope header lists recipient key IDs (pseudonymous, rotating per epoch) so recipients and auditors can verify the recipient set against the directory (THR-046). Channel Identity Keys remain for signing channel metadata only. Case keys (ADR-008) are wrapped only to members authorized after import; excluded members never receive them.
- SECURITY EFFECT: Excluded/accused members hold no key that decrypts the envelope, even with full database access. Hidden-recipient insertion detectable via directory/transparency log.
- PRIVACY EFFECT: Role labels in the directory reveal the org's recipient structure (acceptable; already public-facing). Envelope recipient count reveals routing breadth (padded to a fixed max recipient slot count, default 16, with dummy slots).
- USABILITY EFFECT: Source sees a simple optional checklist "Is your report about any of these people/roles?"; default none selected.
- OPERATIONAL EFFECT: Each member's client must be online at least once per epoch to publish next epoch keys (pre-publishes 4 epochs ahead). If no eligible member keys exist, intake for that channel shows "temporarily unavailable" (fail closed) rather than encrypting to fewer/other parties.
- ALTERNATIVES REJECTED: (a) policy-only; (b) group keys still expose the group containing the accused.
- EVIDENCE: INC-22 (Barclays/Staley), ADR-015, R2 CoverDrop per-journalist keys, R1 SecureDrop Protocol per-journalist one-time keys.

### ADR-031 Licensing of reusable crypto/safety libraries (amends ADR-020)
- DECISION: `candor-core` (C-11) and `candor-safefs` (ADR-027) are dual-licensed Apache-2.0 OR MIT to maximize independent reuse, review and funding; all other Trust Path code remains AGPL-3.0-or-later. Both remain in the public repository, reproducibly built and in audit scope.
- EVIDENCE: R6 licensing analysis; Sovereign Tech Agency funds base libraries.

### ADR-032 Onion service key on multiple intake hosts in HA profiles (amends ADR-024)
- DECISION: EE-HA/GOV-ONPREM may place the same onion service private key on ≤2 intake gateway hosts (active/passive; OnionBalance-style active/active deferred). This doubles THR-044 exposure; both hosts are within the Secret Placement Manifest (ADR-028) and monitored equally. Single-host profiles keep one copy plus an offline encrypted backup.

### ADR-033 Amendments from author review round 1 (amends ADR-008, -010, -012, -025, -030)
1. **Anonymous recipient slots (ADR-030).** The cleartext envelope header SHALL NOT contain recipient key IDs. It carries exactly 16 fixed-size HPKE slots (real + dummy, randomly ordered); recipients trial-decrypt all slots. The real recipient list (key IDs + directory tree head) is inside the AEAD-protected payload, signed by the Tier V client or the sealer, so recipients/auditors verify it against the Key Directory. Relies on KEM key-privacy (anonymity) of X-Wing/ML-KEM — recorded as ASM (see 40). Effect: server and DB thieves cannot tell which members were excluded (would otherwise hint at the accused).
2. **Epoch key retirement gated on import (ADR-008).** A member epoch private key is destroyed only after BOTH its decrypt window has passed AND every envelope stored under that epoch has been imported (or the envelope has been explicitly rejected with dual approval). Un-imported envelopes older than 7 days raise an escalation to the independent channel. Prevents suppression-by-waiting.
3. **Erasure Key vault (ADR-025) — layered construction (clarified in revision round 2).** Each case has a per-case **Erasure Key** (256-bit symmetric) held in an Erasure Key Vault (separate process/volume, excluded from routine backups; own backup with ≤14-day retention, see ADR-044(4)). The member-key wraps of the case key stored in the DB are **encrypted under the Erasure Key as an outer layer**: `stored_wrap = AEAD(EK_case, HPKE-wrap(member_pk, case_key))`. The Erasure Key alone decrypts nothing (it only removes the outer layer from wraps that still require a member private key); the server therefore never gains the ability to decrypt case content (ADR-007/008 preserved). Destroying the Erasure Key renders all backed-up copies of that case's wraps — and therefore its content — unreadable once vault backups older than the erasure have expired (≤14 days). Documented as the upper bound of "delete" for backups.
4. **Import time coarsening (ADR-010).** Case records store only `received_date` (UTC day). Relay pull times are not persisted beyond day granularity; the automatic import audit event records the date only.
5. **Viewer decryption scope (ADR-012).** Attachment content is decrypted only inside the viewer sandbox (C-17), with a single-use per-job key handed in; Candor Desk main process never holds attachment plaintext.

---

## 7. Revision ADRs from adversarial review (process/REVIEW-A.md, REVIEW-B.md, REVIEW-C.md)

These ADRs are binding and supersede conflicting text in earlier ADRs and documents. Disposition of every reviewer finding is recorded in `REVIEW-REPORT.md`.

### ADR-034 Tier W session and draft state (resolves RVW-A-02, A-07, B-12, B-13; supersedes 11 §5.6 on-disk drafts)
- DECISION: Tier W drafts (text and identity block) live **only in Intake Sealer RAM** (mlocked, no swap), keyed by an opaque session handle; attachment parts uploaded during a session are encrypted under a per-session key that exists only in sealer RAM and are written to a tmpfs staging area; the final HPKE seal of the content key happens **only after** the recipient set is fixed at Submit. Single timer set: 20 min idle, 2 h absolute; expiry zeroizes. The passphrase is **never stored** anywhere; it is displayed on the Recovery Credential screen and the source must confirm it (re-type 3 randomly chosen words) before the submission is finalized; if the response is lost, the submission is not finalized and the source restarts. Restart of the sealer loses drafts (accepted; UI states this). PRD text "typed text is never stored server-side" is amended to "never persisted to disk".
- EFFECT: removes on-disk passphrase/identity/timer residue; bounded RAM exposure only.

### ADR-035 Intake integrity evidence against compelled or compromised operators (resolves RVW-A-01, A-03, A-13, A-17; RVW-C-04)
- DECISION:
  1. **External Watchers**: the public reproducible release publishes digests of all static source-UI assets and templates; ≥2 independent watcher organisations (at least one outside the operator's jurisdiction for EE/GOV/MANAGED) periodically fetch the onion service over Tor and compare served static assets, CSP headers and the Sealer's signed **running manifest** (release digest) to the transparency log; mismatches are published.
  2. **Operator Statement**: a quorum-signed (k-of-n, including ≥1 independent role) operator statement ("no compelled modification, no instrumentation of intake memory, no targeted update") is published in the Key Directory every 30 days; absence or failure to renew is shown to sources as a warning banner. (Honest limit: canaries are legally uncertain and can be coerced; they are a signal, not a guarantee.)
  3. **Confidential-VM profile (optional, HIGH/GOV)**: the Sealer may run in an AMD SEV-SNP or Intel TDX confidential VM; its attestation report binds the sealer measurement to a logged release; Desk and watchers verify it. TEEs have a record of side-channel breaks; this is defense in depth, recorded as an assumption in 40, never presented to sources as a guarantee.
  4. **Intake memory/packet capture during incident response** requires approval by an independent role (channel OVERSIGHT or external ombudsman) in addition to the organisation's IR lead, captures are encrypted to independent custodians, and a source-visible INCIDENT_NOTICE directory entry is published.
  5. Source-facing honesty text (11, 05) SHALL state: "If the intake server is compromised or legally compelled while you use the website (no-JavaScript) version, what you type, and your passphrase when you log in, can be captured. For the highest risk, use the Candor Source App."
  6. 02/03 SHALL only credit controls actually specified; threat ratings are re-derived.

### ADR-036 Key Directory change governance (resolves RVW-A-04, A-05, A-06, A-08, A-29; RVW-C-05)
- DECISION:
  1. Channel Identity Key (CIK) held only by the channel's **Triage Set** (ADR-037) and OVERSIGHT, never by every member.
  2. Roster additions, role-label changes and COI-policy loosening are **time-locked 72 h** (GOV/HIGH: 7 days), notified content-free to all current members and OVERSIGHT, and require dual approval with ≥1 approver from an independent role; the `person_ref` for enrolment is verified out of band by the second approver. Removals and tightening take effect immediately.
  3. Role labels are certified (signed) by OVERSIGHT; Tier V clients warn when a member key is <7 days old.
  4. **Follow-up sealing rule**: follow-up messages from a source are sealed only to members who were in the eligible set of the original report AND are still members; access for later members comes only via case-key wrapping by the Triage Set (audited).
  5. Key Directory checkpoints require ≥2 external witness cosignatures (≥1 outside the operating organisation) in EE/GOV/MANAGED; recommended in CE. Tier V clients pin the last seen tree head (persistent pin in the Source App; for the web bundle, the pin is shown as a short fingerprint the source may note).
  6. The intake enforces a **snapshot high-water mark** (monotonic tree size and time; rollback rejected) and derives time from an independent source (signed Tor consensus valid-after as floor, plus Roughtime), not from Z-CORE alone.
  7. Directory publications (epoch keys, roster changes) are batched to a fixed weekly publication slot to avoid revealing staff activity timing.
- Tier W limit (honest): Tier W sources cannot verify the directory themselves; verification for them is performed by Desk at import (recipient-list check) and by External Watchers; the Tier W UI SHALL NOT present verification affordances it cannot deliver.

### ADR-037 Triage-first routing and blinded COI state (amends ADR-030; resolves RVW-B-01, B-02, B-03, B-04, A-18; RVW-C-05)
- DECISION:
  1. Each channel defines a **Triage Set** of ≥2 members holding independent-body role labels (ombudsman, audit committee, external counsel, IG, ethics officer; or channel owner + OVERSIGHT where none exist). Envelopes are wrapped **only** to eligible Triage Set Member Epoch Keys after the source's COI ticks remove any flagged roles. If fewer than 1 eligible triage member remains, the source is directed to an alternative independent channel (fail closed).
  2. After triage assesses COI (including direct-manager/manager-chain checks using HR data held outside Candor or by the triage member), the Triage Set wraps the Case Key to further investigators. Non-triage members never list, receive notifications for, or trial-decrypt intake envelopes; channel dashboards for non-triage roles show no intake counts.
  3. COI exclusions are stored only as blinded tags `HMAC(K_case_excl, user_id)` with `K_case_excl = HKDF(case_key, "candor/coi-excl/v1")`, padded to 8 tags per case; the server checks membership blindly; Desks verify on sync that no wrap exists for an excluded user. Audit reason codes SHALL NOT distinguish COI removals from other removals; no event, table or export associates a user identity with a COI exclusion for a specific case.
  4. The COI checklist screen states: "Your answers are encrypted and seen only by the independent triage team, who use them to keep the people involved away from your report. They may still suggest what your report is about."

### ADR-038 Arrival/import decoupling and constant-schedule signals (amends ADR-010, ADR-017, ADR-033(4); resolves RVW-A-09, A-19, A-20, A-22, A-27; RVW-B-06, B-11; RVW-C-02)
- DECISION:
  1. Relay imports run on a **fixed schedule** (default 4×/day at fixed times; HIGH/GOV: 1×/day at a fixed time), never event-driven; therefore case DB WAL/commit times, blob mtimes and backups reveal only the schedule slot. Blob object metadata times are normalized to the slot time; import audit events carry date only.
  2. Staff notifications are **constant-schedule**: a content-free daily digest is sent at a fixed time every day to each subscribed member whether or not anything is pending (or notifications are disabled, the HIGH default). No event-driven email.
  3. Message/submission dates are displayed to staff at day granularity (standard) or ISO week (HIGH); per-case lists of source activity days are not stored — each follow-up record stores only the import slot date; quota history is not retained (current counters only, reset daily).
  4. Optional source **delayed delivery**: the source may choose "deliver after a random delay of 1–3 days"; the sealed envelope is held in the intake with a release date.
  5. Tier W uploads are padded (ADR-011 buckets) before staging; global rate-limit/queue states are not exposed in any response or dashboard beyond a coarse daily health band.
  6. Undecryptable/unimportable envelopes: after 14 days pending and dual-approved rejection they are deleted so epoch keys can retire; escalation per ADR-033(2) is rate-limited per channel.

### ADR-039 Metadata-private reply retrieval (resolves RVW-A-10, A-26)
- DECISION: Tier V clients retrieve replies by **fetch-all dead-drop**: the intake publishes all reply ciphertexts of the last 30 days in fixed-size pages; the client downloads the full set and trial-decrypts locally, so the server cannot tell which mailbox was checked. Tier W necessarily performs server-side lookup after passphrase derivation (documented residual). No per-mailbox access time, count or history is stored; `tier` column and own-message history are removed from the intake schema; header digests retained ≤24 h for dedup only.

### ADR-040 Platform package supply chain and security floors (resolves RVW-A-12, A-13, A-16; RVW-C-17)
- DECISION: OS, tor and PostgreSQL packages for Z-INTAKE and Z-CORE come from a pinned, snapshot-based mirror; each Candor release includes a TUF-signed **Platform Manifest** (package names, versions, hashes) that the self-test verifies; tor packages from the Tor Project repository pinned by key and version. Trust-path components refuse to start below a signed **security floor** version; Fleet Manager ring policies cannot hold an instance below the floor. Emergency releases keep a minimum 2-hour cooling period with ≥2 signers from ≥2 organisations; release signers and builders span ≥2 organisations and ≥2 jurisdictions (amends ADR-022). Secure boot uses the distribution-signed shim/kernels; no per-kernel offline signing ceremony is required.

### ADR-041 Client acquisition as a metadata flow (resolves RVW-A-14)
- DECISION: The Candor Source App is downloadable from the Candor project's onion service and independent mirrors (reproducible, signed); the operating organisation's clearnet information site SHALL NOT host the App or log downloads; it links to the project distribution and explains that downloading over Tor is safest. App-store distribution is optional and documented as leaving account-linked records.

### ADR-042 Desk containment per platform and hostile-string rendering (resolves RVW-A-15, A-24, A-30; RVW-C Section 508 viewer finding)
- DECISION: Supported Desk platforms are tiered. **Tier 1**: Linux with KVM microVM viewer, and Qubes OS. **Tier 2**: Windows (Hyper-V isolated VM viewer) and macOS (Virtualization.framework VM viewer). Where no hardware-isolated viewer is available, only CL-0 (metadata-free text preview of sanitized text) is permitted and originals cannot be opened. Source-supplied strings are rendered as plain text only (no HTML/Markdown rendering) in the webview with a strict CSP and Trusted Types. Pixel-rendered copies are labelled "rendering — not evidence"; converter output hash and converter release digest are recorded; sanitized copies include an OCR text layer produced inside the sandbox for accessibility.

### ADR-043 Recipient device custody for independent channels (resolves RVW-C-01, RVW-A-24)
- DECISION: Channels whose adversary may be the operating organisation (type INDEPENDENT: IG, audit committee, ombudsman, external counsel, ethics) SHALL require **independent-custody devices** for Triage Set members: Desk devices not enrolled in the organisation's MDM/EDR/DLP/VDI, with hardware authenticators whose attestation is recorded; Desk verifies its own binary against the transparency log and reports its release digest (non-authoritative, detects accidental divergence only). The Admin UI shows the custody status; enabling an INDEPENDENT channel without it is DANGEROUS. Honest residual: an organisation that controls a member's endpoint can defeat Desk protections; the spec cannot prevent this technically.

### ADR-044 Key-access continuity, records obligations and recovery (resolves RVW-C-03, C-06, C-07, C-14)
- DECISION:
  1. SCIM/HR/IdP changes can only **suspend** server-side authorization; deleting a member's key wraps requires dual control, a 7-day cooling-off and OVERSIGHT notice (except source-requested erasure or retention expiry).
  2. `min_recipients` per case default **2**; each member SHALL enrol ≥2 hardware authenticators (primary + stored backup).
  3. GOV profile default: Organization Recovery Quorum **enabled** (ADR-013) with custodians from independent roles, disclosed to sources on the landing page, because records law may prohibit unrecoverable loss; CE/EE default remains disabled.
  4. Erasure Key Vault is replicated to the DR site within HA RPO; vault backups retained ≤14 days; restore applies the signed **erasure log** (append-only list of erased case IDs) before serving. Infrastructure-level backups (hypervisor/SAN) of core hosts MUST exclude the vault volume; the config checker asks for attestation and the documentation states that otherwise the 14-day deletion bound does not hold. HIGH/GOV: vault on physical host TPM, not vTPM.
  5. Records/FOIA/ATIP/GDPR/eDiscovery searches are performed in the Desk of an authorized member (local index over cases they can decrypt); a Records Custodian role receives explicit, audited, time-bounded case grants from the Triage Set; there is no server-side global search.

### ADR-045 Organisation-as-adversary controls (resolves remaining RVW-C governance findings)
- DECISION: Break-glass requires one approver from an independent role outside the legal/management chain; Fleet Manager cannot disable intake, lower security floors, or change routing (tighten-only for logging/retention; availability-affecting actions require the customer's independent role); small-organisation mode requires at least one external party (e.g., external counsel or board member) as OVERSIGHT and displays "reduced separation of duties" to admins and in the published operator statement.

### ADR-046 Consistency resolutions and parameter fixes (resolves RVW-C-08 and author open issues)
1. **Intake DB replication**: none in any profile (`wal_level=minimal`, no archiving, `track_commit_timestamp=off`). EE-HA intake failover is active/passive on shared-nothing hosts; envelopes pending on a failed node are recovered when its disk is recovered; the source sees "received" only after local fsync. HA-002 amended.
2. **HSM failure**: no fallback signing keys (FAIL-013 prevails over HA-013).
3. **Update paths**: Z-INTAKE fetches updates via the project's onion mirror over Tor; Z-CORE via an egress-restricted HTTPS mirror; both verify TUF.
4. **Uploads**: 08's resumable-upload protocol is canonical (per-upload tokens, no cross-session resume, 8 MiB chunks, 24 h max resume within one session only in Tier V; Tier W no resume). Per-file cap 4 GiB (standard), 16 GiB only in EE profiles with 08 chunk count raised accordingly.
5. **Metrics regime** (single source of truth: 24 §TEL): k = 10, minimum period one calendar month, complementary suppression, no medians/ratios/percentiles for cells < k, no per-channel metrics for channels with < 3 cases/month, SOC sees only global daily health bands.
6. **Config labels**: only SAFE / ADVANCED / DANGEROUS ("WEAKENING" → DANGEROUS). CE-SINGLE default isolation = VMs; container-only = ADVANCED.
7. **Source passphrase KDF**: Argon2id m=64 MiB, t=3, p=1 (security rests on ≈129-bit entropy; stretching is defense in depth), per-deployment salt acceptable for that reason; Tier W derivations limited by a concurrency semaphore (default 4) plus PoW. FIPS profile: PBKDF2-HMAC-SHA-512, 210,000 iterations. Sources may rotate their passphrase from the inbox.
8. **Post-quantum transport residual**: Tor onion circuits currently use classical key exchange; recorded Tier W sessions are exposed to harvest-now-decrypt-later. Documented; HIGH-risk guidance recommends Tier V (end-to-end hybrid PQ HPKE); adopt PQ onion handshakes when Tor ships them.
9. **Vanguards**: full vanguards add-on for HIGH; if unmaintained, rely on built-in vanguards-lite and Arti's vanguards (documented fallback).
10. **Recipient key IDs** never read from cleartext headers anywhere (RUI-055 amended).
11. **Staff exact timestamps**: permitted only in the enumerated SECURITY/SYSTEM tables listed in 09 (sessions, job leases, config cool-off, break-glass expiry) and audit events for staff actions; never for source-originated events.
12. **Two additional keys** are recognized in 04: Intake Routing Key (reply routing without case DB holding source account IDs) and Connector Key (export package encryption to integrations).

### ADR-047 Final round decisions from revision cross-document requests
1. **Source App on-device state** (DISP-G1): the Source App creates, at install, a fixed-size encrypted vault (CoverDrop-style) that exists whether or not it is used; Key Directory pins, the organisation's onion address and any passphrase-derived material live only inside it, unlocked by the passphrase. No plaintext organisation identifier is stored on the device. Residual: the app's presence itself (documented in 05).
2. **Follow-up dates** (RVW-B-11, DISP-G8): follow-up import dates are stored only inside the encrypted case record (under the case key); the cleartext case row keeps only `last_import_month`.
3. **Chaff envelopes** (RVW-B-04, RVW-A-09, DISP-G8): the Intake Sealer writes undecryptable chaff envelopes at a constant Poisson rate (default mean 1 per 2 h per channel, parameter in 24 §TEL-independent config) into the same store with identical format; real envelopes replace a scheduled chaff slot where possible (bounded delay ≤2 h, or immediate for the source-visible confirmation with the chaff schedule adjusted). Triage members routinely fail to decrypt envelopes, so exclusion is not inferable from a failed trial decryption; disk order/time reveals the chaff schedule rather than submissions. Chaff is discarded at import.
4. **Freshness bounds** (DISP-G8): the sealer and Tier V clients refuse to seal to a Key Directory snapshot older than 7 days (fail closed, "channel temporarily unavailable"); confidential-VM attestation evidence is refreshed at least every 24 h.
5. **IDENTIFIED mode over the onion service** (DISP-G4) is permitted: a source may choose to identify; identity goes to the Sealed Identity Store (ADR-014); the mode banner changes accordingly. ADR-002 amended.
6. **Per-locale passphrase wordlists** (DISP-G4) are permitted if each list is reviewed for unambiguous, non-offensive words and the word count is set so entropy ≥128 bits (`words = ceil(128 / log2(list_size))`); the wordlist language is not stored server-side. Passphrases are normalized (NFKC, lowercase, single spaces) before derivation.
7. **Case-key continuity after vault loss** (DISP-G6): each member's Desk keeps a hardware-sealed local cache of the case keys it is authorized for; after an Erasure Key Vault restore or loss, an authorized Desk re-creates outer-layer wraps under a new Erasure Key. Desk caches honour the erasure log on every sync (erased cases are purged locally).
8. **Per-case metadata erasure** (DISP-G6, RVW-B-21): sensitive cleartext case metadata fields (category, title, custom fields) are encrypted under a key derived from the case's Erasure Key, so erasure also removes metadata from backups within the ≤14-day bound.
9. **Intake DR deletion durability** (RVW-A-28): source-initiated deletions are recorded in a signed intake deletion list replicated to Z-CORE via the relay; any intake restore applies it before serving.
10. **MANAGED audit export key** (DISP-G6): audit exports in the MANAGED profile are encrypted to a customer-held key; the vendor cannot read audit contents.
11. **Canonical constants registry** is owned by `39-REQUIREMENTS-TRACEABILITY.md` §Constants and checked by the spec-constant lint (ST-167, SG-25).

### ADR-048 Owner sign-offs (2026-10-01)
The project owner approved the following judgement calls raised during revision:
1. **GOV profile Tier W default**: for CJIS/FIPS-mandated government deployments, the no-JavaScript web path (Tier W) is preselected OFF; enabling it is ADVANCED and requires a recorded agency determination (22 GOV-028).
2. **GOV Recovery Quorum**: enabled by default in the GOV profile, custodians from independent roles, disclosed to sources (ADR-044(3)).
3. **Library licensing**: `candor-core` and `candor-safefs` are Apache-2.0 OR MIT; all other Trust Path code AGPL-3.0-or-later (ADR-031).
4. **Implementation scope**: implementation begins with the Community Edition only (open-source Trust Path, milestones RM-0 and RM-1 of 38). No Enterprise module work until CE 1.0 GA (RM-004).

### ADR-049 Verification-pass corrections (2026-10-01; process/VERIFICATION-PASS.md)
1. **Vanguards** (amends ADR-001, ADR-046(9)): the Python `vanguards` add-on is dormant (no commit since 2023-10-31, last tag v0.3.1), so its maintenance gate fails. All profiles, including HIGH, use C-tor's built-in **vanguards-lite**; the add-on SHALL NOT be deployed. Full vanguards arrive with the Arti migration (Arti enables vanguards by default).
2. **Arti PoW** (amends 16 NET-017 / RM-12): Arti's onion-service PoW exists only behind the experimental `hs-pow-full` feature. Arti migration of the intake onion service is blocked until PoW is available in a non-experimental, default-enabled form; until then C-tor ≥0.4.8 with PoW remains the intake daemon.
3. **Unconfirmed CVE identifiers**: CVE-2026-45020 [CVE record unconfirmed], -46647, -46648 and -50000 appear on GitHub advisory pages cited in R1/R2, but no CVE List record was found on 2026-10-01. Specs cite them as "[CVE record unconfirmed]"; the design lessons stand on the advisory descriptions (B-GL-37, B-SD-20) regardless of CVE numbering.

### ADR-050 Implementation findings from candor-core (2026-10-01; crates/candor-core/SPEC-NOTES.md)
1. **Dummy-slot encapsulation randomness** (amends 04 §13.2): X-Wing encapsulation consumes 64 bytes of randomness. The 32-byte HKDF output `r` is expanded as `enc_rand = ChaCha20(key = r, nonce = 0^96, counter = 0)` keystream bytes 0..63. KATs pin this.
2. **Passphrase wordlist** (amends 04 §11.1): the four hyphenated entries of the EFF large wordlist (`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`) violate the separator rule and are excluded; the shipped list has 7,772 words (10 words ≈ 129.24 bits). The SHA-256 of the unmodified upstream file and of the shipped list are recorded in the constants registry.
3. **Full recipient-set verification** (amends 04 §13.2/§13.4, closes a gap where slot counting detected extra recipients but not a listed recipient swapped for an attacker key): each Recipient List entry carries `{slot_index, key_id, enc_rand (64 B)}`. Real slots are encapsulated with that randomness (drawn from the CSPRNG at sealing). Every recipient, having CK, re-derives every slot deterministically: listed slots by re-encapsulating to the listed member key from the Key Directory with `enc_rand`, dummy slots per item 1, and requires byte equality for all 16 slots. Revealing `enc_rand` inside the AEAD gives recipients nothing beyond CK, which they already hold. Any mismatch quarantines the envelope (THR-046).
4. **Source KEM key** uses HPKE `DeriveKeyPair(kem_seed)`; dummy slot index `i` equals the slot position in the block.

### ADR-051 Integration decisions, first Community Edition build (2026-10-01)
1. **sha3 duplicate (cargo-deny exception)**: `hpke =0.14.1` uses sha3 0.12 directly and sha3 0.11 via `ml-kem 0.3.2`. Both are RustCrypto with no advisory. A version-pinned `skip` for `sha3@0.11.0` is enabled in `deny.toml` as an interim exception approved by the project owner; it expires 2026-12-30 and must be removed when ml-kem moves to sha3 0.12.
2. **Source page size classes** (11 §5.4): the size class stays a function of the request type (unauthenticated GET → P1), never of the page, so that page identity is not revealed by size. S02 stays in P1. Every shipped locale must render every P1 page within budget; this is enforced by a build-time test. A locale that cannot fit S02 moves its high-risk guidance into a linked sub-page (S02b, also P1) rather than enlarging S02.
3. **Audit retention and labels**: `20-LOGGING-AUDITING.md` is canonical for audit-event names, health-band labels and audit-log retention defaults (400 days for SECURITY/CASE streams, 30 days for SYSTEM). `09-DATABASE.md` and `24` §TEL defer to it for these values. 24 §TEL remains canonical for metric thresholds (k, period, suppression).
4. **Form token name**: the no-JS form CSRF field is named `csrf`; 08 and 11 align to it.
5. **Reproducible builds**: the reproducibility check remaps the source, target and Cargo-home path prefixes. Build scripts that embed `OUT_DIR` paths otherwise make `.rlib` outputs path-dependent.

### ADR-052 RM-2 audit-driven decisions (2026-10-01; process/audits/AUDIT-RM2-*.md)
1. **Uniform envelope shape (AUD-RM2-SEA-01).** Text-bearing objects (SUBMISSION, SOURCE_MESSAGE, IDENTITY) are always padded to the maximum bucket of their type, removing size as a signal. Every intake envelope group has the same object set — main object + ATTACHMENT_BUNDLE + IDENTITY — with dummy objects where the source supplied none. Chaff groups are built identically; chaff bundle sizes are drawn from a configured distribution approximating real attachments (residual: unusually large real bundles remain distinguishable by size; documented in 03 and 05 guidance).
2. **No account linkage on envelope commit (AUD-RM2-SEA-02; amends 07/09).** Envelope rows carry no account reference. Account creation and update are a separate store operation, exercised by chaff too (dummy accounts with random lookup tags that expire like abandoned real accounts). Delivery-delay offsets for chaff are drawn from the same distribution as real choices. A seized intake store cannot separate real from chaff envelopes by metadata.
3. **COI filtering per person (AUD-RM2-SEA-03).** Exclusion applies to the person (user identity key), not the roster entry: if any of a person's role labels is excluded, all of that person's member keys are excluded.
4. **IPC robustness (AUD-RM2-SEA-04).** Every unix-socket service enforces a connection cap, per-connection read/idle timeouts and memory caps, and keeps accepting after `EMFILE` (back-off, never exit the accept loop).
5. **Fail closed on hardening and randomness.** Services refuse to start if their in-process hardening (dumpable off, core limit, mlock, Landlock) cannot be applied, unless an explicit, logged developer flag is set; any CSPRNG failure aborts the operation.
6. **Verified snapshots.** Key Directory snapshots are only usable through a `VerifiedSnapshot` type produced by checking signatures, witness cosignatures, continuity and the high-water mark. The sealer reloads verified snapshots in place by atomic swap, so sessions survive.
7. **cargo-deny exception:** `sha2@0.10.9` (pulled by sqlx; no advisory) is an interim pinned skip, expiring 2026-12-30.
8. **cargo-vet staging:** PR CI requires `safe-to-deploy` for all dependencies; `candor-crypto-reviewed` is enforced by the release workflow (release gate) and needs real Crypto Reviewer audits before RM-6. Baseline exemptions never grant crypto-reviewed.
9. **Database migrations:** `candorctl migrate` runs as a dedicated OS user `candor-migrate` mapped by a single peer-auth `pg_hba` line to a migration role; no superuser single-user mode.
10. **Sealer egress:** the sealer's syscall allow-list permits `connect` for AF_UNIX only (store socket).
11. **Circuit IDs:** the per-circuit identifier exported by tor may be used in memory only, for per-circuit rate limiting (16 §7.1 prevails over 17 §5.5); never persisted, logged or exported.
12. **Secret placement:** the manifest includes the intake batch signing key (K31) and sealer signing key (K35).
13. **Tier W draft cap:** draft text is capped at 40 KiB so a SUBMISSION always fits its 64 KiB bucket (amends 07's 96 KiB).
14. **Intake database:** no time-typed columns; account rows are rewritten only at fixed import slots (`uniform_rewrite`); upload quotas live only in process memory; expected duplicates never raise server errors; intake PostgreSQL logging is disabled (`log_min_messages = panic`, output discarded).

### ADR-053 Intake host observability without metadata (2026-10-01; deploy/SPEC-NOTES.md D-27, D-28; AUD-RM2-DEP-04/05/06)
1. **No tor control interface on the intake instance** (amends NET-009 and 16 §15): `ControlPort 0`, no `ControlSocket`. Control access would expose circuit/stream events (exact visit times) and path-selection settings. Intake health comes from unit/process state and a periodic self-fetch of the onion's health endpoint through a SOCKS listener on the client-only `candor-update` tor instance (unix socket, health group only). Descriptor-integrity checks move to the external monitor (C-25), which fetches descriptors itself.
2. **No source-path service output in any journal** (amends NET-008, 20 §11.3 and the 32 logging rows): tor, web, sealer, store and intake PostgreSQL set `StandardOutput=null`, `StandardError=null`, `LogLevelMax=emerg`, because journald stores microsecond timestamps that cannot be coarsened. Hour-granular SYSTEM events (LOG-004) go only through a candor-log sink that truncates time before writing. Host journal: `Storage=volatile`, `MaxRetentionSec=24h`, `MaxFileSec=1h`, `Audit=no`, no forwarding. Crash diagnosis uses unit state or a dual-approved, time-boxed (≤1 h) debugging window. Residual: kernel OOM/segfault lines, limited by `kernel.printk` and `dmesg_restrict`, kept ≤24 h in RAM.
