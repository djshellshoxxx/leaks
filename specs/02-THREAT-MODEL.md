# 02 — Threat Model

Status: Draft v1.0 · Edition applicability: both (CE and EE; EE-only components marked) · Owner: Security Architecture

## 1. Purpose and scope

This is the formal threat model for Candor, written **before implementation** so that the design documents (04–38) implement mitigations for enumerated threats instead of discovering them later. It owns the `THR-` (threat) and `ADV-` (adversary) identifier spaces.

Contents: asset inventory (§4); system model, trust boundaries and data flows (§5); adversary catalog ADV-01..ADV-30 (§6); STRIDE per zone (§7); LINDDUN privacy analysis (§8); threat catalog THR-001..THR-048 (retained from DECISIONS §5) and THR-100..THR-125 (new) (§9); attack trees (§10); abuse cases (§11); component compromise analysis for every component in DECISIONS §4 plus infrastructure elements (§12); threat-model obligations (§13); residual risks (§14); open issues (§15).

Scope: all deployment profiles (ADR-024), both client tiers (ADR-004), all three modes (ADR-002), CE and EE, and the MANAGED service. Out of scope: physical safety of individuals beyond platform influence; legal strategy.

## 2. Context and dependencies

| Document | Relation |
|---|---|
| `DECISIONS.md` | Component IDs (C-nn), zones, ADRs, core threat IDs THR-001..048 (retained verbatim in title). |
| `01-PRODUCT-REQUIREMENTS.md` | Personas map to adversaries (a persona can be an adversary: PER-08 → ADV-04). |
| `03-PRIVACY-ANONYMITY.md` | Metadata inventory and legal-compulsion inventory are the "observable information" ground truth for §6. |
| `04-CRYPTOGRAPHY.md`, `15-AUTHENTICATION-AUTHORIZATION.md`, `16-TOR-I2P.md`, `10-FILE-EVIDENCE-PIPELINE.md`, `20-LOGGING-AUDITING.md`, `28-SUPPLY-CHAIN.md`, `33-RELEASE-UPDATE-SECURITY.md` | Primary mitigation owners referenced below. |
| `29-SECURITY-TESTING.md`, `30-ANONYMITY-TESTING.md`, `37-SECURITY-AUDIT-PLAN.md` | Verification of mitigations; test IDs assigned there. |
| `31-INCIDENT-RESPONSE.md` | Executes the recovery procedures of §12. |
| `40-SECURITY-ASSUMPTIONS.md` | ASM-* IDs. This document states assumptions in words and tags them `[A:…]`; `40` assigns the ASM IDs (see Open Issues). |

Evidence base: R3 incidents (INC-01..74), R4 anonymity attacks (B-AN-*), R1/R2 advisories (B-SD-*, B-OS-*, B-GL-*), R5 crypto/sanitization/supply chain (B-CR-*).

## 3. Method and rating

1. **Model**: zones and components from DECISIONS §4; data flows DF-nn (§5.3).
2. **Adversaries** (§6) defined by capability, not intent labels only.
3. **STRIDE** per zone (§7) for security; **LINDDUN** (§8) for privacy/anonymity.
4. **Threats** (§9): each with description, adversaries, assets, components, inherent risk, mitigations, residual risk.
5. **Attack trees** (§10) for the five mandated goals plus two additional (unseal identity, hidden recipient).
6. **Component compromise** (§12): assume total compromise of each component, derive what is learned, blast radius, detection, recovery.

**Rating scale.** Likelihood L1 (rare: requires capabilities few adversaries have and no known instance) … L5 (expected: observed routinely). Impact I1 (minor availability/annoyance) … I5 (source identified, or mass disclosure of report content, or silent persistent compromise of all instances). Risk = L×I: 1–4 Low, 5–9 Medium, 10–15 High, 16–25 Critical. "Inherent" = without Candor-specific mitigations; "Residual" = with mitigations specified in the referenced documents, under the stated assumptions.

**Standard assumptions used below** (to be assigned ASM IDs in `40-SECURITY-ASSUMPTIONS.md`):

| Tag | Assumption |
|---|---|
| [A:TOR] | Tor v3 onion services provide sender anonymity against adversaries that do not observe both the source's link to its guard and the service's link, and do not control the relevant guards. |
| [A:DEV] | The source's device, OS and Tor Browser/Source App are not compromised at the time of use. |
| [A:RCP] | At least one authorized recipient endpoint (C-15/C-16) per case is uncompromised and its hardware token is not coerced. |
| [A:CRYPTO] | HPKE/X-Wing, XChaCha20-Poly1305/ChaCha20-Poly1305, AES-256-GCM, HKDF, Argon2id, Ed25519, ML-DSA-65, ML-KEM are secure as specified and implemented without exploitable flaws in candor-core. |
| [A:BUILD] | At least one of the ≥ 2 independent builders and at least a threshold of release signers are honest and uncompromised. |
| [A:MON] | At least one party independent of the operator monitors the release and key transparency logs (THR-118). |
| [A:OPSEC] | The source follows the guidance for their risk level (network, device, timing, content). |
| [A:SEAL] | The kernel/hypervisor of the intake host enforces process isolation and memory locking for C-07. |
| [A:TIME] | Hosts have time within ±5 minutes of true time from ≥ 2 independent sources. |

## 4. Asset inventory

Properties: C = confidentiality, I = integrity, A = availability, U = unlinkability (inability to link to a person or to other actions).

| ID | Asset | Property | Where it exists | Harm if compromised |
|---|---|---|---|---|
| AST-01 | Real-world identity of an anonymous source | U, C | Nowhere in the platform by design; inferable from content/behavior | Retaliation, dismissal, prosecution, physical harm |
| AST-02 | Source network identity (IP, access network, ISP account) | U, C | Source device, local network, ISP, Tor guard; never in Candor (ADR-001) | Direct identification |
| AST-03 | Source behavioral/timing metadata (visit times, frequency, sizes) | U | Tor network observers; C-05/C-06 transiently; day-granularity in C-08 | Intersection with employer logs (INC-31) |
| AST-04 | Report content (text, questionnaire answers) | C, I | C-02/C-03 (plaintext); C-07 transiently (Tier W); ciphertext in C-08/C-12/C-13/C-27; plaintext in C-15/C-17 | Disclosure, identification through content, harm to accused |
| AST-05 | Evidence attachments (originals) and embedded file metadata | C, I | As AST-04 | As AST-04; metadata identifies source (INC-17, INC-20) |
| AST-06 | Existence of a report and the fact that it concerns a person/role | C | Case metadata (C-12), COI exclusions, key-wrapping sets, notifications | Accused alerted; evidence destruction; retaliation |
| AST-07 | Source Passphrase and derived source keys | C | Source memory/paper; C-03 memory; C-07 memory transiently (Tier W login) | Mailbox takeover, impersonation (THR-121) |
| AST-08 | Mailbox replies | C, I | Sealed in C-08/C-12; plaintext at C-15 and at source | Disclosure; manipulation of source |
| AST-09 | Sealed identity (CONFIDENTIAL) | C | Encrypted to Identity Custodian keys in C-12/C-13 | Direct identification |
| AST-10 | Channel Identity Keys (signing) | I | Wrapped on member C-15 | Roster/epoch-key forgery (THR-046) |
| AST-11 | Channel Epoch private keys | C | Wrapped on member C-15; destroyed after window | Decrypt envelopes in window |
| AST-12 | Case keys | C | Wrapped to member X-Wing keys (C-12 stores wrappings) | Decrypt case |
| AST-13 | Staff identity/encryption private keys | C, I | C-15 sealed by hardware token | Decrypt all cases of that member; impersonate |
| AST-14 | Identity Custodian keys | C | Custodian C-15 + hardware token | Unseal identities |
| AST-15 | Recovery Quorum shares | C | Offline hardware tokens (C-28) | With k shares: decrypt all cases wrapped to quorum |
| AST-16 | Onion service private key | C, I | C-05; offline backup | Impersonate intake; phish sources (THR-044) |
| AST-17 | Release signing / TUF / transparency-log keys | I | Offline threshold custody (C-32) | Malicious update to all instances (THR-025) |
| AST-18 | Key Directory & Transparency Log integrity | I | C-14, published via C-06, verified by C-03/C-15 | Hidden recipient / key substitution (THR-046, THR-102) |
| AST-19 | Source-side code integrity (Tier W HTML/CSS; WEBCAT bundle; Source App) | I | C-06, C-33, app stores | Hushmail-class capture (THR-007), NIT (THR-008) |
| AST-20 | Desk / viewer / admin code integrity | I | C-33, C-15, C-17, C-19 | Key theft, plaintext theft |
| AST-21 | Server-visible case metadata (allow-list) | C, I | C-12 | Inference of report topics, workload, routing |
| AST-22 | Audit logs | I, C | C-24 | Covering tracks; logs becoming identifying (THR-038) |
| AST-23 | Staff credentials and sessions | C, I | C-21, C-15, tokens | Impersonation |
| AST-24 | Configuration (rosters, COI map, DANGEROUS flags, routing rules) | I | C-10, C-12, C-14, config files | Silent weakening (THR-035) |
| AST-25 | Backups | C, I, A | C-27 | Resurrection of deleted data; theft (INC-55) |
| AST-26 | Intake availability | A | C-05..C-08 | Sources pushed to unsafe channels |
| AST-27 | Evidence integrity / chain of custody | I | Hashes in encrypted case record; CASE audit | Unusable evidence; wrongful outcomes |
| AST-28 | Intake service location (host IP, hosting provider) | C | Hosting provider, operator | Seizure, targeted compulsion, guard discovery |
| AST-29 | Vendor-side customer metadata (who runs Candor; opaque instance IDs; support tickets) | C | C-34, C-35, C-36 | Mapping onion address → organization; targeted updates |
| AST-30 | Program statistics / aggregates | C | C-10 reports, C-26, telemetry | Small-cell inference (THR-039) |
| AST-31 | Export Packages | C, I | Created in C-15; external destinations | Uncontrolled disclosure |
| AST-32 | Identity of recipients/custodians/quorum holders | C | Key directory (roles, fingerprints), HR | Coercion targets (THR-116) |
| AST-33 | Time source integrity | I | NTP/chrony on hosts | SLA, epochs, audit ordering (THR-043) |
| AST-34 | Infrastructure at-rest keys (LUKS/TPM, DB TDE, backup encryption) | C | Hosts, TPM, C-29 | Media-level exposure (not content: ADR-008) |
| AST-35 | Source repository, CI secrets, build environment integrity | I | C-30, C-31 | Supply-chain compromise (THR-024) |

## 5. System model

### 5.1 Trust boundary diagram

```mermaid
flowchart LR
  subgraph ZSRC[Z-SRC source device - untrusted by Candor]
    C01[C-01 Device+OS]
    C02[C-02 Tor Browser]
    C03[C-03 Source App + Arti]
  end
  subgraph ZNET[Z-NET Tor network]
    C04[C-04 Relays / HSDir / intro / rendezvous]
  end
  subgraph ZINTAKE[Z-INTAKE onion-only host(s)]
    C05[C-05 Intake Gateway tor+PoW+vanguards]
    C06[C-06 Source Web Service]
    C07[C-07 Intake Sealer isolated proc]
    C08[(C-08 Intake Store)]
  end
  subgraph ZCORE[Z-CORE internal case zone]
    C09[C-09 Intake Relay - pulls]
    C10[C-10 Case Service + C-22 AuthZ]
    C21[C-21 Auth Service]
    C14[C-14 Key Directory + TLog]
    C23[C-23 Notifications]
    C24[C-24 Audit Log]
    C12[(C-12 Case DB)]
    C13[(C-13 Blob Store)]
  end
  subgraph ZRCP[Z-RCP recipient endpoints]
    C15[C-15 Candor Desk]
    C16[C-16 Workstation OS]
  end
  subgraph ZVIEW[Z-VIEW containment]
    C17[C-17 Viewer microVM/DispVM]
    C18[C-18 Air-gapped station]
  end
  subgraph ZADM[Z-ADM]
    C19[C-19 Admin Console/candorctl]
    C20[C-20 Admin workstation]
    C28[C-28 Recovery Quorum offline]
  end
  subgraph ZSOC[Z-SOC]
    C25[C-25 Monitor]
    C26[C-26 SIEM export EE]
  end
  subgraph ZBAK[Z-BAK]
    C27[(C-27 Backups)]
  end
  subgraph ZSUP[Z-SUPPLY]
    C30[C-30 Repo] --> C31[C-31 CI + builders] --> C32[C-32 Signing+TUF+TLog] --> C33[C-33 Mirror]
  end
  subgraph ZVEN[Z-VENDOR]
    C34[C-34 Fleet Mgr EE]
    C35[C-35 Licensing EE]
    C36[C-36 Support]
  end
  C37[C-37 Clearnet info site]
  C38[C-38 Confidential clearnet intake - off by default]

  C02 -- TB-01 --> C04
  C03 -- TB-01 --> C04
  C04 -- TB-02 --> C05
  C05 -- TB-03 unix socket --> C06
  C06 -- TB-04 IPC --> C07
  C07 -- TB-05 --> C08
  C09 -- TB-06 core-initiated pull only --> C08
  C09 --> C10
  C10 -- TB-07 --> C12
  C10 --> C13
  C15 -- TB-08 mTLS staff path --> C10
  C15 -- TB-09 one-way file in / pixels out --> C17
  C19 -- TB-10 --> C10
  C25 -- TB-11 pull --> C05
  C10 -- TB-11 allow-list events --> C26
  C12 -- TB-12 --> C27
  C33 -- TB-13 TUF-verified --> C05
  C33 -- TB-13 --> C15
  C34 -. TB-14 opaque IDs .-> C19
  C23 -- TB-19 content-free --> EXT[External mail/chat]
  C10 -- TB-17 Export Packages only --> C40[C-40 Connectors EE]
  C37 -. TB-15 publishes onion address .- C02
  C38 -. TB-16 .- C02
```

Physical/virtual substrate (C-39, hypervisor, TPM/HSM C-29) underlies every server zone (TB-18).

### 5.2 Trust boundaries

| ID | Boundary | Crossing | Controls at boundary |
|---|---|---|---|
| TB-01 | Source device → Tor network | Tor cells (possibly via bridge) | Tor Browser/Arti; no Candor code on this path except C-03 |
| TB-02 | Tor → Intake Gateway | Rendezvous circuits to onion service | Onion-only, PoW, vanguards, intro rate limits (ADR-001, ADR-026) |
| TB-03 | tor daemon → C-06 | HTTP over Unix socket; optional circuit-ID PROXY header | No IP ever present; header allow-list; no access log (ADR-016) |
| TB-04 | C-06 → C-07 | Streamed plaintext (Tier W) or ciphertext (Tier V); passphrase at login | Separate process/UID, seccomp, mlock, no swap, no core dump (ADR-004) |
| TB-05 | C-06/C-07 → C-08 | Sealed envelopes, source account records | DB role separation; only sealed data written |
| TB-06 | Z-INTAKE ↔ Z-CORE | C-09 pulls envelopes; pushes sealed replies + key-directory snapshots | Firewall: no Z-INTAKE-initiated connection; mTLS; batch signatures (ADR-009) |
| TB-07 | Z-CORE services → C-12/C-13 | SQL, blob I/O | RLS per tenant, least-privilege DB roles; ciphertext only in C-13 |
| TB-08 | C-15 → C-10 | Desk API (audience `desk-api`) over staff network or restricted-discovery onion; mTLS | WebAuthn/PIV auth, audience-bound tokens (ADR-029), deny-by-default routes |
| TB-09 | C-15 → C-17 | One file into disposable, network-less VM; sanitized PDF/pixels out | Qubes/microVM isolation; no network; one-way flow (ADR-012) |
| TB-10 | Z-ADM → servers | SSH with hardware-backed keys; `candorctl` admin API (audience `admin-api`) | Dual approval for DANGEROUS config; SECURITY audit |
| TB-11 | Servers → Z-SOC | Health pull; allow-listed events | Typed event schema, k-threshold counters, no source-sensitive fields (ADR-016) |
| TB-12 | Servers → Z-BAK | Encrypted backup streams | Backups of ciphertext; key material excluded (ADR-025) |
| TB-13 | Z-SUPPLY → instances | Packages, images, TUF metadata | TUF threshold signatures, reproducible builds, transparency log (ADR-022) |
| TB-14 | Z-VENDOR ↔ customer | Fleet status (opaque IDs), license files, support bundles | No onion address in cleartext, no content, no keys; scrubbed bundles (INC-56) |
| TB-15 | Internet → C-37 | HTTPS GETs | Static; no forms; no logs; Tor-exit check in memory only (ADR-003) |
| TB-16 | Internet → C-38 | HTTPS form posts (CONFIDENTIAL only) | Off by default; "NOT ANONYMOUS"; separate host |
| TB-17 | Z-CORE → external systems | Export Packages; scrubbed events | Human-created, dual-approved for originals (ADR-018) |
| TB-18 | Hypervisor/hardware → guests | Memory, disk, CPU | Dedicated hosts for Z-INTAKE (ADR-024), disk encryption, TPM measured boot |
| TB-19 | C-23 → mail/chat providers | Content-free notifications | Fixed text, hourly digest (ADR-017) |

### 5.3 Data flows

| ID | Flow | From → To | Data | Tier/mode notes |
|---|---|---|---|---|
| DF-01 | Onion address discovery | C-37 / press / word of mouth → source | Onion address, guidance | C-37 compromise → THR-103 |
| DF-02 | Landing GET | C-02/C-03 → C-05 → C-06 | HTTP GET; padded HTML response | Tier W |
| DF-03 | Key-directory fetch | C-06 → C-02/C-03 | Signed roster, epoch keys, release hashes | Verified only in Tier V |
| DF-04 | Submission (Tier W) | C-02 → C-06 → C-07 → C-08 | Plaintext stream → sealed envelope | Plaintext transient in C-07 |
| DF-05 | Submission (Tier V) | C-03 → C-06 → C-08 | Client-sealed envelope | Server sees ciphertext only |
| DF-06 | Source login | C-02 → C-06 → C-07 | Passphrase (Tier W) / signed challenge (Tier V) | Argon2id in C-07 (Tier W) |
| DF-07 | Mailbox fetch/decrypt | C-08 → C-07 → C-06 → C-02 (Tier W) / C-08 → C-06 → C-03 (Tier V) | Sealed replies | Tier W decrypts in C-07 RAM |
| DF-08 | Relay pull | C-09 ⇐ C-08 | Sealed envelope batches | Core-initiated |
| DF-09 | Reply push | C-09 ⇒ C-08 | Sealed replies, key-directory snapshots | Core-initiated |
| DF-10 | Import | C-10 → C-15 | Sealed envelopes | Desk decrypts, creates case, wraps case key |
| DF-11 | Case operations | C-15 ↔ C-10/C-12/C-13 | Encrypted case objects, allow-listed metadata | |
| DF-12 | Evidence viewing | C-15 → C-17 → C-15 | Original file in, sanitized derivative out | |
| DF-13 | Export | C-15 → recipient of Export Package | Encrypted package | Dual approval for originals |
| DF-14 | Admin operations | C-19/C-20 → C-10/C-05.. | Config, upgrades | DANGEROUS config dual approval |
| DF-15 | Monitoring | C-25 ⇐ hosts; C-10 → C-26 → SIEM | Health, allow-listed events | EE for C-26 |
| DF-16 | Backup | hosts → C-27 | Ciphertext + config | |
| DF-17 | Updates | C-33 → all hosts, C-15, C-03 | Signed artifacts + TUF metadata | Identical for all customers |
| DF-18 | Notifications | C-23 → external mail/chat → staff | Fixed text | Hourly digest |
| DF-19 | Vendor management | C-34/C-35/C-36 ↔ customer | Opaque IDs, license files, scrubbed bundles | EE / MANAGED |
| DF-20 | Identity unsealing | Custodian C-15 ×2 → sealed identity | Identity plaintext on custodian endpoint | CONFIDENTIAL |
| DF-21 | Quorum recovery | C-28 shares → offline ceremony → case key re-wrap | Case keys | Only if enabled |
| DF-22 | Confidential clearnet submission | Browser → C-38 → C-07-equivalent sealer | Plaintext over TLS, sealed at C-38 | NOT ANONYMOUS |

## 6. Adversary catalog

Format per adversary: **Capabilities · Assets targeted · Observable information · Possible attacks · Mitigations · Residual risk**. "Observable information" lists what the adversary can see *given Candor's design* (ground truth: `03-PRIVACY-ANONYMITY.md` §8 metadata inventory). Personas from `01-PRODUCT-REQUIREMENTS.md` §4 are referenced as PER-nn.

### ADV-01 Curious employee
- **Capabilities:** Ordinary employee access: intranet, email, chat, office network; sees colleagues' behavior; may notice who uses a personal phone at odd times; no admin rights.
- **Assets targeted:** AST-01, AST-06 (gossip about who reported what).
- **Observable information:** Public C-37 page, the onion address, the existence of the program; colleagues' physical behavior; organizational announcements that reveal investigations.
- **Possible attacks:** Shoulder-surfing a source (THR-048); inferring the reporter from investigation actions (THR-125); spreading rumors from program statistics (THR-039).
- **Mitigations:** Source guidance on device/location (`05-SOURCE-OPSEC.md`); investigation-discretion guidance for investigators (`14-CASE-MANAGEMENT.md`); k-thresholded statistics (`03` §12); no in-office kiosks recommended.
- **Residual risk:** Low–Medium. Physical-world observation and gossip are outside platform control.

### ADV-02 Malicious employee
- **Capabilities:** As ADV-01 plus intent; may social-engineer IT/helpdesk; may submit false reports; may watch colleagues' devices; may hold privileged access to unrelated systems (email archive, DLP console).
- **Assets targeted:** AST-01, AST-06, AST-26 (flooding), AST-04 (via social engineering of recipients).
- **Observable information:** As ADV-01; plus whatever their unrelated privileged systems log (e.g., proxy logs showing Tor use — THR-002).
- **Possible attacks:** THR-033 (false/flood reports), THR-122 (fabricated evidence), THR-124 (helpdesk pretexting, INC-26), THR-002 (Tor-use correlation if they run proxy logs), THR-029 (pulling data from integrations).
- **Mitigations:** ADR-026 (PoW, quotas, triage queue); ADR-018 (no automatic integration flows); staff auth with hardware tokens and no helpdesk reset of key-bearing credentials (`15-AUTHENTICATION-AUTHORIZATION.md`); provenance and evidence-integrity handling for fabricated evidence (`10-FILE-EVIDENCE-PIPELINE.md`).
- **Residual risk:** Medium for false reports (inherent to any open intake); Low for platform-mediated identification.

### ADV-03 Malicious recipient
- **Capabilities:** Legitimate channel/case member with Desk, hardware token and case keys for cases they are granted; can read, reply, export (subject to dual approval), annotate; can collude with others.
- **Assets targeted:** AST-04, AST-05, AST-06, AST-31; case suppression; AST-01 (see ADV-30 for identification-specific).
- **Observable information:** Full plaintext of granted cases; server-visible case metadata of cases in their channels; received day; reply history; their own CASE audit trail.
- **Possible attacks:** THR-019, THR-020 (suppressing or leaking to the accused), THR-041 (forwarding originals), THR-029 (off-platform export), THR-105 (bait replies), THR-106 (moving source off-platform), THR-037 (tampering: deleting notes).
- **Mitigations:** Least-privilege grants and COI exclusions (ADR-015); ≥ 2 members per case (ADR-013) so suppression is visible; SLA escalation to an independent role when ack/feedback overdue (`14`); dual approval for original exports (ADR-018); immutable originals + hashes (ADR-012); CASE audit with signed checkpoints reviewed by an independent auditor (ADR-016); plain-text-only replies (PRD-025).
- **Residual risk:** Medium. A recipient with legitimate access can photograph a screen or retype content; cryptography cannot stop an authorized reader from disclosing. Detection relies on audit and process.

### ADV-04 Malicious administrator
- **Capabilities:** Root on Candor servers (Z-INTAKE, Z-CORE), hypervisor console, DB superuser, backup access, network config, ability to deploy configuration; cannot sign releases; holds no case keys.
- **Assets targeted:** AST-04 (via Tier W sealer), AST-02/03 (enable logging), AST-18 (key substitution), AST-06 (who reported what), AST-22 (erase trail), AST-26.
- **Observable information:** Everything the servers store (ciphertext, allow-listed case metadata, received days, padded sizes, channel IDs, staff audit logs); in real time: Tier W plaintext passing through C-07 if they modify or inspect it; request timing at C-05/C-06 in RAM; never source IP (not present).
- **Possible attacks:** THR-018; THR-014 (patch or ptrace sealer — Tier W); THR-035 (enable debug logging); THR-046/THR-102 (serve forged roster/epoch keys to Tier W sources, who cannot verify); THR-007 (serve modified HTML to a targeted source); THR-022 (steal staff sessions); THR-038 (tamper audit); THR-101 (drop/replay envelopes); THR-020 (suppress reports about themselves).
- **Mitigations:** Admin ≠ case access (ADR-015); Tier V clients verify key directory and releases (ADR-004, `04`); sealer hardening and remote attestation of sealer measurement to Desk (`06-SYSTEM-ARCHITECTURE.md`); DANGEROUS config dual approval + source-visible config digest; hash-chained audit with external witness checkpoints (ADR-016); secret-placement manifest (ADR-028); Desk alarms on sequence gaps in envelope batches (THR-101); two-person rule for production root in CE-HARDENED+ (`32-OPERATIONS.md`).
- **Residual risk:** High for Tier W (a determined root admin on the intake can read Tier W submissions during their tenure and target specific sources with altered HTML — honestly disclosed); Low–Medium for Tier V (limited to metadata, DoS, and suppression detectable by sequence checks).

### ADV-05 Compromised administrator (external attacker holding admin credentials/workstation)
- **Capabilities:** As ADV-04 via stolen credentials or malware on C-20; may lack physical/hypervisor access; wants stealth.
- **Assets targeted:** As ADV-04; AST-17/35 if admin also has supply-chain roles (must not — separation).
- **Observable information:** As ADV-04 within reach of stolen credentials.
- **Possible attacks:** THR-022, THR-014, THR-035, THR-042 (ransomware), THR-013 (at-rest keys), THR-124.
- **Mitigations:** Hardware-bound SSH/admin keys (FIDO2), dedicated admin workstations (INC-41 lesson; `17-INFRASTRUCTURE.md`), no admin access from personal devices; dual approval for DANGEROUS changes; immutable/append-only backups (ADR-025, `19`); SECURITY audit alerts to an independent reviewer; secret-placement checks.
- **Residual risk:** Medium (Tier W plaintext window during compromise; ransomware limited to availability because content keys are off-server).

### ADV-06 Organization management (including executives who may be accused)
- **Capabilities:** Authority over IT, HR, legal, security; can order staff to act; controls budgets, hiring of recipients; can request statistics; controls corporate network, devices, email archive, badge and print logs; may attempt Barclays-style unmasking (INC-22).
- **Assets targeted:** AST-01, AST-06, AST-30, AST-04 (reports about themselves), AST-26 (defunding/switching off).
- **Observable information:** Program statistics (k-thresholded, quarterly); existence of program; corporate telemetry (see ADV-07/08); everything they can order admins to reveal (see ADV-04 observable set).
- **Possible attacks:** THR-020, THR-110 (inferring they are the subject via COI exclusions), THR-039/THR-120 (small-cell stats), THR-116 (coercing recipients), THR-018 via ordered admins, THR-035 (ordering dangerous config), THR-125 (investigation actions narrow the pool).
- **Mitigations:** Independent-body channels and COI exclusions before key wrapping (ADR-015); roster changes visible to sources (PRD-038); DANGEROUS config visible in source-facing config digest (`03` §7); k-thresholds (`03` §12); external witness of audit logs; regulator-facing documentation of independence (ISO 37002; B-CO-01); legal protections (EU Art 16, B-CO-02).
- **Residual risk:** Medium–High in organizations where management controls all recipients. Candor makes unmasking attempts **detectable and costly**, not impossible; a board that fires the ombudsman is outside technical control.

### ADV-07 Corporate security department
- **Capabilities:** SOC/SIEM, EDR on endpoints, proxy/DNS logs, DLP with document fingerprinting and canary tokens, print audit logs, badge logs, email archive with LLM search, forensic imaging of corporate devices; may be asked to "find the leaker".
- **Assets targeted:** AST-01, AST-02, AST-03, AST-06.
- **Observable information:** Candor SECURITY/SYSTEM events via C-26 (EE; allow-listed, no source-sensitive fields); corporate network metadata showing Tor/bridge use (not destination); document access/print logs; canary-token callbacks (THR-107); internal writing corpus for stylometry (THR-010).
- **Possible attacks:** THR-002, THR-004 (WF of the portal from corporate egress), THR-010 (LLM stylometry against employee corpus, B-AN-36..38), THR-016 (seeking source data in SIEM), THR-107/108 (beacons, hash lookups), THR-120.
- **Mitigations:** C-26 allow-list with no source-sensitive fields (ADR-016); SOURCE-SENSITIVE counters bucketed (`03` §12); evidence viewer network-less (ADR-012) defeating beacons; no external hash lookups (PRD-069); source guidance: personal device/network, bridges, don't print, paraphrase (`05`); response padding (ADR-011).
- **Residual risk:** High for sources who use corporate devices/networks or submit uniquely-accessed documents; Low for platform-mediated leakage.

### ADV-08 Employer monitoring the source
- **Capabilities:** Endpoint agents (EDR/MDM/screen recording/keyloggers) on managed devices; TLS interception on corporate network; managed browsers; mobile device management on BYOD with work profiles; Wi-Fi logs.
- **Assets targeted:** AST-01, AST-02, AST-03, AST-07 (passphrase keylogging), AST-04 (screen capture).
- **Observable information:** On a managed device: everything (Tor Browser installation, keystrokes, files). On a managed network: Tor/bridge usage timing and volume, not onion destination (modulo WF).
- **Possible attacks:** THR-002, THR-004, THR-034, THR-048, THR-011 (timing intersection with document access logs).
- **Mitigations:** Candor cannot protect a monitored device ([A:DEV] violated). Guidance at C-37 and landing: never use work devices/networks (INC-31); bridges; Tails; wait before submitting after accessing documents; no fine-grained timestamps anywhere (ADR-010).
- **Residual risk:** Critical for sources who ignore guidance; stated plainly in UI.

### ADV-09 ISP (source-side or service-side)
- **Capabilities:** Observes all traffic of a subscriber: IP, timing, volume; subject to legal compulsion; can retain flow records (NetFlow) for months; may assist LE.
- **Assets targeted:** AST-02, AST-03; AST-28 (service-side ISP).
- **Observable information:** Source-side: Tor (or bridge) connection, timing, volume. Service-side: Tor traffic of the intake host, timing, volume.
- **Possible attacks:** THR-002; THR-003 in combination with service-side observation; THR-004 (WF); THR-005 contributions (guard location of service).
- **Mitigations:** Onion-only (ADR-001); vanguards on service; response padding; guidance on bridges and non-home networks for high-risk sources; intake traffic from multiple sources and cover probes (C-25) adds noise but is not cover traffic.
- **Residual risk:** Medium for high-risk sources if the same entity (or cooperating ISPs) observes both ends — Tor does not defend against this (R4 §2.1, B-AN-02..05).

### ADV-10 Hosting provider
- **Capabilities:** Physical and hypervisor access to hosted servers; network flow logs; snapshots; remote console; subject to legal process in its jurisdiction.
- **Assets targeted:** AST-04 (Tier W memory), AST-16, AST-28, AST-25, AST-34.
- **Observable information:** Intake host's Tor traffic (no source IPs: onion); disk contents (ciphertext + at-rest-encrypted volumes); memory if it snapshots VMs (Tier W plaintext transiently, derived source keys during logins, onion private key).
- **Possible attacks:** THR-030, THR-031, THR-044 (copying onion key), THR-014 (memory scraping), THR-123 (side channels).
- **Mitigations:** Dedicated hosts for Z-INTAKE (ADR-024); on-prem preferred; full-disk encryption with TPM-sealed keys + measured boot (`17`); onion key in memory only, loaded from TPM-sealed store; Tier V recommended in PRIVATE-CLOUD; AMD SEV-SNP/Intel TDX confidential VMs **optional** hardening for PRIVATE-CLOUD (`17`) with honest caveats.
- **Residual risk:** Medium–High for Tier W in hosted/PRIVATE-CLOUD profiles; Low for Tier V content; onion-key theft remains possible → impersonation risk (THR-044).

### ADV-11 Cloud provider
- **Capabilities:** As ADV-10 plus control-plane access (IAM, KMS, snapshot APIs), default-on flow logs, managed-service telemetry, multi-tenant co-residency.
- **Assets targeted:** As ADV-10; AST-34 (cloud KMS keys), AST-25 (snapshots/object storage).
- **Observable information:** As ADV-10; plus API audit trails, KMS usage timing (could correlate with imports).
- **Possible attacks:** THR-030, THR-045, THR-017 (snapshots beyond deletion), THR-123.
- **Mitigations:** PRIVATE-CLOUD profile documents provider-observer risk; content keys never in cloud KMS (ADR-008); Z-INTAKE on dedicated instances; disable provider snapshot/backup features for Z-INTAKE; object storage holds only E2E ciphertext (INC-59, REQ-H-59); managed service uses per-customer dedicated intake (ADR-021).
- **Residual risk:** Medium for Tier W; Low for content under Tier V; metadata (volume, timing of imports) visible.

### ADV-12 CDN
- **Capabilities:** TLS termination and full visibility of HTTP traffic for sites it fronts; request logs; JavaScript injection capability (INC-46, INC-54).
- **Assets targeted:** AST-02, AST-03 of visitors to C-37 / C-38; AST-19 if a CDN were on a source path.
- **Observable information:** For C-37 (if fronted by a CDN): visitor IPs of the information site, timing. Nothing on the onion path.
- **Possible attacks:** THR-036, THR-007 (injecting a modified onion address or script into C-37), THR-103.
- **Mitigations:** No CDN on any source submission path (REQ-H-54, INC-54); C-37 SHOULD be self-hosted without CDN; if a CDN is used for C-37, it is documented as observing visitors; onion address published with signature and in multiple channels; C-37 contains no scripts (CSP).
- **Residual risk:** Low for anonymous submissions; Medium for "who looked at the information page" if CDN-fronted.

### ADV-13 Malicious Tor relay (including Sybil operators)
- **Capabilities:** Runs guard/middle/HSDir relays (KAX17: ~16 % guard / 35 % middle probability, B-AN-24); can tag cells (RELAY_EARLY, INC-29), perform circuit fingerprinting (B-AN-20), congestion attacks.
- **Assets targeted:** AST-02 (source guard), AST-28 (service guard discovery), AST-03.
- **Observable information:** As guard: source IP, timing, that the client visits an onion service (circuit fingerprinting). As service-side relay: service guard/IP after guard discovery.
- **Possible attacks:** THR-003, THR-005, THR-004.
- **Mitigations:** Current tor with vanguards-lite (clients) and full vanguards on service (ADR-001, B-AN-11..13); PoW; onion-only (no exits); tor patch SLA ≤ 72 h (PRD-061); short-lived source sessions (INC-35).
- **Residual risk:** Low–Medium; network-level attacks by relay Sybils are in the Tor threat model and mitigated there, not eliminated.

### ADV-14 Malicious I2P peer
- **Capabilities:** Floodfill/netDb Sybil and eclipse attacks, HS IP deanonymization (B-AN-55..57), network flooding (B-AN-54).
- **Assets targeted:** Would target AST-02/AST-28 if I2P were supported.
- **Observable information:** None related to Candor: I2P is not shipped (ADR-001).
- **Possible attacks:** THR-115-class downgrade if a third party offered an "I2P mirror" of a Candor instance; phishing via fake I2P eepsite (THR-103).
- **Mitigations:** No I2P transport; transport adapter admission criteria (ADR-001); source guidance states the only legitimate address type is the published .onion.
- **Residual risk:** Low (out of architecture); unofficial mirrors are a phishing concern only.

### ADV-15 Local network attacker (Wi-Fi, café, hotel, shared LAN)
- **Capabilities:** Observe/modify local traffic; ARP/DNS spoofing; captive portals; can see Tor use; cannot break Tor encryption.
- **Assets targeted:** AST-02, AST-03, AST-19 (tamper C-37 over HTTP), AST-16 (phish with fake onion address).
- **Observable information:** Tor/bridge use, timing, volume; clearnet visits to C-37 (DNS + SNI).
- **Possible attacks:** THR-002, THR-004, THR-103 (inject fake onion address into a non-HTTPS page or via DNS spoofing of C-37).
- **Mitigations:** C-37 HTTPS with HSTS preload, onion address also published via signed statement and Onion-Location (ADR-003); self-authenticating onion addresses; bridges guidance.
- **Residual risk:** Low for content; Medium for "this person used Tor at this café at this time" if combined with other evidence.

### ADV-16 Remote attacker (opportunistic or targeted, internet-based)
- **Capabilities:** Scanning, exploitation of web/app vulnerabilities, phishing staff, credential stuffing, DoS, ransomware.
- **Assets targeted:** AST-26, AST-04 (via server compromise), AST-23, AST-22.
- **Observable information:** Onion landing page; C-37; public key directory; staff emails (phishing).
- **Possible attacks:** THR-014, THR-021, THR-022, THR-032, THR-042, THR-100, THR-104.
- **Mitigations:** Minimal attack surface (onion-only, no clearnet listener, Rust trust path, deny-by-default routes ADR-029); phishing-resistant staff auth (WebAuthn/PIV); PoW; backups; secret-placement; security testing (`29`).
- **Residual risk:** Medium (software vulnerabilities exist; server compromise ≠ content compromise for Tier V).

### ADV-17 Advanced persistent threat (APT)
- **Capabilities:** Custom exploits, long dwell time, supply-chain operations, lateral movement from corporate IT into Candor, targeting of individuals (recipients, developers).
- **Assets targeted:** AST-04/05 (at recipient endpoints), AST-13, AST-17, AST-35, AST-01.
- **Observable information:** After endpoint compromise: plaintext of that recipient's cases; after server compromise: as ADV-04.
- **Possible attacks:** THR-013, THR-014, THR-023, THR-024, THR-025, THR-109, THR-123.
- **Mitigations:** Recipient keys on hardware tokens; evidence only in containment VMs; AIRGAP-RCP for highest risk; reproducible, threshold-signed builds and transparency (ADR-022); separation of release signing from infra admin; dependency review (cargo-vet); independent audits (`37`).
- **Residual risk:** High for highest-value targets; APT compromise of a recipient endpoint exposes that recipient's cases.

### ADV-18 Law enforcement
- **Capabilities:** Legal process (subpoenas, warrants, production and preservation orders, gag orders, prospective interception orders — INC-03, INC-04, INC-07, INC-12), device seizure, NITs (INC-27/28), running seized onion services, relay operation (INC-29), ISP data (INC-35).
- **Assets targeted:** AST-01, AST-02, AST-04, AST-09, AST-16, AST-25.
- **Observable information:** Whatever the operator can disclose (`03` §10 legal-compulsion table): ciphertext, allow-listed metadata, received days, staff audit logs; plaintext only through recipients/custodians or prospective Tier W interception.
- **Possible attacks:** THR-026, THR-007/008 (compelled modified client code or NIT via seized server), THR-031, THR-034 (source device seizure), THR-116 (compelling staff).
- **Mitigations:** Data minimization (ADR-010/011, `03`); keys off-server (ADR-007); Tier V verified clients + transparency (ADR-004/022); no targeted updates (ADR-022); source guidance on device forensics (THR-048); canary/transparency reporting (`24`/`36`); Sealed Identity Store with legal-basis workflow (ADR-014).
- **Residual risk:** Medium. Operators can be compelled to modify Tier W intake prospectively; Tier V users are protected unless transparency monitoring fails. Custodians can be compelled to unseal identities (lawful by design in CONFIDENTIAL mode).

### ADV-19 Intelligence agency
- **Capabilities:** Large-scale passive collection at IXPs/cables, relay operation, exploit stockpiles, supply-chain interdiction, HUMINT (insider placement), cryptanalytic resources.
- **Assets targeted:** AST-01..05, AST-17, AST-35.
- **Observable information:** Broad network visibility (both ends for many paths), Tor traffic patterns, possibly both source and service ISPs.
- **Possible attacks:** THR-003, THR-005, THR-024, THR-025, THR-012 (harvest-now-decrypt-later → PQ hybrid), THR-017.
- **Mitigations:** PQ hybrid KEM X-Wing (ADR-006); onion-only + vanguards; reproducible builds + threshold signing; no plaintext persistence; guidance for highest-risk sources (Tails, timing decorrelation).
- **Residual risk:** High for sources targeted by an agency with end-to-end visibility; Candor is not designed to defeat a global adversary (NG-03).

### ADV-20 Nation-state (government apparatus beyond intelligence: courts, regulators, censorship, security services)
- **Capabilities:** Censorship/Tor blocking (B-AN-30), compelled operators/vendors within jurisdiction, criminalization of tools, coercion of individuals, demanding backdoors from vendors (Juniper INC-50 class), control of national CAs/ISPs.
- **Assets targeted:** AST-26 (blocking), AST-17/19 (backdoor demands), AST-01, AST-32.
- **Observable information:** As ADV-18/19 in-jurisdiction.
- **Possible attacks:** THR-026, THR-025 (compelled vendor update), THR-032 (blocking), THR-116, THR-113 (compelling vendor fleet manager).
- **Mitigations:** Bridges guidance; no targeted updates, threshold signers in ≥ 2 jurisdictions (`33`); transparency log; vendor holds no keys/content; managed service jurisdiction disclosure; warrant canary/transparency report policy (`24`).
- **Residual risk:** High in-jurisdiction for operator-side coercion of Tier W and for blocking; Tor-use itself may be criminalized — outside technical control.

### ADV-21 Global network observer (GPA)
- **Capabilities:** Observes most internet links simultaneously; end-to-end correlation (DeepCorr/DeepCoFFEA B-AN-04/05).
- **Assets targeted:** AST-02, AST-03.
- **Observable information:** Source ↔ Tor entry and Tor ↔ service timing/volume for most paths.
- **Possible attacks:** THR-003, THR-011 (with any timing leak).
- **Mitigations:** None sufficient at the network layer (R4 §2.1). Partial: response padding, batching of relay imports, day-granular timestamps, no replies timing correlation; transport adapter for future cover-traffic transports (ADR-001, R4 §6).
- **Residual risk:** Critical for targeted sources; explicitly out of the design envelope (NG-03) and disclosed.

### ADV-22 Malicious software supplier (vendor of a component Candor ships or depends on: OS distro, tor, hardware token, HSM, hypervisor)
- **Capabilities:** Ship backdoored code or firmware; weak RNG (INC-50/51/61); telemetry in products.
- **Assets targeted:** AST-12/13 (keys), AST-04, AST-19/20.
- **Observable information:** Whatever its component processes.
- **Possible attacks:** THR-024, THR-012 (weak keys), THR-013.
- **Mitigations:** Source-built pinned dependencies from VCS (REQ-H-37); weak-key and KAT checks at startup (REQ-H-51); EC keys generated in software via vetted libraries, hardware used for wrapping only (REQ-H-61); diversity (hardware token wraps, does not generate content keys); independent audits.
- **Residual risk:** Medium; firmware and CPU-level backdoors are beyond verification.

### ADV-23 Compromised dependency (open-source package hijack/typosquat/maintainer takeover)
- **Capabilities:** Malicious code in a crate/npm package/Debian package executed at build or runtime (INC-37, INC-40, INC-42..45).
- **Assets targeted:** AST-35, AST-19/20, AST-04 (runtime exfiltration), AST-13.
- **Observable information:** Build environment secrets; runtime data of the process it runs in.
- **Possible attacks:** THR-024, THR-025.
- **Mitigations:** cargo-vet + cargo-deny, pinned lockfiles, internal mirror allow-list (REQ-H-43), lifecycle scripts disabled (REQ-H-42), minimal dependency policy for trust path, egress-denied runtime (intake has no outbound except tor), reproducible builds (ADR-019/022, `28`).
- **Residual risk:** Medium; review can miss well-hidden backdoors (xz).

### ADV-24 Malicious platform developer (insider in the Candor project/vendor)
- **Capabilities:** Commit access, code review participation, knowledge of internals; may attempt subtle crypto or logging bugs (Juniper-like); may be coerced.
- **Assets targeted:** AST-19/20, AST-17, AST-35.
- **Observable information:** Source code; no production customer data (vendor holds none).
- **Possible attacks:** THR-024, THR-012, THR-016 (introduce logging of sensitive fields), THR-025.
- **Mitigations:** Two-person review for trust-path code, CODEOWNERS for crypto/logging, signed commits (REQ-H-50), typed logging API with prohibited-field lint (ADR-016), threshold release signing with independent signers, public transparency, external audits, formal models (ADR-006).
- **Residual risk:** Low–Medium.

### ADV-25 Compromised CI/CD
- **Capabilities:** Modify build outputs, steal signing credentials present in CI, alter tests (SolarWinds INC-38, Codecov INC-39, tj-actions INC-44).
- **Assets targeted:** AST-35, AST-17, AST-19/20.
- **Observable information:** Source code, CI secrets.
- **Possible attacks:** THR-024, THR-025.
- **Mitigations:** ≥ 2 independent reproducible builders whose outputs must match before signing (ADR-022); signing keys offline, never in CI (C-32); actions pinned by SHA (REQ-H-44); OIDC short-lived creds (REQ-H-39); SLSA provenance.
- **Residual risk:** Low if builder independence holds [A:BUILD].

### ADV-26 Legal-compulsion adversary (any party able to obtain binding orders against operator, vendor, staff, hosting provider, or source)
- **Capabilities:** Production orders, preservation orders, prospective interception/modification orders, gag orders, contempt sanctions (INC-02), mutual legal assistance (INC-03, INC-05).
- **Assets targeted:** All data the target can produce; ability to modify service.
- **Observable information:** Precisely the legal-compulsion inventory in `03` §10.
- **Possible attacks:** THR-026, THR-007 (compelled modification), THR-111 (compelled unsealing), THR-116, THR-113/114 (compelling vendor).
- **Mitigations:** "Can't, not won't" data minimization; keys on endpoints; Tier V transparency; published compelled-disclosure inventory (REQ-H-06); vendor has no content/keys/onion-address mapping in cleartext (C-34); legal-response procedure with two-person approval (`31`).
- **Residual risk:** Medium; prospective compelled modification of Tier W intake is the principal residual and is disclosed.

### ADV-27 Physical attacker
- **Capabilities:** Theft/seizure of servers, disks, backups, laptops, tokens; evil-maid; cold-boot; hardware implants; coercion of the physical holder.
- **Assets targeted:** AST-13, AST-15, AST-16, AST-25, AST-34, AST-04 in RAM.
- **Observable information:** At-rest encrypted disks; RAM if powered and accessible.
- **Possible attacks:** THR-031, THR-013, THR-044, THR-116.
- **Mitigations:** FDE with TPM + PIN/network-bound unlock for servers (`17`); keys on hardware tokens with PIN retry limits; quorum shares geographically/role-separated; tamper-evident seals and physical logs (PHYS in `17`); memory encryption where available.
- **Residual risk:** Medium; a live-seized intake host may yield onion key and Tier W in-flight plaintext.

### ADV-28 Forensic investigator (examining a seized source or recipient device)
- **Capabilities:** Full disk forensics, memory forensics, browser artifact recovery, mobile extraction tools.
- **Assets targeted:** AST-07, AST-04/05 residue, AST-01 (evidence of having used Candor).
- **Observable information:** Tor Browser installation and possible residue; Source App installation; downloaded files; notes of passphrase; Desk caches on recipient devices.
- **Possible attacks:** THR-048, THR-034.
- **Mitigations:** No-JS, no-storage source UI (no persistent cookies, `Cache-Control: no-store`); no downloads offered to sources; Source App stores nothing but optional encrypted state with deniability guidance (`05`); Tails recommendation; Desk local data encrypted with hardware-bound keys and purged per retention.
- **Residual risk:** Medium; presence of Tor Browser or Source App on a device is itself evidence; Candor cannot hide installation.

### ADV-29 Malicious whistleblower uploading hostile content
- **Capabilities:** Craft malicious documents (parser exploits CVE-2021-22204 class, B-CR-56), zip/decompression bombs (B-CR-52), beacons/canary tokens, polyglots, path-traversal filenames (B-SD-33..35), XSS payloads in text (B-GL-37, Hush Line CVE-2024-38521), huge volumes.
- **Assets targeted:** AST-20 (recipient endpoints), AST-26, AST-04 of other cases (via compromised recipient), AST-06.
- **Observable information:** Only what the source-facing UI shows (roster, fingerprints).
- **Possible attacks:** THR-023, THR-107, THR-119, THR-033, THR-122.
- **Mitigations:** Servers never parse (ADR-012); network-less disposable viewer; pixels-to-PDF sanitizer; `candor-safefs` content-addressed names (ADR-027); text rendered as plain text; size/quotas/PoW (ADR-026); malicious-server/hostile-content harness (`29`).
- **Residual risk:** Low–Medium (hypervisor escape from C-17 remains possible; AIRGAP-RCP further reduces).

### ADV-30 Malicious recipient trying to identify the whistleblower
- **Capabilities:** Legitimate case access (ADV-03) plus intent to unmask; can send tailored questions and bait, analyze content/stylometry against internal corpora, correlate received day with access logs, ask colleagues, request unsealing, abuse Export Packages to pass data to management.
- **Assets targeted:** AST-01, AST-09.
- **Observable information:** Full case plaintext, received day (not time), padded sizes (already has true sizes after decryption), their own replies and the source's responses (day granularity).
- **Possible attacks:** THR-019, THR-105 (bait/canary questions, individualized information in replies to see what leaks), THR-106 (lure off-platform, INC-21), THR-010 (stylometry), THR-111 (unsealing abuse), THR-125 (investigation actions to smoke out), THR-107 (planting beacons in documents requested from the source).
- **Mitigations:** No source metadata to read (ADR-010); plain-text replies with no links/resources (PRD-025); source UI warns about bait questions and requests to switch channels (`05`); unsealing needs two custodians + legal basis + source notice (ADR-014); ≥ 2 recipients per case and independent audit review of case actions; COI exclusions; training (PRD-074).
- **Residual risk:** Medium–High; a determined authorized reader can often narrow the candidate set from content alone. Candor cannot prevent inference from content; it removes platform-provided metadata that would make it easy.

## 7. STRIDE analysis per zone

Each row: STRIDE category → concrete threats in that zone → THR IDs → principal mitigations (owner docs). Residual ratings are in §9.

### 7.1 Z-SRC (C-01, C-02, C-03)
| STRIDE | Threat in zone | THR | Mitigations |
|---|---|---|---|
| S | Phishing onion/look-alike address; fake Source App; fake "Candor" page in another origin | THR-103, THR-044 | Self-authenticating onion; signed address statements on C-37 and in app; app signature + transparency (`33`); guidance (`05`) |
| T | Modified Tier W HTML by compromised server; malicious browser extension; tampered Source App download | THR-007, THR-008 | Tier V verification (WEBCAT/app); TB Safest; reproducible app builds; no-JS UI |
| R | Source denies submission; adversary claims source submitted | THR-121 | Deniability is a feature: no source signatures leave the envelope except with source key (pseudonymous); no device binding |
| I | Device residue; keylogging; screen capture; fingerprinting; metadata in files | THR-048, THR-006, THR-009, THR-034 | No-store headers, no downloads, TB uniformity, client-side metadata stripping (Tier V), guidance |
| D | Tor blocked; PoW delays; oversized uploads fail on slow circuits | THR-032 | Bridges; PoW tuning; resumable uploads in Tier V only with unlinkable tokens (THR-047) |
| E | Browser exploit (NIT) escalates to device | THR-008 | JS-free UI; strict CSP; TB Safest guidance; patched TB |

### 7.2 Z-NET (C-04)
| STRIDE | Threat | THR | Mitigations |
|---|---|---|---|
| S | Malicious HSDir/intro points; fake descriptors impossible for v3 without key | THR-044, THR-005 | v3 onion keys; key custody |
| T | Cell tagging (RELAY_EARLY), active watermarking | THR-003, THR-005 | Current tor; CGO when available (B-AN-45) |
| R | n/a | — | — |
| I | Guard discovery; traffic correlation; WF; circuit fingerprinting | THR-003, THR-004, THR-005, THR-002 | Vanguards; padding; short sessions; guidance |
| D | Onion DoS; Tor-wide DDoS | THR-032 | PoW (ADR-026); standby onion |
| E | n/a | — | — |

### 7.3 Z-INTAKE (C-05..C-08)
| STRIDE | Threat | THR | Mitigations |
|---|---|---|---|
| S | Source session hijack; staff impersonation irrelevant (no staff access on intake); onion key theft | THR-044, THR-100, THR-121 | Session tokens audience-bound (ADR-029), `__Host-` cookies, Argon2id; onion key TPM-sealed |
| T | Altered HTML/roster served to Tier W sources; replay/drop of envelopes; forged key-directory snapshot | THR-007, THR-046, THR-101, THR-102 | Signed snapshots verified by Tier V; batch sequence + Desk gap detection; sealer measurement attestation (`06`) |
| R | Operator denies having received a submission | THR-101 | Signed receipt token to source (Tier V) covering envelope hash; Desk sequence audit |
| I | Tier W plaintext in C-07; logs; circuit IDs; crash dumps; timing; service location leak via egress | THR-014, THR-016, THR-011, THR-104, THR-123 | Sealer isolation (mlock, no core, seccomp); logs disabled (ADR-016); egress deny except tor; response padding; RAM-only rate-limit state |
| D | Intro flooding; Argon2id login exhaustion; upload flooding; disk fill | THR-032, THR-033 | PoW; bounded KDF concurrency; quotas; disk quotas with oldest-first rejection of new uploads (never deleting unpulled envelopes) |
| E | Web-service RCE → sealer memory; container escape | THR-014 | Separate UID/namespaces; C-07 minimal API; Rust; no shell tools on image |

### 7.4 Z-CORE (C-09..C-14, C-21..C-24)
| STRIDE | Threat | THR | Mitigations |
|---|---|---|---|
| S | Staff impersonation; stolen tokens; forged roster changes | THR-022, THR-046 | WebAuthn/PIV; token audience/tenant binding; roster signatures (PRD-038) |
| T | Tampered case metadata; audit log edits; COI map edits; deleting cases to suppress | THR-020, THR-038, THR-037, THR-035 | Hash-chained audit with external witness; signed config; ≥ 2 members per case; Desk-side integrity checks of case objects (AEAD with context binding, INC-66) |
| R | Staff deny actions | THR-037 | CASE/SECURITY audit signed checkpoints |
| I | DB theft; metadata inference; cross-tenant leaks; SIEM leakage | THR-015, THR-021, THR-045, THR-016, THR-039 | Content encrypted to endpoint keys; RLS; allow-listed metadata; typed logging |
| D | Ransomware; DB corruption; queue starvation | THR-042 | Immutable backups; intake store-and-forward 14 days |
| E | IDOR/authorization bypass; admin API reachable with desk token | THR-021 | Deny-by-default route registry (ADR-029); policy tests |

### 7.5 Z-RCP (C-15, C-16)
| STRIDE | Threat | THR | Mitigations |
|---|---|---|---|
| S | Phished staff; malicious Desk build | THR-022, THR-025 | Hardware tokens; signed Desk updates via TUF |
| T | Malware alters Desk or evidence | THR-037, THR-013 | Code signing, OS hardening, evidence hashes |
| R | Recipient denies export | THR-041 | Export audit + dual approval |
| I | Key theft; cloud sync/AI assistants/indexers ingest plaintext; screenshots | THR-013, THR-109, THR-041 | Desk data in encrypted app store excluded from indexing/sync; guidance; AIRGAP-RCP |
| D | Lost devices/tokens → key loss | THR-117 | ≥ 2 members; optional quorum |
| E | Hostile file exploits Desk | THR-023 | Desk never renders evidence; C-17 only |

### 7.6 Z-VIEW (C-17, C-18)
| STRIDE | Threat | THR | Mitigations |
|---|---|---|---|
| S | Fake "sanitized" output from compromised viewer | THR-037 | Output re-verified: PDF normalized by qpdf in a second disposable VM (`10`) |
| T | Viewer image tampered | THR-024 | Signed, reproducible viewer images |
| R | — | — | — |
| I | Beacons calling home; VM escape leaks other evidence | THR-107, THR-023 | Network-less VM; one file per VM; destroy after use |
| D | Decompression bombs | THR-119 | Resource limits (CPU/RAM/time/disk) |
| E | Hypervisor escape | THR-023 | Qubes/Firecracker hardening; AIRGAP-RCP for high risk |

### 7.7 Z-ADM (C-19, C-20, C-28)
| STRIDE | Threat | THR | Mitigations |
|---|---|---|---|
| S | Admin impersonation | THR-022 | FIDO2 SSH, admin-api audience |
| T | Dangerous config applied silently | THR-035 | Dual approval; source-visible config digest |
| R | Admin denies change | THR-038 | SECURITY audit |
| I | Admin workstation malware reads secrets | THR-013 | Dedicated hardened workstation; no content keys on admins |
| D | Admin destroys infrastructure | THR-042 | Offline backups; intake redundancy |
| E | Admin escalates to case access by adding self to roster | THR-046, THR-018 | Roster signatures by members; source-visible roster |

### 7.8 Z-SOC (C-25, C-26)
| STRIDE | Threat | THR | Mitigations |
|---|---|---|---|
| S | Fake health data hides compromise | THR-038 | Signed health reports; self-test attestation |
| T | Monitor modified to probe/log source traffic | THR-016 | Monitor has no access to intake request data; pull-only metrics endpoint |
| R | — | — | — |
| I | SIEM receives source-sensitive events; counters reveal activity | THR-016, THR-039 | Allow-list schema; bucketed counters |
| D | Monitoring alert floods | THR-032 | Rate-limited alerts |
| E | Monitor host as pivot into intake | THR-014 | Monitor→intake only on metrics port; no SSH from monitor |

### 7.9 Z-BAK (C-27)
| STRIDE | Threat | THR | Mitigations |
|---|---|---|---|
| S | Restore of attacker-crafted backup | THR-042 | Signed backup manifests |
| T | Backup tampering | THR-042 | Hash-chained manifests; immutability |
| R | — | — | — |
| I | Backup theft; retention past deletion | THR-017, THR-015 | Ciphertext only; content keys not in backups (ADR-025) |
| D | Backup deletion/ransomware | THR-042 | Offline/WORM copies |
| E | — | — | — |

### 7.10 Z-SUPPLY (C-30..C-33)
| STRIDE | Threat | THR | Mitigations |
|---|---|---|---|
| S | Maintainer account takeover | THR-024 | Hardware-key MFA; trusted publishing |
| T | Malicious commit/dependency/build | THR-024 | Two-person review; cargo-vet; reproducible dual builds |
| R | — | — | Signed commits, transparency log |
| I | Leaking signing keys | THR-025 | Offline threshold keys |
| D | Mirror outage | THR-025 | Multiple mirrors; TUF freeze detection |
| E | Targeted update to one customer | THR-025 | Identical artifacts; transparency; no instance identity in update requests |

### 7.11 Z-VENDOR (C-34..C-36) and Internet-facing (C-37, C-38)
| STRIDE | Threat | THR | Mitigations |
|---|---|---|---|
| S | Fake support contacting customers; spoofed C-37 | THR-124, THR-103 | Support via authenticated channel; signed onion statements |
| T | Fleet manager pushes malicious config; C-37 address replaced | THR-113, THR-103 | Fleet manager cannot push trust-path config without local dual approval; C-37 content signed and monitored |
| R | — | — | — |
| I | Vendor learns customer ↔ onion mapping; support bundles contain secrets | THR-027, THR-114 | Opaque IDs, scrubbed bundles (INC-56) |
| D | License server outage | THR-114 | Offline license files (PRD-004) |
| E | Vendor access path into customer network | THR-027 | No inbound vendor access; outbound-only, customer-initiated |

### 7.12 Infrastructure substrate (C-39, C-29, network, DNS, time)
| STRIDE | Threat | THR | Mitigations |
|---|---|---|---|
| S | DNS/NTP spoofing | THR-043, THR-104 | Intake uses tor for all egress, no DNS; NTS/multiple sources |
| T | Firmware/hypervisor implants | THR-030, THR-031 | Measured boot, dedicated hardware for Z-INTAKE |
| R | — | — | — |
| I | Co-tenant side channels; snapshots | THR-045, THR-123, THR-030 | Dedicated hosts; disable snapshots on Z-INTAKE |
| D | Power/network loss | THR-032 | HA in EE |
| E | VM escape | THR-030 | Patching; minimal hypervisor surface |

## 8. LINDDUN privacy analysis

LINDDUN categories: **L**inking, **I**dentifying, **N**on-repudiation, **D**etecting, **D**ata disclosure, **U**nawareness, **N**on-compliance.

| Category | Threat scenario in Candor | Flows / stores | THR | Mitigation | Residual |
|---|---|---|---|---|---|
| Linking | Multiple submissions by the same source linked via passphrase reuse, stylistic similarity, or intake-side session state | DF-04..07, C-08 | THR-010, THR-047, THR-011 | Default one passphrase per report (ADR-005); resumable upload tokens unlinkable to account; no cross-case correlation features (PRD-033) | Content/style linking by humans remains |
| Linking | Source visits linked across time by guard, WF, or employer network logs | DF-02..07 | THR-002, THR-003, THR-004 | Guidance to minimize return visits and vary networks; no reply notifications | Medium for repeat visitors from same network |
| Linking | Envelope ↔ exact arrival time via batch sequence + relay pull logs | C-08, C-09, C-24 | THR-011 | Day-only timestamps; no record joins batch number to exact time (`03` META) | ≤ pull-interval window to a live intake observer |
| Identifying | Source IP captured by platform | DF-02..07 | THR-001 | Onion only; no IP present | Negligible under [A:TOR] |
| Identifying | File metadata, printer dots, content | DF-04/05, DF-12 | THR-009, THR-010 | Client-side stripping (Tier V), sanitized derivatives, guidance | Content-based identification remains |
| Identifying | Confidential identity unsealed improperly | DF-20 | THR-111 | Dual custodians, legal basis, source notice, audit | Coercion of two custodians |
| Non-repudiation | Source cryptographically bound to a submission in a way usable against them (e.g., a signature verifiable by third parties tied to a device) | C-03, envelopes | THR-121 | Source keys derive from passphrase only; no device keys; source signatures only verifiable with pseudonymous source public key; no hardware attestation of source device | If passphrase seized, adversary can prove control of mailbox |
| Non-repudiation | Audit logs prove a staff member looked up a particular source | C-24 | THR-038 | CASE audit uses pseudonymous case IDs; no source-sensitive events | Staff actions are (deliberately) attributable |
| Detecting | Mere fact of using Candor detectable (Tor use; Source App installed; C-37 visit) | DF-01, TB-01 | THR-002, THR-048 | Guidance; C-37 without CDN/logs; bridges | Tor use visible locally; app installation visible |
| Detecting | Accused detects existence of report via key-wrap changes, COI exclusions, notifications, SLA dashboards | C-12, C-14, C-23 | THR-110, THR-028, THR-006 | Exclusions not disclosed to excluded users; content-free notifications; key-directory publishes roster per channel, not per case | Lost-access side channel if the accused previously had broad access |
| Data disclosure | Plaintext in Tier W sealer; plaintext at endpoints; backups; Export Packages | C-07, C-15, C-27, DF-13 | THR-014, THR-013, THR-017, THR-029 | ADR-004/007/018/025 | Endpoint compromise |
| Data disclosure | Logs/crash dumps/support bundles | C-24, C-36 | THR-016 | Typed logging; no core dumps; scrubbed bundles | Low |
| Unawareness | Source believes they are anonymous when confidential; does not understand Tier W exposure; does not know escrow is enabled | UI | THR-040, THR-115 | Mode banner; tier statement; escrow visible; comprehension testing (SM-07) | Users skip text |
| Unawareness | Recipients unaware that opening originals, printing, cloud sync, AI assistants leak | Z-RCP | THR-041, THR-109 | Training gate; Desk warnings; export controls | Human error |
| Non-compliance | Retention beyond necessity; unlawful unsealing; statistics violating Art 16 "indirect identification" | C-10, C-12, reports | THR-017, THR-111, THR-039 | Retention engine; unseal workflow; k-thresholds | Jurisdictional variance |

## 9. Threat catalog

Inherent and residual risk use §3 scale (L×I). Residual assumes the referenced mitigations are implemented and the listed assumptions hold. Tier differences are noted where they matter.

### 9.1 Core threats THR-001..THR-048 (retained from DECISIONS §5)

| ID | Threat (full description) | Adversaries | Assets | Components | Inherent | Principal mitigations | Residual |
|---|---|---|---|---|---|---|---|
| THR-001 | **Source IP/network identity observed or logged by a platform component.** Any Candor component (web server, app, proxy, WAF, logging, crash reporter, monitoring) receiving or recording a routable source address, as in Proton's compelled IP logging (INC-03) or onion services leaking via `mod_status` (INC-34). | ADV-04, ADV-10, ADV-18, ADV-26 | AST-02 | C-05, C-06, C-38, C-37 | 5×5=25 | Onion-only intake; backends bound to Unix socket; no clearnet listener; no reverse proxy on source path (ADR-001, ADR-009); C-37 exit-list check in memory only (ADR-003) | 1×5=5 (C-38 is by definition not anonymous and labelled) |
| THR-002 | **Source network activity correlated by employer/ISP/local network.** Observer sees that a person used Tor (or a bridge) and when, and intersects with document access, print logs or submission timing (INC-31 Harvard; R4 §2.2). | ADV-07, ADV-08, ADV-09, ADV-15 | AST-02, AST-03 | C-01, C-04 | 4×5=20 | Guidance: never employer networks/devices, bridges, delay (`05`); day-granular timestamps (ADR-010); no source-visible events revealing arrival time to the org | 3×5=15 (behavior-dependent; outside platform control) |
| THR-003 | **End-to-end traffic/timing correlation by a network adversary** observing both the source's entry and the service's entry (B-AN-01..05, INC-35). | ADV-09, ADV-19, ADV-20, ADV-21 | AST-02 | C-04, C-05 | 3×5=15 | Onion-only; full vanguards on service; padding; batching; short sessions; no always-on client (INC-35); future cover-traffic transport (ADR-001) | 2×5=10 (not defended against GPA, NG-03) |
| THR-004 | **Website/onion fingerprinting** of a source's visit to the Candor onion by a local observer (B-AN-15..20). | ADV-07, ADV-08, ADV-09, ADV-15 | AST-03 | C-02, C-06 | 3×4=12 | Minimal, uniform, padded responses (ADR-011, PRD-056); single-origin assets; guidance to browse other onions/sites in the same session | 2×4=8 |
| THR-005 | **Guard discovery / malicious relays against the onion service**, leading to service location and then compulsion/seizure (B-AN-09..13, INC-29/30). | ADV-13, ADV-18, ADV-19 | AST-28, AST-16 | C-05 | 3×4=12 | Full vanguards; current tor; PoW; dedicated host; no egress other than tor | 2×4=8 |
| THR-006 | **Browser fingerprinting / tracking identifiers** (cookies, storage, CSS/JS probes, scheme flooding INC-36) used to recognize a returning source or link to a non-Tor identity. | ADV-04, ADV-07, ADV-18 | AST-01, AST-03 | C-02, C-06 | 3×4=12 | No JS required; no persistent cookies; `__Host-` session cookie only after login; no client hints; no media-query-conditional resource loads; UA/Accept-Language never stored (`03` META); CSP | 1×4=4 (malicious server could still attempt; Tier V/TB Safest limit) |
| THR-007 | **Malicious or compelled server delivers altered client code** (Hushmail INC-01 class): modified HTML/JS or app update capturing plaintext or passphrase, possibly targeted at one source. | ADV-04, ADV-05, ADV-18, ADV-26 | AST-04, AST-07, AST-19 | C-06, C-33, C-03 | 4×5=20 | Tier V: WEBCAT-verified bundle or reproducible, threshold-signed Source App with transparency (ADR-004, ADR-022); Tier W honesty statement; no-JS Tier W limits active code; Desk-side detection of HTML digest drift via published source-UI digests (`11`) | Tier W: 3×5=15; Tier V: 1×5=5 |
| THR-008 | **Browser exploit delivered to the source** (NIT class, INC-27/28) by a seized or compromised server. | ADV-18, ADV-04, ADV-17 | AST-02, AST-01 | C-02, C-06 | 3×5=15 | Source UI works at Safest (no JS); CSP `script-src 'none'` on Tier W pages; guidance to use Safest and Tails; TB updates | 2×5=10 (0-days in TB layout engine remain) |
| THR-009 | **Document metadata identifies the source** (EXIF GPS, Office author, revision history, PDF XMP, embedded thumbnails) (INC-17, INC-18, INC-20). | ADV-30, ADV-06, ADV-07 | AST-01, AST-05 | C-03, C-15, C-17 | 5×5=25 | Tier V client-side strip with source review (PRD-017); sanitized derivatives default in Desk (ADR-012); guidance | 3×5=15 (Tier W and unsupported formats; PRNU not removable) |
| THR-010 | **Content/stylometry/canary-trap/printer-dots identify the source** (B-AN-34..43; INC-16, INC-73). | ADV-06, ADV-07, ADV-30 | AST-01 | Content | 4×5=20 | Guidance (paraphrase, don't print, don't submit unique copies); DEDA-style scan anonymization option in C-17; no server/3rd-party LLM (PRD-069) | 3×5=15 (inherent to content) |
| THR-011 | **Timing metadata identifies the source**: exact timestamps, activity patterns, reply-read timing, import timing (INC-16, INC-74, B-AN-21/22). | ADV-04, ADV-06, ADV-30, ADV-18 | AST-03 | C-06, C-08, C-09, C-10, C-12, C-24 | 4×5=20 | Day-only storage (ADR-010); no read receipts; replies visible at next login; no persistent join of batch seq↔exact time (`03`); daily-batch option for HIGH profile | 2×5=10 |
| THR-012 | **Cryptographic design/implementation failure exposes content** (INC-61..67). | ADV-19, ADV-17, ADV-24 | AST-04, AST-05, AST-12 | C-11 | 2×5=10 | Standard constructions (HPKE, X-Wing, age-STREAM), formal models, KATs, constant-time libs, external crypto review (ADR-006, `04`) | 1×5=5 |
| THR-013 | **Key theft** (server, recipient, backup, HSM) exposes content. | ADV-05, ADV-17, ADV-27 | AST-11..15, AST-34 | C-15, C-16, C-29, C-27, C-28 | 3×5=15 | No server content keys (ADR-007/008); hardware-bound wrapping; epoch destruction; keys not in backups (ADR-025); quorum offline | 2×5=10 (endpoint theft exposes that member's cases) |
| THR-014 | **Server compromise exposes plaintext in memory or future submissions.** | ADV-04, ADV-05, ADV-10, ADV-16, ADV-17 | AST-04, AST-07 | C-06, C-07 | 4×5=20 | Tier V removes; Tier W: isolated sealer, mlock, no swap/core, minimal attack surface, sealer attestation (ADR-004) | Tier W 3×5=15; Tier V 1×3=3 (metadata only) |
| THR-015 | **Database/storage theft exposes content or metadata.** | ADV-05, ADV-10, ADV-11, ADV-27 | AST-04, AST-21 | C-08, C-12, C-13 | 3×4=12 | Content E2E-encrypted; allow-listed metadata only; at-rest encryption for media | 2×2=4 |
| THR-016 | **Log/SIEM/metrics/tracing/crash-dump leakage** of source-sensitive data (INC-58, INC-60, INC-56). | ADV-04, ADV-07, ADV-24 | AST-02..04 | C-24, C-25, C-26, all | 4×4=16 | Typed allow-list logging; prohibited-field lint; access logs off; no core dumps; no off-host crash reports (ADR-016) | 1×4=4 |
| THR-017 | **Backup/snapshot/replica retains data beyond deletion** (INC-55). | ADV-10, ADV-11, ADV-18 | AST-25 | C-27, C-39 | 3×4=12 | Crypto-erasure propagates (ADR-025); keys absent from backups; snapshots disabled for Z-INTAKE | 2×3=6 |
| THR-018 | **Malicious/curious administrator reads reports or identifies the source** (INC-68..71). | ADV-04, ADV-05 | AST-04, AST-01 | C-05..C-14, C-19 | 4×5=20 | Admin ≠ case access; no source metadata to find; Tier V; audit; roster signatures | Tier W 3×5=15 (in-flight); otherwise 1×5=5 |
| THR-019 | **Malicious investigator/recipient identifies or retaliates against the source** (INC-22). | ADV-03, ADV-30 | AST-01 | C-15 | 4×5=20 | Least privilege; no metadata; audit; COI; ≥ 2 members; independent oversight | 3×4=12 |
| THR-020 | **Accused person (incl. executives/admins) accesses, suppresses or learns of the report.** | ADV-06, ADV-04, ADV-03 | AST-06, AST-26 | C-10, C-14, C-22 | 4×5=20 | COI exclusion before wrapping; independent channels; SLA escalation to independent role; admin has no case capability; deletion requires retention rules + dual approval | 2×4=8 |
| THR-021 | **Authorization bypass / IDOR / cross-tenant access** (GlobaLeaks CVE-2026-46647/45020, B-GL-37). | ADV-16, ADV-03 | AST-04, AST-21 | C-10, C-22, C-06 | 4×4=16 | Deny-by-default routes, audience-bound tokens (ADR-029); crypto access control (no key → no plaintext); RLS | 2×3=6 |
| THR-022 | **Authentication compromise of recipient/admin** (phishing, credential theft, OTP reuse — Hush Line CVE-2024-38523). | ADV-16, ADV-17, ADV-05 | AST-23, AST-13 | C-21, C-15, C-20 | 4×4=16 | WebAuthn/PIV phishing-resistant; hardware-bound key unwrap; step-up for sensitive actions | 2×4=8 |
| THR-023 | **Hostile uploaded file exploits recipient/viewer** (B-CR-56, CVE-2021-22204). | ADV-29, ADV-17 | AST-20, AST-13 | C-15, C-17, C-18 | 5×5=25 | No server parsing; network-less disposable viewer; pixels-to-PDF; safefs (ADR-012, ADR-027) | 2×4=8 |
| THR-024 | **Supply-chain compromise** (dependency, build, CI, signing, repository) (INC-37..52). | ADV-22..25 | AST-35, AST-17, AST-19, AST-20 | C-30..C-33 | 4×5=20 | Reproducible dual builds, threshold signing, transparency, cargo-vet, pinned deps, two-person review (ADR-019, ADR-022) | 2×5=10 |
| THR-025 | **Malicious or compromised update delivered to instances** (targeted or broad) (INC-15, INC-38, INC-49). | ADV-25, ADV-26, ADV-20, ADV-24 | AST-19, AST-20 | C-32, C-33, all | 3×5=15 | TUF threshold; identical artifacts; transparency monitors; update client sends no instance identity (ADR-022) | 1×5=5 [A:MON] |
| THR-026 | **Legal compulsion of operator or vendor to disclose or modify** (INC-01..07, INC-12). | ADV-18, ADV-26 | All | C-05..C-14, C-34..C-36 | 4×5=20 | Minimization; keys on endpoints; Tier V; published compelled-disclosure inventory (`03` §10) | Tier W prospective modification 3×5=15; retrospective disclosure 2×2=4 |
| THR-027 | **Vendor/support personnel access to customer data or deployment metadata.** | ADV-24, ADV-26 | AST-29, AST-04 | C-34, C-35, C-36 | 3×4=12 | No vendor access paths; opaque IDs; scrubbed bundles; MANAGED vendor holds no content keys | 2×3=6 |
| THR-028 | **Notification content/metadata leakage** (email, SMS, push) (INC-57, INC-25). | ADV-18, ADV-07 | AST-06, AST-03 | C-23 | 4×3=12 | Content-free, hourly digest, no source notifications (ADR-017) | 1×2=2 |
| THR-029 | **Enterprise integration exfiltrates report content to general systems.** | ADV-03, ADV-07, ADV-06 | AST-04, AST-31 | C-40, C-26 | 3×5=15 | Export Packages only (ADR-018); dual approval for originals | 2×4=8 |
| THR-030 | **Cloud/hosting provider observes metadata, snapshots memory/disks.** | ADV-10, ADV-11 | AST-04, AST-16, AST-28 | C-39 | 3×5=15 | Dedicated hosts; FDE; Tier V; confidential VMs optional | Tier W 2×5=10; Tier V 2×2=4 |
| THR-031 | **Physical seizure/theft** of servers, workstations, backups, HSM. | ADV-27, ADV-18 | AST-13..16, AST-25 | C-39, C-16, C-27, C-29 | 3×4=12 | FDE, tokens with PIN limits, quorum separation, ciphertext backups | 2×3=6 |
| THR-032 | **Denial of service / resource exhaustion** against intake. | ADV-16, ADV-20, ADV-29 | AST-26 | C-05..C-08 | 4×4=16 | PoW; quotas; bounded KDF concurrency; standby onion; store-and-forward | 3×3=9 |
| THR-033 | **Spam/abuse/flooding of intake; malicious false reports.** | ADV-02, ADV-29 | AST-26, triage capacity | C-06, C-10 | 4×3=12 | PoW, per-account quotas, triage queue with SPAM state (ADR-026) | 3×2=6 |
| THR-034 | **Source credential loss or theft** (passphrase disclosure, device seizure). | ADV-08, ADV-28, ADV-18 | AST-07, AST-08 | C-01, C-03 | 3×4=12 | Generated passphrase, not stored; guidance on storage; no recovery (ADR-005) | 2×4=8 |
| THR-035 | **Misconfiguration or dangerous option enables metadata collection.** | ADV-04, ADV-06 | AST-02, AST-03 | C-19, all | 4×4=16 | CFG classification; DANGEROUS needs dual approval; self-test & source-visible config digest; no option can enable IP logging on onion path (no code exists) | 2×3=6 |
| THR-036 | **Telemetry/analytics/third-party resources expose users** (INC-53). | ADV-12, ADV-24 | AST-02, AST-03 | C-06, C-03, C-15 | 4×4=16 | No third-party resources; zero source telemetry; opt-in admin telemetry only (ADR-023) | 1×3=3 |
| THR-037 | **Evidence tampering / chain-of-custody break.** | ADV-03, ADV-04 | AST-27 | C-13, C-15, C-24 | 3×4=12 | Hashes at import in encrypted record; immutable originals; audit | 1×4=4 |
| THR-038 | **Audit records themselves become source-identifying** (or tampered). | ADV-04, ADV-06 | AST-22, AST-01 | C-24 | 3×4=12 | Four event classes; no SOURCE-SENSITIVE events; pseudonymous case IDs; hash chain + external witness (ADR-016) | 1×3=3 |
| THR-039 | **Aggregate reports/metrics enable inference of source identity** (small cells) (INC-74, INC-10). | ADV-06, ADV-07 | AST-30, AST-01 | C-10, C-26 | 4×4=16 | k-thresholds, complementary suppression, coarse periods, fixed query set (`03` §12) | 2×3=6 |
| THR-040 | **Mode confusion**: user believes they are anonymous when confidential/identified. | All | AST-01 | C-06, C-38 | 4×5=20 | Mode banner; C-38 "NOT ANONYMOUS"; explicit transitions; comprehension tests | 2×5=10 |
| THR-041 | **Recipient/investigator operational mistake** (forwarding originals, printing, cloud upload) (INC-16, INC-24). | ADV-03 (non-malicious) | AST-05, AST-01 | C-15, C-16 | 5×5=25 | Sanitized derivatives default; dual-approval original export; training gate; Desk warnings; AIRGAP-RCP | 3×4=12 |
| THR-042 | **Ransomware / destructive attack on case data.** | ADV-16, ADV-05 | AST-25, AST-26 | C-12, C-13, C-27 | 3×4=12 | Immutable/offline backups; content already encrypted; intake independent | 2×3=6 |
| THR-043 | **Clock manipulation / wrong time** affects SLA, crypto epochs, logs. | ADV-04, ADV-15 | AST-33 | all | 2×3=6 | Multiple time sources (NTS), epoch validity checks with tolerance, monotonic batch seq | 1×3=3 |
| THR-044 | **Onion service private key compromise** (impersonation/phishing of sources). | ADV-10, ADV-27, ADV-04 | AST-16 | C-05 | 2×5=10 | TPM-sealed key; offline backup custody; standby address; Tier V pins channel keys (impersonator cannot decrypt Tier V envelopes without epoch keys) | Tier W 2×5=10; Tier V 1×3=3 |
| THR-045 | **Multi-tenant co-residency leakage.** | ADV-11, ADV-16 | AST-04, AST-21 | C-12, C-39 | 2×4=8 | EE only, low/moderate-risk tenants; RLS; per-tenant keys and onions (ADR-021) | 1×3=3 |
| THR-046 | **Hidden recipient insertion / key substitution** (Anom INC-14; Matrix INC-62). | ADV-04, ADV-06, ADV-18 | AST-18, AST-04 | C-14, C-06, C-15 | 3×5=15 | Roster signed by member quorum, transparency log, client verification (Tier V), source-visible roster, Desk verifies wraps | Tier W 2×5=10; Tier V 1×5=5 [A:MON] |
| THR-047 | **Resumable/chunked upload metadata correlates sessions.** | ADV-04, ADV-18 | AST-03 | C-06, C-08 | 3×3=9 | No resumable uploads in Tier W; Tier V upload tokens random, unlinkable to source account, 24 h TTL, deleted at finalization | 1×3=3 |
| THR-048 | **Source device forensic residue** (history, downloads, codename written down). | ADV-28, ADV-08 | AST-07, AST-01 | C-01, C-02, C-03 | 4×4=16 | No downloads to source; no-store; Tails guidance; app minimal state | 3×4=12 |

### 9.2 Additional threats THR-100..THR-125

| ID | Threat (full description) | Adversaries | Assets | Components | Inherent | Principal mitigations | Residual |
|---|---|---|---|---|---|---|---|
| THR-100 | **Online guessing / brute force of source credentials** against the login endpoint or the stored verifier. | ADV-16, ADV-04 | AST-07, AST-08 | C-06, C-07, C-08 | 2×4=8 | ≈129-bit passphrase; Argon2id; PoW; per-circuit and global rate limits (ADR-005/026) | 1×4=4 |
| THR-101 | **Replay, reordering, dropping or duplication of envelopes/replies** by a compromised intake or relay (malicious-server integrity; Threema/Telegram class INC-63/64). | ADV-04, ADV-05 | AST-04, AST-08, AST-26 | C-08, C-09 | 3×4=12 | Monotonic batch sequence signed by C-07 key; Desk gap/duplicate detection; per-mailbox message counters authenticated in envelopes; Tier V signed receipt to source | 2×3=6 (suppression detectable, not preventable) |
| THR-102 | **Key-directory equivocation, split view or freeze** (serving a targeted source an old or forged epoch key/roster). | ADV-04, ADV-18 | AST-18 | C-14, C-06 | 3×5=15 | Signed tree heads, consistency proofs, epoch freshness (max age 14 days) checks in Tier V, gossip of tree heads via C-37 and Desk | Tier W 2×5=10; Tier V 1×4=4 [A:MON] |
| THR-103 | **Onion-address substitution/phishing** via compromised/spoofed C-37, look-alike addresses, ads, search poisoning, fake mirrors (incl. I2P "mirrors"). | ADV-15, ADV-12, ADV-16, ADV-18 | AST-16, AST-01 | C-37, C-02 | 3×5=15 | Signed onion-address statement (channel identity key) on C-37, in Source App, printed materials; Onion-Location; HSTS; guidance to verify | 2×5=10 |
| THR-104 | **Onion-service location disclosure** via misconfiguration or egress (DNS, NTP, apt, error pages with host IP, co-hosted services) (INC-33, INC-34). | ADV-16, ADV-18 | AST-28 | C-05, C-06, C-39 | 3×4=12 | Egress default-deny except tor; updates fetched over tor; loopback/Unix-socket binding; no status endpoints; no co-hosting (REQ-H-33/34) | 1×4=4 |
| THR-105 | **Tracking/bait content in replies**: remote resources, links, unique facts or canary questions designed to make the source reveal themselves or to detect where the reply is re-leaked. | ADV-30, ADV-06 | AST-01 | C-15, C-06 | 3×5=15 | Plain-text replies, no links/resources (PRD-025); source warnings about questions that could identify them; ≥ 2 recipients see replies (audit) | 2×4=8 |
| THR-106 | **Social engineering to move the source off-platform** or into identifying actions (Lamo INC-21). | ADV-30, ADV-02 | AST-01 | C-15, source | 3×5=15 | Persistent UI warning; recipient code of conduct; replies attributed to role+fingerprint | 2×5=10 |
| THR-107 | **Document call-home beacons** (canary tokens, remote templates, tracking pixels, DNS beacons, macro callbacks) fired when evidence is opened, alerting the originating organization that the document was leaked and to whom. | ADV-07, ADV-06 | AST-06, AST-01 | C-17, C-15, C-16 | 4×5=20 | Evidence opened only in network-less VM; no opening in Desk or host OS; sanitized derivatives; guidance to sources that documents may contain canaries | 1×4=4 (source-side opening before submission is outside control) |
| THR-108 | **Evidence hash/sample submitted to external services** (VirusTotal, cloud AV, EDR cloud sandbox, DLP) revealing the leaked document's existence. | ADV-07, ADV-12 | AST-06 | C-16, C-17 | 4×4=16 | PRD-069; Desk stores evidence only in encrypted app store; guidance to exclude Desk data dirs from cloud AV submission; AIRGAP-RCP | 2×4=8 |
| THR-109 | **Recipient-side AI assistants, cloud sync, OS indexing** ingest decrypted content (Copilot, Spotlight, OneDrive, screenshot history features). | ADV-07, ADV-11, ADV-03 (non-malicious) | AST-04, AST-05 | C-15, C-16 | 4×4=16 | Desk marks windows as capture-protected where OS supports; plaintext never written to user-visible paths; indexing exclusion; training; recommended hardened workstation profile (`17`) | 2×4=8 |
| THR-110 | **COI exclusion / access-change side channel** reveals to the accused that a report concerns them (e.g., they lose access they previously had, or see a case count they cannot open). | ADV-06, ADV-04 | AST-06 | C-10, C-22, C-14, C-15 | 3×4=12 | Excluded users never see existence of the case (no count, no placeholder); roster is per channel not per case; COI exclusions applied at import silently; independent channels for leadership | 2×3=6 |
| THR-111 | **Identity-Custodian unsealing abuse or coerced unsealing.** | ADV-06, ADV-26, ADV-30 | AST-09 | C-15, C-10 | 3×5=15 | Two custodians; legal basis; source notice unless deferral recorded; CASE audit reviewed independently (ADR-014) | 2×5=10 |
| THR-112 | **Recovery-Quorum collusion, coercion or share theft.** | ADV-06, ADV-27, ADV-26 | AST-15 | C-28 | 2×5=10 | Off by default; k-of-n from independent roles; source-visible escrow status; offline ceremony with audit (ADR-013) | 1×5=5 |
| THR-113 | **Fleet Manager / vendor management plane used as command channel** (config push, exfiltration, instance deanonymization, compelled vendor). | ADV-24, ADV-26, ADV-20 | AST-24, AST-29 | C-34 | 3×5=15 | Fleet manager is read/status only for trust-path config; any change requires local dual approval; no onion addresses in cleartext; outbound-only | 1×4=4 |
| THR-114 | **Phone-home**: licensing, update checks or telemetry reveal instance identity, onion address or activity levels. | ADV-26, ADV-24 | AST-29, AST-30 | C-35, C-33, C-25 | 3×4=12 | Offline license files; update client over tor with no instance ID; telemetry off by default and schema-fixed (ADR-022/023) | 1×3=3 |
| THR-115 | **Mode/tier downgrade without informed consent**: Tier V → Tier W silently (e.g., WEBCAT or app fails), or ANONYMOUS → CONFIDENTIAL through UI trickery or confusing defaults. | ADV-04, ADV-18 | AST-04, AST-01 | C-06, C-03 | 3×5=15 | Tier V clients never fall back automatically; explicit confirmation screens; mode shown persistently | 1×5=5 |
| THR-116 | **Coercion of individual staff** (recipients, custodians, quorum holders, admins) to decrypt, unseal or alter. | ADV-06, ADV-18, ADV-20 | AST-13..15 | People | 3×5=15 | Multi-party controls (dual approval, quorum); duress procedures; independent audit; key roles spread across jurisdictions/organizations for high-risk deployments | 2×5=10 |
| THR-117 | **Key loss** leading to irrecoverable case data (all members lose devices/tokens, no quorum). | Non-adversarial; ADV-16 (ransomware), ADV-27 (theft) | AST-12, AST-13 | C-15, C-28 | 3×4=12 | ≥ 2 members per case; token backups (second registered token per user); optional quorum; warnings | 2×3=6 |
| THR-118 | **Absence of independent transparency-log monitoring** nullifies mitigations for THR-007/025/046/102. | ADV-24, ADV-26 | AST-17, AST-18 | C-14, C-32 | 3×5=15 | ≥ 2 independent monitors funded/recruited (e.g., civil-society orgs); Desk and Source App gossip tree heads; public monitor status page | 2×5=10 |
| THR-119 | **Decompression bombs and parser DoS** against viewer or client (B-CR-52). | ADV-29 | AST-20, AST-26 | C-17, C-15 | 4×2=8 | VM resource limits; per-file time budget; no automatic processing | 2×1=2 |
| THR-120 | **Differencing/query attacks on metrics** (overlapping filters, repeated regeneration) defeating k-thresholds. | ADV-06, ADV-07 | AST-30 | C-10, C-26 | 3×4=12 | Fixed report catalog; no ad hoc queries; complementary suppression; regeneration rate limits (`03` §12) | 1×3=3 |
| THR-121 | **Source coercion/compromise of passphrase**: adversary logs in as the source to read replies and impersonate the source to recipients. | ADV-18, ADV-08, ADV-28 | AST-07, AST-08 | C-06, C-15 | 2×4=8 | Replies minimal; recipients trained to verify unexpected behavior; source may close mailbox; no replay of old content beyond what exists | 2×3=6 |
| THR-122 | **Fabricated/manipulated evidence** (forged documents, deepfake media) to mislead investigations or smear an accused. | ADV-02, ADV-29 | AST-27, integrity of outcomes | C-15, C-17 | 3×4=12 | Investigative procedures; provenance notes; no automatic trust in content; evidence hashes | 3×3=9 (inherent) |
| THR-123 | **Micro-architectural/side-channel leakage** from C-07 or C-11 on shared hardware (timing, cache, speculative execution). | ADV-10, ADV-11, ADV-17 | AST-04, AST-11 | C-07, C-11, C-39 | 2×4=8 | Dedicated hosts for Z-INTAKE; constant-time crypto; microcode/kernel mitigations | 1×4=4 |
| THR-124 | **Support/helpdesk social engineering** to reset staff credentials, obtain bundles or data (INC-26, INC-56). | ADV-02, ADV-16 | AST-23 | C-21, C-36 | 3×4=12 | No helpdesk reset of key-bearing credentials; re-enrolment requires in-person/dual approval; support never receives content or secrets | 1×4=4 |
| THR-125 | **Investigation-action leakage**: investigative steps (who is interviewed, which records are pulled, timing of HR actions) narrow the candidate source set for the accused or management. | ADV-06, ADV-30, ADV-01 | AST-01 | Process (C-15) | 4×5=20 | Investigation-planning guidance and "source-exposure check" task in case workflow (`14`); independent investigators for leadership cases | 3×4=12 |

## 10. Attack trees

Notation: `[OR]` any child suffices; `[AND]` all children required. Each leaf: `{THR; primary mitigation; residual L×I}`. Tier-specific leaves are marked (W)/(V).

### TREE-1 Goal: identify an anonymous source

```
G1 Identify the anonymous source of report R  [OR]
├── 1.1 Obtain source network identity  [OR]
│   ├── 1.1.1 Read IP from Candor components            {THR-001; onion-only, no IP present; 1×5}
│   ├── 1.1.2 End-to-end correlation  [AND]
│   │   ├── observe source ↔ guard (ISP/employer/relay) {THR-002/003}
│   │   └── observe service ↔ guard or know arrival time {THR-005/011; vanguards, day-only timestamps; 2×5}
│   ├── 1.1.3 Guard discovery of source + ISP compulsion (BKA/Ricochet pattern) {THR-003; short sessions, no always-on client; 1×5}
│   ├── 1.1.4 Deliver exploit to source browser (NIT) [AND]
│   │   ├── control or compel C-06                        {THR-007/008}
│   │   └── source runs JS / vulnerable TB                 {no-JS UI, Safest guidance; 2×5}
│   └── 1.1.5 Source uses clearnet C-38 believing anonymous {THR-040; NOT ANONYMOUS labels; 2×5}
├── 1.2 Correlate with organizational logs  [AND]
│   ├── 1.2.1 Know who used Tor/bridges when (proxy/EDR/Wi-Fi logs) {THR-002; guidance; 3×5}
│   └── 1.2.2 Know when report arrived / was read [OR]
│       ├── exact timestamps in Candor                    {THR-011; not stored; 1×5}
│       ├── notification timing                           {THR-028; hourly content-free digest; 1×3}
│       ├── investigation actions reveal report date     {THR-125; guidance; 3×4}
│       └── reply-read timing                             {no read receipts; 1×4}
├── 1.3 Identify from content  [OR]
│   ├── 1.3.1 File metadata                               {THR-009; stripping/sanitize; 3×5}
│   ├── 1.3.2 Stylometry vs internal corpus (LLM)          {THR-010; guidance only; 3×5}
│   ├── 1.3.3 Canary/watermark in document                 {THR-010; guidance; 3×5}
│   ├── 1.3.4 Printer MIC / scan artifacts                 {THR-010; DEDA option, don't-print guidance; 2×5}
│   └── 1.3.5 Unique knowledge (only 3 people knew)        {inherent; guidance; 4×5}
├── 1.4 Abuse platform functions  [OR]
│   ├── 1.4.1 Bait questions / tracking content in replies {THR-105; plain text replies; 2×4}
│   ├── 1.4.2 Lure off-platform                            {THR-106; warnings; 2×5}
│   ├── 1.4.3 Unseal identity (CONFIDENTIAL only)          {THR-111; dual custodian; 2×5}
│   ├── 1.4.4 Small-cell statistics / differencing         {THR-039/120; k-thresholds; 1×3}
│   └── 1.4.5 Audit/SIEM data                              {THR-016/038; allow-list; 1×3}
├── 1.5 Obtain source credential and device [OR]
│   ├── 1.5.1 Seize device; forensic residue               {THR-048; Tails guidance; 3×4}
│   └── 1.5.2 Keylogger/EDR on managed device               {ADV-08; guidance only; 3×5}
└── 1.6 Fingerprint returning visitor                      {THR-006; no persistent identifiers; 1×4}
```
Dominant residual paths: 1.2 and 1.3 (behavior and content), consistent with R4's conclusion that non-network channels dominate.

### TREE-2 Goal: read report content

```
G2 Read plaintext of report R without authorization  [OR]
├── 2.1 At intake  [OR]
│   ├── 2.1.1 (W) Compromise C-06/C-07 during submission   {THR-014; sealer isolation; 3×5}
│   ├── 2.1.2 (W) Compel operator to modify intake          {THR-026/007; disclosure; 3×5}
│   ├── 2.1.3 (V) Serve malicious client code                {THR-007; WEBCAT/app signatures + transparency; 1×5}
│   ├── 2.1.4 Substitute channel epoch key (hidden recipient) [AND]
│   │   ├── forge/equivocate key directory                   {THR-046/102}
│   │   └── (W) source cannot verify / (V) monitors absent   {THR-118; W 2×5, V 1×5}
│   └── 2.1.5 Impersonate onion with stolen key              {THR-044; TPM seal; (W) 2×5, (V) 1×3}
├── 2.2 At rest  [OR]
│   ├── 2.2.1 Steal C-08/C-12/C-13/C-27 data                 {THR-015/017; ciphertext only; 1×5}
│   ├── 2.2.2 Break crypto                                   {THR-012; standard PQ hybrid; 1×5}
│   └── 2.2.3 Obtain epoch private keys after window         {destroyed (ADR-008); 1×5}
├── 2.3 At recipient  [OR]
│   ├── 2.3.1 Compromise a member's C-16 + unlock token      {THR-013; hardware wrap; 2×5}
│   ├── 2.3.2 Phish member credentials                       {THR-022; WebAuthn; 2×4}
│   ├── 2.3.3 Hostile file → viewer escape → Desk            {THR-023; network-less VM; 2×4}
│   ├── 2.3.4 Cloud sync/AI assistant ingestion              {THR-109; exclusions; 2×4}
│   └── 2.3.5 Authorized reader leaks                         {THR-019/041; audit, dual approval; 3×4}
├── 2.4 Via authorization system  [OR]
│   ├── 2.4.1 Admin adds self to roster                      {THR-046; member signatures; 1×5}
│   ├── 2.4.2 IDOR / cross-tenant                             {THR-021; no key → no plaintext; 1×3}
│   └── 2.4.3 Break-glass abuse                                {dual authorization + post-hoc review; 2×4}
├── 2.5 Via recovery paths  [OR]
│   ├── 2.5.1 Collude/coerce k quorum holders                 {THR-112; off by default; 1×5}
│   └── 2.5.2 Restore old backup with un-erased keys          {THR-017; keys not in backups; 1×5}
└── 2.6 Via integrations/exports                               {THR-029; Export Packages only; 2×4}
```

### TREE-3 Goal: suppress a report (the accused prevents action)

```
G3 Prevent report R from being acted upon  [OR]
├── 3.1 Prevent submission  [OR]
│   ├── 3.1.1 DoS the onion                                    {THR-032; PoW, standby onion; 3×3}
│   ├── 3.1.2 Block Tor on corporate network                    {guidance: personal network; 3×2}
│   └── 3.1.3 Phish sources to a fake portal                     {THR-103; signed addresses; 2×5}
├── 3.2 Drop/alter submission in transit  [OR]
│   ├── 3.2.1 Intake admin deletes envelopes                     {THR-101; sequence gap detection in Desk; 2×3}
│   └── 3.2.2 Relay withholds batches                            {Desk alarms on missing seq; C-25 alert; 2×3}
├── 3.3 Control the recipients  [OR]
│   ├── 3.3.1 Accused is a recipient                              {THR-020; COI exclusion before wrap; 1×4}
│   ├── 3.3.2 Accused adds loyal recipient                         {THR-046; roster signatures, visible roster; 2×4}
│   └── 3.3.3 Recipient sits on case                                {SLA escalation to independent role; 2×3}
├── 3.4 Destroy case data  [OR]
│   ├── 3.4.1 Admin deletes DB rows                                 {backups; audit; ≥2 members detect; 2×3}
│   ├── 3.4.2 Ransomware                                             {THR-042; offline backups; 2×3}
│   └── 3.4.3 Premature disposition via retention change            {retention changes are DANGEROUS config; legal hold; 1×4}
└── 3.5 Discredit                                                      {THR-122 fabricated counter-evidence; process; 3×3}
```

### TREE-4 Goal: deliver malicious client code (to sources or staff)

```
G4 Get attacker-controlled code executed in C-02/C-03/C-15/C-17  [OR]
├── 4.1 Via the live server  [OR]
│   ├── 4.1.1 (W) Modify Tier W HTML/CSS for a targeted source    {THR-007; no JS executes at Safest; HTML-only capture of form still possible: 3×5}
│   ├── 4.1.2 Serve JS bundle not matching WEBCAT manifest          {THR-007; WEBCAT blocks; 1×5}
│   └── 4.1.3 Serve browser exploit                                   {THR-008; no-JS, CSP; 2×5}
├── 4.2 Via updates  [OR]
│   ├── 4.2.1 Compromise CI/builder  [AND]
│   │   ├── compromise builder A                                     {THR-024}
│   │   └── compromise independent builder B                         {ADR-022; 1×5}
│   ├── 4.2.2 Steal threshold of signing keys                        {offline threshold; 1×5}
│   ├── 4.2.3 Targeted update to one customer  [AND]
│   │   ├── sign special artifact                                    {requires 4.2.2}
│   │   └── avoid transparency log detection                          {THR-118; monitors; 1×5}
│   ├── 4.2.4 Freeze/rollback attack via mirror                      {TUF expiry/version checks; 1×3}
│   └── 4.2.5 Compelled vendor release                                {THR-025/026; threshold signers across jurisdictions; 1×5}
├── 4.3 Via dependencies                                              {THR-024; cargo-vet, pinned, reviewed; 2×5}
├── 4.4 Via distribution  [OR]
│   ├── 4.4.1 Fake Source App download site                           {THR-103; signed hashes out of band; 2×4}
│   └── 4.4.2 App-store account compromise                            {reproducible builds, in-app verification; 2×4}
└── 4.5 Via Fleet Manager config push                                  {THR-113; no trust-path config push; 1×4}
```

### TREE-5 Goal: compromise recipients via a hostile upload

```
G5 Compromise a recipient endpoint or other cases via submitted content  [OR]
├── 5.1 Exploit server-side processing                                 {none exists (ADR-012); 1×4}
├── 5.2 Exploit Desk  [OR]
│   ├── 5.2.1 Filename path traversal / archive header injection        {ADR-027 safefs, content-addressed names; 1×4}
│   ├── 5.2.2 XSS/HTML injection in text fields                         {plain-text rendering; Tauri CSP; 1×4}
│   └── 5.2.3 Malformed envelope → parser bug in candor-core            {fuzzing, Rust; 2×4}
├── 5.3 Exploit viewer and escape  [AND]
│   ├── 5.3.1 Exploit renderer in C-17 (e.g. CVE-2021-22204 class)       {sandboxed; assumed possible}
│   └── 5.3.2 Escape microVM/DispVM                                       {hypervisor hardening; AIRGAP-RCP; 1×5}
├── 5.4 Beacon/call-home when opened                                     {THR-107; network-less; 1×4}
├── 5.5 Social engineering "please open in Word to see macros"           {training; Desk refuses host-open without dual approval; 2×4}
├── 5.6 Resource exhaustion (zip bomb)                                    {THR-119; limits; 2×1}
└── 5.7 Sanitizer output carries payload (polyglot survives)             {pixels-to-PDF re-rasterization; second-VM qpdf normalization; 1×4}
```

### TREE-6 Goal: unseal a CONFIDENTIAL source's identity without lawful basis

```
G6 Obtain sealed identity  [OR]
├── 6.1 Coerce/collude two Identity Custodians                          {THR-111/116; independent custodians; 2×5}
├── 6.2 Compromise a custodian endpoint + one other custodian's approval {THR-013; dual crypto approval (2-of-n unwrap); 1×5}
├── 6.3 Fabricate legal basis                                           {independent review of unseal audit; source notice; 2×4}
└── 6.4 Infer identity from case content despite sealing                 {Art 16 indirect identification; redaction; 3×4}
```

### TREE-7 Goal: insert a hidden recipient (Anom class)

```
G7 Cause future submissions to be decryptable by attacker  [OR]
├── 7.1 Add attacker key to channel roster  [AND]
│   ├── obtain ≥2 member signatures (coerce/compromise)                 {THR-046/116; 1×5}
│   └── source does not notice roster change                             {roster shown; Tier V diff warning; 2×4}
├── 7.2 Serve forged epoch key to targeted source                        {THR-102; Tier V verification; (W) 2×5, (V) 1×5}
├── 7.3 Enable Recovery Quorum with attacker-held shares                 {DANGEROUS dual approval; escrow visible to sources; 1×5}
└── 7.4 Malicious client release that adds a key                          {TREE-4; 1×5}
```

## 11. Abuse cases

Misuse by legitimate users or of legitimate features. Each abuse case becomes a negative test (`29-SECURITY-TESTING.md`).

| ID | Actor | Abuse | THR | Prevention / detection |
|---|---|---|---|---|
| ABUSE-01 | Admin (PER-08) | Enables verbose/debug logging on intake to capture request details | THR-035, THR-016 | Trust-path code contains no request-logging capability; log level cannot include fields outside schema; config digest change visible to sources |
| ABUSE-02 | Admin | Adds themself or management to a channel roster | THR-046 | Roster changes require member signatures; published; sources see roster |
| ABUSE-03 | Admin | Restores an old backup to "recover" deleted cases | THR-017 | Keys not in backups; restored ciphertext undecryptable after crypto-erasure |
| ABUSE-04 | Management (PER-10) | Requests statistics "by department and month" to find the reporter | THR-039, THR-120 | Fixed catalog; department dimension disallowed; k-thresholds |
| ABUSE-05 | Management | Orders SOC to correlate Tor usage with report received dates | THR-002, THR-011 | Received date is day-only; guidance to sources; audit of staff actions; legal (EU Art 19 retaliation) — technical control partial |
| ABUSE-06 | Recipient (PER-03) | Exports originals to personal email | THR-041, THR-029 | Dual approval for originals; export audit |
| ABUSE-07 | Recipient | Sends a reply containing a unique detail to detect re-leak | THR-105 | Second member sees replies; audit review; source guidance |
| ABUSE-08 | Investigator | Interviews only the few people who knew a fact, exposing the source | THR-125 | Source-exposure checklist task before interviews |
| ABUSE-09 | Custodian | Unseals identity out of curiosity | THR-111 | Dual approval; source notice; audit review |
| ABUSE-10 | Security team (PER-09) | Adds source-sensitive fields to SIEM exporter | THR-016 | C-26 schema fixed in trust-path code; exporter cannot add fields |
| ABUSE-11 | Source (ADV-29) | Floods with fabricated reports against a rival | THR-033, THR-122 | PoW, quotas; triage; SPAM state; no automatic action on accused |
| ABUSE-12 | Source | Submits malware to compromise investigators | THR-023 | ADR-012 containment |
| ABUSE-13 | Vendor support (C-36) | Requests full logs/HAR from customer for "debugging" | THR-027, THR-124 | Support bundles generated by `candorctl` with fixed scrub schema; support never requests source-side data |
| ABUSE-14 | Fleet Manager operator | Correlates instance IDs with customer contracts to map onion addresses | THR-113, THR-027 | Fleet Manager never receives onion address in cleartext (only salted hash for health) |
| ABUSE-15 | Accused executive | Changes retention schedule to dispose of case early | THR-020 | Retention changes DANGEROUS (dual approval, not by accused per COI), legal hold, audit |
| ABUSE-16 | Recipient | Uses break-glass to open a case they are excluded from | THR-020 | Break-glass requires dual authorization, excludes COI-flagged users, triggers post-hoc independent review |

## 12. Component compromise analysis

Assumption for every row: **the component is completely compromised** (attacker has full control of code, memory and storage of that component, and its credentials), and all other components are intact unless stated. Recovery procedures are executed per `31-INCIDENT-RESPONSE.md`.

### 12.1 Standard recovery primitives

| ID | Primitive |
|---|---|
| RP-A | **Rebuild**: wipe or replace hardware/VM; reinstall from TUF-verified packages; restore only data (never binaries/config scripts) from backups; run self-test and Secret Placement Manifest check (ADR-028). |
| RP-B | **Epoch rotation**: channel members publish new epoch keys immediately; mark compromised epochs revoked in key directory; destroy compromised epoch private keys after importing pending envelopes. |
| RP-C | **Channel identity rotation**: new channel identity key generated on a member's Desk, cross-signed by roster quorum (and old key if not compromised); transparency-log entry; sources see "channel keys changed on YYYY-MM-DD" notice. |
| RP-D | **Member revocation**: revoke staff device/keys in key directory; rotate case keys of affected cases for future content; re-wrap to remaining members; review CASE audit for that member. |
| RP-E | **Onion rotation**: activate pre-generated standby onion (separately keyed); publish signed statement on C-37, in Source App config, and in key directory; old address shows nothing (key assumed attacker-held) — warn via all out-of-band channels. |
| RP-F | **Infrastructure credential rotation**: DB roles, mTLS certs, SSH/FIDO2 registrations, at-rest keys, backup encryption keys, API tokens. |
| RP-G | **Notification**: internal IR, regulators where required (e.g., GDPR Art 33 within 72 h — B-CO-09), affected staff; source-facing notice on landing page stating facts and recommended actions (no speculation). |
| RP-H | **Supply-chain response**: freeze updates (TUF targets with short expiry left to lapse / signed freeze), rotate compromised signing keys via TUF root rotation, rebuild from last verified commit, publish advisory and transparency-log annotations. |
| RP-I | **Audit verification**: verify hash chain against external witness checkpoints; identify tampering window. |

### 12.2 Per-component analysis

| Component | What happens if completely compromised | What the attacker learns | Blast radius | Detection | Recovery |
|---|---|---|---|---|---|
| **C-01 Source device + OS** | Attacker controls everything the source does: keystrokes, screen, files, network. | Source identity, passphrase, all plaintext the source types/uploads/reads, Candor usage. | That source (all their reports). Not other sources. | Not by Candor. Source-side only (AV, behavior). | Source guidance: stop using device, new device/Tails, new passphrase/new report; the old mailbox should be considered read by adversary (close mailbox from clean device). |
| **C-02 Source browser (Tor Browser)** | Malicious browser/extension or exploited TB: can leak IP, plaintext, passphrase. | As C-01 for browsing session. | That source. | Candor cannot detect (no fingerprinting). | As C-01; guidance to reinstall TB from verified source or use Tails. |
| **Anonymity client (tor in Tor Browser; Arti in C-03)** | Bypass Tor, reveal IP to observers, route through attacker relays. | Source IP (to network observer), visited onion. | That source. | Not by server (by design no IP check). | Reinstall verified client; reconsider exposure; new passphrase if session exposed. |
| **C-03 Candor Source App** | Malicious build or device-level compromise of app: capture plaintext/passphrase, encrypt to attacker keys, exfiltrate outside Tor. | Everything the app handles for affected users. If malicious *release*: all app users after update. | Individual (device-level) or all app users (release-level, THR-025). | Release-level: reproducibility mismatch, transparency-log monitors, independent rebuilds. | RP-H; revoke release; in-app kill switch via TUF; advisory to sources via C-37 and landing page. |
| **C-04 Tor network** (large fraction of relays malicious) | Correlation, guard discovery, DoS. | Source IPs of those observed at both ends; service location. | Potentially many sources over time; service location. | Tor Project bad-relay detection; not by Candor. | RP-E if service location exposed; rely on Tor Project remediation; consider moving service host. |
| **C-05 Intake Gateway** | Attacker controls tor daemon and onion key; can impersonate intake, observe circuits, drop traffic, run own web service. | Onion private key; timing and sizes of requests; circuit IDs; (with C-06 replacement) Tier W plaintext of new submissions. **Never** source IPs. | All future Tier W submissions to this instance until detected; Tier V clients refuse forged keys. | Self-test integrity mismatch, sealer attestation failure seen by Desk, C-25 file-integrity alerts, unexpected egress. | RP-A, RP-E (onion key assumed stolen), RP-B, RP-F, RP-G; notice to sources advising any Tier W submissions in window may have been read. |
| **C-06 Source Web Service (frontend + source API)** | Serve modified HTML (THR-007), exploit attempts (THR-008), forged roster/epoch keys to Tier W clients, capture passphrases at login (Tier W), observe Tier W plaintext as it streams to C-07. | Tier W plaintext and passphrases during window; source session activity (in RAM); no IP. Tier V: ciphertext only + sizes/timing. | All Tier W sources using the instance during compromise; Tier V: metadata only. | Published source-UI digest mismatch (checked by C-25 onion probe and Desk), sealer attestation, WEBCAT failure reports by Tier V users, integrity monitoring. | RP-A, RP-B (rotate epochs to be safe), RP-F, RP-G; recommend Tier W sources who logged in during window close mailbox and resubmit with new passphrase. |
| **C-07 Intake Sealer (encryption service)** | Read all Tier W plaintext and derived source keys at login; encrypt to attacker keys; skip encryption; weaken randomness. | Tier W content and source private keys of sources logging in during window (can decrypt their replies). | Tier W sources during window. Tier V unaffected (sealer handles ciphertext passthrough only). | Desk verifies envelope structure and signature by sealer key registered in key directory; KAT self-tests; attestation. | RP-A; rotate sealer signing key; RP-B; RP-G; sources notified as C-06. |
| **C-08 Intake Store (intake DB)** | Read/modify/delete sealed envelopes, source account records, pending replies. | Ciphertext; padded sizes; received days; channel IDs; number of source accounts; auth verifiers (offline guessing infeasible at ≈129 bits). | Availability/integrity of pending submissions; no content. | Batch sequence gaps/duplicates at Desk (THR-101); DB integrity checks. | Restore from last good state if needed; RP-A; RP-F; sources whose pending envelopes were dropped cannot be identified — landing-page notice with date range. |
| **C-09 Intake Relay** | Withhold/drop/replay batches; push forged replies (cannot sign as staff); attempt to connect into intake (it initiates by design). Pivot into Z-CORE. | Ciphertext batches; sequence numbers; timing of pulls. | Availability; Z-CORE pivot attempt. | Sequence gap alarms; relay signature checks; Z-CORE network monitoring. | RP-A; RP-F (relay mTLS certs); verify Z-CORE hosts for lateral movement. |
| **C-10 Case Service (API)** | Serve wrong data to Desk, withhold cases, modify allow-listed metadata, tamper workflow state, attempt to trick Desk into wrapping keys to attacker (blocked by Desk verification of roster), issue forged notifications. | Allow-listed case metadata for all tenants; staff identities and activity; no content. | Workflow integrity/availability; metadata of all cases. | Desk-side consistency checks (signed case objects, roster verification), audit chain mismatch vs witness, SLA anomalies. | RP-A, RP-F, RP-I; reconcile case state from Desk-signed objects; RP-G if metadata exfiltrated. |
| **C-11 candor-core crypto library** (malicious or flawed) | Everywhere it runs: weak keys, key exfiltration, plaintext leakage. | Potentially all content protected by affected versions. | All instances running the version; long-term exposure for stored ciphertext. | KATs, differential testing vs second implementation, formal verification, audits, reproducibility. | RP-H; emergency release; re-encryption campaign (Desk re-wraps case keys and re-encrypts objects under new keys); advisory. |
| **C-12 Case Database** | Read/modify/delete rows; tamper metadata; delete cases. | Allow-listed metadata, wrapped keys (useless without member private keys), ciphertext objects, audit if co-located. | Availability/integrity; metadata disclosure. | Checksums, Desk object signatures, audit witness mismatch. | Restore from backup; RP-F; RP-I. |
| **C-13 Case Blob Store (object storage)** | Read/delete/replace ciphertext blobs. | Ciphertext and padded sizes only. | Availability/integrity of evidence. | AEAD failure on open; hash mismatch vs record. | Restore blobs from backup; RP-F. |
| **C-14 Key Directory & Transparency Log** | Equivocate, add hidden keys, freeze, rollback. | Nothing secret (public data). | All Tier W sources (cannot verify); Tier V only if monitors absent (THR-118). | Consistency proofs, gossip via C-37/Desk/monitors, Desk verification of roster signatures. | Publish signed incident annotation; members re-sign roster; RP-C if channel key misuse suspected. |
| **C-15 Candor Desk** (on one endpoint; or malicious release) | Endpoint: decrypt all cases of that member, sign as member, approve exports, alter case content. Release: all members. | Endpoint: plaintext of member's cases + their channels' pending imports (epoch keys). Release: everything recipients see. | One member's ACL, or everything (release). | Anomalous CASE audit patterns reviewed by independent role; release transparency. | RP-D for member; RP-B; RP-H for release; review exports in window; RP-G. |
| **C-16 Recipient workstation OS** (including investigation workstations) | As C-15 endpoint compromise, plus keystroke/screen capture of token PIN; cloud sync exfil. | As C-15 endpoint. | Member's ACL. | EDR (customer), Desk integrity checks, anomaly review. | Reimage; RP-D; new hardware token; RP-B. |
| **C-17 Evidence Viewer (malware-analysis / containment VM)** | Hostile file controls the disposable VM; can alter derivative output for that file; attempts escape. | That single file's plaintext (already in VM). | One file (per-VM disposability); escape → C-16 compromise. | Output verification in second VM; VM crash telemetry local; hypervisor alerts. | Destroy VM (automatic); if escape suspected treat as C-16 compromise; patch viewer image. |
| **C-18 Air-gapped Viewing Station** | Attacker with physical/ supply access controls station. | All evidence viewed on it. | Cases viewed on station. | Physical tamper seals; periodic re-imaging with verified media. | Reimage from verified media; review derivatives exported during window. |
| **C-19 Admin Console / candorctl** (malicious build or session) | Issue admin actions with admin credentials; propose DANGEROUS config (needs second approver). | Infrastructure state; no content. | Infrastructure; availability. | SECURITY audit; dual approval notifications. | RP-F; revert config from signed baseline; RP-I. |
| **C-20 Admin workstation** | Stolen admin credentials, SSH agent hijack; pivot to servers. | As ADV-05. | Servers administered by that admin (not content). | Unusual admin actions; FIDO2 touch requirement limits silent use. | Reimage; re-enroll FIDO2; RP-F; review SECURITY audit; treat servers as possibly compromised (RP-A as indicated). |
| **C-21 Authentication Service (auth provider)** | Issue tokens for any staff user; bypass MFA. | Staff metadata. **Not** content: case keys require member hardware tokens on Desk. | Server-side authorization (metadata, workflow actions); cannot decrypt. | Token audience/issuer checks; Desk requires hardware-bound key proof per sensitive action. | RP-A; rotate token signing keys; invalidate sessions; RP-F. |
| **External IdP (EE OIDC/SAML)** | Assert any staff identity to C-21. | Staff directory. | As C-21 (server access), not content. | IdP logs; hardware-key binding mismatch. | Disable federation; fall back to local WebAuthn; re-establish trust. |
| **C-22 Authorization Engine** | Grant arbitrary server-side access. | Metadata across cases/tenants. | Metadata; workflow. Content still requires keys. | Policy test suite at startup; audit anomalies. | RP-A; re-verify policy bundle signatures. |
| **C-23 Notification Service** | Send misleading notifications; learn notification timing. | Staff contact addresses; that "something needs attention" (hourly). | Phishing staff; minimal metadata. | Staff reports; mail logs. | RP-A; RP-F (SMTP creds); warn staff. |
| **C-24 Audit Log Service (logging)** | Drop, alter or fabricate events; read staff activity. | Staff actions (pseudonymous case IDs). No source-sensitive data. | Accountability loss for tampering window. | External witness checkpoint mismatch (RP-I). | RP-I; RP-A; restore from witnessed checkpoints; annotate gap. |
| **Host logging (journald/syslog)** | Read/alter system logs. | System events only (no request logs exist). | Forensics degraded. | Log forwarding integrity. | RP-A. |
| **C-25 Health/Self-test Agent + Monitor host (monitoring)** | Report false health; probe intake metrics endpoint; attempt pivot. | Bucketed counters, host health. | Detection blinded; pivot limited to metrics port. | Cross-check with Desk-side sequence monitoring; external onion probe from second vantage. | RP-A; re-verify self-test attestations. |
| **C-26 SIEM export gateway / customer SIEM** | Read allow-listed events; inject false events; (customer SIEM) correlate with corporate data. | SECURITY/SYSTEM events, bucketed counters. No source data. | Staff activity visibility to SOC; no source data. | Schema validation at gateway. | RP-A; RP-F. |
| **C-27 Backup Agent + Store** | Read/delete/alter backups; restore malicious data. | Ciphertext, allow-listed metadata, config (excluding keys). | Recoverability; metadata. | Signed manifests; restore tests. | Rebuild backup chain; verify manifests; RP-F (backup keys). |
| **C-28 Organization Recovery Quorum** (≥ k shares) | Reconstruct quorum private key. | All case keys wrapped to quorum (all cases, if enabled). | Every case of the tenant. | Offline ceremony logs; share-holder attestations; sources see escrow status. | Generate new quorum key; re-wrap all cases (Desk campaign); revoke old; RP-G; publish in key directory. |
| **C-29 HSM / PKCS#11 / TPM** | Use/extract keys it protects (at-rest keys, onion key sealing, release keys if HSM-backed). | Infrastructure keys; onion key (if sealed by that TPM). | Host at-rest data; onion impersonation. | Vendor attestation; anomaly in key usage logs. | Replace device; RP-F; RP-E if onion key sealed there. |
| **KMS (at-rest key management: LUKS/TPM, DB TDE, cloud KMS in PRIVATE-CLOUD)** | Decrypt storage media. | Only what is on media: ciphertext and allow-listed metadata (content keys are not at-rest keys — ADR-008). | Metadata. | KMS audit logs. | RP-F; re-encrypt volumes. |
| **Reverse proxy (staff path only)** | Intercept staff API traffic (mTLS terminates here in EE-HA). **There is no reverse proxy on the source path** (onion → Unix socket → C-06). | Staff tokens, allow-listed metadata in transit; case objects are E2E ciphertext. | Staff session hijack (mitigated by token binding). | Certificate pinning in Desk; anomalies. | RP-A; RP-F; invalidate sessions. |
| **Operator network (Z-CORE/Z-ADM LAN, firewalls)** | MITM internal traffic; bypass segmentation. | mTLS-protected metadata; ciphertext. | Lateral movement. | mTLS failures; NIDS. | Re-segment; RP-F. |
| **DNS (operator and public)** | Redirect C-37/mirrors/staff endpoints; intake uses no DNS. | Who resolves C-37 (visitor metadata at resolver). | Phishing of onion address via C-37 domain hijack (THR-103). | DNSSEC, CT monitoring, signed onion statements. | Restore DNS; publish incident; RP-E only if onion key also affected. |
| **Time source (NTP/NTS)** | Skew clocks. | — | SLA errors, epoch validity edge cases, audit ordering. | Multi-source disagreement alarms. | Re-sync; review epoch/SLA decisions in window. |
| **C-30 Source repository & review** | Insert malicious commits; rewrite history. | Source code (public anyway). | All future releases if undetected. | Signed commits, two-person review, reproducible release diffs. | RP-H; audit history from signed mirrors. |
| **C-31 CI + builders (build runner)** | Produce malicious artifacts from one builder. | CI secrets (short-lived). | None if other builder independent (outputs mismatch). | Reproducibility mismatch blocks signing. | Rebuild builder from scratch; RP-H if any artifact signed. |
| **C-32 Release signing + TUF + transparency log** (threshold of keys) | Sign malicious updates. | — | All instances. | Transparency monitors; reproducibility checks by third parties. | RP-H (root rotation with offline keys); advisory; forensic comparison. |
| **C-33 Package/update mirror (package repo, update server)** | Serve stale/withheld/malicious artifacts; observe update fetches. | Fetch timing (over tor for intake; opaque for others). | DoS/freeze only (signatures enforced; update infra separate from signing, REQ-H-49). | TUF expiry/freeze detection. | Switch mirror; rebuild mirror. |
| **C-34 Enterprise Fleet Manager (enterprise mgmt server)** | Read fleet status; attempt config pushes. | Opaque instance IDs, versions, health; no onion addresses in cleartext, no content, no keys. | Non-trust-path config proposals (require local approval). | Local approval prompts; audit. | Disconnect fleet; rotate fleet credentials; review applied changes. |
| **C-35 Licensing service (licensing infra)** | Issue/revoke licenses. | Customer contract data; no instance identity required (offline files). | EE module availability only (PRD-004). | License validation errors. | Re-issue licenses; no security impact on trust path. |
| **C-36 Vendor support infrastructure** | Read support tickets and bundles. | Scrubbed bundles (versions, config classes, errors); customer contact info. | Customer metadata; social-engineering material. | Vendor security monitoring. | Notify customers; rotate any credentials inadvertently shared; review bundle scrub schema. |
| **C-37 Clearnet Information Site** | Replace onion address (phishing), inject scripts, log visitors. | Visitor IPs of the info site. | Sources directed to fake portal (Tier W at risk; Tier V verifies channel keys). | Signed onion statement mismatch detected by Source App/monitors; external integrity monitoring. | Restore site; publish signed notice; RP-E not needed unless onion key affected. |
| **C-38 Confidential Clearnet Intake** | Read submissions in transit (TLS terminated here), log IPs. | CONFIDENTIAL sources' IPs and plaintext. | C-38 users during window. | Integrity monitoring. | RP-A, RP-B for channels reachable via C-38, RP-G incl. notice to C-38 users. |
| **C-39 Hypervisor** | Read guest memory/disks, snapshot, inject code. | Everything on guests: Tier W plaintext in C-07, onion key, at-rest keys in memory. | All VMs on host (CE-SINGLE: intake and core together). | Measured boot/attestation; unusual snapshot activity. | Treat all guests as compromised: RP-A on new hardware, RP-E, RP-B, RP-F, RP-G. |
| **C-39 Physical server / storage hardware** | Firmware implants, DMA, cold boot. | As hypervisor. | All data processed on that server. | Measured boot mismatch; tamper seals. | Replace hardware; as hypervisor. |
| **C-40 Integration Connectors** | Leak Export Packages already sent; inject data into external systems. | Export Package content (what humans exported). | Exported material only. | Connector audit. | Revoke connector credentials; notify recipients of packages. |
| **Mail relay / chat provider (notification sink)** | Read notifications. | "Action requires attention" + instance label, hourly timing. | Negligible. | — | Rotate SMTP creds. |

## 13. Requirements (threat-model obligations)

These rows state obligations that keep this threat model effective and traceable. Mitigation requirements themselves are owned by the documents referenced in §9 (prefixes per DECISIONS §3). Because DECISIONS §3 assigns this document only `THR-`/`ADV-`, obligations use the reserved range **THR-900..THR-999**, which SHALL never be used for threats (see Open Issues OI-02).

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| THR-900 | This threat model SHALL be reviewed and re-issued at every minor release, and within 30 days of any new ADR, new component, Candor security incident, or publication of a relevant attack (e.g., new WF/correlation result). | INC-35; B-AN-57; DECISIONS §6 | THR-003; THR-024 | C-30 | INSP: release checklist item; version history of this file |
| THR-901 | Every threat THR-001..THR-048 and THR-100..THR-125 SHALL map to ≥ 1 mitigating requirement and ≥ 1 verification in `39-REQUIREMENTS-TRACEABILITY.md`; unmapped threats SHALL block release. | DECISIONS §1 | THR-001..THR-048; THR-100..THR-125 | C-30 | TST: traceability parser job `thr-coverage` fails on unmapped THR IDs |
| THR-902 | Every component in DECISIONS §4 SHALL have a compromise-analysis row in §12; adding a component without a row SHALL block the ADR. | ADR-028; B-SD-22 | THR-014; THR-035 | C-30 | TST: parser compares §12 component IDs with DECISIONS §4 |
| THR-903 | The malicious-server test harness (ADR-027) SHALL implement the capabilities of ADV-04 and ADV-05 against C-03 and C-15: altered HTML/bundles, forged rosters and epoch keys, replayed/dropped/reordered envelopes and replies, path-injection names, oversized fields. | ADR-027; B-SD-28; B-SD-33; B-SD-35; INC-62; INC-66 | THR-007; THR-046; THR-101; THR-102 | C-03; C-15 | TST: harness suite in `29` covers each listed capability |
| THR-904 | The cryptographic protocol models (Tamarin/ProVerif) SHALL include adversary capabilities of ADV-04 (intake/core control), ADV-13 (network), and compromise of one case member, and SHALL prove secrecy of envelope content (Tier V) and authenticity of roster changes. | ADR-006; B-SD-38; B-SD-39; INC-63 | THR-012; THR-046; THR-102 | C-11 | AUD: formal-model review before 1.0 |
| THR-905 | Attack trees TREE-1..TREE-7 SHALL be exercised by an independent red team before 1.0 and annually thereafter, with results feeding residual ratings. | B-GL-19; B-SD-40 | THR-018; THR-019; THR-023; THR-025 | C-05; C-10; C-15 | AUD: red-team scope in `37` |
| THR-906 | Every abuse case ABUSE-01..ABUSE-16 SHALL have an automated negative test or, where not automatable, a documented procedural control with an inspection record. | INC-22; INC-68; INC-70 | THR-016; THR-020; THR-039; THR-046 | C-10; C-15; C-19 | TST: negative-test IDs listed in `29`; INSP: procedure records |
| THR-907 | Each recovery primitive RP-A..RP-I and each §12 recovery procedure SHALL be exercised in a tabletop exercise at least annually, and RP-A, RP-B, RP-E in a live drill on a staging instance before 1.0. | INC-55; INC-58 | THR-014; THR-044; THR-042 | C-05; C-15; C-27 | DEMO: drill reports (`31`) |
| THR-908 | A plain-language "What Candor protects against — and what it does not" statement derived from §6 residual risks SHALL be published on the onion landing page and C-37, and reviewed against this document at every release. | DECISIONS §0; INC-12 | THR-040 | C-06; C-37 | INSP: release review; TST: page presence |
| THR-909 | Deployments SHALL NOT be declared production-ready unless at least two independent parties are registered as transparency-log monitors for release and key-directory logs, and Candor Desk and the Source App gossip signed tree heads they observe. | INC-14; INC-15; B-CR-42 | THR-118; THR-025; THR-046; THR-102 | C-14; C-32; C-03; C-15 | DEMO: monitor registry; TST: gossip consistency test |
| THR-910 | Residual risks rated High or Critical in §9 SHALL each be listed in the operator security guide with the operator actions that reduce them (e.g., Tier V for high-risk channels, AIRGAP-RCP). | DECISIONS §0 | THR-003; THR-007; THR-014; THR-041 | C-19 | INSP: operator guide review |
| THR-911 | Operators SHALL be able to configure a channel to **require Tier V** (Tier W submissions refused with guidance), and the admin console SHALL recommend this for channels designated high-risk. | ADR-004; INC-01 | THR-007; THR-014; THR-026 | C-06; C-19 | TST: channel-policy test rejects Tier W submissions |
| THR-912 | For the HIGH timing profile, C-09 SHALL import envelopes into Z-CORE once per UTC day at a uniformly random time, so that import timing carries no information finer than the day. | ADR-010; INC-16; B-AN-21 | THR-011 | C-09 | TST: scheduler distribution test |

## 14. Residual risks and limitations

| # | Residual risk | Rating | Why it remains | Honest statement to users |
|---|---|---|---|---|
| R-01 | Source identified by content, knowledge, style, watermarks | High | Inherent in disclosure | "What you write and upload can identify you. Candor cannot remove that." |
| R-02 | Source identified via employer/ISP observation of Tor use + timing | High (if guidance ignored) | Tor use is observable (THR-002) | "Do not use your work device or network." |
| R-03 | Tier W plaintext exposure to a live-compromised or compelled intake | High | ADR-004 design limit | Tier W statement; Tier V recommended |
| R-04 | Global/end-to-end network adversary correlation | High for targeted sources | Out of design envelope (NG-03) | "Tor does not protect against an adversary who can watch both ends." |
| R-05 | Authorized recipient discloses or retaliates | Medium–High | Authorized access cannot be cryptographically constrained | Oversight, audit, independent channels |
| R-06 | Recipient endpoint compromise | Medium | Endpoints are complex | Hardware tokens, containment, AIRGAP-RCP |
| R-07 | Coercion of multiple custodians/quorum holders/staff | Medium | Human factors | Multi-party controls; visible escrow status |
| R-08 | Transparency without monitors | Medium | Ecosystem dependency | THR-909 gating |
| R-09 | Investigation actions reveal the source | Medium–High | Process, not technology | Investigator guidance |
| R-10 | Hypervisor/physical compromise of intake host | Medium | Substrate trust | Dedicated hardware, measured boot |
| R-11 | Zero-day in Tor Browser layout engine at Safest | Low–Medium | Third-party software | Tails, patch promptly |

## 15. Open issues

| # | Issue | Proposed resolution |
|---|---|---|
| OI-01 | ASM identifiers: this document uses descriptive tags `[A:…]`; `40-SECURITY-ASSUMPTIONS.md` must assign ASM IDs and back-reference. | Owner of `40` to map each tag to an ASM ID; this document to be updated in v1.1. |
| OI-02 | **Open Issue for ADR revision:** DECISIONS §3 gives this document the `THR-`/`ADV-` prefixes only; threat-model obligations are therefore placed in THR-900..999. Mixing threats and requirements in one namespace may confuse the traceability parser. | Propose a new prefix `TM-` for threat-model obligations via an ADR amendment; until then THR-9xx are requirements, never threats. |
| OI-03 | **Open Issue for ADR revision:** DECISIONS does not fix the staff transport (internal mTLS vs restricted-discovery onion) or sealer remote attestation to Desk; this model assumes both are available (§5.2 TB-08, §12 C-06/C-07 detection). | `06-SYSTEM-ARCHITECTURE.md` to decide; recommend an ADR "Staff access path and sealer attestation". |
| OI-04 | **Open Issue for ADR revision:** ADR-009 fixes relay pull at 15±10 min and ADR-010 records batch time; combined, a party holding intake + core records can bound arrival to ≈ 25 min. THR-912 adds a daily-random import mode for HIGH profile. | Amend ADR-010 to state that import timestamps persisted in Z-CORE are day-granular and to adopt the HIGH-profile daily import. |
| OI-05 | Tier W HTML-only capture (TREE-4 4.1.1) cannot be prevented even at Safest; only Tier V addresses it. | THR-911 lets operators require Tier V per channel; product decision for defaults in `01`. |
| OI-06 | Confidential VMs (SEV-SNP/TDX) for PRIVATE-CLOUD are listed as optional hardening; their attestation and side-channel record needs evaluation. | `17-INFRASTRUCTURE.md` to evaluate. |
| OI-07 | Research gaps flagged UNVERIFIED in R4 (Arti onion-service production status, vanguards add-on maintenance, current Tor Metrics) affect residual ratings for THR-003/005. | Re-rate after R4 follow-up (R4 §8). |
