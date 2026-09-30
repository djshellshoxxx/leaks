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
