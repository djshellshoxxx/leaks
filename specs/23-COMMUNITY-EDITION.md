# 23 — Community Edition (CE) and Small Business Secure Profile
Status: Draft v1.1 (revision round 2: ADR-034..046) · Edition applicability: CE (parity statements cover EE) · Owner: Core Product team

## 1. Purpose and scope

This document gives the precise feature definition of the Community Edition (CE):
- AGPL-3.0-or-later;
- self-hosted;
- one organization with multiple channels (DECISIONS §2).

CE is a **complete, production product**. It is not a demo:
- it carries every anonymity, cryptographic and logging-suppression protection that EE has;
- it carries every feature that protects sources in a single-organization deployment (Charter test T2, see `21-ENTERPRISE.md` §3).

This document also defines the **Small Business Secure Profile (SMB)**. SMB is a packaging of CE for organizations without security staff. It simplifies operation **without weakening anonymity**.

## 2. Context and dependencies

| Topic | Document |
|---|---|
| Binding decisions | `DECISIONS.md` §2, ADR-001..046 (ADR-034..046 supersede conflicting earlier text) |
| EE feature boundary | `21-ENTERPRISE.md` |
| Licensing and Edition Charter | `24-LICENSING-BUSINESS-MODEL.md` |
| Profiles CE-SINGLE and CE-HARDENED | `18-DEPLOYMENT.md` |
| Updates | `33-RELEASE-UPDATE-SECURITY.md` |
| Backups | `19-BACKUPS-DR.md` |
| Case lifecycle and COI | `14-CASE-MANAGEMENT.md` |
| Retention and legal hold | `35-DATA-RETENTION-DELETION.md` |
| Accessibility and localization | `26-ACCESSIBILITY.md` |
| Admin UI and health dashboard | `13-FRONTEND-ADMIN.md` |
| Configuration classes | `32-OPERATIONS.md` |

## 3. CE feature specification

| # | Feature | CE content (normative summary; detail in owning doc) | Owning doc |
|---|---|---|---|
| F01 | Anonymous reporting over Tor | Tor v3 onion service with PoW and vanguards-lite (ADR-001). No clearnet fallback (ADR-002). Tier W no-JS and Tier V Source App (ADR-004); Tier W drafts only in Sealer RAM, 20 min idle / 2 h absolute (ADR-034). 10-word passphrase, Argon2id m=64 MiB (ADR-005, ADR-046(7)). Optional source delayed delivery (ADR-038(4)). | 16, 11, 05 |
| F02 | Encrypted reports and attachments | HPKE X-Wing channel epoch keys (ADR-006/008). STREAM 64 KiB chunks. Padding (ADR-011). Recipient keys on endpoints (ADR-007). | 04, 10 |
| F03 | Two-way communication | Source mailbox via passphrase. Replies shown at next login. Tier V retrieves replies by fetch-all dead-drop (ADR-039). Day-granular dates (ISO week in HIGH). No receipts or presence (ADR-010, ADR-038(3)). | 11, 12 |
| F04 | Recipients | Candor Desk (C-15). Hardware-wrapped keys (FIDO2 PRF, PIV/smart card, TPM; software fallback with warning). Local WebAuthn accounts. | 12, 15 |
| F05 | Case management | ISO 37002 lifecycle (receive → assess → address → conclude). Tasks. Notes. Detriment-risk assessment. Retaliation check-ins. SLA engine with calendar/business days and holiday calendars (R6 WB-04..06, WB-23). | 14 |
| F06 | Metadata minimization | Day-granular timestamps. No IP, UA or circuit logging. Attachments never parsed on servers (ADR-010, -012, -016). Relay imports at fixed slots, never event-driven (ADR-038(1)). | 03 |
| F07 | Secure deletion | Crypto-erasure plus best-effort physical deletion, with documented limits (ADR-025). | 35 |
| F08 | Basic audit | Hash-chained, signed checkpoints. Four classes. `candorctl audit verify`. Local scrubbed JSONL export of SECURITY and SYSTEM events (ADR-016). | 20 |
| F09 | Basic workflow | Fixed lifecycle states. Assignment. Templates. Acknowledgement and feedback timers (EU 7-day / 3-month defaults, B-CO-02). | 14 |
| F10 | Localization | Source and staff UI i18n. RTL. EN/FR parity pack. Community translations. | 26 |
| F11 | Accessibility | WCAG 2.2 AA target. No CAPTCHA. Save-and-resume within one session only (Tier W drafts live in Sealer RAM, ADR-034). Works in Tor Browser "Safest" (B-CO-28, R6 C). | 26 |
| F12 | Backups | Encrypted to an offline k-of-n key. Case content already end-to-end encrypted. Restore test (REQ-H-55). | 19 |
| F13 | Documented upgrades | Upgrade guide per release. N-1→N migration tested. Rollback procedure. | 33 |
| F14 | Secure deployment | CE-SINGLE and CE-HARDENED profiles. Secret Placement Manifest verification (ADR-028). Pinned-key installer (R2 R-INST-01). | 18 |
| F15 | Security updates | TUF, threshold-signed, reproducible, transparency-logged, identical for all (ADR-022). Fixes released at the same moment as EE (ADR-020). | 33 |
| F16 | **COI routing basics** | Triage-first routing: envelopes wrapped only to the channel's Triage Set of ≥ 2 independent-role members after source COI ticks (ADR-037(1)); blinded COI tags (ADR-037(3)); fail-closed redirect to an alternative independent channel. Channels routing to independent bodies. COI map. Category rule for accounting/audit matters going to the audit committee (SOX §301, B-CO-69). Break-glass with dual authorization including an independent-role approver (ADR-015, ADR-045). | 14, 15 |
| F17 | **Legal hold (basic)** | Per-case hold and sealed-matter flag. Blocks disposition. Restricts circulation. Reason code. Dual approval. 90-day review reminder (R6 WB-36). | 35 |
| F18 | Sealed Identity Store | Identity encrypted to custodians. Unseal requires legal basis, dual approval and a reporter notice (ADR-014). | 14, 04 |
| F19 | Recovery Quorum (optional) | k-of-n, off by default in CE, published to sources (ADR-013). (GOV profile enables it by default, ADR-044(3).) | 04 |
| F20 | Evidence handling | Immutable original plus sanitized derivative. Hashes. Custody records. C-17 containment (ADR-012). | 10 |
| F21 | Redaction and Export Packages | Human-created, redaction-reviewed. Dual approval for originals (ADR-018). | 10, 14 |
| F22 | Basic reporting | KPI dashboard under the single metrics regime of `24-LICENSING-BUSINESS-MODEL.md` §TEL (ADR-046(5)). | 14, 24 |
| F23 | DSAR restriction workflow | Restriction reason codes. Deferred-notice timers (R6 WB-15). | 14 |
| F24 | Notifications | Content-free, **constant-schedule** daily digest at a fixed time to each subscribed member whether or not anything is pending, or disabled (HIGH default); SMTP or webhook (ADR-017, ADR-038(2)). | 20 |
| F25 | Staff authentication | WebAuthn/FIDO2 phishing-resistant by default. PIV/smart card supported (B-CO-41). | 15 |
| F26 | HSM/TPM | TPM 2.0 sealing by default. PKCS#11 integration available (unsupported without EE). | 17 |
| F27 | FIPS build profile | Source and build recipe public. Unsupported and without evidence package in CE. | 04 |
| F28 | Compliance pack loader | Open pack schema. Starter packs: EU Directive generic, SOX §301 generic, PSDPA generic (CC BY 4.0). | 25 |
| F29 | Clearnet Information Site | Static generator. Onion-Location. No submission form (C-37). Does not host the Source App or log downloads; links to the project distribution (ADR-041). | 18 |
| F30 | Confidential Clearnet Intake | Off by default. Separately branded NOT ANONYMOUS (C-38, ADR-002). | 11 |
| F31 | Telemetry | None from sources. Instance telemetry OFF by default and opt-in, using the fixed schema (ADR-023). | 24 |
| F32 | Multiple channels | Unlimited channels per organization. Each has its own keys and onion service option. | 06 |
| F33 | Intake integrity evidence | Published digests of static source-UI assets and templates; Sealer signed running manifest; support for External Watchers (recommended in CE; ADR-035(1)); quorum-signed Operator Statement every 30 days with source-visible warning on lapse (ADR-035(2)); optional confidential-VM Sealer (ADR-035(3)); independent approval for intake capture during IR (ADR-035(4)). | 06, 11, 31 |
| F34 | Key Directory governance | CIK held only by Triage Set and OVERSIGHT; 72 h time-lock for roster additions, role-label changes and COI loosening; follow-up sealing rule; snapshot high-water mark and independent time; weekly publication slot; external witness cosignatures recommended in CE (ADR-036). | 04, 14 |
| F35 | Recipient device custody | `desk-preflight` checks (same code as EE ENT-034); independent-custody devices required for INDEPENDENT channels (ADR-043); Desk self-verifies its binary against the transparency log. | 12 |
| F36 | Key-access continuity | Automation can only suspend; wrap deletion needs dual control, 7-day cooling-off and OVERSIGHT notice; `min_recipients` = 2; ≥ 2 authenticators per member (ADR-044(1)(2)). Erasure Key Vault excluded from infrastructure backups (ADR-044(4)). | 04, 14, 19 |
| F37 | Records-search support | Desk-local search over cases the member can decrypt; Records Custodian grants from the Triage Set; no server-side global search (ADR-044(5)). | 12, 35 |
| F38 | Platform integrity | Pinned snapshot mirror, TUF-signed Platform Manifest verified by self-test, signed security floor (ADR-040); Z-INTAKE updates via the project onion mirror over Tor, Z-CORE via an egress-restricted HTTPS mirror (ADR-046(3)). | 28, 33 |
| F39 | Small-organisation mode | External OVERSIGHT party, "reduced separation of duties" disclosure (ADR-045); see §4.4. | 23 |

All protections introduced by ADR-034..ADR-046 are CE features (Charter test T1/T2, `21-ENTERPRISE.md` §3); none is gated by an EE entitlement.

CE does **not** include the EE items listed in `21-ENTERPRISE.md` §4, classes S and V:
- HA orchestration;
- multi-tenancy;
- Fleet Manager;
- SSO/SCIM;
- advanced workflow designer and rule engine;
- advanced retention, holds, evidence, reporting and audit exports;
- SIEM connectors;
- records connectors;
- policy management;
- certified compliance packs;
- vendor services.

## 4. Small Business Secure Profile (SMB)

### 4.1 Target and constraints

- **Target:** organizations of 50–500 workers subject to EU Art 8(3) or similar (B-CO-02), with 1–3 designated recipients and no in-house security team.
- **Constraint:** SMB **SHALL NOT** relax any anonymity, crypto or logging default. It changes how defaults are *delivered and operated*, not what they are. Separation of duties is **not** a configuration default the checker can see (RVW-C-09); where the organisation cannot staff it, SMB states the reduction honestly and adds an external party (§4.4).
- **Operator realism:** the organisation needs a named competent operator for the `18-DEPLOYMENT.md` operational load budget. Where it has none, MANAGED by an independent operator or a consortium instance is the recommended path (RVW-C-17).

### 4.2 Components

| Component | Specification |
|---|---|
| **Simple installer** `candor-setup` | Interactive TUI. Also a headless YAML mode. It: (1) verifies the release signature against the fingerprint printed in the docs and in the transparency log (no TOFU, R2 R-INST-01); (2) detects the host (supported: Debian 13 on a physical host or the reference appliance VM image); (3) creates VMs for Z-INTAKE and Z-CORE on one host (CE-SINGLE) or configures two hosts (CE-HARDENED, recommended); (4) generates the onion key locally; (5) enrols a second, distinct admin or the external co-signer (§4.4) before go-live, and runs the channel ceremony with a Triage Set of ≥ 2 members' Desks, each with ≥ 2 hardware authenticators; (6) runs the config checker; (7) prints the onion address and a QR code for the information site. Target completion ≤ 60 min for a non-specialist (DEMO). |
| **Secure defaults** | ANONYMOUS channel. Tor-only. Tier W and Tier V enabled. Clearnet intake off. Recovery Quorum off. Telemetry off. Update paths per ADR-046(3). Imports at fixed slots (4×/day). Content-free constant-schedule daily digest. Retention 365 days after closure. Metrics per `24-LICENSING-BUSINESS-MODEL.md` §TEL. CE-SINGLE isolation = VMs (container-only is ADVANCED, ADR-046(6)). |
| **Minimal admin** | Admin tasks reduced to: add/remove recipient, rotate recipients' devices, view health, apply updates (automatic), run backup, run restore test. All via the Desk admin mode. No web admin (ADR-007). |
| **Automatic signed updates** | Unattended TUF updates on by default. Security releases apply within 24 h. Feature releases apply in the weekly maintenance window (default Sunday 03:00 local, ±60 min random). Kernel updates use the distribution-signed shim/kernels, so no offline per-kernel signing ceremony blocks them (ADR-040; resolves the RVW-C-17 contradiction). Intake is restarted with the outage page shown. Automatic rollback if post-update self-test fails. Z-INTAKE fetches via the project onion mirror over Tor; Z-CORE via an egress-restricted HTTPS mirror (ADR-046(3)). No instance identifier is sent (ADR-022). Trust-path components refuse to start below the signed security floor (ADR-040). |
| **Backup wizard** | Generates the backup key k-of-n (default 2-of-3 for SMB) on 3 hardware tokens or printed Shamir cards. Schedules a nightly encrypted backup to a local disk or customer S3-compatible target. Prompts a quarterly restore test on a spare VM. The wizard refuses to complete until the first test restore of a synthetic canary case succeeds. |
| **Config checker** `candorctl check` | Runs at install, after every update, daily, and on demand. Checks: Secret Placement Manifest (ADR-028); clearnet listeners; Tor, web-server and access logs disabled; core dumps disabled; swap encrypted or off; NTP sources; disk encryption; TUF metadata freshness; certificate expiry; ≥2 key holders per active case; recipients using the software-fallback wrapping; dangerous-config inventory; backup age and last restore test; channel epoch key pre-generation horizon (≥ 3 epochs ahead); Platform Manifest and security floor (ADR-040); Operator Statement freshness (≤ 30 days); Triage Set size ≥ 2 per channel and ≥ 2 authenticators per member; Erasure Key Vault backup-exclusion attestation on virtualized hosts (ADR-044(4)); independent-custody status for INDEPENDENT channels (ADR-043); count of distinct enrolled persons (small-organisation mode trigger, §4.4). Output: pass/warn/fail with remediation text. It never includes case data. |
| **Security health dashboard** | In Desk admin mode (not a web page). Traffic-light tiles for each checker category. Update status. Days since last restore test. Onion service reachability (synthetic probe). Pending dual approvals and time-locked roster changes. Only global daily health bands for intake (ADR-038(5)); aggregate counts follow `24-LICENSING-BUSINESS-MODEL.md` §TEL. No per-case or per-source information. |

### 4.3 SMB-specific decisions

| Question | Decision | Rationale |
|---|---|---|
| Single recipient allowed? | **No** (changed in revision round 2). `min_recipients` = 2 and the Triage Set needs ≥ 2 members (ADR-044(2), ADR-037(1)). Where the organisation has only one internal recipient, the second is an external party (external counsel, ombudsperson, board member) who also serves as OVERSIGHT (§4.4). | Single-holder channels let one reimage destroy access (suppression, RVW-C-03) and cannot satisfy triage-first routing. |
| COI exhaustion? | If the source's COI ticks exclude every Triage Set member, the source is shown the alternative independent channel (ADR-037(1)). SMB requires ≥ 1 external recipient on every ANONYMOUS channel so this path exists (RVW-C-18). | Availability of a lawful channel (EU Art 8/9). |
| VPS or public cloud? | Allowed only under PRIVATE-CLOUD with a provider-observer disclosure screen (THR-030). The appliance on an owned host is recommended. | ADR-024 |
| Tier W only? | No. Tier V download instructions are always shown on the landing page. | ADR-004 |
| Software-fallback recipient keys? | Allowed with a persistent warning in the dashboard. Two FIDO2 keys per recipient are recommended (≈ low-cost hardware). | ADR-007 |
| Email notifications via a cloud mail provider? | Allowed, because the content is fixed and the schedule is constant (ADR-017, ADR-038(2)); the provider sees one identical message per day per subscribed member. | INC-57; RVW-A-19 |

### 4.4 Small-organisation mode (ADR-045; RVW-C-09)

Trigger: fewer than 4 distinct enrolled natural persons (distinctness per `15-AUTHENTICATION-AUTHORIZATION.md` person binding; accounts sharing an authenticator identity count as one person). The checker enforces the mode; it cannot be switched off while the trigger holds.

| Dual control that needs distinct persons | In small-organisation mode |
|---|---|
| OVERSIGHT (and its independent approvals: break-glass, roster, COI loosening, IR capture) | Held by ≥ 1 **external party** (external counsel, statutory auditor, board member or a certified ombuds service); mandatory (ADR-045) |
| Second USER_ADMIN / second key-admin for roster additions | The external party acts as second approver and performs the out-of-band identity check |
| Recovery/backup quorum shares (IRK, backup k-of-n) | ≥ 1 share with the external party, so no internal person holds k |
| H-MON admin ≠ SYS_ADMIN | Not achievable in CE-SINGLE; stated honestly (below) |
| Identity Custodian ≠ Channel Owner | External party may hold the second custodian role; otherwise the Sealed Identity Store is disabled and CONFIDENTIAL intake is off |

Disclosure: admins see "Separation of duties: reduced" in the dashboard; the published Operator Statement and the source landing page configuration digest carry the same text (ADR-045).

Honest limits: in CE-SINGLE (and in small-organisation mode generally) a malicious SYS_ADMIN is **not detectable** by Candor's own attestation, because the monitor runs on the same hypervisor or is administered by the same person. High-risk sources are advised to use Tier V only; External Watchers (ADR-035(1)) are the only independent check.

## 5. Parity table: CE vs EE

"Security-equivalent?" asks whether a CE source faces **the same confidentiality and anonymity protection** as an EE source for the same threat. "No" entries state which property differs.

| Capability | CE | EE | Security-equivalent? |
|---|---|---|---|
| Onion-only anonymous intake, PoW, vanguards | ✓ | ✓ | Yes |
| Tier W / Tier V clients | ✓ | ✓ | Yes |
| Crypto suite CANDOR-STD-1 | ✓ | ✓ | Yes |
| CANDOR-FIPS-1 | Source + recipe (unsupported) | Supported with evidence | Yes (algorithms identical). Assurance evidence differs. |
| Recipient keys on endpoints; hardware wrapping | ✓ | ✓ | Yes |
| Metadata minimization, padding, no IP logging | ✓ | ✓ | Yes |
| Logging allow-list / scrubbing | ✓ | ✓ (same code) | Yes |
| Sealed Identity Store, unseal workflow | ✓ | ✓ | Yes |
| Basic COI routing, source-flag exclusions, break-glass | ✓ | ✓ plus advanced rule engine | Yes for COI protection. EE adds routing convenience; COI invariant identical (ENT-003). |
| Triage-first routing, blinded COI tags | ✓ | ✓ (EE rule sets evaluated in the same AGPL Desk evaluator) | Yes (ADR-037) |
| Tier W RAM-only drafts; fetch-all reply retrieval (Tier V); delayed delivery | ✓ | ✓ | Yes (ADR-034, ADR-039, ADR-038(4)) |
| Published asset digests, Sealer running manifest, External Watcher support | ✓ (watchers recommended) | ✓ (≥ 2 watchers required for EE/GOV/MANAGED) | Yes for the mechanism. EE/GOV deployments are required to be watched; a CE instance is only as watched as its operator arranges (`36-OPEN-SOURCE-GOVERNANCE.md` registry is open to CE). |
| Operator Statement (quorum-signed, 30 days) | ✓ | ✓ | Yes (ADR-035(2)) |
| Key Directory governance (time-locks, high-water mark, weekly slot) | ✓ (witness cosignatures recommended) | ✓ (≥ 2 external witnesses required) | Yes for the mechanism; witness requirement differs as in ADR-036(5). |
| Confidential-VM Sealer option | ✓ (code and docs) | ✓ plus supported hardware list | Yes (ADR-035(3)) |
| Fixed-slot imports, constant-schedule notifications | ✓ | ✓ | Yes (ADR-038) |
| `desk-preflight`, independent custody for INDEPENDENT channels | ✓ | ✓ plus maintained catalogue support | Yes (ADR-043) |
| Key-access continuity rules, `min_recipients` = 2 | ✓ | ✓ | Yes (ADR-044) |
| Platform Manifest, security floor | ✓ | ✓ | Yes (ADR-040) |
| Small-organisation mode | ✓ | ✓ | Yes (ADR-045) |
| Legal hold (per case, sealed matter) | ✓ | ✓ plus matter-level holds | Yes |
| Crypto-erasure deletion | ✓ | ✓ | Yes |
| Retention engine | Per channel | Plus schedule import, disposition review | Yes. EE adds records-law tooling. |
| Audit log (hash-chained, signed) | ✓ | ✓ plus WORM and scheduled exports | Yes for integrity. Tamper *detection* latency may be lower in EE with external WORM anchoring. CE can anchor to an external witness manually. |
| SIEM integration | Local scrubbed export only | Connectors (C-26) | **No for detection capability** (EE shortens detection). Confidentiality same. |
| HA / clustering / DR automation | No (single node, manual DR) | ✓ | **No for availability.** Confidentiality same. Anonymous path fails closed in both. |
| Multi-tenancy | No (single org) | ✓ | N/A. CE avoids co-residency entirely. |
| SSO / SCIM | No (local WebAuthn) | ✓ | Yes. WebAuthn is phishing-resistant. SSO adds an IdP observer in EE. |
| PIV/CAC | Smart-card wrapping ✓ | Plus FPKI policy | Yes |
| HSM / PKCS#11 | TPM default; PKCS#11 code present | Supported HSM configurations | Yes for content (the HSM never holds content keys). EE hardens server signing keys. |
| Fleet Manager | No | ✓ | N/A |
| Notifications content-free, constant schedule | ✓ | ✓ plus Teams (same schedule, ENT-035) | Yes |
| Evidence containment (C-17) | ✓ | ✓ plus bundles | Yes |
| Reporting under the 24 §TEL regime | ✓ | ✓ plus regulator exports | Yes |
| Automatic signed updates | ✓ | ✓ (plus LTS) | Yes (same artifacts). LTS changes cadence, not protection. |
| Security fix timing | Same moment | Same moment | Yes (ENT-030) |
| Vendor support / SLAs | Community | Contract | N/A (no protection effect) |
| Telemetry | Off, opt-in schema | Off, opt-in schema | Yes |

## 6. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| CE-001 | CE SHALL include every Trust Path component and every protection listed in §3 F01–F39, including every protection introduced by ADR-034..ADR-046. A release SHALL fail if any CE build lacks a protection present in EE. | ADR-020; ADR-034..ADR-046; B-CO-60 | THR-024 | C-30, C-31 | TST: edition feature-parity test comparing protection manifests (manifest lists each ADR-034..046 protection); AUD |
| CE-002 | CE and EE SHALL build Trust Path binaries from the same source tree and same reproducible recipe. The Trust Path artifact hashes SHALL be identical across editions. | ADR-022; REQ-H-14 | THR-024, THR-025 | C-31, C-32 | TST: cross-edition hash comparison |
| CE-003 | CE SHALL support unlimited channels in one organization, each with its own channel keys and optional separate onion service. | ADR-008 | THR-045 | C-10, C-05 | TST |
| CE-004 | CE SHALL implement COI routing basics: triage-first wrapping to a Triage Set of ≥ 2 independent-role members, source-flagged role exclusions, blinded COI tags, the COI map, fail-closed redirect to an alternative independent channel, category→audit-committee rules and break-glass with dual authorization including an independent-role approver. | ADR-015; ADR-037; ADR-045; INC-22; B-CO-69 | THR-020 | C-22, C-10, C-15 | TST: COI test suite (shared with EE) incl. excluded-member inference test (30) |
| CE-005 | CE SHALL implement per-case legal hold and the sealed-matter flag, with dual approval, reason codes and a 90-day review reminder. | B-CO-15; R6 WB-36 | THR-017, THR-037 | C-10 | TST |
| CE-006 | CE SHALL implement the SLA engine with calendar and business-day modes, holiday calendars, and pause/extension with justification. | B-CO-02; B-CO-24 | — | C-10 | TST: clock fixture suite (EU 7d/3m; AB 5/10/120 bd) |
| CE-007 | CE SHALL implement the Sealed Identity Store and unseal workflow identical to EE. | ADR-014; B-CO-13 | THR-018, THR-019 | C-10, C-15 | TST (shared suite) |
| CE-008 | CE SHALL provide a local scrubbed JSONL export of SECURITY and SYSTEM events produced by the same allow-list code as C-26. | ADR-016; INC-60 | THR-016 | C-24 | TST: canary scrub test |
| CE-009 | CE SHALL provide KPI reporting under the single metrics regime of `24-LICENSING-BUSINESS-MODEL.md` §TEL (ADR-046(5)), reading parameters from the shared constants registry. | INC-74; INC-70; ADR-046(5); RVW-B-08 | THR-039 | C-10 | TST; TST: spec-constant lint (27 SG-25) |
| CE-010 | CE documentation SHALL state, for every EE-only capability, whether its absence changes source protection, using the §5 table. | Design | THR-040 | C-30 | INSP |
| CE-011 | CE SHALL provide a supported release window: each minor release receives security fixes until 90 days after the next minor release. Majors overlap by ≥ 180 days. | B-CR-50 | THR-025 | C-32 | INSP: release calendar |
| CE-012 | CE upgrade guides SHALL be published with each release and tested N-1→N in CI. | Design | THR-042 | C-31 | TST: upgrade job |
| CE-013 | CE SHALL NOT contain license checks, feature-unlock keys or network calls to vendor services. | ADR-023; C-35 | THR-036 | all CE | TST: network egress test; INSP |
| CE-014 | CE compliance-pack loader and starter packs (EU, SOX, PSDPA generic) SHALL be included and licensed CC BY 4.0. | B-CO-02; B-CO-69; B-CO-19 | — | C-10 | INSP |
| CE-015 | CE SHALL include PKCS#11 and TPM integration code and the CANDOR-FIPS-1 build recipe. | ADR-006; ADR-020 | THR-013 | C-11, C-29 | TST: build job for FIPS profile |
| CE-016 | CE SHALL warn continuously in Desk admin when any active case has fewer than 2 active key holders. | ADR-013 | THR-042 | C-15, C-19 | TST |
| CE-017 | CE documentation SHALL state that CE is not CJIS-, FedRAMP- or PBMM-assessed. | B-CO-46; B-CO-43; B-CO-48 | THR-035 | C-30 | INSP |
| CE-018 | CE landing pages and Desk SHALL display the Operator Statement status and SHALL support registration with External Watchers and Key Directory witnesses from the `36-OPEN-SOURCE-GOVERNANCE.md` registry without any EE entitlement. | ADR-035(1)(2); ADR-036(5); RVW-A-01; RVW-A-08 | THR-007, THR-026, THR-046 | C-06, C-14, C-15 | TST: expired statement banner; TST: watcher/witness enrolment in CE build |
| SMB-001 | The SMB profile SHALL NOT change any default of ADR-001..ADR-046. A CI test SHALL compare the effective security configuration of SMB against CE-SINGLE and CE-HARDENED. Only the documented operational deltas (update automation, backup k=2-of-3, wizard, small-organisation mode external party) SHALL differ. | ADR-020; ADR-045 | THR-035 | C-19 | TST: `smb-config-diff` |
| SMB-002 | `candor-setup` SHALL verify release signatures against a pinned fingerprint and a transparency-log inclusion proof before installing. It SHALL NOT fetch keys by TOFU. | B-GL-41; REQ-H-48; REQ-H-52 | THR-024, THR-025 | C-19, C-32 | ST: tampered installer and substituted key |
| SMB-003 | `candor-setup` SHALL refuse to finish until every ANONYMOUS channel has a Triage Set of ≥ 2 enrolled members (≥ 1 of them external where the organisation has only one internal recipient), each with ≥ 2 hardware authenticators, and a second distinct admin or external co-signer is enrolled. The single-recipient acknowledgment path is withdrawn. | ADR-044(2); ADR-037(1); ADR-045; RVW-C-03; RVW-C-09 | THR-042, THR-020, THR-018 | C-19 | TST: setup blocks with one recipient or one admin |
| SMB-004 | SMB automatic updates SHALL apply security releases within 24 h and feature releases in a weekly window with ±60 min random offset, using distribution-signed kernels (no offline per-kernel signing, ADR-040). Z-INTAKE SHALL fetch via the project onion mirror over Tor and Z-CORE via an egress-restricted HTTPS mirror (ADR-046(3)), with no instance identifier. | ADR-022; ADR-023; ADR-040; ADR-046(3); RVW-C-17 | THR-025, THR-036 | C-33, C-19 | TST: update client network capture per zone; TST: unattended kernel update reboots without a token |
| SMB-005 | An update whose post-update self-test fails SHALL be rolled back automatically, and SHALL alert via content-free notification. | Design; INC-49 | THR-025 | C-19, C-25 | TST: fault injection |
| SMB-006 | The backup wizard SHALL generate the backup key as k-of-n (default 2-of-3). It SHALL NOT complete until a canary restore succeeds. It SHALL prompt restore tests every 90 days. | INC-55; REQ-H-55 | THR-042, THR-013 | C-27 | DEMO; TST |
| SMB-007 | `candorctl check` SHALL implement every check listed in §4.2 and SHALL run daily. A fail on a Secret Placement, clearnet-listener, logging, Platform Manifest or security-floor check SHALL alert every admin within 1 h through the constant-schedule channel's next digest and the Desk dashboard. | ADR-028; ADR-040; B-SD-22; INC-34 | THR-035, THR-016, THR-025 | C-25 | TST: each check has a positive and negative fixture |
| SMB-008 | The health dashboard SHALL show no per-case or per-source data. Intake activity SHALL appear only as the global daily health band (ADR-038(5)); counts SHALL follow the `24-LICENSING-BUSINESS-MODEL.md` §TEL regime. | INC-70; ADR-038(5); ADR-046(5); RVW-B-07 | THR-039 | C-19 | TST |
| SMB-009 | SMB SHALL present a provider-observer disclosure and require acknowledgment before installing on a VPS or public cloud. | ADR-024; INC-59 | THR-030 | C-19 | TST |
| SMB-010 | `candor-setup` guided mode SHALL be completable by a non-specialist in ≤ 60 min in usability testing (n ≥ 5, success ≥ 80%), and the SMB profile SHALL be validated in a 6-month operational pilot measuring actual person-hours against the `18-DEPLOYMENT.md` operational load budget. | Design; RVW-C-17 | — | C-19 | DEMO: usability study; DEMO: pilot report |
| SMB-011 | SMB SHALL display a persistent warning for each recipient using software-fallback key wrapping. | ADR-007 | THR-013 | C-15 | TST |
| SMB-012 | The SMB landing page template SHALL include small-organization anonymity guidance when configured population < 250. | INC-73 | THR-010 | C-06 | TST |
| SMB-013 | SMB SHALL keep channel epoch keys pre-generated ≥ 3 epochs ahead and SHALL warn at < 2. | ADR-008 | THR-032 | C-15, C-25 | TST |
| SMB-014 | When fewer than 4 distinct natural persons are enrolled, small-organisation mode (§4.4) SHALL be enforced: an external party SHALL hold OVERSIGHT and act as second approver for identity checks and roster additions, SHALL hold ≥ 1 share of each quorum so no internal person holds k, and "Separation of duties: reduced" SHALL appear in the admin dashboard, the Operator Statement and the landing-page configuration digest. | ADR-045; RVW-C-09 | THR-018, THR-020 | C-19, C-14, C-06 | TST: checker enforces mode and disclosure below 4 persons; INSP: enrolment witness record |
| SMB-015 | Every ANONYMOUS channel in SMB SHALL have ≥ 1 external recipient (ombudsperson or external counsel) in its Triage Set, and an alternative independent channel for COI exhaustion. | ADR-037(1); RVW-C-18 | THR-020, THR-032 | C-10, C-06 | TST: setup and checker block channel activation without it |
| SMB-016 | SMB documentation and the installer SHALL state that in CE-SINGLE and small-organisation mode a malicious SYS_ADMIN is not detectable by Candor's own attestation, and SHALL recommend Tier V for high-risk sources. | RVW-C-09; ADR-035(5) | THR-018, THR-040 | C-19, C-37 | INSP; TST: installer prompt |

## 7. Residual risks and limitations

- **CE-SINGLE** (intake and core as VMs on one host) has weaker isolation than separate hosts. A hypervisor compromise defeats ADR-009 separation. The installer recommends CE-HARDENED.
- **Automatic updates** trust the release process. Threshold signing and transparency logging reduce this risk (ADR-022), but a compromise of the threshold would propagate quickly.
- **SMB organizations** usually have small anonymity sets. Content-based identification cannot be prevented technically.
- **Small-organisation mode** replaces missing internal separation of duties with an external party; it does not create independence where the external party is captured, and in CE-SINGLE a malicious administrator remains undetectable by Candor itself.
- **Watchers for CE** are voluntary: a CE instance nobody watches has no external check on Tier W integrity beyond the Operator Statement, which a compelled operator may keep renewing.
- **Requiring ≥ 2 recipients** (SMB-003) raises the entry cost for very small organisations; some will not deploy rather than engage an external party.
- **Single-node CE** has no availability guarantees. During an outage, sources see an outage page and may use less safe channels. Guidance addresses this.
- Community support has no SLA.

## 8. Open issues

1. Reference appliance hardware list and pricing guidance for SMB.
2. Resolved by ADR-041: the Source App is distributed from the Candor project's onion service and independent mirrors; the organisation's clearnet information site does not host it.
3. Catalogue of certified external ombuds/co-signer services for small-organisation mode (§4.4), and whether the Foundation should vet them (`36-OPEN-SOURCE-GOVERNANCE.md`).
