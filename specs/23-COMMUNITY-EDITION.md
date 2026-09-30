# 23 — Community Edition (CE) and Small Business Secure Profile
Status: Draft v1.0 · Edition applicability: CE (parity statements cover EE) · Owner: Core Product team

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
| Binding decisions | `DECISIONS.md` §2, ADR-001..029 |
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
| F01 | Anonymous reporting over Tor | Tor v3 onion service with PoW and vanguards-lite (ADR-001). No clearnet fallback (ADR-002). Tier W no-JS and Tier V Source App (ADR-004). 10-word passphrase (ADR-005). | 16, 11, 05 |
| F02 | Encrypted reports and attachments | HPKE X-Wing channel epoch keys (ADR-006/008). STREAM 64 KiB chunks. Padding (ADR-011). Recipient keys on endpoints (ADR-007). | 04, 10 |
| F03 | Two-way communication | Source mailbox via passphrase. Replies shown at next login. Day-granular dates. No receipts or presence (ADR-010). | 11, 12 |
| F04 | Recipients | Candor Desk (C-15). Hardware-wrapped keys (FIDO2 PRF, PIV/smart card, TPM; software fallback with warning). Local WebAuthn accounts. | 12, 15 |
| F05 | Case management | ISO 37002 lifecycle (receive → assess → address → conclude). Tasks. Notes. Detriment-risk assessment. Retaliation check-ins. SLA engine with calendar/business days and holiday calendars (R6 WB-04..06, WB-23). | 14 |
| F06 | Metadata minimization | Day-granular timestamps. No IP, UA or circuit logging. Attachments never parsed on servers (ADR-010, -012, -016). | 03 |
| F07 | Secure deletion | Crypto-erasure plus best-effort physical deletion, with documented limits (ADR-025). | 35 |
| F08 | Basic audit | Hash-chained, signed checkpoints. Four classes. `candorctl audit verify`. Local scrubbed JSONL export of SECURITY and SYSTEM events (ADR-016). | 20 |
| F09 | Basic workflow | Fixed lifecycle states. Assignment. Templates. Acknowledgement and feedback timers (EU 7-day / 3-month defaults, B-CO-02). | 14 |
| F10 | Localization | Source and staff UI i18n. RTL. EN/FR parity pack. Community translations. | 26 |
| F11 | Accessibility | WCAG 2.2 AA target. No CAPTCHA. Save-and-resume. Works in Tor Browser "Safest" (B-CO-28, R6 C). | 26 |
| F12 | Backups | Encrypted to an offline k-of-n key. Case content already end-to-end encrypted. Restore test (REQ-H-55). | 19 |
| F13 | Documented upgrades | Upgrade guide per release. N-1→N migration tested. Rollback procedure. | 33 |
| F14 | Secure deployment | CE-SINGLE and CE-HARDENED profiles. Secret Placement Manifest verification (ADR-028). Pinned-key installer (R2 R-INST-01). | 18 |
| F15 | Security updates | TUF, threshold-signed, reproducible, transparency-logged, identical for all (ADR-022). Fixes released at the same moment as EE (ADR-020). | 33 |
| F16 | **COI routing basics** | Channels routing to independent bodies. Source-flagged "concerns: [roles]" exclusions. COI map. Category rule for accounting/audit matters going to the audit committee (SOX §301, B-CO-69). Break-glass with dual authorization and post-hoc review (ADR-015). | 14, 15 |
| F17 | **Legal hold (basic)** | Per-case hold and sealed-matter flag. Blocks disposition. Restricts circulation. Reason code. Dual approval. 90-day review reminder (R6 WB-36). | 35 |
| F18 | Sealed Identity Store | Identity encrypted to custodians. Unseal requires legal basis, dual approval and a reporter notice (ADR-014). | 14, 04 |
| F19 | Recovery Quorum (optional) | k-of-n, off by default, published to sources (ADR-013). | 04 |
| F20 | Evidence handling | Immutable original plus sanitized derivative. Hashes. Custody records. C-17 containment (ADR-012). | 10 |
| F21 | Redaction and Export Packages | Human-created, redaction-reviewed. Dual approval for originals (ADR-018). | 10, 14 |
| F22 | Basic reporting | KPI dashboard with k ≥ 20 suppression and month granularity (INC-74). | 14 |
| F23 | DSAR restriction workflow | Restriction reason codes. Deferred-notice timers (R6 WB-15). | 14 |
| F24 | Notifications | Content-free, hourly digest, SMTP or webhook (ADR-017). | 20 |
| F25 | Staff authentication | WebAuthn/FIDO2 phishing-resistant by default. PIV/smart card supported (B-CO-41). | 15 |
| F26 | HSM/TPM | TPM 2.0 sealing by default. PKCS#11 integration available (unsupported without EE). | 17 |
| F27 | FIPS build profile | Source and build recipe public. Unsupported and without evidence package in CE. | 04 |
| F28 | Compliance pack loader | Open pack schema. Starter packs: EU Directive generic, SOX §301 generic, PSDPA generic (CC BY 4.0). | 25 |
| F29 | Clearnet Information Site | Static generator. Onion-Location. No submission form (C-37). | 18 |
| F30 | Confidential Clearnet Intake | Off by default. Separately branded NOT ANONYMOUS (C-38, ADR-002). | 11 |
| F31 | Telemetry | None from sources. Instance telemetry OFF by default and opt-in, using the fixed schema (ADR-023). | 24 |
| F32 | Multiple channels | Unlimited channels per organization. Each has its own keys and onion service option. | 06 |

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
- **Constraint:** SMB **SHALL NOT** relax any anonymity, crypto or logging default. It changes how defaults are *delivered and operated*, not what they are.

### 4.2 Components

| Component | Specification |
|---|---|
| **Simple installer** `candor-setup` | Interactive TUI. Also a headless YAML mode. It: (1) verifies the release signature against the fingerprint printed in the docs and in the transparency log (no TOFU, R2 R-INST-01); (2) detects the host (supported: Debian 13 on a physical host or the reference appliance VM image); (3) creates VMs for Z-INTAKE and Z-CORE on one host (CE-SINGLE) or configures two hosts (CE-HARDENED, recommended); (4) generates the onion key locally; (5) runs the channel ceremony with ≥2 recipients' Desks; (6) runs the config checker; (7) prints the onion address and a QR code for the information site. Target completion ≤ 60 min for a non-specialist (DEMO). |
| **Secure defaults** | ANONYMOUS channel. Tor-only. Tier W and Tier V enabled. Clearnet intake off. Recovery Quorum off. Telemetry off. Update check over Tor. Content-free notifications (hourly). Retention 365 days after closure. k = 20. |
| **Minimal admin** | Admin tasks reduced to: add/remove recipient, rotate recipients' devices, view health, apply updates (automatic), run backup, run restore test. All via the Desk admin mode. No web admin (ADR-007). |
| **Automatic signed updates** | Unattended TUF updates on by default. Security releases apply within 24 h. Feature releases apply in the weekly maintenance window (default Sunday 03:00 local, ±60 min random). Intake is restarted with the outage page shown. Automatic rollback if post-update self-test fails. Update fetch over Tor. No instance identifier is sent (ADR-022). |
| **Backup wizard** | Generates the backup key k-of-n (default 2-of-3 for SMB) on 3 hardware tokens or printed Shamir cards. Schedules a nightly encrypted backup to a local disk or customer S3-compatible target. Prompts a quarterly restore test on a spare VM. The wizard refuses to complete until the first test restore of a synthetic canary case succeeds. |
| **Config checker** `candorctl check` | Runs at install, after every update, daily, and on demand. Checks: Secret Placement Manifest (ADR-028); clearnet listeners; Tor, web-server and access logs disabled; core dumps disabled; swap encrypted or off; NTP sources; disk encryption; TUF metadata freshness; certificate expiry; ≥2 key holders per active case; recipients using the software-fallback wrapping; dangerous-config inventory; backup age and last restore test; channel epoch key pre-generation horizon (≥ 3 epochs ahead). Output: pass/warn/fail with remediation text. It never includes case data. |
| **Security health dashboard** | In Desk admin mode (not a web page). Traffic-light tiles for each checker category. Update status. Days since last restore test. Onion service reachability (synthetic probe). Pending dual approvals. Aggregate counts use k ≥ 20 and show "<20" otherwise. No per-case or per-source information. |

### 4.3 SMB-specific decisions

| Question | Decision | Rationale |
|---|---|---|
| Single recipient allowed? | Allowed only with an explicit acknowledgment that loss of that device means permanent loss of access (ADR-013). The wizard proposes a second recipient such as external counsel or an ombudsperson. | Availability vs simplicity. Protection is unchanged. |
| VPS or public cloud? | Allowed only under PRIVATE-CLOUD with a provider-observer disclosure screen (THR-030). The appliance on an owned host is recommended. | ADR-024 |
| Tier W only? | No. Tier V download instructions are always shown on the landing page. | ADR-004 |
| Software-fallback recipient keys? | Allowed with a persistent warning in the dashboard. Two FIDO2 keys per recipient are recommended (≈ low-cost hardware). | ADR-007 |
| Email notifications via a cloud mail provider? | Allowed, because the content is fixed (ADR-017). The digest timing observer is disclosed. | INC-57 |

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
| Notifications content-free | ✓ | ✓ plus Teams | Yes |
| Evidence containment (C-17) | ✓ | ✓ plus bundles | Yes |
| Reporting k-threshold | ✓ | ✓ plus regulator exports | Yes |
| Automatic signed updates | ✓ | ✓ (plus LTS) | Yes (same artifacts). LTS changes cadence, not protection. |
| Security fix timing | Same moment | Same moment | Yes (ENT-030) |
| Vendor support / SLAs | Community | Contract | N/A (no protection effect) |
| Telemetry | Off, opt-in schema | Off, opt-in schema | Yes |

## 6. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| CE-001 | CE SHALL include every Trust Path component and every protection listed in §3 F01–F32. A release SHALL fail if any CE build lacks a protection present in EE. | ADR-020; B-CO-60 | THR-024 | C-30, C-31 | TST: edition feature-parity test comparing protection manifests; AUD |
| CE-002 | CE and EE SHALL build Trust Path binaries from the same source tree and same reproducible recipe. The Trust Path artifact hashes SHALL be identical across editions. | ADR-022; REQ-H-14 | THR-024, THR-025 | C-31, C-32 | TST: cross-edition hash comparison |
| CE-003 | CE SHALL support unlimited channels in one organization, each with its own channel keys and optional separate onion service. | ADR-008 | THR-045 | C-10, C-05 | TST |
| CE-004 | CE SHALL implement COI routing basics: source-flagged role exclusions, the COI map, independent-body channels, category→audit-committee rules and break-glass with dual authorization. | ADR-015; INC-22; B-CO-69 | THR-020 | C-22, C-10 | TST: COI test suite (shared with EE) |
| CE-005 | CE SHALL implement per-case legal hold and the sealed-matter flag, with dual approval, reason codes and a 90-day review reminder. | B-CO-15; R6 WB-36 | THR-017, THR-037 | C-10 | TST |
| CE-006 | CE SHALL implement the SLA engine with calendar and business-day modes, holiday calendars, and pause/extension with justification. | B-CO-02; B-CO-24 | — | C-10 | TST: clock fixture suite (EU 7d/3m; AB 5/10/120 bd) |
| CE-007 | CE SHALL implement the Sealed Identity Store and unseal workflow identical to EE. | ADR-014; B-CO-13 | THR-018, THR-019 | C-10, C-15 | TST (shared suite) |
| CE-008 | CE SHALL provide a local scrubbed JSONL export of SECURITY and SYSTEM events produced by the same allow-list code as C-26. | ADR-016; INC-60 | THR-016 | C-24 | TST: canary scrub test |
| CE-009 | CE SHALL provide KPI reporting with k ≥ 20 suppression and month granularity. | INC-74; INC-70 | THR-039 | C-10 | TST |
| CE-010 | CE documentation SHALL state, for every EE-only capability, whether its absence changes source protection, using the §5 table. | Design | THR-040 | C-30 | INSP |
| CE-011 | CE SHALL provide a supported release window: each minor release receives security fixes until 90 days after the next minor release. Majors overlap by ≥ 180 days. | B-CR-50 | THR-025 | C-32 | INSP: release calendar |
| CE-012 | CE upgrade guides SHALL be published with each release and tested N-1→N in CI. | Design | THR-042 | C-31 | TST: upgrade job |
| CE-013 | CE SHALL NOT contain license checks, feature-unlock keys or network calls to vendor services. | ADR-023; C-35 | THR-036 | all CE | TST: network egress test; INSP |
| CE-014 | CE compliance-pack loader and starter packs (EU, SOX, PSDPA generic) SHALL be included and licensed CC BY 4.0. | B-CO-02; B-CO-69; B-CO-19 | — | C-10 | INSP |
| CE-015 | CE SHALL include PKCS#11 and TPM integration code and the CANDOR-FIPS-1 build recipe. | ADR-006; ADR-020 | THR-013 | C-11, C-29 | TST: build job for FIPS profile |
| CE-016 | CE SHALL warn continuously in Desk admin when any active case has fewer than 2 active key holders. | ADR-013 | THR-042 | C-15, C-19 | TST |
| CE-017 | CE documentation SHALL state that CE is not CJIS-, FedRAMP- or PBMM-assessed. | B-CO-46; B-CO-43; B-CO-48 | THR-035 | C-30 | INSP |
| SMB-001 | The SMB profile SHALL NOT change any default of ADR-001..ADR-029. A CI test SHALL compare the effective security configuration of SMB against CE-SINGLE and CE-HARDENED. Only the documented operational deltas (update automation, backup k=2-of-3, wizard) SHALL differ. | ADR-020 | THR-035 | C-19 | TST: `smb-config-diff` |
| SMB-002 | `candor-setup` SHALL verify release signatures against a pinned fingerprint and a transparency-log inclusion proof before installing. It SHALL NOT fetch keys by TOFU. | B-GL-41; REQ-H-48; REQ-H-52 | THR-024, THR-025 | C-19, C-32 | ST: tampered installer and substituted key |
| SMB-003 | `candor-setup` SHALL refuse to finish until ≥2 recipients have enrolled, or the admin has acknowledged the single-recipient loss risk in a recorded prompt. | ADR-013 | THR-042 | C-19 | TST |
| SMB-004 | SMB automatic updates SHALL apply security releases within 24 h and feature releases in a weekly window with ±60 min random offset. Update fetch SHALL go over Tor with no instance identifier. | ADR-022; ADR-023 | THR-025, THR-036 | C-33, C-19 | TST: update client network capture |
| SMB-005 | An update whose post-update self-test fails SHALL be rolled back automatically, and SHALL alert via content-free notification. | Design; INC-49 | THR-025 | C-19, C-25 | TST: fault injection |
| SMB-006 | The backup wizard SHALL generate the backup key as k-of-n (default 2-of-3). It SHALL NOT complete until a canary restore succeeds. It SHALL prompt restore tests every 90 days. | INC-55; REQ-H-55 | THR-042, THR-013 | C-27 | DEMO; TST |
| SMB-007 | `candorctl check` SHALL implement every check listed in §4.2 and SHALL run daily. A fail on a Secret Placement, clearnet-listener or logging check SHALL alert every admin within 1 h. | ADR-028; B-SD-22; INC-34 | THR-035, THR-016 | C-25 | TST: each check has a positive and negative fixture |
| SMB-008 | The health dashboard SHALL show no per-case or per-source data. Counts SHALL be k ≥ 20 thresholded. | INC-70 | THR-039 | C-19 | TST |
| SMB-009 | SMB SHALL present a provider-observer disclosure and require acknowledgment before installing on a VPS or public cloud. | ADR-024; INC-59 | THR-030 | C-19 | TST |
| SMB-010 | `candor-setup` guided mode SHALL be completable by a non-specialist in ≤ 60 min in usability testing (n ≥ 5, success ≥ 80%). | Design | — | C-19 | DEMO: usability study |
| SMB-011 | SMB SHALL display a persistent warning for each recipient using software-fallback key wrapping. | ADR-007 | THR-013 | C-15 | TST |
| SMB-012 | The SMB landing page template SHALL include small-organization anonymity guidance when configured population < 250. | INC-73 | THR-010 | C-06 | TST |
| SMB-013 | SMB SHALL keep channel epoch keys pre-generated ≥ 3 epochs ahead and SHALL warn at < 2. | ADR-008 | THR-032 | C-15, C-25 | TST |

## 7. Residual risks and limitations

- **CE-SINGLE** (intake and core as VMs on one host) has weaker isolation than separate hosts. A hypervisor compromise defeats ADR-009 separation. The installer recommends CE-HARDENED.
- **Automatic updates** trust the release process. Threshold signing and transparency logging reduce this risk (ADR-022), but a compromise of the threshold would propagate quickly.
- **SMB organizations** usually have small anonymity sets. Content-based identification cannot be prevented technically.
- **Single-node CE** has no availability guarantees. During an outage, sources see an outage page and may use less safe channels. Guidance addresses this.
- Community support has no SLA.

## 8. Open issues

1. Reference appliance hardware list and pricing guidance for SMB.
2. Whether Tier V Source App download should be mirrored on each instance's onion site: this is a verifiability vs availability trade-off, to be coordinated with `33-RELEASE-UPDATE-SECURITY.md`.
