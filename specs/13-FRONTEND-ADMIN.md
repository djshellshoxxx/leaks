# 13 — Administration, Security Operations and Enterprise Management User Interfaces
Status: Draft v1.1 (revision round 2: ADR-034..ADR-046) · Edition applicability: ADMIN UI and SECURITY OPERATIONS UI: both (CE and EE); ENTERPRISE MANAGEMENT UI: EE only · Owner: Platform Experience team (with Security Architecture, Operations and Accessibility review)

## 1. Purpose and scope

This document specifies three staff-facing interfaces that **never display report content**:

1. **ADMIN UI**: the admin mode of Candor Desk plus `candorctl` (C-19, running on admin workstations C-20). It covers users and enrollment, channels, key ceremonies, configuration with SAFE / ADVANCED / DANGEROUS classification and friction, updates, backups, and the self-test dashboard.
2. **SECURITY OPERATIONS UI (SOC UI)**: the SecOps mode of Candor Desk, backed by C-25 (health and self-test), C-24 (audit) and C-26 (SIEM export, EE). It covers health, integrity, scrubbed security events, anomaly alerts and audit-log verification.
3. **ENTERPRISE MANAGEMENT UI (EM UI)**: the web UI of the Enterprise Fleet Manager (C-34, EE). It covers the fleet of instances, tenants (as opaque slots), organization hierarchy, policy packs, licenses and update rollout. It holds no content and no onion addresses.

**Protection statement.** These UIs are designed so that system administration, security monitoring and fleet management can be performed **without any capability to read reports or identify sources**:
- admins hold no case keys and publish no member epoch keys (ADR-015, ADR-030; `15-AUTHENTICATION-AUTHORIZATION.md` §5.7);
- security telemetry is allow-listed and scrubbed (ADR-016);
- the fleet holds only opaque instance metadata (ADR-022; `21-ENTERPRISE.md` §9).

This implements protections P-09 (admin has no content access), P-13 (update integrity), P-17 (audit tamper evidence), P-25 (tenant isolation) and P-28 (service location hiddenness) of `40-SECURITY-ASSUMPTIONS.md`. It assumes:
- administrators are trusted for availability, not confidentiality (ASM-044);
- operator independence holds where the organization is the adversary (ASM-043);
- at least one honest monitor exists (ASM-036);
- the audit witness is honest (ASM-048).

**Residual risk:** a malicious admin can still deny service, delete data or weaken *future* Tier W intake by deploying unreviewed code. The last is detectable, not preventable (ASM-116, §9).

## 2. Context and dependencies

| Document | Dependency |
|---|---|
| `DECISIONS.md` | ADR-013 (Recovery Quorum = DANGEROUS), ADR-015 (admin ≠ case access), ADR-016 (audit classes), ADR-017, ADR-020, ADR-021 (multi-tenancy), ADR-022 (TUF, no targeted updates), ADR-023 (telemetry), ADR-024 (profiles), ADR-028 (Secret Placement Manifest), ADR-029 (audiences), ADR-030 (member epoch keys, role labels), ADR-032 (onion key on ≤ 2 HA hosts) |
| `DECISIONS.md` revision ADRs | ADR-035 (operator statement, External Watchers, independent approval of intake captures, INCIDENT_NOTICE), ADR-036 (CIK holders, time-locked roster changes, certified role labels, weekly publication slot), ADR-037 (Triage Set), ADR-038 (constant-schedule notifications, fixed import schedule, coarse daily health band), ADR-040 (Platform Manifest, security floors), ADR-043 (independent-custody devices), ADR-044 (suspend-only automation, ≥ 2 authenticators, GOV recovery default, EKV DR), ADR-045 (independent approvers, Fleet limits, small-organisation mode), ADR-046 §5–§6 (metrics regime in 24 §TEL; SAFE/ADVANCED/DANGEROUS labels only) |
| `15-AUTHENTICATION-AUTHORIZATION.md` | Roles (SYS_ADMIN, USER_ADMIN, SECURITY_OFFICER, AUDITOR, OVERSIGHT, CHANNEL_OWNER, TENANT_ADMIN, RECOVERY_TRUSTEE, RECORDS_CUSTODIAN), admin sessions (idle 10 min, absolute 2 h), step-up transaction confirmation (§4.7), dual-control list DC-01..DC-17 (§5.8) |
| `24-LICENSING-BUSINESS-MODEL.md` §TEL | Single source of truth for aggregate/metrics suppression (ADR-046 §5) |
| `20-LOGGING-AUDITING.md` | Event classes and schemas, checkpoints, witness, `candorctl audit verify`, anomaly rule AUD-008, SIEM allow-list |
| `21-ENTERPRISE.md` | Fleet Manager data model (§9.2), command allow-list (§9.3), tenancy rules (§6) |
| `32-OPERATIONS.md` | CFG configuration classification catalogue (normative list of settings and classes); HUM controls |
| `33-RELEASE-UPDATE-SECURITY.md` | TUF roles, transparency log, reproducible-build attestations |
| `19-BACKUPS-DR.md` | Backup contents, restore tests |
| `14-CASE-MANAGEMENT.md` | Channel, COI map, SLA packs, questionnaire schema |
| `40-SECURITY-ASSUMPTIONS.md` | Class-C checks shown on dashboards: ASM-103, -104, -106, -107, -111, -114, -116, -117, -118, -121, -122 |
| `26-ACCESSIBILITY.md` | WCAG 2.2 AA; Section 508 §504 (authoring tools) for the questionnaire builder |

## 3. Common rules for all three UIs

| # | Rule |
|---|---|
| CR-1 | **No content surfaces.** No screen, export, tooltip, error or search result may contain report text, attachments, identity data, case titles, source answers or per-case metadata beyond pseudonymous IDs where explicitly specified. |
| CR-2 | **Aggregates follow the single metrics regime** of `24-LICENSING-BUSINESS-MODEL.md` §TEL (ADR-046 §5): k = 10, minimum period one calendar month, complementary suppression, no medians/ratios/percentiles for cells < k, no per-channel metrics for channels with < 3 cases/month. The SOC and admin dashboards show intake state only as **global daily health bands** (ADR-038 §5). No daily or hourly report-derived counts exist in any UI (INC-70, INC-74; THR-039; RVW-B-07, RVW-B-08). |
| CR-3 | **Bundled UI, no third parties.** ADMIN and SOC UIs are modes of the signed Desk bundle. The EM UI is a server-rendered web app from C-34 with strict CSP (`default-src 'self'`; no third-party origins). There are no analytics or remote fonts (ADR-023). |
| CR-4 | **Phishing-resistant auth and step-up.** Hardware FIDO2/PIV login (`15` §4.1). Step-up transaction confirmation for every operation in `15` §4.7, where the confirmation dialog shows the operation descriptor in human-readable form before the authenticator touch. |
| CR-5 | **Audience separation.** ADMIN = `admin-api`; SOC = `admin-api` with SECURITY_OFFICER / AUDITOR scopes; EM UI = the separate C-34 audience. Tokens are never shared across audiences (ADR-029). |
| CR-6 | **Everything is audited.** Every state-changing action creates a SECURITY-class event (`20`). The UI shows the event ID in the success message. |
| CR-7 | **Honest state.** Pending approvals, cooling-off timers, time-locked directory changes, failing self-tests, active DANGEROUS settings, custody exceptions and reduced separation of duties are shown persistently. They are never collapsed or hidden by default. |
| CR-9 | **Configuration labels.** Only SAFE, ADVANCED and DANGEROUS exist (ADR-046 §6; "WEAKENING" is DANGEROUS). Capabilities for which no setting exists at all are listed as "not available" (§4.5), not as a fourth class. |
| CR-8 | **Accessibility.** WCAG 2.2 AA, keyboard-complete, screen-reader tested (`26`). Status is never shown by color alone. |

## 4. ADMIN UI (C-19)

### 4.1 Shell and navigation
```
+----------------------------------------------------------------------------------+
| Candor Admin — Instance "Acme-EU-1" (CE-HARDENED)   [DANGEROUS: 1 active] [Lock]|
| REDUCED SEPARATION OF DUTIES — external oversight: Smith & Co (counsel)          |
+-------------+--------------------------------------------------------------------+
| Dashboard   |  Self-test: 23 pass · 1 warn · 0 fail      Updates: 1.4.2 (floor 1.4.0) |
| Users       |  Backups: last OK 2026-09-30 · restore test 2026-08-14             |
| Channels    |  Pending approvals: 2   Cooling-off: 1 (Recovery Quorum, 51 h)     |
| Custody     |  Time-locked directory changes: 1 (effective 2026-10-03)           |
|             |  Operator statement: signed 2026-09-12 · next due 2026-10-12       |
| Keys & cer. |                                                                    |
| Config      |  You cannot see reports. Administrators hold no case keys.         |
| Updates     |                                                                    |
| Backups     |                                                                    |
| Self-test   |                                                                    |
| Audit (own) |                                                                    |
| Support     |                                                                    |
+-------------+--------------------------------------------------------------------+
```
- A persistent header shows the instance label, deployment profile (ADR-024), a "DANGEROUS: n active" chip (CR-7) and Lock.
- The dashboard carries a fixed line: "You cannot see reports. Administrators hold no case keys." This sets correct expectations and discourages social-engineering requests ("can you look at report X?").
- **Small-organisation mode banner (ADR-045; RVW-C-09):** when the instance runs in small-organisation mode (fewer than 4 distinct enrolled persons holding the roles required by `15` §5.1 separation of duties), a persistent, non-dismissable banner reads "REDUCED SEPARATION OF DUTIES — some dual controls are performed with an external party: {external_oversight_label}." Small-organisation mode cannot be activated unless at least one external party (external counsel, board member, statutory auditor or certified ombuds service) is enrolled as OVERSIGHT; the same statement is included in the published operator statement (ADR-035 §2) and shown to sources (`11` S03). Leaving the mode requires DC-09.

### 4.2 Users & enrollment (USER_ADMIN)
- **List columns:** display name, `person_ref`, roles, status (`PENDING_ENROLLMENT` / active / deactivated), authenticator class and attestation model (ASM-114), enrolled devices, `last_staff_activity_day` (date only).
- **Actions:**

| Action | Rule |
|---|---|
| Invite | Creates `PENDING_ENROLLMENT`. Enrollment links are delivered out of band (never via a notification containing role or case data). |
| Approve enrollment | DC-07: 2 USER_ADMINs; for accounts joining an INDEPENDENT channel or a Triage Set, the second approver holds an independent role and records that `person_ref` was verified out of band (ADR-036 §2). Attestation check shown (AAGUID, model, firmware against deny-list). Enrollment is incomplete until **≥ 2 hardware authenticators** (primary + stored backup) are registered (ADR-044 §2); the UI shows "1 of 2 authenticators" until then. Two accounts presenting the same authenticator attestation serial are flagged as one person (RVW-C-09) |
| Assign / remove role | DC-07. The UI **blocks** combinations violating static separation of duties (SYS_ADMIN with any case role on one account; USER_ADMIN = SYS_ADMIN person in CE-HARDENED+) with an explanation |
| Suspend (was "Deactivate") | Single USER_ADMIN, or SCIM/HR/IdP signal, immediate: sessions revoked, no ciphertext delivery, **keys and wraps intact** (ADR-044 §1). OVERSIGHT is notified content-free. Shows: "Suspension does not remove access to cases. Cases where this person is one of fewer than 2 key holders: {n}." |
| Delete key wraps | DC-15 (CASE_LEAD or CHANNEL_OWNER + OVERSIGHT), executes ≥ 7 days after approval with a visible countdown and OVERSIGHT notice; blocked if < 2 key holders would remain; not used for source-requested erasure or retention expiry (ADR-044 §1; RVW-C-03) |
| Reactivate | DC-07 |
| Revoke device / authenticator | Immediate. Step-up required |

- **Not available:**
  - "log in as" or impersonation;
  - resetting a user's key-unlock factor so as to gain their keys;
  - viewing a user's case list;
  - exporting user lists with case memberships (membership is visible only to CHANNEL_OWNER in the channel view).

### 4.3 Channels (CHANNEL_OWNER; OVERSIGHT approves; SYS_ADMIN read-only)
- **Channel list:** name, channel type (INDEPENDENT / STANDARD, ADR-043), handling body description, modes allowed (ANON / CONF / IDENT), Triage Set custody state, availability state:
  - *Accepting*;
  - *Unavailable — no eligible Triage Set member with a current epoch key* (ADR-030, ADR-037 fail-closed);
  - *Warning — Triage Set below 2 eligible members* (ADR-037 §1);
  - *Custody exception active* (DANGEROUS, DC-16).
  Intake counts are never shown here (ADR-037 §2; CR-2).
- **Triage Set (ADR-037 §1):** the editor requires ≥ 2 members holding independent-body role labels (ombudsman, audit committee, external counsel, IG, ethics officer), or channel owner + OVERSIGHT where none exist. The Channel Identity Key is held only by the Triage Set and OVERSIGHT (ADR-036 §1); other members' Desks never receive it.
- **Membership & role labels:**
  - Each member entry shows the role label (public in C-14), whether the label is **certified by OVERSIGHT** (ADR-036 §3), "member since" date, the member's epoch-key pre-publication horizon (target: 4 epochs ahead, ADR-030) and the last epoch-key publication day.
  - Adding members, adding Triage Set members, and changing role labels are DC-08 (CHANNEL_OWNER + ≥ 1 approver from an independent role). The second approver verifies `person_ref` out of band (ADR-036 §2).
  - **Time lock (ADR-036 §2; RVW-A-05, RVW-C-05):** additions, role-label changes and COI-policy loosening take effect for sealing only **72 h** after log inclusion (**7 days** in the GOV and HIGH profiles). The UI shows a pending-change card with the effective date and a countdown, and states: "All current members and OVERSIGHT have been notified. Sources will see 'Recipients of this channel are changing on {date}'." During the time lock, any current Triage Set member or OVERSIGHT can file an objection, which blocks activation until resolved by OVERSIGHT. Removals and COI tightening take effect immediately and show no countdown.
  - **Publication slot (ADR-036 §7):** directory entries (epoch keys, roster changes) are published in the fixed weekly slot. The card shows "Will be published in the weekly slot on {date}" so publication timing does not reveal staff activity (RVW-A-29).
  - The resulting Key Directory entry is signed by a CIK holder (Triage Set or OVERSIGHT). The UI shows "Pending signature by a Triage Set member or OVERSIGHT" until signed.
- **COI map editor** (DC-08; loosening is time-locked as above):
  - Rows: subject role (what a report may concern) → excluded roles/users. Relational subjects that describe the source ("the source's direct manager") are not offered; "a manager in the reporter's line" is resolved by the Triage Set at triage (ADR-037 §2; RVW-B-03).
  - Validation warns when an exclusion would leave a category with 0 eligible Triage Set members, and suggests the channel's independent fallback channel.
  - Preview: "A report in category *Fraud* that ticks *CFO* will be first read by: Audit Committee Chair, External Counsel."
  - COI exclusions for individual cases are never visible here; they exist only as blinded tags (ADR-037 §3).
- **Questionnaire builder** (an authoring tool under Section 508 §504 / EN 301 549 clause 11.8):
  - It permits only the field types in `11-FRONTEND-SOURCE.md` §7 S05.
  - It rejects identity field types in ANONYMOUS-capable channels (SOPS-021).
  - It requires a visible label and help text for every field.
  - It shows a readability score for question text.
  - It previews in no-JS rendering at 320 px and 1280 px widths.
  - It warns when a field's wording asks for exact dates, names of colleagues present, or other identifying details.
- **Other channel settings:** SLA pack (calendar/business days, jurisdiction), retention class, source-visible status set, identity-custodian set (≥ 2), acknowledgment template, deployment guidance placeholders (`05` §6 placeholders; core `sops.*` keys not editable, SOPS-028).

### 4.3a Device custody (ADR-043; RVW-C-01)
- **Custody register view** (OVERSIGHT and SECURITY_OFFICER; SYS_ADMIN read-only): per enrolled Desk device of Triage Set members: custody class (independent attested / organisation-managed / unknown), attestation record (authenticator attestation, custody declaration that the device is not enrolled in the organisation's MDM/EDR/DLP/VDI, OVERSIGHT co-signature, date), last Desk release-digest report (ADR-043; labelled "self-reported, non-authoritative").
- **Record custody:** a guided workflow in which the member declares the device's management state, OVERSIGHT co-signs with step-up, and the record is published to C-14. Re-attestation every 180 days; expired records revert to "unknown".
- **INDEPENDENT channel without independent custody:** enabling or keeping an INDEPENDENT channel whose Triage Set has any member without attested independent custody is **DANGEROUS** (DC-16: SECURITY_OFFICER + OVERSIGHT, impact statement, cooling-off, 90-day re-confirmation). The impact statement reads: "Members of the first-reading team use computers that {organization} manages. {organization}'s IT administrators may be able to read reports in this channel. Sources will be told this." Activation adds a disclosure to the channel descriptor shown to sources.
- Honest limit shown on the page: "Candor cannot verify how a computer is really managed. This record is a declaration by the member and OVERSIGHT, not a technical guarantee."

### 4.4 Keys & ceremonies
Ceremonies are **guided, witnessed procedures**. Every ceremony run produces a signed transcript that participants countersign with their hardware keys.

| Ceremony | Participants (minimum) | Where | Output | Class |
|---|---|---|---|---|
| Instance initialization | SYS_ADMIN + SECURITY_OFFICER + 1 witness (OVERSIGHT) | Admin workstation + target hosts | Secret Placement Manifest baseline (ADR-028), audit signing key in TPM/HSM (AUD-002), onion key generation + offline encrypted backup | ADVANCED |
| Channel creation | CHANNEL_OWNER + ≥ 2 Triage Set members + OVERSIGHT witness | Triage Set and OVERSIGHT Desks | Channel Identity Key held only by the Triage Set and OVERSIGHT (ADR-036 §1); OVERSIGHT-certified role labels; initial member epoch keys (4 epochs) published in the next weekly slot | ADVANCED |
| Identity Custodian key set | ≥ 2 IDENTITY_CUSTODIANs + OVERSIGHT witness | Custodian Desks | Custodian keys in C-14 | ADVANCED |
| Recovery Quorum setup (ADR-013) | SYS_ADMIN + SECURITY_OFFICER (DC-09) + k-of-n RECOVERY_TRUSTEEs present + OVERSIGHT | **Offline** machine (air-gapped), hardware tokens | Quorum public key published in C-14; source-visible escrow statement updates (`05` GC-01) | CE/EE: **DANGEROUS**. GOV profile: performed at installation by default with custodians from independent roles (ADR-044 §3); disabling it in GOV is DANGEROUS and requires a recorded records-officer determination (RVW-C-14) |
| Operator statement signing (ADR-035 §2) | k-of-n statement signers incl. ≥ 1 independent role (OVERSIGHT or external) | Signer Desks | Quorum-signed OPERATOR_STATEMENT ("no compelled modification, no instrumentation of intake memory, no targeted update"; plus "reduced separation of duties" in small-organisation mode) published in C-14 | Due every 30 days; the dashboard shows the due date from day 21 and a persistent warning after day 30 ("Sources now see a warning", `11` WB-1). A signer can decline without giving a reason; the UI never pressures ("sign now") |
| Onion key rotation / standby address | SYS_ADMIN + SECURITY_OFFICER | Intake host(s) | New onion key; C-37 update checklist; ADR-032 placement on ≤ 2 hosts in HA | ADVANCED |
| Audit key rotation | SECURITY_OFFICER + AUDITOR | TPM/HSM | New checkpoint key in C-14 | ADVANCED |
| HSM initialization (EE) | per ASM-115 | HSM | Non-exportability attestation recorded | ADVANCED |

**Ceremony UI rules:**
1. Steps are displayed one at a time. Each shows "Who must be present", the "Exact action" and the "Expected result". Each is confirmed by the named participant's step-up.
2. Steps cannot be skipped or reordered.
3. Abort leaves no partial key material (the ceremony tool zeroizes).
4. The transcript (step, participant, timestamp, public outputs, hashes) is exported as a signed file and logged as a SECURITY event.
5. Private key material is never displayed.
6. The offline ceremony tool is a separate signed package run from read-only media. The Admin UI only prepares the plan and imports the signed transcript.

### 4.5 Configuration: SAFE / ADVANCED / DANGEROUS (and capabilities not available)
The normative catalogue of settings and classes is owned by `32-OPERATIONS.md` (CFG). This section specifies the **UI friction** each class receives.

| Class | Who | Friction | Takes effect | Visibility |
|---|---|---|---|---|
| **SAFE** | SYS_ADMIN (or CHANNEL_OWNER for channel-scoped) | Session only; diff preview | Immediately | SECURITY event |
| **ADVANCED** | SYS_ADMIN | Step-up transaction confirmation; typed reason ≥ 20 chars; diff preview with "What this changes" text; SECURITY_OFFICER notified | Immediately | SECURITY event; listed in the "Advanced settings changed (30 days)" panel |
| **DANGEROUS** | Proposer SYS_ADMIN + approver SECURITY_OFFICER (DC-09); OVERSIGHT notified | Step-up for both. The **impact statement** is shown and must be scrolled through (not a checkbox), including source-facing effects. The proposer types the setting key to confirm. **Cooling-off period** (default 72 h, minimum 24 h) during which OVERSIGHT or SECURITY_OFFICER may veto. Pre-activation checks (e.g., quorum ceremony done) | After cooling-off and checks | Persistent "DANGEROUS: n active" chip in the ADMIN and SOC UIs. Source-visible disclosure where applicable (e.g., escrow statement on S03). Re-confirmation every 90 days or the setting auto-reverts, where safe to revert |
| *Not available* (not a class, CR-9) | Nobody | No UI, CLI, API or config-file path exists | — | Documented in 32 and in the UI "About security limits" page |

**Illustrative mapping** (32 is authoritative):

| Setting | Class |
|---|---|
| Session idle lock within allowed range; SLA values; UI language defaults; daily digest send time; dual-render check ON (`10` §5.4) | SAFE |
| Notification mode off → daily digest (ADR-038 §2); clipboard policy for Desk; enabling the Tier V web bundle (SUI-045); OS notifications allowed; container-only isolation in CE-SINGLE (ADR-046 §6) | ADVANCED |
| Enable Recovery Quorum in CE/EE, or disable it in GOV (ADR-013, ADR-044 §3); enable Confidential Clearnet Intake C-38 (ADR-002); enable instance telemetry (ADR-023); enable diagnostic logging on Z-CORE; allow TOTP fallback or synced passkeys (DC-09); allow native-format export exceptions; disable dual approval for non-original exports in HIGH profile; SIEM exporter field additions (C-26); weaken any `24` §TEL suppression parameter (e.g., lower k); INDEPENDENT channel without independent custody (DC-16, ADR-043); leave small-organisation mode; anything formerly labelled "WEAKENING" (ADR-046 §6) | DANGEROUS |
| Source IP or access logging on Z-INTAKE; tor/web access logs; third-party scripts or analytics on source surfaces; clearnet ANONYMOUS mode; disabling envelope encryption; admin case access; CAPTCHA services; targeted builds; Tier W draft or session timers (fixed by ADR-034); event-driven staff notifications (ADR-038 §2); holding below the security floor (ADR-040) | Not available (no setting exists) |

**Configuration as code.**
- `candorctl config plan|apply` enforces the identical class and approval rules. `apply` of a DANGEROUS change creates the same approval object and cooling-off timer.
- Drift between the running config and the approved config is a self-test failure.

**Configuration screen wireframe:**
```
| Config › Security › Recovery Quorum                              [DANGEROUS]      |
| Current: OFF                                                                       |
| What this changes:                                                                 |
|  • A backup key split among 5 trustees can unlock ALL cases wrapped to it (3 of 5). |
|  • Sources will see: "A backup key is split between …; 3 together could unlock."  |
|  • Requires an offline key ceremony before activation.                             |
| Reason (required): [______________________________________________]               |
| Type the setting name to confirm: [recovery_quorum.enabled______]                  |
| [ Propose change ]  → needs SECURITY_OFFICER approval · 72 h cooling-off · OVERSIGHT |
```

### 4.6 Updates
- **Displays:**
  - installed version per component and host;
  - available TUF targets for the configured channel;
  - for each target: signature threshold met ✓, transparency-log inclusion ✓ (entry index), witness cosignatures ✓ (ASM-110), reproducible-build attestations (≥ 2 independent builders matched, builder operators listed, ASM-108), and **Platform Manifest** verification (OS, tor and PostgreSQL package names, versions and hashes, ADR-040);
  - the current signed security floor and whether every component is above it;
  - security advisory flag;
  - release notes (bundled in signed metadata, not fetched from the web);
  - Desk client version distribution across staff devices.
- **Actions:**
  - schedule in maintenance window;
  - apply now (ADVANCED);
  - **hold** up to 30 days with reason (after 30 days the instance alerts regardless, ENT-040). A release that raises the signed **security floor** (ADR-040) cannot be held: trust-path components below the floor refuse to start, and the UI shows "This release is required. Components older than {floor} will stop" with the date.
  - Emergency releases show their minimum 2-hour cooling period and the ≥ 2 signer organisations (ADR-040).
- **Not available:** upload a package, install from URL, downgrade below the TUF minimum version, per-host custom builds (ADR-022).
- **Failure display:** a verification failure (bad signature, missing log inclusion, builder mismatch) is shown as a blocking red-striped panel with "Do not install. Report to the security officer." and raises a SECURITY event.

### 4.7 Backups & DR
- **Status:** last successful backup per store; size; next run; retention; **last restore test** date and result (quarterly target; overdue = warn).
- **Erasure Key Vault (ADR-044 §4; RVW-C-06, RVW-C-07):** DR replication state within the HA RPO; vault backup retention (≤ 14 days); last signed erasure-log entry and its replication; last restore drill in which the erasure log was applied before serving.
- **Infrastructure-backup attestation:** a required, signed attestation by the owning team that hypervisor/SAN/infrastructure backups of core hosts exclude the vault volume (and, for HIGH/GOV, that the vault is on a physical host TPM, not a vTPM). Until attested, the panel shows persistently: "Not attested: deleted reports may remain recoverable from infrastructure backups beyond 14 days." The same text appears in the configuration digest.
- **Contents inventory** (from `19-BACKUPS-DR.md`): what is in the backup (ciphertext stores, config, audit) and **what is intentionally not** (case keys, member private keys, epoch private keys). The statement shown is: "A stolen backup contains no key that decrypts reports."
- **Actions:** run backup now (SAFE); start restore test into an isolated environment (ADVANCED); production restore (DANGEROUS-equivalent friction via DC-09, because rollback can reintroduce deleted data within the backup window, ADR-025).
- No browsing of backup contents.

### 4.8 Self-test dashboard (C-25)
Each check shows its ID, status (PASS / WARN / FAIL / UNKNOWN in text + icon), last run, evidence summary (never content) and a runbook link to local bundled docs.

| Check | Source |
|---|---|
| Secret Placement Manifest verified (all hosts, all feature flags) | ADR-028; ASM-107 |
| tor version, PoW enabled, vanguards, single-hop off, advisory age < 72 h | ASM-106 |
| Clock offset ≤ 5 min across ≥ 3 sources; epoch publication suspended if not | ASM-103 |
| CSPRNG readiness, KAT results, weak-key checks | ASM-104, ASM-105 |
| Running trust-path binary hashes present in the transparency log | ASM-116 |
| C-07 hardening (no swap/encrypted swap, no core dumps, ptrace scope) | ASM-118 |
| Logging configuration (no access logs, journald settings, capture tools absent) | `20` LOG-018 |
| Audit chain + witness cosignature verification | `20` AUD-004; ASM-048 |
| Member epoch-key horizon per channel (≥ 4 epochs; channels at 0 = unavailable) | ADR-030 |
| Cases with < 2 key holders (count only) | ASM-122 |
| Key-directory consistency proofs / gossip | ASM-111 |
| Backup freshness, restore-test age | `19` |
| Certificate and internal mTLS expiry buckets | `17` |
| Onion service self-reachability (via Tor loopback probe) | `16` |
| C-17 containment probe fleet status (per Desk, count only) | ASM-117 |
| Recovery Quorum custody attestations (if enabled) | ASM-121 |
| Legal-process transparency statement freshness (if enabled) | ASM-120 |
| Operator statement (ADR-035 §2) present, quorum-valid and ≤ 30 days old | ADR-035 |
| External Watcher results for this instance: static-asset, CSP and running-manifest comparisons published by ≥ 2 watchers (≥ 1 outside the jurisdiction for EE/GOV/MANAGED) | ADR-035 §1 |
| Platform Manifest verified; all components at or above the security floor | ADR-040 |
| Intake snapshot high-water mark monotonic; intake time source = Tor consensus floor + Roughtime (not Z-CORE alone) | ADR-036 §6 |
| Key Directory checkpoints carry ≥ 2 witness cosignatures (≥ 1 external in EE/GOV/MANAGED) | ADR-036 §5 |
| Triage Set custody attestations current for INDEPENDENT channels (count of exceptions only) | ADR-043 |
| Members with < 2 authenticators (count only) | ADR-044 §2 |
| Erasure Key Vault replicated; erasure log consistent; infrastructure-backup exclusion attested | ADR-044 §4 |

A FAIL on a Class-C check auto-opens an incident per ASM-113 and shows the incident ID.

### 4.9 Audit (own actions) and Support
- SYS_ADMIN sees SYSTEM events and their own SECURITY events. The full SECURITY and CASE streams are for AUDITOR/OVERSIGHT (`15`).
- **Support bundle:**
  1. The admin selects scope.
  2. The UI generates a bundle locally, scrubbed of tokens, content, onion addresses, hostnames of Z-INTAKE and user identities (`12` RUI-054; INC-56). Semantic scrubbing (RVW-B-18): configuration only as `{key, class, value_hash}` except enumerated/boolean values (no channel names, role labels, COI maps, calendars or time zones); SYSTEM events truncated to the hour; relay/import events excluded; no staff pseudonyms (role labels only).
  3. It shows a **full preview** of every file and requires explicit approval before any transfer to vendor support (C-36).

## 5. SECURITY OPERATIONS UI (SOC UI)

Roles: SECURITY_OFFICER (operate), AUDITOR (read and verify), OVERSIGHT (receives insider-activity alerts). It is delivered as the SecOps mode of Candor Desk, reading C-25/C-24 via `admin-api` scopes. EE deployments may additionally forward allow-listed events to a SIEM via C-26 (`20` §13). This UI is the local, privacy-preserving source of truth.

### 5.1 Health overview
Tiles per zone (Z-INTAKE, Z-CORE, Z-BAK, Z-SOC, admin workstations, Desks): state text, failing checks count, last heartbeat. Intake availability is shown **only as a coarse global daily health band** (OK / DEGRADED / UNAVAILABLE for the previous UTC day, plus "intake reachable now: yes/no"); no PoW effort level, queue depth or rate-limit state is displayed (ADR-038 §5; ADR-046 §5; RVW-A-27). **No submission timing and no submission counts.**

### 5.2 Integrity
- **Panels:**
  - running binary hashes vs transparency log (ASM-116);
  - TUF metadata freshness and expiry;
  - file-integrity monitoring summary per host;
  - Secret Placement Manifest result;
  - onion key unexpected-change flag;
  - key-directory consistency (ASM-111) with the last gossip exchange;
  - audit witness status.
- Any failure is presented with severity and "what this might mean" text (e.g., "An unlisted binary is running on the intake host. Tier W submissions may be exposed until resolved (ASM-013).").

### 5.3 Security events viewer
- **Scope:** SECURITY and SYSTEM class events only (ADR-016). Fields are rendered strictly from the `20` §5 allow-listed schema. There is **no free-text field display**, because schema-typed events have none.
- **Filters:** event type, stream, time range, staff actor (`person_ref`), host role.
- **Intake-derived data:** only the global daily health band (§5.1). The v1.0 hourly request-rate bands and daily submission counts are withdrawn (RVW-B-07, RVW-B-31; ADR-046 §5). Report-derived statistics exist only as `24` §TEL monthly aggregates in the governance reports, not in the SOC UI. There is no per-circuit, per-request or per-submission view.
- **Export:** audit export uses DC-10 (2 of AUDITOR / OVERSIGHT / SECURITY_OFFICER), producing an encrypted, signed file with checkpoint proofs (`20` AUD-009).

### 5.4 Anomaly alerts

| Alert family | Examples | Routed to | SOC sees |
|---|---|---|---|
| Staff case-access anomalies | > 3× 30-day median distinct cases opened/day or > 20/day (AUD-008); export spikes; repeated failed unseal requests; break-glass | **OVERSIGHT** (independent of the accessor's management chain, REQ-H-69) | A **weekly** count of alerts of this family routed (RVW-B-31 item 3). No day, no case refs, no user identity unless SECURITY_OFFICER is also OVERSIGHT |
| Authentication | New device enrollment, failed step-ups ≥ 5/h, attestation deny-list hits, cross-audience token replay | SECURITY_OFFICER | Full event fields |
| Configuration | ADVANCED/DANGEROUS proposals, approvals, vetoes, drift | SECURITY_OFFICER + OVERSIGHT | Full |
| Integrity | §5.2 failures | SECURITY_OFFICER; auto-incident per ASM-113 | Full |
| Availability | Intake daily health band DEGRADED/UNAVAILABLE, epoch-key horizon < 2 epochs on any channel, Triage Set below 2 eligible members | SYS_ADMIN + SECURITY_OFFICER; OVERSIGHT for Triage Set/runway (RVW-C-18) | Full (daily band only for intake) |
| Governance | Operator statement overdue; External Watcher mismatch; custody exception activated; time-locked roster change pending; security floor not met | SECURITY_OFFICER + OVERSIGHT | Full |
| Audit | Chain break, witness failure, checkpoint gap | SECURITY_OFFICER + AUDITOR + OVERSIGHT | Full |

- **Alert lifecycle:** new → acknowledged (by whom) → investigating → resolved/false positive, with a mandatory resolution note (a typed category and a short text stored in the SECURITY stream; the note field is validated to reject content-like strings longer than 500 chars).
- Alerts never include report content or case references outside OVERSIGHT's view.

### 5.5 Audit-log verification
- **Per stream** (SECURITY, CASE, SYSTEM): chain head, last checkpoint sequence, last verified (hourly 24 h window; daily full, `20` AUD-004), witness cosignature status and lag, retention tombstones.
- "Verify now" runs `candorctl audit verify` and shows the result: checkpoint range, Merkle roots matched, signatures valid, witnesses valid.
- A failure shows the first failing checkpoint and opens an incident.
- **CASE stream verification is hash-only for SECURITY_OFFICER.** Payloads of CASE events are viewable only by AUDITOR/OVERSIGHT per `15`.

### 5.6 Incident handoff
"Open incident" creates an IR record (`31-INCIDENT-RESPONSE.md`) with selected SECURITY/SYSTEM events attached (schema-typed, scrubbed) and a severity preset from the alert family. There is no attachment of arbitrary files.

**Intake memory or packet capture (ADR-035 §4; RVW-C-04).** The incident screen offers "Request intake memory/packet capture" only as an approval object that requires (a) the organisation's IR lead and (b) an independent role (channel OVERSIGHT or external ombudsman) with step-up. The approval screen states: "A capture can include what sources type on the website and their passphrases. It will be encrypted to independent custodians, and sources will see an incident notice." On approval, the capture is encrypted to the independent custodians' keys (never to the requester), and the UI requires publication of the source-visible INCIDENT_NOTICE directory entry (text reviewed by the independent approver) before the capture tooling is unlocked.

```
| SecOps — Alerts                                                   [Filter v]     |
| Sev  Family        Summary                                   Day        State    |
| HIGH Integrity     Unlisted binary hash on intake-1          2026-09-30 New      |
| MED  Staff access  Insider-activity alert routed to OVERSIGHT 2026-09-29 Routed  |
| LOW  Auth          5 failed step-ups (user p-19c2)           2026-09-29 Ack'd    |
| [Acknowledge] [Open incident] [Resolve…]                                         |
```

## 6. ENTERPRISE MANAGEMENT UI (EM UI, C-34, EE)

### 6.1 Delivery and access
- A server-rendered web application served by C-34 over TLS on the customer's management network (or vendor-operated in MANAGED, ADR-024). It is not in the Trust Path.
- It has no source-facing function and never runs on Z-INTAKE (ENT-037).
- CSP: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'`.
- It has no third-party resources.
- **Fleet roles** (local to C-34):
  - FLEET_ADMIN: rollout, policy propose;
  - FLEET_POLICY_APPROVER: second approval for policy packs;
  - FLEET_VIEWER.
  All use hardware FIDO2 with attestation (ASM-114) and step-up for rollout and policy actions.

### 6.2 Fleet overview
Table: `instance_id` (opaque, first 8 hex characters shown), `display_label`, profile, release version, update lag (days), health summary (pass/warn/fail counts from the C-25 map), `onion_key_changed_unexpectedly` flag, `onion_key_age_bucket`, `cert_expiry_bucket`, policy bundle version, license state, `last_checkin_day`. **No onion addresses, hostnames of intake, tenant or channel names, user lists or case counts** (`21` §9.2).

### 6.3 Instance detail
- All §9.2 fields.
- A fixed notice in place of any address: "Onion address: **not stored in Fleet Manager**. View it on the instance's Admin Console."
- **Label lint:** if `display_label` matches `[a-z2-7]{56}` or contains `.onion`, a blocking warning is shown and saving requires explicit override (ENT-039).
- **Commands** limited to the `21` §9.3 allow-list:
  - schedule update;
  - run self-test;
  - rotate internal certs;
  - apply policy bundle;
  - request support bundle (requires local approval and preview);
  - set update window.
- **Fleet limits (ADR-045; RVW-C-13):** the EM UI has **no** function to disable, pause or throttle intake, close a channel, lower a security floor, hold an instance below the floor, change routing, Triage Sets, COI maps or recipients, or raise `min_recipients`. Logging and retention can only be tightened. **Availability-affecting commands** (an update schedule that restarts intake, internal-certificate rotation) are queued as requests that execute only after local approval by the customer's OVERSIGHT or designated independent role (`15` DC-17); the EM UI shows "Awaiting customer independent approval" and never auto-executes them.

### 6.4 Tenants (opaque slots) and organization hierarchy
- **Tenants:**
  - Per instance, the EM UI shows tenant slots by opaque tenant ID, the customer-assigned risk tier (LOW/MODERATE) and the entitlements.
  - Tenant *names* are not stored (`21` §9.2).
  - Creating or deleting a tenant from the EM UI **queues a request** on the instance that requires DC-14 local confirmation by the customer TENANT_ADMIN.
  - The EM UI **refuses** to place a tenant marked HIGH risk, or of a high-risk customer type, on a shared instance, and shows "High-risk tenants require a dedicated instance (ADR-021)".
- **Organization hierarchy:**
  - A tree of customer-labelled nodes (e.g., Group → Region → Subsidiary) to which instances and tenant slots are attached.
  - Policy packs inherit **downward and can only be tightened** by child nodes.
  - A fixed banner reads: "The hierarchy controls fleet management only. It never gives a parent organization access to a subsidiary's reports or metadata" (THR-020; ADR-015).

### 6.5 Policy packs
- **Definition:** a signed bundle of configuration **constraints**: bounds, prohibitions, required values for SAFE/ADVANCED settings, and mandatory update windows.
- **Rules:**
  - Packs are **tighten-only** (`21` §9.3). They can never enable a DANGEROUS setting or relax a local restriction.
  - The authoring UI validates this and shows a diff per instance ("will tighten: `logging.retention_days` max 30 → 14"). Keys that affect availability or routing (e.g., `intake.min_recipients`, `authz.break_glass`, `backup.retention_days`, channel settings) are not fleet-settable at all (ADR-045).
  - Publishing needs FLEET_ADMIN + FLEET_POLICY_APPROVER.
  - The instance agent verifies the signature and class and refuses non-conforming items. The refusal report is shown in the EM UI per instance.
- **Rollout:** staged by hierarchy node or instance group, with a conflict report.

### 6.6 License
- Offline license files (C-35) are uploaded or distributed through the fleet. The UI shows entitlements, expiry and instance binding. There is **no phone-home**.
- License expiry or invalidity **never disables source intake, decryption, case access, export or security updates**. Only EE modules degrade (for example SIEM exporter, connectors, HA orchestration). The UI states this explicitly.

### 6.7 Update rollout
- **Target selection:** from the **public TUF repository only**, with signature, transparency-log inclusion, witness cosignature and reproducibility attestations displayed (as §4.6).
- **Waves:** customer-defined groups (e.g., "canary: 2 instances", then "remaining"), windows and pause/resume. Every wave installs the same artifact hash (ADR-022). The UI shows that hash.
- **Not available:** custom builds, per-instance artifacts, downgrade below the TUF minimum, holding any instance below the signed security floor (ADR-040), holding any instance more than 30 days without the instance's own alert (ENT-040).
- **Status:** per instance: scheduled / downloading / verified / applied / failed (with verification-failure reason), and update lag.

### 6.8 Support bundles and fleet audit
- Support-bundle requests show state (awaiting local approval → previewed → released) and never auto-release.
- The fleet audit log records all fleet-operator actions (who, what, when) and is exportable to the customer.

## 7. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| AUI-001 | The ADMIN UI SHALL display no report content, case titles, source answers, attachments, identity data or per-case metadata, and SHALL show the fixed "Administrators hold no case keys" statement on the dashboard. | ADR-015; INC-70 | THR-018 | C-19 | TST: UI crawl with canary case data → 0 hits; INSP |
| AUI-002 | Admin accounts SHALL NOT hold case-key wraps or publish member epoch keys. Desk in admin mode SHALL refuse to publish member epoch keys. | ADR-015; ADR-030; `15` §5.7 | THR-018 | C-19, C-15, C-11 | TST: admin account key-directory entries = none; ST: attempt publish → rejected |
| AUI-003 | The ADMIN UI SHALL provide no impersonation, "log in as", key-factor reset yielding keys, user case-list view, or membership export outside the channel view. | INC-69, INC-70; REQ-H-68 | THR-018, THR-021 | C-19, C-22 | INSP: feature review; ST: API probe for such endpoints |
| AUI-004 | Role assignment and enrollment approval SHALL require DC-07. The UI SHALL block role combinations violating `15` §5.1 static separation of duties. | `15` DC-07; INC-68 | THR-018, THR-022 | C-19, C-22 | TST: SoD negative tests |
| AUI-005 | Enrollment approval SHALL display authenticator attestation (AAGUID, model, firmware status) and SHALL block authenticators failing the ASM-114 allow- or deny-lists in HIGH and GOV profiles. | ASM-114; INC-61 | THR-022 | C-19, C-21 | TST: deny-listed AAGUID fixture |
| AUI-006 | Suspension (formerly deactivation) SHALL be immediate by a single USER_ADMIN or SCIM/HR/IdP signal, SHALL revoke sessions but keep keys and wraps intact, SHALL notify OVERSIGHT content-free, and SHALL display cases whose key-holder count is below 2 (count only); key-wrap deletion SHALL be possible only via DC-15 with a 7-day cooling-off (amended, ADR-044 §1). | ASM-122; `15` §4.6; ADR-013; ADR-044 §1; RVW-C-03 | THR-042, THR-022 | C-19 | TST |
| AUI-007 | Channel membership, Triage Set and role-label changes SHALL require DC-08 (≥ 1 independent approver) and SHALL be pending until signed by a CIK holder (Triage Set or OVERSIGHT); additions, label changes and COI loosening SHALL show the 72 h (GOV/HIGH 7-day) time lock with effective date, objection control and weekly publication slot; removals and tightening SHALL apply immediately (amended, ADR-036 §1–§2, §7). | ADR-030; ADR-036; REQ-H-62 (INC-62); RVW-A-05; RVW-C-05 | THR-046, THR-018 | C-19, C-15, C-14 | TST: unsigned change not published; addition not used for sealing before the time lock ends; objection blocks activation; removal immediate |
| AUI-008 | The channel list SHALL show channel type, Triage Set custody state and availability state per ADR-030/ADR-037 (accepting / unavailable — no eligible Triage Set member / warning — Triage Set below 2 / custody exception active) and each member's epoch-key horizon, and SHALL NOT show intake counts (amended). | ADR-030; ADR-037; ADR-043 | THR-046, THR-032 | C-19, C-25 | TST: fixtures for each state |
| AUI-009 | The COI map editor SHALL require DC-08 (loosening time-locked), SHALL NOT offer relational subjects describing the source, SHALL preview the resulting first readers per category and flagged role, and SHALL warn when any combination leaves 0 eligible Triage Set members (amended). | ADR-015; ADR-030; ADR-036 §2; ADR-037; RVW-B-03; INC-22 | THR-020 | C-19 | TST |
| AUI-010 | The questionnaire builder SHALL restrict field types per `11-FRONTEND-SOURCE.md` §7 S05, reject identity fields in ANONYMOUS-capable channels, require labels and help text, and preview no-JS rendering at 320 px and 1280 px. | REQ-H-05; SOPS-021; 508 §504 [B-CO-32] | THR-040 | C-19 | TST: builder negative tests; a11y check of generated form |
| AUI-011 | Channel settings SHALL NOT allow editing or removal of core `sops.*` guidance keys. Only placeholders and added cards are editable. | `05` SOPS-028; ADR-020 | THR-035 | C-19 | TST |
| AUI-012 | Key ceremonies SHALL be guided step-by-step with named participants, per-step step-up confirmation, no skipping, zeroization on abort, and a signed transcript logged as a SECURITY event. Private key material SHALL never be displayed. | ADR-013; ADR-028; B-GL-30 (CoverDrop offline provisioning) | THR-013, THR-018 | C-19, C-29 | DEMO: ceremony rehearsal; TST: abort leaves no key files |
| AUI-013 | Recovery Quorum setup SHALL run only via the offline ceremony tool, SHALL be classed DANGEROUS (DC-09 + cooling-off) in CE/EE and performed by default at installation in GOV with independent-role custodians (disabling it in GOV DANGEROUS), and on activation SHALL update the source-visible escrow statement via C-14 (amended, ADR-044 §3). | ADR-013; ADR-044 §3; `05` SOPS-007; RVW-C-14 | THR-013, THR-040 | C-19, C-28, C-14 | TST: S03 escrow text changes after activation |
| AUI-014 | The configuration UI SHALL apply the §4.5 friction per class: SAFE (diff, session); ADVANCED (step-up, reason ≥ 20 chars, SECURITY_OFFICER notice); DANGEROUS (DC-09, impact statement, typed confirmation, cooling-off ≥ 24 h (default 72 h) with veto, persistent chip, 90-day re-confirmation). | ADR-013; THR-035; B-SD-13 (SEC-01-010 re-auth) | THR-035, THR-018 | C-19, C-22 | TST: each class path; veto during cooling-off cancels change |
| AUI-015 | Not-available capabilities (§4.5; formerly "FORBIDDEN", not a configuration class per ADR-046 §6) SHALL have no UI, CLI, API or config-file path, and the UI SHALL list them on an "About security limits" page. | ADR-016; ADR-023; ADR-002 | THR-035, THR-016 | C-19 | ST: config fuzzing for forbidden keys → rejected; INSP |
| AUI-016 | `candorctl config apply` SHALL enforce the same classes, approvals and cooling-off as the UI. Config drift from the approved state SHALL fail self-test. | THR-035; INC-59 | THR-035 | C-19, C-25 | TST: CLI parity tests; drift fixture |
| AUI-017 | The Updates screen SHALL display, per available target, TUF signature threshold, transparency-log inclusion, witness cosignatures and ≥ 2 matching reproducible-build attestations, and SHALL block installation when any is missing. | ADR-022; ASM-108, ASM-110; INC-38, INC-48 | THR-025, THR-024 | C-19, C-32 | TST: fixtures missing each element → install blocked |
| AUI-018 | The Updates screen SHALL NOT offer package upload, install-from-URL, downgrade below the TUF minimum or per-host builds. Holds SHALL be limited to 30 days, and releases raising the security floor SHALL NOT be holdable (amended, ADR-040). | ADR-022; ADR-040; ENT-040 | THR-025 | C-19 | INSP; TST |
| AUI-019 | The Backups screen SHALL show the contents inventory including what is intentionally excluded (case keys, member private keys, epoch private keys) and the last restore-test result. Production restore SHALL require DC-09 friction. | ADR-025; INC-55 | THR-017, THR-013 | C-19, C-27 | TST; INSP |
| AUI-020 | The self-test dashboard SHALL present every §4.8 check with status in text and icon, last run and evidence summary. Class-C failures SHALL auto-open an incident per ASM-113 and display its ID. | ASM-103..107, -116..-118, -121, -122; ADR-028 | THR-035, THR-025 | C-19, C-25 | TST: each check fixture; incident creation test |
| AUI-021 | Support bundles SHALL be generated locally, scrubbed (tokens, content, onion addresses, Z-INTAKE hostnames, user identities), fully previewable, and released only after explicit approval. | INC-56 (REQ-H-56) | THR-027, THR-016 | C-19, C-36 | TST: canary scrub test |
| AUI-022 | Aggregate report-derived counts in the ADMIN UI SHALL follow CR-2, i.e., the `24` §TEL regime (k = 10, ≥ one calendar month, complementary suppression, no medians/ratios for cells < k, no per-channel metrics below 3 cases/month); no daily counts SHALL be shown (amended, ADR-046 §5). | INC-70, INC-74; ADR-046 §5; RVW-B-07; RVW-B-08 | THR-039 | C-19 | TST: suppression unit tests |
| AUI-023 | Admin sessions SHALL follow `15` §4.6 (idle 10 min, absolute 2 h, one concurrent session). Locking SHALL clear the UI. | `15` §4.6; ADR-029 | THR-022 | C-19 | TST |
| AUI-024 | Every state-changing admin action SHALL create a SECURITY event whose ID is shown in the success message. | ADR-016 | THR-018, THR-037 | C-19, C-24 | TST |
| AUI-025 | Step-up confirmation dialogs SHALL display the human-readable operation descriptor that is hashed into the WebAuthn challenge. | `15` §4.7; B-SD-13; ADR-029 | THR-022, THR-007 | C-19 | TST: descriptor shown = descriptor signed |
| AUI-026 | The ADMIN UI SHALL meet WCAG 2.2 AA and EN 301 549 clause 11. The questionnaire builder SHALL meet Section 508 §504 / EN 301 549 11.8 authoring-tool requirements. | B-CO-32, B-CO-34 | — | C-19 | TST: automated a11y; DEMO: AT test |
| AUI-027 | The custody register (§4.3a) SHALL show each Triage Set device's custody class and attestation; enabling or keeping an INDEPENDENT channel whose Triage Set lacks attested independent custody SHALL be DANGEROUS (DC-16) and disclosed to sources. | ADR-043; RVW-C-01; RVW-A-24 | THR-018, THR-041 | C-19, C-14 | TST: INDEPENDENT channel with one "unknown" device → activation requires DC-16 with cooling-off; descriptor disclosure present |
| AUI-028 | The dashboard SHALL show a persistent small-organisation "reduced separation of duties" banner whenever that mode is active; the mode SHALL NOT be activatable without an external OVERSIGHT enrolled, and SHALL be reflected in the operator statement and source-facing S03. | ADR-045; RVW-C-09 | THR-018, THR-040 | C-19, C-14 | TST: < 4 distinct persons → mode required; no external OVERSIGHT → activation refused; banner and S03 text present |
| AUI-029 | Enrollment SHALL be incomplete until ≥ 2 hardware authenticators are registered, and the UI SHALL flag accounts sharing an authenticator attestation serial as one person. | ADR-044 §2; RVW-C-03; RVW-C-09 | THR-042, THR-022 | C-19, C-21 | TST: single-authenticator account cannot receive wraps; duplicate serial flagged |
| AUI-030 | The Triage Set editor SHALL require ≥ 2 members with independent-body role labels (or channel owner + OVERSIGHT), SHALL restrict CIK holding to the Triage Set and OVERSIGHT, and SHALL show OVERSIGHT certification of role labels. | ADR-036 §1, §3; ADR-037 §1; RVW-B-02 | THR-020, THR-046 | C-19, C-14 | TST: one-member Triage Set rejected; non-triage member Desk never receives CIK; uncertified label shown as such |
| AUI-031 | The operator-statement ceremony SHALL require a k-of-n quorum incl. ≥ 1 independent role, SHALL show the due date from day 21 and a persistent warning after day 30, and SHALL include the small-organisation statement when applicable. | ADR-035 §2; ADR-045; RVW-A-01 | THR-025, THR-026 | C-19, C-14 | TST: quorum without independent signer rejected; day-31 fixture → warning in ADMIN/SOC and `11` WB-1 shown |
| AUI-032 | The Updates screen SHALL display Platform Manifest verification and the current security floor, and SHALL show emergency-release cooling and signer organisations. | ADR-040; RVW-A-12; RVW-A-16 | THR-024, THR-025 | C-19, C-32 | TST: manifest hash mismatch → blocked; floor-raising release not holdable |
| AUI-033 | The Backups screen SHALL show Erasure Key Vault DR replication and erasure-log state and SHALL require an infrastructure-backup exclusion attestation, displaying the 14-day-bound warning until attested. | ADR-044 §4; RVW-C-06; RVW-C-07 | THR-017 | C-19, C-27 | TST: missing attestation → persistent warning and configuration-digest text; restore drill applies erasure log before serving |
| AUI-034 | Support bundles SHALL apply semantic scrubbing: configuration as `{key, class, value_hash}` (enums/booleans excepted), SYSTEM events truncated to the hour, relay/import events excluded, no staff pseudonyms. | RVW-B-18; INC-56 | THR-027, THR-016 | C-19, C-36 | TST: seeded config with channel names/COI/calendars → none in bundle; no `sys.relay_*` events; timestamps at hour precision |
| AUI-035 | The self-test dashboard SHALL include the ADR-035/036/040/043/044 checks listed in §4.8. | ADR-035; ADR-036; ADR-040; ADR-043; ADR-044 | THR-025, THR-035, THR-043 | C-19, C-25 | TST: failure fixture per new check |
| SOCUI-012 | Intake memory/packet capture SHALL be requestable only as an approval object requiring the IR lead and an independent role, SHALL encrypt captures to independent custodians, and SHALL require publication of an INCIDENT_NOTICE before capture tooling unlocks. | ADR-035 §4; RVW-C-04 | THR-018, THR-014 | C-25, C-19, C-14 | TST: IR-lead-only approval → capture locked; with independent approval but no notice → locked; capture ciphertext not decryptable by requester |
| SOCUI-013 | The SOC UI SHALL raise Governance alerts for overdue operator statements, External Watcher mismatches, custody exceptions, pending time-locked roster changes and unmet security floors, routed to SECURITY_OFFICER and OVERSIGHT. | ADR-035; ADR-036; ADR-040; ADR-043 | THR-025, THR-046 | C-25 | TST: fixture per alert |
| EMUI-013 | Availability-affecting fleet commands SHALL be queued and executed only after local approval by the customer's OVERSIGHT or designated independent role (DC-17); the EM UI SHALL NOT auto-execute them. | ADR-045; RVW-C-13 | THR-032, THR-020 | C-34, C-19 | TST: cert-rotation command without local DC-17 approval never executes |
| EMUI-014 | The EM UI SHALL NOT allow any instance or ring to be held below the signed security floor. | ADR-040; RVW-A-13 | THR-025 | C-34 | TST: hold request below floor rejected by UI and agent |
| SOCUI-001 | The SOC UI SHALL display only SECURITY and SYSTEM events rendered from the allow-listed schemas, and SOURCE-SENSITIVE data only as `20` §5.4 k-thresholded counters. | ADR-016; INC-60 | THR-016, THR-038 | C-25, C-24 | TST: schema-conformance of rendered fields; canary test |
| SOCUI-002 | Intake-derived data SHALL be displayed only as a global daily health band; no request-rate bands, PoW levels, queue states or submission counts SHALL be displayed. There SHALL be no per-circuit, per-request or per-submission views (amended, ADR-038 §5, ADR-046 §5). | ADR-010; ADR-016; ADR-038 §5; ADR-046 §5; RVW-B-07; RVW-A-27 | THR-011, THR-039 | C-25 | TST: API contract; INSP |
| SOCUI-003 | The Integrity view SHALL show running-binary hash status (ASM-116), TUF freshness, file integrity, Secret Placement Manifest, onion key unexpected change, key-directory consistency and witness status, with explanatory impact text for failures. | ASM-107, ASM-111, ASM-116; ADR-028 | THR-025, THR-044 | C-25 | TST: failure fixtures |
| SOCUI-004 | Staff case-access anomaly alerts (AUD-008 and similar) SHALL be routed to OVERSIGHT. The SOC UI SHALL show only a weekly count of alerts of that family routed, without day, case references or user identity, unless the viewer holds OVERSIGHT (amended, RVW-B-31). | REQ-H-69 (INC-69); INC-68 | THR-019, THR-038 | C-25, C-24 | TST: role-based rendering |
| SOCUI-005 | Alert resolution SHALL require a category and a note of ≤ 500 characters, stored in the SECURITY stream. | ADR-016; INC-60 | THR-016 | C-25 | TST |
| SOCUI-006 | The Audit view SHALL show per-stream chain head, checkpoints, last verification, witness status and lag, SHALL offer "Verify now" (`candorctl audit verify`), and SHALL open an incident on failure. | `20` AUD-002..AUD-004; ASM-048; ADR-016; INC-68 | THR-037, THR-038 | C-25, C-24 | TST: tampered chain fixture |
| SOCUI-007 | SECURITY_OFFICER SHALL verify the CASE stream by hash only. CASE payloads SHALL be viewable only by AUDITOR/OVERSIGHT. | `15` §5.1; ADR-016 | THR-019 | C-25, C-22 | TST: role tests |
| SOCUI-008 | Audit export SHALL require DC-10 and produce an encrypted, signed file with checkpoint proofs. | `20` AUD-009; ADR-018 | THR-029 | C-24, C-22 | TST |
| SOCUI-009 | Incident handoff SHALL attach only schema-typed, scrubbed events and SHALL NOT accept arbitrary file attachments. | INC-56 | THR-016 | C-25 | TST |
| SOCUI-010 | The SOC UI SHALL persistently display active DANGEROUS settings and pending cooling-off changes. | THR-035; ADR-013 | THR-035 | C-25, C-19 | TST |
| SOCUI-011 | The SOC UI SHALL meet WCAG 2.2 AA, with severity conveyed by text and icon, not color alone. | B-CO-28 | — | C-25 | TST |
| EMUI-001 | The EM UI SHALL NOT store, request or display onion addresses, onion keys, Z-INTAKE hostnames or IPs, tenant or channel names, user lists, case counts beyond TEL rules, or CASE events. | ADR-022; `21` §9.2; INC-03 | THR-026, THR-027 | C-34 | TST: schema inspection; UI crawl with canary onion string → 0 |
| EMUI-002 | The EM UI SHALL lint `display_label` for v3-onion patterns and `.onion` and SHALL require explicit override to save. | `21` ENT-039; ADR-022; INC-03 | THR-026 | C-34 | TST |
| EMUI-003 | Fleet commands offered by the EM UI SHALL be limited to the `21` §9.3 allow-list. The UI SHALL have no function to read cases, add members, change routing, Triage Sets or COI maps, disable or throttle intake, lower or hold below a security floor, raise `min_recipients`, enable clearnet, logging or escrow, or deliver code (amended, ADR-045, ADR-040). | `21` §9.3; ADR-022 | THR-025, THR-027 | C-34 | ST: API probing; INSP |
| EMUI-004 | Update rollout SHALL select only public TUF targets, SHALL display signature, log inclusion, witness and reproducibility status and the single artifact hash for all waves, and SHALL NOT allow custom or per-instance artifacts or downgrades. | ADR-022; INC-15; INC-49 | THR-025 | C-34, C-32 | TST |
| EMUI-005 | Policy packs SHALL be tighten-only for logging and retention and SHALL NOT contain availability- or routing-affecting keys (ADR-045), SHALL require FLEET_ADMIN + FLEET_POLICY_APPROVER, SHALL show per-instance diffs, and SHALL display instance-side refusal reports. | `21` §9.3; THR-035; ADR-022 | THR-035 | C-34 | TST: pack that relaxes a bound or enables DANGEROUS → rejected in UI and by agent |
| EMUI-006 | The organization hierarchy SHALL govern only fleet management. The UI SHALL state that it grants no access to reports or metadata of child nodes. | ADR-015; INC-22 | THR-020 | C-34 | INSP; TST: no data path from hierarchy to instance content APIs |
| EMUI-007 | Tenant creation or deletion SHALL be queued for DC-14 local confirmation. The EM UI SHALL refuse to place HIGH-risk tenants on shared instances. | ADR-021; `15` DC-14 | THR-045 | C-34 | TST |
| EMUI-008 | License expiry or invalidity SHALL NOT disable intake, decryption, case access, export or security updates. The UI SHALL state which EE modules degrade. Licensing SHALL require no phone-home. | ADR-020; ADR-023 | THR-032 | C-34, C-35 | TST: expired license fixture → core functions operate |
| EMUI-009 | EM UI access SHALL use hardware FIDO2 with attestation and step-up for rollout and policy actions, and a strict CSP with no third-party origins. | ASM-114; INC-46 | THR-022, THR-036 | C-34 | TST: header test; auth tests |
| EMUI-010 | Support-bundle requests from the EM UI SHALL NOT auto-release. Release SHALL require local approval after preview (AUI-021). | INC-56 | THR-027 | C-34, C-19 | TST |
| EMUI-011 | All fleet-operator actions SHALL be recorded in a fleet audit log exportable to the customer. | ADR-016 | THR-027 | C-34 | TST |
| EMUI-012 | The EM UI SHALL meet WCAG 2.2 AA. | B-CO-28 | — | C-34 | TST: automated a11y; DEMO |

## 8. Residual risks and limitations

1. **SYS_ADMIN can deploy or run unreviewed code on Z-INTAKE**, exposing future Tier W submissions (ASM-013). ASM-116 hash statements and External Watchers (ADR-035 §1) detect modified static assets and running manifests, not selector-based memory capture; the operator statement is a signal, not a guarantee.
2. **Admins can deny service or destroy data** (ASM-044). Backups and dual control reduce, but do not remove, this risk.
3. **Cooling-off periods delay emergency hardening changes** only for DANGEROUS settings. Tightening is never DANGEROUS by design, but misclassification in 32 could create friction.
4. **Anomaly alerts** are threshold-based and evadable by slow insiders (INC-68 class).
5. **Fleet Manager compromise** can delay updates (bounded by the 30-day instance alert), mislabel health or phish fleet operators. It cannot read content.
6. **Role labels and channel structure are public** in C-14 (ADR-030 privacy effect); weekly publication slots hide timing, not the changes themselves (RVW-B-32).
7. **Custody records are declarations.** The custody register cannot verify how a device is really managed (ADR-043 residual).
8. **Small organisations** still concentrate trust; the external OVERSIGHT and the disclosure are the only anchors (ADR-045; RVW-C-09).
9. **Time locks delay legitimate staffing** by 72 h or 7 days; emergency staffing must use existing members or break-glass.

## 9. Open issues

- **OI-13-1:** Align fleet roles (FLEET_ADMIN, FLEET_POLICY_APPROVER, FLEET_VIEWER) with `15-AUTHENTICATION-AUTHORIZATION.md`, which currently lists no fleet roles.
- **OI-13-2:** `32-OPERATIONS.md` (CFG catalogue) is not yet written. §4.5's illustrative mapping must be reconciled with it.
- **OI-13-3:** Decide the 90-day auto-revert behavior for each DANGEROUS setting. Some, such as Recovery Quorum, cannot safely auto-revert and should instead escalate to OVERSIGHT.
- **OI-13-4:** Define the SOC UI's handling in EE deployments where SIEM (C-26) is the primary console. This spec keeps the local UI authoritative.
