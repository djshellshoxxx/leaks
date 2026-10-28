# 31 — Incident Response

Status: Draft v1.2 (final consistency pass: ADR-047, cross-document requests) · previously v1.1 (revision round 2: ADR-034..046) · Edition applicability: both (vendor PSIRT duties apply to the Candor project and EE vendor; operator duties apply to every deployment) · Owner: Security Team (operator IR) / Candor PSIRT (vendor IR)

## 1. Purpose and scope

This document defines incident response (IR) for Candor deployments and for the Candor project as software vendor:
- a severity model weighted towards source anonymity;
- IR roles, including conflict-of-interest (COI) exclusion;
- how to **preserve evidence without creating new source metadata**;
- how to **notify sources safely**: only through the platform (onion site banner, inbox, signed notices), never through any identity channel;
- regulatory notification hooks;
- twenty playbooks (PB-15..PB-20 added in revision round 2 for the organisation-as-adversary cases of RVW-C-22), each structured DETECT / CONTAIN / PRESERVE / NOTIFY / ROTATE / RECOVER / LESSONS:

| ID | Playbook |
|---|---|
| PB-01 | Source anonymity suspected compromised |
| PB-02 | Application compromised |
| PB-03 | Database stolen |
| PB-04 | Encryption key stolen |
| PB-05 | Recipient credential stolen |
| PB-06 | Malicious administrator |
| PB-07 | Ransomware |
| PB-08 | Supply-chain compromise |
| PB-09 | Malicious release |
| PB-10 | Onion key compromise |
| PB-11 | HSM compromise |
| PB-12 | Physical seizure |
| PB-13 | Backup theft |
| PB-14 | Recipient workstation malware |
| PB-15 | Organisational suppression / mass key loss |
| PB-16 | IdP / SCIM / SOAR compromise or attribute poisoning |
| PB-17 | Unauthorized roster change, role-label change or orphan re-key |
| PB-18 | Recipient endpoint tampering by the organisation (MDM/EDR/IRM/VDI) |
| PB-19 | Leadership-implicated incident (organisation as adversary) |
| PB-20 | Notification-transport or SIEM-sink compromise |
| PB-21 | Erasure Key Vault loss or tampering (ADR-047(7)) |
| PB-22 | Key Directory freshness or attestation failure (channel fail-closed, ADR-047(4)) |

Disaster-recovery mechanics are in `19-BACKUPS-DR.md` (DR-P*). Seizure yields are in `17-INFRASTRUCTURE.md` §8. Release and update mechanics are in `33-RELEASE-UPDATE-SECURITY.md`.

## 2. Context and dependencies

| Source | Use |
|---|---|
| ADR-002, 005, 007, 008, 010, 013, 014, 015, 016, 017, 022 | Modes; source passphrase; endpoint keys; epoch keys; timing; recovery; sealed identity; admin ≠ case access; audit classes; content-free notifications; TUF |
| `02-THREAT-MODEL.md` | THR-* definitions |
| `04-CRYPTOGRAPHY.md` | Key types and rotation procedures referenced by ROTATE steps |
| `14-CASE-MANAGEMENT.md`, `15-AUTHENTICATION-AUTHORIZATION.md` | Case freeze, ACL changes, revocation |
| `16-TOR-I2P.md` | Onion rotation mechanics, standby address |
| `20-LOGGING-AUDITING.md` | Evidence sources and their privacy limits |
| `25-COMPLIANCE.md` | Legal notification duties |
| `32-OPERATIONS.md` | Self-test alerts that feed DETECT; small-organisation mode (§4.5) |
| ADR-035(4), 036, 037, 043, 044, 045 (revision round 2) | Independent approval and INCIDENT_NOTICE for intake memory/packet capture; roster time-locks; Triage Set and blinded COI; independent-custody devices; key-access continuity; break-glass independent approver and small-organisation mode |

Research basis:

| Incident / research | What it teaches |
|---|---|
| Freedom Hosting and Playpen: servers seized and then operated against users (INC-27, INC-28) | Seized servers can be run against their visitors |
| Riseup sealed warrants and a lapsed canary (INC-07) | Operators may be gagged |
| Okta support-system HAR leak (INC-56) and Storm-0558 crash dump (INC-58) | Diagnostics carry secrets |
| LastPass (INC-55) | Backups are production |
| xz, SolarWinds, 3CX, CCleaner, NotPetya (INC-37, INC-38, INC-41, INC-48, INC-49) | Supply-chain and update-channel compromise |
| Barclays CEO attempt to unmask a whistleblower (INC-22) | Executives seeking source identity |
| SecureDrop GHSA-rqwh (onion client-auth keys copied to Monitor) [B-SD-22] | Secret placement must be verified |
| SecureDrop advisory practice: detailed root cause [B-SD-20] | Publish root cause |
| R4: keep a standby onion address for DoS or seizure events [B-AN-26] | Pre-generate a standby address |
| EU CRA reporting obligations from 11 Sep 2026 [B-CR-50, B-CR-51]; GDPR Art 33/34 [B-CO-09]; NIS2 Art 23 [B-CO-47] | Regulatory notification duties |

## 3. IR principles specific to Candor

1. **Source safety outranks forensic completeness.** Never collect or create data that could identify a source in order to investigate an incident.
2. **IR does not grant case access.** Admins and the security team hold no case keys (ADR-015). IR SHALL NOT use break-glass to read report content, except in PB-01 or PB-14 when the case's own members decide it is needed, under dual approval, and it is recorded.
3. **Fail closed.** When the intake may be live-compromised, stop intake (the onion goes unreachable). There is no clearnet alternative (ADR-002).
4. **Assume seizure can become "seized and operated"** (INC-28). Rotate every key the adversary could hold, and tell sources through channels the adversary does not control (C-37 site, Source App verified notices, signed key-directory entries).
5. **Conflict of interest applies to IR.** Persons implicated in reports, or in the incident, are excluded from the IR team and from notifications (THR-020, INC-22).
6. **Honesty.** Notices state what may have been exposed and what was not. They never say "no data was affected" unless that is verified.
7. **IR is not a pretext** (RVW-C-04, ADR-035(4)). The captures that could yield Tier W plaintext, passphrases or source timing (E-MEM of H-INTAKE, E-NET on N-INTAKE-EXT or RCP-ONION uplinks) require an **independent approver** in addition to the organisation's own IR roles, are encrypted to custodians that include that approver, and are **self-disclosing**: the capture tool publishes a source-visible `INCIDENT_NOTICE` entry in the key directory before it runs.

## 4. Roles

| Role | Held by | Duties | Exclusions |
|---|---|---|---|
| IR Lead | Security team member on the IR rota | Declares the incident, sets severity, owns the timeline, approves evidence capture | Must not be a channel member of an affected case (avoids content bias) |
| Platform Admin(s) | Candor admins (≥ 2) | Execute containment and rotation with `candorctl ir …` | An admin implicated in PB-06 is replaced by the Emergency Admin set |
| Emergency Admin set | Persons appointed by OVERSIGHT (not by the admin chain), with hardware tokens sealed in a two-person safe; defined as the platform break-glass admin set in `15-AUTHENTICATION-AUTHORIZATION.md` §5.6 (v1.0 referred to an undefined "break-glass admin set") | Take over platform administration in PB-06 and PB-19 | Must not report to an implicated person |
| Independent Approver | Channel OVERSIGHT, the GOV inspector general's designated independent official, or an external ombudsman/counsel (ADR-035(4), ADR-045); never a person in the management or legal reporting line of the organisation | Co-approves E-MEM of H-INTAKE and E-NET captures; holds one share of every intake capture key; receives the capture evidence precondition (§6.1) | Anyone named in the COI map for affected cases |
| Channel Owner(s) | Recipients owning affected channels | Decide on SSN-ACCOUNT notices; case-level containment; any content-dependent assessment | COI list applies |
| DPO / Privacy | Data protection officer | Breach-risk assessment; regulator and data-subject notification decisions | — |
| Legal Counsel | Internal/external counsel (tagged `internal` or `external`; only external counsel counts as independent, RVW-C-10) | Legal holds, compelled-disclosure handling, seizure interaction, anti-retaliation | — |
| Independent Oversight | Audit committee / ombudsman (as configured in routing, ADR-015) | Informed of SEV-0/1 involving executives or admins; **runs IR** in PB-19 with an external retained IR firm under a pre-signed engagement letter | Anyone named in the COI map for affected cases |
| Candor PSIRT | Candor project / EE vendor | Product vulnerabilities, malicious releases, CRA reporting, advisories | — |
| Communications | Designated | Clearnet statements (C-37) | Receives no case details |

### 4.1 Minimal IR roles for small organisations (RVW-C-22, ADR-045)

In small-organisation mode (`32-OPERATIONS.md` §4.5) the full role set cannot be staffed. The minimum is:

| Role | Small-organisation holder |
|---|---|
| IR Lead | The operator (SYS_ADMIN) or, if the operator is implicated, the external OVERSIGHT holder |
| DPO / Legal | One person (or the external counsel), recorded as combined |
| Independent Approver | The **external** OVERSIGHT holder required by small-organisation mode; never waivable |
| Platform Admin | The operator, plus the MANAGED/consortium operator or a pre-contracted external technician for PB-06/PB-19 |
| Emergency Admin set | The external OVERSIGHT holder holds the sealed emergency tokens |
| IEK custodians | 2-of-3: operator, combined DPO/Legal, external OVERSIGHT |

Every combination is disclosed in the Operator Statement ("Reduced separation of duties"). Tabletop cadence is twice yearly (IR-029).

## 5. Severity model (anonymity-weighted)

| SEV | Definition | Examples | Declare within | First containment within |
|---|---|---|---|---|
| SEV-0 | Source identity or report content likely exposed, or a live capability to expose it exists now | Intake live-compromised (Tier W exposure); recipient device + token stolen; insider leaked identity; malicious release installed | 15 min of detection | 1 h |
| SEV-1 | A capability to expose exists but is not live, or metadata of sources is exposed | DB dump stolen; onion key copied; admin credential stolen; backup set + IRK share compromised | 1 h | 4 h |
| SEV-2 | Trust-path integrity or availability incident without an exposure path | Ransomware on core with clean backups; DoS; HSM failure | 4 h | 24 h |
| SEV-3 | Minor or hygiene issue | Single misconfiguration caught by the checker; expired certificate | 1 business day | per plan |

Any incident involving a possible link between a person and a report is at least SEV-1.

## 6. Evidence preservation without creating source metadata

### 6.1 Evidence classes

| Class | Examples | Contains source-sensitive data? | Handling |
|---|---|---|---|
| E-SYS | journald, SECURITY/SYSTEM audit, self-test history, config snapshots, package lists, attestation quotes | No (by design: allow-listed fields, ADR-016) | Hash, sign, store in the IR evidence vault |
| E-HOST | Disk images of H-CORE, H-MON | Server metadata (17 §8.5–8.6) | Encrypt at capture to the IR Evidence Key; vault |
| E-INTAKE | Disk image of H-INTAKE | Intake store metadata, onion key | As E-HOST; **onion key considered compromised thereafter** (rotate) |
| E-MEM | RAM image of H-INTAKE | **Yes**: Tier W plaintext in flight and drafts (ADR-034), passphrases, derived source keys | Capture only with IR Lead + DPO + **Independent Approver** (ADR-035(4)), only if the forensic value outweighs creating a new copy of source data, and only after the evidence precondition below. Encrypted in the capture tool before writing (never write plaintext RAM to disk) to a **one-time capture key** split 2-of-2 between the Independent Approver and the DPO (not the standing IEK). The tool publishes an `INCIDENT_NOTICE` (§7.1) before capture starts. Maximum retention 90 days unless under legal hold. Analysis only on an air-gapped forensic workstation in the presence of the Independent Approver or their delegate. Never shared with third parties |
| E-MEM-CORE | RAM image of H-CORE | Staff session tokens, no report plaintext | As E-HOST |
| E-NET | Packet captures | On N-INTAKE-EXT: **Tor traffic timing = source timing metadata** | Forbidden on N-INTAKE-EXT and on RCP-ONION uplinks by default. Allowed on N-RELAY, N-CORE, N-MGMT and N-BAK (internal, ciphertext). An ext capture needs IR Lead + DPO + Legal + **Independent Approver**, the evidence precondition, headers only, ≤ 24 h, encrypted to a one-time capture key split with the Independent Approver, ≤ 30-day retention, and a published `INCIDENT_NOTICE` |
| E-CASE | Case content, exported evidence | Yes | Not IR evidence. Only case members may review it, inside Candor, recorded in the CASE audit |
| E-SRC | Submitted files (possible malware) | Yes: content and possibly identity | Never uploaded to public or third-party services (VirusTotal-class, cloud sandboxes, public hash lookups: a hash lookup reveals possession and can identify the document). Analysis only in C-17/C-18 or an air-gapped lab by case members |

**Evidence precondition for E-MEM/E-NET on the intake (RVW-C-04).** A SEV-0 declared by the organisation alone does not unlock these captures. The Independent Approver SHALL be shown at least one of: an `integrity.attestation` FAIL recorded by an H-MON administered per HUM-006; an External Watcher mismatch report (ADR-035(1)); a Platform Manifest or running-manifest mismatch; or an external vulnerability advisory affecting the running release. Without it, `candorctl ir capture` for these classes is refused. An attestation mismatch that an admin can induce (e.g., a modified kernel command line) is therefore not sufficient alone when the admin chain is the suspected party (PB-19).

### 6.2 Evidence handling rules

- **IR Evidence Key (IEK)**: an X-Wing keypair generated at install. Its private key is Shamir 2-of-3 split between the IR Lead, the DPO and an **independent holder** (OVERSIGHT or external counsel; in-house Legal only if no independent role exists, recorded as reduced separation) (RVW-C-04). All evidence except intake E-MEM/E-NET is encrypted to the IEK at the capture point (`candorctl ir capture …`); intake E-MEM/E-NET use the one-time capture key of §6.1.
- **Chain of custody**: every artifact gets a signed custody record containing SHA-256 and BLAKE3, capture tool version, operator identities (two), and UTC time of the **staff action**. Custody records are appended to the SECURITY audit stream (THR-037).
- **Do not enable debug or verbose logging** on Z-INTAKE during IR. Allowed alternative: `ir diagnostic mode`, which adds only allow-listed SYSTEM fields (process states, resource counters, error codes) and never request data, circuit IDs, timestamps finer than the incident window, or payloads. It auto-expires after 24 h.
- **No new timestamps of source actions** may be derived: do not correlate intake store `received_epoch_day` with host-level artifacts (for example filesystem inode times) to reconstruct exact submission times. Where filesystem timestamps are already present in an image, the analyst SHALL NOT extract them for data paths (analysis-tool profile excludes `/var/lib/candor/intake/**` timestamp extraction).
- **Chaff in intake images** (ADR-047(3)): intake store images contain chaff envelopes indistinguishable from real ones. Analysts SHALL NOT attempt to separate them or to count submissions from envelopes; affected-window assessments use days and import slots only.
- **Vendor support**: support bundles follow `32-OPERATIONS.md` §8 scrubbing. Vendors never receive E-MEM, E-INTAKE, E-CASE or E-SRC.
- **MANAGED** (ADR-047(10)): audit exports are encrypted to the customer-held audit export key, so the vendor's IR team cannot read them; the customer's IR Lead decrypts the needed audit extracts and shares only scrubbed findings with the vendor. Intake memory/packet capture on a vendor-operated intake requires the customer's independent approver as in §3 item 7, and the capture is encrypted to custodians that include a customer-side holder.
- **Destruction**: at incident close + legal hold release, evidence is crypto-erased (destroy the IEK-wrapped DEKs) and destruction is recorded.

### 6.3 IR tooling (`candorctl ir`)

```bash
set -euo pipefail
candorctl ir declare --sev 0 --title "intake attestation mismatch"         # opens IR record (SECURITY audit)
candorctl ir intake stop --reason "IR-2026-014"                              # fail closed: tor onion disabled, sealer stopped
candorctl ir isolate --host core --allow mgmt                                # nftables IR profile: only N-MGMT to IR workstation
candorctl ir capture disk --host intake --to /media/ir-vault --two-person     # encrypted to IEK on the fly
candorctl ir capture memory --host core --to /media/ir-vault --two-person     # H-MON-verified core capture
candorctl ir capture memory --host intake --to /media/ir-vault --two-person \
  --dpo-approval <token> --independent-approval <token> --evidence <record-id>   # appends INCIDENT_NOTICE first, then captures
candorctl ir freeze-config                                                   # blocks config changes except IR profile
candorctl update freeze                                                      # stops automatic updates (PB-08/PB-09)
candorctl ir notice draft --type SSN-GLOBAL --template compromise-intake-window
```

## 7. Notifying sources safely

### 7.1 Channels (the only permitted ones)

| Notice type | Delivered via | Audience | Authenticity |
|---|---|---|---|
| SSN-GLOBAL | A banner on every source-web page (landing, submission, login, inbox) of the affected channel(s) and a dedicated `/security-notice` page | All visitors, including sources whose devices are later inspected (the text must be safe to be seen) | Signed by ≥ 2 Channel Identity Keys or the org roster key. Published in the key directory (C-14). Tier V clients verify it; Tier W shows a fingerprint and the verification instructions |
| SSN-ACCOUNT | An E2EE message in the affected source accounts' inboxes, like a reply (to source keys), visible at next login (ADR-010: no push) | Specific sources | Signed by the channel identity; displayed with an "Official security notice" style |
| SSN-CLEARNET | A statement on the Clearnet Information Site (C-37) plus a signed text file, and the same statement in the key directory | Everyone, including sources who cannot reach the onion | OpenPGP/Sigstore-style signature by the org roster key; fingerprints published in advance |
| SSN-APP | Source App (C-03) shows verified notices fetched from the key directory | Tier V users | Verified against pinned trust anchors |
| INCIDENT_NOTICE (ADR-035(4)) | A key-directory entry type appended **automatically by the capture tool** before any intake E-MEM/E-NET capture; it carries the capture class, the capture day and the approver role labels (no reasons, no case references). Tier V clients and Desks surface it; Tier W shows the `capture-performed` banner for ≥ 90 days; External Watchers republish it | All sources and staff | Signed by the capture tool's directory key **and** cosigned by the Independent Approver's key; a capture without a published, cosigned entry is refused by the tool |

**Forbidden**: email, SMS, phone, postal mail, messaging apps, social media DMs, or contact through an employer, HR or managers. Also forbidden: any channel tied to an identity for **anonymous** sources. There is no push to sources (ADR-017).

For CONFIDENTIAL or IDENTIFIED reporters whose identity sits in the Sealed Identity Store (ADR-014), the SSN-ACCOUNT channel is used first. Out-of-platform contact happens only if law requires it (e.g., EU Directive notice before identity disclosure; `25-COMPLIANCE.md`) and only through the Identity Custodian unsealing procedure, with dual approval and legal basis recorded.

### 7.2 Notice rules

1. Notices SHALL use pre-approved templates (§7.3). Free-text additions require Channel Owner + DPO review.
2. SSN-GLOBAL text SHALL be safe to be seen on a seized device. It warns and advises but never implies that the reader in particular is affected.
3. SSN-ACCOUNT SHALL NOT reveal information about other sources or internal investigation details that could endanger the source.
4. Notices SHALL be published at once when decided. Notices stay visible for ≥ 90 days.
5. Notice publication SHALL itself create no new source metadata. The server records only that notice N was published and when (a staff action). It does **not** record which accounts displayed or read it.
6. Advice must be actionable, for example:
   - "stop using this passphrase and create a new submission";
   - "if you used Tor Browser at the Standard security level between DATE1 and DATE2 (days) …";
   - "the address has changed; verify the new address at …".

### 7.3 Templates (excerpt; full set in `11-FRONTEND-SOURCE.md` i18n catalog)

| Template ID | Text (EN, abridged) |
|---|---|
| compromise-intake-window | "Security notice. Between {DAY_FROM} and {DAY_TO} this submission service may have been accessed by an unauthorized party. Messages and files submitted **without** the Candor Source App during that period may have been readable by that party. Submissions made with the verified Candor Source App were encrypted on your device. If this concerns you, consider not sending further information from the same environment. Guidance: {LINK_ONION_GUIDE}." |
| metadata-exposure | "Security notice. A copy of internal service records (such as counts of submissions per day and encrypted data) was taken. It did not include the contents of reports, your passphrase, or your network address, which this service never records." |
| onion-rotated | "This address is retired. Do not submit here. The new address is published on {C37_URL} and signed by key {FPR}. Verify before use." |
| recipient-credential | "Security notice (account). A staff credential was misused between {DAY_FROM} and {DAY_TO}. Replies you received in that period may not have come from our team. Do not act on requests received in that period to reveal your identity." |
| passphrase-advice | "If you think someone else knows your passphrase, stop using it. You can change it from your inbox, or start a new submission with a new passphrase and mention that you had an earlier one, if you want to." (passphrase rotation, ADR-046(7)) |
| capture-performed | "Security notice. On {DAY} the operator made an incident-response recording of the submission server's memory or network traffic, approved by {INDEPENDENT_ROLE_LABEL}. If you used the website (no-JavaScript) version on that day, what you typed and your passphrase may be included in that recording. Consider changing your passphrase. The Candor Source App encrypts on your device." |

## 8. Other notifications

| Party | When | Content limits |
|---|---|---|
| Supervisory authority (GDPR Art 33) | Personal-data breach likely to result in risk: ≤ 72 h after awareness [B-CO-09] | Use the compelled-disclosure inventory (REQ-H-06) and `17-INFRASTRUCTURE.md` §8 seizure tables to describe categories. Never include source identities or report content |
| Data subjects (GDPR Art 34) | High risk. Whistleblower identity exposure is treated as high risk (R6, B-CO-09) | Via SSN channels only for anonymous sources. A public communication (SSN-GLOBAL / SSN-CLEARNET) where individual contact is impossible |
| NIS2 authority / CSIRT | Entities in NIS2 scope: 24 h early warning, 72 h notification, 1-month report [B-CO-47] | As above |
| ENISA CRA Single Reporting Platform (vendor) | Actively exploited vulnerability or severe incident in Candor as a product, from 11 Sep 2026 [B-CR-50, B-CR-51] | Product-level technical details only |
| Customers (vendor → EE customers; MANAGED operator → tenants) | SEV-0/1 affecting them: ≤ 24 h | Opaque instance IDs. No cross-customer details |
| Tor Project | Onion-service or tor vulnerability discovered | Technical only |
| Law enforcement | Only by decision of Legal + management (excluding COI persons) | Nothing that can identify sources. Consider whether the report itself exposes sources (THR-026) |
| Upstream projects (Debian, crates) | Vulnerability in a dependency | Coordinated disclosure |
| Persons concerned (accused persons, witnesses, other data subjects named in reports; GDPR Art 34, RVW-C-14) | A breach likely to result in high risk to them | Scoping is done **by case members in their Desks** (the only place where content is readable, ADR-044(5)): the Triage Set of each affected channel runs a signed federated search over the cases it can decrypt and records per case "persons concerned present: yes/no" as a content-free CASE event; completeness is tracked as cases × responses. Notification content is decided by the Channel Owner + DPO and never reveals the source or the existence of other reports beyond what the breach itself exposed. Target: scoping result within 72 h of awareness to support the Art 33 notification |
| Records / FOIA / ATIP / eDiscovery requests arising from an incident | Legal requirement | Performed in authorised members' Desks or by a Records Custodian with explicit, audited, time-bounded case grants from the Triage Set (ADR-044(5)); no server-side global search exists |

## 9. Playbooks

Common first steps for every playbook: (1) `candorctl ir declare`; (2) staff the roles in §4, applying the COI exclusions; (3) open an evidence vault; (4) set a notification clock (GDPR 72 h, NIS2 24 h, CRA 24 h where applicable).

### PB-01 Source anonymity suspected compromised

| Phase | Actions |
|---|---|
| DETECT | A source reports retaliation or confrontation (inbox message); a recipient or ombudsman notices that a subject knows of the report; an Export Package appears outside the case; audit analytics flag unusual access (a staff member outside the ACL attempting access, bulk export, access immediately before a known confrontation); a media report; a COI-map violation detected by `14-CASE-MANAGEMENT.md` checks |
| CONTAIN | Reduce the case ACL to the case owner + an independent handler (ombudsman/external counsel channel) through a time-bounded grant, excluding every person who is a possible leak origin (ADR-015); suspend exports and Export Package creation for the case; revoke sessions of suspected staff (PB-05 if credentials are implicated); send SSN-ACCOUNT `passphrase-advice` + a tailored safety note approved by the Channel Owner and Legal; **do not** discuss suspicions in channels the suspected person can read (email, chat) |
| PRESERVE | CASE audit for the case (who viewed or exported what, when), SECURITY audit, Export Package records, integration/connector logs (C-40), notification logs (content-free). **Do not** build a "who is the source" hypothesis document. Investigate **access paths**, not source identity |
| NOTIFY | DPO (identity exposure = high risk, Art 33/34 assessment); Legal (anti-retaliation: EU Directive 2019/1937 [B-CO-02]); Independent Oversight; **not** the implicated line management or executives (INC-22) |
| ROTATE | If platform credentials were misused: PB-05 rotations. Remove the leaked person from all channels; case-key re-wrap for remaining members (future confidentiality; past disclosure cannot be undone). Update the COI map. If the leak came via an Export Package, revoke outstanding exports and review the recipients of the export |
| RECOVER | The case continues under independent handlers. Retaliation-protection measures per `25-COMPLIANCE.md`. Follow-up with the source only via the platform |
| LESSONS | Classify the root cause: platform (authz/audit gap), process (export, meeting circulation), content inference (THR-010: stylometry, canary documents, distribution-list size), or source-side (device, network). Feed changes into COI templates, export controls, recipient training (THR-041) |

### PB-02 Application compromised (Z-INTAKE or Z-CORE)

| Phase | Actions |
|---|---|
| DETECT | `host.attestation_mismatch`; debsums/file-manifest failure; `egress_violation=true`; secret-manifest violation; unexpected listening sockets; AppArmor denial count anomaly (counts only); external vulnerability report or exploit in the wild; transparency-log monitor alert about the key directory (unexpected key entries) |
| CONTAIN | **Intake suspected (SEV-0):** `candorctl ir intake stop` immediately (fail closed; sources see an unreachable onion, never a clearnet fallback). **Core suspected:** isolate (`ir isolate`), revoke all staff sessions (ADR-029 tokens), suspend relay pulls and backups, keep intake running only if intake integrity is verified by attestation from a clean H-MON |
| PRESERVE | E-SYS; E-HOST/E-INTAKE disk images; E-MEM-CORE if useful; E-MEM of intake **only** with DPO + Independent Approver approval, the evidence precondition and a published INCIDENT_NOTICE (§6.1). Freeze config. Export self-test, attestation, Platform Manifest and External Watcher history. Record T0 candidates |
| NOTIFY | DPO; Channel Owners. If Tier W exposure is possible, SSN-GLOBAL `compromise-intake-window` with day-granular window [T0, containment]. Candor PSIRT if a product vulnerability is suspected (vendor → CRA if actively exploited). Customers/tenants (MANAGED) |
| ROTATE | Intake: new source onion key (PB-10 procedure), SSH-onion keys, relay mTLS pair, Argon2 deployment salt (forces nothing on sources; new accounts only), monitor credentials. Core: RCP-ONION keys and client-auth keys or RCP-LAN certificates (re-enroll Desks), audit/directory signing keys if not in an HSM, backup-agent key, DB credentials, WORM agent credentials. Verify key-directory consistency: every channel/recipient key entry must carry valid Channel Identity signatures. Invalid entries mean THR-046 (key substitution), and affected channels must be re-verified by members |
| RECOVER | DR-P4 (`19-BACKUPS-DR.md`): rebuild from clean media; restore pre-T0 sets; apply the erasure log (core) and the merged intake deletion list (intake, ADR-047(9)) before serving; Desk re-wrap for missing Erasure Keys (`19-BACKUPS-DR.md` §11.2); new golden PCRs; self-test; reopen intake; publish the resolution notice |
| LESSONS | Root-cause advisory (FPF-style detail [B-SD-20]); a regression test for each finding (R1 R-AUDIT-1); update this playbook |

### PB-03 Database stolen

| Phase | Actions |
|---|---|
| DETECT | Unexpected large reads by DB roles (connection-level stats; no statement logging of data); DB credential use from unexpected hosts; public-bucket/scan alerts; extortion message; dumps found outside the manifest (secret/data scan) |
| CONTAIN | Revoke DB credentials; identify the exfiltration path (backup misconfiguration, DBA account, app compromise → PB-02); block the path |
| PRESERVE | DB connection records, host images of the implicated path, cloud/storage access logs (short retention: capture immediately) |
| NOTIFY | Exposure assessment using `17-INFRASTRUCTURE.md` §8.6: no report plaintext, no IPs, day-granular dates, counts, padded sizes, workflow metadata (C-12), COI exclusions. DPO decides on Art 33/34. SSN-GLOBAL `metadata-exposure` if intake data (C-08) was taken. Oversight if C-12 workflow metadata reveals subjects (COI) |
| ROTATE | DB and relay credentials; any secret stored in the DB (none by design; verify). Source auth verifiers are not rotated (about 129-bit passphrases resist offline guessing, ADR-005). Offer `passphrase-advice` only if a KDF weakness is suspected |
| RECOVER | Close the path; verify with the config checker; consider accelerating retention/deletion for data that no longer needs to exist |
| LESSONS | Re-evaluate which C-12 fields must be server-readable (`09-DATABASE.md`) |

### PB-04 Encryption key stolen

| Key stolen | Immediate exposure | CONTAIN / ROTATE | NOTIFY |
|---|---|---|---|
| Recipient X-Wing/identity key (device + unlock) | That user's ACL cases; epoch keys of their channels within the window | PB-05 | PB-05 |
| Member epoch private key (ADR-030) | Envelopes wrapped to that member in that epoch (≤ 7-day epoch) if the attacker also has the ciphertext (from intake/core/backup). Envelopes from which the member was COI-excluded are not exposed | The member's Desk revokes the compromised and pre-published member epoch keys in the key directory and publishes new ones (intake stops wrapping to revoked keys on the next directory snapshot push); other eligible members import pending envelopes at once so that ciphertext is removed from intake after the ack; assess the ciphertext exposure path | SSN-GLOBAL if the ciphertext exposure path is confirmed |
| Channel Identity Key | Ability to sign epoch keys and recipient-set changes → key substitution (THR-046) for new submissions | New Channel Identity Key signed by the org roster key + ≥ 2 members; publish the revocation in the key directory; Tier V clients pin the new key via the signed transition; transparency monitors confirm | SSN-GLOBAL + SSN-APP: "key changed on {DAY}, verify fingerprint {FPR}" |
| Case key | That case's content | Re-key the case: a new case key, re-encrypt case records and evidence DEK wrappings (`04-CRYPTOGRAPHY.md`), destroy the old wrappings | Channel Owner decides on SSN-ACCOUNT |
| Recovery Quorum shares (≥ k) | All cases wrapped to the Quorum | Generate a new Quorum key; re-wrap all cases; destroy the old wrappings; publish the Quorum change (ADR-013 transparency) | SEV-0; DPO; Oversight |
| Backup KEK (IRK ≥ k) | Historical server metadata in backups | DR-P9; early key-epoch rotation | As PB-13 |
| Audit or key-directory signing key | Forged audit checkpoints / log entries | New key; publish rotation; re-anchor with an external witness; verify past checkpoints against the witness | Internal |
| Release signing key | → PB-09 | | |
| Onion key | → PB-10 | | |
| HSM | → PB-11 | | |

PRESERVE: how the key left its boundary (manifest scan, attestation, device forensics). LESSONS: why the key was exposable (was it hardware-bound? placed per the manifest?).

### PB-05 Recipient credential stolen

| Phase | Actions |
|---|---|
| DETECT | User reports a lost or stolen device or token, or coercion; new-device enrollment the user did not make; an access pattern anomaly on staff accounts (volume, hours, cases never accessed before), detected by privacy-preserving staff audit analytics (`20-LOGGING-AUDITING.md`) |
| CONTAIN | Disable the account; revoke all sessions and device keys (key-directory revocation entry); block new enrollments for the user; mark the device for remote wipe (best effort; Desk honors it on next contact) |
| PRESERVE | CASE and SECURITY audit for the account since last-known-good; enrollment records |
| NOTIFY | Channel Owners of affected channels; DPO if cases in the ACL could have been read. SSN-ACCOUNT `recipient-credential` to sources in cases where the attacker could have replied or requested information in the window [T0, revocation] |
| ROTATE | For every case in the user's ACL: re-wrap the case key to the remaining members; remove the old user's wrappings. Revoke all of the user's member epoch keys (current and pre-published, ADR-030) in the key directory, so that intake stops wrapping new envelopes to them. Other members import pending envelopes at once so their ciphertext leaves intake. Revoke the user's RCP-ONION client-auth key or RCP-LAN device certificate. If the channel would drop below `min_recipients`, intake for it fails closed (ADR-030, `34-PERFORMANCE-SCALABILITY.md` FAIL table) until a replacement member enrolls. If the user was an Identity Custodian: rotate the custodian keys and re-seal the identity store entries (ADR-014) |
| RECOVER | Re-enroll the user with in-person identity verification and new hardware keys |
| LESSONS | Token handling, device posture, PIN strength, travel policy |

### PB-06 Malicious administrator

| Phase | Actions |
|---|---|
| DETECT | DANGEROUS config change without valid dual approval (checker exit ≥ 20); secret-manifest violations; attestation mismatch after an admin session; SSH certificate issuance anomalies; backup-store admin actions; attempts to create staff accounts and enroll them into channels (fails without member wrapping, ADR-008, but is logged); a report about the admin received **through Candor** (routed to an independent channel via the COI map) |
| CONTAIN | The Emergency Admin set (§4; appointed by OVERSIGHT, physical console where needed) revokes the admin's SSH CA principals, FIDO2 registrations and admin-api roles; if the admin's reporting chain is implicated, switch to PB-19; freeze config; stop intake if host integrity is in doubt (the admin had root → SEV-0 for Tier W exposure since the admin's first suspicious action) |
| PRESERVE | SECURITY audit (admin actions), SSH certificate log, host images, config history, HSM audit |
| NOTIFY | Management excluding the admin's reporting chain if implicated; Legal; DPO; Oversight. SSN-GLOBAL `compromise-intake-window` if Tier W exposure is plausible |
| ROTATE | Everything the admin could reach: source onion key (PB-10), SSH-onion keys, relay/monitor mTLS, Tang keys (re-bind FDE), WORM store root credentials (if the admin knew the safe), HSM PINs/partitions the admin could activate, IRK shares held by the admin (re-split the IRK), RCP-ONION keys or RCP-LAN server key |
| RECOVER | Rebuild all hosts the admin had root on (DR-P4) |
| LESSONS | Review separation of duties (`32-OPERATIONS.md` HUM controls), two-person SSH issuance for H-INTAKE, and access expiry |

### PB-07 Ransomware

| Phase | Actions |
|---|---|
| DETECT | Canary-file alert; RT-0 anomalies; services failing on encrypted files; ransom note; mass file changes on H-CORE or workstations |
| CONTAIN | Pull the uplinks of affected hosts; power off H-INTAKE (safer than a running compromised intake); isolate H-CORE, keeping it powered for E-MEM-CORE capture if it may hold the ransomware key; block WS-ADM sessions; verify H-BAK integrity (WORM) from H-MON |
| PRESERVE | E-HOST images, E-MEM-CORE, ransom note, RT-0 history; determine T0 |
| NOTIFY | DPO (availability breach + possible exfiltration of metadata); regulators as required; SSN-GLOBAL if the intake outage exceeds 24 h or data loss affects sources (for example, source accounts created after the last restorable set) |
| ROTATE | All online secrets (as PB-02). The source onion key only if the intake was touched |
| RECOVER | DR-P4 (rebuild from clean media; restore chain-verified pre-T0 sets; if the dwell time exceeds the 14-day vault retention, restore the latest verifiable vault set with dual approval and re-wrap missing cases from Desks, `19-BACKUPS-DR.md` DR-012; apply the erasure log). Exfiltration is metadata-only by design (`17-INFRASTRUCTURE.md` §8); payment is an organizational decision outside this spec |
| LESSONS | Entry vector; backup coverage; admin workstation hygiene |

### PB-08 Supply-chain compromise (dependency, build, CI, repository)

| Phase | Actions |
|---|---|
| DETECT | Independent builders disagree (reproducibility mismatch, ADR-022); cargo-vet/deny alerts; an upstream advisory (xz-class, INC-37); SBOM match against a malicious-package feed; CI anomaly (tj-actions-class, INC-44); transparency monitor sees an unexpected artifact |
| CONTAIN | **Vendor:** freeze the TUF targets role (no new releases), revoke affected targets, rotate CI credentials, lock the repository (branch protection audit). **Operator:** `candorctl update freeze`; determine whether an affected version is installed (`candorctl version --sbom-match <advisory>`) |
| PRESERVE | Build logs, provenance attestations, builder images, dependency lockfiles, the transparency-log entries |
| NOTIFY | CRA ENISA reporting (vendor) if actively exploited [B-CR-50]; customers; upstream; public advisory with root cause |
| ROTATE | CI tokens, builder credentials, any signing subkey reachable from compromised infrastructure (root and targets keys are offline/threshold, ADR-022) |
| RECOVER | Clean rebuild from pinned commits on rebuilt builders; publish the fixed release; operators upgrade. If a compromised build was installed → PB-09 then PB-02 |
| LESSONS | Dependency review policy (`28-SUPPLY-CHAIN.md`), pinning, builder independence |

### PB-09 Malicious release (a signed release carries malicious code)

| Phase | Actions |
|---|---|
| DETECT | Independent rebuilders fail to reproduce a published artifact; the transparency log shows an artifact outside the release process; post-update behavior (egress violations, attestation changes not matching the published golden values); operator or researcher report. By design all customers receive identical artifacts (ADR-022), so fleet-wide monitoring by any party detects it |
| CONTAIN | **Vendor:** publish a TUF targets update that revokes the release (marks it `revoked`) and freezes updates; if the targets keys are compromised, root rotation by the 3-of-5 offline root holders; advisory on the clearnet site, project onion and mailing lists. **Operator:** `candorctl update freeze`; `candorctl rollback apply --to <last-known-good>` (permitted for revoked versions when the target is known-good, with dual approval); if intake ran the release → `ir intake stop` |
| PRESERVE | The malicious artifact, TUF metadata snapshots, log inclusion proofs, affected hosts' images |
| NOTIFY | All customers; CRA; public advisory; SSN-GLOBAL on affected instances if Tier W exposure was possible |
| ROTATE | Vendor: compromised signing keys; TUF root if needed. Operator: treat affected hosts as PB-02 (all online secrets, onion key if intake affected) |
| RECOVER | Rebuild affected hosts from a known-good release; verify reproducibility of the fixed release by ≥ 2 independent builders before signing |
| LESSONS | Signing ceremony, threshold holders, builder independence, monitor coverage |

### PB-10 Onion key compromise

| Phase | Actions |
|---|---|
| DETECT | The key was found outside its manifest; a host holding it was compromised or seized; H-MON's descriptor check shows introduction points or descriptor revisions that are not ours (Knowledge (unverified): detectability depends on HSDir behavior, `16-TOR-I2P.md`); reports of a phishing clone |
| CONTAIN | Activate the **pre-generated standby onion key**, stored offline in BS-SECRETS and never on C-05 (`16-TOR-I2P.md` NET-020; R4 recommendation [B-AN-26]), or generate a new one; publish the new address signed by ≥ 2 Channel Identity Keys / org roster key in the key directory; Tier V apps switch automatically after verification; stop serving intake on the old address; from a **clean** host, keep serving the old address with only the `onion-rotated` notice for 90 days (reduces the attacker's hit rate; cannot be exclusive, since an attacker holding the key can also publish) |
| PRESERVE | How the key leaked (manifest scans, host images) |
| NOTIFY | SSN-CLEARNET (C-37 updated with Onion-Location and a signed statement); SSN-APP; SSN-GLOBAL on the new address; third-party directories listing the address; press statement if the address was widely publicized |
| ROTATE | Source onion key (on both intake hosts in EE-HA/GOV, ADR-032); BS-SECRETS re-export; generate a new offline standby |
| RECOVER | Verify via an external Tor client that the new descriptor resolves to our service; monitor the old address |
| LESSONS | Key custody; whether an Arti keystore/HSM integration is now feasible |

### PB-11 HSM compromise

| Phase | Actions |
|---|---|
| DETECT | HSM tamper event; HSM audit log anomalies (unexpected key usage, logins); signatures (audit checkpoints, directory entries, SSH certificates) that do not match expected issuance; a vendor advisory for the HSM firmware |
| CONTAIN | Disable affected partitions/roles; revoke SSH certificates issued by the HSM CA (KRL); stop key-directory publication until a new log key is installed. **No fallback signing keys** are activated (ADR-046(2)); audit checkpoints queue per `34-PERFORMANCE-SCALABILITY.md` F5c |
| PRESERVE | HSM audit logs, tamper records, issued-signature inventory |
| NOTIFY | Internal; Oversight; vendor; customers (MANAGED) |
| ROTATE | Every key resident in the HSM (`17-INFRASTRUCTURE.md` §6.5): audit signing (re-anchor externally), key-directory log key (publish a signed transition; clients re-pin), SSH CA, internal CA (re-issue relay/monitor certificates), DB TDE (re-encrypt), backup KEK if resident (DR-P9) |
| RECOVER | A new HSM from a trusted supply chain; ceremony (two-person); restore keys only from pre-compromise wrapped backups if the compromise was physical-only and the backups predate T0, otherwise generate new |
| LESSONS | HSM firmware policy, tamper monitoring |

### PB-12 Physical seizure (lawful or unlawful) or theft

| Phase | Actions |
|---|---|
| DETECT | Physical event; loss of host heartbeats at H-MON; chassis-intrusion or seal discrepancy; notification by counsel |
| CONTAIN | **Lawful seizure:** comply as advised by counsel; do not destroy evidence or obstruct; request the scope in writing. **In all cases:** treat every key on the seized assets as compromised (per `17-INFRASTRUCTURE.md` §8 state analysis); stop remote intake operations that depend on seized hosts; revoke seized workstations' device keys (PB-05) and admin credentials (FIDO2 registrations of seized tokens) |
| PRESERVE | Inventory of seized assets with serials and seal status; last-known state (powered or off, unlock mode) → determines S-OFF vs S-LIVE exposure |
| NOTIFY | Legal first (gag orders may restrict notification, cf. INC-07). Where allowed: SSN-GLOBAL/SSN-CLEARNET describing what the seized assets could contain, derived from `17-INFRASTRUCTURE.md` §8, and advising sources. Where not allowed: the design relies on transparency mechanisms (key-directory monitors, Tier V pinning) that do not depend on the operator speaking |
| ROTATE | Source onion (PB-10) if intake hosts were seized (**new address**, not restored: DR-004); relay/monitor keys, RCP-ONION keys or RCP-LAN certificates; SSH; Tang keys (if the Tang host was seized); IRK re-split if shares were seized; epoch keys for channels whose members' devices were seized |
| RECOVER | DR-P3 on new hardware at a different location where appropriate |
| LESSONS | Was the FDE unlock mode appropriate? Tang placement? Retention minimization? |

### PB-13 Backup theft

| Phase | Actions |
|---|---|
| DETECT | Missing offline media in rotation; store access by unexpected principals (short-retention store logs); extortion; RT-0 detects reads from unknown credentials (if the store supports read logging) |
| CONTAIN | Identify stolen sets (IDs, key epoch); verify the IRK custody status (all custodians confirm possession) |
| PRESERVE | Rotation log, custody records, store logs |
| NOTIFY | With IRK intact: exposure = metadata of sizes and counts of sets only (`17-INFRASTRUCTURE.md` §8.7); DPO assessment (likely low risk). If BS-SECRETS media were stolen: SEV-1 → PB-10 |
| ROTATE | **Accelerated key epoch:** create a new BK-DATA, take a full backup under it, and once the new sets cover the needed restore points, destroy the IRK shares of the old BK early. This makes the stolen sets permanently undecryptable (`19-BACKUPS-DR.md` §8). If BS-SECRETS was stolen: rotate every secret in it |
| RECOVER | Replace media; review transport |
| LESSONS | Media handling, courier procedure |

### PB-14 Recipient workstation malware

| Phase | Actions |
|---|---|
| DETECT | EDR alert (EDR SHALL be configured with no automatic sample upload for Candor paths; `32-OPERATIONS.md`); Candor Desk self-integrity failure; Desk or webview crash reports found leaving the host; Export Packages found in a cloud-sync root (RVW-C-11); C-17 viewer anomaly (network attempt from the disposable VM, crash patterns); unexpected outbound connections from WS-RCP; a user report |
| CONTAIN | Disconnect the workstation; remove the hardware token; revoke the device key and sessions (PB-05); assume exposure of everything the user decrypted since T0 and of any case key/epoch key used while the token was inserted (keys are hardware-wrapped and cannot be exported, but can be **used** by malware while unlocked) |
| PRESERVE | Disk image encrypted to the IEK. It is E-CASE-class if decrypted content may be cached: access limited to case members + IR Lead, analyzed air-gapped. Malware samples analyzed offline; **never** uploaded to public services (§6.1 E-SRC) |
| NOTIFY | Channel Owners; DPO; SSN-ACCOUNT for affected cases if replies could have been forged; if the malware arrived via a submitted file → assess THR-023 and warn other recipients handling the same case; do **not** notify the source that "your file contained malware" unless the Channel Owner decides it is safe and useful |
| ROTATE | PB-05 rotations (re-wrap cases, member epoch key revocation, RCP client credentials) |
| RECOVER | Reimage from known-good media; re-enroll the device; verify C-17 isolation configuration |
| LESSONS | Was a file opened outside C-17? Viewer escape? Update the sanitization pipeline (`10-FILE-EVIDENCE-PIPELINE.md`) |

### PB-15 Organisational suppression / mass key loss (RVW-C-03, RVW-C-22(c))

| Phase | Actions |
|---|---|
| DETECT | `keys.epoch_runway` falling for several members at once; several members' devices reimaged, revoked or offline in the same week; SCIM deactivations or HR attribute changes that would remove key holders; un-imported envelopes older than 7 days (ADR-033(2) escalation); OVERSIGHT's dead-man canary (`14-CASE-MANAGEMENT.md`) |
| CONTAIN | OVERSIGHT (not management) leads. Freeze all wrap deletions: IdP/HR changes already only **suspend** (ADR-044(1)); refuse any pending dual-control wrap deletion; block device revocations except those requested by the device holder personally; ask each affected member to activate their stored backup authenticator (ADR-044(2)) |
| PRESERVE | SCIM/IdP change log, MDM/reimaging tickets (requested from IT in writing), SECURITY audit of suspensions and revocations, `keys.epoch_runway` history |
| NOTIFY | OVERSIGHT; external counsel; Independent Oversight's own board/regulator where law provides it. If intake for a channel fails closed, sources are directed to the channel's `independent_route` (`34-PERFORMANCE-SCALABILITY.md` F5) |
| ROTATE | Re-wrap case keys from any surviving holder to replacement members appointed by OVERSIGHT; GOV: Recovery Quorum ceremony (ADR-044(3)) |
| RECOVER | DR-P6 (`19-BACKUPS-DR.md`); enrol replacements under the 72 h/7 d roster time-lock (ADR-036(2)) with OVERSIGHT as the independent approver |
| LESSONS | Key-holder site diversity (`19-BACKUPS-DR.md` §11.1); independent-custody devices (ADR-043); whether the channel needs an external member |

### PB-16 IdP / SCIM / SOAR compromise or attribute poisoning (RVW-C-22(b))

| Phase | Actions |
|---|---|
| DETECT | Mass deactivations or group changes; manager-chain edits affecting COI computation; SOAR `force re-enrollment` bursts; sign-ins from unusual IdP tenants |
| CONTAIN | Disconnect the SCIM bridge (set to read-only); IdP changes can only suspend server-side authorization (ADR-044(1)), so no keys are lost; staff authenticate with their hardware authenticators directly (the IdP never unlocks keys, AUTH-011) |
| PRESERVE | SCIM request log, IdP audit export (requested from the IdP owner), Candor SECURITY audit |
| NOTIFY | OVERSIGHT; SECURITY_OFFICER; DPO if staff data was altered |
| ROTATE | SCIM bearer tokens; SSO federation certificates; re-verify every suspension with the member out of band |
| RECOVER | Lift suspensions after verification; re-enable SCIM with the manager-chain attribute excluded from COI computation until the IdP is clean |
| LESSONS | Whether a dedicated IdP is needed for INDEPENDENT channels |

### PB-17 Unauthorized roster change, role-label change or orphan re-key (RVW-C-05, RVW-C-22(d))

| Phase | Actions |
|---|---|
| DETECT | Content-free roster-change notifications to members and OVERSIGHT during the 72 h (GOV/HIGH 7 d) time-lock (ADR-036(2)); Desk warning about a member key < 7 days old; transparency-log monitor or witness alert on CHANNEL_ROSTER / CHANNEL_IDENTITY entries; a role label without an OVERSIGHT certification (ADR-036(3)) |
| CONTAIN | An existing member or OVERSIGHT files an objection, which blocks activation during the time-lock; if already active, remove the new member (removals take effect immediately) and publish revocation of its epoch keys |
| PRESERVE | Directory entries, approval records, `person_ref` verification evidence |
| NOTIFY | OVERSIGHT; SSN-GLOBAL/SSN-APP if envelopes were sealed to the unauthorized member ("recipients of this channel changed between {DAY_FROM} and {DAY_TO}") |
| ROTATE | Channel Identity Key if its holders approved the change under duress or were compromised (PB-04); follow-up sealing continues only to members of the original eligible set (ADR-036(4)) |
| RECOVER | Re-verify every roster member out of band by OVERSIGHT |
| LESSONS | Holder distribution of the Channel Identity Key and Org Root shares |

### PB-18 Recipient endpoint tampering by the organisation (RVW-C-01, RVW-C-22(e))

| Phase | Actions |
|---|---|
| DETECT | Desk self-check reports a binary digest not in the transparency log (detects accidental divergence only, ADR-043); a member reports an MDM-pushed "Candor Desk" package, EDR live-response session, screen-recording or insider-risk agent, or VDI session; custody status in the Admin UI changes from independent to managed |
| CONTAIN | Treat the device as PB-14 (compromised); the member stops using it; OVERSIGHT suspends the member's case access from that device; the member continues on an independent-custody device |
| PRESERVE | Device inventory and MDM/EDR records (requested from IT in writing, noting that IT may be the adversary), Desk self-check history |
| NOTIFY | OVERSIGHT; external counsel; DPO. Do **not** notify the organisation's IT/security team first if it may be the actor |
| ROTATE | PB-05 rotations for the member |
| RECOVER | Re-enrol on an independent-custody device (ADR-043) |
| LESSONS | Whether INDEPENDENT-channel members were ever on managed devices; update the custody attestation |

### PB-19 Leadership-implicated incident (organisation as adversary) (RVW-C-22(a))

| Phase | Actions |
|---|---|
| DETECT | Any incident where management, the IR Lead's reporting chain, IT/security leadership or in-house Legal may be implicated; an identity request by an executive recorded as `case.identity_request_refused`; a pretextual SEV-0 declaration without the evidence precondition (§6.1) |
| CONTAIN | IR is run by **OVERSIGHT** with an external retained IR firm under a pre-signed engagement letter; the Emergency Admin set replaces platform admins in the implicated chain; captures follow §6.1 with OVERSIGHT as Independent Approver; implicated persons are removed from IR, notifications and approvals (IR-003) |
| PRESERVE | As the underlying playbook; evidence encrypted to custodians that exclude implicated persons |
| NOTIFY | Board/regulator/IG as law provides; SSN notices per the underlying playbook; the Operator Statement is not renewed if its signers cannot truthfully sign (ADR-035(2)) |
| ROTATE | Per the underlying playbook, performed by the Emergency Admin set |
| RECOVER | Per the underlying playbook |
| LESSONS | Whether the independent roles are genuinely independent (TEN classification, `21-ENTERPRISE.md`) |

### PB-20 Notification-transport or SIEM-sink compromise (RVW-C-22(f))

| Phase | Actions |
|---|---|
| DETECT | Unexpected recipients or forwarding rules on notification mailboxes; SIEM sink exposure reports; webhook endpoint changes |
| CONTAIN | Disable the affected transport (`notify.transport` none; Desk badge only) or SIEM export; notifications are content-free and constant-schedule (ADR-038(2)), so exposure is limited to the staff address list and daily digest times |
| PRESERVE | Transport configuration history; C-26 export logs |
| NOTIFY | SECURITY_OFFICER; DPO (staff personal data) |
| ROTATE | Webhook secrets, SMTP credentials, SIEM tokens, pinned certificates |
| RECOVER | Re-enable with pinned transport over tor |
| LESSONS | Whether staff event export should be day-granular only (`20-LOGGING-AUDITING.md`) |

### PB-21 Erasure Key Vault loss or tampering (ADR-047(7), ADR-044(4))

| Phase | Actions |
|---|---|
| DETECT | `ekv verify` failures (AEAD mismatch against DB rows); vault volume missing or unmountable; K33 unseal failure after hardware change; RT-5/RT-7 findings; unexpected infrastructure-level copy of the vault (INFRA-037 attestation invalidated) |
| CONTAIN | Stop serving EK-layered wraps (F5d); `candorctl ir freeze-config`; if tampering is suspected (keys substituted or deleted by an attacker), treat as PB-02 for Z-CORE in parallel |
| PRESERVE | Vault volume image (encrypted to IEK); `ekv verify --report-missing` output (case IDs only); BS-ERASURE/BS-ERASELOG chain status |
| NOTIFY | SECURITY_OFFICER, OVERSIGHT, Channel Owners (content-free: "case opening paused"); DPO if an infrastructure copy of the vault exists (the 14-day deletion bound failed; `35-DATA-RETENTION-DELETION.md` conditional statement) |
| ROTATE | New K33; new Erasure Keys for every case in the missing list (never re-use a restored key for a missing case) |
| RECOVER | DR-P10, then the dual-approved Desk re-wrap of `19-BACKUPS-DR.md` §11.2: erasure log applied first on server and Desks; holders re-create inner wraps and metadata fields; other holders verify; cases without a surviving holder go to DR-P6 |
| LESSONS | Vault replication/backup cadence; key-holder dispersion; whether an infrastructure backup exclusion was honoured |

### PB-22 Key Directory freshness or attestation failure (ADR-047(4))

| Phase | Actions |
|---|---|
| DETECT | SYSTEM `kd_snapshot_stale` from the intake (snapshot older than 7 days by the independent time floor); Tier V clients or watchers report stale snapshots; confidential-VM attestation evidence older than 24 h; channels showing "temporarily unavailable" |
| CONTAIN | Nothing to relax: sealing stays refused (fail closed); never push an unsigned or backdated snapshot and never disable the check. Determine the cause: relay outage, Z-CORE freeze (possible suppression, THR-020), witness cosignature shortage, time-source attack on the intake (THR-043), TEE failure |
| PRESERVE | Relay and directory publication logs (SYSTEM), witness responses, intake time-floor records (consensus `valid-after`, Roughtime responses) |
| NOTIFY | OVERSIGHT (a withheld directory can be suppression); Channel Owners; sources via SSN-GLOBAL if the outage exceeds 24 h, pointing to each channel's `independent_route` |
| ROTATE | Only if the cause is a compromise (then per PB-02/PB-11) |
| RECOVER | Publish a fresh, witness-cosigned snapshot at the next publication opportunity (an out-of-slot publication is allowed only for recovery and is recorded); confirm sealing resumes; for TEE failure, restart the sealer VM and verify fresh attestation |
| LESSONS | Relay redundancy; witness availability; whether suppression was attempted (escalate to PB-19 if leadership-implicated) |

## 10. Exercises

| Exercise | Frequency | Scope |
|---|---|---|
| Tabletop | Quarterly (rotate playbooks so each is exercised ≥ once in 2 years; PB-01, PB-02, PB-10, PB-19 yearly). Small-organisation mode: twice yearly, each playbook ≥ once in 3 years (RVW-C-17) | Roles, decisions, notice drafting (templates signed in a test directory) |
| Technical drill | Yearly (EE-HA/GOV twice yearly) | Onion rotation in the lab, IR capture tooling, DR-P4 combined with PB-02 |
| Notice rehearsal | Yearly | Publish a test SSN on a staging instance; verify that Tier V verifies and Tier W displays the fingerprint |

## 11. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| IR-001 | Each deployment SHALL maintain the twenty playbooks of §9 (PB-01..PB-20), each with DETECT, CONTAIN, PRESERVE, NOTIFY, ROTATE, RECOVER and LESSONS, adapted to its profile. | INC-27; INC-55; INC-37; RVW-C-22 | THR-014, THR-031, THR-042 | C-19 | INSP: playbook set review; DEMO: tabletop records |
| IR-002 | Severity SHALL be assigned per §5. Any incident involving a possible person-to-report link SHALL be at least SEV-1. | INC-22 | THR-019, THR-020 | C-19 | INSP: IR records sample |
| IR-003 | The IR team SHALL exclude persons implicated in the incident or listed in COI maps for affected cases. Notifications SHALL not be sent to them. | ADR-015; INC-22 | THR-020 | C-10, C-22 | DEMO: tabletop with an executive-implicated scenario; INSP |
| IR-004 | IR SHALL NOT use break-glass to read report content except in PB-01/PB-14, by decision of the case's own members under dual approval that includes one approver from an independent role outside the legal/management chain (ADR-045), recorded in the CASE audit. | ADR-015; ADR-045; REQ-H-68; RVW-C-10 | THR-018 | C-22, C-24 | TST: break-glass without a case-member co-sign is refused; INSP: audit review |
| IR-005 | When Z-INTAKE may be live-compromised, the intake SHALL be stopped (fail closed) within 1 h of declaration. No clearnet or alternative anonymous path SHALL be offered. | ADR-002; INC-28 | THR-014, THR-007 | C-05, C-06 | TST: `ir intake stop` disables the onion service and sealer; DEMO: drill timing |
| IR-006 | All IR evidence SHALL be encrypted at capture to the IR Evidence Key (2-of-3 split, ≥ 1 holder from an independent role) or, for intake E-MEM/E-NET, to a one-time capture key split with the Independent Approver, with signed chain-of-custody records in the SECURITY audit. | INC-58; THR-037; ADR-035(4); RVW-C-04 | THR-037, THR-016 | C-19, C-24 | TST: capture tool writes no plaintext (canary scan of the target media); custody signature verification |
| IR-007 | Memory capture of H-INTAKE SHALL require IR Lead + DPO + Independent Approver approval and the evidence precondition of §6.1, SHALL publish a cosigned INCIDENT_NOTICE before starting, SHALL be encrypted in the capture tool before any write, and SHALL be retained ≤ 90 days unless under legal hold. | ADR-004; ADR-035(4); REQ-H-58; RVW-C-04 | THR-016, THR-014, THR-127 | C-19, C-14 | TST: `capture memory --host intake` without either approval token, without an evidence record, or when the INCIDENT_NOTICE append fails is refused |
| IR-008 | Packet capture on N-INTAKE-EXT or RCP-ONION uplinks SHALL be disabled by default and SHALL require IR Lead + DPO + Legal + Independent Approver approval, the evidence precondition and a published INCIDENT_NOTICE; headers only, ≤ 24 h, encrypted to a one-time capture key split with the Independent Approver, ≤ 30-day retention. | B-AN-01; ADR-016; ADR-035(4); RVW-C-04 | THR-003, THR-011, THR-127 | C-05, C-19, C-14 | TST: IR tooling refuses ext capture lacking any approval, evidence record or notice; INSP |
| IR-009 | IR SHALL NOT enable debug logging on Z-INTAKE. Only the allow-listed `ir diagnostic mode` MAY be used, and it SHALL auto-expire after 24 h. | INC-60; ADR-016 | THR-016 | C-06, C-07 | TST: diagnostic mode output schema contains no request data, circuit IDs or payloads; expiry test |
| IR-010 | Submitted files, their hashes and IR memory/disk images SHALL NOT be uploaded to public or third-party analysis services. | INC-56; THR-010 | THR-016, THR-027 | C-17, C-19 | INSP: IR procedure; TST: EDR/IR tool config disables cloud sample submission for Candor paths |
| IR-011 | Evidence analysis SHALL NOT extract or derive exact timestamps of source actions from host artifacts of intake data paths. | ADR-010 | THR-011 | C-19 | INSP: forensic tool profile; AUD |
| IR-012 | Source notifications SHALL use only SSN-GLOBAL, SSN-ACCOUNT, SSN-CLEARNET and SSN-APP. Identity channels (email, SMS, phone, employer) SHALL NOT be used for anonymous sources. | ADR-002; ADR-017; INC-57 | THR-028, THR-040 | C-06, C-14, C-37 | INSP: notice procedure; TST: notice API exposes no identity-channel sender |
| IR-013 | Source security notices SHALL be signed by ≥ 2 Channel Identity Keys or the org roster key, published in the key directory, verified by Tier V clients, and shown with fingerprint and verification instructions in Tier W. | ADR-004; ADR-022 | THR-044, THR-007 | C-14, C-03, C-06 | TST: unsigned or single-signed notice rejected by the Source App; UI test for Tier W display |
| IR-014 | Notice publication SHALL NOT record which source accounts displayed or read a notice. | ADR-010; ADR-016 | THR-011, THR-038 | C-06, C-08 | TST: DB/log diff before and after notice display shows no per-account records |
| IR-015 | SSN-GLOBAL texts SHALL be pre-approved templates safe to be seen on a seized device, and SHALL not imply that a particular reader is affected. | INC-23 | THR-048, THR-034 | C-06 | INSP: template review by Legal and DPO; DEMO: usability review |
| IR-016 | Notices SHALL remain visible for ≥ 90 days. Windows SHALL be expressed at day granularity. | ADR-010 | THR-011 | C-06 | TST: notice expiry and granularity tests |
| IR-017 | Out-of-platform contact with CONFIDENTIAL/IDENTIFIED reporters SHALL occur only via the Identity Custodian unsealing procedure with legal basis and dual approval. | ADR-014; B-CO-02 | THR-018, THR-040 | C-10, C-21 | TST: unsealing without dual approval refused; INSP |
| IR-018 | Each deployment SHALL keep a pre-generated standby onion key, stored offline only, and a documented, rehearsed onion-rotation procedure including C-37 and key-directory publication. | B-AN-26; INC-28 | THR-044, THR-032 | C-05, C-14, C-37 | DEMO: yearly rotation drill in the lab; TST: standby key present per manifest |
| IR-019 | After onion rotation, the old address SHALL serve only the `onion-rotated` notice (from a clean host) for 90 days and SHALL NOT accept submissions. | INC-28 | THR-044 | C-05, C-06 | TST: submission endpoints are disabled on retired-address config |
| IR-020 | Recipient-credential incidents SHALL trigger case-key re-wrapping for the remaining members and immediate revocation of all the user's member epoch keys (current and pre-published) in the key directory. | ADR-008; ADR-030 | THR-013, THR-022 | C-15, C-14 | TST: incident simulation verifies that revoked-key wrappings are removed and that intake stops wrapping to the revoked member epoch keys after the next directory push |
| IR-021 | Channel Identity Key compromise SHALL be handled by a signed transition (org roster key + ≥ 2 members) published in the transparency-logged key directory. | ADR-008; ADR-022; INC-14 | THR-046 | C-14, C-03 | TST: Source App accepts only valid transitions; transparency monitor detects unsigned changes |
| IR-022 | Vendor PSIRT SHALL be able to freeze and revoke releases via TUF metadata within 4 h of a SEV-0 product incident, and SHALL publish an advisory with root cause. | ADR-022; B-SD-20; INC-38 | THR-025 | C-32, C-33 | DEMO: yearly freeze/revoke drill on a staging TUF repo |
| IR-023 | Operators SHALL be able to freeze automatic updates and roll back to a known-good version with dual approval, including from a revoked release. | ADR-022; INC-49 | THR-025 | C-19, C-33 | TST: `update freeze` + rollback-from-revoked tests |
| IR-024 | The vendor SHALL implement CRA Art 14 reporting (actively exploited vulnerabilities, severe incidents) via the ENISA Single Reporting Platform with a 24 h early-warning capability. | B-CR-50; B-CR-51 | THR-025, THR-024 | C-36 | INSP: PSIRT runbook; DEMO: reporting rehearsal |
| IR-025 | Operator runbooks SHALL include GDPR Art 33 (72 h) and, where applicable, NIS2 (24 h/72 h) notification steps, using the compelled-disclosure inventory to describe categories without source data. | B-CO-09; B-CO-47; REQ-H-06 | THR-026 | C-19 | INSP: runbook review |
| IR-026 | After hostile compromise or seizure of a host, every key present on that host per its manifest SHALL be rotated, and recovery SHALL follow DR-P4 (clean rebuild). | ADR-028; INC-28 | THR-044, THR-013 | C-19 | DEMO: IR drill; TST: `ir rotate --host` covers every manifest entry |
| IR-027 | EDR or anti-malware on recipient workstations SHALL be configured with no automatic sample or file upload for Candor data paths and C-17 images; OS and webview crash reporting for Desk processes SHALL be disabled and Export Packages SHALL NOT be written to cloud-sync roots (owner of the Desk-side controls: `12-FRONTEND-RECIPIENT.md`). | INC-56; RVW-C-11 | THR-016, THR-027, THR-109 | C-16, C-15 | INSP: EDR policy export; TST: config check on managed devices where supported |
| IR-028 | Backup-theft incidents SHALL trigger an accelerated backup-key epoch (new BK, fresh full backup, early destruction of the old IRK shares). | INC-55; B-CR-33 | THR-017, THR-015 | C-27, C-28 | DEMO: tabletop; INSP: key-epoch register |
| IR-029 | Tabletop exercises SHALL be held quarterly (twice yearly in small-organisation mode) and technical drills yearly (twice yearly for EE-HA/GOV), with every playbook exercised at least once every 2 years (3 years in small-organisation mode). | R1 R-AUDIT-1; RVW-C-17 | THR-042 | C-19 | DEMO: exercise records |
| IR-030 | Every IR finding SHALL produce a regression test, rule or checker item before the incident is closed. | B-SD-28 (R1 R-AUDIT-1) | THR-035 | C-30 | INSP: closure checklist; TST: traceability job |
| IR-031 | IR records and custody logs SHALL be retained per legal requirement and destroyed afterwards by crypto-erasure, with the destruction recorded. | ADR-025 | THR-017 | C-19 | INSP: destruction records |
| IR-032 | Where legal gag orders prevent notification, the deployment SHALL rely on key-directory transparency and client pinning. The operator's documentation SHALL state this limitation publicly. | INC-07; ADR-022 | THR-026, THR-046 | C-14, C-37 | INSP: public threat-model text |
| IR-033 | The IR capture tool SHALL append an INCIDENT_NOTICE entry (capture class, day, approver role labels; cosigned by the Independent Approver) to the key directory before any intake E-MEM/E-NET capture, and Tier V clients, Desks and the Tier W `capture-performed` banner SHALL surface it for ≥ 90 days. | ADR-035(4); RVW-A-03; RVW-C-04 | THR-127, THR-135 | C-19, C-14, C-06, C-03 | TST: capture in the lab → directory entry present and cosigned before the first captured byte; banner visible on Tier W pages |
| IR-034 | When management, the IR Lead's chain, IT/security leadership or in-house Legal may be implicated, IR SHALL be run under PB-19 by OVERSIGHT with an external IR firm engaged under a pre-signed engagement letter, and platform administration SHALL pass to the Emergency Admin set appointed by OVERSIGHT. | RVW-C-22; ADR-045; INC-22 | THR-020, THR-018, THR-127 | C-19, C-22 | DEMO: yearly PB-19 tabletop; INSP: engagement letter and Emergency Admin appointment records |
| IR-035 | Breach scoping for persons concerned SHALL be performed by case members in their Desks via signed federated searches with completeness tracking, and SHALL never use a server-side global search. | ADR-044(5); RVW-C-14; B-CO-09 | THR-019, THR-016 | C-15, C-10 | DEMO: tabletop producing a completeness report; INSP: no server-side search route (AUTHZ-006) |
| IR-036 | In small-organisation mode, the IR roles SHALL be staffed per §4.1, the Independent Approver role SHALL be held by the external OVERSIGHT party and SHALL NOT be waived, and the combined roles SHALL be disclosed in the Operator Statement. | ADR-045; RVW-C-09; RVW-C-22 | THR-139, THR-127 | C-19 | INSP: role register; TST: capture tool refuses when Independent Approver = IR Lead |
| IR-037 | PB-15 SHALL be triggered when two or more members of a channel lose key access (device revocation, reimaging, suspension) within 7 days; during PB-15 no wrap deletion SHALL be executed except at the personal request of the holder. | ADR-044(1); RVW-C-03 | THR-128, THR-020 | C-22, C-25 | TST: simulated mass suspension → PB-15 alert to OVERSIGHT; pending wrap deletions blocked |
| IR-038 | Every recovery of Z-INTAKE in any playbook SHALL apply the merged intake deletion list (BS-INTAKE copy plus the newest Z-CORE replica) before the intake serves sources, and every Z-CORE recovery SHALL apply the erasure log before serving and use only the dual-approved Desk re-wrap for missing Erasure Keys (PB-21). | ADR-047(7); ADR-047(9); ADR-044(4); RVW-A-28 | THR-017, THR-042 | C-08, C-09, C-10 | TST: 29 ST-174, ST-175; DEMO: technical drill |
| IR-039 | A stale Key Directory snapshot or stale attestation SHALL be handled by PB-22 without relaxing the fail-closed sealing rule; any out-of-slot recovery publication SHALL be recorded and reported to OVERSIGHT. | ADR-047(4); ADR-036(6); ADR-036(7) | THR-020, THR-043, THR-046 | C-07, C-09, C-14 | TST: 29 ST-172; DEMO: tabletop |
| IR-040 | IR analysis SHALL NOT attempt to distinguish chaff from real envelopes or derive submission counts or times from intake images. | ADR-047(3); ADR-010 | THR-011, THR-016 | C-08 | INSP: IR report review; TST: `candorctl ir` offers no envelope-count tooling |
| IR-041 | In MANAGED, audit data used in IR SHALL be decrypted only by the customer with its customer-held audit export key, and intake memory/packet captures SHALL be encrypted to custodians including a customer-side holder. | ADR-047(10); ADR-035(4); RVW-C-21 | THR-027, THR-026 | C-24, C-36 | INSP: MANAGED IR runbook; TST: vendor-side decrypt of an audit export fails (29 ST-176) |

## 12. Residual risks and limitations

1. Notices reach only sources who return to the platform or check C-37. A source who never returns is not warned.
2. Onion addresses cannot be revoked in Tor. An adversary holding an old key can keep impersonating it. Only source-side verification (Tier V pinning, C-37 checks) mitigates this.
3. A gagged operator cannot warn sources. Transparency mechanisms detect key substitution but not passive seizure.
4. Memory capture during IR creates a new copy of source-sensitive data. Independent approval, split capture keys and the self-disclosing INCIDENT_NOTICE (ADR-035(4)) reduce but do not remove this risk: collusion that includes the Independent Approver, or an organisation that modifies the intake binary instead of "doing IR", is not prevented (the latter is detectable only by External Watchers and only if untargeted).
5. Past disclosures cannot be undone. Rotation protects only future confidentiality.
6. Staff audit analytics used for detection can themselves create a surveillance risk for staff. They are scoped per `20-LOGGING-AUDITING.md` and `32-OPERATIONS.md` HUM controls.
7. Playbooks do not create independence where none exists. In small organisations the external OVERSIGHT holder is the only independent party; if captured, PB-19 offers no protection.
8. Persons-concerned scoping depends on members completing searches; completeness tracking shows gaps but cannot force them.

## 13. Open issues

1. Descriptor-based detection of a second publisher for our onion address needs validation (`16-TOR-I2P.md`).
2. The SSN template catalog needs translation and a legal review per jurisdiction pack (`26-ACCESSIBILITY.md`, `25-COMPLIANCE.md`).
3. Warrant canary: resolved by ADR-035(2) (quorum-signed Operator Statement every 30 days; absence shown to sources). Legal review per jurisdiction remains with `25-COMPLIANCE.md`.
4. A remote-wipe signal for Candor Desk (PB-05) needs a design in `12-FRONTEND-RECIPIENT.md` that cannot be abused by a compromised server to destroy evidence (ADR-027 malicious-server model).
5. The INCIDENT_NOTICE entry type and its cosignature format are owned by `04-CRYPTOGRAPHY.md` (key-directory entry types); the Emergency Admin (break-glass) set by `15-AUTHENTICATION-AUTHORIZATION.md` §5.6; the federated records/persons-concerned search by `35-DATA-RETENTION-DELETION.md` / `12-FRONTEND-RECIPIENT.md`. This document follows their final text.
