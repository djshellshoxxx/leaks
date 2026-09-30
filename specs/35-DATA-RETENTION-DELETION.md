# 35 — Data Retention and Deletion
Status: Draft v1.1 (round-2 revision: ADR-033(3), 038, 039, 044, 046) · Edition applicability: both (CE: retention engine, legal hold, crypto-erasure, verification; EE/GOV: records-schedule import, disposition authority workflow, archival export, HSM-backed erasure keys) · Owner: Data Lifecycle team

## 1. Purpose and scope

Specifies how long every class of data is kept, how organizations configure retention, how legal holds override it, and how deletion is performed and verified — cryptographically (ADR-025) and physically — across live stores, backups, replicas, snapshots, attachments, logs, exported evidence and recipient devices. Covers source-initiated delete/abandon, the interplay of GDPR and records law, and an honest statement of where "delete" does not mean immediate physical erasure.

**Protection statement.**
- WHAT: confidentiality of reports, evidence and source-linked metadata after their retention ends.
- FROM WHOM: later attackers or compelling parties who obtain storage media, backups or snapshots (THR-017, THR-031, THR-030, THR-026); insiders who would keep or restore deleted cases (THR-018).
- ASSUMPTIONS: keys are destroyed in all copies (NIST SP 800-88r2 crypto-erase precondition, B-CR-33); the Erasure Key Vault (§6.2) is not backed up beyond its bounded backup window, and infrastructure-level backups/snapshots (hypervisor, SAN, enterprise backup) of core hosts exclude the vault volume, as attested by their owners (ADR-044(4)); member devices sync within the device-offline limit or are revoked; plaintext never reached persistent media (no swap, tmpfs disposables; B-CR-33 caveat). Registered as ASM-027 (key erasure effective), ASM-047 (backup operators do not hold member unlock factors), ASM-029 (HSM integrity), ASM-019 (recipient workstation integrity) in `40-SECURITY-ASSUMPTIONS.md`. Protection: 40 P-18.
- RESIDUAL RISK: exported copies, copies on lost/unsynced devices, human notes, and plaintext that reached swap or journals cannot be reached by crypto-erase; server-visible case metadata persists in data backups until they expire (§7 B7); the 14-day bound for backups does not hold where an infrastructure backup copied the vault despite the attestation.

## 2. Context and dependencies

| Doc | Relationship |
|---|---|
| `DECISIONS.md` ADR-005, 008, 009, 010, 013, 014, 016, 025, 033(3), 037, 038, 039, 044, 046 | binding |
| `04-CRYPTOGRAPHY.md` | key hierarchy, wrapping, zeroization |
| `10-FILE-EVIDENCE-PIPELINE.md` | evidence objects, derivatives, exports |
| `14-CASE-MANAGEMENT.md` | states RETAINED/DISPOSED, Art 17 purge, epoch-key abandonment |
| `15-AUTHENTICATION-AUTHORIZATION.md` | dual control DC-03, DC-05, DC-12 |
| `19-BACKUPS-DR.md` | backup sets (BS-CORE, BS-CORE-WAL, BS-INTAKE, BS-ERASURE), retention values and DR procedures — **19 is canonical for backup retention numbers**; this doc constrains content and deletion semantics |
| `20-LOGGING-AUDITING.md` | audit retention and case tombstones |
| `25-COMPLIANCE.md` | jurisdiction retention packs, DSAR |
| `17-INFRASTRUCTURE.md` | storage media, SSD/TRIM, encryption at rest |

## 3. Principles

1. **Minimize first.** Data never collected needs no deletion (ADR-010, ADR-016).
2. **Crypto-erasure is the primary deletion primitive**; physical deletion is best-effort (ADR-025; B-CR-33; GlobaLeaks overwrite-on-SSD caveat, B-GL-04).
3. **Every retained datum has a clock** (retention class) and an owner.
4. **Legal hold always wins** over automatic deletion; nothing else does.
5. **Deletion is recorded, not hidden:** a signed deletion receipt proves what was destroyed without retaining the destroyed content.
6. **Honesty:** users are told where deletion is delayed or incomplete (§11).

## 4. Data inventory and retention classes

| # | Data object | Location | Protection | Retention class / default | Deletion mechanism |
|---|---|---|---|---|---|
| D-01 | Sealed submission envelope (ciphertext) | C-08 Intake Store; BS-INTAKE (≤ 14 d) while un-pulled | Member Epoch Keys (ADR-008, ADR-030) | Until C-09 pull acknowledged + 24 h; delayed-delivery envelopes held until their release date (ADR-038(4)); undecryptable envelopes: 14 days pending + dual-approved rejection (ADR-038(6)) | Delete row/blob; epoch-key destruction makes all copies unreadable |
| D-02 | Source account record (`lookup_id`, public keys, verifier, month-granular `activity_month`) | C-08; BS-INTAKE (≤ 14 d) | none needed beyond minimization | `SRC-ACCOUNT`: until case disposed, or 365 days after `activity_month` (month of the last envelope commit or last reply made available; never login-based, RVW-B-11), or source deletion (§9) — whichever first | Row delete + intake deletion list (§7 B6) + backup expiry |
| D-03 | Sealed replies | C-08 (fetch-all dead-drop set, ADR-039); BS-INTAKE (≤ 14 d) | source key | `SRC-REPLY`: `intake.reply_retention_days` after `available_day`, **default 30** (the ADR-039 publication window); no read tracking (RVW-B-11) | Row delete + intake deletion list |
| D-04 | `received_day` / `import_slot_date` (dates only; no batch times, ADR-038(1)) | C-08, C-12 | — | with D-02 / case | with parent |
| D-05 | Member Epoch private keys (ADR-030) | Triage Set Desks (wrapped), C-12 wraps | member keys | decrypt window (14 d) and until all envelopes of the epoch imported or rejected (CASE-020, ADR-038(6)) | Destroy wraps + Desk zeroize |
| D-06 | Case record (encrypted) | C-12 | case key | by outcome (§5) | Crypto-erase case key (§6) |
| D-07 | Evidence blobs (ORIGINAL, DERIVED) | C-13 | per-object DEK wrapped under case key | with case; DERIVED may be deleted earlier | Crypto-erase + blob delete |
| D-08 | Case-key wraps (member, quorum) | C-12, each wrap stored as `AEAD(E_case, wrap)` (outer Erasure layer, §6.2) | member X-Wing keys (inner) + Erasure Key (outer) | with case; deletion of a single member's wraps per 15 DC-15 (7-day cooling-off) | Destroy Erasure Key + delete wraps |
| D-09 | Sealed Identity Store entries (ADR-014) | C-12 | Identity Custodian keys + Erasure Key | `IDENTITY`: shortest of case retention or configured identity retention (default: case closure + 30 days, aligned with 21 ENT-009, RVW-B-33(c)) | Crypto-erase identity DEK |
| D-10 | Server-visible case metadata (channel, state, flags, ACL user IDs, SLA dates, `received_day`, `import_slot_date`, 8 blinded COI tags) | C-12; BS-CORE sets | at-rest + backup encryption only | with case; tombstone after disposal (§6.4); in BS-CORE until set expiry (§7 B7) | Row delete → tombstone; backup expiry |
| D-11 | Audit streams | C-24 | append-only | `20-LOGGING-AUDITING.md` §12 | Interval deletion / case tombstone |
| D-12 | Desk local cache (wrapped keys, cached ciphertext, sanitized copies) | C-15/C-16 | device key + member key | while membership valid; purge on tombstone sync | Zeroize + file delete in encrypted app store |
| D-13 | Viewer VM scratch | C-17 | tmpfs | per job | VM destruction |
| D-14 | Export Packages | outside system (media, recipients) | recipient keys / LUKS | **not controllable** | Custody record only; recall request workflow (§8) |
| D-15 | Backups | C-27 Backup Store | backup encryption key + inner encryption | per `19-BACKUPS-DR.md` (BAK-019): BS-CORE ≤ 35 days; BS-CORE-WAL, BS-INTAKE and BS-ERASURE ≤ 14 days; EE monthly BS-CORE sets up to 12 months only as ADVANCED with the warning that server-visible metadata of disposed cases persists for that long | Expiry + crypto properties (§7) |
| D-16 | Replicas (EE-HA streaming replicas) | C-12 replicas | same as primary | real-time | Deletes replicate; crypto-erase applies |
| D-17 | VM/disk snapshots and infrastructure-level backups (hypervisor, SAN, enterprise backup of core hosts) | C-39 / provider / customer backup estate | at-rest encryption | operator-defined; **MUST exclude the vault volume** (attested, ADR-044(4)) and SHOULD be ≤ BS-CORE retention | Snapshot deletion; crypto-erase (only if vault excluded) |
| D-18 | Notifications | C-23 outbound queue | content-free | 7 days | Row delete |
| D-19 | SOURCE-SENSITIVE counters | C-08 (daily), C-24 (monthly) | — | daily: until monthly aggregation; monthly: 13 months | Row delete |
| D-20 | Z-INTAKE host logs | journald volatile | — | ≤ 24 h (max 48 h), per 20 §12 | Volatile |
| D-21 | Staff accounts, authenticator registrations | C-21 | — | account life + 400 days (SECURITY audit alignment) | Row delete; key bundles remain in C-14 (append-only, public keys only) |
| D-22 | Key Directory / transparency log entries | C-14 | public | permanent (public keys, hashes, role labels; no personal names on ANONYMOUS channels, 14 §8.1) | Not deleted (append-only log; retired-member role labels remain — see §15 item 9) |
| D-23 | Deletion receipts | C-24 / C-12 | signed | 10 years default | Interval deletion |
| D-24 | Erasure Key Vault (per-case E_case) | H-CORE host-local file (never a DB schema), DR-site replica; BS-ERASURE (≤ 14 d) | TPM (physical TPM for HIGH/GOV) or HSM | with case | E_case destruction on all replicas (§6.2) |
| D-25 | Erasure log (signed append-only list of erased case IDs, ADR-044(4)) | C-24 and witness-cosigned checkpoints; included in every backup set | signed | ≥ longest backup retention in force + 1 year (default 10 years, aligned with D-23) | Interval deletion after all backups predating the entries have expired |
| D-26 | Intake deletion list (hashes of deleted `lookup_id`s and reply references, RVW-A-28) | C-08; included in BS-INTAKE | none (random-looking hashes) | 30 days (≥ BS-INTAKE retention + margin) | Row delete |

## 5. Case retention schedules (organization policy)

### 5.1 Policy model

Retention policy = signed tenant configuration (`candor.retention.v1`), versioned, dual-approved (CHANNEL_OWNER + RECORDS_OFFICER or OVERSIGHT), with per-channel overrides and optional imported jurisdiction/records packs (EE: NARA/LAC/state schedule import).

| Field | Example |
|---|---|
| `class_id` | `CLOSED_SUBSTANTIATED` |
| `trigger` | `event:closure_approved` / `event:dismiss_approved` / `event:referred` / `event:purge_approved` |
| `duration` | `P3Y` |
| `then` | `DISPOSE` / `REVIEW` (human decision) / `ARCHIVE_EXPORT_THEN_DISPOSE` (records transfer) |
| `requires_disposition_authority` | bool (GOV/records law) |
| `legal_ref` | text |

### 5.2 Defaults (CE generic; jurisdiction packs override; not legal advice)

| Class | Trigger | Default | Rationale |
|---|---|---|---|
| `SPAM_ABUSE` | dismiss (SPAM) | 7 days | minimization; allow reviewer correction |
| `IRRELEVANT_PURGE` | EU Art 17 purge approved | immediate (content); tombstone only | B-CO-02 Art 17 |
| `OUT_OF_SCOPE_DISMISSED` | dismiss (OUT_OF_SCOPE) | 90 days | feedback period; GlobaLeaks default 90-day report TTL as reference (R2 §1.7, GlobaLeaks `tip_timetolive` default; B-GL-38) |
| `CLOSED_NO_ACTION` | closure, outcome unsubstantiated/inconclusive | 1 year | ISO 37002 8.4 post-closure detriment monitoring (B-CO-01) |
| `CLOSED_SUBSTANTIATED` | closure, outcome substantiated | 3 years | remediation evidence, possible proceedings |
| `REFERRED` | referral acknowledged | 1 year | receiving body is custodian |
| `LITIGATION` | legal hold release | 1 year after release then REVIEW | proceedings |
| `IDENTITY` | closure | 90 days after closure unless case under hold | EU Art 16 minimization of identity (B-CO-02) |

EU-oriented packs follow Art 18(1) "no longer than necessary and proportionate" and national/CNIL guidance (B-CO-12; specific durations UNVERIFIED in R6 and must be confirmed by `25-COMPLIANCE.md`). GOV packs follow agency records schedules (44 USC ch. 33; LAC Act s.12; B-CO-19/R6 Topic B).

### 5.3 Retention engine

- C-10 job `RETENTION` runs daily; computes due dispositions; for each due case creates a `DISPOSAL_PROPOSAL` requiring DC-03 approval (RECORDS_OFFICER or OVERSIGHT + CASE_LEAD). If `then=DISPOSE` and no approval within 30 days, reminders escalate to OVERSIGHT (content-free); **no silent auto-deletion of cases** (anti-suppression symmetry: deletion is as controlled as closure) — except classes `SPAM_ABUSE` and D-01/D-03/D-18/D-19/D-20 which are automatic.
- Tenant option `AUTO_DISPOSE_AFTER_GRACE` (default off): if enabled, disposal proceeds automatically 30 days after proposal unless objected; enabling is DANGEROUS (dual approval) because it enables deletion by inaction.
- Policy changes never shorten retention of already-closed cases without an explicit reviewed recompute (dual approval), preventing retroactive mass deletion by a policy edit (THR-020).

## 6. Secure and cryptographic deletion (ADR-025)

### 6.1 What must be destroyed to crypto-erase a case

| Key material | Where copies exist | Destruction action |
|---|---|---|
| Case key K (and generations K', K''…) | wrapped to each member X-Wing key (C-12), wrapped to Recovery Quorum key (C-12, optional), cached in member Desks (D-12), in backups of C-12 | (a) delete wraps in C-12; (b) destroy the case's Erasure Key (§6.2), rendering wraps in backups/replicas/snapshots undecryptable; (c) Desk tombstone → zeroize |
| Per-object DEKs | wrapped under K inside case record | unreachable once K is unreachable |
| Identity DEK (ADR-014) | wrapped to Identity Custodians + Erasure Key | same pattern |
| Member Epoch keys | member Desks, C-12 wraps | destroyed per ADR-008/ADR-030 schedule (independent of case) |

### 6.2 Erasure Key Vault semantics (outer layer; ADR-033(3), ADR-044(4))

Problem solved: member-key wraps live in C-12 and therefore in data backups, and member private keys persist on devices; without an extra layer a restored backup plus any current member's device would still decrypt a "deleted" case.

Construction (layered, never direct):
- Each case has a random 256-bit **Erasure Key** E_case. Every member-key wrap, quorum wrap and identity-DEK wrap is stored in C-12 as `AEAD(E_case, wrap)`: E_case is an **outer** layer around wraps that still require a member (or quorum/custodian) private key to open.
- **No wrap of the case key directly under E_case exists anywhere.** E_case alone, or E_case plus the DB, opens nothing (DEL-004, DEL-018). This is the binding reading of ADR-033(3)'s "additionally wrapped" (RVW-B-21(c)).
- **Location:** a host-local vault file on H-CORE — never a PostgreSQL schema, so it is never in WAL, Patroni replicas or BS-CORE (RVW-C-08). CE: TPM-sealed SQLite; HIGH/GOV: sealed to the **physical** host TPM, not a vTPM (ADR-044(4)); EE: HSM (C-29) objects or HSM-wrapped store.
- **DR replication:** the vault is replicated to the DR site within the HA RPO (ADR-044(4)); disposal is confirmed on all replicas (primary, standby, DR) before the receipt is signed.
- **Backups:** only BS-ERASURE, retained ≤ 14 days on every tier (19 BAK-028/029). Every restore applies the signed **erasure log** (D-25) before serving (§7 B3).
- **Infrastructure-level backups** (hypervisor, SAN, enterprise VM backup) of core hosts MUST exclude the vault volume and vTPM state; the configuration checker requires a signed attestation by the owning team (`cfg.attestation_recorded`), and without it the published deletion statement omits the 14-day backup bound (§11, DEL-020) (RVW-C-06).
- **Availability dependency:** loss of all vault copies makes every case unreadable server-side until members' Desks re-wrap case keys they hold (re-wrap procedure owned by 04/12/19; RVW-C-07). This is a deliberate trade-off: the same property that bounds deletion makes the vault an availability dependency.
- Disposal = destroy E_case on all vault replicas (HSM destroy object / TPM-store row delete + VACUUM) + delete wraps + delete blobs + append case ID to the erasure log + tombstones.

Resulting bound: T_erase(backups) = disposal time + BS-ERASURE retention (≤ 14 days), independent of data-backup retention (≤ 35 days, or ≤ 12 months for ADVANCED monthly sets) — **for content only**, and **only if** infrastructure-level backups exclude the vault. Server-visible metadata follows §7 B7.

### 6.3 Physical deletion (best-effort)

| Store | Action | Limits |
|---|---|---|
| C-13 blobs (filesystem) | unlink; filesystem on LUKS2; periodic `fstrim` | SSD wear-levelling, CoW snapshots retain blocks |
| C-13 (S3-compatible on-prem) | DeleteObject incl. all versions; bucket versioning off or lifecycle purge ≤ 1 day | provider retention, replication lag |
| C-12 PostgreSQL | DELETE + `VACUUM` of affected tables (daily); WAL segments retained ≤ 24 h beyond archive needs | WAL archives in backups (covered by EKV) |
| EKV (TPM-sealed SQLite) | `secure_delete=ON`, VACUUM | flash media remanence (mitigated: E_case stored encrypted under TPM-sealed key rotated monthly; old sealing key destroyed) |
| HSM objects | C_DestroyObject | HSM vendor backups (must be disabled or aligned with EKV window) |
| Desk | delete encrypted cache files; zeroize memory | OS swap/hibernation (Desk requires encrypted swap or none; documented) |
| Media end-of-life | NIST SP 800-88r2 Purge/Destroy (B-CR-33) per `17-INFRASTRUCTURE.md` | — |

Overwrite-based "secure deletion" is not relied upon (unreliable on SSD/CoW/cloud; B-GL-04).

### 6.4 Tombstones and deletion receipts

After disposal, remaining server-side records are:
- Case tombstone (C-12): `case_id`, tenant, retention class, disposal date, receipt ID. No channel, ACL, COI tags, dates of receipt, or states (minimize).
- CASE audit tombstone (`20-LOGGING-AUDITING.md` AUD-012).
- Deletion receipt (signed by the Audit key and by the approvers' identity keys): {receipt_id, case_id, disposal date, class, legal hold check result, approvers, list of destroyed key IDs (E_case ID, wrap IDs), number of blobs deleted, BS-ERASURE expiry date, erasure-log sequence number, verification results (§12)}. No content, hashes of content or filenames.

## 7. Backups, replicas and snapshots

| Rule | Detail |
|---|---|
| B1 | Data backups (BS-CORE, BS-CORE-WAL, BS-INTAKE) contain C-08/C-12/C-13 data in encrypted form plus configuration; they never contain the vault, member private keys, Member Epoch private keys (unwrapped), or the Recovery Quorum private key (19 constrains the Backup Agent C-27). |
| B2 | Backup encryption (outer layer) uses BK-DATA (19) — protects metadata only; content protection is inner (REQ-H-55). |
| B3 | **Erasure log applied on restore (ADR-044(4)).** Before a restored instance serves any request, C-10 applies the signed erasure log (D-25, taken from the witness-cosigned audit checkpoints, not from the restored set alone): rows, blobs and wraps of every listed case are deleted and any vault entry for them is destroyed. If the erasure log cannot be verified, the instance refuses to start. |
| B4 | EE-HA and DR: disposal deletes replicate; the vault is replicated to the standby and DR site within the HA RPO and disposal is confirmed on all vault replicas before the receipt is signed. Intake DBs are not replicated in any profile (ADR-046(1)). |
| B5 | Hypervisor/cloud snapshots and infrastructure-level backups of Z-CORE hosts MUST exclude the vault volume (and vTPM state) — attested by the owning team, because the guest cannot detect them; C-25 checks snapshot inventories where platform APIs allow (PRIVATE-CLOUD/MANAGED). Without the attestation, §11 states that the 14-day bound does not hold (RVW-C-06). |
| B6 | **Intake backups (19 BS-INTAKE, ≤ 14 days):** contain source account records (D-02), sealed replies (D-03) and not-yet-pulled envelopes (D-01), encrypted to BK-DATA. Source deletions are made durable across intake DR by the intake deletion list (D-26): it is included in BS-INTAKE and applied immediately after any intake restore, and C-09 re-push after DR skips replies whose mailbox or reply reference is listed (RVW-A-28). Intake onion keys are backed up only in BS-SECRETS per ADR-028 placement. |
| B7 | **Case metadata in backups (minimized, RVW-B-21(a)).** After disposal, BS-CORE sets taken before disposal still hold the case's server-visible metadata until they expire (≤ 35 days default): channel, state, flags, ACL user IDs, SLA dates, `received_day`, `import_slot_date`, 8 blinded COI tags (not identifiable without the case key, ADR-037(3)) and pre-disposal CASE audit events. They do **not** hold: COI exclusion identities, follow-up day lists (ADR-038(3)), recipient key IDs (ADR-033(1)), batch times, or any content. EE monthly sets retained up to 12 months (ADVANCED) extend this metadata tail and the configuration dialog says so. |
| B8 | **Object Lock.** Compliance-mode locks (19 BAK-006) cannot be shortened; an urgent purge (EU Art 17 "manifestly irrelevant", accidentally captured identity data) is executed by E_case destruction, which makes locked content unreadable after BS-ERASURE expiry; server-visible metadata in locked sets remains until the lock expires (documented, RVW-B-21(d)). |

## 8. Exported evidence

- Export Packages (10 §15) leave the system's control. Deletion of a case does not delete exports.
- Custody records of exports are retained with the case and survive in the deletion receipt as counts (destination classes) only.
- Recall workflow: at disposal, the approvers see the list of exports (package IDs, destination classes, recipients) and must confirm one of: `RECALL_REQUESTED` (content-free notice to known recipients via their own channels), `RETAINED_BY_RECIPIENT_UNDER_LAW`, `DESTROYED_CONFIRMED` (recipient attestation). The choice is recorded in the receipt.

## 9. Source-initiated delete and abandon

| Action | Effect | Honest message to source |
|---|---|---|
| "Delete my mailbox" (source logged in) | Deletes D-02 source account record and D-03 replies immediately from the live intake; adds their hashes to the intake deletion list (D-26) so an intake restore cannot resurrect them; encrypted copies in BS-INTAKE expire within 14 days; the case team learns only "mailbox closed during ISO week W", released after a random 3–21 day delay (14 CASE-035, RVW-B-26); future replies impossible | "Your mailbox and its replies have been deleted from the live system now. Encrypted backup copies expire within 14 days and are never restored. The team will learn, within a few weeks, that the mailbox was closed; if you close it right after something happens at work, that timing could point to you. What you already submitted remains with the organization under its retention policy, because it may be needed to act on your report." |
| "Withdraw my report" (message) | Creates a case task; handling per policy (e.g., stop investigation where lawful, consider Art 17 purge); not automatic deletion | "Your request has been sent to the case team. They may be legally required to keep or act on the report." |
| Abandonment (365 days after the account's `activity_month`, default) | D-02/D-03 deleted automatically; case unaffected; no login tracking exists (RVW-B-11) | Shown at submission: "Your mailbox is deleted about 12 months after the last message in either direction. Replies can be read for 30 days after they arrive." |
| Lost passphrase | Nothing to delete by identity (no recovery by design, ADR-005); account expires by abandonment rule | "We cannot recover or delete your mailbox without your passphrase." |

Tier W deletion requires login (C-07 verifies passphrase); Tier V signs the deletion request with the source key.

## 10. Legal holds

| Aspect | Specification |
|---|---|
| Scope | case (all objects, wraps, identity entries), or specific evidence objects; tenant-wide hold (e.g., litigation) by COUNSEL with OVERSIGHT approval. A tenant-wide hold SHALL NOT block source-initiated mailbox deletion or scheduled Sealed Identity Store deletion unless the hold order expressly names them (RVW-C-10) |
| Set / release | DC-05 dual control (COUNSEL + CASE_LEAD or OVERSIGHT), step-up; `hold_ref` (external matter ID) encrypted in case; server stores hold flag + review date |
| Disclosure | while any tenant-wide hold is active the source landing page shows "A legal hold currently suspends deletion" (no detail) |
| Effect | blocks all deletion incl. DERIVED objects, Art 17 purge, source-initiated case effects (mailbox deletion still allowed: it does not delete case content), retention proposals; audit/receipt retention extended |
| Review | every 90 days reminder to COUNSEL; unreviewed hold > 180 days escalates to OVERSIGHT |
| Release | returns case to its retention clock; if due, disposal proposal created |
| Sealed matters (e.g., qui tam 31 USC 3730(b)) | `SEALED_MATTER` flag (14) + hold |

## 11. Where "delete" ≠ physical erasure

| Situation | What "delete" means there | When physical/cryptographic unrecoverability is reached | User-facing statement |
|---|---|---|---|
| Case disposal | Crypto-erase via E_case destruction on all vault replicas + wraps + blobs deleted + erasure-log entry | Live: immediately. Content in Candor backups: after BS-ERASURE expiry (≤ 14 days). Server-visible metadata in backups: after BS-CORE expiry (≤ 35 days; ≤ 12 months for ADVANCED monthly sets). Infrastructure-level backups: 14-day bound only if they exclude the vault (attested). Physical blocks: unknown | Generated from configuration (DEL-020). With attestation: "Deleted cases become unreadable immediately on the live system. Their content becomes unreadable in backups within 14 days; case-handling records (dates, status, who worked on it) remain in encrypted backups for up to {bs_core_retention} days." Without attestation: "…The organisation has not confirmed that its own server backups exclude the deletion keys, so copies may remain readable in those backups for longer." |
| SSD/flash media | Blocks may persist after unlink/TRIM | Unrecoverable only via crypto-erase (LUKS + content crypto) or media Purge/Destroy (B-CR-33) | Admin docs |
| Legal hold | Deletion suspended | After hold release + retention | Case UI banner "Deletion suspended: legal hold" |
| Records-law disposition required | Deletion waits for disposition authority | After approval | Admin/records officer UI |
| Exported evidence | Not deleted | Never by the system | Disposal dialog lists exports |
| Member device offline | Cached material remains until device syncs | On next sync; if device offline > 30 days, the device is **suspended** (no further delivery) and OVERSIGHT decides on revocation; wraps are deleted only under DC-15 (ADR-044(1), RVW-C-03) | Admin device list |
| Lost/stolen device | Cached ciphertext + possibly wrapped keys | Protected by device key + hardware authenticator; never "erased" | Incident procedure (31) |
| Source mailbox deletion | Account + replies deleted; hashes added to the intake deletion list | Live: immediately. BS-INTAKE copies: expire ≤ 14 days and are never restored into service (deletion list applied on restore, B6) | §9 message |
| Audit records | Replaced by tombstone | Backups: per SECURITY backup rotation (audit contains no content) | Audit policy |
| Key Directory entries | Never deleted (public keys) | n/a | Transparency policy |
| Plaintext that reached swap/hibernation/journal | Not reachable by crypto-erase | Unknown | Desk requirements forbid unencrypted swap; documented residual |
| Human notes, printouts, screenshots | Outside system | Never by the system | Training (32 HUM) |

## 12. Deletion verification

| Check | Method | When |
|---|---|---|
| V1 Wraps absent | query C-12 for any wrap rows of case_id = 0 | at disposal |
| V2 E_case absent | vault lookup returns NOT_FOUND on all vault replicas incl. standby and DR site; HSM object handle invalid | at disposal |
| V3 Blobs absent | C-13 list/HEAD for each blob_ref (incl. versions) = 404 | at disposal |
| V4 Decryption impossible | test decryption with a designated verification member key is not performed (would require key access); instead: structural check that no `AEAD(E_case, …)` can be opened because E_case missing | at disposal |
| V5 Desk purge | each member Desk acknowledges tombstone processing (signed ack); missing acks listed in receipt; devices without ack after 30 days are suspended and escalated to OVERSIGHT | ≤ 30 days |
| V6 BS-ERASURE expiry | BS-ERASURE inventory (all tiers) shows no set older than disposal time + 14 days | at disposal + 14 days; recorded as receipt addendum |
| V7 Backup restore test | quarterly: restore a backup predating a test-case disposal to an isolated host; attempt to open the test case with a test member key → must fail (E_case missing); erasure-log application removes rows; intake restore test shows a deleted test mailbox is not resurrected | quarterly (19) |
| V9 Erasure log | case ID appended to the signed erasure log and included in a witness-cosigned checkpoint | at disposal |
| V8 Receipt integrity | receipt signatures and inclusion in witness-cosigned audit checkpoint | at disposal |

## 13. GDPR and records-law interplay

| Topic | Rule in Candor |
|---|---|
| Storage limitation (GDPR Art 5(1)(e)); EU Directive Art 18(1) | Retention classes with bounded defaults; policy documented in ROPA/DPIA templates (25) |
| Manifestly irrelevant data (Directive Art 17) | Triage purge action (CASE-028), immediate crypto-erase |
| Right to erasure (GDPR Art 17) by a person concerned or reporter | Evaluated case-by-case; exceptions Art 17(3)(b) legal obligation and (e) legal claims; decision recorded with reason code; erasure executed via standard disposal or partial purge (evidence-level) with dual control |
| Right of access (Art 15) vs reporter protection (Art 15(4), Art 23 national restrictions) | DSAR workflow in `25-COMPLIANCE.md`; deletion engine never deletes to evade a pending DSAR: a pending DSAR places a temporary hold (`DSAR_PENDING`, max 3 months) |
| Deferred notice to persons concerned (Art 14(5)(b)) | timer in case; independent of retention |
| Records law (44 USC ch. 31/33; LAC Act s.12; state schedules) | `requires_disposition_authority=true` blocks disposal until RECORDS_OFFICER records authority reference; archival export (PDF/A + JSON/XML metadata) before disposal when schedule demands transfer (EE) |
| FOIA/ATIP | Retention unaffected by requests except statutory preservation holds (treated as legal holds) |
| Discoverability (FOIA/ATIP, DSAR Art 15, eDiscovery, breach scoping Art 33/34 incl. persons concerned) | Searches run only in the Desk of an authorized member or a RECORDS_CUSTODIAN holding explicit time-bounded case grants from the Triage Set, over a local index of cases it can decrypt; no server-side global search (ADR-044(5); `14-CASE-MANAGEMENT.md` §8.7). Completeness is evidenced per case by signed hit/no-hit attestations. |
| Records custody (GOV) | GOV profile default: Organization Recovery Quorum **enabled** with custodians from independent roles, disclosed to sources on the landing page, because records law may prohibit unrecoverable loss (ADR-044(3)); CE/EE default remains disabled. Where disabled in a records-scheduled deployment, the records officer's written acceptance of device-loss risk is recorded. |
| Conflict resolution order | Legal hold > statutory records obligation > DSAR pending hold > retention schedule > minimization defaults |

## 14. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| RET-001 | Every data object in §4 SHALL have a defined retention class, owner and deletion mechanism, and the inventory SHALL be machine-readable and checked in CI against the database schema. | B-CO-09 (GDPR Art 5(1)(e)); B-CO-02 (Art 18) | THR-017; THR-015 | C-10; C-12 | TST: schema-to-inventory drift check in CI |
| RET-002 | Sealed envelopes in C-08 SHALL be deleted within 24 h after the C-09 pull is acknowledged. | ADR-009; ADR-008 | THR-015; THR-031 | C-08; C-09 | TST: envelope absent 24 h after ack (time-advanced) |
| RET-003 | Source account records SHALL be deleted on source request, on case disposal, or 365 days (configurable 90–730) after the last reply delivered, whichever occurs first. | ADR-005; REQ-H-23 | THR-034; THR-015 | C-08 | TST: each trigger fixture |
| RET-004 | Pending sealed replies SHALL be deleted 30 days after being read or 365 days after creation, whichever occurs first. | ADR-010 | THR-015 | C-08 | TST: time-advanced fixtures |
| RET-005 | Retention policies SHALL be signed, versioned tenant configurations requiring dual approval, and SHALL support per-channel overrides and imported jurisdiction/records packs (EE). | B-CO-02 (Art 18); R6 Topic B | THR-020; THR-035 | C-10; C-19 | TST: unsigned or single-approved policy rejected |
| RET-006 | Policy changes SHALL NOT shorten the retention of already closed or dismissed cases without an explicit recompute approved under dual control. | INC-22 | THR-020 | C-10 | TST: policy edit leaves existing due dates unchanged until approved recompute |
| RET-007 | Case disposal SHALL require a disposal proposal approved under DC-03, except for `SPAM_ABUSE` class; automatic disposal after a grace period SHALL be available only as a DANGEROUS configuration. | ADR-025; INC-22 | THR-020; THR-018 | C-10; C-22 | TST: disposal without approvals denied; grace mode requires dual-approved config |
| RET-008 | The default retention classes of §5.2 SHALL ship in the CE generic pack, labelled as defaults requiring legal review. | B-CO-12; B-CO-01 | — | C-10 | INSP: pack content and labels |
| RET-009 | Legal holds SHALL be set and released only under DC-05 dual control with step-up, SHALL block all deletion paths for the held scope (incl. Art 17 purge and derived-object deletion), and SHALL trigger review reminders every 90 days and OVERSIGHT escalation after 180 days unreviewed. | R6 WB-36; B-CO-15 | THR-037; THR-020 | C-10; C-22 | TST: each deletion path attempted under hold → denied; reminder and escalation timers |
| RET-010 | A pending DSAR SHALL place a temporary `DSAR_PENDING` hold (max 3 months) preventing disposal of the affected case. | B-CO-09 (Art 15); B-CO-10 | THR-020 | C-10 | TST: disposal blocked while DSAR pending |
| RET-011 | When `requires_disposition_authority` is set, disposal SHALL be blocked until a RECORDS_OFFICER records the authority reference, and archival export SHALL precede disposal when the schedule requires transfer. | R6 Topic B (44 USC 3303; LAC Act s.12) | — | C-10 | TST: disposal blocked without authority reference |
| RET-012 | Snapshots of Z-CORE volumes SHALL have lifetime ≤ the EKV snapshot lifetime or exclude the EKV volume and be subject to deletion-ledger replay; C-25 SHALL check snapshot inventories where platform APIs allow. | ADR-025; INC-55 | THR-017; THR-030 | C-25; C-39 | TST: over-age snapshot fixture raises violation; INSP: deployment docs |
| RET-013 | Desk caches of case material SHALL be purged on processing of a revocation or disposal tombstone, and devices not acknowledging within 30 days SHALL be revoked. | ADR-025 | THR-017; THR-031 | C-15; C-21 | TST: tombstone processing removes cache files; missing ack → device revoked |
| RET-014 | Audit and receipt retention SHALL follow `20-LOGGING-AUDITING.md` §12 and SHALL be extended for cases under legal hold. | ADR-016 | THR-037 | C-24 | TST: hold extends CASE stream retention |
| DEL-001 | Case deletion SHALL be performed by cryptographic erasure: destruction of the case Erasure Key in all EKV copies, deletion of all case-key and identity wraps, and deletion of evidence blobs, followed by best-effort physical deletion. | ADR-025; B-CR-33 | THR-017; THR-031 | C-10; C-12; C-13; C-29 | TST: post-disposal state checks V1–V3; AUD: crypto-erase design review |
| DEL-002 | All case-key wraps and identity-DEK wraps SHALL be stored only encrypted under a per-case Erasure Key held in the Erasure Key Vault, which SHALL be excluded from data backups. | ADR-025; INC-55; REQ-H-55 | THR-017 | C-12; C-27; C-29 | TST: backup content inventory contains no EKV material; INSP: backup agent config |
| DEL-003 | EKV snapshots SHALL be stored separately from data backups and SHALL be retained no longer than the configured EKV lifetime (default 14 days, range 1–35 days). | ADR-025 | THR-017 | C-29; C-27 | TST: EKV snapshot rotation job; over-age snapshot absent |
| DEL-004 | Possession of the EKV alone SHALL NOT enable decryption of any case content. | ADR-015; ADR-007 | THR-018; THR-014 | C-12; C-29 | TST: attacker model test with EKV + DB + blobs but no member key → no plaintext; AUD: crypto review |
| DEL-005 | Restoring any backup SHALL replay the deletion-receipt ledger before the restored instance serves requests, removing records and blobs of disposed cases. | ADR-025; INC-55 | THR-017; THR-018 | C-10; C-27 | TST: restore backup predating disposal; disposed case absent after replay; service refuses to start if ledger unavailable |
| DEL-006 | Each disposal SHALL produce a deletion receipt signed by the audit key and approvers, listing destroyed key IDs, blob count, legal-hold check, export dispositions and verification results V1–V8, and containing no content, content hashes or filenames. | ADR-025; B-CR-33 | THR-037; THR-016 | C-10; C-24 | TST: receipt schema test; signature verification; canary absence |
| DEL-007 | After disposal only the minimal tombstone of §6.4 SHALL remain in C-12. | ADR-016; ADR-010 | THR-015 | C-12 | TST: row inspection post-disposal |
| DEL-008 | Deletion verification V1–V3 and V8 SHALL complete before the disposal is reported successful; V5 and V6 SHALL be recorded as receipt addenda when complete. | B-CR-33 | THR-017 | C-10; C-25 | TST: induced failure of any check leaves disposal in `VERIFYING` state and alerts |
| DEL-009 | A quarterly restore test (V7) SHALL demonstrate that a pre-disposal backup cannot yield the disposed case's content. | INC-55; REQ-H-55 | THR-017 | C-27; C-25 | DEMO: quarterly restore-test report; TST: automated variant in staging |
| DEL-010 | Physical deletion SHALL include PostgreSQL VACUUM of affected tables within 24 h, blob deletion of all object versions, and filesystem TRIM on LUKS2 volumes; overwrite-based deletion SHALL NOT be claimed as a guarantee. | B-GL-04; B-CR-33 | THR-017 | C-12; C-13; C-39 | INSP: job configuration; TST: blob versions absent |
| DEL-011 | Disposal approvers SHALL be shown all Export Packages of the case and SHALL record a disposition (RECALL_REQUESTED, RETAINED_BY_RECIPIENT_UNDER_LAW, DESTROYED_CONFIRMED) for each before disposal completes. | ADR-018; INC-24 | THR-041 | C-10; C-15 | TST: disposal blocked with unresolved export entries |
| DEL-012 | Sources SHALL be able to delete their mailbox (account record and pending replies) after authentication, with the §9 message stating that submitted material is retained under the organization's policy. | ADR-005; ADR-002; B-CO-09 | THR-034; THR-040 | C-06; C-07; C-03; C-08 | TST: deletion removes D-02/D-03; DEMO: copy review |
| DEL-013 | The source UI SHALL state the mailbox abandonment period at submission time. | ADR-002 | THR-040 | C-06; C-03 | DEMO: copy review |
| DEL-014 | EU Art 17 irrelevant-data purges and GDPR erasure decisions SHALL be executed through the same crypto-erasure mechanism at case or evidence level with dual control and reason codes. | B-CO-02 (Art 17); B-CO-09 (Art 17) | THR-017 | C-10; C-15 | TST: evidence-level purge removes DEK wrap and blob; audit event present without content |
| DEL-015 | Processes and VMs handling plaintext (C-07, C-15, C-17) SHALL run without unencrypted swap and with core dumps disabled, and the Desk SHALL refuse to run on hosts with unencrypted swap or hibernation unless a documented override is recorded. | B-CR-33 (CE caveat); REQ-H-58 | THR-017; THR-031 | C-07; C-15; C-17 | TST: Desk startup check on host with plain swap → refuse/warn; SIGSEGV no core |
| DEL-016 | User-facing and administrator documentation SHALL present the §11 table of situations where deletion is delayed or incomplete. | ADR-025 | THR-040 | C-15; C-19 | INSP: documentation review |
| DEL-017 | Epoch private keys SHALL be destroyed (wraps deleted, Desk zeroize) at the later of decrypt-window end and import or abandonment of all envelopes of the epoch. | ADR-008 | THR-013; THR-017 | C-15; C-12 | TST: destruction timing fixtures (see CASE-020) |

## 15. Residual risks and limitations

1. **EKV window.** For the EKV snapshot lifetime (default 14 days), a party with an EKV snapshot, a data backup and a current member's unlocked key could recover a disposed case.
2. **Member key persistence.** Until member X-Wing keys rotate, any surviving copy of wraps + E_case + a member device key suffices; periodic member key rotation (see `04-CRYPTOGRAPHY.md`) shrinks this.
3. **Outside-system copies.** Exports, printouts, notes, screenshots and recipient systems are unaffected by deletion.
4. **Offline/lost devices.** Revocation cannot erase data on devices the organization no longer controls.
5. **Provider layers.** Cloud/hypervisor snapshots and storage-provider replication in PRIVATE-CLOUD/MANAGED profiles may outlive our controls (THR-030).
6. **HSM backups.** HSM vendor backup features can retain E_case; must be disabled or aligned — a configuration dependency.
7. **Media remanence.** Physical traces on SSDs persist; only crypto-erase and end-of-life Purge/Destroy address them.

## 16. Open issues

1. OI-35-1: Confirm jurisdiction retention defaults (CNIL référentiel durations, EDPS guidance, state/agency schedules) with `25-COMPLIANCE.md`; current defaults are generic.
2. OI-35-2: EKV implementation on CE-SINGLE (TPM availability on commodity/VM hosts); fallback to an offline-key-sealed file with documented weaker guarantees.
3. OI-35-3: Whether `D-21` staff account data retention aligns with employment-law retention in each jurisdiction.
4. OI-35-4: ASM-027 should reference the Erasure Key Vault backup exclusion (DEL-002/003) and device-sync revocation (RET-013) as its monitoring method.

### Open Issues for ADR revision

- **ADR-025 propagation claim.** ADR-025 says key destruction propagates to backups because "case keys wrapped only to member keys and quorum". Member-key wraps are themselves in backed-up C-12 and member private keys persist on devices, so destroying live wraps does **not** make backup copies unreadable. This spec conforms to the ADR's intent by adding a per-case **Erasure Key** layer held in a non-backed-up Erasure Key Vault with a bounded snapshot lifetime (§6.2, DEL-002/003). Proposed ADR amendment: "Case-key wraps are stored under a per-case Erasure Key held outside data backups; crypto-erasure destroys the Erasure Key; backups become unreadable for the case within the EKV snapshot lifetime (default 14 days)."
- **ADR-008 epoch destruction wording** (see `14-CASE-MANAGEMENT.md`), reflected in DEL-017.
