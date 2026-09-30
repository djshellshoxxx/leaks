# 35 — Data Retention and Deletion
Status: Draft v1.0 · Edition applicability: both (CE: retention engine, legal hold, crypto-erasure, verification; EE/GOV: records-schedule import, disposition authority workflow, archival export, HSM-backed erasure keys) · Owner: Data Lifecycle team

## 1. Purpose and scope

Specifies how long every class of data is kept, how organizations configure retention, how legal holds override it, and how deletion is performed and verified — cryptographically (ADR-025) and physically — across live stores, backups, replicas, snapshots, attachments, logs, exported evidence and recipient devices. Covers source-initiated delete/abandon, the interplay of GDPR and records law, and an honest statement of where "delete" does not mean immediate physical erasure.

**Protection statement.**
- WHAT: confidentiality of reports, evidence and source-linked metadata after their retention ends.
- FROM WHOM: later attackers or compelling parties who obtain storage media, backups or snapshots (THR-017, THR-031, THR-030, THR-026); insiders who would keep or restore deleted cases (THR-018).
- ASSUMPTIONS: keys are destroyed in all copies (NIST SP 800-88r2 crypto-erase precondition, B-CR-33); the Erasure Key Vault (§6.2) is not backed up beyond its bounded backup window; member devices sync within the device-offline limit or are revoked; plaintext never reached persistent media (no swap, tmpfs disposables; B-CR-33 caveat). Registered as ASM-027 (key erasure effective), ASM-047 (backup operators do not hold member unlock factors), ASM-029 (HSM integrity), ASM-019 (recipient workstation integrity) in `40-SECURITY-ASSUMPTIONS.md`. Protection: 40 P-18.
- RESIDUAL RISK: exported copies, copies on lost/unsynced devices, human notes, and plaintext that reached swap or journals cannot be reached by crypto-erase.

## 2. Context and dependencies

| Doc | Relationship |
|---|---|
| `DECISIONS.md` ADR-005, 008, 009, 010, 013, 014, 016, 025 | binding |
| `04-CRYPTOGRAPHY.md` | key hierarchy, wrapping, zeroization |
| `10-FILE-EVIDENCE-PIPELINE.md` | evidence objects, derivatives, exports |
| `14-CASE-MANAGEMENT.md` | states RETAINED/DISPOSED, Art 17 purge, epoch-key abandonment |
| `15-AUTHENTICATION-AUTHORIZATION.md` | dual control DC-03, DC-05, DC-12 |
| `19-BACKUPS-DR.md` | backup architecture (this doc constrains content and lifetime) |
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
| D-01 | Sealed submission envelope (ciphertext) | C-08 Intake Store | RG epoch key (ADR-008) | Until C-09 pull acknowledged + 24 h | Delete row/blob; epoch-key destruction makes all copies unreadable |
| D-02 | Source account record (`lookup_id`, public keys, verifier) | C-08 | none needed beyond minimization | `SRC-ACCOUNT`: until case disposed, or 365 days after last reply delivered, or source deletion (§9) — whichever first | Row delete + backup expiry |
| D-03 | Sealed replies awaiting source | C-08 | source key | `SRC-REPLY`: until read + 30 days, max 365 days | Row delete |
| D-04 | Source `received_day` / batch metadata | C-08, C-12 | — | with D-02 / case | with parent |
| D-05 | RG epoch private keys | member Desks (wrapped), C-12 wraps | member keys | decrypt window (14 d) and until all envelopes of the epoch imported or abandoned (CASE-020) | Destroy wraps + Desk zeroize |
| D-06 | Case record (encrypted) | C-12 | case key | by outcome (§5) | Crypto-erase case key (§6) |
| D-07 | Evidence blobs (ORIGINAL, DERIVED) | C-13 | per-object DEK wrapped under case key | with case; DERIVED may be deleted earlier | Crypto-erase + blob delete |
| D-08 | Case-key wraps (member, quorum) | C-12 (erasure-layer encrypted, §6.2) | member X-Wing keys + Erasure Key | with case | Destroy Erasure Key + delete wraps |
| D-09 | Sealed Identity Store entries (ADR-014) | C-12 | Identity Custodian keys + Erasure Key | `IDENTITY`: shortest of case retention or configured identity retention (default: case closure + 90 days) | Crypto-erase identity DEK |
| D-10 | Server-visible case metadata (state, ACL, SLA) | C-12 | at-rest encryption only | with case; tombstone after disposal (§6.4) | Row delete → tombstone |
| D-11 | Audit streams | C-24 | append-only | `20-LOGGING-AUDITING.md` §12 | Interval deletion / case tombstone |
| D-12 | Desk local cache (wrapped keys, cached ciphertext, sanitized copies) | C-15/C-16 | device key + member key | while membership valid; purge on tombstone sync | Zeroize + file delete in encrypted app store |
| D-13 | Viewer VM scratch | C-17 | tmpfs | per job | VM destruction |
| D-14 | Export Packages | outside system (media, recipients) | recipient keys / LUKS | **not controllable** | Custody record only; recall request workflow (§8) |
| D-15 | Backups | C-27 Backup Store | backup encryption key + inner encryption | backup rotation (default 35 days daily, 12 weeks weekly, 12 months monthly — see 19) | Expiry + crypto properties (§7) |
| D-16 | Replicas (EE-HA streaming replicas) | C-12 replicas | same as primary | real-time | Deletes replicate; crypto-erase applies |
| D-17 | VM/disk snapshots (hypervisor, cloud) | C-39 / provider | at-rest encryption | operator-defined; **must be ≤ backup window** | Snapshot deletion; crypto-erase |
| D-18 | Notifications | C-23 outbound queue | content-free | 7 days | Row delete |
| D-19 | SOURCE-SENSITIVE counters | C-08 (daily), C-24 (monthly) | — | daily: until monthly aggregation; monthly: 13 months | Row delete |
| D-20 | Z-INTAKE host logs | journald volatile | — | ≤ 48 h (max 7 days) | Volatile |
| D-21 | Staff accounts, authenticator registrations | C-21 | — | account life + 400 days (SECURITY audit alignment) | Row delete; key bundles remain in C-14 (append-only, public keys only) |
| D-22 | Key Directory / transparency log entries | C-14 | public | permanent (public keys, hashes only) | Not deleted (contains no personal content; staff key entries use pseudonymous IDs) |
| D-23 | Deletion receipts | C-24 / C-12 | signed | 10 years default | Interval deletion |

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
| RG epoch keys | member Desks, C-12 wraps | destroyed per ADR-008 schedule (independent of case) |

### 6.2 Erasure Key layer (makes key destruction propagate to backups)

Problem: ADR-025 states that key destruction propagates to backups because "case keys wrapped only to member keys and quorum". But the member-key wraps themselves are stored in C-12 and therefore in backups; member private keys remain valid on devices; so a restored backup plus any current member's device would still decrypt a "deleted" case.

Design (this spec; see Open Issues for ADR revision):
- Each case has a random 256-bit **Erasure Key** E_case. All case-key wraps and identity-DEK wraps are stored as `AEAD(E_case, wrap)` in C-12.
- E_case values are stored only in the **Erasure Key Vault** (EKV): a dedicated store in Z-CORE (CE: TPM-sealed SQLite file on the core host; EE: HSM C-29 objects or HSM-wrapped store), **excluded from regular backups**.
- EKV has its own backup stream with a short, fixed lifetime: encrypted EKV snapshots retained ≤ 14 days (configurable 1–35 days), stored separately from C-27 data backups. After disposal, E_case is gone from all EKV snapshots within that window.
- E_case is not a content key: it only unlocks wraps that still require a member private key. Server/admin possession of EKV does not expose content (ADR-015 preserved).
- Disposal = delete E_case from EKV (HSM destroy object / TPM-store row delete + VACUUM) + delete wraps + delete blobs + tombstones.

Resulting guarantee: T_erase(backups) = disposal time + EKV snapshot lifetime (default 14 days), independent of data-backup retention (e.g., 12 months).

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
- Case tombstone (C-12): `case_id`, tenant, retention class, disposal date, receipt ID. No channel, RG, dates of receipt, or states (minimize).
- CASE audit tombstone (`20-LOGGING-AUDITING.md` AUD-012).
- Deletion receipt (signed by the Audit key and by the approvers' identity keys): {receipt_id, case_id, disposal date, class, legal hold check result, approvers, list of destroyed key IDs (E_case ID, wrap IDs), number of blobs deleted, EKV snapshot expiry date, verification results (§12)}. No content, hashes of content or filenames.

## 7. Backups, replicas and snapshots

| Rule | Detail |
|---|---|
| B1 | Backups contain C-08/C-12/C-13 data in its encrypted form plus infrastructure config; they never contain EKV, member private keys, RG epoch private keys (unwrapped), or the Recovery Quorum private key (19 constrains the Backup Agent C-27). |
| B2 | Backup encryption (outer layer) uses a backup key (EE: HSM; CE: offline key) — protects metadata only; content protection is inner (REQ-H-55). |
| B3 | Restoring a backup older than a disposal must not resurrect cases: on restore, C-10 replays the deletion-receipt ledger (kept in the EKV-independent receipt store and in the witness-cosigned audit checkpoints) and re-applies disposals (deletes rows/blobs whose receipts exist). Wraps are already unusable (E_case missing). |
| B4 | EE-HA replicas: disposal deletes replicate synchronously; EKV is replicated only within the HA cluster (not to backups) and deletion is confirmed on all EKV replicas before the receipt is signed. |
| B5 | Hypervisor/cloud snapshots of Z-CORE volumes are prohibited unless their lifetime ≤ EKV snapshot lifetime and they exclude the EKV volume or are covered by B3; C-25 checks snapshot inventory where the platform API permits (PRIVATE-CLOUD/MANAGED); otherwise documented residual risk (THR-030). |
| B6 | Z-INTAKE hosts are not backed up except configuration and onion keys per ADR-028 placement; sealed envelopes are transient and not backed up. |

## 8. Exported evidence

- Export Packages (10 §15) leave the system's control. Deletion of a case does not delete exports.
- Custody records of exports are retained with the case and survive in the deletion receipt as counts (destination classes) only.
- Recall workflow: at disposal, the approvers see the list of exports (package IDs, destination classes, recipients) and must confirm one of: `RECALL_REQUESTED` (content-free notice to known recipients via their own channels), `RETAINED_BY_RECIPIENT_UNDER_LAW`, `DESTROYED_CONFIRMED` (recipient attestation). The choice is recorded in the receipt.

## 9. Source-initiated delete and abandon

| Action | Effect | Honest message to source |
|---|---|---|
| "Delete my mailbox" (source logged in) | Deletes D-02 source account record and D-03 pending replies immediately; case team notified in case timeline ("source closed mailbox", day-granular); future replies impossible | "Your mailbox and any unread replies have been deleted. What you already submitted remains with the organization and is kept according to its retention policy, because it may be needed to act on your report." |
| "Withdraw my report" (message) | Creates a case task; handling per policy (e.g., stop investigation where lawful, consider Art 17 purge); not automatic deletion | "Your request has been sent to the case team. They may be legally required to keep or act on the report." |
| Abandonment (no login for 365 days after last reply, default) | D-02/D-03 deleted automatically; case unaffected | Shown at submission: "If you do not log in for 12 months after our last reply, your mailbox will be deleted." |
| Lost passphrase | Nothing to delete by identity (no recovery by design, ADR-005); account expires by abandonment rule | "We cannot recover or delete your mailbox without your passphrase." |

Tier W deletion requires login (C-07 verifies passphrase); Tier V signs the deletion request with the source key.

## 10. Legal holds

| Aspect | Specification |
|---|---|
| Scope | case (all objects, wraps, identity entries), or specific evidence objects; tenant-wide hold (e.g., litigation) by COUNSEL with OVERSIGHT approval |
| Set / release | DC-05 dual control (COUNSEL + CASE_LEAD or OVERSIGHT), step-up; `hold_ref` (external matter ID) encrypted in case; server stores hold flag + review date |
| Effect | blocks all deletion incl. DERIVED objects, Art 17 purge, source-initiated case effects (mailbox deletion still allowed: it does not delete case content), retention proposals; audit/receipt retention extended |
| Review | every 90 days reminder to COUNSEL; unreviewed hold > 180 days escalates to OVERSIGHT |
| Release | returns case to its retention clock; if due, disposal proposal created |
| Sealed matters (e.g., qui tam 31 USC 3730(b)) | `SEALED_MATTER` flag (14) + hold |

## 11. Where "delete" ≠ physical erasure

| Situation | What "delete" means there | When physical/cryptographic unrecoverability is reached | User-facing statement |
|---|---|---|---|
| Case disposal | Crypto-erase via E_case destruction + wraps + blobs deleted | Live: immediately. Backups/snapshots: after EKV snapshot lifetime (default 14 days). Physical blocks: when overwritten by the filesystem/SSD (unknown) | "Deleted cases become unreadable immediately on the live system and in backups within 14 days." |
| SSD/flash media | Blocks may persist after unlink/TRIM | Unrecoverable only via crypto-erase (LUKS + content crypto) or media Purge/Destroy (B-CR-33) | Admin docs |
| Legal hold | Deletion suspended | After hold release + retention | Case UI banner "Deletion suspended: legal hold" |
| Records-law disposition required | Deletion waits for disposition authority | After approval | Admin/records officer UI |
| Exported evidence | Not deleted | Never by the system | Disposal dialog lists exports |
| Member device offline | Cached material remains until device syncs | On next sync; if device offline > 30 days, device is revoked and treated as lost (residual) | Admin device list |
| Lost/stolen device | Cached ciphertext + possibly wrapped keys | Protected by device key + hardware authenticator; never "erased" | Incident procedure (31) |
| Source mailbox deletion | Account + replies deleted | Intake backups: none (not backed up, B6); live immediately | §9 message |
| Audit records | Replaced by tombstone | Backups: per SECURITY backup rotation (audit contains no content) | Audit policy |
| Key Directory entries | Never deleted (public keys) | n/a | Transparency policy |
| Plaintext that reached swap/hibernation/journal | Not reachable by crypto-erase | Unknown | Desk requirements forbid unencrypted swap; documented residual |
| Human notes, printouts, screenshots | Outside system | Never by the system | Training (32 HUM) |

## 12. Deletion verification

| Check | Method | When |
|---|---|---|
| V1 Wraps absent | query C-12 for any wrap rows of case_id = 0 | at disposal |
| V2 E_case absent | EKV lookup returns NOT_FOUND on all EKV replicas; HSM object handle invalid | at disposal |
| V3 Blobs absent | C-13 list/HEAD for each blob_ref (incl. versions) = 404 | at disposal |
| V4 Decryption impossible | test decryption with a designated verification member key is not performed (would require key access); instead: structural check that no `AEAD(E_case, …)` can be opened because E_case missing | at disposal |
| V5 Desk purge | each member Desk acknowledges tombstone processing (signed ack); missing acks listed in receipt; devices without ack after 30 days are revoked | ≤ 30 days |
| V6 EKV snapshot expiry | EKV snapshot inventory shows no snapshot older than disposal time + lifetime | at disposal + lifetime; recorded as receipt addendum |
| V7 Backup restore test | quarterly: restore a backup predating a test-case disposal to an isolated host; attempt to open the test case with a test member key → must fail (E_case missing); ledger replay removes rows | quarterly (19) |
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
