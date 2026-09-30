# 14 — Case Management
Status: Draft v1.0 · Edition applicability: both (CE: full workflow, SLA engine, COI routing, anti-suppression; EE adds rule designer, multi-jurisdiction calendar packs, regulator exports) · Owner: Case Workflow team

## 1. Purpose and scope

Specifies the lifecycle of a report from intake to deletion: intake, classification, triage, acknowledgement, assignment, escalation, investigation, evidence management, communication, decision, remediation, closure, retention and deletion. It defines the case state machine, the SLA engine, conflict-of-interest (COI) routing (ADR-015), anti-suppression controls, chain of custody and metrics.

**Protection statement.**
- WHAT: the report's existence, content and handling integrity; the source's identity; persons concerned.
- FROM WHOM: persons named in or implicated by a report, including executives, board members, HR, compliance, security staff and system administrators (THR-020); malicious or negligent investigators (THR-019); administrators (THR-018).
- ASSUMPTIONS: at least one independent body (ombudsman, audit committee, external counsel, IG) is configured and its members' devices are not controlled by the accused; the COI map is maintained; the Z-CORE clock is trustworthy within ±5 min (THR-043); the external audit witness is operated outside the accused's control (to be registered in `40-SECURITY-ASSUMPTIONS.md`).
- RESIDUAL RISK: a sufficiently senior accused who controls *all* configured independent bodies, the hosting, and the witness can still suppress a report; social pressure on investigators; COI not declared by the source or detected by triage.

## 2. Context and dependencies

| Doc | Relationship |
|---|---|
| `DECISIONS.md` ADR-005, 008, 009, 010, 013, 014, 015, 016, 017, 018, 025 | binding |
| `10-FILE-EVIDENCE-PIPELINE.md` | evidence objects, transformations, exports |
| `15-AUTHENTICATION-AUTHORIZATION.md` | roles, permissions, dual control, break-glass |
| `20-LOGGING-AUDITING.md` | CASE-class events; metrics counters |
| `35-DATA-RETENTION-DELETION.md` | retention schedules, legal hold, disposal |
| `04-CRYPTOGRAPHY.md` | case keys, routing-group epoch keys, re-keying |
| `25-COMPLIANCE.md` | jurisdiction packs, DSAR, statutory reporting |
| `12-FRONTEND-RECIPIENT.md`, `13-FRONTEND-ADMIN.md` | UIs |
| `11-FRONTEND-SOURCE.md` | source mailbox, COI selector, status display |

Components: C-10 Case Service (workflow, SLA engine), C-22 Authorization Engine, C-12 Case DB, C-13 Blob Store, C-14 Key Directory, C-15 Desk, C-23 Notification Service, C-24 Audit.

## 3. Data model (case-level)

Server-visible (C-12, cleartext; minimal): `case_id` (random 128-bit, display `CS-` + 10-char base32 prefix), `tenant_id`, `channel_id`, `routing_group_id`, `state`, `flags`, `received_day`, `import_batch`, SLA timer rows (anchor dates, due dates, status), ACL rows (user IDs, relation), COI exclusion rows (user/group IDs), approval records, legal-hold reference, retention class, `last_staff_activity_day` (date only).

Encrypted case record (case key; see `04-CRYPTOGRAPHY.md`): report text, questionnaire answers, category (fine-grained), persons concerned, detriment-risk assessment, investigation plan, notes, evidence records (10 §4), custody log (§10), decision, remediation actions, source messages.

Coarse category (`category_class`, ≤ 12 values, e.g., FINANCIAL, SAFETY, HR_CONDUCT, PRIVACY, OTHER) is server-visible only if the tenant enables SLA/route rules that need it; otherwise encrypted. Rationale: routing and SLA may depend on category (e.g., SOX §301 accounting → audit committee), but category is sensitive (THR-015).

## 4. Case state machine

### 4.1 States

| State | Meaning | ISO 37002 | Who sees content |
|---|---|---|---|
| `PENDING_IMPORT` | Envelope(s) in Intake Store/C-09 not yet imported; server knows only routing group, received_day, batch | 8.1 | nobody (ciphertext) |
| `NEW` | Imported by a routing-group member; case key created and wrapped to eligible members | 8.1 | routing-group members minus COI exclusions |
| `TRIAGE` | Classification, scope, detriment-risk assessment, COI check | 8.2 | triage team |
| `ASSESSMENT` | Assigned case lead decides whether and how to investigate | 8.2 | case members |
| `INVESTIGATION` | Active fact-finding | 8.3 | case members |
| `ON_HOLD` | Waiting for source information or external event (SLA pause only where rule permits) | 8.3 | case members |
| `DECISION` | Findings drafted; awaiting second reviewer | 8.4 | case members + reviewer |
| `REMEDIATION` | Corrective actions tracked | 8.4 / 10 | case members |
| `CLOSED` | Closure approved, feedback given; post-closure detriment monitoring active | 8.4 | case members (read-only) |
| `REFERRED` | Transferred to another channel/independent body/external authority | 8.3 | receiving body |
| `DISMISSED` | Out of scope, spam, or manifestly irrelevant (second reviewer required) | 8.2 | case members (read-only) |
| `RETAINED` | Closed/dismissed, awaiting disposal date (may carry `LEGAL_HOLD`) | 7.5 | per retention policy |
| `DISPOSED` | Crypto-erased; tombstone only | 7.5 | nobody |

Overlay flags (not states): `LEGAL_HOLD`, `SEALED_MATTER` (e.g., qui tam seal), `IDENTITY_SEALED` (ADR-014), `COI_ALERT`, `CANARY_ESCALATED`, `SLA_BREACH`, `BREAK_GLASS_ACTIVE`, `HIGH_DETRIMENT_RISK`.

### 4.2 Transitions

```mermaid
stateDiagram-v2
  [*] --> PENDING_IMPORT
  PENDING_IMPORT --> NEW: import (routing-group member)
  PENDING_IMPORT --> NEW: oversight import after canary
  NEW --> TRIAGE: start triage
  TRIAGE --> ASSESSMENT: assign lead
  TRIAGE --> DISMISSED: dismiss (2nd reviewer)
  TRIAGE --> REFERRED: refer (2nd reviewer if external)
  ASSESSMENT --> INVESTIGATION: open investigation
  ASSESSMENT --> DECISION: no-investigation decision
  INVESTIGATION --> ON_HOLD: pause
  ON_HOLD --> INVESTIGATION: resume
  INVESTIGATION --> DECISION: submit findings
  DECISION --> INVESTIGATION: reviewer returns
  DECISION --> REMEDIATION: approve with actions
  DECISION --> CLOSED: approve closure (2nd reviewer)
  REMEDIATION --> CLOSED: actions done (2nd reviewer)
  REFERRED --> RETAINED: referral acknowledged
  DISMISSED --> RETAINED
  CLOSED --> RETAINED: post-closure monitoring ends
  CLOSED --> INVESTIGATION: reopen (2nd reviewer)
  RETAINED --> DISPOSED: disposal (dual approval, no hold)
  DISPOSED --> [*]
```

| Transition | Guard | Actor | Dual control | CASE audit event |
|---|---|---|---|---|
| import | actor holds routing-group epoch key; not COI-excluded | INTAKE_TRIAGER / OVERSIGHT (canary) | no | `case.imported` |
| start triage | — | INTAKE_TRIAGER | no | `case.state_changed` |
| assign lead | assignee eligible (§7), COI attestation signed by assignee | CHANNEL_OWNER or TRIAGER | no | `case.assigned` |
| dismiss | reason code (OUT_OF_SCOPE, SPAM, DUPLICATE, MANIFESTLY_IRRELEVANT); feedback to source queued | CASE_LEAD | yes: REVIEWER ≠ proposer, not COI-excluded | `case.dismiss_requested`, `case.dismiss_approved` |
| refer | destination (channel, independent body, authority); reason | CASE_LEAD | yes if destination is external | `case.referred` |
| submit findings | decision record present | CASE_LEAD | no | `case.state_changed` |
| approve closure | feedback-to-source sent or documented exception; remediation plan or none; custody complete | REVIEWER | yes (reviewer ≠ lead; not COI-excluded; not in accused list) | `case.closure_approved` |
| reopen | reason | CASE_LEAD | yes | `case.reopened` |
| disposal | retention date reached; no `LEGAL_HOLD`; records-authority approval where configured | RETENTION job proposes; RECORDS_OFFICER + CASE_LEAD/OVERSIGHT approve | yes | `case.disposed` (see 35) |

The server enforces transitions (C-10) and the Desk enforces cryptographic prerequisites (only key holders can produce signed decision records). An invalid transition returns `409` and emits a SECURITY event `authz.denied`.

## 5. Lifecycle stages

| Stage | Key activities | Artifacts (encrypted) | Timers |
|---|---|---|---|
| Intake | Source submits (Tier W/V); optional auto-acknowledgement at intake (§6.4); routing-group selection incl. COI flags (§8.3) | envelope, manifest | ACK timer starts at `received_day` |
| Classification | `category_class`, sub-category, jurisdiction pack, reporter relationship (EU Art 4 taxonomy), anonymous/confidential/identified mode (ADR-002) | classification record | — |
| Triage | scope check, urgency (IMMEDIATE_DANGER flag), detriment-risk assessment (ISO 37002 8.2; low/medium/high + mitigations), COI check (§8.4), duplicate linking (staff-only, never auto-correlation across sources: REQ-H-08) | triage record | TRIAGE decision timer (e.g., Alberta 10 business days) |
| Acknowledgement | reply to source via mailbox (template; never through notifications) | ACK message | ACK timer satisfied |
| Assignment | case lead + members; COI attestations; key wrapping to members | ACL + wraps | — |
| Escalation | SLA-driven or manual escalation to independent body; canary (§9.4) | escalation record | — |
| Investigation | plan, interviews (minutes per EU Art 18), evidence handling (10), requests to source | plan, notes | INVESTIGATION timer (optional) |
| Evidence management | per `10-FILE-EVIDENCE-PIPELINE.md`; custody (§10) | evidence/XF records | — |
| Communication | two-way mailbox; day-granularity dates (ADR-010); no read receipts; identity unseal notices (ADR-014, EU Art 16(3)) | messages | FEEDBACK timer |
| Decision | substantiated/partly/unsubstantiated/inconclusive; rationale | decision record | — |
| Remediation | corrective actions (ISO 37002 cl. 10 register) with owners and due dates; owners outside case see only action text approved for them (no source data) | action register | action due dates |
| Closure | feedback to source, closure approval, post-closure detriment check-ins (default at +30, +90, +180 days) | closure record | check-in timers |
| Retention | retention class by outcome; legal hold | retention record | disposal date |
| Deletion | crypto-erasure (35) | deletion receipt | — |

## 6. SLA engine

### 6.1 Timer definition (tenant policy, signed JSON; schema `candor.sla.v1`)

| Field | Type | Example |
|---|---|---|
| `timer_id` | string | `EU_ACK_INTERNAL` |
| `anchor` | event or date expression | `received_day`, `event:ack_sent`, `min(event:ack_sent, received_day+P7D)` |
| `duration` | ISO 8601 duration or `NBD` business days | `P7D`, `P3M`, `120BD` |
| `calendar` | `CALENDAR` or `BUSINESS` | `BUSINESS` |
| `holiday_calendar` | ID of signed holiday set | `CA-AB-2027` |
| `weekend` | weekday set | `[SAT,SUN]` |
| `timezone` | IANA tz of legal obligation | `Europe/Berlin` |
| `due_rule` | `START_OF_DUE_DAY` (conservative) or `END_OF_DUE_DAY` | `START_OF_DUE_DAY` |
| `satisfied_by` | event list | `[ack_sent]` |
| `reminders` | offsets before due | `[-3D, -1D]` |
| `pause_allowed` | bool + allowed reasons | `false` for EU ACK |
| `extension` | max total, justification codes, approver role, source-notice template | `{max: P3M, codes: [COMPLEXITY, ...], approver: REVIEWER, notify_source: true}` |
| `on_breach` | actions | `[flag SLA_BREACH, notify OVERSIGHT, canary]` |
| `legal_ref` | text | `EU 2019/1937 Art 9(1)(b)` |
| `advisory_only` | bool | `true` for DOJ 120-day window reminders |

### 6.2 Computation rules

1. Anchor `received_day` is the UTC date of receipt (ADR-010). Because the exact time is unknown, the engine treats the anchor as the **start** of that date in the tenant timezone, minus one day if the tenant timezone is ahead of UTC (conservative: deadlines are never later than the legal deadline computed from the true receipt time).
2. Calendar months: add months to the anchor date; if the day does not exist, clamp to the last day of the month (e.g., 31 Jan + P1M = 28/29 Feb).
3. Business days: count days that are neither in `weekend` nor in the holiday calendar; the anchor day itself is day 0.
4. Pauses (only if `pause_allowed`): stop the clock on `ON_HOLD` with reason; resumption extends due date by the paused business/calendar days; each pause and resume is audited.
5. Extensions: require justification code + free-text (encrypted), approver ≠ requester, total ≤ `extension.max`; if `notify_source`, a mailbox template is queued (EU Art 11(2)(d) external channels: 3 → 6 months "in duly justified cases").
6. Holiday calendars are signed data packages (EE packs; CE ships an importer for ICS files and a base set); a calendar change never shortens an already-running timer without an audited recompute approved by the channel owner.
7. Clock: C-10 uses the Z-CORE system clock synchronized via authenticated time (NTS) from ≥2 sources; if drift > 5 min or time jumps backward, the engine freezes breach actions, raises a SECURITY event and continues reminders only (THR-043).

### 6.3 Default timer packs

| Pack | Timer | Duration | Calendar | Notes |
|---|---|---|---|---|
| EU-INTERNAL (default for EU tenants) | ACK | 7 days from receipt | calendar | Art 9(1)(b); no pause |
| | FEEDBACK | 3 months from ACK, or from receipt+7 days if no ACK | calendar | Art 9(1)(f); extension not permitted (flag breach) |
| EU-EXTERNAL (authorities) | ACK | 7 days | calendar | Art 11(2)(b); may be disabled per reporter request or if it would jeopardise protection |
| | FEEDBACK | 3 months; extendable to 6 months with justification | calendar | Art 11(2)(d) |
| CA-AB-PIDA | ACK | 5 business days | business | B-CO-24 (statutory basis UNVERIFIED) |
| | DECISION_TO_INVESTIGATE | 10 business days | business | |
| | INVESTIGATION | 120 business days; extension by chief officer/Commissioner | business | |
| US-SOX (advisory) | Audit-committee routing | immediate | — | SOX §301 routing, not a timer |
| US-DOJ-PILOT (advisory) | 120-day internal-report window reminder | 120 days | calendar | advisory only (R6 A4) |
| GENERIC | ACK 7d, FEEDBACK 90d | calendar | CE default outside EU |
| POST-CLOSURE | detriment check-ins at 30/90/180 days | calendar | ISO 37002 8.4 |

These are defaults, not legal advice; `25-COMPLIANCE.md` owns jurisdiction content.

### 6.4 Acknowledgement mechanics

- **Auto-acknowledgement at intake (default ON):** at submission, the source client (Tier V) or C-07 (Tier W) places a static, pre-signed acknowledgement message (channel template, day-granularity date) into the source's mailbox. On import, the case records `ack_sent` with date = `received_day`. This makes acknowledgement independent of any staff member (anti-suppression) and needs no extra metadata.
- **Manual acknowledgement:** a staff reply marked as ACK.
- Acknowledgements and all source communication go only through the mailbox; replies become visible on the source's next login (ADR-010, ADR-017).

### 6.5 Reminders and notifications

All reminders use ADR-017 content-free notifications: text "Candor: secure case-management action requires attention" + instance label; no case ID, count, state or due date; hourly digest (default), jittered ±10 min. Details appear only after login in the Desk task list.

## 7. Assignment and eligibility

A staff user U is *eligible* for case C iff all hold (evaluated by C-22):
1. U is active, enrolled with a registered hardware key (see 15), and has role permitting the relation.
2. U is a member of C's routing group (or the case was explicitly granted to U by an existing member per policy).
3. U is not in C's COI exclusion set (§8) and has signed a COI attestation for C ("I have no conflict of interest with the matters and persons in this case"; attestation text encrypted in case; signing event audited).
4. Tenant/department boundary permits (15 AUTHZ ABAC).
5. Any time-bounded grant has not expired.

Case key wrapping to U happens only after (1)–(5) pass; revocation re-keys (§8.5).

## 8. Conflict-of-interest routing (ADR-015)

### 8.1 Concepts

- **Channel:** what the source picks (e.g., "Financial misconduct", "Report to the Audit Committee").
- **Routing group (RG):** a set of recipients holding their own epoch keys (ADR-008 epoch keys are generated per RG). Each channel has one DEFAULT RG plus zero or more COI RGs. An envelope is encrypted to exactly one RG's current epoch key, so **excluded users never receive decryptable material** — exclusion is cryptographic, not only a server check.
- **COI map:** signed tenant policy mapping *subject roles* (who a report may concern) → *excluded principals* (roles/groups/users) → *alternate RG*. Published in C-14 as part of the channel descriptor so sources (and Tier V clients) can see where a COI-flagged report goes and who can read it.
- **Independent bodies:** RGs whose members are independent of management: OMBUDSMAN, INSPECTOR_GENERAL, ETHICS_COMMITTEE, BOARD_AUDIT_COMMITTEE, EXTERNAL_COUNSEL, THIRD_PARTY_INVESTIGATOR, CIVILIAN_OVERSIGHT, EXTERNAL_AUTHORITY_LIAISON.

### 8.2 Default COI routing table

| Report concerns (subject role) | Excluded before any access | Default alternate RG | Fallback if not configured |
|---|---|---|---|
| Source's direct manager | the manager; (EE) manager chain up to 2 levels via directory attribute | DEFAULT RG minus excluded | — |
| HR department / HR staff | HR group | ETHICS_COMMITTEE or OMBUDSMAN | EXTERNAL_COUNSEL |
| Compliance function / whistleblowing function staff | compliance group incl. channel owners | BOARD_AUDIT_COMMITTEE or OMBUDSMAN | EXTERNAL_COUNSEL |
| Corporate security / investigations unit | security group; SOC readers of SECURITY logs are notified only content-free | OMBUDSMAN or EXTERNAL_COUNSEL | THIRD_PARTY_INVESTIGATOR |
| Senior executives (C-suite) | executive group + their direct reports in whistleblowing roles | BOARD_AUDIT_COMMITTEE | EXTERNAL_COUNSEL |
| CEO | CEO, executive group, CEO's staff office | BOARD_AUDIT_COMMITTEE (independent directors only) | EXTERNAL_COUNSEL |
| Board members / board chair | board group (except the independent audit committee members not named) | EXTERNAL_COUNSEL | EXTERNAL_AUTHORITY_LIAISON (regulator referral guidance) |
| System administrators / IT | admin role holders, IT group | OMBUDSMAN or ETHICS_COMMITTEE (admins have no content access anyway: ADR-015) | EXTERNAL_COUNSEL |
| Department heads | the department head + department staff in whistleblowing roles | ETHICS_COMMITTEE or INSPECTOR_GENERAL | OMBUDSMAN |
| Local officials (municipal) | the official's office, council staff | INSPECTOR_GENERAL or municipal ethics commissioner | EXTERNAL_AUTHORITY_LIAISON |
| Elected officials | elected officials' offices; political staff | ETHICS_COMMITTEE (statutory ethics commission) or INSPECTOR_GENERAL | EXTERNAL_AUTHORITY_LIAISON |
| Law enforcement / police | the agency's command and internal affairs if implicated | CIVILIAN_OVERSIGHT or INSPECTOR_GENERAL | EXTERNAL_AUTHORITY_LIAISON |
| Accounting, internal controls, auditing (by category, not person) | management | BOARD_AUDIT_COMMITTEE (SOX §301) | EXTERNAL_COUNSEL |
| Members of an independent body itself | the named members | another independent body | EXTERNAL_COUNSEL |

If a COI RG resolves to an empty set of eligible recipients, the channel descriptor marks that option unavailable and the source is told (in Tier W/V UI) which external authority information applies (EU Art 9(1)(g)); the system SHALL NOT silently route to DEFAULT.

### 8.3 Source-side COI selection

- The channel page offers "My report concerns (optional): [ ] my manager [ ] HR [ ] compliance [ ] security [ ] senior management [ ] CEO [ ] board [ ] IT administrators [ ] department head [ ] …" (tenant-configured list from the COI map), plus "I prefer an independent body" where configured.
- Selection deterministically maps to one RG; the client (Tier V) or C-07 (Tier W) encrypts to that RG's epoch key after verifying the RG key signature against C-14.
- Honest disclosure shown next to the selector: the list of role labels who will be able to read the report, and "The server can see which group your report was sent to, but not its content."

Metadata note: the RG key ID is visible to Z-INTAKE and Z-CORE (required for addressing). Knowing "a report went to the audit-committee RG" is itself information (see §15).

### 8.4 Triage-time COI detection

Sources may not flag COI. During triage:
1. Triager records `persons_concerned` (encrypted) and maps them to staff directory entries where they are Candor users (local directory; EE: SCIM attributes incl. `manager` chain).
2. C-22 computes the exclusion set from the COI map + named users + their manager chain (EE) + self-declared recusals.
3. Excluded current members are removed immediately (§8.5); if the triager themself is implicated, they must recuse (attestation) — and a non-excluded member or OVERSIGHT is alerted.
4. A case can only be moved to an RG where no current member is excluded.

### 8.5 Removal and re-keying

On exclusion or revocation of member X from case C:
1. Server removes X's ACL and wrapped-key rows immediately and blocks ciphertext delivery to X.
2. The next member client to open C generates a new case key K', re-encrypts the case record head and wraps K' to remaining members; new evidence and records use K'. Existing blobs keep their per-object DEKs, which are re-wrapped under K' (X may retain DEKs it already cached: residual risk, §15).
3. Event `case.member_removed` (reason COI/REVOKED) + `case.rekeyed`.
4. X's Desk receives a revocation tombstone and purges cached case material on next sync.

## 9. Anti-suppression controls

| Control | Mechanism | Threat |
|---|---|---|
| AS-1 Accused cannot see | Cryptographic COI exclusion before key wrapping (§8) | THR-020 |
| AS-2 Accused cannot close | Closure/dismissal require a second reviewer who is not proposer, not excluded, not in `persons_concerned` | THR-020 |
| AS-3 Accused cannot delete | No user-facing delete of cases; disposal only by retention engine + dual approval + no hold; evidence deletion within a case only for DERIVED objects or dual-approved Art 17 purge | THR-020; THR-037 |
| AS-4 Tamper evidence | All transitions/approvals in the hash-chained CASE audit stream with signed checkpoints and external witness (20) | THR-037; THR-018 |
| AS-5 Admin cannot suppress silently | Admins cannot alter case state (no permission); config changes affecting routing/SLA/COI are dual-approved and notify OVERSIGHT content-free | THR-018; THR-035 |
| AS-6 Canary escalation | §9.4 | THR-020 |
| AS-7 Independent visibility | OVERSIGHT metadata register: per-case pseudonymous ID, RG, state, SLA status, days since last staff activity — no content, no source data | THR-020 |
| AS-8 Auto-acknowledgement | §6.4 removes dependency on staff for first contact | THR-020 |
| AS-9 Reassignment limits | Reassigning away from an independent RG to a management RG requires OVERSIGHT approval | THR-020 |
| AS-10 Source-visible status | Source mailbox shows coarse status (RECEIVED, IN_REVIEW, CLOSED) and closure feedback; the source can escalate "I received no response" which creates an OVERSIGHT escalation | THR-020 |

### 9.4 Canary (dead-man) escalation

Triggers (configurable; defaults):
- C1: envelope in `PENDING_IMPORT` > 3 calendar days.
- C2: case with no staff activity (any audited case action) > 14 calendar days while in NEW..INVESTIGATION.
- C3: any SLA breach.
- C4: source-initiated "no response" escalation.
- C5: closure/dismissal approved within 24 h of import (possible rubber-stamping) — notify only.

Action: C-10 sets `CANARY_ESCALATED`, sends content-free notification to the OVERSIGHT RG, and adds the case to the OVERSIGHT register with trigger code.

Access by oversight: tenant chooses per RG:
- `OVERSIGHT_MODE=SILENT_MEMBER`: OVERSIGHT members are members of every RG (hold epoch keys) but do not see content unless they perform an audited "oversight import/open" action. Disclosed in the channel descriptor (THR-046 transparency).
- `OVERSIGHT_MODE=METADATA_ONLY`: OVERSIGHT sees the register only and can compel action via governance, not decrypt.

Suppression of the canary itself: OVERSIGHT Desk clients independently evaluate C1/C2 from signed register snapshots pulled at least daily, and alert locally if (a) snapshots stop arriving for > 48 h or (b) checkpoint signatures/witness cosignatures fail (20). This moves the dead-man check off infrastructure the accused could control.

Epoch-key interaction: channel epoch private keys (ADR-008) are not destroyed while any envelope encrypted to that epoch remains un-imported, unless a dual-approved "abandon envelope" decision by OVERSIGHT is recorded (see 35).

## 10. Chain of custody

### 10.1 Custody events (recorded in the encrypted per-case Custody Log, signed per entry by the actor's identity key, hash-chained per evidence object)

| Event | Fields (encrypted) |
|---|---|
| IMPORT | evid_id, sha256, blake3, received_day, import_batch, manifest_match, importer |
| ACCESS | evid_id, containment level (L0–L4), purpose code, actor, ts |
| TRANSFORM | xform_id, inputs, outputs, actor, ts |
| EXPORT | package ID, evid_ids, destination class, approvers, reason code, PSR ID, ts |
| TRANSFER | from RG/body → to RG/body, approvers, ts (referral) |
| CUSTODY_CHANGE | custodian (case lead) change, approver, ts |
| HOLD / RELEASE | legal hold reference, ts |
| DELETE | evid_id, method (crypto-erase), receipt ID, ts |

The CASE audit stream (20) records a pseudonymous counterpart of each event (no hashes, names or sizes). The custody log's head hash per case is included (HMAC under a case-derived key) in the CASE event, binding the two without revealing content.

### 10.2 Balancing custody against anonymity

| Custody need | Anonymity-preserving choice |
|---|---|
| "When was it received?" | `received_day` only (ADR-010); custody starts at import |
| "Who submitted it?" | Not recorded; source-signed manifest proves the same passphrase holder submitted all items, not who |
| "From which device/network?" | Never recorded (THR-001) |
| Integrity from source to case | Source manifest hash (10 §5.2) + STREAM AEAD |
| Court-ready custody report | Generated from Custody Log by case lead; mandatory identity-deducibility review (EU Art 16(1)) and second reviewer before release |

## 11. Communication with the source

- Two-way mailbox; message dates at day granularity; no read receipts or typing indicators (ADR-010).
- Templates: ACK, request for information, feedback (EU Art 9(1)(f)), extension notice, closure, identity-unseal notice (ADR-014, EU Art 16(3)), post-closure detriment check-in.
- Staff messages are signed by the case (channel identity) — individual staff names are not shown to sources unless configured (reduces targeting of staff).
- Oral reports and meetings (EU Art 9(2), 18(2)–(4)): transcript/minutes stored as TRANSCRIPT evidence; the source can review and confirm via mailbox; confirmation recorded.

## 12. Decision, remediation, closure

- Decision record: outcome enum, rationale, legal basis, signed by case lead; reviewer approval signed.
- Remediation: actions with owner (may be non-member; they receive only approved action text via an Export Package, ADR-018), due date, status; ISO 37002 cl. 10 corrective-action register.
- Closure checklist (all required unless reviewer records exception): feedback sent; custody log verified (`candorctl evidence verify` pass); no pending exports; retention class set; post-closure check-ins scheduled; identity seal state reviewed.

## 13. Retention and deletion (summary)

Retention class is set at closure/dismissal from outcome (see `35-DATA-RETENTION-DELETION.md` for schedules). EU Art 17 "manifestly irrelevant" data: purge action available at triage with second reviewer; content crypto-erased, audit keeps only `case.data_purged` with reason code.

## 14. Reporting and metrics

| Audience tier | Examples | Suppression rule | Time granularity |
|---|---|---|---|
| FUNCTION (whistleblowing function staff with case access) | own caseload, SLA status | none beyond access control | day |
| GOVERNANCE (management, board, oversight dashboards) | counts by category_class, outcome, SLA compliance, time-to-ack/close medians | cells with count < k suppressed, k default 10, minimum 5; complementary suppression so suppressed cells cannot be derived from totals | month |
| PUBLIC / STATUTORY (EU Art 27 stats, annual reports, PSDPA reports) | totals, outcome ratios | k default 20, minimum 10 (REQ-H-70); no cross-tab of more than 2 dimensions | month or coarser (REQ-H-74) |

Metrics are computed by C-10 from server-visible fields plus values that case leads explicitly release (e.g., substantiation outcome). Source-sensitive counters (submissions received per day) are governed by 20 (SOURCE-SENSITIVE class) and never exported below k or finer than a month for GOVERNANCE/PUBLIC.

KPIs (ISO 37002 cl. 9): volume, % acknowledged within SLA, median days to acknowledge/feedback/close, substantiation rate, retaliation/detriment reports, reopen rate, canary escalations count.

## 15. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| CASE-001 | C-10 SHALL implement the state machine of §4 and SHALL reject any transition not listed in §4.2, emitting a SECURITY `authz.denied` event. | B-CO-01 (ISO 37002 8.1–8.4) | THR-020; THR-021 | C-10 | TST: exhaustive transition matrix test (all state pairs × roles) |
| CASE-002 | Closure, dismissal, reopening and disposal SHALL require approval by a second reviewer who is not the proposer, not COI-excluded and not recorded in `persons_concerned`. | ADR-015; INC-22; B-CO-02 (Art 9(1)(c)) | THR-020; THR-019 | C-10; C-22 | TST: same-user, excluded-user and concerned-user approvals denied; valid pair succeeds |
| CASE-003 | No role SHALL have a user-facing operation to delete a case; case disposal SHALL occur only via the retention engine with dual approval and absence of legal hold. | ADR-025; INC-22 | THR-020; THR-037 | C-10 | TST: API route inventory contains no case-delete route outside retention module; disposal with hold denied |
| CASE-004 | The SLA engine SHALL support calendar and business-day durations, ISO 8601 month arithmetic with end-of-month clamping, per-tenant timezones, signed holiday calendars, weekend sets, pauses only where the timer permits, and justified extensions approved by a different user. | B-CO-02 (Art 9, 11); B-CO-24; R6 §0 item 1 | THR-043 | C-10 | TST: golden-date test vectors (EU 7d/3m, 31 Jan + P1M, Alberta 5/10/120 BD with holidays, DST transitions) |
| CASE-005 | Anchors based on `received_day` SHALL be computed conservatively so that no computed deadline is later than the legal deadline for any possible receipt time within that UTC day. | ADR-010; B-CO-02 (Art 9(1)(b)) | THR-043 | C-10 | TST: property test over all tz offsets −12..+14 |
| CASE-006 | The default EU-INTERNAL pack SHALL set ACK = 7 calendar days from receipt without pause and FEEDBACK = 3 months from acknowledgement or from receipt + 7 days if not acknowledged. | B-CO-02 (Art 9(1)(b),(f)) | — | C-10 | TST: pack conformance vectors |
| CASE-007 | The EU-EXTERNAL pack SHALL allow extending FEEDBACK from 3 to at most 6 months only with a justification code, approver and queued source notice. | B-CO-02 (Art 11(2)(d)) | — | C-10 | TST: extension beyond 6 months rejected; notice queued |
| CASE-008 | Auto-acknowledgement at intake SHALL be available (default ON) using a static pre-signed channel template placed in the source mailbox at submission, recorded as `ack_sent` on import. | B-CO-02 (Art 9(1)(b)); ADR-010 | THR-020 | C-06; C-07; C-03; C-10 | TST: submission via Tier W and Tier V shows ACK on next login; case shows ack_sent=received_day |
| CASE-009 | SLA reminders and escalations SHALL be delivered only as ADR-017 content-free notifications (fixed text + instance label, hourly digest, ±10 min jitter). | ADR-017; INC-57; INC-25 | THR-028 | C-23 | TST: notification payload equality test; timing test shows no per-event emission |
| CASE-010 | The SLA engine SHALL freeze breach actions and raise a SECURITY event when authenticated time sources disagree by > 5 min or the clock moves backward. | Design; ADR-010 | THR-043 | C-10 | TST: clock-skew injection |
| CASE-011 | Case keys SHALL be wrapped only to users eligible per §7, and a COI attestation signed by the user SHALL precede their first wrap for that case. | ADR-015; B-CO-02 (Art 9(1)(c)) | THR-020; THR-019 | C-15; C-22 | TST: wrap attempt without attestation refused by Desk and server |
| CASE-012 | Case state, flags, ACL, SLA timers and approvals stored in C-12 SHALL NOT include report content, persons concerned, fine-grained category or free text; `category_class` SHALL be server-visible only when a tenant rule requires it. | ADR-016; THR-015 | THR-015; THR-018 | C-12; C-10 | INSP: schema review; TST: DB dump canary grep |
| CASE-013 | Triage SHALL include a detriment-risk assessment (low/medium/high with mitigation plan) and set `HIGH_DETRIMENT_RISK` when high, which restricts case membership changes to CASE_LEAD + REVIEWER dual approval. | B-CO-01 (ISO 37002 8.2) | THR-019 | C-10; C-15 | TST: flag enforcement test; DEMO: triage form |
| CASE-014 | Duplicate/related-case linking SHALL be a manual staff action within the case team; the system SHALL NOT automatically correlate submissions across source accounts. | REQ-H-08; ADR-005 | THR-019 | C-10; C-15 | INSP: no correlation job; TST: two submissions with identical text are not auto-linked |
| CASE-015 | Remediation action owners outside the case SHALL receive only reviewer-approved action text via an Export Package, never case content or source data. | ADR-018 | THR-029; THR-020 | C-10; C-40 | TST: action export contains only approved fields |
| CASE-016 | Closure SHALL require: feedback sent (or reviewer exception), custody verification pass, no pending export approvals, retention class set, and post-closure detriment check-ins scheduled (default 30/90/180 days). | B-CO-01 (ISO 37002 8.4); B-CO-02 (Art 9(1)(f)) | THR-037 | C-10 | TST: closure blocked for each missing precondition |
| CASE-017 | The source mailbox SHALL show coarse status (RECEIVED, IN_REVIEW, CLOSED) and allow a "no response received" escalation that triggers canary C4. | B-CO-01 (8.4); INC-22 | THR-020 | C-06; C-10 | TST: escalation creates OVERSIGHT register entry |
| CASE-018 | Canary triggers C1–C5 of §9.4 SHALL be evaluated at least hourly by C-10 and SHALL set `CANARY_ESCALATED` and notify the OVERSIGHT RG content-free. | INC-22; REQ-H-69 | THR-020 | C-10; C-23 | TST: time-advanced fixtures for each trigger |
| CASE-019 | OVERSIGHT Desk clients SHALL independently evaluate canary triggers C1/C2 from signed register snapshots and SHALL alert locally when snapshots are missing > 48 h or checkpoint/witness verification fails. | INC-68; REQ-H-68 | THR-020; THR-018 | C-15; C-24 | TST: withheld snapshot and forged checkpoint produce local alerts |
| CASE-020 | Channel epoch private keys SHALL NOT be destroyed while envelopes encrypted to that epoch remain un-imported, unless OVERSIGHT records a dual-approved abandon decision. | ADR-008; INC-22 | THR-020 | C-15; C-09 | TST: destruction job skips epochs with pending envelopes; abandon requires two OVERSIGHT approvals |
| CASE-021 | The OVERSIGHT metadata register SHALL contain only case pseudonym, RG, state, flags, SLA status and days since last staff activity, and SHALL NOT contain content, persons concerned, category detail or source data. | ADR-016; ADR-015 | THR-020; THR-039 | C-10 | INSP: register schema; TST: field allow-list test |
| CASE-022 | Reassignment of a case from an independent-body RG to a non-independent RG SHALL require OVERSIGHT approval. | ADR-015; INC-22 | THR-020 | C-10; C-22 | TST: reassignment without OVERSIGHT approval denied |
| CASE-023 | Every custody event of §10.1 SHALL be appended to the encrypted per-case Custody Log, signed by the actor and hash-chained per evidence object, and a pseudonymous counterpart SHALL be emitted to the CASE audit stream binding the custody-log head by keyed MAC. | ADR-012; ADR-016; B-CO-02 (Art 12) | THR-037; THR-038 | C-15; C-24 | TST: custody chain verification; tampered entry detected; audit event lacks hashes/names |
| CASE-024 | Custody records SHALL begin at import and SHALL NOT record submission time finer than `received_day`, source device, network or client information. | ADR-010; INC-16 | THR-011; THR-001 | C-15 | INSP: schema; TST: record grep for time/UA fields |
| CASE-025 | A court/regulator custody report SHALL require an identity-deducibility review and second-reviewer approval before release. | B-CO-02 (Art 16(1)) | THR-019; THR-041 | C-15; C-10 | TST: release blocked without both records |
| CASE-026 | Metrics for GOVERNANCE audiences SHALL suppress cells with count < k (default 10, minimum 5) with complementary suppression and month granularity; PUBLIC/STATUTORY outputs SHALL use k ≥ 20 by default (minimum 10) and no cross-tabulation beyond 2 dimensions. | REQ-H-70; REQ-H-74; INC-74 | THR-039 | C-10 | TST: differencing-attack test (totals minus visible cells) cannot recover suppressed cells; k floor not configurable below minimum |
| CASE-027 | Identity unsealing (ADR-014) SHALL be a case action requiring legal basis, dual approval by IDENTITY_CUSTODIANs, and a queued source notice with written reasons unless a recorded deferral reason applies. | ADR-014; B-CO-02 (Art 16(2)-(3)); B-CO-13 | THR-019; THR-020 | C-10; C-15 | TST: unseal without either approval or basis denied; notice queued or deferral recorded |
| CASE-028 | EU Art 17 "manifestly irrelevant" purge SHALL be available at triage with second-reviewer approval and SHALL crypto-erase the content while retaining only a reason-coded audit event. | B-CO-02 (Art 17) | THR-017 | C-10; C-15 | TST: purge leaves no content wrap; event present without content |
| CASE-029 | Oral reports and meeting minutes SHALL be stored as TRANSCRIPT evidence and the source SHALL be able to review and confirm them via the mailbox, with confirmation recorded. | B-CO-02 (Art 18(2)-(4)) | — | C-10; C-15 | DEMO: transcript review flow |
| ROUTE-001 | Each channel SHALL define a DEFAULT routing group and optional COI routing groups, each with its own epoch keys, and envelopes SHALL be encrypted to exactly one routing group so that excluded users never receive decryptable material. | ADR-015; ADR-008 | THR-020 | C-14; C-07; C-03; C-15 | TST: excluded member's client cannot decrypt a COI-routed envelope (crypto test); INSP: key-directory descriptors |
| ROUTE-002 | The signed COI map and RG membership (role labels) SHALL be published in C-14 in the channel descriptor, and source clients SHALL display who can read a report sent to the selected RG. | ADR-015; REQ-H-14; INC-14 | THR-046; THR-020 | C-14; C-06; C-03 | TST: descriptor signature verification; UI shows labels; tampered descriptor rejected by Tier V |
| ROUTE-003 | The default COI routing table of §8.2 SHALL ship as a template covering direct manager, HR, compliance, corporate security, senior executives, CEO, board, system administrators, department heads, local officials, elected officials, law enforcement and accounting/audit matters. | ADR-015; INC-22; B-CO-69 (SOX §301) | THR-020 | C-10 | INSP: template content review; TST: template loads and validates |
| ROUTE-004 | If a COI selection resolves to an RG with no eligible recipients, the option SHALL be shown unavailable with external-reporting information and the system SHALL NOT fall back to the DEFAULT RG. | ADR-015; B-CO-02 (Art 9(1)(g)) | THR-020 | C-06; C-03; C-10 | TST: empty-RG fixture shows unavailable option; no silent routing |
| ROUTE-005 | Accounting, internal-control and auditing category reports SHALL be routable directly to the BOARD_AUDIT_COMMITTEE RG bypassing management, configurable per tenant. | B-CO-69 (SOX §301) | THR-020 | C-10; C-14 | TST: category routing rule test |
| ROUTE-006 | Triage-time COI detection SHALL compute exclusions from the COI map, named persons concerned, self-declared recusals and (EE) directory manager chains up to a configurable depth (default 2), and SHALL remove excluded members immediately. | ADR-015; B-CO-01 | THR-020 | C-22; C-10 | TST: fixtures for each source of exclusion |
| ROUTE-007 | Removal of a member for COI or revocation SHALL block ciphertext delivery immediately and SHALL cause re-keying of the case key on the next member client open, with re-wrapping of object DEKs. | ADR-015; ADR-008 | THR-020; THR-019 | C-10; C-15 | TST: removed member receives 403 immediately; new records unreadable with old key |
| ROUTE-008 | Changes to COI maps, RG membership, OVERSIGHT_MODE and SLA packs SHALL require dual approval and SHALL generate content-free notifications to OVERSIGHT and a CASE/SECURITY audit event. | ADR-015; ADR-013 | THR-018; THR-035; THR-046 | C-10; C-19; C-22 | TST: single-approver change rejected; OVERSIGHT notification observed |
| ROUTE-009 | OVERSIGHT_MODE SILENT_MEMBER SHALL be disclosed in the channel descriptor, and any oversight open/import of content SHALL be an audited action visible to the case team. | ADR-015; INC-14 | THR-046; THR-018 | C-14; C-10 | TST: descriptor shows mode; oversight open emits event visible in case timeline |
| ROUTE-010 | System administrators SHALL NOT be members of any RG by virtue of their admin role, and admin-role holders SHALL be excluded by default from all COI-alternate RGs. | ADR-015 | THR-018 | C-22 | TST: policy test; admin enrollment into RG requires separate non-admin identity |
| ROUTE-011 | A referral to another RG, independent body or external authority SHALL preserve ORIGINAL evidence unmodified (EU Art 12(4)) and SHALL be recorded as a TRANSFER custody event. | B-CO-02 (Art 12(4)) | THR-037 | C-10; C-15 | TST: transferred case evidence hashes equal originals |

## 16. Residual risks and limitations

1. **RG metadata.** Z-INTAKE and Z-CORE learn which RG a report targets (e.g., "a report concerning the CEO went to the audit committee") and its `received_day`. In small organizations this can be highly revealing and may itself prompt retaliation hunts (THR-011, THR-020). Mitigation options (all partial): encourage independent-body channels as normal defaults; aggregate RGs; see Open Issues.
2. **Cached keys.** A member removed for COI may retain case keys or DEKs cached before removal; re-keying protects only future material (THR-019).
3. **Undeclared conflicts.** COI detection depends on sources and triagers naming persons concerned and on staff honesty in attestations.
4. **Captured independent bodies.** If the accused controls the audit committee, counsel and hosting, canary escalation reaches the wrong people; external regulator reporting guidance remains the backstop (EU Art 9(1)(g)).
5. **Timing of staff actions.** Exact staff-action timestamps (permitted by ADR-010) near import can narrow the submission time to the C-09 pull window (15±10 min) when staff act immediately; see `20-LOGGING-AUDITING.md`.
6. **SLA law drift.** Jurisdiction timelines may change (EU Directive review 2026–2027, R6 A2); packs must be maintained.
7. **Small-number metrics.** Even with k-suppression, repeated reports over time may enable inference; month granularity and complementary suppression reduce but do not remove this (THR-039).

## 17. Open issues

1. OI-14-1: Whether `category_class` should ever be server-visible; alternatively evaluate category-dependent SLA/routing client-side at import (costs: server cannot enforce).
2. OI-14-2: Manager-chain COI (EE) needs a directory attribute feed; CE must rely on manual entry.
3. OI-14-3: Source-visible status values may leak case outcome to someone who seizes the source's passphrase (THR-034); decide default granularity with `05-SOURCE-OPSEC.md`.
4. OI-14-4: Assumption IDs (independent body integrity, clock trust, witness independence) to be registered in `40-SECURITY-ASSUMPTIONS.md`.

### Open Issues for ADR revision

- **ADR-008 / ADR-015: routing groups.** ADR-008 defines epoch keys per *channel*; ADR-015 requires exclusion before key wrapping. If all channel members hold the channel epoch key, an excluded member (e.g., the accused HR head who is a channel member) can decrypt the envelope before triage applies exclusions. This spec therefore introduces per-channel **routing groups** each with its own epoch keys (§8.1). Proposed ADR amendment: "Epoch keys are generated per routing group; a channel has ≥1 routing group; the source-selected COI option determines the routing group."
- **ADR-008 epoch-key destruction ("after window + import").** Interpreted as "after the later of the decrypt window end and import of all envelopes of that epoch"; otherwise a suppressing member could let the window lapse to destroy reports. CASE-020 codifies this; ADR text should state it explicitly.
- **ADR-010 import batch time.** Case import "records batch time"; combined with the 15±10 min pull interval this bounds submission time to a ~25 min window in low-volume instances. Proposed: case-visible field is batch *number* and `received_day` only; exact batch time kept only in C-09 operational state for ≤ 24 h.
