# 03 — Privacy and Anonymity

Status: Draft v1.1 (revision round 2: ADR-034..046, REVIEW-A/B/C; disposition in `process/DISP-G1.md`) · Edition applicability: both (CE and EE; MANAGED service covered in §10.3) · Owner: Privacy Engineering + Security Architecture

## 1. Purpose and scope

This document defines precisely what Candor means by **anonymous**, **confidential** and **identified**; from whom each protection holds and under which assumptions; and — in the **formal metadata inventory** (§8) — exactly which data each layer of the system sees for each request type, and what happens to it. It also contains the **legal-compulsion inventory** (§10) listing everything an operator or the vendor could be forced to produce, the analysis of whether Tor should be required (§11), and the aggregation/inference controls and k-thresholds for all statistics (§12).

It owns the `ANON-` (anonymity and modes), `META-` (metadata handling) and `PRIV-` (privacy governance, minimization, statistics, compulsion) requirement prefixes.

The inventory is **normative**: any datum not listed for a layer SHALL NOT be collected at that layer (META-001).

## 2. Context and dependencies

| Document | Relation |
|---|---|
| `DECISIONS.md` | ADR-001 (onion only), ADR-002 (three modes, no fallback), ADR-003 (Tor required, no fingerprinting), ADR-004 (Tier W/V), ADR-005 (passphrase), ADR-008 (keys), ADR-009 (intake/core, pull), ADR-010 (timing), ADR-011 (padding), ADR-014 (sealed identity), ADR-016 (audit classes), ADR-017 (notifications), ADR-021 (tenancy), ADR-023 (telemetry), ADR-025 (deletion), ADR-030/033 (per-member keys, anonymous slots, Erasure Key Vault, import coarsening), and the binding revision ADRs ADR-034 (Tier W drafts), ADR-035 (intake integrity evidence), ADR-036 (directory governance), ADR-037 (triage-first, blinded COI), ADR-038 (arrival/import decoupling, constant-schedule signals), ADR-039 (metadata-private replies), ADR-041 (client acquisition), ADR-043 (device custody), ADR-044 (key continuity, vault backups), ADR-045 (organisation-as-adversary), ADR-046 (consistency parameters). |
| Canonical owners (ADR-046 and revision brief) | `08-API.md` upload protocol; `24-LICENSING-BUSINESS-MODEL.md` §TEL (§8–§9) metrics regime; `09-DATABASE.md` exact-timestamp tables and column classification; `04-CRYPTOGRAPHY.md` keys and formats; `11-FRONTEND-SOURCE.md` page size classes, CSP and cookie. Where this document previously restated these values it now references the owner. |
| `02-THREAT-MODEL.md` | Adversaries ADV-01..30, threats THR-*, component compromise analysis; this document is the ground truth for "observable information" in `02` §6. |
| `01-PRODUCT-REQUIREMENTS.md` | Modes, metrics (SM-*), prohibited claims. |
| `05-SOURCE-OPSEC.md` | Source guidance implementing the behavioral assumptions in §4. |
| `11-FRONTEND-SOURCE.md`, `16-TOR-I2P.md`, `20-LOGGING-AUDITING.md`, `35-DATA-RETENTION-DELETION.md` | Implement META requirements. |
| `25-COMPLIANCE.md` | GDPR/EU Directive mappings (Art 16 confidentiality incl. indirect identification; Art 18 records). |
| `40-SECURITY-ASSUMPTIONS.md` | ASM IDs for the assumptions tagged `[A:…]` here (same tags as `02` §3). |

## 3. Definitions

### 3.1 Reporting modes (ADR-002, ADR-014)

| Mode | Definition (normative) | Who can know the source's identity | Network path | UI label (EN) |
|---|---|---|---|---|
| **ANONYMOUS** | A report submitted through the Tor onion service (C-05) for which Candor has collected **no identifier of the source**: no name, contact identifier, network address, device identifier, account at another service, or exact timestamp of source action. The source is known to Candor only by a random pseudonymous `source_account_id` and a passphrase-derived public key. | Nobody **through Candor data**. Others may infer identity from content, behavior or external observation (§5). | Onion only (ADR-001) | **ANONYMOUS** — "Candor is not collecting who you are." |
| **CONFIDENTIAL** | A report where the source's identity (or network identity) is knowable to the operator, but access to it is restricted. Two sub-cases: **(C1) sealed identity** — source submitted via onion and voluntarily provided identity data, which is encrypted only to the Identity Custodian key set (ADR-014) and never shown in the case view; **(C2) clearnet confidential** — submitted via C-38, where the hosting path necessarily sees the source's IP address; identity fields, if any, sealed as in C1. | C1: Identity Custodians (≥ 2 must cooperate to unseal). C2: additionally anyone with access to network paths to C-38 (ISP, hosting, operator network). | C1 onion; C2 clearnet HTTPS | **CONFIDENTIAL — NOT ANONYMOUS** |
| **IDENTIFIED** | A report whose reporter is named to the case team (source chose to be named, or staff recorded a report received in person/by phone). | Case team members. | Any | **IDENTIFIED** — "Your name is visible to the people handling this report." |

**Transitions** (§6): only towards less anonymity, only by explicit confirmed action of the source (or, for staff-entered reports, at creation). An ANONYMOUS report becomes C1 when the source adds identity; C1 becomes IDENTIFIED when the source consents to reveal identity to the case team. Withdrawal of sealed identity (deleting it before any unsealing) yields label **CONFIDENTIAL (identity withdrawn)** — never ANONYMOUS again, because Identity Custodians may already have been in a position to learn it.

### 3.2 Anonymity and confidentiality as used here

- **Anonymity (this platform):** the property that the platform's data, logs, backups, key material and operators cannot link a report or mailbox to a real-world person or to a network location, **and** that different reports by the same source are not linkable by platform data unless the source chooses to link them. It is *sender anonymity with respect to the platform*, bounded by: (a) the anonymity network's properties [A:TOR]; (b) the source's device integrity [A:DEV]; (c) the source's behavior [A:OPSEC]; (d) content. It is **not** a promise that nobody can figure out who the source is.
- **Anonymity set:** the set of people who could plausibly be the source given what an adversary observes. On a corporate network, the relevant set may be "employees who used Tor today" — possibly one person (R4 §2.1; INC-31).
- **Confidentiality (of identity):** identity is known to a designated, minimal set of custodians and is technically protected (encryption to custodian keys + dual control) from everyone else, including administrators, recipients and the vendor.
- **Content confidentiality:** report content readable only by holders of case keys (authorized case members, and the Recovery Quorum if enabled — ADR-013).
- **Unlinkability:** absence of platform data that links two actions (two visits, two reports, a visit and a report) to the same person, beyond the mailbox relation the source creates by logging in with the same passphrase.
- **Pseudonymity:** the `source_account_id` and source public key are pseudonyms: stable within one mailbox, random, and not derived from any identifier.
- **Tier W / Tier V** (ADR-004): Tier W = no-JS web; plaintext, drafts and the passphrase pass transiently through C-06/C-07 RAM (drafts only in sealer RAM, never persisted to disk, ADR-034). Tier V = verified client (Source App or WEBCAT-verified bundle); plaintext never reaches servers; replies retrieved by fetch-all (ADR-039).

### 3.3 Terms used in the inventory

| Term | Meaning |
|---|---|
| Source action | Any request initiated by a source (R-01..R-07, source-side R-10). |
| Exact timestamp | Resolution finer than one UTC calendar day. |
| Rounded timestamp | UTC calendar day (`received_epoch_day`), or coarser. |
| Padded size | Size after ADR-011 bucketing. |

## 4. Assumptions

Protection statements in this document hold only under these assumptions (tags as in `02-THREAT-MODEL.md` §3; ASM IDs assigned in `40-SECURITY-ASSUMPTIONS.md`).

| Tag | Assumption | If violated | ASM (40) |
|---|---|---|---|
| [A:TOR] | Tor provides sender anonymity against adversaries not observing both ends/controlling guards. | Network identity exposed to that adversary (THR-003). | ASM-001..003, ASM-005 |
| [A:DEV] | Source device, OS, browser/app not compromised. | Everything the source does is exposed (ADV-08). | ASM-004, ASM-008 |
| [A:OPSEC] | Source follows risk-appropriate guidance (personal device and network; no immediate submission after unique document access; no printing; minimal identifying content; few, batched return visits). | Identification by behavior/content/visit days (THR-002, THR-010, THR-134). | ASM-007, ASM-009, ASM-011 |
| [A:RCP] | ≥ 1 uncompromised recipient endpoint per case; tokens not coerced. | Content of that member's cases exposed. | ASM-019 |
| [A:CUSTODY] | Triage Set devices on INDEPENDENT channels are not administered by the organisation (ADR-043). | The organisation reads what those members read (THR-126). | ASM-053 |
| [A:SEAL] | Intake host kernel/hypervisor isolates C-07. | Tier W plaintext exposure. | ASM-014, ASM-015 |
| [A:MON] | Independent transparency monitors and ≥ 2 external directory witnesses exist (mandatory EE/GOV/MANAGED, ADR-036(5)). | Tier V verification weakens (THR-118). | ASM-036, ASM-051 |
| [A:WATCH] | ≥ 2 independent External Watchers publish mismatches (ADR-035(1)). | Untargeted intake modification unsignalled. | ASM-050 |
| [A:KEMPRIV] | Slot KEMs are key-private (ADR-033(1)). | Server/DB thieves learn which members were excluded before import. | ASM-049 |
| [A:BAKEXCL] | Infrastructure-level backups exclude the Erasure Key Vault (ADR-044(4)). | "Deleted" cases stay recoverable for the life of those backups (THR-130). | ASM-054 |
| [A:CRYPTO] | Primitives and candor-core implementation secure. | Content exposure (THR-012). | ASM-024..026 |
| [A:LAW] | Operators and custodians comply with the published legal-response procedure (two-person, inventory-only). | Over-disclosure of the limited metadata that exists. | ASM-042 |

## 5. Protected-from-whom matrix

Legend: **P** = protected by design under §4 assumptions (Candor holds nothing useful, or cryptography prevents access); **PA** = partially protected (see note); **NP** = not protected (by design or unavoidable); **n/a** = not applicable. Tier differences: "W/V" shows Tier W / Tier V.

| Protected item ↓ / From → | Org mgmt | Admin (curious/malicious) | Case recipients | Other staff | Accused | Hosting/cloud | Employer network/endpoint monitoring | ISP/local network | Global network adversary | LE compelling operator | Vendor (EE/MANAGED) | Forensic exam of source device |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Source IP / network location | P | P | P | P | P | P | PA¹ | PA¹ | NP² | P | P | NP |
| Source identity (ANONYMOUS) | PA³ | W: PA⁴ / V: PA³ | PA³ | P | PA³ | W: PA⁴ / V: P | PA¹ | PA¹ | NP² | W: PA⁵ / V: P | EE: P / MANAGED: W: PA⁴, V: PA²⁰ | NP⁶ |
| Source identity (CONFIDENTIAL C1, sealed) | P⁷ | P | P⁷ | P | P⁷ | P | n/a | n/a | n/a | PA⁸ | P | NP |
| Report content | PA⁹ ²² | W: PA⁴ / V: P | NP (authorized) | P | P¹⁰ | W: PA⁴ / V: P | P | P | P | W: PA⁵ / V: PA¹¹ | P | NP⁶ |
| Embedded file metadata (EXIF, author) | P | W: PA⁴ / V: P | PA¹² | P | P | W: PA⁴ / V: P | P | P | P | PA¹¹ | P | NP |
| Existence of a report / that it concerns X | PA¹³ | PA¹⁴ | NP | P | PA¹⁵ | PA¹⁶ | P | P | P | PA¹⁴ | MANAGED: PA¹⁶ / EE: P | NP |
| Submission timing finer than one day | PA²¹ | PA¹⁷ | PA¹⁷ | P | P | PA¹⁷ | NP¹ | NP¹ | NP | PA¹⁷ | EE: P / MANAGED: PA¹⁷ | NP |
| Which members were excluded (who the report concerns) | PA²³ | P²⁴ | NP (Triage Set; case team after import) | P | PA¹⁵ | P²⁴ | P | P | P | P²⁴ | P²⁴ | NP |
| Sequence of a source's follow-up days | PA²⁵ | NP²⁵ | NP²⁵ | P | P | PA²⁵ | NP¹ | NP¹ | NP | NP²⁵ | EE: P / MANAGED: NP²⁵ | NP |
| Times a mailbox is checked | P | W: PA⁴ / V: P²⁶ | P | P | P | W: PA⁴ / V: P²⁶ | NP¹ | NP¹ | NP | W: PA⁵ / V: P²⁶ | EE: P / MANAGED: W: PA⁴, V: P²⁶ | NP |
| Channel chosen | PA¹³ | NP | NP | P | PA¹⁵ | P¹⁸ | P | P | P | NP¹⁴ | P | NP |
| Mailbox replies | P⁹ | W: PA⁴ / V: P | NP | P | P | W: PA⁴ / V: P | P | P | P | W: PA⁵ / V: PA¹¹ | P | NP⁶ |
| Linkage between two reports of one source | P¹⁹ | P¹⁹ | PA³ | P | PA³ | P | PA¹ | PA¹ | NP | P¹⁹ | P | NP |
| That the source used Tor/Candor at all | P | P | n/a | P | P | P | NP | NP | NP | P | P | NP |

Notes:
1. Observers of the source's own network/device see Tor (or bridge) use and timing, not the onion destination (modulo website fingerprinting, THR-004). Protection depends on [A:OPSEC] (personal network/device, bridges).
2. Not in the design envelope (NG-03, `02` ADV-21).
3. Inference from content, style, knowledge, investigation actions remains possible (THR-010, THR-125).
4. A live-compromised intake (or its host) can read Tier W plaintext and passphrases in transit through C-06/C-07 (ADR-004). A captured passphrase yields all replies stored for that mailbox, every `mailbox_id` derived from it (linking the source's reports), the source's COI preferences in `prefs_ct`, the ability to write as the source, and — for any later login — the exact time of that visit (RVW-A-03, RVW-A-10; ADR-035(5)). Stored data is ciphertext. No specified control detects a careful targeted modification; External Watchers detect only untargeted changes to static assets, CSP headers and the running manifest (ADR-035(1)).
5. Operator can be compelled prospectively to modify Tier W intake; retrospective data contains no plaintext.
6. Only what the source's device retains (guidance: Tails, no downloads; Candor stores nothing on the device beyond a memory-only session cookie).
7. Unless the person is an Identity Custodian (≥ 2 custodians required to unseal).
8. Lawful unsealing by custodians under ADR-014 procedure; source notified where law requires.
9. Unless the person is a case member.
10. Triage-first routing: envelopes are wrapped only to the eligible Triage Set after the source's COI ticks (ADR-037); anonymous recipient slots (ADR-033). Protection fails if the accused is a Triage Set member not flagged by the source, or is added later by the Triage Set (audited).
11. Only via compelled case members or quorum holders; the operator itself holds no content keys.
12. Recipients see sanitized derivatives by default; originals (with metadata) available under access controls (ADR-012).
13. Program statistics are k-thresholded and period-aggregated (§12); management learns volumes, not individual reports.
14. Server-visible case metadata (channel, coarse category, state, received day, import-slot dates of follow-ups) exists and can be disclosed (§10). COI exclusions are stored only as blinded tags (ADR-037(3)).
15. Side channels minimized (THR-110), not eliminated: non-triage members see no intake envelopes, notifications or counts (ADR-037(2)); an excluded Triage Set member still sees an envelope it cannot open; workload of colleagues remains observable.
16. Provider sees traffic volume and storage growth, not report subjects.
17. No record stores source action time finer than a day. Residues: (a) import happens only at fixed schedule slots (default 4×/day; HIGH/GOV 1×/day, ADR-038(1)), so core DB commit/WAL times, blob times, backups and case records reveal the slot, which bounds arrival to the preceding slot interval unless the source chose delayed delivery (ADR-038(4)); (b) until the envelope is relayed, C-08 database pages, WAL and filesystem metadata on the intake host can bound the arrival time (not a record; overwritten after relay); (c) a live-compromised intake sees exact times in RAM.
18. Channel ID stored on encrypted-at-rest volumes; a provider with memory access could read it.
19. Default: one passphrase per report (ADR-005); if the source reuses a passphrase, reports are linked in the mailbox by design.
20. In MANAGED the vendor holds every server-side datum of §10.1 for all customers, plus the live Tier W capture capability (RVW-B-19); Tier V content is protected, metadata is not.
21. The organisation does not receive submission times from Candor, but staff reactions (logins after the daily digest, Desk activity, network flows) reach its IdP/SIEM/network logs (THR-129); notifications are constant-schedule (ADR-038(2)).
22. P holds only if recipient endpoints are not administered by the organisation (ADR-043 independent custody on INDEPENDENT channels); an organisation controlling a member's endpoint can read what that member reads (THR-126).
23. Program statistics and dashboards reveal nothing about exclusions (non-triage roles see no intake counts, ADR-037(2)); a management member who is excluded may still infer it from workload side channels.
24. Exclusions are held only as blinded tags `HMAC(K_case_excl, user_id)` padded to 8 per case; no event, table or export associates a user identity with a COI exclusion (ADR-037(3)). Before import, anonymous slots hide the excluded set subject to [A:KEMPRIV]. A live Z-CORE attacker who also holds a member Desk can compute tags.
25. Each follow-up record stores only its import-slot date (ADR-038(3)); absent delayed delivery that date equals the arrival day, so the list of follow-up dates of one case remains visible to case members (UTC day, or ISO week in HIGH) and to anyone holding C-12 or its backups. Intersected with employer Tor-use logs this narrows candidates (THR-134); guidance: batch visits, use delayed delivery.
26. Tier V retrieves replies by fetch-all dead-drop; the server cannot tell which mailbox was checked; no per-mailbox access time, count or history is stored (ADR-039). Tier W requires server-side lookup after passphrase derivation (documented residual).

## 6. Mode lifecycle

```mermaid
stateDiagram-v2
  [*] --> ANONYMOUS: onion submission (default)
  [*] --> CONFIDENTIAL_C2: C-38 clearnet submission (NOT ANONYMOUS)
  [*] --> IDENTIFIED: staff-entered named report
  ANONYMOUS --> CONFIDENTIAL_C1: source adds identity (confirm screen)
  CONFIDENTIAL_C1 --> IDENTIFIED: source consents to be named to case team (confirm screen)
  CONFIDENTIAL_C2 --> IDENTIFIED: source consents
  CONFIDENTIAL_C1 --> CONFIDENTIAL_WITHDRAWN: source withdraws sealed identity (no unsealing occurred)
  CONFIDENTIAL_C1 --> CONFIDENTIAL_C1: lawful unsealing (dual custodian, legal basis, notice)
  CONFIDENTIAL_WITHDRAWN --> CONFIDENTIAL_C1: source adds identity again
  ANONYMOUS --> CONFIDENTIAL_SEEN: staff record self-identification in a message (excerpt sealed immediately)
```

Rules: no transition to ANONYMOUS from any other state; staff cannot change the mode of a report except to record that a source identified themselves in a message (which requires a confirmation stored as a CASE event and a mailbox notice to the source). Because the identifying passage has already been readable by case members, the Desk SHALL immediately seal the passage to the Identity Custodian key set, replace it in the case copy with "[identity sealed]", exclude it from Export Packages, and label the report **CONFIDENTIAL (identity seen by case team)**; the mailbox notice states which roles had already been able to read it: "You wrote something that identifies you. The people in these roles could read it before it was locked: {roles}. Your report is now CONFIDENTIAL, not anonymous." (RVW-B-15; ANON-010 as amended).

## 7. Mode indicator requirements

| Surface | Requirement |
|---|---|
| Onion source pages (Tier W) | Top-of-page banner on every page, rendered server-side as the first focusable landmark (`role="status"`, not color-only): icon + mode word + one-line meaning + link "What this protects". ANONYMOUS text (normative; `11` SHALL generate `sui.mode.*` strings from this cell, ANON-027): "ANONYMOUS — Candor does not collect who you are. Your writing and files can still identify you." Tier line (platform-neutral, RVW-B-16): "Web mode: encrypted on arrival. [What are my options?]" The options page, the step before final Submit and the login page SHALL show the ADR-035(5) statement verbatim: "If the intake server is compromised or legally compelled while you use the website (no-JavaScript) version, what you type, and your passphrase when you log in, can be captured. For the highest risk, use the Candor Source App." plus: "Anyone with your passphrase can read your replies and write as you. Each time you sign in, a compromised server could note the exact time." (ANON-022). |
| Source App (Tier V) | Same banner plus "Verified client — end-to-end encrypted" and the verified roster digest; if verification fails the app blocks submission (no fallback, ANON-012). |
| Confidential flows | Before the source adds identity: full-page confirmation "You are about to share who you are. After this your report is CONFIDENTIAL, NOT ANONYMOUS. Your identity will be locked so that only designated Identity Custodians can open it, and only with a legal reason. The custodians work for {organization}. A court or regulator can require them to reveal your name. If they do, you will normally be told, but this can be delayed. The people handling your report can still read what you write." Buttons: "Keep anonymous" (default focus) / "Share my identity" (RVW-B-14(d)(f); ANON-026). |
| C-38 clearnet pages | Header on every page, all locales: "CONFIDENTIAL — NOT ANONYMOUS. Your internet address is visible to our hosting provider and network operators." No ANONYMOUS word anywhere on C-38 except in "not anonymous" and a link to the onion instructions. Distinct visual theme (not reusing onion colors). |
| Escrow status | Every channel page: "Recovery escrow: DISABLED" or "Recovery escrow: ENABLED — keys held jointly by: <roles>" (ADR-013). GOV profile default is ENABLED with custodians from independent roles and SHALL be stated on the landing page (ADR-044(3)). |
| Who can unlock reports | Every channel page, generated from live configuration (ANON-028, RVW-B-14(b)): "Your report is first read by: {triage role labels}. It may later be shared with: {investigator roles}. {oversight_statement} {break_glass_statement} {escrow_statement}". |
| COI checklist (S04b-equivalent) | Verbatim (ADR-037(4)): "Your answers are encrypted and seen only by the independent triage team, who use them to keep the people involved away from your report. They may still suggest what your report is about." Plus (RVW-B-03): "Ticking your own manager tells the triage team which team you work in." |
| Recipient device custody (INDEPENDENT channels) | "Devices of the people who first read reports here are: independently managed / managed by {organization}" from the ADR-043 custody status (ANON-031). |
| Operator Statement | If the quorum-signed Operator Statement (ADR-035(2)) is absent or older than 30 days, every page shows a warning banner: "This site's operators have not renewed their statement that the service has not been secretly modified. This can be a warning sign." (ANON-025). |
| Tier W verification affordances | Tier W pages SHALL NOT present key-fingerprint or witness checks as a protection; where shown, the fixed sentence applies: "Checking these values does not protect a report sent from this website; only the Candor app checks them before encrypting." (ADR-036 Tier W limit; ANON-023). |
| Configuration digest | Landing footer: "Configuration: <8-char digest> · profile <name> · last changed <ISO week>" (week, not day: RVW-B-33(a)) linking to a page listing all non-default privacy-relevant settings (DANGEROUS/ADVANCED CFG classes, ADR-046(6)), whether a legal hold suspends deletion, whether the deployment attests infrastructure-backup exclusion of the Erasure Key Vault (ADR-044(4)), and — in small-organisation mode — "Separation of duties: reduced" (ADR-045). |
| Candor Desk | Mode chip on every case header and case list row; exports carry the mode in the Export Package manifest; IDENTIFIED/CONFIDENTIAL cases show whether sealed identity exists (never the identity). |
| Staff-to-source replies | Replies never assert a mode; Desk warns when a reply makes claims about the source's protection (ANON-014). |

## 8. Formal metadata inventory

### 8.1 Legend, layers and request types

**Disposition codes** (for each field × layer × request):

| Code | Meaning | Maps to classification |
|---|---|---|
| `N` | Never present at this layer (not transmitted to it, or removed before it). | NEVER COLLECT |
| `D` | Arrives by protocol but is **dropped at ingress** by the header allow-list before any handler reads it; never logged or stored. | NEVER COLLECT |
| `R` | Present only as **unparsed bytes in transit buffers** (e.g., tor daemon forwarding a decrypted stream, C-06 streaming a body to C-07); never parsed, logged or stored. | TRANSIENT MEMORY ONLY |
| `T` | Parsed/used in RAM for the request (or for the stated TTL); never written to disk, logs, swap or crash dumps. | TRANSIENT MEMORY ONLY |
| `C` | Collected and stored in cleartext at this layer (retention per §8.4). | COLLECT |
| `C↓` | Collected only in coarsened form (UTC day; ADR-011 size bucket). | COLLECT (coarsened) |
| `E` | Stored/relayed only encrypted to keys this layer does not hold. | ENCRYPT |
| `O` | Observable by infrastructure outside Candor's control (Tor relays, ISP); Candor neither receives nor stores it. | (external) |
| `S` | Exists only on the source's own device; Candor never requests or reads it. | (source-held) |
| `—` | Layer not on this request's path, or field not applicable to this request. | — |

**Layers:** Dev = source device (C-01/C-02/C-03) · Tor = Tor network (C-04) · GW = Intake Gateway tor daemon (C-05) · SWS = Source Web Service (C-06) · Seal = Intake Sealer (C-07) · IST = Intake Store (C-08) · Rel = Intake Relay (C-09) · Case = Case Service incl. AuthZ/Auth (C-10/C-21/C-22) · DB = Case Database (C-12) · Blob = Case Blob Store (C-13) · Logs = Audit Log Service (C-24) + host logs · Bak = Backups (C-27) · Notif = Notification Service (C-23).

**Request types:** R-00 client acquisition (outside Candor's servers; §8.2a) · R-01 landing GET (incl. static CSS) · R-02 new submission (POST) · R-03 attachment upload from mailbox · R-04 source login · R-05 fetch replies (mailbox GET) · R-06 send follow-up message · R-07 delete (close mailbox) · R-08 recipient API calls (Desk → Case Service, incl. reply-push sub-flow) · R-09 admin calls · R-10 key-directory fetch · R-11 health checks.

**Counters:** instance-wide SOURCE-SENSITIVE counters (`CTR:` in `08-API.md`, e.g. `logins`, `followups`) may be incremented by R-02..R-07. They carry none of the fields below, are never kept per account, and leave C-24/C-25 only as a coarse **global daily health band** (ADR-038(5), ADR-046(5); §12.4). Per-account quota uses a current-day counter only, reset daily; no quota history (ADR-038(3)).

**Field semantics:** for source requests (R-01..R-07, R-10) the fields describe the **source**; for R-08/R-09 they describe the **staff user**; for R-11 the monitor. F25 (content) is added to the mandated field list because the inventory is incomplete without it.

Tables §8.2 describe **Tier W** (default). Tier V and C-38 deltas are in §8.3. Server-side items that are not keyed to one request are listed in §8.6 (normative).

### 8.2a R-00 Client acquisition and first contact (ADR-041; RVW-A-14, RVW-B-16, RVW-B-17)

Candor's servers are not on this path; the rows state what third parties can record and what Candor requires so that it does not add to it.

| Path | Who can record what | Candor requirement |
|---|---|---|
| Source App from the Candor project's onion service or independent mirrors, over Tor | Mirror operator: nothing identifying (onion); local network: Tor use | Primary distribution (ADR-041); reproducible, signed; no per-tenant builds; branding is runtime data |
| Source App from an app store (optional) | Store operator: account, device, install time — account-linked, compellable (ADV-26) | Documented as leaving account-linked records; UI and `05` guidance state it (ANON-024) |
| Download from the organisation's clearnet information site | Organisation proxy/EDR: user, time, file | **Prohibited**: the organisation's clearnet site SHALL NOT host the App or log downloads; it links to the project distribution (ADR-041) |
| Visit to C-37 from a work device or network | Organisation proxy/EDR: user, time — before any guidance is displayed | C-37 has no logs/CDN (META-024); onion address published offline and as non-hyperlinked intranet text; first viewport warns about work devices (ANON-029) |
| Tor Browser download | Local network/ISP: download of Tor | Guidance only (`05`) |

### 8.2 Per-request inventory (Tier W)

#### R-01 Landing GET (onion; no session; includes static CSS and key-directory page views)
| # | Field | Dev | Tor | GW | SWS | Seal | IST | Rel | Case | DB | Blob | Logs | Bak | Notif |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F01 | Source IP | S | O | N | N | — | — | — | — | — | — | N | — | — |
| F02 | Network route (circuit) | S | O | T | T¹ | — | — | — | — | — | — | N | — | — |
| F03 | Timestamp exact | S | O | T | T | — | — | — | — | — | — | N | — | — |
| F04 | Timestamp rounded | S | N | N | N | — | — | — | — | — | — | N | — | — |
| F05 | Request length | S | O | T | T | — | — | — | — | — | — | N | — | — |
| F06 | Response length | S | O | T | T² | — | — | — | — | — | — | N | — | — |
| F07 | Upload size | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F08 | File type (sniffed) | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F09 | Filename | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F10 | MIME type | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F11 | Browser type (UA) | S | N | R | D | — | — | — | — | — | — | N | — | — |
| F12 | OS | S | N | R | D | — | — | — | — | — | — | N | — | — |
| F13 | Screen size | S | N | N | N³ | — | — | — | — | — | — | N | — | — |
| F14 | Locale | S | N | R | T⁴ | — | — | — | — | — | — | N | — | — |
| F15 | Timezone | S | N | N | N | — | — | — | — | — | — | N | — | — |
| F16 | Fonts | S | N | N | N³ | — | — | — | — | — | — | N | — | — |
| F17 | JS capabilities | S | N | N | N⁵ | — | — | — | — | — | — | N | — | — |
| F18 | Cookies | N | N | N | N | — | — | — | — | — | — | N | — | — |
| F19 | Account id | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F20 | Report id | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F21 | Recipient/channel id | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F22 | Geographic data | S | N | N | N | — | — | — | — | — | — | N | — | — |
| F23 | Device id | S | N | N | N | — | — | — | — | — | — | N | — | — |
| F24 | Auth data | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F25 | Content | — | — | — | — | — | — | — | — | — | — | — | — | — |

¹ Rendezvous circuit ID delivered to C-06 (tor `HiddenServiceExportCircuitID`), used only for per-circuit rate limiting, keyed with a per-boot HMAC key, TTL ≤ 10 min (META-004). ² Padded to the route's size class (META-008). ³ No client hints, no media-query- or font-conditional resource loads (META-013). ⁴ Locale comes from the URL path; `Accept-Language` is read only on the root path to suggest a language, never stored (META-002). ⁵ If the source's browser subsequently fetches the optional WEBCAT bundle, C-06 learns in RAM that JS is enabled for that circuit (T); never stored.

#### R-02 New submission (SW-03..SW-08 in `08-API.md`: start → message/file parts → Recovery Credential confirmation → send). Drafts (text and identity block) live only in C-07 mlocked RAM keyed by an opaque session handle; attachment parts are encrypted under a per-session key that exists only in sealer RAM and are written to a tmpfs staging area; the final HPKE seal of the content key happens only after the recipient set is fixed at Submit; 20 min idle / 2 h absolute; expiry or sealer restart zeroizes (ADR-034).
| # | Field | Dev | Tor | GW | SWS | Seal | IST | Rel | Case | DB | Blob | Logs | Bak | Notif |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F01 | Source IP | S | O | N | N | N | N | N | N | N | N | N | N | N |
| F02 | Network route | S | O | T | T | N | N | N | N | N | N | N | N | N |
| F03 | Timestamp exact | S | O | T | T | T¹ | N¹² | N | N | N¹³ | N¹³ | N | N | N |
| F04 | Timestamp rounded | S | N | N | N | T | C↓² | T | T | C↓¹³ | N | N | C↓ | N |
| F05 | Request length | S | O | T | T | T | N | N | N | N | N | N | N | N |
| F06 | Response length | S | O | T | T | N | N | N | N | N | N | N | N | N |
| F07 | Upload size | S | O³ | T | T | T | C↓ | T | T | C↓ | C↓ | N | C↓ | N |
| F08 | File type (sniffed) | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F09 | Filename | S | N | R | R | T | E | E | E | E | E | N | E | N |
| F10 | MIME type | S | N | R | R | T | E | E | E | E | E | N | E | N |
| F11 | Browser type (UA) | S | N | R | D | N | N | N | N | N | N | N | N | N |
| F12 | OS | S | N | R | D | N | N | N | N | N | N | N | N | N |
| F13 | Screen size | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F14 | Locale | S | N | R | T | T⁴ | E | E | E | E | N | N | E | N |
| F15 | Timezone | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F16 | Fonts | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F17 | JS capabilities | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F18 | Cookies (session, set at start) | T | N | R | T | T | N | N | N | N | N | N | N | N |
| F19 | Account id | N | N | N | T | T | C⁵ | E | E | E | N | N | C/E¹¹ | N |
| F20 | Report id (envelope/blob id) | N | N | N | N | T | C | T | T | C | C⁶ | N | C | N |
| F21 | Recipient/channel id | N | N | R | T | T | C | T | T | C | N | N | C | N |
| F22 | Geographic data | N | N | N | N | N | N | N | N | N | N | N | N | N |
| F23 | Device id | N | N | N | N | N | N | N | N | N | N | N | N | N |
| F24 | Auth data | S | N | R | T⁷ | T⁸ | C⁹ | N | N | E¹⁰ | N | N | C | N |
| F25 | Content (text, answers, files) | S | N | R | R | T | E | E | E | E | E | N | E | N |

¹ Used to compute `received_epoch_day`, a delayed-delivery release date if chosen (ADR-038(4)), and to select current Triage Set Member Epoch Keys (ADR-030, ADR-037); discarded. ² `received_epoch_day` + monotonic `batch_seq` (+ release date for delayed delivery); no record anywhere joins `batch_seq` to an exact time (META-005). ³ Tier W cannot pad on the wire: Tor relays and the intake uplink see approximate unpadded volume and time per upload (RVW-A-22); parts are padded to ADR-011 buckets before tmpfs staging (ADR-038(5)); guidance recommends Tier V for size-sensitive material. ⁴ UI language code sealed inside the manifest (visible only to recipients, who see the report's language anyway) and inside the source's own `prefs_ct`; never in cleartext (ANON-018). ⁵ `source_account_id`, passphrase-derived `lookup_tag` and `auth_pk`, and per-report `mailbox_id` (`04-CRYPTOGRAPHY.md`); `source_account_id` never leaves Z-INTAKE in cleartext — Z-CORE holds only `routing_ct` sealed to the Intake Routing Key and `mailbox_id` inside encrypted case records (`06-SYSTEM-ARCHITECTURE.md`). ⁶ Random object ID, not derived from content hash or envelope ID. ⁷ Session cookie, CSRF token and optional PoW token; RAM only. ⁸ Passphrase generated by C-07, **never stored** anywhere (not in C-08, not on disk, not for re-display); displayed on the Recovery Credential screen and the source must re-type 3 randomly chosen words before the submission is finalized; if the response is lost the submission is not finalized and the source restarts (ADR-034); held only in C-07 RAM until confirmation or session expiry; KDF per R-04 note ⁴; zeroized after key derivation. The v1.0/`11` re-display of a persisted passphrase (T_SAVED_CRED) is superseded (RVW-B-13). ⁹ `lookup_tag`, `auth_pk` and `prefs_ct` (sealed to the source's own key); never the passphrase. ¹⁰ Source public key travels inside the envelope; Z-CORE stores it only encrypted in the case record (Desk uses it to seal replies). ¹¹ C in Z-INTAKE backups; E (`routing_ct`, encrypted case fields) in Z-CORE backups. ¹² No record; but until the envelope is relayed at the next import slot, C-08 heap pages, WAL (`wal_level=minimal`, no archiving or replication, ADR-046(1)) and filesystem metadata can bound the arrival time for a forensic examiner of the intake host (PR-09). ¹³ Imports run only at fixed schedule slots (default 4×/day; HIGH/GOV 1×/day, ADR-038(1)); C-12 stores `received_date` (UTC day) and C-12/C-13 commit, WAL and object-metadata times equal the slot time, never the arrival time. Staff see the day (standard) or ISO week (HIGH) (ADR-038(3)).

#### R-03 Attachment upload from mailbox (logged-in session)
| # | Field | Dev | Tor | GW | SWS | Seal | IST | Rel | Case | DB | Blob | Logs | Bak | Notif |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F01 | Source IP | S | O | N | N | N | N | N | N | N | N | N | N | N |
| F02 | Network route | S | O | T | T | N | N | N | N | N | N | N | N | N |
| F03 | Timestamp exact | S | O | T | T | T | N | N | N | N | N | N | N | N |
| F04 | Timestamp rounded | S | N | N | N | T | C↓ | T | T | C↓ | N | N | C↓ | N |
| F05 | Request length | S | O | T | T | T | N | N | N | N | N | N | N | N |
| F06 | Response length | S | O | T | T | N | N | N | N | N | N | N | N | N |
| F07 | Upload size | S | O | T | T | T | C↓¹ | T | T | C↓ | C↓ | N | C↓ | N |
| F08 | File type (sniffed) | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F09 | Filename | S | N | R | R | T | E | E | E | E | E | N | E | N |
| F10 | MIME type | S | N | R | R | T | E | E | E | E | E | N | E | N |
| F11 | Browser type (UA) | S | N | R | D | N | N | N | N | N | N | N | N | N |
| F12 | OS | S | N | R | D | N | N | N | N | N | N | N | N | N |
| F13 | Screen size | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F14 | Locale | S | N | R | T | N | N | N | N | N | N | N | N | N |
| F15 | Timezone | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F16 | Fonts | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F17 | JS capabilities | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F18 | Cookies (session) | T² | N | R | T | T | N | N | N | N | N | N | N | N |
| F19 | Account id | N | N | N | T | T | C | E | E | E | N | N | C/E | N |
| F20 | Report id | N | N | N | N | T | C | T | T | C | C | N | C | N |
| F21 | Recipient/channel id | N | N | N | T | T | C | T | T | C | N | N | C | N |
| F22 | Geographic data | N | N | N | N | N | N | N | N | N | N | N | N | N |
| F23 | Device id | N | N | N | N | N | N | N | N | N | N | N | N | N |
| F24 | Auth data (session) | T | N | R | T | T³ | N | N | N | N | N | N | N | N |
| F25 | Content (file) | S | N | R | R | T | E | E | E | E | E | N | E | N |

¹ Plus per-account quota: current-day counter only, reset daily; no history (ADR-038(3); META-027; META-021 withdrawn). ² Memory-only session cookie (no Expires/Max-Age; name and attributes per `11`); Tor Browser discards it on close. ³ Session handle → derived source keys in C-07 RAM, zeroized as specified in `04-CRYPTOGRAPHY.md` and in any case at logout, 20 min idle or 2 h absolute.

#### R-04 Source login (POST passphrase)
| # | Field | Dev | Tor | GW | SWS | Seal | IST | Rel | Case | DB | Blob | Logs | Bak | Notif |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F01 | Source IP | S | O | N | N | N | N | — | — | — | — | N | N | — |
| F02 | Network route | S | O | T | T¹ | N | N | — | — | — | — | N | N | — |
| F03 | Timestamp exact | S | O | T | T | T | N² | — | — | — | — | N | N | — |
| F04 | Timestamp rounded | S | N | N | N | N | N² | — | — | — | — | N | N | — |
| F05 | Request length | S | O | T | T | T | N | — | — | — | — | N | N | — |
| F06 | Response length | S | O | T | T | N | N | — | — | — | — | N | N | — |
| F07 | Upload size | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F08 | File type | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F09 | Filename | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F10 | MIME type | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F11 | Browser type (UA) | S | N | R | D | N | N | — | — | — | — | N | N | — |
| F12 | OS | S | N | R | D | N | N | — | — | — | — | N | N | — |
| F13 | Screen size | S | N | N | N | N | N | — | — | — | — | N | N | — |
| F14 | Locale (UI; also inside `prefs_ct`) | S | N | R | T | T | E | — | — | — | — | N | E | — |
| F15 | Timezone | S | N | N | N | N | N | — | — | — | — | N | N | — |
| F16 | Fonts | S | N | N | N | N | N | — | — | — | — | N | N | — |
| F17 | JS capabilities | S | N | N | N | N | N | — | — | — | — | N | N | — |
| F18 | Cookies (session set) | T | N | R | T | T | N | — | — | — | — | N | N | — |
| F19 | Account id | N | N | N | T | T | C³ | — | — | — | — | N | C | — |
| F20 | Report id | N | N | N | N | N | N | — | — | — | — | N | N | — |
| F21 | Recipient/channel id | N | N | N | N | N | N | — | — | — | — | N | N | — |
| F22 | Geographic data | N | N | N | N | N | N | — | — | — | — | N | N | — |
| F23 | Device id | N | N | N | N | N | N | — | — | — | — | N | N | — |
| F24 | Auth data (passphrase) | S | N | R | R | T⁴ | C⁵ | — | — | — | — | N | C⁵ | — |
| F25 | Content | — | — | — | — | — | — | — | — | — | — | — | — | — |

¹ Per-circuit and global failed-login rate limiting in RAM (META-004); saturation states are not exposed beyond a daily health band (ADR-038(5)). ² No per-account last-login, login day or login count is stored (ADR-010, ADR-039); only the instance-wide SOURCE-SENSITIVE counter `logins` is incremented (§12.4). ³ Existing record read via `lookup_tag`; not modified by login. ⁴ Argon2id m=64 MiB, t=3, p=1 (FIPS profile: PBKDF2-HMAC-SHA-512, 210,000 iterations), limited by a concurrency semaphore (default 4) plus PoW (ADR-046(7)) → seed → keys; passphrase and seed zeroized at end of request; derived keys per `04`. A live or compelled intake captures the passphrase here (note 4 of §5). ⁵ `lookup_tag`/`auth_pk` (read-only).

#### R-05 Fetch replies (mailbox GET, session)
| # | Field | Dev | Tor | GW | SWS | Seal | IST | Rel | Case | DB | Blob | Logs | Bak | Notif |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F01 | Source IP | S | O | N | N | N | N | — | — | — | — | N | N | — |
| F02 | Network route | S | O | T | T | N | N | — | — | — | — | N | N | — |
| F03 | Timestamp exact | S | O | T | T | T | N¹ | — | — | — | — | N | N | — |
| F04 | Timestamp rounded (reply day) | T | N | R | T | T | C↓² | — | — | — | — | N | C↓ | — |
| F05 | Request length | S | O | T | T | N | N | — | — | — | — | N | N | — |
| F06 | Response length | S | O | T | T³ | N | N | — | — | — | — | N | N | — |
| F07 | Upload size | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F08 | File type | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F09 | Filename | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F10 | MIME type | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F11 | Browser type (UA) | S | N | R | D | N | N | — | — | — | — | N | N | — |
| F12 | OS | S | N | R | D | N | N | — | — | — | — | N | N | — |
| F13 | Screen size | S | N | N | N | N | N | — | — | — | — | N | N | — |
| F14 | Locale (UI; also inside `prefs_ct`) | S | N | R | T | T | E | — | — | — | — | N | E | — |
| F15 | Timezone | S | N | N | N | N | N | — | — | — | — | N | N | — |
| F16 | Fonts | S | N | N | N | N | N | — | — | — | — | N | N | — |
| F17 | JS capabilities | S | N | N | N | N | N | — | — | — | — | N | N | — |
| F18 | Cookies (session) | T | N | R | T | T | N | — | — | — | — | N | N | — |
| F19 | Account id | N | N | N | T | T | C | — | — | — | — | N | C | — |
| F20 | Report id (reply ids) | N | N | N | T | T | C | — | — | — | — | N | C | — |
| F21 | Recipient id (role + key fingerprint of replier) | T | N | R | T | T | E | — | — | — | — | N | E | — |
| F22 | Geographic data | N | N | N | N | N | N | — | — | — | — | N | N | — |
| F23 | Device id | N | N | N | N | N | N | — | — | — | — | N | N | — |
| F24 | Auth data (session; derived source private key) | T | N | R | T | T⁴ | N | — | — | — | — | N | N | — |
| F25 | Content (replies) | T⁵ | N | R | T | T | E | — | — | — | — | N | E | — |

¹ No "read"/"seen" marker, fetch counter, per-mailbox access time or history is stored (ADR-039). Tier W necessarily looks up the mailbox server-side after passphrase derivation, so a live or compelled intake can log when a given mailbox is checked (THR-135); Tier V uses fetch-all (§8.3). ² Day on which the staff reply was pushed (staff-action metadata). ³ Mailbox paginated so each page fits one size class (`11`). ⁴ Derived keys decrypt replies in C-07; C-06 receives rendered plaintext fragments. ⁵ Rendered page in Tor Browser memory; `Cache-Control: no-store`. Own-message history ("sent on YYYY-MM-DD") is not stored in any cleartext table (ADR-039); if shown it comes from ciphertext encrypted to the source key.

#### R-06 Send follow-up message (POST, session; text only)
| # | Field | Dev | Tor | GW | SWS | Seal | IST | Rel | Case | DB | Blob | Logs | Bak | Notif |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F01 | Source IP | S | O | N | N | N | N | N | N | N | N | N | N | N |
| F02 | Network route | S | O | T | T | N | N | N | N | N | N | N | N | N |
| F03 | Timestamp exact | S | O | T | T | T | N | N | N | N | N | N | N | N |
| F04 | Timestamp rounded | S | N | N | N | T | C↓ | T | T | C↓ | N | N | C↓ | N |
| F05 | Request length | S | O | T | T | T | N | N | N | N | N | N | N | N |
| F06 | Response length | S | O | T | T | N | N | N | N | N | N | N | N | N |
| F07 | Upload size (message size) | S | O | T | T | T | C↓¹ | T | T | C↓ | N | N | C↓ | N |
| F08 | File type | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F09 | Filename | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F10 | MIME type | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F11 | Browser type (UA) | S | N | R | D | N | N | N | N | N | N | N | N | N |
| F12 | OS | S | N | R | D | N | N | N | N | N | N | N | N | N |
| F13 | Screen size | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F14 | Locale | S | N | R | T | N | N | N | N | N | N | N | N | N |
| F15 | Timezone | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F16 | Fonts | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F17 | JS capabilities | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F18 | Cookies (session) | T | N | R | T | T | N | N | N | N | N | N | N | N |
| F19 | Account id | N | N | N | T | T | C | E | E | E | N | N | C/E | N |
| F20 | Report id (new envelope id) | N | N | N | N | T | C | T | T | C | N | N | C | N |
| F21 | Recipient/channel id | N | N | N | T | T | C | T | T | C | N | N | C | N |
| F22 | Geographic data | N | N | N | N | N | N | N | N | N | N | N | N | N |
| F23 | Device id | N | N | N | N | N | N | N | N | N | N | N | N | N |
| F24 | Auth data (session) | T | N | R | T | T | N | N | N | N | N | N | N | N |
| F25 | Content (message) | S | N | R | R | T | E | E | E | E | N | N | E | N |

¹ 4 KiB bucket (ADR-011). Each follow-up record in C-12 stores only its import-slot date; no per-case list of source activity days is kept elsewhere (ADR-038(3)). The follow-up dates of one case nevertheless remain visible to case members and to holders of C-12 and its backups (§5 note 25). Optional delayed delivery (1–3 days random, ADR-038(4)) decouples them from visit days.

#### R-07 Delete / close mailbox (SW-15: POST with passphrase re-entry)
| # | Field | Dev | Tor | GW | SWS | Seal | IST | Rel | Case | DB | Blob | Logs | Bak | Notif |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F01 | Source IP | S | O | N | N | N | N | N | N | N | N | N | N | N |
| F02 | Network route | S | O | T | T | N | N | N | N | N | N | N | N | N |
| F03 | Timestamp exact | S | O | T | T | T | N | N | N | N | N | N | N | N |
| F04 | Timestamp rounded | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F05 | Request length | S | O | T | T | N | N | N | N | N | N | N | N | N |
| F06 | Response length | S | O | T | T | N | N | N | N | N | N | N | N | N |
| F07–F10 | Upload/file fields | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F11 | Browser type (UA) | S | N | R | D | N | N | N | N | N | N | N | N | N |
| F12 | OS | S | N | R | D | N | N | N | N | N | N | N | N | N |
| F13 | Screen size | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F14 | Locale | S | N | R | T | N | N | N | N | N | N | N | N | N |
| F15 | Timezone | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F16 | Fonts | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F17 | JS capabilities | S | N | N | N | N | N | N | N | N | N | N | N | N |
| F18 | Cookies (session; invalidated) | T | N | R | T | T | N | N | N | N | N | N | N | N |
| F19 | Account id | N | N | N | T | T | C→del² | N | N | E³ | N | N | C⁴ | N |
| F20 | Report id | N | N | N | N | N | N | N | N | N | N | N | N | N |
| F21 | Recipient/channel id | N | N | N | N | N | N | N | N | N | N | N | N | N |
| F22 | Geographic data | N | N | N | N | N | N | N | N | N | N | N | N | N |
| F23 | Device id | N | N | N | N | N | N | N | N | N | N | N | N | N |
| F24 | Auth data (passphrase re-entry; `lookup_tag`, `auth_pk`) | S | N | R | R | T | C→del² | N | N | N | N | N | C⁴ | N |
| F25 | Content (pending replies) | — | — | — | — | N | E→del² | N | N | N | N | N | E⁴ | N |

² Source account record (`lookup_tag`, `auth_pk`, `prefs_ct`, mailbox ids) and pending replies deleted from C-08 immediately (PRD-028); no closure envelope is created; a deletion tombstone (hash of `lookup_tag`) is kept for the backup window so that a restore does not resurrect the mailbox (META-016, RVW-A-28; owned by `19`). ³ Z-CORE holds only `routing_ct`; the intake reports the closure to Z-CORE only after a uniformly random delay of 3–21 days and at ISO-week granularity (META-033, RVW-B-26), so the closure date cannot be matched to workplace events. ⁴ Persists in Z-INTAKE backups until their expiry (14-day rolling, §8.4).

#### R-08 Recipient API calls (Candor Desk → Case Service), incl. reply-push sub-flow
Fields describe the **staff user**. Source device and intake source-facing layers are not on the path; the reply-push sub-flow reaches IST via the relay.

| # | Field | Dev | Tor | GW | SWS | Seal | IST | Rel | Case | DB | Blob | Logs | Bak | Notif |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F01 | Staff IP | — | —¹ | — | — | — | N | N | T | N | N | C² | C² | N |
| F02 | Network route | — | —¹ | — | — | — | N | N | N | N | N | N | N | N |
| F03 | Timestamp exact | — | —¹ | — | — | — | N | T | T | C³ | N | C³ | C | N⁴ |
| F04 | Timestamp rounded | — | — | — | — | — | C↓⁵ | T | T | C↓ | N | N | C↓ | N |
| F05 | Request length | — | —¹ | — | — | — | N | T | T | N | N | N | N | N |
| F06 | Response length | — | —¹ | — | — | — | N | N | T | N | N | N | N | N |
| F07 | Upload size (case objects) | — | — | — | — | — | N | N | T | C↓ | C↓ | N | C↓ | N |
| F08 | File type (detected in C-17, stored in case record) | — | — | — | — | — | N | N | E | E | E | N | E | N |
| F09 | Filename | — | — | — | — | — | N | N | E | E | E | N | E | N |
| F10 | MIME type | — | — | — | — | — | N | N | E | E | E | N | E | N |
| F11 | Client type (Desk version) | — | — | — | — | — | N | N | T | N | N | C⁶ | C | N |
| F12 | OS | — | — | — | — | — | N | N | N | N | N | N | N | N |
| F13 | Screen size | — | — | — | — | — | N | N | N | N | N | N | N | N |
| F14 | Locale (staff profile) | — | — | — | — | — | N | N | T | C | N | N | C | N |
| F15 | Timezone (staff profile, display only) | — | — | — | — | — | N | N | T | C | N | N | C | N |
| F16 | Fonts | — | — | — | — | — | N | N | N | N | N | N | N | N |
| F17 | JS capabilities | — | — | — | — | — | N | N | N | N | N | N | N | N |
| F18 | Cookies | — | — | — | — | — | N | N | N⁷ | N | N | N | N | N |
| F19 | Account id (staff user id; reply target as sealed `routing_ct`) | — | — | — | — | — | C⁸ | E | T/E | C/E | N | C | C/E | C⁹ |
| F20 | Report id (case id, object ids) | — | — | — | — | — | C⁸ | T | T | C | C | C¹⁰ | C | N |
| F21 | Recipient ids (members, grants) | — | — | — | — | — | E⁸ | T | T | C | N | C | C | N |
| F22 | Geographic data | — | — | — | — | — | N | N | N | N | N | N | N | N |
| F23 | Device id (Desk device key fingerprint) | — | — | — | — | — | N | N | T | C | N | C | C | N |
| F24 | Auth data (token; WebAuthn assertion) | — | — | — | — | — | N | N | T | C¹¹ | N | N¹² | C¹¹ | N |
| F25 | Content (case objects; replies) | — | — | — | — | — | E | E | E | E | E | N | E | N |

¹ `O` if the staff path uses a restricted-discovery onion instead of the internal network (`16-TOR-I2P.md`). ² SECURITY audit, authentication and step-up events only; IP field nulled after 90 days. ³ Staff action timestamps (exact) — only in the SECURITY/SYSTEM tables enumerated in `09` (sessions, job leases, config cool-off, break-glass expiry) and audit events for staff actions; never for source-originated events or events triggered by them, e.g. import (ADR-046(11), ADR-038(1)). ⁴ Notifications are sent on a constant daily schedule whether or not anything is pending (ADR-038(2)); no event time reaches C-23. ⁵ Reply day. ⁶ On login events. ⁷ Desk uses audience-bound bearer tokens, no cookies (ADR-029). ⁸ Reply push: intake decrypts `routing_ct` with the Intake Routing Key to find the mailbox and stores the sealed reply under it; replier role/fingerprint are sealed inside the reply. ⁹ Staff notification address (configuration). ¹⁰ Pseudonymous case id in CASE audit. ¹¹ WebAuthn credential public keys and token-signing metadata (C-21 tables); never private keys. ¹² Secrets never logged.

#### R-09 Admin calls (Admin Console / `candorctl` → admin-api; SSH to hosts)
| # | Field | Dev | Tor | GW | SWS | Seal | IST | Rel | Case | DB | Blob | Logs | Bak | Notif |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F01 | Admin IP | — | — | T¹ | N | N | N | T¹ | T | N | N | C² | C | N |
| F02 | Network route | — | — | N | N | N | N | N | N | N | N | N | N | N |
| F03 | Timestamp exact | — | — | T | N | N | N | T | T | C | N | C | C | T |
| F04 | Timestamp rounded | — | — | N | N | N | N | N | N | N | N | N | N | N |
| F05 | Request length | — | — | T | N | N | N | T | T | N | N | N | N | N |
| F06 | Response length | — | — | T | N | N | N | T | T | N | N | N | N | N |
| F07–F10 | Upload/file fields | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F11 | Client type (candorctl version) | — | — | N | N | N | N | N | T | N | N | C | C | N |
| F12 | OS | — | — | N | N | N | N | N | N | N | N | N | N | N |
| F13 | Screen size | — | — | N | N | N | N | N | N | N | N | N | N | N |
| F14 | Locale | — | — | N | N | N | N | N | T | C | N | N | C | N |
| F15 | Timezone | — | — | N | N | N | N | N | T | C | N | N | C | N |
| F16 | Fonts | — | — | N | N | N | N | N | N | N | N | N | N | N |
| F17 | JS capabilities | — | — | N | N | N | N | N | N | N | N | N | N | N |
| F18 | Cookies | — | — | N | N | N | N | N | N | N | N | N | N | N |
| F19 | Account id (admin user id) | — | — | T¹ | N | N | N | T¹ | T | C | N | C | C | T³ |
| F20 | Report id | — | — | N | N | N | N | N | N | N | N | N | N | N |
| F21 | Recipient/channel id (config objects) | — | — | N | N | N | N | N | T | C | N | C | C | N |
| F22 | Geographic data | — | — | N | N | N | N | N | N | N | N | N | N | N |
| F23 | Device id (FIDO2 credential id) | — | — | T¹ | N | N | N | T¹ | T | C | N | C | C | N |
| F24 | Auth data | — | — | T¹ | N | N | N | T¹ | T | C⁴ | N | N | C⁴ | N |
| F25 | Content | — | — | N | N | N | N | N | N | N | N | N | N | N |

¹ Host-level SSH (FIDO2) on intake/relay hosts via the management network; sshd authentication events kept in host logs ≤ 90 days. ² SECURITY audit; IP nulled after 90 days. ³ Approval-request notifications for DANGEROUS config (content-free). ⁴ Credential public keys only.

#### R-10 Key-directory fetch (source side via onion; Desk side via Case Service)
| # | Field | Dev | Tor | GW | SWS | Seal | IST | Rel | Case | DB | Blob | Logs | Bak | Notif |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F01 | Source IP | S | O | N | N | — | N¹ | T¹ | N | — | — | N | — | — |
| F02 | Network route | S | O | T | T | — | N | N | N | — | — | N | — | — |
| F03 | Timestamp exact | S | O | T | T | — | N | T¹ | T² | — | — | N | — | — |
| F04 | Timestamp rounded | S | N | N | N | — | N | N | N | — | — | N | — | — |
| F05 | Request length | S | O | T | T | — | N | N | T² | — | — | N | — | — |
| F06 | Response length | S | O | T | T³ | — | N | N | T² | — | — | N | — | — |
| F07–F10 | Upload/file fields | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F11 | Browser/client type | S | N | R | D | — | N | N | T² | — | — | N | — | — |
| F12 | OS | S | N | R | D | — | N | N | N | — | — | N | — | — |
| F13 | Screen size | S | N | N | N | — | N | N | N | — | — | N | — | — |
| F14 | Locale | S | N | R | N | — | N | N | N | — | — | N | — | — |
| F15 | Timezone | S | N | N | N | — | N | N | N | — | — | N | — | — |
| F16 | Fonts | S | N | N | N | — | N | N | N | — | — | N | — | — |
| F17 | JS capabilities | S | N | N | N | — | N | N | N | — | — | N | — | — |
| F18 | Cookies | N | N | N | N⁴ | — | N | N | N | — | — | N | — | — |
| F19 | Account id | N | N | N | N⁴ | — | N | N | T² | — | — | N | — | — |
| F20 | Report id | N | N | N | N | — | N | N | N | — | — | N | — | — |
| F21 | Recipient/channel id | N | N | N | N⁵ | — | C¹ | T¹ | C¹ | — | — | N | — | — |
| F22 | Geographic data | N | N | N | N | — | N | N | N | — | — | N | — | — |
| F23 | Device id | N | N | N | N | — | N | N | T² | — | — | N | — | — |
| F24 | Auth data | N | N | N | N | — | N | N | T² | — | — | N | — | — |
| F25 | Content (public key-directory snapshot) | T | N | R | T | — | C¹ | T¹ | C¹ | — | — | N | — | — |

¹ Snapshot pushed by C-09 to C-08 and served by C-06; published data, not source data. Directory publications (epoch keys, roster changes) are batched to a fixed weekly publication slot (ADR-036(7), META-034); the intake enforces a snapshot high-water mark (ADR-036(6)). ² Desk-side fetch (authenticated staff call). ³ Snapshot served as one fixed object per publication; clients always fetch the **entire** directory, never a per-channel subset, so the fetch does not reveal channel choice (META-011). ⁴ Served identically with or without a session; the session cookie is not required and not read on this route. ⁵ Not selected by the source.

#### R-11 Health checks (C-25 metrics pull; onion reachability probe)
| # | Field | Dev | Tor | GW | SWS | Seal | IST | Rel | Case | DB | Blob | Logs | Bak | Notif |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| F01 | Source IP | N | N | N | N | N | N | N | N | N | N | N | N | N |
| F02 | Network route (probe circuit) | — | O¹ | T | T | N | N | N | N | N | N | N | N | N |
| F03 | Timestamp exact (health sample time) | — | O¹ | T | T | T | T | T | T | T | T | C² | N | T³ |
| F04 | Timestamp rounded | — | N | N | N | N | N | N | N | N | N | N | N | N |
| F05 | Request length | — | O¹ | T | T | N | N | N | N | N | N | N | N | N |
| F06 | Response length | — | O¹ | T | T | N | N | N | N | N | N | N | N | N |
| F07–F10 | Upload/file fields | — | — | — | — | — | — | — | — | — | — | — | — | — |
| F11–F17 | Client characteristics | — | N | N | N | N | N | N | N | N | N | N | N | N |
| F18 | Cookies | — | N | N | N | N | N | N | N | N | N | N | N | N |
| F19 | Account id | — | N | N | N | N | N | N | N | N | N | N | N | N |
| F20 | Report id | — | N | N | N | N | N | N | N | N | N | N | N | N |
| F21 | Recipient id | — | N | N | N | N | N | N | N | N | N | N | N | N |
| F22 | Geographic data | — | N | N | N | N | N | N | N | N | N | N | N | N |
| F23 | Device id | — | N | N | N | N | N | N | N | N | N | N | N | N |
| F24 | Auth data (probe HMAC; metrics mTLS) | — | N | R | T⁴ | T | T | T | T | N | N | N | N | N |
| F25 | Content (health status, bucketed counters) | — | N | R | T | T | T | T | T | T | T | C⁵ | N | T³ |

¹ The monitor's own Tor traffic (its guard sees the monitor host). ² SYSTEM events, 90 days; SYSTEM events triggered by source actions (e.g., relay pulls with arrivals) carry no time finer than the import slot and no arrival-count bucket (META-029). ³ Alert notifications to operators (content-free about sources). ⁴ Probes carry an HMAC header so C-06 excludes them from counters; the HMAC key is per-deployment. ⁵ SOURCE-SENSITIVE counters leave only as a global daily health band (§12.4). External Watcher probes (ADR-035(1)) are ordinary anonymous onion GETs of static assets and the running manifest, like R-01.

### 8.3 Deltas: Tier V and Confidential Clearnet (C-38)

| Request | Field | Tier W (above) | **Tier V** |
|---|---|---|---|
| R-02/R-03/R-06 | F09 Filename, F10 MIME, F25 Content at GW/SWS/Seal | R / R / T | **E** at every server layer (client-encrypted before upload; C-07 not involved except envelope passthrough) |
| R-02/R-03/R-06 | F07 Upload size at Tor/GW/SWS/Seal | O (exact) / T (exact) | **Padded client-side**; exact size exists only on device and inside the ciphertext |
| R-02/R-04 | F24 Auth data | Passphrase T in C-07 | Passphrase **never leaves device**; server sees signature over a server challenge (T) and stores public keys (C) |
| R-03 | Upload mechanism | Single POST per part, no resume (ADR-046(4)) | Resumable upload per the canonical protocol of `08-API.md` (ADR-046(4)): per-upload random tokens, 8 MiB chunks, no cross-session resume, resume ≤ 24 h only within one session; tokens **not linked to `source_account_id` until finalization**; chunks deleted on finalize or expiry (META-020, THR-047). Per-file cap 4 GiB (standard), 16 GiB only in EE profiles. |
| R-05 | Reply retrieval | Server-side lookup after passphrase derivation; T (decrypted in C-07) | **Fetch-all dead-drop** (ADR-039): the client downloads all reply ciphertexts of the last 30 days in fixed-size pages and trial-decrypts locally; no authentication, no mailbox selector, so F19/F24 are **N** at SWS/Seal/IST for this request; replies **E**, decrypted on device only |
| all | F11 Client type | UA dropped | Source App sends fixed `User-Agent: Candor-Source` with no version/platform; protocol major version in a request header (T) |
| all | F14 Locale | URL path | Not sent |
| R-10 | Verification | None: Tier W sources cannot verify the directory; verification for them is Desk's recipient-list check at import and External Watchers (ADR-036 Tier W limit) | Full snapshot + signed tree head + consistency proof + ≥ 2 external witness cosignatures (EE/GOV/MANAGED) verified; tree head pinned and gossiped (ADR-036(5), THR-118) |
| Dev | Local state | TB memory only | Source App keeps a **persistent Key Directory tree-head pin** (ADR-036(5); public data, but its presence and tenant are forensic evidence — PR-13, ANON-019 as amended); no other persistent state by default; optional encrypted local state (passphrase-derived key) only if the source opts in, with forensic-residue warning. Web bundle: pin shown as a short fingerprint the source may note. |

| Request | Field | Onion (Tier W) | **C-38 Confidential Clearnet** |
|---|---|---|---|
| all | F01 Source IP | N at all Candor layers | **T** at C-38 TCP/TLS stack (RAM only), **O** at ISP, hosting provider, any network operator; never logged by Candor (META-025) |
| all | F02 Route | O (Tor) | O (Internet path) |
| all | TLS client fingerprint (JA3/JA4) | n/a | T at TLS terminator; never stored |
| all | F11 UA | D | D |
| all | Mode | ANONYMOUS | CONFIDENTIAL (C2) — "NOT ANONYMOUS" |
| other fields | | as Tier W | as Tier W; content sealed by the same sealer code (separate instance on the C-38 host) |

### 8.4 Field disposition summary

| # | Field | Classification (sources) | Stored where (if at all) | Retention | Who can access | Purpose |
|---|---|---|---|---|---|---|
| F01 | IP address | **NEVER COLLECT** (onion). Staff/admin: COLLECT in SECURITY audit | Staff: C-24 SECURITY stream; host sshd logs | Staff IP nulled after 90 days | Security reviewers, auditors | Detect staff credential misuse |
| F02 | Network route / circuit | **TRANSIENT MEMORY ONLY** | C-05/C-06 RAM (HMAC-keyed circuit ID) | ≤ 10 min | Nobody (automated rate limiter) | Per-circuit rate limiting (ADR-026) |
| F03 | Exact timestamp | Sources: **TRANSIENT MEMORY ONLY** (no record; import-slot times and pre-relay C-08 residue per §5 note 17). Staff actions: COLLECT only in the tables enumerated by `09` and staff-action audit events, never for source-originated or source-triggered events (ADR-046(11)) | Staff: C-24, C-12 | SECURITY 400 days; CASE: case life + 12 months; SYSTEM 90 days | Auditors; case members for their cases | Accountability of staff actions (ADR-010) |
| F04 | Rounded timestamp (UTC day) | **COLLECT (coarsened)** | C-08 (`received_epoch_day`, delayed-delivery release date), C-12 (`received_date`; import-slot date per follow-up), backups | C-08 until relayed at the next import slot (≤ 6 h default; ≤ 24 h HIGH/GOV; plus the delayed-delivery hold of 1–3 days if chosen); C-12 case retention | Case members (day; ISO week in HIGH); admins (metadata) | SLA computation (EU Art 9), display |
| F05 | Request length | **TRANSIENT MEMORY ONLY** | RAM | Request | Nobody | HTTP processing, limits |
| F06 | Response length | **TRANSIENT MEMORY ONLY** (padded) | RAM | Request | Nobody | — |
| F07 | Upload size | Exact: **TRANSIENT** (Tier W) / never (Tier V); padded: **COLLECT (coarsened)**; exact: **ENCRYPT** inside envelope | C-08, C-12, C-13 (padded) | With object | Case members (exact, after decryption); admins (padded) | Quotas, storage |
| F08 | File type (sniffed) | **NEVER COLLECT** on servers; detected only in C-17 and **ENCRYPT**ed in case record | Case record | Case retention | Case members | Evidence handling |
| F09 | Filename | **ENCRYPT** | Inside envelope/case record | Case retention | Case members | Evidence context (source warned; may rename) |
| F10 | MIME type (declared) | **ENCRYPT** | Inside envelope | Case retention | Case members | Hint only; never trusted |
| F11 | Browser type / UA | **NEVER COLLECT** (dropped). Staff: Desk version COLLECT | C-24 (staff) | 400 days | Security reviewers | Staff client version enforcement |
| F12 | OS | **NEVER COLLECT** | — | — | — | — |
| F13 | Screen size | **NEVER COLLECT** | — | — | — | — |
| F14 | Locale | **TRANSIENT MEMORY ONLY** in cleartext; language code **ENCRYPT**ed in the manifest and in the source's own `prefs_ct`. Staff: COLLECT (profile) | Envelope/case record; C-08 `prefs_ct`; C-12 (staff) | Case retention | Case members | Render UI; reply language |
| F15 | Timezone | **NEVER COLLECT** (sources). Staff: COLLECT (profile) | C-12 (staff) | Account life | Staff user, admins | Staff display of SLA times |
| F16 | Fonts | **NEVER COLLECT** | — | — | — | — |
| F17 | JS capabilities | **NEVER COLLECT** (bundle fetch observable only transiently) | — | — | — | — |
| F18 | Cookies | **TRANSIENT MEMORY ONLY** (memory-only session cookie after login; none before). Staff: none | C-06/C-07 RAM session table | Idle 20 min; absolute 2 h | Nobody | Session continuity |
| F19 | Account id | **COLLECT** at intake only (`source_account_id`, `lookup_tag`, `auth_pk`, mailbox ids); Z-CORE: **ENCRYPT** (`routing_ct` sealed to the Intake Routing Key; `mailbox_id` in encrypted case record); staff user id COLLECT | C-08, Z-INTAKE backups; ciphertext in C-12 | C-08: until mailbox closed or case disposed | Automated intake routing; case members (mailbox_id after decryption) | Route replies to the mailbox |
| F20 | Report id (envelope, case, object ids) | **COLLECT** (random; never shown to source) | C-08, C-12, C-13 | As object | Case members; admins (metadata) | Storage/workflow |
| F21 | Recipient / channel id | **COLLECT** (channel id); recipient user ids COLLECT in Z-CORE | C-08, C-12, C-14 | Config life / case retention | Admins (metadata), case members | Routing, key selection |
| F22 | Geographic data | **NEVER COLLECT** (no GeoIP anywhere, including staff) | — | — | — | — |
| F23 | Device id | **NEVER COLLECT** (sources). Staff: Desk device key fingerprint COLLECT | C-14, C-12, C-24 | Device registration life + 400 days | Admins, auditors | Device binding, revocation |
| F24 | Auth data | Passphrase: **TRANSIENT MEMORY ONLY**, never stored or re-displayed from storage (C-07, Tier W; ≤ request at login, or until Recovery Credential confirmation within the ≤ 2 h draft session for a new passphrase, ADR-034); `lookup_tag` + `auth_pk`: **COLLECT**; staff: WebAuthn public keys COLLECT | C-08 (source), C-21/C-12 (staff) | Mailbox life / credential life | Automated verification only | Authentication |
| F25 | Content | **ENCRYPT** (Tier W plaintext TRANSIENT in C-06/C-07; tor daemon raw buffers) | C-08, C-12, C-13, backups (ciphertext) | Case retention; crypto-erasure on disposition | Case key holders | The purpose of the platform |

Backups (`19-BACKUPS-DR.md` owns the schedule): Z-INTAKE backup = C-08 account records + pending replies only (no envelopes older than one relay cycle) + deletion tombstones, 14-day rolling; Z-CORE backups 35-day rolling and contain all server-visible metadata of cases (including cases disposed after the backup was taken) until they expire (RVW-B-21); content keys never in backups (ADR-025); Erasure Key Vault excluded from routine backups, own backups ≤ 14 days, replicated to the DR site within HA RPO, signed erasure log applied before serving after restore; infrastructure-level backups (hypervisor/SAN) of core hosts MUST exclude the vault volume — otherwise the 14-day deletion bound does not hold (ADR-044(4)). Conflicting statements in `35` ("intake backups: none"; 12-month monthly core sets) are listed as cross-document requests.

### 8.5 Data-minimization principles

| ID | Principle |
|---|---|
| DM-01 | **Default deny:** a datum not listed for a layer in §8.2 is NEVER COLLECT there. |
| DM-02 | **Can't, not won't:** prefer architectures where the component never receives a datum over policies not to store it (onion instead of "no IP logging"). |
| DM-03 | **Coarsen at the edge:** the first component that must persist a value persists only the coarsest form that serves the purpose (UTC day, size bucket). |
| DM-04 | **Encrypt what humans need, store nothing else:** anything recipients need but servers do not (filenames, exact sizes, reply language) goes inside the envelope. |
| DM-05 | **No joins that recreate precision:** no persistent record may join two coarse values that together recover fine data (batch sequence + exact pull time). |
| DM-06 | **Transient means bounded:** every `T` datum has a stated TTL and lives in memory that is mlocked (C-07) or at least never swapped/dumped (all trust-path processes). |
| DM-07 | **No source telemetry and no behavioral metrics:** nothing is counted per source visit (PRD §11). |
| DM-08 | **Staff data is minimized too:** staff IPs expire from audit at 90 days; no keystroke/screen monitoring features. |
| DM-09 | **Aggregates are data:** statistics are subject to §12 before leaving the case team. |
| DM-10 | **Inventory changes are privacy changes:** any change to §8 requires privacy review and a version bump of this document (PRIV-001). |
| DM-11 | **Source-triggered means source-derived:** any row, event or log whose time is causally triggered by a source action (import, relay pull with arrivals, source-initiated escalation, mailbox closure) is treated as source timing and recorded at slot/day granularity or released on a fixed schedule (ADR-038, ADR-046(11); RVW-B-06). |
| DM-12 | **Sequences and tuples are data:** minimisation is assessed for the joint tuple of all cleartext fields per envelope/case and for sequences over time (follow-up days), not per field (RVW-A-26, RVW-B-11). |
| DM-13 | **Staff reactions are a proxy for source actions:** staff-side events exported outside Candor (SIEM, IdP, notifications) are minimised as if they were source-derived (RVW-B-31, RVW-C-02; THR-129). |

### 8.6 Server-side items not keyed to a single request (normative; added in revision round 2)

The v1.0 inventory omitted items that implementing specs re-introduced (RVW-B general finding; RVW-B-01, -06, -11, -12, -13, -21, -22; RVW-A-02, -09, -10, -26). This table is part of the normative inventory (META-001). Any SS/WF-class column of `09` that does not map to a row of §8.2–§8.6 is an inventory violation (PRIV-018).

| Item | Where | Form | Retention | Visible to | Decision / finding |
|---|---|---|---|---|---|
| Tier W draft text and identity block | C-07 mlocked RAM, keyed by opaque session handle | Plaintext in RAM only; never persisted, including on error paths | ≤ 20 min idle / 2 h absolute; zeroized on expiry, submit, discard or sealer restart | Nobody (live intake compromise: PR-01) | ADR-034; RVW-A-02, RVW-B-12 |
| Tier W draft attachment parts | tmpfs staging on H-INTAKE | Padded, encrypted under a per-session key held only in sealer RAM; no wraps to any member until Submit | As draft session | Nobody | ADR-034, ADR-038(5); RVW-A-07 |
| Per-draft timers / expiry values | — | **Not stored** (in-RAM index only) | — | — | ADR-034; RVW-A-02 |
| Source passphrase | — | **Not stored** | — | — | ADR-034; RVW-B-13 |
| Sealed envelopes awaiting import | C-08 | Ciphertext + `received_epoch_day` + `batch_seq` (+ release date if delayed delivery) | Until acknowledged after the next import slot / release date | Operator (metadata) | ADR-038(1)/(4) |
| Unimportable envelopes | C-08 | As above | Deleted after 14 days pending with dual-approved rejection | Operator | ADR-038(6) |
| Envelope `tier` column | — | **Removed** | — | — | ADR-039; RVW-A-26 |
| Header digest (dedup) | C-08 / C-12 | Hash | ≤ 24 h | Operator | ADR-039; RVW-A-26, RVW-B-33(e) |
| Per-mailbox access time, count, own-message history | — | **Not stored** | — | — | ADR-039; RVW-A-10, RVW-A-26 |
| Per-account upload quota | C-08 (or C-06/C-07 RAM) | Current-day counter only, reset daily | 1 day | Automated | ADR-038(3); RVW-A-26, RVW-B-11 |
| Account `activity_day` (for inactive-mailbox purge) | C-08 | Day of last envelope commit (see note) | Mailbox life | Operator | Retained by `09`; RVW-B-11 proposes month granularity — cross-document request |
| Mailbox-closed signal to Z-CORE | C-08 → C-12 | Flag, ISO week, released after random 3–21 days | Case life | Case members, admins | META-033; RVW-B-26 |
| Deletion tombstones | C-08, BS-INTAKE | Hash of deleted `lookup_tag`/reply ref | Backup window (14 d) | Operator (reveals that a deletion occurred, not whose) | RVW-A-28 (owned by `19`) |
| Import-slot date of each follow-up | C-12 | UTC day (display ISO week in HIGH) | Case life | Case members; DB/backup holders | ADR-038(3); residual RVW-B-11 (§5 note 25) |
| Import audit event | C-24 CASE | Date only; no exact `ts` for source-triggered events | CASE retention | Auditors | ADR-038(1), ADR-033(4); RVW-B-06 |
| Core DB commit/WAL, blob object metadata times | C-12, C-13, backups | Equal to the import slot time | Backup retention | Operator | ADR-038(1); RVW-A-09 |
| COI exclusions | C-12 | Blinded tags `HMAC(K_case_excl, user_id)`, `K_case_excl = HKDF(case_key, "candor/coi-excl/v1")`, padded to 8 per case; no `source` enum in cleartext | Case life | Nobody can read identities without the case key | ADR-037(3); RVW-B-01 |
| COI removal reason codes in audit | C-24 | Not distinguishable from other removals | — | — | ADR-037(3); RVW-B-01 |
| Source's COI answers ("report concerns…") | Inside the sealed envelope (Triage Set only) | Encrypted | Case life | Triage Set; later case members if shared | ADR-037(4) |
| Recipient key IDs in cleartext headers | — | **Never** (16 anonymous slots) | — | — | ADR-033(1), ADR-046(10); RVW-B-30 |
| Staff notifications | C-23 → mail/chat | Fixed text, constant daily schedule to each subscribed member, or disabled | Transport's retention | Transport operator (learns subscriber list) | ADR-038(2); RVW-A-19, RVW-B-05 |
| Global rate-limit / queue states | RAM; dashboards | Only a coarse daily health band | — | Admins, SOC | ADR-038(5), ADR-046(5); RVW-A-27 |
| Key Directory publications | C-14 | Epoch keys and roster changes batched to a fixed weekly slot; OVERSIGHT-certified role labels | Log life | Public | ADR-036(3)/(7); RVW-A-29, RVW-B-32 |
| Operator Statement, INCIDENT_NOTICE, platform manifest, running manifest | C-14, TUF | Signed public statements | Log life | Public | ADR-035(1)/(2)/(4), ADR-040 |
| External Watcher reports | Watchers' publications | Comparison results | Watchers' policy | Public | ADR-035(1) |
| IR captures of intake memory/traffic | Encrypted to independent custodians | Ciphertext | Per `31` | Custodians jointly | ADR-035(4); RVW-C-04 |
| Recipient device custody status | C-12 / Admin UI; channel descriptor | Enum + authenticator attestation | Device life | Admins, sources (INDEPENDENT channels) | ADR-043 |
| Erasure Key Vault + signed erasure log | Vault volume on H-CORE (physical TPM for HIGH/GOV); DR replica; vault backups | Per-case Erasure Keys; list of erased case IDs | Keys until disposition; vault backups ≤ 14 d | Operator (keys alone decrypt nothing) | ADR-033(3), ADR-044(4); RVW-C-06, C-07 |
| Records-search indices | Desk of an authorized member only | Local encrypted index | Per Desk retention | That member | ADR-044(5); no server-side global search |

## 9. Cross-layer correlation analysis

What an adversary learns by **combining** layers (single-layer compromise is in `02-THREAT-MODEL.md` §12).

| Combination | What becomes linkable | Bound | Residual |
|---|---|---|---|
| C-08 + C-12 + Intake Routing Key (both DBs and intake host) | Pseudonymous mailbox ↔ case; received day; padded sizes; channel | Nothing identifying: no IP, no exact time, no device data | Volume/topic inference from coarse category (THR-015) |
| C-08 + C-24 + C-09 host logs + C-12 WAL/backups | Batch sequence ↔ pull time ↔ arrival | META-005: no persistent join of `batch_seq` with exact pull time; imports only at fixed slots, commit/blob times equal slot time (ADR-038(1), `02` TM-015) | Import-slot granularity (≤ 6 h default; ≤ 24 h HIGH/GOV); C-08 page/WAL residue until relay (PR-09); exact time only for a *live* observer |
| Live C-05/C-06 + Tor guard of the source | Source IP ↔ submission | Requires both a live intake compromise and control/observation of the source's guard (THR-003) | Out of design envelope for GPA |
| Live C-06/C-07 (Tier W) | Plaintext + passphrase ↔ circuit | Circuit IDs are HMAC-keyed per boot; no IP | Tier W honesty statement |
| Case content + employer logs | Report ↔ employee (content, access logs, Tor use) | Candor contributes only the received **day** | Content/behavior (R-01, `02` §14) |
| Notifications + mail provider | Digest ↔ "something happened" | Content-free, constant daily schedule to each subscribed member whether or not anything is pending, or disabled (ADR-038(2)); v1.0 hourly event-driven digest was an existence oracle (RVW-A-19, RVW-B-05) | Subscriber list reveals who holds Candor roles; low otherwise |
| Staff reaction timing (IdP sign-ins, SIEM staff auth events, Desk update fetches, RCP-LAN flows) + employer Tor-use logs | Staff activity burst ↔ report arrival ↔ employee who used Tor | Fixed import slots (staff cannot react before a slot); constant-schedule digests; SOC sees only daily health bands (ADR-046(5)); SIEM staff-event granularity owned by `20` | Medium: day-level correlation remains; hour-level if staff react immediately to a slot (THR-129; RVW-B-31, RVW-C-02) |
| Follow-up import-slot dates (C-12) + employer Tor-use logs | Sequence of visit days ↔ employee | Only slot dates stored; ISO week in HIGH; delayed delivery 1–3 days (ADR-038(3)/(4)); guidance to batch messages | Medium–High for sources who send several follow-ups from observable networks (THR-134; RVW-B-11) |
| Excluded member's view (envelopes, notifications, dashboards) | "A report concerns me" + day | Triage-first: non-triage members see no intake envelopes, notifications or counts; dashboards count only cases the viewer can open (ADR-037(2); §12) | An excluded Triage Set member sees an unopenable envelope; workload side channels (THR-110) |
| C-08 + C-12 + Intake Routing Key + live intake (operator targets one case) | Case ↔ mailbox ↔ exact return-visit times | Tier V fetch-all: no mailbox selector reaches the server (ADR-039) | Tier W: full exposure prospectively (THR-135; RVW-A-10) |
| Everything server-visible, all customers (MANAGED vendor) | Cross-customer aggregation | Vendor holds no content keys; per-customer intake | All of §10.1 per customer, plus live Tier W capture capability (§10.3; RVW-B-19) |
| Support bundles + vendor | Org chart of the whistleblowing function; arrival timing | No relay events, config as value hashes, vendor retention ≤ 30 d (`32`; RVW-B-18) | Low |
| Organisation-managed recipient endpoint + case content | Everything that member reads | Independent custody for INDEPENDENT channels (ADR-043) | Full for org-managed endpoints (THR-126) |
| Key-directory fetch + submission | Channel chosen ↔ visit | Full-snapshot fetch (META-011) | None added |
| Program statistics across periods | Differencing to isolate a report | Fixed catalog, suppression, rounding (§12) | Low |

## 10. Legal-compulsion inventory

"Operator" = the organization running Candor (self-hosted CE/EE). "Vendor" = the company providing EE and the MANAGED service. "Can disclose" means *technically able to produce if compelled*; whether it must is a legal question. This inventory implements REQ-H-06 (R3) and is published with every release (PRIV-002).

### 10.1 Self-hosted (CE and EE; identical unless noted)

Corrected in revision round 2 (RVW-B general finding: the v1.0 table omitted data that implementing specs store). Rows marked **(r2)** are new or changed. The table is generated-in-principle from §8 and the `09` column classification (PRIV-018); where they disagree, the more disclosing statement applies until reconciled.

| Data | Exists? | Where | Encrypted? | Who has key | Retention | Can operator disclose? |
|---|---|---|---|---|---|---|
| Source IP address (ANONYMOUS) | **No** | — | — | — | — | **No** — never received (onion) |
| Source IP (C-38 CONFIDENTIAL) | Transient only | C-38 host RAM | — | — | Connection | **Only prospectively** (if compelled to start logging, which requires modifying trust-path code; External Watchers see only untargeted changes) |
| Source device/browser characteristics | **No** | — | — | — | — | **No** |
| Exact time of source actions **(r2)** | **No record.** Residues: import-slot times in core DB commit/WAL, blob metadata and backups (ADR-038(1)); C-08 page/WAL/filesystem residue until the envelope is relayed | C-12, C-13, backups; H-INTAKE disk | At rest only | Operator | Slot times: backup retention (≤ 35 d core); intake residue: until overwritten after relay | **Slot time: yes** (bounds arrival to the preceding slot interval: ≤ 6 h default, ≤ 24 h HIGH/GOV; not if delayed delivery was chosen). **Intake residue: possibly**, by forensic examination of a seized intake before relay. Prospectively a live intake could be modified to record exact times |
| `received_epoch_day` / `received_date` | Yes | C-08, C-12, backups | At-rest media encryption only | Operator | Case retention | **Yes** |
| Import-slot date of each follow-up message **(r2)** | Yes | C-12 (one date per follow-up record), backups | At rest only | Operator | Case retention | **Yes** — the list of days on which a source's follow-ups arrived (UTC day; equals visit day unless delayed delivery was used). Intersected with employer Tor-use logs this can narrow candidates (RVW-B-11) |
| Delayed-delivery release date **(r2)** | Yes, only if the source chose it | C-08 | At rest | Operator | Until release | **Yes** (a day) |
| Padded sizes, channel id, number of envelopes/day | Yes | C-08, C-12, C-13 | At rest only | Operator | Case retention | **Yes** |
| Envelope `tier` (W/V) **(r2)** | **No** (removed, ADR-039) | — | — | — | — | **No** |
| Header digest **(r2)** | Yes | C-08/C-12 | Hash | Operator | ≤ 24 h (ADR-039) | **Yes**, within 24 h only |
| Report text, questionnaire answers | Yes (ciphertext) | C-08 (until relayed), C-12, backups | **Yes, E2E** (Triage Set member epoch keys → case key) | Case members' endpoint keys; Recovery Quorum if enabled | Case retention | **Ciphertext only.** Plaintext only via compelled case members/quorum holders — or from endpoints the organisation administers (THR-126) |
| Report plaintext in transit — **Tier W** | Transient | C-06/C-07 RAM | — | — | Seconds | **Only prospectively** by modifying intake (disclosed risk, THR-026) |
| Report plaintext in transit — **Tier V** | **No** | — | — | — | — | **No** (modification of clients detectable via transparency) |
| Tier W drafts (unsent text, identity blocks) **(r2)** | RAM only; attachment parts on tmpfs under a RAM-only per-session key | H-INTAKE | Parts: yes (key in RAM only) | Nobody after session end | ≤ 2 h; lost on sealer restart | **No** retrospectively (never persisted, ADR-034); prospectively a live intake could capture them |
| Attachments | Yes (ciphertext) | C-08, C-13, backups | **Yes, E2E** | As above | Case retention | Ciphertext only |
| Filenames, MIME types | Yes (inside ciphertext) | As attachments | **Yes** | As above | Case retention | Ciphertext only |
| Source Passphrase **(r2)** | **No** — never stored, not even for re-display (ADR-034) | — | — | — | — | **No** retrospectively; **yes prospectively** for Tier W (captured at the next login by a modified intake) |
| Source account record (`source_account_id`, `lookup_tag`, `auth_pk`, mailbox ids, `prefs_ct`, `activity_day`, current-day quota counter) **(r2)** | Yes | C-08, Z-INTAKE backups | At rest only (`prefs_ct` sealed to source key) | Operator | Until mailbox closed/case disposed (or inactive purge); backups 14 d | **Yes** — nothing identifying; `lookup_tag` cannot be inverted at ≈129-bit passphrase entropy; no login times, access counts, own-message history or quota history exist (ADR-038(3), ADR-039) |
| Mailbox-closed flag **(r2)** | Yes | C-12 | At rest | Operator | Case life | **Yes** — ISO week, reported 3–21 days after the closure (META-033) |
| Deletion tombstones **(r2)** | Yes | C-08, BS-INTAKE | Hash | Operator | 14 d | **Yes** — reveals that a deletion occurred, not whose |
| Intake Routing Key (links `routing_ct` in C-12 to mailboxes in C-08) | Yes | Intake host (TPM-sealed where available) | Yes | Operator | Service life | **Yes** — with both databases it links case ↔ pseudonymous mailbox; nothing identifying by itself, but it lets a compelled operator target one case's mailbox prospectively (Tier W, THR-135) |
| COI exclusions ("who the report concerns") **(r2)** | Blinded tags only (8 per case, padded) | C-12 | HMAC under a key derived from the case key | Case members | Case life | **No identities** — without the case key the tags reveal nothing; no audit event or reason code distinguishes COI removals (ADR-037(3)). Source's COI answers are inside the envelope (Triage Set only) |
| Which members hold wraps for a case | Yes | C-12 | At rest | Operator | Case life | **Yes** — reveals who can read the case (after import the excluded set can be inferred by comparing with the channel roster) |
| Erasure Key Vault + signed erasure log (ADR-033(3), ADR-044(4)) **(r2)** | Yes | Vault volume on the core host (physical TPM for HIGH/GOV); DR replica; vault backups | Sealed on host | Operator | Keys until disposition; vault backups ≤ 14 d | **Yes**, but an Erasure Key alone decrypts nothing. If infrastructure-level backups include the vault volume (not attested), disposed cases remain recoverable by a later holder of member keys for the life of those backups (THR-130) |
| Mailbox replies | Yes (ciphertext) | C-08, C-12 | **Yes** (to source key; copy under case key) | Source (passphrase); case members | Mailbox life / case retention | Ciphertext only |
| Sealed identity (CONFIDENTIAL C1) | Yes (ciphertext) | C-12/C-13 | **Yes**, to Identity Custodian key set | ≥ 2 Identity Custodians jointly | Case retention; source may withdraw | **Only via custodians** under ADR-014 procedure (dual approval, legal basis, source notice) |
| Server-visible case metadata (state, coarse category, SLA dates, assignee ids, legal hold) | Yes | C-12 | At rest only | Operator | Case retention | **Yes** |
| Case notes, findings, interview records | Yes (ciphertext) | C-12/C-13 | **Yes** (case key) | Case members | Case retention | Ciphertext only; via compelled members |
| Case keys, Member Epoch private keys (ADR-030), staff private keys | Yes | Staff endpoints (wrapped by hardware) | **Yes** | Individual staff + hardware token | Member epoch keys destroyed after the 14-day window **and** import or dual-approved rejection of all their envelopes (ADR-033(2), ADR-038(6)) | **Operator (as organization) cannot** without compelling individuals — unless it administers their endpoints (THR-126; ADR-043 for INDEPENDENT channels) |
| Recovery Quorum shares (if enabled; **GOV default enabled**, ADR-044(3)) | Yes | Offline tokens of k-of-n holders | Yes | Holders | Until rotated | Only by compelling ≥ k holders; escrow status is public to sources |
| Onion service private key | Yes | C-05 (TPM-sealed), offline backup; ≤ 2 hosts in HA (ADR-032) | Yes | Operator | Service life | **Yes** — enables impersonation of the intake (THR-044) but not decryption of past envelopes |
| Staff accounts, roles, device fingerprints, device custody status | Yes | C-12, C-14, C-21 | At rest | Operator | Account life | **Yes** |
| SECURITY audit (staff auth, admin actions; staff IP ≤ 90 d) | Yes | C-24 | At rest; hash-chained | Operator | 400 days | **Yes** — staff login times are staff-reaction timing (THR-129) |
| CASE audit (staff actions with pseudonymous case ids; import events date-only) | Yes | C-24 | At rest; hash-chained | Operator | Case life + 12 months | **Yes** — no source-sensitive fields; no COI-specific reason codes |
| SYSTEM events, SOURCE-SENSITIVE counters | Yes | C-24, C-25 | At rest | Operator | 90 days | **Yes** — source-triggered SYSTEM events at slot granularity; counters leave only as daily health bands |
| IR captures of intake memory/traffic **(r2)** | Only if an incident capture was approved | Encrypted to independent custodians | Yes | Independent custodians jointly | Per `31` | **Only with the independent custodians**; each capture is announced by an INCIDENT_NOTICE (ADR-035(4)) |
| Notifications **(r2)** | Yes (outbound) | Mail/chat provider | Provider-dependent | Provider | Provider's | Constant daily text to each subscribed member (or none): reveals who holds Candor roles, not when reports arrive (ADR-038(2)) |
| Export Packages already sent | Yes | Destinations | Per package | Package recipients | Destination's | Outside Candor |
| Backups **(r2)** | Yes | C-27 | Ciphertext + at-rest; content keys absent | Operator (backup key) | Z-INTAKE 14 d; Z-CORE 35 d (`19`) | **Yes, but** content remains undecryptable; disposed cases undecryptable ≤ 14 days after Erasure Key destruction **only if** infrastructure-level backups exclude the vault (ADR-044(4)); server-visible **metadata** of disposed cases remains in Z-CORE backups until they expire |
| **EE only:** SIEM events via C-26 | Yes | Customer SIEM | Customer's | Customer | Customer's | SECURITY/SYSTEM events only; staff auth events carry staff-reaction timing (THR-129; granularity owned by `20`) |
| **EE only:** Fleet Manager status (opaque instance ID, version, health) **(r2)** | Yes | C-34 (customer or vendor hosted) | At rest | Fleet operator | 90 days | **Yes**, no content/keys/onion address **or onion hash** (v1.0 "salted onion hash" removed, RVW-B-20, aligned with `21`) |
| **EE only:** License files | Yes | Instance + vendor records | Signed | Vendor | Contract | Contract metadata only |
| Operator Statement, INCIDENT_NOTICE, platform/running manifests, Key Directory **(r2)** | Yes | C-14, TUF, watchers | Signed, public | — | Log life | Public; the directory reveals role labels and weekly roster changes of each channel |
| Records-search indices (ADR-044(5)) **(r2)** | Yes, on Desks only | Authorized member endpoints | Yes | That member | Desk retention | **Not by the operator**; only via the member |
| Clearnet info site (C-37) access data **(r2)** | **No** (no logs; no CDN, META-024) | — | — | — | — | **No** — but the organisation's own proxy/EDR logs visits from work devices (§8.2a) |
| Tor daemon logs **(r2)** | Notice-level, no circuit/client data | C-05, volatile | — | — | ≤ 24 h (aligned with `16` NET-008; v1.0 said 7 days) | No source data |

### 10.2 Tier W vs Tier V summary

| Question | Tier W | Tier V |
|---|---|---|
| Can a compelled operator hand over past report plaintext? | No | No |
| Can a compelled operator hand over past **replies**, link the source's reports, or read the source's COI preferences? **(r2)** | **Yes, prospectively**: at the source's next login the passphrase yields all stored replies (≤ retention), every `mailbox_id` and `prefs_ct`, and lets the adversary write as the source (RVW-A-03) | No |
| Can a compelled operator capture **future** plaintext without detection? | **Yes, for Tier W submissions** (modify C-06/C-07). External Watchers detect only untargeted changes to static assets, CSP and running manifest; a targeted or memory-only change is not detected; an optional confidential-VM sealer may detect a changed sealer measurement (ADR-035) | No — requires a signed malicious client release visible in transparency logs |
| Can a compelled operator capture a source's passphrase? | **Yes, prospectively** (at next login) | No |
| Can a compelled operator log **when** a specific source's mailbox is checked? **(r2)** | **Yes, prospectively** (server-side lookup; RVW-A-10) | No — fetch-all retrieval (ADR-039) |
| Can a compelled operator add a hidden recipient for a targeted source? | **Yes, prospectively** (serve forged directory; Tier W cannot verify); detectable afterwards by Desk's recipient-list check if a slot is added, not if plaintext is copied | Detectable (roster/epoch signatures, witnesses, transparency, pin) |
| Can recorded traffic be decrypted later (harvest-now-decrypt-later)? **(r2)** | **Possibly**, if a quantum-capable adversary recorded the onion circuit (classical key exchange; ADR-046(8)) | Content no (hybrid PQ HPKE); metadata yes |
| Can the operator identify the source's IP? | No | No |

### 10.3 MANAGED service (vendor-operated; ADR-021, ADR-024)

In MANAGED, the vendor operates Z-INTAKE (dedicated per customer), Z-CORE, backups, Fleet Manager and support; the customer's staff hold all content keys on their Desk endpoints; the vendor holds no content, identity-custodian or quorum keys. **Everything in §10.1 marked "Can operator disclose: Yes" is disclosable by the vendor for every customer**, and one order can cover many customers (RVW-B-19). The table lists what differs or is vendor-specific.

| Data / capability | Exists at vendor? | Where | Encrypted? | Who has key | Retention | Can vendor disclose? |
|---|---|---|---|---|---|---|
| Source IP | **No** | — | — | — | — | **No** |
| Report/attachments/replies/sealed identity | Yes (ciphertext) | Vendor-hosted C-08/C-12/C-13/C-27 | **Yes, E2E** | Customer staff / custodians only | Per customer policy | **Ciphertext only** |
| **Live capability:** Tier W plaintext, drafts, passphrases, replies at login, return-visit times **(r2)** | Transient | Vendor-hosted C-06/C-07 and hypervisor | — | — | Seconds | **Prospectively** — the vendor is subject to the same compelled-modification risk as an operator and additionally controls the hypervisor; customers with high-risk channels SHOULD require Tier V (`02` TM-012) |
| **Live capability:** onion impersonation **(r2)** | Yes | Vendor-hosted C-05 | TPM-sealed | Vendor | Service life | **Yes** — customers may hold the offline backup |
| All server-visible metadata of §10.1: received days, follow-up slot dates, padded sizes, channel ids, wrap holders, blinded COI tags, mailbox-closed flags, delayed-delivery dates **(r2)** | Yes | Vendor-hosted C-08/C-12/backups | At rest (vendor keys) | Vendor | Per customer policy | **Yes** |
| SECURITY audit (incl. staff IPs ≤ 90 d) and CASE audit (all investigator actions, staff exact timestamps) **(r2)** | Yes | Vendor-hosted C-24 | At rest | Vendor | As §10.1 | **Yes** |
| Notification addressees (the customer's whistleblowing staff list) **(r2)** | Yes | Vendor-hosted C-23 config | At rest | Vendor | Config life | **Yes** |
| Customer identity ↔ onion address | Yes | Vendor contracts/ops | — | Vendor | Contract | **Yes** (unavoidable for a managed service; disclosed to customers) |
| Fleet status, licences | Yes | C-34, C-35 | At rest | Vendor | 90 d / contract | **Yes** |
| Support tickets and scrubbed bundles **(r2)** | Yes | C-36 | Vendor | Vendor | ≤ 30 days for bundles (aligned with `32` §8; v1.0 said 2 years); tickets per contract | Yes — no content or secrets; no relay events; config as value hashes (RVW-B-18) |

### 10.4 Prospective compulsion (orders to start collecting or modify)

| Order | Technically possible? | Detectable? | Notes |
|---|---|---|---|
| Start logging source IPs (onion) | **No** — IPs never reach the service | — | Tor property [A:TOR] |
| Start logging exact timestamps / circuit IDs **(r2)** | Yes (modify intake) | Only if the modification changes what External Watchers are served (untargeted); otherwise no | Circuit IDs alone do not identify people; but an operator that also controls the source's likely network (employer) can resolve one case to its mailbox via the Intake Routing Key and log every Tier W return visit to intersect with its own network logs (RVW-A-10). Tier V fetch-all removes the mailbox selector (ADR-039) |
| Capture Tier W plaintext/passphrases **(r2)** | Yes (modify C-06/C-07) | External Watchers detect changes to static assets, CSP headers or the signed running manifest **only if untargeted** (ADR-035(1)); a selector-based or memory-only modification is **not** detected by any specified control; optional confidential-VM attestation (HIGH/GOV) may detect a changed sealer measurement but has a record of side-channel breaks (ADR-035(3)); lapse of the Operator Statement is a signal only (ADR-035(2)) | Disclosed Tier W limitation (ADR-035(5)). v1.0 reliance on "sealer attestation to Desk" and "published source-UI digests" withdrawn — neither is specified (RVW-A-01) |
| Capture intake memory/traffic under an incident-response pretext **(r2)** | Yes, if approved | Requires an independent-role approver (OVERSIGHT or external ombudsman) in addition to the IR lead, captures encrypted to independent custodians, and a source-visible INCIDENT_NOTICE (ADR-035(4)) | Collusion including the independent approver remains possible |
| Serve targeted malicious client (Tier V) | Requires threshold release signing across ≥ 2 organisations and jurisdictions (ADR-040) **and** evading transparency monitors and witnesses | Yes, by monitors (THR-118) | ADR-022 forbids per-customer builds |
| Push targeted update to one instance, or hold one instance on a vulnerable release **(r2)** | Targeted build: as above. Withholding: Fleet ring policies cannot hold an instance below the signed security floor (ADR-040) | Yes (transparency; running manifest compared by watchers) | Update client sends no instance identity |
| Add a recipient or loosen COI policy for future reports **(r2)** | Yes, with dual approval incl. an independent approver | Time-locked 72 h (GOV/HIGH 7 d), content-free notice to all members and OVERSIGHT, logged in the directory (ADR-036(2)) | Tier V warns on keys < 7 days old |
| Order the vendor's Fleet Manager to disable intake or change routing **(r2)** | **No** (ADR-045) | — | Availability-affecting actions require the customer's independent role |
| Unseal a CONFIDENTIAL identity | Yes, via ≥ 2 custodians | Recorded; source notified unless deferral recorded (deferral capped, PRIV-008) | Lawful by design |
| Enable Recovery Quorum retroactively for existing cases | Requires case members' Desks to re-wrap | Visible to sources (escrow status) and in CASE audit | GOV default is enabled from the start (ADR-044(3)) |
| Disclose program statistics | Yes | — | Only outputs of the `24` §TEL regime exist |

## 11. Should Tor be required? (ADR-003 analysis)

| Option | Anonymity effect | Usability / accessibility | Risk of misunderstanding | Legal/operational | Verdict |
|---|---|---|---|---|---|
| **A. Tor required for ANONYMOUS via onion-only endpoint** | Platform never sees IP; no fingerprinting needed to "check" Tor (any request on the onion came over Tor) | Requires Tor Browser or Source App (one download); fails on networks blocking Tor unless bridges | Low: anonymous path is unique | Onion ops (PoW, keys); Tor use visible locally | **Chosen** (ADR-001/003) |
| B. Tor recommended; clearnet form also labelled anonymous | Hosting/CDN/ISP see IP; "no-log" is policy only, compellable (INC-03) | Easiest | High (THR-040) | Commercial norm (R2 §5) | Rejected |
| C. Clearnet form that refuses non-Tor visitors via Tor-exit IP check | Exit sees plaintext unless HTTPS; clearnet hosting sees exit IPs only; still vulnerable to CDN/TLS termination; exits are a known attack surface (BTCMITM20, B-AN-25) | Medium | Medium | Exit list staleness | Rejected (onion strictly better) |
| D. Tor Browser fingerprint check (UA/JS probes) to enforce "Tor Browser only" | Requires fingerprinting code on the source path (THR-006); breaks at Safest | Poor | Medium | — | Rejected (ADR-003) |
| E. Tor + I2P | I2P users get weaker anonymity under the same label (R4 §5) | Complex | High | Two networks | Rejected (ADR-001) |

**Consequences and obligations**
1. Sources who cannot or will not use Tor are offered **only** CONFIDENTIAL paths (C-38 if enabled, or other organizational channels), explicitly labelled NOT ANONYMOUS — never a degraded "anonymous" path.
2. C-37 may compare the visitor's IP to the public Tor exit list **in memory** to show "You are not using Tor" or "Open in Tor Browser" guidance (Onion-Location); the result is never logged or stored (ANON-015).
3. Guidance covers: Tor Browser at Safest; Tails for high risk; bridges (obfs4, Snowflake, WebTunnel) on hostile networks (B-AN-30, B-AN-31); jurisdictions where Tor use is itself risky (use a network not associated with you; consider not using Tor from home); iOS/Onion Browser as weaker (R4 §3.3).
4. Tor's visibility on employer networks is disclosed on C-37 and the landing page (THR-002).
5. The transport abstraction (ADR-001) allows future cover-traffic transports that address "Tor use is a signal"; until then that residual is stated.
6. **First contact is itself metadata** (RVW-B-17, RVW-C-20; THR-138): the onion address SHALL also be published offline (posters, printed cards, QR codes) and on intranets only as non-hyperlinked text with "Don't open this at work. Copy it into Tor Browser at home."; C-37's first viewport shows the work-device warning above everything else; for INDEPENDENT channels C-37 SHOULD be hosted outside the organisation's web stack (a static host without access logs); operators MAY use a neutral multi-organisation directory run by the project (ANON-029).
7. **Client acquisition** (ADR-041): the Source App is obtained from the project's onion service or independent mirrors; the organisation's clearnet site never hosts or logs it; app-store installs are documented as account-linked (§8.2a, ANON-024).
8. **Sources who cannot use Tor** (phone-only on iOS, only a work device, Tor blocked): where a channel offers C-38 or a staffed hotline, S01-equivalent pages present it as a clearly labelled CONFIDENTIAL alternative rather than leaving sources to improvise (RVW-B-28; `11`).

## 12. Aggregation, inference and k-thresholds

**Single source of truth (ADR-046(5)).** All numeric parameters of the metrics regime — k, minimum period, suppression, magnitude statistics, channel minimums, SOC visibility — are defined **only** in `24-LICENSING-BUSINESS-MODEL.md` §TEL (§8–§9). This section defines audiences, prohibited dimensions and inference controls and quotes the ADR-046(5) values for readability; it does not restate any other number. v1.0 values that conflicted (M1 k ≥ 5; M2 quarterly with a switch to monthly at 240 reports/year; M3 k ≥ 20 yearly; M4 rolling 7-day buckets) are withdrawn (RVW-B-07, -08, -09).

ADR-046(5) values: **k = 10**; minimum period **one calendar month**; complementary suppression; **no medians, ratios or percentiles** for cells < k; **no per-channel metrics** for channels with < 3 cases/month; **SOC sees only global daily health bands**.

### 12.1 Audience classes

| Class | Audience | Threshold / period | Allowed dimensions (max 2 per table) | Prohibited dimensions |
|---|---|---|---|---|
| **M0** Case-team views | Users with access to the cases shown | none (they can see the cases) | any | — |
| **M1** Channel operations | Channel members | Counts **only of cases the viewer can open** (i.e., M0) — no aggregate of cases the viewer cannot open is shown to them (RVW-B-04). Non-triage roles see **no intake counts** at all (ADR-037(2)) | state, SLA status, coarse category | source-behavior metrics (PRD §11) |
| **M2** Program reporting | Program owners, management, board, internal audit (no case access) | `24` §TEL (k = 10, ≥ 1 calendar month, tumbling periods published only after the period closes) | channel group, coarse category, outcome, SLA met/not met, mode (ANONYMOUS vs other, as totals only) | department, location, business unit, accused role/level, submission weekday/hour, language/locale, Tier W/V, attachment presence/size, source follow-up counts per case; channels with < 3 cases/month (ADR-046(5)); channels with declared population < 50 unless merged into a channel group (PRIV-021) |
| **M3** External / public | Public, regulators | `24` §TEL; statutory exact counts only where law requires them (documented per jurisdiction pack) | channel type, coarse category, outcome | all M2 prohibitions + channel names that identify small bodies |
| **M4** Operational health | Admins, SOC (C-25/C-26), telemetry | **Global daily health band only** (ADR-046(5), ADR-038(5)); no per-hour, per-channel, per-tenant or rolling-window source-derived values | instance-wide only | everything else |

### 12.2 Suppression and inference rules (M1–M3)

1. **Primary and complementary suppression** per `24` §TEL.
2. **Magnitude rule** (ADR-046(5); RVW-B-08): medians, percentiles and ratios are published only if the underlying cell has n ≥ k; ratios additionally only if the numerator is not 0 or n; otherwise "—". Medians of durations are rounded to whole weeks (PRIV-017).
3. **Zero cells** are shown as 0 only in M0/M1; in M2/M3 zero and "< k" are merged.
4. **Tumbling periods only** (RVW-B-09): all displays are fixed, non-overlapping periods published once after the period closes; no rolling windows; no intra-period cumulative figures for M1+ audiences; no daily refresh of open periods.
5. **No regime switches within a year**: any rule that depends on volume (e.g., small-tenant single-total rule of `24` §TEL) is evaluated once per calendar year with hysteresis (switch back only after 2 consecutive years below the threshold).
6. **Temporal differencing:** a report for period P cannot be regenerated with different filters; corrections are issued as a new version replacing the old, both retained in audit; no "since last report" deltas finer than the period.
7. **Fixed catalog:** only reports defined in the signed report catalog (`14-CASE-MANAGEMENT.md`) can be generated; no ad hoc query interface over case data for M1–M3 audiences; `v_case_counts`-style per-channel/week views for admins are not permitted (cross-document request to `09`).
8. **Viewer knowledge:** suppression assumes the viewer may know every case they can open; no M1–M3 figure may be derivable into "cases I am excluded from" (RVW-B-04).
9. **Formal privacy accounting** for M3 (e.g., bounded noise with a published annual budget) is an open research item (§15 OI-08).

### 12.3 Inference risks addressed

| Risk | Example | Control |
|---|---|---|
| Small cells | "1 fraud report from Finance in March" | M2 prohibits department; k = 10 (`24` §TEL) |
| Differencing | Total(month) − Total(month excluding category X) | Fixed catalog; complementary suppression |
| Rolling/cumulative displays | 0 → "1–4" transition pinpoints a day | Tumbling periods, published after close (rule 4) |
| Regime switches | Before/after a volume threshold | Yearly evaluation with hysteresis (rule 5) |
| Magnitude statistics | Median over 3 cases; 1/1 substantiation | Magnitude rule (rule 2) |
| Subtraction by an excluded viewer | M1 total minus cases I can open | M1 shows only openable cases; non-triage roles see no intake counts (rule 8, ADR-037(2)) |
| Small channels | "Plant 7 Safety" (14 staff) | No per-channel metrics < 3 cases/month; population-based channel groups (PRIV-021) |
| Outcome linkage | "Substantiated harassment case" + a known dismissal | Outcome × category limited to 2 dims; k |
| Mode linkage | "Only CONFIDENTIAL report this month" | Mode only as totals |
| Operational counters | SOC sees intake activity rise the day after a meeting | Global daily health band only (M4) |
| Telemetry | Vendor sees instance activity | Telemetry schema per `24` §TEL (ADR-023) |
| Attribute exposure to recipients | Showing recipients "reporter is in a team of 3" | No such attributes exist (REQ-H-10 k ≥ 50 would apply if ever added) |

### 12.4 Operational counters (M4)

| Aspect | Rule |
|---|---|
| What is counted | Only instance-wide event counts declared as `CTR:` in `08-API.md` (e.g., `accounts_started`, `submissions`, `logins`, `followups`, `account_deletions`); never per account, per circuit, per channel, per tier. |
| Storage | Raw counters exist only inside C-24/C-25 for alert evaluation, one integer per counter per UTC day, retained per `24` §TEL. |
| Display/export | Only as a **global daily health band** (ADR-046(5)); C-26, telemetry, SOC views and dashboards receive band labels, never integers, hourly values or per-channel values. |
| Alerting | Abuse/health alerts (e.g., flood detection) evaluate raw counters inside C-24/C-25 and emit only "threshold exceeded" events, at day granularity. |
| Prohibited use | Counters SHALL NOT be used as product success metrics (`01` §11). |

## 13. Requirements

### 13.1 Anonymity and modes (ANON-)

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| ANON-001 | In ANONYMOUS mode the system SHALL NOT collect, request or store any source name, contact identifier, network address, device identifier, browser/OS characteristic, geographic datum, or exact timestamp of a source action, at any layer, as specified in §8. | ADR-001; ADR-010; INC-03; INC-05; INC-08 | THR-001; THR-006; THR-011 | C-05; C-06; C-07; C-08 | TST: inventory-conformance test (`inventory-check`) inspects DB schemas, log schemas and HTTP handlers against §8; AUD: privacy audit |
| ANON-002 | ANONYMOUS submissions SHALL be accepted only on the onion service; no clearnet endpoint SHALL accept submissions labelled or rendered as ANONYMOUS, and no automatic fallback SHALL exist. | ADR-001; ADR-002; INC-54 | THR-001; THR-040 | C-05; C-37; C-38 | TST: C-37 route scan finds no POST endpoints; C-38 pages contain no "ANONYMOUS" label except "NOT ANONYMOUS" |
| ANON-003 | Source-facing components SHALL NOT perform browser fingerprinting, User-Agent sniffing, JavaScript capability probes or Tor Browser detection. | ADR-003; INC-36; B-AN-15 | THR-006 | C-06; C-37 | INSP: code review ban list; TST: C-06 handlers receive no UA header (allow-list test) |
| ANON-004 | Every Tier W page SHALL be served with `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'` and SHALL function fully with JavaScript disabled; pages hosting the optional WEBCAT bundle SHALL use the manifest-defined CSP. | INC-27; INC-28; B-SD-21; B-CR-40 | THR-008; THR-036 | C-06 | TST: header test on all routes; no-JS end-to-end suite |
| ANON-005 | No cookie SHALL be set on landing, channel or informational pages; from the start of a new report (or after login) exactly one session cookie SHALL be set, with a ≥ 128-bit random value, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Expires`/`Max-Age`, and `Secure` with the `__Host-` prefix where the browser treats `.onion` as a secure context. | ADR-005; INC-36 | THR-006; THR-048 | C-06 | TST: cookie attribute tests; landing responses contain no `Set-Cookie` |
| ANON-006 | By default each new report SHALL receive a new passphrase and a new `source_account_id`; adding a report to an existing mailbox SHALL require an explicit choice with a linkability warning. | ADR-005; INC-32 | THR-010; THR-047 | C-06; C-07; C-03 | TST: default flow creates new account; DEMO: warning comprehension |
| ANON-007 | The current mode SHALL be displayed per §7 on every source page, every Source App screen, every C-38 page and every Desk case view, using text plus icon (never color alone). | ADR-002; B-CO-28 | THR-040 | C-06; C-03; C-38; C-15 | TST: snapshot tests per route/locale; DEMO: SM-07 comprehension ≥ 90 % |
| ANON-008 | Mode transitions SHALL follow §6 only; no transition to ANONYMOUS from any other mode SHALL be possible; each source-initiated transition SHALL require a full-page confirmation with "Keep anonymous" as the default-focused action. | ADR-002; ADR-014 | THR-040; THR-115 | C-06; C-03; C-10 | TST: state-machine tests; UI focus test |
| ANON-009 | If a source withdraws sealed identity before any unsealing, the system SHALL crypto-erase the sealed identity object and label the report CONFIDENTIAL (identity withdrawn); if unsealing has occurred, withdrawal SHALL be refused with an explanation. | ADR-014; ADR-025; B-CO-09 | THR-040; THR-111 | C-15; C-10 | TST: withdrawal flow tests |
| ANON-010 | When staff record that a source self-identified inside a message, the system SHALL require a CASE event with confirmation, change the mode to CONFIDENTIAL, seal the identifying excerpt to the Identity Custodian key set on request, and send a mailbox notice to the source. | ADR-014; B-CO-02 (Art 16) | THR-040; THR-019 | C-15; C-10 | TST: mode-change workflow test |
| ANON-011 | Export Packages SHALL carry the report mode in their manifest and SHALL NOT include sealed identity unless unsealed under ADR-014 and explicitly selected with dual approval. | ADR-014; ADR-018 | THR-029; THR-111 | C-15 | TST: manifest test; export with identity requires dual approval |
| ANON-012 | Tier V clients SHALL NOT automatically fall back to Tier W or to any unverified code path when verification or connectivity fails; they SHALL block submission and explain the failure. | ADR-004; INC-01 | THR-115; THR-007 | C-03 | TST: malicious-server harness verification-failure cases |
| ANON-013 | The onion landing page and C-37 SHALL publish a "What this protects — and what it does not" page generated from §5, listing each protected item, from whom, the assumptions (§4) and the residual risks, reviewed each release. | DECISIONS §0; INC-12 | THR-040 | C-06; C-37 | INSP: release review; TST: page presence and version match |
| ANON-014 | Staff-to-source replies SHALL be checked by Desk for claims about the source's protection ("anonymous", "untraceable", "no one will know" and locale equivalents) and Desk SHALL warn the sender before sending. | DECISIONS §0; THR-040 | THR-040 | C-15 | TST: claims-lint on reply composer |
| ANON-015 | C-37 MAY check the visitor IP against the public Tor exit list to show guidance; the IP and result SHALL be held only in memory for the request and SHALL NOT be logged, stored or used for any other purpose. | ADR-003; B-AN-54 | THR-001; THR-036 | C-37 | TST: C-37 config has access logging disabled; INSP: code review |
| ANON-016 | Source guidance (`05-SOURCE-OPSEC.md`) SHALL cover Tor Browser at Safest, Tails for high-risk sources, bridges (obfs4, Snowflake, WebTunnel), avoiding employer devices and networks, iOS limitations, delaying submissions after document access, and minimizing return visits; C-37 and the landing page SHALL link to it before the first submission step. | INC-31; INC-35; B-AN-30; B-AN-31; B-AN-21 | THR-002; THR-003; THR-004 | C-06; C-37; C-03 | TST: link presence; DEMO: usability comprehension |
| ANON-017 | The system SHALL NOT offer any mechanism to contact a source outside the mailbox (no email, SMS, phone, push), and SHALL NOT accept contact identifiers in ANONYMOUS channels. | ADR-005; ADR-017; INC-05; INC-25; INC-57 | THR-028; THR-034 | C-06; C-23 | INSP: schema review; TST: questionnaire-lint rejects contact fields |
| ANON-018 | The source's UI language SHALL NOT be stored or logged in cleartext anywhere; it MAY be sealed inside the manifest (for reply language) and inside the source's own `prefs_ct`; the language selector SHALL note that language can narrow who they are. | Design; INC-10 | THR-010 | C-06; C-07; C-03 | TST: DB/log schema scan finds no locale column for sources; envelope inspection |
| ANON-019 | The Source App SHALL keep no persistent local state by default; optional encrypted local state SHALL require opt-in with a forensic-residue warning. | INC-23; REQ-H-23 (R3) | THR-048 | C-03 | TST: file-system diff after session on each platform |
| ANON-020 | Source-facing responses SHALL carry `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and SHALL contain no external links, custom URL schemes or `file:` URIs. | INC-36; REQ-H-36 (R3) | THR-048; THR-006 | C-06 | TST: header and link crawler test |

### 13.2 Metadata handling (META-)

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| META-001 | Every component SHALL collect only the data listed for its layer in §8; any datum not listed SHALL be treated as NEVER COLLECT; changes to §8 SHALL require privacy review and a new version of this document. | REQ-H-06 (R3); INC-60 | THR-016; THR-035 | all | TST: `inventory-check` in CI; INSP: privacy review record per change |
| META-002 | C-06 SHALL pass to handlers only these request headers: `Host`, `Content-Type`, `Content-Length`, `Transfer-Encoding`, `Cookie` (authenticated routes), `Accept-Language` (root path only, transient), and the tor circuit-ID PROXY header; all other headers SHALL be dropped at ingress. | ADR-003; INC-60; B-SD-21 | THR-006; THR-016 | C-06 | TST: header allow-list fuzz test |
| META-003 | The intake tor daemon SHALL run with `SafeLogging 1` and log level ≤ notice; C-06 SHALL have no access log; error pages SHALL be generic and contain no host names, IPs, versions or stack traces. | ADR-016; INC-34; REQ-H-34 (R3); B-SD-21 | THR-001; THR-016; THR-104 | C-05; C-06 | TST: config test; error-page content test |
| META-004 | Per-circuit rate-limit state SHALL be held only in RAM, keyed by HMAC(per-boot random key, circuit ID), with entries expiring ≤ 10 minutes after last use. | ADR-026 | THR-001; THR-011 | C-05; C-06 | TST: unit test on TTL and keying; INSP: no persistence path |
| META-005 | C-08 SHALL store only `received_epoch_day` and a monotonic `batch_seq` for envelopes; no persistent record in any component SHALL associate a `batch_seq` (or envelope id) with a time finer than one UTC day. | ADR-010; ADR-033; INC-16; B-AN-21 | THR-011 | C-08; C-09; C-24 | TST: schema test; log-schema test for relay events (no `batch_seq` field) |
| META-006 | Z-CORE SHALL record case receipt and import in case records and CASE audit at UTC-day granularity. | ADR-010; ADR-033 | THR-011 | C-10; C-12; C-24 | TST: import event schema test |
| META-007 | The system SHALL NOT store any record of source logins, mailbox fetches, "seen"/"read" state, or last-activity time. | ADR-010; B-SD-01 | THR-011 | C-06; C-07; C-08 | TST: schema test; login leaves C-08 unchanged (row hash equality) |
| META-008 | Tier W HTML responses SHALL be padded to the route's size class from {16, 32, 64, 128} KiB as assigned in `08-API.md`; success and error responses of the same route SHALL share a class; no page SHALL exceed 128 KiB (mailbox pages paginate); the stylesheet SHALL be a single padded file. | ADR-011; B-AN-16; B-AN-20 | THR-004 | C-06 | TST: response-size class test over all routes and locales |
| META-009 | Messages SHALL be padded to 4 KiB buckets (max 64 KiB) and attachments to the ADR-011 geometric buckets; Tier V clients SHALL pad before upload. | ADR-011; B-GL-24 | THR-004; THR-015 | C-07; C-03; C-11 | TST: padding KATs |
| META-010 | Filenames and MIME types SHALL exist server-side only inside sealed envelopes and SHALL NOT be used for storage paths; the source UI SHALL warn that filenames can identify them and Tier V SHALL offer renaming before upload. | ADR-027; INC-18; B-SD-33 | THR-009 | C-07; C-03; C-15 | TST: storage paths are random IDs; UI warning presence |
| META-011 | Key-directory data SHALL be served as one complete snapshot object per epoch; clients SHALL fetch the full snapshot, never per-channel subsets. | ADR-008; B-AN-16 | THR-004; THR-011 | C-06; C-14; C-03 | TST: API exposes no per-channel key route to sources |
| META-012 | No component SHALL perform GeoIP lookups or store geographic data about sources or staff. | INC-08; INC-09; INC-13 | THR-001; THR-016 | all | INSP: dependency ban list (GeoIP DBs); TST: `inventory-check` |
| META-013 | Source pages SHALL NOT send `Accept-CH`/`Critical-CH`, and stylesheets SHALL NOT contain `@font-face` rules with `local()` sources, or `url()` references inside `@media`, `@supports` or `@container` blocks. | ADR-003; INC-36 | THR-006 | C-06 | TST: CSS lint job `css-privacy-lint` |
| META-014 | Source sessions SHALL be stored only in C-06/C-07 RAM with idle timeout 20 minutes (warning at 17 minutes, one-action extension) and absolute timeout 2 hours; derived source keys SHALL be zeroized on logout, timeout or process restart. | ADR-005; B-SD-09; B-CO-28 | THR-014; THR-034 | C-06; C-07 | TST: timeout tests; memory-zeroization test under Miri/valgrind |
| META-015 | Staff IP addresses SHALL be recorded only in SECURITY audit authentication/step-up events and host SSH logs, and SHALL be nulled after 90 days. | ADR-016; B-GL-04 | THR-016 | C-24; C-21 | TST: retention job test |
| META-016 | Z-INTAKE backups SHALL contain only C-08 source account records and pending replies (no envelopes older than one relay cycle) and SHALL be retained 14 days rolling; onion keys SHALL be backed up separately offline. | ADR-025; INC-55 | THR-017 | C-27; C-08 | TST: backup content manifest test |
| META-017 | Notifications SHALL use the fixed ADR-017 text, SHALL be batched into at most one digest per hour per recipient, and SHALL contain no case id, count, channel or time of submission. | ADR-017; INC-57 | THR-028 | C-23 | TST: notification payload snapshot test |
| META-018 | Health probes SHALL authenticate with a per-deployment HMAC header and be excluded from counters; SOURCE-SENSITIVE counters SHALL be exported only as M4 buckets over 7 days. | ADR-016; INC-70 | THR-039; THR-016 | C-25; C-06 | TST: counter export schema test |
| META-019 | Trust-path processes SHALL disable core dumps (`RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`), SHALL not send crash reports off-host, and panic messages SHALL be restricted to static strings without request data. | INC-58; REQ-H-58 (R3) | THR-016 | C-05; C-06; C-07; C-10 | TST: crash test verifies no dump and scrubbed output |
| META-020 | Tier V chunked uploads SHALL use a random 256-bit `upload_token` not linked to `source_account_id` until finalization, fixed 1 MiB chunks, and deletion of chunks at finalization or after 24 hours. | THR-047 (DECISIONS) | THR-047 | C-06; C-08; C-03 | TST: chunk lifecycle test |
| META-021 | Per-source upload quota accounting SHALL store only padded bytes per UTC day per `source_account_id`, retained 30 days rolling. | ADR-026; ADR-010 | THR-011; THR-033 | C-08 | TST: quota table schema/retention test |
| META-022 | Z-INTAKE hosts SHALL have egress default-deny except to the Tor network via the local tor daemon; they SHALL NOT perform DNS resolution; package updates SHALL be fetched over Tor. | INC-33; REQ-H-33 (R3) | THR-104; THR-114 | C-05; C-39 | TST: egress firewall test; DNS query capture shows none |
| META-023 | Any TLS terminator on the staff path SHALL log only schema-defined fields (no bodies, no query strings, no tokens). | ADR-016; INC-56 | THR-016 | C-10 | TST: log-schema test |
| META-024 | C-37 SHALL have no access logs, cookies, analytics or third-party resources; if operated behind a CDN, the landing and guidance pages SHALL state that the CDN can see visitors of the information site. | INC-46; INC-53; REQ-H-53 (R3) | THR-036; THR-103 | C-37 | TST: C-37 header/resource crawler; config test |
| META-025 | C-38 SHALL NOT log client IP addresses or TLS fingerprints; they SHALL exist only in the network stack/TLS terminator memory for the connection. | ADR-002; INC-03 | THR-001; THR-040 | C-38 | TST: log inspection after test submissions |
| META-026 | The Source App SHALL send a fixed `User-Agent: Candor-Source` without version or platform, and only a protocol major-version header. | ADR-003 | THR-006 | C-03 | TST: request capture test |

### 13.3 Privacy governance, compulsion and statistics (PRIV-)

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| PRIV-001 | Any new stored field, log field, metric or integration SHALL undergo a documented privacy review against §8 and §12 before merge into trust-path code. | REQ-H-60 (R3); B-CO-09 | THR-016; THR-035 | C-30 | INSP: PR template gate; CODEOWNERS for schema/log files |
| PRIV-002 | Each release SHALL publish the legal-compulsion inventory (§10) for that version, and the operator console SHALL display it. | REQ-H-06 (R3); INC-06; INC-12 | THR-026 | C-19; C-37 | INSP: release artifacts include inventory; TST: console page presence |
| PRIV-003 | The operator legal-response procedure SHALL restrict responses to data in §10, require two-person approval, and record each request and response in SECURITY audit. | INC-71; REQ-H-71 (R3) | THR-026; THR-018 | C-19; C-24 | DEMO: tabletop legal-request exercise; INSP: procedure document |
| PRIV-004 | Metrics SHALL be classified M0–M4 and SHALL apply the thresholds, granularity and dimension rules of §12.1. | INC-74; INC-70; REQ-H-70 (R3); REQ-H-74 (R3) | THR-039 | C-10; C-15; C-25; C-26 | TST: report generator tests with synthetic small cells |
| PRIV-005 | M1–M3 reports SHALL apply the suppression algorithm of §12.2, including complementary suppression, marginal rounding and the small-tenant rule. | INC-74; B-CO-12 | THR-039; THR-120 | C-10 | TST: differencing attack test suite (derive suppressed cells from published tables must fail) |
| PRIV-006 | M1–M3 statistics SHALL be producible only from the signed report catalog; the system SHALL provide no ad hoc query interface over case data to users without case access. | INC-70 | THR-120; THR-039 | C-10; C-19 | INSP: route registry; TST: unauthorized query attempts rejected |
| PRIV-007 | Instance telemetry, if enabled, SHALL NOT include submission, login, reply or case counts at any granularity finer than M4 buckets, and SHALL NOT include onion addresses or tenant names. | ADR-023; B-CO-66 | THR-114; THR-036 | C-25 | TST: telemetry schema test |
| PRIV-008 | Unsealing of CONFIDENTIAL identity SHALL require a legal-basis record, approval by two Identity Custodians, and a mailbox notice to the source with written reasons unless a deferral reason is recorded; each deferral SHALL be re-reviewed every 90 days. | ADR-014; B-CO-02 (Art 16(3)) | THR-111 | C-15; C-10; C-24 | TST: unseal workflow; DEMO: custodian exercise |
| PRIV-009 | Desk SHALL provide redaction support and warnings for indirect identifiers (role, team, location, dates, writing style) before any export or disclosure, reflecting EU Art 16(1) "directly or indirectly deduced". | B-CO-02 (Art 16); INC-10 | THR-019; THR-041 | C-15; C-17 | DEMO: redaction workflow; TST: export checklist gate |
| PRIV-010 | Data-subject requests from sources SHALL be supported via the mailbox only (access to their own submissions and replies; withdrawal of sealed identity; mailbox closure); the documentation SHALL state that Candor cannot locate a source's data by name or contact identifier because it holds none. | B-CO-09; B-CO-10 | THR-040 | C-06; C-07 | INSP: documentation review; TST: mailbox export of own data |
| PRIV-011 | Candor SHALL ship a DPIA template pre-filled from §8 and §10 for operators. | B-CO-09; B-CO-10; B-CO-12 | THR-035 | C-19 | INSP: template presence per release |
| PRIV-012 | For MANAGED service, the vendor SHALL publish §10.3 for its service, a semi-annual transparency report of legal requests received (counts, types, outcomes), and SHALL notify affected customers of requests unless legally prohibited. | INC-06; INC-07; REQ-H-07 (R3) | THR-026; THR-027 | C-36; C-34 | DEMO: published report; INSP: contract terms |
| PRIV-013 | Intake-side data SHALL be deleted per §8.4: envelopes after Z-CORE acknowledgement (typically ≤ one relay cycle; envelopes un-imported for > 7 days escalated per ADR-033), source account records and pending replies when the mailbox is closed or the case disposed. | ADR-009; ADR-025 | THR-015; THR-017 | C-08; C-09 | TST: lifecycle tests |
| PRIV-014 | Staff personal data SHALL be minimized: no keystroke, screen or activity monitoring features; staff IP retention per META-015; staff time zone and locale used only for display. | B-CO-09; DM-08 | THR-016 | C-15; C-21 | INSP: feature review |
| PRIV-015 | The protected-from-whom matrix (§5) and the Tier W/V compulsion summary (§10.2) SHALL be reproduced verbatim in operator documentation and SHALL be re-validated against the implementation before each release. | DECISIONS §0 | THR-040; THR-026 | C-19; C-37 | INSP: release checklist; AUD: privacy audit scope |
| PRIV-016 | Programs that publish statistics SHALL be warned in the admin console when their annual volume is below 50 reports that only annual totals are permitted (small-tenant rule). | INC-74 | THR-039 | C-19 | TST: console warning test |

## 14. Residual risks and limitations

| # | Residual | Why | Disclosure |
|---|---|---|---|
| PR-01 | Tier W plaintext and passphrases transit C-06/C-07 RAM; a live or compelled intake can capture them prospectively. | No-JS web cannot encrypt client-side (ADR-004). | Tier W statement; §10.2; channels can require Tier V. |
| PR-02 | Tor daemon and C-06 hold raw bytes (R) of every request transiently; a live compromise of C-05 sees them. | Onion termination is on the intake host. | §8 legend; component compromise in `02`. |
| PR-03 | Tier W uploads reveal approximate unpadded size to Tor relays and the intake host. | No client-side padding without JS. | Guidance: Tier V for size-sensitive material. |
| PR-04 | Received day + channel + coarse category can, with organizational knowledge, narrow candidates. | Needed for SLAs/routing. | Protected-from-whom notes 13–15. |
| PR-05 | Content and behavior identification (style, knowledge, timing of Tor use). | Outside platform control. | `05` guidance; ANON-013 page. |
| PR-06 | k-thresholds reduce but do not eliminate inference by insiders with rich side knowledge. | Statistical disclosure control limits. | §12 conservative defaults. |
| PR-07 | CONFIDENTIAL identity can be lawfully unsealed. | By design (legal obligations). | §3 definition; notice (PRIV-008). |
| PR-08 | MANAGED service: vendor knows which customer runs which onion service and holds the onion key. | Operational necessity. | §10.3; customers may self-host. |

## 15. Open issues

| # | Issue | Proposed resolution |
|---|---|---|
| OI-01 | Import-time coarsening was raised here and has been adopted as ADR-033(4). META-005/006 implement it; a live intake observer can still bound arrival to one pull interval. | Resolved (ADR-033); HIGH-profile daily import in `02` TM-013 addresses the live-observer residual. |
| OI-02 | ASM IDs for `[A:…]` tags pending in `40-SECURITY-ASSUMPTIONS.md`. | Map in v1.1. |
| OI-03 | `__Host-`/`Secure` cookie behaviour on `.onion` origins in current Tor Browser needs confirmation. | Knowledge (unverified); verify in `30-ANONYMITY-TESTING.md`; ANON-005 already conditions on secure-context treatment. |
| OI-04 | Whether padding every Tier W page to 64/128 KiB is sufficient against onion-specific WF (Tik-Tok 64.7 % on onion sites, B-AN-16) is unmeasured. | Anonymity test campaign in `30`; may require uniform page weight across all routes. |
| OI-05 | M2 monthly granularity threshold (≥ 240 reports/12 months) and department-size threshold (500 staff) are design choices without empirical calibration. | Validate with statistical disclosure control review before 1.0. |
| OI-06 | Retention defaults for SECURITY audit (400 days) and CASE audit (case life + 12 months) must be reconciled with jurisdiction packs (`25`, `35`). | Joint review. |
| OI-07 | Staff transport choice (internal mTLS vs restricted-discovery onion) affects R-08/R-09 "Tor" column. | Decision in `06`/`16`; see `02` OI-03. |
