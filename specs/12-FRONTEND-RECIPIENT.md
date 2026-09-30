# 12 — Recipient User Interface Specification (Candor Desk)
Status: Draft v1.2 (final consistency round: ADR-047) · Edition applicability: both (CE core; EE adds connector targets in export and SSO-bridged unlock policy) · Owner: Recipient Experience team (with Security Architecture, Case Management and Accessibility review)

## 1. Purpose and scope

This document specifies the user interface of **Candor Desk** (C-15), the signed, reproducible desktop client (Tauri 2) used by recipients and investigators. It covers:
- inbox and triage;
- the case view;
- the secure conversation;
- the evidence panel with containment-level indicators;
- the viewer launch;
- redaction;
- the Export Package workflow;
- conflict-of-interest (COI) indicators;
- SLA views;
- notifications;
- identity-unseal and break-glass requests;
- keyboard and accessibility;
- safety interlocks;
- the in-app recipient OPSEC guidance.

The Desk admin mode is specified in `13-FRONTEND-ADMIN.md`.

**Protection statement.** The Desk UI is designed so that:
- decrypted case content is shown only to users whose devices hold the case key (ADR-007, ADR-008, ADR-015);
- untrusted evidence is never parsed outside the containment environment C-17/C-18 (ADR-012);
- report content leaves the Desk only through an explicit, redaction-verified, audited Export Package (ADR-018).

This protects sources and case content against recipient operational mistakes (THR-041), hostile files (THR-023), onward leakage (THR-029) and excess insider access (THR-019, THR-020). It implements protections P-08, P-10, P-11, P-12, P-15, P-16 and P-20 of `40-SECURITY-ASSUMPTIONS.md`. It assumes:
- the recipient workstation OS (C-16) is not compromised while unlocked (ASM-019);
- the hardware unlock token is held by the user and keeps keys non-exportable (ASM-028);
- C-17 isolation holds (ASM-015, ASM-020);
- recipients follow handling procedures for actions the UI cannot enforce (ASM-021);
- Identity Custodians do not collude (ASM-031);
- channel membership signing keys are not jointly compromised (ASM-033).

It cannot stop a malicious authorized recipient from reading, photographing or retyping content they can legitimately view (§14).

## 2. Context and dependencies

| Document | Dependency |
|---|---|
| `DECISIONS.md` | ADR-007 (no browser recipient UI; hardware-bound keys), ADR-008 (case keys), ADR-010 (day-granularity receipt), ADR-012 (containment, original + derivative, dual approval for originals), ADR-014 (Sealed Identity Store), ADR-015 (COI, break-glass), ADR-016 (audit classes), ADR-017 (content-free notifications), ADR-018 (Export Packages), ADR-025 (deletion), ADR-027 (safefs, malicious-server harness) |
| `04-CRYPTOGRAPHY.md` | Case-key wrapping, message signing, re-wrap on routing |
| `10-FILE-EVIDENCE-PIPELINE.md` | Derivative generation, hashes, transformation records, verification tooling |
| `14-CASE-MANAGEMENT.md` | Case states, triage, routing, SLA engine, source-visible status |
| `15-AUTHENTICATION-AUTHORIZATION.md` | Unlock methods, roles, ABAC, COI, time-bounded grants, break-glass |
| `20-LOGGING-AUDITING.md` | CASE and SECURITY event schemas emitted by Desk actions |
| `32-OPERATIONS.md` | Human-factor controls (HUM-*), configuration classes |
| `05-SOURCE-OPSEC.md` | Promises made to sources that this UI must honor (SOPS-033, SOPS-041) |
| `26-ACCESSIBILITY.md` | WCAG 2.2 AA / EN 301 549 clause 11 for Desk |
| `40-SECURITY-ASSUMPTIONS.md` | P-08, P-10, P-11, P-12, P-15, P-16, P-20; ASM-015, -019, -020, -021, -028, -031, -033; checks ASM-111 (proof verification and gossip), ASM-116 (running-binary hash warning), ASM-117 (containment probe), ASM-122 (case key-holder warnings) |
| `DECISIONS.md` ADR-030, ADR-033 §1 | Per-member epoch keys; **16 anonymous HPKE slots, no recipient key IDs anywhere in cleartext** (ADR-033 §1, ADR-046 §10; the v1.0 phrase "envelope header lists recipient key IDs" is withdrawn, RVW-B-30); COI filter before wrapping |
| `DECISIONS.md` revision ADRs | ADR-036 (directory governance, follow-up sealing rule), ADR-037 (triage-first routing, blinded COI tags), ADR-038 (fixed import schedule, constant-schedule digests, day/ISO-week dates, unopenable-envelope rejection), ADR-042 (platform tiers, plain-text rendering of hostile strings, "rendering — not evidence", OCR text layer), ADR-043 (independent-custody devices), ADR-044 (key-access continuity, local records search), ADR-045 (independent approver for break-glass), ADR-046 §10 (no key IDs from cleartext headers) |
| `DECISIONS.md` final round | ADR-047(3) (chaff envelopes: failed trial decryption is normal), ADR-047(7) (Desk case-key cache, re-wrap after Erasure Key Vault restore or loss, erasure-log purge on every sync), ADR-047(8) (per-case metadata ciphertext re-created on re-wrap), ADR-047(2) (follow-up dates only inside the encrypted case record) |

## 3. Design principles

| # | Principle | Rule |
|---|---|---|
| RP-1 | **Safe by default, explicit to deviate** | The default action on any evidence is the sanitized copy. Riskier actions need an extra, labelled step. |
| RP-2 | **Containment always visible** | Every evidence item and every open viewer shows its containment level (§6) in text, icon and pattern. |
| RP-3 | **No silent egress** | No content leaves Desk except via the Export Package flow. There is no "open with", "share", "save as" or drag-out. |
| RP-4 | **Least data on screen** | Identity is never in the case view (ADR-014). Source metadata is shown only as policy allows (received day, channel, mode). |
| RP-5 | **Warn at the point of action** | Warnings attach to the action they concern (export, print, reply). They are not global banners that users learn to ignore. |
| RP-6 | **Dense but accessible** | Tables and panels for professional throughput, with full keyboard support, screen-reader semantics and zoom. |
| RP-7 | **No remote content** | The Desk UI is bundled. It fetches no remote code, fonts, images or help pages. |
| RP-8 | **Honest status** | Sync, key-directory and containment availability are shown in a status bar. Failures are never hidden. |

## 4. Application shell

```
+----------------------------------------------------------------------------------+
| Candor Desk  [Workspace: Acme / Audit Committee v]      [Search]   [!2] [?] [Lock]|
+-----------+----------------------------------------------------------------------+
| Inbox (3) |                                                                      |
| My cases  |                       (content region)                               |
| All cases |                                                                      |
| Tasks/SLA |                                                                      |
| Exports   |                                                                      |
| Requests  |                                                                      |
| Guide     |                                                                      |
+-----------+----------------------------------------------------------------------+
| Sync: last import slot 2026-09-30 | Keys: directory consistent ✓ | Viewer: ready |
| (Tier 1: KVM microVM) | Custody: independent (attested) | Version 1.4.2 (current)     |
+----------------------------------------------------------------------------------+
```
- The status bar (`role="status"`) reports sync (import slot date, never a time), key-directory consistency (C-14 proofs), the Desk platform tier and C-17 availability (`10` §6.1), device custody status (§4.2), device posture and the update state.
- Regions: navigation (`<nav>`), content (`<main>`), status bar (`<footer>`). `F6` cycles regions.
- The window title is always "Candor Desk". It never contains a case reference or content, because OS window lists and task switchers are visible to screen-recording and EDR tools on managed hosts.

### 4.1 Unlock and posture (R01)
- **Unlock:** hardware-bound unlock per ADR-007: FIDO2 `hmac-secret`/PRF, PIV smartcard + PIN, or TPM + PIN. A CE software-passphrase fallback shows a persistent "Weaker protection: software key" badge.
- **Posture checks at unlock:**

| Check | Default |
|---|---|
| OS full-disk encryption on | block if off (config) |
| OS screen lock ≤ 10 min | warn |
| Desk version current per TUF metadata | block if older than the security-fix window (33) |
| C-17 containment probe passed (ASM-117: no network route, no key-material mount, fresh disk) | block all attachment viewing (CL-2/CL-3) until it passes; text (CL-1) still available |
| Running trust-path binaries match the transparency log (ASM-116 signed statement from C-25) | blocking warning |
| Desk's own binary and loaded modules match the transparency-logged release; the Desk reports its release digest to C-25 (ADR-043). **Non-authoritative:** a modified build can lie; this detects accidental divergence and unsophisticated repackaging only | blocking warning |
| Platform tier (`10` §6.1) and containment probe | Reduced tier → text-only mode (§R06); shown in status bar |
| Managed-endpoint indicators (best effort, RVW-A-24, RVW-C-01, RVW-C-11): enterprise EDR/MDM agents, remote-assist or screen-recording tools, insider-risk agents, VDI/RDP session, OS AI screenshot features (e.g., Recall), cloud clipboard, crash-dump upload policy, sync-client roots | persistent "Managed endpoint — people who administer this computer may be able to see what you see" banner; blocking for INDEPENDENT-channel Triage Set members unless custody is attested (§4.2) |
| `desk-preflight` (`21-ENTERPRISE.md` ENT-034): signed, TUF-distributed product catalogue checked at enrolment, at each unlock and at least daily (EDR sample submission / live response, DLP/eDiscovery collection, remote assist, screen recording, Recall-class capture, cloud clipboard, sync roots, crash upload) | findings feed the managed-endpoint banner; blocking for INDEPENDENT-channel Triage Set members; an override for an INDEPENDENT channel requires OVERSIGHT approval and is CASE/SECURITY-audited |
| System clock within ±5 min of the signed key-directory timestamp (THR-043) | warn |
| Key-directory consistency | block on split-view detection |

- Posture results are shown as a checklist with pass/warn/block states in text.
- **Update metadata:** the Desk refreshes TUF metadata through the Z-CORE mirror endpoint on a fixed daily schedule, not on each start, so Desk starts are not visible to vendor mirrors or corporate proxies (RVW-C-02 item 4; `33-RELEASE-UPDATE-SECURITY.md`, cross-document request).
- **Crash handling (RVW-C-11):** the Desk disables OS and webview crash reporting for its processes (Windows WER `LocalDumps` off and `DontSendAdditionalData`; WebView2 crash reporter disabled by policy; macOS `ReportCrash` exclusion), sets `PR_SET_DUMPABLE=0` / `SetProcessMitigationPolicy` equivalents, and defaults Export Package destinations to a Desk-managed encrypted folder; detected sync roots (OneDrive Known Folder Move, Dropbox, Google Drive, iCloud Drive) are refused as export destinations unless OVERSIGHT approves.
- **Locking:**
  - The session auto-locks after `DESK_IDLE_LOCK` (default 10 min, range 2–30, SAFE config).
  - It also locks on OS lock or sleep, and on smartcard removal.
  - Locking clears decrypted content from the webview DOM and drops plaintext caches.
  - Unsaved reply text survives lock in memory under the session key.

### 4.2 Device custody indicator (ADR-043; RVW-C-01, RVW-A-24)
- Every Desk shows a persistent status-bar item **"Custody: independent (attested)"**, **"Custody: organisation-managed"** or **"Custody: unknown"**. "Independent" means the device is recorded in C-14 as not enrolled in the operating organisation's MDM/EDR/DLP/VDI, with its hardware authenticator attestation recorded (ADR-043); the record is made by the admin custody workflow (`13-FRONTEND-ADMIN.md` §4.3a) and co-signed by OVERSIGHT.
- For a member of a **Triage Set of an INDEPENDENT channel** (IG, audit committee, ombudsman, external counsel, ethics), a Desk whose custody is not "independent (attested)" shows a blocking banner: "This device is not recorded as independent of {organization}. People who manage it could read reports. You cannot receive new reports on this channel from this device." The Desk does not publish Member Epoch Keys for that channel from such a device, unless the channel has an active DANGEROUS custody exception (`15` DC-16; `13` §4.3a), in which case the banner remains non-dismissable.
- Honest text in the Guide (RO-16) and in the indicator's details: "An organization that controls this computer can defeat Candor's protections. Candor cannot prevent this technically (ADR-043)."

### 4.3 Case-key cache and access continuity (ADR-047(7); RVW-C-07)
- **Cache.** The Desk keeps a hardware-sealed local cache of every case key (all live versions) the member is authorized for, as keystore records sealed by the member's hardware-bound key (format `04-CRYPTOGRAPHY.md` §9.10). It is updated on every sync. The status bar shows "Case keys: cached for {n} cases" only in R13 Settings, never in window titles or notifications.
- **Erasure log first.** On every sync the Desk verifies the signed erasure log (hash chain) **before** any other operation and purges, for each listed case, the cached keys, blinded-tag state, local search-index entries (R15) and any local copies. A Desk that cannot verify the log shows "Case access paused: the deletion record could not be checked" and opens no cached case until it can. Removal of the member from a case purges that case from the cache when the removal takes effect (ADR-044(1) cooling-off applies to server wraps only).
- **Restore case access (R16).** After an Erasure Key Vault restore or loss, cases marked `ek_missing` appear to their current key holders as a task "Restore access for {n} cases". For each case the holder's Desk re-creates HPKE wraps of its cached case key to every ACL member (and the Recovery Quorum key when enabled), re-creates the case's metadata ciphertexts from its decrypted case record (ADR-047(8)), and uploads them for layering under the new Erasure Key. A second holder or OVERSIGHT approves (step-up). Each receiving Desk checks the key against the case's latest record before accepting it; a failure shows "This key does not open the case — do not use" and raises a SECURITY alert. Cases for which no holder has a cached key are listed as "Lost: no key holder has this case" with the records-law note of `35-DATA-RETENTION-DELETION.md`. CASE events are content-free.
- **Honest text** (R13 details): "Your Desk keeps keys for your cases so that access can be restored if the server's key vault is lost. Anyone who unlocks this Desk with your hardware key can open those cases."

## 5. Screens

### R02 Inbox / Triage
- **Purpose:** receive newly imported reports and decide initial handling (`14-CASE-MANAGEMENT.md` triage).
- **Who:** only members of the channel's **Triage Set** (ADR-037). Non-triage members never list, receive notifications for, or trial-decrypt intake envelopes, and their channel views show no intake counts (ADR-037 §2; RVW-A-18, RVW-B-04). For them the Inbox navigation item is absent.
- **Table columns:**

| Column | Content |
|---|---|
| Ref | Case pseudonym (for example `C-7F3K-2Q`), random and not derived from any source data |
| Channel | Channel name |
| Received | Import slot date `YYYY-MM-DD` (standard) or ISO week `YYYY-Www` (HIGH) (ADR-038 §3); never a time |
| Mode | ANON / CONF / IDENT badge (text + pattern) |
| Category | Source-selected category |
| Files | Count |
| Risk | "Few people know" flag from source answer (`05` §8.7): shows `HIGH` when "1–5". Visible to Triage Set and case lead only (RVW-B-33 f) |
| COI | "Exclusions applied" icon (no count in the list; details in §8) |
| SLA | Next due (e.g., "Acknowledge by 2026-10-07") |
| Status | New / Triaged / Spam-held / Unopenable |

- **Recipient-set check (ADR-030, ADR-033 §1, ADR-046 §10; RUI-055 amended):** envelope headers carry 16 anonymous HPKE slots and **no recipient key IDs** anywhere in cleartext. On import the Desk (1) trial-decrypts the slots with its own current Member Epoch Keys; (2) verifies the source-signed recipient list inside the decrypted manifest (`08-API.md` SA-12 `manifest_ct`) against the channel's eligible Triage Set in C-14, with inclusion and consistency proofs and the snapshot high-water mark (ADR-036 §6; ASM-111); (3) checks that every non-dummy slot opens to a listed member when trial-decrypted by that member's Desk (reported via the import record, `04` §12) and that no wrap exists for a user whose blinded COI tag is in the case's tag set (ADR-037 §3); and (4) for follow-ups, checks the ADR-036 §4 rule (recipients ⊆ original eligible set ∩ current members). Any unknown, extra or ineligible recipient raises a SECURITY alert, and the envelope is shown as "Recipient set could not be verified — do not accept". The Inbox shows "Encrypted to: {n} first readers" and their role labels.
- **Failed trial decryption is normal (ADR-047(3)).** The intake store holds chaff envelopes written at a constant rate in the same format as real envelopes, and real envelopes may be sealed to other Triage Set members. A pending envelope that none of this Desk's Member Epoch Keys opens is therefore **not** listed, counted, flagged or alerted on, and the Desk records nothing about it locally; it is not a sign of exclusion. Chaff never becomes a case: it is discarded at import (`04-CRYPTOGRAPHY.md` §12.7) and is excluded from every count and metric (`24-LICENSING-BUSINESS-MODEL.md` §TEL).
- **Actions** (row menu and keyboard):
  - **Open preview** (text answers at CL-1);
  - **Accept as case**: creates the case and, after the Triage Set's COI assessment (including manager-chain checks using HR data held outside Candor, ADR-037 §2), wraps the Case Key to the chosen investigators. The Desk computes blinded COI tags `HMAC(K_case_excl, user_id)` (ADR-037 §3) for source-ticked and COI-map exclusions, stores them padded to 8 tags, and refuses to wrap to any excluded user;
  - **Route to another channel**: requires reason; COI re-evaluated; re-wrap;
  - **Hold as spam/abuse**: ADR-026 triage queue; retention per `35-DATA-RETENTION-DELETION.md`;
  - **Reject unopenable**: shown only for envelopes the server marks `rejectable` in DA-20 (pending ≥ 14 days and reported unopenable by every Triage Set Desk; chaff is removed at import and never enters this queue), with dual approval per `15` DC-12 (ADR-038 §6);
  - **Assign**.
- **Not available:** source identity, IP, device, exact time, "similar reports", author or style matching, cross-report linking except where the *source* linked reports under the same passphrase (SOPS-041; REQ-H-08).
- **Empty state:** "No new reports. Reports are imported at fixed times each day. The last import was on {date}." (ADR-038 §1)
- **A11y:** a data grid with sortable column headers (`aria-sort`), row selection by keyboard (arrow keys, Space). Badges have text.

```
| Inbox — Audit Committee (first readers)                     [Filter v] [Sort v]  |
| Ref        Received    Mode  Category  Files Risk  COI SLA              Status   |
| C-7F3K-2Q  2026-09-30  ANON  Fraud     2     HIGH  ⊘   Ack by 10-07   New      |
| C-9QZ1-8M  2026-09-29  CONF  Conduct   0     -     -   Ack by 10-06   New      |
| [Open preview] [Accept as case] [Route…] [Hold as spam] [Assign…]               |
```

### R03 Case view
- **Header strip:**
  - case ref, mode badge, status;
  - SLA chips (Acknowledge, Feedback, Investigation), each with due date and state text;
  - COI indicator (§8);
  - risk panel toggle;
  - members count.
- **Tabs:** Overview · Conversation · Evidence · Tasks · Audit (case-lead only) · Export.
- **Overview:**
  - questionnaire answers rendered at CL-1 as plain text via text nodes (no HTML, no Markdown, no links; SI-17);
  - the source's "people kept out" roles (visible to Triage Set members and the case lead only; ADR-037 §3);
  - channel;
  - received date (import slot date at day granularity, or ISO week in the HIGH profile; ADR-038 §3);
  - source-visible status selector (the coarse set from 14; changing it shows "The source will see: In progress").
- **Risk panel** (`05` §8.7, INC-16, INC-10; visible to Triage Set and case lead, RVW-B-33 f):
  - "Few people know: 1–5";
  - "Files include photos or scans (printer dots or location possible)";
  - "Mode: ANONYMOUS";
  - guidance lines: "Avoid investigation steps that narrow the group to the source, such as asking IT who printed or opened a specific document. Paraphrase in findings."
- **Members panel:** list of members (name, role, grant expiry). Add/remove goes through AuthZ + COI (§8). Self-recusal is available.
  - **Removal** (DA-37) shows the member as "Suspended — key not yet deleted". **Delete key access** (DA-49) is a separate action: a case lead requests it, a different case lead or OVERSIGHT approves with step-up, and the request shows "Takes effect on {not_before_day} (7-day cooling-off); OVERSIGHT is informed". It is refused with "At least {min_recipients} people must keep access" when the `min_recipients` floor would be broken. No reason field is sent to the server (generic events).
  - **Records grant** (Triage Set members only; DA-36 `access_level=records`): grantee from the RECORDS_CUSTODIAN role, mandatory expiry per `14-CASE-MANAGEMENT.md` §8.7, shown in the list with its expiry day.
- **Self-identification in a message (CASE-037; RVW-B-15):** on any source message, "Contains the source's identity" seals the selected passage to the Identity Custodians (ADR-014), replaces it in the case copy with "[identity sealed]", excludes it from export templates, sets the source-visible "identity seen by case team" flag and changes the case mode label to CONFIDENTIAL. Confirmation: "This hides the passage from the case and tells the source that the team has seen their identity."
- **`RESTRICTED_OVERSIGHT` rendering (`14` §9.5):** such cases show the flag chip "Restricted oversight" (no names); in the OVERSIGHT register they appear with pseudonym and SLA status only, and opening their CASE events prompts for the DC-10 dual approval.
- **Intermediary mode (`14` CASE-039):** in channels with intermediary mode, non-triage investigators see a **Case Brief** tab (Triage-Set-written, paraphrased, encrypted) instead of the Overview answers, Conversation and Evidence; the tab states "Prepared by the first readers. The source's own words and files stay with them." Triage Set members have a "Write Case Brief" editor with the SI-10/SI-11 detectors and the E5 verbatim-quote check applied.
- **Not shown:** identity (sealed; see R11), IP, device data, exact times.

```
| C-7F3K-2Q  [ANONYMOUS]  In progress   Ack ✓ 10-02 | Feedback due 12-30 | ⊘ COI 1 |
| [Overview] [Conversation] [Evidence] [Tasks] [Audit] [Export]                     |
| What is this about?  Fraud                                                         |
| What happened?  "In March the ..."                                                |
| About how many people know? 1–5   ⚠ HIGH identification risk — see Risk panel      |
| Source-visible status: [In progress v]  (The source will see: "In progress")      |
```

### R04 Secure Conversation
- **Thread:**
  - messages with sender (source shown as "Source"; staff by display name), import slot date at day or ISO-week granularity (ADR-038 §3; follow-ups carry only their import slot date), and signature state (verified / failed);
  - source messages rendered at CL-1 as plain text via text nodes, with bidi and control characters visualised (SI-17);
  - attachments listed with containment badges (link to R05).
- **Composer:**
  - plain-text editor;
  - template picker (acknowledgment, request for clarification, feedback, closure) with localized templates;
  - "Preview as the source will see it" (shows the day date, team label and plain-text rendering);
  - Send: signs with the staff identity key, encrypts to the source key and the case key (04).
- **Reply interlocks:**
  - **SI-10 side-channel detector:** on Send, the draft is scanned for email addresses, phone numbers, URLs, messenger names (Signal, WhatsApp, Telegram, Teams, Slack), and phrases like "call me", "email me" or "meet". If any are found, a modal warns: "This message may invite the source to use another channel. Sources are told the team will never ask this (`05` GC-36). Continue only if policy allows and the source requested it." Choices: [Edit message] [Send anyway — reason required] (REQ-H-21; SOPS-033).
  - **SI-11 identity-probing reminder:** templates and a banner remind: "Ask only what you need to investigate. Don't ask questions whose main effect is to identify the source (role, shift, team) unless the source offered it." A soft lint flags phrases such as "what is your name", "which department", "your manager".
  - **SI-12 no timing promises:** a warning if the draft contains clock times or "within the hour" (the source sees replies only on login; ADR-010).
  - **SI-19 prompting-pattern warning (RVW-A-10 item 4):** if a member sends ≥ 3 replies in one case within 7 days without an intervening source message, or a reply whose main content is a request to "check in" or "reply soon", the Desk warns: "Frequent replies can prompt the source to sign in more often. Each visit can be used to identify them. Combine your questions into one message." [Edit] [Send anyway — reason required]. Overrides are CASE-audited.
- **Delayed reaction (RVW-C-02, RVW-C-11):** the composer and the source-visible status selector offer "Release later" (equal weight with "Send now"): the signed, encrypted reply or status change is held by C-10 and released on a random day 1–3 days later at the daily release time, so the source-visible effect of a staff action does not align with an import slot or a staff login. The HIGH-profile default is "Release later" for the first reply to a new report. The Guide (RO-17) explains that this does not hide the staff member's own login and activity times from their organisation.
- **No read receipts, typing indicators or "seen" states** in either direction (ADR-010).
- **A11y:**
  - Messages are `article` elements with headings.
  - The composer has a label and character count via `aria-describedby`, updated politely.
  - Send is `Ctrl/Cmd+Enter`.

### R05 Evidence panel
- For each evidence object, a card shows:
  - **Original:** type (by magic, determined in C-17), size, SHA-256 and BLAKE3 (truncated, with copy for verification), received day, "Immutable" state, and containment level.
  - **Derivatives:** the sanitized working copy and redacted versions, each with `derived_from`, the transformation record (tool and version, e.g., "pixels-to-PDF v…, OCR on") and a verification result.
  - **Metadata report** (generated in C-17 from the original, schema-validated and length-bounded by the Desk, `10` §5.3): author fields, GPS present y/n, device model, printer-dot detection result for scans, embedded files, and `external_refs` (hosts/URLs listed as inert plain text). All values are rendered as plain text only (SI-17). It carries a warning banner: "This report may contain information that identifies the source. Don't copy it into case notes or exports."
  - **Rendering label (ADR-042):** every sanitized copy shows "Rendering — not evidence. Verify details against the original before relying on them.", the converter release digest (short form, full on request), the output hash verification state, and, where run, the dual-render result (`10` §5.4; `DUAL_MISMATCH` pages listed).
- **Actions and their containment:**

| Action | Level | Availability |
|---|---|---|
| View sanitized copy | CL-2 | Default (primary button) |
| Open original in disposable viewer | CL-3 | Requires C-17. Confirm dialog (SI-02). Logged CASE event |
| Send original to air-gapped station | CL-4 | Requires C-18 enrollment. Produces an encrypted transfer bundle on removable media via Export-like flow (dual approval if policy) |
| Generate new derivative | runs in C-17 | Options: pixels-to-PDF (default), OCR on/off, greyscale + threshold (removes most printer dots; B-CR-54), crop margins |
| View metadata report | CL-1 text | Case-lead and investigator roles only (config) |
| Download / Open with system app / Save as | — | **Not available** (SI-01) |

```
| Evidence (2)                                                                     |
| file-01.pdf  PDF · 2.1 MB · received 2026-09-30 · ORIGINAL (immutable)           |
|   SHA-256 3f9a…c21e  BLAKE3 88d0…17aa                            [Copy hashes]   |
|   ┌ SANITIZED COPY · CL-2 SAFE VIEWER ┐  pixels-to-PDF, OCR · verified ✓         |
|   Rendering — not evidence · converter 3.2.0 (a91c…) · dual-render: match       |
|   [ View sanitized copy ]  [ Open original (disposable viewer, CL-3)… ]           |
|   [ Metadata report ⚠ ]   [ New derivative… ]  [ Redact… ]                      |
```

### R06 Viewer
- **Platform gating (ADR-042; `10` §6.1):** CL-2 and CL-3 are available only on Tier 1/Tier 2 hosts whose containment probe passed. In reduced mode the Desk shows "This computer has no isolated viewer. You can read text only." and offers the accessible text rendition of existing sanitized copies (CL-1) and the AIRGAP flow for originals.
- **CL-2 safe viewer:**
  - Displays **only raw, bounded RGBA frames** produced by a fresh L1 VM that rasterizes the stored sanitized derivative (PDF/A pages or PNG) inside C-17. The Desk host decodes no PNG, PDF or other image format (RVW-A-15 item 2; `10` FILE-003). The frame reader is the same fixed-header, fuzzed reader as the Stage 1→2 channel.
  - Zoom, page navigation, and search in the OCR text layer (produced inside the sandbox, ADR-042).
  - **Accessible text view** (RVW-C-16): a toggle "Text view" shows the accessible text rendition (OCR_TEXT object) as a navigable document with headings, lists, tables and page markers, rendered as plain text in native elements, fully usable with screen readers, magnifiers and speech input. Selection in the text view highlights the region on the page image and vice versa. The text view carries the same "Rendering — not evidence" label and an OCR-confidence note ("OCR may contain errors").
  - Text copy is subject to the clipboard policy (SI-06).
- **CL-3 disposable viewer:**
  - C-17 starts a fresh network-less hardware-isolated VM (Tier 1: microVM or DispVM; Tier 2 hosts do not open originals natively, `10` §6.1), and the original opens there.
  - The Desk shows the viewer window framed with a thick border and a persistent label: **"ORIGINAL · DISPOSABLE VIEWER · NO NETWORK · closes and is destroyed when you close this window"**.
  - Clipboard from the VM to the host is disabled by default.
  - On close, the VM is destroyed, and an audit event is recorded.
- Both viewers exclude themselves from screen capture where the OS allows (SI-07).

### R07 Redaction workspace
- **Input:** a sanitized derivative (never the original). Redaction produces a new derivative version.
- **Tools:**
  1. **Area redaction:** draw a box with the mouse, or use the keyboard: arrow keys move a cursor rectangle; `Shift+Arrows` resize; `Enter` confirms. A coordinates dialog is also available. This covers WCAG 2.5.7 (dragging alternative).
  2. **Text redaction:** select OCR text (keyboard selection supported) → "Redact selection".
  3. **Search & redact:** a term list or regex, with all matches listed, each toggleable.
  4. **Suggestions:** detectors for emails, phones, IBANs, national-ID patterns, employee-ID patterns (channel config), and names from a case-specific "protect list" (e.g., the source-sensitive terms a case lead adds).
- Each redaction carries a **reason code** (e.g., SOURCE-ID, THIRD-PARTY, LEGAL-PRIV, OTHER + text).
- **Apply:**
  - C-17 burns redactions into rasterized pages (removing the text layer in the redacted regions), rebuilds the OCR layer from the redacted pixels only, and outputs a new derivative.
  - The **verifier** runs text extraction, OCR of the raster, a hidden-layer and annotation scan, and an incremental-update scan (REQ-H-19). It must find **zero** occurrences of any redacted string.
  - A failed verification blocks use in exports and shows the failing page and region.
- **Optional four-eyes:** a second reviewer approves the redaction set (policy per channel; default ON for exports of CONF/IDENT cases).
- **A11y:**
  - Redaction boxes are listed in a table (page, region, reason, text if OCR), so screen-reader users can review and edit them without the canvas.
  - The canvas has a text alternative summary ("Page 3: 4 redactions").

### R08 Export Package workflow
An **Export Package** is the only way content leaves Desk (ADR-018). It is a wizard with 8 steps, and the step list is always visible.

| Step | Content | Rules |
|---|---|---|
| E1 Items | Pick messages, answers and evidence derivatives; originals only if the role allows | Originals flagged "requires dual approval" (ADR-012) |
| E2 Purpose & destination | Destination type: (a) encrypted file for named recipient key(s) (age/X-Wing, 04), (b) EE connector (C-40) target, (c) print. Legal basis / purpose code + free-text justification | Destination allow-list per channel; print allowed only if policy enables it |
| E3 Redaction review | Each item must have a verified redacted derivative or an explicit "no redaction needed" attestation per item, with reason | Blocks on any unverified redaction |
| E4 Format | Flattened PDF/A-2b or PNG pages (default). Native formats (DOCX, original PDFs) **blocked by default** (REQ-H-18); allowing them is a per-export DANGEROUS-class exception requiring dual approval | Metadata scrub of outputs (XMP, `/Info`) |
| E5 Source-protection checks | (i) **Verbatim quote check:** counts contiguous source-authored text > `N_VERBATIM` words (default 50) in export items and requires sign-off "paraphrase recommended" (INC-73; REQ-H-73); (ii) identity-hint scan over export text (same detectors as R07); (iii) risk-panel reminders ("Few people know: 1–5"); (iv) **beacon/canary warning for ORIGINAL items** flagged `EXTERNAL_REFS` or `ACTIVE_CONTENT` (RVW-A-25; `10` §15 E9–E10): modal "This original contains live links or active content ({n} external references listed). If it is opened on a computer with a network connection, it can notify its author, and that can identify the source. It will be exported inside an extra encrypted container with a no-network warning." — acknowledged by requester and each approver; (v) **candidate-set estimate** for exports whose destination is HR, remediation owners or IT, or whose purpose is an investigation step such as a log query (RVW-B-23 item 3): the requester records "About how many people could this step point to?"; if < 10, a second reviewer holding an independent role must approve | Warnings are acknowledged with reason; not silently bypassed |
| E6 Approvals | Required approvers (policy): originals → 2 approvers other than the requester, and in INDEPENDENT channels ≥ 1 approver with an independent role outside the legal/management chain (`10` FILE-046; ADR-045); CONF/IDENT cases → case lead; HIGH profile → dual approval for all exports | Approvers review a read-only preview in Desk |
| E7 Generate & verify | C-17 builds the package; the verifier checks for zero metadata canaries, zero redacted-string hits and the output hash manifest | Failure blocks |
| E8 Deliver & record | Encrypted file written through `candor-safefs` to a user-chosen location, or connector push, or print. CASE audit event with export ID, item hashes, approvers, destination (no content) | The package manifest includes the export ID, item hashes and `derived_from` chain; it contains no source passphrase-derived identifiers or internal key IDs |

**Warnings before export and print (SI-03, SI-04)** are modal and name the concrete risks:
- **Export:** "Exported files leave Candor's protection. Anyone who gets this file can read it. Verify the recipient. Never send exports to AI tools, cloud drives or chat."
- **Print:**
  - "Printers and print servers keep logs, and paper copies can be photographed and scanned."
  - "Printed pages may carry tracking dots that identify your printer."
  - "Collect printouts immediately. Store and destroy them under your records policy."
  - Print uses the flattened package only, adds a visible footer "Export {id} · Confidential", and is logged.

### R09 Tasks & SLA dashboard
- **Views:** "My deadlines", "Team deadlines", and "Paused clocks".
- **Columns:** case ref, clock (Acknowledge / Feedback / Investigation / Custom), due date, state (text: "Due in 2 days", "Overdue by 3 days", "Paused: awaiting source"), and basis (calendar / business days; jurisdiction pack).
- **Actions:** complete milestone (e.g., "Feedback given", which opens the Conversation composer with the feedback template), pause with a mandatory justification, extend (where law allows, e.g., external channel 3 → 6 months) with a reason.
- **Colors plus text plus icons.** Overdue rows use a bold "OVERDUE" label and a stripe pattern.
- **Aggregates** (counts by state) are shown to team leads only. Any aggregate shown outside the case team follows `24-LICENSING-BUSINESS-MODEL.md` §TEL (k = 10, ≥ one calendar month, complementary suppression, no medians/ratios for cells < k; ADR-046 §5) (THR-039; INC-74).

### R10 Notifications center
- **In-app** (visible only after unlock): new report in channel (Triage Set members only, ADR-037 §2), source replied, SLA approaching or overdue, approval requested (export, unseal, break-glass), key-directory alert (including time-locked roster changes pending, ADR-036 §2), update available, posture and custody warnings. Each links to the item.
- **OS notifications** (optional, default OFF): the fixed text "Candor: action requires attention". No case ref, count, channel or time (ADR-017). Lock-screen previews are disabled.
- **External notifications** (email/Matrix/Teams via C-23; ADR-038 §2): either **off** (the HIGH-profile default; the Desk badge is the only signal) or a **constant-schedule daily digest** sent at a fixed local time every day to each subscribed member, whether or not anything is pending, with identical content ("Candor: please check Candor Desk · {instance label}"). No event-driven or hourly notification exists. The UI shows the exact content and the fixed send time.

### R11 Identity unseal request (CONFIDENTIAL/IDENTIFIED cases; ADR-014)
- **Request form:**
  - legal basis (select from the jurisdiction pack + free text);
  - necessity justification;
  - scope (full identity / contact method only);
  - duration (default 24 h view window);
  - source notification: "Notify source" (default where law requires, EU Art 16(3)), or "Defer notice" with reason and review date.
- **Approvals:** 2 Identity Custodians, not including the requester.
- **Display after approval:**
  - Separate window, labelled "SEALED IDENTITY".
  - Content is excluded from screen capture and auto-hides after 5 min (re-open is logged).
  - Copy is disabled.
  - Never rendered in the case view, exports or search.
- Every view is a SECURITY-class audit event.

### R12 Break-glass (ADR-015)
- **Form:** reason category, justification, requested scope and duration (max 8 h).
- **Approval:** requires dual authorization per `15-AUTHENTICATION-AUTHORIZATION.md`, including **one approver from an independent role outside the legal/management chain** (ADR-045; RVW-C-10). The request form shows the eligible independent approvers; a request without one cannot be submitted.
- **Key donor view (RVW-C-10 item 2):** a member asked to wrap the case key to the break-glass requester is shown the full approval set and may refuse; a refusal is recorded as a CASE event visible to OVERSIGHT.
- **During use:** the UI shows a persistent red-and-striped banner "BREAK-GLASS ACCESS — under independent review" with the time remaining.
- **Post-hoc review:** a task is created for the independent reviewer (ombudsperson or audit committee).
- **COI:** source-flagged COI exclusions cannot be bypassed via the ordinary member-add path. Break-glass is the only route, and it is flagged "COI OVERRIDE" in review.

### R13 Settings & Guide
- **Personal settings:** language, density, theme (system / light / dark / high contrast), keyboard shortcuts (remap, disable single-key), reduced motion, OS notifications on/off.
- **Policy-locked settings** (shown read-only with the policy source): idle lock, clipboard policy, print availability, screen-capture exclusion.
- **Guide:** the recipient OPSEC guidance (§12), available offline in the app bundle.

### R14 Case audit (case lead)
- A chronological list of CASE events for this case: opened, viewed evidence (level), exported, redacted, member changes, status changes, unseal and break-glass references. Staff actions have exact times (ADR-010, ADR-046 §11 allow exact times for staff actions); import events carry the import slot date only (ADR-038 §1). Member-removal events use the generic reason `REMOVED`, never distinguishing COI (ADR-037 §3).
- Read-only. Hash-chain verification status comes from C-24.

### R15 Records search (ADR-044 §5; RVW-C-14)
- **Where:** in the Desk of an authorized member, over a **local encrypted index** of cases that member can decrypt. There is no server-side global search.
- **Records Custodian:** a RECORDS_CUSTODIAN user receives explicit, audited, time-bounded case grants (case-key wraps with an expiry) from the Triage Set; the Desk then indexes and searches only those cases.
- **Query form:** terms and/or person names, date range (import slot dates), legal basis (FOIA/ATIP, DSAR, eDiscovery hold, breach scoping) and reference. Results list case refs and matching item types with hit counts; opening a hit follows normal CL rules.
- **Excluded:** Sealed Identity Store content (never indexed), source passphrase-derived data, and cases the user cannot decrypt.
- **Output:** a signed, content-free hit/no-hit attestation per searched case for the records file; exporting content goes through R08.
- **Audit:** each query is a CASE event (query hash, legal-basis code, case count; no terms in cleartext).

## 6. Containment level indicators

| Level | Label (text shown) | Meaning | Visual (not color-only) |
|---|---|---|---|
| CL-0 | SEALED | Ciphertext only. Not decrypted on this device | Lock glyph + grey dotted border |
| CL-1 | TEXT · SAFE RENDER | Plain text (answers, messages) rendered by Desk as text only; no parsing beyond UTF-8 validation | "T" glyph + thin solid border |
| CL-2 | SANITIZED COPY · SAFE VIEWER · RENDERING — NOT EVIDENCE | Derivative from C-17 (pixels→PDF/PNG with OCR text layer), displayed only as raw bounded frames rasterized inside C-17; accessible text view available | Shield glyph + double border |
| CL-3 | ORIGINAL · DISPOSABLE VIEWER | Original opened inside a network-less disposable VM; destroyed on close | Hazard glyph + thick striped border + persistent window label |
| CL-4 | ORIGINAL · AIR-GAPPED STATION | Original transferred to C-18 | Air-gap glyph + thick double border |
| CL-X | BLOCKED | Action unavailable (e.g., C-17 not ready, policy) with the reason | Crossed glyph + text reason |

- Every evidence card, viewer frame, export item and audit event shows the level label.
- The label is part of the accessible name (e.g., "file-01.pdf, SANITIZED COPY, safe viewer").

## 7. Safety interlocks

| ID | Interlock | Behavior |
|---|---|---|
| SI-01 | No open-original outside viewer | Desk offers no "Open with", "Save as", "Download", "Reveal in folder", drag-out or OS share for originals or derivatives. Decrypted bytes are never written to the host filesystem outside `candor-safefs`-managed, memory-backed storage (ADR-027). |
| SI-02 | CL-3 confirmation | Opening an original shows: "You are opening the original file. It may contain malware or hidden data that identifies the source. It will open in a disposable viewer with no network." Buttons: [Open original] [View sanitized copy instead]. |
| SI-03 | Export warning | §R08 E2/E8 modal. There is no "don't show again". |
| SI-04 | Print warning | §R08. Print only via the Export Package. Policy may disable print entirely (default: disabled in HIGH profile). |
| SI-05 | No remote fetch | URLs in content are rendered as inert text. "Copy link" requires confirmation: "Visiting links from reports can reveal you and the case. Use an isolated browser." Nothing in Desk ever fetches a URL from content (INC-65). |
| SI-06 | Clipboard policy | Policy `blocked` / `warn` (default) / `allowed`. With `warn`, the first copy per session shows "Copied text leaves Candor's protection". The Desk clears its clipboard contents 60 s after copy or on lock. The VM-to-host clipboard is off in CL-3. |
| SI-07 | Screen-capture exclusion | Default ON: Windows `WDA_EXCLUDEFROMCAPTURE`, macOS `sharingType = .none`. On Linux (not generally supported) the UI shows "Screen capture cannot be blocked on this system". |
| SI-08 | OS trace avoidance | No OS recent-documents registration, jump lists, thumbnails, Spotlight/Windows Search indexing of Desk data directories (exclusion set at install), and no window titles with case data. |
| SI-09 | Idle lock | `DESK_IDLE_LOCK` (§4.1). |
| SI-10 | Side-channel detector | §R04. |
| SI-11 | Identity-probing reminder | §R04. |
| SI-12 | Timing-promise warning | §R04. |
| SI-13 | Identity isolation | Identity is shown only in R11 windows. It never appears in search, exports or notifications. |
| SI-14 | Unverified content | A message or envelope that fails a signature or AEAD check is shown as "Could not be verified — do not rely on this content", with no partial plaintext (REQ-H-65). |
| SI-15 | Malicious-server resilience | All server-supplied names and metadata are treated as untrusted display strings. They never become paths or commands (ADR-027). |
| SI-16 | No AI/cloud integrations | Desk has no built-in AI assistant, translation service, cloud spell-check or cloud storage integration. OS text services are disabled on content fields where possible. |
| SI-17 | Hostile-string rendering (ADR-042; RVW-A-15) | Every string that originates from a source, a C-17 VM or the server (answers, messages, filenames, metadata report, OCR text, `external_refs`, role labels) is rendered **as plain text via text nodes only**: no `innerHTML` or other HTML sinks, no Markdown, no auto-linking. Unicode bidi controls and C0/C1/format characters are visualised as visible escape glyphs (e.g., `⟨U+202E⟩`). The webview runs with CSP `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src ipc: http://ipc.localhost; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; require-trusted-types-for 'script'; trusted-types candor-desk`, the Tauri isolation pattern, and a per-window capability allow-list (viewer windows hold no decrypt/export capabilities). |
| SI-18 | Crash and sync hygiene (RVW-C-11) | §4.1 crash-handling and export-destination rules. |
| SI-19 | Prompting-pattern warning | §R04. |

## 8. Conflict-of-interest indicators (ADR-015, ADR-037)

- **Storage model (ADR-037 §3):** COI exclusions exist on the server only as blinded tags `HMAC(K_case_excl, user_id)`, `K_case_excl = HKDF(case_key, "candor/coi-excl/v1")`, padded to 8 tags per case. The server checks tag membership blindly. Audit reason codes never distinguish COI removals from other removals, and no event, table or export associates a user identity with a COI exclusion for a specific case.
- **Case header chip:** "⊘ COI exclusions applied" (no count). The details popover, **visible to Triage Set members and the case lead only**, lists: source-flagged roles, matched COI map entries, self-recusals, and overrides (break-glass only). Other members see no chip.
- **Sync check:** on every case sync, each member Desk verifies that no case-key wrap exists for a user whose tag is in the case's tag set; a violation raises a SECURITY alert and blocks the case view for that member until OVERSIGHT reviews.
- **Member add:** the adding member's Desk computes the candidate's tag. If excluded, the picker shows "This person cannot be added to this case" (to the case lead and Triage Set: "Excluded by conflict-of-interest rule"). The attempt is logged with a generic reason code.
- **Routing:** the route dialog shows "COI will be re-evaluated for the new channel; excluded users will not receive keys".
- **Self-recusal:** "I have a conflict of interest" → confirm → Desk destroys the user's own case-key wrapping (04), removes membership, and notifies the case lead. The audit event uses the generic reason `REMOVED`. It is irreversible without re-grant by the case lead after COI review.
- **The user's own exclusion is invisible** to them: excluded users never receive keys or case listings, and non-triage members see no intake envelopes or counts (ADR-015, ADR-037 §2). There is no indicator for them, by design.

## 9. Keyboard

| Action | Default shortcut | Notes |
|---|---|---|
| Command palette | Ctrl/Cmd+K | Every command is searchable |
| Go to Inbox / My cases / Tasks | Ctrl/Cmd+1 / 2 / 3 | |
| Cycle regions | F6 / Shift+F6 | |
| Next / previous item in list | ↓ / ↑ | Within focused grid |
| Open item | Enter | |
| Send message | Ctrl/Cmd+Enter | |
| Lock now | Ctrl/Cmd+L | |
| Close dialog / viewer | Esc | Viewer close asks for confirmation for CL-3 |
| Shortcut help | Ctrl/Cmd+/ | |
| Single-key shortcuts (j/k, g i) | **Off by default** | Can be enabled or remapped (WCAG 2.1.4) |

All functionality is operable by keyboard (WCAG 2.1.1). There are no keyboard traps, including in viewers: `Esc` or `Ctrl/Cmd+W` always exits. Focus order follows the visual order. Focus returns to the invoking control after dialogs close.

## 10. Accessibility (summary; full target in `26-ACCESSIBILITY.md`)

- Conformance: WCAG 2.2 AA, applied to the Tauri webview UI. EN 301 549 v4.1.1 clause 11 (software) and Section 508 Chapter 5 (502 interoperability with AT, 503 applications).
- Semantics: native elements; ARIA grid only where a data grid is needed; live regions (`polite`) for status bar changes, sync completion and send confirmations; `assertive` only for lock-imminent and verification failures.
- Visual: text contrast 4.5:1, non-text 3:1; high-contrast theme; honours OS forced colors and reduced motion (no animations beyond 150 ms opacity fades, none under reduced motion); app zoom 50–300 %; layout reflows to a single column at 400 % of a 1280 px window.
- Redaction and viewers offer non-pointer alternatives (R07). Hash values offer "copy" plus a spoken, grouped format.
- Tested with NVDA and JAWS (Windows, WebView2), VoiceOver (macOS, WKWebView) and Orca (Linux, WebKitGTK) per `26-ACCESSIBILITY.md` matrix. Known risk: WebKitGTK/Orca maturity (§14).

## 11. Notifications and timing behavior

- No per-report push notification. External notifications are content-free and constant-schedule (one fixed-time daily digest whether or not anything is pending), or off (ADR-017 as amended by ADR-038 §2). Imports happen at fixed slots (ADR-038 §1), so staff reactions to an import reveal only the slot, not the submission time.
- In-app counts are visible only after unlock.
- The Desk never tells the source when staff read messages. Replies become visible to the source only when the source logs in (ADR-010).

## 12. Recipient OPSEC guidance (in-app Guide; summary, normative)

| ID | Guidance (EN master, `rui.guide.*`) | Evidence |
|---|---|---|
| RO-01 | Use Candor Desk only on your designated workstation. Don't install it on personal or shared devices. | ADR-007; B-SD-05 |
| RO-02 | Open files only in the Candor viewer. Never save, forward or open originals in other apps. | ADR-012; INC-16 |
| RO-03 | Don't photograph your screen or take screenshots of case content. | INC-16; THR-041 |
| RO-04 | Never paste report content into AI tools, translators, cloud documents, corporate email, chat or ticketing systems. Use Export Packages when content must move. | ADR-018; INC-56; THR-029 |
| RO-05 | Avoid printing. If policy allows it, print only from an Export Package, collect pages immediately, and destroy them per policy. | B-AN-41; INC-16 |
| RO-06 | When checking facts with others, including the organization concerned, never share originals or images of them. Share paraphrased, redacted summaries. In a real case, sharing a copy of a leaked document to verify it helped identify the source. | INC-16 (REQ-H-16) |
| RO-07 | Don't try to find out who the source is, and don't ask questions whose main effect is to identify them. Treat "few people know" as a warning. Avoid steps like asking IT who opened or printed a document. | INC-22; REQ-H-22; THR-019 |
| RO-08 | Keep the conversation in Candor. Never invite the source to email, phone or chat. | REQ-H-21; INC-24 |
| RO-09 | Paraphrase source wording in findings and publications. Long verbatim quotes can identify the writer's style. | INC-73; REQ-H-73 |
| RO-10 | Protect your hardware key and PIN. Report loss or suspected compromise immediately to your security officer. | ADR-007; THR-022 |
| RO-11 | Lock Candor when you step away. Work where others can't see your screen. | THR-041 |
| RO-12 | If you have a conflict of interest, recuse yourself using "I have a conflict of interest". | ADR-015; INC-22 |
| RO-13 | Be suspicious of messages asking you to install Candor updates or tools from links. Updates come only through Candor's verified update process. | INC-38; INC-52; ADR-022 |
| RO-14 | Notifications never contain case details. Don't forward them, or add details to them. | ADR-017; INC-57 |
| RO-15 | Don't open links found in reports on your normal browser or network. Use an isolated environment agreed with your security team. | INC-65; SI-05 |
| RO-16 | If you are a first reader for an independent channel, use only a device that your organization does not manage (no company MDM, EDR, DLP or remote desktop). An organization that controls your computer can read what you read. | ADR-043; RVW-C-01; RVW-A-24 |
| RO-17 | Don't react to reports in ways others can time: avoid logging in, messaging colleagues or changing calendars right after an import. Work on reports in your usual routine. | ADR-038; RVW-C-02; RVW-B-31 |
| RO-18 | Don't send many short replies to prompt the source to check in. Each visit can put the source at risk. | RVW-A-10 |
| RO-19 | Sanitized copies are renderings, not evidence. Check important details against the original in the disposable viewer before relying on them. | ADR-042; RVW-A-30 |

## 13. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| RUI-001 | The recipient UI SHALL be delivered only as the signed Candor Desk application. No server component SHALL serve a browser-based recipient UI. | ADR-007; INC-01 | THR-007, THR-014 | C-15, C-06, C-10 | INSP: route registry has no recipient web routes; ST: scan of Z-CORE/Z-INTAKE endpoints |
| RUI-002 | The Desk UI bundle SHALL load no remote code, fonts, images, styles or help content. Its webview SHALL use the SI-17 CSP (connections only to the Tauri IPC channel; Trusted Types enforced), the Tauri isolation pattern and per-window capability allow-lists (amended, ADR-042). | REQ-H-46 (INC-46); ADR-019; ADR-042; RVW-A-15 | THR-036, THR-008, THR-023 | C-15 | TST: network sandbox run of the UI test suite; INSP: CSP config; TST: viewer window invoking decrypt/export IPC → denied |
| RUI-003 | Unlock SHALL use a hardware-bound key per ADR-007. The software fallback SHALL display a persistent "Weaker protection" badge. | ADR-007; B-SD-13 (SEC-01-010) | THR-022, THR-013 | C-15, C-21 | TST: unlock matrix; DEMO |
| RUI-004 | The Desk SHALL run the §4.1 posture checks at unlock and SHALL block on key-directory split view, disabled disk encryption (policy) or Desk version older than the security-fix window. | INC-67; ADR-022 | THR-046, THR-025, THR-031 | C-15, C-14 | TST: posture fixtures for each check |
| RUI-005 | The Desk SHALL auto-lock after `DESK_IDLE_LOCK` (default 10 min), on OS lock or sleep, and on smartcard removal, and SHALL clear decrypted content from the UI on lock. | THR-041; INC-16 | THR-041, THR-031 | C-15 | TST: lock triggers; DOM inspection after lock contains no canary |
| RUI-006 | Window titles, OS notifications and task-switcher labels SHALL NOT contain case references or content. | ADR-017; INC-57 | THR-028, THR-041 | C-15 | TST: title assertion across screens |
| RUI-007 | The Inbox SHALL show only the §R02 columns, with the import slot date at day granularity (ISO week in HIGH), and SHALL NOT show source IP, device data, exact times or identity (amended, ADR-038 §3). | ADR-010; REQ-H-09 (INC-09) | THR-011, THR-019 | C-15, C-10 | TST: API contract test (08) + UI snapshot |
| RUI-008 | The Desk SHALL NOT provide authorship attribution, stylometric similarity, "similar reports" or metadata-based cross-report linking. Only source-created linkage (same passphrase) SHALL be shown. | REQ-H-08; INC-73; `05` SOPS-041 | THR-010, THR-019 | C-15, C-10 | INSP: feature review per release |
| RUI-009 | Accepting or routing a report SHALL be performed by a Triage Set member, SHALL apply COI exclusions (stored as blinded tags, ADR-037 §3) before wrapping the case key, and excluded users SHALL never receive keys or listings (amended, ADR-037). | ADR-015; ADR-037; INC-22; RVW-B-01; RVW-B-02 | THR-020 | C-15, C-22, C-11 | TST: integration test: excluded user's device has no wrapping; listing API returns 404 |
| RUI-010 | The case header SHALL show the COI indicator (§8), SLA chips, mode badge and status. COI details SHALL be visible only to Triage Set members and the case lead (amended, ADR-037). | ADR-015 | THR-020, THR-040 | C-15 | TST: role-based render tests |
| RUI-011 | Member additions SHALL be checked against COI and AuthZ. Excluded users SHALL be shown as disabled with a reason. Source-flagged exclusions SHALL be overridable only via break-glass (R12). | ADR-015 | THR-020, THR-021 | C-15, C-22 | TST: negative tests; ST: API bypass attempt |
| RUI-012 | A self-recusal action SHALL destroy the user's own case-key wrapping, remove membership and notify the case lead. | ADR-015; ADR-025 | THR-020 | C-15, C-11 | TST: post-recusal decrypt attempt fails |
| RUI-013 | The case view SHALL display, to Triage Set members and the case lead only, a risk panel including the source's "how many people know" answer and file-class warnings, with investigation-narrowing guidance (amended, RVW-B-33 f). | `05` §8.7; INC-16; INC-10 | THR-019, THR-010 | C-15 | TST; INSP copy |
| RUI-014 | Source identity (CONF/IDENT) SHALL be displayed only in R11 after dual custodian approval, in a capture-excluded window that auto-hides after 5 min, with copy disabled. It SHALL never appear in the case view, search, exports or notifications. | ADR-014; B-CO-02 (Art 16) | THR-018, THR-019 | C-15, C-22 | TST: search index lacks identity canary; export scan; ST: API authZ tests |
| RUI-015 | Unseal requests SHALL capture legal basis, justification, scope, duration and source-notice decision (notify or defer with reason and review date), and SHALL require 2 custodians excluding the requester. | ADR-014; R6 WB-09 | THR-018 | C-15, C-22, C-24 | TST: workflow tests; AUD: audit trail review |
| RUI-016 | Every evidence item, viewer and export item SHALL display its containment level (§6) as text in its accessible name and visually, not by color alone. | ADR-012; WCAG 1.4.1 | THR-023, THR-041 | C-15, C-17 | TST: a11y tree check; visual regression |
| RUI-017 | The default evidence action SHALL be the CL-2 sanitized copy. Opening an original SHALL require the SI-02 confirmation and SHALL occur only in C-17 (CL-3) or C-18 (CL-4). | ADR-012; REQ-H-16; R5 §D.3 | THR-023, THR-009 | C-15, C-17 | TST: no code path renders original bytes in the Desk process (IPC audit); DEMO |
| RUI-018 | The Desk SHALL offer no download, save-as, open-with, reveal-in-folder, drag-out or OS share for evidence, and SHALL NOT write decrypted evidence to host storage outside `candor-safefs` memory-backed areas. | ADR-027; ADR-018; B-SD-33..35 | THR-041, THR-029 | C-15 | TST: filesystem watcher during e2e (no plaintext canary on disk); INSP |
| RUI-019 | The CL-3 viewer SHALL be network-less, SHALL disable VM-to-host clipboard by default, SHALL show the persistent ORIGINAL label, and SHALL be destroyed on close with a CASE audit event. | ADR-012; B-SD-05; B-CR-44 | THR-023 | C-17, C-15 | TST: VM network namespace test; clipboard test; audit event check |
| RUI-020 | The CL-2 viewer SHALL display only raw, bounded RGBA frames rasterized inside C-17 from a stored derivative whose output hash matches its transformation record; the Desk host SHALL NOT decode PNG, PDF or any image format (amended, ADR-012, RVW-A-15 item 2). | INC-65; B-CR-56; RVW-A-15 | THR-023 | C-15, C-17 | TST: `desk-no-parser` dependency check; ST: hostile-frame fuzzing; TST: hash mismatch rejected |
| RUI-021 | The metadata report SHALL be generated only in C-17, shown only to configured roles, carry a source-identification warning, and SHALL be excluded from exports unless explicitly selected with approval. | INC-17; INC-20 | THR-009, THR-019 | C-15, C-17 | TST: role gating; export exclusion test |
| RUI-022 | Redaction SHALL operate on derivatives, SHALL burn redactions into the raster and rebuild text layers from redacted pixels, and SHALL be verified (text extraction, OCR, hidden-layer, incremental-update scans) with zero hits before use in any export. | REQ-H-19 (INC-19); B-CR-44 | THR-019, THR-029 | C-15, C-17 | TST: canary-string redaction corpus incl. overlay/annotation/form-field failure patterns |
| RUI-023 | The redaction workspace SHALL provide keyboard and coordinate-based alternatives to dragging, and a tabular list of redactions editable without the canvas. | WCAG 2.5.7, 2.1.1; B-CO-28 | — | C-15 | TST: keyboard-only e2e; DEMO: SR user test |
| RUI-024 | Content SHALL leave Desk only via the §R08 Export Package workflow. The wizard SHALL enforce steps E1–E8. | ADR-018; REQ-H-24 (INC-24) | THR-029, THR-041 | C-15, C-40 | TST: attempt export via each alternate path fails; e2e wizard tests |
| RUI-025 | Exports including originals SHALL require dual approval per `15-AUTHENTICATION-AUTHORIZATION.md` DC-01 (2 distinct eligible case members, neither COI-excluded, each with transaction-confirmation step-up). The requester SHALL NOT count as an approver. Policy SHALL be able to require dual approval for all exports (default ON in HIGH profile). | ADR-012; REQ-H-16 | THR-019, THR-029 | C-15, C-22 | TST: approval-gate tests; ST: API bypass |
| RUI-026 | Native formats SHALL be blocked from export by default. Outputs SHALL be flattened PDF/A-2b or PNG with XMP and `/Info` removed, and verified free of metadata canaries. | REQ-H-18 (INC-18) | THR-009, THR-029 | C-15, C-17 | TST: DOCX with tracked changes/comments/author canaries → export output has 0 canaries (exiftool, pdfinfo, qpdf --qdf, text grep) |
| RUI-027 | The export wizard SHALL run the verbatim-quote check (`N_VERBATIM` default 50 words) and the identity-hint scan, and SHALL require acknowledgement with reason for each warning. | INC-73 (REQ-H-73) | THR-010 | C-15 | TST: fixture with 60-word quote triggers sign-off |
| RUI-028 | Export and print SHALL be preceded by the SI-03/SI-04 warnings, with no "don't show again". Print SHALL be available only from an Export Package and only if policy allows. | REQ-H-16; B-AN-41 | THR-041 | C-15 | TST: UI tests; policy tests |
| RUI-029 | Every export SHALL create a CASE audit event with export ID, item hashes, approvers and destination, and SHALL NOT include content in the audit record. | ADR-016; ADR-018 | THR-037, THR-038 | C-15, C-24 | TST: audit schema validation |
| RUI-030 | Export package manifests SHALL include the item hashes and `derived_from` chain and SHALL NOT include source-derived identifiers, key IDs or internal hostnames. | ADR-012; REQ-H-11 | THR-037, THR-016 | C-15 | TST: manifest schema allow-list |
| RUI-031 | Messages to sources SHALL be signed by the staff identity key and encrypted to the source key and case key. The UI SHALL provide a "Preview as the source will see it". | ADR-005; INC-62 | THR-046, THR-012 | C-15, C-11 | TST: signature verification by Source App test harness |
| RUI-032 | The composer SHALL run the SI-10 side-channel detector and SI-11/SI-12 lints on Send, requiring edit or reasoned override. Overrides SHALL be CASE-audited. | REQ-H-21 (INC-21); `05` SOPS-033 | THR-019, THR-028 | C-15 | TST: detector fixtures (email, phone, URL, messenger names in 10 locales) |
| RUI-033 | The Desk SHALL NOT display or emit read receipts, typing indicators or presence, and SHALL show source message dates as import slot dates at day granularity (ISO week in HIGH) (amended, ADR-038 §3). | ADR-010 | THR-011 | C-15 | TST; INSP |
| RUI-034 | Content failing signature or AEAD verification SHALL be displayed only as an error state, with no partial plaintext. | REQ-H-65 (INC-65); REQ-H-66 | THR-012, THR-007 | C-15, C-11 | TST: tampered-ciphertext fixtures |
| RUI-035 | Server-supplied names and metadata SHALL be treated as untrusted display strings and never used as paths, commands or HTML. | ADR-027; B-SD-33..36 | THR-007, THR-023 | C-15 | TST: malicious-server harness (path traversal, HTML injection, oversized fields) |
| RUI-036 | URLs in content SHALL be rendered inert. The Desk SHALL never fetch any URL derived from content. "Copy link" SHALL require confirmation. | INC-65; SI-05 | THR-008, THR-023 | C-15 | TST: network sandbox with URL-laden fixtures |
| RUI-037 | The clipboard policy (`blocked`/`warn`/`allowed`, default `warn`) SHALL be enforced, and the Desk SHALL clear its copied content after 60 s or on lock. | THR-041; INC-16 | THR-041, THR-029 | C-15 | TST: clipboard tests per OS |
| RUI-038 | The Desk SHALL request OS screen-capture exclusion for all content windows where supported (default ON), and SHALL display a notice where unsupported. | THR-041; managed-endpoint screen recording (R4 §1 adversary A); INC-16 | THR-041 | C-15 | TST: capture API test on Windows and macOS |
| RUI-039 | The Desk SHALL avoid OS traces: no recent-documents, jump lists or thumbnails, and data directories excluded from OS indexing at install. | REQ-H-23 analogue for recipients; THR-031; INC-23 | THR-031, THR-041 | C-15, C-16 | TST: forensic diff of recipient workstation after e2e |
| RUI-040 | The Desk SHALL contain no AI assistant, cloud translation, cloud spell-check or cloud-storage integration, and SHALL disable OS cloud text services on content fields where possible. | INC-13; INC-53; SI-16 | THR-029, THR-036 | C-15 | INSP: dependency and feature review; TST: network sandbox |
| RUI-041 | OS notifications SHALL be off by default and, when on, SHALL use only the fixed text "Candor: action requires attention", with no counts or references. | ADR-017; INC-57 | THR-028 | C-15, C-23 | TST |
| RUI-042 | The SLA dashboard SHALL show clocks with due dates, state text and basis (calendar/business), SHALL require justification for pause or extension, and aggregates shown outside the case team SHALL follow the single metrics regime of `24-LICENSING-BUSINESS-MODEL.md` §TEL (k = 10, ≥ monthly period, complementary suppression, no medians/ratios for cells < k; ADR-046 §5) (amended). | R6 §0 (SLA); B-CO-02; INC-74; ADR-046 §5; RVW-B-07; RVW-B-08 | THR-039 | C-15, C-10 | TST: SLA fixtures; suppression test |
| RUI-043 | Changing the source-visible status SHALL display the exact text the source will see before saving. | ADR-002; `11-FRONTEND-SOURCE.md` SUI-054 | THR-019 | C-15 | TST |
| RUI-044 | Break-glass sessions SHALL display a persistent banner with the time remaining, SHALL be limited to ≤ 8 h, and SHALL create an independent-review task. | ADR-015; INC-68 | THR-018, THR-019 | C-15, C-22, C-24 | TST; AUD |
| RUI-045 | The case audit view SHALL show CASE events with hash-chain verification status from C-24 and SHALL be read-only. | ADR-016 | THR-037 | C-15, C-24 | TST: tampered chain → UI shows failure |
| RUI-046 | All Desk functionality SHALL be keyboard-operable, with the §9 defaults. Single-key shortcuts SHALL be off by default and remappable. | WCAG 2.1.1, 2.1.2, 2.1.4; B-CO-28 | — | C-15 | TST: keyboard-only e2e; DEMO |
| RUI-047 | The Desk SHALL meet WCAG 2.2 AA, EN 301 549 v4.1.1 clause 11 and Section 508 Chapter 5 as specified in `26-ACCESSIBILITY.md`, verified with NVDA, JAWS, VoiceOver and Orca. | B-CO-28, B-CO-32, B-CO-34 | — | C-15 | TST: automated a11y; DEMO: AT matrix; AUD: third-party ACR (EE) |
| RUI-048 | The in-app Guide SHALL include RO-01..RO-19, bundled offline, and SHALL be shown at first unlock and after each change to RO text. | REQ-H-16; INC-16 | THR-041 | C-15 | INSP; TST: first-run flow |
| RUI-049 | The status bar SHALL show sync, key-directory consistency, C-17 availability, device posture and update state, announced via a polite live region on change. | RP-8; INC-67 | THR-046, THR-025 | C-15 | TST |
| RUI-050 | Evidence cards SHALL show original hashes (SHA-256, BLAKE3), immutability state and the derivative transformation records. | ADR-012; R6 WB-11 | THR-037 | C-15 | TST: hash matches import record |
| RUI-051 | The "Generate new derivative" action SHALL offer greyscale + threshold and margin-crop options for scans, labelled as reducing printer-dot and handling-mark exposure. | REQ-H-16; B-CR-54 | THR-010 | C-15, C-17 | TST: DEDA-style detector on output finds no pattern (fixture) |
| RUI-052 | Inbox triage actions SHALL include Accept, Route (with reason), Hold as spam/abuse, and Assign, each producing a CASE audit event. | ADR-026; ADR-016 | THR-033 | C-15, C-10 | TST |
| RUI-053 | Unsent reply text SHALL survive auto-lock in memory under the session key and be restored after unlock. | WCAG 2.2.5 (adopted); COGA; B-CO-28; B-CO-36 | — | C-15 | TST |
| RUI-054 | The Desk SHALL NOT expose any function that returns source metadata beyond the §R02/§R03 fields, including in debug or support modes, and support bundles SHALL be scrubbed of content and tokens. | REQ-H-26, REQ-H-56 (INC-56) | THR-027, THR-016 | C-15, C-36 | TST: support bundle canary scrub test |
| RUI-055 | On import, the Desk SHALL NOT read recipient key IDs from any cleartext header; it SHALL verify the recipient set by trial decryption of the anonymous slots and by checking the source-signed recipient list inside the decrypted manifest against the eligible Triage Set in C-14 (inclusion and consistency proofs, snapshot high-water mark), the blinded COI tags and, for follow-ups, the ADR-036 §4 rule; it SHALL treat any unexplained recipient as a SECURITY alert and block acceptance (amended, ADR-046 §10, ADR-033 §1). | ADR-030; ADR-033 §1; ADR-036 §4, §6; ADR-046 §10; INC-14; INC-62; ASM-111; RVW-B-30; RVW-C-08 | THR-046 | C-15, C-14 | TST: malicious-server harness inserts an extra recipient slot → alert + block |
| RUI-056 | Attachment viewing (CL-2, CL-3) SHALL be disabled until the C-17 containment probe (ASM-117) passes at Desk start and daily. The status bar SHALL show the probe result. | ASM-117; ADR-012 | THR-023 | C-15, C-17 | TST: probe failure fixture (network route present) → viewing disabled |
| RUI-057 | The Desk SHALL display a blocking warning when C-25's signed statement reports running trust-path binary hashes absent from the transparency log for the current release, and SHALL verify its own binary against the transparency log and report its release digest (labelled non-authoritative, ADR-043). | ASM-116; INC-28 | THR-025, THR-007 | C-15, C-25 | TST: fixture with unknown hash → warning |
| RUI-058 | The case Members panel SHALL warn when fewer than `min_recipients` (default 2, ADR-044 §2) members hold active keys, SHALL show members with fewer than 2 enrolled authenticators, and SHALL require explicit acknowledgement of permanent loss before removing the last key holder; deletion of key wraps prompted by IdP/HR changes SHALL be shown as "suspended — pending dual-controlled deletion after 7 days" (ADR-044 §1). | ASM-122; ADR-013; ADR-044 §1–§2; RVW-C-03 | THR-042 | C-15, C-10 | TST |
| RUI-059 | The Desk SHALL enforce the `10` §6.1 platform tiers: CL-2/CL-3 only on Tier 1/2 hosts with a passing containment probe; in reduced mode only CL-0/CL-1 text; the tier SHALL be shown in the status bar. | ADR-042; RVW-A-15 | THR-023 | C-15, C-17 | TST: reduced-mode fixture (gVisor-only, VDI) → viewer and "Open original" disabled with reason |
| RUI-060 | All source-, VM- and server-originated strings SHALL be rendered via text nodes only, with no HTML/Markdown interpretation or auto-linking, and with bidi/control characters visualised (SI-17). | ADR-042; RVW-A-15 item 3 | THR-023, THR-007, THR-008 | C-15 | TST: hostile-string corpus (HTML, `<script>`, `javascript:` URLs, RLO, zero-width, 1 MB strings) in every rendering path → inert; lint forbids `innerHTML`/`dangerouslySetInnerHTML`/`v-html` |
| RUI-061 | Every sanitized copy SHALL display "Rendering — not evidence", the converter release digest, output-hash verification state and dual-render result; CL-2 frames SHALL NOT be shown if the output hash fails. | ADR-042; RVW-A-30 | THR-037, THR-122 | C-15 | TST: tampered rendering → refused; label snapshot |
| RUI-062 | The CL-2 viewer SHALL offer an accessible text view of the OCR text rendition, navigable with screen readers, linked bidirectionally to page regions. | ADR-042; RVW-C-16; Section 508 §502 [B-CO-32]; EN 301 549 11.5 [B-CO-34] | — | C-15 | TST: a11y-tree snapshot of text view; DEMO: NVDA/VoiceOver/Orca reading a 5-page scanned PDF |
| RUI-063 | The export wizard SHALL show the E5 (iv) beacon/canary warning for flagged ORIGINAL items, require acknowledgment by requester and each approver, and produce the `10` §15 E10 inner container. | RVW-A-25; ADR-018 | THR-010, THR-041 | C-15 | TST: remote-template DOCX export → modal, acknowledgments, inner container |
| RUI-064 | The Desk SHALL show the §4.2 custody indicator; for Triage Set members of INDEPENDENT channels it SHALL block epoch-key publication and new-report receipt on devices without attested independent custody unless a DANGEROUS custody exception is active. | ADR-043; RVW-C-01; RVW-A-24 | THR-018, THR-041 | C-15, C-14 | TST: org-managed fixture on INDEPENDENT channel → banner + no MEK publication; exception active → banner persists |
| RUI-065 | The Desk SHALL run best-effort managed-endpoint detection at unlock and daily (§4.1) and SHALL show a persistent "Managed endpoint" banner when indicators are found. | RVW-A-24; RVW-C-01; RVW-C-11 | THR-041, THR-108 | C-15 | TST: fixtures with common EDR/MDM/remote-assist agents and Recall enabled → banner; INSP: catalogue review per release |
| RUI-066 | The Desk SHALL disable OS/webview crash reporting and process dumps for its processes and SHALL refuse detected sync-client roots as export destinations without OVERSIGHT approval. | RVW-C-11 | THR-016, THR-029, THR-041 | C-15 | TST: crash Desk with canary content → no dump written or uploaded; export to OneDrive KFM path → refused |
| RUI-067 | Only Triage Set members SHALL list, receive notifications for, or trial-decrypt intake envelopes; non-triage roles SHALL see no intake counts. | ADR-037 §2; RVW-A-18; RVW-B-04 | THR-020 | C-15, C-10 | TST: non-triage member API and UI → no inbox, no counts, no envelope fetches |
| RUI-068 | External notifications SHALL be either off (HIGH default) or a constant-schedule daily digest with fixed content sent every day at a fixed time; no event-driven notification SHALL exist. | ADR-038 §2; RVW-A-19; RVW-C-02 | THR-028, THR-011 | C-15, C-23 | TST: 30-day trace of digest send times and content with and without imports → identical |
| RUI-069 | The composer SHALL run the SI-19 prompting-pattern warning and require edit or reasoned override, CASE-audited. | RVW-A-10 item 4 | THR-011, THR-105 | C-15 | TST: 3 replies in 7 days without source message → warning |
| RUI-070 | Exports to HR, remediation owners or IT, or for investigation steps such as log queries, SHALL require a recorded candidate-set estimate; estimates < 10 SHALL require approval by a reviewer holding an independent role. | RVW-B-23 item 3 | THR-019, THR-125 | C-15, C-22 | TST: export with estimate 4 and no independent reviewer → blocked |
| RUI-071 | Break-glass requests SHALL require an approver from an independent role outside the legal/management chain, and key donors SHALL see the approval set and be able to refuse with a recorded event. | ADR-045; RVW-C-10 | THR-019, THR-020 | C-15, C-22 | TST: request with two in-house counsel approvers → cannot submit; donor refusal → CASE event visible to OVERSIGHT |
| RUI-072 | Records search (R15) SHALL run only locally over cases the user can decrypt, SHALL never index sealed identity, SHALL produce signed content-free hit/no-hit attestations, and SHALL audit each query without cleartext terms. | ADR-044 §5; RVW-C-14 | THR-019, THR-016 | C-15, C-24 | TST: index inspection lacks identity canary; query audit event has hash only; records custodian grant expiry → cases no longer searchable |
| RUI-073 | Desk TUF metadata refresh SHALL use the Z-CORE mirror endpoint on a fixed daily schedule, not on each start. | RVW-C-02 item 4; ADR-046 §3 | THR-011, THR-036 | C-15 | TST: network capture over 5 Desk restarts → one refresh at the scheduled time, only to Z-CORE |
| RUI-074 | The Inbox SHALL offer "Reject unopenable" for envelopes no Triage Set Desk could open, only after 14 days pending and with dual approval per `15` DC-12. | ADR-038 §6; RVW-A-20 | THR-033 | C-15, C-22 | TST: day-13 attempt refused; day-14 with one approver refused; with two → deleted |
| RUI-075 | The Desk SHALL treat a pending envelope that none of its Member Epoch Keys opens as normal (chaff or another member's envelope, ADR-047(3)): it SHALL NOT list, count, flag, alert on or locally record such envelopes, and the "Reject unopenable" action SHALL be offered only for envelopes marked `rejectable` by DA-20. | ADR-047(3); ADR-037 §2; RVW-B-04; RVW-A-18 | THR-020, THR-110 | C-15 | TST (30): fixture with chaff and envelopes for other members → Inbox, counts, logs and local state identical to a fixture without them |
| RUI-076 | The Desk SHALL keep the §4.3 hardware-sealed case-key cache, SHALL verify the signed erasure log before any other operation on every sync, and SHALL purge cached keys, tags, index entries and local copies of every listed or removed case; it SHALL open no cached case while the log cannot be verified. | ADR-047(7); ADR-044(1), (4); ADR-025 | THR-042, THR-017 | C-15 | TST: erase case → next sync purges cache (keystore inspection); tampered erasure log → cached cases refused |
| RUI-077 | The R16 "Restore access" task SHALL re-create wraps and metadata ciphertexts for `ek_missing` cases from the cached case key with a second-holder or OVERSIGHT approval, SHALL key-confirm on each receiving Desk before acceptance, and SHALL emit content-free CASE events. | ADR-047(7), (8); RVW-C-07 | THR-042, THR-020 | C-15, C-10 | TST: vault-loss drill (19) → all cases with ≥ 1 cached holder restored; wrong key → rejected with SECURITY alert |
| RUI-078 | Member removal SHALL suspend access only; key-wrap deletion SHALL be available only through the DA-49 request/approve UI (distinct approver, step-up, 7-day cooling-off, `min_recipients` floor) with generic events. | ADR-044(1), (2); RVW-C-03 | THR-042, THR-020 | C-15, C-10 | TST: remove → "Suspended"; deletion before not_before_day or below floor → refused |
| RUI-079 | The Desk SHALL provide the CASE-037 self-identification sealing action, `RESTRICTED_OVERSIGHT` rendering per `14` §9.5, and the intermediary-mode Case Brief view per `14` CASE-039. | RVW-B-15; RVW-B-25; RVW-B-23 | THR-018, THR-019, THR-010 | C-15 | TST: seal passage → case copy shows "[identity sealed]", source flag set; intermediary-mode investigator sees no raw text or files |
| RUI-080 | The Desk SHALL run `desk-preflight` (21 ENT-034) at enrolment, each unlock and daily from a signed TUF-distributed catalogue; an override for an INDEPENDENT-channel Triage Set member SHALL require OVERSIGHT approval. | ENT-034; ADR-043; RVW-C-01; RVW-C-11 | THR-041, THR-108 | C-15 | TST: catalogue fixtures → findings; override without OVERSIGHT → refused |
| RUI-081 | The composer and status selector SHALL offer "Release later" (random day 1–3 days later) with equal weight to "Send now", defaulting to "Release later" for the first reply in the HIGH profile. | RVW-C-02; RVW-C-11; ADR-038 | THR-011 | C-15, C-10 | TST: released items' days uniform over 1–3 days over 10^3 fixtures; HIGH default snapshot |

## 14. Residual risks and limitations

1. **Authorized insiders** can read, photograph or retype what they can view. Interlocks raise effort and create audit trails but do not prevent this (THR-019). Detection relies on audit review and anomaly alerts (`13-FRONTEND-ADMIN.md` SOCUI).
2. **Screen-capture exclusion** is best-effort. It does not stop cameras, hypervisor-level capture, or some EDR tools. It is unavailable on many Linux desktops.
3. **The clipboard** cannot be fully controlled at the OS level. Other apps can read clipboard contents during the 60 s window.
4. **A compromised or organisation-controlled recipient workstation (C-16)** defeats all UI interlocks and exposes the cases that user can access (bounded by ACL, ADR-008). The Desk's self-check of its own binary and the managed-endpoint detection are non-authoritative: a modified build or a stealthy agent can lie (ADR-043 residual; RVW-C-01). Independent custody is required only for Triage Set members of INDEPENDENT channels; other members on managed devices remain exposed to their administrators.
5. **Verified redaction** covers text and known hidden layers. It cannot detect visual identification (handwriting, faces, layouts) unless a human redacts them.
6. **Accessibility of Tauri webviews** varies by platform. WebKitGTK with Orca on Linux is historically less mature (Knowledge (unverified)).
7. **Side-channel, identity-probing and prompting detectors** are heuristic and bypassable by rephrasing.
8. **Renderings may be falsified** by a compromised converter; labels, digests and dual rendering reduce but do not remove this (RVW-A-30).
9. **Reduced-mode Desks** (no hardware-isolated viewer) cannot view attachments; users may be pushed to insecure workarounds (photographing another screen). The Guide and custody rules address this only procedurally.
10. **OCR-based accessibility** is approximate; rasterized originals remain partially conformant (declared in the ACR, `26`).
11. **Staff reaction timing:** constant-schedule digests and fixed import slots remove event-driven signals, but humans still react to urgent reports; day-level correlation remains (RVW-C-02 residual).
12. **Cached case keys on endpoints** (ADR-047(7)) lengthen the exposure of case keys on each member's device: a captured device plus its hardware authenticator and PIN opens every cached case, including cases the member no longer actively works on, until the next erasure-log sync or removal purges them.
13. **Chaff presentation depends on 04 §12.7:** if chaff is removed before Desks list pending envelopes, an excluded Triage Set member can still observe an envelope it cannot open; RUI-075 then only prevents the Desk from surfacing it.

## 15. Open issues

- **OI-12-1:** Define the exact C-17 IPC protocol for CL-3 pixel streaming vs a native DispVM window (Qubes) in `10-FILE-EVIDENCE-PIPELINE.md` (Tier 2 hosts do not open originals natively, `10` §6.1).
- **OI-12-2:** Resolved in part by ADR-042: the CSP, Trusted Types and isolation pattern are specified in SI-17; IPC command naming remains with `06-SYSTEM-ARCHITECTURE.md`.
- **OI-12-3:** Decide whether visible export footers should include the exporting user's identifier (accountability) or only the export ID. This spec uses the export ID only, to avoid enabling canary-style tracing of staff that could also be misused.
- **OI-12-4:** Validate the `N_VERBATIM = 50` default with investigators and journalists.
- **OI-12-5:** Local encrypted search index design (tokenization, deletion propagation under ADR-025) belongs in `09-DATABASE.md`/`35-DATA-RETENTION-DELETION.md`; the UI and scope are now fixed by ADR-044 §5 (R15).
- **OI-12-6:** The managed-endpoint detection catalogue (products, signatures) needs an owner and update cadence (`21-ENTERPRISE.md` OI-3; RVW-C-11).
