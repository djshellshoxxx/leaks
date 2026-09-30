# 12 — Recipient User Interface Specification (Candor Desk)
Status: Draft v1.0 · Edition applicability: both (CE core; EE adds connector targets in export and SSO-bridged unlock policy) · Owner: Recipient Experience team (with Security Architecture, Case Management and Accessibility review)

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
| `DECISIONS.md` ADR-030 | Per-member epoch keys; envelope header lists recipient key IDs; COI filter before wrapping |

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
| Sync: last pull batch 2026-09-30 | Keys: directory consistent ✓ | Viewer: ready  |
| (CL-3 microVM) | Device: disk encrypted ✓ | Version 1.4.2 (current)              |
+----------------------------------------------------------------------------------+
```
- The status bar (`role="status"`) reports sync, key-directory consistency (C-14 proofs), C-17 availability, device posture and the update state.
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
| System clock within ±5 min of the signed key-directory timestamp (THR-043) | warn |
| Key-directory consistency | block on split-view detection |

- Posture results are shown as a checklist with pass/warn/block states in text.
- **Locking:**
  - The session auto-locks after `DESK_IDLE_LOCK` (default 10 min, range 2–30, SAFE config).
  - It also locks on OS lock or sleep, and on smartcard removal.
  - Locking clears decrypted content from the webview DOM and drops plaintext caches.
  - Unsaved reply text survives lock in memory under the session key.

## 5. Screens

### R02 Inbox / Triage
- **Purpose:** receive newly imported reports and decide initial handling (`14-CASE-MANAGEMENT.md` triage).
- **Who:** channel members with the `intake` permission (holders of channel epoch keys, ADR-008).
- **Table columns:**

| Column | Content |
|---|---|
| Ref | Case pseudonym (for example `C-7F3K-2Q`), random and not derived from any source data |
| Channel | Channel name |
| Received | `YYYY-MM-DD` (ADR-010; never a time) |
| Mode | ANON / CONF / IDENT badge (text + pattern) |
| Category | Source-selected category |
| Files | Count |
| Risk | "Few people know" flag from source answer (`05` §8.7): shows `HIGH` when "1–5" |
| COI | "Exclusions applied" icon + count |
| SLA | Next due (e.g., "Acknowledge by 2026-10-07") |
| Status | New / Triaged / Spam-held |

- **Recipient-set check (ADR-030):** on import, Desk verifies that the envelope header's recipient key IDs match eligible member epoch keys in the Key Directory (C-14, with inclusion and consistency proofs, ASM-111). Any unknown or extra recipient slot (other than padding dummies) raises a SECURITY alert, and the envelope is shown as "Recipient set could not be verified — do not accept". The Inbox also shows "Encrypted to: {n} members" and, for the case lead, the role labels.
- **Actions** (row menu and keyboard):
  - **Open preview** (text answers at CL-1);
  - **Accept as case**: creates the case, re-wraps content keys into a new Case Key for the assigned members after COI exclusion (ADR-008, ADR-015);
  - **Route to another channel**: requires reason; COI re-evaluated; re-wrap;
  - **Hold as spam/abuse**: ADR-026 triage queue; retention per `35-DATA-RETENTION-DELETION.md`;
  - **Assign**.
- **Not available:** source identity, IP, device, exact time, "similar reports", author or style matching, cross-report linking except where the *source* linked reports under the same passphrase (SOPS-041; REQ-H-08).
- **Empty state:** "No new reports. Reports are pulled from intake in batches. The last batch was on {date}."
- **A11y:** a data grid with sortable column headers (`aria-sort`), row selection by keyboard (arrow keys, Space). Badges have text.

```
| Inbox — Audit Committee                                     [Filter v] [Sort v]  |
| Ref        Received    Mode  Category  Files Risk  COI SLA              Status   |
| C-7F3K-2Q  2026-09-30  ANON  Fraud     2     HIGH  ⊘1  Ack by 10-07   New      |
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
  - questionnaire answers rendered at CL-1 as plain text (no HTML, no links);
  - the source's "people kept out" roles (case-lead visible);
  - channel;
  - received day;
  - source-visible status selector (the coarse set from 14; changing it shows "The source will see: In progress").
- **Risk panel** (`05` §8.7, INC-16, INC-10):
  - "Few people know: 1–5";
  - "Files include photos or scans (printer dots or location possible)";
  - "Mode: ANONYMOUS";
  - guidance lines: "Avoid investigation steps that narrow the group to the source, such as asking IT who printed or opened a specific document. Paraphrase in findings."
- **Members panel:** list of members (name, role, grant expiry). Add/remove goes through AuthZ + COI (§8). Self-recusal is available.
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
  - messages with sender (source shown as "Source"; staff by display name), day date, and signature state (verified / failed);
  - source messages rendered at CL-1;
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
- **No read receipts, typing indicators or "seen" states** in either direction (ADR-010).
- **A11y:**
  - Messages are `article` elements with headings.
  - The composer has a label and character count via `aria-describedby`, updated politely.
  - Send is `Ctrl/Cmd+Enter`.

### R05 Evidence panel
- For each evidence object, a card shows:
  - **Original:** type (by magic, determined in C-17), size, SHA-256 and BLAKE3 (truncated, with copy for verification), received day, "Immutable" state, and containment level.
  - **Derivatives:** the sanitized working copy and redacted versions, each with `derived_from`, the transformation record (tool and version, e.g., "pixels-to-PDF v…, OCR on") and a verification result.
  - **Metadata report** (generated in C-17 from the original): author fields, GPS present y/n, device model, printer-dot detection result for scans, embedded files. It carries a warning banner: "This report may contain information that identifies the source. Don't copy it into case notes or exports."
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
|   [ View sanitized copy ]  [ Open original (disposable viewer, CL-3)… ]           |
|   [ Metadata report ⚠ ]   [ New derivative… ]  [ Redact… ]                      |
```

### R06 Viewer
- **CL-2 safe viewer:**
  - Renders derivative page images (PNG pages from C-17 output). Decoding happens in a separate sandboxed renderer process with no network and no filesystem write.
  - Zoom, page navigation, search in the OCR text layer.
  - Text copy is subject to the clipboard policy (SI-06).
- **CL-3 disposable viewer:**
  - C-17 starts a fresh network-less microVM or DispVM, and the original opens there.
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
| E5 Source-protection checks | (i) **Verbatim quote check:** counts contiguous source-authored text > `N_VERBATIM` words (default 50) in export items and requires sign-off "paraphrase recommended" (INC-73; REQ-H-73); (ii) identity-hint scan over export text (same detectors as R07); (iii) risk-panel reminders ("Few people know: 1–5") | Warnings are acknowledged with reason; not silently bypassed |
| E6 Approvals | Required approvers (policy): originals → 2 approvers other than the requester; CONF/IDENT cases → case lead; HIGH profile → dual approval for all exports | Approvers review a read-only preview in Desk |
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
- **Aggregates** (counts by state) are shown to team leads only. Counts below `k = 5` are suppressed in any view shown outside the case team (THR-039; INC-74).

### R10 Notifications center
- **In-app** (visible only after unlock): new report in channel, source replied, SLA approaching or overdue, approval requested (export, unseal, break-glass), key-directory alert, update available, posture warnings. Each links to the item.
- **OS notifications** (optional, default OFF): the fixed text "Candor: action requires attention". No case ref, count, channel or time (ADR-017). Lock-screen previews are disabled.
- **External notifications** (email/Matrix/Teams via C-23): configured by admin. The UI shows the exact content that will be sent ("Candor: secure case-management action requires attention · {instance label}") and the batching interval (default hourly digest).

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
- **Approval:** requires dual authorization per `15-AUTHENTICATION-AUTHORIZATION.md`.
- **During use:** the UI shows a persistent red-and-striped banner "BREAK-GLASS ACCESS — under independent review" with the time remaining.
- **Post-hoc review:** a task is created for the independent reviewer (ombudsperson or audit committee).
- **COI:** source-flagged COI exclusions cannot be bypassed via the ordinary member-add path. Break-glass is the only route, and it is flagged "COI OVERRIDE" in review.

### R13 Settings & Guide
- **Personal settings:** language, density, theme (system / light / dark / high contrast), keyboard shortcuts (remap, disable single-key), reduced motion, OS notifications on/off.
- **Policy-locked settings** (shown read-only with the policy source): idle lock, clipboard policy, print availability, screen-capture exclusion.
- **Guide:** the recipient OPSEC guidance (§12), available offline in the app bundle.

### R14 Case audit (case lead)
- A chronological list of CASE events for this case: opened, viewed evidence (level), exported, redacted, member changes, status changes, unseal and break-glass references. Staff actions have exact times (ADR-010 allows exact times for staff).
- Read-only. Hash-chain verification status comes from C-24.

## 6. Containment level indicators

| Level | Label (text shown) | Meaning | Visual (not color-only) |
|---|---|---|---|
| CL-0 | SEALED | Ciphertext only. Not decrypted on this device | Lock glyph + grey dotted border |
| CL-1 | TEXT · SAFE RENDER | Plain text (answers, messages) rendered by Desk as text only; no parsing beyond UTF-8 validation | "T" glyph + thin solid border |
| CL-2 | SANITIZED COPY · SAFE VIEWER | Derivative from C-17 (pixels→PDF/PNG), displayed in the sandboxed image renderer | Shield glyph + double border |
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

## 8. Conflict-of-interest indicators

- **Case header chip:** "⊘ COI: {n} exclusions applied". The details popover lists:
  - source-flagged roles;
  - pre-configured COI map entries matched;
  - self-recusals;
  - overrides (break-glass only).
  Visible to the case lead. Other members see only the count.
- **Member add:** the picker marks excluded users "Excluded by conflict-of-interest rule" and disables them. The reason is shown to the case lead. The attempt is logged.
- **Routing:** the route dialog shows "COI will be re-evaluated for the new channel; excluded users will not receive keys".
- **Self-recusal:** "I have a conflict of interest" → confirm → Desk destroys the user's own case-key wrapping (04), removes membership, and notifies the case lead. It is irreversible without re-grant by the case lead after COI review.
- **The user's own exclusion is invisible** to them: excluded users never receive keys or case listings (ADR-015). There is no indicator for them, by design.

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

- No per-report push notification. External notifications are content-free, batched and jittered (ADR-017).
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

## 13. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| RUI-001 | The recipient UI SHALL be delivered only as the signed Candor Desk application. No server component SHALL serve a browser-based recipient UI. | ADR-007; INC-01 | THR-007, THR-014 | C-15, C-06, C-10 | INSP: route registry has no recipient web routes; ST: scan of Z-CORE/Z-INTAKE endpoints |
| RUI-002 | The Desk UI bundle SHALL load no remote code, fonts, images, styles or help content. Its webview CSP SHALL restrict connections to the Tauri IPC channel. | REQ-H-46 (INC-46); ADR-019 | THR-036, THR-008 | C-15 | TST: network sandbox run of the UI test suite; INSP: CSP config |
| RUI-003 | Unlock SHALL use a hardware-bound key per ADR-007. The software fallback SHALL display a persistent "Weaker protection" badge. | ADR-007; B-SD-13 (SEC-01-010) | THR-022, THR-013 | C-15, C-21 | TST: unlock matrix; DEMO |
| RUI-004 | The Desk SHALL run the §4.1 posture checks at unlock and SHALL block on key-directory split view, disabled disk encryption (policy) or Desk version older than the security-fix window. | INC-67; ADR-022 | THR-046, THR-025, THR-031 | C-15, C-14 | TST: posture fixtures for each check |
| RUI-005 | The Desk SHALL auto-lock after `DESK_IDLE_LOCK` (default 10 min), on OS lock or sleep, and on smartcard removal, and SHALL clear decrypted content from the UI on lock. | THR-041; INC-16 | THR-041, THR-031 | C-15 | TST: lock triggers; DOM inspection after lock contains no canary |
| RUI-006 | Window titles, OS notifications and task-switcher labels SHALL NOT contain case references or content. | ADR-017; INC-57 | THR-028, THR-041 | C-15 | TST: title assertion across screens |
| RUI-007 | The Inbox SHALL show only the §R02 columns, with received date at day granularity, and SHALL NOT show source IP, device data, exact times or identity. | ADR-010; REQ-H-09 (INC-09) | THR-011, THR-019 | C-15, C-10 | TST: API contract test (08) + UI snapshot |
| RUI-008 | The Desk SHALL NOT provide authorship attribution, stylometric similarity, "similar reports" or metadata-based cross-report linking. Only source-created linkage (same passphrase) SHALL be shown. | REQ-H-08; INC-73; `05` SOPS-041 | THR-010, THR-019 | C-15, C-10 | INSP: feature review per release |
| RUI-009 | Accepting or routing a report SHALL apply COI exclusions before wrapping the case key. Excluded users SHALL never receive keys or listings. | ADR-015; INC-22 | THR-020 | C-15, C-22, C-11 | TST: integration test: excluded user's device has no wrapping; listing API returns 404 |
| RUI-010 | The case header SHALL show the COI indicator (§8), SLA chips, mode badge and status. COI details SHALL be visible to the case lead only. | ADR-015 | THR-020, THR-040 | C-15 | TST: role-based render tests |
| RUI-011 | Member additions SHALL be checked against COI and AuthZ. Excluded users SHALL be shown as disabled with a reason. Source-flagged exclusions SHALL be overridable only via break-glass (R12). | ADR-015 | THR-020, THR-021 | C-15, C-22 | TST: negative tests; ST: API bypass attempt |
| RUI-012 | A self-recusal action SHALL destroy the user's own case-key wrapping, remove membership and notify the case lead. | ADR-015; ADR-025 | THR-020 | C-15, C-11 | TST: post-recusal decrypt attempt fails |
| RUI-013 | The case view SHALL display a risk panel including the source's "how many people know" answer and file-class warnings, with investigation-narrowing guidance. | `05` §8.7; INC-16; INC-10 | THR-019, THR-010 | C-15 | TST; INSP copy |
| RUI-014 | Source identity (CONF/IDENT) SHALL be displayed only in R11 after dual custodian approval, in a capture-excluded window that auto-hides after 5 min, with copy disabled. It SHALL never appear in the case view, search, exports or notifications. | ADR-014; B-CO-02 (Art 16) | THR-018, THR-019 | C-15, C-22 | TST: search index lacks identity canary; export scan; ST: API authZ tests |
| RUI-015 | Unseal requests SHALL capture legal basis, justification, scope, duration and source-notice decision (notify or defer with reason and review date), and SHALL require 2 custodians excluding the requester. | ADR-014; R6 WB-09 | THR-018 | C-15, C-22, C-24 | TST: workflow tests; AUD: audit trail review |
| RUI-016 | Every evidence item, viewer and export item SHALL display its containment level (§6) as text in its accessible name and visually, not by color alone. | ADR-012; WCAG 1.4.1 | THR-023, THR-041 | C-15, C-17 | TST: a11y tree check; visual regression |
| RUI-017 | The default evidence action SHALL be the CL-2 sanitized copy. Opening an original SHALL require the SI-02 confirmation and SHALL occur only in C-17 (CL-3) or C-18 (CL-4). | ADR-012; REQ-H-16; R5 §D.3 | THR-023, THR-009 | C-15, C-17 | TST: no code path renders original bytes in the Desk process (IPC audit); DEMO |
| RUI-018 | The Desk SHALL offer no download, save-as, open-with, reveal-in-folder, drag-out or OS share for evidence, and SHALL NOT write decrypted evidence to host storage outside `candor-safefs` memory-backed areas. | ADR-027; ADR-018; B-SD-33..35 | THR-041, THR-029 | C-15 | TST: filesystem watcher during e2e (no plaintext canary on disk); INSP |
| RUI-019 | The CL-3 viewer SHALL be network-less, SHALL disable VM-to-host clipboard by default, SHALL show the persistent ORIGINAL label, and SHALL be destroyed on close with a CASE audit event. | ADR-012; B-SD-05; B-CR-44 | THR-023 | C-17, C-15 | TST: VM network namespace test; clipboard test; audit event check |
| RUI-020 | The CL-2 renderer SHALL run in a separate sandboxed process without network or filesystem write access and SHALL accept only derivative formats produced by C-17 with a matching derivative hash. | INC-65; B-CR-56 | THR-023 | C-15 | ST: malformed-PNG fuzzing; TST: hash mismatch rejected |
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
| RUI-033 | The Desk SHALL NOT display or emit read receipts, typing indicators or presence, and SHALL show source message dates at day granularity. | ADR-010 | THR-011 | C-15 | TST; INSP |
| RUI-034 | Content failing signature or AEAD verification SHALL be displayed only as an error state, with no partial plaintext. | REQ-H-65 (INC-65); REQ-H-66 | THR-012, THR-007 | C-15, C-11 | TST: tampered-ciphertext fixtures |
| RUI-035 | Server-supplied names and metadata SHALL be treated as untrusted display strings and never used as paths, commands or HTML. | ADR-027; B-SD-33..36 | THR-007, THR-023 | C-15 | TST: malicious-server harness (path traversal, HTML injection, oversized fields) |
| RUI-036 | URLs in content SHALL be rendered inert. The Desk SHALL never fetch any URL derived from content. "Copy link" SHALL require confirmation. | INC-65; SI-05 | THR-008, THR-023 | C-15 | TST: network sandbox with URL-laden fixtures |
| RUI-037 | The clipboard policy (`blocked`/`warn`/`allowed`, default `warn`) SHALL be enforced, and the Desk SHALL clear its copied content after 60 s or on lock. | THR-041; INC-16 | THR-041, THR-029 | C-15 | TST: clipboard tests per OS |
| RUI-038 | The Desk SHALL request OS screen-capture exclusion for all content windows where supported (default ON), and SHALL display a notice where unsupported. | THR-041; managed-endpoint screen recording (R4 §1 adversary A); INC-16 | THR-041 | C-15 | TST: capture API test on Windows and macOS |
| RUI-039 | The Desk SHALL avoid OS traces: no recent-documents, jump lists or thumbnails, and data directories excluded from OS indexing at install. | REQ-H-23 analogue for recipients; THR-031; INC-23 | THR-031, THR-041 | C-15, C-16 | TST: forensic diff of recipient workstation after e2e |
| RUI-040 | The Desk SHALL contain no AI assistant, cloud translation, cloud spell-check or cloud-storage integration, and SHALL disable OS cloud text services on content fields where possible. | INC-13; INC-53; SI-16 | THR-029, THR-036 | C-15 | INSP: dependency and feature review; TST: network sandbox |
| RUI-041 | OS notifications SHALL be off by default and, when on, SHALL use only the fixed text "Candor: action requires attention", with no counts or references. | ADR-017; INC-57 | THR-028 | C-15, C-23 | TST |
| RUI-042 | The SLA dashboard SHALL show clocks with due dates, state text and basis (calendar/business), SHALL require justification for pause or extension, and SHALL suppress counts < 5 outside the case team. | R6 §0 (SLA); B-CO-02; INC-74 | THR-039 | C-15, C-10 | TST: SLA fixtures; suppression test |
| RUI-043 | Changing the source-visible status SHALL display the exact text the source will see before saving. | ADR-002; `11-FRONTEND-SOURCE.md` SUI-054 | THR-019 | C-15 | TST |
| RUI-044 | Break-glass sessions SHALL display a persistent banner with the time remaining, SHALL be limited to ≤ 8 h, and SHALL create an independent-review task. | ADR-015; INC-68 | THR-018, THR-019 | C-15, C-22, C-24 | TST; AUD |
| RUI-045 | The case audit view SHALL show CASE events with hash-chain verification status from C-24 and SHALL be read-only. | ADR-016 | THR-037 | C-15, C-24 | TST: tampered chain → UI shows failure |
| RUI-046 | All Desk functionality SHALL be keyboard-operable, with the §9 defaults. Single-key shortcuts SHALL be off by default and remappable. | WCAG 2.1.1, 2.1.2, 2.1.4; B-CO-28 | — | C-15 | TST: keyboard-only e2e; DEMO |
| RUI-047 | The Desk SHALL meet WCAG 2.2 AA, EN 301 549 v4.1.1 clause 11 and Section 508 Chapter 5 as specified in `26-ACCESSIBILITY.md`, verified with NVDA, JAWS, VoiceOver and Orca. | B-CO-28, B-CO-32, B-CO-34 | — | C-15 | TST: automated a11y; DEMO: AT matrix; AUD: third-party ACR (EE) |
| RUI-048 | The in-app Guide SHALL include RO-01..RO-15, bundled offline, and SHALL be shown at first unlock and after each change to RO text. | REQ-H-16; INC-16 | THR-041 | C-15 | INSP; TST: first-run flow |
| RUI-049 | The status bar SHALL show sync, key-directory consistency, C-17 availability, device posture and update state, announced via a polite live region on change. | RP-8; INC-67 | THR-046, THR-025 | C-15 | TST |
| RUI-050 | Evidence cards SHALL show original hashes (SHA-256, BLAKE3), immutability state and the derivative transformation records. | ADR-012; R6 WB-11 | THR-037 | C-15 | TST: hash matches import record |
| RUI-051 | The "Generate new derivative" action SHALL offer greyscale + threshold and margin-crop options for scans, labelled as reducing printer-dot and handling-mark exposure. | REQ-H-16; B-CR-54 | THR-010 | C-15, C-17 | TST: DEDA-style detector on output finds no pattern (fixture) |
| RUI-052 | Inbox triage actions SHALL include Accept, Route (with reason), Hold as spam/abuse, and Assign, each producing a CASE audit event. | ADR-026; ADR-016 | THR-033 | C-15, C-10 | TST |
| RUI-053 | Unsent reply text SHALL survive auto-lock in memory under the session key and be restored after unlock. | WCAG 2.2.5 (adopted); COGA; B-CO-28; B-CO-36 | — | C-15 | TST |
| RUI-054 | The Desk SHALL NOT expose any function that returns source metadata beyond the §R02/§R03 fields, including in debug or support modes, and support bundles SHALL be scrubbed of content and tokens. | REQ-H-26, REQ-H-56 (INC-56) | THR-027, THR-016 | C-15, C-36 | TST: support bundle canary scrub test |
| RUI-055 | On import, the Desk SHALL verify each envelope's recipient key IDs against eligible member epoch keys in C-14 (inclusion and consistency proofs), SHALL treat any unexplained recipient as a SECURITY alert, and SHALL block acceptance of that envelope. | ADR-030; INC-14; INC-62; ASM-111 | THR-046 | C-15, C-14 | TST: malicious-server harness inserts an extra recipient slot → alert + block |
| RUI-056 | Attachment viewing (CL-2, CL-3) SHALL be disabled until the C-17 containment probe (ASM-117) passes at Desk start and daily. The status bar SHALL show the probe result. | ASM-117; ADR-012 | THR-023 | C-15, C-17 | TST: probe failure fixture (network route present) → viewing disabled |
| RUI-057 | The Desk SHALL display a blocking warning when C-25's signed statement reports running trust-path binary hashes absent from the transparency log for the current release. | ASM-116; INC-28 | THR-025, THR-007 | C-15, C-25 | TST: fixture with unknown hash → warning |
| RUI-058 | The case Members panel SHALL warn when fewer than two members hold active keys, and SHALL require explicit acknowledgement of permanent loss before removing the last key holder. | ASM-122; ADR-013 | THR-042 | C-15, C-10 | TST |

## 14. Residual risks and limitations

1. **Authorized insiders** can read, photograph or retype what they can view. Interlocks raise effort and create audit trails but do not prevent this (THR-019). Detection relies on audit review and anomaly alerts (`13-FRONTEND-ADMIN.md` SOCUI).
2. **Screen-capture exclusion** is best-effort. It does not stop cameras, hypervisor-level capture, or some EDR tools. It is unavailable on many Linux desktops.
3. **The clipboard** cannot be fully controlled at the OS level. Other apps can read clipboard contents during the 60 s window.
4. **A compromised recipient workstation (C-16)** defeats all UI interlocks and exposes the cases that user can access (bounded by ACL, ADR-008).
5. **Verified redaction** covers text and known hidden layers. It cannot detect visual identification (handwriting, faces, layouts) unless a human redacts them.
6. **Accessibility of Tauri webviews** varies by platform. WebKitGTK with Orca on Linux is historically less mature (Knowledge (unverified)).
7. **Side-channel and identity-probing detectors** are heuristic and bypassable by rephrasing.

## 15. Open issues

- **OI-12-1:** Define the exact C-17 IPC protocol for CL-3 pixel streaming vs a native DispVM window (Qubes) in `10-FILE-EVIDENCE-PIPELINE.md`.
- **OI-12-2:** Confirm Tauri 2 webview CSP and IPC scheme details with `06-SYSTEM-ARCHITECTURE.md`.
- **OI-12-3:** Decide whether visible export footers should include the exporting user's identifier (accountability) or only the export ID. This spec uses the export ID only, to avoid enabling canary-style tracing of staff that could also be misused.
- **OI-12-4:** Validate the `N_VERBATIM = 50` default with investigators and journalists.
- **OI-12-5:** Local encrypted search index design (tokenization, deletion propagation under ADR-025) belongs in `09-DATABASE.md`/`35-DATA-RETENTION-DELETION.md`.
