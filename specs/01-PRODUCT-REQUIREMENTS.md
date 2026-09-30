# 01 — Product Requirements

Status: Draft v1.0 · Edition applicability: both (CE and EE; EE-only items marked) · Owner: Product Management + Security Architecture

## 1. Purpose and scope

This document defines **what Candor is, who it serves, what it must do, what it must never do, and how success is measured without tracking sources**. It is the product-level contract from which the design documents (04–38) derive. It owns the `PRD-` requirement prefix.

In scope: product vision and principles; personas and journeys; the two editions and the principle that protections are never paywalled; functional requirements for intake, two-way communication, case management, routing, evidence, retention, internationalization and accessibility; non-functional requirements; non-goals; prohibited claims; success metrics.

Out of scope here (owned elsewhere): threat analysis (`02-THREAT-MODEL.md`), metadata and anonymity definitions (`03-PRIVACY-ANONYMITY.md`), cryptographic protocol (`04-CRYPTOGRAPHY.md`), detailed UI (`11`, `12`, `13`), case workflow internals (`14-CASE-MANAGEMENT.md`), retention mechanics (`35-DATA-RETENTION-DELETION.md`).

## 2. Context and dependencies

| Depends on | Why |
|---|---|
| `DECISIONS.md` (ADR-001..029, component catalog C-01..C-40, THR catalog) | Binding architecture. This PRD restates ADRs only as product commitments. |
| `02-THREAT-MODEL.md` | Adversaries (ADV-*), threats (THR-*), and component-compromise analysis referenced by PRD security requirements. |
| `03-PRIVACY-ANONYMITY.md` | Definitions of ANONYMOUS / CONFIDENTIAL / IDENTIFIED, metadata inventory, legal-compulsion inventory, k-thresholds used by metrics here. |
| `05-SOURCE-OPSEC.md` | Source guidance content referenced by intake requirements. |
| `14-CASE-MANAGEMENT.md` | Case state machine and routing detail (CASE-, ROUTE-). |
| `23-COMMUNITY-EDITION.md`, `21-ENTERPRISE.md`, `22-GOVERNMENT.md`, `24-LICENSING-BUSINESS-MODEL.md` | Edition packaging; Edition Charter text. |
| `25-COMPLIANCE.md`, `26-ACCESSIBILITY.md` | Legal and accessibility mappings (EU Directive 2019/1937, ISO 37002, WCAG 2.2). |
| `40-SECURITY-ASSUMPTIONS.md` | ASM-* assumptions under which every protection statement holds. |

Research inputs: R1 (SecureDrop/OnionShare), R2 (GlobaLeaks/CoverDrop/Hush Line/commercial), R3 (incidents INC-01..74), R4 (anonymity networks), R5 (crypto/sanitization/supply chain), R6 (compliance/a11y/licensing).

## 3. Vision and product principles

**Vision.** Give people inside organizations a way to report wrongdoing that is *designed so that the receiving organization, its administrators, its hosting providers and the software vendor cannot technically identify an anonymous reporter or read reports they are not authorized to read* — under stated assumptions — while giving the people who must act on reports a case-management tool good enough that they do not route around it.

**Positioning.** Candor combines the technical anonymity of newsroom drop systems (SecureDrop, GlobaLeaks Tor mode) with the compliance workflow of commercial hotline SaaS (acknowledgement/feedback SLAs, routing, retention), and rejects the "policy-based anonymity" of the latter (R2 §5: vendor/CDN/cloud see source IP; "we do not log" is compellable and unverifiable).

| # | Principle | Consequence in product |
|---|---|---|
| P1 | **Data that does not exist cannot be leaked, logged or compelled.** (R3 theme 1, INC-06, INC-12) | No source IP, no source contact identifiers, no exact source timestamps, no source device data are ever collected (ADR-001, ADR-005, ADR-010). |
| P2 | **The operator is compellable and seizable; so is the vendor.** (INC-01..07) | Content encrypted to keys held only on recipient endpoints (ADR-007); verified client tier (ADR-004); no vendor access to content in any edition or profile. |
| P3 | **Honesty over reassurance.** (THR-040) | Three explicitly named modes; every protection statement names what/from whom/assumptions/residual risk; prohibited-claims list (§10). |
| P4 | **No paywalled protections.** (ADR-020) | CE and EE share identical trust-path code; EE sells scale, integration, compliance packs and support — never safety. |
| P5 | **Recipients are attack surface.** (R3 theme 3; INC-16, 19, 21, 24) | Sanitized derivatives by default, redaction verification, dual approval for exporting originals, no forwarding outside the platform without an Export Package. |
| P6 | **Insiders exist, including the people being reported on.** (INC-22, INC-68..72) | Admin ≠ case access (cryptographically), COI exclusion before key wrapping, independent-body routing (ADR-015). |
| P7 | **Every third party is a wiretap.** (R3 theme 4) | No third-party scripts, CDNs, SDKs, CAPTCHAs, analytics or push services on any source path (ADR-023, ADR-026). |
| P8 | **Accessibility and usability are security properties.** | A source who cannot complete the flow safely will use email; a recipient who finds Desk painful will forward originals. WCAG 2.2 AA, plain language, no-JS operation. |
| P9 | **Human opsec failures dominate.** (R3 theme 9; R4 §2.2) | Built-in guidance at the moments it matters (before first visit, before upload, before return visit), generated credentials, no user-chosen handles. |

## 4. Personas

Risk level describes the consequence of identification or disclosure to that persona, not their trustworthiness.

| ID | Persona | Description | Goals | Must be able to | Must NOT be able to / must be protected from |
|---|---|---|---|---|---|
| PER-01 | **Source — normal risk** | Employee, contractor, supplier or member of the public reporting e.g. harassment, safety, fraud to an organization's internal channel. Uses personal phone or home laptop; not technical; may be stressed; may have a disability or limited literacy in the UI language. | Report once, maybe answer questions, learn the outcome. | Submit anonymously in ≤ 10 min with Tor Browser at default settings; return with a passphrase; read replies; choose to disclose identity. | Be asked for name/email/phone; be fingerprinted; see "anonymous" when not anonymous; lose a draft to a silent timeout. |
| PER-02 | **Source — high risk** | Whistleblower whose adversary is the organization's leadership, a state, or an intelligence/law-enforcement body; national-security, organized-crime or senior-executive fraud cases. May be forensically examined later (INC-23). | Deliver documents without being identified; keep deniability of device use. | Use Tails + Tor Browser at Safest, or the verified Source App (Tier V); verify recipient keys and escrow status before submitting; receive explicit guidance on timing, networks, printing, stylometry. | Have plaintext exposed to a compromised intake server (use Tier V); be correlated by exact timestamps; be exposed by recipient mistakes with originals. |
| PER-03 | **Recipient (intake triage)** | Compliance or ethics officer who is a member of an intake channel; first reader of new reports. | Triage quickly, acknowledge within SLA, route to the right investigator without seeing more than needed. | Import sealed envelopes into cases; read, acknowledge, reply; assign; mark spam; escalate. | Read cases of channels they are not a member of; see sealed identity; export originals alone. |
| PER-04 | **Investigator** | Internal investigator, internal audit, or IG staff assigned to specific cases. | Analyze evidence safely, record findings, keep chain of custody. | Open evidence in the containment viewer; annotate; request information from the source; record interviews and findings; produce redacted Export Packages. | Open originals outside containment; see cases they are not assigned to; identify the source through platform data. |
| PER-05 | **HR / compliance manager** | Program owner; configures channels, categories, SLAs, retention schedules; oversees case handling; may act as Identity Custodian (ADR-014) if designated. | Run a compliant program (EU 2019/1937, ISO 37002, SOX §301); report aggregate statistics. | Configure workflow; see k-thresholded program metrics; approve exports (as second approver); unseal identity with a recorded legal basis and a second custodian. | Access case content without a case grant; generate statistics that single out a reporter (k-thresholds, §11, `03-PRIVACY-ANONYMITY.md` §12). |
| PER-06 | **Ombudsman / audit committee member** | Independent body designated to receive reports concerning senior management (SOX §301 accounting/audit concerns; ISO 37002 independence). | Receive reports that bypass management; hold Recovery Quorum shares if configured. | Be the sole recipient of an "independent" channel; exclude management roles from a case; hold a quorum share on a hardware token. | Be bypassed by an administrator adding themselves to the channel silently (THR-046). |
| PER-07 | **External counsel** | Outside law firm or external investigator engaged for a specific case or channel. | Access only engaged matters; privilege-preserving workflow. | Receive time-bounded case grants; receive Export Packages; act as quorum holder or Identity Custodian if designated. | Access other matters; retain access after the grant expires. |
| PER-07b | **Identity Custodian** (role, often held by PER-05/PER-07) | Holder of the Sealed Identity Store key set for Confidential reports. | Protect identity; unseal only when legally required. | Unseal with dual approval + legal basis + source notice (ADR-014). | Unseal alone; unseal without an audit record visible to independent reviewers. |
| PER-08 | **System administrator** | IT staff installing and operating Candor hosts. | Keep it running, patched, backed up. | Install, upgrade, configure non-dangerous options, rotate infrastructure keys, run self-tests, restore backups. | Read any report content or sealed identity (holds no case keys — ADR-015); enable a DANGEROUS option alone (CFG dual approval); add a recipient to a channel without the channel's signed approval. |
| PER-09 | **Security team (SOC)** | Corporate security operations monitoring infrastructure health and attacks. | Detect attacks on Candor hosts; incident response. | Receive allow-listed SECURITY/SYSTEM events via C-26 (EE) or local monitor (C-25). | Receive any source-sensitive event, access log, source network data or case content; use Candor telemetry to investigate who reported (INC-22). |
| PER-10 | **Organization management** | Executives and board; sponsors of the program; possibly the accused. | Assurance that the program works; aggregate risk picture. | See k-thresholded, period-aggregated program statistics. | See cases, sources, or statistics granular enough to identify a reporter; learn that a specific report concerns them through platform side channels (THR-110). |
| PER-11 | **Journalist (newsroom deployment)** | Reporter/editor at a news organization running Candor as a tip line (SecureDrop-like use). | Receive documents from high-risk sources; communicate; verify authenticity without exposing the source. | Everything PER-03/PER-04 can do; use AIRGAP-RCP profile; produce sanitized, re-rasterized derivatives for publication (REQ-H-16). | Share originals with third parties for authentication without sanitization (INC-16). |
| PER-12 | **Accused / subject person** (non-user stakeholder) | Person named in a report; may be an executive or administrator. | Due process; data-subject rights where law grants them. | Nothing inside Candor unless granted as part of an investigation step. | Access, suppress, or learn of the report via admin powers or side channels (THR-020, THR-110). |

### 4.1 Key journeys (acceptance scenarios)

| ID | Journey | Personas | Acceptance outline |
|---|---|---|---|
| J-01 | First anonymous submission (Tier W) | PER-01 | Clearnet info page → guidance → Tor Browser → onion landing (mode banner ANONYMOUS) → choose channel → write text, attach files, optional "report concerns" roles → generated 10-word passphrase shown once → submit → confirmation (day-granularity receipt, "check back after 7 days"). No JS. ≤ 10 min for a 2-paragraph report with one file in moderated tests. |
| J-02 | Return and follow-up | PER-01/02 | Enter passphrase → mailbox shows replies with day dates → reply, add files → log out. No "last seen", no read receipts. |
| J-03 | High-risk verified submission (Tier V) | PER-02 | Tails or Source App → client verifies key directory and release transparency proof → displays recipient roster, key fingerprints, escrow status → client-side encryption → submit. |
| J-04 | Triage and acknowledgement | PER-03 | Desk shows new imported cases (received day) → triage (spam / in scope) → acknowledge (templated) within 7 days → assign investigator. |
| J-05 | Evidence analysis | PER-04 | Open attachment → containment viewer (C-17) renders sanitized derivative → annotate → original stays immutable with hashes. |
| J-06 | Report about the CFO | PER-01, PER-06 | Source selects "Audit Committee" channel and flags "concerns: Finance leadership" → COI map excludes CFO and finance roles before key wrapping → only audit committee members hold case keys. |
| J-07 | Confidential disclosure and unsealing | PER-01, PER-07b | Source opts to add identity → UI warns and converts mode to CONFIDENTIAL → identity sealed to custodian keys → investigator never sees it → legal request → dual custodian approval with legal basis → source notified via mailbox (unless deferral recorded). |
| J-08 | Export to external counsel | PER-04, PER-05, PER-07 | Create Export Package → redaction verified → second approver (dual approval for originals) → package encrypted to counsel key → CASE audit record. |
| J-09 | Closure and disposition | PER-03/05 | Close with outcome → feedback to source → retention timer → disposition = crypto-erasure → deletion certificate. |
| J-10 | Newsroom tip line | PER-11 | AIRGAP-RCP profile; publication-safe derivative export; no originals leave the viewing station. |

## 5. Editions

### 5.1 The principle: no paywalled protections

Candor ships as **Community Edition (CE)** and **Enterprise/Government Edition (EE)** (DECISIONS §2, ADR-020). The **Edition Charter** is a public, versioned document that states:

1. Every control that protects a source, a report's content, or keys — the Trust Path — is AGPL-3.0-or-later, reproducibly built and identical in CE and EE.
2. No feature that reduces the risk of source identification, content disclosure, key compromise, malicious update, or metadata collection will ever be moved to, or introduced only in, EE.
3. Security fixes to shared code are released to CE and EE at the same time.
4. EE commercial modules sit outside the trust path, never hold private keys, and never receive plaintext except via a human-created Export Package.
5. EE license expiry or license-server unavailability never disables, weakens or degrades any protection; it disables only commercial modules.

Rationale: open-core relicensing controversies (HashiCorp/OpenTofu, Elastic, Redis — B-CO-60..62) and trust gaps where server components are withheld (Signal server gap B-CO-64) show that users cannot verify protections they cannot inspect; a whistleblowing product whose safety depends on price would push the lowest-budget (often highest-risk) deployments into the weakest configuration.

### 5.2 Capability matrix

| Capability | CE | EE | Notes |
|---|---|---|---|
| Anonymous onion intake, Tier W and Tier V, PoW, vanguards | Yes | Yes | Identical trust path. |
| E2E encryption, epoch keys, case keys, PQ hybrid (CANDOR-STD-1) | Yes | Yes | |
| FIPS profile CANDOR-FIPS-1 | Yes (self-validated build flag) | Yes (+ validated module packaging, attestation docs) | Crypto identical in function; EE adds packaging/evidence for procurement. |
| Candor Desk with containment viewer, sanitized derivatives, redaction verifier | Yes | Yes | |
| COI exclusion, dual approval, break-glass, Sealed Identity Store | Yes | Yes | |
| Audit log (hash-chained, signed checkpoints), k-thresholded metrics | Yes | Yes | |
| Reproducible builds, threshold-signed TUF updates, transparency log | Yes | Yes | |
| Recovery Quorum (off by default) | Yes | Yes | |
| Multi-channel, single tenant | Yes | Yes | |
| Multi-tenant (low/moderate-risk group entities) | No | Yes | ADR-021. |
| SSO/SCIM connector for staff (OIDC/SAML bridge) | No (local WebAuthn/PIV) | Yes | Hardware-bound keys still required for content access. |
| HA orchestration, K8s operator for Z-CORE, DR automation | No | Yes | ADR-024. |
| SIEM exporter (C-26), records/ticketing/HR connectors (C-40) | No | Yes | Export Packages only for content (ADR-018). |
| Compliance/jurisdiction packs (SLA calendars, retention schedules, report templates) | Basic EU + generic | Full packs (EU member states, US federal/state, CA federal/provincial) | Engine in CE; content packs EE. |
| Advanced workflow designer | No | Yes | Workflow engine in CE. |
| Fleet Manager (C-34) | No | Yes | Never holds onion addresses in cleartext, content or keys. |
| Support SLA, formal ACR/VPAT, certification evidence | Community | Yes | |

### 5.3 Deployment profiles

Per ADR-024: CE-SINGLE, CE-HARDENED, EE-ONPREM, EE-HA, GOV-ONPREM, AIRGAP-RCP, PRIVATE-CLOUD, MANAGED. The product SHALL show the active profile and its documented reduced-isolation caveats (e.g., CE-SINGLE runs Z-INTAKE and Z-CORE as VMs on one host) in the admin console and in the source-facing "About this channel" page in plain language.

## 6. Modes and client tiers (product view)

| | Tier W (web, no-JS, default) | Tier V (verified client) |
|---|---|---|
| **ANONYMOUS** (onion only) | Default. Honest statement: "A live-compromised intake server could read what you submit while it is being encrypted." | Recommended for PER-02. Server never sees plaintext. |
| **CONFIDENTIAL** | Onion submission with voluntary identity (sealed) — or optional clearnet C-38 branded "NOT ANONYMOUS". | Same, identity sealed client-side. |
| **IDENTIFIED** | Named reporter (e.g., staff-entered report from a meeting, or a source who chooses to be named). | Same. |

Definitions and the mode-indicator rules are owned by `03-PRIVACY-ANONYMITY.md` §3 and §7. The product rule: the mode is **always visible**, never inferred by the user, and a report can only move towards less anonymity by an explicit, confirmed source action.

## 7. Functional requirements (narrative; normative rows in §12)

### 7.1 Intake
- **Channels.** A tenant has 1..n channels (e.g., "Ethics & Compliance", "Audit Committee — accounting/audit concerns", "External Ombudsman"). Each channel has: display name (per locale), description, recipient roster (roles and member key fingerprints, published in C-14), escrow status, categories, questionnaire, retention schedule, SLA calendar, mode(s) allowed.
- **Landing (onion).** Shows: mode banner; plain-language "what this protects and what it does not" (from `03` §5); channel list; per-channel roster and escrow status; tier statement; links to guidance (`05-SOURCE-OPSEC.md`); "Log in to an existing mailbox".
- **Submission form (Tier W).** Fields: channel (required), category (optional, from channel list), description (free text, required unless ≥ 1 attachment, ≤ 64 KiB UTF-8 after normalization), attachments (`<input type=file multiple>`; default ≤ 20 files and ≤ 500 MiB total per submission; admin-configurable 50 MiB–2 GiB), "This report concerns people in these roles" (multi-select of COI roles, optional), questionnaire answers (optional, configurable), "I want to share my identity" (opens CONFIDENTIAL flow, default off).
- **Questionnaire lint.** Channel questionnaires are validated on save: fields matching identifying patterns (name, email, phone, employee number, address, date of birth, exact date/time of the source's own actions) are rejected in ANONYMOUS channels unless marked optional and accompanied by a warning string; free-text questions display a stylometry hint.
- **Pre-upload guidance.** Before file selection: metadata, printing (MIC dots), photos of screens, canary/watermark warnings (R4 §2.2; INC-16, INC-17, INC-20). Tier V strips EXIF/XMP/IPTC/MakerNote client-side before encryption and shows what was removed (REQ-H-20); Tier W cannot do this without JS and says so, and recipients get sanitized derivatives (ADR-012).
- **Credential.** 10-word passphrase (ADR-005) generated, displayed once, with a "copy" affordance, a printable-free presentation (no "print" button), a checkbox "I have stored this passphrase somewhere safe that is not my work device", and an optional re-entry check of two randomly chosen words (skippable for accessibility).
- **Confirmation.** No report number (the passphrase is the only credential). States received day (UTC), what happens next, when to check back (default "after 7 days"), and how to log out/close Tor Browser.
- **No-anonymous-fallback.** If the onion service is down, C-37 shows an outage notice and the standby onion address (if activated) — never a clearnet form presented as anonymous (ADR-002).
- **Confidential clearnet (C-38, off by default).** Separately branded; every page states "NOT ANONYMOUS — your network address is visible to our hosting provider and network operators"; no shared cookies/assets with C-37 or the onion.

### 7.2 Two-way communication
- Source mailbox: list of the source's own submissions and messages, and replies, dated by UTC day only.
- Source can: send messages (≤ 64 KiB text, padded to 4 KiB buckets), add attachments (same limits), disclose identity (→ CONFIDENTIAL), request closure of the mailbox (deletes the source account record and pending replies at intake; case retention continues per law), log out.
- Recipient replies: plain text only (v1), ≤ 64 KiB, rendered as text with no auto-linking, no HTML, no images, no remote resources, no attachments to source (v1). Templates for acknowledgement, request for information, feedback, closure.
- Replies are sealed to the source's public key by the recipient's Desk, signed by the recipient, and become visible at the source's next login (no push, no email, no SMS; ADR-010, ADR-017).
- No read receipts, typing indicators, presence or "last seen" in either direction.
- Recipient identity shown to the source as role + channel + key fingerprint (REQ-H-21); UI warns sources against moving the conversation to other channels and states that staff will never ask them to.

### 7.3 Case management
- Import: C-09 pulls sealed envelopes; Desk of a channel member decrypts, creates a case, re-wraps content keys into a case key (ADR-008).
- Case states (normative machine in `14-CASE-MANAGEMENT.md`): `NEW → TRIAGE → {SPAM_REJECTED | OUT_OF_SCOPE_REFERRED | ACKNOWLEDGED} → ASSESSMENT → INVESTIGATION → FINDINGS → CLOSED(outcome) → RETENTION → DISPOSED`; overlays `LEGAL_HOLD`, `SEALED_MATTER` (e.g., FCA qui tam 60-day seal, B-CO-15), `ESCALATED`.
- SLA timers: acknowledgement default 7 calendar days from import; feedback default 3 months from acknowledgement (or from day 7 if no acknowledgement) (EU 2019/1937 Art 9(1)(b),(f); B-CO-02); external-channel profile 3 months extendable to 6 with recorded justification; business-day calendars (e.g., 5 business days) per jurisdiction pack.
- Case content (notes, tasks, interview records, findings, attachments, messages) is encrypted under the case key; the server sees only an allow-listed metadata set (defined in `09-DATABASE.md`, constrained by `03-PRIVACY-ANONYMITY.md`).
- Search is client-side in Desk over a locally encrypted index; no server-side full-text index of content.
- Linking cases is manual, by a user who has access to both; the platform provides no automatic cross-case/cross-source correlation (REQ-H-08) and no authorship similarity features.
- Detriment/retaliation tracking: cases can record reported detriment events (ISO 37002; EU Art 19) as case content.
- Interviews and meeting minutes (EU Art 18(2)–(4)): staff-entered records; source review/confirmation of minutes via mailbox message.

### 7.4 Routing
- Source-selected channel is the primary route. Category-based rules may route within a channel (e.g., accounting/audit category → audit committee sub-group, SOX §301).
- COI map: tenant config mapping COI role flags (e.g., "Executive leadership", "Finance leadership", "HR", "IT administration") to users/groups. With per-member epoch keys (ADR-030), the COI filter (source flags + COI map for the category) is applied by the Tier V client or the Tier W sealer **before** wrapping, so excluded members never hold any key that decrypts the envelope; recipient slots are anonymous (16 fixed slots, ADR-033(1)) so servers cannot see who was excluded. If fewer than the channel's minimum eligible members remain, the channel shows "temporarily unavailable" and accepts nothing (fail closed, no alternative path).
- Independent bodies: channels whose rosters contain only ombudsman/audit committee/external counsel; admins and management roles cannot be added without the channel's signed roster change (THR-046).
- Roster changes are signed by an existing channel member quorum (default 2 members, or 1 if roster size is 1 with an audit-committee co-sign), published to the key directory, and visible to sources.
- Re-routing a case to another channel requires a user with access and records a CASE audit event; the destination's COI exclusions are re-applied.

### 7.5 Evidence
- Server-side: attachments are opaque ciphertext; never parsed, previewed, scanned or thumbnailed on servers (ADR-012).
- Desk: original evidence immutable; SHA-256 and BLAKE3 recorded at import inside the encrypted case record; opening any file happens only in C-17 (or C-18); sanitized working copy is a new evidence object with `derived_from` and a transformation record.
- Redaction: rasterize or remove underlying text; export blocked until the verifier confirms no redacted string is extractable (REQ-H-19).
- Export Package: explicit, redaction-reviewed, encrypted to named recipient keys or to a password-protected archive with warning; originals require dual approval; all exports CASE-audited (ADR-018).
- Chain of custody: every evidence access, derivation and export is a CASE audit event with actor, time, object hash.

### 7.6 Retention
- Per-channel retention schedules keyed on outcome (defaults, overridable by jurisdiction packs): SPAM_REJECTED 30 days after decision; OUT_OF_SCOPE_REFERRED 60 days after referral; CLOSED without action 60 days after closure; CLOSED with disciplinary/legal action: until end of proceedings + 12 months (staff sets end date); maximum without explicit renewal 5 years.
- Legal hold overrides disposition; hold requires reason and approver.
- Disposition = cryptographic erasure of case keys and wrappings + best-effort physical deletion (ADR-025), with a deletion certificate (case_id, date, approver, key-destruction evidence).
- Intake side: sealed envelopes deleted from C-08 after Z-CORE acknowledgement (typically within one relay cycle); envelopes not imported into a case within 7 days escalate to the channel's independent role, and member epoch keys are retired only after their envelopes are imported (ADR-033(2)); source account records deleted when the case is disposed or the source closes the mailbox.
- Backups: each case key is also wrapped under a per-case Erasure Key (ADR-033(3)); destroying it at disposition makes all backed-up copies unreadable within ≤ 14 days.

### 7.7 Internationalization
- Source UI at 1.0: English, French, German, Spanish, Italian, Dutch, Polish, Portuguese, Arabic (RTL), Ukrainian; tenant may enable additional community translations.
- Language chosen explicitly and carried in the URL path (`/fr/…`); no persistent language cookie; Accept-Language used transiently only for the initial suggestion (`03-PRIVACY-ANONYMITY.md` META tables).
- Security-critical strings (mode banners, warnings, passphrase instructions, tier statement) are flagged `critical`; each critical translation needs two independent native-speaker reviews before release; untranslated critical strings fall back to English, never to blank.
- Staff UI (Desk/admin) at 1.0: English and French (Canadian federal parity; B-CO-19..21 context), others later.
- Dates shown as UTC calendar day in the locale's format; no timezone detection.

### 7.8 Accessibility
- Source UI, Desk, admin console and clearnet info site conform to WCAG 2.2 AA (ISO/IEC 40500:2025, B-CO-28) and EN 301 549 v4.1.1 (B-CO-34); EE ships a formal ACR.
- Source UI fully operable without JavaScript, with keyboard only, at 400% zoom, and with screen readers supported by Tor Browser's Firefox ESR base.
- No CAPTCHA (ADR-026); session timeouts warn ≥ 2 minutes ahead with a one-action extension (WCAG 2.2.1) and never lose typed text on the server side because none is stored — the UI tells the user this explicitly.
- Accessible authentication (WCAG 3.3.8): passphrase entry allows paste; words entered in one field or ten fields; autocomplete from the EFF word list without JS is not possible, so a printed-word-list alternative is linked in guidance.
- Plain-language source content (target reading level ≈ CEFR B1 / US grade 8) and COGA patterns (B-CO-36).

## 8. Non-functional requirements (summary; normative rows in §12)

| Area | Target |
|---|---|
| Performance — source | Every Tier W page response padded to a fixed size class (≤ 128 KiB each; see `03` META); a 10 MiB submission completes within 180 s over a Tor circuit sustaining ≥ 1 Mbit/s; login (Argon2id m=256 MiB, t=3) completes in ≤ 3 s server time at the design concurrency. |
| Performance — staff | Desk case list with 10,000 cases renders ≤ 2 s; import of 100 envelopes (100 MiB total) ≤ 60 s on reference hardware (`34-PERFORMANCE-SCALABILITY.md`). |
| Capacity | CE-SINGLE: ≥ 2,000 reports/year, ≥ 50 staff users, ≥ 20 channels. EE: ≥ 100,000 reports/year per instance, ≥ 2,000 staff users, ≥ 200 tenants (low/moderate risk only). |
| Availability | Intake onion reachable ≥ 99.5 % per calendar month (EE-HA ≥ 99.9 %), excluding Tor-network-wide outages. Z-CORE outage SHALL NOT stop intake: store-and-forward for up to 14 days. |
| Security | Memory-safe trust path (Rust, ADR-019); reproducible builds; threshold-signed updates; no plaintext on servers except transiently in C-07 (Tier W). |
| Privacy | No source identifier collected; metadata per `03` inventory; zero source telemetry. |
| Maintainability | Supported release lines: current + previous minor; tor security advisories patched ≤ 72 h (REQ-H-29); Candor critical fixes ≤ 7 days, high ≤ 30 days. |
| Portability | Servers: Debian stable (reference Debian 13). Desk: Windows 11, macOS 14+, Debian/Ubuntu LTS, Qubes 4.3 template. Source App: Windows, macOS, Linux, Android; iOS best-effort (weaker, documented). |
| Operability | CE-SINGLE installable by a generalist Linux admin in ≤ 2 h following docs; self-test after every deploy (ADR-028). |
| Upgradability | Upgrade without data loss; intake unavailability ≤ 5 min per upgrade; rollback to previous release supported. |
| Auditability | All staff actions audited (ADR-016); release provenance verifiable by third parties. |
| Usability | SUS ≥ 75 for sources and recipients in moderated studies; task success thresholds in §11. |

## 9. Non-goals (explicit)

Candor v1 will **not**:

| # | Non-goal | Reason |
|---|---|---|
| NG-01 | Provide an "anonymous" clearnet submission path, or fall back to clearnet when the onion is unavailable. | ADR-002; policy anonymity is compellable (INC-03). |
| NG-02 | Ship I2P or any transport not meeting the ADR-001 admission criteria. | R4 §4–5 (B-AN-54, B-AN-57). |
| NG-03 | Protect against a global passive adversary, a compromised source device, or a source who self-identifies through content, behavior or timing. | R4 §2.1; documented residual risk. Cover-traffic transports are future work (R4 §6). |
| NG-04 | Verify who a source is, prove affiliation, or support eligibility checks. | Would create identity data (INC-11); unlinkable credentials are future work. |
| NG-05 | Offer any feature whose purpose or effect is to identify, profile or link sources (authorship similarity, cross-report linking, device or network analytics). | P1, P6; INC-08, INC-22. |
| NG-06 | Analyze report content with server-side or third-party AI/ML, or send content to any external service (including cloud AV/sandbox). | INC-72; THR-108, THR-109. |
| NG-07 | Parse, preview, scan or detonate attachments on servers. | ADR-012. |
| NG-08 | Provide a browser-based recipient/admin UI served by the server. | ADR-007. |
| NG-09 | Contact sources by email, SMS, phone, or push; offer account recovery. | ADR-005, ADR-017; INC-05, INC-57. |
| NG-10 | Let recipients send files, links or rich content to sources (v1). | THR-105, THR-107. |
| NG-11 | Operate a voice hotline or record calls (v1). Staff may enter minutes as IDENTIFIED/CONFIDENTIAL records. | Scope; Art 18 handled via minutes. |
| NG-12 | Publish leaks or act as a publication platform. | Scope. |
| NG-13 | Guarantee legal protection for whistleblowers. | Law is jurisdiction-specific (R6). |
| NG-14 | Provide vendor access to customer content in any profile, including MANAGED. | ADR-007, ADR-020. |
| NG-15 | Provide cross-customer shared intake infrastructure. | ADR-021. |

## 10. Prohibited claims and mandatory phrasing

Applies to UI strings, documentation, marketing, sales material, RFP responses, website and support replies (enforced by `INSP:` review and a CI string-lint job `claims-lint` over all locales).

| Prohibited | Why | Use instead |
|---|---|---|
| "unhackable", "100 % secure", "airtight", "bulletproof", "military-grade" | DECISIONS §0 | "designed to resist …", "reduces the risk of …" |
| "perfectly anonymous", "completely anonymous", "untraceable", "guaranteed anonymity" | False under THR-002/003/010 | "Candor is designed so that it does not learn who you are, if you follow the guidance and your device is not compromised." |
| "anonymous" for any C-38 (clearnet) page or for CONFIDENTIAL/IDENTIFIED reports | THR-040 | "confidential — not anonymous" |
| "We cannot read your report" in Tier W | ADR-004 | "Your report is encrypted on our intake server immediately; a live-compromised intake server could read it while it is being encrypted. Use the verified app for stronger protection." |
| "end-to-end encrypted" for Tier W without qualification | ADR-004 | "encrypted on arrival" (Tier W); "end-to-end encrypted" (Tier V only) |
| "zero-knowledge", "no metadata" | Some metadata exists (`03` inventory) | "minimal metadata — see what we store" (link to the inventory) |
| "Nobody can ever find out who you are", "no one will know" | Content, behavior, network observers | Name the residual risks. |
| "Tor makes you invisible" | Tor use is visible locally (THR-002) | "Tor hides your network address from us; your employer or ISP may see that you use Tor." |
| "Your data is deleted" without qualification | ADR-025 | "Deleted by destroying its encryption keys; copies may persist on storage media until overwritten; legal holds may delay deletion." |
| "Compliant with <law>" as a product property | Compliance is organizational | "Supports <requirement> (see mapping)." |
| "Audited" without scope, date and auditor | | "Audited by X in YYYY-MM; scope; report link." |
| "No backdoors" | Unverifiable absolute | "Reproducible builds, threshold signing and a public transparency log let independent parties check that the code you run is the published code." |

## 11. Success metrics (no source tracking)

**Rule:** no metric may be computed from source-side behavior (visits, page views, funnel steps, logins, session durations, return frequency, device/browser mix, submission hour/weekday, drop-off). All metrics below are computed from staff-side case data, controlled studies, or release engineering, and every metric shown outside the case team obeys `03-PRIVACY-ANONYMITY.md` §12 (k ≥ 10 for internal program reporting, k ≥ 20 for public statistics, period normally ≥ calendar quarter).

| ID | Metric | Source of data | Target (1.0) | Privacy constraint |
|---|---|---|---|---|
| SM-01 | Acknowledgement within SLA (% of non-spam cases) | Case DB SLA fields | ≥ 95 % | k-thresholded, quarterly |
| SM-02 | Feedback within 3 months (%) | Case DB | ≥ 90 % | same |
| SM-03 | Two-way engagement rate: % of cases where the source sent ≥ 1 message after the first staff reply | Case content counts computed in Desk, aggregated | Trend only (no target) | Computed client-side by authorized user; only aggregate leaves Desk |
| SM-04 | Median time to closure by outcome | Case DB | Trend | quarterly, k ≥ 10 |
| SM-05 | First-submission task success (moderated usability study, ≥ 20 participants incl. ≥ 5 assistive-technology users) | Lab studies (`26`) | ≥ 90 % unaided | Study participants consent; no production data |
| SM-06 | Return-login task success (same study, 7-day gap) | Lab | ≥ 85 % | same |
| SM-07 | Mode comprehension: participants correctly state whether they are anonymous/confidential after completing each flow | Lab | ≥ 90 % | same |
| SM-08 | Accessibility conformance: open WCAG 2.2 AA failures at release | Audit | 0 | — |
| SM-09 | Reproducible-build agreement across ≥ 2 builders | CI | 100 % of release artifacts | — |
| SM-10 | Open critical/high findings from independent audits at release | Audit tracker | 0 critical, 0 high | — |
| SM-11 | Anonymity test suite (`30`) pass rate | CI | 100 % | — |
| SM-12 | Time-to-patch tor advisories / Candor critical CVEs | Release records | ≤ 72 h / ≤ 7 days | — |
| SM-13 | Spam share of imports | Case DB outcomes | Trend | quarterly |
| SM-14 | Adoption | Package-mirror aggregate download counts (no IP retention), voluntary operator registry, EE contracts | Trend | Mirror logs per `03` META rules |
| SM-15 | Recipient safe-handling: exports of originals as % of exports | CASE audit aggregates | ≤ 5 % | internal only |

Instance-wide operational counters (M4 buckets, `03-PRIVACY-ANONYMITY.md` §12.4) exist for abuse and health alerting only and SHALL NOT be used as success metrics.

**Prohibited metrics:** page views, unique visitors, conversion/funnel, bounce, time on page, return-visit frequency, login counts per source, submissions by hour/weekday, Tor Browser security-level distribution, JS-enabled share, locale share of sources, geographic distribution of sources.

## 12. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| PRD-001 | CE and EE SHALL build every Trust Path component (DECISIONS §2) from the same AGPL-3.0-or-later source at the same version, producing bit-identical trust-path artifacts. | ADR-020; B-CO-60; B-CO-64 | THR-024; THR-035 | C-03; C-05; C-06; C-07; C-11; C-15 | TST: CI job `edition-parity` compares trust-path artifact hashes of CE and EE builds; INSP: release checklist |
| PRD-002 | The project SHALL publish a versioned Edition Charter containing the five commitments in §5.1; any change SHALL be announced publicly ≥ 180 days before taking effect and SHALL NOT apply to already-released versions. | ADR-020; B-CO-60; B-CO-61; B-CO-62 | THR-035 | C-30 | INSP: governance review (`36-OPEN-SOURCE-GOVERNANCE.md`) |
| PRD-003 | No protection listed in §5.2 as "Yes" for CE SHALL be absent, disabled or weaker in any EE build or configuration, and no source-protection feature SHALL be introduced EE-first. | ADR-020 | THR-035 | C-06; C-07; C-15 | INSP: per-release edition diff; AUD: open-core boundary review |
| PRD-004 | EE license expiry, invalid license or unreachable licensing service SHALL disable only EE commercial modules and SHALL NOT stop intake, decryption, case access, security updates or any protection. | ADR-020; ADR-022 | THR-032; THR-114 | C-35; C-10 | TST: `license-expiry` integration test with expired and absent license files |
| PRD-005 | EE modules SHALL run only in Z-CORE, Z-ADM or Z-VENDOR, SHALL hold no private keys, and SHALL receive report content only through human-created Export Packages. | ADR-018; ADR-020 | THR-029; THR-027 | C-26; C-34; C-40 | TST: secret-placement manifest check (ADR-028); INSP: module API review |
| PRD-006 | The product SHALL offer exactly three reporting modes named ANONYMOUS, CONFIDENTIAL and IDENTIFIED with the semantics of `03-PRIVACY-ANONYMITY.md` §3, and SHALL display the current mode on every source-facing page and every case view. | ADR-002; ADR-014 | THR-040 | C-06; C-15; C-38 | TST: UI snapshot test asserts mode banner on all source routes; DEMO: mode-comprehension study (SM-07) |
| PRD-007 | ANONYMOUS mode SHALL be reachable only via the Tor v3 onion service of C-05; the product SHALL NOT offer any clearnet path labelled or implied as anonymous, and SHALL NOT fall back to clearnet when the onion is unavailable. | ADR-001; ADR-002; INC-03; B-AN-54 | THR-001; THR-040 | C-05; C-37; C-38 | TST: C-37 has no form endpoints; TST: security test — port scan of intake host shows no clearnet listener |
| PRD-008 | Tier W (no-JS web) SHALL be the default source path and SHALL be fully functional at Tor Browser "Safest"; JavaScript SHALL NOT be required for any source function. | ADR-004; INC-27; INC-28; B-SD-15 | THR-008; THR-006 | C-02; C-06 | TST: end-to-end suite runs all source journeys with JS disabled |
| PRD-009 | The source UI SHALL present the Tier W honesty statement verbatim (ADR-004) before submission, and SHALL offer Tier V (Source App or WEBCAT-verified bundle) with a one-sentence explanation of the difference. | ADR-004; INC-01; B-CR-37 | THR-007; THR-014; THR-040 | C-06 | TST: string presence test in all locales; INSP: `claims-lint` |
| PRD-010 | A tenant SHALL be able to define 1..200 channels, each with its own recipient roster, epoch keys, categories, questionnaire, SLA calendar, retention schedule and allowed modes. | ADR-008; ADR-015; B-CO-02 | — | C-10; C-14 | TST: channel CRUD integration tests |
| PRD-011 | The onion landing page SHALL show, per channel, the recipient roster as roles and key fingerprints from the key directory, and the Recovery Quorum status ("Recovery escrow: ENABLED, held by: …" or "DISABLED"). | ADR-013; ADR-015; INC-14; INC-21 | THR-046; THR-018 | C-06; C-14 | TST: landing renders roster from signed C-14 snapshot; tampered snapshot rejected |
| PRD-012 | The submission form SHALL require only a channel and either a description or ≥ 1 attachment; all other fields SHALL be optional. | B-CO-02; B-CO-12; INC-11 | THR-009 | C-06 | TST: form validation tests |
| PRD-013 | The source UI SHALL NOT contain any field requesting e-mail, phone number, postal address, social-media handle, employee ID or other contact identifier in ANONYMOUS mode, and the questionnaire editor SHALL reject such fields for ANONYMOUS channels. | ADR-005; INC-05; INC-25 | THR-034; THR-040 | C-06; C-19 | TST: questionnaire-lint unit tests with pattern corpus; INSP: UI review |
| PRD-014 | Description text SHALL be limited to 64 KiB UTF-8 (NFC-normalized) and SHALL be stored only inside the sealed envelope padded per ADR-011. | ADR-011 | THR-011; THR-015 | C-07 | TST: boundary tests at 64 KiB ± 1 |
| PRD-015 | Attachments SHALL default to ≤ 20 files and ≤ 500 MiB per submission, configurable per channel between 50 MiB and 2 GiB, with per-source-account quota default 2 GiB per rolling 30 days. | ADR-026; B-SD-09; B-SD-21 | THR-032; THR-033 | C-06; C-07; C-08 | TST: quota and limit tests |
| PRD-016 | Before file selection the UI SHALL display guidance on document metadata, printer tracking dots, photographs of screens, watermarks/canary traps and stylometry, linking to `05-SOURCE-OPSEC.md` content. | INC-16; INC-17; INC-20; B-AN-41; B-AN-34 | THR-009; THR-010 | C-06; C-03 | TST: presence test; DEMO: comprehension item in usability study |
| PRD-017 | Tier V clients SHALL strip EXIF, XMP, IPTC and MakerNote metadata from images and document-level metadata from supported formats before encryption, and SHALL show the source a list of removed fields with an opt-out per file. | INC-20; REQ-H-20 (R3); B-CR-53 | THR-009 | C-03 | TST: metadata-strip corpus test in C-03 CI |
| PRD-018 | The system SHALL generate the Source Passphrase per ADR-005, display it once, never store it, and SHALL NOT allow user-chosen passphrases or handles. | ADR-005; INC-32; B-SD-17 | THR-034; THR-100 | C-07; C-03 | TST: passphrase generator statistical test; code INSP: no persistence path |
| PRD-019 | The submission confirmation SHALL show only the UTC receipt day, next steps and a "check back after N days" hint (default 7); it SHALL NOT show a report number, exact time, or recipient names. | ADR-010 | THR-011 | C-06 | TST: confirmation page snapshot test |
| PRD-020 | A source SHALL be able to voluntarily disclose identity; doing so SHALL require an explicit confirmation screen stating the consequence, SHALL convert the report to CONFIDENTIAL, and SHALL encrypt identity data only to the Identity Custodian key set. | ADR-002; ADR-014; B-CO-02 (Art 16) | THR-040; THR-018; THR-111 | C-06; C-07; C-03; C-15 | TST: identity flow test verifies envelope structure; DEMO: comprehension |
| PRD-021 | When the onion service is unavailable, C-37 SHALL display an outage notice and, if activated, the signed standby onion address, and SHALL NOT display any submission form. | ADR-002; B-AN-26 | THR-032; THR-040 | C-37 | TST: outage-mode test of C-37 |
| PRD-022 | C-38 Confidential Clearnet Intake SHALL be disabled by default, enabling it SHALL be a DANGEROUS configuration requiring dual approval, and every C-38 page SHALL display "NOT ANONYMOUS" in the page header in the active locale. | ADR-002; INC-54 | THR-040; THR-035 | C-38; C-19 | TST: default-config test; UI string test all locales |
| PRD-023 | The source mailbox SHALL list the source's own submissions and messages and staff replies with UTC-day dates only. | ADR-010 | THR-011 | C-06; C-03 | TST: mailbox render test contains no time-of-day |
| PRD-024 | Sources SHALL be able to send follow-up messages (≤ 64 KiB) and attachments (same limits as PRD-015) from the mailbox. | Design | — | C-06; C-07 | TST: follow-up journey |
| PRD-025 | Staff replies to sources SHALL be plain text only, ≤ 64 KiB, rendered without auto-linking, HTML, images, remote resources or attachments. | INC-65; R3 theme 4 | THR-105; THR-107 | C-15; C-06; C-03 | TST: reply-render test with HTML/URL/data-URI payloads |
| PRD-026 | Replies SHALL become visible to the source only at the source's next login; the product SHALL NOT notify sources by any channel and SHALL NOT offer read receipts, typing, presence or last-seen indicators in either direction. | ADR-010; ADR-017; INC-57; B-AN-21 | THR-011; THR-028 | C-06; C-10; C-15 | TST: API has no read-state fields; INSP: schema review |
| PRD-027 | Every reply SHALL display the sending recipient's role, channel and key fingerprint, and the mailbox SHALL state that staff will never ask the source to move to another channel. | INC-21; REQ-H-21 (R3) | THR-106; THR-046 | C-06; C-15 | TST: reply view test |
| PRD-028 | Sources SHALL be able to close their mailbox, which SHALL delete the source account record and pending replies at intake within one relay cycle and tell the source that case records continue per legal retention. | B-CO-09; ADR-025 | THR-034; THR-017 | C-06; C-08; C-09 | TST: close-mailbox test verifies deletion in C-08 |
| PRD-029 | The case workflow SHALL implement the states and overlays of §7.3 with transitions defined in `14-CASE-MANAGEMENT.md`. | B-CO-01; B-CO-02 | — | C-10 | TST: state-machine property tests |
| PRD-030 | The system SHALL run an acknowledgement SLA (default 7 calendar days from import) and a feedback SLA (default 3 months from acknowledgement or from day 7), configurable per channel in calendar or business days with holiday calendars, and an external-channel extension to 6 months requiring a recorded justification. | B-CO-02 (Art 9, 11); B-CO-24 | THR-043 | C-10 | TST: SLA engine tests incl. DST/holiday cases |
| PRD-031 | All case content (notes, messages, tasks, interview records, findings, evidence) SHALL be encrypted under the case key; the server SHALL store in cleartext only the allow-listed case metadata defined in `09-DATABASE.md`. | ADR-007; ADR-008; INC-07 | THR-015; THR-018 | C-10; C-12; C-13; C-15 | TST: DB column audit test against allow-list; TST: security test — DB dump inspection |
| PRD-032 | Content search SHALL be performed only client-side in Candor Desk over a locally encrypted index. | ADR-007 | THR-015; THR-018 | C-15 | INSP: no server search endpoint in route registry |
| PRD-033 | The product SHALL NOT provide automatic correlation, clustering or similarity scoring across cases or sources (including authorship/stylometric similarity); case linking SHALL be a manual action by a user with access to both cases, recorded in CASE audit. | INC-08; REQ-H-08 (R3) | THR-019; THR-010 | C-10; C-15 | INSP: feature review; TST: link action requires both grants |
| PRD-034 | Cases SHALL support recording detriment/retaliation events, interview minutes, and source confirmation of minutes via the mailbox. | B-CO-01; B-CO-02 (Art 18, 19) | — | C-15; C-10 | TST: minutes confirmation journey |
| PRD-035 | Case access SHALL be granted only per ADR-015 (RBAC+ABAC+case ACL+COI+time-bounded grants), and system administrators SHALL hold no case keys. | ADR-015; INC-68; INC-70 | THR-018; THR-021 | C-22; C-10; C-15 | TST: authorization matrix tests; TST: security test — admin cannot decrypt any case |
| PRD-036 | Sources SHALL be able to flag "this report concerns people in these roles" from the channel's role labels; the COI filter SHALL be applied before per-member wrapping so excluded members never receive any key able to decrypt the envelope or the case, and the channel SHALL fail closed if too few eligible members remain. | ADR-015; ADR-030; ADR-033; INC-22 | THR-020; THR-110 | C-15; C-22 | TST: excluded user's key absent from wrapping set |
| PRD-037 | Category-based routing rules SHALL be able to route accounting/internal-control/audit categories directly to an audit-committee group, bypassing management roles. | B-CO-69 (SOX §301) | THR-020 | C-10; C-22 | TST: routing rule tests |
| PRD-038 | Changes to a channel roster SHALL require signatures from ≥ 2 existing members (or 1 member plus an independent co-signer when the roster has one member), SHALL be published to the key directory, and SHALL be visible to sources before their next submission. | ADR-015; INC-14; INC-62 | THR-046; THR-018 | C-14; C-15 | TST: unsigned roster change rejected by C-06/C-03; TST: security test — malicious-admin roster insertion |
| PRD-039 | Re-routing a case to another channel SHALL re-apply the destination channel's COI exclusions and SHALL be recorded in CASE audit. | ADR-015 | THR-020 | C-10; C-15 | TST: re-route test |
| PRD-040 | Servers SHALL treat attachments as opaque ciphertext and SHALL NOT parse, preview, thumbnail, scan or detonate them. | ADR-012; B-CR-56 | THR-023; THR-014 | C-06; C-07; C-08; C-10; C-13 | INSP: no parser dependencies in server crates (cargo-deny ban list); TST: security test — hostile file corpus |
| PRD-041 | Candor Desk SHALL open attachments only inside C-17 (or C-18) and SHALL record SHA-256 and BLAKE3 of each original at import inside the encrypted case record. | ADR-012; INC-65 | THR-023; THR-037 | C-15; C-17 | TST: Desk has no in-process renderer for evidence types; hash-at-import test |
| PRD-042 | Sanitized working copies SHALL be separate evidence objects linked by `derived_from` with a transformation record; originals SHALL be immutable. | ADR-012; B-CR-44 | THR-037; THR-009 | C-15; C-17 | TST: derivation record test; mutation attempt rejected |
| PRD-043 | The redaction tool SHALL rasterize or remove underlying text and SHALL block export until the verifier confirms no redacted string is extractable. | INC-19; REQ-H-19 (R3) | THR-041; THR-010 | C-17; C-15 | TST: redaction corpus test (overlay-box PDFs) |
| PRD-044 | Content SHALL leave the platform only via Export Packages; exporting originals SHALL require dual approval; every export SHALL be CASE-audited with actor, time, object hashes and destination key. | ADR-018; INC-24; INC-16 | THR-029; THR-041 | C-15; C-10; C-24 | TST: export without second approval rejected; audit event test |
| PRD-045 | Retention schedules SHALL be configurable per channel and outcome with the defaults of §7.6, and legal hold SHALL override disposition. | B-CO-02 (Art 18); B-CO-09; B-CO-12 | THR-017 | C-10 | TST: retention engine tests |
| PRD-046 | Disposition SHALL be performed by cryptographic erasure per ADR-025/ADR-033(3) (Erasure Key destruction; backups unreadable ≤ 14 days) and SHALL produce a deletion certificate. | ADR-025; ADR-033; B-CR-33; INC-55 | THR-017 | C-10; C-15; C-27 | TST: post-disposition decryption attempt fails from DB+backup restore |
| PRD-047 | Sealed envelopes SHALL be deleted from C-08 after Z-CORE acknowledgement; envelopes not imported into a case within 7 days SHALL raise an escalation to the channel's independent role. | ADR-008; ADR-009; ADR-033 | THR-015; THR-017 | C-08; C-09 | TST: envelope TTL test |
| PRD-048 | The source UI SHALL ship with ≥ 10 locales at 1.0 including ≥ 1 RTL locale, with the language carried in the URL path and no persistent language cookie. | B-CO-19; B-CO-26; Design | THR-006 | C-06 | TST: locale routing tests; RTL visual regression |
| PRD-049 | Strings tagged `critical` SHALL require two independent native-speaker reviews before release and SHALL fall back to English if missing. | THR-040; B-CO-36 | THR-040 | C-06; C-03 | INSP: translation review records; TST: missing-string fallback |
| PRD-050 | Staff UI SHALL be available in English and French at 1.0 with full parity. | B-CO-19; B-CO-26 | — | C-15; C-19 | TST: string-coverage check |
| PRD-051 | Source UI, Desk, admin console and C-37 SHALL conform to WCAG 2.2 AA and EN 301 549 v4.1.1; EE SHALL ship a formal ACR. | B-CO-28; B-CO-34; B-CO-32 | — | C-06; C-15; C-19; C-37 | TST: automated a11y checks in CI; AUD: manual accessibility audit |
| PRD-052 | The source UI SHALL be operable by keyboard only, at 400 % zoom, and with screen readers, all with JavaScript disabled. | B-CO-28 | — | C-06 | DEMO: assistive-technology usability sessions |
| PRD-053 | Source sessions SHALL warn ≥ 2 minutes before idle timeout and offer one-action extension; the UI SHALL tell the source that typed text is not saved server-side. | B-CO-28 (2.2.1); INC-23 | THR-048 | C-06 | TST: timeout warning test (no-JS meta refresh + form) |
| PRD-054 | The product SHALL NOT use CAPTCHAs; abuse controls SHALL follow ADR-026. | ADR-026; INC-46 | THR-033; THR-036 | C-05; C-06 | INSP: dependency and asset review |
| PRD-055 | Passphrase entry SHALL accept paste and either a single field or ten per-word fields. | B-CO-28 (3.3.8) | THR-034 | C-06; C-03 | TST: login input variants |
| PRD-056 | Every Tier W source page response SHALL be padded to its size class as defined in `03-PRIVACY-ANONYMITY.md`, and no source page SHALL exceed 128 KiB before padding. | ADR-011; B-AN-16; B-AN-20 | THR-004 | C-06 | TST: response-size class test |
| PRD-057 | A 10 MiB Tier W submission SHALL complete within 180 s on a Tor circuit sustaining ≥ 1 Mbit/s in the reference test harness. | Design | THR-032 | C-05; C-06; C-07 | TST: performance harness (`34`) |
| PRD-058 | CE-SINGLE SHALL support ≥ 2,000 reports/year, 50 staff users and 20 channels; EE SHALL support ≥ 100,000 reports/year, 2,000 staff users and 200 tenants per instance. | Design | THR-032 | C-10; C-12 | TST: load tests (`34`) |
| PRD-059 | Intake SHALL continue accepting submissions during a Z-CORE outage for up to 14 days (store-and-forward). | ADR-009 | THR-032; THR-042 | C-08; C-09 | TST: core-outage chaos test |
| PRD-060 | The intake onion SHALL be reachable ≥ 99.5 % per calendar month (EE-HA ≥ 99.9 %), excluding Tor-network-wide outages, measured by C-25 onion probes. | Design; B-AN-26 | THR-032 | C-05; C-25 | TST: SLO monitoring; DEMO: monthly availability report |
| PRD-061 | tor security advisories SHALL be released to all supported lines ≤ 72 h after upstream fix; Candor critical vulnerabilities ≤ 7 days; high ≤ 30 days. | INC-29; REQ-H-29 (R3) | THR-005; THR-008 | C-05; C-33 | INSP: release records vs advisory dates |
| PRD-062 | The product SHALL collect zero telemetry from source clients and source interfaces, and instance telemetry SHALL be off by default per ADR-023. | ADR-023; INC-53; INC-72 | THR-036; THR-114 | C-03; C-06; C-25 | TST: anonymity test — network capture of source journeys shows only onion traffic; TST: default config |
| PRD-063 | The source path SHALL load no script, style, font, image or other resource from any origin other than the onion itself. | INC-46; INC-53; REQ-H-46 (R3) | THR-036; THR-006 | C-06 | TST: CSP `default-src 'self'` test; crawler asserts no external origins |
| PRD-064 | CE-SINGLE SHALL be installable by a generalist Linux administrator in ≤ 2 hours following published docs, ending with a passing self-test. | ADR-028; Design | THR-035 | C-25; C-19 | DEMO: timed install study with ≥ 5 admins |
| PRD-065 | Upgrades SHALL preserve all data, SHALL limit intake unavailability to ≤ 5 minutes, and SHALL support rollback to the previous release. | ADR-022 | THR-025; THR-032 | C-33; C-05 | TST: upgrade/rollback CI job |
| PRD-066 | UI, docs, marketing and support templates SHALL NOT contain the prohibited claims of §10 in any locale. | DECISIONS §0; INC-01 | THR-040 | C-06; C-37; C-15 | TST: CI job `claims-lint`; INSP: marketing review |
| PRD-067 | The product SHALL NOT compute or display any metric derived from source-side behavior listed as prohibited in §11. | INC-53; INC-74; REQ-H-74 (R3) | THR-039; THR-036 | C-10; C-25 | INSP: metrics catalog review; TST: no source-behavior counters in schema |
| PRD-068 | Program metrics shown outside the case team SHALL obey the k-thresholds and period granularity of `03-PRIVACY-ANONYMITY.md` §12. | INC-74; REQ-H-70 (R3) | THR-039; THR-120 | C-10; C-19 | TST: small-cell suppression tests; TST: security test — differencing attack attempts |
| PRD-069 | The product SHALL NOT send report content or attachments, or hashes of them, to any external AI, antivirus, sandbox or reputation service. | INC-72; ADR-012 | THR-108; THR-109 | C-15; C-17; C-10 | TST: C-17 network-less assertion; INSP: dependency review |
| PRD-070 | The admin console SHALL display the active deployment profile and its isolation caveats, and the source "About this channel" page SHALL summarize them in plain language. | ADR-024 | THR-040; THR-035 | C-19; C-06 | TST: profile banner test |
| PRD-071 | Recipients SHALL be able to use templated acknowledgement, request-for-information, feedback and closure replies, with templates localized per channel. | B-CO-02 (Art 9) | — | C-15 | TST: template rendering |
| PRD-072 | The system SHALL display a system-generated receipt confirmation to the source at submission time (UTC day), and the channel SLA configuration SHALL state whether this counts as acknowledgement (default: it does not). | B-CO-02 (Art 9(1)(b)) | THR-011 | C-06; C-10 | TST: configuration test |
| PRD-073 | Identity unsealing SHALL require a recorded legal basis, approval by two Identity Custodians, and a templated source notice via the mailbox unless a deferral reason is recorded. | ADR-014; B-CO-02 (Art 16(3)) | THR-111; THR-018 | C-15; C-10; C-24 | TST: unseal workflow tests; AUD: custodian procedure |
| PRD-074 | Recipient onboarding SHALL include mandatory safe-handling training content (originals, printing, forwarding, cloud sync, AI assistants) acknowledged in Desk before first case access. | INC-16; INC-24; R3 theme 3 | THR-041; THR-109 | C-15 | DEMO: onboarding flow; TST: gate before first access |
| PRD-075 | The product SHALL support the AIRGAP-RCP profile in which evidence is viewed on C-18 and only sanitized derivatives leave it. | ADR-012; ADR-024; INC-16 | THR-023; THR-041 | C-18; C-15 | DEMO: newsroom workflow demonstration |
| PRD-076 | Recipient/admin interfaces SHALL be delivered only as the signed Candor Desk application and `candorctl`; servers SHALL NOT serve any browser-based staff UI. | ADR-007; INC-01 | THR-007; THR-022 | C-15; C-19; C-10 | TST: security test — route scan finds no HTML staff UI |
| PRD-077 | Program owners SHALL be able to generate a periodic program report (volumes by channel/category/outcome, SLA compliance) that is k-thresholded per PRD-068 and signed by Candor for integrity. | B-CO-01; B-CO-07 | THR-039 | C-10; C-15 | TST: report generator tests |
| PRD-078 | Success metrics SM-01..SM-15 SHALL be measurable without adding any data collection beyond `03-PRIVACY-ANONYMITY.md` inventory. | P1 | THR-036; THR-039 | C-10 | INSP: metrics-to-inventory mapping review |

## 13. Residual risks and limitations

| # | Residual risk | Why it remains | Mitigation / disclosure |
|---|---|---|---|
| RR-01 | Tier W plaintext exposure to a live-compromised intake (C-06/C-07). | No-JS web cannot encrypt client-side (ADR-004). | Honest statement; Tier V; isolated sealer; see `02` component compromise. |
| RR-02 | Sources identified by content, timing, employer monitoring, or behavior. | Outside platform control (R4 §2.2; INC-16, INC-31). | Guidance (`05`); day-granularity timestamps; no fine-grained metrics. |
| RR-03 | Visible Tor use on employer networks narrows the anonymity set to "employees using Tor". | THR-002; INC-31. | Guidance to use personal devices/networks and bridges. |
| RR-04 | Plain-text-only replies and no recipient→source files reduce convenience. | Deliberate (THR-105, THR-107). | Revisit in v2 with safe-rendering design. |
| RR-05 | No account recovery: a lost passphrase ends the source's two-way channel. | ADR-005. | Clear guidance; source may submit again (new mailbox). |
| RR-06 | Key loss if all case members lose devices and no quorum is configured. | ADR-013 default no escrow. | ≥ 2 members per case; warnings; optional quorum (THR-117). |
| RR-07 | Success metrics are coarser than conventional product analytics; product decisions rely on lab studies. | P1. | Accepted trade-off. |
| RR-08 | Compliance with jurisdiction-specific retention defaults may need legal validation. | Some retention values in R6 are UNVERIFIED (R6 line 151). | Jurisdiction packs reviewed by counsel (`25`). |
| RR-09 | iOS sources rely on Onion Browser (WebKit), weaker than Tor Browser. | R4 §3.3. | Documented as weaker; recommend other device. |

## 14. Open issues

| # | Issue | Proposed resolution |
|---|---|---|
| OI-01 | Default retention values (§7.6) mix CNIL-style norms and design choices; R6 marks some EDPS/CNIL specifics UNVERIFIED. | `25-COMPLIANCE.md` to confirm per jurisdiction; defaults remain configurable. |
| OI-02 | Whether a system receipt at submission satisfies EU Art 9(1)(b) acknowledgement varies by national transposition. | Default: does not count; jurisdiction packs may change. |
| OI-03 | Recipient→source attachments (e.g., sending a consent form) are requested by some compliance teams. | v2: only server-sanitized, re-rendered PDFs produced in C-17, never originals; requires `02` update. |
| OI-04 | Voice intake (EU Art 18(2)) is a common procurement requirement. | Out of scope v1; design study for an offline voice-to-text flow with voice anonymization on a recipient endpoint. |
| OI-05 | Locale list for 1.0 is a proposal; public-sector buyers (Canada) require EN/FR parity for staff UI which is included. | Confirm with `26-ACCESSIBILITY.md` owners. |
