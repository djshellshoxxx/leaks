# 37 — Security Audit, Disclosure and Assurance Plan
Status: Draft v1.2 (final consistency pass: ADR-047) · previously v1.1 (revision round 2: ADR-034..046) · Edition applicability: both (CE and EE share one disclosure process; EE modules audited additionally) · Owner: Security Lead (Assurance Programme), with Governance (36) for publication and funding

## 1. Purpose and scope

This document defines how Candor's security and anonymity claims are **independently checked** and how vulnerabilities are **received, fixed and disclosed**:

- external assurance activities: the pre-release penetration test, recurring independent audits, major-version audits, cryptographic review and formal verification, anonymity review, infrastructure review, supply-chain review, source-code review, reproducible-build verification, and (since round 2) the Confidential-VM (TEE) sealer profile review, the External Watcher and Operator Statement programme review, and the Key Directory governance and organisation-as-adversary controls review (A15–A17);
- responsible disclosure: the vulnerability disclosure policy (VDP), intake channels (including an anonymous onion channel), SLAs, embargoes, public advisories, the CVE process, EU CRA reporting, and a bug bounty with scope, rewards and safe harbor;
- shared disclosure across the Community and Enterprise/Government editions (ADR-020);
- the audit publication policy and a schedule by milestone.

Honest language: independent audits find some defects in a time-boxed scope. A clean audit report means the auditors did not find issues in the reviewed scope and time. It is not a certification of security.

## 2. Context and dependencies

| Document | Relationship |
|---|---|
| `DECISIONS.md` | ADR-006 (formal modelling before 1.0), ADR-020 (simultaneous CE/EE fixes; trust path public and auditable), ADR-022 (reproducible builds, threshold signing), ADR-027 (safe-path API and harness), ADR-035 (external watchers, operator statement, optional Confidential-VM sealer, IR capture approval), ADR-036/037 (directory governance, triage-first routing, blinded COI), ADR-040 (platform manifest, security floors, signer/builder spread), ADR-042/043 (Desk containment tiers, independent custody), ADR-044/045 (key-access continuity, Erasure Key Vault, organisation-as-adversary controls) |
| `40-SECURITY-ASSUMPTIONS.md` | TEE and watcher-independence assumptions whose validity A15/A16 re-check |
| `27-SECURE-DEVELOPMENT.md` | Triage and fix SLAs (§14), root-cause and regression rules (SDL-051..SDL-053), gate SG-22 (pentest), SG-21 (finding→test mapping) |
| `28-SUPPLY-CHAIN.md` | Controls audited by the supply-chain review and reproducible-build verification |
| `29-SECURITY-TESTING.md` | ST-140 (pentest), ST-141 (red team), ST-142 (LLM-assisted sweep), ST-012 (finding regression mapping) |
| `30-ANONYMITY-TESTING.md` | Compromise drills and canary results that the anonymity review re-checks |
| `31-INCIDENT-RESPONSE.md` | Actively exploited vulnerabilities and incidents escalate to IR |
| `33-RELEASE-UPDATE-SECURITY.md` | Security release channel, emergency release path |
| `36-OPEN-SOURCE-GOVERNANCE.md` | Publication authority, funding, maintainer roles |
| `38-IMPLEMENTATION-ROADMAP.md` | Milestones against which §12 schedules activities |
| `25-COMPLIANCE.md` | CRA/NIS2 and procurement evidence using audit outputs |

Research basis:
- SecureDrop's public audit history, the Trail of Bits SecureDrop Workstation assessment with 26 findings (1 High), the 7ASecurity 2024 audit, the Bugcrowd bounty, and the practice of tracking audit IDs as public issues [B-SD-13, B-SD-28, B-SD-40, B-SD-41, B-SD-43]. The same bug class recurred after audit fixes (TOB-SDW-012 → CVE-2025-24888 → CVE-2026-35465) [B-SD-33, B-SD-35].
- The SecureDrop Protocol crypto audit and formal analysis [B-SD-37, B-SD-38, B-CR-24, B-CR-25].
- GlobaLeaks' eight published audits, 2013–2026, including the 2026 LLM-adversary source audit, and its SECURITY.md SLA [B-GL-03, B-GL-13..B-GL-19].
- OnionShare ROS audit and advisories [B-OS-04].
- Dangerzone's Include Security audit [B-CR-44].
- CRA reporting and steward duties [B-CR-50, B-CR-51]; CISA Secure by Design CVE/VDP goals (R5 §C).

## 3. Programme principles

1. **Independence.** Auditors are external and have no commercial interest in the outcome. No firm performs more than two consecutive engagements of the same type (rotation).
2. **Full access.** Auditors receive the source code, threat model (02), this spec set, the lab (29 E2/E3), and the ability to talk to developers. They never receive production data or real submissions.
3. **Classes, not instances.** Every finding produces a regression test or static rule (29 ST-012) and a variant analysis (27 SDL-053). The recurrence of the path-traversal class at SecureDrop is the cautionary example.
4. **Publish.** Reports are published in full (§11).
5. **Anonymity is a first-class severity dimension** (§8.2).
6. **Trust path parity.** CE and EE are audited on the same trust-path code (ADR-020). EE modules are audited additionally for boundary violations.

## 4. Assurance activity catalogue

| Activity | Scope | Auditor qualification | Minimum effort | Trigger / frequency | Output |
|---|---|---|---|---|---|
| **A1 Pre-release penetration test** | Release candidate: source web over Tor (Tier W/V incl. RAM-only drafts and passphrase confirmation), Source App (incl. fetch-all reply retrieval), Desk + desk/admin APIs (incl. hostile-string rendering), relay and fixed-schedule import, key directory, viewer containment on every Desk platform tier (ADR-042), installer, host hardening for CE-HARDENED and EE-ONPREM; malicious-server, malicious-insider and organisation-as-adversary perspectives | Web/API/desktop/mobile pentest firm with Tor and Rust experience | 4 person-weeks (major); 1–2 person-weeks (scoped minor) | Every major RC; any minor adding attack surface (§4.1) | Report; retest letter |
| **A2 Recurring independent audit** | Rotating deep-dive across trust-path components so that every T0/T1 component is covered at least every 24 months | Security firm (different from last A2) | 6 person-weeks/year | Yearly | Report |
| **A3 Major-version audit** | Full architecture + code review of all changed T0/T1 components since the last major, plus threat-model review | Security firm + independent cryptographer | 8–10 person-weeks | Each major (1.0, 2.0, …) before GA | Report |
| **A4 Cryptographic design review** | Protocol composition (HPKE/X-Wing, epoch keys, source key derivation, key directory/transparency, STREAM + key commitment, padding), parameter choices, FIPS profile; ADR-047: chaff envelope construction and the import-time discard mechanism, Erasure-Key-derived metadata key, Source App vault format, Desk case-key cache sealing and re-wrap, per-locale wordlist entropy and normalization | Academic or specialist cryptographers (≥2 people, ≥1 external to any vendor) | 4 person-weeks | Protocol design freeze; any protocol change | Report; spec errata |
| **A5 Formal verification** | Tamarin/ProVerif models: secrecy, authentication, forward secrecy for submissions/replies/epochs, key directory consistency (incl. the 7-day snapshot freshness bound, ADR-047(4)), Desk re-wrap after vault loss (no wrap to non-ACL or excluded keys, ADR-047(7)); optional verified parsers (hax/F*/Kani) for envelope and safefs | Formal-methods group | 8–12 person-weeks initial; 2 person-weeks per protocol change | Before 1.0 (ADR-006); on protocol changes | Models (public), proof report |
| **A6 Crypto implementation review** | `candor-core` and all callers: constant-time, zeroization, nonce handling, misuse resistance, FIPS build | Crypto-engineering auditors | 3–4 person-weeks | Before 1.0; each major; change to crypto backend | Report |
| **A7 Anonymity review** | Metadata inventory vs implementation; canary harness completeness; compromise-drill answers and the generation of the drill oracle from the 03 inventory and 09 classifications (30 §6.3, ANT-034); the inferential tests and their adversary models (timing correlation, visit-day intersection, exclusion inference, all-surface small-cell/differencing: 30 §9A); timing/size/fingerprinting; fixed-schedule import and constant-schedule notifications; fetch-all reply retrieval; blinded COI; chaff indistinguishability and excluded-triage-member inference (30 AT-082, AT-087, AT-088); encrypted follow-up dates (AT-081); Source App device seizure (AT-090); Tor configuration; telemetry; aggregate outputs against 24 §TEL | Anonymity/privacy researchers (Tor/traffic-analysis background) | 3 person-weeks | Before 1.0; each major; after any SEV-1 anonymity regression | Report; updated disclosure inventory review |
| **A8 Infrastructure review** | Deployment profiles (ADR-024), host hardening baselines, secret placement (ADR-028), zone separation (ADR-009), backup design incl. Erasure Key Vault replication, erasure-log restore and the infrastructure-backup exclusion attestation (ADR-044(4)), Platform Manifest verification and security floors (ADR-040), intake no-replication settings (ADR-046(1)), the intake deletion list and its Z-CORE replica across DR and failover (ADR-047(9)), Desk re-wrap procedure (19 §11.2), H-MON without uplink and the separate `alert-relay` host (17 §4.3.2), MANAGED customer-held audit export key and verifier (ADR-047(10)), HA (EE), Kubernetes (EE-HA) | Infrastructure security firm | 3 person-weeks | Before 1.0; each new profile; each major | Report |
| **A9 Supply-chain review** | SLSA Build L3 / Source L4 assessment, builder independence, mirror controls incl. the pinned snapshot mirror for OS/tor/PostgreSQL packages and the TUF-signed Platform Manifest (ADR-040), signer and builder spread (≥ 2 organisations, ≥ 2 jurisdictions), emergency-release cooling and signer rules, security-floor issuance, CI hardening, key custody, TUF metadata practices, signing-ceremony observation, SAMM re-score | Supply-chain security specialists | 2–3 person-weeks + ceremony attendance | Before 1.0; yearly; after any keyholder or builder change | Report; ceremony attestation |
| **A10 Source-code review (incl. LLM-assisted)** | Whole trust-path code base with a human + LLM-assisted adversary model (GlobaLeaks 2026 [B-GL-19]); authorization, tenancy, mass-assignment, logic flaws | Security firm with LLM-assisted methodology, human validation of every finding | 4 person-weeks | Yearly (may be combined with A2) | Report |
| **A11 Reproducible-build verification** | Independent rebuild of release artefacts from source by a third party not operating Builder A or B; publishes attestations | Independent rebuilder (e.g. a reproducible-builds community member or partner org) | 1 person-week per major + automated per release | Every release (automated); manual per major | Signed rebuild attestation |
| **A12 EE module boundary audit** | EE commercial modules (C-26, C-34, C-35, C-36 tooling, C-40, SSO/SCIM, HA operator): verify no plaintext, keys or source-trust-path access; API usage only per ADR-020 | Security firm | 2–3 person-weeks | EE GA; each EE major | Report (published; modules are source-available to auditors) |
| **A13 Mobile Source App audit** | C-03 Android (and iOS if shipped) and desktop builds: MASVS incl. PRIVACY; Arti embedding; residue; the fixed-size encrypted vault (ADR-047(1)): no plaintext organisation identifier outside it, size invariance, unlock timing (29 ST-171, 30 AT-090) | Mobile security firm | 2 person-weeks | Before Source App GA; each major of C-03 | Report |
| **A14 Accessibility-security audit** (optional) | Assistive technology interaction with security prompts (mode warnings, passphrase display and 3-word confirmation, operator-statement banner, COI checklist) | Accessibility auditors | 1 person-week | Before 1.0 | Report (feeds 26, 30 §10) |
| **A15 Confidential-VM (TEE) sealer review** (conditional) | The optional SEV-SNP/TDX sealer profile (ADR-035(3)): measurement binding of the sealer image to a transparency-logged release; generation and binding of the sealer key inside the TEE; attestation freshness (≤ 24 h, ADR-047(4); 29 ST-173), replay and debug/migration policy checks in Desk and watcher verifiers (29 ST-156); guest hardening, interrupt/side-channel posture and firmware/TCB version policy; honesty of all source-, operator- and procurement-facing statements (never presented as a guarantee); the ASM entries in 40 | Firm or academic group with confidential-computing and side-channel expertise | 3–4 person-weeks | Before the TEE profile is offered; each major while offered; within 90 days after a published TEE break affecting supported CPUs | Report; updated ASM review |
| **A16 External Watcher and Operator Statement programme review** | ADR-035(1)(2): watcher reference implementation (code audit; fetch over Tor; coverage of static assets, templates, CSP headers and the signed running manifest; sampling against selective serving; publication path); independence of watcher organisations (≥ 2, ≥ 1 outside the operator's jurisdiction for EE/GOV/MANAGED; no shared funding/control with operator or vendor); operator-statement quorum composition (k-of-n incl. ≥ 1 independent role), 30-day renewal, banner behaviour, small-organisation disclosure (ADR-045); IR capture approval and INCIDENT_NOTICE publication (ADR-035(4)) | Security firm with web-integrity and governance experience; not itself a watcher organisation | 2–3 person-weeks | Before 1.0 GA; yearly; on any watcher-protocol change or change of watcher organisations | Report; published watcher-independence statement |
| **A17 Key Directory governance and organisation-as-adversary review** | ADR-036/037/043/044/045: time-locks (72 h; GOV/HIGH 7 days) and their clock sources; dual approval with an independent role and out-of-band `person_ref` verification; OVERSIGHT role-label certification; witness cosignature independence (≥ 2, ≥ 1 outside the operating organisation); snapshot high-water mark and independent time floor; weekly publication slot; follow-up sealing rule; Triage Set composition and triage-first enforcement; blinded COI storage (tags, padding, reason-code uniformity); break-glass independent approver; Fleet Manager restrictions; key-wrap deletion cooling-off and SCIM suspend-only; independent-custody enforcement for INDEPENDENT channels. Reviewed from the perspective of a management that controls the IdP, endpoints, mail and legal functions (RVW-C premise) | Security firm + governance/insider-threat specialist; ≥ 1 reviewer independent of any EE customer | 3–4 person-weeks | Protocol design freeze (design review); 1.0 RC (implementation review); each major; any change to directory, routing or approval code | Report |

### 4.1 When a minor release needs a scoped pentest (A1)
Any of the following:
- a new network-reachable endpoint on the source path;
- a new file format handled in C-17;
- new authentication or authorization mechanisms;
- a new deployment profile;
- new EE integration types;
- changes to C-07 sealing;
- the introduction of Tier V web delivery;
- changes to Key Directory governance, time-locks, witness handling, triage-first routing or COI blinding (also triggers A17);
- introduction of, or changes to, the Confidential-VM sealer profile (also triggers A15);
- changes to the watcher protocol, running-manifest format or operator-statement format (also triggers A16);
- changes to the fetch-all reply retrieval protocol, draft handling in C-07, or the import schedule mechanism;
- changes to the chaff schedule or discard mechanism, the Source App vault, the metadata-erasure key, the intake deletion list or the Desk re-wrap path (ADR-047; also triggers A7 for chaff and A13 for the vault).

### 4.2 Auditor selection and independence
- Written conflict-of-interest declaration.
- No auditor may be a keyholder (28), a Builder B operator, or an EE reseller. An A16 auditor may not be a watcher organisation or a directory witness; an A17 auditor may not be a directory witness for any instance whose governance evidence it reviews.
- A2/A10 firms rotate after two consecutive engagements. A4/A5 involve at least one academic or non-commercial participant.
- Contracts require (a) the right for Candor to publish the full report, (b) regression artefacts (PoCs, Semgrep/CodeQL rules) delivered with findings, and (c) an embargo period of no more than 90 days, after which publication proceeds even if fixes are pending (unfixed items are then disclosed with mitigations).

### 4.3 Audit inputs checklist (provided to auditors)
- Spec set 00–40 and DECISIONS.md.
- Threat model version.
- Previous audit reports and their fix/regression mapping.
- 29/30 latest results including drill reports, the generated drill oracle, inferential-test reports (30 §9A) and the spec-constant registry and lint results (29 ST-167).
- Watcher publications, witness cosignature logs and operator statements from the bounty lab instances (A16/A17).
- The lab environment.
- Test accounts.
- Build instructions.
- An SBOM.
- Known accepted risks (27 exceptions register).

## 5. Findings management

| Step | Rule |
|---|---|
| Tracking | Each finding receives a public tracking ID `CANDOR-AUD-<year>-<firm>-<nn>` and a private issue during embargo; made public at fix or publication (SecureDrop SEC-01-xxx pattern [B-SD-13]) |
| Severity | CVSS 4.0 base + Anonymity Impact Rating (AIR, §8.2); final = max of both mappings |
| SLA | Per 27 §14 |
| Regression | No closure without mapped test/rule (29 ST-012) and variant analysis (27 SDL-053) |
| Retest | Auditor retests Critical/High fixes; retest letter published |
| Disagreement | If Candor disputes a finding, the report publishes both positions; severity downgrade requires Security Lead + one external reviewer |

## 6. Responsible disclosure (VDP)

### 6.1 Channels
1. **Onion reporting channel.** A dedicated Candor instance run by the project (the project uses its own product), reachable via onion service. It is suitable for reporters who need anonymity, including insiders at customer organizations reporting deployment issues.
2. Email to `security@<project-domain>` encrypted to a published OpenPGP key (fingerprint published in ≥2 independent places, 28 SCM-046).
3. Private vulnerability reporting on the primary forge (GitHub Security Advisories or equivalent).
4. The bug bounty platform (§9), for reporters who want rewards.

`SECURITY.md` in each repository and `/.well-known/security.txt` (RFC 9116, Knowledge (unverified)) on the project site and C-37 list the channels. C-37 templates shipped to operators include a security.txt that points to the **operator's** contact **and** to the project VDP for software issues.

### 6.2 Service levels

| Stage | Target |
|---|---|
| Acknowledgement | ≤ 2 business days (≤ 24 h for reports marked "actively exploited" or "source deanonymization") |
| Triage with severity + AIR | ≤ 7 days |
| Fix availability | Per 27 §14 (Critical/anonymity A3 ≤ 7 days; High ≤ 30 days; Medium ≤ 90 days; Low next minor) |
| Coordinated disclosure | Default 90 days from report or at fix release + 14 days for operator updates, whichever is earlier; extensions by agreement; actively exploited issues disclosed as soon as a fix or mitigation exists |
| Reporter updates | At least every 14 days |

GlobaLeaks publishes an 8-hour acknowledgement target [B-GL-03]. Candor's 2-business-day target is deliberately conservative for a volunteer-inclusive project. It may be tightened once staffing is known (open issue).

### 6.3 Pre-notification
- Operators of any edition may subscribe to a **free** signed security-announcement list (no payment, no EE contract required). Subscription requires no onion address or instance identity.
- For Critical/A3 issues, subscribers receive advance notice up to **7 days** before public disclosure. The notice contains severity, affected versions, release date and interim mitigations, but no exploit details.
- EE customers receive **no earlier or more detailed** notice than CE subscribers (ADR-020; SAP-026).

## 7. Advisories and CVE process

- **CVE for every vulnerability** fixed in a released version, including internally found ones (CISA Secure by Design goal, R5 §C). Advisories include a CWE and a CVSS 4.0 vector.
- **CNA.** Candor applies to become a CVE Numbering Authority for its own products within 12 months of 1.0. Until then, CVEs are requested through the forge's CNA (GitHub Security Advisories) (Knowledge (unverified) that GitHub acts as CNA for hosted projects).
- **Advisory template (mandatory sections):**
  - summary;
  - affected versions/editions/profiles;
  - fixed versions;
  - CVSS 4.0 vector;
  - **AIR and an "Anonymity impact statement"**: what an attacker could have learned about sources, from which components, over which time window, written in the honest language of DECISIONS §0;
  - root cause (as SecureDrop does in its advisories, R1);
  - detection guidance and indicators, if any, including what operators can check without creating new source-linked records;
  - mitigations/workarounds;
  - credit (with the reporter's consent; pseudonyms welcome);
  - timeline.
- Advisories are published simultaneously on: the forge advisory database, the project site and its onion mirror, the signed announcement list, and OSV (via the forge).
- **Source-facing notice.** If a vulnerability may have exposed sources (A2/A3), the advisory includes plain-language text that operators are asked to show on their source landing page (C-37) and in the source UI, in all supported languages (26).

### 7.1 EU Cyber Resilience Act reporting
- CRA Article 14 reporting obligations for actively exploited vulnerabilities and severe incidents apply from **11 Sep 2026** via the ENISA Single Reporting Platform [B-CR-50, B-CR-51]. Knowledge (unverified): early warning within 24 h, notification within 72 h, final report within 14 days after a corrective measure is available.
- Role determination requires legal review [R5 §C]. The non-profit publishing the FOSS release is plausibly an *open-source software steward*. The EE vendor entity is plausibly a *manufacturer*.
- Runbook: the Security Lead determines "actively exploited" within 12 h of credible evidence and informs the legal contact. Reports are filed by each role-holder entity. Reports never include source data or customer onion addresses.

## 8. Severity model

### 8.1 CVSS 4.0
Base metrics per FIRST CVSS 4.0 (Knowledge (unverified) spec details). Environmental metrics are left to operators.

### 8.2 Anonymity Impact Rating (AIR)

| AIR | Meaning | Examples | Minimum final severity |
|---|---|---|---|
| A0 | No effect on source anonymity or metadata | Admin-only UI bug | CVSS mapping |
| A1 | Exposes metadata already in, or equivalent to, the 03 disclosure inventory, or coarse aggregates | Day-level counts visible to an unintended staff role | Medium |
| A2 | Exposes metadata beyond the inventory that narrows the anonymity set or links submissions (sub-day timing, exact sizes, linking two passphrases, client fingerprint) | Exact submission timestamp written to a log | High |
| A3 | Exposes or could expose source identity, network address, content, or credentials | IP logging; plaintext persisted; passphrase leak; targeted-update path | Critical |

## 9. Bug bounty

### 9.1 Scope

| In scope | Out of scope |
|---|---|
| Latest stable and LTS releases of all trust-path components (C-03, C-05 config, C-06..C-15, C-17, C-19, C-21..C-25, C-27 agent) | Any **customer/operator production instance** (never test against real deployments; this protects real whistleblowers) |
| The project-operated **bounty lab instances**: an onion service and a clearnet C-37 demo, clearly labelled "TEST — do not submit real information" | Social engineering of project staff, keyholders or operators; physical attacks |
| Release and update infrastructure: TUF metadata, repositories, transparency-log integration (read-only testing; no DoS) | Volumetric DoS; spam of lab intake beyond 100 submissions/day per researcher |
| Build reproducibility breaks, provenance forgery, CI configuration flaws in public repos (report-only; no exploitation of CI secrets) | Vulnerabilities only in unsupported versions (> N-2 minors) |
| EE modules (source-available) running in a vendor-provided lab | Third-party services not operated by the project; Tor network attacks requiring relay operation against real users |
| Anonymity/metadata leaks demonstrated with canary data in lab | Reports without a reproducible PoC or clear analysis; automated-scanner output without validation |

### 9.2 Rewards (USD, initial; reviewed yearly with budget in 36)

| Severity (final, §8) | Reward range | AIR A2/A3 bonus |
|---|---|---|
| Critical | 5,000 – 20,000 | +50% for A3 |
| High | 2,000 – 7,500 | +25% for A2 |
| Medium | 500 – 2,000 | — |
| Low | 100 – 500 | — |
| Supply-chain integrity bypass (e.g., getting an unlogged or under-threshold update accepted in lab) | Critical tier regardless of CVSS | — |

- For comparison, SecureDrop's Bugcrowd programme paid about $500–$2,500 [B-SD-41, R1]. Candor's higher top tier reflects the value of source-deanonymization findings, and the amounts depend on funding.
- Payment options include pseudonymous payout where the bounty platform and law allow, or donation to a charity of the researcher's choice. Candor does not require legal identity beyond what payment law requires. Reporters who want anonymity may use the onion channel without a reward.
- Duplicates: the first valid report gets the reward. Findings already known from an internal or audit tracker (with timestamped private issue) are not rewarded but are credited.

### 9.3 Safe harbor
The published VDP includes a safe-harbor statement:
- Good-faith research within scope is considered authorized. The project will not pursue or support legal action (including computer-misuse, anti-circumvention and contract claims) against researchers who follow the policy, and will state so to third parties if asked.
- Researchers must:
  - test only against lab instances or their own installations;
  - never access, modify or retain data belonging to others;
  - stop and report immediately if they encounter what appears to be **real whistleblower data or a real deployment**, delete it and make no copies;
  - avoid privacy violations and service degradation;
  - give reasonable time before disclosure per §6.2.
- The project cannot grant authorization on behalf of **operators**. Testing operator instances requires the operator's written permission, and the bounty does not cover it.
- The wording is reviewed by counsel in the jurisdictions of the steward and the EE vendor. Knowledge (unverified): disclose.io-style safe-harbor templates are the starting point.

## 10. CE/EE shared disclosure

- **One process, one advisory.** A vulnerability in shared (trust-path or other common) code is published as a single advisory listing affected CE versions, EE versions and profiles. Fixes are released to CE and EE **simultaneously** (ADR-020). EE customers get no private early fix.
- **EE-only module vulnerabilities** go through the same VDP, CVE and advisory process and are publicly disclosed (the modules are source-available, ADR-020). An advisory is never suppressed because the affected code is commercial.
- **Managed service (MANAGED profile)**: when the vendor operates instances, vendor-side incidents also follow 31. Advisories state whether managed instances were affected and when they were patched.
- **Backports** to supported CE and EE branches follow the same SLA. LTS lines are defined identically for both editions in 33.
- **Charter enforcement.** Any proposal to delay a CE fix, or to give EE customers more detailed information than CE operators, violates the Edition Charter (ADR-020) and must be refused by the Security Lead. Governance (36) records the refusal.

## 11. Audit publication policy

| Rule | Specification |
|---|---|
| What is published | Full final report of every external assurance activity A1–A17, including methodology, scope, findings, severity, Candor response per finding, and retest results |
| When | Within 30 days after all Critical/High findings are fixed and released, and **no later than 120 days after report delivery** regardless of fix status (unfixed items then published with mitigations and planned dates) |
| Redactions | Only: (a) exploit details of unfixed issues until fixed (max 90 days extra), (b) personal data of individuals, (c) any customer/operator identifying information. Each redaction is marked with a reason. No redaction of findings, severity or count |
| Where | Project site and onion mirror, repository `audits/` directory (signed commit), and the forge release attached to the fixed version |
| Summary | A plain-language summary of each report, including honest statements of limitations (scope not covered, time box) |
| Index | A public audit index with firm, dates, scope, versions, report link and finding counts by severity, in the SecureDrop/GlobaLeaks tradition [B-SD-43, B-GL-13..B-GL-19] |
| No suppression | Contracts forbid NDA terms that prevent publication. An audit that is commissioned but not published is listed in the index with the reason |

## 12. Schedule by milestone

Milestone names align with `38-IMPLEMENTATION-ROADMAP.md`. The exact milestone IDs are owned by 38.

| Milestone | Activities (must be complete before the milestone exits) | Notes |
|---|---|---|
| Protocol design freeze | A4 crypto design review; A5 initial formal models (secrecy/authentication lemmas proven, incl. follow-up sealing rule, triage-first wrapping and directory high-water mark); A17 governance design review | ADR-006 requires both before 1.0; design freeze is the cheapest time to fix |
| Alpha (internal) | A9 supply-chain review of pipeline design (builders, mirrors, key ceremonies dry run); threat-model review by A3 firm (1 week) | Keys used in alpha are TEST-ONLY |
| Beta (public, non-production) | A10 source-code review #1 (incl. LLM-assisted); A7 anonymity review #1; A8 infrastructure review (CE-SINGLE, CE-HARDENED); bounty opens on lab instances (reduced rewards 50%) | Beta release notes carry "not for real submissions" |
| 1.0 Release Candidate | A1 full pentest; A6 crypto implementation review; A5 final proofs; A11 independent rebuild; A13 Source App audit (if the Source App ships at 1.0); A17 implementation review; A7 anonymity review #2 covering the inferential tests; A14 optional | SG-22 gate |
| 1.0 GA | All reports published per §11; bounty full rewards; CNA application submitted; first root key ceremony observed by the A9 auditor; A16 watcher and operator-statement programme review complete | EE/GOV/MANAGED require ≥ 2 independent watchers (ADR-035(1)), so A16 precedes their GA at the latest |
| EE 1.0 GA | A12 EE module boundary audit; A8 for EE-ONPREM, EE-HA, PRIVATE-CLOUD; A1 scoped pentest of multi-tenancy (ADR-021) | — |
| GOV / FIPS profile GA | A6 review of CANDOR-FIPS-1 build; A8 for GOV-ONPREM and AIRGAP-RCP (incl. physical-TPM vault and Recovery Quorum default, ADR-044(3)(4)); A17 for GOV time-lock/approval settings | FIPS module validation is the module vendor's; Candor audits integration |
| MANAGED profile launch | A8 of vendor-operated infrastructure; A7 anonymity review focused on the provider-observer risk and the documented vendor union (30 AT-031/AT-032); A16 review of watcher independence from the vendor | — |
| Confidential-VM (TEE) profile offered | A15 TEE sealer review; A1 scoped pentest of attestation endpoints and verifiers | Profile SHALL NOT be offered before A15 is published |
| Every minor (1.x) | ST-142 LLM-assisted sweep; A1 scoped pentest if §4.1 triggers; A11 automated rebuild | — |
| Yearly | A2 recurring audit (rotating component focus); A10 (may merge with A2); A9 supply-chain review + SAMM re-score; A16 watcher programme review; bounty programme review | Rotation ensures every T0/T1 component is audited at least every 24 months |
| Each major (2.0, 3.0, …) | A3 major-version audit; A1 full pentest; A7 anonymity review; A17 governance review; A15 if the TEE profile is offered; A4/A5 if protocol changed; A6 if crypto backend changed | SG-22 gate |
| Event-driven | A7 after any SEV-1 anonymity regression or any inferential-test (30 §9A) failure accepted as residual; A9 after keyholder/builder change or supply-chain incident; A4/A5 on protocol change; A15 after a published TEE break affecting supported CPUs; A16 on watcher-organisation change or a published watcher mismatch; A17 on governance-code change | Within 90 days of the event |

Indicative first-year budget (1.0 cycle, excluding bounty payouts): about 62–80 external person-weeks across A1, A3–A11, A13, A16 and A17 (plus 3–4 for A15 if the TEE profile ships in the first year). This is an engineering estimate; the SecureDrop Workstation assessment by Trail of Bits alone was 6 person-weeks [B-SD-28].

## 13. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| SAP-001 | The project SHALL operate the assurance programme A1–A13, A16 and A17 (A14 optional; A15 whenever the Confidential-VM profile is offered) with the scopes, efforts and triggers in §4. | B-SD-43; B-GL-13; B-GL-19 | THR-012; THR-021; THR-023; THR-024 | C-30 | INSP: audit index vs §12 schedule; AUD: yearly A9 re-checks programme |
| SAP-002 | A pre-release external penetration test (A1) SHALL be completed on every major release candidate, and on minors meeting §4.1 triggers, with no open Critical/High findings at signing. | B-SD-28; B-SD-40; B-GL-18 | THR-021; THR-023; THR-014; THR-001 | C-06; C-10; C-15; C-03; C-17 | AUD: A1 report; TST: ST-140 status in SG-22 |
| SAP-003 | Every T0/T1 component SHALL receive an external code-level audit at least every 24 months. | B-GL-19; B-SD-43 | THR-012; THR-021; THR-023 | C-11; C-06; C-07; C-10; C-15 | INSP: coverage matrix in audit index |
| SAP-004 | A major-version audit (A3) SHALL be completed before each major GA. | B-SD-28 | THR-021; THR-014; THR-012 | C-30 | AUD: A3 report |
| SAP-005 | A cryptographic design review (A4) by ≥2 cryptographers, ≥1 external to any vendor, SHALL be completed at protocol design freeze and on every protocol change. | ADR-006; B-SD-37; INC-62; INC-63; INC-66; INC-67 | THR-012 | C-11 | AUD: A4 report |
| SAP-006 | Formal models (Tamarin/ProVerif) of the submission, reply, epoch-key and key-directory protocols SHALL be published and proven before 1.0 GA and re-verified on changes. | ADR-006; REQ-H-63; B-CR-25; B-SD-38 | THR-012; THR-046 | C-11; C-14 | AUD: A5 report; TST: ST-030 |
| SAP-007 | A crypto implementation review (A6) SHALL cover constant-time behaviour, zeroization, nonce handling and the FIPS profile before 1.0 and each major. | INC-51; INC-64 | THR-012; THR-013 | C-11 | AUD: A6 report |
| SAP-008 | An anonymity review (A7) SHALL re-check the metadata inventory, canary coverage and compromise-drill answers before 1.0, at each major and within 90 days after any SEV-1 anonymity regression. | INC-60; INC-03; REQ-H-06 | THR-001; THR-011; THR-016; THR-038; THR-039 | C-06; C-07; C-08; C-24 | AUD: A7 report |
| SAP-009 | An infrastructure review (A8) SHALL cover each deployment profile before that profile is declared GA. | ADR-024; B-SD-22 | THR-030; THR-035; THR-013 | C-05; C-25; C-27; C-39 | AUD: A8 report |
| SAP-010 | A supply-chain review (A9), including observation of the first root key ceremony and a SLSA assessment, SHALL be completed before 1.0 and yearly thereafter. | INC-37; INC-38; INC-41; B-CR-46 | THR-024; THR-025 | C-30; C-31; C-32; C-33 | AUD: A9 report and ceremony attestation |
| SAP-011 | An independent party not operating Builder A or B SHALL rebuild each major release manually and publish a signed attestation; automated independent rebuilds SHALL run for every release. | B-SD-26; B-CR-43; ADR-022 | THR-024; THR-025 | C-31 | AUD: A11 attestation; TST: ST-131 |
| SAP-012 | EE commercial modules SHALL be audited (A12) for trust-path boundary compliance at EE GA and each EE major, and the reports SHALL be published. | ADR-020 | THR-027; THR-029 | C-26; C-34; C-35; C-36; C-40 | AUD: A12 report |
| SAP-013 | The Source App SHALL be audited (A13) against MASVS including privacy before GA and at each major. | REQ-H-57; INC-57 | THR-006; THR-036; THR-048 | C-03 | AUD: A13 report |
| SAP-014 | Auditors SHALL be independent (written COI declaration; not keyholders, builders or resellers), and A2/A10 firms SHALL rotate after two consecutive engagements. | B-GL-13; B-GL-14; B-GL-18; B-GL-19 | THR-024 | C-30 | INSP: contracts and COI declarations |
| SAP-015 | Audit contracts SHALL grant the project the right to publish full reports, require delivery of regression artefacts (PoCs, rules), and limit embargo to ≤90 days. | B-SD-28; B-SD-13 | THR-024 | C-30 | INSP: contract clause review |
| SAP-016 | Auditors SHALL NOT receive production data, real submissions or production keys. | INC-56 | THR-015; THR-027 | C-30 | INSP: access records; engagement rules |
| SAP-017 | Every finding SHALL receive a public tracking ID, CVSS 4.0 and AIR severity, a mapped regression test or rule, and a variant analysis before closure; Critical/High fixes SHALL be retested by the auditor. | B-SD-13; B-SD-28; B-SD-35 | THR-021; THR-023; THR-001 | C-30 | TST: ST-012; INSP: retest letters |
| SAP-018 | Severity downgrades of external findings SHALL require the Security Lead plus one external reviewer, and disputed findings SHALL be published with both positions. | B-GL-19 | THR-024 | C-30 | INSP: finding records |
| SAP-019 | The project SHALL publish a VDP with the channels in §6.1, including an anonymous onion reporting channel operated on Candor itself, and `security.txt`/`SECURITY.md` in every repository and site. | B-SD-41; B-GL-03; REQ-H-03 | THR-001; THR-024 | C-37; C-30 | INSP: presence check job over repos and sites; DEMO: test report via onion channel quarterly |
| SAP-020 | Vulnerability reports SHALL be acknowledged within 2 business days (24 h for actively exploited or A3), triaged within 7 days, and reporters updated at least every 14 days. | B-GL-03; B-SD-41 | THR-024 | C-30 | INSP: VDP metrics report quarterly |
| SAP-021 | Coordinated disclosure SHALL default to 90 days from report or fix release + 14 days, whichever is earlier; actively exploited issues SHALL be disclosed as soon as a fix or mitigation exists. | B-SD-41 | THR-024; THR-025 | C-30 | INSP: advisory timelines |
| SAP-022 | Every vulnerability fixed in a released version SHALL receive a CVE with CWE and CVSS 4.0 vector; the project SHALL apply to become a CNA within 12 months of 1.0 GA. | R5 §C (CISA Secure by Design); B-CR-50 | THR-024 | C-30 | INSP: advisory database; CNA application record |
| SAP-023 | Advisories SHALL follow the §7 template including an anonymity impact statement in honest language and root cause, and SHALL be published simultaneously on forge, site, onion mirror and announcement list. | B-SD-33; B-SD-35; DECISIONS §0 | THR-040; THR-024 | C-37; C-30 | INSP: advisory template lint job |
| SAP-024 | For A2/A3 vulnerabilities, advisories SHALL include source-facing plain-language notice text in all supported languages for display by operators. | REQ-H-12; INC-03 | THR-040; THR-001 | C-06; C-37 | INSP: advisory review; DEMO: rendering on C-37 template |
| SAP-025 | CRA Article 14 notifications SHALL be filed via the ENISA Single Reporting Platform by the applicable role-holder entity within the regulatory deadlines, without source data or customer onion addresses. | B-CR-50; B-CR-51 | THR-024; THR-026 | C-30 | INSP: CRA runbook drill yearly; legal review record |
| SAP-026 | CE and EE SHALL share one disclosure process and one advisory per vulnerability; fixes SHALL be released simultaneously and EE customers SHALL NOT receive earlier or more detailed notice than CE announcement-list subscribers. | ADR-020 | THR-024; THR-025 | C-32; C-33 | INSP: release timestamps per edition; AUD: A9 |
| SAP-027 | Vulnerabilities in EE-only modules SHALL be disclosed publicly through the same process. | ADR-020 | THR-027; THR-029 | C-26; C-34; C-35; C-40 | INSP: advisory database |
| SAP-028 | A free, signed security-announcement list SHALL provide up to 7 days' pre-notification for Critical/A3 issues to any operator without requiring payment or instance identification. | ADR-020; ADR-022 | THR-025 | C-33 | INSP: list configuration; DEMO: test announcement |
| SAP-029 | The project SHALL run a bug bounty with the scope, reward tiers and exclusions in §9, including a prohibition on testing operator instances and a stop-and-report rule for real whistleblower data. | B-SD-41 | THR-001; THR-015; THR-021 | C-30; C-37 | INSP: published bounty policy; yearly programme review |
| SAP-030 | The project SHALL operate dedicated, clearly labelled bounty lab instances (onion and clearnet demo) that contain only synthetic data. | B-SD-41 | THR-015 | C-05; C-06; C-37 | INSP: lab configuration; AT-001 run on lab instance |
| SAP-031 | The VDP SHALL include a counsel-reviewed safe-harbor statement covering good-faith research within scope. | B-SD-41; B-GL-03 | THR-024 | C-30 | INSP: legal review record |
| SAP-032 | Researchers SHALL be able to report pseudonymously and to receive rewards pseudonymously or as charitable donations where law allows. | REQ-H-05 | THR-001 | C-30 | INSP: bounty platform settings |
| SAP-033 | Full audit reports SHALL be published within 30 days after Critical/High fixes are released and no later than 120 days after delivery, with redactions limited to §11 categories and each redaction justified. | B-SD-43; B-GL-13; B-GL-19; B-CR-44 | THR-024 | C-37; C-30 | INSP: audit index dates vs delivery dates |
| SAP-034 | A public audit index SHALL list every commissioned assurance activity, including unpublished ones with reasons. | B-SD-43 | THR-024 | C-37 | INSP: index completeness vs contracts |
| SAP-035 | Assurance activities SHALL be scheduled per §12 and a milestone SHALL NOT exit while its required activities are incomplete. | ADR-006 | THR-012; THR-024 | C-30 | INSP: milestone exit checklist (38) |
| SAP-036 | An LLM-assisted source audit sweep (ST-142) SHALL run for each minor release with human triage of every candidate finding. | B-GL-19 | THR-021; THR-023 | C-30 | TST: ST-142 triage completion |
| SAP-037 | The assurance programme, VDP metrics and bounty statistics SHALL be summarized in a yearly public transparency report, with aggregate counts only. | B-SD-43; REQ-H-74 | THR-024; THR-039 | C-37 | INSP: published report |
| SAP-038 | Before the optional Confidential-VM sealer profile is offered, and at each major while it is offered, an independent review (A15) SHALL assess measurement binding to logged releases, in-TEE key generation, attestation verifier logic in Desk and watchers, TCB/firmware policy and side-channel posture, and SHALL confirm that no source-facing text presents the TEE as a guarantee; a published TEE break affecting supported CPUs SHALL trigger A15 within 90 days. | ADR-035; RVW-A-01 | THR-014; THR-026; THR-007 | C-07; C-15; C-25 | AUD: A15 report; TST: 29 ST-156 |
| SAP-039 | The External Watcher and Operator Statement programme SHALL be reviewed (A16) before 1.0 GA, yearly, and on any change of watcher protocol or watcher organisations, including code audit of the reference watcher, verification of watcher independence (≥ 2 organisations, ≥ 1 outside the operator's jurisdiction for EE/GOV/MANAGED) and of operator-statement quorum composition; the review SHALL publish a watcher-independence statement. | ADR-035; ADR-045; RVW-A-01; RVW-A-13; RVW-C-04 | THR-007; THR-014; THR-025; THR-026 | C-06; C-07; C-14; C-37 | AUD: A16 report; TST: 29 ST-154; ST-155; ST-157 |
| SAP-040 | Key Directory governance and organisation-as-adversary controls SHALL be reviewed (A17) at protocol design freeze, at 1.0 RC, at each major and on any change to directory, routing, COI or approval code, from the perspective of a management that controls the IdP, endpoints, mail and legal functions. | ADR-036; ADR-037; ADR-043; ADR-044; ADR-045; RVW-A-04; RVW-A-05; RVW-A-08; RVW-B-01; RVW-B-02; RVW-C-01; RVW-C-03; RVW-C-05; RVW-C-09; RVW-C-10 | THR-018; THR-020; THR-046; THR-043 | C-10; C-14; C-15; C-21; C-22; C-34 | AUD: A17 report; TST: 29 ST-146..ST-152; ST-162..ST-164 |
| SAP-041 | Auditors of A16 SHALL NOT be watcher organisations or directory witnesses, and auditors of A17 SHALL NOT act as directory witnesses for instances whose governance evidence they review. | ADR-035; ADR-036 | THR-026; THR-046 | C-30 | INSP: COI declarations |
| SAP-042 | The anonymity review (A7) SHALL assess the adversary models and thresholds of the inferential tests (30 §9A) and the generation of drill oracles from the 03 inventory, and SHALL report any inferential residual that the project has accepted. | RVW-B-29; ADR-038; ADR-046 | THR-011; THR-039; THR-020 | C-08; C-12; C-24 | AUD: A7 report; TST: 30 AT-080..AT-085 |
| SAP-043 | The infrastructure (A8) and supply-chain (A9) reviews SHALL cover, respectively, the Erasure Key Vault replication/restore/erasure-log path and the infrastructure-backup exclusion attestation, and the Platform Manifest, pinned package mirror, security-floor issuance and the ≥ 2-organisation / ≥ 2-jurisdiction signer and builder spread. | ADR-040; ADR-044; RVW-A-12; RVW-A-16; RVW-C-06; RVW-C-07; RVW-C-17 | THR-017; THR-024; THR-025 | C-12; C-27; C-31; C-32; C-33; C-39 | AUD: A8 and A9 reports; TST: 29 ST-153; ST-158; ST-159 |
| SAP-044 | The ADR-047 controls SHALL be in audit scope before 1.0 GA: chaff construction and discard, metadata-erasure key, vault format, re-wrap and wordlists in A4; freshness bound and re-wrap in A5; chaff, encrypted follow-up dates and device seizure in A7; deletion list, re-wrap, alert-relay and MANAGED audit key in A8; the Source App vault in A13; attestation freshness in A15. | ADR-047 | THR-020, THR-017, THR-048, THR-027, THR-046 | C-03, C-07, C-08, C-10, C-15, C-24 | AUD: A4, A5, A7, A8, A13, A15 reports; INSP: scope letters list the ADR-047 items |

## 14. Residual risks and limitations

- **Audits are time-boxed samples.** Bugs survive audits. SecureDrop's path-traversal class recurred after audit fixes, and GlobaLeaks shipped authorization bugs after eight audits [B-SD-33, B-SD-35, B-GL-37]. The programme relies on regression rules and continuous testing (29/30) between audits.
- **Formal proofs cover models, not code.** Implementation divergence is caught only by review, KATs and differential tests.
- **Funding dependence.** Rewards and audit cadence depend on budget (36). Underfunding would lengthen intervals. SAP-035 makes milestone exit depend on completed audits, so a budget shortfall delays milestones rather than silently skipping audits.
- **Bounty lab realism.** Lab instances do not reproduce operator-specific configurations. Operator misconfigurations are out of bounty scope and rely on the config checker and operator audits.
- **Legal safe harbor is limited.** The project cannot bind operators or prosecutors. Researchers in some jurisdictions may still face legal risk.
- **CRA role and deadline details** are pending legal review, and the 24 h/72 h/14 d timelines above are Knowledge (unverified).
- **TEE reviews age quickly.** A15 assesses a TEE profile against known side channels at review time; new breaks can invalidate it between reviews. The TEE is defense in depth only (ADR-035(3)).
- **Watchers and governance can be captured.** A16 verifies stated independence and code; it cannot detect a watcher organisation that is secretly compelled or colluding, nor can A17 stop collusion among independent approvers. These are recorded as assumptions in 40.
- **Audits of attested infrastructure rely on attestations.** A8 can check that the backup-exclusion attestation workflow exists and is enforced by the checker, not that a customer's hypervisor team told the truth (ADR-044(4)).
- **Pre-notification risk.** Advance notice to subscribers could leak before public disclosure. It is limited to non-exploit details and 7 days.

## 15. Open issues

1. Staffing model for 24/7 acknowledgement of A3/actively-exploited reports: volunteer rotation vs EE vendor security team. EE staffing must not create CE/EE disparity (SAP-026).
2. Choice of bounty platform vs self-hosted programme, including support for pseudonymous payouts.
3. Legal entity mapping for CRA roles (steward vs manufacturer) and who files which reports.
4. Whether A5 extends to verified implementations (hax/F*, Kani) of envelope parsing and `candor-safefs` before 2.0.
5. Coordinate milestone names and IDs with 38 once RM- IDs are fixed.
6. Tighten the acknowledgement SLA (cf. GlobaLeaks 8 h [B-GL-03]) once staffing is known.
7. Identify candidate watcher organisations and A16 auditors early enough that EE/GOV/MANAGED GA is not blocked (coordinate with 36 for funding).
8. Availability of firms with confidential-computing and side-channel expertise for A15; if none is available, the TEE profile is not offered.

### Open Issues for ADR revision
- None. Conforms to DECISIONS.md. Suggest adding to ADR-020 an explicit rule that the pre-notification list is edition-neutral (SAP-026/SAP-028), so that commercial pressure cannot erode it later.
