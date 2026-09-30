# 25 — Compliance Layer and Control Mapping
Status: Draft v1.1 (revision round 2: ADR-034..046) · Edition applicability: both (CE: mapping and starter packs; EE: certified packs, evidence automation) · Owner: Compliance Engineering (with Legal)

## 1. Purpose and scope

This document defines:
- the **configurable compliance layer**: jurisdiction-aware clocks, notices, retention, exemptions and templates, delivered as compliance packs;
- **control mappings** from external frameworks and laws to Candor features, the customer's responsibilities, and evidence artifacts.

**Language rule (binding).** Candor never claims that using it makes an organization compliant. Mappings show *how Candor features can support* an obligation. Compliance is achieved by the deploying organization's policies, people and processes, assessed by its own auditors or counsel. Every UI, document and marketing text is checked for the prohibited claims list (COMP-001).

Research basis: R6 (B-CO-*), R5 (B-CR-47..51 for SSDF, CRA, CNSA), R3 incidents. R6 verification tags carry over:
- items marked [K] or UNVERIFIED in R6 remain so here;
- they require counsel confirmation before being relied upon.

## 2. Context and dependencies

| Topic | Document |
|---|---|
| Government profile | `22-GOVERNMENT.md` |
| EE evidence automation; enterprise integrations | `21-ENTERPRISE.md` (E21, E23, §8.1) |
| Revision controls mapped here | `DECISIONS.md` ADR-034..ADR-046 (§4–§6 rows cite them; COMP-025) |
| Metrics regime (single source) | `24-LICENSING-BUSINESS-MODEL.md` §TEL (ADR-046(5)) |
| CE starter packs | `23-COMMUNITY-EDITION.md` F28 |
| Accessibility | `26-ACCESSIBILITY.md` |
| Secure development / supply chain | `27-SECURE-DEVELOPMENT.md`, `28-SUPPLY-CHAIN.md` |
| Incident response / breach notification | `31-INCIDENT-RESPONSE.md` |
| Retention | `35-DATA-RETENTION-DELETION.md` |
| Governance, CRA | `36-OPEN-SOURCE-GOVERNANCE.md` |
| Audit | `37-SECURITY-AUDIT-PLAN.md` |
| Traceability | `39-REQUIREMENTS-TRACEABILITY.md` |

Requirement-prefix references in the mapping tables (e.g., `ANON-*`, `CRYPTO-*`, `CASE-*`) refer to the owning documents per DECISIONS §3.

## 3. Compliance layer architecture

```mermaid
flowchart LR
  P[Compliance pack: signed data bundle] --> L[Pack loader: AGPL, schema allow-list]
  L -->|clocks, calendars| SLA[SLA engine C-10]
  L -->|retention schedules| RET[Retention engine C-10]
  L -->|notices, external channels| UI[Source UI templates C-06 / Info site C-37]
  L -->|exemption tags, restriction codes| CASE[Case records C-10/C-12]
  L -->|DPIA/PIA/ROPA/SORN templates| DOC[Document generator C-19]
  L -->|report catalogue definitions| REP[Stats reports C-10, k-threshold enforced]
  L -.x.->|FORBIDDEN| CFG[Anonymity / logging / crypto / network config]
```

## 4. Control mapping: whistleblowing standards and law

Legend:
- Candor features cite ADRs and requirement prefixes.
- "Evidence" names the artifact an auditor receives.
- R6 WB-nn IDs (draft control catalogue) are used for traceability.

### 4.1 ISO 37002:2021 (guidance; not certifiable, B-CO-01)

| Clause | Candor features / requirements | Customer responsibility | Evidence artifact |
|---|---|---|---|
| 4 Context / scope (who can report) | Channel configuration for reporter categories (employees, contractors, suppliers, public); CASE-* | Define scope and publish the policy | Channel configuration export; policy document |
| 5 Leadership: independent function | Triage-first routing to independent-role Triage Sets and blinded COI (ADR-037); independent-role approvers for break-glass, roster changes and IR capture; Fleet cannot change routing; small-organisation mode with external OVERSIGHT (ADR-035(4), ADR-036(2), ADR-045); independent-custody recipient devices (ADR-043); admin ≠ case access; CASE-*, ROUTE-*, AUTHZ-* | Appoint the function; board oversight; fund independent devices and external parties | Role roster; Triage Set roster; custody status report; COI map export (pseudonymous); AUTHZ test reports |
| 7.5 Documented information and confidentiality | E2E encryption (ADR-006..008); audit (ADR-016); intake integrity evidence: External Watchers, Operator Statement, Key Directory witnesses (ADR-035, ADR-036); CRYPTO-*, LOG-* | Document-control procedures; arrange watchers | Crypto audit report; audit-chain verification output; watcher reports; Operator Statement history |
| 8.1 Receiving | Onion intake, multi-channel, acknowledgement SLA; ANON-*, SUI-* | Staff intake of oral reports | SLA report (k-thresholded) |
| 8.2 Assessing (incl. detriment risk) | Triage form with detriment-risk assessment; CASE-* | Perform assessments | Case template export |
| 8.3 Addressing (protection) | Sealed identity (ADR-014); retaliation check-ins; key-access continuity against suppression (ADR-044(1)(2)); CASE-* | Investigate; protect the reporter | Workflow configuration; unseal-event audit (SECURITY class); wrap-deletion approvals |
| 8.4 Concluding (feedback, post-closure monitoring) | Feedback timer; post-closure check-in schedule; CASE-* | Give feedback | SLA report |
| 9 Performance evaluation | KPI catalogue under the `24-LICENSING-BUSINESS-MODEL.md` §TEL regime (ADR-046(5)) | Management review | KPI report |
| 10 Improvement | Corrective-action register (EE) | Run corrective actions | Register export |

### 4.2 EU Directive 2019/1937 (B-CO-02, [K] article text)

| Article | Candor features / requirements | Customer responsibility | Evidence artifact |
|---|---|---|---|
| Art 6(2) anonymous reports | ANONYMOUS channel toggle (default on); ADR-002 | Decide per national law | Configuration export |
| Art 8(5)/(6)/(9) third-party operation, shared resources, municipal sharing | MANAGED profile with confidential-VM or Tier-W-off option, customer-held audit and backup keys, transparency reports (ENT-041..ENT-043); EE multi-tenancy with OVERSIGHT-signed risk classification (ADR-021; TEN-*) | Contracts (GDPR Art 28); retain follow-up duties | DPA template; tenant isolation test report (TEN-*); compelled-disclosure inventory (ENT-025) |
| Art 9(1)(a) secure design, confidentiality incl. third parties | ADR-006..009, -014..016; Tier W RAM-only drafts (ADR-034); intake integrity evidence (ADR-035); fixed import slots and constant-schedule notifications (ADR-038); fetch-all replies (ADR-039); independent custody (ADR-043); ANON-*, CRYPTO-*, AUTHZ-* | Access policy; staff training; keep integrations within `21-ENTERPRISE.md` §8.1 | Audit reports; AUTHZ matrix tests; anonymity test reports (30) |
| Art 9(1)(b) 7-day acknowledgement | SLA engine (CE-006); pack clock `ack=P7D calendar` | Acknowledge | SLA report |
| Art 9(1)(c) impartial person; follow-up communication | Triage-first routing (ADR-037); COI routing; two-way mailbox | Designate person | Role roster; Triage Set roster |
| Art 9(1)(f) feedback ≤ 3 months | Feedback clock anchored to acknowledgement or day 7. Feasibility depends on: a reachable mailbox (source accounts created after the last intake backup can be lost in intake DR, `19-BACKUPS-DR.md`); a channel that is not closed by COI exhaustion (redirect to an alternative independent channel, ADR-037(1)); and ≥ 2 key holders (ADR-044(2)) | Give feedback; staff the alternative channel | SLA report; channel-availability report |
| Art 9(1)(g) external-channel information | Pack content blocks: competent authorities per member state | Keep content current | Rendered landing page snapshot |
| Art 9(2) oral reporting and meetings | Staff-entered reports with `channel_of_origin`; meeting-request workflow; voice upload (best-effort distortion labelled) | Staff the phone line | Workflow configuration |
| Art 11 external channels (3 or 6 months) | Justified-extension flag | Authority procedures | SLA report |
| Art 12(1),(4) integrity; forward without modification | Immutable originals with hashes (ADR-012); Export Package with hash manifest | Forward promptly | Custody records; manifest |
| Art 16 identity confidentiality; notice before disclosure | Sealed Identity Store and unseal workflow with notice/deferral (ADR-014) | Legal-basis decisions | Unseal audit events |
| Art 17 purge irrelevant data | "Mark irrelevant → purge" action (crypto-erasure, ADR-025); DEL-*. The ≤ 14-day backup bound holds **only** if infrastructure backups exclude the Erasure Key Vault (ADR-044(4); HA-018) | Triage decisions; attest backup exclusion | Deletion audit (content-free); backup-exclusion attestation |
| Art 18 records; transcripts with reporter check | Case register; transcript review via mailbox; see §6.1 for what retention is technically feasible | Retention policy | Register export; retention configuration; records-feasibility statement (COMP-027) |
| Art 22 persons concerned | Confidentiality flags on subjects; COI | Subject-rights process | AUTHZ tests |
| Art 27 statistics | Statistics export under the 24 §TEL regime (EE regulator mode) | Report to authority | Statistics report |

### 4.3 GDPR (B-CO-09 [K]; EDPS B-CO-10; CNIL B-CO-12)

| Article | Candor features / requirements | Customer responsibility | Evidence artifact |
|---|---|---|---|
| Art 5 (minimization, storage limitation) | ADR-010 day-granular timestamps; fixed import slots, no per-case activity-day lists (ADR-038); ADR-016; retention engine; META-*, PRIV-*, RET-* | Define purposes and retention | Data-flow report (generated); retention configuration |
| Art 6, 9, 10 lawful basis | Pack lawful-basis register template | Choose the basis | ROPA export |
| Art 14(5)(b) deferred notice to persons concerned | Deferred-notice timer with reason | Decide deferral | Case audit (CASE class) |
| Art 15, 15(4), 23 access and restrictions | Locating personal data is done by Desk-local search over cases the searcher can decrypt, by an authorized member or a Records Custodian with Triage-Set grants; there is no server-side search (ADR-044(5); ENT-045). DSAR restriction workflow (CE F23) | Apply national restrictions; ensure a Records Custodian is granted all in-scope cases | DSAR decision log; completeness report |
| Art 25 privacy by design and default | No third-party resources; no telemetry by default (ADR-023); no IP logging | Keep defaults | CSP and header test reports; telemetry status |
| Art 28 processor | MANAGED DPA template; subprocessor register; compelled-disclosure inventory incl. live capabilities (ENT-025) | Sign the DPA | DPA; subprocessor list; inventory |
| Art 30 ROPA | ROPA generator from the data model | Complete and maintain | ROPA export |
| Art 32 security | CRYPTO-*, AUTH-*, BAK-*, ST- tests | Operate securely | Audit reports; test reports |
| Art 33/34 breach notification (72 h) | IR runbook with an identity-exposure severity class (IR-*); scoping of affected **persons concerned** (accused, witnesses) is performed by case members in their Desks, because servers cannot read content (COMP-028) | Notify; keep case members reachable within 72 h | IR records; scoping attestation |
| Art 35 DPIA | DPIA template per edition and profile | Perform the DPIA | Completed DPIA |
| Ch. V transfers | Residency pinning; `staff_region` transfer gate (ENT-027) | Transfer instruments | Configuration; approval records |

## 5. Control mapping: security frameworks

### 5.1 NIST CSF 2.0 (B-CO-42 [K])

| Function | Candor features / requirements | Customer responsibility | Evidence artifact |
|---|---|---|---|
| GV Govern | Edition Charter; governance (OSG-*); compliance packs | Risk strategy; roles | Charter; governance records |
| ID Identify | Component catalogue (C-01..C-40); SBOM (SCM-*); data-flow report | Asset inventory | SBOM; data-flow report |
| PR Protect | CRYPTO-*, AUTH-*, AUTHZ-*, INFRA-*, DEP-* | Configure; train | Configuration checker output; audits |
| DE Detect | Self-test (C-25); audit chain; SIEM export (EE) | SOC monitoring (scoped per ADR-016) | Self-test history; SIEM canary results |
| RS Respond | IR-* runbooks; content-free alerts | Execute IR | IR records |
| RC Recover | BAK-*, DR-*; restore tests | DR drills | Restore-test records |

### 5.2 NIST SP 800-53 Rev 5, Release 5.2.0 (B-CO-40)

| Control | Candor features / requirements | Customer responsibility | Evidence artifact |
|---|---|---|---|
| AC-2, AC-3, AC-6 | RBAC+ABAC+ACL+COI (ADR-015); triage-first (ADR-037); suspend-only SCIM/HR/SOAR (ENT-016, ENT-032, ENT-033; ADR-044(1)); AUTHZ-* | Account management | AUTHZ matrix test report |
| AC-5 separation of duties | Dual control with independent-role approvers (ADR-036(2), ADR-045); small-organisation mode with external party (SMB-014, GOV-037) | Staff distinct persons or engage an external party | Role roster; person-binding records; mode status |
| AC-6(9), AU-2, AU-9, AU-10 | Hash-chained, signed audit (ADR-016); LOG-*, AUD-* | Review logs | Chain verification output; checkpoint signatures |
| AU-3 (content), AU-11 | Allow-list schema; class-based retention | Retention policy | Schema; retention configuration |
| CM-2, CM-6, CM-7 | Config checker; CFG classes SAFE/ADVANCED/DANGEROUS (ADR-046(6)); fleet-settable key allow-list (ENT-008) | Baseline approval | Checker reports |
| CM-3, CM-5 change control | Key Directory time-locks and independent approval for roster, role-label and COI changes; weekly publication slot (ADR-036) | Approve changes | Key Directory history; approval records |
| CP-9, CP-10 | Encrypted backups, k-of-n (BAK-*); HA/DR (HA-*); Erasure Key Vault replicated to DR and erasure log applied on restore (HA-017; ADR-044(4)); key-holder continuity drill (HA-019); ≥ 2 key holders and ≥ 2 authenticators (ADR-044(2)) | Drills; disperse custodians | Restore-test records; quorum-reachability drill records |
| IA-2(1),(2), IA-5 | WebAuthn/FIDO2; PIV (B-CO-41); AUTH-* | Credential issuance | Auth configuration; AAL mapping |
| IR-4, IR-6 | IR-*; intake capture requires an independent approver and a source-visible notice (ADR-035(4)); IR-6 indicators never include source IPs (they do not exist) | Execute; report | IR records |
| RA-5 | ST-* tests; public advisories (OSG-*) | Patch | Scan reports; update-lag status |
| **SA-15(13)** (5.2.0 new) | Developer testing evidence published per release (SDL-*) | Review | Release test evidence bundle |
| **SA-24** (5.2.0 new) | Design for cyber resiliency: intake/core separation, fail-closed, crypto-erasure (ADR-009, -025) | — | Architecture document; audit |
| **SI-2(7)** (5.2.0 new) | Signed, verified updates; update-lag alerts (ADR-022; UPD-*; ENT-040) | Apply updates | TUF metadata; update logs |
| SI-7, **SI-7(12)** (revised) | Reproducible builds; integrity verification; transparency log (REL-*, SCM-*); TUF-signed Platform Manifest verified by self-test and signed security floor (ADR-040); External Watchers compare served assets and Sealer running manifest with the log (ADR-035(1)); optional confidential-VM Sealer attestation (ADR-035(3)) | Verify; arrange watchers | Rebuild attestations; watcher reports; Platform Manifest check output |
| SC-7 | Zones; no inbound Z-INTAKE→Z-CORE (ADR-009); INFRA-* | Network enforcement | Firewall configuration; reachability tests |
| SC-8, SC-13, SC-28 | HPKE/AEAD (ADR-006); FIPS profile; inner FIPS TLS for Desk↔Core in FIPS-mandated deployments (GOV-032); Tier W preselected off in CJIS/FIPS-mandated GOV (GOV-028); CRYPTO-*. Tor is outside the boundary (§5.7) | Choose profile; record Tier W determination | Crypto audit; CMVP certificate reference; GOV-011 determination |
| SC-12 | Key hierarchy (ADR-008); KEY-*; Recovery Quorum default-enabled in GOV (ADR-044(3)) | Ceremonies; appoint independent custodians | Ceremony records; custodian roster |
| MP-6 media sanitization | Crypto-erasure (ADR-025); vault excluded from hypervisor/SAN backups, physical TPM for HIGH/GOV (ADR-044(4); HA-018) | Attest backup exclusions | Destruction certificates; exclusion attestations |
| AU-2, AU-6, AU-12, SI-3, SI-4, RA-5 on Z-INTAKE | Alternative implementation (§5.7) | Accept tailoring in the SSP | Tailoring annex |
| SR-3, SR-4, SR-11 | Supply chain (SCM-*); SBOM; SLSA; pinned snapshot platform mirror; signers and builders across ≥ 2 organisations and ≥ 2 jurisdictions (ADR-040; OSG-*) | Supplier assessment | SBOM; provenance; signer-custody attestation |
| PS-3 | — | Personnel screening (CJIS) | HR records |
| SA-9 external system services | External Watchers and Key Directory witnesses from the Foundation registry (ADR-035(1), ADR-036(5); `36-OPEN-SOURCE-GOVERNANCE.md`) | Select watchers; review their reports | Watcher/witness agreements; published mismatch reports |

### 5.3 NIST SSDF SP 800-218 v1.1 / Rev 1 IPD (B-CR-47, B-CR-48)

| Practice group | Candor features / requirements | Customer responsibility | Evidence artifact |
|---|---|---|---|
| PO (prepare the organization) | SDL-* policy; governance (OSG-*) | — | SDL policy |
| PS (protect the software) | Signed commits; protected branches; threshold signing (REL-*, SCM-*) | — | Repository settings export; signing logs |
| PW (produce well-secured software) | Rust memory safety (ADR-019); ASVS L3; fuzzing; malicious-server harness (ADR-027) | — | Test reports |
| RV (respond to vulnerabilities) | CNA and advisory process (OSG-*) | Apply fixes | Advisories; CSAF/VEX |
| Attestation form | Optional after OMB M-26-05 (B-CR-48); provided by EE | Collect if required | Signed attestation |

### 5.4 Cryptography requirements

| Requirement | Candor features | Customer responsibility | Evidence artifact |
|---|---|---|---|
| FIPS 140-3 (B-CO-49; B-CR-11, B-CR-12) | CANDOR-FIPS-1 via a validated module (AWS-LC FIPS); approved-mode self-tests. Open: the key-privacy assumption for MLKEM1024-P384 anonymous recipient slots (ADR-033(1)) must be recorded in `40-SECURITY-ASSUMPTIONS.md` before the anonymous-slot property is claimed in the FIPS profile (RVW-C-15) | Deploy the FIPS build; keep the module version aligned with the certificate | CMVP certificate number; build manifest showing the module hash |
| FIPS 140-2 sunset (Sept 2026, UNVERIFIED exact date) | No 140-2-only modules in the FIPS profile | — | Module list |
| CNSA 2.0 (B-CR-10) | Not an NSS. MLKEM1024, AES-256, SHA-384 available. ML-DSA-65 in release roots (ADR-006). | Determine applicability | Profile document |
| PQC migration (OMB M-26-15, B-CR-04; NIST IR 8547, B-CR-03) | Hybrid PQ now (ADR-006) | Agency PQC plan | CBOM (CycloneDX) |
| CCCS guidance (Canada) (Knowledge (unverified)) | NIST-approved algorithms in the FIPS profile | Confirm with CCCS guidance | Crypto profile document |

### 5.5 Canada ITSG-33 / PBMM (B-CO-48)

| Control area | Candor features | Customer responsibility | Evidence artifact |
|---|---|---|---|
| ITSG-33 control catalogue (derived from 800-53) | Same as §5.2 | Security assessment and authorization (SA&A) | ITSG-33 mapping (EE) |
| PBMM cloud profile | PRIVATE-CLOUD/MANAGED in a Canadian region; residency (GOV-014) | Cloud-provider assessment | CCCS assessment (provider); Candor mapping |

### 5.6 US programs

| Program | Candor features | Customer responsibility | Evidence artifact |
|---|---|---|---|
| FedRAMP 20x (B-CO-43) | MANAGED only: machine-readable KSI evidence (OSCAL); boundary and inherited-risk annex (§5.7) | Agency ATO; accept Tor as an external overlay | KSI evidence feed; annex |
| GovRAMP (B-CO-44) | MANAGED state/local | Agency authorization | Package |
| CMMC 2.0 / SP 800-171 (B-CO-45) | Controls in §5.2 subset; CUI handling guidance (`22-GOVERNMENT.md`) | Contractor assessment | 800-171 mapping |
| CJIS v6.0 (B-CO-46) | GOV-018; GOV-028; GOV-032; MFA; FIPS; audit; tailoring annex (§5.7) | Screening; agency policies | CJIS addendum mapping |

### 5.7 Control tailoring and boundary annex (SSP-ready; RVW-C-12, RVW-C-15)

Published per release as part of the EE evidence set (COMP-026). It states where Candor meets a control by **alternative implementation** because the conventional implementation would defeat source protection.

| Control / expectation | Conventional implementation (not used on Z-INTAKE) | Candor alternative | Residual stated in the SSP |
|---|---|---|---|
| Authorization boundary vs Tor | Authorize all interconnections | Tor is an **external anonymity overlay outside the boundary**; the boundary starts at C-05; content confidentiality rests on HPKE/AEAD (FIPS profile), not on Tor | Tor primitives are not FIPS-validated; Tier W plaintext crosses Tor before FIPS encryption (GOV-028 preselects Tier W off in FIPS-mandated deployments) |
| SI-3 malicious code protection | EDR with kernel memory scanning and cloud upload | Candor-built on-host integrity and malware scanner with offline signatures via TUF, results in the C-25 schema only (per `17-INFRASTRUCTURE.md`); Platform Manifest verification (ADR-040) | Signature coverage lags commercial EDR |
| SI-4 system monitoring; AU-2/AU-12 event logging | Log forwarder shipping all access logs | ADR-016 classes; C-25 self-test; SECURITY/SYSTEM events via the scrubbed C-26 path; no access logs by design | Source-side events are deliberately not logged (SOURCE-SENSITIVE class) |
| AU-6 review | SOC review of full logs | SOC review of coarsened staff events (ENT-047) and health bands | SOC cannot investigate individual source sessions |
| RA-5 vulnerability scanning | Authenticated network scanner on the host | Authenticated package inventory via `candorctl` against the SBOM and advisory feeds; security floor (ADR-040) | No active network scanning of intake |
| IR-6 incident reporting indicators | IP-based indicators | Indicators are hashes, release digests and configuration findings; source IPs never exist | Some reporting forms expect IPs |
| Guest-invisible infrastructure (port mirroring, LUN/hypervisor snapshots, BMC console logging) | Not addressed | Signed attestations by owning teams (GOV-035; HA-018) | Attestations can be false |

### 5.8 Revision controls (ADR-034..ADR-046) mapping summary

| ADR | Control | Primary frameworks supported |
|---|---|---|
| **ADR-034** | Tier W drafts only in Sealer RAM | GDPR Art 5(1)(c), 25; EU Art 9(1)(a) |
| **ADR-035** | External Watchers; Operator Statement; confidential-VM Sealer; independent IR capture approval | SI-7, SA-9, IR-4; ISO 37002 7.5; EU Art 9(1)(a) |
| **ADR-036** | Key Directory change governance | CM-3, CM-5, AC-5; ISO 37002 5 |
| **ADR-037** | Triage-first routing; blinded COI | AC-3, AC-6; EU Art 9(1)(c), 16; ISO 37002 5 |
| **ADR-038** | Fixed import slots; constant-schedule notifications | GDPR Art 5, 25; EU Art 9(1)(a) |
| **ADR-039** | Fetch-all reply retrieval | GDPR Art 5, 25 |
| **ADR-040** | Platform Manifest; security floor; signer/builder spread | SI-2(7), SI-7, SR-3, SR-11 |
| **ADR-041** | Source App acquisition off the organisation's site | GDPR Art 25 |
| **ADR-042** | Desk containment tiers; OCR text layer | SC-39, SI-3 (endpoint); Section 508 / EN 301 549 |
| **ADR-043** | Independent-custody recipient devices | AC-5, SC-7 (endpoint); ISO 37002 5 |
| **ADR-044** | Key-access continuity; GOV Recovery Quorum; vault DR and backup exclusion; Desk-local records search | CP-9, CP-10, MP-6, SC-12; GDPR Art 15, 17; records law (§6.1) |
| **ADR-045** | Organisation-as-adversary controls; small-organisation mode | AC-5; ISO 37002 5 |
| **ADR-046** | Consistency fixes (single metrics regime, config labels, update paths, KDF) | CM-6; GDPR Art 5; EU Art 27 |

## 6. Control mapping: records, accessibility, procurement, residency, privacy

| Area / control | Candor features / requirements | Customer responsibility | Evidence artifact |
|---|---|---|---|
| Records: disposition by schedule (44 USC 3303 [K]; LAC s.12 [K]; state schedules) | Retention engine; schedule import (EE); disposition block (GOV-020); unmapped deletions blocked in records-scheduled channels (GOV-034); RET-*, DEL-*. Retention is feasible only as far as keys survive (§6.1) | Obtain disposition authority; enable Recovery Quorum or accept loss risk in writing | Disposition certificates; records-feasibility statement (COMP-027) |
| Records: archival export (M-23-07 [K]) | PDF/A + JSON/XML Export Package (ENT-019) | Transfer | Manifest |
| FOIA/ATIP exemption tagging and search | Tags and extract workflow (GOV-008, GOV-009); Desk-local search by Records Custodian with Triage-Set grants and completeness report (GOV-033; ENT-045) | Decisions; request grants for all in-scope cases | Extract log; completeness report |
| WCAG 2.2 AA / ISO/IEC 40500:2025 (B-CO-28) | A11Y-*; in-sandbox OCR text layer for sanitized copies (ADR-042) | Content authored by the customer | Audit report; ACR (partial conformance declared for rasterized originals) |
| Section 508 (WCAG 2.0 AA, B-CO-32) | A11Y-* | Procurement | ACR (VPAT 508 edition) |
| EN 301 549 v4.1.1 (B-CO-34); CAN/ASC-EN 301 549 (B-CO-35) | A11Y-* | Procurement | ACR (INT edition) |
| ADA Title II (WCAG 2.1 AA; 2027/2028 deadlines, B-CO-30) | A11Y-* | Content | ACR |
| AODA (B-CO-37) | A11Y-* | — | ACR |
| Official Languages Act / Charter of the French Language | I18N-*; GOV-016 | Translation of custom content | i18n completeness report |
| Public-sector procurement (SBOM, source access, audits) | `22-GOVERNMENT.md` §11 | — | Procurement bundle |
| Data residency (GDPR Ch. V; Law 25 PIA before transfer; GC residency [K]) | Region pinning; ENT-027; GOV-014 | Choose the region; perform the PIA | Configuration; PIA |
| Québec Law 25 (privacy by default; PIA; incident register) (B-CO-27 [K]) | Defaults (ADR-023); PIA template; IR register | Designate a responsible person | PIA; register |
| PIPEDA / Bill C-36 (pending, B-CO-22) | Same privacy controls | Monitor legislation | — |
| NIS2 Art 21/23 (B-CO-47 [K]) | IR-*; supply-chain attestations | Entity obligations | IR records |
| EU CRA (B-CR-50, B-CR-51) | Vulnerability handling; SBOM; ENISA reporting runbook (OSG-*) | — (vendor and steward obligation) | CRA technical file |

### 6.1 Records-law feasibility statements (corrected in revision round 2; RVW-C-14)

Earlier text implied that retention, search and disposition obligations are met by "tagging and disposition" features. That was not accurate for an endpoint-key design. The statements below replace it and are what Candor documentation, packs and sales material may claim (COMP-001 applies).

| Obligation | Feasible? | Under which configuration | What Candor cannot do |
|---|---|---|---|
| Retain a record for the scheduled period (NARA/LAC/state schedules; EU Art 18) | **Yes, conditionally** | Recovery Quorum enabled (GOV default, ADR-044(3)), or ≥ 2 key holders per case with ≥ 2 authenticators each and suspend-only automation (ADR-044(1)(2)); vault replicated to DR (HA-017) | Guarantee retention without escrow: if every key holder's devices and authenticators are lost, content is unrecoverable (ADR-013). This may be an unauthorized destruction under records law; agencies must decide in writing (GOV-031). |
| Locate records across cases (FOIA/ATIP, Privacy Act, DSAR, eDiscovery, breach scoping) | **Yes, by Desk-local search** | Records Custodian with Triage-Set grants for all in-scope cases; completeness report (ADR-044(5); ENT-045) | Server-side search, or search of cases no authorized person can decrypt. Completeness is only as good as the grants actually issued. |
| Produce records while protecting reporter identity (FOIA (b)(7)(D), ATIA s.16.5, Privacy Act exemptions) | Yes | Exemption tags; Sealed Identity Store never in extracts (GOV-008, GOV-009) | Prevent identification through content itself in small populations. |
| Destroy records at end of schedule, provably | **Yes, conditionally** | Crypto-erasure after disposition approval; vault backups ≤ 14 days; infrastructure backups exclude the vault (HA-018) | Assure the 14-day bound if hypervisor/SAN/image backups copy the vault; Candor cannot detect this from inside the guest and relies on attestation. |
| Prevent destruction of records before schedule | Yes, for Candor-initiated actions | Records-scheduled channels block or map envelope rejection, abandonment and source-initiated deletion (GOV-034); legal holds (ENT-011, CE-005) | Prevent physical destruction of devices by the organisation. |
| Notify persons concerned of a breach within 72 h (GDPR Art 33/34) | Yes, if case members are reachable | Desk-based scoping by case members (COMP-028) | Scope a breach from the server side; content is not readable there. |

## 7. Jurisdiction profiles (summary; packs implement them)

| Jurisdiction | Key obligations (source) | Pack contents | Notes |
|---|---|---|---|
| **Canada federal** | PSDPA ss.10–13, 19, 44 (B-CO-19); ATIA s.16.5 (B-CO-20); Privacy Act; ITSG-33/PBMM (B-CO-48); Official Languages Act; C-290 died (B-CO-21) | PSIC external info; s.16.5 mandatory tag; EN/FR notices; PIA template | Coverage categories configurable pending reform |
| Canada provincial | ON PSOA Part VI; AB PIDA 5/10/120 business days (B-CO-24); BC PIDA (B-CO-25); QC D-11.1 and CMQ (B-CO-26); Law 25 | Business-day calendars; commissioner contacts; FR | AB clocks may be policy, not statute (UNVERIFIED) |
| Canada private | PIPEDA; C-36 pending (B-CO-22) | Privacy notice templates | — |
| **US federal** | WPA/WPEA incl. anti-gag 2302(b)(13); IG Act 5 USC 407(b) (B-CO-13); OSC 1213(h); SOX §301/§806; Dodd-Frank §922 and Rule 21F-17; FCA qui tam seal; 41 USC 4712 (B-CO-16); FedRAMP 20x; CMMC; CJIS (B-CO-69, -43, -45, -46) | Anti-gag statement; SEC/CFTC/OSC/IG external info; audit-committee routing rule; SOX 180-day OSHA reminder; FCA sealed-matter flag; 4712 rights notice; DOJ 120-day advisory clock (UNVERIFIED mechanics) | Clocks are advisory reminders, not legal advice (R6 WB-40) |
| **US states** | CA Lab. Code §1102.5, Gov. Code §8547 [K]; NY Labor Law §740 (B-CO-18), CSL §75-b [K]; state public-records exemptions (B-CO-70, UNVERIFIED specifics) | NY §740 notice; state exemption tags; state schedules | Per-state packs |
| **US municipalities** | Local ordinances (e.g., IG ordinances; UNVERIFIED sections); ADA Title II; state records laws; CJIS for police | Public-report intake; Spanish; statistics | See `22-GOVERNMENT.md` §5.3 |
| **EU** | Directive 2019/1937 (B-CO-02); national transposition (27 variants); GDPR; CNIL 2023-064 (B-CO-12); EDPS 2019 (B-CO-10); NIS2; CRA | Per-member-state pack: anonymity acceptance, competent authorities, retention, Art 23 restrictions | Evaluation and amendment expected 2026–27 (B-CO-04, B-CO-08) |
| Reference | UK PIDA (B-CO-67); Australia Part 9.4AAA (B-CO-68) | Optional packs | — |

## 8. Compliance pack design

### 8.1 Format

A pack is a signed tarball:
- `pack.json` manifest;
- `clocks.yaml`;
- `calendars/*.ics` (holidays);
- `retention.yaml`;
- `notices/<locale>/*.md` (restricted Markdown: no HTML, no links except `https:` and `.onion` to allow-listed hosts);
- `exemptions.yaml`;
- `templates/*.md` (DPIA, PIA, ROPA, SORN);
- `reports.yaml` (catalogue definitions only; k is enforced by the engine).

Manifest fields:
- `pack_id`, `version` (semver), `jurisdiction` (ISO 3166-1/-2), `effective_from`;
- `legal_review` (reviewer org, date; EE certified packs);
- `sources[]` (citations);
- `license`;
- `signature` (Ed25519 by the pack publisher key, listed in the TUF `packs` role, or a customer-local key for custom packs).

### 8.2 Allow-list: what a pack may and may not set

| Pack MAY set | Pack MAY NOT set |
|---|---|
| SLA clocks (calendar or business days, anchors, extensions) | Anything in the anonymity, network, crypto, logging or telemetry configuration |
| Holiday calendars | Enable C-38 clearnet intake, Recovery Quorum, CASE-class export, or lower k |
| Retention periods (subject to COMP-008) | Routing rules that bypass COI |
| Notices and external-channel text | Scripts, HTML, remote resources |
| Exemption tags; DSAR restriction codes | Staff roles or grants |
| Document templates | Notification content beyond ADR-017 |
| Report definitions (engine enforces §9 of doc 24) | Identifying intake fields in ANONYMOUS channels (ENT-005) |

### 8.3 Lifecycle

- Packs are fetched via TUF (CE starter packs and EE certified packs) or imported locally.
- Diffs are displayed. Activation requires dual approval.
- Pack changes are SECURITY-audited.
- Conflicts between multiple packs (e.g., EU + national) are resolved by explicit precedence in the manifest (`extends`). The strictest clock wins where two apply.

## 9. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| COMP-001 | No Candor UI, document, pack or marketing material SHALL claim that use of Candor makes an organization compliant or certified. A lint of prohibited phrases (e.g., "GDPR compliant", "makes you compliant", "certified whistleblowing") SHALL run in CI on docs and UI strings. | B-GL-10 (self-declaration critique); DECISIONS §0 | THR-040 | C-30 | TST: phrase lint; INSP |
| COMP-002 | Each mapping row SHALL identify Candor features, customer responsibility and an evidence artifact. The traceability tool SHALL fail on rows with an empty column. | Design | — | C-30 | TST: doc parser (`39-REQUIREMENTS-TRACEABILITY.md`) |
| COMP-003 | The pack loader SHALL enforce the §8.2 allow-list. Any key outside it SHALL reject the whole pack. | ADR-020; B-GL-37 (CVE-2026-46647) | THR-035 | C-10 | TST: pack fuzz with forbidden keys; ST |
| COMP-004 | Packs SHALL be signed. Publisher keys SHALL be delegated in TUF (`packs` role) or registered locally with dual approval. Unsigned packs SHALL be rejected. | ADR-022; B-CR-45 | THR-025 | C-10, C-33 | TST: unsigned and wrong-key rejection |
| COMP-005 | Pack activation SHALL display a semantic diff and require dual approval. It SHALL be SECURITY-audited. | Design; ADR-016 | THR-035 | C-19 | TST |
| COMP-006 | Notice Markdown SHALL be rendered by a restricted renderer: no raw HTML, no images, and links only to allow-listed hosts. | INC-53; B-GL-39 (Hush Line XSS) | THR-006, THR-036 | C-06 | TST: renderer XSS corpus |
| COMP-007 | The SLA engine SHALL support calendar and business-day clocks, holiday calendars, anchors (receipt, acknowledgement, day-7 fallback), justified extensions and pauses, with every change CASE-audited. | B-CO-02 (Art 9, 11); B-CO-24 | — | C-10 | TST: clock fixture suite |
| COMP-008 | Retention values from packs exceeding 365 days after closure SHALL require a recorded legal basis. Sealed Identity Store retention SHALL NOT exceed case retention. | B-CO-02 (Art 17, 18); B-CO-12; ADR-014 | THR-017 | C-10 | TST |
| COMP-009 | The platform SHALL generate DPIA, PIA, ROPA and SORN drafts from the live data model and configuration, listing every stored field per zone. | B-CO-09 (Art 30, 35); B-CO-27 | THR-035 | C-19 | TST: generator vs schema diff |
| COMP-010 | The DSAR workflow SHALL require a restriction reason code for whistleblowing cases, SHALL support partial redacted disclosure, SHALL locate data only by Desk-local search under ENT-045 with a completeness report, and SHALL never include the Sealed Identity Store in a subject-access output to a person concerned. | B-CO-09 (Art 15(4), 23); B-CO-10; B-CO-11; ADR-044(5); RVW-C-14 | THR-019, THR-020 | C-10, C-15 | TST; ST: DSAR by accused; DEMO: DSAR drill with completeness report |
| COMP-011 | Default packs SHALL include external-channel information and SHALL contain no language restricting reporting to authorities (anti-gag). | B-CO-69 (WPEA 2302(b)(13); SEC 21F-17) | THR-040 | C-06 | INSP: legal review record per pack |
| COMP-012 | EE SHALL export control-implementation evidence in OSCAL (component definition and assessment results) for SP 800-53r5.2.0, and KSI evidence for MANAGED FedRAMP 20x offerings. | B-CO-40; B-CO-43 | — | C-19 | TST: OSCAL schema validation |
| COMP-013 | The FIPS profile build manifest SHALL record the validated module name, version, CMVP certificate reference and module hash. Self-test SHALL fail if the running module hash differs. | B-CR-11; B-CR-12; B-CO-49 | THR-012 | C-11, C-25 | TST |
| COMP-014 | A CycloneDX CBOM (cryptographic inventory) SHALL be produced per release for PQC migration reporting. | B-CR-04; B-CR-03 | THR-012 | C-31 | TST: CBOM generation job |
| COMP-015 | Evidence artifacts generated for auditors (KPI reports, audit exports, configuration exports) SHALL contain no SOURCE-SENSITIVE data and SHALL apply the `24-LICENSING-BUSINESS-MODEL.md` §TEL regime to any counts or statistics. | ADR-016; ADR-046(5); INC-74; RVW-B-08 | THR-039, THR-038 | C-10, C-24 | TST: canary scan of evidence bundle; TST: spec-constant lint (27 SG-25) |
| COMP-016 | Retention and disposition SHALL be blocked where a pack-declared schedule requires retention or a legal hold applies. Crypto-erasure SHALL follow recorded approval. Pack and product text SHALL NOT state that Candor guarantees retention unless the deployment has the Recovery Quorum enabled; otherwise it SHALL state the device-loss limitation of §6.1. | B-CO-69; ADR-025; ADR-013; ADR-044(3); RVW-C-14 | THR-037, THR-042 | C-10 | TST; TST: COMP-001 lint includes the retention-guarantee phrase set |
| COMP-017 | Each jurisdiction pack SHALL cite sources in `sources[]`, carry `effective_from`, and carry a reviewer record for EE certified packs. Items marked UNVERIFIED in research SHALL be flagged in the pack UI. | R6 method | — | C-10 | INSP |
| COMP-018 | Where several packs apply, precedence SHALL be explicit. Where two clocks bind the same milestone, the earliest deadline SHALL be used. | B-CO-02; B-CO-24 | — | C-10 | TST |
| COMP-019 | The EU CRA technical file (SBOM, vulnerability handling, support period, secure defaults) SHALL be maintained per release. The ENISA reporting runbook SHALL be tested annually. | B-CR-50; B-CR-51 | THR-024 | C-30 | INSP; DEMO: tabletop |
| COMP-020 | Accessibility conformance SHALL be evidenced by an ACR per minor release (CE: self-assessed; EE: third-party) that declares partial conformance for rasterized originals and documents the in-sandbox OCR text layer (ADR-042). | B-CO-28; B-CO-32; B-CO-34; ADR-042; RVW-C-16 | — | C-06, C-15 | AUD; TST: automated a11y CI |
| COMP-021 | Business-day calendars SHALL be supplied per jurisdiction. The engine SHALL refuse to compute a business-day deadline without a calendar. | B-CO-24 | — | C-10 | TST |
| COMP-022 | Advisory legal clocks (SOX 180-day, DOJ 120-day, FCA seal) SHALL be labelled "advisory reminder, not legal advice" in UI. | R6 WB-40; B-CO-17 | THR-040 | C-15 | INSP |
| COMP-023 | The generated data-flow report SHALL list every zone, component, data category, retention and observer (including HA observers from `21-ENTERPRISE.md` §5.4 and the integrations of §8.1), the IdP as staff-timing observer where SSO is used, recipient-device custody status, and every customer attestation for guest-invisible infrastructure settings (GOV-035, HA-018). | B-CO-09 (Art 30); ADR-016; ADR-043; ADR-044(4); RVW-C-12 | THR-035 | C-19 | TST: report includes all deployed roles and attestation fields |
| COMP-024 | Referral Export Packages SHALL carry the original's hash so that the receiving body can verify the report was not modified. | B-CO-02 (Art 12(4)); ADR-012 | THR-037 | C-15 | TST |
| COMP-025 | Every control introduced by ADR-034..ADR-046 SHALL appear in at least one mapping row (§4–§6, §5.8), and the traceability tool SHALL fail if an ADR-034..046 control has no mapping. | ADR-034..ADR-046; RVW-B-29(f) | THR-035 | C-30 | TST: doc parser (`39-REQUIREMENTS-TRACEABILITY.md`) |
| COMP-026 | EE SHALL publish per release the §5.7 control-tailoring and boundary annex in SSP-ready form (OSCAL where applicable). | RVW-C-12; RVW-C-15; B-CO-40; B-CO-43 | THR-016, THR-035 | C-19 | TST: OSCAL schema validation; INSP |
| COMP-027 | The platform SHALL generate a per-deployment records-feasibility statement from live configuration, stating for each §6.1 obligation whether it is feasible and the limiting condition (e.g., Recovery Quorum disabled, vault backup-exclusion attestation missing, no Records Custodian). | ADR-044; RVW-C-14; RVW-C-06 | THR-042, THR-017, THR-040 | C-19 | TST: generator output changes with each condition fixture |
| COMP-028 | The IR runbook and Desk SHALL support breach scoping for persons concerned (Art 33/34): case members run a Desk-local query for the affected data categories and return content-free per-case attestations, tracked for completeness against the 72 h clock. | B-CO-09 (Art 33, 34); RVW-C-14; RVW-C-22 | THR-015, THR-019 | C-15, C-10 | DEMO: tabletop; TST: attestation tracking |

## 10. Residual risks and limitations

- Laws change. Mapping accuracy depends on pack maintenance, and several sources are [K] or UNVERIFIED (R6 register).
- Some obligations conflict with source protection: records retention versus minimization, and exact statutory counts versus k-thresholds. The platform surfaces the conflict. It cannot resolve it legally.
- Endpoint-only keys make retention depend on key survival: without the Recovery Quorum, loss of every key holder's devices destroys records (§6.1). With it, the quorum is a compellable escrow key. There is no configuration without one of these two risks.
- Deletion and destruction claims depend on customer attestations about infrastructure backups that Candor cannot verify from inside the guest.
- The §5.7 tailoring may not be accepted by every authorizing official; some will reject any Tor dependency. That is a market limit, not a fixable defect.
- Evidence artifacts show that controls exist. They do not show that customer processes follow them.
- Packs are data that shape workflow. A malicious pack is bounded by the allow-list, but can still mislead staff through its notice content.

## 11. Open issues

1. OSCAL component-definition granularity (per component C-nn or per profile).
2. Whether the EAA covers whistleblowing channels (R6 UNVERIFIED #6).
3. Tracking of EU Directive amendments (2026–27) and Canadian PSDPA reform.
