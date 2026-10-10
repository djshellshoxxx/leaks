# 22 — Government Deployment Profile (GOV-ONPREM and government variants)
Status: Draft v1.2 (final consistency pass: ADR-047) · previously v1.1 (revision round 2: ADR-034..046) · Edition applicability: EE (GOV profile); CE usable by small public bodies with limitations stated in §4 · Owner: Public Sector Solutions team

## 1. Purpose and scope

This document defines how Candor is deployed for public bodies:
- municipalities;
- state and provincial governments;
- federal departments;
- Inspector General (IG) offices;
- ethics offices;
- ombudsmen;
- law-enforcement internal affairs (IA) and civilian oversight.

It covers procurement, government identity, information classification, records and access-to-information laws, retention, accessibility, data sovereignty, HSMs and controlled networks.

Requirements differ by level and by jurisdiction. This document **does not assume they are identical** (§3).

**Classified information:** Candor is **not designed or accredited for classified national-security information**. This includes US Confidential/Secret/Top Secret, Canadian Protected C and Classified, and intelligence-community systems under PPD-19 / 50 USC 3234 (B-CO-69; R6 A4). Use for classified information is prohibited unless a separate accreditation program is completed. No such program exists at v1.0.

Nothing here says that deploying Candor makes an agency compliant. The mapping of controls to obligations is in `25-COMPLIANCE.md`.

## 2. Context and dependencies

| Topic | Document |
|---|---|
| Profiles | `18-DEPLOYMENT.md` (GOV-ONPREM, AIRGAP-RCP, PRIVATE-CLOUD) |
| Dedicated-instance rules | `21-ENTERPRISE.md` §6.3 |
| Control mapping | `25-COMPLIANCE.md` |
| FIPS suite | `04-CRYPTOGRAPHY.md` (CANDOR-FIPS-1, ADR-006) |
| PIV and roles | `15-AUTHENTICATION-AUTHORIZATION.md` |
| Retention and legal hold | `35-DATA-RETENTION-DELETION.md` |
| Accessibility | `26-ACCESSIBILITY.md` |
| Human controls | `32-OPERATIONS.md` |
| Assumptions | `40-SECURITY-ASSUMPTIONS.md` |
| ADRs | ADR-002, -005, -013, -014, -015, -016, -018, -021, -024, -025; revision ADRs -035 (watchers, Operator Statement, confidential VM, IR capture), -036 (directory governance), -037 (triage-first), -038 (import/notification schedule), -043 (custody), -044 (recovery, records), -045 (organisation-as-adversary), -046 |
| Enterprise integrations and custody | `21-ENTERPRISE.md` §8.1, ENT-034, ENT-045, ENT-049 |

## 3. Differences by level (do not assume uniformity)

| Dimension | Municipality | State / provincial | Federal department | IG / ethics / ombudsman / integrity commissioner | Law-enforcement IA / civilian oversight |
|---|---|---|---|---|---|
| Typical reporters | Employees and the public (R6 A5) | Employees and contractors | Employees, contractors (41 USC 4712) | Employees, contractors and the public; anonymous accepted (5 USC 407(b), B-CO-13) | Public complainants; officers reporting peers |
| Main statutes (examples) | Local by-laws; state whistleblower acts (CA Gov. Code §53296 [K]); EU Art 8(9) exemption < 10,000 inhabitants (B-CO-02); Québec municipal regime via CMQ (B-CO-26) | CA §8547, NY CSL §75-b [K]; ON PSOA Part VI; AB PIDA 5/10/120 business days (B-CO-24); BC PIDA (B-CO-25); Québec D-11.1 (B-CO-26) | WPA/WPEA (5 USC 2302); PSDPA ss.10–13 (B-CO-19) | IG Act 5 USC 407(b); OSC 5 USC 1213(h); PSDPA s.44 | Police acts, CJIS Security Policy v6.0 (B-CO-46) |
| Identity confidentiality | Policy or by-law, sometimes statutory | Statutory in most regimes | Statutory (PSDPA s.11; 5 USC 407(b)) | Statutory, with an "unavoidable disclosure" determination (IG) | Statutory or collective-agreement; informer-privilege analogues (B-GL-43) |
| Records / access to information | State or provincial public-records acts; municipal FOI | State FOI with exemptions (e.g., FL §112.3188, UNVERIFIED specifics, B-CO-70) | FOIA (b)(6), (b)(7)(C), (b)(7)(D); Privacy Act (k)(2); ATIA s.16.5 (mandatory refusal, B-CO-20); Privacy Act s.22.3 | Same as federal; plus IG-specific | Public-records plus CJI restrictions |
| Records retention authority | State archives schedules | State archives; LAC for none | NARA schedules (44 USC 3303) [K]; LAC Act s.12 disposition authorities [K] | Agency-specific schedules (UNVERIFIED whether a GRS item exists) | State or department schedules; CJIS |
| Security baseline | NIST CSF 2.0 (B-CO-42); GovRAMP for SaaS (B-CO-44) | GovRAMP; state policies; CCCS guidance (CA) | SP 800-53r5.2.0 Moderate (B-CO-40); FedRAMP 20x if SaaS (B-CO-43); ITSG-33 / PBMM (B-CO-48) | Same as federal, plus independence from the audited agency | CJIS v6.0: MFA, FIPS encryption, audit, personnel screening (B-CO-46) |
| Classification ceiling | Unclassified | Unclassified / sensitive | CUI (US); Protected B (CA) | CUI / Protected B | CJI (US); Protected B (CA police) |
| Identity for staff | Local WebAuthn or municipal IdP | State IdP; smart cards in some | PIV/CAC (FIPS 201-3, B-CO-49); GC PKI and enterprise credentials (Knowledge (unverified)) | PIV/CAC; separate IdP from the audited agency where feasible | Agency credentials; advanced authentication per CJIS |
| Accessibility | ADA Title II WCAG 2.1 AA, deadlines 2027-04-26 / 2028-04-26 (B-CO-30); AODA (B-CO-37) | ADA Title II; AODA; Québec French | Section 508 (WCAG 2.0 AA, B-CO-32); EN 301 549 via CAN/ASC (B-CO-35); Official Languages Act EN/FR [K] | Same as federal | ADA Title II |
| Languages | Local needs, e.g., Spanish (R6 A5) | EN/FR (Québec, NB), others | EN/FR mandatory in Canada | Same | Local |
| Residency | State or province; sometimes none | In-state or in-province often contractual | Canada: Protected B in Canada [K; instrument UNVERIFIED]; US: US-only for CUI and CJI practice | Same | CJIS: agency-controlled |
| IT capacity | Low: often no dedicated security team | Medium | High | Low to medium (small offices) | Medium, but the IT is controlled by the department being overseen |
| Main adversary to source | Local officials; small anonymity set | Agency management | Agency management; compellable by other agencies | **The audited agency, including its CIO and SOC** | **The police department itself**: investigative powers, surveillance tools, legal process |
| Recommended profile | **MANAGED by an independent operator or a consortium-run instance (recommended)**; CE-HARDENED self-operation only with a named competent operator and the `18-DEPLOYMENT.md` operational load budget met; EE multi-tenant consortium (low or moderate risk only). Small-organisation mode (ADR-045) applies when fewer than 4 distinct persons are enrolled. | EE-ONPREM or GOV-ONPREM | GOV-ONPREM (+ AIRGAP-RCP optional) | GOV-ONPREM **dedicated** (ADR-021), administered by IG staff, not by agency IT | GOV-ONPREM **dedicated**, hosted by the civilian oversight body or an external operator, not by the police department |

## 4. Profile summary (GOV-ONPREM)

| Area | GOV-ONPREM setting |
|---|---|
| Instance | Dedicated (ADR-021). No shared-instance multi-tenancy for IG, IA, ethics or ombudsman bodies. |
| Crypto | CANDOR-FIPS-1 build with a CMVP-validated module (B-CR-11, B-CR-12). CANDOR-STD-1 remains available where no FIPS mandate exists. |
| Source tiers | Tier W and Tier V. The GOV installer requires an explicit, recorded agency determination (GOV-011). For CJIS or FIPS-mandated deployments the preselected SAFE value is **Tier W disabled** (Tier V FIPS Source App and, where available, the WEBCAT-verified bundle); enabling Tier W is ADVANCED and shows the ADR-035(5) honesty text (GOV-028; RVW-C-15). |
| Sealer isolation | Confidential-VM Sealer (AMD SEV-SNP or Intel TDX) with attestation bound to a logged release, verified by Desk and External Watchers (ADR-035(3)). SHOULD for all GOV-ONPREM; SHALL for IG/IA deployments that keep Tier W enabled (GOV-029). Never presented to sources as a guarantee. |
| Import and notification schedule | Relay imports **1×/day at a fixed time** (ADR-038(1)). Staff dates displayed at **ISO-week** granularity for IG/IA channels (HIGH) and day granularity otherwise (ADR-038(3)). Notifications disabled by default (HIGH); if enabled, one constant daily digest (ADR-038(2)). Key Directory publications in the fixed weekly slot (ADR-036(7)). Roster additions, role-label changes and COI loosening time-locked **7 days** (ADR-036(2)). |
| Intake integrity evidence | ≥ 2 External Watchers, ≥ 1 outside the operator's jurisdiction (ADR-035(1)); Operator Statement every 30 days signed by a quorum with ≥ 1 independent role (ADR-035(2)); Key Directory checkpoints with ≥ 2 external witness cosignatures (ADR-036(5)) (GOV-030). |
| Hosts | Separate Z-INTAKE and Z-CORE hosts (ADR-009). Agency-owned or oversight-body-owned hardware, or a GovCloud / Protected B region under PRIVATE-CLOUD with documented provider observers. |
| Keys | Recipient keys on PIV/CAC or FIPS 140-3 hardware tokens; each member enrols ≥ 2 authenticators; `min_recipients` = 2 (ADR-044(2)). Server-side signing keys in an HSM (FIPS 140-3 Level 3 recommended). Erasure Key Vault on a physical-host TPM or HSM, never a vTPM (ADR-044(4)). **Recovery Quorum ENABLED by default** (ADR-044(3)), custodians from independent roles, disclosed on the landing page (§7.1; GOV-031). |
| Admin independence | Administrators come from the oversight body, not from the overseen agency's IT (INC-22 lesson). Break-glass needs one approver from an independent role outside the legal/management chain (ADR-045). IR memory or packet capture on intake needs approval by the IG's designated independent official or OVERSIGHT and triggers a source-visible INCIDENT_NOTICE (ADR-035(4)). |
| Recipient devices | IG, IA, ethics and ombudsman channels are INDEPENDENT (ADR-043): Triage Set members use independent-custody devices not enrolled in the overseen agency's MDM/EDR/DLP/VDI (`21-ENTERPRISE.md` ENT-049). |
| Staff transport | In FIPS-mandated deployments Desk↔Core traffic is protected by an inner TLS 1.3 session terminated at C-10 using the validated module, whether RCP-LAN or RCP-ONION carries it (GOV-032). |
| Logging | ADR-016 classes. No SOC export of CASE class. The SIEM feed goes to the oversight body's SOC or to none, in the coarsened staff-event form of ENT-047. |
| Retention | Per records schedule with legal hold. The Sealed Identity Store has its own schedule (§7). |
| Updates | TUF, identical for all customers (ADR-022); Z-INTAKE via the project onion mirror over Tor, Z-CORE via an egress-restricted in-zone HTTPS mirror (ADR-046(3)); signed Platform Manifest and security floor (ADR-040). An offline update bundle is supported for controlled networks (§10). |
| Vendor access | None by default. Support is by scrubbed bundle only (see `21-ENTERPRISE.md` ENT-020). |

CE for small public bodies:
- CE is permitted for municipalities and small agencies.
- It lacks the FIPS evidence package, PIV federation policy, records-schedule import and a formal ACR.
- It is **not CJIS-assessed**, and the documentation SHALL say so (R6 B, CJIS row).
- CE carries every protection above (triage-first, watchers, Operator Statement, constant-schedule notifications, custody preflight; `23-COMMUNITY-EDITION.md` §5). A small public body on CE with fewer than 4 distinct enrolled persons SHALL run small-organisation mode with an external OVERSIGHT party (ADR-045).

## 5. Government use cases and specific design

### 5.1 IG, ethics offices and ombudsmen

- **Unavoidable-disclosure determination.** The unseal workflow (ADR-014) has a record type `ig_unavoidable_disclosure` with required fields:
  - statutory basis (enum: 5 USC 407(b), 5 USC 1213(h) imminent danger, PSDPA s.11 procedural fairness, other);
  - determining official;
  - date;
  - notice-to-reporter decision and deferral reason.
- **Public intake.** Channels are open to the public; there is no employee verification.
- **Staff-entered reports.** Reports from phone, mail or walk-ins are entered via Desk with a `channel_of_origin` flag (R6 WB-01). They default to CONFIDENTIAL mode, not ANONYMOUS, unless the intake officer records that no identity was received (THR-040).
- **Referral.** Referral to another agency's IG, to OSC or to PSIC uses an Export Package with an integrity hash (R6 WB-11; EU Art 12(4) analogue).
- **Independence.** The instance, its admins, its HSM and its backup custody are controlled by the IG office. The audited agency's IT provides at most rack space and power. Its staff have no console, hypervisor or backup access (GOV-004).

### 5.2 Law-enforcement internal affairs and civilian oversight (CJIS)

| Issue | Design |
|---|---|
| Adversary | The department and its officers have surveillance tools, legal process and local network control. Treat as ADV class "organization with investigative powers" (INC-22, INC-26). |
| Hosting | Hosted by the civilian oversight body, a separate government entity or an external operator. Not on police-department infrastructure (GOV-005). |
| CJI | Complaints may contain CJI after investigation begins. The CJIS addendum applies to Z-CORE, Z-RCP and backups: MFA (advanced authentication), FIPS-validated encryption at rest, audit, personnel screening of admins, and incident response (B-CO-46). |
| Phases | CJIS v6.0 audits phase in from 2025-10-01, with full compliance by 2027-10-01 (B-CO-46). |
| Officer reporters | Guidance: never use department devices, MDTs or department Wi-Fi. Use a personal device on a non-department network (see `05-SOURCE-OPSEC.md`). |
| Public complainants | Offer ANONYMOUS (onion) and CONFIDENTIAL (optional clearnet C-38, branded NOT ANONYMOUS) with clear mode labels (ADR-002). |

### 5.3 Municipalities

- **Small anonymity sets.** With 50 employees, content alone can identify a reporter (INC-73). The landing page shows a small-organization warning (GOV-012).
- **Low IT capacity.** The recommended path is MANAGED by an independent operator or a consortium-run instance (RVW-C-17). Self-operating the CE SMB profile (`23-COMMUNITY-EDITION.md`) requires a named competent operator and the operational load budget of `18-DEPLOYMENT.md`; with fewer than 4 distinct enrolled persons, small-organisation mode (ADR-045) with an external OVERSIGHT party is mandatory. An EE consortium uses one tenant per municipality. The consortium is allowed only when no D1–D7 trigger applies (`21-ENTERPRISE.md` §6.3). A municipal IG or auditor fraud hotline is D1, so it gets a dedicated instance.
- **Public annual statistics.** The metrics regime of `24-LICENSING-BUSINESS-MODEL.md` §TEL (ADR-046(5)) applies; public statistics additionally use year granularity when yearly totals are below 100 (GOV-013; INC-74).

### 5.4 Federal departments

- **US.**
  - Internal disclosure intake does not replace OSC, IG or MSPB channels. External-channel information is displayed (WPEA anti-gag, 5 USC 2302(b)(13); B-CO-69).
  - A SORN template is provided for agencies (R6 A4).
- **Canada.**
  - Senior officer designation (PSDPA s.10). PSIC referral information is shown.
  - ATIA s.16.5 tag is mandatory on all PSDPA case records (GOV-008).
  - Bilingual EN/FR UI with parity (GOV-016), including an English and a French passphrase wordlist, each reviewed and sized for ≥ 128 bits (ADR-047(6)); the chosen wordlist language is not stored server-side.

## 6. Government identity (staff only)

| Credential | Use | Design |
|---|---|---|
| PIV/CAC (FIPS 201-3) | Desk key wrapping (ADR-007) and staff authentication (AAL3 per SP 800-63-4, B-CO-41) | Smart-card wrapping is CE code (AGPL). EE adds FPKI path-validation configuration and local CRL caching (see `21-ENTERPRISE.md` ENT-017). |
| Agency IdP federation (SAML/OIDC) | Staff login | IdP never grants keys (ENT-015). For IG and IA, prefer an IdP not administered by the overseen agency (GOV-006). |
| GC enterprise credentials / GC PKI (Knowledge (unverified)) | Staff login in Canadian federal deployments | Same rules as above. |
| Citizen identity services (e.g., Login.gov, GCKey — Knowledge (unverified)) | **Prohibited for sources in ANONYMOUS mode** (ADR-005). Permitted only in IDENTIFIED-mode channels that are separately branded. | GOV-007 |

## 7. Records, access to information and retention

| Requirement | Design |
|---|---|
| Exemption tagging | Per-record tags: US (b)(5), (b)(6), (b)(7)(C), (b)(7)(D), Privacy Act (k)(2); CA ATIA s.16.5, Privacy Act s.22.3; configurable state and provincial equivalents (R6 WB-35). |
| FOIA/ATIP / Privacy Act / eDiscovery search | There is no server-side cross-case search (ADR-044(5)). The Records Custodian (RECORDS role, `15-AUTHENTICATION-AUTHORIZATION.md`) requests grants for the cases in scope (scope selected by server-visible metadata: channel and received day); the Triage Set issues explicit, audited, time-bounded grants; the search runs over a local index in the Records Custodian's Desk; the Desk produces a content-free completeness report (cases in scope × cases searched) for the response file (GOV-033; `21-ENTERPRISE.md` ENT-045). |
| FOIA/ATIP extract | The extract workflow produces redacted Export Packages with reason codes. It **never** includes the Sealed Identity Store (GOV-009). |
| Disposition | Disposition by schedule (NARA, LAC disposition authority, state schedules). Destruction is **blocked** where a schedule requires retention (LAC Act s.12 [K]; 44 USC 3303 [K]). The block is recorded. |
| Conflict with source protection | Records law can require retaining data that source protection would delete. Resolution: minimize what becomes a record. The Sealed Identity Store is scheduled separately. Sources see "Records retained under [schedule] for up to N years" on the landing page (GOV-010). |
| Archival transfer | PDF/A plus JSON/XML metadata, with a hash manifest (M-23-07 [K]). |
| Legal hold / sealed matter | FCA qui tam seal (31 USC 3730(b)), with restricted circulation (R6 WB-36). |
| Crypto-erasure vs records | Crypto-erasure (ADR-025) is executed only after the disposition authority permits it. A certificate of destruction is recorded. |
| Unauthorized-destruction risk | Loss of every key holder's device (reduced further by each member Desk's hardware-sealed case-key cache used for re-wrap after an Erasure Key Vault loss, ADR-047(7); `19-BACKUPS-DR.md` §11.2), rejection of an undecryptable envelope (ADR-038(6)) and source-initiated deletion can each amount to destruction of a record. Mitigations: Recovery Quorum enabled by default (§7.1); `min_recipients` = 2 and ≥ 2 authenticators per member (ADR-044(2)); suspend-only automation (ADR-044(1)); in records-scheduled channels, envelope rejection and source-initiated deletion are mapped to a recorded disposition authority (e.g., a transitory-records item) or blocked (GOV-034). Source-initiated deletion affects the source mailbox; the case record follows the schedule, and the landing page says so. |
| Non-records (ADR-047(3)) | Chaff envelopes written by the Intake Sealer carry no content and are discarded at import; they are not records and their discard is not a disposition. Only real envelopes become case records |
| Metadata disposition (ADR-047(8)) | Category, title and custom fields are encrypted under the case's Erasure-Key-derived key, so an authorized crypto-erasure also removes them from backups within ≤ 14 days; before disposition they remain available to records searches in authorized Desks (GOV-033) |
| Infrastructure copies | Hypervisor, SAN and image-level backups of core hosts exclude the Erasure Key Vault; the owning team signs an exclusion attestation (GOV-035; `21-ENTERPRISE.md` HA-018). Without it, destruction certificates overstate what was destroyed. |

### 7.1 Recovery Quorum default (ADR-044(3))

Records law may prohibit unrecoverable loss, so GOV-ONPREM enables the Organization Recovery Quorum (C-28, ADR-013) by default:
- custodians: k-of-n (default 3-of-5) from independent roles (e.g., IG counsel, records officer, an external party such as the ombudsperson or an external auditor); no coalition of the overseen agency's management can reach k;
- disclosure: the landing page and the Key Directory show "Recovery escrow: ENABLED, held by: <roles>"; the Source App shows the same;
- disabling it is DANGEROUS and requires a written determination by the agency records officer (and, where applicable, the NARA or LAC liaison) co-signed by OVERSIGHT, accepting device-loss risk; the determination is recorded and the landing page changes accordingly (GOV-031).

Honest residual: every escrow key is a new compellable target. Sources are told, and the quorum's existence is a reason some sources will prefer another channel.

## 8. Classification, FIPS and the Tor layer

- **Supported ceilings:** CUI (US, aligned to SP 800-171 guidance where DoD contractors are involved; CMMC phase-in B-CO-45), Protected B (Canada, PBMM / ITSG-33, B-CO-48), CJI (US). **Not supported:** classified information, Protected C.
- **FIPS scope statement.**
  - The confidentiality of report content rests on CANDOR-FIPS-1 HPKE/AEAD via a validated module.
  - The Tor transport uses non-FIPS primitives and is treated as an **anonymity layer, not the confidentiality control** (Knowledge (unverified) re Tor primitives).
  - In **Tier W**, plaintext traverses Tor to C-06/C-07 before FIPS encryption. Deployments that need FIPS-validated protection of content *in transit* must use the Tier V FIPS Source App; in CJIS or FIPS-mandated deployments Tier W is preselected OFF (GOV-028).
  - **Staff path.** Desk-API traffic uses an inner TLS 1.3 session with the validated module terminated at C-10, independent of whether RCP-LAN or RCP-ONION carries it (GOV-032). RCP-ONION is then an outer anonymity/network layer only.
  - **Anonymous recipient slots.** ADR-033(1) relies on KEM key privacy; for CANDOR-FIPS-1 (MLKEM1024-P384 hybrid) this assumption must be recorded in `40-SECURITY-ASSUMPTIONS.md` or the FIPS profile must use pure ML-KEM-1024 slots (cross-document request; RVW-C-15).
  - **FedRAMP 20x (MANAGED).** The SSP treats Tor as an external anonymity overlay outside the authorization boundary; AU-2/AU-12/SI-4/IR-6 are met by the alternative implementations mapped in `25-COMPLIANCE.md` §5.7 (IP indicators never exist by design).
  - Whether public complaint content counts as CJI or CUI at submission time is an agency determination, and is recorded in the deployment's security plan (GOV-011).
- **CNSA 2.0** (B-CR-10) is not required: Candor is not a National Security System. The GOV profile offers ML-KEM-1024 / AES-256 / SHA-384 parameters (CANDOR-FIPS-1). ML-DSA-65 is used for release roots per ADR-006. ML-DSA-87 alignment is an open issue (§13).
- **Canada.** CCCS cryptographic guidance applies to GC systems (Knowledge (unverified); guidance identifier not verified). CANDOR-FIPS-1 uses NIST-approved algorithms, which CCCS generally recognizes (Knowledge (unverified)).

## 9. Data sovereignty and HSMs

| Item | GOV requirement |
|---|---|
| Hosting location | In-country (and in-province or in-state where contract requires). Z-INTAKE, Z-CORE, Z-BAK and the DR site all in the same sovereignty zone (GOV-014). |
| Keys | Recipient keys on hardware in the custody of named officials. HSM for server signing keys, located in-zone. |
| Vendor personnel | No remote access. If support must view a screen, a customer-controlled session is used without case content. Vendor staff in CJIS support must meet CJIS personnel screening. For Canadian Protected B support, staff hold the security screening the contract requires (Knowledge (unverified) re level). |
| Tor | Tor relays are global by nature. The source's circuit crosses foreign relays. This is **not** a residency violation of stored data, but the agency must document it (GOV-015). |
| Update source | A TUF mirror inside the zone (C-33) that pulls the public signed metadata. |

## 10. Controlled networks

- **Air-gapped recipients (AIRGAP-RCP).** Import is by one-way media using signed batches. The Desk runs on an isolated network. C-17 is on the same air-gapped host or a Qubes DispVM.
- **Offline updates.** A TUF-signed update bundle is carried on media. Verification is identical to online updates. Rollback and freeze protection use TUF metadata expiry (default: timestamp 7 days, relaxed to 30 days for offline bundles, with an explicit warning; see `33-RELEASE-UPDATE-SECURITY.md`).
- **Agency network egress.** Agency networks (e.g., under trusted-internet-connection architectures, Knowledge (unverified)) often block or flag Tor. Sources are told to use personal devices on non-agency networks.
- **Monitoring mandates on Z-INTAKE.** CJIS/FedRAMP SI-3/SI-4/RA-5/AU-6 expectations are met by the alternative implementations in `25-COMPLIANCE.md` §5.7 (Candor integrity scanner and package inventory per `17-INFRASTRUCTURE.md`, platform manifest verification, attestation). EDR on H-INTAKE stays prohibited. Infrastructure knobs the guest cannot see (switch-port mirroring, LUN snapshots, BMC console logging, hypervisor snapshots) are covered by signed attestations of the owning teams (GOV-035; RVW-C-12).
- **SOC non-correlation policy.** The agency SHALL adopt a written policy that SOC alerts on Tor use are not correlated with hotline activity and not used to identify reporters. This is a customer responsibility, checked by the GOV deployment checklist (GOV-017). It reduces THR-002 only as a policy. It is not technical protection.

## 11. Procurement support

| Artefact | Provided by | Notes |
|---|---|---|
| ACR / VPAT 2.x INT edition (508, EN 301 549, WCAG 2.2) | EE | Third-party audited (B-CO-32, B-CO-34) |
| SBOM (CycloneDX) and signed provenance | CE and EE | `28-SUPPLY-CHAIN.md` |
| SSDF mapping; Secure Software Development Attestation Form (optional after OMB M-26-05) | EE | B-CR-47, B-CR-48 |
| SP 800-53r5.2.0 control implementation summary (OSCAL) | EE | B-CO-40 |
| FedRAMP 20x KSI evidence (MANAGED only) | EE | B-CO-43 |
| GovRAMP package (MANAGED only) | EE | B-CO-44 |
| ITSG-33 / PBMM control mapping | EE | B-CO-48 |
| CJIS addendum and control mapping | EE | B-CO-46 |
| Source-code access for evaluators | CE (AGPL public); EE modules source-available | ADR-020 |
| Third-party audit reports | Public for CE Trust Path | `37-SECURITY-AUDIT-PLAN.md` |
| Open-source policy fit | AGPL is OSI-approved (government open-source policies, R6 D5) | M-16-21 [K] |
| DPIA / PIA / SORN templates | CE (templates); EE (auto-filled) | R6 WB-16 |

## 12. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| GOV-001 | Documentation, installer and landing page SHALL state that Candor is not designed or accredited for classified information or Protected C. The installer SHALL require acknowledgment in GOV profile. | B-CO-69; B-CO-48 | THR-035 | C-19, C-37 | INSP; TST: installer prompt |
| GOV-002 | IG, ethics, ombudsman, IA and civilian-oversight deployments SHALL use a dedicated instance (ADR-021). | ADR-021; INC-22 | THR-020, THR-045 | C-34, C-19 | INSP: tenant risk classification; TST: onboarding block |
| GOV-003 | The unseal workflow SHALL support record type `ig_unavoidable_disclosure` with required fields statutory basis, determining official, date, notice decision and deferral reason. It SHALL require dual approval. | B-CO-13; B-CO-69; ADR-014 | THR-018, THR-019 | C-10 | TST: workflow tests; ST: single-approver attempt |
| GOV-004 | In IG deployments, no personnel of the audited agency SHALL hold admin, hypervisor, console, backup or HSM roles. Secret Placement Manifest verification SHALL list the custodians. | INC-22; REQ-H-22; ADR-028 | THR-018, THR-020 | C-19, C-27, C-29 | AUD; INSP: role roster vs org chart |
| GOV-005 | IA and oversight deployments SHALL NOT be hosted on infrastructure administered by the police department being overseen. | INC-22; B-CO-46 | THR-020, THR-030 | C-39 | INSP; AUD |
| GOV-006 | GOV deployments SHOULD federate with an IdP not administered by the overseen agency. IG and IA deployments SHALL use such an IdP or local WebAuthn only. Where an agency-administered IdP is used, the deployment record and data-flow report SHALL document the IdP administrator as a staff-activity timing observer. | ADR-015; ADR-043; B-CO-41; RVW-C-02 | THR-022, THR-020, THR-011 | C-21 | INSP; TST: IG/IA profile validator rejects agency IdP without local-only mode |
| GOV-007 | Citizen or government identity services SHALL NOT be offered in ANONYMOUS channels. They MAY be offered only in IDENTIFIED channels branded as such. A source MAY choose IDENTIFIED mode over the onion service without any identity service (ADR-047(5)); the identity then goes only to the Sealed Identity Store under the statutory confidentiality regime of §3 (e.g., 5 USC 407(b)) and the mode banner changes. | ADR-005; ADR-002; ADR-047(5) | THR-040 | C-06, C-21 | TST: config validator rejects combination |
| GOV-008 | Deployments configured for PSDPA SHALL tag every case record with ATIA s.16.5, and SHALL prevent removal of the tag. | B-CO-20 | THR-026 | C-10 | TST: tag immutability |
| GOV-009 | FOIA/ATIP extracts SHALL exclude Sealed Identity Store contents and SHALL carry per-redaction reason codes. They SHALL be built only from Desk-local searches (GOV-033). | B-CO-20; B-CO-69; ADR-014; ADR-044(5) | THR-026, THR-019 | C-10, C-15 | TST: extract builder; ST: identity inclusion attempt |
| GOV-010 | The landing page SHALL state the governing records schedule and the maximum retention. | B-CO-02 (Art 18); ADR-025 | THR-040 | C-06 | TST: render |
| GOV-011 | The GOV installer and security plan template SHALL record the agency's determination of (a) whether Tier W submissions may contain CJI or CUI, and (b) whether Tier V FIPS is mandated. Where it is mandated, Tier W SHALL be disabled unless the determination records an ADVANCED override, and the landing page SHALL direct sources to the Tier V client first. | B-CO-46; ADR-004; ADR-035(5); RVW-C-15 | THR-012, THR-035, THR-014 | C-06, C-03, C-19 | TST: installer blocks without determination; INSP |
| GOV-012 | Channels whose configured population is < 250 SHALL display the small-organization anonymity warning (content and style can identify). | INC-73; B-AN-34 | THR-010 | C-06 | TST: config-driven render |
| GOV-013 | Published statistics SHALL use the `24-LICENSING-BUSINESS-MODEL.md` §TEL regime (ADR-046(5)), read from the shared constants registry. Granularity SHALL additionally be yearly when the annual total is < 100. | INC-74; B-CO-02 (Art 27); ADR-046(5); RVW-B-08 | THR-039 | C-10 | TST: report generator; TST: spec-constant lint |
| GOV-014 | All GOV zones (intake, core, backup, DR) SHALL be located in the declared sovereignty zone. The installer SHALL record the zone, and self-test SHALL verify configured endpoints against it. | B-CO-48; R6 residency | THR-030 | C-25 | INSP; TST: endpoint allow-list |
| GOV-015 | The GOV data-flow statement SHALL disclose that Tor circuits traverse foreign relays and that this involves transit, not storage. | ADR-001 | THR-003 | C-37 | INSP |
| GOV-016 | Canadian federal deployments SHALL present all source and staff UI in EN and FR with parity. The release gate SHALL fail if any string lacks a translation. | B-CO-19; Official Languages Act [K] | — | C-06, C-15 | TST: i18n completeness gate |
| GOV-017 | The GOV deployment checklist SHALL require a documented SOC non-correlation policy for Tor use, signed by the agency head or IG. | INC-22; ADR-001 | THR-002 | C-19 | INSP |
| GOV-018 | CJIS deployments SHALL enable the CANDOR-FIPS-1 build, hardware MFA for all staff, audit retention per the CJIS addendum, and personnel-screening attestations for all admins. Monitoring controls on Z-INTAKE SHALL be met by the alternative implementations of `25-COMPLIANCE.md` §5.7, never by EDR or log forwarders on H-INTAKE. | B-CO-46; RVW-C-12 | THR-022, THR-018, THR-016 | C-11, C-21, C-24, C-25 | AUD; INSP; TST: checker fails on EDR/log-shipper presence on H-INTAKE |
| GOV-019 | The offline update bundle SHALL be verified with the same TUF roles and thresholds as online updates. Metadata expiry relaxation SHALL be capped at 30 days. | ADR-022; B-CR-45 | THR-025 | C-33 | TST: expired/forged bundle rejection |
| GOV-020 | Disposition SHALL be blocked when a configured schedule requires retention. Crypto-erasure SHALL run only after the disposition approval is recorded. | B-CO-69; ADR-025 | THR-037 | C-10 | TST: schedule engine |
| GOV-021 | Staff-entered reports SHALL carry `channel_of_origin`. They SHALL default to CONFIDENTIAL unless the entering officer attests that no identity was received. | B-CO-02 (Art 9(2)); ADR-002 | THR-040 | C-15, C-10 | TST |
| GOV-022 | Public-body landing pages SHALL list external channels (OSC, IG, PSIC, provincial commissioners, SEC as applicable). They SHALL contain no language restricting external reporting. | B-CO-69; B-CO-02 (Art 9(1)(g)) | THR-040 | C-06, C-37 | INSP: legal template review |
| GOV-023 | GOV profile SHALL disable vendor remote access by default. Enabling it SHALL be CFG-dangerous with an expiry ≤ 72 h. | INC-56; INC-68 | THR-027 | C-19 | TST |
| GOV-024 | EE SHALL provide an ACR (VPAT 2.x INT) based on a third-party audit, updated for every minor release that changes UI. It SHALL declare partial conformance for rasterized originals, document the in-sandbox OCR text layer (ADR-042) and authenticator accommodations (`15-AUTHENTICATION-AUTHORIZATION.md`), and state that VDI is unavailable to Triage Set members of INDEPENDENT channels (ADR-043). | B-CO-32; B-CO-34; B-CO-35; ADR-042; RVW-C-16 | — | C-06, C-15 | AUD |
| GOV-025 | HSMs in GOV profile SHALL be FIPS 140-3 validated (Level 3 recommended), located in-zone, with vendor cloud telemetry disabled. | B-CR-29; B-CO-49 | THR-013 | C-29 | INSP: certificate check |
| GOV-026 | AIRGAP-RCP import SHALL use signed one-way batches. Desk SHALL verify signatures before import, and no return channel SHALL exist from the air-gapped network except signed reply batches carried on media. | ADR-012; B-SD-28 | THR-023, THR-013 | C-18, C-15 | TST; ST |
| GOV-027 | The GOV SORN, PIA and DPIA templates SHALL describe every data field stored per zone. They SHALL be generated from the data model, not hand-maintained. | B-CO-16; R6 WB-16 | THR-035 | C-19 | TST: template generator diff vs schema |
| GOV-028 | In CJIS or FIPS-mandated deployments the installer SHALL preselect `intake.tier_w.enabled=false` (SAFE); enabling Tier W SHALL be ADVANCED, recorded in the GOV-011 determination and accompanied by the ADR-035(5) source-facing honesty text. | ADR-004; ADR-035(5); B-CO-46; RVW-C-15 | THR-012, THR-014, THR-035 | C-06, C-19 | TST: installer default per profile; INSP |
| GOV-029 | GOV-ONPREM SHOULD, and IG/IA deployments that keep Tier W enabled SHALL, run the Sealer in a confidential VM (SEV-SNP/TDX) whose attestation is logged against the release, refreshed at least every 24 h (ADR-047(4)), and verified by Desk at import and by External Watchers. It SHALL NOT be presented to sources as a guarantee. | ADR-035(3); RVW-A-01 | THR-007, THR-014, THR-018 | C-07, C-15 | TST: Desk rejects Tier W envelopes with missing/unlogged attestation; INSP: landing text |
| GOV-030 | GOV deployments SHALL have ≥ 2 External Watchers (≥ 1 outside the operator's jurisdiction) from the `36-OPEN-SOURCE-GOVERNANCE.md` registry, publish the Operator Statement every 30 days with ≥ 1 independent-role signer, and require ≥ 2 external witness cosignatures (≥ 1 outside the operating organisation) on Key Directory checkpoints. | ADR-035(1); ADR-035(2); ADR-036(5); RVW-A-01; RVW-A-08 | THR-007, THR-026, THR-046 | C-14, C-06, C-25 | TST: checker fails with < 2 registered watchers or witnesses; TST: expired statement banner; INSP |
| GOV-031 | GOV-ONPREM SHALL enable the Organization Recovery Quorum by default with custodians from independent roles such that no management-only coalition reaches k, and SHALL disclose it on the landing page and in the Key Directory. Disabling it SHALL be DANGEROUS and require a written records-officer determination co-signed by OVERSIGHT. | ADR-044(3); ADR-013; RVW-C-14; RVW-C-03 | THR-042, THR-020, THR-013 | C-28, C-06, C-14 | TST: default config; TST: disclosure render; INSP: custodian roster vs org chart |
| GOV-032 | In FIPS-mandated deployments Desk↔Core traffic SHALL be protected by an inner TLS 1.3 session terminated at C-10 using the validated module, regardless of whether RCP-LAN or RCP-ONION carries it. | B-CO-46; B-CO-49; ADR-006; RVW-C-15 | THR-012, THR-022 | C-15, C-10, C-11 | TST: capture shows FIPS-approved cipher suite inside the transport; INSP |
| GOV-033 | Records, FOIA/ATIP, Privacy Act and eDiscovery searches SHALL follow ENT-045: Records Custodian grants issued by the Triage Set, Desk-local search, content-free completeness report attached to the response file, and CASE audit. | ADR-044(5); RVW-C-14 | THR-018, THR-021 | C-15, C-22 | DEMO: FOIA drill; TST: completeness report |
| GOV-034 | In records-scheduled channels, rejection of undecryptable envelopes (ADR-038(6)), DC-12 abandonment and source-initiated deletion SHALL each be mapped to a recorded disposition authority or blocked; the landing page SHALL state what source-initiated deletion removes. | RVW-C-14; ADR-038(6); ADR-025 | THR-037, THR-017 | C-10, C-06 | TST: schedule engine blocks unmapped deletions; INSP |
| GOV-035 | The GOV deployment checklist SHALL require signed attestations by the owning teams for infrastructure settings invisible to the guest: switch-port mirroring or NetFlow on intake ports, intake LUN snapshots, BMC console logging, hypervisor snapshots and image-level backups of core hosts (including Erasure Key Vault exclusion). Attestations SHALL appear in the data-flow report (COMP-023). | RVW-C-12; RVW-C-06; ADR-044(4) | THR-016, THR-017, THR-030 | C-19, C-39 | INSP; TST: checker blocks go-live without attestations |
| GOV-036 | GOV-ONPREM SHALL default to: relay imports 1×/day at a fixed time; staff date display at ISO-week granularity for IG/IA channels; notifications disabled (constant daily digest if enabled); Key Directory publications in the weekly slot; 7-day time-lock for roster additions, role-label changes and COI loosening. | ADR-038(1)-(3); ADR-036(2); ADR-036(7) | THR-011, THR-028, THR-046 | C-09, C-23, C-14 | TST: GOV profile config conformance |
| GOV-037 | Small public bodies with fewer than 4 distinct enrolled persons SHALL run small-organisation mode (ADR-045) with ≥ 1 external party as OVERSIGHT, and the published Operator Statement SHALL state "reduced separation of duties". | ADR-045; RVW-C-09; RVW-C-17 | THR-018, THR-020 | C-19, C-14 | TST: checker enforces mode below 4 persons; INSP |

## 13. Residual risks and limitations

- Records laws can force retention of data that source protection would delete. That data remains compellable.
- The default-enabled Recovery Quorum (GOV-031) is a compellable escrow key held by independent roles; if those roles are captured or coerced, every case wrapped to it is exposed. It is disclosed to sources.
- Desk-local records search (GOV-033) depends on Triage-Set cooperation for grants and on the Records Custodian's device; completeness evidence is only as good as the scope metadata.
- Confidential-VM sealing (GOV-029) has a record of side-channel breaks and depends on the TEE vendor; it is defense in depth.
- Guest-invisible infrastructure settings (GOV-035) rest on attestations by teams that may report to the audited agency.
- The SOC non-correlation policy is only a policy. A hostile agency can still see Tor use from its own network (THR-002).
- Small municipalities have tiny anonymity sets. No technical control removes content-based identification.
- The FIPS claim does not extend to Tor transport, or to Tier W in-transit plaintext.
- Agencies can be compelled by other agencies. IG independence is legal, not technical.
- UNVERIFIED items: Canadian data-residency instrument, CCCS crypto guidance identifiers, federal GRS coverage of hotline records, state exemption wording.

## 14. Open issues

1. CUI marking support (banner and portion marking) in Desk exports needs a design.
2. Protected B cloud (PBMM) MANAGED region: CCCS assessment path to be decided.
3. ML-DSA-87 (CNSA 2.0 level) for release roots in the GOV profile vs ADR-006's ML-DSA-65: a candidate ADR revision.
