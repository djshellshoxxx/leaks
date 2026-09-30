# 22 — Government Deployment Profile (GOV-ONPREM and government variants)
Status: Draft v1.0 · Edition applicability: EE (GOV profile); CE usable by small public bodies with limitations stated in §4 · Owner: Public Sector Solutions team

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
| ADRs | ADR-002, -005, -013, -014, -015, -016, -018, -021, -024, -025 |

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
| Recommended profile | CE-HARDENED, or MANAGED by an independent operator; EE multi-tenant consortium (low or moderate risk only) | EE-ONPREM or GOV-ONPREM | GOV-ONPREM (+ AIRGAP-RCP optional) | GOV-ONPREM **dedicated** (ADR-021), administered by IG staff, not by agency IT | GOV-ONPREM **dedicated**, hosted by the civilian oversight body or an external operator, not by the police department |

## 4. Profile summary (GOV-ONPREM)

| Area | GOV-ONPREM setting |
|---|---|
| Instance | Dedicated (ADR-021). No shared-instance multi-tenancy for IG, IA, ethics or ombudsman bodies. |
| Crypto | CANDOR-FIPS-1 build with a CMVP-validated module (B-CR-11, B-CR-12). CANDOR-STD-1 remains available where no FIPS mandate exists. |
| Source tiers | Tier W and Tier V. For CJIS or FIPS-mandated deployments, the Tier V FIPS build of the Candor Source App is recommended (§8). |
| Hosts | Separate Z-INTAKE and Z-CORE hosts (ADR-009). Agency-owned or oversight-body-owned hardware, or a GovCloud / Protected B region under PRIVATE-CLOUD with documented provider observers. |
| Keys | Recipient keys on PIV/CAC or FIPS 140-3 hardware tokens. Server-side signing keys in an HSM (FIPS 140-3 Level 3 recommended). Recovery Quorum optional, with shares held by statutorily independent roles. |
| Admin independence | Administrators come from the oversight body, not from the overseen agency's IT (INC-22 lesson). |
| Logging | ADR-016 classes. No SOC export of CASE class. The SIEM feed goes to the oversight body's SOC or to none. |
| Retention | Per records schedule with legal hold. The Sealed Identity Store has its own schedule (§7). |
| Updates | TUF, identical for all customers (ADR-022). An offline update bundle is supported for controlled networks (§10). |
| Vendor access | None by default. Support is by scrubbed bundle only (see `21-ENTERPRISE.md` ENT-020). |

CE for small public bodies:
- CE is permitted for municipalities and small agencies.
- It lacks the FIPS evidence package, PIV federation policy, records-schedule import and a formal ACR.
- It is **not CJIS-assessed**, and the documentation SHALL say so (R6 B, CJIS row).

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
- **Low IT capacity.** Use the CE SMB profile (`23-COMMUNITY-EDITION.md`), MANAGED by an independent operator, or an EE consortium with one tenant per municipality. The consortium is allowed only when no D1–D7 trigger applies (`21-ENTERPRISE.md` §6.3). A municipal IG or auditor fraud hotline is D1, so it gets a dedicated instance.
- **Public annual statistics.** k ≥ 20, month granularity or coarser, and year granularity when yearly totals are below 100 (GOV-013; INC-74).

### 5.4 Federal departments

- **US.**
  - Internal disclosure intake does not replace OSC, IG or MSPB channels. External-channel information is displayed (WPEA anti-gag, 5 USC 2302(b)(13); B-CO-69).
  - A SORN template is provided for agencies (R6 A4).
- **Canada.**
  - Senior officer designation (PSDPA s.10). PSIC referral information is shown.
  - ATIA s.16.5 tag is mandatory on all PSDPA case records (GOV-008).
  - Bilingual EN/FR UI with parity (GOV-016).

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
| FOIA/ATIP extract | The extract workflow produces redacted Export Packages with reason codes. It **never** includes the Sealed Identity Store (GOV-009). |
| Disposition | Disposition by schedule (NARA, LAC disposition authority, state schedules). Destruction is **blocked** where a schedule requires retention (LAC Act s.12 [K]; 44 USC 3303 [K]). The block is recorded. |
| Conflict with source protection | Records law can require retaining data that source protection would delete. Resolution: minimize what becomes a record. The Sealed Identity Store is scheduled separately. Sources see "Records retained under [schedule] for up to N years" on the landing page (GOV-010). |
| Archival transfer | PDF/A plus JSON/XML metadata, with a hash manifest (M-23-07 [K]). |
| Legal hold / sealed matter | FCA qui tam seal (31 USC 3730(b)), with restricted circulation (R6 WB-36). |
| Crypto-erasure vs records | Crypto-erasure (ADR-025) is executed only after the disposition authority permits it. A certificate of destruction is recorded. |

## 8. Classification, FIPS and the Tor layer

- **Supported ceilings:** CUI (US, aligned to SP 800-171 guidance where DoD contractors are involved; CMMC phase-in B-CO-45), Protected B (Canada, PBMM / ITSG-33, B-CO-48), CJI (US). **Not supported:** classified information, Protected C.
- **FIPS scope statement.**
  - The confidentiality of report content rests on CANDOR-FIPS-1 HPKE/AEAD via a validated module.
  - The Tor transport uses non-FIPS primitives and is treated as an **anonymity layer, not the confidentiality control** (Knowledge (unverified) re Tor primitives).
  - In **Tier W**, plaintext traverses Tor to C-06/C-07 before FIPS encryption. Deployments that need FIPS-validated protection of content *in transit* must use the Tier V FIPS Source App.
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
| GOV-006 | GOV deployments SHOULD federate with an IdP not administered by the overseen agency. When they do not, the deployment record SHALL document the IdP administrator as a staff-activity observer. | ADR-015; B-CO-41 | THR-022, THR-020 | C-21 | INSP |
| GOV-007 | Citizen or government identity services SHALL NOT be offered in ANONYMOUS channels. They MAY be offered only in IDENTIFIED channels branded as such. | ADR-005; ADR-002 | THR-040 | C-06, C-21 | TST: config validator rejects combination |
| GOV-008 | Deployments configured for PSDPA SHALL tag every case record with ATIA s.16.5, and SHALL prevent removal of the tag. | B-CO-20 | THR-026 | C-10 | TST: tag immutability |
| GOV-009 | FOIA/ATIP extracts SHALL exclude Sealed Identity Store contents and SHALL carry per-redaction reason codes. | B-CO-20; B-CO-69; ADR-014 | THR-026, THR-019 | C-10, C-15 | TST: extract builder; ST: identity inclusion attempt |
| GOV-010 | The landing page SHALL state the governing records schedule and the maximum retention. | B-CO-02 (Art 18); ADR-025 | THR-040 | C-06 | TST: render |
| GOV-011 | The GOV security plan template SHALL record the agency's determination of (a) whether Tier W submissions may contain CJI or CUI, and (b) whether Tier V FIPS is mandated. Where it is mandated, the landing page SHALL direct sources to the Tier V client first. | B-CO-46; ADR-004 | THR-012, THR-035 | C-06, C-03 | INSP |
| GOV-012 | Channels whose configured population is < 250 SHALL display the small-organization anonymity warning (content and style can identify). | INC-73; B-AN-34 | THR-010 | C-06 | TST: config-driven render |
| GOV-013 | Published statistics SHALL use k ≥ 20 suppression. Granularity SHALL be yearly when the annual total is < 100, and monthly at finest otherwise. | INC-74; B-CO-02 (Art 27) | THR-039 | C-10 | TST: report generator |
| GOV-014 | All GOV zones (intake, core, backup, DR) SHALL be located in the declared sovereignty zone. The installer SHALL record the zone, and self-test SHALL verify configured endpoints against it. | B-CO-48; R6 residency | THR-030 | C-25 | INSP; TST: endpoint allow-list |
| GOV-015 | The GOV data-flow statement SHALL disclose that Tor circuits traverse foreign relays and that this involves transit, not storage. | ADR-001 | THR-003 | C-37 | INSP |
| GOV-016 | Canadian federal deployments SHALL present all source and staff UI in EN and FR with parity. The release gate SHALL fail if any string lacks a translation. | B-CO-19; Official Languages Act [K] | — | C-06, C-15 | TST: i18n completeness gate |
| GOV-017 | The GOV deployment checklist SHALL require a documented SOC non-correlation policy for Tor use, signed by the agency head or IG. | INC-22; ADR-001 | THR-002 | C-19 | INSP |
| GOV-018 | CJIS deployments SHALL enable the CANDOR-FIPS-1 build, hardware MFA for all staff, audit retention per the CJIS addendum, and personnel-screening attestations for all admins. | B-CO-46 | THR-022, THR-018 | C-11, C-21, C-24 | AUD; INSP |
| GOV-019 | The offline update bundle SHALL be verified with the same TUF roles and thresholds as online updates. Metadata expiry relaxation SHALL be capped at 30 days. | ADR-022; B-CR-45 | THR-025 | C-33 | TST: expired/forged bundle rejection |
| GOV-020 | Disposition SHALL be blocked when a configured schedule requires retention. Crypto-erasure SHALL run only after the disposition approval is recorded. | B-CO-69; ADR-025 | THR-037 | C-10 | TST: schedule engine |
| GOV-021 | Staff-entered reports SHALL carry `channel_of_origin`. They SHALL default to CONFIDENTIAL unless the entering officer attests that no identity was received. | B-CO-02 (Art 9(2)); ADR-002 | THR-040 | C-15, C-10 | TST |
| GOV-022 | Public-body landing pages SHALL list external channels (OSC, IG, PSIC, provincial commissioners, SEC as applicable). They SHALL contain no language restricting external reporting. | B-CO-69; B-CO-02 (Art 9(1)(g)) | THR-040 | C-06, C-37 | INSP: legal template review |
| GOV-023 | GOV profile SHALL disable vendor remote access by default. Enabling it SHALL be CFG-dangerous with an expiry ≤ 72 h. | INC-56; INC-68 | THR-027 | C-19 | TST |
| GOV-024 | EE SHALL provide an ACR (VPAT 2.x INT) based on a third-party audit, updated for every minor release that changes UI. | B-CO-32; B-CO-34; B-CO-35 | — | C-06, C-15 | AUD |
| GOV-025 | HSMs in GOV profile SHALL be FIPS 140-3 validated (Level 3 recommended), located in-zone, with vendor cloud telemetry disabled. | B-CR-29; B-CO-49 | THR-013 | C-29 | INSP: certificate check |
| GOV-026 | AIRGAP-RCP import SHALL use signed one-way batches. Desk SHALL verify signatures before import, and no return channel SHALL exist from the air-gapped network except signed reply batches carried on media. | ADR-012; B-SD-28 | THR-023, THR-013 | C-18, C-15 | TST; ST |
| GOV-027 | The GOV SORN, PIA and DPIA templates SHALL describe every data field stored per zone. They SHALL be generated from the data model, not hand-maintained. | B-CO-16; R6 WB-16 | THR-035 | C-19 | TST: template generator diff vs schema |

## 13. Residual risks and limitations

- Records laws can force retention of data that source protection would delete. That data remains compellable.
- The SOC non-correlation policy is only a policy. A hostile agency can still see Tor use from its own network (THR-002).
- Small municipalities have tiny anonymity sets. No technical control removes content-based identification.
- The FIPS claim does not extend to Tor transport, or to Tier W in-transit plaintext.
- Agencies can be compelled by other agencies. IG independence is legal, not technical.
- UNVERIFIED items: Canadian data-residency instrument, CCCS crypto guidance identifiers, federal GRS coverage of hotline records, state exemption wording.

## 14. Open issues

1. CUI marking support (banner and portion marking) in Desk exports needs a design.
2. Protected B cloud (PBMM) MANAGED region: CCCS assessment path to be decided.
3. ML-DSA-87 (CNSA 2.0 level) for release roots in the GOV profile vs ADR-006's ML-DSA-65: a candidate ADR revision.
