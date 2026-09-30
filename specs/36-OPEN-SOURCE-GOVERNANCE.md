# 36 — Open-Source Governance
Status: Draft v1.1 (revision round 2: ADR-035, ADR-036, ADR-040) · Edition applicability: both · Owner: Candor Foundation Board / Technical Steering Committee

## 1. Purpose and scope

This document defines how the Candor project is governed:
- legal structure;
- maintainers and the security team;
- contribution model (DCO vs CLA);
- trademark policy;
- review rules for Trust Path code;
- vulnerability disclosure shared across CE and EE;
- CVE Numbering Authority (CNA) plan;
- advisory publication;
- EU Cyber Resilience Act role analysis;
- funding;
- succession and bus factor;
- fork-friendliness;
- Edition Charter enforcement;
- signer, builder and witness jurisdiction rules (ADR-040);
- the External Watcher and Key Directory witness programme (ADR-035(1), ADR-036(5));
- project transparency reports and compelled-modification statements.

## 2. Context and dependencies

| Topic | Source |
|---|---|
| Editions and Trust Path | `DECISIONS.md` §2, ADR-020, ADR-022 |
| Watchers, Operator Statement, directory witnesses, signer spread | ADR-035, ADR-036(5), ADR-040 |
| Charter text | `24-LICENSING-BUSINESS-MODEL.md` §7 |
| Secure development | `27-SECURE-DEVELOPMENT.md` |
| Supply chain and signing | `28-SUPPLY-CHAIN.md` |
| Incident response | `31-INCIDENT-RESPONSE.md` |
| Release and update | `33-RELEASE-UPDATE-SECURITY.md` |
| Audits | `37-SECURITY-AUDIT-PLAN.md` |
| Research | R6 D3, D5, D6 (B-CO-50..66); R5 CRA (B-CR-50, B-CR-51); R2 GlobaLeaks governance (B-GL-01..03); R3 supply chain (INC-37..52) |

## 3. Governance model

### 3.1 Legal structure

| Entity | Role | Holds |
|---|---|---|
| **Candor Foundation** (non-profit; jurisdiction to be chosen by the Board with legal review; candidates listed in §19) | Steward of CE. Owns the trademark. Hosts the repository organization, the TUF root keys ceremony and the CNA. Enforces the Charter. | Trademark; domain names; TUF root role (with individual key holders); CNA; Charter |
| **Vendor company(ies)** | Develops and sells EE. Contributes to CE. May be one or several. | Copyright in its own contributions and EE modules; trademark *license* (conditional on Charter compliance) |
| **Contributors** | Individuals and organizations | Their own copyright (DCO) |

Rationale:
- GlobaLeaks shows the value of separating the trademark and license steward (Hermes Center) from the commercial operator (WBS) (B-GL-01).
- It also shows the risk of single-maintainer concentration (R2 §1.1).

### 3.2 Bodies

| Body | Composition | Powers | Decision rule |
|---|---|---|---|
| **Board** | 5–7 directors. ≤ 2 affiliated with any single vendor. ≥ 2 from civil-society or press-freedom organizations. ≥ 1 from a user organization (public body or NGO). | Budget, trademark, Charter enforcement, CNA oversight | Majority. Charter amendments need a 2/3 supermajority and may only strengthen the Charter. |
| **Technical Steering Committee (TSC)** | 5–9 maintainers. ≤ 40% from any single employer. | Architecture (ADRs), release policy, maintainer appointments | Lazy consensus. Contested decisions by 2/3 vote. ADR changes to Trust Path invariants need 2/3. |
| **Security Team** | 4–8 members. ≥ 2 employers. ≥ 2 jurisdictions. Vetted under §6.2. | Vulnerability triage, embargo, advisory, CNA operations | Two-person rule for embargo decisions |
| **Release Signers** | 5 root key holders and 3 targets key holders (ADR-022), spread per §3.4 (ADR-040): no single organisation or jurisdiction can reach any signing threshold. ≥ 1 root key held by an unaffiliated civil-society or press-freedom organisation. | Sign releases after reproducibility verification | Threshold 2-of-3 targets, 3-of-5 root (ADR-022); emergency releases ≥ 2 signers from ≥ 2 organisations after ≥ 2 h cooling (ADR-040) |
| **Watcher and Witness Council** | 3–5 members appointed by the Board; majority from civil-society organisations; ≤ 1 vendor-affiliated | Admits, reviews and removes External Watchers and Key Directory witnesses (§15); publishes the registry | Majority; removal of a watcher needs a published reason |
| **Charter Ombudsperson** | 1 person, independent of all vendors, appointed by the Board for 2 years | Receives Charter complaints and publishes findings | Reports to the Board |

### 3.3 Maintainer roles

| Role | Rights | Appointment | Requirements |
|---|---|---|---|
| Contributor | Open PRs | — | DCO sign-off |
| Reviewer | Approve non-Trust Path PRs | TSC vote | 10 merged PRs; 3 months activity |
| Maintainer | Merge rights on assigned areas | TSC vote | Reviewer for 6 months; hardware-key-signed commits; 2FA with FIDO2 on the forge |
| Trust Path Maintainer | Approve Trust Path PRs | TSC 2/3 vote | Maintainer for 12 months; completed secure-coding review; identity verified by 2 existing TP maintainers |
| Emeritus | None | Automatic after 12 months of inactivity, or on request | — |

### 3.4 Signer, builder and witness spread (ADR-040; RVW-A-16)

| Role | Holders | Spread rule | Rationale |
|---|---|---|---|
| TUF root | 5, threshold 3 | ≥ 3 organisations and ≥ 3 jurisdictions; no organisation and no jurisdiction holds more than 2 keys; ≥ 1 key with an unaffiliated civil-society organisation | A single-jurisdiction order cannot reach 3-of-5 (reconciles REL-007 and SCM-042 on ≥ 3 jurisdictions; cross-document request) |
| TUF targets and delegated trust-path roles | 3, threshold 2 | 3 distinct organisations and 3 distinct jurisdictions (no two holders share either) | 2-of-3 cannot be met inside one organisation or one jurisdiction |
| Reproducible builders | ≥ 2 | Builder A and Builder B operated by different organisations in different jurisdictions | Compelling both builders requires two legal systems |
| Emergency release signing | ≥ 2 signers | ≥ 2 organisations; ≥ 2-hour cooling; source diff and gate evidence published at signing (`27-SECURE-DEVELOPMENT.md` SDL-062) | Keeps review time for watchers and monitors |
| Advisory signing key (Security Team) | ≥ 2 holders | ≥ 2 jurisdictions | Advisory integrity |
| Key Directory witnesses and External Watchers | see §15 | ≥ 1 per watched instance outside the operator's jurisdiction | Split-view and compelled-modification detection |

Jurisdiction is the legal system that can compel the key holder (residence and employer seat); a holder changing jurisdiction triggers re-evaluation within 30 days. Holder spread is re-attested yearly and published.

## 4. Contribution model: DCO, not CLA

**Decision: Developer Certificate of Origin v1.1 (B-CO-56)** with `Signed-off-by`.

| Option | Pros | Cons | Decision |
|---|---|---|---|
| DCO | Low friction. Community-friendly. No relicensing power, so it is a structural guard against relicensing (R6 D3). | No dual licensing | **Chosen** |
| CLA (license grant) | Enables dual licensing | The HashiCorp/Elastic/Redis relicensing path (B-CO-60..62). Deters contributors. | Rejected |
| Copyright assignment to the Foundation | Enforcement standing | Friction. Concentrates power. | Rejected. The Foundation instead relies on DCO plus the trademark for quality control. |

Consequences:
- EE modules must be separate works authored by the vendor (ADR-020).
- Vendors cannot relicense contributors' CE code.
- Enforcement actions against AGPL violators are brought by copyright holders. The Foundation coordinates and may receive enforcement delegation from willing contributors.

## 5. Trademark policy

- **Mark:** "Candor" (working name) and logo, owned by the Foundation.
- **Unmodified builds:** anyone may use the name for **unmodified**, reproducibly built official releases. This includes self-hosting and managed hosting ("Candor, hosted by X").
- **Modified Trust Path:** builds with a modified Trust Path **SHALL NOT** use the name. They must rebrand. This protects sources from lookalike builds (R6 D6.5; INC-14 honeypot lesson).
- **Modified non-Trust Path:** themes and translations are allowed with the name if the Trust Path artifact hashes match the official release.
- **Commercial use of the name** (EE, "Candor Enterprise", certified partner) requires a trademark license. The license is **conditional on Charter compliance** and revocable by Board decision after an Ombudsperson finding.
- **Charter-breach remedy:** if a licensee breaches the Charter, the Foundation may grant any Charter-compliant fork the right to describe itself as "Candor-compatible (Charter-compliant)" (Charter §8).
- **Hosted instances:** a hosted instance using the name must display the operator identity and the release version on the source landing page.

## 6. Contribution and review rules

### 6.1 Trust Path code (paths listed in `TRUSTPATH.toml` at the repo root; CI-enforced)

| Rule | Value |
|---|---|
| Approvals | ≥ 2 Trust Path Maintainers, from ≥ 2 different employers, neither the author |
| Security review | ≥ 1 Security Team member for changes to crypto, key handling, parsing, authentication, authorization, logging schema or update code |
| Commits | Signed with a hardware-backed key registered in `MAINTAINERS.keys` |
| Dependencies | New dependency requires cargo-vet audit entries and a TSC-visible justification. Unsafe code requires a `SAFETY:` justification and a security-team approval. |
| CI | Must pass reproducibility check (2 builders), malicious-server harness (ADR-027), route-authorization inventory (ADR-029), logging allow-list lint (ADR-016), license boundary (BIZ-001) |
| Cooling period | 72 h between final approval and merge for crypto and update code. 24 h otherwise, except embargoed security fixes. |
| AI-generated code | Permitted. Disclosed in the PR. The same review rules apply. The author must be able to explain it. |
| Binary blobs | Prohibited in the Trust Path. Test vectors must be generated or documented. |
| Build-script changes | Treated as Trust Path (INC-37: build-time injection) |

### 6.2 Security Team vetting

Requirements:
- ≥ 12 months of project activity or equivalent verified reputation;
- identity verified by two existing members;
- conflict-of-interest declaration, updated yearly (including employment by governments or security vendors);
- hardware-key 2FA;
- embargo NDA.

Removal is by a 2/3 TSC vote.

## 7. Vulnerability disclosure (shared CE/EE)

| Aspect | Policy |
|---|---|
| Intake | `security@` (PGP and age keys published), a GitHub private advisory, **and an onion service form** (dogfooding Candor itself). Anonymous reports accepted. |
| Scope | All CE code, EE modules, infrastructure (TUF repositories, mirrors, website), documentation errors that cause unsafe configuration |
| Acknowledgement | ≤ 48 h (target 8 h, as GlobaLeaks B-GL-03) |
| Triage and severity | ≤ 5 business days. CVSS v4 **plus** an anonymity-impact rating (A0 none … A3 source identification possible) following Hush Line's anonymity-weighted rubric (R2 §8.9) |
| Fix targets | A3 or critical: ≤ 7 days. High: ≤ 30 days. Medium: ≤ 90 days. Low: next release. |
| Embargo | Default ≤ 90 days. ≤ 14 days if exploited in the wild. |
| **Pre-notification list** | Criteria-based, never payment-based (ENT-030). Eligible: distribution packagers; national CERTs; operators of registered high-risk deployments (CE or EE) vetted by the Security Team. Maximum 7 days before publication. |
| Simultaneity | CE and EE fixes are published at the same moment. EE customers receive no earlier notice than the pre-notification list (Charter §4). |
| Reporter credit | Offered. Anonymous credit supported. |
| Safe harbor | Good-faith research safe-harbor statement. No legal action for research within the policy. |
| Bounty | Funded when revenue allows. Never conditional on NDA beyond the embargo. |
| `security.txt` | On every official domain and on the onion information site |

## 8. CVE Numbering Authority plan

| Phase | Timeline | Action |
|---|---|---|
| P0 | Now to CNA approval | Request CVEs via the GitHub Security Advisories CNA (Knowledge (unverified) re current CNA arrangements) |
| P1 | Before 1.0 GA | The Foundation applies to become a CNA scoped to "Candor project software (CE and EE modules)" under the appropriate root (MITRE or an open-source root such as the OpenSSF-related roots; Knowledge (unverified)) |
| P2 | After approval | ≥ 2 Security Team members trained as CNA operators. CVE records published with CWE, CVSS v4, affected version ranges and CPE/PURL. |
| P3 | Ongoing | Publish OSV records and **CSAF 2.0** advisories with **VEX** statements for dependency CVEs that do not affect Candor |

## 9. Advisory publication

Each advisory contains:
- ID (CVE plus `CANDOR-YYYY-NNN`);
- affected editions, versions and profiles;
- CVSS v4 and anonymity-impact rating;
- description;
- whether exploitation could identify sources or expose content, and **what operators should check**, for example audit indicators;
- fixed versions with TUF target hashes and transparency-log entries;
- workarounds;
- credits.

Channels:
- repository advisories;
- project website plus onion mirror;
- signed mailing list;
- CSAF feed;
- OSV.

Advisories are signed with the Security Team key (ML-DSA-65 + Ed25519 dual signature, ADR-006). Post-incident reports for A2/A3 issues are published within 30 days of the fix.

## 10. EU Cyber Resilience Act analysis (B-CR-50, B-CR-51; legal review required)

| Actor | Likely CRA role | Obligations (summary) | Candor response |
|---|---|---|---|
| Candor Foundation (non-profit; publishes CE; no monetization of CE) | **Open-source software steward**, plausibly. This depends on "sustained support" and on the absence of commercial activity by the Foundation. | Documented cybersecurity policy. Vulnerability handling. Cooperation with market-surveillance authorities. Reporting of actively exploited vulnerabilities (conservative date **11 Sep 2026**, B-CR-50). No CE marking. No fines. | This document plus `27-SECURE-DEVELOPMENT.md` as the published cybersecurity policy. ENISA Single Reporting Platform account (B-CR-51). |
| Vendor(s) selling EE, support or MANAGED | **Manufacturer** for EE products placed on the EU market (Knowledge (unverified) re services vs products) | Essential requirements, conformity assessment, technical file, support period, SBOM, vulnerability handling, reporting (Art 14 from 11 Sep 2026), full obligations from 11 Dec 2027 (B-CR-50) | CRA technical file per EE release (COMP-019). Support period declared (≥ 5 years for LTS). |
| Vendor integrating CE into EE | Manufacturer integrating an open-source component | Due diligence on the integrated component. Report vulnerabilities found to the steward. | Upstream-first fixing. Shared Security Team. |
| Community packagers / redistributors | Depends on commercial activity | — | Guidance page |
| Customers running Candor internally | Generally not manufacturers | — | — |

Open legal questions:
- whether Foundation grant income or donations from vendors create "commercial activity";
- whether MANAGED hosting is a "product" or a service outside CRA scope (possibly NIS2 instead).

**Conservative stance:** the Foundation meets steward obligations and voluntarily follows manufacturer-grade vulnerability handling for CE.

## 11. Funding

| Source | Use | Constraint |
|---|---|---|
| EE vendor contributions (membership fees to the Foundation) | Security team, audits, infrastructure | Vendor ≤ 50% of Foundation annual income (goal by year 3). No vendor board majority. |
| Grants: NLnet/NGI (status UNVERIFIED), Sovereign Tech Agency for base libraries (B-CO-53), OTF (volatile, B-CO-52), press-freedom foundations | Audits, accessibility, crypto libraries, Tor tooling | No grant requiring user analytics (BIZ-012). No single funder > 35% of income. |
| Individual and institutional donations | General | Donor list published above a threshold (e.g., ≥ 5,000 EUR/year) |
| Government open-source programs | Features serving public bodies | Must not introduce requirements conflicting with the Charter |
| Reserve | 12 months of Security Team and infrastructure costs | Target by year 3 |

Lessons applied:
- GlobaLeaks was grant-funded, with volatility and single-maintainer concentration (B-CO-50, B-CO-51, R2 §1.1).
- OTF's 2025 grant termination (B-CO-52) shows why funder diversification is needed.

## 12. Succession and bus factor

| Asset | Minimum holders | Spread | Recovery |
|---|---|---|---|
| Trust Path Maintainers | ≥ 4 active | ≥ 2 employers | TSC appoints; mentorship program |
| Security Team | ≥ 4 | ≥ 2 employers, ≥ 2 jurisdictions | — |
| TUF root keys | 5 holders, threshold 3 | Per §3.4 (≥ 3 organizations, ≥ 3 jurisdictions, ≤ 2 per organisation or jurisdiction) | Documented rotation ceremony. Loss of ≤ 2 keys is recoverable. |
| TUF targets keys | 3 holders, threshold 2 | Per §3.4 (3 organisations, 3 jurisdictions) | Root re-delegation |
| Reproducible builders | ≥ 2 | Different organisations and jurisdictions | Third builder on standby |
| Watcher/witness registry signing key | 3 holders, threshold 2 | ≥ 2 organisations | Board re-issues |
| Forge organization owners | ≥ 3 | ≥ 2 organizations | Board designates |
| Domain registrar and DNS | ≥ 2 accounts with hardware 2FA | Foundation-controlled | Registrar lock |
| Onion keys for project sites | Held offline by ≥ 2 | — | Re-key with a signed announcement |
| CNA credentials | ≥ 2 | — | — |

Additional rules:
- A bus-factor report is published quarterly: the number of people who have merged in each Trust Path area in the last 6 months. Any area with fewer than 2 triggers a TSC action item.
- Dead-man procedure: if no release has been signed for 12 months, or the Security Team is unreachable for 30 days, the Board appoints interim maintainers from the emeritus list.

## 13. Fork-friendliness

The following are designed so that a Charter-compliant fork remains possible if the Foundation or vendor fails:
- all Trust Path code is AGPL;
- build recipes are reproducible;
- documentation is CC BY-SA;
- TUF metadata formats are open;
- data formats (envelopes, key directory, Export Packages) are specified publicly;
- migration tooling can re-point instances to a new TUF root through a documented, locally approved root-rotation procedure (it requires admin dual approval on each instance, so it can never be forced remotely);
- no CLA and no proprietary build dependencies.

The trademark policy is the only restriction: forks rebrand.

## 14. Charter enforcement

| Mechanism | Detail |
|---|---|
| Bylaws | The Charter is incorporated in the Foundation bylaws. Amendment is strengthen-only, by 2/3 Board plus 2/3 TSC. |
| Trademark license | Vendor licenses are conditional on Charter compliance (§5) |
| Automated checks | CI license boundary (BIZ-001). Cross-edition hash equality (CE-002). Release-time source visibility (BIZ-004). Simultaneous fix timestamps (ENT-030). |
| Annual Charter audit | Independent reviewer checks EE module inventory vs Trust Path, advisory timelines, telemetry schema and pricing bases (BIZ-005). The report is public. |
| Ombudsperson | Receives complaints (including anonymously via the project's own Candor instance). Publishes findings within 60 days. |
| Remedies | Public finding. Trademark-license suspension. Fork-endorsement right (Charter §8). |

## 15. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| OSG-001 | The trademark SHALL be owned by a non-profit Foundation, not by any vendor. | B-GL-01; B-CO-60 | THR-024 | C-30 | INSP: registration records |
| OSG-002 | No single vendor SHALL hold more than 2 Board seats or more than 40% of TSC seats. | B-CO-60; B-CO-61 | THR-024 | C-30 | INSP: annual composition report |
| OSG-003 | Contributions SHALL be accepted under DCO v1.1 only. CI SHALL reject commits without `Signed-off-by`. The project SHALL NOT adopt a CLA or copyright assignment for CE. | B-CO-56; R6 D3 | THR-024 | C-30 | TST: DCO check |
| OSG-004 | Trust Path paths SHALL be defined in `TRUSTPATH.toml`. Changes SHALL require ≥ 2 Trust Path Maintainer approvals from ≥ 2 employers, excluding the author. | REQ-H-14; INC-37 | THR-024 | C-30 | TST: branch-protection policy check; AUD |
| OSG-005 | Changes to crypto, key handling, parsing, authentication, authorization, logging schema or update code SHALL require Security Team approval, and SHALL wait 72 h after approval before merging (except embargoed fixes). | INC-37; INC-51 | THR-024, THR-012 | C-30 | TST: merge-gate bot |
| OSG-006 | All commits to protected branches SHALL be signed with hardware-backed keys listed in `MAINTAINERS.keys`. | INC-37; INC-44 | THR-024 | C-30 | TST: signature verification job |
| OSG-007 | Build scripts, CI workflows and release tooling SHALL be treated as Trust Path. CI actions SHALL be pinned by commit hash. | INC-37; INC-44; INC-39 | THR-024 | C-31 | TST: workflow lint |
| OSG-008 | Binary blobs SHALL NOT be committed to Trust Path paths. | INC-37 | THR-024 | C-30 | TST: blob scanner |
| OSG-009 | The vulnerability policy SHALL accept reports via email (PGP/age), forge private advisory, and an onion-service Candor instance, including anonymous reports. | B-GL-03; ADR-001 | THR-024 | C-30 | DEMO; INSP |
| OSG-010 | Acknowledgement SHALL occur ≤ 48 h. Fix targets SHALL be ≤ 7 days for critical/A3, ≤ 30 days high, ≤ 90 days medium. Compliance SHALL be reported yearly. | B-GL-03 | THR-025 | C-30 | AUD: disclosure metrics |
| OSG-011 | Severity SHALL include an anonymity-impact rating A0–A3 in addition to CVSS v4. | R2 §8.9 (B-GL-33) | THR-001, THR-019 | C-30 | INSP |
| OSG-012 | Pre-notification SHALL be criteria-based, SHALL NOT depend on payment, and SHALL precede publication by ≤ 7 days. | ADR-020 | THR-025 | C-30 | AUD: list membership review |
| OSG-013 | CE and EE fixes for shared code SHALL be published at the same time. Timestamps SHALL be recorded in the transparency log. | ADR-020 | THR-025 | C-32 | TST: release timestamp comparison |
| OSG-014 | The Foundation SHALL become a CNA before 1.0 GA. Until then, CVEs SHALL be requested through an existing CNA. | B-CR-50; Knowledge (unverified) | THR-024 | C-30 | INSP |
| OSG-015 | Advisories SHALL be published as CVE, OSV and CSAF 2.0 (with VEX for non-affecting dependency CVEs). They SHALL be signed with the Security Team key. | B-CR-50; SSDF RV (B-CR-47) | THR-025 | C-30 | TST: CSAF schema validation |
| OSG-016 | Advisories for A2/A3 issues SHALL include operator detection guidance. Post-incident reports SHALL be published within 30 days of the fix. | INC-37; INC-38 | THR-019 | C-30 | INSP |
| OSG-017 | The Foundation SHALL publish a CRA cybersecurity policy, register for the ENISA Single Reporting Platform, and report actively exploited vulnerabilities per Art 14 timelines. | B-CR-50; B-CR-51 | THR-024 | C-30 | INSP; DEMO: annual tabletop |
| OSG-018 | Each EE vendor SHALL maintain a CRA technical file and declare a support period ≥ 5 years for LTS releases. | B-CR-50 | THR-025 | C-32 | INSP |
| OSG-019 | TUF root keys SHALL be held by 5 holders from ≥ 3 organizations and ≥ 2 jurisdictions (threshold 3). Targets keys SHALL be held by 3 holders from ≥ 2 organizations (threshold 2). | ADR-022; INC-48; INC-49 | THR-025, THR-026 | C-32 | AUD: key-holder attestation; ceremony records |
| OSG-020 | Every Trust Path area SHALL have ≥ 2 people who merged in the last 6 months. A quarterly bus-factor report SHALL be published. | R2 §1.1 (B-GL-01) | THR-024 | C-30 | TST: report generator from git history |
| OSG-021 | The Foundation SHALL maintain a documented dead-man procedure (12 months without release, or 30 days Security Team unreachable, triggers Board appointment of interim maintainers). | B-CO-52 | THR-025 | C-30 | INSP |
| OSG-022 | No single funder SHALL exceed 35% of Foundation annual income, and vendor income SHALL NOT exceed 50%, from year 3. Funders above the published threshold SHALL be disclosed. | B-CO-52; B-CO-50 | THR-026 | C-30 | AUD: financial statement |
| OSG-023 | Instances SHALL support a locally approved TUF root rotation (dual admin approval), enabling migration to a fork's update root without a remote forcing mechanism. | ADR-022; B-CR-45 | THR-025 | C-33, C-19 | TST: root-rotation drill |
| OSG-024 | The Edition Charter SHALL be incorporated in the bylaws and trademark licenses. An independent Charter audit SHALL be published annually. | ADR-020 | THR-024 | C-30 | AUD |
| OSG-025 | A Charter Ombudsperson independent of vendors SHALL accept complaints (including anonymous ones) and publish findings within 60 days. | ADR-020; INC-22 | THR-024 | C-30 | INSP |
| OSG-026 | Hosted instances using the trademark SHALL display the operator identity and release version on the source landing page. | INC-14 | THR-040 | C-06 | INSP: trademark-license condition; TST: template |
| OSG-027 | Builds whose Trust Path artifact hashes differ from official releases SHALL NOT use the trademark. The trademark policy SHALL require rebranding of such forks. | INC-14; R6 D6 | THR-007, THR-024 | C-30 | INSP |
| OSG-028 | AI-assisted contributions SHALL be disclosed in the PR and SHALL meet identical review rules. | B-GL-19 | THR-024 | C-30 | INSP: PR template check |

## 16. Residual risks and limitations

- **DCO leaves the Foundation without copyright standing.** AGPL enforcement depends on contributors.
- **Governance cannot stop a determined insider** within threshold limits. The two-employer and threshold rules raise the collusion cost but do not remove it (INC-37).
- **Legal compulsion** of individual key holders in one jurisdiction is mitigated by jurisdiction spread, not eliminated (THR-026).
- **CRA role determinations** are unsettled. The conservative stance may impose costs.
- **Funding caps** may slow development in early years.

## 17. Open issues

1. Foundation jurisdiction. Candidates: a Swiss association, a German e.V., a Dutch stichting, a US 501(c)(3), or a fiscal host (e.g., an existing open-source foundation). Criteria: legal compulsion exposure, CRA steward status, grant eligibility.
2. Whether the TUF root should include one key held by an unaffiliated press-freedom organization.
3. Bounty funding source and scale.
