# R6 — Compliance, Accessibility & Licensing Research for a Whistleblowing Platform

**Purpose:** input to a *control mapping* for a whistleblowing platform shipped as a FOSS **Community Edition (CE)** and a commercial **Enterprise/Government Edition (EE)**. This is not legal advice. Every obligation below should be confirmed by counsel in the deploying jurisdiction before it is treated as a requirement.

**Research date:** 2026-09-30.

**Method and limitations (read this first):**
- Research used web search over primary and secondary sources. Direct page fetches were blocked by the session egress proxy for most primary hosts (eur-lex, edps, nist, fedramp, ada.gov, justice.gc.ca, law.cornell.edu). The session's web-search budget also ran out before every item could be checked.
- Each statement therefore carries a verification tag:
  - **[V]**: confirmed in-session from a search result that quotes or summarizes the primary source, or from a reputable secondary source that cites it. The bibliography ID is given.
  - **[K]**: from the researcher's prior knowledge of the primary text (stable, long-standing law or standards). It was **not re-verified in this session**. Treat it as needing citation check before publication.
  - **UNVERIFIED**: a specific fact (date, number, status) that could not be confirmed. It must be checked before anyone relies on it.
- No URLs, case numbers or figures have been invented. Where a URL is given as "canonical, not fetched", it follows the publisher's standard pattern, but it was not opened in-session.

---

## 0. Executive summary: what matters most for the product

1. **Clocks are configurable policy, not constants.**
   - The EU Directive sets a 7-day acknowledgement (calendar days) and 3-month feedback for internal channels. For external channels, feedback is 3 months, extendable to 6.
   - Alberta practice uses 5 / 10 / 120 *business* days.
   - SOX, the SEC, DOJ's 120-day window and FCA seals all run their own clocks.
   - Product implication: one jurisdiction-aware **SLA engine** (calendar vs business days, holiday calendars, pause/extension with justification, audit trail).
2. **Identity confidentiality is statutory in almost every regime.** Sources include EU Art 16, 5 USC 407(b) (IG), 5 USC 1213(h) (OSC), PSDPA s.11, SEC Rule 21F-7, and Australia s.1317AAE.
   - Product implication: a **sealed-identity model**. Identity and "identity-deducible" data are compartmented. Unsealing needs a recorded legal basis and dual control, and the reporter is notified where law requires (EU Art 16(3)). Every access is tamper-evidently logged.
3. **GDPR and whistleblower confidentiality collide at Art 15 (access) and Art 14 (notice to persons concerned).**
   - The resolution is Art 15(4) (rights of others), Art 14(5)(b), and national Art 23 restrictions.
   - Product implication: a **DSAR workflow with restriction reasons**, deferred-notice timers and redaction. It must not be a one-click "export everything".
4. **Accessibility deadlines are live.**
   - US ADA Title II rule: WCAG 2.1 AA. Deadlines were **extended by one year** by a DOJ interim final rule on 2026-04-20, to 2027-04-26 and 2028-04-26 **[V B-CO-30]**.
   - EAA applies since 2025-06-28. EN 301 549 v4.1.1 (WCAG 2.2) was published 2026-09-02, with OJ citation expected in late 2026 **[V B-CO-34]**.
   - Section 508 is still WCAG 2.0 AA **[V B-CO-32]**.
   - Build to **WCAG 2.2 AA** (ISO/IEC 40500:2025 **[V B-CO-28]**) plus COGA patterns. That satisfies all of them.
5. **Security baselines.**
   - US: SP 800-53 Rev 5 **Release 5.2.0** (2025-08-27; new SA-15(13), SA-24, SI-2(7)) **[V B-CO-40]**; SP 800-63-4 (2025-07-31) **[V B-CO-41]**; FedRAMP 20x KSIs **[V B-CO-43]**; GovRAMP (renamed from StateRAMP 2025-02) **[V B-CO-44]**; CJIS v6.0 **[V B-CO-46]**; CMMC in DFARS since 2025-11-10 **[V B-CO-45]**.
   - Canada: ITSG-33 with the CCCS Medium cloud profile / PBMM **[V B-CO-48]**.
6. **Licensing recommendation.**
   - License the CE as **AGPL-3.0-or-later**, with the **DCO** (not a CLA).
   - Rule: **no closed code in the whistleblower trust path** (reporter UI, crypto, submission/storage, key handling, anonymity features).
   - EE value sits in integrations, scale, compliance packaging, assurance artefacts and support.
   - Avoid BSL/FSL/SSPL for anything security-relevant. The HashiCorp→OpenTofu, Elastic and Redis episodes show the trust and fork cost **[V B-CO-60..63]**.

---

## TOPIC A — Whistleblowing law and standards

### A1. ISO 37002:2021 — Whistleblowing management systems (guidelines)

- **Nature:** guidance ("should"). It is **not certifiable**, and it applies to all organizations regardless of type or size **[V B-CO-01]**.
- **Principles:** trust, impartiality and protection. Some summaries add accessibility **[V B-CO-01]**.
- **Structure:** the ISO harmonized structure, clauses 4–10 **[K]**:
  - **4 Context:** issues, interested parties, scope of the WMS. Decide who can report (employees, contractors, suppliers, public) and on what.
  - **5 Leadership:** top-management commitment, whistleblowing policy, roles. A *whistleblowing function* independent of line management.
  - **6 Planning:** risks and opportunities, objectives.
  - **7 Support:** resources, competence, awareness, communication, documented information. This includes confidentiality of documented information.
  - **8 Operation:** the four-step process **[V B-CO-01]**:
    - **8.1 Receiving reports:** multiple channels, anonymous option, acknowledgement, recording.
    - **8.2 Assessing reports:** triage, including the likelihood and seriousness of wrongdoing *and* the **risk of detriment to the whistleblower** (a detriment risk assessment) **[K]**.
    - **8.3 Addressing reports:** investigation, protection and support of the whistleblower and of relevant interested parties (including persons implicated).
    - **8.4 Concluding cases:** close-out, feedback to the whistleblower, records, and monitoring for detriment after closure.
  - **9 Performance evaluation:** monitoring, measurement, internal audit, management review. Metrics such as volume, time-to-acknowledge, time-to-close, substantiation rate and detriment incidents.
  - **10 Improvement:** nonconformity and corrective action, continual improvement.
- **Relation to other ISO standards [K]:**
  - **ISO 37301:2021** (compliance management systems) is *requirements*, Type A (certifiable). It contains a "raising concerns" requirement that ISO 37002 can operationalise.
  - **ISO 37001** (anti-bribery) also requires a "raising concerns" procedure. ISO 37002 is the detailed "how".
  - Whether a revised ISO 37001 edition was published in 2025 is **UNVERIFIED**.
  - All three share the harmonized structure, so one integrated management system is feasible.

**Platform implications:**
- Case lifecycle states aligned to 8.1–8.4.
- A **detriment-risk assessment** form at triage, with periodic reassessment and post-closure check-ins.
- Impartial routing with conflict-of-interest recusal.
- A policy and document repository.
- A KPI dashboard (clause 9).
- A corrective-action register (clause 10).

### A2. EU Directive (EU) 2019/1937 (Whistleblower Protection Directive)

Article content below is **[K]** from the Directive text (canonical: [B-CO-02]) unless noted otherwise.

| Article | Obligation | Platform requirement |
|---|---|---|
| Art 4 | Personal scope: workers, self-employed, shareholders, management bodies, volunteers and trainees, job applicants, former workers, contractors and suppliers | Intake form with a "relationship to organization" taxonomy. Channels must be openable to non-employees (Art 8(2)). |
| Art 6(2) | Member states decide whether legal entities must accept and follow up **anonymous** reports | Per-tenant switch: "accept anonymous" on or off. The default should be on, because several member states require it. |
| Art 7(2) | Encourage internal reporting first where the breach can be addressed internally without retaliation risk | Public-facing page explaining internal vs external options (see Art 9(1)(g)). |
| Art 8(1),(3) | Legal entities in private and public sectors must establish internal channels. The private-sector obligation applies to entities with **50 or more workers** (financial-services entities regardless of size, Art 8(4)). | Licensing and packaging that suits SMEs. |
| Art 8(5) | Channels may be operated **by a third party** | Hosted/SaaS mode and processor contracts (GDPR Art 28). |
| Art 8(6) | Entities with **50–249 workers** may **share resources** for receipt and investigation | Multi-tenant "shared service" mode. Confidentiality and follow-up duties stay with each entity, so strict tenant separation is required. |
| Art 8(9) | Public sector: all public entities, but member states *may exempt* **municipalities with fewer than 10,000 inhabitants or fewer than 50 workers**. Channels may be shared between municipalities or run by joint authorities. | Municipal consortium mode with separated tenants. |
| Art 9(1)(a) | Channels designed and operated **securely**, ensuring confidentiality of the reporter and any **third party mentioned**, and preventing access by unauthorised staff | Need-to-know RBAC per case, encryption, audit. Third-party names in reports also get protection. |
| Art 9(1)(b) | **Acknowledge receipt within 7 days** | SLA timer (default 7 calendar days, configurable). Auto-acknowledge option through the anonymous mailbox. |
| Art 9(1)(c) | Designate an **impartial** person or department to follow up, maintain communication, ask for further information and give feedback | Handler assignment, COI recusal, and a two-way anonymous messaging channel. |
| Art 9(1)(d),(e) | Diligent follow-up, including of anonymous reports where national law provides | Case tasks, investigation plan. |
| Art 9(1)(f) | **Feedback within a reasonable timeframe not exceeding 3 months** from acknowledgement, or 3 months from the end of the 7-day period if there was no acknowledgement | A second SLA timer anchored to the acknowledgement date (or day 7). A "feedback given" event is required. |
| Art 9(1)(g) | Clear and easily accessible information on **external** reporting procedures | Per-jurisdiction content blocks listing competent authorities. |
| Art 9(2) | Reporting **in writing or orally, or both**. Oral reporting by telephone or voice messaging, and on request a **physical meeting within a reasonable timeframe**. | Web written channel, voice-message upload with **voice distortion** option (a common industry practice, not a Directive requirement), and a meeting-request workflow. |
| Art 11(2) | External (authority) channels: acknowledge within 7 days (unless the reporter asked otherwise or it would jeopardise protection); feedback **3 months, or 6 months in duly justified cases** | Regulator/authority deployments (EE). Support a justified-extension flag. |
| Art 12 | External channels must be independent and autonomous, ensure completeness, integrity and confidentiality, and give durable storage. **Art 12(4):** staff who receive reports through other channels must forward them **promptly and without modification**. | Integrity hashing of original submissions (immutable original plus a working copy). A "forward/refer" function that preserves the original. |
| Art 13 | Authorities publish information on their websites (conditions, contact details, procedures, confidentiality rules) | Public-information CMS pages. |
| Art 16(1) | Reporter identity must not be disclosed to anyone beyond authorised staff without **explicit consent**. This also covers **any other information from which identity may be directly or indirectly deduced.** | A sealed identity vault, redaction tooling for indirect identifiers (role, location, writing style caveat), and consent capture. |
| Art 16(2)–(3) | Disclosure only where there is a necessary and proportionate legal obligation (investigations, judicial proceedings). The reporter must be **informed beforehand with written reasons**, unless that would jeopardise the investigation. | An "unseal" workflow: legal basis field, dual approval, templated notice to the reporter through the mailbox, and a deferral reason if the notice is withheld. |
| Art 17 | Processing under GDPR and EUDPR. Personal data manifestly not relevant **shall not be collected, or if accidentally collected, deleted without undue delay** | A triage action "mark irrelevant → purge" with an audit record that does not keep the content. |
| Art 18(1) | Keep **records of every report**, stored no longer than necessary and proportionate | Case register plus retention engine. |
| Art 18(2)–(4) | Recorded phone or voice: with consent, keep a recording or a complete, accurate transcript. Unrecorded line: accurate minutes. Meetings: recording or minutes. The reporter can **check, rectify and agree by signing** the transcript or minutes. | Transcript editor with a reporter review/sign-off step (e-signature or mailbox confirmation). Consent capture before recording. |
| Art 22 | Identity of **persons concerned** is protected while investigations are ongoing | RBAC and confidentiality flags also apply to subjects. |
| Art 23 | Member states must penalise breaches of confidentiality and hindering of reporting | Audit evidence for accountability. |
| Art 26 | Transposition deadline 17 Dec 2021; Art 8(3) for 50–249-worker entities from **17 Dec 2023** | — |
| Art 27 | Member-state statistics (annual, Art 27(2)); Commission reports | Statistics export (EE regulator mode). |

**Transposition and enforcement status:**
- The Commission's Art 27(1) implementation report is **COM(2024) 269, dated 3 July 2024**. It found that all 27 member states have transposing laws but none is yet fully compliant. Gaps include material scope and retaliation protection **[V B-CO-03, B-CO-04]**.
- **CJEU financial penalties, 6 March 2025:**
  - Cases: C-149/23 Germany, C-150/23 Luxembourg, C-152/23 Czechia, C-154/23 Estonia, C-155/23 Hungary.
  - Lump sums: Germany €34m; Czechia €2.3m; Hungary €1.75m; Luxembourg €375k; Estonia €500k plus a €1,500/day periodic penalty **[V B-CO-05, B-CO-06]**.
  - Poland's separate case and penalty (reportedly C-147/23, 2024) are **UNVERIFIED**. The fate of the Spain and Italy referrals is **UNVERIFIED**; they were reportedly withdrawn after transposition.
- **Evaluation and action plan:**
  - The Commission opened a consultation on 25 Aug 2025 toward an **Action Plan on Whistleblower Protection** and an evaluation of the Directive. A questionnaire ran **28 Jan – 22 Apr 2026** **[V B-CO-04, B-CO-07]**.
  - NEIWA (the network of national whistleblowing authorities) filed a submission on "review and potential amendment" in April 2026 **[V B-CO-08]**.
  - Whether the Art 27(3) impact report (due 17 Dec 2025) has been published is **UNVERIFIED**.
  - Product implication: expect possible amendment proposals in 2026–2027. Keep scope and timelines data-driven, not hard-coded.

### A3. GDPR as applied to whistleblowing

All GDPR items are **[K]**; the canonical text is [B-CO-09].
- **Art 5 principles:** purpose limitation, minimisation, storage limitation, integrity/confidentiality, accountability.
  - Product: minimal intake fields, retention engine, audit.
- **Art 6(1)(c)** (legal obligation, where national law transposes the Directive) or 6(1)(e) (public task) or 6(1)(f) (legitimate interest, for voluntary schemes). **Art 9/10** covers special-category and criminal-offence data, which is common in reports.
  - Product: a per-tenant lawful-basis register; special-category flags on case data.
- **Art 13/14 transparency:**
  - The *person concerned* must normally be informed (Art 14). **Art 14(5)(b)** allows deferral where informing would seriously impair the objectives.
  - Product: a deferred-notice timer and reason; templates.
- **Art 15 access vs confidentiality:**
  - **Art 15(4):** the right to a copy must not adversely affect the rights and freedoms of others, which includes the reporter.
  - **Art 23:** member-state restrictions. Many national transposition laws restrict access rights to protect the reporter.
  - EDPS and DPA guidance: restrictions need internal rules and **documented reasons** **[V B-CO-10, B-CO-11]**.
  - Product: a DSAR module that auto-flags whistleblowing cases, requires a restriction-reason code, supports partial disclosure with redaction, and logs the decision.
- **Art 25 data protection by design and by default:**
  - No IP logging on reporter endpoints.
  - Metadata stripping of attachments.
  - No third-party scripts, fonts or analytics on reporter pages.
  - Opt-in telemetry only.
- **Art 28:** processor terms for SaaS/EE hosting. **Art 30:** ROPA export.
- **Art 32:** encryption, pseudonymisation, resilience, regular testing.
- **Art 33/34:** breach notification (72h to the supervisory authority). The incident workflow must be able to assess whistleblower-identity exposure as high risk.
- **Art 35 DPIA:** whistleblowing schemes typically meet WP248/EDPB criteria (sensitive data, vulnerable data subjects, systematic evaluation). Several national DPIA lists name whistleblowing explicitly; the French CNIL list is **[K]**, and the exact list entries are UNVERIFIED.
  - Product: ship a **DPIA template** and a data-flow description per edition.
- **Chapter V transfers:** data-residency choice and a subprocessor register.

**Regulator guidance:**
- **EDPS Guidelines on processing personal information within a whistleblowing procedure (Dec 2019)** update the 2016 guidance. They apply to EU institutions under Reg. 2018/1725 but are widely used as a reference **[V B-CO-10]**. Key themes: defined channels, confidentiality of all persons, minimisation, restriction of rights with documented reasons.
  - Specific EDPS retention recommendations (e.g., short deletion windows for non-pursued reports) were not verified in-session: **UNVERIFIED**.
- **CNIL référentiel "alertes professionnelles":** deliberation **n° 2023-064 of 6 July 2023**, replacing the 2019 version **[V B-CO-12]**. It covers retention, security, outsourcing, anonymous reports and information duties. It explicitly applies to third-party providers of reception/processing services.
- **EDPB:** no dedicated whistleblowing guideline was found; **UNVERIFIED** whether one exists as of 2026. The EDPB's general guidance (Art 23 restrictions guidelines 10/2020, DPIA, data protection by design 4/2019) applies **[K]**.

### A4. United States — federal

| Regime | Key provisions | Platform implications |
|---|---|---|
| **Whistleblower Protection Act (1989)**, 5 USC 2302(b)(8)–(9) **[K]** | Prohibits personnel actions against federal employees for protected disclosures | Retaliation-tracking fields, and export for OSC/MSPB proceedings. |
| **WPEA 2012** (Pub. L. 112-199) **[K]** | Clarifies that "any disclosure" is protected (including to supervisors and in normal duties, with conditions). **Anti-gag:** non-disclosure policies must carry a statement preserving whistleblower rights, 5 USC 2302(b)(13). | Platform terms, NDAs and banners must not restrict protected disclosures. Ship an "anti-gag" standard statement in templates. |
| **OSC**, 5 USC 1213 **[K]** | OSC Disclosure Unit. **1213(h):** the identity of a whistleblower may not be disclosed without consent unless there is imminent danger to public health or safety or an imminent violation of criminal law. | Sealed identity plus an emergency-disclosure exception path. |
| **IG Act** (recodified at 5 USC 401–424 by Pub. L. 117-286, 2022) **[K]**; **5 USC 407(b)** **[V B-CO-13]** | An IG shall not, after receiving a complaint or information from an employee, disclose the employee's identity without consent, *unless the IG determines disclosure is unavoidable during the investigation*. IG Whistleblower Protection Coordinator **[K]**. | An "unavoidable disclosure determination" record type. Hotline intake for employees *and* the public (most IG hotlines accept public and anonymous reports). |
| **Sarbanes-Oxley §301**, 15 USC 78j-1(m)(4) **[K]** | The audit committee must establish procedures for (A) the receipt, retention and treatment of complaints about accounting, internal controls and auditing, and (B) the **confidential, anonymous submission by employees** of concerns | A category-based routing rule: accounting/audit concerns go **directly to the audit committee** queue, bypassing management. Retention settings. |
| **SOX §806**, 18 USC 1514A **[K]** | Retaliation protection. A complaint is filed with OSHA, 180-day limit. | Retaliation case type; deadline reminders. |
| **Dodd-Frank §922**, 15 USC 78u-6; SEC Rules 17 CFR 240.21F **[K]** | Awards of 10–30% of sanctions over $1M. **Rule 21F-7** confidentiality; anonymous submission via counsel. **Rule 21F-17(a):** no person may impede an individual from communicating with the SEC (including through confidentiality agreements). FY2025: about 27,000 tips, about $60M awarded **[V B-CO-14]**. | Never block or deter external reporting. The UI must state that reporters may go to the SEC, CFTC and others. Export packages for counsel. |
| **False Claims Act**, 31 USC 3729–3733 **[K]** | **Qui tam:** 3730(b); the complaint is filed **under seal for 60 days** (extendable); 3730(h) retaliation. **Status:** on 2026-09-01 the 11th Circuit (*Zafirov*) held that the qui tam provisions do not violate the Appointments Clause, reversing the 2024 district ruling; other Article II challenges were remanded **[V B-CO-15]**. | Litigation-hold and "sealed matter" flag restricting internal circulation. Legal-hold overrides retention. |
| **41 USC 4712** (civilian contractors and grantees; NDAA FY2013 §828, pilot made permanent 2016) and **10 USC 4701** (DoD/NASA, formerly 10 USC 2409) **[V B-CO-16; K for 10 USC 4701 renumbering]** | Protects disclosures of gross mismanagement of a federal contract or grant, gross waste, abuse of authority, or violation of law. The IG investigates and reports (180 days **[K]**). Contractors must inform employees of their rights **[K]**. | Contractor tenants: rights-notice content; routing to the agency OIG. |
| **DOJ Corporate Whistleblower Awards Pilot** (2024-08-01; updated 2025-05-12) **[V B-CO-17]** | Awards for original information leading to forfeiture over $1M in specified areas. A **120-day** window links internal reports to DOJ eligibility and company self-disclosure credit **[K — mechanics UNVERIFIED in-session]**. | A 120-day clock from internal-report date for corporate tenants (a compliance-counsel alert). |
| **FOIA / Privacy Act** interaction **[K]** | FOIA exemptions 5 USC 552(b)(6) (personal privacy), (b)(7)(C) (law-enforcement privacy), **(b)(7)(D) (confidential source)**, (b)(5) (deliberative). Privacy Act system-of-records notice; (k)(2) investigatory exemption, with a promise of confidentiality. | Per-record FOIA/ATIP **exemption tagging** and redaction export; a SORN template for agencies. |

**Other federal programs to support as referral destinations [K]:** CFTC, IRS (26 USC 7623), FinCEN AML whistleblower (AMLA 2020, 31 USC 5323), OSHA's many statutes, and the Intelligence Community (PPD-19, 50 USC 3234) — the IC is out of scope for EE without an accreditation strategy.

### A5. United States — states and municipalities

- **California Labor Code §1102.5 [K]:**
  - Protects disclosures to government or law enforcement, to a person with authority over the employee, or to another employee with authority to investigate. Also covers refusing to participate in unlawful activity.
  - A civil penalty applies; the 2024 amendment (SB 497) created a rebuttable presumption for adverse action within 90 days (**UNVERIFIED**).
  - **California Whistleblower Protection Act** (Gov. Code §8547 et seq.; State Auditor hotline) and §53296 et seq. for local-agency employees **[K]**.
  - Implication: the internal "person with authority to investigate" is itself a protected channel, so internal-channel records matter in litigation.
- **New York Labor Law §740, amended effective 2022-01-26 [V B-CO-18]:**
  - Covers **former employees and independent contractors**.
  - "Reasonable belief" standard.
  - A **notice must be posted conspicuously**, and **[K]** may also be posted electronically.
  - Public employees: Civil Service Law §75-b **[K]**.
  - Implication: a rights-notice content module; the contractor/former-employee intake taxonomy.
- **State public-records confidentiality [K]:**
  - Many states shield whistleblower identity and IG/auditor hotline records from public-records requests. An example is Florida §112.3188; exact wording is UNVERIFIED.
  - Implication: records tagged for state public-records exemptions; per-state configuration.
- **Municipal ethics, IG and auditor hotlines [K]:**
  - Examples: the NYC Department of Investigation, the Chicago Office of Inspector General (Municipal Code ch. 2-56, with confidentiality provisions — exact section UNVERIFIED), and city auditor fraud hotlines under Yellow Book / ACFE practice.
  - Typical needs: public (non-employee) reports, anonymous intake, a telephone option, Spanish and other languages, public annual statistics, and ADA Title II accessibility (see C3).
- **State records retention [K]:** state archives set retention schedules (e.g., for audit/IG case files). The platform needs a schedule-import function per tenant.

### A6. Canada — federal

- **Public Servants Disclosure Protection Act (PSDPA), S.C. 2005, c. 46 [K]:**
  - **s.10:** chief executives must establish internal procedures and designate a senior officer for disclosures.
  - **s.11:** chief executives must protect the identity of persons involved and the confidentiality of information, subject to other law and procedural fairness.
  - **s.12:** disclosure to a supervisor or senior officer. **s.13:** disclosure to the **Public Sector Integrity Commissioner (PSIC)**.
  - **s.16:** public disclosure in limited urgent cases. **s.19:** reprisal prohibited. **s.44:** Commissioner confidentiality.
  - Annual reporting by chief executives **[K]**.
  - Canonical source [B-CO-19].
- **Access to Information Act s.16.5 [V B-CO-20]:** the head of a government institution **shall refuse** to disclose any record containing information created for making a PSDPA disclosure or in the course of an investigation into one.
  - The parallel Privacy Act s.22.3 is **[K]**.
  - Product: mandatory ATIP-exemption tag on all PSDPA case records.
- **Reform:**
  - A TBS-led review and task force (2021–2022) is **[K]**; the report details are UNVERIFIED.
  - **Bill C-290** (Public Sector Integrity Act; private member's bill, Bloc Québécois) reached **second reading in the Senate (Oct 2024)** and **died on prorogation in January 2025**. It would have broadened coverage (including contractors), added protected recipients, extended the reprisal-complaint period and added a duty to support whistleblowers **[V B-CO-21]**.
  - Any 2025–2026 reintroduction is **UNVERIFIED**.
  - Product implication: keep coverage categories (e.g., contractors, RCMP, CAF) configurable.
- **Privacy:**
  - The **Privacy Act** covers federal institutions **[K]**. TBS Directive on Privacy Impact Assessment **[K]**: a PIA is required for new programs using personal information.
  - Private sector: **PIPEDA** still governs.
  - **Bill C-27** (CPPA/AIDA) died on prorogation in January 2025 **[V B-CO-22]**.
  - **Bill C-36, the Protecting Privacy and Consumer Data Act (PPCDA),** was introduced **2026-06-15**. It would replace PIPEDA Part 1 and create a Digital Safety and Data Protection Commission, with stronger cross-border transfer rules **[V B-CO-22, B-CO-23]**. It is not law as of 2026-09-30 (**UNVERIFIED** whether it has passed second reading).
- **Security:**
  - **ITSG-33** (IT security risk management; control catalogue derived from NIST 800-53) **[K]**.
  - **ITSP.50.103** cloud security categorization and the **CCCS Medium cloud control profile** for **Protected B / Medium integrity / Medium availability (PBMM)** **[V B-CO-48]**.
  - PSDPA case files are typically **Protected B**. Some may be Protected C, which is out of scope for cloud **[K]**.
  - Data residency: the GC direction to store Protected B and below in Canada for cloud (Direction on Electronic Data Residency / TBS policy instruments) is **[K]**; the exact current instrument is UNVERIFIED.
- **Records:** Library and Archives of Canada Act, **s.12** (no disposal without consent of the Librarian and Archivist, via disposition authorities) **[K]**.
- **Language:** the **Official Languages Act** requires bilingual (EN/FR) service for federal institutions **[K]**. The UI and notices must be fully bilingual.

### A7. Canada — provinces

- **Ontario:** Public Service of Ontario Act, 2006, **Part VI** (disclosure of wrongdoing); the **Integrity Commissioner** is the external recipient **[K]**. Municipal whistleblowing is by local by-law or policy (e.g., the Toronto Auditor General Fraud & Waste Hotline) **[K]**.
- **Alberta:** Public Interest Disclosure (Whistleblower Protection) Act; **Public Interest Commissioner** **[K]**.
  - Institutional procedures made under it (school divisions) specify **acknowledgement within 5 business days**, a **decision on investigation within 10 business days**, and **investigation completion within 120 business days**, with extensions by the chief officer or Commissioner **[V B-CO-24]**.
  - Whether these figures are statutory or policy is **UNVERIFIED**; the statute text was not fetched.
  - Implication: **business-day SLA calendars** are mandatory in the SLA engine.
- **British Columbia:** Public Interest Disclosure Act, S.B.C. 2018 c.22. In force for ministries from Dec 2019, with **phased expansion** to the broader public sector; the BC Ombudsperson is the external recipient **[K]**. A 2025/26 annual report exists **[V B-CO-25]**.
- **Québec:**
  - **Act to facilitate the disclosure of wrongdoings relating to public bodies (CQLR c. D-11.1):** assented 2016-12-09, in force 2017-05-01, with the **Protecteur du citoyen** as recipient **[V B-CO-26]**.
  - Extended to **municipalities from 2018-10-19**, with municipal disclosures going to the Commission municipale du Québec's **Commissaire à l'intégrité municipale et aux enquêtes** **[V B-CO-26]**.
  - **Law 25** (S.Q. 2021, c. 25) **[K]**, phased in 2022–2024:
    - a **privacy impact assessment** for any information-system project involving personal information;
    - a **PIA before communicating personal information outside Québec**;
    - confidentiality-incident register and notification;
    - **privacy by default** (highest confidentiality settings by default);
    - a designated person in charge of personal information.
  - The Charter of the French Language (as amended by Bill 96) requires French-language availability **[K]**.

### A8. Reference regimes

- **UK Public Interest Disclosure Act 1998** (inserted Part IVA and s.47B into the Employment Rights Act 1996) **[K]**:
  - Qualifying disclosures made in the reasonable belief that they are in the public interest; prescribed persons.
  - **No statutory duty** to run internal channels. FCA SYSC 18 does require them for certain financial firms **[K]**.
  - Failure-to-prevent-fraud offence (ECCTA 2023, in force 2025-09-01) and "reasonable procedures" guidance, which references whistleblowing **[K; UNVERIFIED in-session]**.
- **Australia, Corporations Act 2001 Part 9.4AAA [K]:**
  - s.1317AA eligible whistleblowers and recipients; **s.1317AAE** identity confidentiality (an offence to disclose); s.1317AAD public-interest and emergency disclosures.
  - **s.1317AI:** public companies and large proprietary companies must have a whistleblower policy.
  - ASIC Regulatory Guide 270 **[K]**.

---

## TOPIC B — Security frameworks, records and residency

| Framework | Status (as of 2026-09-30) | Implication |
|---|---|---|
| **NIST CSF 2.0** | Published Feb 2024; adds the **Govern (GV)** function **[K]** | Map platform controls to GV/ID/PR/DE/RS/RC. Useful for municipalities and non-federal buyers. |
| **SP 800-53 Rev 5, Release 5.2.0** | 2025-08-27. New **SA-15(13)**, **SA-24**, **SI-2(7)**; revised **SI-7(12)**; driven by EO 14306 on software update/patch integrity. 800-53B baselines re-issued unchanged **[V B-CO-40]**. | Signed updates, integrity verification, secure update channel, developer testing evidence, **reproducible builds**. These also serve FOSS trust. |
| **SP 800-63-4** | Final **2025-07-31** **[V B-CO-41]**. AAL2 verifiers must **offer a phishing-resistant option**. AAL3 requires phishing-resistant, non-exportable keys. **Syncable authenticators (passkeys)** are recognised (usable at AAL2, not AAL3). | Handlers and admins: WebAuthn/passkeys by default; PIV/CAC and hardware keys for AAL3 (EE). **Reporters must never be required to authenticate** (anonymity), so use a receipt code or key only. |
| **FIPS 140-3** | Current CMVP standard. The FIPS 140-2 validations sunset (moved to historical) in **Sept 2026** **[K — UNVERIFIED exact date]**. | EE "FIPS mode" using a **140-3-validated** module (e.g., the OpenSSL 3 FIPS provider or AWS-LC FIPS; check certificates at time of build). |
| **FIPS 201-3** (PIV) | Published Jan 2022 **[K]** | PIV/CAC smart-card login for federal handlers (EE), via SAML/OIDC IdP federation. |
| **FedRAMP 20x** | Phase 2 (Moderate) pilot ran 2025-11-18 to end of Mar 2026. First pilot authorizations 2026-03-06; 6 more by 2026-04-27. **KSIs:** about 56 Low and 61 Moderate indicators (per a secondary source), machine-readable and continuously validated **[V B-CO-43]**. | EE SaaS: produce **machine-readable evidence (OSCAL/KSI)** from the platform. The CE self-host does not need FedRAMP; the agency authorizes its own hosting. |
| **GovRAMP** (formerly StateRAMP) | Rebranded 2025-02-14; same legal entity **[V B-CO-44]** | State and local SaaS buyers. Reuses the FedRAMP-style 800-53 baselines **[K]**. |
| **CMMC 2.0** | DFARS final rule (48 CFR) published 2025-09-10, **effective 2025-11-10**. Three-year phase-in to 2028-11-10 **[V B-CO-45]**. | Relevant only if the platform processes CUI for DoD contractors, e.g., hotline cases containing CUI. EE deployment guidance aligned with NIST SP 800-171. |
| **CJIS Security Policy v6.0** | Released 2024-12-27; aligned to the 800-53 Moderate baseline; phased audits from **2025-10-01**, full compliance by **2027-10-01**; **MFA** a priority sanctionable control since 2024-10-01 **[V B-CO-46]** | Police internal-affairs and complaint units: when cases contain CJI, EE on-prem or GovCloud deployment with CJIS addendum, personnel screening, MFA, FIPS-validated encryption and audit. The CE should document "not CJIS-assessed". |
| **Canada ITSG-33 / CCCS Medium (PBMM)** | See A6 **[V B-CO-48]** | EE Canadian region; CCCS cloud assessment pursued for SaaS. |
| **EU NIS2** (Directive 2022/2555) | Transposition deadline 2024-10-17 **[K]**. Art 21 risk-management measures; **Art 23 incident reporting: 24h early warning, 72h notification, 1-month final report** **[K]**. Transposition and infringement status in 2025–26: **UNVERIFIED**. | Public-administration and large-enterprise customers may be NIS2 entities. The vendor (if SaaS/managed service) may be an "ICT service management" entity. Provide incident-support SLAs and supply-chain attestations. |
| **ISO/IEC 27001:2022** | Annex A: 93 controls **[K]** | EE SaaS operations certified. Key controls: A.5.15 access control, A.5.34 PII, A.8.15 logging, A.8.24 crypto, A.5.33 records, A.5.23 cloud services. |
| **SOC 2** | AICPA Trust Services Criteria (2017, revised points of focus 2022) **[K]** | Type II for EE SaaS (Security, Confidentiality, Privacy). |

**Records management:**
- **US federal:** Federal Records Act (44 USC ch. 31, 33) and 36 CFR Chapter XII Subchapter B **[K]**.
  - IG and hotline case files are usually under **agency-specific schedules**. Whether a General Records Schedule item covers hotline records is **UNVERIFIED** and must be checked per agency.
  - OMB/NARA **M-23-07** (electronic records transition) **[K]**.
  - Product: electronic records with metadata, **disposition by schedule**, legal-hold override, and **export in archival formats** (PDF/A plus JSON/XML metadata) for transfer or accession.
- **Canada:** see A6 (LAC Act s.12; disposition authorities).
- **States:** state records acts and schedules (A5).

**FOIA/ATIP interaction:** see A4 and A6. Platform needs:
- a per-record exemption tag (US b(6), b(7)(C), b(7)(D), Privacy Act (k)(2); CA ATIA s.16.5, Privacy Act s.22.3; state equivalents);
- redaction with reason codes;
- an "ATIP/FOIA extract" workflow that never exports the sealed identity vault.

**Data residency:** tenant-level region pinning (EU, CA, US-commercial, US-GovCloud), with keys held in-region. Customer-managed keys or HSM (EE). A subprocessor list per region. Québec Law 25's PIA before extra-provincial transfer; GDPR Chapter V.

---

## TOPIC C — Accessibility

| Regime | Standard | Dates | Implication |
|---|---|---|---|
| **WCAG 2.2** | W3C Recommendation (Oct 2023 **[K]**); also **ISO/IEC 40500:2025** (2nd ed., published Sept 2025, free from ISO) **[V B-CO-28]** | — | Design target: **WCAG 2.2 AA**. |
| **WCAG 3** | Working Draft (latest 2026-03-03; about 174 outcome-based requirements; new scoring). CR targeted ~Q4 2027; Recommendation not before 2028. It will not immediately supersede WCAG 2 **[V B-CO-29]**. | — | Monitor only. |
| **US Section 508** | 2017 refresh incorporates **WCAG 2.0 A/AA** **[V B-CO-32]**. The Access Board issued an RFI on updating (reported 2025) **[V B-CO-32; UNVERIFIED details]**. | In force | Federal buyers: an **ACR/VPAT 2.x (508 edition)**. |
| **ADA Title II web rule** (28 CFR Part 35 Subpart H, April 2024) | **WCAG 2.1 AA** for state/local government web content and mobile apps **[V B-CO-30]** | Originally 2026-04-24 (50k+ population) and 2027-04-26 (smaller entities and special districts). **Extended by interim final rule on 2026-04-20 to 2027-04-26 and 2028-04-26**; comments closed 2026-06-22 **[V B-CO-30, B-CO-31]**. | Municipal, county and state tenants: the whistleblower portal is covered public-facing web content, and staff tools are relevant to ADA Title I and employment. |
| **European Accessibility Act** (Dir. 2019/882) | Harmonised standard **EN 301 549**. v3.2.1 (2021) references WCAG 2.1 **[K]**. **v4.1.1 published 2026-09-02** aligns with **WCAG 2.2 A/AA**; OJ citation expected about 2026-11-30 to 2026-12-16 **[V B-CO-34]**. | EAA applies from **2025-06-28** **[V B-CO-34]** | The EAA covers specific consumer products and services. A whistleblowing channel is not obviously an EAA "service" (**UNVERIFIED**; legal analysis needed). Public-sector bodies are covered by the **Web Accessibility Directive (EU) 2016/2102**, which references EN 301 549 **[K]**. Build to v4.1.1. |
| **Canada — Accessible Canada Act** (S.C. 2019, c.10) | **CAN/ASC-EN 301 549:2024** adopted as a National Standard (May 2024); GC guidance for ICT procurement **[V B-CO-35]** | Accessible Canada Regulations planning and reporting cycles **[K]** | Federal buyers: EN 301 549 conformance report. The TBS Standard on Web Accessibility (WCAG 2.0 AA) remains for GC web **[K; current status UNVERIFIED]**. |
| **Ontario AODA** | O. Reg. 191/11 (IASR) s.14: WCAG 2.0 AA for public sector and large organizations by 2021-01-01 **[K]** | In force | Ontario tenants. |
| **W3C COGA** | "Making Content Usable for People with Cognitive and Learning Disabilities" (W3C Group Note, 2021) **[K]** | — | Critical for whistleblowers under stress. |

**Accessibility requirements specific to whistleblowing UX (derived):**
- **No session time-outs that lose data** (WCAG 2.2.1 Timing Adjustable). Use "save and resume" through the receipt code. Warn before any time-out.
- **WCAG 2.2 3.3.8 Accessible Authentication (Minimum):**
  - Receipt codes must be pasteable, and handler login must allow password managers and passkeys.
  - No cognitive-function tests (and so **no CAPTCHA puzzles**; use privacy-preserving rate-limiting or proof-of-work instead).
- **3.3.7 Redundant Entry:** don't re-ask for information already given. **3.2.6 Consistent Help:** help link in the same place on every page. **2.4.11 Focus Not Obscured.** **2.5.8 Target Size (Minimum).**
- **Voice and oral channels** also serve people who cannot write easily (and Directive Art 9(2)). Provide **text alternatives for voice-distorted recordings** (transcripts, reviewed by the reporter).
- **Plain-language** policy and rights content (COGA), a reading level target, step-by-step wizard, progress indicator, and the ability to review before submission.
- **Tor Browser compatibility:** the accessible UI must work with JavaScript restricted (Tor Browser "Safer" and "Safest" security levels). Progressive enhancement is required.
- **Multilingual and RTL support;** EN/FR for Canada and Québec.
- Screen-reader-safe **security indicators:** don't convey warnings only by color.
- EE deliverables: an **ACR in the VPAT 2.x "INT" edition** covering 508, EN 301 549 and WCAG 2.x, plus third-party audit reports.

---

## Draft control-mapping table

Legend:
- **Edition:** CE = in the Community Edition; EE = Enterprise/Government only; CE+ = in CE with EE hardening or automation.
- Source codes: EU-WBD = Directive 2019/1937; ISO = ISO 37002; 53 = SP 800-53r5.2.0; 63 = SP 800-63-4.

| ID | Control | Primary sources | Implementation notes | Edition |
|---|---|---|---|---|
| WB-01 | Multi-channel intake: web written, voice message, meeting request, staff-entered phone/mail | EU-WBD 9(2); ISO 8.1; SOX 301 | Staff-entered reports are flagged with the channel of origin | CE |
| WB-02 | Anonymous submission with no account and no identifying metadata | EU-WBD 6(2); SOX 301(m)(4)(B); ISO 8.1; GDPR 25 | No IP, UA or fingerprint logging on reporter endpoints; onion service support; attachment metadata scrubbing | CE |
| WB-03 | Two-way anonymous mailbox via receipt code or key | EU-WBD 9(1)(c); ISO 8.1–8.4 | High-entropy code; optional client-side key derivation | CE |
| WB-04 | Acknowledgement SLA (default 7 calendar days; configurable, e.g., 5 business days for Alberta) | EU-WBD 9(1)(b), 11(2)(b); AB PIDA procedures | SLA engine with business/calendar mode, holiday calendars and escalation | CE (engine); EE (multi-jurisdiction calendars packs) |
| WB-05 | Feedback SLA (3 months from acknowledgement or day 7; external 3 or 6 months with justification); investigation SLA (e.g., 120 business days) | EU-WBD 9(1)(f), 11(2)(d); AB procedures | A "feedback given" milestone; extension reason required | CE |
| WB-06 | Triage and scope assessment, including detriment-risk assessment | ISO 8.2; EU-WBD 17 | Out-of-scope → purge irrelevant personal data or refer | CE |
| WB-07 | Impartial handler assignment and conflict-of-interest recusal | EU-WBD 9(1)(c); ISO impartiality; SOX 301 | Accused-person exclusion lists; audit-committee routing for accounting matters | CE; EE (rule engine) |
| WB-08 | Need-to-know, case-level access control | EU-WBD 9(1)(a), 16; PSDPA s.11; 53 AC-3, AC-6; ISO 27001 A.5.15 | Per-case access lists; break-glass with justification | CE |
| WB-09 | Sealed identity vault and unseal workflow (legal basis, dual control, reporter notice or deferral) | EU-WBD 16(1)–(3); 5 USC 407(b); 5 USC 1213(h); SEC 21F-7; Corps Act s.1317AAE | Identity fields encrypted to a separate key; unseal events are high-severity audit | CE |
| WB-10 | Redaction of direct and indirect identifiers (reporter, third parties, persons concerned) | EU-WBD 16(1), 22; GDPR 15(4) | Redaction layers; the original stays immutable | CE; EE (assisted/NLP redaction, run locally) |
| WB-11 | Integrity of original submissions; forwarding without modification | EU-WBD 12(1),(4) | Hash of the original; referral packages carry the hash | CE |
| WB-12 | Register of every report | EU-WBD 18(1); ISO 7.5 | Minimal register fields; no identity | CE |
| WB-13 | Oral report records: consented recording or transcript; reporter check, rectify and sign-off; meeting minutes | EU-WBD 18(2)–(4) | Transcript review through the mailbox; e-sign | CE (manual); EE (local speech-to-text) |
| WB-14 | Retention and disposition schedules; legal hold; deletion certificates | EU-WBD 18; GDPR 5(1)(e); CNIL 2023-064; 44 USC 3303; LAC Act s.12; FCA seal | Schedule by outcome; holds override; crypto-shredding | CE; EE (NARA/LAC schedule import, archival export) |
| WB-15 | Data-subject-rights handling with restriction logic | GDPR 12–23 (esp. 14(5)(b), 15(4), 23); EDPS 2019 | Restriction reason codes; deferred-notice timers | CE+ |
| WB-16 | Privacy notices, DPIA and PIA templates, ROPA export | GDPR 13/14, 30, 35; Québec Law 25; TBS PIA directive | Templates per edition and data flow | CE (templates); EE (auto-filled) |
| WB-17 | Encryption in transit and at rest; end-to-end encryption to handlers | GDPR 32; 53 SC-8, SC-13, SC-28; CJIS 5.10 | Per-case keys; handler keys; key-recovery policy | CE |
| WB-18 | FIPS 140-3-validated cryptography mode; customer-managed keys or HSM | FIPS 140-3; FedRAMP; CJIS; ITSG-33 SC-13 | Build profile with validated provider | EE |
| WB-19 | Handler MFA; phishing-resistant for privileged users; PIV/CAC | 63 AAL2/AAL3; FIPS 201-3; CJIS IA; 53 IA-2(1),(2) | WebAuthn/passkeys in CE; PIV and FIDO hardware enforcement in EE | CE (WebAuthn); EE (PIV, policy) |
| WB-20 | SSO (SAML/OIDC) and SCIM provisioning | 53 AC-2; ISO 27001 A.5.16 | — | EE |
| WB-21 | Tamper-evident audit log free of reporter-identifying data | 53 AU-2, AU-9, AU-10; ISO 27001 A.8.15; EU-WBD 16 | Hash-chained; exportable; SIEM feed | CE (log); EE (SIEM, WORM) |
| WB-22 | Reporter-side privacy by default: no third-party resources or analytics; no telemetry by default | GDPR 25; Québec Law 25 privacy-by-default | Content Security Policy that blocks third-party content; self-hosted fonts | CE |
| WB-23 | Retaliation and detriment monitoring after the report and after closure | ISO 8.3, 8.4; EU-WBD 19–21; SOX 806; 5 USC 2302(b)(8) | Scheduled check-in messages; a retaliation-complaint case type | CE |
| WB-24 | Statistics and KPI reporting (anonymised, small-cell suppression) | EU-WBD 27(2); ISO 9.1; PSDPA annual reports | Minimum-count thresholds to avoid re-identification | CE (basic); EE (regulator exports) |
| WB-25 | Information on external channels and rights notices | EU-WBD 9(1)(g), 13; NY LL 740 notice; 41 USC 4712; SEC 21F-17 | Jurisdiction content packs; **no gag language** | CE |
| WB-26 | Anti-gag terms: platform terms and templates preserve the right to report externally | WPEA 5 USC 2302(b)(13); SEC 21F-17 | Legal review of templates | CE |
| WB-27 | Shared-resource and consortium mode with strict tenant isolation | EU-WBD 8(6), 8(9) | Separate keys and admins per tenant | EE (multi-tenant) |
| WB-28 | Data residency and region pinning; subprocessor transparency | GDPR Ch. V; Québec Law 25 s.17 (PIA before transfer) [K]; GC data residency [K] | Region-scoped keys | EE (SaaS); CE (self-host inherently) |
| WB-29 | Accessibility: WCAG 2.2 AA; ACR/VPAT; EN 301 549 v4.1.1 | ADA Title II; §508; WAD/EAA; ACA; AODA | Automated plus manual testing in CI; published ACR | CE (conformance); EE (formal ACR, audit) |
| WB-30 | Cognitive accessibility and anti-lockout (save and resume, no CAPTCHA, plain language) | WCAG 2.2.1, 3.3.7, 3.3.8; COGA | Proof-of-work or rate-limits instead of CAPTCHA | CE |
| WB-31 | Multilingual UI; EN/FR parity; RTL | Official Languages Act; Charter of the French Language | — | CE |
| WB-32 | Incident response incl. breach notification support | GDPR 33/34; NIS2 23; CJIS IR; FedRAMP IR; Law 25 | Identity-exposure severity class | CE (runbook); EE (vendor SLA) |
| WB-33 | Secure supply chain: signed releases, SBOM, reproducible builds, update integrity | 53 SA-15(13), SA-24, SI-2(7), SI-7(12); EO 14306 | Public build attestations (SLSA-style) | CE |
| WB-34 | Continuous-monitoring evidence (OSCAL, FedRAMP 20x KSIs) | FedRAMP 20x; 53 CA-7 | Machine-readable evidence API | EE |
| WB-35 | FOIA/ATIP exemption tagging and extract workflow | 5 USC 552(b)(6),(7)(C),(7)(D); Privacy Act (k)(2); ATIA s.16.5; Privacy Act (Can.) s.22.3 | Never includes the identity vault | CE (tags); EE (ATIP workflow) |
| WB-36 | Legal hold and sealed-matter flag | FCA 31 USC 3730(b)(2); litigation holds | Blocks disposition; restricts circulation | CE |
| WB-37 | Personnel-security and CJIS deployment profile | CJIS v6.0; 53 PS family | Documented deployment pattern | EE |
| WB-38 | Governance artefacts: policy templates, roles, training records, management review | ISO 37002 cl. 5, 7, 9, 10; CSF 2.0 GV | — | CE (templates); EE (tracking) |
| WB-39 | Anonymous-report acceptance toggle and handling policy per jurisdiction | EU-WBD 6(2) and national laws | Default on | CE |
| WB-40 | Deadline clocks for external regimes: SOX 180-day OSHA filing, DOJ 120-day pilot window, FCA seal | 18 USC 1514A; DOJ pilot; 31 USC 3730 | Advisory reminders only (not legal advice) | EE |

---

## Jurisdiction notes (quick reference)

- **EU:**
  - Internal channels are mandatory for entities with 50 or more workers and for public entities; municipalities under 10,000 inhabitants or under 50 workers may be exempted by the member state.
  - Clocks: 7 days / 3 months internal; 7 days / 3–6 months external.
  - The national transposition law governs anonymity, retention, the Art 23 restrictions and the competent authorities. Maintain a **per-member-state content and configuration pack**.
  - Penalty cases (2025) show active enforcement. An evaluation and possible amendment are coming (2026–27).
- **US federal:**
  - There is no single "internal channel" mandate outside SOX 301 (issuers) and program-specific rules. IG hotlines are the core government use case, with 5 USC 407(b) identity protection.
  - Products must not impede SEC or other external reporting.
  - FOIA exemptions are needed.
  - Security: FedRAMP (20x for SaaS), 800-53r5.2, 800-63-4; FIPS 140-3 for federal crypto.
- **US states:** a patchwork of whistleblower statutes (CA 1102.5, NY LL 740 and CSL 75-b), state IG and auditor hotlines, and public-records exemptions. GovRAMP covers SaaS. ADA Title II now runs to April 2027 or April 2028.
- **US municipalities:** ethics, IG and auditor hotlines accept public reports, anonymous intake and phone. Other needs: ADA Title II WCAG 2.1 AA, state records schedules, open-records exemptions, CJIS for police internal-affairs complaints, and Spanish or multilingual support.
- **Canada federal:**
  - PSDPA internal procedures (s.10) and confidentiality (s.11), PSIC, the mandatory ATIA s.16.5 exemption, and the Privacy Act.
  - Security: Protected B / PBMM (ITSG-33, CCCS Medium), Canadian data residency, EN/FR.
  - Reform pending: C-290 died January 2025; watch for a successor.
  - Private-sector privacy: PIPEDA, with Bill C-36 (PPCDA) pending since June 2026.
- **Canadian provinces:**
  - Ontario: PSOA Part VI.
  - Alberta: PIDA, with business-day clocks.
  - BC: PIDA 2018, phased expansion.
  - Québec: D-11.1 with the Protecteur du citoyen, municipalities to CMQ/CIME; Law 25 PIA and privacy by default; French language.
  - Accessibility: AODA (Ontario).

---

## TOPIC D — Licensing and business model

### D1. License options

| License | Nature | Pros for this project | Cons |
|---|---|---|---|
| **AGPL-3.0-or-later** | Strong copyleft; **§13** requires offering source to users interacting over a network **[K]** | Closes the SaaS loophole, so competitors hosting a modified CE must publish changes. Aligned with the category leaders: **GlobaLeaks is AGPLv3+ with §7 additional terms** **[V B-CO-50]**, and SecureDrop is AGPLv3 **[K]**. Strong trust signal. OSI and FSF approved, so it qualifies for government open-source policies and FOSS funders. | Some enterprises ban AGPL internally (policy friction). Dual-licensing needs copyright consolidation (a CLA). Proprietary EE modules must be separable works, not derivative of AGPL code, or the vendor must own all copyright. |
| **GPL-3.0** | Strong copyleft, no network clause | Familiar | SaaS forks need not share changes. Weaker than AGPL for a web app. |
| **MPL-2.0** | File-level weak copyleft | Allows proprietary extensions alongside; simple for open-core | Modified MPL files must be shared, but new closed files are allowed, so it is easier for third parties to close up the product. |
| **Apache-2.0** | Permissive, with an explicit patent grant | Maximum adoption and embedding; simplest for government reuse | Anyone (including a hostile or low-quality vendor) can ship closed, modified forks under the brand-free name. Weakest guarantee that the code whistleblowers rely on is the code that runs. |
| **BSL 1.1 / FSL / SSPL / ELv2 (source-available)** | Not OSI open source | Protects against cloud free-riding | **Trust and ecosystem damage.** HashiCorp's 2023 move from MPL to BSL produced the **OpenTofu** fork under the Linux Foundation (2023-09-20; 1.6.0 in Jan 2024); IBM closed its HashiCorp acquisition 2025-02-27 **[V B-CO-60]**. Elastic moved to SSPL/ELv2 in 2021 **[K]** and **added AGPL in Aug 2024** **[V B-CO-61]**. Redis moved to SSPL/RSAL in Mar 2024, spawning **Valkey**, then **added AGPLv3 with Redis 8 on 2025-05-01** **[V B-CO-62]**. Sentry's **FSL** (Nov 2023) converts to Apache/MIT after two years but is not OSI **[V B-CO-63]**. Ineligible for many government OSS policies and FOSS grants **[K]**. |

**Open-core precedents:**
- **GitLab:** CE MIT plus proprietary EE, source-visible **[K]**.
- **Mattermost:** a mix of MIT/AGPL/Apache for the open-source parts and a commercial enterprise license **[K; exact current split UNVERIFIED]**.
- **Sentry:** FSL **[V B-CO-63]**.
- Lesson: open-core works commercially when the paid tier is organizational (SSO, compliance, scale, support). It generates controversy when core functionality or security moves behind the paywall, or when the license changes after a community has formed.

### D2. Trust implications of closed components in security software

- **Signal:** the server repository went about a year (from April 2020) without public updates, during which MobileCoin payment code was developed. Hundreds of commits were published in April 2021 after criticism **[V B-CO-64]**. Lesson: publication lag is itself a trust event. Commit to **same-day source publication for released versions**.
- **Threema:** open-sourced its apps under **AGPLv3 in Dec 2020**, with **reproducible builds** for Android and an external **Cure53 audit** **[V B-CO-65]**. Lesson: open source plus reproducible builds plus published audits is the trust package.
- **Proton:** open-sourced its client apps and published audits (**[K]**, dates UNVERIFIED). Server code is closed; the trust model relies on end-to-end encryption, so the server need not be trusted for confidentiality.
- **Wire:** open-sourced clients (2016) and server (2017, GPL) **[K; UNVERIFIED in-session]**.
- **Principle for this platform:** any component that sees **plaintext report content, keys, or reporter network metadata** must be FOSS, reproducibly built and auditable in the CE. That covers the reporter UI, submission API, crypto, storage, anonymity features and handler decryption client. Closed EE code may only touch things like ciphertext routing, IdP integration, compliance reporting on non-identifying metadata, and deployment tooling.

### D3. Contributor model: CLA vs DCO

- **DCO** (Developer Certificate of Origin; sign-off per commit) **[K]**: low friction and community-friendly. It does **not** let the vendor relicense contributions, so dual licensing of the whole codebase becomes impossible once external contributions land.
- **CLA with a broad license grant or copyright assignment** **[K]**: enables dual licensing (commercial non-AGPL license for OEMs or embedding). It is also the mechanism behind the HashiCorp-, Elastic- and Redis-style relicensing, which reduces community trust and contribution.
- **Middle ground:** use the DCO plus a public **license pledge**, e.g., a governance document committing that the CE will remain OSI-licensed. Optionally put copyright in a neutral foundation. If commercial relicensing is essential, use a CLA with an explicit commitment that contributions will always *also* be available under AGPL. The FSF-style "contributor assignment with reversion" is **[K]**.

### D4. Telemetry norms

- **Go (2023):**
  - Russ Cox's "transparent telemetry" design was first proposed as opt-out. After community feedback (February 2023) it was changed to **opt-in** for uploads; counters stay local by default.
  - Accepted April 2023; shipped in Go 1.23 (August 2024) **[V B-CO-66]**.
- **Homebrew:** anonymous analytics, **opt-out** (`brew analytics off`), with a self-hosted analytics backend **[K; details UNVERIFIED]**.
- **VS Code:** a `telemetry.telemetryLevel` setting (off, crash, error, all) **[K]**. VSCodium exists largely to strip telemetry **[K]**.
- **Recommendation:** for a whistleblowing system, **zero telemetry by default in both CE and EE**.
  - Never collect anything from reporter-facing surfaces.
  - Admin-side opt-in only; aggregate-only; published schema; locally inspectable before upload (Go model).
  - Update checks behind a toggle, with no instance identifiers.
  - Document everything in a "what leaves your server" page.

### D5. Funding and sustainability

- **GlobaLeaks (Hermes Center):**
  - Grant-funded from the start: USAID Serbia (0.1 prototype, 2011); **OTF** (several grants, e.g., $108,400, $234,000, $108,000); **Hivos** (€200,000); Lush Digital Fund; OSIFE; GIZ (€41,000); the European Commission (EAT and Speak Up Europe projects) **[V B-CO-50, B-CO-51]**.
  - Commercial hosting/support offerings around GlobaLeaks exist **[K; UNVERIFIED specifics]**.
- **SecureDrop (Freedom of the Press Foundation):** a nonprofit, donor-funded model; free software with support for newsrooms **[K]**.
- **Open Technology Fund:** USAGM terminated OTF's grant on 2025-03-15. OTF sued in D.D.C.; funding payments later resumed and DOJ argued the case was moot **[V B-CO-52]**. Treat OTF as **volatile** as a funding source.
- **Sovereign Tech Agency (Germany):** the Sovereign Tech Fund became part of the **Sovereign Tech Agency** in 2024. Investments of about €23.5M in over 60 projects by late 2024; minimum €50k per project; focused on *base technologies* **[V B-CO-53]**. A whistleblowing app is likely out of scope; shared libraries (crypto, onion-service tooling, accessibility components) might fit.
- **NLnet / NGI Zero** (EU Horizon-funded open-internet grants) **[K]**. 2025–26 NGI funding continuity is **UNVERIFIED**.
- **Government open-source policies** favour OSI licenses: US **M-16-21** Federal Source Code Policy and the SHARE IT Act (**UNVERIFIED** status); EU "public money, public code" and the Interoperable Europe Act; Canada's Directive on Service and Digital "open source first" rules **[K]**.

### D6. Recommendation

1. **CE: AGPL-3.0-or-later**, optionally with narrowly scoped §7 additional terms like GlobaLeaks' (e.g., preserving a "powered by / security notice" to users). Keep additional terms minimal so the license stays unambiguous.
2. **Contribution model:** **DCO**, plus a public **"Open Core Charter"**:
   - Everything in the trust path is and remains AGPL.
   - Security fixes are always released to the CE at the same time as the EE.
   - No feature is moved from CE to EE.
   - An OSI-license commitment backed by a foundation or trademark steward.
3. **EE (commercial license) for organizational and assurance features:**
   - SSO/SCIM, PIV and FIPS mode packaging, multi-tenant and consortium management, jurisdiction content packs, retention-schedule import;
   - FedRAMP, GovRAMP and CCCS evidence automation (OSCAL/KSI), SIEM and WORM integrations, advanced redaction;
   - SLA-backed support and hosted regions.
   - Also offer source-available access to EE modules for customers and auditors (escrow or read-only access), so government buyers can inspect everything they run.
4. **Assurance package in the CE:** reproducible builds, signed releases, SBOM, public third-party audits, a published threat model, a security.txt / vulnerability disclosure policy, and zero telemetry by default.
5. **Trademark policy:** this is how quality is protected (forks must rebrand), not the copyright license.
6. **Funding mix:** EE revenue plus grants for public-good components (accessibility, crypto libraries) plus hosted service. Avoid dependence on any single government funder (see OTF 2025).

---

## Open items / UNVERIFIED register

1. EU Art 27(3) Commission impact report (due 2025-12-17): publication status.
2. Poland CJEU penalty (C-147/23) details; outcome of the Spain and Italy referrals.
3. ISO 37001 revision (2025?) and the exact wording of the ISO 37002 principles (the standard was not accessed; it is paywalled).
4. FIPS 140-2 historical-status sunset date (Sept 2026).
5. NIS2 transposition and infringement status in 2026.
6. Whether the EAA covers whistleblowing channels as a "service".
7. Alberta PIDA statutory timelines vs policy timelines.
8. Canadian federal data-residency instrument currently in force; TBS web accessibility standard status.
9. The mechanics of the DOJ pilot's 120-day window after the May 2025 revision.
10. State-specific public-records exemptions (Florida §112.3188 etc.) and Chicago MCC section numbers.
11. Proton and Wire open-sourcing dates; the current Mattermost license split; Homebrew analytics backend details.
12. NLnet/NGI funding continuity for 2026; SHARE IT Act status.
13. Bill C-36 legislative stage; any PSDPA reform bill after C-290.

---

## Bibliography

Verification tags as above. "Fetched" means the page itself was opened. In this session, most items were verified through search results that summarise or quote them.

| ID | Title | URL | Date | Relevance | Status |
|---|---|---|---|---|---|
| B-CO-01 | PECB whitepaper, "ISO 37002:2021 Whistleblowing Management Systems"; SCC standards DB entry ISO 37002:2021 | https://pecb.com/whitepaper/iso-370022021-whistleblowing-management-systems ; https://scc-ccn.ca/standardsdb/standards/8176115 | 2021 (std) | 4-step process (8.1–8.4), principles | V (secondary) |
| B-CO-02 | Directive (EU) 2019/1937 on the protection of persons who report breaches of Union law (OJ L 305, 26.11.2019) | https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32019L1937 (canonical, not fetched; egress blocked) | 2019-10-23 | Arts 4–27 | K |
| B-CO-03 | Commission report COM(2024) 269 on implementation of Directive 2019/1937 (summary via EU Monitor / ANCI Lombardia) | https://www.eumonitor.eu/9353000/1/j4nvhdfdk3hydzq_j9vvik7m1c3gyxp/vmen52azq7xb | 2024-07-03 | Transposition gaps | V |
| B-CO-04 | Whistleblowing International Network / EU Whistleblowing Monitor, "EU Evaluation of Whistleblowing Directive Now Underway" and Apr 2026 roundup | https://whistleblowingmonitor.eu/eu-evaluation-of-whistleblowing-directive-now-underway/ ; https://whistleblowingmonitor.eu/roundup-of-updates-april-2026/ | 2025–2026 | Evaluation, action-plan consultation | V |
| B-CO-05 | CURIA press / eucrim, "ECJ Ordered Several Member States to Financial Penalties for Failing to Transpose Whistleblowers Directive" | https://eucrim.eu/news/ecj-ordered-several-member-states-to-financial-penalties-for-failing-to-transpose-whistleblowers-directive/ | 2025-03-06 | C-149/23 et al., penalties | V |
| B-CO-06 | BAILII copy of CJEU judgment C-149/23 Commission v Germany | https://mansfield.bailii.org/eu/cases/EUECJ/2025/C14923.html | 2025-03-06 | Primary judgment | V (listed; not fetched) |
| B-CO-07 | EESC information report, "Evaluation of the whistle-blower protection directive" | https://www.eesc.europa.eu/en/our-work/opinions-information-reports/information-reports/evaluation-whistle-blower-protection-directive | 2025–2026 | Evaluation | V (listed) |
| B-CO-08 | NEIWA Submission on the Review and Potential Amendment of the Directive | https://whistleblowingmonitor.eu/wp-content/uploads/2026/05/NEIWA-Submission-on-the-Review-and-Potential-Amendment-of-Directive-APR2026.fin_.pdf | 2026-04 | Future amendments | V (listed; not fetched) |
| B-CO-09 | Regulation (EU) 2016/679 (GDPR) | https://eur-lex.europa.eu/eli/reg/2016/679/oj (canonical, not fetched) | 2016-04-27 | Arts 5, 14, 15, 23, 25, 32, 35 | K |
| B-CO-10 | EDPS, Guidelines on processing personal information within a whistleblowing procedure | https://edps.europa.eu/sites/edp/files/publication/19-12-17_whisteblowing_guidelines_en.pdf | 2019-12-17 | Confidentiality, minimisation, restrictions | V (search summary) |
| B-CO-11 | Luxembourg CNPD, information notice for external reports (example DPA practice) | https://cnpd.public.lu/content/dam/cnpd/fr/support/lanceurs-alerte/notice-dinformation-signalements-externes-en.pdf | n.d. | Rights restrictions practice | V (listed) |
| B-CO-12 | CNIL, "La CNIL met à jour son référentiel « alertes professionnelles »" (délibération n° 2023-064) | https://www.cnil.fr/fr/la-cnil-met-jour-son-referentiel-alertes-professionnelles | 2023-07-06 | Retention, security, outsourcing | V |
| B-CO-13 | 5 U.S.C. §407, Complaints by employees (GovInfo link) | https://www.govinfo.gov/link/uscode/5/407 | current | IG identity confidentiality | V |
| B-CO-14 | Phillips & Cohen / Whistleblowers Blog summaries of SEC Whistleblower Program FY2025 Annual Report | https://www.phillipsandcohen.com/sec-whistleblower-program-annual-report-for-fy-2025-shows/ | 2025-11/2026 | Program stats | V (secondary) |
| B-CO-15 | Crowell & Moring, "Next Stop, Supreme Court? Eleventh Circuit Upholds the Constitutionality of the FCA's Qui Tam Provisions"; Goodwin alert | https://www.crowell.com/en/insights/client-alerts/next-stop-supreme-court-eleventh-circuit-upholds-the-constitutionality-of-the-fcas-qui-tam-provisions ; https://www.goodwinlaw.com/en/insights/publications/2026/09/alerts-hltc-eleventh-circuits-zafirov-decision-leaves-constitutional-questions-open | 2026-09 | Zafirov | V (secondary) |
| B-CO-16 | Federal Register, FAR interim rule on the 41 USC 4712 pilot (GovInfo) | https://www.govinfo.gov/content/pkg/FR-2013-09-30/pdf/2013-23703.pdf | 2013-09-30 | Contractor whistleblowers | V (listed) |
| B-CO-17 | Mintz, "DOJ Issues Its Highly Anticipated Whistleblower Awards Pilot"; Foley, May 2025 update | https://www.mintz.com/insights-center/viewpoints/2024-08-15-doj-issues-its-highly-anticipated-whistleblower-awards-pilot ; https://www.foley.com/insights/publications/2025/05/doj-criminal-division-updates-part-2-corporate-criminal-whistleblower-awards-pilot/ | 2024-08 / 2025-05 | DOJ pilot | V (secondary) |
| B-CO-18 | Phillips Lytle, "New York State Expands Workplace Whistleblower Protections" | https://phillipslytle.com/insights/client-alerts/new-york-state-expands-workplace-whistleblower-protections/ | 2022-01-07 | NY LL 740 | V (secondary) |
| B-CO-19 | Public Servants Disclosure Protection Act, S.C. 2005, c. 46 | https://laws-lois.justice.gc.ca/eng/acts/P-31.9/ (canonical, not fetched) | current | ss.10–13, 19 | K |
| B-CO-20 | Access to Information Act, s.16.5 | https://laws-lois.justice.gc.ca/eng/acts/A-1/section-16.5-20190621.html | in force 2019-06-21 | ATIP exemption | V |
| B-CO-21 | LEGISinfo, Bill C-290 (44-1), Public Sector Integrity Act; openparliament.ca | https://parl.ca/LegisInfo/en/bill/44-1/c-290 ; https://openparliament.ca/bills/44-1/C-290/ | 2022–2025 | PSDPA reform (died) | V |
| B-CO-22 | DLA Piper, "Canada tables Bill C-36, the Protecting Privacy and Consumer Data Act" | https://www.dlapiper.com/insights/publications/2026/06/canada-tables-bill-c36-the-protecting-privacy-and-consumer-data-act | 2026-06-17 | Federal privacy reform; C-27 death | V (secondary) |
| B-CO-23 | Osler, "The Protecting Privacy and Consumer Data Act (Bill C-36): key obligations" | https://www.osler.com/en/insights/reports/the-protecting-privacy-and-consumer-data-act-bill-c-36-key-obligations-and-enforcement-overview/ | 2026 | C-36 detail | V (listed) |
| B-CO-24 | Alberta school-division administrative procedures under PIDA (e.g., Westwind AP 403; Parkland AP 199) | https://westwind.ab.ca/board-of-trustees/procedures/4119 ; https://www.psd.ca/board/administrative-procedures/4494 | n.d. | 5/10/120 business-day clocks | V (policy-level) |
| B-CO-25 | BC Public Interest Disclosure Act 2025/26 annual report (BC Public Service) | https://www2.gov.bc.ca/assets/gov/careers/about-the-bc-public-service/ethics/pida_25-26_annual_report.pdf | 2026 | BC PIDA practice | V (listed; not fetched) |
| B-CO-26 | Protecteur du citoyen, "Disclosure of wrongdoings relating to public bodies…"; LégisQuébec D-11.1 | https://protecteurducitoyen.qc.ca/en/node/1444 ; https://www.legisquebec.gouv.qc.ca/en/document/cs/D-11.1/20241201 | 2016–2024 | Québec regime | V |
| B-CO-27 | Québec Law 25 (Act to modernize legislative provisions as regards the protection of personal information, S.Q. 2021, c. 25) | https://www.legisquebec.gouv.qc.ca (canonical host; specific URL not verified) | 2021-09-22 | PIA, privacy by default | K |
| B-CO-28 | ISO, ISO/IEC 40500:2025 (WCAG 2.2); W3C news | https://www.iso.org/standard/91029.html ; https://lists.w3.org/Archives/Public/w3c-news/2025OctDec/0002.html | 2025 | WCAG 2.2 as ISO | V |
| B-CO-29 | W3C, WCAG 3 Introduction; "For Review: WCAG 3 Working Draft – March 2026" | https://www.w3.org/WAI/WCAG3 ; https://www.w3.org/WAI/news/2026-03-03/wcag3 | 2026-03-03 | WCAG 3 status | V |
| B-CO-30 | Plante Moran, "DOJ extends ADA Title II web accessibility compliance deadlines" | https://plantemoran.com/explore-our-thinking/insight/2026/04/doj-extends-ada-title-ii-web-accessibility-compliance-deadlines | 2026-04 | Title II IFR | V (secondary) |
| B-CO-31 | Jackson Lewis / JD Supra, "DOJ Delays ADA Web Accessibility Compliance Deadlines…" | https://www.jdsupra.com/legalnews/doj-delays-ada-web-accessibility-7295347/ | 2026-04 | Title II IFR | V (secondary) |
| B-CO-32 | Deque, "The Section 508 ICT Refresh has Arrived"; Microassist on Section 508 and WCAG | https://www.deque.com/blog/section-508-ict-refresh-arrived/ ; https://www.microassist.com/digital-accessibility/section-508-and-wcag/ | 2017 / 2025 | 508 = WCAG 2.0 AA | V (secondary) |
| B-CO-33 | DOJ, Title II web and mobile accessibility final rule (28 CFR 35 Subpart H) | https://www.ada.gov/resources/2024-03-08-web-rule/ (canonical, not fetched) | 2024-04-24 | Primary | K |
| B-CO-34 | Davis Wright Tremaine, "European Accessibility Act ICT standards update"; Deque, "EN 301 549 v4.1.1 is final" | https://www.dwt.com/insights/2026/09/european-accessibility-act-ict-standards-update | 2026-09 | EN 301 549 v4.1.1; EAA | V (secondary) |
| B-CO-35 | SCC standards DB, CAN/ASC-EN 301 549:2024; GC a11y procurement guide | https://scc-ccn.ca/standardsdb/standards/4033458 ; https://a11y.canada.ca/en/guide-for-including-accessibility-in-information-and-communication-technology-ict-related-procurement/ | 2024-05 | Canada ICT accessibility | V |
| B-CO-36 | W3C WAI, Making Content Usable for People with Cognitive and Learning Disabilities | https://www.w3.org/TR/coga-usable/ (canonical, not fetched) | 2021 | COGA | K |
| B-CO-37 | Ontario O. Reg. 191/11 (IASR) | https://www.ontario.ca/laws/regulation/110191 (canonical, not fetched) | 2011 (am.) | AODA WCAG 2.0 AA | K |
| B-CO-40 | NIST CSRC news, "NIST Releases Revision to SP 800-53 Controls" (Release 5.2.0) | https://csrc.nist.gov/News/2025/nist-releases-revision-to-sp-800-53-controls | 2025-08-27 | New SA/SI controls | V |
| B-CO-41 | NIST SP 800-63-4, Digital Identity Guidelines (summaries) | https://pages.nist.gov/800-63-4/ (canonical, not fetched) | 2025-07-31 | AAL, phishing-resistant, syncable | V (date via secondary) |
| B-CO-42 | NIST CSF 2.0 (NIST CSWP 29) | https://www.nist.gov/cyberframework (canonical, not fetched) | 2024-02-26 | Govern function | K |
| B-CO-43 | FedRAMP, "FedRAMP 20x Phase 2 Recap" | https://www.fedramp.gov/20x/phases/2/ | 2026 | KSIs, pilot | V (search summary) |
| B-CO-44 | GovRAMP, "StateRAMP Announces Rebrand to GovRAMP…" | https://govramp.org/blog/stateramp-announces-rebrand-to-govramp-reflecting-mission-to-unite-public-and-private-sectors-in-advancing-cybersecurity/ | 2025-02-14 | State/local cloud | V |
| B-CO-45 | DoD CMMC 48 CFR final rule (Federal Register, 2025-09-10), summarised by BDO / Duane Morris | https://www.bdo.com/insights/advisory/defense-contractors-new-reality-the-final-48-cfr-rule-is-bringing-cmmc-into-federal-acquisition | 2025-09-10 | CMMC phase-in | V (secondary) |
| B-CO-46 | CJIS Security Policy v6.0 (summaries: Imprivata; California DOJ ISRS 2025-001) | https://www.oag.ca.gov/system/files/media/2025-isrs-001.pdf | 2024-12-27 | Law-enforcement IA | V (secondary) |
| B-CO-47 | Directive (EU) 2022/2555 (NIS2) | https://eur-lex.europa.eu/eli/dir/2022/2555/oj (canonical, not fetched) | 2022-12-14 | Art 21, 23 | K |
| B-CO-48 | CCCS / cloud-provider Protected B pages (Google Cloud Protected B; Microsoft Azure Canada Protected B) describing ITSP.50.103 / PBMM | https://cloud.google.com/security/compliance/protected-b ; https://www.cyber.gc.ca/ | current | PBMM, ITSG-33 | V (secondary) |
| B-CO-49 | ISO/IEC 27001:2022; AICPA TSC (SOC 2); FIPS 140-3; FIPS 201-3 | https://www.iso.org/standard/27001 ; https://csrc.nist.gov/pubs/fips/140-3/final ; https://csrc.nist.gov/pubs/fips/201-3/final (canonical, not fetched) | 2019–2022 | Baselines | K |
| B-CO-50 | GlobaLeaks GitHub repository (license AGPLv3+ with §7 terms) | https://github.com/globaleaks/globaleaks-whistleblowing-software | current | FOSS whistleblowing precedent | V |
| B-CO-51 | GlobaLeaks, "Funding" page | https://globaleaks.org/about/funding | n.d. | Funding model | V (search summary; fetch blocked) |
| B-CO-52 | OTF, "Open Technology Fund Files Lawsuit to Contest Grant Termination…" | https://www.opentech.fund/news/open-technology-fund-files-lawsuit-to-contest-grant-termination-and-preserve-critical-mission/ | 2025-03 | Funding volatility | V |
| B-CO-53 | BMWK press release on Sovereign Tech Fund/Agency; Interoperable Europe OSOR case study | https://www.bundeswirtschaftsministerium.de/Redaktion/DE/Pressemitteilungen/2024/11/20241104-sovereign-tech-fund.html ; https://interoperable-europe.ec.europa.eu/collection/open-source-observatory-osor/document/funding-open-source-case-study-sovereign-tech-fund | 2024-11 | Public FOSS funding | V |
| B-CO-54 | Freedom of the Press Foundation, SecureDrop (AGPLv3) | https://securedrop.org/ ; https://github.com/freedomofpress/securedrop (canonical, not fetched) | current | Nonprofit model | K |
| B-CO-55 | GNU AGPL v3 text | https://www.gnu.org/licenses/agpl-3.0.html (canonical, not fetched) | 2007-11-19 | §13, §7 | K |
| B-CO-56 | Developer Certificate of Origin | https://developercertificate.org/ (canonical, not fetched) | 2004/v1.1 | Contribution model | K |
| B-CO-60 | Softwareseni / OneUptime analyses of the HashiCorp BSL change, OpenTofu and IBM acquisition | https://www.softwareseni.com/hashicorp-terraform-opentofu-and-the-ibm-acquisition-wild-card-for-infrastructure-as-code/ | 2023–2025 | License-change backlash | V (secondary) |
| B-CO-61 | Business Wire, "Elastic Announces Open Source License for Elasticsearch and Kibana Source Code"; InfoQ | https://www.businesswire.com/news/home/20240829537786/en ; https://www.infoq.com/news/2024/09/elastic-open-source-agpl | 2024-08-29 | Return to AGPL | V |
| B-CO-62 | InfoQ, "Redis AGPL license"; The New Stack, "Redis is open source again" | https://www.infoq.com/news/2025/05/redis-agpl-license ; https://thenewstack.io/redis-is-open-source-again | 2025-05-01 | Return to AGPL | V |
| B-CO-63 | Sentry blog, "Introducing the Functional Source License"; TechCrunch | https://blog.sentry.io/introducing-the-functional-source-license-freedom-without-free-riding ; https://techcrunch.com/2023/11/20/with-functional-source-license-sentry-wants-to-grant-developers-freedom-without-harmful-free-riding/ | 2023-11 | Fair source | V |
| B-CO-64 | Android Police, "It looks like Signal isn't as open source as you thought it was anymore"; XDA | https://www.androidpolice.com/2021/04/06/it-looks-like-signal-isnt-as-open-source-as-you-thought-it-was-anymore | 2021-04-06 | Publication-lag trust | V |
| B-CO-65 | Threema, "Is Threema open source?"; "New Audit Confirms Threema's Security Once Again" | https://threema.ch/en/faq/source_code ; https://threema.com/en/blog/audit-2020-en | 2020-12 | Open-sourcing plus audit | V |
| B-CO-66 | Russ Cox, "Transparent Telemetry" design and opt-in revision; DevClass on Go 1.23 | https://research.swtch.com/telemetry-opt-in.pdf ; https://devclass.com/2024/08/14/go-1-23-released-with-telemetry-uploaded-to-google-but-opt-in-after-developer-feedback | 2023-02 / 2024-08 | Telemetry norms | V |
| B-CO-67 | UK Public Interest Disclosure Act 1998 | https://www.legislation.gov.uk/ukpga/1998/23 (canonical, not fetched) | 1998 | Reference regime | K |
| B-CO-68 | Australia Corporations Act 2001 Part 9.4AAA; ASIC RG 270 | https://www.legislation.gov.au/ ; https://asic.gov.au/ (canonical hosts; specific URLs not verified) | 2019 am. | Reference regime | K |
| B-CO-69 | 15 USC 78j-1(m)(4) (SOX §301); 18 USC 1514A (SOX §806); 15 USC 78u-6 and 17 CFR 240.21F (Dodd-Frank); 31 USC 3729–3733 (FCA); 5 USC 1213, 2302 (WPA/WPEA) | https://uscode.house.gov/ ; https://www.ecfr.gov/ (canonical hosts, not fetched) | current | US federal statutes | K |
| B-CO-70 | Florida Statutes §112.3188 (whistleblower confidentiality); Chicago MCC ch. 2-56; California Labor Code §1102.5 | state/municipal code hosts (not fetched) | current | State/municipal examples | K / UNVERIFIED specifics |

*(IDs B-CO-38/39 and 57–59 intentionally unused.)*
