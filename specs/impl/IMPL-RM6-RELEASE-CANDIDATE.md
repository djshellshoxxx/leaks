# IMPL-RM6 — CE 1.0 Release Candidate: i18n and safety guidance, accessibility, usability studies, LLM-assisted pre-audit, external audits

Status: Draft v1.0 (2026-10-01) · Edition applicability: CE (EE inherits) · Owner: T9 Research/Usability/A11y (i18n, a11y, studies), T7 (audits, RC process), Security Lead (findings) · Roadmap milestone: RM-6

Global rules are in `IMPL-00-SECURE-IMPLEMENTATION-STANDARD.md` and are not repeated. Rule IDs as in `IMPL-RM5-OPERATIONS.md` header.

## 1. Purpose and scope

| Item | Content |
|---|---|
| Goal | Produce a release candidate whose source-facing text is correct in every shipped language, usable by people with disabilities and by non-technical sources, and independently audited before any real organisation publishes an onion address (RM-001) |
| Components | C-06 (source UI strings, page size budgets), C-15/C-19 (Desk and admin UI strings), C-37 (information-site templates and guidance), C-03 only if shipping at 1.0 (otherwise RM-8), C-31/C-32 (RC build on `preview` channel), whole trust path (audit scope) |
| Spec sections | 26 §3–§13 (WCAG 2.2, COGA, AT matrix, I18N pipeline, wordlists, testing); 05 (guidance cards GC-01..GC-38, readability SOPS-003, §9 comprehension); 11 (Tier-0 strings, size classes); 30 §10 (AT-070..AT-075, ethics, sample-size rule); 37 §4, §4.2, §4.3, §5, §11, §12 (audit catalogue, independence, inputs, findings, publication, schedule); 29 ST-140, ST-142; 27 SG-21/22/24 |

### 1.1 Audit label mapping (38 RM-6 labels → 37 activity IDs)

38 RM-6 names four external audits A1–A4; 37 numbers its activities differently. This document uses **RM6-A1..RM6-A4** to avoid ambiguity.

| RM-6 audit | Scope (38) | 37 activities that satisfy it | Must complete before RM-6 exit |
|---|---|---|---|
| RM6-A1 | Crypto & protocol | 37 A4 (crypto design review, at design freeze), A5 final proofs, A6 crypto implementation review | Yes |
| RM6-A2 | Application pentest | 37 A1 full pentest (ST-140), A10 source-code review incl. LLM-assisted, A17 implementation review | Yes |
| RM6-A3 | Anonymity/metadata review | 37 A7 #2 (incl. inferential tests 30 §9A), A14 optional | Yes |
| RM6-A4 | Supply chain & reproducibility | 37 A9 (supply-chain review), A11 independent rebuild, A8 infrastructure review for CE-SINGLE/CE-HARDENED | Yes |

The mismatch is recorded as OI-1 (§9) for 38's owner.

## 2. Preconditions

| # | Precondition |
|---|---|
| P1 | RM-5 exit report signed; SG-16/17/19/20/27 green |
| P2 | Feature freeze: no new trust-path features after RC1 except audit fixes (37 §4.1 triggers re-scope) |
| P3 | 37 "Protocol design freeze" activities done (A4, initial A5, A17 design review); "Beta" activities done (A10 #1, A7 #1, A8, lab bounty at 50%) |
| P4 | Self-hosted Weblate on infrastructure separate from builders, signers and production (26 §12.3) |
| P5 | Ethics board approval for usability round 1 (30 §10.2) |
| P6 | Auditor contracts signed with publication rights, regression-artefact delivery, ≤ 90-day embargo and conflict-of-interest declarations (37 §4.2) |

## 3. Build sequence

### RM6-S1 String catalog freeze and translation-security pipeline

| Aspect | Specification |
|---|---|
| Build | Fluent `.ftl` catalogs per component; class annotations (`sec:critical tier0`, `sec:critical`, `legal`, `ui`); CI translation-security lint; per-locale approval state in the release manifest |
| Rules | Lint rejects translations adding URLs, emails, onion addresses, phone numbers or HTML absent from the source, changing placeables, or exceeding 2.5× length (26 §12.3); no third-party machine translation; self-hosted MT only for `ui`; Weblate output is a PR with normal review and cannot push to release branches; Tier-0 staleness disables the locale on that surface (I18N-005); ICU4X/CLDR data vendored, no runtime locale download; locale carried only in URL path prefix and SHALL NOT be persisted in C-08, envelope cleartext, logs or metrics (ADR-023) |
| Pitfalls | Translator account takeover inserting a phishing onion (INC-47 class: compromised contributor account; INC-43 class impersonation); INC-46/INC-53 (third-party resources) |
| Verify | Lint unit tests with injected URL/onion/placeholder changes; pseudo-locales en-XA, ar-XB, en-XL on every UI PR (26 §12.4); AT-092 (mode banner rendering per locale) |

### RM6-S2 Locale rendering and size budgets

| Aspect | Specification |
|---|---|
| Build | ≥ 10 source-UI locales incl. ≥ 1 RTL (PRD-048, 26 §12.1); build-time test rendering every P1 page per locale within its size class (ADR-051(2)); S02b sub-page fallback |
| Rules | Size class depends on request type, never on page or locale (ADR-051(2), SI-C-06); no inline styles or external fonts; bundled fonts subset per script with identical response classes; passphrase rendered in `<bdi dir="ltr">` isolate (26 §12.7) |
| Pitfalls | INC-36 (Tor Browser fingerprinting via resources); page-identity leakage by size (THR-004) |
| Verify | AT-040..AT-048 size tests per locale; route × outcome × locale size enumeration (SI-C-06 verify); axe in no-JS Firefox ESR at Tor Browser base |

### RM6-S3 Source OPSEC guidance, safety tips and documentation set

| Aspect | Specification |
|---|---|
| Build | Guidance cards GC-01..GC-38 (05) in all locales; Tier W honesty statement (ADR-004, ADR-035 §5); first-contact guidance; operator documentation set (install, operate, backup, IR, upgrade, verification steps 33 §18); C-37 template with security.txt (37 §6.1) |
| Rules | Tier-0/critical review rules (26 §12.2): Tier-0 = translator + 2 independent native reviewers; critical = translator + 1 reviewer + back-translation spot check; readability FK ≤ 8.0 / ≤ 10.0 high-risk (SOPS-003), CEFR B1 elsewhere; per-locale wordlist admission gate (26 §12.7, ADR-047(6)) with entropy ≥ 128 bits; docs site and C-37 templates load no third-party resources and no analytics (ADR-023); no guidance claims stronger than the spec (DECISIONS §0 language rules) |
| Pitfalls | INC-16, INC-21, INC-31, INC-32 (human/process deanonymizations), INC-20/INC-17 (metadata in files), INC-73 (stylometry) |
| Verify | `sops-readability` CI; language-rule lint for banned claims across docs and catalogs; wordlist admission record per locale; comprehension items K1–K8 in studies |

### RM6-S4 Accessibility conformance (WCAG 2.2 AA) and audit

| Aspect | Specification |
|---|---|
| Build | Fixes until 26 §13.1 automated gates pass; manual expert review (26 §13.2) by reviewers not on the feature team; AT matrix walkthroughs (26 §13.3); ACR (CE self-assessed); optional 37 A14 accessibility-security audit |
| Rules | No third-party accessibility overlays or services (26 §11); no accessibility feedback data collected from sources; security prompts (mode banners, passphrase confirmation S10/S10c, COI checklist) tested with AT; Desk CL-2 accessible text view for scanned attachments produced inside the sandbox (ADR-042) |
| Pitfalls | Overlay vendors injecting third-party JS (INC-46 class) |
| Verify | axe-core 0 serious/critical in en, en-XA, ar-XB; Nu HTML checker 0 errors; keyboard-walk match; 320 px reflow; 0 open AA failures at RC (PRD SM-08) |

### RM6-S5 Usability-security study round 1

| Aspect | Specification |
|---|---|
| Build | Studies AT-070..AT-075 with groups G1..G6 (30 §10.3); synthetic scenarios; lab devices; RC on an isolated lab instance labelled TEST |
| Rules | Ethics: consent, withdrawal, pseudonymous IDs, no face video, audio deleted ≤ 30 days, data ≤ 12 months, never entered into a Candor instance (30 §10.2); sample-size rule for threshold claims (n ≥ 59 / 0 failures for ≤ 5 %, n ≥ 29 / 0 for ≤ 10 %), otherwise report upper bound only; published report aggregate with k ≥ 10 per cell; every SCE root-caused UI vs user and UI-caused SCEs = 0 |
| Pitfalls | INC-16/INC-21 (human error is the dominant deanonymization class); mode confusion THR-040 |
| Verify | Thresholds of 30 §10.4 (mode identification ≥ 95 %, false-anonymous ≤ 5 %, SCE sources ≤ 10 % / staff ≤ 5 %, recovery ≥ 90 % at 7 d); SG-24 |

### RM6-S6 RC cut, QA matrix and per-release test plan

| Aspect | Specification |
|---|---|
| Build | RC tagged (signed, two-party reviewed) and published on `preview` channel only (installer refuses on production profile flag, 33 §9.1); `qa/<ver>/test-plan.md` from `feature/*` PR labels; QA matrix (profiles CE-SINGLE, CE-HARDENED × Desk Linux/macOS/Windows × locales) (R8 §1.1 "SG-QA") |
| Rules | QA and audit only start after an RC exists (B-SL-01); RC built by Builders A and B with equal hashes (SG-13); RC keys are TEST-ONLY |
| Verify | QA matrix 100% filled and signed by release manager; SG-01..SG-29 run on RC |

### RM6-S7 LLM-assisted pre-audit (SL-R-013, ST-142)

| Aspect | Specification |
|---|---|
| Build | Internal adversarial code review of the whole trust path with an LLM-assisted pipeline before any of RM6-A1..A4 start; findings triaged by humans; report `process/audits/AUDIT-RM6-LLM.md` attached to the RM-6 entry gate |
| Rules | Every candidate finding validated by a human with a PoC or a reasoned dismissal; each confirmed finding gets a red→green regression test (SL-R-014) and variant analysis (27 SDL-053); embargoed findings, unreleased fixes, credentials and any non-synthetic data SHALL NOT be sent to third-party LLM services; use a self-hosted model or a contract with no retention/training; record model, version, prompts set and corpus commit for reproducibility; LLM review supplements and never replaces the independent audit gate or external audits; focus areas from R9 §2–§6 (authorization, tenancy, mass-assignment, logic, parser, metadata sinks) |
| Pitfalls | GlobaLeaks 2026 LLM-adversary audit found 29 issues (B-SL-09, INC-SL-15): attackers have the same tooling |
| Verify | All findings closed or accepted (Security Lead + one external reviewer for downgrades) before A1–A4 kickoff; mapping in SG-21 report |

### RM6-S8 Audit preparation and lab

| Aspect | Specification |
|---|---|
| Build | Audit input package per 37 §4.3 (spec set, threat model version, prior reports with fix mapping, 29/30 results incl. drill oracle and inferential reports, constants registry, SBOM, exceptions register, build instructions); isolated lab instances with TEST keys and synthetic data only; test accounts |
| Rules | Lab shares no keys, hosts, onion addresses or credentials with any production or bounty instance; auditors receive accounts with least privilege per test perspective (malicious server, insider, organisation-as-adversary); auditor independence per 37 §4.2 (no keyholder, no Builder B operator, no EE reseller) |
| Verify | Inspection checklist signed by Security Lead; ST-121 on lab hosts |

### RM6-S9 External audits RM6-A1..A4 and findings management

| Aspect | Specification |
|---|---|
| Build | Run audits per §1.1; findings tracked as `CANDOR-AUD-<year>-<firm>-<nn>` (37 §5); severity = max(CVSS 4.0, AIR mapping) (37 §8) |
| Rules | No closure without mapped test or static rule (ST-012, SG-21) and a red→green regression (SL-R-014); auditor retests all Critical/High; disputes published with both positions; auditors deliver PoCs and Semgrep/CodeQL rules; fixes go through the normal independent audit gate (§7) |
| Pitfalls | INC-101..INC-109 (SecureDrop/OnionShare repeated path, IPC and archive bugs); INC-112..INC-119 (GlobaLeaks/Hush Line authz and header bugs) |
| Verify | 0 open Critical/High across RM6-A1..A4; retest letters; SG-22 |

### RM6-S10 Publication and release decision

| Aspect | Specification |
|---|---|
| Build | Publish full reports, plain-language summaries and audit index (37 §11) on project site, onion mirror and `audits/` (signed commit) |
| Rules | Redactions only per 37 §11 with reasons; no production onion for a real organisation before RM-6 exit (RM-001); signed RM-6 milestone report (RM-005) |
| Verify | Inspection of published index; RM-001 checklist sign-off |

## 4. Auditor threat checklist (component-specific)

| # | Check | Threats |
|---|---|---|
| 1 | Can a translation introduce a link, onion address, contact or instruction that contradicts a Tier-0 meaning and still ship? | THR-040, THR-007 |
| 2 | Is the selected locale or wordlist language persisted or logged anywhere server-side? | THR-016, THR-039 |
| 3 | Does any locale push a P1 page into a different size class or load different resources? | THR-004, THR-006 |
| 4 | Do mode banners and honesty statements render correctly in RTL, at 400 % zoom and with screen readers? | THR-040 |
| 5 | Do docs, C-37 templates or the a11y tooling load any third-party resource? | THR-036 |
| 6 | Did study data or LLM pre-audit inputs leave the controlled environment (third-party services, real data)? | THR-027, THR-016 |
| 7 | Is each audit finding mapped to a regression test and retested, and are downgrades justified by two people? | THR-024 |
| 8 | Do lab or RC instances share any key, onion address or host with production or bounty labs? | THR-044, THR-013 |
| 9 | Is the RC build reproducible on both builders and confined to the `preview` channel? | THR-024, THR-025 |
| 10 | Does any guidance text claim stronger protection than the spec allows (DECISIONS §0)? | THR-040 |

## 5. Test plan

| Test | Command / tool | Gate |
|---|---|---|
| Fluent and security lint | `cargo run -p candor-i18n-lint -- --catalogs i18n/ --strict` (placeables, URLs/onions, length ratio) | PR |
| Pseudo-locales | e2e suites with `LOCALE=en-XA` and `LOCALE=ar-XB` | PR (UI) |
| Size budgets | build-time P1 render test per locale; AT-040..AT-048 | SG-12 |
| A11y automated | axe-core headless in no-JS Firefox ESR; `vnu --errors-only`; token contrast script; keyboard walk | PR; 26 §13.1 |
| Readability | `sops-readability --max-fk 8.0` (`10.0` high-risk) | PR |
| Banned-claims lint | `rg -i -f tools/banned-claims.txt specs/ docs/ i18n/` returns nothing (term list generated from DECISIONS §0) | PR |
| Studies | AT-070..AT-075 protocols (30 §10.5) | SG-24 |
| LLM sweep | ST-142 pipeline on tag `rc1`; report to `process/audits/AUDIT-RM6-LLM.md` | RM-6 entry |
| Pentest | ST-140 (37 A1) | SG-22 |
| Regression mapping | SG-21 report generator over audit trackers | SG-21 |
| Full gates on RC | SG-01..SG-29 incl. AT canary over 8 profiles at max verbosity (30 §11) | RC |

## 6. OPSEC checklist

| Exposure | Control |
|---|---|
| Weblate host compromise or translator impersonation | Separate host, 2FA, recorded reviewer identities for critical strings, lint, PR review |
| Locale reveals source language/country | Not persisted; same size classes; wordlist language not stored (ADR-047(6)) |
| Study participants' identities and recordings | 30 §10.2 ethics rules; aggregate k ≥ 10 reporting; lab devices only |
| Real whistleblowing need disclosed in a study | Neutral resources list; participant not recruited further (30 §10.2) |
| Auditors' access to lab | Synthetic data only; separate keys; access ends at report delivery |
| LLM pre-audit leaks embargoed issues | Self-hosted or no-retention contract; no embargoed material to third parties |
| Audit reports reveal customer/operator data | Redaction rule (c) in 37 §11; labs contain none |
| RC accidentally used for a real deployment | `preview` channel refused on production profile flag; RC banner "not for real submissions" |

## 7. Exit criteria

| Type | Criterion |
|---|---|
| Roadmap (38 RM-6) | RM6-A1..A4 complete; all Critical/High fixed and re-tested; usability study meets mode-comprehension targets of 30 §10.4; public audit reports published |
| Spec gates | ≥ 10 locales incl. RTL with all Tier-0 strings approved; 0 open WCAG 2.2 AA failures; SG-21, SG-22, SG-24 pass; QA matrix signed; LLM pre-audit closed before external audits (SL-R-013) |
| Audit gate | Each step RM6-S1..S10 audited independently (`process/audits/AUDIT-RM6-Sn.md`); every fix from external audits passes the same gate; 0 open Critical/High; Medium fixed or lead-accepted in writing |
| Milestone record | Signed RM-6 report logged (RM-005); RM-001 sign-off |

## 8. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| IMP-RM6-001 | Translations SHALL be rejected in CI if they add URLs, email or onion addresses, phone numbers or HTML absent from the source string, alter placeables, or exceed 2.5× source length. | INC-47; INC-46 | THR-040, THR-007 | C-06 | TST: i18n security lint unit tests; INSP |
| IMP-RM6-002 | Tier-0 strings SHALL ship in a locale only after translator plus two independent native reviewers approve; staleness SHALL disable that locale on the affected surface. | 26 §12.2; I18N-005 | THR-040 | C-06 | TST: release-manifest approval check |
| IMP-RM6-003 | The source's selected locale and wordlist language SHALL NOT be persisted in C-08, envelope cleartext, logs or metrics. | ADR-023; ADR-047(6) | THR-016, THR-039 | C-06 | AT-001 with locale markers; TST: schema inspection |
| IMP-RM6-004 | Every shipped locale SHALL render every P1 page within its request-type size class. | ADR-051(2); ADR-011 | THR-004 | C-06 | TST: build-time locale size test; AT-040 |
| IMP-RM6-005 | Docs, C-37 templates and accessibility tooling SHALL load no third-party resources and no overlays. | INC-46; INC-53 | THR-036 | C-37 | AT-050..AT-058; TST: resource-origin scan |
| IMP-RM6-006 | Source-facing guidance and documentation SHALL pass the readability thresholds of SOPS-003 and a banned-claims lint. | DECISIONS §0; INC-16 | THR-040, THR-041 | C-06 | TST: `sops-readability`; TST: banned-claims lint |
| IMP-RM6-007 | The RC SHALL have 0 serious/critical axe violations and 0 open WCAG 2.2 AA failures on source, Desk and admin surfaces. | 26 §13; B-CO-28 | THR-040 | C-15 | TST: axe/vnu CI; INSP: expert review; AUD: A14 (optional) |
| IMP-RM6-008 | Usability round 1 SHALL meet the 30 §10.4 thresholds or report confidence bounds without threshold claims, with 0 UI-caused security-critical errors. | INC-16; INC-21 | THR-040, THR-041 | C-06 | DEMO: AT-070..AT-075; SG-24 |
| IMP-RM6-009 | Study data SHALL follow 30 §10.2 ethics rules and SHALL never enter a Candor instance. | 30 §10.2 | THR-016 | C-06 | INSP: ethics record; DEMO: data-handling audit |
| IMP-RM6-010 | An LLM-assisted adversarial code review of the trust path SHALL be completed and its findings closed or accepted before RM6-A1..A4 begin; embargoed material SHALL NOT be sent to third-party LLM services. | SL-R-013; B-SL-09 | THR-024, THR-021 | C-30 | ST-142; INSP: AUDIT-RM6-LLM report |
| IMP-RM6-011 | RM6-A1 (37 A4/A5/A6), RM6-A2 (37 A1/A10/A17), RM6-A3 (37 A7) and RM6-A4 (37 A9/A11/A8) SHALL complete with 0 open Critical/High after retest. | RM-001; INC-101 | THR-012, THR-021, THR-016, THR-024 | C-32 | AUD: published reports; ST-140; SG-22 |
| IMP-RM6-012 | Every closed finding SHALL map to a regression test that failed before the fix. | SL-R-014; B-SD-28 | THR-024 | C-31 | TST: SG-21 mapping report |
| IMP-RM6-013 | Audit and RC lab instances SHALL share no keys, onion addresses, hosts or credentials with production or bounty instances. | INC-106; RM-001 | THR-044, THR-013 | C-05 | ST-121 on lab; INSP |
| IMP-RM6-014 | The RC SHALL be published only on the `preview` channel and SHALL be refused by installers on production profiles. | 33 §9.1 | THR-025 | C-32 | TST: installer channel refusal |
| IMP-RM6-015 | Full audit reports SHALL be published within 37 §11 limits with only the permitted redactions. | 37 §11; B-SD-43 | THR-024 | C-30 | INSP: audit index |

## 9. Residual risks and open issues

| # | Item | Handling |
|---|---|---|
| R1 | Studies find defects but small n cannot prove low error rates | Sample-size rule; bounds reported; repeated each major |
| R2 | Native reviewers for some locales are scarce; review quality varies | Two-reviewer rule for Tier-0; locale disabled rather than shipped stale |
| R3 | LLM tools produce false negatives; their absence of findings proves nothing | Used only as pre-filter; external audits remain mandatory |
| R4 | Audit time boxes leave unreviewed code | Plain-language limitation statements in published summaries (37 §11); A2 rotation |
| OI-1 | 38 RM-6 audit labels A1–A4 do not match 37 activity IDs | Mapping §1.1; cross-document request to 38 owner to cite 37 IDs |
| OI-2 | 38 RM-8/RM-9/RM-10/RM-11 audit labels (A5–A8) also differ from 37 (A13, A12, A8, A8/A7/A16) | Mapped in IMPL-RM8..RM11; same request |
