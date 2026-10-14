# 38 — Implementation Roadmap

Status: Draft v1.0 · Edition applicability: both · Owner: Lead Architect / Program Management

## 1. Purpose and scope

Sequences the build of Candor so that (a) security-critical foundations exist before features depend on them, (b) every milestone exits only through the security gates of `27-SECURE-DEVELOPMENT.md` (SG-01..SG-24) and the anonymity regression suite of `30-ANONYMITY-TESTING.md`, and (c) independent audits (`37-SECURITY-AUDIT-PLAN.md`) happen before, not after, sources are exposed to the software. It also assigns work packages to the separate teams the specification set is written for.

## 2. Principles

1. **Trust path first.** candor-core (C-11), candor-safefs (ADR-027), the envelope/key-directory formats (04) and the intake/core separation (ADR-009) are built and reviewed before any UI polish.
2. **No source exposure before audit.** No production onion address is published for a real organisation before milestone RM-6 exit (external crypto review + pentest + anonymity review closed at High/Critical = 0).
3. **Regression-proof privacy from day one.** The canary/marker sink scan (AT-001 family in 30) runs in CI from RM-1, so metadata leaks are caught when introduced, not in audit.
4. **Community first, same code.** CE ships the complete trust path; EE modules (ADR-020) start only after CE 1.0 is audited, so commercial pressure cannot shape the trust path.
5. **Formal model before freeze.** The protocol (04 §sequence diagrams) is modelled in Tamarin/ProVerif and the model is kept in the repository; wire formats freeze only after the model checks pass.

## 3. Teams and work packages

| Team | Owns (spec) | Components |
|---|---|---|
| T1 Crypto & Protocol | 04, 16 (key parts), 33 (signing) | C-11, C-14, C-28, C-29 |
| T2 Intake | 06, 07, 08 (source/relay APIs), 11, 16 | C-05, C-06, C-07, C-08, C-09, C-37, C-38 |
| T3 Case Core | 07, 08 (desk/admin APIs), 09, 14, 15, 20, 35 | C-10, C-12, C-13, C-21..C-24 |
| T4 Desk & Viewer | 10, 12, 13, 26 | C-15, C-17, C-18, C-19 |
| T5 Source App | 11 (Tier V), 04 | C-03 |
| T6 Platform/Infra | 17, 18, 19, 32, 34 | C-25, C-27, C-39, installers, images |
| T7 Supply Chain & Release | 27, 28, 29, 33, 37 | C-30..C-33 |
| T8 Enterprise (starts RM-7) | 21, 22, 24, 25 | C-26, C-34, C-35, C-36, C-40 |
| T9 Research/Usability/A11y | 05, 26, 30 (§usability) | studies, guidance text, translations |

## 4. Milestones

| ID | Milestone | Scope (deliverables) | Exit criteria (all required) | Depends on |
|---|---|---|---|---|
| RM-0 | Foundations | Repos, protected branches, DCO, CI with pinned actions, cargo-vet/deny, SBOM generation, two independent reproducible builders bootstrapped, TUF root ceremony (test keys), threat-model baseline (02) signed off | 28 SCM gates green on empty skeleton; two builders produce bit-identical skeleton artifact; SG gates wired into CI | — |
| RM-1 | candor-core & formats | HPKE/X-Wing, STREAM, KDF tree, envelope with 16 anonymous slots, key-directory log format, safe-fs API; KAT + Wycheproof + property + fuzz targets; Tamarin/ProVerif model v1 | 100% KAT pass; fuzzers 72 h no crash; formal model proves secrecy/authentication lemmas listed in 04; internal crypto review sign-off | RM-0 |
| RM-2 | Intake zone (Tier W) | Intake Gateway torrc, Source Web Service (no-JS), Intake Sealer isolation, Intake Store, PoW + rate limits, source passphrase flow, drafts-in-RAM, reply fetch | AT-001 marker scan: zero hits in all sinks; no-JS flow passes at Tor Browser "Safest"; malicious-input fuzz of form parsers; ST authz suite for source audience | RM-1 |
| RM-3 | Core zone | Relay pull, Case Service, DB schema + RLS, authz engine with COI, audit log hash chain, notifications (content-free), Erasure Key Vault, retention jobs | IDOR/cross-tenant suites pass; audit chain verification tool; relay one-way enforced by firewall test; compromise drills AT-020..AT-024 produce expected minimal answers | RM-1, RM-2 |
| RM-4 | Candor Desk & Viewer | Desk (Tauri), hardware-bound key storage (FIDO2 PRF/PIV/TPM), import & re-wrap, case UI, conversation, viewer microVM with pixels-to-PDF + mat2 + qpdf, export package with dual approval | Malicious-server harness (ADR-027) passes; hostile-file corpus (29) contained at CL-1; WCAG 2.2 AA audit of Desk; Desk reproducible build verified | RM-3 |
| RM-5 | Operations | Installers (CE-SINGLE, CE-HARDENED), config checker, self-test agent, secret placement manifest verification, backup wizard + restore test, signed auto-update via TUF, incident playbook tooling | Fresh install → config checker all-green without manual hardening; restore drill meets 19 RPO/RTO; update rollback/freeze tests pass | RM-3, RM-4 |
| RM-6 | CE 1.0 release candidate | Full source UI i18n (≥10 locales incl. RTL), accessibility, source OPSEC guidance, documentation set, usability study round 1 | External audits A1 (crypto & protocol), A2 (application pentest), A3 (anonymity/metadata review), A4 (supply-chain & reproducibility) complete; all Critical/High fixed and re-tested; usability study shows mode-comprehension ≥ target in 30; public audit reports published | RM-5 |
| RM-7 | CE 1.0 GA | Public release, bug bounty live, advisories process, LTS branch cut | Release signed by threshold across ≥2 organisations; transparency log entries witnessed; post-release canary scan of reference deployment clean | RM-6 |
| RM-8 | Tier V clients | Candor Source App (desktop; Arti embedded), WEBCAT-signed web bundle (enabled only when WEBCAT support is available in Tor Browser) | Source App reproducible across builders; A5 audit (client) complete; key-directory verification UX tested | RM-7 |
| RM-9 | EE foundations | Fleet Manager (no onion-address DB), SSO bridge (first factor only), PIV/CAC, HSM/PKCS#11, SIEM exporter (allow-list), records connector via Export Packages | ENT privacy-risk mitigations verified; AT marker scan extended to EE modules and fleet/support flows; A6 audit (EE modules) | RM-7 |
| RM-10 | EE-HA & GOV | HA profiles, DR automation, FIPS profile (AWS-LC FIPS), GOV profile hardening, compliance packs, OSCAL evidence export | HA observer inventory (21) verified by test; FIPS-mode KATs; failover drills; A7 audit (infrastructure/HA) | RM-9 |
| RM-11 | Managed service | Dedicated per-customer intake, vendor-access controls, support-bundle scrubbing, jurisdiction documentation | Vendor-compromise drill (30) shows no content/source identity available to vendor; A8 audit | RM-10 |
| RM-12 | Transport evolution | Arti onion-service migration; evaluation of cover-traffic transport per Transport Adapter admission criteria (16) | Arti parity tests (PoW, vanguards equivalent); independent anonymity review of any new transport | RM-7 |

## 5. Critical path and risk register

| Risk | Impact | Mitigation |
|---|---|---|
| Formal model finds protocol flaw late | Format churn, delays | Model built in RM-1 before any consumer code; formats versioned (suite IDs) |
| WEBCAT not available in Tor Browser | Tier V web path unavailable | Tier W default + Source App; web bundle ships disabled (04, 33) |
| Arti onion services not production-ready | Stay on C-tor longer | C-tor 0.4.8+ with PoW/vanguards is baseline; RM-12 is not on CE critical path |
| Independent second builder operator not found | Cannot meet ADR-022 | Budget in 24 BIZ; partner with reproducible-builds community/second org before RM-6 |
| Hardware-key PRF support varies by platform | Desk key unlock fallback | PIV/TPM fallbacks (15); software fallback only with CE warning |
| Usability study shows mode confusion | Source harm | RM-6 gate; iterate 11 copy before GA |
| Audit budget | Delay | Grants (OTF/NLnet/STA per 24/36) planned at RM-0 |

## 6. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| RM-001 | No production onion address for a real organisation SHALL be published before RM-6 exit criteria are met. | INC-101; B-SD-28 | THR-012, THR-014 | C-05 | INSP: release checklist sign-off; AUD: A1–A4 reports published |
| RM-002 | The anonymity marker scan (30 AT-001 family) SHALL run in CI from RM-2 onward and block merges on any hit. | INC-60; F-001 | THR-016 | C-31 | TST: CI job `anon-marker-scan` required status |
| RM-003 | Wire formats SHALL NOT be frozen until the formal protocol model passes all lemmas listed in 04. | B-CR-24; B-CR-25 | THR-012 | C-11 | INSP: model check CI artefact; AUD: A1 |
| RM-004 | EE module development SHALL NOT begin before CE 1.0 GA, and SHALL NOT modify Trust Path code except via public AGPL contributions. | ADR-020 | THR-027 | C-34 | INSP: repository boundary check in CI (EE repo cannot import intake crates) |
| RM-005 | Every milestone exit SHALL record the SG gate results (27) and open audit findings in a signed milestone report. | ADR-022 | THR-024 | C-32 | INSP: signed report in transparency log |
