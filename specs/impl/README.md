# specs/impl — Secure implementation specifications

Status: Draft v1.0 (2026-10-01) · Owner: Security Lead with Lead Architect

This directory explains, step by step, **how** to build each milestone of `../38-IMPLEMENTATION-ROADMAP.md` securely. The numbered specs `00`–`40` and `DECISIONS.md` say **what** Candor must do, and they stay normative. The IMPL documents add implementation rules, pitfalls from past incidents, auditor checklists, test commands and exit gates. If an IMPL document conflicts with a numbered spec or an ADR, the spec or ADR wins and the conflict is recorded as an open issue (precedence: `IMPL-00` §2).

Research basis: `../../research/R7-secure-implementation.md` (rules `SI-x-nn`, bibliography `B-SI-`), `../../research/R8-secure-dev-lifecycle.md` (rules `SL-R-nnn`, incidents `INC-SL-nn`, bibliography `B-SL-`) and `../../research/R9-secure-code-audit.md` (audit method, `B-AU-`). Historical incidents `INC-nn` come from R3 / `00-RESEARCH.md`.

## 1. Index

| Doc | Milestone | Scope (summary) | Primary teams |
|---|---|---|---|
| [IMPL-00-SECURE-IMPLEMENTATION-STANDARD.md](IMPL-00-SECURE-IMPLEMENTATION-STANDARD.md) | all | Global rules: per-change workflow, Rust coding rules, secrets, logging, input bounds, IPC, confinement, dependencies, test pyramid, review roles, **independent audit gate**, evidence, Definition of Done, `IMP-` traceability | all |
| [IMPL-RM0-FOUNDATIONS.md](IMPL-RM0-FOUNDATIONS.md) | RM-0 | Repositories, CI, supply-chain gates, reproducible builders, TUF test-key ceremony | T7 |
| [IMPL-RM1-CORE-LIBRARIES.md](IMPL-RM1-CORE-LIBRARIES.md) | RM-1 | candor-core, formats, key directory, safefs, log, source-ui, formal model | T1, T2, T3, T7 |
| [IMPL-RM2-INTAKE.md](IMPL-RM2-INTAKE.md) | RM-2 | Intake gateway, source web service (no-JS), sealer, intake store | T2 |
| [IMPL-RM3-CORE-ZONE.md](IMPL-RM3-CORE-ZONE.md) | RM-3 | Relay, case service, DB/RLS, authz/COI, audit log, vault, retention | T3 |
| [IMPL-RM4-DESK-VIEWER](IMPL-RM4-DESK-VIEWER.md) | RM-4 | Candor Desk, hardware-bound keys, viewer microVM, export | T4 |
| [IMPL-RM5-OPERATIONS.md](IMPL-RM5-OPERATIONS.md) | RM-5 | Installers, config checker, self-test, backup/restore and drills, signed auto-update, Platform Manifest and floors, support bundles | T6, T7 |
| [IMPL-RM6-RELEASE-CANDIDATE.md](IMPL-RM6-RELEASE-CANDIDATE.md) | RM-6 | i18n with translation security, safety guidance, accessibility, usability studies, LLM-assisted pre-audit (SL-R-013), external audits RM6-A1..A4 | T9, T7 |
| [IMPL-RM7-GA-RELEASE.md](IMPL-RM7-GA-RELEASE.md) | RM-7 | Threshold key ceremonies, TUF repository, transparency log and witnesses, two-builder verification, VDP/advisories/CVE, bug bounty, LTS | T7, Security Lead |
| [IMPL-RM8-SOURCE-APP.md](IMPL-RM8-SOURCE-APP.md) | RM-8 | Source App with embedded Arti, fixed-size encrypted vault (ADR-047(1)), distribution (ADR-041), WEBCAT web bundle (disabled until supported) | T5, T1, T7 |
| [IMPL-RM9-EE-FOUNDATIONS.md](IMPL-RM9-EE-FOUNDATIONS.md) | RM-9 | Fleet Manager, SSO bridge (first factor only), PIV/CAC, HSM/PKCS#11, SIEM exporter, records connectors | T8 |
| [IMPL-RM10-HA-GOV-FIPS.md](IMPL-RM10-HA-GOV-FIPS.md) | RM-10 | HA topology and observers, DR automation, CANDOR-FIPS-1 build, GOV hardening, OSCAL evidence | T8, T6, T1 |
| [IMPL-RM11-MANAGED.md](IMPL-RM11-MANAGED.md) | RM-11 | Dedicated per-customer intake, vendor access controls, ticketing and bundles, jurisdiction documentation, vendor-compromise drill | T8, vendor ops |
| [IMPL-RM12-TRANSPORT.md](IMPL-RM12-TRANSPORT.md) | RM-12 | Arti onion-service migration gates (ADR-049), parity tests, phased rollout, cover-traffic transport admission (16 §6.3) | T2, T6, T9 |

Order: RM-0 → RM-1 → RM-2 → RM-3 → RM-4 → RM-5 → RM-6 → RM-7, then RM-8, RM-9 → RM-10 → RM-11, and RM-12 independently after RM-7 (38 §4). EE work (RM-9+) does not start before CE 1.0 GA (RM-004, ADR-048(4)).

## 2. Structure of every step document

| § | Content | Used by |
|---|---|---|
| 1 | Purpose and scope: components `C-nn`, spec sections implemented, out of scope | builder, auditor |
| 2 | Preconditions that must hold before work starts | lead |
| 3 | Build sequence: ordered steps (`RMn-Sx`), each with build, interfaces, rules (cited `SI-`/`SL-R-`/ADR IDs), incident pitfalls, step verification | builder |
| 4 | Component-specific auditor threat checklist (with `THR-` IDs) | independent auditor |
| 5 | Test plan with tool commands and the SG gate each feeds | builder, CI |
| 6 | OPSEC checklist: metadata, vendor and operator exposure the step could create | builder, auditor |
| 7 | Exit criteria: roadmap exit (38), SG gates (27), audit gate, milestone record | lead |
| 8 | Requirements `IMP-RMn-NNN` in the 6-column format of DECISIONS §1 | traceability |
| 9 | Residual risks and open issues | lead, 40 owner |

## 3. How to use these documents with the audit gate

| Stage | Who | What | Output |
|---|---|---|---|
| 1. Plan | Lead | Confirm §2 preconditions; assign one step `RMn-Sx` per work package | Work package referencing step ID |
| 2. Build | Builder | Follow IMPL-00 (global rules) and the step's §3 rules; write tests from §5; check §6 | Code, tests, `SPEC-NOTES.md` incl. "Security self-review" (IMPL-00 §14.2) |
| 3. Review | Reviewer(s) per IMPL-00 §12 | Code review; Definition of Done (IMPL-00 §15) | Approvals |
| 4. Independent audit | Auditor ≠ builder ≠ approving reviewer | IMPL-00 §13 procedure, `process/AUDIT-CHECKLIST.md`, R9, plus the step's §4 checklist and §6 OPSEC checklist | `process/audits/AUDIT-RMn-Sx.md` (findings table, verdict) |
| 5. Fix and re-test | Builder, then auditor | Fix every Critical/High; fix Medium or obtain the lead's written acceptance with expiry; red→green regression per fix (SL-R-014) and variant scan | Auditor closure sign-off |
| 6. Integrate | Lead | Merge only with 0 open Critical/High (IMP-STD-019; BUILD-BRIEF audit gate) | Merged step |
| 7. Milestone exit | Lead, Security Lead | All steps closed; §7 criteria met; SG results recorded | Signed milestone report in transparency log (RM-005) |

Rules that apply across all stages:
- Builders never audit their own code for this gate.
- External audits (37) supplement but never replace the per-step independent audit; fixes from external audits pass the same gate.
- Before external audits RM6-A1..A4, the LLM-assisted pre-audit (ST-142, SL-R-013) runs and its findings are closed (IMPL-00 §13 item 6; IMPL-RM6 S7).
- Severity follows IMPL-00 §13 item 3 and 37 §8 (CVSS 4.0 and AIR, final = max).

## 4. Audit label mapping (38 roadmap labels → 37 activity IDs)

38 uses its own audit labels; 37 owns the activity catalogue. The IMPL documents use the 37 IDs.

| 38 label | Milestone | 37 activities |
|---|---|---|
| A1 crypto & protocol | RM-6 | A4, A5 (final proofs), A6 |
| A2 application pentest | RM-6 | A1 (ST-140), A10, A17 |
| A3 anonymity/metadata | RM-6 | A7 (#2), A14 optional |
| A4 supply chain & reproducibility | RM-6 | A9, A11, A8 (CE profiles) |
| A5 client | RM-8 | A13 |
| A6 EE modules | RM-9 | A12 (+ A1 scoped, A8 EE-ONPREM) |
| A7 infrastructure/HA | RM-10 | A8 (+ A6 FIPS, A17 GOV) |
| A8 managed | RM-11 | A8 vendor infrastructure, A7 provider-observer, A16 (A15 if TEE) |

## 5. Traceability

- Requirement IDs: `IMP-STD-NNN` (IMPL-00) and `IMP-RMn-NNN` (step docs), never reused (IMPL-00 §16).
- `IMP-` is not yet registered in DECISIONS §3, and `tools/traceability.py` does not yet scan `specs/impl/*.md` (IMPL-00 OI-IMPL-1).
- Some `IMP-RM5..RM12` rows quote canonical values from 18/19/33/04 (for example intervals, thresholds, sizes) for readability. Those values are owned by their specs and the constants registry (39 §Constants, ST-167). When the spec-constant lint is extended to `specs/impl/`, any drift fails it; until then, reviewers check quoted values against the owning spec.

## 6. Consolidated cross-document requests from RM-5..RM-12 docs

| # | Request | Owner | Source |
|---|---|---|---|
| X-1 | Cite 37 activity IDs in 38 milestone exit criteria (see §4) | 38 | IMPL-RM6 OI-1/OI-2 |
| X-2 | Align 38 RM-7 "≥ 2 organisations" with 33/ADR-040 (targets: 3 organisations; root: ≥ 3) | 38 | IMPL-RM7 OI-1 |
| X-3 | Specify playbook-runner subcommands for 31 playbooks | 31, 18 | IMPL-RM5 OI-1 |
| X-4 | Decide FIPS anonymous-slot key privacy (ASM in 40 or pure ML-KEM-1024 slots) | 04, 22, 40 | IMPL-RM10 OI-1 |
| X-5 | Record Source App UI framework per platform in an ADR | DECISIONS | IMPL-RM8 OI-1 |
| X-6 | Register `IMP-` prefix in DECISIONS §3 and extend traceability and constants lint to `specs/impl/` | DECISIONS, 39 | IMPL-00 OI-IMPL-1 |
| X-7 | Create `process/AUDIT-CHECKLIST.md` and `process/audits/` | process | IMPL-00 OI-IMPL-2 |
