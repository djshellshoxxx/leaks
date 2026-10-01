# IMPL-RM11 — Managed service: dedicated per-customer intake, vendor-access controls, support-bundle scrubbing, jurisdiction documentation

Status: Draft v1.0 (2026-10-01) · Edition applicability: EE (MANAGED profile) · Owner: T8 Enterprise; T6 Platform/Infra; vendor operations lead; Security Lead · Roadmap milestone: RM-11

Global rules are in `IMPL-00-SECURE-IMPLEMENTATION-STANDARD.md` and are not repeated. Rule ID sources as in `IMPL-RM5-OPERATIONS.md`.

## 1. Purpose and scope

| Item | Content |
|---|---|
| Goal | A vendor operates Candor for customers such that a compromised, curious or compelled vendor cannot read report content or identify sources, and everything the vendor *can* observe is listed and disclosed |
| Components | C-05..C-08 per customer (dedicated intake gateway and onion key), C-10..C-14 (vendor-operated core), C-34 (vendor-hosted Fleet), C-36 (vendor support infrastructure, ticketing, bundles), C-24 (audit export to customer-held key), C-25, C-27, C-39 |
| Spec sections | ADR-021 (dedicated intake per customer), ADR-024 (MANAGED), ADR-035 (watchers, operator statement, optional Confidential-VM sealer), ADR-045, ADR-047(10); 18 §4.8, §8.1 item 10; 17 INFRA-046; 21 §6.3, §9; 32 §8 (support bundles); 30 AT-031/AT-032 (vendor union drill); 25 §5.7 (FedRAMP 20x annex); 31 (vendor-side IR); 37 A8, A7, A16, A15 (if TEE) |

## 2. Preconditions

| # | Precondition |
|---|---|
| P1 | RM-10 exit (HA, DR, GOV hardening audited) |
| P2 | Vendor legal entity, jurisdiction analysis and legal-compulsion policy drafted (THR-026) |
| P3 | ≥ 2 External Watchers independent of the vendor, ≥ 1 outside the operator's jurisdiction (ADR-035(1)) |
| P4 | Customer-held key procedures: audit export key (ADR-047(10)), Fleet command key (21 §9.3), attestation verifier (18 §8.1 item 10) |

## 3. Build sequence

### RM11-S1 Tenant provisioning with dedicated intake

| Aspect | Specification |
|---|---|
| Build | Provisioning pipeline creating, per customer, a dedicated intake host/VM (never a shared cluster), onion key generated on that host, dedicated sealer and store; customer-specific Key Directory and channel keys created by the customer's own Desks |
| Rules | No cross-customer shared Z-INTAKE (ADR-021); onion key never leaves the intake host except as BS-SECRETS to the customer-controlled IRK quorum; provisioning system stores opaque instance IDs, not onion addresses (C-34 rule); provisioning logs exclude secrets and addresses; vendor never holds customer recipient or case keys (ADR-007); per-customer infrastructure separation recorded in the Secret Placement Manifest |
| Pitfalls | INC-113 (cross-tenant action), INC-45 (worm-style spread across shared tooling), INC-54 (shared infrastructure leak) |
| Verify | ST-121 per tenant; cross-tenant isolation tests (no route between tenants' intake hosts); AT-031/AT-032 |

### RM11-S2 Vendor access controls

| Aspect | Specification |
|---|---|
| Build | Just-in-time access broker for vendor operators: time-bounded, ticket-bound grants approved by the customer's admin plus independent role for availability-affecting actions (ADR-045); access via restricted-discovery staff onion or out-of-band management; per-host distinct SSH host keys; session command logging (not screen recording of Desk) delivered to the customer |
| Rules | Vendor operators hold no Desk roles and no case keys; no standing root on intake hosts; break-glass requires the customer's independent role; all vendor access events in SECURITY class, exported to the customer encrypted to the customer-held audit key (ADR-047(10)); access credentials hardware-bound (FIDO2); vendor staff screening per contract (22 §9 for GOV); no vendor tooling that dumps DB, memory or tor state |
| Pitfalls | INC-68..INC-72 (insiders abusing privileged access), INC-56 (support system breach), INC-58 (crash dumps with keys) |
| Verify | ST-068 (admin ≠ case access) under vendor roles; ST-176 (customer-held audit export key); access-without-approval negative tests |

### RM11-S3 Customer-held trust anchors and attestation

| Aspect | Specification |
|---|---|
| Build | Customer-held attestation verifier registered before go-live and verifying ≥ 1 quote (18 §8.1 item 10, INFRA-046); optional Confidential-VM sealer profile (ADR-035(3)) only after 37 A15; running-manifest publication to watchers |
| Rules | Attestation evidence freshness ≤ 24 h (ADR-047(4)); TEE never presented as a guarantee (37 A15 honesty requirement); Fleet command key customer-held (vendor relays, cannot author); watchers independent of vendor |
| Verify | ST-173 (attestation freshness), ST-155 (watcher mismatch), ST-156 (verifier replay/debug policy) |

### RM11-S4 Support-bundle scrubbing and vendor ticketing (C-36)

| Aspect | Specification |
|---|---|
| Build | Vendor ticketing configured per 32 §8: bundles accepted only as encrypted allow-list bundles created by the operator; automated re-scan on receipt; retention ≤ 30 days with deletion confirmation |
| Rules | Ticket forms forbid HAR files, screenshots of Desk, DB dumps and case data, with upload filters rejecting those types; tickets reference instance IDs, never onion addresses or tenant names; support staff cannot request diagnostics from sources (REQ-H-56); INDEPENDENT-channel bundles only to vendor or OVERSIGHT key, never corporate helpdesk |
| Pitfalls | INC-56 (Okta HAR files), INC-60 |
| Verify | AT canary over ticket store; upload-filter tests; retention job test |

### RM11-S5 Jurisdiction and compulsion documentation

| Aspect | Specification |
|---|---|
| Build | Per-customer data-location statement (all zones, DR, backups, support staff locations); vendor legal-compulsion policy and published transparency report; source-facing operator statement inputs (ADR-035(2)); FedRAMP 20x boundary annex where offered (25 §5.7) |
| Rules | Documentation states what the vendor can be compelled to produce (the 30 vendor-union answer set) and what it cannot (content, keys, source identity) under stated assumptions (ASM-*); no warrant-canary promises the vendor cannot keep (INC-07); statements use DECISIONS §0 language |
| Pitfalls | INC-02 (Lavabit TLS key compulsion), INC-03/INC-05 (provider disclosed IP/recovery data), INC-04 (compelled monitoring) |
| Verify | INSP against AT-031/AT-032 expected answers; legal review record |

### RM11-S6 Vendor-compromise drill and audits

| Aspect | Specification |
|---|---|
| Build | Drill: red team with full vendor privileges (Fleet, provisioning, support, hosting, monitoring) attempts to obtain content or source identity; 37 A8 of vendor infrastructure, A7 focused on provider-observer risk, A16 watcher independence, A15 if TEE offered |
| Verify | Drill answers ⊆ expected minimal answers (30 §6.3); reports published; 0 open Critical/High |

## 4. Auditor threat checklist (component-specific)

| # | Check | Threats |
|---|---|---|
| 1 | Does any intake host, sealer, store, key or network segment serve more than one customer? | THR-045, THR-027 |
| 2 | Can vendor staff gain standing or unapproved access, or access without customer-visible audit? | THR-027, THR-018 |
| 3 | Can vendor tooling capture memory, tor state, DB dumps or Desk screens? | THR-014, THR-027 |
| 4 | Are audit exports readable by the vendor? | THR-027, THR-038 |
| 5 | Can the vendor author Fleet commands or forge attestation/running manifests unnoticed by customer verifiers and watchers? | THR-025, THR-026 |
| 6 | Do provisioning or ticketing systems store onion addresses, tenant names or staff identities? | THR-027 |
| 7 | Does compulsion documentation match the drill's actual answer set? | THR-026 |

## 5. Test plan

| Test | Command / tool | Gate |
|---|---|---|
| Isolation | per-tenant ST-121; network reachability matrix between tenant hosts | RM11-S1 |
| Vendor access | ST-068 as vendor roles; JIT broker negative tests | SG-08 |
| Audit key | ST-176 | SG-29 |
| Attestation | ST-156, ST-173 | SG-29 |
| Watchers | ST-155 | SG-28 |
| Support | AT-001 over ticket store and bundles; upload-filter tests | SG-10 |
| Drill | AT-031, AT-032 vendor union; red-team report | SG-11 |
| Audits | 37 A8, A7, A16 (A15) | RM-11 exit |

## 6. OPSEC checklist

| Exposure | Control |
|---|---|
| Vendor sees per-customer traffic volume and uptime | Disclosed in vendor-union answer set; chaff (ADR-047(3)) and fixed import slots limit inference |
| Vendor hosting provider observes VMs | PRIVATE-CLOUD residuals apply; optional TEE with honest limits |
| Support tickets carry identifying data | Upload filters, allow-list bundles, ≤ 30-day retention |
| Vendor staff locations create jurisdictional exposure | Documented per customer |
| Fleet check-ins reveal instance liveness | Day-granular, via Tor |
| Billing/licensing records reveal customers | Kept separate from operational systems; no onion addresses |

## 7. Exit criteria

| Type | Criterion |
|---|---|
| Roadmap (38 RM-11) | Vendor-compromise drill shows no content or source identity available to vendor; managed-infrastructure audit complete (38 "A8" = 37 A8, plus A7 and A16 per 37 "MANAGED profile launch") |
| Spec gates | SG-08, SG-10, SG-11, SG-28, SG-29 on MANAGED profile; go-live gate item 10 enforced |
| Audit gate | Each step RM11-S1..S6 audited independently (`process/audits/AUDIT-RM11-Sn.md`); 0 open Critical/High; Medium fixed or lead-accepted in writing |
| Milestone record | Signed RM-11 report logged (RM-005) |

## 8. Requirements

| ID | Requirement | Evidence | Threats | Component | Verification |
|---|---|---|---|---|---|
| IMP-RM11-001 | Each MANAGED customer SHALL have a dedicated intake host, onion key, sealer and store, with no shared Z-INTAKE resource across customers. | ADR-021; INC-113 | THR-045, THR-027 | C-05 | TST: isolation matrix; ST-121; AUD: A8 |
| IMP-RM11-002 | Onion keys SHALL be generated on the customer's intake host and SHALL leave it only as BS-SECRETS encrypted to the customer-controlled IRK quorum. | ADR-028; INC-106 | THR-044, THR-027 | C-05 | ST-121; INSP: provisioning code |
| IMP-RM11-003 | Vendor operators SHALL have no standing access, no Desk roles and no case keys; each access SHALL be time-bounded, approved per ADR-045 and audited to the customer. | ADR-045; INC-68; INC-70 | THR-027, THR-018 | C-36 | ST-068; TST: JIT broker negative tests |
| IMP-RM11-004 | Audit exports in MANAGED SHALL be encrypted to a customer-held key. | ADR-047(10) | THR-027, THR-038 | C-24 | ST-176 |
| IMP-RM11-005 | Go-live SHALL require a customer-held attestation verifier that has verified at least one quote, with evidence refreshed at least every 24 h. | INFRA-046; ADR-047(4) | THR-014, THR-026 | C-25 | ST-173; ST-156 |
| IMP-RM11-006 | Vendor ticketing SHALL accept only encrypted allow-list support bundles, reject HAR files, screenshots and dumps, and delete bundles within 30 days. | INC-56; 32 §8 | THR-027, THR-016 | C-36 | AT-001 on ticket store; TST: upload filter |
| IMP-RM11-007 | Provisioning, Fleet and ticketing systems SHALL NOT store onion addresses, tenant channel names or staff identities. | 21 §9.2; ADR-022 | THR-027 | C-34 | TST: schema tests; AT-001 |
| IMP-RM11-008 | Jurisdiction and compulsion documentation SHALL state, per customer, what the vendor can and cannot produce, consistent with the AT-031/AT-032 drill answers. | INC-02; INC-03; INC-04 | THR-026 | C-36 | INSP: documentation vs drill report |
| IMP-RM11-009 | A vendor-compromise drill SHALL show no access to content or source identity before RM-11 exit. | 38 RM-11; 30 §6 | THR-027, THR-026 | C-10 | AT-031; AT-032; AUD: A7 |
| IMP-RM11-010 | External Watchers for MANAGED customers SHALL be independent of the vendor with ≥ 1 outside the operator's jurisdiction. | ADR-035(1) | THR-007, THR-026 | C-06 | ST-155; AUD: A16 |

## 9. Residual risks and open issues

| # | Item | Handling |
|---|---|---|
| R1 | A vendor with root on intake hosts can capture Tier W plaintext during a live compromise | ADR-004 honest statement; Tier V recommended; watchers detect non-selective divergence only |
| R2 | Vendor observes traffic volume, uptime and timing per customer | Disclosed; chaff and fixed slots reduce inference |
| R3 | TEE profile reduces but does not remove vendor/host risk | A15; honest statements |
| R4 | Legal compulsion can force the vendor to deploy modified intake code | Identical builds, floors, logs and watchers make targeted change detectable only if non-selective; disclosed |
