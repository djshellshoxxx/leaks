# DISP-G8 — Disposition of review findings for group G8

Documents: `specs/29-SECURITY-TESTING.md` (v1.1), `specs/30-ANONYMITY-TESTING.md` (v1.1), `specs/37-SECURITY-AUDIT-PLAN.md` (v1.1).
Basis: DECISIONS.md ADR-030/033 and ADR-034..ADR-046; REVIEW-A/B/C.

New IDs added (none renumbered or reused):
- **29:** ST-143..ST-167 (§14A; ST-167 is the spec-constant consistency lint with its initial registry table), SECT-031..SECT-040. The existing ST-025/034/066/069/079/082/108/110/140/141 were amended in place.
- **30:** AT-069, AT-076..AT-086 (§9A inferential, §9B revision leakage, AT-084 drill), ANT-033..ANT-038. AT-043 and AT-048 were rewritten in place and marked REVISED (same subject, ADR-038). AT-013/040/046/047/051/060/065/066 and ANT-009/016/018/020/025 were amended. Drill expected answers §6.3 were rewritten. Journeys J10–J16 and sinks S23–S25 were added.
- **37:** A15 (TEE sealer review), A16 (watcher and operator-statement programme review), A17 (directory governance and organisation-as-adversary review), SAP-038..SAP-043. A1/A7/A8/A9/A14, §4.1 triggers, §4.2 independence, §4.3 inputs and the §12 schedule were amended.

Note on AT IDs: AT-069 and AT-080..AT-083 keep the IDs that RVW-B-02/-29 proposed, because they were free and other groups may cite them. All other new AT IDs were allocated sequentially: AT-076..AT-079 and AT-084..AT-086.

| Finding | Disposition | Changes (doc §, requirement IDs) | Residual risk |
|---|---|---|---|
| RVW-A-01 | Fixed (verification and audit coverage; primary controls in 02/06/11 per ADR-035) | 29 ST-154 (operator-statement banner), ST-155 (external-watcher mismatch), ST-156 (TEE attestation verifier), SECT-035; 30 AT-024 detection signals; 37 A15, A16, SAP-038, SAP-039 | A root attacker who keeps the served assets and the reported manifest unchanged is not detected without a TEE. Watchers and canaries can be compelled. |
| RVW-A-02 | Fixed | 29 ST-143, ST-145, SECT-032; 30 AT-076, journeys J10–J12/J16, sink S23, ANT-035 | Bounded exposure of RAM during a live intake compromise (AT-024). |
| RVW-A-04 | Fixed (tests) | 29 ST-149 (rollback/freeze, independent time floor), SECT-033; 30 AT-025 answer | The freshness bound is not numeric in ADR-036(6) (cross-document request 1). |
| RVW-A-05 | Fixed (tests) | 29 ST-150 (time-lock, independent approver), SECT-033; 37 A17, SAP-040 | Collusion among independent approvers. |
| RVW-A-06 | Fixed (tests) | 29 ST-148 (follow-up sealing rule) | — |
| RVW-A-07 | Fixed | 29 ST-144 (back-navigation TST as proposed) | — |
| RVW-A-08 | Fixed (tests) | 29 ST-151 (≥ 2 witness cosignatures, tree-head pin) | CE witnesses are only recommended, so CE shows a warning instead of rejecting. |
| RVW-A-09 | Partially fixed | 30 AT-040 (WAL, ctime/btime, S3 `Last-Modified`), AT-077, AT-048 revised to fixed-schedule import, AT-021 answer, ANT-016; §13; §14 OI-1 | The intake still writes at submission time, so heap order, ctime and local LSNs remain (the ADRs did not adopt tmpfs slot writes). A slot still reveals a ≤ 6 h window by default. |
| RVW-A-10 | Fixed (tests) | 29 ST-166; 30 AT-078, AT-047, AT-020 answer | Tier W uses server-side lookup (ADR-039 residual). AT-078 verifies that this leaves no persisted trace. |
| RVW-A-12 | Fixed (tests/audit) | 29 ST-153; 37 A9 scope, SAP-043 | — |
| RVW-A-13 | Fixed (tests/audit) | 29 ST-153 (Fleet cannot hold below floor), ST-155; 37 A16 | Selective serving to one targeted circuit is detected only by sampling. |
| RVW-A-15 | Fixed | 29 ST-160 (hostile-string fuzz + corpus; new strategy `hostile-string`; `fuzz_desk_string_render`), ST-161, SECT-037, SECT-038; 37 A1 scope | Hypervisor escape. The Tier 2 platform VMs are tested only for absence of NIC, shares and clipboard. |
| RVW-A-16 | Fixed (tests/audit) | 29 ST-153 (emergency cooling 2 h, ≥ 2 organisations); 30 AT-029; 37 A9, SAP-043 | — |
| RVW-A-17 | Fixed (tests) | 29 ST-152 (Tier W shows no verification affordance it cannot deliver) | Tier W sources still cannot verify the directory themselves (ADR-036). |
| RVW-A-18 | Fixed (tests) | 29 ST-146; 30 AT-069, AT-082 | An excluded triage member sees an envelope it cannot open (see RVW-B-04). |
| RVW-A-19 | Fixed (tests) | 30 AT-043 revised (constant-schedule), ANT-018 | Staff reactions to the digest (RVW-B-31). |
| RVW-A-20 | Fixed (tests) | 29 ST-165, ST-034 | — |
| RVW-A-21 | Fixed (tests) | 29 ST-066, ST-167 registry (timers, cookie, size classes); 30 AT-046, AT-051 (values read from 11 via the registry) | The cookie name value is owned by 11. It is not restated here. |
| RVW-A-26 | Fixed (test part) | 30 AT-079 (joint uniqueness, `tier` absent, mandatory dummy IDENTITY object), AT-020 answer | Received day + channel + size bucket remain a weak link. |
| RVW-A-29 | Fixed (tests) | 29 ST-152 (weekly publication slot); 30 AT-086, sink S24 | Weekly-granular roster change dates remain public. |
| RVW-A-30 | Fixed (tests) | 29 ST-161 ("rendering — not evidence" label, converter hash recorded) | A compromised converter can still produce a false rendering. The label and the hashes support detection only. |
| RVW-B-01 | Fixed | 29 ST-147, SECT-034; 30 AT-084 (new drill), AT-021/022/023/026 answers updated as proposed, ANT-035 | A live Z-CORE attacker who also controls a member Desk can compute tags. |
| RVW-B-02 | Fixed | 29 ST-146; 30 AT-069 (as proposed) | A captured Triage Set. The accused triage member who is not ticked can read the report (reported variant of AT-069). |
| RVW-B-03 | Fixed (test part) | 30 §10.4 questionnaire item on tick visibility, ANT-038 | Content still reveals the reporting line. |
| RVW-B-04 | Partially fixed | 30 AT-082 (as proposed for non-triage members), AT-043; 29 ST-146 | The chaff proposal was not adopted by ADR-037. An excluded **triage** member can still observe an undecryptable envelope. This is documented in 30 §13 and as an Open Issue for ADR revision. |
| RVW-B-05 | Fixed | 30 AT-043 rewritten (addressee set/send times independent of channel; χ² over 1,000 submissions), ANT-018 | Staff reaction timing (RVW-B-31). |
| RVW-B-06 | Fixed (test and oracle part) | 30 AT-021/022 "upper bound" removed and replaced by slot semantics, AT-040, AT-077, AT-080 | Slot granularity is 6 h in the default profile. Live intake observation remains. |
| RVW-B-07 | Fixed (test part) | 30 AT-023 (no SIEM counters), AT-065 (references 24 §TEL, all surfaces), AT-085; 29 ST-167 spec-constant lint (proposed fix 3) | Very low-volume instances. |
| RVW-B-08 | Fixed (test part) | 30 AT-065/066 (magnitude statistics), AT-085(e) | Rich side knowledge. |
| RVW-B-09 | Fixed (test part) | 30 AT-066 (rolling, cumulative, regime switches, telemetry flips), AT-085(c) | Statutory exact counts, where the law requires them. |
| RVW-B-11 | Partially fixed | 30 AT-047 (reply-deletion exception removed), AT-081 (visit-day intersection), AT-021 honest note, §13, §14 OI-7 | ADR-038(3) still stores the follow-up import slot date server-side. AT-081 is expected to fail for the DB view under an independent-usage model (cross-document request 2). |
| RVW-B-12 | Fixed | 29 ST-143, ST-066 (single timer set); 30 AT-076 | — |
| RVW-B-13 | Fixed | 29 ST-145; 30 AT-076 (M-PASS) | Live intake compromise at login (AT-024). |
| RVW-B-14 | Fixed (30 part) | 30 §10.4 questionnaire items as proposed, ANT-038 | Comprehension varies. |
| RVW-B-17 | Fixed (30 part) | 30 SCE definition (C-37/intranet from work network), G1c persona | Organisations may ignore the guidance. |
| RVW-B-18 | Fixed (30 part) | 30 AT-013 semantic checks | Screenshots and admin-typed ticket text. |
| RVW-B-19 | Fixed (30 part) | 30 AT-032 (documented MANAGED vendor union), sink S25; 37 MANAGED launch now includes A16 | One legal order to the vendor covers many customers. Hypervisor observation of Tier W. |
| RVW-B-21 | Partially fixed | 30 AT-026 rewritten (no "union" oracle; vault ≤ 14 days; infrastructure image check); 29 ST-158, ST-159 | The metadata of disposed cases persists in BS-CORE until retention expiry, because no metadata-erasure layer is specified by the ADRs. |
| RVW-B-27 | Partially fixed | 30 §10.4 recovery target ≥ 85 % at 30 days, unsafe storage reported per method, AT-075 | The 7-word proposal was rejected: ADR-005/ADR-046(7) keep 10 words. |
| RVW-B-28 | Fixed | 30 G1b/G1c personas, Tor-failure task, unsafe-fallback metric, sample-size rule (n ≥ 59 for ≤ 5 %), AT-060, ANT-037 | Lab studies still differ from real stress. |
| RVW-B-29 | Fixed | 30 §3 principles 5–6, §9A AT-080 (timing correlation), AT-081 (visit-day intersection), AT-082 (exclusion inference), AT-083 (parameter consistency), AT-085 (small-cell/differencing on all surfaces), generated oracle ANT-034, ANT-033; 29 ST-167 (lint location: registry owned by 39); 37 A7, SAP-042 | Unknown unknowns. The tests are only as good as their adversary models. |
| RVW-B-30 | Fixed (30 part) | 30 AT-020/021 answers (16 anonymous slots, no key IDs; fail if any column holds key IDs); 29 ST-025 wording; ST-167 superseded-variant list | Relies on KEM key privacy (40). |
| RVW-B-31 | Accepted residual (documented) | 30 AT-080 staff-reaction scenario (reported, non-gating), AT-023 answer, §13 | Candor does not generate this signal. The primary fix is in 20. |
| RVW-C-01 | Fixed (tests/audit) | 29 ST-162, ST-141 objectives; 37 A17 | An organisation that controls the endpoint defeats Desk protections (ADR-043 honest residual). |
| RVW-C-02 | Fixed (tests) | 30 AT-043, AT-080 | IdP/SIEM login timing (see RVW-B-31). |
| RVW-C-03 | Fixed (tests) | 29 ST-163, ST-141 | — |
| RVW-C-04 | Fixed (tests/audit) | 29 ST-157; 37 A16 | Collusion that includes OVERSIGHT. |
| RVW-C-05 | Fixed (tests/audit) | 29 ST-150, ST-151; 37 A17, SAP-040 | Capture of the independent roles. |
| RVW-C-06 | Fixed (tests/audit) | 29 ST-159; 30 AT-026; 37 A8, SAP-043 | The check relies on an attestation that the checker cannot verify. |
| RVW-C-07 | Fixed (tests) | 29 ST-158 (vault ≥ 15 days old, DR replica, erasure log) | — |
| RVW-C-09 / C-10 / C-13 | Fixed (tests) | 29 ST-164 | — |
| RVW-C-11 | Fixed (test part, as proposed item 3) | 29 ST-110 extended to Desk and webview crash reporting, SECT-040 | Vendor products change faster than the catalogue can track. |
| RVW-C-17 | Fixed (test part) | 29 ST-153 | — |
| Other RVW-A/B/C findings | Not applicable to this group | Their AFFECTED and fix fields do not touch 29/30/37 (checked by grep over all three reviews) | — |

Counts (55 findings): Fixed 49 (the grouped C-09/C-10/C-13 row counts as 3); Partially fixed 5 (A-09, B-04, B-11, B-21, B-27); Accepted residual 1 (B-31); Rejected 0.

## Cross-document requests

1. **04 / 06:** set a numeric Key Directory snapshot freshness bound (ADR-036(6)) and an attestation freshness bound for the TEE sealer (ADR-035(3)). 29 ST-149 and ST-156 read these values from the registry.
2. **09 / 03 (RVW-B-11):** ADR-038(3) keeps the follow-up import slot date in cleartext. Consider storing follow-up dates only inside the encrypted case record, or making delayed delivery the default for follow-ups. 30 AT-081 is likely to fail for the DB view otherwise. This needs an ADR amendment if adopted.
3. **DECISIONS (RVW-B-04):** add chaff envelopes or decoy slots so that an excluded **triage** member cannot observe an undecryptable envelope. Until then, 03 must list this residual.
4. **39:** own the machine-readable constants registry `spec/constants.yaml` and the tagging convention `⟦const:NAME⟧` used by 29 ST-167 / 30 AT-083. Seed it from the table in 29 §14A.7. Also add the RVW-B-30 superseded-phrase list per ADR amendment.
5. **03:** publish the §10 disclosure inventory in machine-readable form, checked against the 09 classifications, so that drill oracles can be generated (30 ANT-034). Add these rows: follow-up import slot dates; import slot window (≤ 6 h default); excluded triage member observes an undecryptable envelope; MANAGED vendor union; metadata of disposed cases in BS-CORE until expiry; delayed-delivery release dates on intake.
6. **09:** enumerate the cleartext-field allow-list per envelope and per import row (used by 30 AT-079). Confirm that no stored reply↔account mapping exists for fetch-all (30 AT-020).
7. **11:** confirm the canonical session-cookie name, since 03/07/08 use `__Host-cs` (RVW-A-21), and the page size classes (§5.4), for the registry.
8. **24 §TEL:** provide an enumerated catalogue of every aggregate surface (dashboards, admin, SOC, SYSTEM streams, telemetry, Fleet, support bundles, published statistics) for 30 AT-065/AT-085.
9. **27:** add ST-143..ST-167 and the new AT gates to the release gate mapping (SG-07/10/11/22/24). Add ST-167 to the PR pipeline for `specs/` changes.
10. **38:** add A15/A16/A17 to milestone exit checklists (37 §12). A16 must precede EE/GOV/MANAGED GA.
11. **40:** record the assumptions on which A15/A16/A17 depend: TEE side-channel limits; watcher independence and non-compulsion; honesty of independent approvers.
12. **32:** confirm the support-bundle rules (hour truncation, no `sys.relay_*`, config as `{key, class, value_hash}`) that 30 AT-013 now checks. Confirm the CFG entries for the backup-exclusion attestation (29 ST-159).
