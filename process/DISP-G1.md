# DISP-G1 — Disposition of review findings for group G1

Group G1 documents: `specs/01-PRODUCT-REQUIREMENTS.md` (v1.1), `specs/02-THREAT-MODEL.md` (v1.1), `specs/03-PRIVACY-ANONYMITY.md` (v1.1), `specs/40-SECURITY-ASSUMPTIONS.md` (v1.1).
Inputs: DECISIONS.md ADR-030/033 and ADR-034..046; REVIEW-A (30 findings), REVIEW-B (33), REVIEW-C (24).

Scope rule. Every finding is listed, because duty (a) required every review threat to be reflected in 02 (THR-126..THR-142, ADV-31/32, re-rated THR rows). "Fixed" and "Partially fixed" refer to **the G1 part** of the finding; changes needed in documents owned by other groups are in "Cross-document requests". Where a reviewer fix conflicts with an ADR, the ADR was applied and the difference is noted.

Abbreviations: r2 = revision round 2; "02 THR-nnn re-rated" = mitigation and residual cells re-derived under 02 §3.1 (ADR-035(6): credit only specified controls).

## Special duties (summary)

| Duty | Where done |
|---|---|
| (a) Re-derive 02 ratings crediting only specified controls; new threats THR-126+; organisation-as-adversary / managed-endpoint threats | 02 §3.1 rating rule; ASM mapping in §3; ADV-04/06/07/10/12/18/20/26 amended; new ADV-31 (organisation as operator-adversary), ADV-32 (enterprise infrastructure administrator); THR-007, -011, -012, -013, -014, -017, -018, -019, -020, -023..-028, -030, -033, -034, -037, -041, -046, -047, -102..-104, -107..-110, -113, -116..-118, -121, -123 re-derived; new §9.3 THR-126..THR-142; trees, abuse cases ABUSE-17..22, §12 rows, TM-013 withdrawn, TM-014..TM-019, R-12..R-16, OI updates |
| (b) Correct 03 metadata inventory and §10 compulsion tables | 03 §5 matrix (3 new rows, notes 4/10/14/15/17 rewritten, notes 20–26), §8.2a R-00, R-02..R-11 notes, §8.3 Tier V deltas, §8.4, new normative §8.6 (32 items), §9 (8 new rows), §10.1 rewritten (15 rows new/changed, marked r2), §10.2 (3 new rows), §10.3 rewritten for MANAGED incl. live capabilities, §10.4 (4 new rows, 2 corrected) |
| (c) 40 assumptions: KEM key-privacy, TEE, watchers/witness independence, independent-custody devices, infra-backup exclusion of the vault | 40 ASM-049 (KEM key privacy incl. FIPS hybrid), ASM-050 (External Watchers), ASM-051 (directory witnesses), ASM-052 (TEE, optional), ASM-053 (independent-custody devices), ASM-054 (infra-backup exclusion of vault), plus ASM-055..061; P-31..P-34; K-14..K-19; ASM-125..ASM-137; amended ASM-010/013/019/022/027/033/036/041/043/046/047, ASM-110/116/122; ASM-120 withdrawn |
| (d) PRD amendment per ADR-034 | 01 §7.1 Credential, §7.8, J-01, PRD-018, PRD-053 (text "never stored server-side" → "never persisted to disk"), PRD-079; §10 prohibited-claim rows |

## Disposition table

| Finding | Disposition | Changes (doc §, requirement IDs) | Residual risk |
|---|---|---|---|
| RVW-A-01 | Fixed | 02 §3.1 (withdraws "sealer attestation to Desk", "published source-UI digests", "warrant canary" credits), ADV-04/18/20/26, THR-007/014/026 re-rated, §12 C-05/C-06/C-07, OI-03 resolved; 03 §5 note 4, §10.2, §10.4 "Capture Tier W" row, ANON-022, ANON-025; 40 ASM-013, ASM-050, ASM-052, ASM-056, ASM-116 amended, ASM-126/128/132; 01 PRD-009, PRD-087 | A selector-targeted or memory-only Tier W modification is undetectable by any specified control; TEE optional and not credited (ADR-035). Reviewer's mandatory TEE for HIGH/GOV/MANAGED not adopted (ADR-035(3) makes it optional). |
| RVW-A-02 | Fixed | 03 R-02 header, note ⁸, §8.6 draft rows, META-014; 01 §7.8, PRD-053, PRD-079; 02 THR-014, THR-134 | Drafts lost on sealer restart/2 h (01 RR-11). 06/07/09/11 text owned elsewhere. |
| RVW-A-03 | Partially fixed | 03 §5 note 4, §10.2 new row, ANON-022; 02 THR-014, THR-121, THR-135, §12 C-06 recovery (INCIDENT_NOTICE, rotation); 40 ASM-010, ASM-013; 01 PRD-018 (rotation, ADR-046(7)) | Reply-retention minimisation and "COI prefs only on opt-in" not decided by ADR (cross-doc 04/09/11). A live capture still exposes all stored replies. |
| RVW-A-04 | Fixed | 02 THR-102 (withdrew "14-day freshness"), new THR-132, TB-06, §7.3 T, §7.12 S, TREE-7 7.2b; 40 ASM-041, ASM-055, K-17, ASM-131 | Tor-consensus manipulation requires directory-authority control. VR-5/VR-9 changes owned by 04. |
| RVW-A-05 | Fixed | 02 THR-131, THR-046, ABUSE-02, §7.7 E, TREE-7; 01 §7.4 roster governance, PRD-038; 40 ASM-033, ASM-058 | Collusion of independent approver + Triage Set; ADR-036 time lock is 72 h/7 d (reviewer proposed 7 d default; ADR wins). |
| RVW-A-06 | Fixed | 02 THR-131, THR-046; 01 §7.4 (follow-up sealing rule) | Reviewer's source opt-in to new members replaced by ADR-036(4) (later members only via Triage Set case-key wrap). |
| RVW-A-07 | Fixed | 01 PRD-079; 03 §8.6; 02 THR-131, THR-014 | None beyond A-02. |
| RVW-A-08 | Fixed | 02 THR-102, THR-118, TM-010; 03 §8.3 R-10 and Dev rows, ANON-019 amended; 40 ASM-051, ASM-110 amended, ASM-127 | CE without external witnesses (residual in THR-102/118); persistent pin is device residue (02 OI-08, 03 PR-13/OI-10). "App embeds tenant checkpoint" claim owned by 04/33. |
| RVW-A-09 | Partially fixed | 02 TM-013 withdrawn, TM-015, THR-011/034, LINDDUN, OI-04; 03 §5 note 17, R-02 notes ¹²/¹³, META-005, META-028, §8.6, §10.1 exact-time row | Slot-level timing; C-08 page/WAL residue until relay (03 PR-09) — reviewer's intake tmpfs commit staging not adopted by ADR-038/046(1). |
| RVW-A-10 | Partially fixed | 02 THR-135, ABUSE-22; 03 §5 row "times a mailbox is checked", note 26, §10.2, §10.4, META-007, META-031; 01 PRD-026, PRD-086 | Tier W return-visit logging remains (ADR-039 documented residual); Intake Routing Key TEE/split not adopted. |
| RVW-A-11 | Accepted residual (documented) | 02 THR-136, R-16, TREE-2 2.1.7; 03 §10.2 row, PR-15, ANON-022 | Until Tor ships PQ onion handshakes (ADR-046(8)). |
| RVW-A-12 | Fixed | 02 THR-024, THR-137; 03 META-022; 40 ASM-059, ASM-134 | Upstream-at-source backdoor logged, not detected. |
| RVW-A-13 | Partially fixed | 02 THR-137, THR-113; 03 §10.4 row; 40 ASM-050, ASM-126, ASM-134 | SERVER_STATE entry not adopted beyond the signed running manifest; root operator can forge local reports. |
| RVW-A-14 | Fixed | 03 §8.2a R-00, ANON-024, §11 item 7; 02 THR-138, DF-26; 01 PRD-082; 40 ASM-060, ASM-135 | iOS App-Store-only (01 RR-09). |
| RVW-A-15 | Fixed (G1 part) | 02 THR-023 (ADR-042 tiers, plain-text strings), §7.5 E | Hypervisor escape. Implementation 10/12. |
| RVW-A-16 | Fixed (G1 part) | 02 THR-025, THR-137, ADV-20; 40 "ADR-022" open issue resolved by ADR-040 | Cross-jurisdiction coercion; REL-007 vs SCM-042 owned by 28/33. |
| RVW-A-17 | Fixed | 03 §7 row, ANON-023, §8.3 R-10; 02 THR-046 residual | As A-01. |
| RVW-A-18 | Partially fixed | 02 THR-110 re-rated ("until import"), LINDDUN; 03 §5 notes 15/23/24, PR-14 | Chaff envelopes not adopted (ADR-037 chose triage-first); excluded Triage Set member still sees an unopenable envelope. |
| RVW-A-19 | Fixed | 02 THR-028, TB-19, DF-18, §12 C-23/mail rows; 03 META-017, §9; 40 ASM-046; 01 PRD-081 | Subscriber list visible; staff reactions (THR-129). |
| RVW-A-20 | Fixed | 02 THR-033, §7.3 D; 03 PRIV-013; 01 §7.6, PRD-047 | Reviewer's NOT_MINE mechanism replaced by ADR-038(6) 14-day dual-approved rejection. |
| RVW-A-21 | Fixed (G1 part) | 03 ANON-004, META-008 (defer to 11), OI-04; 01 §8, PRD-056 | Request-sequence fingerprinting. Single size class decision owned by 11. |
| RVW-A-22 | Partially fixed | 03 R-02 note ³, META-038, PR-03; 02 §7.3 I | Wire-level unpadded Tier W upload volume/time remains; cover traffic not adopted. |
| RVW-A-23 | Fixed (G1 part) | 03 §10.1 tor-log row (≤ 24 h), META-024 (no CDN), META-022 (egress matrix owner 16); 02 ADV-12, THR-104 | Egress matrix itself owned by 16/17. |
| RVW-A-24 | Partially fixed | 02 THR-126, THR-108, THR-109, ADV-32, OI-09; 40 ASM-053, ASM-129; 01 PRD-083, OI-07 | ADR-043 covers INDEPENDENT channels only; org-managed endpoints elsewhere rated 4×5 residual. |
| RVW-A-25 | Partially fixed | 02 THR-107 re-rated (ORIGINAL export 3×4), not credited until specified | Owned by 10/12. |
| RVW-A-26 | Fixed | 03 §8.6 (tier removed, header digest ≤ 24 h, quota current-day, no own-message history), META-007, META-027, META-031, DM-12; 01 PRD-015, PRD-023; 02 THR-134 | Received day + channel + size buckets; IDENTITY-object normativity owned by 04/06. |
| RVW-A-27 | Fixed | 02 THR-140; 03 §8.6, META-018, R-04 note ¹ | Tor PoW effort public. |
| RVW-A-28 | Fixed (G1 part) | 03 META-016, R-07 note ², §8.6 tombstones; 01 PRD-028; 02 THR-017, THR-130 | Tombstones reveal that a deletion occurred. Implementation 19. |
| RVW-A-29 | Fixed | 03 META-034, §8.6; 02 LINDDUN; ADR-036(7) | Weekly epoch structure visible. |
| RVW-A-30 | Fixed (G1 part) | 02 THR-037 (ADR-042 labelling, converter digest) | Dual-render check not adopted; common-mode renderer bug. |
| RVW-B-01 | Fixed | 03 §8.6, §10.1 COI row, META-030, §5 row + note 24; 02 THR-133, TREE-1 1.4.6; 01 PRD-036 | Live Z-CORE + member Desk can compute tags. 09/14/20 implementation. |
| RVW-B-02 | Fixed | 01 §7.4 triage-first, J-06, PRD-036, PRD-085; 02 THR-020, THR-110; 03 §5 note 10 | Captured Triage Set (ASM-057). |
| RVW-B-03 | Partially fixed | 03 §7 COI checklist rows, ANON-021; 02 THR-142 | Template and SCIM `manager` changes owned by 14/15; content often reveals team. |
| RVW-B-04 | Partially fixed | 03 §12.1 M1, §12.2 rule 8, §9 row, note 15/23; 02 THR-110, LINDDUN; 01 PRD-085 | Chaff not adopted; excluded Triage Set member; workload side channel. |
| RVW-B-05 | Fixed | As A-19; 03 §8.6 notification row | Addressee set = who holds Candor roles. |
| RVW-B-06 | Partially fixed | 03 DM-11, META-029, §10.1 exact-time row, §5 note 17; 01 §10 prohibited claim ("only the date"); 02 THR-011, THR-134 | Slot-level timing; 20/32/05 implementation (GC-01/GC-34 text). |
| RVW-B-07 | Fixed | 03 §12 rewritten (single regime `24` §TEL per ADR-046(5); M4 = global daily health band), META-018, PRIV-004 | Reviewer asked 03 to be the single source; ADR-046(5) names 24 §TEL — ADR wins. 09/13/20/30 restatements. |
| RVW-B-08 | Fixed | 03 §12.2 magnitude rule, PRIV-017, PRIV-004; 01 §11 rule, SM-01/04/13 | Reviewer's M2 quarterly/k≥20 public replaced by ADR-046(5) k = 10, ≥ 1 month. |
| RVW-B-09 | Fixed | 03 §12.2 rules 4–6, §12.3, OI-08 (noise research) | `new_cases_bucket` telemetry owned by 24. |
| RVW-B-10 | Partially fixed | 03 §12.1 M2 dims, PRIV-021; 02 THR-142 | `routing_visible` (21) and `category_class` (14) owned elsewhere; channel choice visible to DB. |
| RVW-B-11 | Partially fixed | 03 §5 row + note 25, R-06 note, §8.6, META-006, META-027, ANON-030, OI-09, PR-04; 02 THR-134; 01 PRD-080, RR-12 | ADR-038(3) keeps one import-slot date per follow-up (reviewer's "dates only inside encrypted record" not adopted — ADR wins); `activity_day` month and 35 "read/login" wording owned by 09/35. |
| RVW-B-12 | Fixed | 01 §7.8, PRD-053, PRD-079; 03 R-02, META-014, §8.6 | Reviewer's tmpfs/UNLOGGED cookie-keyed drafts replaced by ADR-034 RAM-only drafts. |
| RVW-B-13 | Fixed | 03 R-02 note ⁸, §10.1 passphrase row, META-032; 01 §7.1, PRD-018 | ADR-034: 3 random words (reviewer proposed words #3/#8). Live C-07 compromise. |
| RVW-B-14 | Fixed (G1 part) | 03 §7 (banner single-sourced, tier line, confidential copy, who-can-unlock), ANON-026/027/028, PRIV-008 (12-month deferral cap); 01 §10 claims | (e) IDENTIFIED-via-onion not resolved by any ADR (cross-doc); 05/11 copy. |
| RVW-B-15 | Fixed | 03 §6 rules + state diagram, ANON-010 | Members remember what they read. |
| RVW-B-16 | Fixed | 03 §7 tier line, ANON-024; 02 THR-138; 01 PRD-082 | iOS residual. |
| RVW-B-17 | Fixed | 03 §11 item 6, ANON-029, §8.2a; 02 THR-138 | Organisations may ignore advice. |
| RVW-B-18 | Fixed (G1 part) | 03 §10.3 bundle retention ≤ 30 d, META-037; 02 THR-027 | Admin-typed ticket text. 32 implementation. |
| RVW-B-19 | Fixed | 03 §10.3 rewritten (all §10.1 data + live capabilities), §5 vendor column, notes 20, PRIV-012, PRIV-019, PR-08; 02 THR-141, ADV-26 | Customer-held audit/backup keys not adopted (no ADR); hypervisor-level Tier W observation. |
| RVW-B-20 | Fixed (G1 part) | 03 §10.1 Fleet row (no onion hash), PRIV-007 (no Z-INTAKE crash counts); 02 ABUSE-14, THR-027 | Fleet transport over Tor owned by 21. |
| RVW-B-21 | Partially fixed | 03 §8.4 backups paragraph, §10.1 Backups/vault rows, META-016, PR-12; 01 §7.6 (layered EK wording), PRD-046; 02 THR-017, THR-130 | Metadata erasure layer not adopted; metadata in backups until expiry; 35 D-15 conflict (cross-doc). |
| RVW-B-22 | Accepted residual (documented) | 03 META-016 keeps BS-INTAKE (14 d) with tombstones; §10.1 account-record row | No ADR removes BS-INTAKE; reviewer's re-provisioning design is for 19/ADR. |
| RVW-B-23 | Partially fixed | 02 THR-142, THR-019 re-rated to 3×5, TREE-1 1.4.7; triage-first (01 PRD-085) | Originals custody and intermediary mode owned by 10/14; content knowledge. |
| RVW-B-24 | Not applicable to this group | — (05/11; THR-010 unchanged) | Semantic canaries. |
| RVW-B-25 | Partially fixed | 03 META-030 (register/CASE reads apply blinded set); 02 THR-133 | 14/20 implementation; captured oversight. |
| RVW-B-26 | Fixed | 03 META-033, R-07 note ³, §8.6, §10.1 mailbox-closed row; 01 PRD-028 | Delayed oversight signal. |
| RVW-B-27 | Rejected (with reason) | 03 R-04 note ⁴ records ADR-046(7) | ADR-046(7) keeps ≈129-bit (10-word) passphrases with m=64 MiB; lost-passphrase guidance owned by 05. |
| RVW-B-28 | Partially fixed | 03 §11 item 8 | Study design owned by 30; lab vs real stress. |
| RVW-B-29 | Partially fixed | 03 PRIV-018, ANON-027; 02 TM-019 | New tests owned by 30/39. |
| RVW-B-30 | Fixed (G1 part) | 03 §8.6 recipient key IDs row; 40 ASM-049, ASM-125, K-19 | Relies on KEM key privacy; 12/14/30 errata. |
| RVW-B-31 | Partially fixed | 03 DM-13, META-035, §9 row, PR-10; 02 THR-129, §7.8 I; 40 ASM-061 | 20 §13 export granularity; network observation of Desk connections. |
| RVW-B-32 | Partially fixed | 03 META-034 (weekly slot, day dates) | Names for ANONYMOUS channels and retired-label genericisation owned by 14/35. |
| RVW-B-33 | Partially fixed | (a) 03 §7 ISO week; (d) timers per ADR-034; (e) 03 §8.6 header digest | (b) 14, (c) 21/35, (f) 12 — cross-doc. |
| RVW-C-01 | Fixed (G1 part) | 02 ADV-31, ADV-32, THR-126, TREE-2 2.3.6, TREE-4 4.4.3, ABUSE-19, §12 C-16 + new endpoint-management row, TM-017, R-12; 40 ASM-019, ASM-043 (no longer server-only), ASM-053, ASM-129, K-18; 01 PRD-083, RR-10 | Org-managed endpoints outside INDEPENDENT channels; server/peer-verified Desk attestation not adopted (ADR-043: non-authoritative self-report). |
| RVW-C-02 | Partially fixed | 02 THR-129, TB-21, ADV-07; 03 META-017, META-035, §9; 40 ASM-061; 01 PRD-081 | IdP/network logs outside Candor; 20/33/12 changes. |
| RVW-C-03 | Fixed (G1 part) | 02 THR-128, §7.4 T, §7.5 D, TREE-3 3.4.4, ABUSE-18; 40 ASM-022, ASM-122; 01 §7.6 key continuity, PRD-084 | Physical destruction of all devices; 14/15/32/35 implementation. |
| RVW-C-04 | Fixed (G1 part) | 02 THR-127, ABUSE-17, DF-25; 03 PRIV-020, §10.1 IR row, §10.4; 40 ASM-133; 01 PRD-087 | Collusion incl. independent approver; 31 implementation. |
| RVW-C-05 | Fixed (G1 part) | 02 THR-131; 01 PRD-038; 40 ASM-033, ASM-058 | Captured independent body; K01 share distribution (04). |
| RVW-C-06 | Fixed | 02 THR-130, ABUSE-20, §7.9, §7.12; 03 META-036, §10.1 vault/backups rows; 40 ASM-054, ASM-130, K-16; 01 §7.6, PRD-046, RR-14 | Attestation only as honest as the virtualization team. |
| RVW-C-07 | Partially fixed | 02 THR-130, THR-117, §12 vault row; 40 ASM-022 | Desk case-key caching/re-wrap and ransomware-dwell restore owned by 04/19. |
| RVW-C-08 | Fixed (G1 part) | 03 §10.1 vault location wording (vault volume, no DB schema), intake no replication (ADR-046(1)) in R-02 note ¹²; 02 THR-025 (update paths ADR-046(3)) | HA/HSM/RUI-055 items owned by 21/34/12. |
| RVW-C-09 | Partially fixed | 02 THR-139; 40 ASM-058; 01 PRD-088; 03 §7 config digest ("reduced separation of duties"), ANON-031 | `person_ref` binding and installer second admin owned by 15/18. |
| RVW-C-10 | Fixed (G1 part) | 02 THR-139, THR-116, ABUSE-16, ABUSE-21; 01 PRD-088; 03 §7 config digest (legal-hold disclosure) | Lawful court orders; 15/35/21 implementation. |
| RVW-C-11 | Partially fixed | 02 THR-126, THR-041 | Crash-reporting and sync-root controls owned by 12/21. |
| RVW-C-12 | Not applicable to this group | 02 ADV-32 notes guest-invisible knobs | Owned by 17/32/25. |
| RVW-C-13 | Fixed (G1 part) | 02 THR-113, THR-137, §7.11 T, §12 C-34; 03 §10.4 Fleet row | Vendor compulsion to withhold updates bounded by security floor; 21/33 implementation. |
| RVW-C-14 | Fixed (G1 part) | 03 PRIV-022, §8.6; 01 §7.3 search, PRD-084 | Reviewer's federated search protocol replaced by ADR-044(5) Desk-local search + Records Custodian grants; every escrow is compellable. |
| RVW-C-15 | Fixed (G1 part) | 40 ASM-049 (FIPS MLKEM1024-P384 key privacy), ASM-125, K-19 | Remainder (Tier W FIPS default, RCP-ONION, SSP annex) owned by 22/25/15. |
| RVW-C-16 | Not applicable to this group | — | Owned by 10/12/15/26 (ADR-042 OCR layer). |
| RVW-C-17 | Not applicable to this group | — | Owned by 17/18/23 (ADR-040 secure boot). |
| RVW-C-18 | Partially fixed | 02 THR-128 (COI exhaustion, runway); 01 §7.4 fail-closed redirect (ADR-037(1)) | Intake RPO owned by 19. |
| RVW-C-19 | Not applicable to this group | 02 THR-128 residual notes custodian dispersion owned by 19 | Owned by 19/21. |
| RVW-C-20 | Partially fixed | 03 §11 item 6, ANON-029, §10.1 C-37 row; 02 THR-129, THR-138, OI-03 | INFRA-025/DEP-032/NET-025 owned by 16/17/18. |
| RVW-C-21 | Fixed (G1 part) | 03 §10.3 live capabilities, PRIV-019; 02 THR-141 | Customer-held verifier/witness owned by 18/21; hardware-level compelled capture. |
| RVW-C-22 | Partially fixed | 02 ADV-31, ABUSE-17..21, THR-139 | Playbooks PB-15..19 owned by 31. |
| RVW-C-23 | Partially fixed | 02 THR-139 (TRC self-assessment listed, not credited) | TEN-005 owned by 21. |
| RVW-C-24 | Not applicable to this group | — | Owned by 24/21. |

**Counts by disposition (87 findings):** Fixed 29 · Fixed (G1 part) 20 · Partially fixed 29 · Accepted residual (documented) 2 · Rejected (with reason) 1 · Not applicable to this group 6.

## Open Issues for ADR revision (status)

| Doc | Item | Status |
|---|---|---|
| 02 | OI-01 ASM mapping | Resolved (02 §3). |
| 02 | OI-02 TM- prefix | Still open (unchanged). |
| 02 | OI-03 sealer attestation | Resolved by ADR-035 (staff transport still open). |
| 02 | OI-04 import timing | Resolved by ADR-038(1). |
| 02 | OI-06 confidential VMs | Resolved by ADR-035(3). |
| 40 | ADR-022 signer distribution / witnesses | Resolved by ADR-040 and ADR-036(5). |
| 40 | ADR-005/006 Argon2 memory | Resolved by ADR-046(7). |
| 40 | ADR-009 CE-SINGLE | Partially resolved by ADR-046(6). |
| 02/03/40 | **New:** ADR-036(5) persistent Source App pin vs device residue | Open (02 OI-08, 03 OI-10, 40 §11 item 8). |
| 03 | **New:** follow-up slot dates (ADR-038(3)) remain an intersection risk | Open (03 OI-09). |

## Cross-document requests

1. **04-CRYPTOGRAPHY** — (a) key-privacy analysis of X-Wing and MLKEM1024-P384 combiner for slots, or pure ML-KEM-1024 slots in FIPS (40 ASM-049/125); (b) remove "Source App embeds tenant checkpoint" (VR-3) and align freshness bounds with ADR-036(5)/(6) (RVW-A-08, A-04); (c) derived-key residency for Tier W sessions consistent with ADR-034 (03 R-03 note ³ defers to 04); (d) make "exactly one IDENTITY object per initial envelope" normative for both tiers (RVW-A-26); (e) K01 share distribution so no management-only coalition reaches k (RVW-C-05); (f) Desk case-key caching and re-wrap-from-Desk procedure (RVW-C-07).
2. **05-SOURCE-OPSEC / 11-FRONTEND-SOURCE** — adopt 03 §7 strings verbatim (ANON-022/023/025/026/027/028/031), COI checklist text (ADR-037(4) + own-manager sentence), platform-neutral tier line, delayed-delivery option (ANON-030), acquisition guidance (ANON-024), offline onion publication (ANON-029); correct GC-01/GC-34 "only the date, not the time" (RVW-B-06); remove T_SAVED_CRED/SUI-028 re-display and 24 h drafts (ADR-034); single CSP/cookie/size classes (11 canonical); resolve IDENTIFIED-via-onion (RVW-B-14(e)) — needs an ADR.
3. **08-API** — remove size-class/CSP/static-route definitions superseded by 11 (RVW-A-21); `CTR:` counters exported only as daily health band; no per-mailbox reply route for Tier V (META-031).
4. **09-DATABASE** — blinded COI tags (drop `coi_exclusion.user_id`, `source` enum); remove `tier`, quota history, own-message history; header digest ≤ 24 h; `v_case_counts` removal; `activity_day` coarsening (RVW-B-11 item 3); import slot = commit/blob time; publish SS/WF column classification for 03 PRIV-018 generation.
5. **12-FRONTEND-RECIPIENT** — Desk crash reporting off, export outside sync roots (RVW-C-11); prompting-pattern interlock (RVW-A-10 item 4); "How many people know" only to Triage Set (RVW-B-33(f)); RUI-055/R02 no cleartext key IDs (RVW-B-30).
6. **14-CASE-MANAGEMENT** — Triage Set routing, remove "Source's direct manager" relational option, register/CASE reads apply blinded exclusions (RVW-B-25), `last_staff_activity_day` (RVW-B-33(b)), originals custody / intermediary mode (RVW-B-23), `category_class` for ANONYMOUS (RVW-B-10), fixed report catalog references to 24 §TEL; personal names not published for ANONYMOUS channels (RVW-B-32).
7. **15-AUTHENTICATION-AUTHORIZATION** — `person_ref` bound to authenticator attestation, second admin before go-live (RVW-C-09); SCIM `manager` optional/off for ANONYMOUS channels (RVW-B-03); suspend-only semantics (ADR-044(1)); break-glass independent approver (ADR-045).
8. **16-TOR-I2P / 17-INFRASTRUCTURE** — single normative H-INTAKE egress matrix; tor log retention ≤ 24 h; no C-37 CDN (RVW-A-23); intake time floor Tor consensus + Roughtime (ADR-036(6)); INFRA-025 uplink independence for D1/D2 (RVW-C-20).
9. **19-BACKUPS-DR** — intake deletion tombstones applied on restore (RVW-A-28, 03 META-016); vault DR replication and erasure log (ADR-044(4)); custodian dispersion (RVW-C-19); state that core backups hold metadata of disposed cases until expiry.
10. **20-LOGGING-AUDITING** — no COI-specific reason codes (ADR-037(3)); date-only `ts` for source-triggered CASE/SYSTEM events, remove `batch_count_bucket` (RVW-B-06, 03 META-029); SIEM staff-auth export at ≤ hour precision batched daily in HIGH/GOV (03 META-035; RVW-B-31/C-02).
11. **21-ENTERPRISE** — Fleet transport over Tor or customer-hosted (RVW-B-20); ENT-007 `routing_visible` restriction (03 PRIV-021); TEN-005 signed by tenant OVERSIGHT (RVW-C-23); MANAGED customer-held verifier/witness (RVW-C-21).
12. **24-LICENSING-BUSINESS-MODEL §TEL** — align TEL-010/011 with ADR-046(5) (k = 10; current text says k = 20 lowerable to 5); add magnitude rule and channel minimum (< 3 cases/month); tumbling periods and yearly regime evaluation (03 §12.2); drop or yearly-only `new_cases_bucket` (RVW-B-09).
13. **30-ANONYMITY-TESTING / 39-REQUIREMENTS-TRACEABILITY** — tests for 02 TM-015/018/019 and 03 PRIV-018/ANON-027; spec-constant lint; drill oracles generated from 03 §10; THR-126..THR-142 in traceability.
14. **31-INCIDENT-RESPONSE** — IR capture per ADR-035(4) (03 PRIV-020, 40 ASM-133); playbooks for organisation-as-adversary, SCIM compromise, mass key loss, rogue roster, MDM tampering (RVW-C-22).
15. **32-OPERATIONS** — support-bundle rules (03 META-037); vendor bundle retention ≤ 30 d (RVW-B-18).
16. **35-DATA-RETENTION-DELETION** — reconcile "intake backups: none" and D-15 12-month core sets with 19/03 (RVW-B-21); remove "read"/"login"-based retention (RVW-B-11 item 4); conditional deletion statement (ADR-044(4)); tenant-wide holds not blocking source deletion unless named (RVW-C-10).
17. **DECISIONS.md** — consider amendments: (a) ADR-036(5) pin stored only in opt-in encrypted state (02 OI-08); (b) follow-up dates only inside encrypted case record (03 OI-09); (c) resolve IDENTIFIED via onion (RVW-B-14(e)); (d) ADR-033(3) wording "member-key wraps stored encrypted under the Erasure Key; no direct wrap" (RVW-B-21(c)) — 01 §7.6 already uses the layered wording.
