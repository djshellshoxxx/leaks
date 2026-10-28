# DISP-G5 — Disposition of review findings for group G5

Documents: `specs/14-CASE-MANAGEMENT.md`, `specs/15-AUTHENTICATION-AUTHORIZATION.md`, `specs/20-LOGGING-AUDITING.md`, `specs/24-LICENSING-BUSINESS-MODEL.md`, `specs/35-DATA-RETENTION-DELETION.md` (all now Draft v1.1).

Binding inputs applied: ADR-030, 031, 033, 034–046. Where a reviewer fix conflicted with an ADR, the ADR was followed; the difference is noted in the table.

No existing requirement ID was renumbered or reused. Withdrawn: TEL-007. Amended in place (marked "(amended ADR-0xx / RVW-…)"): CASE-005, 009, 012, 017, 018, 020, 021, 026, 028; ROUTE-001, 002, 003, 006, 007, 008, 012, 013, 014; AUTH-004, 006, 008, 012, 015, 019; AUTHZ-010, 023; LOG-003, 007, 011, 013, 016, 019; AUD-003, 006, 010, 011; BIZ-001, 007; TEL-009, 010, 011; RET-003, 004, 009, 012, 013; DEL-002, 003, 005, 006, 008, 012, 013.

New IDs:
- 14: CASE-030..039 and ROUTE-015..022.
- 15: AUTH-021..022 and AUTHZ-024..030.
- 20: LOG-020..023 and AUD-016.
- 24: BIZ-013..014 and TEL-015..021.
- 35: RET-015..016 and DEL-018..024.

## Findings

| Finding | Disposition | Changes (doc §, requirement IDs) | Residual risk |
|---|---|---|---|
| RVW-A-01 | Partially fixed | 24: BIZ-013 (in MANAGED, the vendor publishes the ADR-035(2) operator statement and a per-jurisdiction transparency report). The rest of the finding belongs to 02/03/06/11/32. | Canary statements are a signal, not a guarantee (ADR-035(2)). |
| RVW-A-05 | Fixed | 14 §8.1, §8.8; ROUTE-008 (amended), ROUTE-015, ROUTE-019. 15 DC-08; AUTHZ-025. The CIK is held only by the Triage Set and OVERSIGHT. The reviewer asked for a 7-day time lock; ADR-036(2) sets 72 h (7 days in GOV/HIGH), and the ADR wins. | Collusion between an independent-role approver and the Triage Set. The change is still visible in the time-locked log. |
| RVW-A-06 | Fixed | 14 §8.6; ROUTE-018 (follow-up sealing rule, ADR-036(4)). | If all original ETS members leave, follow-ups fail closed. The source sees the copy stated in §8.6. |
| RVW-A-09 | Partially fixed | 14 §3 (`import_slot_date`, no batch time); CASE-032. 20 §4; LOG-013; LOG-021. 35 D-04, §7 B7. | Slot-level timing remains. WAL and blob-metadata normalization is owned by 09/19 (cross-document request). |
| RVW-A-18 | Partially fixed | 14 §8.1, §8.4; ROUTE-015, ROUTE-016, ROUTE-017. 20 P-16; LOG-020. Non-triage members never trial-decrypt envelopes. Chaff envelopes were not adopted by ADR-037/038 (OI-14-5). | After triage, the case ACL still hints at exclusions (14 §16 item 1). Triage Set members still see envelopes they cannot open. |
| RVW-A-19 | Fixed | 14 §6.5; CASE-009 (constant-schedule digest, or pull-only; ADR-038(2)). | Staff logging in after the digest is visible to corporate IT (15 §8 item 11). |
| RVW-A-20 | Fixed | 14 §4.2, §9.4; CASE-020 (amended); CASE-018 (C1 rate limit). 35 D-01, D-05. ADR-038(6) (14 days + dual-approved rejection) replaces the reviewer's NOT_MINE protocol. | A 14-day forward-secrecy tail per epoch for undecryptable envelopes. |
| RVW-A-23 | Partially fixed | 20 §6.2, §11.3, §12; LOG-007; AUD-011 (Z-INTAKE logs ≤ 24 h, aligned with 16 NET-008). 35 D-20. The egress matrix and the C-37 CDN rule belong to 16/17/03. | Root compromise of the intake can alter logging. |
| RVW-A-24 | Fixed | 15 §5.11; AUTH-021; DC-16; OI-15-2 (ADR-043 independent custody). 14 §7 item 6. | Custody is attested, not proven (15 §8 item 8). |
| RVW-A-27 | Partially fixed | 24 §9.4: health bands are daily and global, with thresholds at ≥ 10× peak; TEL-018. The limits themselves are set in 04/08/16. | The Tor PoW effort is public. |
| RVW-A-28 | Fixed | 35 D-26, §7 B6, §9, §11; DEL-022 (intake deletion list applied on restore; re-push skips listed items). | The hashes show that a deletion happened, not whose. |
| RVW-A-29 | Fixed (14 portion) | 14 §8.1; ROUTE-014, ROUTE-020 (weekly publication slot, day-only dates). Checkpoint cadence stays in 04. | The weekly epoch structure is visible. |
| RVW-B-01 | Fixed | 14 §3, §8.4; CASE-012; ROUTE-017 (8 blinded tags, blind check, Desk verification). 20 §5.1 (no `COI_EXCLUDED`), §5.2 (`REMOVED` only, no excluded count); P-16; LOG-020. 15 §5.4; AUTHZ-023. | Case members know who is concerned. A live Z-CORE attacker who also holds a member Desk can compute tags. |
| RVW-B-02 | Fixed | 14 §8 (triage-first); ROUTE-001 (amended); ROUTE-004; ROUTE-015; ROUTE-016 (ADR-037). | A captured Triage Set (14 §16 item 2). First human contact is slower; ACK is met by auto-ACK. |
| RVW-B-03 | Fixed (14/15 portion) | 14 §8.2 (relational "direct manager" removed; reporting line checked by the Triage Set), §8.3 copy (ADR-037(4)); ROUTE-003; ROUTE-006. 15 §4.4: `manager` is not ingested; AUTH-012. | Report content can still reveal the reporting line. Copy in 11/05 is requested. |
| RVW-B-04 | Partially fixed | 14 ROUTE-016; CASE-009. 24 §9.2 (M1 retired); TEL-017. Chaff was not adopted. | Triage Set members can still notice envelopes they cannot open. A colluding member can tip off the accused. |
| RVW-B-05 | Fixed | 14 §6.5; CASE-009 (constant addressee set and send time). | Staff reactions are observable (RVW-B-31). |
| RVW-B-06 | Fixed (14/20 portion) | 20 §4 (date-only `ts` for system and import events), §5.3 (`sys.relay_daily` replaces `sys.relay_pull`), P-17, §14; LOG-013; LOG-019; LOG-021. 14 §16 item 6; CASE-017 (C4 release within 72 h); CASE-032. | A live intake compromise still sees exact times. Core WAL behaviour is owned by 09/19. |
| RVW-B-07 | Fixed | 24 §9 (§TEL is the single source); TEL-018; TEL-021. 20 §5.4; LOG-011. 14 §14; CASE-026. The reviewer wanted 03 §12 to be canonical; ADR-046(5) names 24 §TEL, and the ADR wins. | Low-volume instances reveal "≥ 1 report this month" to M2 audiences where k is met. |
| RVW-B-08 | Fixed | 24 §9.3; TEL-010, TEL-011 (k = 10, upward only); TEL-015 (magnitude rules). 14 §14; CASE-026. The reviewer proposed M2 quarterly and M3 k ≥ 20; ADR-046(5) sets k = 10 and a monthly minimum, and the ADR wins (tenants may raise k). | Side knowledge (24 §11). |
| RVW-B-09 | Partially fixed | 24 §8.2 (#21 removed); TEL-007 withdrawn; TEL-019; TEL-020 (tumbling windows, release after close, yearly switch evaluation with hysteresis). Differential-privacy accounting remains open (24 OI-2). | Statutory exact counts. No noise mechanism. |
| RVW-B-10 | Partially fixed | 14 §3 (`category_class` never server-visible for ANONYMOUS reports; OI-14-1 resolved); ROUTE-022. 24 TEL-016 (population ≥ 50 and ≥ 3 cases for the per-channel dimension). `routing_visible` (21 ENT-007) is a cross-document request. | Channel choice stays server-visible for the life of the case. |
| RVW-B-11 | Fixed (14/35 portion) | 14 CASE-032 (follow-up days only in the encrypted record; ISO week for HIGH). 35 D-02 (`activity_month`), D-03 (30 days after `available_day`), §9; RET-003; RET-004. | Network observers still see Tor use. Schema changes are needed in 09 (request). |
| RVW-B-14 | Partially fixed | 14 §8.3; ROUTE-002 (descriptor carries the escrow, break-glass, oversight and SoD statements used for generated copy). Copy fixes belong to 05/11/03. | Comprehension varies. |
| RVW-B-15 | Fixed (14 portion) | 14 §11; CASE-037 (immediate sealing and mode label). | Members remember what they read. 03 ANON-010 needs alignment. |
| RVW-B-18 | Fixed (20 portion) | 20 §14; LOG-019 (hour-truncated SYSTEM events, no relay events, hashed config, no staff pseudonyms, semantic check). | Screenshots and ticket text are out of scope. 32 §8 must align. |
| RVW-B-19 | Partially fixed | 24 BIZ-013 (vendor transparency report and operator statement). 20 AUD-016 (customer-controlled witness in MANAGED). The rest belongs to 03/18/21. | Hypervisor-level observation of Tier W. |
| RVW-B-20 | Fixed (24 portion) | 24 §8.1, §8.2 #14; TEL-019 (crash counts exclude Z-INTAKE; no `health-full` in GOV-ONPREM). | Linkable telemetry tuples (§8.3). |
| RVW-B-21 | Partially fixed | 35: §6.2 and DEL-018 (layered Erasure Key, (c)); §7 B6, §9, §11, DEL-012, DEL-024 (accurate statements, (b)); §7 B7 and DEL-023 (metadata minimized, (a)); §7 B8 (Object Lock, (d)); D-15 aligned to 19. 20 §16 item 7. The metadata-erasure-key ADR (fix 2) was not adopted by ADR-044. | Server-visible metadata stays in BS-CORE for ≤ 35 days (≤ 12 months with ADVANCED monthly sets) and in locked sets. |
| RVW-B-22 | Accepted residual (documented) | 35 §7 B6, §15 item 10: BS-INTAKE contents and the 14-day bound are stated accurately. Removing BS-INTAKE is not mandated by any ADR, and 19 owns the backup sets. | A BS-INTAKE seizure within 14 days yields verifiers and reply presence. |
| RVW-B-23 | Partially fixed | 15 §4.4; AUTH-012 (no `manager` ingestion); AUTHZ-030 (no directory attributes in case views). 14 §11; CASE-039 (optional intermediary mode). "Originals custody" is not adopted by any ADR. The candidate-set estimate belongs to 12. | Content knowledge. Tier W originals can reach the Triage Set. |
| RVW-B-25 | Partially fixed | 14 §8.2 (OVERSIGHT/AUDITOR row), §9.5; CASE-021; CASE-036. 20 §9; AUD-006. | The flag shows that some oversight holder is excluded. With exactly 2 holders, the other can infer which. |
| RVW-B-26 | Fixed (14/35 portion) | 14 §9.4, §11; CASE-017; CASE-035. 35 §9 copy; DEL-012. | Delayed signals slow oversight. 03/05/11 copy is requested. |
| RVW-B-30 | Fixed | 14 §3, §4.1, §8.1, §16; ROUTE-013 (no key IDs in cleartext). | Relies on KEM key privacy (ASM in 40). |
| RVW-B-31 | Fixed (20 portion) | 20 §13; LOG-022; AUD-010 (pseudonymous actors, date-only, daily batches, health bands); OI-20-3 resolved. | Network-level observation of Desk connections. |
| RVW-B-32 | Partially fixed | 14 §8.1 (no personal names on ANONYMOUS channels); ROUTE-002; ROUTE-020 (weekly slot). Relabelling retired members in the append-only log (35 D-22) is rejected in this group because it breaks verifiability; it is requested from 04. | 35 §15 item 9. |
| RVW-B-33 | Partially fixed | (b) 14 §3: `last_staff_activity_day` removed. (c) 35 D-09 set to closure + 30 days, aligned with ENT-009. (f) ROUTE-016: only the Triage Set sees intake before triage. (a), (d), (e) are not in G5 documents. | Low. |
| RVW-C-01 | Partially fixed | 15 §5.11; AUTH-021; DC-16; OI-15-2 (ADR-043). Server-verified TPM attestation of Desks is not adopted by ADR-043: the Desk self-report is non-authoritative. | An organisation that controls the endpoint defeats Desk protections. |
| RVW-C-02 | Fixed (14/15/20 portion) | 14 CASE-009. 20 §13; LOG-022; AUD-010. 15 §4.4 (IdP documented as an observer). Desk TUF refresh (33) and delayed reaction (12) are requested. | Day-level correlation of staff reactions. |
| RVW-C-03 | Fixed | 14 §7, §8.5; CASE-033; AS-11. 15 §4.2, §4.4, §5.8 DC-15; AUTH-006; AUTH-012; AUTH-019; AUTHZ-024. 35 §11; RET-013 (suspend, not revoke). | Physical destruction of every holder's devices and authenticators. `intake.min_recipients` in 32 still needs alignment. |
| RVW-C-05 | Fixed | 14 §8.8; ROUTE-008; ROUTE-015; ROUTE-019. 15 §4.2; DC-07; DC-08; AUTH-015; AUTHZ-025. The ADR's 72 h / 7 days is used instead of the reviewer's 14 days. K01 share distribution belongs to 04. | A captured independent body. |
| RVW-C-06 | Fixed | 35 §6.2, §7 B5, §11 (conditional statement); RET-012; DEL-020; DEL-021 (physical TPM in HIGH/GOV). | The attestation may be dishonest. |
| RVW-C-07 | Partially fixed | 35 §6.2 (availability dependency, DR replication); DEL-019. The Desk re-wrap path and DR-P4 for dwell > 14 days are requested from 04/12/19. | Loss of all vault copies needs member re-wrap. |
| RVW-C-08 | Partially fixed (vault item) | 35 §6.2; DEL-018 (host-local file, never a DB schema). Other items belong to 09/12/17/21/33. | — |
| RVW-C-09 | Fixed (15 portion) | 15 §4.2, §5.12; AUTHZ-027 (small-organisation mode with external OVERSIGHT and banner); AUTHZ-028 (`person_ref` binding). The installer's second admin is requested from 18. | Small organisations still concentrate trust. |
| RVW-C-10 | Fixed (15/35 portion) | 15 §5.1 (internal/external COUNSEL), §5.6; AUTHZ-010 (independent approver, 24 h delay, donor refusal). 35 §10; RET-009 (tenant hold scope and disclosure). ENT-019 is requested. | Court orders still compel production. |
| RVW-C-11 | Partially fixed | 20 §6.2; LOG-023 (Desk crash reporting disabled). The KFM/sync-root and ENT-034 parts belong to 12/21. | Vendor products change. |
| RVW-C-13 | Partially fixed | 24 §4 C-34 row; BIZ-014. 15 §5.12; AUTHZ-026 (fleet allow-list); DC-17. 20 §6.2 (Desk bundles never go to a corporate helpdesk on INDEPENDENT channels). Fleet key custody and vendor mirrors belong to 21/33. | Compelled withholding of updates within the allowed window. |
| RVW-C-14 | Fixed | 14 §8.7; CASE-034. 15 §5.1 RECORDS_CUSTODIAN; AUTHZ-029. 35 §13; RET-015; RET-016 (GOV quorum default, ADR-044(3)). The federated protocol is realised as Desk-local search per ADR-044(5). | Search completeness depends on grants. Escrow is a compellable key. |
| RVW-C-15 | Accepted residual (documented) | 15 §8 item 9; OI-15-1 remains open. The Tier W/FIPS items belong to 22/25/40. | Authenticator validation scope. |
| RVW-C-16 | Fixed (15 portion) | 15 §4.7; AUTH-022 (accommodation). Viewer accessibility belongs to 10/12 (ADR-042). | Partial conformance for rasterized originals. |
| RVW-C-18 | Fixed (14 portion) | 14 §6.6; ROUTE-021 (independent alternative channel, `intake.coi_exhausted`); CASE-038 (runway warnings to OVERSIGHT); CASE-030. Source-account RPO belongs to 19. | Very small organisations may have no independent route. |
| RVW-C-19 | Partially fixed | 14 §9.6; CASE-038 (site-diversity warning). Custodian dispersion and the RTO fix belong to 19/21. | More coercion targets. |
| RVW-C-21 | Partially fixed | 20 AUD-016 (customer-controlled witness in MANAGED). Everything else belongs to 18/21. | Hardware-level compelled capture. |
| RVW-C-22 | Partially fixed | 15 §5.6 (the platform break-glass admin set is defined). The playbooks belong to 31. | Playbooks do not create independence. |
| RVW-C-24 | Fixed | 24 §4 licence terms; BIZ-007 (safety automation and SSO continue; only configuration is frozen). | Negligible. |
| RVW-A-25 | Not applicable to this group | Flagged only by a "15" reference that points to 10 §15, not to document 15. | — |

Special duties, all done:
- 14: triage-first routing (§8, ROUTE-001/015/016); the follow-up sealing rule (§8.6, ROUTE-018); records custodian and Desk-local search (§8.7, CASE-034); SLA feasibility (§6.6, CASE-030/031, with the EU 7-day ACK met by auto-ACK); constant-schedule notifications (§6.5, CASE-009).
- 15: suspend-only SCIM (AUTH-012); wrap-deletion cooling-off (DC-15, AUTHZ-024); ≥ 2 authenticators (AUTH-006); break-glass independent approver (AUTHZ-010); time-locked roster changes (DC-08, AUTHZ-025); independent-custody devices (§5.11, AUTH-021); fleet roles (§5.12, AUTHZ-026).
- 20: COI reason codes removed; import events date-only (LOG-013/021); no relay buckets in bundles (LOG-019); LOG-020.
- 24: §TEL made canonical, with k = 10, monthly periods, complementary suppression and no medians below k; B-07/B-08 inconsistencies resolved.
- 35: EKV outer-layer semantics (§6.2, DEL-018); erasure log applied on restore (DEL-005); infrastructure-backup exclusion caveat (DEL-020); case metadata in backups minimized (B7, DEL-023); source deletion durable across intake DR (DEL-022); accurate "delete" statements (§9, §11, DEL-024).

## Cross-document requests

1. **03-PRIVACY-ANONYMITY**
   - Replace the §12 parameters with a reference to 24 §TEL: M1 and M4 are retired, and M2/M3 use k = 10.
   - META-017: constant-schedule notifications.
   - Update the §10.1 inventory: COI blinded tags, the backup metadata tail (35 §7 B7), BS-INTAKE contents, and removal of "salted onion hash".
   - R-07: mailbox-closed signal delayed 3–21 days, reported per week.
   - ANON-010: mandatory immediate sealing (14 CASE-037).
   - §10.3: vendor support retention ≤ 30 days.
2. **09-DATABASE**
   - Replace `coi_exclusion.user_id` and the `source` enum with 8 blinded tags; `coi_facts` becomes a blind membership test.
   - Remove `import_batch` and batch times; add `import_slot_date`.
   - Remove `last_staff_activity_day`.
   - Change the `reply` retention default from 90 to 30 days after `available_day`.
   - Change `activity_day` to `activity_month`.
   - Add the intake deletion-list table (35 D-26).
   - Align `counter_daily` and `v_case_counts` with 24 §TEL (remove the per-channel weekly admin counts).
   - Confirm the vault is a host-local file, not a schema.
3. **19-BACKUPS-DR**
   - Remove "separate schema" from BS-ERASURE.
   - DR-P1: apply the intake deletion list after restore, and skip re-push of listed replies.
   - Apply the signed erasure log on every restore.
   - Replicate the vault to the DR site within the HA RPO.
   - DR-P4: handle dwell > 14 days.
   - Specify the Desk re-wrap path (OI-6).
   - Monthly BS-CORE sets: ADVANCED, with a warning that metadata persists.
4. **04-CRYPTOGRAPHY**
   - Specify the `K_case_excl` label and the blind-check protocol.
   - Desk case-key cache and re-wrap procedure (RVW-C-07).
   - Weekly directory publication slot.
   - Consider salted commitments for role labels so retired labels can be withdrawn from public view without breaking verifiability (RVW-B-32).
   - K01 share distribution across independent roles (RVW-C-05).
5. **07-BACKEND**
   - The notification job becomes a constant daily digest.
   - Fixed relay import slots.
   - `sys.relay_daily`.
   - C4 random release within 72 h.
   - Mailbox-closed delay of 3–21 days.
6. **08-API**
   - SW-03 fail-closed page shows the independent alternative channel instead of "no alternative path" (ROUTE-004/021).
   - Mailbox deletion writes the intake deletion list.
   - Rename counters per 20 §5.4.
7. **11-FRONTEND-SOURCE and 05-SOURCE-OPSEC**
   - COI checklist copy (ADR-037(4)) plus "first read by {triage labels}".
   - Mailbox-deletion copy (14-day backup expiry, delayed signal).
   - Abandonment copy and 30-day reply availability.
   - Follow-up fail-closed copy (14 §8.6).
   - GC-01/GC-34 timing statements.
8. **12-FRONTEND-RECIPIENT**
   - Date display by day, or ISO week for HIGH.
   - Non-triage members see no pending envelopes.
   - Self-identification sealing UI.
   - `RESTRICTED_OVERSIGHT` rendering.
   - Intermediary-mode Case Brief.
   - Desk crash-reporting controls (LOG-023).
   - Candidate-set estimate for exports (RVW-B-23).
9. **13-FRONTEND-ADMIN**
   - SOC views show only global daily health bands.
   - Metrics per 24 §TEL.
   - Custody status and small-organisation banner.
10. **21-ENTERPRISE**
    - ENT-007: no `routing_visible` fields on ANONYMOUS channels.
    - ENT-008: fleet allow-list per 15 §5.12.
    - ENT-019: OVERSIGHT co-approval for litigation exports.
    - Fleet transport over Tor for GOV/HIGH.
    - ENT-032: "force re-enrollment" keeps the keystore.
11. **22-GOVERNMENT**
    - Recovery Quorum enabled by default in GOV (35 RET-016).
    - Map DC-12 rejection and source deletion to a disposition authority.
12. **23-COMMUNITY-EDITION**
    - SMB-008 references 24 §TEL.
    - Small-organisation mode (15 AUTHZ-027).
13. **30-ANONYMITY-TESTING**
    - Update the AT-021/023/026/040/043/047 oracles.
    - Add tests for excluded-member inference, timing correlation (LOG-021) and the COI identity sink (LOG-020).
14. **31-INCIDENT-RESPONSE**
    - Playbooks for SCIM/IdP suspension storms and roster capture.
    - Reference the platform break-glass admin set (15 §5.6).
15. **32-OPERATIONS**
    - `metrics.k_threshold`: upward only, minimum 10.
    - `intake.min_recipients` and case minimum holders default 2 (ADR-044(2)).
    - `notify.mode` default constant/pull.
    - Support bundle §8 per LOG-019.
    - CFG attestation item for infrastructure-backup vault exclusion.
    - Remove the WEAKENING labels.
16. **33-RELEASE-UPDATE-SECURITY**: Desk TUF refresh via the Z-CORE mirror on a fixed daily schedule (RVW-C-02).
17. **18-DEPLOYMENT**
    - The installer requires a second admin or an external co-signer.
    - Attestations for shared-virtualization Z-CORE.
18. **39-REQUIREMENTS-TRACEABILITY**: a spec-constant lint consuming `spec/constants/tel.yaml` (TEL-021).
19. **40-SECURITY-ASSUMPTIONS**
    - New ASMs: Triage Set not captured; independent-role declarations honest; infrastructure-backup attestation honest.
    - ASM-027 monitoring references DEL-020.
20. **DECISIONS.md**: reword ADR-033(3) "additionally wrapped" to the layered construction (RVW-B-21 fix 1). 35 §6.2 already applies the layered reading.
