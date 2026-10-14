# DISP-G4 — Disposition of review findings for group G4

Documents: `05-SOURCE-OPSEC.md`, `10-FILE-EVIDENCE-PIPELINE.md`, `11-FRONTEND-SOURCE.md`, `12-FRONTEND-RECIPIENT.md`, `13-FRONTEND-ADMIN.md`, `26-ACCESSIBILITY.md` (all bumped to Draft v1.1).

New requirement IDs: SOPS-047..058; FILE-037..046; SUI-061..081; RUI-059..074; AUI-027..035, SOCUI-012..013, EMUI-013..014; A11Y-032..038.
Withdrawn (rows kept, prefixed "WITHDRAWN (ADR-034)"): SUI-009, SUI-010, SUI-028. Route `/saved` withdrawn.
Amended in place (marked "amended"): SOPS-001/007/022/026/032/040/046; FILE-002/009; EVID-004; SUI-005/008/011/012/016/019/021/029/035/044/047/049/053/057/058/059; RUI-002/007/009/010/013/020/033/042/048/055/057/058; AUI-006/007/008/009/013/015/018/022, SOCUI-002/004, EMUI-003/005; A11Y-011/023.

| Finding | Disposition | Changes (doc §, requirement IDs) | Residual risk |
|---|---|---|---|
| RVW-A-01 | Partially fixed | 11 §1, S01, S03, §5.2.1 WB-1/WB-2, §8 V-14, SUI-064, SUI-069; 05 GC-01, GC-38, GC-42, SOPS-048, SOPS-057; 13 §4.4 operator-statement ceremony, §4.8 watcher/statement checks, AUI-031, AUI-035, SOCUI-013 | Selector-based memory capture by a compelled operator is not detectable by watchers; Tier W banners are server-rendered and suppressible; TEE profile is defense in depth only (ADR-035). Stated in 11 §15.1 and 05 §11.11/16 |
| RVW-A-02 | Fixed | 11 §4, §5.6 rewritten (sealer-RAM session record, `__Host-cs`, 20 min / 2 h, no wall-clock), §5.7, §5.9, §6 state machine, SUI-061, SUI-011/012 amended, SUI-009 withdrawn; 26 §4 AD-01 (2.2.1 Essential exception), A11Y-011, A11Y-034 | Drafts lost on restart/expiry (stated to sources); live intake compromise still sees drafts |
| RVW-A-03 | Partially fixed | 11 S01/S03/S11 honesty lines (SUI-064), S11r rotation (SUI-068; HIGH offer at each login); 05 GC-32, GC-35, SOPS-058 | Reply minimisation, `prefs_ct` COI re-ask and BS-INTAKE exclusion belong to 03/07/09/19 (cross-doc). Rotation does not help against a live compromise |
| RVW-A-05 | Fixed | 13 §4.3 time-lock UI, objection control, independent approver, OVERSIGHT-certified labels (AUI-007, AUI-030); 11 WB-3, S03 "Recent changes", V-3 roster diff (SUI-072) | Three-party collusion (independent member + key-admin + CIK holder) remains, now time-locked and public |
| RVW-A-06 | Fixed | 11 S12 recipient text, SUI-074; 12 R02 follow-up check, RUI-055 | Follow-ups fail closed if all original members leave |
| RVW-A-07 | Fixed | 11 §5.6 attachment staging, final seal at Submit, SUI-062 (SUI-010 withdrawn); 10 §5.1, FILE-002 | Content key in sealer RAM during the draft (as A-02) |
| RVW-A-08 | Fixed (client side) | 11 §4, §8 V-3, SUI-049, SUI-072 (≥ 2 witnesses, Tor-fetched cosigned checkpoint, persistent pin) | First contact still trusts the out-of-band K01 fingerprint; persistent pin is a device trace (11 §15.12) |
| RVW-A-09 | Partially fixed (G4 scope) | 10 §4.2 `received_day` = import slot date, EVID-004; 12 R02 empty state, RUI-007 | WAL/backup/object-store behaviour is owned by 09/18/19 |
| RVW-A-10 | Partially fixed | 11 §4, V-2, SUI-073 (fetch-all), S03/S11 Tier W residual text (SUI-077); 05 GC-33; 12 SI-19, RUI-069, RO-18 | Tier W per-mailbox lookup residual (ADR-039); edge observation of visits |
| RVW-A-11 | Partially fixed | 11 S03 HIGH `<details>`, S11r, §15.11; 05 GC-38 HIGH, §4.3, SOPS-049 | HNDL on Tier W until Tor ships PQ handshakes (ADR-046 §8) |
| RVW-A-12 | Partially fixed (display only) | 13 §4.6 Platform Manifest + floor, §4.8, AUI-032 | Package pipeline owned by 17/28/33 |
| RVW-A-13 | Partially fixed | 11 WB-1 (operator statement); 13 §4.6, §6.7 floor, AUI-018, EMUI-014 | Root-level forgery of state reports without TEE |
| RVW-A-14 | Fixed | 11 §4, §8 V-11, §9 C-37 rule, SUI-071; 05 GC-38, SOPS-051 | iOS App-Store-only; store records compellable |
| RVW-A-15 | Fixed | 10 §5.3 output validation, §6 L1 row, §6.1 platform tiers (OI-10-2 resolved), H8, FILE-009 amended, FILE-037/038/042; 12 §4.1, R06 (no host PNG decode), SI-17 CSP/Trusted Types/isolation, RUI-002/020 amended, RUI-059/060 | Hypervisor escape; Tier 2 substrates have less hardening history (Knowledge (unverified)) |
| RVW-A-16 | Partially fixed (display only) | 13 §4.6 emergency cooling and signer organisations shown, AUI-032 | Owned by 28/33 |
| RVW-A-17 | Fixed | 11 §4, S03 (fingerprints/witness/hash removed from Tier W; fixed sentence), SUI-019 amended, SUI-066; 05 §7 S03 row | Tier W verification only after the fact (Desk import, watchers) |
| RVW-A-18 | Partially fixed | 12 R02 "Who", §8, RUI-067 (non-triage members never list/fetch envelopes); 13 §4.3 no intake counts | Chaff envelopes not adopted by any ADR; workflow side channels (THR-125) remain |
| RVW-A-19 | Fixed | 12 R10, §11, RUI-068; 13 §4.5 mapping | Staff reaction behaviour still observable on corporate networks (12 RO-17) |
| RVW-A-20 | Fixed (UI) | 12 R02 "Reject unopenable" (DC-12, ≥ 14 days), RUI-074 | Protocol (NOT_MINE) owned by 04/07 |
| RVW-A-21 | Fixed | 11 §1 canonical ownership, §5.3 single CSP, §5.4 route-fixed classes + login floor, §5.6 cookie `__Host-cs`, §14, SUI-005/008 amended, SUI-070; OI-11-3 resolved | Request sequences/inter-request timing still fingerprintable; 03/08 text must be aligned (cross-doc) |
| RVW-A-22 | Partially fixed | 11 §4, §5.4 rule 6, S06 honesty text, SUI-062, SUI-077; 10 §11, FILE-002; 05 §7 S06 row | Wire volume visible to two-ended observers; cover traffic not adopted |
| RVW-A-23 | Not applicable to this group | 11 §9 already forbids CDNs on C-37 | Egress matrix owned by 16/17; 03 CDN allowance (cross-doc) |
| RVW-A-24 | Partially fixed | 12 §4.1 managed-endpoint checks, §4.2 custody indicator, RUI-064/065, RO-16; 13 §4.3a, AUI-027 | Detection is best-effort; org-controlled endpoints defeat Desk (ADR-043 residual) |
| RVW-A-25 | Fixed | 10 §4.2 `external_refs`, §12 H3, §13 PSR beacon item, §15 E7/E9/E10, FILE-043/044; 12 R08 E5(iv), RUI-063 | Downstream recipients may ignore the no-network instruction |
| RVW-A-27 | Fixed (G4 scope) | 11 S90, SUI-081; 13 §5.1, §5.3, SOCUI-002 | Tor PoW effort is public |
| RVW-A-29 | Fixed (UI) | 13 §4.3 weekly publication slot display, AUI-007 | Changes themselves remain public (RVW-B-32) |
| RVW-A-30 | Partially fixed | 10 §4.3 fields, §5.4 rendering integrity, dual-render (HIGH default), H5, FILE-040/041; 12 R05 label, RUI-061, RO-19 | Common-mode renderer bugs |
| RVW-B-01 | Fixed (UI scope) | 12 §8 blinded tags, generic `REMOVED` reason, R14; 13 §4.3 no per-case exclusions shown | Server tables/log schemas owned by 09/20 |
| RVW-B-02 | Fixed | 11 S04/S04b/S08 triage-first ("first read by"), SUI-021/057/058/059 amended; 12 R02, RUI-009, RUI-067; 13 Triage Set editor, AUI-030; 05 GC-01 | Captured Triage Set |
| RVW-B-03 | Fixed | 11 S04b caution, no relational subjects, SUI-065; 05 GC-40, SOPS-054; 13 COI editor, AUI-009 | Report content can reveal the reporting line |
| RVW-B-04 | Partially fixed | 12 RUI-067 (non-triage no listing/counts) | Chaff not adopted; colluding member can tip off |
| RVW-B-05 | Fixed (G4 scope) | 12 R10, RUI-068 constant-schedule digest | Mail-provider metadata of fixed digests reveals subscription, not arrivals |
| RVW-B-06 | Fixed (G4 scope) | 05 GC-01/GC-34 rewritten, SOPS-040, SOPS-047; 10 EVID-004 | Live intake compromise sees exact times |
| RVW-B-07 | Fixed (G4 scope) | 13 CR-2, §5.1, §5.3, SOCUI-002, AUI-022; 12 RUI-042 → 24 §TEL | Weekly/monthly buckets on tiny instances |
| RVW-B-08 | Fixed (G4 scope) | 13 CR-2, AUI-022; 12 R09, RUI-042 → 24 §TEL (k = 10, no medians < k) | Rich side knowledge |
| RVW-B-10 | Not applicable to this group | — (14/03/21 own routing fields) | — |
| RVW-B-11 | Fixed (G4 scope) | 05 GC-33/GC-34, §4.3, §8.13, SOPS-050; 11 S08/S12 delayed delivery, V-12, SUI-067; 12 RUI-033/068 day/week | Source's own network sees Tor-use days |
| RVW-B-12 | Fixed | 11 §5.6 (RAM-only, ADR-034), S05b zeroize, SUI-061, OI-11-6 resolved; 26 §5 COGA row | Live compromise sees drafts; PRD wording owned by 01 (cross-doc) |
| RVW-B-13 | Fixed | 11 S09/S10/S10c/S10s, SUI-063 (SUI-028 withdrawn), ADR-005 open issue resolved; 05 §8.8, SOPS-022 | Live C-07 compromise |
| RVW-B-14 | Partially fixed | (a) 11 §5.2 banner from 03 §7, SUI-075; (b) 05 GC-01 generated statements, SOPS-047; (c) 05 GC-01/34, SOPS-040; (d)(f) 11 S04 CONFIDENTIAL consequence and banner; (e) IDENTIFIED-via-onion still open in 11 §16 (no ADR) | Comprehension varies |
| RVW-B-15 | Partially fixed | 11 §5.2 "CONFIDENTIAL (identity seen by case team)" banner state, OI-11-5 | Mandatory immediate sealing (03 ANON-010) and the status flag are owned by 03/14 (cross-doc) |
| RVW-B-16 | Fixed | 11 §5.2 platform-neutral tier line; 05 GC-38, SOPS-051 | 03 §7 tier line must be aligned (cross-doc) |
| RVW-B-17 | Fixed | 05 GC-43, §7 C-37 first viewport, §8.14, SOPS-026 amended, SOPS-055 | Organisations may ignore the advice; neutral directory domain is optional (03) |
| RVW-B-18 | Fixed (UI) | 13 §4.9 semantic scrubbing, AUI-034 | Bundle allow-list owned by 32/20 (cross-doc) |
| RVW-B-21 | Partially fixed | 11 S13 backup statement generated from config, SUI-080 | Backup/EKV design owned by 19/35 |
| RVW-B-23 | Partially fixed | 12 R08 E5(v) candidate-set estimate, RUI-070; triage-first (ADR-037) | "Originals custody" ADR amendment and intermediary mode were not adopted by ADR-034..046; content + HR join remains (PR-05) |
| RVW-B-24 | Fixed | 05 §8.5a, SOPS-052; 11 S08 item 7, SUI-076 | Semantic canaries survive |
| RVW-B-26 | Partially fixed | 11 S13, SUI-080; 05 GC-35, §8.12, SOPS-032 | Delayed/week-granular closure signal requires 03/35 change (cross-doc) |
| RVW-B-27 | Partially fixed | 11 S10c confirm-before-send, S11r; 05 GC-39, SOPS-053, OI-05-6 | 7-word default rejected: conflicts with ADR-005/ADR-046 §7 (ADR wins) |
| RVW-B-28 | Partially fixed | 05 GC-41, SOPS-056; 11 S01 NOT ANONYMOUS alternative, SUI-079 | Study design owned by 30 (cross-doc) |
| RVW-B-30 | Fixed | 12 §2, R02, RUI-055 (no cleartext key IDs) | KEM key-privacy assumption |
| RVW-B-31 | Partially fixed | 13 §5.4 weekly anomaly counts, SOCUI-004; 12 RO-17 | SIEM export granularity owned by 20 (cross-doc) |
| RVW-B-32 | Accepted residual (documented) | 13 §4.3 weekly slot, §8.6 | Roster changes remain public by design (ADR-030) |
| RVW-B-33 | Partially fixed | (d) 11 timers aligned with 03 META-014/08; (f) 05 §8.7, 12 R02/R03, RUI-013 | (a),(b),(c),(e) owned by 03/14/21/35/09 |
| RVW-C-01 | Partially fixed | 12 §4.1, §4.2, RUI-057/064/065; 13 §4.3a, AUI-027 (DC-16 DANGEROUS) | Org-controlled endpoints and hardware implants defeat Desk; custody is a declaration (ADR-043) |
| RVW-C-02 | Partially fixed | 12 R10/§11 constant digests, RUI-068, RUI-073 (Desk TUF via Z-CORE daily), RO-17; 10 EVID-004 | IdP/SIEM timing owned by 15/20/21; day-level correlation remains |
| RVW-C-03 | Fixed (UI) | 13 §4.2 suspend vs DC-15, AUI-006/029; 12 RUI-058 | Physical destruction of all devices |
| RVW-C-04 | Fixed (UI) | 13 §5.6 capture approval object, SOCUI-012; 11 WB-2 | Lawful compulsion of the independent approver |
| RVW-C-05 | Fixed | 13 AUI-007/030; 11 WB-3, SUI-069, SUI-072 | Captured independent body |
| RVW-C-06 | Fixed (UI) | 13 §4.7 infrastructure-backup attestation, AUI-033 | Attestation is organisational, not technical |
| RVW-C-07 | Fixed (UI) | 13 §4.7 EKV DR/erasure log, AUI-033 | Owned by 19 |
| RVW-C-08 | Fixed (G4 item) | 12 RUI-055 | Other items owned by 09/17/19/21/33 |
| RVW-C-09 | Fixed (UI) | 13 §4.1 banner, AUI-028/029; 11 S01/S03, SUI-078; 05 GC-01 `{reduced_sod_statement}` | Small organisations still concentrate trust |
| RVW-C-10 | Partially fixed | 12 R12, RUI-071; 10 E3, FILE-046; 12 E6 | Legal-hold and litigation-export rules owned by 35/21 |
| RVW-C-11 | Fixed | 12 §4.1 crash/sync hygiene, SI-18, RUI-065/066 | Vendor products change faster than the catalogue (OI-12-6) |
| RVW-C-13 | Fixed (EM UI) | 13 §6.3 fleet limits, §6.5, EMUI-003/005/013; 12 RUI-073 | Vendor can still withhold updates (instance alert) |
| RVW-C-14 | Fixed (UI) | 12 R15 records search, RUI-072, OI-12-5; 13 §4.4 GOV recovery default, AUI-013 | Every escrow-like mechanism is compellable; disclosed to sources (05 GC-01) |
| RVW-C-16 | Fixed (with declared partial conformance) | 10 §5.3 OCR layer + accessible rendition, FILE-039; 12 R06 text view, RUI-062; 26 §3.3, AD-01, A11Y-032..038, OI-26-5/6 | Rasterized originals partially conformant; English wordlist unresolved (ADR-005 open issue) |
| RVW-C-18 | Partially fixed | 11 S04b-X lists independent fallback first; 13 §5.4 Triage/runway alerts to OVERSIGHT | `min_recipients`, SMB external recipient and intake RPO owned by 32/23/19 |
| RVW-C-21 | Partially fixed (G4 scope) | 05 GC-38/§4.3 recommend Tier V for high risk | MANAGED Tier W default owned by 18/21 |
| RVW-C-12, RVW-C-15, RVW-C-19, RVW-C-24, RVW-A-04, RVW-B-19 | Not applicable to this group | Matched only by document-number false positives or owned elsewhere (17/18/19/21/22/24/25/32) | — |

## Disposition counts
76 findings: Fixed (incl. "Fixed (UI/G4 scope)") 40 · Partially fixed 27 · Accepted residual (documented) 1 · Rejected 0 (one sub-proposal rejected inside RVW-B-27: 7-word passphrase conflicts with ADR-005/ADR-046 §7, ADR wins) · Not applicable to this group 8.

## Cross-document requests
1. **03-PRIVACY-ANONYMITY:** ANON-004 CSP and any size-class text → reference `11` §5.3/§5.4 (RVW-A-21); §7 Tier W tier line → platform-neutral "Web mode: encrypted on arrival. [What are my options?]" (RVW-B-16); landing configuration-digest footer at week granularity (RVW-B-33 a); delete the C-37 CDN allowance (RVW-A-23); delay the mailbox-closed signal to Z-CORE (random 3–21 days, week granularity) (RVW-B-26); ANON-010 mandatory immediate sealing and an "identity seen by case team" source-visible flag (RVW-B-15); inventory rows for sealer-RAM drafts and tmpfs staging (ADR-034).
2. **08-API:** SW-03 currently shows the passphrase at `/new` — replace with `11` S09/S10/S10c flow (`/review`, `/check`, `/newphrase`, `/submit`; passphrase shown before send, 3-word confirmation); add `/rotate`, `/rotate/confirm`; drop 16/32/64/128 KiB route classes in favour of `11` §5.4 P1/P2 rule; SW-19 static route not used by Tier W; extend the 2 s login floor to successful logins as `T_LOGIN_FLOOR` (default 3 s); envelope release-date field for delayed delivery (ADR-038 §4).
3. **04-CRYPTOGRAPHY:** authenticated key-change SOURCE_MESSAGE for passphrase rotation; confirm per-part DEK wrapped under a per-session RAM key with HPKE wraps only at Submit (ADR-034).
4. **07-BACKEND / 09-DATABASE:** remove `draft_part`, `draft_gc`, `draft_generation` and any session/draft rows from C-08; sealer RAM session table and tmpfs staging (ADR-034); `T_LOGIN_FLOOR`.
5. **01-PRODUCT-REQUIREMENTS:** PRD-053/§7.8 copy → "never persisted to disk; kept in server memory for at most 2 hours" (ADR-034).
6. **14-CASE-MANAGEMENT:** remove relational subject "Source's direct manager" from the default COI template (RVW-B-03); provide the `independent_route` fallback channel used by `11` S04b-X; identity-seen flag in source-visible status (RVW-B-15).
7. **15-AUTHENTICATION-AUTHORIZATION:** staff step-up accessibility accommodation (180 s window, PIV/platform UV) referenced by A11Y-036; custody attestation record format for `13` §4.3a; confirm role name RECORDS_CUSTODIAN (ADR-044 §5) used by `12` R15.
8. **20-LOGGING-AUDITING:** SIEM export of staff auth events at day granularity / pseudonymous (RVW-B-31, RVW-C-02); records-search and custody events; generic `REMOVED` reason code (RVW-B-01).
9. **32-OPERATIONS:** CFG entries `intake.tier_w.draft_quota`, `T_LOGIN_FLOOR`, `evidence.dual_render`, notification mode/digest time; remove `T_DRAFT`, `T_IDLE_AUTH`, `T_ABS_AUTH`; support-bundle semantic scrubbing (RVW-B-18).
10. **33-RELEASE-UPDATE-SECURITY:** Desk TUF refresh via Z-CORE mirror on a fixed daily schedule (RVW-C-02 item 4; `12` RUI-073); Source App single generic build, onion distribution (ADR-041).
11. **18-DEPLOYMENT:** operator first-contact publication checklist (`05` §8.14, SOPS-055); installer requires second admin or external party before go-live (RVW-C-09).
12. **30-ANONYMITY-TESTING / 29-SECURITY-TESTING:** disk-imaging test after draft/abandon/error flows (SUI-061); S10/S10c loss tests (SUI-063); size-class invariance (SUI-005); phone-only and work-device personas (RVW-B-28); AT tasks for CL-2 text view and passphrase confirmation (`26` §13.3).
13. **34-PERFORMANCE-SCALABILITY:** tmpfs RAM sizing for Tier W staging (2 GiB default quota per draft).
14. **35-DATA-RETENTION-DELETION / 19-BACKUPS-DR:** value for `{intake_backup_days}` used in `11` S13 (or "no backups"); closure-signal delay (with 03).
15. **21-ENTERPRISE:** owner and cadence for the managed-endpoint detection catalogue (`12` OI-12-6; ENT-034).
16. **DECISIONS (ADR revision candidates, not resolved by ADR-034..046):** IDENTIFIED mode via onion (ADR-002; `11` §16); localized passphrase wordlists (ADR-005; `26` §16); Tier W source-initiated sandboxed cleaning (ADR-012 vs REQ-H-17; `05` §12).
