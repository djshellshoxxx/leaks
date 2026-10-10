# DISP-FINAL-F2 — Final consistency pass (round 3), agent F2

Scope: 10, 11, 12, 13, 14, 15, 16, 20, 24, 26, 35. Inputs: DECISIONS.md ADR-001..047, cross-document requests of DISP-G1..G8, CONSISTENCY-BRIEF.md. "Already present" = the target text already satisfied the request (verified against the current file); no edit needed.

New requirement IDs: SUI-082..086 (11); RUI-075..081 (12); AUI-036..039 (13); CASE-040..044 (14); AUTH-023..024, AUTHZ-031..033 (15); LOG-024..025, AUD-017..018 (20); TEL-022 (24); I18N-017 (26); EVID-011 (10); DEL-025..027, RET-017 (35). Nothing renumbered; amended rows marked "(amended …)". Constants lint (`tools/constants_lint.py`): 0 conflicts in F2 documents.

## Request disposition

| Request (from DISP-Gx) | Target doc | Action (Applied/Skipped+reason) |
|---|---|---|
| G1-2: adopt 03 §7 strings, COI text + own-manager sentence, platform-neutral tier line, delayed delivery, acquisition guidance | 11 | Already present (SUI-075 generation, S04b, §5.2 tier line, S08 item 9, V-11) |
| G1-2: remove T_SAVED_CRED/SUI-028 re-display and 24 h drafts; single CSP/cookie/size classes | 11 | Already present (SUI-009/010/028 WITHDRAWN; §5.3/§5.4/§5.6 canonical); verified no persisted-draft remnants |
| G1-2: resolve IDENTIFIED via onion (RVW-B-14(e)) | 11 | Applied per ADR-047(5): S05b IDENTIFIED text, SUI-086, ADR open issue closed |
| G1-2 / G2-5: GC-01/GC-34 timing, iOS "higher trace", offline onion publication | 11 | Skipped: guidance text owned by 05 (11 shows day-only dates; 16 NET-049 covers publication) |
| G1-5: Desk crash reporting off, export outside sync roots, prompting interlock, "how many know" Triage-only, no cleartext key IDs | 12 | Already present (§4.1, RUI-066, SI-19/RUI-069, R02 Risk column, RUI-055) |
| G1-6: Triage Set routing, drop "Source's direct manager", blinded exclusions on reads, no `last_staff_activity_day`, `category_class`, report catalog → 24, no names on ANONYMOUS channels | 14 | Already present (§8.1–8.2, CASE-021/036, §3, §14) |
| G1-6 / G5-8: originals custody / intermediary mode | 14, 12 | Already present in 14 (CASE-039); Applied in 12 (Case Brief view, RUI-079) |
| G1-7: `person_ref` bound to attestation; second admin before go-live | 15 | Applied: `person_ref` verification signature (§4.2), DC-19 go-live, AUTHZ-032/033 |
| G1-7: SCIM `manager` off for ANONYMOUS; suspend-only; break-glass independent approver | 15 | Applied (manager not ingested in any channel; SCIM DELETE = suspension, AUTH-024); break-glass already present (§5.6) |
| G1-8 / G3-6 / G6-1: single normative H-INTAKE egress matrix | 16 | Applied: §14.2 rewritten to 17 §4.3.1 E1–E5 + inbound I1 (TCP 7443 on `relay0`) / I2; 8443/`int0` and 9443 pull withdrawn; nftables updated; NET-031 amended |
| G1-8: tor log retention ≤ 24 h; no C-37 CDN | 16 | Already present (NET-008, §11.3, NET-030) |
| G1-8 / G3-6: intake time floor Tor consensus + Roughtime over Tor; withdraw C-09 SOCK refclock | 16 | Applied: §14.3 rewritten (no SOCK refclock, Roughtime over `candor-update` SOCKS, values aligned with 17 §4.5, fail-closed rule, feasibility fallback) |
| G3-6: "no NTP" in the matrix | 16 | Applied as "no clearnet NTP"; internal H-MON NTS (E4) kept because 17 INFRA-007 (normative for the matrix) requires it; Z-CORE is never a time source |
| G3-6: update-tor UID; agent push on dedicated interface | 16 | Applied (`_tor-candor-update`, `candor-update` instance; E3 push on `mgmt0`) |
| G6-1: remove "updates pushed by C-09"; §15 exporter "pulled by C-25" contradicts ARCH-014 | 16 | Applied (NET-044 wording; exporter values pushed by `candor-health`, NET-036 amended) |
| G6-1: C-37 outside the organisation's web stack | 16 | Already present (§11.3, NET-048) |
| G1-10 / G3-9 / G4-8: no COI reason codes, generic `REMOVED`, no `COI_EXCLUDED` | 20 | Already present (P-16, LOG-020, `authz.denied`) |
| G1-10: date-only `ts` for source-triggered events; remove `batch_count_bucket` | 20 | Already present (§4, LOG-021; field absent) |
| G1-10: SIEM staff-auth ≤ hour precision, daily batch in HIGH/GOV | 20 | Applied (§13: finer than hour not available in HIGH/GOV) |
| G3-9: `wrap_deletion_*`, `coi_wrap_violation`, `relay_slot_overrun`, `platform_mismatch` | 20 | Applied (renamed/added events; 14 updated to `case.coi_wrap_violation`) |
| Task: event names aligned with 08/09 | 20 | Applied: §5.5 alias table maps every 08 `CLASS:name`, 07 and 19 name to a canonical type; LOG-024 CI check |
| G4-8: records-search and custody events | 20 | Applied `records.search_performed`; custody events already present |
| G6-17: `sys.relay_*` aligned with import slots; `case.identity_request_refused` schema | 20 | Applied (`sys.relay_daily` slots_overrun, `sys.relay_slot_overrun`; new CASE event) |
| G7-8: coarsened staff auth export | 20 | Already present (LOG-022) |
| Counter names (G3-11 via 20 §5.4) | 20 | Applied: counters renamed to `submissions`, `accounts_created`, `account_deletions`; `source_logins`/`replies_delivered` withdrawn (none exist per 07/09) |
| ADR-047(10) MANAGED customer-held audit export key | 20, 13 | Applied (AUD-017, `audit.exported` recipient fingerprint; 13 SOC export text, AUI-039) |
| G1-12: TEL-010/011 k = 10 | 24 | Already present (k = 10, upward only) |
| G1-12: magnitude rule, channel minimum (< 3 cases/month), tumbling periods, yearly regime evaluation | 24 | Already present (§9.3, TEL-015/016/020); Applied §9.4a summary for the registry |
| G1-12: drop `new_cases_bucket` | 24 | Already present (field #21 removed, TEL-007 withdrawn) |
| G3-11: confirm counter names and monthly RL-09 export as inputs | 24 | Applied (§9.4 "Counters (confirmed)" and "Input path" rows) |
| Task: chaff not counted | 24, 20, 35 | Applied (§9.4 chaff row, TEL-022, LOG-025, D-19) |
| G6-6: BIZ-007 keeps fencing/failover/SSO/SIEM on expiry; COI-exhaustion counter entry | 24 | Applied (BIZ-007 amended; §9.4 COI-exhaustion row) |
| G7-9: BIZ-007 class-S safety automation after expiry; §TEL single source | 24 | Applied (BIZ-007 per ENT-050); single source already stated |
| G8-8: enumerated aggregate-surface catalogue | 24 | Applied (§9.7 AS-01..AS-19, TEL-022) |
| G5-18 / ADR-047(11): constants file for the lint | 24 | Applied (TEL-021 amended to the 39-owned registry `tools/constants.json`) |
| G1-16 / G6-4: reconcile intake backups and D-15 with 19 | 35 | Applied (D-01/D-03 never in BS-INTAKE; B6 rewritten to 19 BS-INTAKE contents; D-15 already aligned) |
| G1-16: remove read/login-based retention | 35 | Already present (RET-003/004) |
| G1-16 / G6-4: conditional deletion statement (ADR-044(4) / INFRA-037-type attestation) | 35 | Applied (§9 statement generated from configuration; DEL-025) |
| G1-16 / G7-12 / G6-4: tenant-wide holds do not block source deletion unless named | 35 | Already present (§10, RET-009) |
| G2-15 / G3-15: reply retention 30 days; erasure log | 35 | Already present (D-03, D-25); D-25 now names BS-ERASELOG |
| G3-15: Tier V has no intake accounts; `activity_month`; cooling-off not for retention expiry | 35 | Applied (D-02, D-08); `activity_month` already present |
| G4-14: value of `{intake_backup_days}`; closure-signal delay | 35, 11 | Applied (14 days, B6; 11 S13 text states 3–21-day, week-granular delay) |
| G6-4: federated persons-concerned / records search; BS-ERASELOG | 35 | Applied (§13 Discoverability row → 31 COMP-028; D-25) |
| G7-12: D-09 identity retention = closure + 30 d; records-scheduled deletion mapping (GOV-034) | 35 | D-09 already present; mapping Applied (§13 row, RET-017) |
| ADR-047(8) per-case metadata erasure | 35, 14, 10 | Applied (35 D-10a, §6.1, §6.2 bound, B7, residual 8, DEL-026; 14 §3, CASE-041; 10 OI) |
| ADR-047(9) intake deletion list | 35, 11, 13, 20 | Applied (35 D-26, B6, DEL-025; 11 S13; 13 Backups panel; 20 `backup.restore_performed` flags, AUD-018) |
| ADR-047(7) Desk cache erasure | 35, 12, 14, 10 | Applied (35 D-12, §6.2, V5, DEL-027; 12 §4.3, RUI-076/077; 14 §8.5, §9.6, CASE-043; 10 EVID-011) |
| G2-5: passphrase confirmation, ADR-035(5) + rotation, Operator-Statement banner, VR-13 sentence, "read first by" | 11 | Already present (S10/S10c, SUI-064, S11r, WB-1, S03, S04b) |
| G2-5: "write down all words or none" | 11 | Applied (S10) |
| G2-5: Source App pin is a device trace; download over Tor; C-37 first-viewport warning | 11 | Applied residual 12 rewritten for the ADR-047(1) vault; download over Tor and C-37 already present (§9, 16 NET-048) |
| G2-6: Triage Set roles and grants; blinded-tag checks; COI-neutral codes; stale header key-ID text | 12, 13, 14, 15, 20 | Already present |
| G2-6: SCIM suspend-only + 7-day wrap-deletion cooling; ≥ 2 authenticators; offline keystore backup at enrolment | 15 | Applied offline keystore backup (§4.2, AUTH-023); rest already present |
| G2-6: out-of-band `person_ref` verification signature; device-custody display | 15, 13 | Applied (15 §4.2); custody display already present (13 §4.3a) |
| G2-6 / G3-18: OBJECTION / pending-change UI | 13 | Applied (state machine + Object/Uphold/Overrule, AUI-037) |
| G3-1: routes `POST /inbox` action `rotate-passphrase` (SW-22) and `/.well-known/candor/manifest` (SW-23) | 11 | Applied (§5.5 route tables; `/robots.txt` added) |
| G3-1: move `/keys` / `/verify` content into `/status` and `/safety` | 11 | Applied (§5.5 note: no such routes; content on S03/S02) |
| G3-1: remove persisted draft store, `T_DRAFT`, `T_SAVED_CRED`, 30 min/4 h timers, `k_draft`; S09/S10; `/new` no passphrase; delayed delivery; S04b text; follow-ups to original set | 11 | Already present (verified; only WITHDRAWN rows mention them); follow-up fail-closed text Applied (S12, SUI-085) |
| G3-4: DA-20 `import_date`/`rejectable`, Triage-only | 12 | Applied (`rejectable` drives "Reject unopenable"); Triage-only already present |
| G3-4: local COI/manager-chain before DA-30; blinded tags; ISO week in HIGH; Desk updates via DA-90 daily | 12 | Already present (R02, §8, RUI-073) |
| G3-4: DA-49 wrap-deletion UI; records grants | 12 | Applied (Members panel, RUI-078) |
| G3-5: Triage Set semantics and ROUTE-* alignment; `case.received_date` = import slot date | 14 | Applied received_date (§3); ROUTE-* already aligned |
| G3-5 / G6-7: SCIM suspend-only, `DEACTIVATION` semantics, ≥ 2 authenticators, independent approvers | 15 | Applied (§4.4 SCIM row, AUTH-024); rest already present |
| G3-18: Triage Set management, custody status, `alternative_channel_id` | 13 | Applied `alternative_channel_id`, population estimate, `min_recipients` (AUI-036); rest already present |
| G4-6: `independent_route` fallback; identity-seen flag | 14 | Applied `independent_route` naming and COI-exhaustion routing (§8.1); identity-seen already present (§11) |
| G4-7: step-up accessibility 180 s; custody attestation record format; RECORDS_CUSTODIAN name | 15 | Applied `DEVICE_CUSTODY` record format (§5.11); 180 s (AUTH-022) and role name already present |
| G4-16: IDENTIFIED via onion; localized wordlists | 11, 14, 26 | Applied per ADR-047(5)/(6) (11 S05b/S09/S11, SUI-082/086; 14 §11; 26 §12.7, I18N-017) |
| G4-16: Tier W source-initiated sandboxed cleaning | — | Skipped: not addressed to an F2 document (05/ADR-012) |
| G5-7: mailbox-deletion copy, abandonment and 30-day replies, follow-up fail-closed copy | 11 | Applied (S13, inbox retention line, S12) |
| G5-8: self-identification sealing UI; `RESTRICTED_OVERSIGHT` rendering; intermediary Case Brief | 12 | Applied (R03, RUI-079) |
| G5-8: date display; no pending envelopes for non-triage; crash reporting; candidate-set estimate | 12 | Already present |
| G5-9: SOC only health bands; metrics per 24 §TEL; custody and small-org banner | 13 | Already present |
| G6-7: Emergency Admin role; Independent Approver; dual control for intake E-MEM/E-NET | 15 | Applied (EMERGENCY_ADMIN, INDEPENDENT_APPROVER in §5.1; DC-18; AUTHZ-031/032) |
| G6-7: small-organisation substitutions; replace WEAKENING labels | 15 | Applied substitutions (§5.12); WEAKENING only in "former WEAKENING" notes (no label left) |
| Task: fleet roles | 15 | Applied (FLEET_OPERATOR role; `fleet` allow-list aligned with 21 ENT-008 §9.3 keys) |
| G6-9: Desk re-wrap procedure; custody self-check | 12 | Applied re-wrap (§4.3 R16); custody self-check already present |
| G6-10: `key_holder_site_diversity`; COI-exhaustion to independent route; `min_recipients` 2 | 14 | Applied COI-exhaustion routing; rest already present |
| G6-13: `capture-performed` banner; mailbox loss after outage; Tier W "mailbox temporarily unavailable" after failover | 11 | Applied (WB-2c verbatim from 31; `sui.login.failover`; SUI-085) |
| G6-13: COI-exhaustion message; "draft lost after restart" | 11 | Already present (S04b-X, S92) |
| G6-20(b)/(d): MANAGED customer-held audit key; per-case metadata erasure | 20, 13, 35, 14 | Applied per ADR-047(10)/(8) |
| G7-2: Source App embeds watcher/witness key set; cosigned checkpoint over Tor | 11 | Applied (V-3) |
| G7-4: `desk-preflight` (ENT-034); delayed reaction option | 12 | Applied (§4.1 row, RUI-080; R04 "Release later", RUI-081) |
| G7-4: server/peer-verified Desk attestation | 12 | Skipped: phrased as "consider"; ADR-043 keeps the Desk self-check non-authoritative and no ADR adopts remote attestation |
| G7-5: Records Custodian grant flow; close OI-15-1; accommodations | 15 | Applied OI-15-1 closure; grant flow (AUTHZ-029) and accommodations (AUTH-022) already present |
| G7-16: Triage Set Desk evaluates EE rule sets and `routing_visible`; channel population rules | 14 | Applied (§8.1 bullets, CASE-044) |
| G8-3 / ADR-047(3): chaff envelopes; failed trial decryption is normal | 12, 14, 20, 24, 35, 10 | Applied (12 R02, RUI-075; 14 §4.1/§8.1, CASE-042, OI-14-5 resolved; 20 §5.5 note, LOG-025; 24 §9.4; 35 D-01; 10 deps) |
| G8-7: canonical session cookie name and page size classes | 11 | No change: confirmed `__Host-cs`, P1 = 65,536 B, P2 = 131,072 B (§5.4, §5.6) |
| ADR-047(1) Source App encrypted vault | 11 | Applied (V-15, V-3, V-12, SUI-072 amended, SUI-083, residual 12) |
| ADR-047(2) follow-up dates encrypted | 14, 10, 35 | Applied (14 §3 `last_import_month`, CASE-040; 10 §4.2; 35 D-04/B7) |
| ADR-047(4) 7-day Key Directory freshness bound | 11, 13 | Applied (V-3, SUI-084; 13 not-available setting) |
| ADR-047(6) per-locale wordlists, NFKC | 11, 26, 13 | Applied (11 S09/S10/S11, SUI-042/082; 26 §12.7, A11Y-012 amended, I18N-017; 13 SAFE setting) |
| Contradiction check: 20 min/2 h, 16 slots, k = 10, fixed imports, 10 words, Argon2id 64 MiB | all F2 docs | No conflicts found (lint clean). 15 §4.1 staff CE software-passphrase fallback uses Argon2id 256 MiB for local Desk key unlock; ADR-046(7) governs only the source passphrase, so it was left unchanged |
| Contradiction: 13 listed "lower k" as DANGEROUS | 13 | Applied: lowering k below 10 moved to "Not available" (ADR-046 §5) |

## Follow-ups for other owners (found during this pass)

| Item | Owner |
|---|---|
| 17 §4.3.1 E1 and its ruleset use UID `debian-tor`; 16 §7.1/§14.2 use `_tor-candor-intake` (per-instance layout). Ports and interfaces now agree (7443/`relay0`, 8514/`mgmt0`). Recorded as 16 OI-8 | 17 |
| 04 §9.14 serves the running manifest at `/.well-known/candor/running-manifest`; 08 SW-23 (followed by 11) uses `/.well-known/candor/manifest` | 04 or 08 |
| 04 §12.7 (chaff, K41 disposition), cited by 04 §3, 09 and now 12/14/20, is not yet present in 04 | 04 |
| Records-custodian grant expiry: 08 DA-36 allows ≤ 90 days; 14 §8.7 and 15 §5.5/AUTHZ-029 say ≤ 30 days | 08 |
| 08 audit column uses short names; 20 §5.5 maps them. 08 could switch to the canonical dotted names | 08 |
