# DISP-FINAL-F1 — Final consistency pass (round 3), agent F1

Documents: 01, 02, 03, 04, 05, 06, 07, 08, 09, 40. Inputs: DECISIONS.md ADR-001..047; cross-document requests of DISP-G1..G8. All edited documents are now "Draft v1.2 (round-3 consistency pass: ADR-047)". New requirement IDs: PRD-090..092; TM-020; ANON-032..034, META-039..042, PRIV-023..024; CRYPTO-069..074, KEY-073..077; SOPS-059..061; ARCH-056..061; BE-075..078; API-053..058; DB-056..061 (DB-053 withdrawn); ASM-062..066 (register), ASM-138..139 (requirements), P-35/P-36, K-20/K-21. New key IDs in 04: K41 (chaff disposition), K42 (MANAGED audit export), K43 (case metadata key), K44 (Source App vault); KD entry types 0x14 SERVER_STATE, 0x1A DISPOSITION_KEY, 0x1B AUDIT_EXPORT_KEY.

## ADR-047 application

| ADR-047 item | Target doc(s) | Action |
|---|---|---|
| (1) Source App encrypted vault | 04 §11.8 (K44, CRYPTO-071), VR-1/VR-3, §15.2, §27 #19; 05 GC-38, new GC-44, SOPS-059; 03 §5 note 6, §7, §8.3, §8.6, §10.1/§10.2, ANON-019 amended, ANON-032, PR-13; 01 §7.1, PRD-090; 02 THR-048 re-rated, OI-08 resolved; 06 ARCH-060; 40 ASM-063 | Applied |
| (2) Follow-up dates only inside encrypted case record; `last_import_month` | 09 `case.last_import_month`, `import_envelope.import_date` nulled at import, `message.day` NULL, lint L17, DB-056, §8.1; 03 notes 14/25, §8.4 F04, §8.6, §9, §10.1, META-006 amended, META-039, OI-09 resolved; 06 §8.1, ARCH-059, R-10; 02 THR-134 re-rated, R-14 | Applied |
| (3) Chaff envelopes | 04 §12.7 (format, Poisson rate 1/2 h/channel, `disposition_ct` to K41, discard at derived hold slot), §14.6, §12.5, CRYPTO-069/070, KEY-075, OI-18/19; 07 §5.2a, ops 0x25 NOTE_REAL, job `chaff_discard`, CFG `intake.chaff.*`, BE-075/076; 09 `disposition_ct`, chaff rows, lint L18, DB-059; 08 RL-02, API-057; 06 §8.1, §9, §13, ARCH-056, R-3/O-2 resolved; 03 notes 15, §8.6, §9, §10.1, §10.4, ANON-034; 02 THR-110 re-rated, TM-020; 40 ASM-062, P-35, K-21 | Applied |
| (4) Directory snapshot ≤ 7 days; attestation ≤ 24 h | 04 VR-5 (24 h fail-closed superseded; 24 h now alert only), §9.14, §12.6, CRYPTO-073; 07 §12, §13, BE-060 amended; 06 §7.1, ARCH-057; 08 §7, SW-02, SA-12, API-058; 03 §7, R-10, §10.4; 02 THR-132; 40 ASM-052/055, K-20 | Applied |
| (5) IDENTIFIED over onion | 03 §3.1, §6, ANON-033; 01 §6, PRD-091; 05 GC-45, SOPS-060; 04 §9.2; 02 THR-040 | Applied |
| (6) Per-locale wordlists, NFKC normalization, language not stored | 04 §11.1, §11.2, §11.3, KEY-016 amended, CRYPTO-072; 05 GC-32 `{passphrase_word_count}`, SOPS-061, OI-05-5 resolved; 01 §7.1/§7.7/§7.8, PRD-092; 03 F14, META-042; 07 LOAD_PREFS; 09 `prefs_ct`, DB-061; 08 SW-10; 40 ASM-065 | Applied |
| (7) Desk case-key cache, re-wrap after vault restore/loss, erasure-log purge | 04 §9.10, KEY-073; 09 §5.6 `REKEY_MISSING`; 07 §5.12, job `ek_rewrap_pending`, BE-077; 06 ARCH-058; 03 §8.6, §10.1; 02 THR-117; 40 ASM-064, ASM-027 | Applied |
| (8) Per-case metadata erasure key | 04 §9.10a (K43 = HKDF(EK, case_id, "candor/v1/ek-meta"), used only inside the EKV), KEY-074; 09 `case_meta`, META_SEAL/OPEN, lint L16, DB-057; 07 §5.12; 06 §8.1, ARCH-058; 03 §8.4, §8.6, §10.1, META-040; 02 THR-017; 40 P-36 | Applied |
| (9) Signed intake deletion list | 04 §18.6 (K31-signed), KEY-077; 09 `deletion_list`, `core.intake_deletion_list`, DB-053 withdrawn → DB-058; 07 §5.3/§5.4 steps 10–11 + restore push-back, BE-074 amended; 08 SW-14, SW-15, RL-01 `restored`, RL-11, RL-12, API-054; 06 §8.6, ARCH-015 amended; 03 §8.2 R-07 note, §8.4, §8.6, §10.1, META-016 amended, META-041; 02 THR-017 | Applied |
| (10) MANAGED customer-held audit export key | 04 §9.15 (K42, entry 0x1B), KEY-076; 03 §10.3, PRIV-024; 02 THR-141; 06 ARCH-061; 40 ASM-066 | Applied |
| (11) Constants registry in 39 | Constants named for the registry: `KD_SNAPSHOT_MAX_AGE`, `ATTEST_MAX_AGE`, `CHAFF_MEAN_INTERVAL`, `CHAFF_FOLLOWUP_SHARE`, `CHAFF_BUCKETS_*`, `VAULT_SIZE`, wordlist hashes (04, 40 ASM-138) | Applied (registry content owned by 39) |

## Cross-document requests

| Request (from DISP-Gx) | Target doc | Action (Applied/Skipped+reason) |
|---|---|---|
| G1-1(a) key-privacy analysis of hybrid slots / pure ML-KEM FIPS | 04, 40 | Applied earlier (04 OI-15, 40 ASM-049/ASM-125); verified |
| G1-1(b) remove "Source App embeds tenant checkpoint"; freshness bounds | 04 | Applied: VR-1 now "single generic build embeds no tenant data"; freshness per ADR-047(4) (VR-5) |
| G1-1(c) derived-key residency for Tier W sessions | 04 | Already present (§9.13 last bullet); verified |
| G1-1(d) exactly one IDENTITY object per initial envelope, both tiers | 04 | Already normative (§9.2, VR-9(f)); verified |
| G1-1(e) K01 share distribution | 04 | Already present (§21.3, KEY-069) |
| G1-1(f) Desk case-key cache and re-wrap | 04 | Applied (§9.10, KEY-073; ADR-047(7)) |
| G1-2 05 strings, COI text, tier line, delayed delivery, acquisition, first contact, GC-01/34 timing, no T_SAVED_CRED/24 h drafts, IDENTIFIED via onion | 05 | Applied earlier except IDENTIFIED via onion, now Applied (GC-45, SOPS-060; ADR-047(5)) |
| G1-3 08: remove size-class/CSP/static route; CTR daily health band; no per-mailbox reply route for Tier V | 08 | Applied (size classes/CSP already point to 11; SW-19 withdrawn; CTR legend now monthly + health band; SA-13..15 withdrawn) |
| G1-4 09: blinded COI tags; no tier/quota/own-message history; header digest 24 h; `v_case_counts`; `activity_day` coarsening; slot = commit/blob time; SS/WF classification | 09 | Applied (most in r2; `activity_month`; cleartext allow-list §8.1 added) |
| G1-8 no C-37 CDN | 03 | Already Applied (META-024; §10.1 C-37 row) |
| G1-9 intake deletion tombstones applied on restore | 03, 06, 09 | Applied as signed intake deletion list (ADR-047(9)) |
| G1-17(b) follow-up dates only in encrypted record | 03, 09 | Applied (ADR-047(2)) |
| G1-17(c) IDENTIFIED via onion | 01, 03, 05 | Applied (ADR-047(5)) |
| G2-2 06 §8.5 host-agent push → C-25 pull | 06 | Skipped: superseded by 17 §4.3.1 E3 (agent push) and ARCH-014 push-only (DISP-G6-1/2); 06 now references 17 §4.3.1 |
| G2-2 one update path per zone; close O-3 | 06 | Already Applied (§8.7, ARCH-018; O-3 resolved) |
| G2-3 fetch-all page API; unauthenticated Tier V follow-ups; rotation endpoint; `routing_ct = {mailbox_id, reply_seq}`; `release_day`; running manifest; KD entry types; SW-17 VR-13; close 07 O-4 / 08 O-2 | 07, 08 | Applied (SA-19/20 fixed order; SA-12; SW-22/27/28; routing_ct fixed in 06/08/09; KD type list + name mapping in 07 §5.10/08 §7; O-2/O-4 closed) |
| G2-4 09: high-water row; blinded tags; `prefs_ct` contents and `kdf_version`; reply 30 days; `release_day`; erasure log; EKV export to K25; vault DR | 09 | Applied (r2) + `prefs_ct` corrected to 04 §11.4 fields |
| G2-5 05 copy items (confirmation, rotation, banner, VR-13, write all words, iOS, Tor download, pin trace, C-37) | 05 | Already Applied (GC-32/38/41/42/43); pin now in vault (GC-44) |
| G2-11 03: tor logs ≤ 24 h; no CDN; R-00; Tier W login residual; fetch-all; REPLY headers | 03 | Already Applied (r2); verified |
| G2-17 40: CA-10/NA-6, TEE CA-6, CA-9 hybrid | 40 | Already Applied (ASM-055, ASM-052, ASM-049) |
| G3-2 04 byte formats, K_case_excl, K_sp, key-update, VR-9, Argon2 64 MiB, dummy IDENTITY, Desk cache | 04 | Applied (formats present; SERVER_STATE added; Desk cache ADR-047(7)); 07 `K_sp` mapped to 04 K36 |
| G3-3 03 inventories (no Tier V accounts, fetch-all, `counter_month`, tags, `import_date`, digest 24 h, reply 30 d, `activity_month`, tombstones, notifications, BS-INTAKE) | 03 | Applied (tombstones → deletion list; `activity_month` row fixed) |
| G3-17 PRD-053 "never persisted to disk" | 01 | Applied |
| G3-19 re-rate THR-007/THR-014; ASMs time floor and backup attestation | 02, 40 | Verified already re-derived in r2 (credit only specified controls); ASMs exist (ASM-054/055) |
| G4-1 03: ANON-004 CSP/size → 11; tier line; digest week; no CDN; mailbox-closed delay; ANON-010 immediate sealing; RAM draft/tmpfs rows | 03 | Already Applied (r2); verified |
| G4-2 08: SW-03 flow → /review, /check, /newphrase, /submit; /rotate, /rotate/confirm; 11 §5.4 P1/P2; SW-19; `T_LOGIN_FLOOR` 3 s incl. successful logins; release-date field | 08 | Applied (SW-04 withdrawn; SW-08 = /review; SW-24..29 added; SW-10; API-053/056) |
| G4-3 04 key-change SOURCE_MESSAGE; per-part DEK under session key | 04 | Already Applied (§11.7, §9.13) |
| G4-4 07/09 remove draft rows; sealer RAM/tmpfs; `T_LOGIN_FLOOR` | 07, 09 | Applied (drafts withdrawn in r2; `intake.login_floor` CFG, BE-010 amended) |
| G4-5 PRD-053/§7.8 "kept in server memory for at most 2 hours" | 01 | Applied |
| G4-16 IDENTIFIED via onion; localized wordlists | 01, 03, 04, 05 | Applied (ADR-047(5)/(6)) |
| G5-1 03: §12 → 24 §TEL, M1/M4 retired, k = 10; META-017; §10.1 tags, backup tail, BS-INTAKE, no salted onion hash; R-07 delay; ANON-010; vendor ≤ 30 d | 03 | Applied (M1/M4 clarified as non-regimes; others present from r2) |
| G5-2 09: 8 blinded tags; remove `import_batch`, add slot date; remove `last_staff_activity_day`; reply 30 d; `activity_month`; deletion-list table; counters per 24 §TEL; vault host-local | 09 | Applied; `import_batch_no` kept as a timeless slot number (no batch time), consistent with ARCH-043 |
| G5-4 04: `K_case_excl`; Desk cache; weekly slot; K01 shares | 04 | Applied |
| G5-4 04: salted commitments for role labels (consider) | 04 | Skipped (not adopted by any ADR; logged as 04 OI-20) |
| G5-5 07: constant digest; fixed slots; `sys.relay_daily`; C4 release ≤ 72 h; mailbox-closed 3–21 d | 07 | Applied (C4 and mailbox-closed as signal envelopes with random `release_day`, SEAL_SIGNAL, BE-078; 04 §13.4 kinds 2/3) |
| G5-6 08: fail-closed page names alternative channel; mailbox deletion writes deletion list; counter names per 20 §5.4 | 08 | Applied (SW-02, SW-15, API-054/058; `submissions` → `submissions_received` in 04/07/08/09). `accounts_created`/`account_deletions` are not yet in 20 §5.4 and 20's `source_logins` conflicts with 09's "no login counters": left for 20/24 owners |
| G5-7 05 COI copy, deletion copy, abandonment, follow-up fail-closed, GC-01/34 | 05 | Already Applied (r2); verified |
| G5-19 40: Triage Set, independent approvers, backup attestation ASMs; ASM-027 → DEL-020 | 40 | Applied (ASM-057/058/054 existed; ASM-027 now cites DEL-020) |
| G6-2 06 §8.5/ARCH-004 → 17 §4.3.1 E1–E5; F8b; H-MON no route/MTA; C-26 not on H-MON | 06 | Applied (§8.5, §10, ARCH-004 amended; chrony E4 bounded by independent time) |
| G6-3 03: tor logs ≤ 24 h; no CDN; vendor ≤ 30 d; META-016 BS-INTAKE | 03 | Applied (META-016 amended for deletion list) |
| G6-8 04: INCIDENT_NOTICE/Operator Statement types; layered EK; Desk re-wrap for missing EKs; VMK escrow format; Argon2 per ADR-046(7) | 04 | Applied (all present; re-wrap after restore extended per ADR-047(7)) |
| G6-11 09: EKV host-local; tombstones and erasure log tables; intake `pg_params`; blob times | 09 | Applied (deletion list replaces tombstones) |
| G6-12 08: tombstones on reply re-publish; Tier W lookup vs tombstones; page size at EE scale; 2,048 chunks | 08 | Applied (RL-05, SW-10, SA-19 sizing note; §5.1 already 2,048) |
| G6-19 40: time floor ASM; TEE ASM | 40 | Already Applied (ASM-055, ASM-052) + 24 h attestation freshness |
| G6-20(b)/(d) MANAGED audit key; per-case metadata erasure key | 04, 09, 03, 40 | Applied (ADR-047(10)/(8)) |
| G6-20(a) core-mediated re-provisioning of intake accounts | — | Skipped: not adopted by ADR-047 |
| G7-1 03: remove salted onion hash; IdP/staff-reaction observer on ANON-013 page; MANAGED §10.3 | 03 | Applied (hash already removed; ANON-013 amended; §10.3 audit-export row) |
| G7-2 04: witness key set in Source App; attestation entry format; SERVER_STATE; K01 shares | 04 | Applied (SERVER_STATE 0x14 added; others present) |
| G7-3 40: KEM key privacy ASM; staff reaction day-level ASM | 40 | Already Applied (ASM-049, ASM-061) |
| G8-1 04/06 numeric snapshot and attestation freshness | 04, 06 | Applied (7 days / 24 h, ADR-047(4)) |
| G8-2 09/03 follow-up dates inside encrypted record | 09, 03 | Applied (ADR-047(2)) |
| G8-3 chaff / 03 residual | 03, 04, 06, 07, 09 | Applied (ADR-047(3)) |
| G8-5 03 machine-readable §10 inventory + rows (follow-up dates, slot window, excluded triage member, MANAGED union, disposed-case metadata, release dates) | 03 | Applied (PRIV-023; rows added/updated in §8.6, §10.1, §10.3) |
| G8-6 09 cleartext allow-list per envelope/import row; no reply↔account mapping for fetch-all | 09 | Applied (§8.1, DB-060; mapping exists only for Tier W) |
| G8-11 40: A15/A16/A17 dependencies (TEE limits, watcher independence, approver honesty) | 40 | Applied (ASM-052 audit note; ASM-050, ASM-058 existing) |

## Other consistency fixes (DECISIONS.md)

| Fix | Target doc | Action |
|---|---|---|
| Recipient slots configurable upward vs ADR-033(1) "exactly 16" | 06 ARCH-038, 07 CFG `envelope.recipient_slots` | Applied: fixed at 16 |
| Checkpoint cadence daily (07/08) vs hourly (04 §14.3) | 07 §5.10, job table, BE-061; 08 §7 | Applied: hourly fixed cadence per 04 |
| Sealer snapshot age "3 days" (07) vs ADR-047(4) | 07 §12, BE-060 | Applied: 7 days |
| Intake NTP "no NTP" (06) vs 17 §4.3.1 E4 | 06 §10, ARCH-004 | Applied: E4 permitted inside Tor-consensus/Roughtime bounds (ADR-036(6) "not from Z-CORE alone") |
| KD entry-type names differ between 04 and 07/08 | 07 §5.10, 08 §7 | Applied: explicit mapping; 04 canonical |
| `prefs_ct` contents (09/07 listed COI selection and language) vs 04 §11.4 and RVW-A-03 | 07, 09 | Applied |
| 01 "copy affordance" in no-JS Tier W vs 04 §11.1 | 01 §7.1 | Applied: Source App only |
| PRD-063 verification cited `default-src 'self'` vs single CSP in 11 §5.3 | 01 | Applied |

Timers (20 min / 2 h), k = 10 monthly, fixed import schedule, 10-word default passphrase and Argon2id 64 MiB were checked in all ten documents; no further contradictions found.
