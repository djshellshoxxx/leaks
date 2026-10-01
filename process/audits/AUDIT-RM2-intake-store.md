# AUDIT-RM2 — candor-intake-store (C-08 Intake Store)

| Item | Value |
|---|---|
| Step | RM-2 (intake zone), component C-08 |
| Audited commit | `55f3356f1fc4544edef6398f8126731bbc1649b0` (working tree clean for the crate) |
| Scope | `crates/candor-intake-store/{src/*.rs, migrations/0001_intake_schema.sql, tests/*, scripts/pg-test.sh, Cargo.toml, README.md, SPEC-NOTES.md}` (7,413 lines) |
| Tiering (27 §4) | T1: `pg.rs`, `migrations/0001_intake_schema.sql`, `deletion.rs`, `validate.rs`, `deaddrop.rs`, `rng.rs`, `error.rs`, `types.rs` (all reached by source- or relay-originated data). T2: `memory.rs`, `lint.rs`, `store.rs`, tests, `scripts/pg-test.sh` |
| Auditor | Independent security auditor (did not write this code) |
| Date | 2026-10-01 |
| Inputs read | R9 (§1, §6.3, §6.6, §8); AUDIT-CHECKLIST; BUILD-BRIEF "Security and OPSEC bar" + RM-2 addendum; IMPL-RM2-INTAKE §4 (A1–A15); 09 §5.1, §8 (L1–L18), §10, §11, §13; 07 §5.3/§5.4, BE-074; 08 RL-01..RL-12, SA-19/SA-20, §3.8, API-037/054; crate README + SPEC-NOTES (incl. "Security self-review") |
| Time per phase | A1 ≈ 10 %, A2 ≈ 10 %, A3 ≈ 55 % (every line of `pg.rs`, migration, `deletion.rs`, `validate.rs`, `deaddrop.rs`), A4 ≈ 20 % (tools + live PostgreSQL probes + PoC), A5 ≈ 5 % |

## Summary

| Severity | Count | IDs |
|---|---|---|
| Critical | 0 | — |
| High | 2 | STO-01, STO-02 |
| Medium | 5 | STO-03 … STO-07 |
| Low | 6 | STO-08 … STO-13 |
| Info | 4 | STO-14 … STO-17 |

**Gate: FAIL** (2 open High, 5 open Medium). The SQL layer is clean (static SQL only, all values bound, no injection path), RLS is ENABLE+FORCE on every data table with a non-owner, NOBYPASSRLS app role, and the KD high-water-mark logic and relay anti-replay counter are correct. The open problems are metadata residue that PostgreSQL itself creates (row `xmin`, server error log lines), deletion-list integrity on the restore path, and the published reply set.

What is done well (evidence for refuted goals): every SQL text is a `const &str` and the crate never uses `AssertSqlSafe`, `QueryBuilder` or `format!` in `pg.rs` (lint test). Driver errors are reduced to `StoreError::Backend`. No `timestamp`/`inet` types exist, and `track_commit_timestamp = off` is tested. IDs are 128-bit CSPRNG values. Claim order uses the random `envelope_ref`. The `SET LOCAL`-equivalent `set_config(..., true)` runs in every transaction. Triggers pin `search_path` and none is `SECURITY DEFINER`. `TEMP` is revoked from PUBLIC. `session_replication_role` cannot be set by the app (probe). The shuffle is unbiased Fisher–Yates with rejection sampling. Ed25519 verification is `verify_strict`. Chain comparisons are constant-time. No panics or unchecked casts on input paths (clippy deny set clean).

## A2 — Threat model and attacker goals

Trust boundaries: C-06/C-07 (source-originated data over local IPC: envelopes, new accounts, lookup tags, quota) → store; C-09 relay (authenticated, Z-CORE: claims, acks, reply pushes, snapshots, deletion-list pull/push) → store; seizure of the intake host / DB files (ADV disk-seizure / hosting-provider adversaries, 02 §6); anyone over Tor fetching SA-19/SA-20 pages; operator running the test script as root.

| # | Attacker goal | Result |
|---|---|---|
| G1 | Inject SQL through any stored or bound value | **Refuted**: static SQL only, all values bound, lint test `no_dynamic_sql`; migration `EXECUTE format(... %I/%L ...)` uses only `current_database()` and literals |
| G2 | Bypass RLS (owner, BYPASSRLS, SECURITY DEFINER, missing FORCE, wrong tenant) | **Refuted** for the app role (tests `pg_rls_tenant_isolation`, `pg_roles_and_grants`, `pg_refuses_privileged_role`; probe: no role membership, TEMP denied, `session_replication_role` denied). Hardening gaps → STO-08 |
| G3 | Recover exact or finer-than-allowed time of a source action from the seized DB | **Finding** STO-01 (`xmin` + in-DB day anchors), STO-11 (pg_stat) |
| G4 | Recover exact time of a source action from logs | **Finding** STO-02 |
| G5 | Learn whether an account/locator exists through errors/timing | **Refuted** at store level: `AccountExists`/`NotFound` are internal codes, and caller-side timing is documented as BE-010. Log side channel → STO-02 |
| G6 | Remove or rewrite deletion-list entries (compromised app role) so deletions are undone after restore | **Finding** STO-03 |
| G7 | Resurrect deleted accounts after a restore/failover (truncated/gapped push, missing restore flag) | **Finding** STO-04, STO-05, STO-09 |
| G8 | Roll back the KD snapshot high-water mark / relay counter | **Refuted**: `validate::snapshot` matrix, the `intake_meta_monotonic` trigger (probe and test), `GREATEST` on restore, and the strictly increasing counter `UPDATE … WHERE relay_req_counter < $1` |
| G9 | Replay a relay request | **Refuted** at store level (strictly increasing persisted counter, kept on restore); binding the counter to each op is the caller's job |
| G10 | Tell real from dummy dead-drop entries, or learn the reply count or arrival slot | **Finding** STO-06 |
| G11 | Learn access patterns from the dead drop (who fetched what, order by insertion) | **Refuted**: byte-identical shared pages, uniform random placement over all positions, no access state, `ORDER BY reply_ref` (random) |
| G12 | Crash or exhaust the store (panic, OOM, lock hold) | **Refuted for panics** (clippy deny set, bounded inputs). **Finding** STO-07, STO-12 for memory and CPU |
| G13 | Distinguish chaff from real envelopes in the DB | **Refuted** for schema and values (identical rows). Hazard via counter `xmin` noted in STO-01 |
| G14 | Abuse the test script (root) to escalate or leak | **Finding** STO-13 (Low) |

## A4 — Tool runs (versions and triage)

| Tool | Version / pin | Command | Result | Triage |
|---|---|---|---|---|
| PG integration tests | PostgreSQL 16 via `scripts/pg-test.sh` | `pg-test.sh <probe>` running `cargo test -p candor-intake-store --locked` | 17 + 12 + 20 + 5 tests pass, PG suite **enabled** | — |
| Live PG probes | psql 16 against the migrated DB as `candor_istore` | see STO-01/03/08/11 | 4 confirmations | findings |
| PoC (MemoryStore, same `validate` code as PG) | scratch crate outside repo | gap push / empty push / rebuild diff | confirms STO-04, STO-06 | findings |
| clippy deny set | 1.94.1 | `cargo clippy -p candor-intake-store --all-targets --all-features -- -D warnings` | clean | — |
| clippy audit extras | 1.94.1 | §C list | 27 warnings in crate: `as_conversions`/`cast_*` at `types.rs:82,100` (clamped `days_from_civil` result), `pg.rs:619`/`memory.rs:217` (`i16::MAX as u16` const), `deaddrop.rs:194-195` (consts 64/30); `integer_division` in Hinnant date math `types.rs:111-128` | all false positive (bounded constants or clamped values; date math is on a `u32` day input, which cannot overflow `i64`) |
| cargo-deny | 0.20.2, `--offline` | `cargo deny --offline check` | advisories ok, licenses ok, sources ok, **bans FAILED**: duplicate `sha2` (0.10.9 via sqlx-core) | STO-17 (already disclosed by builder, needs lead `skip` decision) |
| cargo-audit | 0.22.1, advisory-db `9b3a3b73` (2026-09-30), 1,277 advisories | `--no-fetch --deny warnings` | exit 0, no findings | — |
| cargo-vet | 0.10.2 | `cargo vet --locked` | 101 unvetted (workspace-wide, includes sqlx*, tokio) | STO-17 |
| cargo-geiger | 0.13.0 | Ratio | crate: 0 unsafe used; `unsafe_code = "forbid"` workspace lint | — |
| shellcheck | 0.9.0 | `-S style scripts/pg-test.sh` | clean | — |
| secrets scan | rg | `git log -p -- crates/candor-intake-store \| rg …` | none | — |
| fixture scan (B12.2) | rg | IPv4 pattern in tests | none | — |
| semgrep | — | not run: `process/semgrep/` local rules do not exist yet (ST-008), and `p/rust` is blocked here | — | noted |

---

## Findings

### AUD-RM2-STO-01 — PostgreSQL row `xmin`/`ctid` record per-account last-activity order, and in-DB day anchors turn it into a day; quota reset touches only active accounts
- Severity: **High**
- Location: `crates/candor-intake-store/src/pg.rs:143-144` (`SQL_ACCOUNT_TOUCH`, unconditional rewrite), `pg.rs:150-153` (`SQL_QUOTA_CONSUME`, `SQL_QUOTA_RESET … WHERE quota_bucket <> 0`), `pg.rs:1005-1012`, `pg.rs:677-683`; schema `migrations/0001_intake_schema.sql:114-122` (commit 55f3356)
- Category: B1.2, B9.4 (+ CWE-212, CWE-359)
- Description: Every UPDATE writes a new tuple whose system column `xmin` is the writing transaction's id. Transaction ids increase monotonically. `freeze` keeps the visible `xmin` (PG ≥ 9.4). The store rewrites `source_account` on every envelope commit (`SQL_ACCOUNT_TOUCH` runs even when `activity_month` does not change), every reply arrival and every upload (`quota_consume`). So each account row carries the txid of its **last activity**. Live probe as `candor_istore`: a no-op `GREATEST(activity_month, same)` moved `xmin` 912 → 913 and `ctid` (0,1) → (0,2), and `SELECT xmin, ctid` is permitted. The intake DB also holds rows that map txids to days: `reply.available_day` (dense, 30 days, one per pushed reply), `deletion_list.del_day`, `directory_snapshot.applied_day` and `envelope.received_date`. Interpolating gives an account's last-activity **day** within the last ~30 days, and the order of activity between accounts. That defeats the RVW-B-11 coarsening (`activity_month`) and ADR-010 "no last seen".
  - `quota_reset` updates only rows with `quota_bucket <> 0`, so after the daily job the reset txid marks exactly the accounts that uploaded that day.
  - Hazard: if the daemon calls `counter_add` per real submission (09 says it is held in sealer RAM; nothing in the store enforces batching), the `counter_month` row's `xmin` lies next to the real envelope's `xmin`. That separates real from chaff (ADR-047(3)).
  - `ctid` and physical order keep account creation order.
- Exploit scenario: an adversary who seizes the intake host or its decrypted DB files (disk-seizure / hosting adversary, 02 §6) reads `xmin` of all `source_account` rows (or parses heap pages). They anchor txids with `reply.xmin ↔ available_day`. They get each account's last-activity day and the accounts that were active on a given day. Combined with external knowledge ("the suspect used Tor on day D"), this narrows the anonymity set. It persists for the account's lifetime, well beyond the WAL residual that 09 §13 accepts.
- Fix recommendation:
  1. Make `SQL_ACCOUNT_TOUCH` conditional (`WHERE activity_month < $2`) so it writes at most once per month.
  2. Make `quota_reset` rewrite **all** rows of `source_account` in one transaction (no `WHERE quota_bucket <> 0`), so every live account shares one daily `xmin`. Or keep `quota_bucket` in RAM; it is "today only" and has no durability need.
  3. Add a periodic maintenance step (daily, at the fixed job time) that rewrites `source_account` and then runs `VACUUM (FULL)` or `CLUSTER … USING` the random primary key. This erases intra-day order, dead tuples and physical (`ctid`) creation order.
  4. Require `counter_add` to be flushed only at fixed times (document it on the trait and enforce it with a RAM accumulator in the store).
  5. Add a live test asserting that, after `quota_reset`, all `source_account.xmin` values are equal and that a same-month touch does not create a new tuple version.
  6. Add `xmin`/`ctid` to the 09 §13 residual list. This is spec feedback: the IMPL-RM3 core plan already treats `xmin` as a timing channel.
- Spec / requirement reference: ADR-010, ADR-038(3), ADR-046(5), ADR-047(3); 09 §5.1 `activity_month` (RVW-B-11), §8 L11/L15, §13; IMPL-RM2 §4 A1, A11, A12; BUILD-BRIEF "Metadata"
- Status: Open

### AUD-RM2-STO-02 — Expected-path unique violations become server ERROR lines with a millisecond timestamp (exact time of a source retry)
- Severity: **High** (base Critical "exact time persisted", lowered one level: it needs a duplicate/retry event and host log access; the line carries no identifier)
- Location: `crates/candor-intake-store/src/pg.rs:691-704` (`AccountLink::New` → `23505` → `AccountExists`), `pg.rs:709-726` (`header_sha256` → `DuplicateEnvelope`), `pg.rs:727-741` (duplicate `blob_id`), `pg.rs:534-545` (`init`), `pg.rs:1322-1335` (snapshot version)
- Category: B1.2, B1.3, B9.5 (+ CWE-532)
- Description: The store detects duplicates by letting PostgreSQL raise `unique_violation` and mapping SQLSTATE 23505. PostgreSQL writes every ERROR to the server log when `log_min_messages = warning` (09 §10, and `pg-test.sh`). `log_min_error_statement = panic` suppresses only the STATEMENT line. `log_error_verbosity = terse` removes DETAIL (so no key value), but the line `ERROR: duplicate key value violates unique constraint "envelope_header_sha256_key"` is still emitted, prefixed by `%m` (millisecond timestamp, 09 §10 `log_line_prefix`). `DuplicateEnvelope` exists for idempotent sealer retries (07 §5.3), and a Tor user double-submitting the first report hits `AccountExists`. So these events happen in normal operation, and each writes an exact-time record of source activity to journald.
- Exploit scenario: an adversary with access to the running intake host's journal (seizure of a running host, or a hosting provider reading volatile logs) sees `…unique constraint "source_account_locator_hash_key"` at 14:03:07.412. That timestamps a source's (re)submission to the millisecond and can be matched against network observation of a suspect.
- Fix recommendation: never use errors for expected outcomes on source paths. Use `INSERT … ON CONFLICT DO NOTHING` (or `… RETURNING`) and test `rows_affected`/the returned row to produce `AccountExists`/`DuplicateEnvelope`/duplicate blob. Keep 23505 mapping only as a backstop. Add a live test that runs the duplicate paths with `log_min_messages = warning` and asserts that no ERROR line is emitted (capture the server log in `pg-test.sh` to a 0600 temp file instead of `/dev/null`). Spec feedback: for the intake profile, consider `log_min_messages = fatal` and a `log_line_prefix` without `%m`, or minute granularity.
- Spec / requirement reference: ADR-010, ADR-016; 09 §10 Logging; 20 §11; IMPL-RM2 §4 A1, A11; R9 §6.3 [B-AU-21]; BUILD-BRIEF "Metadata"
- Status: Open

### AUD-RM2-STO-03 — Deletion-list "append-only" trigger is bypassable by the app role: set `relayed = true`, then delete every entry including the head
- Severity: Medium
- Location: `crates/candor-intake-store/migrations/0001_intake_schema.sql:179-198` (`deletion_list_guard`), `:270-271` (app grants `DELETE` and `UPDATE (relayed)`); SPEC-NOTES decision 15 and self-review ("append-only deletion list even against a compromised app role (tested)")
- Category: B9.3 (+ CWE-284, CWE-693)
- Description: The trigger refuses deletion of `relayed = false` rows, but the same role may flip `relayed` false → true and has table `DELETE`. Live probe as `candor_istore` with three unrelayed entries: a direct `DELETE` was refused (P0004); then `UPDATE candor.deletion_list SET relayed = true; DELETE FROM candor.deletion_list;` succeeded, **0 rows remaining** (head included). The "never delete the newest entry" rule exists only in `SQL_DEL_PRUNE`, not in the database. `pg_durability_and_guards` tests only the single-statement cases, so the self-review claim is unproven.
- Exploit scenario: an adversary with code execution as the app (or a bug) erases unrelayed deletion entries before the next RL-11 copy. After a restore or failover, the deleted source accounts or replies come back (ADR-047(9) violated). Deleting the head also makes the next `make_entry` restart at seq 1, which forks against the Z-CORE copy, so RL-12 then fails closed forever (DoS).
- Fix recommendation: do not grant `UPDATE (relayed)` and `DELETE` to `candor_istore`. Route marking and pruning through two narrow `SECURITY DEFINER` functions owned by the migrator, with `SET search_path = pg_catalog, candor`. They should: mark only `seq ≤ LEAST(after, max(seq))`; prune only `relayed AND del_day < cutoff AND seq < max(seq)`; and enforce a minimum `del_day` age for pruning. Alternatively, have the trigger refuse any DELETE of the max-seq row and any DELETE in a transaction that also changed `relayed` (statement-level transition tables). Add a regression test for the two-statement bypass.
- Spec / requirement reference: ADR-047(9); 09 §5.1 `deletion_list` ("pruned only after the relay has acknowledged them"), §11.5; BE-074; KEY-077
- Status: Open

### AUD-RM2-STO-04 — `apply_pushed_deletion_list` accepts a gapped, truncated or empty push and clears restore-pending
- Severity: Medium
- Location: `crates/candor-intake-store/src/validate.rs:197-236` (`merge_pushed`), `src/deletion.rs:237-268` (`verify_chain` with `anchor = None`), `src/pg.rs:1195-1272` (`SQL_CLEAR_RESTORE` unconditional)
- Category: B12.1, integrity / fail-closed (+ CWE-345, CWE-354)
- Description: When `pushed[0].seq − 1` is not present locally, the run is verified **unanchored**: only internal links and the genesis rule are checked. Nothing requires the pushed run to start at or before `local_head + 1`, or to end at or after `local_head`. An empty push returns early. In all cases `restore_pending` is then cleared. PoC (MemoryStore; the PG impl calls the same `merge_pushed`):
  - local `[1,2]` + pushed `[5,6]` gave `Ok(6)`, `serving_allowed = true`, local seqs `[1, 2, 5, 6]` (entries 3 and 4 never applied);
  - local `[1,2]` + pushed `[]` gave `Ok(2)`, `serving_allowed = true`.

  SPEC-NOTES and the trait doc claim "no gaps".
- Exploit scenario: after a BS-INTAKE restore, a faulty or compromised relay, or a stale or partially replicated Z-CORE copy, pushes a suffix or nothing. The store clears the flag and serves. The accounts deleted in the missing range (sources who asked to be deleted) are live again on the restored node and appear in later snapshots and backups. A source's deletion request is silently undone.
- Fix recommendation: in `merge_pushed`, reject when `!pushed.is_empty() && pushed[0].seq > local_head_seq + 1` (gap) unless the run is anchored to an existing local entry. Reject an empty or short push while `restore_pending` unless `local_head` is already ≥ the Z-CORE head. Have RL-12 carry the Z-CORE head `(seq, chain_hash)` and require the merged local head to equal it. After merging, re-verify that the local list is contiguous from its lowest retained seq to the head. Add tests for the gap, empty and truncated cases on both implementations.
- Spec / requirement reference: ADR-047(9); 07 BE-074; 08 RL-12, API-054; 09 §5.1 restore rule
- Status: Open

### AUD-RM2-STO-05 — No way to enter restore-pending for an EE-HA failover to a recovered disk, so the store fails open
- Severity: Medium
- Location: `crates/candor-intake-store/src/store.rs` (trait: no "mark restored" operation); `src/pg.rs:250-257` (the only writers of `restore_pending = true` are `restore_backup` paths); `pg.rs:569-573` (`serving_allowed`)
- Category: B8.4-style fail-closed (+ CWE-636)
- Description: 07 §6.3 "Restore push-back", 08 RL-12 and BE-074 require "any intake restore **or failover to a recovered node**" to refuse service until the newest list is applied, and RL-01 must report `restored`. The store sets `restore_pending` only inside `restore_backup` (which requires an empty store). A node brought back from its own recovered disk keeps `restore_pending = false`, so `serving_allowed()` returns true and C-06 serves with a local deletion list that may lack deletions made on the peer node during the outage. There is also no durable "epoch" or peer marker that would let the store detect this by itself.
- Exploit scenario: EE-HA node A fails; sources delete accounts on node B; A's disk is recovered and A is promoted. A serves the deleted accounts (login works, mailbox replies present) until a relay push happens. RL-12 is sent only "when RL-01 reports `restored`", so that may be never.
- Fix recommendation: add `IntakeStore::mark_restore_pending()` (persisted, idempotent) for `candorctl` / the failover procedure. Better, persist a random `node_epoch` in `intake_meta` that is rotated by the active node at each slot. A mismatch with the relay's view at startup forces `restore_pending`. Document the call in the failover runbook and add a test.
- Spec / requirement reference: 07 BE-074; 08 RL-01/RL-12; 09 §5.1 restore rule, §10 Replication (EE-HA); ADR-047(9)
- Status: Open

### AUD-RM2-STO-06 — Dead-drop dummies are regenerated at every rebuild while real entries persist, so diffing two sets reveals the real count and each reply's arrival slot
- Severity: Medium
- Location: `crates/candor-intake-store/src/deaddrop.rs:150-198` (`build`: fresh `dummy_body` per rebuild); `src/pg.rs:336` (`open` defaults to `RandomDummyReplies`)
- Category: B1.7 (+ CWE-203)
- Description: real reply ciphertexts are fixed bytes and reappear in every rebuild for 30 days. Every dummy is new CSPRNG output (or a fresh seal) at each rebuild. Anyone fetching SA-20 at two consecutive slots can intersect the entry sets: entries present in both are exactly the real ones. PoC: two builds of 3 real replies had exactly 3 entries in common. This holds **even with** an ideal `DummyReplies` that produces real-format ciphertexts. So the SPEC-NOTES residual (2) understates the leak ("production should pass a `DummyReplies` …" does not fix it), and the power-of-two/dummy padding hides nothing from a repeat fetcher. Each reply's first-seen slot (its `available_day`/slot) and the per-slot reply volume are public. The production constructor `open()` also defaults to the structurally distinguishable `RandomDummyReplies`.
- Exploit scenario: an observer (anyone over Tor, including the organisation under investigation) polls the index and pages at every slot. They learn how many replies the recipients sent each slot and how long each lived (deletion timing at the next rebuild). That correlates recipient-side activity with a case, against the intent of ADR-039 / API-037 (dummy indistinguishability).
- Fix recommendation: keep dummies stable across rebuilds. Give each dummy a lifetime drawn from the real `available_day` distribution (≤ 30 days), keep it in RAM, and retire or create dummies at the same slot granularity as real replies, so that churn is a fixed process independent of real volume (for example, the constant number of entries retired and added per slot equals a padding target). Remove the `RandomDummyReplies` default from `PgIntakeStore::open` (require an explicit `DummyReplies`). Add a test that diffs two rebuilds and asserts that the intersection size does not equal the real count. Spec feedback for 08 §3.8 / ADR-039: define the dummy lifecycle.
- Spec / requirement reference: ADR-039; 08 SA-19/SA-20, §3.8, API-037/API-040; 07 BE-063; IMPL-RM2 §4 A5
- Status: Open

### AUD-RM2-STO-07 — Published-set rebuild memory is bounded only at 2^15 pages (~147 GB), doubles at power-of-two boundaries and is double-buffered (OOM abort)
- Severity: Medium (remote/IPC resource exhaustion = High; lowered one level because it needs relay/Z-CORE-originated reply volume)
- Location: `crates/candor-intake-store/src/deaddrop.rs:25` (`MAX_PAGE_COUNT = 1 << 15`), `:150-198`; `src/pg.rs:1148-1166` (loads every `reply_ct` of the window, then builds while the old set is still referenced)
- Category: B2.3, B2.6 (+ CWE-770, CWE-400)
- Description: `MAX_REPLIES_PER_PUSH = 500` per push but there is no cap on pushes, window rows or pages. Peak RAM at rebuild ≈ `Σ reply_ct` (≤ 70 KB each) + new pages (`page_count × 4.48 MB`) + old pages still held by `Arc`s. One reply past a power-of-two boundary doubles the page memory (8,192 → 8,193 replies: 573 MB → 1.15 GB of pages, ~2.3 GB peak). With `panic = "abort"`/OOM-kill, the process that serves source pages dies.
- Exploit scenario: a compromised relay, or a flood of recipient replies (insider), pushes tens of thousands of replies inside the window. At the next import slot the store allocates many GB and is OOM-killed. Intake goes down, and restart timing becomes observable.
- Fix recommendation: add a deployment-sized `max_published_pages` (for example the 08 SA-19 EE figure of 128) enforced in `apply_replies` (reject or defer pushes beyond capacity, like a full mailbox) and in `build`. Stream page construction from a cursor instead of materialising all `reply_ct`. Drop the old set before building if memory is tight. Add a test for the cap.
- Spec / requirement reference: 08 SA-19 (memory figure), 16 §13 (DoS); IMPL-RM2 §4 A6; BUILD-BRIEF "Input handling"
- Status: Open

### AUD-RM2-STO-08 — Role and startup hardening gaps: the app role can rewrite its own role defaults, `temp_file_limit` is missing, and `open()` checks neither role membership nor live RLS/trigger state
- Severity: Low
- Location: `crates/candor-intake-store/migrations/0001_intake_schema.sql:25-33`, `:267` (app `UPDATE` on all `intake_meta` columns); `src/pg.rs:124-126`, `:351-362` (`SQL_ROLE_CHECK`)
- Category: B9.3 (+ CWE-250)
- Description:
  - Live probe: `candor_istore` successfully ran `ALTER ROLE candor_istore IN DATABASE probe SET statement_timeout = 0` and `ALTER ROLE candor_istore SET statement_timeout = 0`. PostgreSQL lets ordinary roles set their own defaults, so the per-role timeouts are not a control against a compromised app.
  - 09 §10 requires `temp_file_limit = 1GB` per role; the migration does not set it (probe: `-1`).
  - `open()` rejects superuser, BYPASSRLS and direct table ownership, but not membership in `candor_intake_migrator` (or any owning role). It also does not check that `relforcerowsecurity` and the triggers are still enabled on the live schema.
  - The app role can freely rewrite `kdf_salt`, `schema_hash` and `restore_pending` (probe: accepted). Clearing `restore_pending` directly bypasses BE-074.
- Exploit scenario: needs a compromised app role or a provisioning mistake (for example, granting the migrator role to the app for convenience). Impact: removal of the DB guards (owner can `ALTER TABLE … NO FORCE ROW LEVEL SECURITY` / `DISABLE TRIGGER`) or of timeouts.
- Fix recommendation: set the role settings with `ALTER ROLE … SET` from the migrator and **also** pass `statement_timeout`, `idle_in_transaction_session_timeout` and `temp_file_limit` as connection options in `PgConnectOptions` (the client re-asserts them per session). Add `temp_file_limit = '1GB'`. In `open()`, add `pg_has_role(current_user, 'candor_intake_migrator', 'MEMBER') = false` and no membership in any role owning `candor` objects, and check `relrowsecurity AND relforcerowsecurity` and `tgenabled = 'O'` for the expected triggers. Extend `intake_meta_monotonic` to make `kdf_salt` and `schema_hash` immutable and to allow `restore_pending` true → false only via the deletion-list apply path (e.g. a SECURITY DEFINER function).
- Spec / requirement reference: 09 §10 Roles, Functions; R7 SI-E-02/03; DB-002
- Status: Open

### AUD-RM2-STO-09 — Local deletions are accepted while restore-pending and can fork the chain, blocking RL-12 forever
- Severity: Low
- Location: `crates/candor-intake-store/src/pg.rs:586-616`, `:1052-1127` (no `restore_pending` check in `delete_account`/`delete_replies`/`delete_mailbox`); same in `memory.rs`
- Category: fail-closed (+ CWE-662)
- Description: on a restored store the local head may be behind Z-CORE. A local deletion appends seq `head+1`, which differs from Z-CORE's `head+1`. `merge_pushed` then returns "fork with local list" on every push, so the store can never leave restore-pending. C-06 should show the busy page, but the store does not enforce it (unlike `commit_envelope`/`apply_replies`).
- Exploit scenario: a race or caller bug during a restore window permanently disables intake (DoS) and leaves the restored node in a state that needs manual repair.
- Fix recommendation: return `RestorePending` from all three delete operations (and from `quota_consume`, `lookup_account` and `mailbox_list`, for defence in depth) while the flag is set. Add tests.
- Spec / requirement reference: 07 BE-074; 08 RL-12
- Status: Open

### AUD-RM2-STO-10 — `deletion_list_after(after)` marks entries relayed for any `after`, including values above the head
- Severity: Low
- Location: `crates/candor-intake-store/src/pg.rs:1176-1193` (`i64::try_from(after).unwrap_or(i64::MAX)` then `SQL_DEL_MARK … seq <= $1`)
- Category: integrity (+ CWE-20)
- Description: a pull with `after` ≥ head (or `u64::MAX`) marks every existing entry relayed although the relay received none of them. After 35 days they become prunable, so the only copy may be lost.
- Exploit scenario: relay bug or tampered request (behind the authenticated relay channel and anti-replay counter). Low likelihood; impact on deletion durability.
- Fix recommendation: reject `after > max(seq)` with `InvalidInput`. Mark only entries the relay has provably received: acknowledge in a separate step after the relay has verified and stored them, or mark `seq ≤ min(after, max returned in the previous page)`.
- Spec / requirement reference: 08 RL-11; 09 §5.1 deletion_list retention
- Status: Open

### AUD-RM2-STO-11 — PostgreSQL cumulative statistics keep activity timestamps and counts (`last_autovacuum`, `n_tup_ins/upd/del`) readable by the app role and persisted at shutdown
- Severity: Low
- Location: deployment profile (09 §10 "Statistics") and `scripts/pg-test.sh:67-92`; affects the tables in `migrations/0001_intake_schema.sql:217-222` (aggressive autovacuum makes runs track activity closely)
- Category: B1.2 (+ CWE-212)
- Description: probe: `track_counts = on`; `pg_stat_user_tables` is readable by `candor_istore`. It exposes per-table insert/update/delete totals and `last_autovacuum`/`last_autoanalyze` **timestamps**. With `autovacuum_vacuum_scale_factor = 0.01`, autovacuum on `source_account`/`envelope` fires soon after bursts of source activity, so these timestamps track source activity to minutes. Stats are written to `pg_stat/` on clean shutdown (PG 15+). The counts are aggregates, so not per-source, but `n_tup_upd` deltas between two observations count Tier W activity.
- Exploit scenario: a seized host gives approximate times of recent intake bursts (beyond what WAL retention already gives).
- Fix recommendation: add the cumulative-stats residual to 09 §13. At the daily job, call `pg_stat_reset()` through a migrator-owned SECURITY DEFINER wrapper (`track_counts` must stay on for autovacuum). Revoke `pg_stat_*` view access from the app role where possible. Make sure the stats file is not on unencrypted storage.
- Spec / requirement reference: ADR-010; 09 §10, §13; IMPL-RM2 §4 A1
- Status: Open

### AUD-RM2-STO-12 — Quadratic work under the `intake_meta` row lock in `apply_pushed_deletion_list` (up to 10^6 pushed entries)
- Severity: Low
- Location: `crates/candor-intake-store/src/validate.rs:213-235` (`local.iter().find` per pushed entry), `src/pg.rs:1213-1263` (`acct.contains` per account, `reps.contains` per reply), `src/types.rs:56` (`MAX_PUSHED_DELETION_LIST = 1_000_000`)
- Category: B2.6 (+ CWE-407)
- Description: with up to 10^6 pushed and up to 10^6 local entries, the merge is O(n·m) in Rust CPU while the `FOR UPDATE` lock on `intake_meta` blocks every mutating operation. `idle_in_transaction_session_timeout = 60s` then aborts the transaction, so a large legitimate restore can never complete. It also costs 10^6 strict Ed25519 verifications.
- Exploit scenario: relay-originated (authenticated) large push → intake stalls, restore never completes.
- Fix recommendation: index local entries by seq (`BTreeMap`) and collect hashes in `HashSet`s. Reduce `MAX_PUSHED_DELETION_LIST` to the 35-day retention need. Verify the push outside the locked transaction, then re-check the head inside it.
- Spec / requirement reference: 08 RL-12; IMPL-RM2 §4 A6
- Status: Open

### AUD-RM2-STO-13 — `pg-test.sh` (run as root) leaves a persistent system account and takes unsanitised environment values into `postgresql.conf` / `useradd`
- Severity: Low
- Location: `crates/candor-intake-store/scripts/pg-test.sh:19-20`, `:28-31`, `:57-69`
- Category: B10.7 (+ CWE-250, CWE-15)
- Description:
  - As root the script runs `useradd --system pgtest` and never removes it.
  - `PGUSER_OS` (env) selects the OS user that runs the cluster and is chowned the temp directory, so it can be pointed at any existing account. It is also passed to `useradd` without validation.
  - `CANDOR_TEST_PG_PORT` is written verbatim into `postgresql.conf` (`port = $PORT`), so a newline lets the caller inject configuration.
  - The ident map lets root connect as the DB superuser, and `CANDOR_TEST_PG_SUPERUSER` is exported into the arbitrary command the script runs.

  All inputs come from the invoking user, and the script is test-only. Socket dir and data dir are 0700, `listen_addresses = ''`, no host lines, and cleanup does not follow symlinks (`rm -rf --`).
- Exploit scenario: limited to a confused CI/operator environment (for example, a CI variable set by a PR in a shared runner) running the script as root.
- Fix recommendation: validate `PGUSER_OS` (`^[a-z_][a-z0-9_-]{0,31}$`, must not be root or an existing human UID ≥ 1000 unless created by the script) and `PORT` (`^[0-9]{1,5}$`). Optionally remove the user on exit when the script created it. Document that the script must not run on shared hosts.
- Spec / requirement reference: BUILD-BRIEF RM-2 addendum (test cluster); 27 §12; checklist B10.7
- Status: Open

### AUD-RM2-STO-14 — Deleted replies stay in the public published set until the next rebuild
- Severity: Info
- Location: `crates/candor-intake-store/src/pg.rs:586-616`, `:1052-1127` (no rebuild); `deaddrop.rs` (RAM set)
- Category: B6.5 / retention
- Description: account, mailbox and reply deletion remove rows, but the RAM pages keep serving the ciphertexts until the next import-slot rebuild (≤ 6 h). This is consistent with BE-063 (`set_version` changes only at slots, so the deletion time is not revealed). Record it as an accepted residual in SPEC-NOTES.
- Status: Open (documentation)

### AUD-RM2-STO-15 — `restore_backup` ignores the backup's `kdf_salt` when `intake_meta` already exists
- Severity: Info
- Location: `crates/candor-intake-store/src/pg.rs:1500-1514` (`SQL_META_RESTORE` does not compare `kdf_salt`)
- Description: restoring accounts into a store that was `init`ed with a different salt makes every restored locator unreachable (availability only; no confidentiality impact). Return `Conflict` when the salts differ.
- Status: Open

### AUD-RM2-STO-16 — Claim order by `envelope_ref` is random but fixed per envelope, so a high-ref envelope can be starved under backlog
- Severity: Info
- Location: `crates/candor-intake-store/src/pg.rs:161-163` (`ORDER BY envelope_ref LIMIT $2`), `validate.rs:101-116`
- Description: with more than `max_objects` claimable envelopes, the same high-`envelope_ref` envelopes lose every claim, which feeds BE-069 (>14 days pending). Order leaks nothing. Consider `ORDER BY release_day, envelope_ref`; `release_day` is already day-granular and not sent.
- Status: Open

### AUD-RM2-STO-17 — Supply-chain gate items: `cargo deny` bans fail (duplicate `sha2`), 101 unvetted crates, and the lockfile carries sqlx sqlite/mysql/macros (not compiled)
- Severity: Info (tracked; the deny failure is a gate item in §F.4 and needs the lead's decision already requested in SPEC-NOTES)
- Location: `crates/candor-intake-store/Cargo.toml`; `Cargo.lock`; `deny.toml`
- Description: `cargo deny --offline check` reports "bans FAILED: duplicate sha2 (0.10.9 via sqlx-core)". `cargo vet --locked` reports 101 unvetted (workspace-wide, including `sqlx*` and `tokio`). Cargo.lock lists `sqlx-sqlite`, `sqlx-mysql` and `sqlx-macros(-core)`, which the enabled features do not compile (verified with `cargo tree -e normal`). `sqlx-core` links `log`/`tracing` unconditionally. The crate installs no logger (lint test), and the daemon must not install one either (record this in the C-08 daemon audit).
- Status: Open (lead decision)

---

## Regression tests to add (SG-21)

| Finding | Test |
|---|---|
| STO-01 | live: after `quota_reset`, `count(DISTINCT xmin::text) = 1` on `source_account`; same-month touch keeps `ctid` |
| STO-02 | live with server log captured: duplicate envelope / account emits no `ERROR` line |
| STO-03 | live: `UPDATE relayed=true; DELETE` as `candor_istore` fails; the head row is never deletable |
| STO-04 | both impls: gapped, empty and truncated pushes while restore-pending → `DeletionList` error, flag stays set |
| STO-05 | `mark_restore_pending` persists across reopen; `serving_allowed` false |
| STO-06 | two rebuilds: the intersection size does not reveal the real count |
| STO-07 | `apply_replies` beyond `max_published_pages` capacity is rejected |
| STO-08 | `open()` refuses a member of `candor_intake_migrator`; trigger-disabled schema refused |
| STO-09 | deletes return `RestorePending` while the flag is set |
| STO-10 | `deletion_list_after(u64::MAX)` → `InvalidInput`, nothing marked |

Gate: **FAIL** 2026-10-01 55f3356 (open: 2 High, 5 Medium). Re-test per checklist §G after fixes.

---

## Re-test (round 2)

| Item | Value |
|---|---|
| Re-tested commit | `0f053c076a6083838afe740be239e9318378bfdf` (crate diff vs 55f3356: 16 files, +3,424 / −1,646; well over the 30 % re-audit trigger, so A2–A4 were re-run on all changed files) |
| Inputs | ADR-052 (1), (2), (9), (14); SPEC-NOTES "Fixes for AUD-RM2-STO" and the updated "Security self-review" / residuals |
| Date | 2026-10-01 |
| New code reviewed | `uniform_rewrite`/`rewrite_all`, `candor_intake_maint` role + `PgIntakeMaintenance`, the new `deletion_list_guard` / `intake_meta_monotonic`, 3-object groups (`CommitEnvelope.objects`, `group_digest`), the account split (`create_account`/`update_account`/`purge_inactive_accounts`), generation-based dead drop (`DeadDropConfig`, `PageBuilder`, `rebuild_published_set`), `merge_pushed`/`verify_pushed`, the restore-pending gate, `open_pool` role/guard checks, `pg-test.sh` |

### Evidence runs (round 2)

| Run | Result |
|---|---|
| `scripts/pg-test.sh` with the full crate suite (PG enabled) | 22 + 16 + 26 + 5 tests pass. Includes `pg_uniform_rewrite_xmin`, `pg_no_server_errors_on_expected_paths` (log capture with positive control), `pg_durability_and_guards`, `pg_refuses_privileged_role`, `pg_statistics_reset` |
| Live probes (fresh DB, roles as deployed by the migration) | see the statuses below. Main-table `xmin` after a rewrite: all 1304. **TOAST `xmin` stays 1300/1302/1303** (STO-18) |
| PoC, deletion-list push (MemoryStore; same `merge_pushed`) | gap → `Err(gap after local head)`; empty → `Err(empty push…)`; head-mismatch truncation → `Err(truncated push)`; all keep restore-pending. A truncated push with a matching asserted head → `Ok` (STO-22) |
| PoC, dead-drop generations (K = 8, 1 slot/day) | every slot adds exactly 8 entries (0/1/2 real). Length histogram of the added entries: `{5440: 8}` with no real reply; `{9000: 8}` with one real; `{9000: 7, 21000: 1}` with two (STO-19) |
| clippy deny set | clean |
| shellcheck `-S style` pg-test.sh | clean |
| cargo-audit (db `9b3a3b73`) | exit 0 |
| cargo-deny `--offline check` | advisories / licenses / sources ok. **`bans` aborts with "stack overflow"** (cargo-deny 0.20.2, reproducible, also with `ulimit -s unlimited`). `deny.toml` still has **no** `sha2@0.10.9` skip (ADR-052(7) not applied) → STO-17 stays open; gate §F.4 not met |
| `cargo test` without `CANDOR_TEST_PG` | PG suites skip cleanly (26 pass trivially) |

### Per-finding status

| ID | Sev | Status | Verification |
|---|---|---|---|
| STO-01 | High | **Fixed for heap tuples; not fixed overall → tracked as STO-18** | Quota is out of the DB, commits no longer write accounts, and `uniform_rewrite` gives every heap row of the 8 tables one `xmin` (test + probe). Out-of-line TOAST values keep their original `xmin` and ordered `chunk_id` (STO-18) |
| STO-02 | High | **Fixed** | `ON CONFLICT DO NOTHING` / `NOT EXISTS` on every expected-duplicate path (static read). The zero-ERROR suite test with a working positive control passes. `log_min_messages = panic` (ADR-052(14)) is checked by `pg_settings` |
| STO-03 | Med | **Fixed** (residual → STO-21) | Probe as `candor_istore`: `UPDATE … relayed = true` refused (P0004), `DELETE` refused (no grant). The no-op rewrite is allowed by design |
| STO-04 | Med | **Fixed** (residual → STO-22) | PoC cases A–C rejected and restore-pending persisted; the anchor, overlap, fork, hole-link and contiguity rules were read in `merge_pushed` |
| STO-05 | Med | **Fixed** | `PgIntakeStore::open` sets `restore_pending` on every initialised store; `mark_restore_pending()` exists. Every source op calls `MetaRow::serving()` |
| STO-06 | Med | **Fixed for the diff attack** (new content leaks → STO-19, STO-20) | PoC: two rebuilds differ by exactly K added / K expired whatever the real volume. Dummies are persistent rows and never regenerated. PG `open` requires an explicit `DummyReplies` |
| STO-07 | Med | **Fixed** | Page count is a configuration constant ≤ `HARD_MAX_PAGES` = 128. Page buffers use fallible `try_reserve_exact`, the build is streamed, and the backlog is bounded by `max_pending` ≤ 100,000 |
| STO-08 | Low | **Fixed** (residual 4 accepted by builder, needs lead acceptance) | Probe: with the role default set to `statement_timeout = 0` by the role itself, the client option still gives `30s` (client options take precedence over role settings). `open_pool` refuses owner-role and cross-role membership, unforced RLS and disabled guard triggers. Identity columns are not in the UPDATE grant (probe: `kdf_salt` update denied). The app can still flip `restore_pending` (probe) — documented residual 4 |
| STO-09 | Low | **Fixed** | `serving()` gate in `delete_*`, `create_account`, `update_account`, `lookup_account`, `commit_envelope`, `apply_replies`, `mailbox_list` |
| STO-10 | Low | **Fixed** (see STO-21) | `after > head` → `InvalidInput`; acknowledgement is the monotonic `deletion_acked_seq`, bounded by the trigger |
| STO-11 | Low | **Partially fixed; residual** (non-blocking) | `reset_statistics()` daily (probe: the maintenance role can call `pg_stat_reset()` when provisioned). The view/function revocation was not done; stats still accumulate within a day and are written at shutdown. Lead to accept |
| STO-12 | Low | **Fixed** | `verify_pushed` runs before the row lock; `BTreeMap`/`HashSet`; cap 200,000 |
| STO-13 | Low | **Fixed** | Inputs validated; existing root/human accounts refused; the created user is removed; `umask 077`; log is 0600 |
| STO-14 | Info | **Accepted residual** (builder, residual 5) | An early-deleted real reply is identifiable at slot granularity. This conflicts with the STO-06 goal but is required by SA-19. Lead to record |
| STO-15 | Info | **Fixed** | `Conflict("kdf salt differs")` |
| STO-16 | Info | **Fixed** | `ORDER BY release_day, envelope_ref` |
| STO-17 | Info | **Open** | ADR-052(7) skip not present in `deny.toml`; `bans` check now crashes the tool |

Variant hunt (each pattern checked; "none" means no new issue):
- **TOAST** → STO-18.
- `cmin`/`cmax`: per-statement command ids only; inside the rewrite every row of a table shares one, so nothing new.
- Lock-only `xmax`: equals the rewrite xid (asserted by the test).
- Sequences: none (probe: 0).
- Visibility map, FSM, clog: no times or per-row xids beyond commit status.
- Index tuples: the rewrites are HOT (no indexed value changes), so there are no xids. B-tree TID order equals the `ctid` residual already documented.
- Autovacuum timing: it now follows the slot rewrite, not source actions, and stats are reset daily.
- Maintenance-role abuse: it can only flag rows ≤ `deletion_acked_seq` and delete relayed non-head rows. The trigger does not enforce the 35-day age (only the Rust SQL does); acceptable because acknowledged entries are on Z-CORE. See STO-21 for the app-side lever.
- Restore-pending bypass: only by a compromised app role (residual 4).
- K-entry invariant under carry-over: holds; more than K reals wait in the backlog (PoC + `conf_dead_drop`).
- Account split: the store side is clean. Chaff-account cadence lives in C-06/C-07 (out of scope here; flag for the sealer/web re-test).

### New findings (round 2)

#### AUD-RM2-STO-18 — TOAST tables keep each value's original `xmin` and a monotonic `chunk_id`, so `uniform_rewrite` does not erase the order or linkage of account creation, envelope commits and reply arrival
- Severity: **High**
- Location: `crates/candor-intake-store/src/pg.rs` (`SQL_REWRITE_ACCOUNTS`, `SQL_REWRITE`, `rewrite_all`); `migrations/0001_intake_schema.sql` (`envelope_part.slot_block` 18,692 B, `reply.reply_ct` ≤ 69,996 B, `source_account.prefs_ct` ≤ 4,096 B with `xwing_pk` 1,216 B: all stored out of line in TOAST); test `pg_uniform_rewrite_xmin` (checks heap `xmin` only) (commit 0f053c0)
- Category: B1.2, B9.4 (+ CWE-212); variant of STO-01
- Description: when an UPDATE does not change a TOASTed column, PostgreSQL keeps the existing out-of-line value: the `pg_toast.pg_toast_<oid>` tuples are not rewritten. The rewrite statements (`SET state = state`, `SET padded_size = padded_size`, `SET size_bucket = size_bucket`, `SET activity_month = …`) therefore leave every TOAST tuple with the `xmin` of the transaction that first stored the value. Its `chunk_id` is an OID from the cluster-wide, monotonically increasing OID counter. Probe (superuser):
  - after tx A (account, 4,000 B prefs), tx B (envelope + 3 parts), tx C (reply) and tx D (the exact rewrite statements), every heap row has `xmin` 1304;
  - the TOAST rows still show `source_account` 1300, `envelope_part` 1302 and `reply` 1303, with `chunk_id` 26284 < 26285 < 26288.
- Exploit scenario: a disk-seizure adversary parses the TOAST relations of the intake DB.
  - Each account's creation or last passphrase rotation (the `prefs_ct` TOAST `xmin`/`chunk_id`) and each pending envelope's commit (the `slot_block` TOAST) keep their exact relative order permanently, not just until the next slot.
  - Account creation is a separate operation since ADR-052(2) precisely so that accounts cannot be linked to envelopes. The adjacency of an account-creation xid/chunk_id to an envelope-commit xid/chunk_id links them again (diluted only by chaff accounts and other traffic in between).
  - `reply.available_day` together with the reply TOAST `xmin` gives xid→day anchors, as in STO-01.

  Smaller rows that fit in-line (for example, short `prefs_ct`) are not affected, so exposure depends on the data.
- Fix recommendation: make the rewrite produce new TOAST values. Options:
  - (a) in the rewrite transaction, re-create each row (`DELETE … RETURNING` then `INSERT` of the identical values, ids kept) so that every TOAST value is newly written. Verify empirically, because a no-op expression on the column may keep the old TOAST pointer;
  - (b) set `ALTER TABLE … ALTER COLUMN … SET STORAGE MAIN`/`PLAIN` where sizes allow (`prefs_ct` ≤ 4 KB with `xwing_pk` may exceed the 8 KB page limit for PLAIN; `slot_block`/`reply_ct` cannot);
  - (c) store the large ciphertexts (`slot_block`, `reply_ct`) as blobs via safefs with normalized mtimes instead of in PG.

  Re-assert this in the live test: query `xmin` and `chunk_id` of every TOAST relation of `candor` tables after `uniform_rewrite` and require a single `xmin` and no ordering information. Add TOAST and the OID counter to the 09 §13 residuals until fixed.
- Spec / requirement reference: ADR-010, ADR-052(2), ADR-052(14); 09 §8 L11, §13; IMPL-RM2 §4 A1, A11
- Status: Open

#### AUD-RM2-STO-19 — All dummies of a dead-drop generation copy one real reply's length, so each slot's published entries reveal whether real replies were published and their sizes
- Severity: **Medium**
- Location: `crates/candor-intake-store/src/pg.rs` (`rebuild_published_set`: one `hint` per generation from `rows.get(uniform_below(rows.len()))`, `DEFAULT_DUMMY_BODY_LEN` when there is no real reply); `src/memory.rs` (same); `src/deaddrop.rs` (`DEFAULT_DUMMY_BODY_LEN = 5_440`, `PageBuilder::finish`)
- Category: B1.7 (+ CWE-203); variant of STO-06
- Description: the entries a slot adds are identifiable by diffing two index/page fetches (by design, exactly K). The `u32be` length prefix of each entry is cleartext. With no real reply, all K new entries are 5,440 B. With one real reply, all K take its length L. With two or more reals of different buckets, the dummies copy one of them and the other reals keep distinct lengths. PoC: `{5440: 8}`, `{9000: 8}`, `{9000: 7, 21000: 1}`.
- Exploit scenario: an anonymous observer polling SA-19/SA-20 each slot learns which slots published real replies, a lower bound on how many, and their size buckets. Per-slot reply activity is exactly what the generation scheme is meant to hide (STO-06, API-037).
- Fix recommendation: draw every dummy's length independently from a fixed public distribution of REPLY ciphertext lengths (the bucket distribution in the 39 registry); do not copy from real replies and do not use a constant default. Better still, pad every REPLY to a single ciphertext length, or put the true length inside the encrypted body so that the cleartext prefix is constant. Test: the length multiset of the K added entries is independent of real volume (χ² over many slots).
- Spec / requirement reference: ADR-039; 08 SA-20, §3.8, API-037; 04 §13.5
- Status: Open

#### AUD-RM2-STO-20 — Dummy rows store `size_bucket = ⌈len/4096⌉` while real replies store the plaintext bucket k, which separates real and dummy rows in the DB
- Severity: **Medium**
- Location: `crates/candor-intake-store/src/deaddrop.rs` (`dummy_row`: `k = body.len().div_ceil(4096)`); `src/types.rs` (`IncomingReply.size_bucket`: "k of 4096 × k" plaintext bucket); `migrations/0001_intake_schema.sql` (`reply.size_bucket`)
- Category: B1.7 / ADR-047(3)-style indistinguishability (+ CWE-203)
- Description: a REPLY ciphertext of plaintext bucket k is longer than 4096·k (header 160 B, STREAM tags, stanza). A real row therefore has `(octet_length(reply_ct), size_bucket) = (L, k)`, while a dummy of the same length L gets bucket `⌈L/4096⌉ ≥ k+1`. Inside a generation (STO-19) the dummies copy a real's length, so the one row with the smaller `size_bucket` is the real one. In general, `size_bucket ≠ ⌈len/4096⌉` marks real rows. "Dummies stored exactly like Tier V replies" does not hold.
- Exploit scenario: an intake DB seizure lists exactly which published entries are real Tier V replies, with their generation (slot), defeating the persistent-dummy design at rest.
- Fix recommendation: derive `size_bucket` for dummies with the same rule as real REPLY objects (take it from the `DummyReplies` implementation, which knows the format), or stop storing `size_bucket` for Tier V/dummy rows (it is only needed for Tier W mailbox rendering). Add a test that real and dummy rows satisfy the same length→bucket relation.
- Spec / requirement reference: ADR-039; 08 §3.8 / API-037; 09 §5.1 `reply`
- Status: Open

#### AUD-RM2-STO-21 — The app role can insert an out-of-sequence "head" and advance `deletion_acked_seq` to it; the daily maintenance run then prunes real, never-relayed entries, including the real head
- Severity: Low
- Location: `migrations/0001_intake_schema.sql` (`intake_meta_monotonic`: acknowledgement bounded only by `max(seq)`; `GRANT INSERT ON candor.deletion_list TO candor_istore` with no INSERT check; `GRANT UPDATE (deletion_acked_seq)`; `deletion_list_guard`: age not enforced)
- Category: B9.3 (+ CWE-284); residual of STO-03/STO-10
- Description: probe as `candor_istore`: three unrelayed entries (seq 1–3), then `INSERT` seq 1000 and `UPDATE intake_meta SET deletion_acked_seq = 1000` (accepted). Then, as `candor_intake_maint`, the production mark + prune SQL left `remaining seqs: 1000`. Every real entry older than the cutoff was deleted although the relay never acknowledged it. The junk row also breaks the chain, which the relay would detect at the next RL-11.
- Exploit scenario: a compromised app role erases unrelayed deletion entries older than 35 days (for example, during a long relay outage), so those deletions can be undone after a restore. This needs app compromise and an old unrelayed backlog.
- Fix recommendation: add a BEFORE INSERT trigger requiring `NEW.seq = COALESCE(max(seq), 0) + 1` and `NEW.prev_hash` = SHA-256 chain link of the current head (`pgcrypto` is excluded, so at least require seq contiguity and `NEW.prev_hash <> 0³²` unless seq = 1). Restore and merge inserts would use an owner-run definer path or insert in ascending order. Enforce the 35-day age in `deletion_list_guard` for DELETE.
- Status: Open

#### AUD-RM2-STO-22 — Truncation detection relies on the relay-asserted `core_head`; backups do not carry `deletion_acked_seq`, so after a restore a truncated push with a matching head is accepted
- Severity: Low
- Location: `src/validate.rs` `merge_pushed` (`core_head < acked` is the only independent check); `src/types.rs` `MetaSnapshot` (no `deletion_acked_seq`); `src/pg.rs` `restore_backup`
- Category: integrity / fail-closed (+ CWE-345); residual of STO-04
- Description: PoC D: local `[1,2]` (restored), push `[3,4]` with `core_head = 4` while Z-CORE truly holds 6 → `Ok(4)`, serving. After `restore_backup` the `acked` value is 0, so the `core_head < acked` guard is inert exactly when it matters.
- Exploit scenario: a faulty or compromised relay (or a lagging Z-CORE replica) supplies a short list after a restore; deletions 5–6 are lost on the restored node.
- Fix recommendation: include `deletion_acked_seq` (and the head seq/hash at backup time) in `MetaSnapshot` and keep the higher value on restore. Longer term, have Z-CORE sign `(core_head, chain_hash)` with a key the intake can verify (spec feedback for 08 RL-12).
- Status: Open

### Round-2 summary

| Severity | Open | IDs |
|---|---|---|
| Critical | 0 | — |
| High | 1 | STO-18 (STO-01 is closed for heap tuples; its goal stays open through STO-18) |
| Medium | 2 | STO-19, STO-20 |
| Low | 3 | STO-11 (residual, needs lead acceptance), STO-21, STO-22 |
| Info | 2 | STO-14 (accepted residual, lead to record), STO-17 (deny skip missing; `bans` check crashes) |

Fixed and verified: STO-02, 03, 04, 05, 06 (diff attack), 07, 08, 09, 10, 12, 13, 15, 16, and STO-01 for heap tuples.

Gate: **FAIL** 2026-10-01 0f053c0. Open: 1 High (STO-18), 2 Medium (STO-19, STO-20). §F.4 is also not met because `cargo deny check bans` aborts and the ADR-052(7) skip is missing.

---

## Re-test (round 3)

| Item | Value |
|---|---|
| Re-tested commit | `fc6406987dc9d8d827bb83b02e8ecb3e34418e26` (crate diff vs 0f053c0: 15 files, +1,842 / −301, plus `deny.toml`) |
| New code reviewed | `recreate_toast` (shuffled `col \|\| ''` re-creation), `toast_tuple_target = 8160`, `STORAGE EXTERNAL`, `vacuum_after_rewrite`; `DeadDropConfig::dummy_bucket_weights`, `reply_ct_len`/`reply_bucket_of_len`, `DummyReplies::dummy_body(bucket)`; `deletion_list_append`, `deletion_chain_hash`, `deletion_head_in_chain` triggers/functions; `SignedDeletionHead` (`candor/v1/intake/deletion-head`, strict Ed25519 under `core_pk`); `MetaSnapshot.deletion_head`; `deny.toml` changes |

### Evidence runs (round 3)

| Run | Result |
|---|---|
| `pg-test.sh` with the full crate suite | 28 + 17 + 30 + 6 pass, including `pg_uniform_rewrite_toast`, `pg_dummy_rows_indistinguishable` and `pg_deletion_list_append_guard` |
| **PG PoC with real store code** (scratch crate outside the repo: 4 × {create_account with 4,000 B prefs, commit_envelope, apply_replies}, then `uniform_rewrite` + `vacuum_after_rewrite`; superuser reads TOAST relations and scans every heap/TOAST page with `pageinspect.get_raw_page` for the 8-byte dead-tuple header signature `[old xmin][xmax = rewrite xid]`) | Before: 13 distinct heap xmins; TOAST xmins 746–756 with ascending chunk_ids. After rewrite + VACUUM: **every live heap and TOAST tuple has one xmin**, and `source_account` and `envelope` have no TOAST rows. **But all 143 pre-rewrite tuple images (old xmin) are still in page free space after the VACUUM** (envelope 2, source_account 4, envelope_part TOAST 118, reply TOAST 19). After the next two slot rewrites + VACUUMs, **3 original images were still present (TOAST)** → STO-23 |
| MemoryStore PoC, dead-drop sizes (K = 8; slots with reals of bucket 9, then 2 + 16) | Each slot adds 8 entries with independently drawn buckets; dummies no longer copy real lengths, and all lengths are canonical. A real bucket-16 entry appears once among dummies drawn with weight 6/1,000 (statistical residual, STO-25) |
| clippy deny set; shellcheck | clean |
| `cargo deny --offline check` | **advisories ok, bans ok, licenses ok, sources ok** (with the `sha2@0.10.9` skip, expires 2026-12-30, and `include-dependencies = false` as the stack-overflow workaround) |
| cargo-audit (db `9b3a3b73`) | exit 0 |

### Per-finding status (all IDs)

| ID | Sev | Status | Note |
|---|---|---|---|
| STO-01 | High | **Fixed** (heap), with residual | Live tuples share one xmin (round 2 + this PoC). Residual: rows written between slots have their own xmin until the next slot (SPEC-NOTES residual 3; ≤ one slot spacing), `ctid` order of `source_account` (one-statement rewrite), and dead images in free space → STO-23 |
| STO-02 | High | Fixed | (round 2) |
| STO-03 | Med | Fixed | Round-3 append trigger additionally blocks out-of-sequence inserts |
| STO-04 | Med | Fixed | Pushes must end at a Z-CORE-signed head chaining to the last verified head |
| STO-05 | Med | Fixed | (round 2) |
| STO-06 | Med | **Fixed** (diff attack + sizes), with residual | Persistent generations (round 2) and independent dummy buckets (round 3). Residual statistical leak → STO-25 |
| STO-07 | Med | Fixed | (round 2) |
| STO-08 | Low | Fixed | Residual 4 (app can clear `restore_pending`) still needs lead acceptance |
| STO-09, 10, 12, 13, 15, 16 | — | Fixed | (round 2) |
| STO-11 | Low | **Residual; lead acceptance required** (non-blocking) | Daily `pg_stat_reset()`. Within-day counters, `pg_class.relpages/reltuples` (updated by VACUUM) and `last_vacuum` stay readable. VACUUM/autovacuum timing now follows the fixed slot schedule, not source actions, so the remaining leak is aggregate within-day volume |
| STO-14 | Info | **Accepted residual** (to be recorded by the lead) | Early deletion of a real reply is visible at slot granularity (SA-19 requires removal) |
| STO-17 | Info | **Fixed** (lead) | `bans` runs and passes. `include-dependencies = false` disables dependency file scanning until cargo-deny is fixed (dated in deny.toml); `allow-build-scripts` still gates build.rs |
| STO-18 | High | **Fixed for live tuples**; remainder → STO-23 | Shuffled re-creation gives one xmin and new chunk_ids for all live out-of-line values (PoC + test with Kendall τ control); in-line accounts/envelopes have no TOAST |
| STO-19 | Med | **Fixed** (residual → STO-25) | Bucket drawn independently per dummy from configured weights; canonical lengths |
| STO-20 | Med | **Fixed** | One `reply_bucket_of_len` for every row; RL-05 rejects non-canonical lengths or mismatched buckets (`pg_dummy_rows_indistinguishable`) |
| STO-21 | Low | **Fixed** | `deletion_list_append` permits only chain-extending inserts (my seq-1000 probe is now in the builder's test and refused). Ack requires an in-chain head hash; maintenance re-verifies the Z-CORE signature before flagging. Chained junk with a junk signature passes the DB but cannot be pruned |
| STO-22 | Low | **Fixed**, with residual → STO-24(b) | `MetaSnapshot.deletion_head` is restored; pushes must chain to it and end at a signed head |

Variant hunt (round 3):
- **TOAST `chunk_seq`**: a per-value index (0..n), not an ordering → none.
- **Visibility map / FSM**: bits and free-space classes only → none.
- **VACUUM timing**: runs at the fixed slot → none.
- **`pg_class`/`pg_stat` per-table counters**: aggregate → STO-11 residual.
- **Dead tuple bytes after VACUUM** → **STO-23**.
- **Owner credential used every slot** → STO-24(a).
- **Older signed-head replay after an old-backup restore** → STO-24(b).
- **Dummy-weight tampering or miscalibration** → STO-25.
- **Sequences**: none (round 2).
- **`directory_snapshot` TOAST**: included in the shuffle → none.

### New findings (round 3)

#### AUD-RM2-STO-23 — Plain VACUUM does not erase pre-rewrite tuple images; original xmin (and TOAST chunk_id) survive in page free space, some across later slots
- Severity: **Medium**. Forensic (needs DB files); a bounded and shrinking fraction; the class is the spec's "row versions may persist until page reuse" residual (09 §10/§13). It is not accepted for the creation-order signal that STO-18 rated High, so lead acceptance or a fix is required.
- Location: `crates/candor-intake-store/src/pg.rs` (`vacuum_after_rewrite`, `SQL_VACUUM`: plain VACUUM); claim in SPEC-NOTES / `pg_uniform_rewrite_toast` that raw pages after VACUUM hold "only slot-xmin tuples" (true for line-pointed tuples, false for page bytes)
- Category: B1.2, B6.5 (+ CWE-212, CWE-226)
- Description: VACUUM removes dead line pointers and compacts the page, but does not zero the vacated bytes between `pd_lower` and `pd_upper`. PoC with the real store code: right after `uniform_rewrite` + `vacuum_after_rewrite`, all 143 original tuple headers (original xmin followed by xmax = rewrite xid) were found in page free space across `source_account`, `envelope` and both TOAST relations. TOAST images also carry the original `va_valueid` (chunk_id) in the chunk data. After two further slot rewrites + VACUUMs, 3 original TOAST images were still present. `pageinspect`'s tuple functions do not show these bytes, so the builder's test cannot see them.
- Exploit scenario: a disk-seizure adversary carves raw pages and recovers original transaction ids (and TOAST chunk_ids) of some accounts, envelope parts and replies. That gives creation order and xid adjacency (account creation next to an envelope commit) for the surviving fraction, partially restoring the STO-18 linkage.
- Fix recommendation: run `VACUUM FULL` (or `CLUSTER`) on the intake tables at a fixed maintenance time (for example, daily after the last slot, under a short exclusive lock). It writes fresh relation files; the old files are unlinked (on LUKS, freed blocks hold ciphertext of the old pages, the same as the WAL residual), and run a `CHECKPOINT` afterwards. Alternatively, accept and document "dead tuple images may persist for up to N slots" with measured N. Extend the test with a raw-byte scan for `[old xmin][rewrite xid]` (as in this PoC) after the maintenance step.
- Spec / requirement reference: ADR-010, ADR-052(2)/(14); 09 §10 Deletion, §13; IMPL-RM2 §4 A1
- Status: Open

#### AUD-RM2-STO-24 — (a) The table-owner login runs at every slot; (b) an older Z-CORE-signed head can be replayed after an old-backup restore
- Severity: Low
- Location: (a) `pg.rs` `vacuum_after_rewrite` (connects as the `candor-migrate` login, `SET ROLE candor_intake_migrator`); (b) `deletion.rs` `SignedDeletionHead` (no freshness field), `validate::merge_pushed`
- Category: B9.3 least privilege (+ CWE-250); integrity freshness (+ CWE-294)
- Description:
  - (a) ADR-052(9) intends the migration identity for `candorctl migrate` only, under admin step-up (09 §11.2). Using it from a scheduled job at every slot puts the schema-owner capability (disable RLS/triggers, alter grants) into a routinely running process.
  - (b) A head attestation has no time/epoch. After restoring a backup whose verified head is H_b, a relay can push any older-but-≥ H_b signed head H_o < current. It chains and verifies, so deletions after H_o are not applied (the builder lists this as residual). It needs a compromised or faulty relay holding past attestations; otherwise the relay simply sends the latest.
- Fix recommendation: (a) rely on autovacuum (already aggressive) plus a daily owner VACUUM FULL in the maintenance window (STO-23) run by a separate, minimal unit, or move to PG 17's `pg_maintain` grant when the platform allows. (b) Add a Z-CORE day/slot to the head message and require `head.day ≥ today − 1` (from candor-time) when clearing restore-pending; spec feedback for 08 RL-11/RL-12.
- Status: Open

#### AUD-RM2-STO-25 — Dummy bucket weights are a deployment parameter; a mismatch with the real reply distribution (or tampering) makes rare-bucket real replies likely identifiable
- Severity: Info
- Location: `deaddrop.rs` `DEFAULT_DUMMY_BUCKET_WEIGHTS`, `DeadDropConfig::validate` (only "not all zero")
- Description: per slot, a real reply in a bucket the dummy distribution rarely produces (PoC: bucket 16, weight 6/1,000) stands out with a high likelihood ratio. Indistinguishability holds only if the weights equal the real long-run distribution. A tampered config (for example, all weight on bucket 1) makes every non-bucket-1 entry real. Validation does not bound the weights.
- Fix recommendation: ship the weights in the signed config bundle (not local config), bound the minimum weight per bucket, or, for HIGH/GOV profiles, pad every REPLY to one bucket. Document the calibration duty.
- Status: Open (tracked)

### Round-3 summary

| Severity | Open | IDs |
|---|---|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 1 | STO-23 (fix or lead acceptance with expiry) |
| Low | 2 | STO-11 (residual, lead acceptance), STO-24 |
| Info | 2 | STO-14 (accepted residual, lead to record), STO-25 |

All of STO-01 … STO-22 are fixed and verified, except the documented residuals above.

Gate: **FAIL (conditional)** 2026-10-01 fc64069. No Critical or High is open. §F.2 is not met until STO-23 (Medium) is fixed or accepted in writing by the lead auditor (risk statement, ≤ 90-day expiry). With that acceptance, and the STO-08 residual 4, STO-11 and STO-14 recorded, the step meets §F (tools clean, and every attacker goal is refuted or linked to a finding).

## Lead dispositions (2026-10-01)
- **AUD-RM2-STO-14 — ACCEPTED (lead).** Deleted replies remain in the published fetch-all set until the next import-slot rebuild (≤ 6 h). This is intended: removing them immediately would reveal deletion timing (BE-063). Recorded as residual in the crate SPEC-NOTES. Review again at RM-6.
- **AUD-RM2-STO-08, STO-11, STO-23, STO-24, STO-25 — NOT accepted; to be fixed** (round-4 fixer): role hardening + live RLS/trigger checks at `open()` + `temp_file_limit` (08); `track_counts = off` and `autovacuum = off` on the intake cluster with slot-scheduled VACUUM, stats not persisted (11, deploy-owned settings); daily `VACUUM FULL` of source-linkable tables in a fixed maintenance window, measured with the TOAST/xmin probe (23); separate maintenance login from schema owner and date/epoch-bound signed deletion heads with monotonic counter (24); startup validation of dummy bucket weights against the canonical reply-size distribution, fail closed (25).

---

## Re-test (round 4)

| Item | Value |
|---|---|
| Re-tested commit | `422fbbbfeea657e8bba9cc7004cb6667acaf0ddb` (crate diff vs fc64069: 18 files, +2,122 / −230, including the new `src/staged.rs` and `tests/staged.rs`; new deps `candor-safefs` (path) and `rustix =1.1.2` (`std, fs, net`), dev `tempfile =3.23.0`) |
| New code reviewed | Per-connection stored and effective settings check (`open_pool`, `after_connect`); policy-set and owner-membership refusal; maintenance as database owner (`SQL_VACUUM_ROLE_CHECK`, `vacuum_after_rewrite`, `vacuum_full_daily` + `CHECKPOINT`, `pg_checkpoint` grant); per-table `autovacuum_enabled = false`, no ANALYZE; signed heads with `day` + `counter` (Rust + trigger); `dummy_bucket_weights` probability vector validation; `staged.rs` (SCM_RIGHTS receive, copy, ack). Cross-checked `deploy/intake/postgresql/pg_hba.conf` / `pg_ident.conf` for the maintenance login |

### Evidence runs (round 4)

| Run | Result |
|---|---|
| `pg-test.sh`, profile `intake` (`track_counts = off`, `autovacuum = off`) | 32 + 18 + 34 + 6 + 3 (staged) pass, including `conf_head_replay_after_restore`, `pg_role_defaults_and_live_guards`, `pg_vacuum_login_identity`, `pg_vacuum_full_erases_old_images`, `staged_bundle_hostile_variants_refused`, `staged_surplus_descriptors_closed` |
| `pg-test.sh`, profile `stock` | same counts, all pass |
| **Raw-page probe** (my round-3 PoC on the real store code; now also scanning indexes, TOAST indexes and old TOAST `chunk_id` refs `[chunk_id][seq 0]`) | After the slot VACUUM (maintenance role): 143 old-xmin headers + 16 old chunk_id refs still present (expected; positive control). **After `vacuum_full_daily`: 0 hits in all 87 pages** of every intake table, TOAST table and index |
| Maintenance (database-owner) role abuse probe | see STO-26. Refused: `session_replication_role`, event triggers, `NO FORCE RLS`, `DISABLE TRIGGER` (not table owner). **Allowed:** `CREATE SCHEMA`, `CREATE TABLE public.*`, `GRANT TEMP … TO PUBLIC`, `ALTER DATABASE SET work_mem / search_path / row_security`, `ALTER DATABASE … CONNECTION LIMIT 0`, and `DROP DATABASE <intake db>` from another database (test cluster) |
| Head replay | builder's `conf_head_replay_after_restore` (both stores) plus a read of `merge_pushed`/ack rules: stale counter, same counter with different content, earlier day, and day outside today ± 1 all refused |
| clippy deny set; shellcheck; cargo-deny (all four checks ok); cargo-audit | clean |

### Per-finding status (all IDs)

| ID | Status | Note |
|---|---|---|
| STO-01, 02, 03, 04, 05, 07, 09, 10, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22 | Fixed (unchanged since earlier rounds; the suite still passes) | — |
| STO-06 | Fixed; residual = STO-25 (now validated) | — |
| STO-08 | **Fixed** | Every new connection checks the role's stored defaults and the effective session values, and refuses deviations (probe in `pg_role_defaults_and_live_guards`: self-set `statement_timeout = 0`, `search_path`, `synchronous_commit = off` → refused). `ALTER ROLE` between connections is caught on the next connect (fail closed, DoS only). Settings outside the checked set (e.g. `work_mem`) can only be set by an already compromised role and cause DoS at most (Info). Residual 4 (app can clear `restore_pending`) still needs lead acceptance |
| STO-11 | **Fixed** | `track_counts = off` and `autovacuum = off` in the profile; per-table autovacuum off (incl. TOAST); VACUUM only at fixed slot/maintenance times; no ANALYZE (so no `pg_statistic` copies). Residual: anti-wraparound VACUUM can still be forced by PostgreSQL (its timing depends on xid consumption, i.e. aggregate volume; Info) |
| STO-14 | Accepted residual — **lead to record** | unchanged |
| STO-23 | **Fixed** | Raw-page probe: zero pre-rewrite images after the daily VACUUM FULL. Residual: the unlinked old relation files' blocks stay in filesystem free space on the LUKS volume until reused (same class as the WAL residual, 09 §13; Info) |
| STO-24 | **(a) Fixed** (VACUUM by `candor_intake_maint`, not the schema owner; the new privilege it holds → STO-26). **(b) Fixed with narrow residual** | (b) Signed `day` + monotonic `counter`; RL-12 requires `today − 1 ≤ day ≤ today + 1`. A compromised relay replaying an attestation from the last ~1 day that is still newer than the restored head would lose at most ~1 day of deletions on a restored node (Low residual; lead to record) |
| STO-25 | **Fixed** | Finite probability vector, floor 0.005 per bucket, Σ = 1 ± 1e-6, validated at startup and at each draw (fail closed) |

### New findings (round 4)

#### AUD-RM2-STO-26 — Database ownership gives the maintenance login destructive and denial-of-service powers beyond VACUUM
- Severity: Low. The production `pg_hba.conf` limits `candor_intake_maint` to `/^candor_intake_` databases via the `candor-imaint` peer map, so a single-tenant cluster cannot `DROP` its only intake DB (a DB cannot be dropped while connected to it). Remaining reach: DoS, and on multi-tenant clusters cross-tenant drop.
- Location: `migrations/0001_intake_schema.sql` (`ALTER DATABASE … OWNER TO candor_intake_maint`, `GRANT pg_checkpoint`); design note in SPEC-NOTES (lead-approved)
- Category: B9.3 least privilege (+ CWE-250, CWE-269)
- Description: probe as `candor_intake_maint`. Allowed:
  - `CREATE SCHEMA`, and objects in `public` (it is `pg_database_owner`);
  - `GRANT TEMP ON DATABASE … TO PUBLIC`;
  - `ALTER DATABASE … SET work_mem/search_path/row_security`. These are caught by the app's connect-time check, which fails closed, so a compromise here is a DoS lever;
  - `ALTER DATABASE … CONNECTION LIMIT 0`, which locks out every non-superuser, including the store;
  - from a second database it may connect to, `DROP DATABASE` of an intake DB with no open connections. That destroys pending, not-yet-relayed source submissions.

  On an EE cluster with several `candor_intake_<t>` databases (all owned by the same cluster-wide role, all allowed by the hba regex), a compromised maintenance unit of one tenant can drop or lock another tenant's intake DB when it is idle (for example, during a restart). Not possible: disabling RLS or triggers, event triggers, `session_replication_role`, reading source tables.
- Exploit scenario: code execution as `candor-imaint` (a daily/slot job) → lock out or destroy intake databases. Availability and integrity of unrelayed submissions; no confidentiality impact.
- Fix recommendation:
  - pin the hba line to the exact tenant database (`local candor_intake_<t> candor_intake_maint …`);
  - use one maintenance role per tenant DB;
  - `REVOKE CONNECT ON DATABASE postgres, template1 FROM PUBLIC` in provisioning;
  - have the store's open check alert on `datconnlimit <> -1` and on database-level settings;
  - record the residual (DB owner can `DROP`/lock) in SPEC-NOTES/18.

  When the platform moves to PG 17, replace ownership with `GRANT pg_maintain`.
- Status: Open (non-blocking)

#### AUD-RM2-STO-27 — Staged-bundle receive: no peer-credential check, unbounded blocking on a hostile descriptor, and ack not bound to the commit
- Severity: Low
- Location: `crates/candor-intake-store/src/staged.rs` (`receive_staged_bundle`, `receive_message`, `acknowledge_committed`)
- Category: B8.1, B8.3, B7.1 (+ CWE-287, CWE-400)
- Description: the hardening already present covers truncation flags, exact message length, version, exactly one descriptor (surplus closed, `CMSG_CLOEXEC`), `S_IFREG` only (FIFO, socket, device and directory refused; O_PATH or write-only fds fail at `pread`), size equality, shrink/grow detection, a hash over the copied bytes, and the bound to `min(max_len, 16 GiB)`. Gaps:
  - (1) no `SO_PEERCRED` check in this API: it trusts that the caller verified the peer is `candor-sealer` (the doc does not state that duty);
  - (2) a regular file on a FUSE/NFS/slow mount passed by the peer can block `pread` indefinitely. The calls are blocking with no deadline, so a store worker thread hangs;
  - (3) `acknowledge_committed` ignores its `blob` and `EnvelopeRef` arguments (`let _ = …`). `EnvelopeRef` is constructible, so the "ack only after commit" ordering is a convention, not enforced;
  - (4) a crash between `pending.commit` (blob renamed into the store) and the envelope commit leaves an orphan ciphertext blob; nothing garbage-collects it.
- Exploit scenario: a confused or compromised local peer on `istore.sock` (needs the socket's filesystem permissions) fills the blob store, or wedges workers with a FUSE-backed fd. A daemon bug could ack before commit, so the sealer deletes a staged file whose envelope never committed (lost submission).
- Fix recommendation: verify `SO_PEERCRED` uid/gid inside `receive_staged_bundle` (pass the expected uid). Require `fstatfs` `f_type == TMPFS_MAGIC` (the sealer's staging root) or a sealed memfd (`F_GET_SEALS` ⊇ `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW`), which also makes the copy race-free. Set `SO_RCVTIMEO` and run the copy with a deadline. Have `commit_envelope` return a non-constructible commit token, or check in `acknowledge_committed` that an envelope references `blob.blob_id`. Add a startup GC of unreferenced blobs. Re-test in the C-08 daemon audit.
- Status: Open (non-blocking)

### Round-4 summary

| Severity | Open | IDs |
|---|---|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 2 | STO-26, STO-27 (tracked) |
| Info / accepted residuals | — | Lead to record: STO-08 residual 4, STO-14, STO-24(b) ~1-day window, STO-23 filesystem free-space residual, STO-11 anti-wraparound timing |

All §C tools ran clean on 422fbbb (clippy deny set, cargo-deny all four checks, cargo-audit, shellcheck; PG suites in both profiles). Every attacker goal is refuted or linked to a finding.

Gate: **PASS** 2026-10-01 422fbbb, **conditional** on the lead auditor recording the listed residual acceptances (§F.2/§F.3). The two Lows are tracked and do not block. Any later change to the in-scope files voids this PASS (§G).

## Lead dispositions after round 4 (2026-10-01)
- **STO-26 (Low) — closed by deployment rule:** every intake store runs in its own dedicated PostgreSQL cluster (one cluster per tenant intake; never shared across tenants or with Z-CORE). Recorded as ADR-054(1). Within a dedicated cluster the maintenance role's database-owner powers are bounded by `pg_hba` (single peer line) and the connection-time settings check (STO-08).
- **STO-27 (Low) — scheduled for RM-2 wave 2 integration:** the staged-bundle receiver adds SO_PEERCRED (sealer UID only), a per-receive deadline and size/type checks, an acknowledgement bound to the committed transaction id, and orphan-blob cleanup at each slot. Re-audited with the C-06 web service.
- **Accepted residuals (lead):**
  1. The app role can clear `restore_pending` — accepted: an attacker holding the app role already controls the live intake (full intake compromise is covered by ADR-035 detection, not by this flag).
  2. STO-14 (deleted replies stay published ≤ 6 h) — accepted earlier.
  3. Deletion-head replay window ≈ 1 day — accepted: bounded by the signed day+counter; residual exposure is serving already-deleted ciphertext for ≤ 1 day after an old-backup restore.
  4. Old relation files in filesystem free space after VACUUM FULL — accepted with the mitigations of full-disk encryption (17) and SSD discard/TRIM enabled on the intake volume.
  5. Anti-wraparound VACUUM timing — accepted: wraparound vacuums are triggered by transaction counts, not source actions; monitored by the health agent.
- **Gate: PASS (candor-intake-store), subject to STO-27 at wave-2 integration.**

---

## Re-test (round 5) — delta for STO-26/27

Commit `f2f33a37` (on 501b63b); `staged.rs` (900 lines), `pg.rs`/`memory.rs`/`store.rs` (`blob_referenced`), `tests/{pg,staged}.rs`, sealer `server/handover.rs`; SPEC-NOTES decisions 31/32, self-review 14; ADR-054, ADR-055(1).

**Runs:**
- `pg-test.sh` full crate suite: 32 + 18 + 36 + 6 + 19 pass, including `pg_staged_crash_between_copy_and_commit`, `pg_staged_ack_after_commit`, `staged_wrong_peer_uid_refused`, `staged_stream_socket_refused`, `staged_stalled_peer_times_out`, `staged_sweep_fails_closed`, `staged_unknown_outcome_keeps_blob`, `staged_cancelled_commit_keeps_blob`.
- clippy (`-p candor-intake-store -p candor-sealer`, deny set) clean; cargo-deny all ok.
- PG PoC (wrong-tenant `blob_referenced`): see STO-28.
- Scratch build directories were deleted afterwards (disk 8.4 G free).

**Claims verified by code read and tests:**
- **Peer check before any data:** `SO_PEERCRED` uid = `sealer_uid` (no default) is checked before `recvmsg`, followed by a `SOCK_SEQPACKET` check.
- **Socket deadlines:** `SO_RCVTIMEO` before receiving, `SO_SNDTIMEO` before each answer, clamped 10 ms..60 s.
- **Descriptor rules:**
  - exactly one control message, `SCM_RIGHTS` only, exactly one fd; surplus fds are closed;
  - `TRUNC`/`CTRUNC` refused; exactly 41 bytes;
  - `1 ≤ len ≤ min(max_len, 16 GiB)`;
  - `S_IFREG`, and `F_GET_SEALS ⊇ WRITE|GROW|SHRINK|SEAL`, which only sealable memfds pass, so FUSE/NFS/disk files are refused;
  - `st_size = len`;
  - `pread` copy, then an EOF probe and a constant-time SHA-256 check before the safefs commit.
- **Ack token:** `0x01` only via `acknowledge(CommittedStaged)`. The token has private fields, is not `Clone`, and is minted only after `commit_envelope` returns `Ok` for an envelope whose bundle object (index 1), and only it, names the blob with `padded_size = len`. A `Backend` error is retried once; if that also fails, or the future is dropped, the blob is marked uncertain and protected for one sweep.
- **Sweep:**
  - runs at startup (after `purge_incomplete`) and per slot;
  - lists the directory first, then snapshots the registry;
  - removes only blobs that are not in flight and that `blob_referenced` reports `false`;
  - any lookup error aborts with nothing removed;
  - candidates and removals are CSPRNG-shuffled, at most 1,024 checks and 64 removals per slot;
  - safefs sets directory times to the slot; nothing is logged.

  `PgIntakeMaintenance::blob_referenced` fails closed, and the app role reads `envelope_part` with no new grant.

**ADR-055(1) interop:** the sealer's `BundleWriter` makes a `memfd_create(CLOEXEC|ALLOW_SEALING)` and adds all four seals. `send` uses the same 41-byte header and one `SCM_RIGHTS` fd; `await_ack` accepts exactly one byte `0x01` and refuses any fd. The two sides are compatible. Note (Info): the sealer's `ACK_TIMEOUT` (60 s) can be shorter than the store's worst case (two commit attempts × 30 s `statement_timeout` + fsync). The sealer may then fail a seal whose envelope did commit, which is fail-safe for the source (it retries; a duplicate group is refused) but leaves one extra committed envelope. Also, `hand_over` is not yet called from the sealer's seal path (integration pending; re-check in the C-07/C-08 daemon audit).

**ADR-054 (STO-26):** `deploy/intake/postgresql/pg_hba.conf` now pins each role to the exact `candor_intake_TENANT` database, and every other connection is rejected. The maintenance login therefore cannot reach a second database to `DROP` the intake DB, and with one cluster per tenant there is no cross-tenant reach. Database-level settings and `CONNECTION LIMIT` set by the owner are detected by `config-check` (`deploy/tests/validate.sh`). Residual: the owner can still lock out connections or set DB defaults (detected, fail closed; DoS only). **STO-26 Closed.**

**STO-27: Fixed**, apart from the variant below.

#### AUD-RM2-STO-28 — `blob_referenced` fails open when the tenant context does not match; the orphan sweep would then delete bundles of committed envelopes
- Severity: **Medium** (silent loss of committed submission attachments on a configuration error; violates "fail closed")
- Location: `crates/candor-intake-store/src/pg.rs` `IntakeStore::blob_referenced` (uses `begin_raw()`, which only sets `candor.tenant_id`, with no `intake_meta` visibility check); called by `StagedReceiver::sweep` / `startup`
- Description: RLS hides every `envelope_part` row unless `intake_meta` is visible for the configured tenant. With a wrong tenant id, or an uninitialised or re-initialised database next to an existing blob directory, `SELECT EXISTS(…)` returns `false` rather than an error. PoC on a live PG 16 cluster: after a commit as tenant A, `blob_referenced(bundle)` = `Ok(true)` as tenant A. A store opened with tenant B opens successfully (`serving_allowed` = `NotInitialized`), but `blob_referenced(bundle)` = `Ok(false)`. `startup()` runs the sweep before any operation that would surface `NotInitialized`, so up to 64 referenced bundles per slot would be removed. Their envelopes are later relayed with a missing ATTACHMENT_BUNDLE blob.
- Fix recommendation: run the check inside `self.begin(false)` (which requires the tenant's `intake_meta` row, `NotInitialized` otherwise), so the sweep aborts. Optionally, the sweep should also refuse while `restore_pending` is unresolved. Add a regression test: wrong-tenant and uninitialised stores make `sweep` return an error with the file kept. `MemoryStore` should likewise error when not initialised.
- Status: Open

| Severity | Open after round 5 |
|---|---|
| Critical / High | 0 |
| Medium | 1 (STO-28) |
| Low / Info | residuals listed in round 4 (lead to record) |

Gate: **FAIL** 2026-10-01 f2f33a37, on STO-28 only (one-line fix + test). STO-26 and STO-27 are closed. The earlier residual acceptances are still pending with the lead.

---

## Re-test (round 6) — delta: STO-28 and the commit-time cap

Working tree on `ff8b5c4` (`pg.rs`: `begin_commit`, `SQL_COMMIT_SCOPE`, `db_commit`, `APP_ACQUIRE_TIMEOUT`, `StoreError::Timeout`, `blob_referenced` via `begin(false)` + tenant check; `tests/pg.rs`). Scratch builds were removed afterwards (8.0 G free).

**Runs:**
- `pg-test.sh` full suite: 32 + 18 + 37 + 6 + 19 pass, including `pg_staged_crash_between_copy_and_commit` (now with the STO-28 wrong-tenant and empty-DB assertions) and `pg_staged_stalled_commit_refused`.
- clippy deny set clean.
- PG 16 PoC (scratch crate, real `PgIntakeStore`):

| Case | Result |
|---|---|
| Baseline commit | `Ok`, 12 ms |
| Another session holds `ACCESS EXCLUSIVE` on `candor.envelope` | `Err(Timeout)` after **2.52 s**; nothing committed |
| Pooled backend `SIGSTOP`ed (stand-in for a backend stuck in I/O) | `Err(Timeout)` after **5.00 s** (sqlx test-before-acquire + 5 s `acquire_timeout`) |
| Host write throughput for reference (`dd` 1 GiB, `conv=fsync`) | ≈ 131 MB/s |

**STO-28: Fixed.** `blob_referenced` now runs under `begin(false)` (tenant row required → `NotInitialized`) and compares the tenant (`TenantMismatch`). The regression test, as tenant B on A's database and on an empty initialised-schema database, gets `Err(NotInitialized)`; `sweep`/`startup` return an error and the blob list is unchanged; the correct tenant still gets `Ok(true)`. Info: `MemoryStore::blob_referenced` returns `Ok(false)` when not initialised. It is test-only but public, so make it return `NotInitialized` for parity.

**Commit cap — does the bound hold on PG 16?**
- **Yes for what the server can enforce.** `SET LOCAL statement_timeout = lock_timeout = 2500ms` applies from the statement after the scope statement onward (6 statements ≤ 15 s), and acquire ≤ 5 s. Lock waits and a non-responsive pooled connection end in `Timeout` (PoC).
- **Residuals (Info):**
  - (a) `BEGIN` and the scope statement run under the role's 30 s default (documented).
  - (b) If the backend stalls *after* acquire (uninterruptible I/O, including the `COMMIT` WAL fsync, which runs with interrupts held), neither server timers nor the client bound it (sqlx has no per-query client deadline). The sealer's 60 s then expires first. This is fail-safe: no `0x01`; the blob is kept by the DB reference check if the commit landed. Optional hardening: a monotonic client deadline (`tokio::time::timeout`) around each attempt, with expiry treated as `Uncertain` (the existing `CommitGuard` path).
  - (c) Classifying a `57014` on `COMMIT` as a definite refusal is correct in practice (PG 16 holds interrupts through `CommitTransaction`, and a cancel arriving after it is ignored while reading the next command), and blob safety does not depend on it (the orphan is still DB-checked before removal).

**Timeout refuses cleanly:** `Timeout` → `commit_staged` marks the blob `Orphan` (no retry) → the caller sends `0x00`. The sweep removes the blob only after `blob_referenced` = `false`. The builder's test asserts nothing was committed and the orphan was swept once the lock was released.

#### AUD-RM2-STO-29 — The "copy ≤ 4 s" term of the 45 s budget is not enforced, and the defaults violate it
- Severity: Low (fail-safe: the sealer reports failure and nothing is lost; but the lead's bound does not hold, and large real submissions can fail repeatedly, prompting a source to retry over Tor)
- Location: `crates/candor-intake-store/src/staged.rs` (`StagedReceiver::new(…, max_len)`: bound only by `MAX_PART_PADDED_SIZE` = 16 GiB; copy + safefs fsync happen inside the sealer's ack wait); `crates/candor-sealer/src/server/mod.rs:124` (`max_bundle_bytes: 4 << 30`); `handover.rs` `ACK_TIMEOUT` = 60 s, measured from `send`; SPEC-NOTES decision 32 ("deploy must size `max_len` …")
- Description: the sealer's 60 s starts before the store's copy. The copy budget left after the store's own worst case is 60 − 40 (two attempts) − ε ≈ 20 s, while the decision assumes ≤ 4 s. At the measured ~131 MB/s, a 4 GiB bundle (the sealer default) copies and fsyncs in ≈ 30 s+, so the worst case is ≈ 70 s+ > 60 s. Even the 4 s assumption only holds up to ≈ 0.5 GB on such a disk. No code relates `max_len`, disk throughput and `ACK_TIMEOUT`.
- Fix recommendation (pick one):
  - **(1) Two-phase ack (preferred):** the store sends `0x02` ("copied, committing") right after the safefs commit. The sealer waits for `0x02` with a length-scaled deadline (`base + len / floor_throughput`, e.g. 10 s + len / 50 MB/s), then for `0x01` with the fixed 60 s. Keep the `0x01` token rule. Tests: a 1 GiB bundle succeeds; a stalled copy fails within the scaled deadline.
  - **(2) Enforced cap:** a single signed-profile constant `staged_copy_budget_bytes` (e.g. 512 MiB at a 128 MB/s floor) that both `StagedReceiver::new` (`InvalidInput` if `max_len` exceeds it) and the sealer's `max_bundle_bytes` must respect, with larger submissions split or refused up front by the web UI.

  Either way, record the throughput floor as a deploy requirement checked by `config-check`.
- Status: Open (non-blocking)

| Severity | Open after round 6 |
|---|---|
| Critical / High / Medium | 0 |
| Low | STO-29 (new) |
| Info | MemoryStore not-initialised parity; commit-cap residuals (a)–(c) above |

Gate: **PASS** 2026-10-01 (working tree on ff8b5c4; it must be committed unchanged, or the PASS is void per §G). STO-28 is closed and the commit cap is verified within the limits stated. STO-29 is tracked for the sealer/store owners. The residual acceptances from round 4 are still pending with the lead.

## Lead dispositions after round 6 (2026-10-01)
- **Gate: PASS** at the commit that records this section. STO-26, STO-27 and STO-28 are closed.
- **STO-29 (Low): scheduled for wave-2 integration (C-5, when `hand_over` is wired into the seal path).**
  - The store sends an interim `0x02` ("copied") after the copy.
  - The sealer uses a length-scaled copy deadline (base plus `len / min_copy_rate`), followed by the fixed 60 s commit deadline.
  - Both sides enforce a single bundle-size cap.
  - Re-audit together with the C-06 web service.
- **Info:**
  - `MemoryStore::blob_referenced` will be made fail-closed when the store is uninitialised (done in the same change).
  - The 30 s role default during `BEGIN`/setup is accepted, because the sealer's 60 s bound applies and it fails safe.

---

## Re-test (round 7) — delta: VACUUM FULL test, `F_SEAL_EXEC`, MemoryStore fail-closed

HEAD `e9e6a1a` (no uncommitted changes in the crate). Compared against `ff8b5c4`.

**Runs:** `pg-test.sh` full suite 32 + 18 + 37 + 6 + 20 pass. `pg_vacuum_full_erases_old_images` was run **30× in one cluster: 30 pass / 0 fail**.

**1) `pg_vacuum_full_erases_old_images`: accepted, no weakening.**

| Aspect | Old (ff8b5c4) | New (e9e6a1a) |
|---|---|---|
| Relations | heap + TOAST + all indexes (main fork) | same set (`intake_relations` unchanged) |
| FSM / VM / WAL | not scanned | not scanned (unchanged; FSM/VM hold no tuple data; WAL is the documented 09 §13 residual) |
| Positive control before FULL | 8-byte pattern hits > 0 | the same pattern control **plus** the structural scan must report residue |
| relfilenode changed, content and single slot xmin unchanged | yes | yes |
| After FULL | unanchored 8-byte search for `[old xmin][slot xid]`, `[chunk_id][0]` (TOAST), `[va_valueid][toastrelid]` anywhere | per page: every byte outside header, line-pointer array, `LP_NORMAL` items and special space must be **zero** (strictly stronger for free-space residue, any pattern); live heap/TOAST tuples must not carry an old xmin; TOAST chunks and TOAST-index keys must not carry an old chunk id; heap items must not hold an old TOAST pointer |

- Only one assertion was dropped: the unanchored header search *inside live items*. PostgreSQL never copies a pre-rewrite tuple image into a live tuple's data, so this loses no detection.
- Index items other than TOAST-index keys are not inspected, but stale index bytes can only sit in free space (now required to be zero) or in `LP_DEAD` items. `LP_DEAD` items are not marked covered, so they fail the zero check: the scan is conservative and cannot falsely pass.
- The `_bt_slideleft` exception accepts exactly one copy of the last line pointer (an offset/length, no data), which matches nbtree's sort-build behaviour in PG 16.

**Root cause:** plausible and consistent with the ~1/30 rate.
- Test xids and OIDs are small, cluster-wide counters shared by many test DBs. With ~15 old xids, `[old xmin LE][slot xid]` needs only the two high bytes (zeros, often alignment padding) plus two low bytes of preceding data (a signature tail) to match before a new header with `xmin = slot`: about #old / 65,536 per live tuple × hundreds of tuples ≈ 1/30.
- `[chunk_id][0]` similarly matches a new TOAST header whose `xmin` equals an old chunk OID.
- Independent corroboration: my round-4 raw-page PoC found 0 hits after `VACUUM FULL` on a fresh database.

No real residue is hidden.

**2) `F_SEAL_EXEC`: Fixed.** `REQUIRED_SEALS` now includes `EXEC`. The negative variant "no SEAL_EXEC" is in `staged_bundle_hostile_variants_refused`, and fixtures use `MFD_NOEXEC_SEAL`, so the missing-seal variants are not masked by implied seals. The sealer's `BundleWriter` uses `MFD_NOEXEC_SEAL` and adds `EXEC` (interop OK). Info: `MFD_NOEXEC_SEAL` needs Linux ≥ 6.3; the sealer fails closed with `EINVAL` on older kernels, so the H-INTAKE kernel floor must be recorded (deploy, alongside DEP-29 `vm.memfd_noexec = 2`).

**3) MemoryStore: Fixed.** `blob_referenced` calls `st.meta()?` → `NotInitialized`; `staged_sweep_uninitialised_memory_store_fails_closed` passes and nothing is deleted.

Open after round 7: Critical/High/Medium 0; Low: STO-29 (tracked). Gate: **PASS** 2026-10-01 e9e6a1a. The residual acceptances from round 4 are still pending with the lead.

## Lead note after round 7 (2026-10-01)
- **Gate: PASS at e9e6a1a.**
- The round-4 residual acceptances were recorded under "Lead dispositions after round 4" above, as five accepted residuals plus the STO-26 closure via ADR-054.
- **Kernel floor:** Linux ≥ 6.3 is required for `F_SEAL_EXEC`; it is assigned to deploy (manifest plus a host check).
- **STO-29 (Low):** tracked for wave 2.
