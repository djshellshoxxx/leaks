<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-intake-store — SPEC-NOTES

Component C-08 (Intake Store). Sources: 09-DATABASE.md §5.1, §8, §10, §11; 07-BACKEND.md §5.3, §5.4, §6.3, §12; 08-API.md RL-01..RL-12, SA-19/SA-20, §3.8; ADR-009/010/033/034/038/039/046(1)/047(2,3,9)/052; research/R7 §E; process/audits/AUDIT-RM2-intake-store.md.

## Scope

**Delivered:**
- the `IntakeStore` trait (owner of the intake persistence interface);
- `PgIntakeStore` (sqlx 0.9, PostgreSQL 16);
- `MemoryStore`;
- the signed deletion list;
- the fetch-all dead-drop pages;
- the KD snapshot high-water mark;
- monthly counters (flushed at import slots) and backup/restore content;
- the separate maintenance handle (`PgIntakeMaintenance`);
- the schema lint;
- the test cluster script.

**Not in this assignment (left for the C-08 daemon / follow-ups):**
- Tier V `upload` / `upload_chunk` tables;
- `config_bundle` (RL-07);
- `job_local`;
- tmpfs staging;
- blob file I/O (`candor-safefs`);
- the SEQPACKET IPC and the TLS 1.3 relay endpoint;
- `ACCOUNT_ROTATE` beyond the account-row update (`update_account`; reply-stanza replacement belongs to the daemon);
- typed audit events (`candor-log`);
- encryption of the RL-10 snapshot to the Backup Key;
- 24 §TEL suppression of RL-09 counters.

None of these weaken anything here. Tables that do not exist cannot leak.

## Implementation decisions

1. **`lookup_tag` = `locator_hash`.** 04 §11.4 calls it `lookup_tag`; 09 §5.1 calls the column `locator_hash`. The column keeps the 09 name and the Rust type is `LookupTag`.
2. **`envelope.epoch_index integer` added** (not in 09 §5.1). RL-02 must send `epoch_index`. 09 says `received_date` is "used only to derive the sealing epoch", but no derivation rule (epoch origin) is specified anywhere, and Tier V clients may seal for a ±1-day-skewed epoch. So the store keeps the epoch the sealer reports. It is weekly granularity, coarser than `received_date`, so it adds no information. *Spec feedback:* add the column to 09 §5.1, or specify the derivation.
3. **`intake_meta.restore_pending boolean` added.** BE-074 requires the store to refuse service until the newest deletion list is applied after a restore. A RAM-only flag would be lost on restart and would fail open. While the flag is set:
   - every source operation (`commit_envelope`, `apply_replies`, `lookup_account`, `create_account`, `update_account`, `delete_account`, `delete_replies`, `delete_mailbox`, `mailbox_list`) returns `RestorePending`; relay operations continue (AUD-RM2-STO-09);
   - `serving_allowed()` is false (RL-01 `restored`, C-06 busy page);
   - `PgIntakeStore::open` sets it on every initialised store at process start (failover to a recovered node, AUD-RM2-STO-05); `mark_restore_pending()` sets it for the runbook.
4. **Own migration runner and ledger `candor.schema_migration(version, sha256)`.** sqlx's `_sqlx_migrations` has `installed_on timestamptz`, which violates L11 (no time columns in the intake DB). Migrations:
   - are embedded with `include_str!` and are forward-only;
   - each run in a transaction with `lock_timeout = 10s` and `statement_timeout = 10min` (R7 SI-E-06);
   - are checked for drift by SHA-256. A changed applied migration is refused by both `migrate` and `open`.

   `intake_meta.schema_hash` = `SHA-256("candor/v1/intake/schema" ‖ Σ(u32be version ‖ SHA-256(sql)))` is written at `init` and checked at `open` (BE-050). `migrate()` is for `candorctl migrate` only. The service never migrates at start.
5. **RLS on every intake data table (stricter than 09).** 09 §5.1 says "no RLS needed (single tenant per DB)". R7 SI-E-03 and the coordinator ask for RLS, so it is added as defence in depth. `ENABLE` and `FORCE` are set on all data tables:
   - `intake_meta` is filtered by `tenant_id = current_setting('candor.tenant_id')`;
   - every other table is visible only while `intake_meta` is visible (an uncorrelated `EXISTS`).

   Every store transaction begins with `set_config('candor.tenant_id', …, true)` (SET LOCAL semantics). A store configured for the wrong tenant sees no rows and can write nothing. "Unique/FK keys include `tenant_id`" does not apply: intake tables carry no `tenant_id` (L11 forbids extra columns), and other tenants live in other databases, so cross-tenant unique probes are impossible. `schema_migration` holds no tenant data and has no RLS. The backup role must also SET LOCAL the tenant.
6. **Query functions, not `query!` macros** (assignment instruction: no live DB at compile time). R7 SI-E-05 prefers macros with a committed `.sqlx` offline cache. Compensating controls:
   - every SQL text is a `const &'static str`;
   - sqlx 0.9 accepts only `SqlSafeStr`;
   - `tests/source_lint.rs` fails if `src/` uses `AssertSqlSafe`, `QueryBuilder` or `format!` in `pg.rs`;
   - all values are bound.

   *Follow-up:* switch to `query!` once CI can produce the `.sqlx` cache.
7. **Deletion-list encodings** (04 §18.6 leaves them open):
   - `del_hash = SHA-256("candor/v1/intake/del" ‖ tenant_id(16) ‖ subject(32))`, where the subject is the `lookup_tag`, `mailbox_id` or REPLY `object_hash`;
   - `entry = u64be seq ‖ u8 kind(1 account, 2 mailbox, 3 reply) ‖ del_hash ‖ u32be del_day`;
   - `sig = Ed25519_K31("candor/v1/intake/deletion-list" ‖ prev_hash ‖ entry)`;
   - `prev_hash(1) = 0³²`;
   - `prev_hash(n+1) = SHA-256("candor/v1/intake/deletion-list" ‖ prev_hash(n) ‖ entry(n) ‖ sig(n))`.

   The relay must use `deletion::verify_chain` (or the same encoding). The label `candor/v1/intake/del` is not yet in candor-core's label registry (*feedback for candor-core owner*). The signer runs inside the DB transaction (`DeletionSigner`), because only that transaction knows the chain head.
8. **Dead-drop page format and lifecycle (AUD-RM2-STO-06/07).** Each entry is exactly 70,000 B: `u32be len ‖ reply_ct ‖ CSPRNG fill`, so `reply_ct ≤ 69,996 B` (09 says ≤ 70,000; the 4-byte prefix of 04 §13.5 must fit).
   - The set is a sequence of **generations**, one per fixed import slot (`generation = day × slots_per_day + index`). `rebuild_published_set(slot)` adds exactly K = `per_slot` entries: up to K pending real replies (oldest `available_day` first), topped up with fresh dummies; excess reals wait for the next slot. Missed slots are back-filled with dummy generations; the first publication back-fills the whole 30-day window. A repeated slot adds nothing.
   - Dummies are stored as `reply` rows (`source_account_id` NULL) exactly like Tier V replies, live exactly as long as real entries (same `available_day` = generation day, same expiry) and are never regenerated, also across restarts. `reply.pub_gen` records the generation (NULL = awaiting publication, 0 = padding pool).
   - The window therefore always holds K × 30 × `slots_per_day` entries; the page count is the next power of two of that (a constant of `DeadDropConfig`), and a persistent padding pool fills the last page. Two rebuilds differ by exactly K added and K expired entries whatever the real volume (tests `conf_dead_drop`).
   - Positions are uniformly random over **all** `page_count × 64` positions at every rebuild. `set_version` is a fresh random u64 per rebuild.
   - Pages are built once per rebuild and held in RAM as shared immutable buffers; every requester gets byte-identical pages and nothing about access is recorded.
   - Memory: `DeadDropConfig::validate` refuses more than `HARD_MAX_PAGES` = 128 pages (≈ 573 MB, the 08 SA-19 EE figure; peak ≈ 2 × during a rebuild). Pages are reserved with fallible allocation and filled by streaming 256 rows at a time; overflow is the typed `StoreError::Capacity`, never an OOM abort. The backlog of unpublished replies is bounded by `max_pending` (≤ 100,000); RL-05 rejects beyond it.
   - Implementation decision: the PostgreSQL store requires an explicit `DummyReplies` (no `RandomDummyReplies` default); production passes real-format sealed dummies.
9. **Window and expiry share one boundary.** A reply is published and retained iff `today − available_day < retention` (≤ 30). `expire_replies` clamps any retention above 30 down to 30.
10. **Tier W slots.** The store assigns the lowest free slot 0..31. If all 32 slots are taken, the reply is listed in `rejected` and the relay keeps it in `reply_outbox` for a later slot.
11. **Claim order and limits.**
    - Candidates are ordered by `(release_day, envelope_ref)`: the oldest released envelope goes first, so a high random ref cannot starve (AUD-RM2-STO-16); `release_day` is day-granular and never sent.
    - The first candidate is always taken, even if it alone exceeds `max_bytes`, so a large envelope cannot block the queue forever.
    - An ack listing a digest outside the batch changes nothing.
    - On ack, unacked envelopes of the batch return to the pool and the batch closes.
    - RL-02 `ref` is the intake-local `envelope_ref`. A re-offered envelope keeps its ref, which carries the same information as its unchanged `sha256`.
    - Bytes per group for `max_bytes` = three slot blocks + three padded blobs.
12. **Snapshot rollback rules (BE-060, RL-06).** Signature, witness and consistency verification belong to the KD verifier. The store enforces, atomically under a row lock:
    - `tree_size ≥ hwm`;
    - `checkpoint_day ≥ day_hwm`;
    - `version > directory_version`;
    - `consistent_from == hwm` (the proof must start from the stored mark).

    A re-push of the identical current snapshot returns `AlreadyInstalled`. Only the current and previous versions are kept. A DB trigger additionally refuses any decrease of `kd_tree_size_hwm`, `kd_checkpoint_day_hwm`, `directory_version`, `relay_req_counter` or `last_batch_no`.
13. **Quota (AUD-RM2-STO-01, ADR-052(14)).** Removed from the database: no `quota_bucket` column and no quota API. The daily upload quota lives in C-06/C-07 process RAM (a restart resets it, which is availability-only).
14. **Fixed sizes enforced:**
    - `disposition_ct` = 1,168 B (X-Wing Nenc 1,120 + 48; STD only, since FIPS is unsupported by candor-core);
    - `xwing_pk` = 1,216 B;
    - `prefs_ct` 1..4,096 B;
    - `size_bucket` 1..16 (REPLY buckets 4096·k).

    Part `padded_size` legality (ADR-011 bucket) is checked by the sealer/web, because the ciphertext overhead depends on the object format. The store only bounds it to 1..16 GiB.
15. **Deletions.**
    - Account deletion deletes the account and its replies (envelopes carry no account reference, ADR-052(2)).
    - `delete_mailbox` takes the reply refs from the caller, because the store has no mailbox column.
    - `deletion_list_after(after)` records `after` (the relay's last copied seq) as `intake_meta.deletion_acked_seq` (monotonic, ≤ head, trigger-enforced); `after` above the head is `InvalidInput` and records nothing (AUD-RM2-STO-10). Returned `relayed` = stored flag OR `seq ≤ acked`.
    - **Append-only for the application role (AUD-RM2-STO-03).** `candor_istore` has `SELECT, INSERT` and a column `UPDATE (relayed)` that the trigger allows only as an unchanged rewrite (import-slot rewrite). Only the separate maintenance role `candor_intake_maint` may flip `relayed` (only for `seq ≤ deletion_acked_seq`) and `DELETE` (only relayed entries, never `seq = max(seq)`); the trigger checks `current_user`. Retention rule (documented, enforced by `PgIntakeMaintenance::prune_deletion_list`): delete flagged entries with `del_day < today − 35`, never the head. The maintenance role runs in a separate process under its own OS user; `PgIntakeStore::with_maintenance` exists for tests and single-process setups.
    - No `SECURITY DEFINER` function is used (09 §10 allow-list): separation is by role, grants and trigger.
16. **Restore.**
    - `restore_backup` requires an empty store.
    - Counters and the KD high-water mark keep the higher of the backup and current values.
    - `apply_pushed_deletion_list(entries, core_head, k31_pk, hasher)` (AUD-RM2-STO-04/12): signatures (strict Ed25519 under K31) and internal chain are verified **before** the row lock; under the lock the run must end exactly at the relay-asserted Z-CORE head `core_head` (no truncation), be non-empty when `core_head > 0`, have `core_head ≥ deletion_acked_seq`, start no later than local head + 1 (no gap), link to the local entry before it or overlap the local list (unanchored only when the local list is empty), match every overlapping entry (no fork), link each filled hole to its local successor, and leave a contiguous merged list. Lookups are `BTreeMap`/`HashSet` (no quadratic work). Any validation failure **persists** restore-pending, also on a serving store. Then newer entries are merged and every listed account (by `del_hash` of `locator_hash`) and listed reply (by `object_hash` via `ReplyObjectHasher`; the default `CoreReplyHasher` uses candor-core's `object_hash` over the first 160 bytes of `reply_ct`) is deleted.
    - `MAX_PUSHED_DELETION_LIST` lowered to 200,000.
    - `restore_backup` refuses a backup whose `kdf_salt` differs from an initialised target (`Conflict`, AUD-RM2-STO-15) and validates the whole backup before writing.
    - The deletion list inside a backup is not re-verified at restore (the backup is authenticated by the backup system, 19). The pushed Z-CORE copy is verified.
17. **Durability.** `commit_envelope` returns after `COMMIT`. With `fsync = on` and `synchronous_commit = on` (the default), that means after the WAL flush (ADR-046(1), BE-071). *Spec feedback:* add `synchronous_commit = on` to the 09 §10 intake hardening table. Blob files must be fsynced by the caller **before** `commit_envelope`. `ack_batch` returns the blob ids the caller must delete (BE-014).
18. **Roles in the migration.** Roles are created idempotently in a `DO` block, which needs CREATEROLE: test clusters run it as superuser; production provisions the roles at deployment with the same attributes (ADR-052(9): `candorctl migrate` runs as OS user `candor-migrate`, peer-mapped to the migration role). The migrator receives `CREATE ON DATABASE` and owns every object. `candor_istore`, `candor_intake_maint` and `candor_intake_backup` own nothing and have `NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION`. They get per-database `search_path = candor`. The app and maintenance roles get `statement_timeout 30s` and `idle_in_transaction_session_timeout 60s`, and `temp_file_limit 1GB` (superuser-only setting: applied by the migration when run as superuser, else by provisioning); the backup role gets `default_transaction_read_only`. The app role's `intake_meta` UPDATE is column-level (no `tenant_id`, `schema_hash`, `kdf_salt`, `config_version`); the trigger also makes tenant, salt and schema hash immutable (AUD-RM2-STO-08).
    - `open` (both roles) re-asserts `statement_timeout`, `idle_in_transaction_session_timeout` and `lock_timeout` as connection options (a role can rewrite its own defaults), and refuses: superuser, BYPASSRLS, membership in any role owning a `candor` table, membership in the other intake role, any data table without `ENABLE`+`FORCE` RLS, and a disabled guard trigger.
19. **L11 wording conflicts with 09 §5.1.** L11 bans `kind` and `last_*` columns, but §5.1 itself defines `deletion_list.kind` and `intake_meta.last_batch_no`. The lint exempts exactly those two (*spec feedback*).
20. **Concurrent migrations.** Cluster-wide role DDL races ("tuple concurrently updated"), so tests serialise `migrate`. Production runs one `candorctl migrate` at a time.
21. **Fixed-shape envelope groups (ADR-052(1)).** An envelope row is one group of exactly three objects in order (main SUBMISSION/SOURCE_MESSAGE, ATTACHMENT_BUNDLE, IDENTITY). Each `envelope_part` row (part_no 0..2) holds the object's `object_hash`, its RecipientSlotBlock (exactly 18,692 B, STD) and its blob reference. 09's `header_ct`/`manifest_ct` columns are replaced (the sealer emits sealed objects with slot blocks, `candor-sealer` `EnvelopeObject`). The relay ack digest is `group_sha256 = SHA-256("candor/v1/intake/group" ‖ object_hash₀ ‖ object_hash₁ ‖ object_hash₂)` (`types::group_digest`); RL-02 carries the three object hashes and padded sizes; RL-03 selects `SlotBlock(i)` or `Object(i)`. Blob ids and object hashes within a group must be distinct.
22. **Accounts separate from envelopes (ADR-052(2)).** Envelope rows carry no account reference. `create_account` (also used by chaff for dummy accounts), `update_account` (passphrase rotation: tag, keys, prefs) and `purge_inactive_accounts` (09 `inactive_purge`: `activity_month` started ≥ 365 days ago; abandoned real and dummy accounts expire alike) are separate operations. This supersedes ADR-034's "account in the same transaction as the first envelope".
23. **Import-slot rewrite and activity (AUD-RM2-STO-01).** Account rows change only on create, update (rotation), delete and `uniform_rewrite(slot, counters, active_accounts)`. The web records active accounts (envelope commit) in RAM, like quota, and flushes them at the slot: `activity_month` becomes the slot's month for those accounts and the month of any stored reply ≤ the slot day for Tier W reply arrivals. In the same transaction the RAM-accumulated `counter_month` deltas are added (all-or-nothing, overflow checked in SQL without raising) and every row of `source_account`, `envelope`, `envelope_part`, `reply`, `deletion_list`, `counter_month`, `directory_snapshot` and `intake_meta` is rewritten, so all share one `xmin` (test `pg_uniform_rewrite_xmin`). `counter_add` was removed: counters can no longer be written next to a real envelope. Call order at each slot: relay work (claim/ack, RL-05, RL-11), `rebuild_published_set`, then `uniform_rewrite` last.
24. **Day coarsening (AUD-RM2-STO-01).** `directory_snapshot.applied_day` is stored as the first day of the month (spec gives no granularity; CHECK enforced). `reply.available_day` is the import-slot day: RL-05 runs only in slots, and publication resets it to the generation's slot day; it stays a day because the 30-day retention and window are day-based (09 "Day granularity"). `deletion_list.del_day` stays the deletion day: it is signed into the chain and Z-CORE computes its own 35-day retention from it (09 §5.2.7), so a month would shorten Z-CORE retention (a weakening); see spec feedback. `envelope.received_date` stays a day (09). After the slot rewrite these days anchor only the slot's `xmin`.
25. **Migration 0001 amended in place.** No intake database has been deployed from this crate (the step has not passed its audit gate), so the fixes amend `0001_intake_schema.sql` rather than adding 0002; the ledger hash changes accordingly.

## Spec feedback (for the lead; specs not edited)

- 09 §5.1: add `envelope.epoch_index`, `intake_meta.restore_pending`, `intake_meta.deletion_acked_seq`, `reply.pub_gen` and `schema_migration` (decisions 2, 3, 4, 8, 15); drop `source_account.quota_bucket` (decision 13); replace `envelope.source_account_id/header_ct/manifest_ct/header_sha256` and `envelope_part` with the group shape of decision 21; `directory_snapshot.applied_day` at month granularity (decision 24); DB-013's "updated on envelope commit or reply arrival" becomes "folded in at the import-slot rewrite" (decision 23); ADR-034's same-transaction rule is superseded by ADR-052(2).
- 08 RL-02/RL-03: group descriptor (three object hashes and padded sizes, group digest) and part selectors `slot_block/{i}`, `object/{i}` (decision 21).
- 08 RL-11: `after` above the intake head → `bad_request`; RL-12: add `head_seq` (the Z-CORE head) to the request body so the intake can reject a truncated or empty copy (decision 16).
- 08 §3.8 / ADR-039: define the dummy lifecycle (generations of K entries per import slot, 30-day lifetime, never regenerated; `DeadDropConfig` per profile) and the page count as a configuration constant (decision 8).
- 09 §5.1 `deletion_list.del_day`: allow the import-slot date (or month, with Z-CORE retention computed from the end of that month) so that the signed list does not carry the exact deletion day (decision 24).
- 09 §13 residuals: add row `xmin`/`xmax`/`ctid` (now slot-granular after the rewrite, finer between slots), dead tuples until vacuum, and PostgreSQL cumulative statistics (`last_autovacuum`, `n_tup_*`; reset daily by the maintenance role).
- 09 §10: add the maintenance role `candor_intake_maint` (deletion-list prune, `pg_stat_reset`) and the intake logging settings below.
- 09 §8 L11: exempt `deletion_list.kind` and `intake_meta.last_batch_no`.
- 09 §10: add `synchronous_commit = on`, `log_parameter_max_length = 0` and `log_parameter_max_length_on_error = 0` for the intake profile.
- 04 §18.6: fix the entry/chain encoding (decision 7) and register `candor/v1/intake/del` in the candor-core label registry.
- **Mailbox entries on restore (residual).** A `mailbox` deletion entry cannot be applied to replies **already stored** on a node recovered from an older disk, because `reply` has no mailbox column. Such entries are enforced at deletion time (same transaction) and on every later RL-05 arrival. Stale Tier W replies of a deleted mailbox on a recovered EE-HA node would persist until 30-day expiry. Options: store `H(mailbox)` on Tier W reply rows (they are already account-linked), or delete all of the account's replies when a mailbox is deleted.
- Deletion-list retention (35 days) vs reply retention (30 days): a push of a reply to a mailbox deleted more than 35 days earlier is no longer dropped by the intake. Z-CORE drops `reply_outbox` rows whose mailbox is listed (09 §5.2.7), within the same 35 days.

## Deployment settings (for the deploy owner; AUD-RM2-STO-02/08/11, ADR-052(9)/(14))

The store guarantees that no expected path raises a server error, but PostgreSQL still logs unexpected errors and its own events. For the intake cluster:

| Setting | Value | Why |
|---|---|---|
| `log_min_messages` | `panic` | no ERROR/WARNING line with a `%m` timestamp for any source action |
| `log_min_error_statement` | `panic` | no SQL text |
| `logging_collector` | `off` | no log files |
| server stderr | discarded (`StandardError=null` / `pg_ctl -l /dev/null`) | ADR-052(14) |
| `log_statement`, `log_connections`, `log_disconnections` | `none`, `off`, `off` | 09 §10 |
| `log_parameter_max_length`, `log_parameter_max_length_on_error` | `0`, `0` | no bind values |
| `log_line_prefix` | no `%m`/`%t` if any logging is ever enabled | timestamps |
| `synchronous_commit`, `fsync` | `on`, `on` | ADR-046(1) |
| `temp_file_limit` (roles `candor_istore`, `candor_intake_maint`) | `1GB` | 09 §10; superuser-only, set at provisioning |
| `GRANT EXECUTE ON FUNCTION pg_catalog.pg_stat_reset() TO candor_intake_maint` | provisioning (superuser) | daily statistics reset |
| `track_counts` | `on` (autovacuum needs it); stats directory on encrypted storage | residual below |
| `pg_hba.conf` | `local` peer lines only: `candor-migrate` → migration role, intake web/sealer user → `candor_istore`, maintenance user → `candor_intake_maint`, backup user → `candor_intake_backup` | ADR-052(9) |

Jobs: at each fixed import slot (relay control cycle) `rebuild_published_set(slot)` then `uniform_rewrite(slot, counters, active_accounts)`; daily, as the maintenance OS user, `prune_deletion_list(today)` and `reset_statistics()`; daily `expire_replies` and `purge_inactive_accounts` through the app role. At process start the daemon must call `apply_pushed_deletion_list` (RL-01 reports `restored` until then) and `rebuild_published_set` for the current slot.

## Dependencies

| Crate | Version | Why |
|---|---|---|
| candor-core | path | Ed25519 strict verification and signing for K31 (`sig`); `CoreHeader`/`object_hash` for the default reply hasher. |
| sqlx | =0.9.0, `runtime-tokio`, `postgres`, `uuid`; no defaults, no TLS, no macros, no sqlite/mysql | Spec-mandated DB toolkit (09 §11). Postgres over a Unix socket. ≥ 0.8.1 for RUSTSEC-2024-0363. |
| tokio | =1.48.0, `sync` (dev: `rt`, `macros`) | Async runtime required by sqlx `runtime-tokio`; `RwLock`/`Mutex` for the in-RAM published set and the memory store. |
| uuid | =1.18.1, no defaults | Bind 128-bit random ids to `uuid` columns (sqlx `uuid` feature). No generation features: ids come from getrandom. |
| sha2 | =0.11.0 | `group_sha256`, `del_hash`, chain hash, migration digests. Same version as candor-core. |
| subtle | =2.6.1 | Constant-time comparison of chain hashes and signed entries. |
| zeroize | =1.8.2 | Zeroizing buffers for dummy bodies. |
| getrandom | =0.4.3 | OS CSPRNG (the same pin as candor-core, whose `rand` module is crate-private), with the same all-zero health check. |
| proptest (dev) | =1.11.0 | Property tests. |

**Resolved by ADR-052(7)** (interim pinned skip for `sha2@0.10.9`, expiring 2026-12-30; deny.toml is the lead's). Background: `cargo deny check bans` failed because sqlx-core/sqlx-postgres 0.9.0 depend on `sha2 0.10.9` (SCRAM/MD5 password auth code, unused with peer auth but compiled), and `deny.toml` sets `deny-multiple-versions` for `sha2`. This needs a version-pinned `skip` for `sha2@0.10.9` (with an expiry, as with ADR-051's sha3), or an upstream sqlx move to sha2 0.11. `cargo deny` advisories, licenses and sources pass. sqlx-core also depends on `log`/`tracing` unconditionally. Statement logging is disabled on every connection. The intake processes must not install a `log` logger or a `tracing` subscriber (consistent with the candor-log-only rule).

## Test mapping

| Spec ID | Tests |
|---|---|
| BE-014, RL-02..RL-04, API-047, BE-062 | `conf_claim_ack`, `conf_claim_limits` (both impls) |
| ADR-052(2), BE-056, DB-033 (accounts separate; inactive purge) | `conf_accounts` |
| Input bounds (hostile input) | `conf_envelope_validation`, `conf_reply_rules`, `deaddrop::oversize_body_rejected` |
| BE-063, API-037, API-040, SA-19/SA-20 | `conf_dead_drop`, `deaddrop::page_shape_from_config`, `builder_places_each_entry_once`, `set_version_changes_per_build`, proptests |
| ADR-047(9), KEY-077, RL-11, BE-074, API-054 | `conf_deletion_list`, `conf_backup_restore`, `deletion::tests`, `deletion::props` (arbitrary lists, any bit flip) |
| BE-060, RVW-A-04, RL-06 (rollback) | `conf_kd_snapshots`, `validate::rollback_matrix`, `pg_durability_and_guards` (DB trigger) |
| ADR-052(1)/(2) (groups; accounts separate) | `conf_envelope_validation`, `conf_claim_ack`, `conf_accounts`, `pg_schema_lint_live` |
| AUD-RM2-STO-* regressions | see "Fixes for AUD-RM2-STO" |
| ADR-046(5), L15 | `conf_counters`, schema lint (no per-day table) |
| 07 §5.4 anti-replay | `conf_init_and_meta` |
| DB-007, DB-008, 09 §8 L1–L4, L11–L13 | `lint::migrations_pass_static_lint`, `lint_catches_violations`, `pg_schema_lint_live`, `pg_no_exact_times_stored` |
| L11 `SHOW` (ADR-046(1)), R7 SI-E-04 | `pg_settings` |
| DB-002, R7 SI-E-02 | `pg_roles_and_grants`, `pg_refuses_privileged_role` |
| R7 SI-E-03 RLS isolation | `pg_rls_tenant_isolation` |
| BE-050 | `pg_schema_drift_refused` |
| BE-071 / durability | `pg_durability_and_guards` |
| BE-031 time-lint, R7 SI-E-05, ADR-016 | `tests/source_lint.rs` |

## Security self-review

Checked as an attacker (ASVS 5.0 L3 mindset, BUILD-BRIEF "Security and OPSEC bar"):

- **Metadata.**
  - No column, value or code path holds an IP, User-Agent, circuit data, filename or time finer than a day. Live and static lints prove this for types and names, and `pg_no_exact_times_stored` checks the values.
  - The store reads no clock; `source_lint` forbids it.
  - Commit timestamps are unavailable (`track_commit_timestamp = off`, tested).
  - IDs are 128-bit CSPRNG values.
  - Claim order is `(release_day, random ref)`; `release_day` never leaves the intake.
  - Source actions never write account rows; the import-slot rewrite gives every source-linkable row one `xmin` (live test); quota is RAM-only; counters are written only at the slot.
  - Envelopes carry no account reference (ADR-052(2)).
  - No expected outcome raises a server error, so nothing about a source action reaches the PostgreSQL log (live test with captured log and a positive control).
  - Dead-drop diffs reveal only K added / K expired per slot.
  - `set_version` is random.
  - No per-mailbox access state exists.
  - Debug output of every source-linked type is redacted.
  - Errors carry only static strings. PostgreSQL error details, which can echo `locator_hash` values, are discarded.
- **Logging.**
  - sqlx statement logging is disabled on every connection (tested by source lint).
  - The test cluster uses `log_min_messages=panic`, `log_parameter_max_length*=0`, `log_min_error_statement=panic` and `log_statement=none`; the log goes to a 0600 file only so a test can read it.
  - No `print`, `log` or `tracing` in `src/`.
- **SQL injection.** All SQL is static; no dynamic SQL is possible without `AssertSqlSafe`, which is banned.
- **Least privilege.**
  - The app and maintenance roles are non-owner, NOBYPASSRLS, non-superuser, not members of an owning role or of each other; RLS forced and guard triggers enabled; all verified at `open`.
  - The app role has no TRUNCATE or DDL, no DELETE on `deletion_list`, and column-level UPDATE on `intake_meta` without the identity columns.
  - Only the maintenance role flags and prunes deletion-list entries (acknowledged only, never the head; tested including the two-statement bypass).
  - The backup role is read-only on exactly three tables.
  - DB triggers enforce monotonic counters, immutable identity and the acknowledged-seq bound.
  - Session limits are re-asserted per connection.
- **Network.** Unix socket only: no TLS feature is compiled and there is no TCP in tests (`listen_addresses = ''`, peer auth with an ident map, no host lines).
- **Fail closed.**
  - Restore-pending persists across restarts and is entered at every PostgreSQL process start.
  - Forged, forked, gapped, truncated, unanchored or empty-when-expected deletion lists are rejected, and the rejection persists restore-pending.
  - Every source operation refuses while restore-pending.
  - Schema drift refuses `open`.
  - CSPRNG failure is an error.
  - Unknown enum text from the DB is an `Integrity` error.
  - Oversized inputs are rejected before any DB work.
- **Input handling.**
  - Every external input has an explicit maximum: group shape (exactly 3 objects, fixed slot-block length), part size, reply size, reply count per push, publication backlog, published pages (typed `Capacity`, fallible allocation, streamed build), snapshot body and signatures, pushed list length, deletion page size, claim limits, active accounts per slot.
  - Day values are bounded before date arithmetic.
  - There is no recursion.
  - No `unwrap`, `expect` or indexing on untrusted data (clippy deny set clean).
  - Duplicate refs and blob ids are rejected.
- **Secrets.** The only secret in reach is K31, inside candor-core's zeroizing `SigningKey` (redacted Debug), used through `DeletionSigner`. The KDF salt is public.
- **Residual risks.**
  1. The mailbox-entry restore gap.
  2. `RandomDummyReplies` (tests, `MemoryStore::new`) lacks CoreHeader magic; the PostgreSQL store requires an explicit `DummyReplies`, and production must pass real-format sealed dummies (C-08 daemon), else an observer can tell dummies from real replies by structure.
  3. Between two slot rewrites, rows written since the last slot (new accounts, envelopes, deletion entries) carry their own `xid`, so a live-DB observer sees their order within that interval (≤ one slot spacing), e.g. an account creation adjacent to an envelope commit (diluted by chaff accounts, ADR-052(2)). The rewrite also keeps rows roughly in their physical (`ctid`) order; a periodic owner-run `VACUUM (FULL)`/`CLUSTER` in a maintenance window would erase that (deploy option). Dead tuples and WAL keep old versions until vacuum/recycle (09 §13). Tables with BEFORE UPDATE triggers keep a lock-only `xmax` equal to the rewrite's own `xid` (no extra information; asserted).
  4. A compromised application role can still clear `restore_pending` (the database cannot verify K31 signatures without an extension or a definer function, both excluded by 09 §10); the grants and trigger only stop identity and monotonic-value tampering.
  5. A real reply deleted by its source (or by account deletion) disappears from the published set at the next rebuild while dummies never leave early, so an observer learns that an entry was real and was deleted at that slot (AUD-RM2-STO-14; 08 SA-19 requires removal). The removal is shown only at slot granularity (BE-063).
  6. After a restart, or if a concurrent purge removed rows during a rebuild, missing positions are filled with ephemeral dummies (regenerated at the next rebuild); their number depends only on deletions, not on reply volume.
  7. PostgreSQL cumulative statistics accumulate between daily resets and are written at shutdown (AUD-RM2-STO-11); reset needs the provisioning grant.
  8. Lookup timing for unknown and known `lookup_tag` is the caller's job (BE-010 floor).
  9. Query macros with an offline cache are deferred (decision 6).

## Fixes for AUD-RM2-STO

Every fix has a regression test; "fails on old code" notes how the test catches the pre-fix behaviour.

| Finding | Change | Test(s) |
|---|---|---|
| STO-01 (High) xmin/ctid activity leak | Quota removed from the DB (`quota_bucket`, `quota_consume`, `quota_reset` gone; RAM in C-06/C-07). No per-action account write: `commit_envelope` has no account link at all (ADR-052(2)), `apply_replies` no longer touches the account. `uniform_rewrite(slot, counters, active_accounts)` folds activity and rewrites every row of every source-linkable table in one transaction; `counter_add` removed (counters only flushed at slots). `directory_snapshot.applied_day` = month (decision 24). | `pg_uniform_rewrite_xmin` (mixed workload, then one distinct `xmin` over 8 tables, no foreign `xmax`; account `xmin`/`ctid` unchanged by a commit — old code rewrote the account per commit and had no rewrite op), `conf_activity_fold`, `conf_counters`, `conf_accounts` |
| STO-02 (High) ERROR lines with timestamps | `INSERT … ON CONFLICT DO NOTHING` + row counts for init, accounts, envelopes, parts, replies, deletion entries, snapshots, restore; `update_account` uses `NOT EXISTS`; counter overflow via `ON CONFLICT … WHERE` (no numeric error); all bounds checked in Rust first. Deploy settings listed above. | `pg_no_server_errors_on_expected_paths` (whole conformance suite in databases logging at `warning`, zero ERROR/WARNING/FATAL lines, plus a positive control proving capture — old code logged `unique_violation` for every duplicate), `pg_settings` (`log_min_messages = panic`) |
| STO-03 (Medium) deletion list bypass | App role: no DELETE, `relayed` only as an unchanged rewrite. Maintenance role only flips acknowledged entries and deletes relayed non-head entries (trigger on `current_user`, `deletion_acked_seq`, `max(seq)`). | `pg_durability_and_guards` (two-statement bypass and every variant refused for the app role; head and unacknowledged entries refused for the maintenance role — old code accepted the bypass), `pg_roles_and_grants`, `conf_deletion_list` |
| STO-04 (Medium) gapped/truncated/empty push | `merge_pushed` rules of decision 16 with explicit `core_head`; failures persist restore-pending. | `validate::merge_rules`, `conf_backup_restore` (forged, wrong key, gap, truncated, empty; bad push to a serving store re-enters pending — old code returned `Ok` and served) |
| STO-05 (Medium) failover fails open | PG `open` enters restore-pending on every initialised store; `mark_restore_pending()` for the runbook. | `pg_durability_and_guards` (reopen → not serving until a push ending at the head), `conf_restore_pending_gate` |
| STO-06 (Medium) dead-drop diffing | Persistent generations of exactly K entries per slot, dummies stored and expired like real entries, never regenerated, back-fill, padding pool (decision 8); explicit `DummyReplies` for PG. | `conf_dead_drop` (each rebuild: exactly K added and K expired with 0/3/7/0/2 real replies; repeat slot adds nothing; missed slot adds 2K — old code regenerated every dummy), `deaddrop::generation_plan`, `plan_bounded` |
| STO-07 (Medium) memory | Page count fixed by `DeadDropConfig` (≤ 128 pages, validated), fallible reservation, streamed build, typed `Capacity`; publication backlog bounded by `max_pending`; no count-driven power-of-two growth. | `deaddrop::capacity_bounds`, `conf_reply_backlog` (old code accepted every push and grew the page count) |
| STO-08 (Low) role/startup hardening | Session limits as connection options; `temp_file_limit`; open refuses owner-role or other-intake-role membership, unforced RLS, disabled guard triggers; column-level `intake_meta` UPDATE; tenant/salt/schema hash immutable. | `pg_refuses_privileged_role` (member of migrator, disabled trigger), `pg_roles_and_grants` (`temp_file_limit`, identity columns) |
| STO-09 (Low) deletions while pending | All source operations return `RestorePending`. | `conf_restore_pending_gate` |
| STO-10 (Low) mark beyond head | `after > head` → `InvalidInput`, nothing recorded; acknowledgement is a monotonic, trigger-bounded `deletion_acked_seq`; only the maintenance role flags. | `conf_deletion_list` (`u64::MAX` and `head + 1` refused; prune of unacknowledged entries is 0) |
| STO-11 (Low) pg_stat | `PgIntakeMaintenance::reset_statistics()` (daily); grant at provisioning; residual documented. Revoking catalog views per role was not done: it needs superuser in the migration and does not cover the `pg_stat_get_*` functions (risky, little gain). | `pg_statistics_reset` |
| STO-12 (Low) quadratic merge | Signatures verified before the lock; `BTreeMap`/`HashSet` lookups; `MAX_PUSHED_DELETION_LIST` = 200,000. | `validate::merge_rules`, `conf_backup_restore` |
| STO-13 (Low) pg-test.sh | `PGUSER_OS` and port validated; existing root/human accounts refused; a created user is removed on exit; `umask 077`; log to a 0600 file. | `shellcheck -S style` clean; exercised by every PG run |
| STO-14 (Info) deleted replies until rebuild | Documented residual 5 (slot-granular removal, required by SA-19). | — |
| STO-15 (Info) salt ignored on restore | `Conflict("kdf salt differs")`. | `conf_backup_restore` |
| STO-16 (Info) claim starvation | `ORDER BY release_day, envelope_ref` (both impls). | `conf_claim_fairness` |
| STO-17 (Info) supply chain | No dependency change; sha2 skip decided by ADR-052(7). | — |

