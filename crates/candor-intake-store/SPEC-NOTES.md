<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
# candor-intake-store — SPEC-NOTES

Component C-08 (Intake Store). Sources: 09-DATABASE.md §5.1, §8, §10, §11; 07-BACKEND.md §5.3, §5.4, §6.3, §12; 08-API.md RL-01..RL-12, SA-19/SA-20, §3.8; ADR-009/010/033/034/038/039/046(1)/047(2,3,9); research/R7 §E.

## Scope

**Delivered:**
- the `IntakeStore` trait (owner of the intake persistence interface);
- `PgIntakeStore` (sqlx 0.9, PostgreSQL 16);
- `MemoryStore`;
- the signed deletion list;
- the fetch-all dead-drop pages;
- the KD snapshot high-water mark;
- quota, monthly counters and backup/restore content;
- the schema lint;
- the test cluster script.

**Not in this assignment (left for the C-08 daemon / follow-ups):**
- Tier V `upload` / `upload_chunk` tables;
- `config_bundle` (RL-07);
- `job_local`;
- tmpfs staging;
- blob file I/O (`candor-safefs`);
- the SEQPACKET IPC and the TLS 1.3 relay endpoint;
- `ACCOUNT_ROTATE`;
- typed audit events (`candor-log`);
- encryption of the RL-10 snapshot to the Backup Key;
- 24 §TEL suppression of RL-09 counters.

None of these weaken anything here. Tables that do not exist cannot leak.

## Implementation decisions

1. **`lookup_tag` = `locator_hash`.** 04 §11.4 calls it `lookup_tag`; 09 §5.1 calls the column `locator_hash`. The column keeps the 09 name and the Rust type is `LookupTag`.
2. **`envelope.epoch_index integer` added** (not in 09 §5.1). RL-02 must send `epoch_index`. 09 says `received_date` is "used only to derive the sealing epoch", but no derivation rule (epoch origin) is specified anywhere, and Tier V clients may seal for a ±1-day-skewed epoch. So the store keeps the epoch the sealer reports. It is weekly granularity, coarser than `received_date`, so it adds no information. *Spec feedback:* add the column to 09 §5.1, or specify the derivation.
3. **`intake_meta.restore_pending boolean` added.** BE-074 requires the store to refuse service until the newest deletion list is applied after a restore. A RAM-only flag would be lost on restart and would fail open. While the flag is set:
   - `commit_envelope` and `apply_replies` return `RestorePending`;
   - `serving_allowed()` is false (RL-01 `restored`, C-06 busy page).
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
8. **Dead-drop page format.** Each entry is exactly 70,000 B: `u32be len ‖ reply_ct ‖ CSPRNG fill`, so `reply_ct ≤ 69,996 B` (09 says ≤ 70,000; the 4-byte prefix of 04 §13.5 must fit).
   - Real and dummy entries are placed uniformly at random over **all** `page_count × 64` positions, not only over the first pages.
   - `set_version` is a fresh random u64 per rebuild.
   - Pages are built once per `rebuild_published_set` (called at import slots) and held in RAM as shared immutable buffers, so every requester gets byte-identical pages and nothing about access is recorded.
   - Memory is ≈ 4.48 MB per page (e.g. 128 pages ≈ 573 MB at EE scale, as 08 SA-19 states).
9. **Window and expiry share one boundary.** A reply is published and retained iff `today − available_day < retention` (≤ 30). `expire_replies` clamps any retention above 30 down to 30.
10. **Tier W slots.** The store assigns the lowest free slot 0..31. If all 32 slots are taken, the reply is listed in `rejected` and the relay keeps it in `reply_outbox` for a later slot.
11. **Claim order and limits.**
    - Candidates are ordered by the random `envelope_ref`, so the order leaks no arrival order.
    - The first candidate is always taken, even if it alone exceeds `max_bytes`, so a large envelope cannot block the queue forever.
    - An ack listing a digest outside the batch changes nothing.
    - On ack, unacked envelopes of the batch return to the pool and the batch closes.
    - RL-02 `ref` is the intake-local `envelope_ref`. A re-offered envelope keeps its ref, which carries the same information as its unchanged `sha256`.
12. **Snapshot rollback rules (BE-060, RL-06).** Signature, witness and consistency verification belong to the KD verifier. The store enforces, atomically under a row lock:
    - `tree_size ≥ hwm`;
    - `checkpoint_day ≥ day_hwm`;
    - `version > directory_version`;
    - `consistent_from == hwm` (the proof must start from the stored mark).

    A re-push of the identical current snapshot returns `AlreadyInstalled`. Only the current and previous versions are kept. A DB trigger additionally refuses any decrease of `kd_tree_size_hwm`, `kd_checkpoint_day_hwm`, `directory_version`, `relay_req_counter` or `last_batch_no`.
13. **Quota.** `quota_bucket` is a smallint, so limits are clamped to 32,767. No day is stored: reset depends on the daily `quota_reset` job. If the job is missed, quotas stay consumed: this fails closed for availability and has no privacy impact.
14. **Fixed sizes enforced:**
    - `disposition_ct` = 1,168 B (X-Wing Nenc 1,120 + 48; STD only, since FIPS is unsupported by candor-core);
    - `xwing_pk` = 1,216 B;
    - `prefs_ct` 1..4,096 B;
    - `size_bucket` 1..16 (REPLY buckets 4096·k).

    Part `padded_size` legality (ADR-011 bucket) is checked by the sealer/web, because the ciphertext overhead depends on the object format. The store only bounds it to 1..16 GiB.
15. **Deletions.**
    - Account deletion deletes the account and its replies, and unlinks (`SET NULL`) its pending envelopes, which are still relayed (the submission was made).
    - `delete_mailbox` takes the reply refs from the caller, because the store has no mailbox column.
    - `deletion_list_after(after)` marks entries with `seq ≤ after` as relayed, since the relay holds them.
    - Prune removes only relayed entries older than 35 days and never the newest entry, so the chain head survives. A DB trigger refuses edits to signed fields and deletion of unrelayed entries.
16. **Restore.**
    - `restore_backup` requires an empty store.
    - Counters and the KD high-water mark keep the higher of the backup and current values.
    - `apply_pushed_deletion_list` verifies the pushed list: chain, strict Ed25519 under K31, no gaps, no fork with local entries, and a filled hole must link to its local successor. It then merges newer entries and deletes every listed account (by `del_hash` of `locator_hash`) and listed reply (by `object_hash` via `ReplyObjectHasher`; the default `CoreReplyHasher` uses candor-core's `object_hash` over the first 160 bytes of `reply_ct`).
    - The deletion list inside a backup is not re-verified at restore (the backup is authenticated by the backup system, 19). The pushed Z-CORE copy is verified.
17. **Durability.** `commit_envelope` returns after `COMMIT`. With `fsync = on` and `synchronous_commit = on` (the default), that means after the WAL flush (ADR-046(1), BE-071). *Spec feedback:* add `synchronous_commit = on` to the 09 §10 intake hardening table. Blob files must be fsynced by the caller **before** `commit_envelope`. `ack_batch` returns the blob ids the caller must delete (BE-014).
18. **Roles in the migration.** Roles are created idempotently in a `DO` block, which needs CREATEROLE: test clusters run it as superuser; production provisions the roles at deployment with the same attributes. The migrator receives `CREATE ON DATABASE` and owns every object. `candor_istore` and `candor_intake_backup` own nothing and have `NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION`. They get per-database `search_path = candor`. The app role gets `statement_timeout 30s` and `idle_in_transaction_session_timeout 60s`; the backup role gets `default_transaction_read_only`. `PgIntakeStore::open` refuses to run as a superuser, as a BYPASSRLS role or as a table owner.
19. **L11 wording conflicts with 09 §5.1.** L11 bans `kind` and `last_*` columns, but §5.1 itself defines `deletion_list.kind` and `intake_meta.last_batch_no`. The lint exempts exactly those two (*spec feedback*).
20. **Concurrent migrations.** Cluster-wide role DDL races ("tuple concurrently updated"), so tests serialise `migrate`. Production runs one `candorctl migrate` at a time.

## Spec feedback (for the lead; specs not edited)

- 09 §5.1: add `envelope.epoch_index` and `intake_meta.restore_pending` (decisions 2, 3) and `schema_migration` (decision 4), or specify the alternatives.
- 09 §8 L11: exempt `deletion_list.kind` and `intake_meta.last_batch_no`.
- 09 §10: add `synchronous_commit = on`, `log_parameter_max_length = 0` and `log_parameter_max_length_on_error = 0` for the intake profile.
- 04 §18.6: fix the entry/chain encoding (decision 7) and register `candor/v1/intake/del` in the candor-core label registry.
- **Mailbox entries on restore (residual).** A `mailbox` deletion entry cannot be applied to replies **already stored** on a node recovered from an older disk, because `reply` has no mailbox column. Such entries are enforced at deletion time (same transaction) and on every later RL-05 arrival. Stale Tier W replies of a deleted mailbox on a recovered EE-HA node would persist until 30-day expiry. Options: store `H(mailbox)` on Tier W reply rows (they are already account-linked), or delete all of the account's replies when a mailbox is deleted.
- Deletion-list retention (35 days) vs reply retention (30 days): a push of a reply to a mailbox deleted more than 35 days earlier is no longer dropped by the intake. Z-CORE drops `reply_outbox` rows whose mailbox is listed (09 §5.2.7), within the same 35 days.

## Dependencies

| Crate | Version | Why |
|---|---|---|
| candor-core | path | Ed25519 strict verification and signing for K31 (`sig`); `CoreHeader`/`object_hash` for the default reply hasher. |
| sqlx | =0.9.0, `runtime-tokio`, `postgres`, `uuid`; no defaults, no TLS, no macros, no sqlite/mysql | Spec-mandated DB toolkit (09 §11). Postgres over a Unix socket. ≥ 0.8.1 for RUSTSEC-2024-0363. |
| tokio | =1.48.0, `sync` (dev: `rt`, `macros`) | Async runtime required by sqlx `runtime-tokio`; `RwLock`/`Mutex` for the in-RAM published set and the memory store. |
| uuid | =1.18.1, no defaults | Bind 128-bit random ids to `uuid` columns (sqlx `uuid` feature). No generation features: ids come from getrandom. |
| sha2 | =0.11.0 | `header_sha256`, `del_hash`, chain hash, migration digests. Same version as candor-core. |
| subtle | =2.6.1 | Constant-time comparison of chain hashes and signed entries. |
| zeroize | =1.8.2 | Zeroizing buffers for dummy bodies. |
| getrandom | =0.4.3 | OS CSPRNG (the same pin as candor-core, whose `rand` module is crate-private), with the same all-zero health check. |
| proptest (dev) | =1.11.0 | Property tests. |

**Blocked: needs a lead decision.** `cargo deny check bans` fails because sqlx-core/sqlx-postgres 0.9.0 depend on `sha2 0.10.9` (SCRAM/MD5 password auth code, unused with peer auth but compiled), and `deny.toml` sets `deny-multiple-versions` for `sha2`. This needs a version-pinned `skip` for `sha2@0.10.9` (with an expiry, as with ADR-051's sha3), or an upstream sqlx move to sha2 0.11. `cargo deny` advisories, licenses and sources pass. sqlx-core also depends on `log`/`tracing` unconditionally. Statement logging is disabled on every connection. The intake processes must not install a `log` logger or a `tracing` subscriber (consistent with the candor-log-only rule).

## Test mapping

| Spec ID | Tests |
|---|---|
| BE-014, RL-02..RL-04, API-047, BE-062 | `conf_claim_ack`, `conf_claim_limits` (both impls) |
| ADR-034, BE-056 (no pending account; atomic) | `conf_accounts` |
| Input bounds (hostile input) | `conf_envelope_validation`, `conf_reply_rules`, `deaddrop::oversize_body_rejected` |
| BE-063, API-037, API-040, SA-19/SA-20 | `conf_dead_drop`, `deaddrop::page_shape`, `set_version_changes_per_build`, proptests |
| ADR-047(9), KEY-077, RL-11, BE-074, API-054 | `conf_deletion_list`, `conf_backup_restore`, `deletion::tests`, `deletion::props` (arbitrary lists, any bit flip) |
| BE-060, RVW-A-04, RL-06 (rollback) | `conf_kd_snapshots`, `validate::rollback_matrix`, `pg_durability_and_guards` (DB trigger) |
| BE-064, ADR-038(3) (quota today only) | `conf_quota` |
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
  - Claim order is random.
  - `set_version` is random.
  - No per-mailbox access state exists.
  - Debug output of every source-linked type is redacted.
  - Errors carry only static strings. PostgreSQL error details, which can echo `locator_hash` values, are discarded.
- **Logging.**
  - sqlx statement logging is disabled on every connection (tested by source lint).
  - The test cluster uses `log_parameter_max_length*=0`, `log_min_error_statement=panic` and `log_statement=none`.
  - No `print`, `log` or `tracing` in `src/`.
- **SQL injection.** All SQL is static; no dynamic SQL is possible without `AssertSqlSafe`, which is banned.
- **Least privilege.**
  - The app role is non-owner, NOBYPASSRLS and non-superuser; this is verified at `open`.
  - The app role has no TRUNCATE or DDL.
  - On `deletion_list` the app role has only a column-level UPDATE (`relayed`).
  - The backup role is read-only on exactly three tables.
  - RLS is FORCEd.
  - DB triggers enforce monotonic counters and an append-only deletion list even against a compromised app role (tested).
- **Network.** Unix socket only: no TLS feature is compiled and there is no TCP in tests (`listen_addresses = ''`, peer auth with an ident map, no host lines).
- **Fail closed.**
  - Restore-pending persists across restarts.
  - Forged, forked or gapped deletion lists are rejected, and the store keeps refusing service.
  - Schema drift refuses `open`.
  - CSPRNG failure is an error.
  - Unknown enum text from the DB is an `Integrity` error.
  - Oversized inputs are rejected before any DB work.
- **Input handling.**
  - Every external input has an explicit maximum: header, manifest, parts, part size, reply size, reply count per push, snapshot body and signatures, pushed list length, deletion page size, claim limits.
  - Day values are bounded before date arithmetic.
  - There is no recursion.
  - No `unwrap`, `expect` or indexing on untrusted data (clippy deny set clean).
  - Duplicate refs and blob ids are rejected.
- **Secrets.** The only secret in reach is K31, inside candor-core's zeroizing `SigningKey` (redacted Debug), used through `DeletionSigner`. The KDF salt is public.
- **Residual risks.**
  1. The mailbox-entry restore gap.
  2. `RandomDummyReplies` dummies are size-identical but lack CoreHeader magic, so an observer can count real replies in the 30-day window. Production should pass a `DummyReplies` that seals real REPLY-format objects to a random key (C-08 daemon).
  3. PostgreSQL row versions and WAL segments may keep deleted ciphertext and commit records until vacuum and recycle (09 §13). Autovacuum is aggressive on intake tables.
  4. Lookup timing for unknown and known `lookup_tag` is the caller's job (BE-010 floor).
  5. The published set is held in RAM (≈ 4.5 MB per page).
  6. The sha2 duplicate needs a deny.toml decision.
  7. Query macros with an offline cache are deferred (decision 6).
