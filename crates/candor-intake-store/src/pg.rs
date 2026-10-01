// SPDX-License-Identifier: AGPL-3.0-or-later
//! PostgreSQL implementation of [`IntakeStore`] (09 §5.1, §10, §11).
//!
//! - Every SQL statement is a `&'static str` constant: sqlx 0.9 only accepts
//!   `SqlSafeStr`, and this crate never opts out of that check (a test enforces it),
//!   so no runtime string is ever spliced into SQL. Values are always bound.
//! - Statement logging is disabled on every connection; driver errors are reduced
//!   to content-free [`StoreError`] values (a PostgreSQL error detail can echo row
//!   values).
//! - Every operation runs in a transaction that first sets
//!   `SET LOCAL candor.tenant_id` (row-level security, R7 SI-E-03) and reads
//!   `intake_meta` (row-locked for mutating operations, which serialises chain
//!   appends, batch numbering and mailbox slot assignment).
//! - Dates are bound as day numbers and converted in SQL; no wall clock is read.
//! - No expected outcome relies on a server-side error (AUD-RM2-STO-02):
//!   duplicates use `INSERT … ON CONFLICT DO NOTHING` and row counts, bounds and
//!   rollback rules are checked in Rust first, so PostgreSQL logs no ERROR line
//!   (with its millisecond timestamp) for any source action. Constraint and
//!   trigger errors remain only as a backstop against bugs and tampering.
//! - Source actions never update an account row; every source-linkable row is
//!   rewritten at each fixed import slot ([`IntakeStore::uniform_rewrite`]), so
//!   row `xmin` reveals only the slot (AUD-RM2-STO-01).

use std::sync::Arc;

use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgRow};
use sqlx::{ConnectOptions, Connection, PgConnection, PgPool, Postgres, Row, Transaction};
use tokio::sync::RwLock;
use uuid::Uuid;

use std::collections::HashSet;

use crate::deaddrop::{
    self, DeadDropConfig, DummyReplies, PADDING_GENERATION, PageBuilder, PublishedSet,
};
use crate::deletion::{
    DeletionEntry, DeletionKind, DeletionSigner, ReplyObjectHasher, SignedDeletionHead,
    account_del_hash, mailbox_del_hash, make_entry, reply_del_hash,
};
use crate::error::{Result, StoreError};
use crate::store::{IntakeMaintenance, IntakeStore};
use crate::types::{
    AccountId, AckResult, ApplyRepliesResult, BackupSnapshot, BlobId, ChannelId, ClaimLimits,
    ClaimedBatch, ClaimedObject, CommitEnvelope, CounterCell, CounterDelta, CounterName,
    DELETION_LIST_RETENTION_DAYS, Day, EnvelopeRef, GROUP_OBJECTS, INACTIVE_PURGE_DAYS, ImportSlot,
    IncomingReply, InstallOutcome, KdHighWater, LookupTag, MAILBOX_SLOTS, MAX_DELETION_LIST_PAGE,
    MAX_REPLIES_PER_PUSH, MAX_SLOT_ACTIVE_ACCOUNTS, MailboxId, MetaSnapshot, NewAccount,
    ObjectData, PartRef, PartSelector, REPLY_WINDOW_DAYS, ReplyIndex, ReplyRef, SourceAccount,
    StoredReply, TenantId, VerifiedSnapshot, group_digest, random_id16, reply_bucket_of_len,
};
use crate::validate::{self, SnapshotDecision, day_i32, has_duplicates};

/// Embedded forward-only migrations `(version, sql)`.
pub const MIGRATIONS: &[(i32, &str)] = &[(1, include_str!("../migrations/0001_intake_schema.sql"))];

/// Expected `intake_meta.schema_hash` of this build (BE-050):
/// `SHA-256("candor/v1/intake/schema" ‖ Σ (u32be version ‖ SHA-256(sql)))`.
#[must_use]
pub fn schema_hash() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"candor/v1/intake/schema");
    for (v, sql) in MIGRATIONS {
        h.update(v.to_be_bytes());
        h.update(Sha256::digest(sql.as_bytes()));
    }
    h.finalize().into()
}

fn db(_e: sqlx::Error) -> StoreError {
    StoreError::Backend
}

fn sqlstate(e: &sqlx::Error) -> Option<String> {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
}

/// Map a driver error, translating our trigger SQLSTATEs.
fn db_classified(e: sqlx::Error) -> StoreError {
    match sqlstate(&e).as_deref() {
        Some("P0002") => StoreError::Rollback("monotonic value decreased"),
        Some("P0001" | "P0003" | "P0004") => StoreError::Integrity("schema guard"),
        Some("22003") => StoreError::InvalidInput("numeric overflow"),
        _ => StoreError::Backend,
    }
}

fn uuid(b: &[u8; 16]) -> Uuid {
    Uuid::from_bytes(*b)
}

fn get_id(row: &PgRow, i: usize) -> Result<[u8; 16]> {
    Ok(*row.try_get::<Uuid, _>(i).map_err(db)?.as_bytes())
}

fn get_arr<const N: usize>(row: &PgRow, i: usize) -> Result<[u8; N]> {
    let v: Vec<u8> = row.try_get(i).map_err(db)?;
    v.try_into()
        .map_err(|_| StoreError::Integrity("column length"))
}

fn get_day(row: &PgRow, i: usize) -> Result<Day> {
    let d: i32 = row.try_get(i).map_err(db)?;
    u32::try_from(d)
        .map(Day)
        .map_err(|_| StoreError::Integrity("day"))
}

fn get_u64(row: &PgRow, i: usize) -> Result<u64> {
    let v: i64 = row.try_get(i).map_err(db)?;
    u64::try_from(v).map_err(|_| StoreError::Integrity("negative value"))
}

fn i64_of(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| StoreError::InvalidInput("value out of range"))
}

// ---- SQL (all static) ----

const SQL_SET_TENANT: &str =
    "SELECT pg_catalog.set_config('candor.tenant_id', $1::uuid::text, true)";
const SQL_META: &str = "SELECT tenant_id, restore_pending FROM candor.intake_meta";
const SQL_META_LOCK: &str = "SELECT tenant_id, restore_pending FROM candor.intake_meta FOR UPDATE";
const SQL_LEDGER_EXISTS: &str =
    "SELECT pg_catalog.to_regclass('candor.schema_migration') IS NOT NULL";
const SQL_LEDGER_GET: &str = "SELECT sha256 FROM candor.schema_migration WHERE version = $1";
const SQL_LEDGER_ALL: &str = "SELECT version, sha256 FROM candor.schema_migration ORDER BY version";
const SQL_LEDGER_PUT: &str =
    "INSERT INTO candor.schema_migration (version, sha256) VALUES ($1, $2)";
const SQL_MIGRATE_TIMEOUTS: &str = "SELECT pg_catalog.set_config('lock_timeout', '10s', true), pg_catalog.set_config('statement_timeout', '10min', true)";
/// Privilege and live-guard check at open (AUD-RM2-STO-08): not superuser, not
/// BYPASSRLS, not a member of any role owning a `candor` table, of the
/// database owner (the maintenance role; allowed only when `$2` is true, for
/// the maintenance role itself) or of the other intake role (`$1`); RLS enabled and forced on every data table with exactly the
/// eight tenant policies; and the four guard triggers enabled.
const SQL_ROLE_CHECK: &str = "SELECT r.rolsuper, r.rolbypassrls, \
     EXISTS (SELECT 1 FROM pg_catalog.pg_tables t WHERE t.schemaname = 'candor' \
             AND pg_catalog.pg_has_role(current_user, t.tableowner, 'MEMBER')) \
       OR (NOT $2::bool AND pg_catalog.pg_has_role(current_user, (SELECT d.datdba FROM pg_catalog.pg_database d \
             WHERE d.datname = pg_catalog.current_database()), 'MEMBER')), \
     pg_catalog.pg_has_role(current_user, $1::name, 'MEMBER'), \
     (SELECT count(*) FROM pg_catalog.pg_class k JOIN pg_catalog.pg_namespace n ON n.oid = k.relnamespace \
      WHERE n.nspname = 'candor' AND k.relkind = 'r' AND k.relname <> 'schema_migration' \
      AND NOT (k.relrowsecurity AND k.relforcerowsecurity)), \
     (SELECT count(*) FROM pg_catalog.pg_trigger g JOIN pg_catalog.pg_class k ON k.oid = g.tgrelid \
      JOIN pg_catalog.pg_namespace n ON n.oid = k.relnamespace \
      WHERE n.nspname = 'candor' AND NOT g.tgisinternal AND g.tgenabled = 'O' \
      AND g.tgname IN ('intake_meta_monotonic', 'intake_meta_no_delete', 'deletion_list_guard', \
      'deletion_list_append')), \
     (SELECT count(*) FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class k ON k.oid = p.polrelid \
      JOIN pg_catalog.pg_namespace n ON n.oid = k.relnamespace WHERE n.nspname = 'candor'), \
     (SELECT count(*) FROM pg_catalog.pg_policy p JOIN pg_catalog.pg_class k ON k.oid = p.polrelid \
      JOIN pg_catalog.pg_namespace n ON n.oid = k.relnamespace WHERE n.nspname = 'candor' \
      AND p.polname = 'p_tenant' AND p.polpermissive AND p.polcmd = '*' AND p.polroles = '{0}') \
     FROM pg_catalog.pg_roles r WHERE r.rolname = current_user";
const EXPECTED_GUARD_TRIGGERS: i64 = 4;
/// One `p_tenant` policy (permissive, all commands, PUBLIC) per data table.
const EXPECTED_POLICIES: i64 = 8;
/// Session hardening check, on every new connection (AUD-RM2-STO-08).
/// PostgreSQL lets an ordinary role `ALTER ROLE` its own defaults, which cannot
/// be revoked; so (1) every stored default of the role (cluster-wide and for
/// this database) must be one of [`ALLOWED_ROLE_SETTINGS`] or a
/// `temp_file_limit` (superuser-only: the role cannot write it), and (2) the
/// effective session values (after the startup options of [`SESSION_OPTIONS`],
/// which override role defaults) must be [`EXPECTED_SESSION`], with an
/// effective `temp_file_limit` between 1 kB and [`MAX_TEMP_FILE_LIMIT_KB`]
/// (never unlimited). Anything else refuses the connection (fail closed).
const SQL_SESSION_CHECK: &str = "SELECT COALESCE((SELECT pg_catalog.array_agg(x ORDER BY x) \
     FROM pg_catalog.pg_db_role_setting s, pg_catalog.unnest(s.setconfig) x \
     WHERE s.setrole = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) \
     AND s.setdatabase IN (0, (SELECT d.oid FROM pg_catalog.pg_database d \
     WHERE d.datname = pg_catalog.current_database()))), '{}'::text[]), \
     pg_catalog.current_setting('search_path'), pg_catalog.current_setting('statement_timeout'), \
     pg_catalog.current_setting('idle_in_transaction_session_timeout'), \
     pg_catalog.current_setting('lock_timeout'), \
     pg_catalog.current_setting('synchronous_commit'), pg_catalog.current_setting('row_security'), \
     pg_catalog.current_setting('default_transaction_read_only'), \
     pg_catalog.current_setting('session_replication_role'), \
     pg_catalog.current_setting('default_transaction_isolation'), \
     (SELECT p.setting FROM pg_catalog.pg_settings p WHERE p.name = 'temp_file_limit')";
/// Stored role defaults allowed for `candor_istore` and `candor_intake_maint`
/// (the migration's values) besides a provisioned `temp_file_limit`.
const ALLOWED_ROLE_SETTINGS: [&str; 3] = [
    "idle_in_transaction_session_timeout=60s",
    "search_path=candor",
    "statement_timeout=30s",
];
/// Largest effective `temp_file_limit` (09 §10: 1 GB; the deploy may set less).
const MAX_TEMP_FILE_LIMIT_KB: i64 = 1024 * 1024;
/// Effective session values (columns 1..=9 of [`SQL_SESSION_CHECK`]).
const EXPECTED_SESSION: [&str; 9] = [
    "candor",
    "30s",
    "1min",
    "10s",
    "on",
    "on",
    "off",
    "origin",
    "read committed",
];
const SQL_META_HASH: &str = "SELECT schema_hash FROM candor.intake_meta";
const SQL_META_INSERT: &str = "INSERT INTO candor.intake_meta (tenant_id, schema_hash, kdf_salt) \
     VALUES ($1, $2, $3) ON CONFLICT DO NOTHING";
const SQL_COUNTER_BUMP: &str =
    "UPDATE candor.intake_meta SET relay_req_counter = $1 WHERE relay_req_counter < $1";
const SQL_SET_PENDING: &str = "UPDATE candor.intake_meta SET restore_pending = true";
const SQL_CLEAR_RESTORE: &str = "UPDATE candor.intake_meta SET restore_pending = false";

const SQL_ACCOUNT_BY_TAG: &str = "SELECT account_id, locator_hash, auth_pk, xwing_pk, prefs_ct, \
     (activity_month - DATE '1970-01-01')::int4 FROM candor.source_account WHERE locator_hash = $1";
const SQL_ACCOUNT_TAG_LOCK: &str =
    "SELECT locator_hash FROM candor.source_account WHERE account_id = $1 FOR UPDATE";
const SQL_ACCOUNT_EXISTS: &str =
    "SELECT EXISTS (SELECT 1 FROM candor.source_account WHERE account_id = $1)";
const SQL_ACCOUNT_DELETE: &str = "DELETE FROM candor.source_account WHERE account_id = $1";
const SQL_ACCOUNT_INSERT: &str = "INSERT INTO candor.source_account \
     (account_id, locator_hash, auth_pk, xwing_pk, prefs_ct, activity_month) \
     VALUES ($1, $2, $3, $4, $5, DATE '1970-01-01' + $6::int4) ON CONFLICT DO NOTHING";
/// Passphrase rotation: replace tag, keys and prefs unless the new tag belongs to
/// another account (no unique-violation error on the expected path).
const SQL_ACCOUNT_UPDATE: &str = "UPDATE candor.source_account SET locator_hash = $2, auth_pk = $3, \
     xwing_pk = $4, prefs_ct = $5 WHERE account_id = $1 AND NOT EXISTS (SELECT 1 FROM candor.source_account o \
     WHERE o.locator_hash = $2 AND o.account_id <> $1)";
const SQL_ACCOUNTS_PURGE: &str =
    "DELETE FROM candor.source_account WHERE activity_month <= DATE '1970-01-01' + $1::int4";
const SQL_ACCOUNTS_ALL: &str = "SELECT account_id, locator_hash, auth_pk, xwing_pk, prefs_ct, \
     (activity_month - DATE '1970-01-01')::int4 FROM candor.source_account ORDER BY account_id";

const SQL_ENV_INSERT: &str = "INSERT INTO candor.envelope (envelope_ref, channel_id, group_sha256, \
     disposition_ct, epoch_index, received_date, release_day, batch_no, state) \
     VALUES ($1, $2, $3, $4, $5, DATE '1970-01-01' + $6::int4, DATE '1970-01-01' + $7::int4, NULL, 'sealed') \
     ON CONFLICT DO NOTHING";
const SQL_PART_INSERT: &str = "INSERT INTO candor.envelope_part (envelope_ref, part_no, object_hash, slot_block, \
     blob_id, padded_size) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING";
const SQL_PENDING: &str = "SELECT count(*) FROM candor.envelope";
const SQL_INFLIGHT: &str = "SELECT batch_no FROM candor.envelope WHERE state = 'claimed' LIMIT 1";
/// Oldest release day first, then the random ref (AUD-RM2-STO-16).
const SQL_CANDIDATES: &str = "SELECT envelope_ref FROM candor.envelope WHERE state = 'sealed' \
     AND release_day <= DATE '1970-01-01' + $1::int4 ORDER BY release_day, envelope_ref LIMIT $2";
const SQL_PART_SIZES: &str = "SELECT envelope_ref, padded_size FROM candor.envelope_part \
     WHERE envelope_ref = ANY($1) ORDER BY envelope_ref, part_no";
const SQL_LAST_BATCH: &str = "SELECT last_batch_no FROM candor.intake_meta";
const SQL_SET_BATCH_NO: &str = "UPDATE candor.intake_meta SET last_batch_no = $1";
const SQL_CLAIM: &str =
    "UPDATE candor.envelope SET state = 'claimed', batch_no = $1 WHERE envelope_ref = ANY($2)";
const SQL_BATCH_OBJECTS: &str = "SELECT envelope_ref, channel_id, epoch_index, group_sha256, disposition_ct \
     FROM candor.envelope WHERE batch_no = $1 ORDER BY envelope_ref";
const SQL_BATCH_PARTS: &str = "SELECT p.envelope_ref, p.part_no, p.object_hash, p.padded_size \
     FROM candor.envelope_part p JOIN candor.envelope e ON e.envelope_ref = p.envelope_ref \
     WHERE e.batch_no = $1 ORDER BY p.envelope_ref, p.part_no";
const SQL_OBJ_SLOT: &str = "SELECT p.slot_block FROM candor.envelope_part p \
     JOIN candor.envelope e ON e.envelope_ref = p.envelope_ref \
     WHERE p.envelope_ref = $1 AND e.batch_no = $2 AND p.part_no = $3";
const SQL_OBJ_PART: &str = "SELECT p.blob_id, p.padded_size FROM candor.envelope_part p \
     JOIN candor.envelope e ON e.envelope_ref = p.envelope_ref \
     WHERE p.envelope_ref = $1 AND e.batch_no = $2 AND p.part_no = $3";
const SQL_BATCH_DIGESTS: &str = "SELECT group_sha256 FROM candor.envelope WHERE batch_no = $1";
const SQL_BLOB_REFERENCED: &str =
    "SELECT EXISTS (SELECT 1 FROM candor.envelope_part WHERE blob_id = $1)";
const SQL_ACK_BLOBS: &str = "SELECT p.blob_id FROM candor.envelope_part p \
     JOIN candor.envelope e ON e.envelope_ref = p.envelope_ref \
     WHERE e.batch_no = $1 AND e.group_sha256 = ANY($2) ORDER BY p.envelope_ref, p.part_no";
const SQL_ACK_DELETE: &str =
    "DELETE FROM candor.envelope WHERE batch_no = $1 AND group_sha256 = ANY($2)";
const SQL_UNCLAIM: &str =
    "UPDATE candor.envelope SET state = 'sealed', batch_no = NULL WHERE batch_no = $1";

const SQL_LISTED: &str = "SELECT EXISTS (SELECT 1 FROM candor.deletion_list WHERE \
     (kind = 'reply' AND del_hash = $1) OR (kind = 'mailbox' AND del_hash = $2))";
const SQL_SLOTS_USED: &str =
    "SELECT slot FROM candor.reply WHERE source_account_id = $1 AND slot IS NOT NULL";
const SQL_REPLY_BACKLOG: &str = "SELECT count(*) FROM candor.reply WHERE pub_gen IS NULL";
const SQL_REPLY_INSERT: &str = "INSERT INTO candor.reply (reply_ref, source_account_id, reply_ct, size_bucket, \
     available_day, slot, pub_gen) VALUES ($1, $2, $3, $4, DATE '1970-01-01' + $5::int4, $6, $7) \
     ON CONFLICT DO NOTHING";
const SQL_MAILBOX: &str = "SELECT reply_ref, slot, reply_ct, size_bucket, (available_day - DATE '1970-01-01')::int4 \
     FROM candor.reply WHERE source_account_id = $1 ORDER BY slot";
const SQL_REPLIES_OWNED: &str =
    "SELECT count(*) FROM candor.reply WHERE reply_ref = ANY($1) AND source_account_id = $2";
const SQL_REPLIES_DELETE: &str =
    "DELETE FROM candor.reply WHERE reply_ref = ANY($1) AND source_account_id = $2";
const SQL_REPLIES_PURGE: &str = "DELETE FROM candor.reply WHERE available_day < DATE '1970-01-01' + $1::int4 \
     AND (pub_gen IS NULL OR pub_gen <> 0)";
const SQL_REPLIES_PAGE: &str = "SELECT reply_ref, reply_ct FROM candor.reply WHERE reply_ref > $1 ORDER BY reply_ref LIMIT 256";
const SQL_REPLY_DELETE_ONE: &str = "DELETE FROM candor.reply WHERE reply_ref = $1";

const SQL_PUB_LAST: &str = "SELECT max(pub_gen) FROM candor.reply WHERE pub_gen > 0";
const SQL_PUB_PENDING: &str = "SELECT reply_ref FROM candor.reply \
     WHERE pub_gen IS NULL ORDER BY available_day, reply_ref LIMIT $1";
const SQL_PUB_ASSIGN: &str = "UPDATE candor.reply SET pub_gen = $1, available_day = DATE '1970-01-01' + $2::int4 \
     WHERE reply_ref = ANY($3)";
const SQL_PUB_WINDOW_COUNT: &str =
    "SELECT count(*) FROM candor.reply WHERE pub_gen BETWEEN $1 AND $2";
const SQL_PUB_PADDING_COUNT: &str = "SELECT count(*) FROM candor.reply WHERE pub_gen = 0";
const SQL_PUB_PADDING_TRIM: &str = "DELETE FROM candor.reply WHERE reply_ref IN \
     (SELECT reply_ref FROM candor.reply WHERE pub_gen = 0 ORDER BY reply_ref LIMIT $1)";
const SQL_PUB_STREAM: &str = "SELECT reply_ref, reply_ct FROM candor.reply \
     WHERE (pub_gen BETWEEN $1 AND $2 OR pub_gen = 0) AND reply_ref > $3 ORDER BY reply_ref LIMIT 256";

const SQL_DEL_HEAD: &str = "SELECT d.seq, d.kind::text, d.del_hash, (d.del_day - DATE '1970-01-01')::int4, \
     d.prev_hash, d.sig, d.relayed FROM candor.deletion_list d ORDER BY d.seq DESC LIMIT 1";
const SQL_DEL_ALL: &str = "SELECT d.seq, d.kind::text, d.del_hash, (d.del_day - DATE '1970-01-01')::int4, \
     d.prev_hash, d.sig, (d.relayed OR d.seq <= m.deletion_acked_seq) \
     FROM candor.deletion_list d CROSS JOIN candor.intake_meta m ORDER BY d.seq";
const SQL_DEL_AFTER: &str = "SELECT d.seq, d.kind::text, d.del_hash, (d.del_day - DATE '1970-01-01')::int4, \
     d.prev_hash, d.sig, (d.relayed OR d.seq <= m.deletion_acked_seq) \
     FROM candor.deletion_list d CROSS JOIN candor.intake_meta m WHERE d.seq > $1 ORDER BY d.seq LIMIT $2";
/// New entries are never pre-flagged relayed (the database refuses it too).
const SQL_DEL_INSERT: &str = "INSERT INTO candor.deletion_list (seq, kind, del_hash, del_day, prev_hash, sig, relayed) \
     VALUES ($1, $2::text::candor.deletion_kind, $3, DATE '1970-01-01' + $4::int4, $5, $6, false) \
     ON CONFLICT DO NOTHING";
const SQL_DEL_ACKED: &str = "SELECT deletion_acked_seq, deletion_acked_hash, deletion_acked_sig, \
     (deletion_acked_day - DATE '1970-01-01')::int4, deletion_acked_counter FROM candor.intake_meta";
/// Record a verified Z-CORE head (AUD-RM2-STO-21/24) with a newer attestation
/// counter; the trigger checks that it is part of the local chain and that
/// counter and day never decrease.
const SQL_DEL_ACK: &str = "UPDATE candor.intake_meta SET deletion_acked_seq = $1, deletion_acked_hash = $2, \
     deletion_acked_sig = $3, deletion_acked_day = DATE '1970-01-01' + $4::int4, deletion_acked_counter = $5 \
     WHERE deletion_acked_counter < $5";
const SQL_DEL_AT: &str = "SELECT d.seq, d.kind::text, d.del_hash, (d.del_day - DATE '1970-01-01')::int4, \
     d.prev_hash, d.sig, d.relayed FROM candor.deletion_list d WHERE d.seq BETWEEN $1 AND $1 + 1 ORDER BY d.seq";
/// Flag entries up to the head the maintenance process verified itself.
const SQL_DEL_MARK: &str =
    "UPDATE candor.deletion_list SET relayed = true WHERE NOT relayed AND seq <= $1";
const SQL_DEL_PRUNE: &str = "DELETE FROM candor.deletion_list WHERE relayed AND del_day < DATE '1970-01-01' + $1::int4 \
     AND seq < (SELECT max(seq) FROM candor.deletion_list)";
const SQL_STAT_RESET: &str = "SELECT pg_catalog.pg_stat_reset()";

const SQL_HWM: &str = "SELECT kd_tree_size_hwm, (kd_checkpoint_day_hwm - DATE '1970-01-01')::int4, directory_version \
     FROM candor.intake_meta";
const SQL_HWM_LOCK: &str = "SELECT kd_tree_size_hwm, (kd_checkpoint_day_hwm - DATE '1970-01-01')::int4, directory_version \
     FROM candor.intake_meta FOR UPDATE";
const SQL_SNAP_BODY: &str = "SELECT body FROM candor.directory_snapshot WHERE version = $1";
const SQL_SNAP_INSERT: &str = "INSERT INTO candor.directory_snapshot (version, body, signatures, applied_day) \
     VALUES ($1, $2, $3, DATE '1970-01-01' + $4::int4) ON CONFLICT DO NOTHING";
const SQL_SNAP_META: &str = "UPDATE candor.intake_meta SET kd_tree_size_hwm = GREATEST(kd_tree_size_hwm, $1), \
     kd_checkpoint_day_hwm = GREATEST(kd_checkpoint_day_hwm, DATE '1970-01-01' + $2::int4), directory_version = $3";
const SQL_SNAP_PRUNE: &str = "DELETE FROM candor.directory_snapshot WHERE version < COALESCE((SELECT version FROM \
     candor.directory_snapshot ORDER BY version DESC OFFSET 1 LIMIT 1), 0)";
const SQL_SNAP_CURRENT: &str = "SELECT s.version, s.body, s.signatures FROM candor.directory_snapshot s \
     JOIN candor.intake_meta m ON s.version = m.directory_version";

const SQL_COUNTER_ADD: &str = "INSERT INTO candor.counter_month AS c (month, channel_id, name, value) \
     VALUES (DATE '1970-01-01' + $1::int4, $2, $3::text::candor.counter_name, $4) \
     ON CONFLICT (month, channel_id, name) DO UPDATE SET value = c.value + EXCLUDED.value \
     WHERE c.value::int8 + EXCLUDED.value::int8 <= 2147483647";
const SQL_COUNTERS: &str = "SELECT channel_id, name::text, value FROM candor.counter_month \
     WHERE month = DATE '1970-01-01' + $1::int4 ORDER BY channel_id, name";
const SQL_COUNTERS_PRUNE: &str =
    "DELETE FROM candor.counter_month WHERE month < DATE '1970-01-01' + $1::int4";

/// Import-slot rewrite (AUD-RM2-STO-01): every row of every source-linkable
/// table gets a new version in one transaction. `source_account` also folds
/// `activity_month`: the slot month `$3` for the accounts in `$2` (recorded
/// active in RAM since the last slot) and the month of stored replies ≤ `$1`.
/// Its byte columns are recomputed (`|| ''`) so that they are new datums; the
/// table keeps them in line (`toast_tuple_target`, AUD-RM2-STO-18).
const SQL_REWRITE_ACCOUNTS: &str = "UPDATE candor.source_account a SET activity_month = GREATEST(a.activity_month, \
       CASE WHEN a.account_id = ANY($2) THEN DATE '1970-01-01' + $3::int4 END, \
       (SELECT max(r.available_day - (EXTRACT(DAY FROM r.available_day)::int4 - 1)) FROM candor.reply r \
        WHERE r.source_account_id = a.account_id AND r.available_day <= DATE '1970-01-01' + $1::int4)), \
       xwing_pk = a.xwing_pk || ''::bytea, prefs_ct = a.prefs_ct || ''::bytea";
const SQL_REWRITE: &[&str] = &[
    "UPDATE candor.envelope SET disposition_ct = disposition_ct || ''::bytea",
    "UPDATE candor.deletion_list SET relayed = relayed",
    "UPDATE candor.counter_month SET value = value",
    "UPDATE candor.intake_meta SET relay_req_counter = relay_req_counter",
];
/// Rows with out-of-line (TOAST) values (AUD-RM2-STO-18). An UPDATE that leaves
/// a TOASTed column unchanged keeps the old TOAST tuples (their `xmin` and
/// creation-ordered `chunk_id`); `col || ''` is computed, so PostgreSQL stores a
/// new out-of-line value under a new `chunk_id` in this transaction. Rows are
/// re-created one by one in a CSPRNG-shuffled order across the three tables, so
/// the new chunk_ids follow the shuffle, not creation order.
const SQL_TOAST_PARTS: &str = "SELECT envelope_ref, part_no FROM candor.envelope_part";
const SQL_TOAST_REPLIES: &str = "SELECT reply_ref FROM candor.reply";
const SQL_TOAST_SNAPSHOTS: &str = "SELECT version FROM candor.directory_snapshot";
const SQL_RECREATE_PART: &str = "UPDATE candor.envelope_part SET slot_block = slot_block || ''::bytea \
     WHERE envelope_ref = $1 AND part_no = $2";
const SQL_RECREATE_REPLY: &str =
    "UPDATE candor.reply SET reply_ct = reply_ct || ''::bytea WHERE reply_ref = $1";
const SQL_RECREATE_SNAPSHOT: &str = "UPDATE candor.directory_snapshot SET body = body || ''::bytea, \
     signatures = signatures || ''::bytea WHERE version = $1";
/// Identity check of the VACUUM connection (AUD-RM2-STO-24(a)): it must own the
/// database (PostgreSQL 16 lets the database owner VACUUM every table in it)
/// and must not be a superuser, BYPASSRLS, the schema owner or a member of any
/// role owning a `candor` table (it could then disable RLS or the guard
/// triggers), nor a member of a service role.
const SQL_VACUUM_ROLE_CHECK: &str = "SELECT r.rolsuper OR r.rolbypassrls \
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_tables t WHERE t.schemaname = 'candor' \
                AND pg_catalog.pg_has_role(current_user, t.tableowner, 'MEMBER')) \
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname = 'candor' \
                AND pg_catalog.pg_has_role(current_user, n.nspowner, 'MEMBER')) \
     OR pg_catalog.pg_has_role(current_user, 'candor_istore', 'MEMBER') \
     OR pg_catalog.pg_has_role(current_user, 'candor_intake_backup', 'MEMBER'), \
     (SELECT d.datdba FROM pg_catalog.pg_database d WHERE d.datname = pg_catalog.current_database()) = r.oid \
     FROM pg_catalog.pg_roles r WHERE r.rolname = current_user";
/// The source-linkable tables (with their TOAST tables and indexes).
/// Slot VACUUM (AUD-RM2-STO-11/18): autovacuum is off on the intake cluster,
/// so this is the only routine VACUUM; it makes the dead pre-rewrite heap and
/// TOAST tuples reclaimable (their bytes stay in page free space until the
/// daily VACUUM FULL, AUD-RM2-STO-23). Never `ANALYZE`: `pg_statistic` would
/// copy column values (sampled locator hashes, days) outside the rows.
const SQL_VACUUM: &str = "VACUUM (ANALYZE false) candor.source_account, candor.envelope, \
     candor.envelope_part, candor.reply, candor.deletion_list, candor.counter_month, \
     candor.directory_snapshot, candor.intake_meta";
/// Daily maintenance-window rewrite (AUD-RM2-STO-23): writes fresh relation
/// files for every source-linkable table, its TOAST table and indexes, so no
/// pre-rewrite tuple image (old `xmin`, old TOAST `chunk_id`) survives in page
/// free space; the old files are truncated at commit and unlinked at the next
/// checkpoint. ACCESS EXCLUSIVE lock per table (intake serving is paused).
const SQL_VACUUM_FULL: &str = "VACUUM (FULL, ANALYZE false) candor.source_account, candor.envelope, \
     candor.envelope_part, candor.reply, candor.deletion_list, candor.counter_month, \
     candor.directory_snapshot, candor.intake_meta";
const SQL_CHECKPOINT: &str = "CHECKPOINT";
/// Session limits of the VACUUM connection (a daily VACUUM FULL may take minutes).
const VACUUM_SESSION_OPTIONS: [(&str, &str); 4] = [
    ("statement_timeout", "30min"),
    ("lock_timeout", "60s"),
    ("idle_in_transaction_session_timeout", "60s"),
    ("synchronous_commit", "on"),
];

const SQL_META_FULL: &str = "SELECT tenant_id, kdf_salt, relay_req_counter, last_batch_no, kd_tree_size_hwm, \
     (kd_checkpoint_day_hwm - DATE '1970-01-01')::int4, directory_version, \
     deletion_acked_seq, deletion_acked_hash, deletion_acked_sig, \
     (deletion_acked_day - DATE '1970-01-01')::int4, deletion_acked_counter FROM candor.intake_meta";
const SQL_META_SALT: &str = "SELECT kdf_salt FROM candor.intake_meta FOR UPDATE";
const SQL_NONEMPTY: &str = "SELECT EXISTS (SELECT 1 FROM candor.source_account) OR EXISTS (SELECT 1 FROM candor.envelope) \
     OR EXISTS (SELECT 1 FROM candor.reply) OR EXISTS (SELECT 1 FROM candor.deletion_list)";
const SQL_META_RESTORE: &str = "UPDATE candor.intake_meta SET \
     relay_req_counter = GREATEST(relay_req_counter, $1), last_batch_no = GREATEST(last_batch_no, $2), \
     kd_tree_size_hwm = GREATEST(kd_tree_size_hwm, $3), \
     kd_checkpoint_day_hwm = GREATEST(kd_checkpoint_day_hwm, DATE '1970-01-01' + $4::int4), \
     directory_version = GREATEST(directory_version, $5), restore_pending = true";
const SQL_META_RESTORE_INSERT: &str = "INSERT INTO candor.intake_meta (tenant_id, schema_hash, kdf_salt, \
     relay_req_counter, last_batch_no, kd_tree_size_hwm, kd_checkpoint_day_hwm, directory_version, restore_pending) \
     VALUES ($1, $2, $3, $4, $5, $6, DATE '1970-01-01' + $7::int4, $8, true) ON CONFLICT DO NOTHING";

/// Re-assert the per-session settings on every connection as startup options,
/// which take precedence over role and database defaults (a role can rewrite
/// its own defaults, AUD-RM2-STO-08). `temp_file_limit` is superuser-only and
/// cannot be set (or changed) by the role; it is checked instead.
const SESSION_OPTIONS: [(&str, &str); 7] = [
    ("statement_timeout", "30s"),
    ("idle_in_transaction_session_timeout", "60s"),
    ("lock_timeout", "10s"),
    ("search_path", "candor"),
    ("synchronous_commit", "on"),
    ("row_security", "on"),
    ("default_transaction_read_only", "off"),
];

/// Run all pending embedded migrations, each in its own transaction with lock and
/// statement timeouts (R7 SI-E-06). Intended for `candorctl migrate`, run as the
/// database owner; never called at service start. Already-applied migrations
/// must match their recorded SHA-256 (tamper/drift detection).
pub async fn migrate(opts: &PgConnectOptions) -> Result<()> {
    let mut conn = PgConnection::connect_with(&opts.clone().disable_statement_logging())
        .await
        .map_err(db)?;
    for (version, sql) in MIGRATIONS {
        let digest: [u8; 32] = Sha256::digest(sql.as_bytes()).into();
        let mut tx = conn.begin().await.map_err(db)?;
        sqlx::query(SQL_MIGRATE_TIMEOUTS)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let ledger: bool = sqlx::query(SQL_LEDGER_EXISTS)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?
            .try_get(0)
            .map_err(db)?;
        if ledger {
            let got = sqlx::query(SQL_LEDGER_GET)
                .bind(*version)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
            if let Some(row) = got {
                if get_arr::<32>(&row, 0)? != digest {
                    return Err(StoreError::Integrity(
                        "applied migration differs from build",
                    ));
                }
                tx.rollback().await.map_err(db)?;
                continue;
            }
        }
        sqlx::raw_sql(*sql).execute(&mut *tx).await.map_err(db)?;
        sqlx::query(SQL_LEDGER_PUT)
            .bind(*version)
            .bind(digest.as_slice())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
    }
    conn.close().await.map_err(db)
}

/// Connect as the maintenance role for VACUUM and verify its identity (see
/// `SQL_VACUUM_ROLE_CHECK`; fail closed).
async fn vacuum_conn(vacuum_opts: &PgConnectOptions) -> Result<PgConnection> {
    let mut conn = PgConnection::connect_with(
        &vacuum_opts
            .clone()
            .disable_statement_logging()
            .options(VACUUM_SESSION_OPTIONS),
    )
    .await
    .map_err(db)?;
    let row = sqlx::query(SQL_VACUUM_ROLE_CHECK)
        .fetch_one(&mut conn)
        .await
        .map_err(db)?;
    let privileged: bool = row.try_get(0).map_err(db)?;
    let db_owner: bool = row.try_get(1).map_err(db)?;
    if privileged || !db_owner {
        return Err(StoreError::Integrity(
            "vacuum login must own the database and nothing else",
        ));
    }
    Ok(conn)
}

/// Slot VACUUM (AUD-RM2-STO-11/18/24): run right after each slot's
/// [`IntakeStore::uniform_rewrite`] commits. Autovacuum is off on the intake
/// cluster (`autovacuum = off`, `track_counts = off`, and per table), so this
/// scheduled run is the routine VACUUM; it follows the fixed slot schedule,
/// never source activity. It makes the dead pre-rewrite heap and TOAST tuples
/// reclaimable. It connects as the maintenance role (`candor_intake_maint`,
/// OS user `candor-imaint`), which owns the database but no table and no schema
/// (PostgreSQL 16 lets the database owner vacuum; no `SET ROLE` to the schema
/// owner is needed or possible), never as the schema owner or the app role;
/// the identity is checked first.
pub async fn vacuum_after_rewrite(vacuum_opts: &PgConnectOptions) -> Result<()> {
    let mut conn = vacuum_conn(vacuum_opts).await?;
    sqlx::raw_sql(SQL_VACUUM)
        .execute(&mut conn)
        .await
        .map_err(db)?;
    conn.close().await.map_err(db)
}

/// Daily maintenance-window `VACUUM FULL` (AUD-RM2-STO-23), at a fixed time
/// after the day's last slot, as the maintenance role: rewrites every
/// source-linkable table with its TOAST table and indexes into new files, so
/// no pre-rewrite tuple image (old `xmin`, old TOAST `chunk_id`) survives in
/// page free space, then `CHECKPOINT`s so that the old files are unlinked
/// (needs `pg_checkpoint`, granted at provisioning). Each table is locked
/// ACCESS EXCLUSIVE while it is rewritten: the intake daemon pauses serving
/// for the window (requests would otherwise wait up to `lock_timeout` and
/// fail). An error leaves the remaining tables for the next run; the job
/// retries within the window.
pub async fn vacuum_full_daily(vacuum_opts: &PgConnectOptions) -> Result<()> {
    let mut conn = vacuum_conn(vacuum_opts).await?;
    sqlx::raw_sql(SQL_VACUUM_FULL)
        .execute(&mut conn)
        .await
        .map_err(db)?;
    sqlx::raw_sql(SQL_CHECKPOINT)
        .execute(&mut conn)
        .await
        .map_err(db)?;
    conn.close().await.map_err(db)
}

/// Read the acknowledged head columns (`seq, hash, sig, day, counter` at
/// `i..i+5`).
fn acked_from_row(r: &PgRow, i: usize) -> Result<Option<SignedDeletionHead>> {
    let seq = get_u64(r, i)?;
    let hash: Option<Vec<u8>> = r.try_get(i.saturating_add(1)).map_err(db)?;
    let sig: Option<Vec<u8>> = r.try_get(i.saturating_add(2)).map_err(db)?;
    let day: Option<i32> = r.try_get(i.saturating_add(3)).map_err(db)?;
    let counter = get_u64(r, i.saturating_add(4))?;
    match (seq, hash, sig, day, counter) {
        (0, None, None, None, 0) => Ok(None),
        (s, Some(h), Some(g), Some(d), c) if s > 0 && c > 0 => Ok(Some(SignedDeletionHead {
            seq: s,
            head_hash: h
                .try_into()
                .map_err(|_| StoreError::Integrity("column length"))?,
            day: u32::try_from(d)
                .map(Day)
                .map_err(|_| StoreError::Integrity("day"))?,
            counter: c,
            sig: g
                .try_into()
                .map_err(|_| StoreError::Integrity("column length"))?,
        })),
        _ => Err(StoreError::Integrity("acknowledged head")),
    }
}

async fn acked_head(tx: &mut PgConnection) -> Result<Option<SignedDeletionHead>> {
    acked_from_row(
        &sqlx::query(SQL_DEL_ACKED).fetch_one(tx).await.map_err(db)?,
        0,
    )
}

async fn store_acked(tx: &mut PgConnection, h: &SignedDeletionHead) -> Result<()> {
    sqlx::query(SQL_DEL_ACK)
        .bind(i64_of(h.seq)?)
        .bind(h.head_hash.as_slice())
        .bind(h.sig.as_slice())
        .bind(day_i32(h.day)?)
        .bind(i64_of(h.counter)?)
        .execute(tx)
        .await
        .map_err(db_classified)?;
    Ok(())
}

/// Session hardening check of one connection (AUD-RM2-STO-08, see
/// `SQL_SESSION_CHECK`).
async fn session_ok(conn: &mut PgConnection) -> std::result::Result<bool, sqlx::Error> {
    let row = sqlx::query(SQL_SESSION_CHECK).fetch_one(conn).await?;
    let stored: Vec<String> = row.try_get(0)?;
    if !stored
        .iter()
        .all(|e| ALLOWED_ROLE_SETTINGS.contains(&e.as_str()) || e.starts_with("temp_file_limit="))
    {
        return Ok(false);
    }
    for (i, want) in EXPECTED_SESSION.iter().enumerate() {
        let got: String = row.try_get(i.saturating_add(1))?;
        if got != *want {
            return Ok(false);
        }
    }
    let tfl: String = row.try_get(EXPECTED_SESSION.len().saturating_add(1))?;
    Ok(tfl
        .parse::<i64>()
        .is_ok_and(|kb| (1..=MAX_TEMP_FILE_LIMIT_KB).contains(&kb)))
}

/// Open a pool for an intake role and verify its privileges, its session
/// settings and the live guards (`other` = the intake role this one must not
/// be a member of). Every later pool connection re-runs the session check.
async fn open_pool(
    opts: PgConnectOptions,
    max_connections: u32,
    other: &str,
    db_owner_ok: bool,
) -> Result<PgPool> {
    let opts = opts.options(SESSION_OPTIONS);
    // Checked on a dedicated connection first, so that a refusal is a typed
    // `Integrity` error rather than a pool connection failure.
    let mut conn = PgConnection::connect_with(&opts.clone().disable_statement_logging())
        .await
        .map_err(db)?;
    let row = sqlx::query(SQL_ROLE_CHECK)
        .bind(other)
        .bind(db_owner_ok)
        .fetch_one(&mut conn)
        .await
        .map_err(db)?;
    let sup: bool = row.try_get(0).map_err(db)?;
    let bypass: bool = row.try_get(1).map_err(db)?;
    let owner_member: bool = row.try_get(2).map_err(db)?;
    let other_member: bool = row.try_get(3).map_err(db)?;
    let unforced: i64 = row.try_get(4).map_err(db)?;
    let triggers: i64 = row.try_get(5).map_err(db)?;
    let policies: i64 = row.try_get(6).map_err(db)?;
    let tenant_policies: i64 = row.try_get(7).map_err(db)?;
    if sup || bypass || owner_member || other_member {
        return Err(StoreError::Integrity(
            "intake role is privileged or a member of an owning role",
        ));
    }
    if unforced != 0
        || triggers != EXPECTED_GUARD_TRIGGERS
        || policies != EXPECTED_POLICIES
        || tenant_policies != EXPECTED_POLICIES
    {
        return Err(StoreError::Integrity("schema guards disabled"));
    }
    if !session_ok(&mut conn).await.map_err(db)? {
        return Err(StoreError::Integrity("session settings differ"));
    }
    let applied = sqlx::query(SQL_LEDGER_ALL)
        .fetch_all(&mut conn)
        .await
        .map_err(db)?;
    if applied.len() != MIGRATIONS.len() {
        return Err(StoreError::Integrity("schema version mismatch"));
    }
    for (row, (v, sql)) in applied.iter().zip(MIGRATIONS) {
        let got_v: i32 = row.try_get(0).map_err(db)?;
        let digest: [u8; 32] = Sha256::digest(sql.as_bytes()).into();
        if got_v != *v || get_arr::<32>(row, 1)? != digest {
            return Err(StoreError::Integrity("schema version mismatch"));
        }
    }
    conn.close().await.map_err(db)?;
    PgPoolOptions::new()
        .max_connections(max_connections.max(1))
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                if session_ok(conn).await? {
                    Ok(())
                } else {
                    Err(sqlx::Error::Protocol("session settings differ".into()))
                }
            })
        })
        .connect_with(opts.disable_statement_logging())
        .await
        .map_err(db)
}

async fn begin_tenant(pool: &PgPool, tenant: &TenantId) -> Result<Transaction<'static, Postgres>> {
    let mut tx = pool.begin().await.map_err(db)?;
    sqlx::query(SQL_SET_TENANT)
        .bind(uuid(&tenant.0))
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    Ok(tx)
}

/// PostgreSQL-backed Intake Store (application role `candor_istore`).
pub struct PgIntakeStore {
    pool: PgPool,
    tenant: TenantId,
    published: RwLock<Arc<PublishedSet>>,
    dummies: Box<dyn DummyReplies>,
    cfg: DeadDropConfig,
    maint: Option<PgIntakeMaintenance>,
}

impl core::fmt::Debug for PgIntakeStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PgIntakeStore")
    }
}

struct MetaRow {
    tenant: TenantId,
    restore_pending: bool,
}

impl MetaRow {
    fn serving(&self) -> Result<()> {
        if self.restore_pending {
            return Err(StoreError::RestorePending);
        }
        Ok(())
    }
}

impl PgIntakeStore {
    /// Connect as the application role (`candor_istore`, peer auth over the Unix
    /// socket in production). Refuses a superuser, a BYPASSRLS role, a member of
    /// an owning role or of the maintenance role, disabled RLS or guard
    /// triggers, and a schema that differs from this build (BE-050). The dummy
    /// source is mandatory (production passes real-format dummies, 08 §3.8).
    ///
    /// An initialised store enters restore-pending here, at every process start,
    /// until [`IntakeStore::apply_pushed_deletion_list`] confirms the Z-CORE head
    /// (07 BE-074, failover to a recovered node; AUD-RM2-STO-05).
    pub async fn open(
        opts: PgConnectOptions,
        tenant: TenantId,
        max_connections: u32,
        cfg: DeadDropConfig,
        dummies: Box<dyn DummyReplies>,
    ) -> Result<Self> {
        cfg.validate()?;
        let pool = open_pool(opts, max_connections, "candor_intake_maint", false).await?;
        let empty = deaddrop::empty(&cfg, dummies.as_ref())?;
        let store = Self {
            pool,
            tenant,
            published: RwLock::new(Arc::new(empty)),
            dummies,
            cfg,
            maint: None,
        };
        // If initialised, the recorded schema hash must match (BE-050), and the
        // store must re-synchronise with Z-CORE before serving.
        let mut tx = store.begin_raw().await?;
        let recorded = sqlx::query(SQL_META_HASH)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        if let Some(r) = recorded {
            if get_arr::<32>(&r, 0)? != schema_hash() {
                return Err(StoreError::Integrity("schema hash mismatch"));
            }
            sqlx::query(SQL_SET_PENDING)
                .execute(&mut *tx)
                .await
                .map_err(db_classified)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(store)
    }

    /// Attach a maintenance handle so that this value also implements
    /// [`IntakeMaintenance`] (tests, single-process deployments). Production
    /// runs maintenance in a separate process under its own OS user.
    #[must_use]
    pub fn with_maintenance(mut self, m: PgIntakeMaintenance) -> Self {
        self.maint = Some(m);
        self
    }

    /// Close the pool(s).
    pub async fn close(&self) {
        self.pool.close().await;
        if let Some(m) = &self.maint {
            m.close().await;
        }
    }

    async fn begin_raw(&self) -> Result<Transaction<'static, Postgres>> {
        begin_tenant(&self.pool, &self.tenant).await
    }

    /// Begin a tenant-scoped transaction and read `intake_meta` (row-locked when
    /// `lock`); `NotInitialized` if no row is visible.
    async fn begin(&self, lock: bool) -> Result<(Transaction<'static, Postgres>, MetaRow)> {
        let mut tx = self.begin_raw().await?;
        let q = if lock { SQL_META_LOCK } else { SQL_META };
        let row = sqlx::query(q)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or(StoreError::NotInitialized)?;
        let meta = MetaRow {
            tenant: TenantId(get_id(&row, 0)?),
            restore_pending: row.try_get(1).map_err(db)?,
        };
        Ok((tx, meta))
    }

    /// Persist restore-pending (fail closed after a rejected push).
    async fn persist_pending(&self) -> Result<()> {
        let mut tx = self.begin_raw().await?;
        sqlx::query(SQL_SET_PENDING)
            .execute(&mut *tx)
            .await
            .map_err(db_classified)?;
        tx.commit().await.map_err(db)
    }

    async fn check_owned(
        &self,
        tx: &mut PgConnection,
        account: AccountId,
        ids: &[Uuid],
    ) -> Result<()> {
        let exists: bool = sqlx::query(SQL_ACCOUNT_EXISTS)
            .bind(uuid(&account.0))
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?
            .try_get(0)
            .map_err(db)?;
        if !exists {
            return Err(StoreError::NotFound);
        }
        let n = get_u64(
            &sqlx::query(SQL_REPLIES_OWNED)
                .bind(ids)
                .bind(uuid(&account.0))
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?,
            0,
        )?;
        if usize::try_from(n).ok() != Some(ids.len()) {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn insert_dummy(&self, tx: &mut PgConnection, day: i32, generation: i64) -> Result<()> {
        let (body, bucket) = deaddrop::dummy_row(self.dummies.as_ref(), &self.cfg)?;
        let n = sqlx::query(SQL_REPLY_INSERT)
            .bind(uuid(&random_id16()?))
            .bind(Option::<Uuid>::None)
            .bind(body.as_slice())
            .bind(i16::from(bucket))
            .bind(day)
            .bind(Option::<i16>::None)
            .bind(Some(generation))
            .execute(tx)
            .await
            .map_err(db_classified)?
            .rows_affected();
        if n != 1 {
            return Err(StoreError::Integrity("reply ref collision"));
        }
        Ok(())
    }

    /// The RL-12 merge under the row lock (signatures already verified).
    async fn merge_and_apply(
        &self,
        entries: &[DeletionEntry],
        zhead: &SignedDeletionHead,
        hasher: &dyn ReplyObjectHasher,
    ) -> Result<u64> {
        let (mut tx, m) = self.begin(true).await?;
        let local: Vec<DeletionEntry> = sqlx::query(SQL_DEL_ALL)
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?
            .iter()
            .map(entry_from_row)
            .collect::<Result<_>>()?;
        let verified = acked_head(&mut tx).await?;
        let mut new = validate::merge_pushed(&local, verified.as_ref(), entries, zhead)?;
        // Chain-extending order for the database guard (AUD-RM2-STO-21).
        validate::insertion_order(local.first().map(|e| e.seq), &mut new);
        for e in &new {
            insert_entry(&mut tx, e).await?;
        }
        // The verified head is part of the merged chain: it becomes the
        // acknowledged head (monotonic; AUD-RM2-STO-22).
        if zhead.seq > 0 && verified.is_none_or(|v| v.counter < zhead.counter) {
            store_acked(&mut tx, zhead).await?;
        }
        let acct: HashSet<[u8; 32]> = local
            .iter()
            .chain(new.iter())
            .filter(|e| e.kind == DeletionKind::Account)
            .map(|e| e.del_hash)
            .collect();
        let reps: HashSet<[u8; 32]> = local
            .iter()
            .chain(new.iter())
            .filter(|e| e.kind == DeletionKind::Reply)
            .map(|e| e.del_hash)
            .collect();
        if !acct.is_empty() {
            let rows = sqlx::query(SQL_ACCOUNTS_ALL)
                .fetch_all(&mut *tx)
                .await
                .map_err(db)?;
            for r in &rows {
                let a = account_from_row(r)?;
                if acct.contains(&account_del_hash(&m.tenant, &a.lookup_tag)) {
                    sqlx::query(SQL_ACCOUNT_DELETE)
                        .bind(uuid(&a.account_id.0))
                        .execute(&mut *tx)
                        .await
                        .map_err(db)?;
                }
            }
        }
        if !reps.is_empty() {
            let mut cursor = Uuid::nil();
            loop {
                let rows = sqlx::query(SQL_REPLIES_PAGE)
                    .bind(cursor)
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(db)?;
                let Some(last) = rows.last() else { break };
                cursor = uuid(&get_id(last, 0)?);
                for r in &rows {
                    let ct: Vec<u8> = r.try_get(1).map_err(db)?;
                    if hasher
                        .object_hash(&ct)
                        .is_some_and(|h| reps.contains(&reply_del_hash(&m.tenant, &h)))
                    {
                        sqlx::query(SQL_REPLY_DELETE_ONE)
                            .bind(uuid(&get_id(r, 0)?))
                            .execute(&mut *tx)
                            .await
                            .map_err(db)?;
                    }
                }
            }
        }
        sqlx::query(SQL_CLEAR_RESTORE)
            .execute(&mut *tx)
            .await
            .map_err(db_classified)?;
        let through = head(&mut tx).await?.map_or(0, |e| e.seq);
        tx.commit().await.map_err(db)?;
        Ok(through)
    }
}

/// Rewrite every row of every source-linkable table (AUD-RM2-STO-01).
async fn rewrite_all(tx: &mut PgConnection, slot_day: Day, active: &[Uuid]) -> Result<()> {
    sqlx::query(SQL_REWRITE_ACCOUNTS)
        .bind(day_i32(slot_day)?)
        .bind(active)
        .bind(day_i32(slot_day.month_start())?)
        .execute(&mut *tx)
        .await
        .map_err(db_classified)?;
    for q in SQL_REWRITE {
        sqlx::query(*q)
            .execute(&mut *tx)
            .await
            .map_err(db_classified)?;
    }
    recreate_toast(tx).await
}

/// One row holding out-of-line values.
enum ToastRow {
    Part(Uuid, i16),
    Reply(Uuid),
    Snapshot(i64),
}

/// Re-create every out-of-line value in a CSPRNG-shuffled order
/// (AUD-RM2-STO-18, see `SQL_RECREATE_*`).
async fn recreate_toast(tx: &mut PgConnection) -> Result<()> {
    let mut rows: Vec<ToastRow> = Vec::new();
    for r in sqlx::query(SQL_TOAST_PARTS)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?
    {
        rows.push(ToastRow::Part(
            uuid(&get_id(&r, 0)?),
            r.try_get(1).map_err(db)?,
        ));
    }
    for r in sqlx::query(SQL_TOAST_REPLIES)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?
    {
        rows.push(ToastRow::Reply(uuid(&get_id(&r, 0)?)));
    }
    for r in sqlx::query(SQL_TOAST_SNAPSHOTS)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?
    {
        rows.push(ToastRow::Snapshot(r.try_get(0).map_err(db)?));
    }
    deaddrop::shuffle(&mut rows)?;
    for row in &rows {
        let q = match row {
            ToastRow::Part(e, n) => sqlx::query(SQL_RECREATE_PART).bind(*e).bind(*n),
            ToastRow::Reply(r) => sqlx::query(SQL_RECREATE_REPLY).bind(*r),
            ToastRow::Snapshot(v) => sqlx::query(SQL_RECREATE_SNAPSHOT).bind(*v),
        };
        // A row removed concurrently (e.g. expiry) simply matches nothing.
        q.execute(&mut *tx).await.map_err(db_classified)?;
    }
    Ok(())
}

fn account_from_row(r: &PgRow) -> Result<SourceAccount> {
    Ok(SourceAccount {
        account_id: AccountId(get_id(r, 0)?),
        lookup_tag: LookupTag(get_arr(r, 1)?),
        auth_pk: get_arr(r, 2)?,
        xwing_pk: r.try_get(3).map_err(db)?,
        prefs_ct: r.try_get(4).map_err(db)?,
        activity_month: get_day(r, 5)?,
    })
}

fn entry_from_row(r: &PgRow) -> Result<DeletionEntry> {
    let kind: String = r.try_get(1).map_err(db)?;
    Ok(DeletionEntry {
        seq: get_u64(r, 0)?,
        kind: DeletionKind::parse(&kind)?,
        del_hash: get_arr(r, 2)?,
        del_day: get_day(r, 3)?,
        prev_hash: get_arr(r, 4)?,
        sig: get_arr(r, 5)?,
        relayed: r.try_get(6).map_err(db)?,
    })
}

async fn insert_entry(tx: &mut PgConnection, e: &DeletionEntry) -> Result<()> {
    let n = sqlx::query(SQL_DEL_INSERT)
        .bind(i64_of(e.seq)?)
        .bind(e.kind.as_str())
        .bind(e.del_hash.as_slice())
        .bind(day_i32(e.del_day)?)
        .bind(e.prev_hash.as_slice())
        .bind(e.sig.as_slice())
        .execute(tx)
        .await
        .map_err(db_classified)?
        .rows_affected();
    if n != 1 {
        return Err(StoreError::Integrity("deletion seq already present"));
    }
    Ok(())
}

async fn head(tx: &mut PgConnection) -> Result<Option<DeletionEntry>> {
    sqlx::query(SQL_DEL_HEAD)
        .fetch_optional(tx)
        .await
        .map_err(db)?
        .as_ref()
        .map(entry_from_row)
        .transpose()
}

async fn batch_objects(tx: &mut PgConnection, b: i64) -> Result<Vec<ClaimedObject>> {
    let rows = sqlx::query(SQL_BATCH_OBJECTS)
        .bind(b)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
    let parts = sqlx::query(SQL_BATCH_PARTS)
        .bind(b)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let er = get_id(r, 0)?;
        let mut hashes = [[0u8; 32]; GROUP_OBJECTS];
        let mut sizes = [0u64; GROUP_OBJECTS];
        let mut seen = 0usize;
        for p in &parts {
            if get_id(p, 0)? != er {
                continue;
            }
            let pn: i16 = p.try_get(1).map_err(db)?;
            let i = usize::try_from(pn).map_err(|_| StoreError::Integrity("part"))?;
            *hashes.get_mut(i).ok_or(StoreError::Integrity("part"))? = get_arr(p, 2)?;
            *sizes.get_mut(i).ok_or(StoreError::Integrity("part"))? = get_u64(p, 3)?;
            seen = seen.saturating_add(1);
        }
        if seen != GROUP_OBJECTS {
            return Err(StoreError::Integrity("envelope group shape"));
        }
        let epoch: i32 = r.try_get(2).map_err(db)?;
        out.push(ClaimedObject {
            envelope_ref: EnvelopeRef(er),
            channel_id: ChannelId(get_id(r, 1)?),
            epoch_index: u32::try_from(epoch).map_err(|_| StoreError::Integrity("epoch"))?,
            object_hashes: hashes,
            parts: sizes,
            sha256: get_arr(r, 3)?,
            disposition_ct: r.try_get(4).map_err(db)?,
        });
    }
    Ok(out)
}

impl IntakeStore for PgIntakeStore {
    async fn init(&self, tenant: TenantId, kdf_salt: [u8; 32]) -> Result<()> {
        if tenant != self.tenant {
            return Err(StoreError::TenantMismatch);
        }
        let mut tx = self.begin_raw().await?;
        if sqlx::query(SQL_META)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .is_some()
        {
            return tx.rollback().await.map_err(db);
        }
        let hash = schema_hash();
        let n = sqlx::query(SQL_META_INSERT)
            .bind(uuid(&tenant.0))
            .bind(hash.as_slice())
            .bind(kdf_salt.as_slice())
            .execute(&mut *tx)
            .await
            .map_err(db_classified)?
            .rows_affected();
        if n != 1 {
            // Another tenant's row exists (invisible under RLS): singleton.
            return Err(StoreError::TenantMismatch);
        }
        tx.commit().await.map_err(db)
    }

    async fn tenant(&self) -> Result<TenantId> {
        let (tx, m) = self.begin(false).await?;
        tx.rollback().await.map_err(db)?;
        Ok(m.tenant)
    }

    async fn accept_relay_counter(&self, counter: u64) -> Result<()> {
        let c = i64_of(counter)?;
        let (mut tx, _) = self.begin(true).await?;
        let n = sqlx::query(SQL_COUNTER_BUMP)
            .bind(c)
            .execute(&mut *tx)
            .await
            .map_err(db)?
            .rows_affected();
        if n != 1 {
            return Err(StoreError::Replay);
        }
        tx.commit().await.map_err(db)
    }

    async fn serving_allowed(&self) -> Result<bool> {
        let (tx, m) = self.begin(false).await?;
        tx.rollback().await.map_err(db)?;
        Ok(!m.restore_pending)
    }

    async fn mark_restore_pending(&self) -> Result<()> {
        let (mut tx, _) = self.begin(true).await?;
        sqlx::query(SQL_SET_PENDING)
            .execute(&mut *tx)
            .await
            .map_err(db_classified)?;
        tx.commit().await.map_err(db)
    }

    async fn lookup_account(&self, tag: &LookupTag) -> Result<Option<SourceAccount>> {
        let (mut tx, m) = self.begin(false).await?;
        m.serving()?;
        let row = sqlx::query(SQL_ACCOUNT_BY_TAG)
            .bind(tag.0.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        tx.rollback().await.map_err(db)?;
        row.as_ref().map(account_from_row).transpose()
    }

    async fn delete_account(
        &self,
        account: AccountId,
        today: Day,
        signer: &dyn DeletionSigner,
    ) -> Result<()> {
        day_i32(today)?;
        let (mut tx, m) = self.begin(true).await?;
        m.serving()?;
        let row = sqlx::query(SQL_ACCOUNT_TAG_LOCK)
            .bind(uuid(&account.0))
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or(StoreError::NotFound)?;
        let tag = LookupTag(get_arr(&row, 0)?);
        let h = head(&mut tx).await?;
        let e = make_entry(
            h.as_ref(),
            DeletionKind::Account,
            account_del_hash(&m.tenant, &tag),
            today,
            signer,
        )?;
        insert_entry(&mut tx, &e).await?;
        sqlx::query(SQL_ACCOUNT_DELETE)
            .bind(uuid(&account.0))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)
    }

    async fn create_account(&self, account: NewAccount, today: Day) -> Result<AccountId> {
        validate::new_account(&account)?;
        let month = day_i32(today.month_start())?;
        let (mut tx, m) = self.begin(false).await?;
        m.serving()?;
        let id = random_id16()?;
        let inserted = sqlx::query(SQL_ACCOUNT_INSERT)
            .bind(uuid(&id))
            .bind(account.lookup_tag.0.as_slice())
            .bind(account.auth_pk.as_slice())
            .bind(account.xwing_pk.as_slice())
            .bind(account.prefs_ct.as_slice())
            .bind(month)
            .execute(&mut *tx)
            .await
            .map_err(db_classified)?
            .rows_affected();
        if inserted != 1 {
            return Err(StoreError::AccountExists);
        }
        tx.commit().await.map_err(db)?;
        Ok(AccountId(id))
    }

    async fn update_account(&self, account: AccountId, new: NewAccount) -> Result<()> {
        validate::new_account(&new)?;
        // The meta row lock serialises tag changes, so the NOT EXISTS guard
        // cannot race into a unique-violation error.
        let (mut tx, m) = self.begin(true).await?;
        m.serving()?;
        let n = sqlx::query(SQL_ACCOUNT_UPDATE)
            .bind(uuid(&account.0))
            .bind(new.lookup_tag.0.as_slice())
            .bind(new.auth_pk.as_slice())
            .bind(new.xwing_pk.as_slice())
            .bind(new.prefs_ct.as_slice())
            .execute(&mut *tx)
            .await
            .map_err(db_classified)?
            .rows_affected();
        if n != 1 {
            let exists: bool = sqlx::query(SQL_ACCOUNT_EXISTS)
                .bind(uuid(&account.0))
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?
                .try_get(0)
                .map_err(db)?;
            return Err(if exists {
                StoreError::AccountExists
            } else {
                StoreError::NotFound
            });
        }
        tx.commit().await.map_err(db)
    }

    async fn purge_inactive_accounts(&self, today: Day) -> Result<u64> {
        let cutoff = day_i32(today.saturating_minus(INACTIVE_PURGE_DAYS))?;
        let (mut tx, _) = self.begin(true).await?;
        let n = sqlx::query(SQL_ACCOUNTS_PURGE)
            .bind(cutoff)
            .execute(&mut *tx)
            .await
            .map_err(db)?
            .rows_affected();
        tx.commit().await.map_err(db)?;
        Ok(n)
    }

    async fn commit_envelope(&self, env: CommitEnvelope) -> Result<EnvelopeRef> {
        validate::commit(&env)?;
        let received = day_i32(env.received_date)?;
        let release = day_i32(env.received_date.plus(u32::from(env.release_offset_days))?)?;
        let epoch =
            i32::try_from(env.epoch_index).map_err(|_| StoreError::InvalidInput("epoch index"))?;
        let digest = group_digest(&env.objects.clone().map(|o| o.object_hash));
        let (mut tx, m) = self.begin(false).await?;
        m.serving()?;
        let er = random_id16()?;
        let inserted = sqlx::query(SQL_ENV_INSERT)
            .bind(uuid(&er))
            .bind(uuid(&env.channel_id.0))
            .bind(digest.as_slice())
            .bind(env.disposition_ct.as_slice())
            .bind(epoch)
            .bind(received)
            .bind(release)
            .execute(&mut *tx)
            .await
            .map_err(db_classified)?
            .rows_affected();
        if inserted != 1 {
            return Err(StoreError::DuplicateEnvelope);
        }
        for (i, o) in env.objects.iter().enumerate() {
            let inserted = sqlx::query(SQL_PART_INSERT)
                .bind(uuid(&er))
                .bind(i16::try_from(i).map_err(|_| StoreError::InvalidInput("part"))?)
                .bind(o.object_hash.as_slice())
                .bind(o.slot_block.as_slice())
                .bind(uuid(&o.blob.blob_id.0))
                .bind(i64_of(o.blob.padded_size)?)
                .execute(&mut *tx)
                .await
                .map_err(db_classified)?
                .rows_affected();
            if inserted != 1 {
                return Err(StoreError::InvalidInput("duplicate blob id"));
            }
        }
        // Durable on return: COMMIT waits for the WAL flush (fsync = on,
        // synchronous_commit default on; ADR-046(1)).
        tx.commit().await.map_err(db)?;
        Ok(EnvelopeRef(er))
    }

    async fn pending_count(&self) -> Result<u64> {
        let (mut tx, _) = self.begin(false).await?;
        let row = sqlx::query(SQL_PENDING)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        tx.rollback().await.map_err(db)?;
        get_u64(&row, 0)
    }

    async fn claim_batch(&self, today: Day, limits: ClaimLimits) -> Result<ClaimedBatch> {
        validate::claim_limits(limits)?;
        let d = day_i32(today)?;
        let (mut tx, _) = self.begin(true).await?;
        if let Some(r) = sqlx::query(SQL_INFLIGHT)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
        {
            let b: i64 = r.try_get(0).map_err(db)?;
            let objects = batch_objects(&mut tx, b).await?;
            tx.rollback().await.map_err(db)?;
            return Ok(ClaimedBatch {
                batch_no: u64::try_from(b).map_err(|_| StoreError::Integrity("batch"))?,
                replayed: true,
                objects,
            });
        }
        let cands = sqlx::query(SQL_CANDIDATES)
            .bind(d)
            .bind(i64::from(limits.max_objects))
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        let refs: Vec<Uuid> = cands
            .iter()
            .map(|r| get_id(r, 0).map(|b| uuid(&b)))
            .collect::<Result<_>>()?;
        let parts = sqlx::query(SQL_PART_SIZES)
            .bind(&refs)
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        let mut sizes = Vec::with_capacity(cands.len());
        for r in &cands {
            let er = get_id(r, 0)?;
            let mut ps = Vec::new();
            for p in &parts {
                if get_id(p, 0)? == er {
                    ps.push(get_u64(p, 1)?);
                }
            }
            sizes.push(validate::group_bytes(&ps));
        }
        let chosen: Vec<Uuid> = validate::fill_batch(&sizes, limits)
            .into_iter()
            .filter_map(|i| refs.get(i).copied())
            .collect();
        if chosen.is_empty() {
            tx.rollback().await.map_err(db)?;
            return Ok(ClaimedBatch {
                batch_no: 0,
                replayed: false,
                objects: Vec::new(),
            });
        }
        let last = get_u64(
            &sqlx::query(SQL_LAST_BATCH)
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?,
            0,
        )?;
        let b = last
            .checked_add(1)
            .ok_or(StoreError::Integrity("batch overflow"))?;
        let bi = i64_of(b)?;
        sqlx::query(SQL_SET_BATCH_NO)
            .bind(bi)
            .execute(&mut *tx)
            .await
            .map_err(db_classified)?;
        sqlx::query(SQL_CLAIM)
            .bind(bi)
            .bind(&chosen)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let objects = batch_objects(&mut tx, bi).await?;
        tx.commit().await.map_err(db)?;
        Ok(ClaimedBatch {
            batch_no: b,
            replayed: false,
            objects,
        })
    }

    async fn batch_object(
        &self,
        batch_no: u64,
        envelope: EnvelopeRef,
        part: PartSelector,
    ) -> Result<ObjectData> {
        let b = i64::try_from(batch_no).map_err(|_| StoreError::NotFound)?;
        let (mut tx, _) = self.begin(false).await?;
        let er = uuid(&envelope.0);
        let out = match part {
            PartSelector::SlotBlock(i) => {
                let row = sqlx::query(SQL_OBJ_SLOT)
                    .bind(er)
                    .bind(b)
                    .bind(i16::from(i))
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db)?;
                let row = row.ok_or(StoreError::NotFound)?;
                ObjectData::Bytes(row.try_get(0).map_err(db)?)
            }
            PartSelector::Object(i) => {
                let row = sqlx::query(SQL_OBJ_PART)
                    .bind(er)
                    .bind(b)
                    .bind(i16::from(i))
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db)?;
                let row = row.ok_or(StoreError::NotFound)?;
                ObjectData::Blob(PartRef {
                    blob_id: BlobId(get_id(&row, 0)?),
                    padded_size: get_u64(&row, 1)?,
                })
            }
        };
        tx.rollback().await.map_err(db)?;
        Ok(out)
    }

    async fn ack_batch(&self, batch_no: u64, committed: &[[u8; 32]]) -> Result<AckResult> {
        let b = i64::try_from(batch_no).map_err(|_| StoreError::NotFound)?;
        let (mut tx, _) = self.begin(true).await?;
        let rows = sqlx::query(SQL_BATCH_DIGESTS)
            .bind(b)
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        if rows.is_empty() {
            return Err(StoreError::NotFound);
        }
        let in_batch: Vec<[u8; 32]> = rows.iter().map(|r| get_arr(r, 0)).collect::<Result<_>>()?;
        if committed.iter().any(|d| !in_batch.contains(d)) {
            return Err(StoreError::InvalidInput("digest not in batch"));
        }
        let digests: Vec<Vec<u8>> = committed.iter().map(|d| d.to_vec()).collect();
        let blobs = sqlx::query(SQL_ACK_BLOBS)
            .bind(b)
            .bind(&digests)
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        let blobs_to_delete = blobs
            .iter()
            .map(|r| get_id(r, 0).map(BlobId))
            .collect::<Result<_>>()?;
        let deleted = sqlx::query(SQL_ACK_DELETE)
            .bind(b)
            .bind(&digests)
            .execute(&mut *tx)
            .await
            .map_err(db)?
            .rows_affected();
        sqlx::query(SQL_UNCLAIM)
            .bind(b)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(AckResult {
            deleted: u32::try_from(deleted).unwrap_or(u32::MAX),
            blobs_to_delete,
        })
    }

    async fn apply_replies(
        &self,
        today: Day,
        replies: Vec<IncomingReply>,
    ) -> Result<ApplyRepliesResult> {
        let d = day_i32(today)?;
        if replies.len() > MAX_REPLIES_PER_PUSH {
            return Err(StoreError::InvalidInput("too many replies"));
        }
        let (mut tx, m) = self.begin(true).await?;
        m.serving()?;
        let mut pending = get_u64(
            &sqlx::query(SQL_REPLY_BACKLOG)
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?,
            0,
        )?;
        let max_pending = u64::from(self.cfg.max_pending);
        let mut res = ApplyRepliesResult::default();
        for (i, r) in replies.into_iter().enumerate() {
            let idx = u32::try_from(i).unwrap_or(u32::MAX);
            if !validate::reply(&r) {
                res.rejected.push(idx);
                continue;
            }
            let rh = reply_del_hash(&m.tenant, &r.object_hash);
            let mh = r
                .mailbox_id
                .as_ref()
                .map(|mb| mailbox_del_hash(&m.tenant, mb).to_vec());
            let listed: bool = sqlx::query(SQL_LISTED)
                .bind(rh.as_slice())
                .bind(mh)
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?
                .try_get(0)
                .map_err(db)?;
            let mut dropped = listed;
            let mut slot: Option<i16> = None;
            if let (false, Some(a)) = (dropped, r.account) {
                let exists: bool = sqlx::query(SQL_ACCOUNT_EXISTS)
                    .bind(uuid(&a.0))
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db)?
                    .try_get(0)
                    .map_err(db)?;
                if exists {
                    let used = sqlx::query(SQL_SLOTS_USED)
                        .bind(uuid(&a.0))
                        .fetch_all(&mut *tx)
                        .await
                        .map_err(db)?;
                    let used: Vec<i16> = used
                        .iter()
                        .map(|u| u.try_get(0).map_err(db))
                        .collect::<Result<_>>()?;
                    match (0..i16::from(MAILBOX_SLOTS)).find(|s| !used.contains(s)) {
                        Some(s) => slot = Some(s),
                        None => {
                            res.rejected.push(idx);
                            continue;
                        }
                    }
                } else {
                    dropped = true;
                }
            }
            if dropped {
                res.accepted = res.accepted.saturating_add(1);
                continue;
            }
            if pending >= max_pending {
                res.rejected.push(idx);
                continue;
            }
            let n = sqlx::query(SQL_REPLY_INSERT)
                .bind(uuid(&random_id16()?))
                .bind(r.account.map(|a| uuid(&a.0)))
                .bind(r.reply_ct.as_slice())
                .bind(i16::from(
                    reply_bucket_of_len(r.reply_ct.len())
                        .ok_or(StoreError::InvalidInput("reply length"))?,
                ))
                .bind(d)
                .bind(slot)
                .bind(Option::<i64>::None)
                .execute(&mut *tx)
                .await
                .map_err(db_classified)?
                .rows_affected();
            if n != 1 {
                return Err(StoreError::Integrity("reply ref collision"));
            }
            pending = pending.saturating_add(1);
            res.accepted = res.accepted.saturating_add(1);
        }
        tx.commit().await.map_err(db)?;
        Ok(res)
    }

    async fn mailbox_list(&self, account: AccountId) -> Result<Vec<StoredReply>> {
        let (mut tx, m) = self.begin(false).await?;
        m.serving()?;
        let rows = sqlx::query(SQL_MAILBOX)
            .bind(uuid(&account.0))
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        tx.rollback().await.map_err(db)?;
        rows.iter()
            .map(|r| {
                let slot: i16 = r.try_get(1).map_err(db)?;
                let sb: i16 = r.try_get(3).map_err(db)?;
                Ok(StoredReply {
                    reply_ref: ReplyRef(get_id(r, 0)?),
                    slot: u8::try_from(slot).map_err(|_| StoreError::Integrity("slot"))?,
                    reply_ct: r.try_get(2).map_err(db)?,
                    size_bucket: u8::try_from(sb).map_err(|_| StoreError::Integrity("bucket"))?,
                    available_day: get_day(r, 4)?,
                })
            })
            .collect()
    }

    async fn delete_replies(
        &self,
        account: AccountId,
        replies: &[(ReplyRef, [u8; 32])],
        today: Day,
        signer: &dyn DeletionSigner,
    ) -> Result<u32> {
        day_i32(today)?;
        if replies.len() > usize::from(MAILBOX_SLOTS) {
            return Err(StoreError::InvalidInput("too many replies"));
        }
        let refs: Vec<ReplyRef> = replies.iter().map(|r| r.0).collect();
        if has_duplicates(&refs) {
            return Err(StoreError::InvalidInput("duplicate reply"));
        }
        let (mut tx, m) = self.begin(true).await?;
        m.serving()?;
        let ids: Vec<Uuid> = refs.iter().map(|r| uuid(&r.0)).collect();
        self.check_owned(&mut tx, account, &ids).await?;
        let mut h = head(&mut tx).await?;
        for (_, oh) in replies {
            let e = make_entry(
                h.as_ref(),
                DeletionKind::Reply,
                reply_del_hash(&m.tenant, oh),
                today,
                signer,
            )?;
            insert_entry(&mut tx, &e).await?;
            h = Some(e);
        }
        sqlx::query(SQL_REPLIES_DELETE)
            .bind(&ids)
            .bind(uuid(&account.0))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(u32::try_from(replies.len()).unwrap_or(u32::MAX))
    }

    async fn delete_mailbox(
        &self,
        account: AccountId,
        mailbox: &MailboxId,
        replies: &[ReplyRef],
        today: Day,
        signer: &dyn DeletionSigner,
    ) -> Result<u32> {
        day_i32(today)?;
        if replies.len() > usize::from(MAILBOX_SLOTS) {
            return Err(StoreError::InvalidInput("too many replies"));
        }
        if has_duplicates(replies) {
            return Err(StoreError::InvalidInput("duplicate reply"));
        }
        let (mut tx, m) = self.begin(true).await?;
        m.serving()?;
        let ids: Vec<Uuid> = replies.iter().map(|r| uuid(&r.0)).collect();
        self.check_owned(&mut tx, account, &ids).await?;
        let h = head(&mut tx).await?;
        let e = make_entry(
            h.as_ref(),
            DeletionKind::Mailbox,
            mailbox_del_hash(&m.tenant, mailbox),
            today,
            signer,
        )?;
        insert_entry(&mut tx, &e).await?;
        sqlx::query(SQL_REPLIES_DELETE)
            .bind(&ids)
            .bind(uuid(&account.0))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(u32::try_from(replies.len()).unwrap_or(u32::MAX))
    }

    async fn purge_replies_before(&self, cutoff: Day) -> Result<u64> {
        let c = day_i32(cutoff)?;
        let (mut tx, _) = self.begin(false).await?;
        let n = sqlx::query(SQL_REPLIES_PURGE)
            .bind(c)
            .execute(&mut *tx)
            .await
            .map_err(db)?
            .rows_affected();
        tx.commit().await.map_err(db)?;
        Ok(n)
    }

    async fn expire_replies(&self, today: Day, retention_days: u32) -> Result<u64> {
        let keep = retention_days.min(REPLY_WINDOW_DAYS);
        self.purge_replies_before(today.saturating_minus(keep).plus(1)?)
            .await
    }

    async fn rebuild_published_set(&self, slot: ImportSlot) -> Result<ReplyIndex> {
        let cfg = self.cfg;
        let g = cfg.generation(slot)?;
        let gi = i64_of(g)?;
        let slot_day = day_i32(slot.day)?;
        let k = usize::from(cfg.per_slot);
        let total = u64::try_from(cfg.total_entries()?).map_err(|_| StoreError::Capacity)?;
        let (mut tx, _) = self.begin(true).await?;
        let last: Option<i64> = sqlx::query(SQL_PUB_LAST)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?
            .try_get(0)
            .map_err(db)?;
        let last = last
            .map(u64::try_from)
            .transpose()
            .map_err(|_| StoreError::Integrity("generation"))?;
        for h in deaddrop::generations_to_publish(&cfg, last, g) {
            let day = day_i32(cfg.day_of(h)?)?;
            let hi = i64_of(h)?;
            let mut reals = 0usize;
            if h == g {
                let rows = sqlx::query(SQL_PUB_PENDING)
                    .bind(i64::from(cfg.per_slot))
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(db)?;
                let ids: Vec<Uuid> = rows
                    .iter()
                    .map(|r| get_id(r, 0).map(|b| uuid(&b)))
                    .collect::<Result<_>>()?;
                reals = ids.len();
                sqlx::query(SQL_PUB_ASSIGN)
                    .bind(hi)
                    .bind(day)
                    .bind(&ids)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_classified)?;
            }
            // Dummies are sized from the configured distribution only, never
            // from the real replies of this generation (AUD-RM2-STO-19).
            for _ in reals..k {
                self.insert_dummy(&mut tx, day, hi).await?;
            }
        }
        // Padding pool: window + padding = total entries, exactly.
        let lo = i64_of(cfg.window_start(g))?;
        let window = get_u64(
            &sqlx::query(SQL_PUB_WINDOW_COUNT)
                .bind(lo)
                .bind(gi)
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?,
            0,
        )?;
        let padding = get_u64(
            &sqlx::query(SQL_PUB_PADDING_COUNT)
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?,
            0,
        )?;
        let want = total.checked_sub(window).ok_or(StoreError::Capacity)?;
        if padding > want {
            sqlx::query(SQL_PUB_PADDING_TRIM)
                .bind(i64_of(padding.saturating_sub(want))?)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        let pad_gen = i64_of(PADDING_GENERATION)?;
        for _ in padding..want {
            self.insert_dummy(&mut tx, slot_day, pad_gen).await?;
        }
        // Stream the window into the pre-reserved pages (AUD-RM2-STO-07).
        let mut builder = PageBuilder::new(cfg.page_count()?)?;
        let mut cursor = Uuid::nil();
        loop {
            let rows = sqlx::query(SQL_PUB_STREAM)
                .bind(lo)
                .bind(gi)
                .bind(cursor)
                .fetch_all(&mut *tx)
                .await
                .map_err(db)?;
            let Some(last) = rows.last() else { break };
            cursor = uuid(&get_id(last, 0)?);
            for r in &rows {
                let ct: Vec<u8> = r.try_get(1).map_err(db)?;
                builder.push(&ct)?;
            }
        }
        tx.commit().await.map_err(db)?;
        let set = builder.finish(self.dummies.as_ref(), &cfg)?;
        let idx = set.index();
        *self.published.write().await = Arc::new(set);
        Ok(idx)
    }

    async fn reply_index(&self) -> Result<ReplyIndex> {
        Ok(self.published.read().await.index())
    }

    async fn reply_page(&self, n: u16) -> Result<Arc<[u8]>> {
        self.published.read().await.page(n)
    }

    async fn deletion_list_after(&self, after: u64, limit: u32) -> Result<Vec<DeletionEntry>> {
        let a = i64::try_from(after).map_err(|_| StoreError::InvalidInput("after"))?;
        let lim = i64::from(limit.min(MAX_DELETION_LIST_PAGE));
        let (mut tx, _) = self.begin(false).await?;
        let head_seq = head(&mut tx).await?.map_or(0, |e| e.seq);
        if after > head_seq {
            return Err(StoreError::InvalidInput("after beyond head"));
        }
        let rows = sqlx::query(SQL_DEL_AFTER)
            .bind(a)
            .bind(lim)
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        tx.rollback().await.map_err(db)?;
        rows.iter().map(entry_from_row).collect()
    }

    async fn acknowledge_deletion_head(
        &self,
        head: &SignedDeletionHead,
        core_pk: &[u8; 32],
    ) -> Result<()> {
        head.verify(&self.tenant, core_pk)?;
        let (mut tx, m) = self.begin(true).await?;
        if m.tenant != self.tenant {
            return Err(StoreError::TenantMismatch);
        }
        let local: Vec<DeletionEntry> = sqlx::query(SQL_DEL_ALL)
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?
            .iter()
            .map(entry_from_row)
            .collect::<Result<_>>()?;
        let current = acked_head(&mut tx).await?;
        if validate::ack_head(&local, current.as_ref(), head)? {
            store_acked(&mut tx, head).await?;
            tx.commit().await.map_err(db)
        } else {
            tx.rollback().await.map_err(db)
        }
    }

    async fn apply_pushed_deletion_list(
        &self,
        entries: &[DeletionEntry],
        head: &SignedDeletionHead,
        core_pk: &[u8; 32],
        k31_pk: &[u8; 32],
        hasher: &dyn ReplyObjectHasher,
        today: Day,
    ) -> Result<u64> {
        // Head and entry signatures and the head's freshness are verified
        // before taking the row lock (AUD-RM2-STO-12/22/24).
        let r = match validate::verify_pushed(entries, k31_pk, head, &self.tenant, core_pk, today) {
            Ok(()) => self.merge_and_apply(entries, head, hasher).await,
            Err(e) => Err(e),
        };
        match r {
            Err(e @ (StoreError::DeletionList(_) | StoreError::InvalidInput(_))) => {
                // Fail closed: a rejected push leaves (or puts) the store in
                // restore-pending (AUD-RM2-STO-04).
                self.persist_pending().await?;
                Err(e)
            }
            other => other,
        }
    }

    async fn kd_high_water(&self) -> Result<KdHighWater> {
        let (mut tx, _) = self.begin(false).await?;
        let r = sqlx::query(SQL_HWM).fetch_one(&mut *tx).await.map_err(db)?;
        tx.rollback().await.map_err(db)?;
        hwm_from_row(&r)
    }

    async fn install_directory_snapshot(
        &self,
        snap: VerifiedSnapshot,
        today: Day,
    ) -> Result<InstallOutcome> {
        // applied_day at month granularity (AUD-RM2-STO-01).
        let d = day_i32(today.month_start())?;
        let (mut tx, _) = self.begin(true).await?;
        let hwm = hwm_from_row(
            &sqlx::query(SQL_HWM_LOCK)
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?,
        )?;
        let cur: Option<Vec<u8>> = match sqlx::query(SQL_SNAP_BODY)
            .bind(i64_of(hwm.directory_version)?)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
        {
            Some(r) => Some(r.try_get(0).map_err(db)?),
            None => None,
        };
        let decision = validate::snapshot(&hwm, cur.as_deref(), &snap)?;
        if decision == SnapshotDecision::AlreadyInstalled {
            tx.rollback().await.map_err(db)?;
            return Ok(InstallOutcome::AlreadyInstalled);
        }
        let v = i64_of(snap.version)?;
        let n = sqlx::query(SQL_SNAP_INSERT)
            .bind(v)
            .bind(snap.body.as_slice())
            .bind(snap.signatures.as_slice())
            .bind(d)
            .execute(&mut *tx)
            .await
            .map_err(db_classified)?
            .rows_affected();
        if n != 1 {
            return Err(StoreError::Conflict("snapshot version exists"));
        }
        sqlx::query(SQL_SNAP_META)
            .bind(i64_of(snap.tree_size)?)
            .bind(day_i32(snap.checkpoint_day)?)
            .bind(v)
            .execute(&mut *tx)
            .await
            .map_err(db_classified)?;
        sqlx::query(SQL_SNAP_PRUNE)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(InstallOutcome::Installed)
    }

    async fn current_directory_snapshot(&self) -> Result<Option<crate::store::InstalledSnapshot>> {
        let (mut tx, _) = self.begin(false).await?;
        let r = sqlx::query(SQL_SNAP_CURRENT)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        tx.rollback().await.map_err(db)?;
        r.map(|r| {
            Ok((
                get_u64(&r, 0)?,
                r.try_get(1).map_err(db)?,
                r.try_get(2).map_err(db)?,
            ))
        })
        .transpose()
    }

    async fn uniform_rewrite(
        &self,
        slot: ImportSlot,
        counters: &[CounterDelta],
        active_accounts: &[AccountId],
    ) -> Result<()> {
        day_i32(slot.day)?;
        if active_accounts.len() > MAX_SLOT_ACTIVE_ACCOUNTS {
            return Err(StoreError::InvalidInput("too many active accounts"));
        }
        for c in counters {
            validate::counter_delta(c)?;
        }
        let active: Vec<Uuid> = active_accounts.iter().map(|a| uuid(&a.0)).collect();
        let (mut tx, _) = self.begin(true).await?;
        for c in counters {
            let n = sqlx::query(SQL_COUNTER_ADD)
                .bind(day_i32(c.month)?)
                .bind(uuid(&c.channel_id.0))
                .bind(c.name.as_str())
                .bind(
                    i32::try_from(c.delta)
                        .map_err(|_| StoreError::InvalidInput("counter overflow"))?,
                )
                .execute(&mut *tx)
                .await
                .map_err(db_classified)?
                .rows_affected();
            if n != 1 {
                // Overflow: nothing of this flush is written (rollback on drop).
                return Err(StoreError::InvalidInput("counter overflow"));
            }
        }
        rewrite_all(&mut tx, slot.day, &active).await?;
        tx.commit().await.map_err(db)
    }

    async fn counters_for_month(&self, month: Day) -> Result<Vec<CounterCell>> {
        let mi = day_i32(month)?;
        let (mut tx, _) = self.begin(false).await?;
        let rows = sqlx::query(SQL_COUNTERS)
            .bind(mi)
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        tx.rollback().await.map_err(db)?;
        rows.iter()
            .map(|r| {
                let name: String = r.try_get(1).map_err(db)?;
                let v: i32 = r.try_get(2).map_err(db)?;
                Ok(CounterCell {
                    channel_id: ChannelId(get_id(r, 0)?),
                    name: CounterName::parse(&name)?,
                    value: u32::try_from(v).map_err(|_| StoreError::Integrity("counter"))?,
                })
            })
            .collect()
    }

    async fn prune_counters_before(&self, month: Day) -> Result<u64> {
        let mi = day_i32(month)?;
        let (mut tx, _) = self.begin(false).await?;
        let n = sqlx::query(SQL_COUNTERS_PRUNE)
            .bind(mi)
            .execute(&mut *tx)
            .await
            .map_err(db)?
            .rows_affected();
        tx.commit().await.map_err(db)?;
        Ok(n)
    }

    async fn export_backup(&self) -> Result<BackupSnapshot> {
        let (mut tx, _) = self.begin(false).await?;
        let mr = sqlx::query(SQL_META_FULL)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let accounts = sqlx::query(SQL_ACCOUNTS_ALL)
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        let dl = sqlx::query(SQL_DEL_ALL)
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        tx.rollback().await.map_err(db)?;
        let day: Option<i32> = mr.try_get(5).map_err(db)?;
        Ok(BackupSnapshot {
            meta: MetaSnapshot {
                tenant_id: TenantId(get_id(&mr, 0)?),
                kdf_salt: get_arr(&mr, 1)?,
                relay_req_counter: get_u64(&mr, 2)?,
                last_batch_no: get_u64(&mr, 3)?,
                kd: KdHighWater {
                    tree_size: get_u64(&mr, 4)?,
                    checkpoint_day: day
                        .map(|d| u32::try_from(d).map(Day))
                        .transpose()
                        .map_err(|_| StoreError::Integrity("day"))?,
                    directory_version: get_u64(&mr, 6)?,
                },
                deletion_head: acked_from_row(&mr, 7)?,
            },
            accounts: accounts
                .iter()
                .map(account_from_row)
                .collect::<Result<_>>()?,
            deletion_list: dl.iter().map(entry_from_row).collect::<Result<_>>()?,
        })
    }

    async fn restore_backup(&self, b: BackupSnapshot) -> Result<()> {
        if b.meta.tenant_id != self.tenant {
            return Err(StoreError::TenantMismatch);
        }
        validate::backup(&b)?;
        let mut tx = self.begin_raw().await?;
        let nonempty: bool = sqlx::query(SQL_NONEMPTY)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?
            .try_get(0)
            .map_err(db)?;
        if nonempty {
            return Err(StoreError::Conflict("restore target not empty"));
        }
        let kd = &b.meta.kd;
        let day = kd.checkpoint_day.map(day_i32).transpose()?;
        let existing = sqlx::query(SQL_META_SALT)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        if let Some(r) = existing {
            // AUD-RM2-STO-15: restored locators must be reachable with the salt.
            if get_arr::<32>(&r, 0)? != b.meta.kdf_salt {
                return Err(StoreError::Conflict("kdf salt differs"));
            }
            sqlx::query(SQL_META_RESTORE)
                .bind(i64_of(b.meta.relay_req_counter)?)
                .bind(i64_of(b.meta.last_batch_no)?)
                .bind(i64_of(kd.tree_size)?)
                .bind(day)
                .bind(i64_of(kd.directory_version)?)
                .execute(&mut *tx)
                .await
                .map_err(db_classified)?;
        } else {
            let n = sqlx::query(SQL_META_RESTORE_INSERT)
                .bind(uuid(&b.meta.tenant_id.0))
                .bind(schema_hash().as_slice())
                .bind(b.meta.kdf_salt.as_slice())
                .bind(i64_of(b.meta.relay_req_counter)?)
                .bind(i64_of(b.meta.last_batch_no)?)
                .bind(i64_of(kd.tree_size)?)
                .bind(day)
                .bind(i64_of(kd.directory_version)?)
                .execute(&mut *tx)
                .await
                .map_err(db_classified)?
                .rows_affected();
            if n != 1 {
                return Err(StoreError::TenantMismatch);
            }
        }
        for a in &b.accounts {
            let n = sqlx::query(SQL_ACCOUNT_INSERT)
                .bind(uuid(&a.account_id.0))
                .bind(a.lookup_tag.0.as_slice())
                .bind(a.auth_pk.as_slice())
                .bind(a.xwing_pk.as_slice())
                .bind(a.prefs_ct.as_slice())
                .bind(day_i32(a.activity_month)?)
                .execute(&mut *tx)
                .await
                .map_err(db_classified)?
                .rows_affected();
            if n != 1 {
                return Err(StoreError::Conflict("duplicate account in backup"));
            }
        }
        for e in &b.deletion_list {
            insert_entry(&mut tx, e).await?;
        }
        // The last verified Z-CORE head travels with the backup (AUD-RM2-STO-22):
        // a later push must chain to it.
        if let Some(h) = &b.meta.deletion_head {
            store_acked(&mut tx, h).await?;
        }
        tx.commit().await.map_err(db)
    }
}

impl IntakeMaintenance for PgIntakeStore {
    async fn prune_deletion_list(&self, today: Day) -> Result<u64> {
        self.maint
            .as_ref()
            .ok_or(StoreError::Integrity("maintenance role not attached"))?
            .prune_deletion_list(today)
            .await
    }

    /// Runs as the application role (least privilege: it already holds
    /// `SELECT` on `envelope_part`); statement logging is disabled on the pool
    /// and the id is a bind parameter.
    async fn blob_referenced(&self, blob: BlobId) -> Result<bool> {
        let mut tx = self.begin_raw().await?;
        let found: bool = sqlx::query_scalar(SQL_BLOB_REFERENCED)
            .bind(uuid(&blob.0))
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        tx.rollback().await.map_err(db)?;
        Ok(found)
    }
}

/// Maintenance handle (`candor_intake_maint`, AUD-RM2-STO-03/11): the only role
/// that may flag deletion-list entries relayed and prune them. Run it from the
/// daily job under its own OS user; the application role cannot do either.
pub struct PgIntakeMaintenance {
    pool: PgPool,
    tenant: TenantId,
    core_pk: [u8; 32],
}

impl core::fmt::Debug for PgIntakeMaintenance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PgIntakeMaintenance")
    }
}

impl PgIntakeMaintenance {
    /// Connect as the maintenance role (same privilege and guard checks as the
    /// application role; must not be a member of `candor_istore`). `core_pk` is
    /// the Z-CORE head key: the maintenance process re-verifies the stored
    /// acknowledged head with it before flagging anything (AUD-RM2-STO-21), so a
    /// compromised application role cannot make it prune unrelayed entries.
    pub async fn open(opts: PgConnectOptions, tenant: TenantId, core_pk: [u8; 32]) -> Result<Self> {
        let pool = open_pool(opts, 1, "candor_istore", true).await?;
        Ok(Self {
            pool,
            tenant,
            core_pk,
        })
    }

    /// Close the pool.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Reset PostgreSQL's cumulative statistics for this database (daily job,
    /// AUD-RM2-STO-11): clears per-table activity counts and autovacuum
    /// timestamps. Needs `EXECUTE` on `pg_stat_reset()` (granted at provisioning).
    pub async fn reset_statistics(&self) -> Result<()> {
        sqlx::query(SQL_STAT_RESET)
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }
}

impl IntakeMaintenance for PgIntakeMaintenance {
    async fn prune_deletion_list(&self, today: Day) -> Result<u64> {
        let c = day_i32(today.saturating_minus(DELETION_LIST_RETENTION_DAYS))?;
        let mut tx = begin_tenant(&self.pool, &self.tenant).await?;
        sqlx::query(SQL_META)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or(StoreError::NotInitialized)?;
        // AUD-RM2-STO-21: flag only up to a head this process verified itself:
        // Z-CORE's signature, and the local chain at that seq (if still present).
        if let Some(h) = acked_head(&mut tx).await? {
            h.verify(&self.tenant, &self.core_pk)?;
            let near: Vec<DeletionEntry> = sqlx::query(SQL_DEL_AT)
                .bind(i64_of(h.seq)?)
                .fetch_all(&mut *tx)
                .await
                .map_err(db)?
                .iter()
                .map(entry_from_row)
                .collect::<Result<_>>()?;
            let map: std::collections::BTreeMap<u64, &DeletionEntry> =
                near.iter().map(|e| (e.seq, e)).collect();
            if !validate::links_to_head(&map, &h) {
                return Err(StoreError::DeletionList("acknowledged head not in chain"));
            }
            sqlx::query(SQL_DEL_MARK)
                .bind(i64_of(h.seq)?)
                .execute(&mut *tx)
                .await
                .map_err(db_classified)?;
        }
        let n = sqlx::query(SQL_DEL_PRUNE)
            .bind(c)
            .execute(&mut *tx)
            .await
            .map_err(db_classified)?
            .rows_affected();
        tx.commit().await.map_err(db)?;
        Ok(n)
    }

    /// The maintenance role has no access to `envelope_part` (least
    /// privilege); blob references are checked through the application role
    /// ([`PgIntakeStore`]). Fails closed.
    async fn blob_referenced(&self, _blob: BlobId) -> Result<bool> {
        Err(StoreError::Integrity(
            "blob references are checked by the application role",
        ))
    }
}

fn hwm_from_row(r: &PgRow) -> Result<KdHighWater> {
    let day: Option<i32> = r.try_get(1).map_err(db)?;
    Ok(KdHighWater {
        tree_size: get_u64(r, 0)?,
        checkpoint_day: day
            .map(|d| u32::try_from(d).map(Day))
            .transpose()
            .map_err(|_| StoreError::Integrity("day"))?,
        directory_version: get_u64(r, 2)?,
    })
}
