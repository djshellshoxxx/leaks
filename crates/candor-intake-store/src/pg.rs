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

use std::sync::Arc;

use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgRow};
use sqlx::{ConnectOptions, Connection, PgConnection, PgPool, Postgres, Row, Transaction};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::deaddrop::{self, DummyReplies, PublishedSet, RandomDummyReplies};
use crate::deletion::{
    DeletionEntry, DeletionKind, DeletionSigner, ReplyObjectHasher, account_del_hash,
    mailbox_del_hash, make_entry, reply_del_hash,
};
use crate::error::{Result, StoreError};
use crate::store::IntakeStore;
use crate::types::{
    AccountId, AccountLink, AckResult, ApplyRepliesResult, BackupSnapshot, BlobId, ChannelId,
    ClaimLimits, ClaimedBatch, ClaimedObject, CommitEnvelope, CounterCell, CounterName,
    DELETION_LIST_RETENTION_DAYS, Day, EnvelopeRef, IncomingReply, InstallOutcome, KdHighWater,
    LookupTag, MAILBOX_SLOTS, MAX_DELETION_LIST_PAGE, MAX_REPLIES_PER_PUSH, MailboxId,
    MetaSnapshot, ObjectData, PartRef, PartSelector, REPLY_WINDOW_DAYS, ReplyIndex, ReplyRef,
    SourceAccount, StoredReply, TenantId, VerifiedSnapshot, random_id16,
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

fn is_unique_violation(e: &sqlx::Error) -> bool {
    sqlstate(e).as_deref() == Some("23505")
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
const SQL_ROLE_CHECK: &str = "SELECT r.rolsuper, r.rolbypassrls, \
     (SELECT count(*) FROM pg_catalog.pg_tables t WHERE t.schemaname = 'candor' AND t.tableowner = current_user) \
     FROM pg_catalog.pg_roles r WHERE r.rolname = current_user";
const SQL_META_HASH: &str = "SELECT schema_hash FROM candor.intake_meta";
const SQL_META_INSERT: &str =
    "INSERT INTO candor.intake_meta (tenant_id, schema_hash, kdf_salt) VALUES ($1, $2, $3)";
const SQL_COUNTER_BUMP: &str =
    "UPDATE candor.intake_meta SET relay_req_counter = $1 WHERE relay_req_counter < $1";

const SQL_ACCOUNT_BY_TAG: &str = "SELECT account_id, locator_hash, auth_pk, xwing_pk, prefs_ct, \
     (activity_month - DATE '1970-01-01')::int4, quota_bucket FROM candor.source_account WHERE locator_hash = $1";
const SQL_ACCOUNT_TAG_LOCK: &str =
    "SELECT locator_hash FROM candor.source_account WHERE account_id = $1 FOR UPDATE";
const SQL_ACCOUNT_EXISTS: &str =
    "SELECT EXISTS (SELECT 1 FROM candor.source_account WHERE account_id = $1)";
const SQL_ACCOUNT_DELETE: &str = "DELETE FROM candor.source_account WHERE account_id = $1";
const SQL_ACCOUNT_INSERT: &str = "INSERT INTO candor.source_account \
     (account_id, locator_hash, auth_pk, xwing_pk, prefs_ct, activity_month, quota_bucket) \
     VALUES ($1, $2, $3, $4, $5, DATE '1970-01-01' + $6::int4, 0)";
const SQL_ACCOUNT_TOUCH: &str = "UPDATE candor.source_account SET activity_month = \
     GREATEST(activity_month, DATE '1970-01-01' + $2::int4) WHERE account_id = $1";
const SQL_ACCOUNTS_ALL: &str = "SELECT account_id, locator_hash, auth_pk, xwing_pk, prefs_ct, \
     (activity_month - DATE '1970-01-01')::int4, quota_bucket FROM candor.source_account ORDER BY account_id";
const SQL_ACCOUNT_RESTORE: &str = "INSERT INTO candor.source_account \
     (account_id, locator_hash, auth_pk, xwing_pk, prefs_ct, activity_month, quota_bucket) \
     VALUES ($1, $2, $3, $4, $5, DATE '1970-01-01' + $6::int4, $7)";
const SQL_QUOTA_CONSUME: &str = "UPDATE candor.source_account SET quota_bucket = (quota_bucket::int4 + $2::int4)::int2 \
     WHERE account_id = $1 AND quota_bucket::int4 + $2::int4 <= $3::int4 RETURNING quota_bucket";
const SQL_QUOTA_RESET: &str =
    "UPDATE candor.source_account SET quota_bucket = 0 WHERE quota_bucket <> 0";

const SQL_ENV_INSERT: &str = "INSERT INTO candor.envelope (envelope_ref, channel_id, source_account_id, header_ct, \
     manifest_ct, header_sha256, disposition_ct, epoch_index, received_date, release_day, batch_no, state) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, DATE '1970-01-01' + $9::int4, DATE '1970-01-01' + $10::int4, NULL, 'sealed')";
const SQL_PART_INSERT: &str = "INSERT INTO candor.envelope_part (envelope_ref, part_no, blob_id, padded_size) VALUES ($1, $2, $3, $4)";
const SQL_PENDING: &str = "SELECT count(*) FROM candor.envelope";
const SQL_INFLIGHT: &str = "SELECT batch_no FROM candor.envelope WHERE state = 'claimed' LIMIT 1";
const SQL_CANDIDATES: &str = "SELECT envelope_ref, octet_length(header_ct)::int8, octet_length(manifest_ct)::int8 \
     FROM candor.envelope WHERE state = 'sealed' AND release_day <= DATE '1970-01-01' + $1::int4 \
     ORDER BY envelope_ref LIMIT $2";
const SQL_PART_SIZES: &str = "SELECT envelope_ref, padded_size FROM candor.envelope_part \
     WHERE envelope_ref = ANY($1) ORDER BY envelope_ref, part_no";
const SQL_LAST_BATCH: &str = "SELECT last_batch_no FROM candor.intake_meta";
const SQL_SET_BATCH_NO: &str = "UPDATE candor.intake_meta SET last_batch_no = $1";
const SQL_CLAIM: &str =
    "UPDATE candor.envelope SET state = 'claimed', batch_no = $1 WHERE envelope_ref = ANY($2)";
const SQL_BATCH_OBJECTS: &str = "SELECT envelope_ref, channel_id, epoch_index, octet_length(header_ct)::int8, \
     octet_length(manifest_ct)::int8, header_sha256, disposition_ct FROM candor.envelope \
     WHERE batch_no = $1 ORDER BY envelope_ref";
const SQL_BATCH_PARTS: &str = "SELECT p.envelope_ref, p.padded_size FROM candor.envelope_part p \
     JOIN candor.envelope e ON e.envelope_ref = p.envelope_ref WHERE e.batch_no = $1 \
     ORDER BY p.envelope_ref, p.part_no";
const SQL_OBJ_HEADER: &str =
    "SELECT header_ct FROM candor.envelope WHERE envelope_ref = $1 AND batch_no = $2";
const SQL_OBJ_MANIFEST: &str =
    "SELECT manifest_ct FROM candor.envelope WHERE envelope_ref = $1 AND batch_no = $2";
const SQL_OBJ_PART: &str = "SELECT p.blob_id, p.padded_size FROM candor.envelope_part p \
     JOIN candor.envelope e ON e.envelope_ref = p.envelope_ref \
     WHERE p.envelope_ref = $1 AND e.batch_no = $2 AND p.part_no = $3";
const SQL_BATCH_DIGESTS: &str = "SELECT header_sha256 FROM candor.envelope WHERE batch_no = $1";
const SQL_ACK_BLOBS: &str = "SELECT p.blob_id FROM candor.envelope_part p \
     JOIN candor.envelope e ON e.envelope_ref = p.envelope_ref \
     WHERE e.batch_no = $1 AND e.header_sha256 = ANY($2) ORDER BY p.envelope_ref, p.part_no";
const SQL_ACK_DELETE: &str =
    "DELETE FROM candor.envelope WHERE batch_no = $1 AND header_sha256 = ANY($2)";
const SQL_UNCLAIM: &str =
    "UPDATE candor.envelope SET state = 'sealed', batch_no = NULL WHERE batch_no = $1";

const SQL_LISTED: &str = "SELECT EXISTS (SELECT 1 FROM candor.deletion_list WHERE \
     (kind = 'reply' AND del_hash = $1) OR (kind = 'mailbox' AND del_hash = $2))";
const SQL_SLOTS_USED: &str =
    "SELECT slot FROM candor.reply WHERE source_account_id = $1 AND slot IS NOT NULL";
const SQL_REPLY_INSERT: &str = "INSERT INTO candor.reply (reply_ref, source_account_id, reply_ct, size_bucket, \
     available_day, slot) VALUES ($1, $2, $3, $4, DATE '1970-01-01' + $5::int4, $6)";
const SQL_MAILBOX: &str = "SELECT reply_ref, slot, reply_ct, size_bucket, (available_day - DATE '1970-01-01')::int4 \
     FROM candor.reply WHERE source_account_id = $1 ORDER BY slot";
const SQL_REPLIES_OWNED: &str =
    "SELECT count(*) FROM candor.reply WHERE reply_ref = ANY($1) AND source_account_id = $2";
const SQL_REPLIES_DELETE: &str =
    "DELETE FROM candor.reply WHERE reply_ref = ANY($1) AND source_account_id = $2";
const SQL_REPLIES_PURGE: &str =
    "DELETE FROM candor.reply WHERE available_day < DATE '1970-01-01' + $1::int4";
const SQL_REPLIES_WINDOW: &str = "SELECT reply_ct FROM candor.reply WHERE available_day > DATE '1970-01-01' + $1::int4 ORDER BY reply_ref";
const SQL_REPLIES_PAGE: &str = "SELECT reply_ref, reply_ct FROM candor.reply WHERE reply_ref > $1 ORDER BY reply_ref LIMIT 256";
const SQL_REPLY_DELETE_ONE: &str = "DELETE FROM candor.reply WHERE reply_ref = $1";

const SQL_DEL_HEAD: &str = "SELECT seq, kind::text, del_hash, (del_day - DATE '1970-01-01')::int4, prev_hash, sig, relayed \
     FROM candor.deletion_list ORDER BY seq DESC LIMIT 1";
const SQL_DEL_ALL: &str = "SELECT seq, kind::text, del_hash, (del_day - DATE '1970-01-01')::int4, prev_hash, sig, relayed \
     FROM candor.deletion_list ORDER BY seq";
const SQL_DEL_AFTER: &str = "SELECT seq, kind::text, del_hash, (del_day - DATE '1970-01-01')::int4, prev_hash, sig, relayed \
     FROM candor.deletion_list WHERE seq > $1 ORDER BY seq LIMIT $2";
const SQL_DEL_INSERT: &str = "INSERT INTO candor.deletion_list (seq, kind, del_hash, del_day, prev_hash, sig, relayed) \
     VALUES ($1, $2::text::candor.deletion_kind, $3, DATE '1970-01-01' + $4::int4, $5, $6, $7)";
const SQL_DEL_MARK: &str =
    "UPDATE candor.deletion_list SET relayed = true WHERE seq <= $1 AND NOT relayed";
const SQL_DEL_PRUNE: &str = "DELETE FROM candor.deletion_list WHERE relayed AND del_day < DATE '1970-01-01' + $1::int4 \
     AND seq < (SELECT max(seq) FROM candor.deletion_list)";
const SQL_CLEAR_RESTORE: &str = "UPDATE candor.intake_meta SET restore_pending = false";

const SQL_HWM: &str = "SELECT kd_tree_size_hwm, (kd_checkpoint_day_hwm - DATE '1970-01-01')::int4, directory_version \
     FROM candor.intake_meta";
const SQL_HWM_LOCK: &str = "SELECT kd_tree_size_hwm, (kd_checkpoint_day_hwm - DATE '1970-01-01')::int4, directory_version \
     FROM candor.intake_meta FOR UPDATE";
const SQL_SNAP_BODY: &str = "SELECT body FROM candor.directory_snapshot WHERE version = $1";
const SQL_SNAP_INSERT: &str = "INSERT INTO candor.directory_snapshot (version, body, signatures, applied_day) \
     VALUES ($1, $2, $3, DATE '1970-01-01' + $4::int4)";
const SQL_SNAP_META: &str = "UPDATE candor.intake_meta SET kd_tree_size_hwm = GREATEST(kd_tree_size_hwm, $1), \
     kd_checkpoint_day_hwm = GREATEST(kd_checkpoint_day_hwm, DATE '1970-01-01' + $2::int4), directory_version = $3";
const SQL_SNAP_PRUNE: &str = "DELETE FROM candor.directory_snapshot WHERE version < COALESCE((SELECT version FROM \
     candor.directory_snapshot ORDER BY version DESC OFFSET 1 LIMIT 1), 0)";
const SQL_SNAP_CURRENT: &str = "SELECT s.version, s.body, s.signatures FROM candor.directory_snapshot s \
     JOIN candor.intake_meta m ON s.version = m.directory_version";

const SQL_COUNTER_ADD: &str = "INSERT INTO candor.counter_month (month, channel_id, name, value) \
     VALUES (DATE '1970-01-01' + $1::int4, $2, $3::text::candor.counter_name, $4) \
     ON CONFLICT (month, channel_id, name) DO UPDATE SET value = candor.counter_month.value + EXCLUDED.value";
const SQL_COUNTERS: &str = "SELECT channel_id, name::text, value FROM candor.counter_month \
     WHERE month = DATE '1970-01-01' + $1::int4 ORDER BY channel_id, name";
const SQL_COUNTERS_PRUNE: &str =
    "DELETE FROM candor.counter_month WHERE month < DATE '1970-01-01' + $1::int4";

const SQL_META_FULL: &str = "SELECT tenant_id, kdf_salt, relay_req_counter, last_batch_no, kd_tree_size_hwm, \
     (kd_checkpoint_day_hwm - DATE '1970-01-01')::int4, directory_version FROM candor.intake_meta";
const SQL_NONEMPTY: &str = "SELECT EXISTS (SELECT 1 FROM candor.source_account) OR EXISTS (SELECT 1 FROM candor.envelope) \
     OR EXISTS (SELECT 1 FROM candor.reply) OR EXISTS (SELECT 1 FROM candor.deletion_list)";
const SQL_META_RESTORE: &str = "UPDATE candor.intake_meta SET \
     relay_req_counter = GREATEST(relay_req_counter, $1), last_batch_no = GREATEST(last_batch_no, $2), \
     kd_tree_size_hwm = GREATEST(kd_tree_size_hwm, $3), \
     kd_checkpoint_day_hwm = GREATEST(kd_checkpoint_day_hwm, DATE '1970-01-01' + $4::int4), \
     directory_version = GREATEST(directory_version, $5), restore_pending = true";
const SQL_META_RESTORE_INSERT: &str = "INSERT INTO candor.intake_meta (tenant_id, schema_hash, kdf_salt, \
     relay_req_counter, last_batch_no, kd_tree_size_hwm, kd_checkpoint_day_hwm, directory_version, restore_pending) \
     VALUES ($1, $2, $3, $4, $5, $6, DATE '1970-01-01' + $7::int4, $8, true)";

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

/// PostgreSQL-backed Intake Store.
pub struct PgIntakeStore {
    pool: PgPool,
    tenant: TenantId,
    published: RwLock<Arc<PublishedSet>>,
    dummies: Box<dyn DummyReplies>,
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

impl PgIntakeStore {
    /// Connect as the application role (`candor_istore`, peer auth over the Unix
    /// socket in production). Refuses to run as a superuser, a BYPASSRLS role or
    /// a table owner, and refuses a schema that differs from this build (BE-050).
    pub async fn open(
        opts: PgConnectOptions,
        tenant: TenantId,
        max_connections: u32,
    ) -> Result<Self> {
        Self::open_with_dummies(opts, tenant, max_connections, Box::new(RandomDummyReplies)).await
    }

    /// As [`PgIntakeStore::open`] with a caller-supplied dummy reply source.
    pub async fn open_with_dummies(
        opts: PgConnectOptions,
        tenant: TenantId,
        max_connections: u32,
        dummies: Box<dyn DummyReplies>,
    ) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect_with(opts.disable_statement_logging())
            .await
            .map_err(db)?;
        let row = sqlx::query(SQL_ROLE_CHECK)
            .fetch_one(&pool)
            .await
            .map_err(db)?;
        let sup: bool = row.try_get(0).map_err(db)?;
        let bypass: bool = row.try_get(1).map_err(db)?;
        let owned: i64 = row.try_get(2).map_err(db)?;
        if sup || bypass || owned != 0 {
            return Err(StoreError::Integrity(
                "application role is privileged or owns tables",
            ));
        }
        let applied = sqlx::query(SQL_LEDGER_ALL)
            .fetch_all(&pool)
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
        let empty = deaddrop::empty(dummies.as_ref())?;
        let store = Self {
            pool,
            tenant,
            published: RwLock::new(Arc::new(empty)),
            dummies,
        };
        // If initialised, the recorded schema hash must match (BE-050).
        let mut tx = store.begin_raw().await?;
        let recorded = sqlx::query(SQL_META_HASH)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        if let Some(r) = recorded
            && get_arr::<32>(&r, 0)? != schema_hash()
        {
            return Err(StoreError::Integrity("schema hash mismatch"));
        }
        tx.rollback().await.map_err(db)?;
        Ok(store)
    }

    /// Close the pool.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    async fn begin_raw(&self) -> Result<Transaction<'static, Postgres>> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query(SQL_SET_TENANT)
            .bind(uuid(&self.tenant.0))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        Ok(tx)
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
}

fn account_from_row(r: &PgRow) -> Result<SourceAccount> {
    let q: i16 = r.try_get(6).map_err(db)?;
    Ok(SourceAccount {
        account_id: AccountId(get_id(r, 0)?),
        lookup_tag: LookupTag(get_arr(r, 1)?),
        auth_pk: get_arr(r, 2)?,
        xwing_pk: r.try_get(3).map_err(db)?,
        prefs_ct: r.try_get(4).map_err(db)?,
        activity_month: get_day(r, 5)?,
        quota_bucket: u16::try_from(q).map_err(|_| StoreError::Integrity("quota"))?,
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
    sqlx::query(SQL_DEL_INSERT)
        .bind(i64_of(e.seq)?)
        .bind(e.kind.as_str())
        .bind(e.del_hash.as_slice())
        .bind(day_i32(e.del_day)?)
        .bind(e.prev_hash.as_slice())
        .bind(e.sig.as_slice())
        .bind(e.relayed)
        .execute(tx)
        .await
        .map_err(db_classified)?;
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
        let mut sizes = Vec::new();
        for p in &parts {
            if get_id(p, 0)? == er {
                sizes.push(get_u64(p, 1)?);
            }
        }
        let epoch: i32 = r.try_get(2).map_err(db)?;
        out.push(ClaimedObject {
            envelope_ref: EnvelopeRef(er),
            channel_id: ChannelId(get_id(r, 1)?),
            epoch_index: u32::try_from(epoch).map_err(|_| StoreError::Integrity("epoch"))?,
            header_len: u32::try_from(get_u64(r, 3)?).map_err(|_| StoreError::Integrity("len"))?,
            manifest_len: u32::try_from(get_u64(r, 4)?)
                .map_err(|_| StoreError::Integrity("len"))?,
            parts: sizes,
            sha256: get_arr(r, 5)?,
            disposition_ct: r.try_get(6).map_err(db)?,
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
        let r = sqlx::query(SQL_META_INSERT)
            .bind(uuid(&tenant.0))
            .bind(hash.as_slice())
            .bind(kdf_salt.as_slice())
            .execute(&mut *tx)
            .await;
        match r {
            Ok(_) => tx.commit().await.map_err(db),
            // Another tenant's row exists (invisible under RLS): singleton violated.
            Err(e) if is_unique_violation(&e) => Err(StoreError::TenantMismatch),
            Err(e) => Err(db(e)),
        }
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

    async fn lookup_account(&self, tag: &LookupTag) -> Result<Option<SourceAccount>> {
        let (mut tx, _) = self.begin(false).await?;
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

    async fn quota_consume(&self, account: AccountId, amount: u16, limit: u16) -> Result<u16> {
        let limit = limit.min(i16::MAX as u16);
        let (mut tx, _) = self.begin(false).await?;
        let row = sqlx::query(SQL_QUOTA_CONSUME)
            .bind(uuid(&account.0))
            .bind(i32::from(amount))
            .bind(i32::from(limit))
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_classified)?;
        match row {
            Some(r) => {
                let v: i16 = r.try_get(0).map_err(db)?;
                tx.commit().await.map_err(db)?;
                u16::try_from(v).map_err(|_| StoreError::Integrity("quota"))
            }
            None => {
                let exists: bool = sqlx::query(SQL_ACCOUNT_EXISTS)
                    .bind(uuid(&account.0))
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db)?
                    .try_get(0)
                    .map_err(db)?;
                tx.rollback().await.map_err(db)?;
                Err(if exists {
                    StoreError::QuotaExceeded
                } else {
                    StoreError::NotFound
                })
            }
        }
    }

    async fn quota_reset(&self) -> Result<u64> {
        let (mut tx, _) = self.begin(true).await?;
        let n = sqlx::query(SQL_QUOTA_RESET)
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
        let month = day_i32(env.received_date.month_start())?;
        let epoch =
            i32::try_from(env.epoch_index).map_err(|_| StoreError::InvalidInput("epoch index"))?;
        let (mut tx, m) = self.begin(false).await?;
        if m.restore_pending {
            return Err(StoreError::RestorePending);
        }
        let account: Option<Uuid> = match &env.account {
            AccountLink::None => None,
            AccountLink::Existing(id) => {
                let n = sqlx::query(SQL_ACCOUNT_TOUCH)
                    .bind(uuid(&id.0))
                    .bind(month)
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?
                    .rows_affected();
                if n != 1 {
                    return Err(StoreError::NotFound);
                }
                Some(uuid(&id.0))
            }
            AccountLink::New(n) => {
                let id = uuid(&random_id16()?);
                let r = sqlx::query(SQL_ACCOUNT_INSERT)
                    .bind(id)
                    .bind(n.lookup_tag.0.as_slice())
                    .bind(n.auth_pk.as_slice())
                    .bind(n.xwing_pk.as_slice())
                    .bind(n.prefs_ct.as_slice())
                    .bind(month)
                    .execute(&mut *tx)
                    .await;
                match r {
                    Ok(_) => Some(id),
                    Err(e) if is_unique_violation(&e) => return Err(StoreError::AccountExists),
                    Err(e) => return Err(db(e)),
                }
            }
        };
        let er = random_id16()?;
        let digest: [u8; 32] = Sha256::digest(&env.header_ct).into();
        let r = sqlx::query(SQL_ENV_INSERT)
            .bind(uuid(&er))
            .bind(uuid(&env.channel_id.0))
            .bind(account)
            .bind(env.header_ct.as_slice())
            .bind(env.manifest_ct.as_slice())
            .bind(digest.as_slice())
            .bind(env.disposition_ct.as_slice())
            .bind(epoch)
            .bind(received)
            .bind(release)
            .execute(&mut *tx)
            .await;
        match r {
            Ok(_) => {}
            Err(e) if is_unique_violation(&e) => return Err(StoreError::DuplicateEnvelope),
            Err(e) => return Err(db(e)),
        }
        for (i, p) in env.parts.iter().enumerate() {
            let r = sqlx::query(SQL_PART_INSERT)
                .bind(uuid(&er))
                .bind(i16::try_from(i).map_err(|_| StoreError::InvalidInput("part"))?)
                .bind(uuid(&p.blob_id.0))
                .bind(i64_of(p.padded_size)?)
                .execute(&mut *tx)
                .await;
            match r {
                Ok(_) => {}
                Err(e) if is_unique_violation(&e) => {
                    return Err(StoreError::InvalidInput("duplicate blob id"));
                }
                Err(e) => return Err(db(e)),
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
            sizes.push(validate::object_bytes(get_u64(r, 1)?, get_u64(r, 2)?, &ps));
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
            PartSelector::Header | PartSelector::Manifest => {
                let q = if part == PartSelector::Header {
                    SQL_OBJ_HEADER
                } else {
                    SQL_OBJ_MANIFEST
                };
                let row = sqlx::query(q)
                    .bind(er)
                    .bind(b)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db)?;
                let row = row.ok_or(StoreError::NotFound)?;
                ObjectData::Bytes(row.try_get(0).map_err(db)?)
            }
            PartSelector::Part(i) => {
                let pn = i16::try_from(i).map_err(|_| StoreError::NotFound)?;
                let row = sqlx::query(SQL_OBJ_PART)
                    .bind(er)
                    .bind(b)
                    .bind(pn)
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
        let month = day_i32(today.month_start())?;
        if replies.len() > MAX_REPLIES_PER_PUSH {
            return Err(StoreError::InvalidInput("too many replies"));
        }
        let (mut tx, m) = self.begin(true).await?;
        if m.restore_pending {
            return Err(StoreError::RestorePending);
        }
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
            if let Some(a) = r.account {
                sqlx::query(SQL_ACCOUNT_TOUCH)
                    .bind(uuid(&a.0))
                    .bind(month)
                    .execute(&mut *tx)
                    .await
                    .map_err(db)?;
            }
            sqlx::query(SQL_REPLY_INSERT)
                .bind(uuid(&random_id16()?))
                .bind(r.account.map(|a| uuid(&a.0)))
                .bind(r.reply_ct.as_slice())
                .bind(i16::from(r.size_bucket))
                .bind(d)
                .bind(slot)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            res.accepted = res.accepted.saturating_add(1);
        }
        tx.commit().await.map_err(db)?;
        Ok(res)
    }

    async fn mailbox_list(&self, account: AccountId) -> Result<Vec<StoredReply>> {
        let (mut tx, _) = self.begin(false).await?;
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

    async fn rebuild_published_set(&self, today: Day) -> Result<ReplyIndex> {
        let lower = i64::from(day_i32(today)?).saturating_sub(i64::from(REPLY_WINDOW_DAYS));
        let lower = i32::try_from(lower).map_err(|_| StoreError::InvalidInput("day"))?;
        let (mut tx, _) = self.begin(false).await?;
        let rows = sqlx::query(SQL_REPLIES_WINDOW)
            .bind(lower)
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        tx.rollback().await.map_err(db)?;
        let cts: Vec<Vec<u8>> = rows
            .iter()
            .map(|r| r.try_get(0).map_err(db))
            .collect::<Result<_>>()?;
        let set = deaddrop::build(&cts, self.dummies.as_ref())?;
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
        let a = i64::try_from(after).unwrap_or(i64::MAX);
        let lim = i64::from(limit.min(MAX_DELETION_LIST_PAGE));
        let (mut tx, _) = self.begin(true).await?;
        sqlx::query(SQL_DEL_MARK)
            .bind(a)
            .execute(&mut *tx)
            .await
            .map_err(db_classified)?;
        let rows = sqlx::query(SQL_DEL_AFTER)
            .bind(a)
            .bind(lim)
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        rows.iter().map(entry_from_row).collect()
    }

    async fn apply_pushed_deletion_list(
        &self,
        entries: &[DeletionEntry],
        k31_pk: &[u8; 32],
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
        let new = validate::merge_pushed(&local, entries, k31_pk)?;
        for e in &new {
            insert_entry(&mut tx, e).await?;
        }
        let all: Vec<&DeletionEntry> = local.iter().chain(new.iter()).collect();
        let acct: Vec<[u8; 32]> = all
            .iter()
            .filter(|e| e.kind == DeletionKind::Account)
            .map(|e| e.del_hash)
            .collect();
        let reps: Vec<[u8; 32]> = all
            .iter()
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

    async fn prune_deletion_list(&self, today: Day) -> Result<u64> {
        let c = day_i32(today.saturating_minus(DELETION_LIST_RETENTION_DAYS))?;
        let (mut tx, _) = self.begin(true).await?;
        let n = sqlx::query(SQL_DEL_PRUNE)
            .bind(c)
            .execute(&mut *tx)
            .await
            .map_err(db_classified)?
            .rows_affected();
        tx.commit().await.map_err(db)?;
        Ok(n)
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
        let d = day_i32(today)?;
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
        sqlx::query(SQL_SNAP_INSERT)
            .bind(v)
            .bind(snap.body.as_slice())
            .bind(snap.signatures.as_slice())
            .bind(d)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                if is_unique_violation(&e) {
                    StoreError::Conflict("snapshot version exists")
                } else {
                    db(e)
                }
            })?;
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

    async fn counter_add(
        &self,
        month: Day,
        channel: ChannelId,
        name: CounterName,
        delta: u32,
    ) -> Result<()> {
        if !month.is_month_start() {
            return Err(StoreError::InvalidInput("month"));
        }
        let mi = day_i32(month)?;
        let delta =
            i32::try_from(delta).map_err(|_| StoreError::InvalidInput("counter overflow"))?;
        let (mut tx, _) = self.begin(false).await?;
        sqlx::query(SQL_COUNTER_ADD)
            .bind(mi)
            .bind(uuid(&channel.0))
            .bind(name.as_str())
            .bind(delta)
            .execute(&mut *tx)
            .await
            .map_err(|e| match db_classified(e) {
                StoreError::InvalidInput(_) => StoreError::InvalidInput("counter overflow"),
                o => o,
            })?;
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
        for a in &b.accounts {
            validate::new_account(&crate::types::NewAccount {
                lookup_tag: a.lookup_tag,
                auth_pk: a.auth_pk,
                xwing_pk: a.xwing_pk.clone(),
                prefs_ct: a.prefs_ct.clone(),
            })?;
        }
        if b.deletion_list
            .windows(2)
            .any(|w| matches!(w, [x, y] if y.seq <= x.seq))
        {
            return Err(StoreError::DeletionList("unordered backup list"));
        }
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
        let exists = sqlx::query(SQL_META_LOCK)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .is_some();
        if exists {
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
            sqlx::query(SQL_META_RESTORE_INSERT)
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
                .map_err(|e| {
                    if is_unique_violation(&e) {
                        StoreError::TenantMismatch
                    } else {
                        db(e)
                    }
                })?;
        }
        for a in &b.accounts {
            sqlx::query(SQL_ACCOUNT_RESTORE)
                .bind(uuid(&a.account_id.0))
                .bind(a.lookup_tag.0.as_slice())
                .bind(a.auth_pk.as_slice())
                .bind(a.xwing_pk.as_slice())
                .bind(a.prefs_ct.as_slice())
                .bind(day_i32(a.activity_month)?)
                .bind(i16::try_from(a.quota_bucket).map_err(|_| StoreError::InvalidInput("quota"))?)
                .execute(&mut *tx)
                .await
                .map_err(db_classified)?;
        }
        for e in &b.deletion_list {
            insert_entry(&mut tx, e).await?;
        }
        tx.commit().await.map_err(db)
    }
}

impl PgIntakeStore {
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
