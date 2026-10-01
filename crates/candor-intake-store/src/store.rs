// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `IntakeStore` trait: exactly the persistence operations the intake needs
//! (07 §5.3, §5.4, §6.3; 08 RL-01..RL-12, SA-19/SA-20; 09 §5.1).
//!
//! Callers own: signature/verifier checks on source auth, opening `routing_ct`,
//! verifying KD snapshots, blob file I/O (`candor-safefs`), timing uniformity,
//! scheduling of daily jobs, encryption of backups, and typed audit events
//! (`candor-log`). The store never reads a wall clock: every date is a [`Day`]
//! supplied by the caller's `SourceClock::today()` (07 BE-031).

use std::future::Future;
use std::sync::Arc;

use crate::deletion::{DeletionEntry, DeletionSigner, ReplyObjectHasher};
use crate::error::Result;
use crate::types::{
    AccountId, AckResult, ApplyRepliesResult, BackupSnapshot, ClaimLimits, ClaimedBatch,
    CommitEnvelope, CounterCell, CounterDelta, Day, EnvelopeRef, ImportSlot, IncomingReply,
    InstallOutcome, KdHighWater, LookupTag, MailboxId, NewAccount, ObjectData, PartSelector,
    ReplyIndex,
    ReplyRef, SourceAccount, StoredReply, TenantId, VerifiedSnapshot,
};

/// `(version, body, signatures)` of the installed Key Directory snapshot.
pub type InstalledSnapshot = (u64, Vec<u8>, Vec<u8>);

/// Intake Store operations. Both [`crate::MemoryStore`] and
/// [`crate::PgIntakeStore`] pass the same conformance suite.
pub trait IntakeStore: Send + Sync {
    // ----- meta -----

    /// Initialise `intake_meta` (idempotent for the same tenant; `TenantMismatch`
    /// otherwise). The salt is public (ADR-005).
    fn init(&self, tenant: TenantId, kdf_salt: [u8; 32])
    -> impl Future<Output = Result<()>> + Send;

    /// The tenant (`NotInitialized` before `init`).
    fn tenant(&self) -> impl Future<Output = Result<TenantId>> + Send;

    /// Accept a relay request counter only if strictly greater than the stored
    /// one, persisting it (07 §5.4 anti-replay).
    fn accept_relay_counter(&self, counter: u64) -> impl Future<Output = Result<()>> + Send;

    /// `false` while a restore awaits its deletion list (07 BE-074; RL-01
    /// `restored`). Source-facing callers must show the busy page. The PostgreSQL
    /// store enters this state at every process start (failover to a recovered
    /// node, AUD-RM2-STO-05) until [`IntakeStore::apply_pushed_deletion_list`]
    /// confirms the Z-CORE head.
    fn serving_allowed(&self) -> impl Future<Output = Result<bool>> + Send;

    /// Persistently enter restore-pending (idempotent). Used at process start and
    /// by the failover runbook (`candorctl`).
    fn mark_restore_pending(&self) -> impl Future<Output = Result<()>> + Send;

    // ----- accounts (Tier W) -----

    /// Look up an account by `lookup_tag` (`RestorePending` while restoring).
    /// Verifier checks and uniform timing for unknown tags are the caller's job
    /// (07 §5.3, BE-010). Never writes (no "last seen", ADR-010).
    fn lookup_account(
        &self,
        tag: &LookupTag,
    ) -> impl Future<Output = Result<Option<SourceAccount>>> + Send;

    /// Create a Tier W account (ADR-052(2): separate from envelope commit; chaff
    /// creates dummy accounts through the same call). `AccountExists` if the
    /// `lookup_tag` is taken; `activity_month` = month of `today`.
    fn create_account(
        &self,
        account: NewAccount,
        today: Day,
    ) -> impl Future<Output = Result<AccountId>> + Send;

    /// Replace an account's `lookup_tag`, keys and `prefs_ct` (passphrase
    /// rotation, ADR-046(7)). `NotFound` / `AccountExists` (tag of another account).
    fn update_account(
        &self,
        account: AccountId,
        new: NewAccount,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Daily `inactive_purge` (09 §5.1, DB-033): delete accounts (and their
    /// replies) whose `activity_month` started 365 or more days before `today`.
    /// Abandoned real accounts and chaff dummy accounts expire alike.
    fn purge_inactive_accounts(&self, today: Day) -> impl Future<Output = Result<u64>> + Send;

    /// Delete an account and its replies, appending a signed `account`
    /// deletion-list entry in the same transaction (SW-15, BE-074).
    fn delete_account(
        &self,
        account: AccountId,
        today: Day,
        signer: &dyn DeletionSigner,
    ) -> impl Future<Output = Result<()>> + Send;

    // Quota (BE-064) is held in process RAM by C-06/C-07 and never written to
    // the database (AUD-RM2-STO-01): this trait deliberately has no quota API.

    // ----- envelopes / relay export -----

    /// `COMMIT_ENVELOPE`: insert one fixed-shape envelope group (ADR-052(1)) with
    /// no account reference (ADR-052(2)); returns only after the database commit
    /// (`fsync`, ADR-046(1)). Blob files must be durable before this call. A
    /// repeated group (same digest) is `DuplicateEnvelope` without a server error.
    fn commit_envelope(
        &self,
        env: CommitEnvelope,
    ) -> impl Future<Output = Result<EnvelopeRef>> + Send;

    /// Envelopes not yet acknowledged (includes chaff and held envelopes; RL-01).
    fn pending_count(&self) -> impl Future<Output = Result<u64>> + Send;

    /// RL-02: claim a batch of envelopes with `release_day ≤ today`. If a batch is
    /// still unacked, the same batch is returned with `replayed = true`.
    fn claim_batch(
        &self,
        today: Day,
        limits: ClaimLimits,
    ) -> impl Future<Output = Result<ClaimedBatch>> + Send;

    /// RL-03: a group object's slot block or blob reference.
    fn batch_object(
        &self,
        batch_no: u64,
        envelope: EnvelopeRef,
        part: PartSelector,
    ) -> impl Future<Output = Result<ObjectData>> + Send;

    /// RL-04: delete exactly the envelopes whose group digest is listed (all must
    /// belong to the batch, else nothing changes); the rest of the batch returns to
    /// the claimable pool (BE-014).
    fn ack_batch(
        &self,
        batch_no: u64,
        committed: &[[u8; 32]],
    ) -> impl Future<Output = Result<AckResult>> + Send;

    // ----- replies -----

    /// RL-05: store pushed replies with `available_day = today`; replies whose
    /// target account is gone, or whose mailbox or reply hash is listed, count as
    /// accepted and are dropped (ADR-047(9)). Tier W replies get the lowest free
    /// fixed-mailbox slot; a full mailbox, or a full publication backlog
    /// (`max_pending`, AUD-RM2-STO-07), rejects the reply (the relay retries).
    fn apply_replies(
        &self,
        today: Day,
        replies: Vec<IncomingReply>,
    ) -> impl Future<Output = Result<ApplyRepliesResult>> + Send;

    /// `MAILBOX_LIST` (Tier W): the account's replies ordered by slot
    /// (`RestorePending` while restoring).
    fn mailbox_list(
        &self,
        account: AccountId,
    ) -> impl Future<Output = Result<Vec<StoredReply>>> + Send;

    /// Source deletes replies of its own account; one signed `reply` entry per
    /// reply (`object_hash` supplied by the caller) in the same transaction.
    /// Account, reply and mailbox deletions return `RestorePending` while
    /// restoring (AUD-RM2-STO-09).
    fn delete_replies(
        &self,
        account: AccountId,
        replies: &[(ReplyRef, [u8; 32])],
        today: Day,
        signer: &dyn DeletionSigner,
    ) -> impl Future<Output = Result<u32>> + Send;

    /// `MAILBOX_DELETE`: delete the listed replies of the account and append one
    /// signed `mailbox` entry (future replies to it are dropped on arrival).
    fn delete_mailbox(
        &self,
        account: AccountId,
        mailbox: &MailboxId,
        replies: &[ReplyRef],
        today: Day,
        signer: &dyn DeletionSigner,
    ) -> impl Future<Output = Result<u32>> + Send;

    /// Daily `reply_expiry` and RL-08: delete replies and published dummies with
    /// `available_day < cutoff` (the padding pool is not dated and is kept).
    /// The store also refuses to keep anything older than 30 days: callers pass
    /// `cutoff ≥ today − 30` (enforced by [`IntakeStore::expire_replies`]).
    fn purge_replies_before(&self, cutoff: Day) -> impl Future<Output = Result<u64>> + Send;

    /// `reply_expiry` with `retention_days ≤ 30` (ADR-039): deletes replies whose
    /// age `today − available_day` is ≥ the retention (the same boundary as the
    /// published window).
    fn expire_replies(
        &self,
        today: Day,
        retention_days: u32,
    ) -> impl Future<Output = Result<u64>> + Send;

    /// Publish generation `slot` (exactly K new entries, see [`crate::deaddrop`];
    /// idempotent per slot, missed slots back-filled with dummies) and rebuild the
    /// pages from the persisted generations in the window. Called only at import
    /// slots and once at process start, so `set_version` changes only then
    /// (BE-063, AUD-RM2-STO-06).
    fn rebuild_published_set(
        &self,
        slot: ImportSlot,
    ) -> impl Future<Output = Result<ReplyIndex>> + Send;

    /// SA-19 index of the current published set.
    fn reply_index(&self) -> impl Future<Output = Result<ReplyIndex>> + Send;

    /// SA-20 page `n` of the current published set (identical bytes for everyone).
    fn reply_page(&self, n: u16) -> impl Future<Output = Result<Arc<[u8]>>> + Send;

    // ----- deletion list -----

    /// RL-11: entries with `seq > after`, at most `limit` (≤ 10,000). `after` is
    /// the relay's last copied seq: it is recorded (monotonically) as the
    /// acknowledged seq; `after` above the local head is `InvalidInput` and
    /// changes nothing (AUD-RM2-STO-10). Entries are flagged relayed only by the
    /// maintenance role ([`IntakeMaintenance::prune_deletion_list`]).
    fn deletion_list_after(
        &self,
        after: u64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<DeletionEntry>>> + Send;

    /// RL-12 / restore: verify the pushed Z-CORE copy (chain, K31, contiguous from
    /// the local head, ending exactly at the asserted Z-CORE head `core_head`, no
    /// fork with local entries), merge newer entries, delete every listed account
    /// and reply, then clear the restore-pending flag. Any validation failure
    /// persists restore-pending (fail closed, AUD-RM2-STO-04). Returns
    /// `applied_through_seq`.
    fn apply_pushed_deletion_list(
        &self,
        entries: &[DeletionEntry],
        core_head: u64,
        k31_pk: &[u8; 32],
        hasher: &dyn ReplyObjectHasher,
    ) -> impl Future<Output = Result<u64>> + Send;

    // ----- key directory -----

    /// Current snapshot high-water mark.
    fn kd_high_water(&self) -> impl Future<Output = Result<KdHighWater>> + Send;

    /// RL-06: install a verified snapshot; rejects any rollback below the
    /// high-water mark (BE-060). Keeps the current and previous version only.
    fn install_directory_snapshot(
        &self,
        snap: VerifiedSnapshot,
        today: Day,
    ) -> impl Future<Output = Result<InstallOutcome>> + Send;

    /// The currently installed snapshot (version, body, signatures).
    fn current_directory_snapshot(
        &self,
    ) -> impl Future<Output = Result<Option<InstalledSnapshot>>> + Send;

    // ----- import-slot rewrite and monthly counters (ADR-046(5)) -----

    /// Run at every fixed import slot, after the slot's relay work (AUD-RM2-STO-01,
    /// ADR-052(14)): in one transaction, add the RAM-accumulated monthly counter
    /// deltas, set `activity_month` to the slot's month for the accounts the web
    /// recorded as active since the last slot (RAM-held, like quota) and fold it
    /// from stored replies (never beyond `slot.day`), and rewrite **every** row of
    /// every source-linkable table, so that row `xmin` reveals only the slot.
    /// Everything is validated before anything is written.
    fn uniform_rewrite(
        &self,
        slot: ImportSlot,
        counters: &[CounterDelta],
        active_accounts: &[AccountId],
    ) -> impl Future<Output = Result<()>> + Send;

    /// RL-09 raw cells of a month (suppression per 24 §TEL is the exporter's job).
    fn counters_for_month(
        &self,
        month: Day,
    ) -> impl Future<Output = Result<Vec<CounterCell>>> + Send;

    /// Delete counter months before `month`.
    fn prune_counters_before(&self, month: Day) -> impl Future<Output = Result<u64>> + Send;

    // ----- backup / restore (RL-10, BS-INTAKE) -----

    /// RL-10 snapshot content: meta, accounts, deletion list only.
    fn export_backup(&self) -> impl Future<Output = Result<BackupSnapshot>> + Send;

    /// Restore into an empty store. The KD high-water mark keeps the higher of the
    /// backup and current values; the store is left restore-pending.
    fn restore_backup(&self, backup: BackupSnapshot) -> impl Future<Output = Result<()>> + Send;
}

/// Operations reserved for the separate maintenance role (`candor_intake_maint`,
/// AUD-RM2-STO-03): the application role cannot flag or delete deletion-list
/// entries.
pub trait IntakeMaintenance: Send + Sync {
    /// Daily `deletion_list_prune`: flag entries up to the acknowledged seq as
    /// relayed, then delete relayed entries older than 35 days, always keeping
    /// the newest entry as the chain head (the database refuses anything else).
    fn prune_deletion_list(&self, today: Day) -> impl Future<Output = Result<u64>> + Send;
}
