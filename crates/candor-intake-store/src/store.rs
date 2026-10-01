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
    AccountId, AckResult, ApplyRepliesResult, BackupSnapshot, ChannelId, ClaimLimits,
    ClaimedBatch, CommitEnvelope, CounterCell, CounterName, Day, EnvelopeRef, IncomingReply,
    InstallOutcome, KdHighWater, LookupTag, MailboxId, ObjectData, PartSelector, ReplyIndex,
    ReplyRef, SourceAccount, StoredReply, TenantId, VerifiedSnapshot,
};

/// Intake Store operations. Both [`crate::MemoryStore`] and
/// [`crate::PgIntakeStore`] pass the same conformance suite.
pub trait IntakeStore: Send + Sync {
    // ----- meta -----

    /// Initialise `intake_meta` (idempotent for the same tenant; `TenantMismatch`
    /// otherwise). The salt is public (ADR-005).
    fn init(&self, tenant: TenantId, kdf_salt: [u8; 32]) -> impl Future<Output = Result<()>> + Send;

    /// The tenant (`NotInitialized` before `init`).
    fn tenant(&self) -> impl Future<Output = Result<TenantId>> + Send;

    /// Accept a relay request counter only if strictly greater than the stored
    /// one, persisting it (07 §5.4 anti-replay).
    fn accept_relay_counter(&self, counter: u64) -> impl Future<Output = Result<()>> + Send;

    /// `false` while a restore awaits its deletion list (07 BE-074; RL-01
    /// `restored`). Source-facing callers must show the busy page.
    fn serving_allowed(&self) -> impl Future<Output = Result<bool>> + Send;

    // ----- accounts (Tier W) -----

    /// Look up an account by `lookup_tag`. Verifier checks and uniform timing for
    /// unknown tags are the caller's job (07 §5.3, BE-010).
    fn lookup_account(
        &self,
        tag: &LookupTag,
    ) -> impl Future<Output = Result<Option<SourceAccount>>> + Send;

    /// Delete an account, its replies and its envelope links, appending a signed
    /// `account` deletion-list entry in the same transaction (SW-15, BE-074).
    fn delete_account(
        &self,
        account: AccountId,
        today: Day,
        signer: &dyn DeletionSigner,
    ) -> impl Future<Output = Result<()>> + Send;

    /// Consume `amount` of today's quota if the result stays ≤ `limit`; returns the
    /// new value (BE-064).
    fn quota_consume(
        &self,
        account: AccountId,
        amount: u16,
        limit: u16,
    ) -> impl Future<Output = Result<u16>> + Send;

    /// Daily `quota_reset`: set every `quota_bucket` to 0. No history (ADR-038(3)).
    fn quota_reset(&self) -> impl Future<Output = Result<u64>> + Send;

    // ----- envelopes / relay export -----

    /// `COMMIT_ENVELOPE`: insert the envelope (and, for `AccountLink::New`, its
    /// account) atomically; returns only after the database commit (`fsync`,
    /// ADR-046(1)). Blob files must be durable before this call.
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

    /// RL-03: header, manifest or part reference of an envelope in a batch.
    fn batch_object(
        &self,
        batch_no: u64,
        envelope: EnvelopeRef,
        part: PartSelector,
    ) -> impl Future<Output = Result<ObjectData>> + Send;

    /// RL-04: delete exactly the envelopes whose `header_sha256` is listed (all must
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
    /// fixed-mailbox slot; a full mailbox rejects the reply.
    fn apply_replies(
        &self,
        today: Day,
        replies: Vec<IncomingReply>,
    ) -> impl Future<Output = Result<ApplyRepliesResult>> + Send;

    /// `MAILBOX_LIST` (Tier W): the account's replies ordered by slot.
    fn mailbox_list(
        &self,
        account: AccountId,
    ) -> impl Future<Output = Result<Vec<StoredReply>>> + Send;

    /// Source deletes replies of its own account; one signed `reply` entry per
    /// reply (`object_hash` supplied by the caller) in the same transaction.
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

    /// Daily `reply_expiry` and RL-08: delete replies with `available_day < cutoff`.
    /// The store also refuses to keep anything older than 30 days: callers pass
    /// `cutoff ≥ today − 30` (enforced by [`IntakeStore::expire_replies`]).
    fn purge_replies_before(&self, cutoff: Day) -> impl Future<Output = Result<u64>> + Send;

    /// `reply_expiry` with `retention_days ≤ 30` (ADR-039).
    fn expire_replies(
        &self,
        today: Day,
        retention_days: u32,
    ) -> impl Future<Output = Result<u64>> + Send;

    /// Rebuild the published set from every reply in the 30-day window (called
    /// only at import slots, so `set_version` changes only then; BE-063).
    fn rebuild_published_set(&self, today: Day) -> impl Future<Output = Result<ReplyIndex>> + Send;

    /// SA-19 index of the current published set.
    fn reply_index(&self) -> impl Future<Output = Result<ReplyIndex>> + Send;

    /// SA-20 page `n` of the current published set (identical bytes for everyone).
    fn reply_page(&self, n: u16) -> impl Future<Output = Result<Arc<[u8]>>> + Send;

    // ----- deletion list -----

    /// RL-11: entries with `seq > after`, at most `limit` (≤ 10,000). Entries with
    /// `seq ≤ after` are marked relayed (the relay holds them).
    fn deletion_list_after(
        &self,
        after: u64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<DeletionEntry>>> + Send;

    /// RL-12 / restore: verify the pushed Z-CORE copy (chain, K31, no gaps, no fork
    /// with local entries), merge newer entries, delete every listed account and
    /// reply, then clear the restore-pending flag. Returns `applied_through_seq`.
    fn apply_pushed_deletion_list(
        &self,
        entries: &[DeletionEntry],
        k31_pk: &[u8; 32],
        hasher: &dyn ReplyObjectHasher,
    ) -> impl Future<Output = Result<u64>> + Send;

    /// Daily `deletion_list_prune`: delete relayed entries older than 35 days,
    /// always keeping the newest entry as the chain head.
    fn prune_deletion_list(&self, today: Day) -> impl Future<Output = Result<u64>> + Send;

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
    ) -> impl Future<Output = Result<Option<(u64, Vec<u8>, Vec<u8>)>>> + Send;

    // ----- monthly counters (ADR-046(5)) -----

    /// Add to a monthly counter cell. `month` must be the first day of a month.
    fn counter_add(
        &self,
        month: Day,
        channel: ChannelId,
        name: CounterName,
        delta: u32,
    ) -> impl Future<Output = Result<()>> + Send;

    /// RL-09 raw cells of a month (suppression per 24 §TEL is the exporter's job).
    fn counters_for_month(&self, month: Day) -> impl Future<Output = Result<Vec<CounterCell>>> + Send;

    /// Delete counter months before `month`.
    fn prune_counters_before(&self, month: Day) -> impl Future<Output = Result<u64>> + Send;

    // ----- backup / restore (RL-10, BS-INTAKE) -----

    /// RL-10 snapshot content: meta, accounts, deletion list only.
    fn export_backup(&self) -> impl Future<Output = Result<BackupSnapshot>> + Send;

    /// Restore into an empty store. The KD high-water mark keeps the higher of the
    /// backup and current values; the store is left restore-pending.
    fn restore_backup(&self, backup: BackupSnapshot) -> impl Future<Output = Result<()>> + Send;
}
