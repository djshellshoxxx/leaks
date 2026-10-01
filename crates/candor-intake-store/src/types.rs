// SPDX-License-Identifier: AGPL-3.0-or-later
//! Value types of the Intake Store (09-DATABASE.md §5.1).
//!
//! Every source-linked identifier has a redacted `Debug` so that it can never reach
//! a log line, panic message or error text by accident (ADR-016, BUILD-BRIEF
//! "Security and OPSEC bar").

use core::fmt;

use crate::error::StoreError;

/// Objects per envelope group (ADR-052(1)): main object (SUBMISSION or
/// SOURCE_MESSAGE), ATTACHMENT_BUNDLE, IDENTITY — always all three, with dummy
/// objects where the source supplied none.
pub const GROUP_OBJECTS: usize = 3;
/// Encoded RecipientSlotBlock length for CANDOR-STD-1: `4 + 16 × 1168` (04 §13.2).
pub const SLOT_BLOCK_LEN_STD: usize = 4 + 16 * 1168;
/// Domain label of the group digest (relay ack digest).
pub const GROUP_DIGEST_LABEL: &[u8] = b"candor/v1/intake/group";
/// Upper bound for one part's padded size: 16 GiB, the EE per-file cap (ADR-046(4)).
pub const MAX_PART_PADDED_SIZE: u64 = 16 * 1024 * 1024 * 1024;
/// `disposition_ct` length for CANDOR-STD-1: X-Wing `Nenc` (1120) + 48 (04 §12.7).
pub const DISPOSITION_CT_LEN_STD: usize = 1120 + 48;
/// X-Wing public key length (09 §5.1 `xwing_pk bytea(1216)`).
pub const XWING_PK_LEN: usize = 1216;
/// Maximum `prefs_ct` length (09 §5.1).
pub const MAX_PREFS_CT: usize = 4096;
/// Largest delayed-delivery / signal release offset in days (07 BE-078: U{3..21}).
pub const MAX_RELEASE_OFFSET_DAYS: u8 = 21;
/// Size of one published dead-drop entry (08 §3.8: 70,000 bytes).
pub const REPLY_ENTRY_LEN: usize = 70_000;
/// Entries per published page (08 SA-19: `page_size` = 64 in every profile).
pub const REPLY_PAGE_ENTRIES: usize = 64;
/// Bytes of one published page.
pub const REPLY_PAGE_LEN: usize = REPLY_ENTRY_LEN * REPLY_PAGE_ENTRIES;
/// Published window and maximum reply retention (ADR-039: 30 days).
pub const REPLY_WINDOW_DAYS: u32 = 30;
/// Largest `reply_ct`: the entry is `u32 entry_len ‖ reply_ct` padded to 70,000 B
/// (04 §13.5), so 4 bytes are reserved for the length prefix.
pub const MAX_REPLY_CT: usize = REPLY_ENTRY_LEN - 4;
/// REPLY size buckets: `padded_plaintext_len = 4096 × k`, k = 1..=16 (04 §13.6).
pub const REPLY_BUCKETS: u8 = 16;
/// REPLY bucket unit (04 §13.6).
pub const REPLY_BUCKET_UNIT: usize = 4096;
/// Fixed CANDOR-STD-1 overhead of a `reply_ct = SealedObject(REPLY) ‖ stanza (1)`
/// (04 §13.5): CoreHeader 128 + header_mac 32 + one STREAM tag 16 (every REPLY
/// bucket is one 64 KiB chunk) + HPKE_BASE stanza (70 fixed + X-Wing enc 1120 +
/// u32 ct_len 4 + wrapped CK 32 + tag 16 = 1242). Checked against candor-core in
/// the tests (`reply_ct_len_matches_core`).
pub const REPLY_CT_OVERHEAD_STD: usize = 128 + 32 + 16 + (70 + 1120 + 4 + 32 + 16);

/// Canonical `reply_ct` length of REPLY bucket `k` (AUD-RM2-STO-19/20): the only
/// lengths the store accepts, for real replies and dummies alike.
#[must_use]
pub fn reply_ct_len(bucket: u8) -> Option<usize> {
    if !(1..=REPLY_BUCKETS).contains(&bucket) {
        return None;
    }
    usize::from(bucket)
        .checked_mul(REPLY_BUCKET_UNIT)?
        .checked_add(REPLY_CT_OVERHEAD_STD)
}

/// The single function that derives the stored `reply.size_bucket` from a
/// `reply_ct` length, for real and dummy rows alike (AUD-RM2-STO-20). `None`
/// for any non-canonical length.
#[must_use]
pub fn reply_bucket_of_len(len: usize) -> Option<u8> {
    let body = len.checked_sub(REPLY_CT_OVERHEAD_STD)?;
    if body == 0 || body % REPLY_BUCKET_UNIT != 0 {
        return None;
    }
    let k = u8::try_from(body / REPLY_BUCKET_UNIT).ok()?;
    (reply_ct_len(k) == Some(len)).then_some(k)
}

/// Tier W fixed mailbox size (08 §3.8 `N_fixed = 32`).
pub const MAILBOX_SLOTS: u8 = 32;
/// Replies per RL-05 push (08 RL-05).
pub const MAX_REPLIES_PER_PUSH: usize = 500;
/// Objects per RL-02 claim (08 RL-02).
pub const MAX_CLAIM_OBJECTS: u32 = 500;
/// Bytes per RL-02 claim (08 RL-02: 2 GiB).
pub const MAX_CLAIM_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Entries per RL-11 response (08 RL-11).
pub const MAX_DELETION_LIST_PAGE: u32 = 10_000;
/// Deletion-list retention (09 §5.1: 35 days, pruned only after relay ack).
pub const DELETION_LIST_RETENTION_DAYS: u32 = 35;
/// Largest accepted Key Directory snapshot body (implementation decision, SPEC-NOTES).
pub const MAX_SNAPSHOT_BODY: usize = 32 * 1024 * 1024;
/// Largest accepted Key Directory snapshot signature block (implementation decision).
pub const MAX_SNAPSHOT_SIGNATURES: usize = 1024 * 1024;
/// `inactive_purge` horizon (09 §5.1: 365 days after the start of the last
/// `activity_month`).
pub const INACTIVE_PURGE_DAYS: u32 = 365;
/// Largest number of active accounts flushed at one import slot.
pub const MAX_SLOT_ACTIVE_ACCOUNTS: usize = 1_000_000;
/// Largest number of entries a pushed deletion list (RL-12) may carry: the
/// 35-day retained list at well above EE deletion rates (AUD-RM2-STO-12).
pub const MAX_PUSHED_DELETION_LIST: usize = 200_000;

/// A UTC day number (days since 1970-01-01). The only wall-clock granularity the
/// Intake Store ever accepts or stores (ADR-010, 07 §12 `EpochDay`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Day(pub u32);

impl Day {
    /// `self + n` days, checked.
    pub fn plus(self, n: u32) -> Result<Day, StoreError> {
        self.0
            .checked_add(n)
            .map(Day)
            .ok_or(StoreError::InvalidInput("day overflow"))
    }

    /// `self - n` days, saturating at day 0.
    #[must_use]
    pub fn saturating_minus(self, n: u32) -> Day {
        Day(self.0.saturating_sub(n))
    }

    /// The first day of this day's UTC calendar month.
    #[must_use]
    pub fn month_start(self) -> Day {
        let (y, m, _d) = civil_from_days(i64::from(self.0));
        Day(days_from_civil(y, m, 1).clamp(0, i64::from(u32::MAX)) as u32)
    }

    /// Whether this day is the first of a UTC calendar month.
    #[must_use]
    pub fn is_month_start(self) -> bool {
        self.month_start() == self
    }

    /// The first day of the following month.
    #[must_use]
    pub fn next_month_start(self) -> Day {
        let (y, m, _) = civil_from_days(i64::from(self.0));
        let (ny, nm) = if m == 12 {
            (y.saturating_add(1), 1)
        } else {
            (y, m.saturating_add(1))
        };
        Day(days_from_civil(ny, nm, 1).clamp(0, i64::from(u32::MAX)) as u32)
    }
}

// Howard Hinnant's civil-date algorithms (public domain), with i64 arithmetic.
// Inputs are bounded to u32 day numbers, so no intermediate overflows.
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[allow(clippy::arithmetic_side_effects)]
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

macro_rules! redacted_id {
    ($(#[$m:meta])* $name:ident, $len:expr) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; $len]);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }

        impl $name {
            /// Raw bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }
    };
}

redacted_id!(
    /// Tenant identifier (`intake_meta.tenant_id`).
    TenantId, 16
);
redacted_id!(
    /// Channel identifier (WF).
    ChannelId, 16
);
redacted_id!(
    /// Tier W account identifier; never leaves Z-INTAKE (06 §14).
    AccountId, 16
);
redacted_id!(
    /// Intake-local envelope reference, also the RL-02 `ref` (valid only per batch).
    EnvelopeRef, 16
);
redacted_id!(
    /// Reply row reference.
    ReplyRef, 16
);
redacted_id!(
    /// Random 128-bit blob object id (blob files are managed by the caller via
    /// `candor-safefs`; the store keeps only the reference).
    BlobId, 16
);
redacted_id!(
    /// `lookup_tag` (04 §11.4) = 09's `locator_hash`.
    LookupTag, 32
);
redacted_id!(
    /// Tier W per-report mailbox id (04 §11.4), used only for deletion-list hashing.
    MailboxId, 32
);

impl ChannelId {
    /// Build from raw bytes.
    #[must_use]
    pub fn new(b: [u8; 16]) -> Self {
        Self(b)
    }
}

/// Generate a fresh random 128-bit identifier from the OS CSPRNG (09 §5 "IDs").
pub fn random_id16() -> Result<[u8; 16], StoreError> {
    let mut b = [0u8; 16];
    crate::rng::fill(&mut b).map_err(|_| StoreError::Rng)?;
    Ok(b)
}

/// A Tier W source account row (09 §5.1 `source_account`).
#[derive(Clone, PartialEq, Eq)]
pub struct SourceAccount {
    /// Account id.
    pub account_id: AccountId,
    /// `locator_hash` / `lookup_tag`.
    pub lookup_tag: LookupTag,
    /// Ed25519 auth public key (the "verifier"); verification is the caller's job.
    pub auth_pk: [u8; 32],
    /// X-Wing reply public key (1216 bytes).
    pub xwing_pk: Vec<u8>,
    /// `prefs_ct` (≤ 4096 bytes, ciphertext).
    pub prefs_ct: Vec<u8>,
    /// First day of the month of the last stored envelope or reply. Folded in
    /// only at import-slot rewrites, never per action (AUD-RM2-STO-01).
    pub activity_month: Day,
}

impl fmt::Debug for SourceAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SourceAccount(<redacted>)")
    }
}

/// Account fields supplied when a new Tier W account is committed together with
/// its first envelope (ADR-034: no pending accounts).
#[derive(Clone)]
pub struct NewAccount {
    /// `lookup_tag`.
    pub lookup_tag: LookupTag,
    /// Ed25519 auth public key.
    pub auth_pk: [u8; 32],
    /// X-Wing public key.
    pub xwing_pk: Vec<u8>,
    /// `prefs_ct`.
    pub prefs_ct: Vec<u8>,
}

impl fmt::Debug for NewAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NewAccount(<redacted>)")
    }
}

/// One stored blob reference (09 §5.1 `envelope_part`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PartRef {
    /// Blob object id (blob written and fsynced by the caller before commit).
    pub blob_id: BlobId,
    /// Padded size (ADR-011 bucket; bucket legality is checked by the sealer/web).
    pub padded_size: u64,
}

/// One sealed object of an envelope group: its `object_hash` (04 §13.1), its
/// RecipientSlotBlock and the blob holding the SealedObject (written and fsynced
/// by the caller before commit).
#[derive(Clone, PartialEq, Eq)]
pub struct GroupObject {
    /// `object_hash`.
    pub object_hash: [u8; 32],
    /// Encoded RecipientSlotBlock (exactly [`SLOT_BLOCK_LEN_STD`] bytes).
    pub slot_block: Vec<u8>,
    /// Blob.
    pub blob: PartRef,
}

impl fmt::Debug for GroupObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GroupObject(<redacted>)")
    }
}

/// `COMMIT_ENVELOPE` request (07 §5.3, amended by ADR-052(1)/(2)): exactly one
/// fixed-shape group and no account reference. Real and chaff envelopes are
/// identical.
#[derive(Clone)]
pub struct CommitEnvelope {
    /// Channel.
    pub channel_id: ChannelId,
    /// `[main, bundle, identity]` (ADR-052(1)).
    pub objects: [GroupObject; GROUP_OBJECTS],
    /// Disposition marker (fixed size, opaque to the intake).
    pub disposition_ct: Vec<u8>,
    /// Sealing epoch reported to the relay (RL-02 `epoch_index`).
    pub epoch_index: u32,
    /// `received_date` = `SourceClock::today()` of the caller (day only, ADR-010).
    pub received_date: Day,
    /// `release_day - received_date` (0..=21; ADR-038(4), BE-078).
    pub release_offset_days: u8,
}

/// Group digest = relay ack digest (RL-02 `sha256`):
/// `SHA-256("candor/v1/intake/group" ‖ object_hash₀ ‖ object_hash₁ ‖ object_hash₂)`.
#[must_use]
pub fn group_digest(object_hashes: &[[u8; 32]; GROUP_OBJECTS]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(GROUP_DIGEST_LABEL);
    for o in object_hashes {
        h.update(o);
    }
    h.finalize().into()
}

impl fmt::Debug for CommitEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CommitEnvelope(<redacted>)")
    }
}

/// RL-02 claim limits.
#[derive(Clone, Copy, Debug)]
pub struct ClaimLimits {
    /// ≤ 500.
    pub max_objects: u32,
    /// ≤ 2 GiB.
    pub max_bytes: u64,
}

/// One RL-02 envelope-group descriptor. Carries neither `received_date`,
/// `release_day`, account link nor any kind/tier marker (ADR-038(3), API-047,
/// API-057, ADR-052(2)).
#[derive(Clone, PartialEq, Eq)]
pub struct ClaimedObject {
    /// Intake-local ref.
    pub envelope_ref: EnvelopeRef,
    /// Channel.
    pub channel_id: ChannelId,
    /// Sealing epoch.
    pub epoch_index: u32,
    /// `object_hash` of each group object, in group order.
    pub object_hashes: [[u8; 32]; GROUP_OBJECTS],
    /// Padded blob sizes, in group order.
    pub parts: [u64; GROUP_OBJECTS],
    /// Group digest (relay ack digest, [`group_digest`]).
    pub sha256: [u8; 32],
    /// Opaque disposition marker.
    pub disposition_ct: Vec<u8>,
}

/// An RL-02 batch.
#[derive(Clone, PartialEq, Eq)]
pub struct ClaimedBatch {
    /// Monotonic batch number.
    pub batch_no: u64,
    /// `true` when this is the still-unacked previous batch (RL-02 `conflict`).
    pub replayed: bool,
    /// Objects (random order).
    pub objects: Vec<ClaimedObject>,
}

/// RL-03 part selector (group object index 0..=2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PartSelector {
    /// The object's RecipientSlotBlock.
    SlotBlock(u8),
    /// The object's SealedObject blob.
    Object(u8),
}

/// RL-03 result.
#[derive(Clone, PartialEq, Eq)]
pub enum ObjectData {
    /// Inline bytes (a slot block).
    Bytes(Vec<u8>),
    /// A blob the caller streams from the blob directory.
    Blob(PartRef),
}

/// RL-04 result.
#[derive(Clone, PartialEq, Eq)]
pub struct AckResult {
    /// Envelopes deleted.
    pub deleted: u32,
    /// Blobs the caller must now delete from the blob directory (BE-014).
    pub blobs_to_delete: Vec<BlobId>,
}

/// One RL-05 reply after the caller opened `routing_ct` with the Intake Routing Key.
#[derive(Clone)]
pub struct IncomingReply {
    /// Tier W account the mailbox resolved to; `None` for Tier V replies.
    pub account: Option<AccountId>,
    /// Mailbox id from `routing_ct` (deletion-list check only; never stored).
    pub mailbox_id: Option<MailboxId>,
    /// `object_hash` of the REPLY SealedObject (deletion-list check only).
    pub object_hash: [u8; 32],
    /// `SealedObject ‖ stanza (1)` (04 §13.5).
    pub reply_ct: Vec<u8>,
    /// REPLY size bucket index (k of 4096 × k, 1..=16; 04 §13.6).
    pub size_bucket: u8,
}

impl fmt::Debug for IncomingReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IncomingReply(<redacted>)")
    }
}

/// RL-05 result.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ApplyRepliesResult {
    /// Accepted count (includes silently dropped deleted-target replies, RL-05).
    pub accepted: u32,
    /// Indices of rejected replies.
    pub rejected: Vec<u32>,
}

/// A stored Tier W reply (inbox view, `MAILBOX_LIST`).
#[derive(Clone, PartialEq, Eq)]
pub struct StoredReply {
    /// Ref.
    pub reply_ref: ReplyRef,
    /// Fixed-mailbox slot 0..=31.
    pub slot: u8,
    /// Ciphertext.
    pub reply_ct: Vec<u8>,
    /// Size bucket.
    pub size_bucket: u8,
    /// Day the reply became available.
    pub available_day: Day,
}

impl fmt::Debug for StoredReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoredReply(<redacted>)")
    }
}

/// SA-19 index.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReplyIndex {
    /// Random per rebuild; changes only at rebuilds (import slots).
    pub set_version: u64,
    /// Power of two, ≥ 1; fixed by the deployment's [`crate::DeadDropConfig`]
    /// (never by the number of replies).
    pub page_count: u16,
    /// Always 64.
    pub page_size: u16,
    /// Always 30.
    pub window_days: u16,
}

/// A Key Directory snapshot whose signature chain, witness cosignatures and
/// consistency proof from `consistent_from` the caller has already verified
/// (RL-06; verification belongs to the KD verifier, not the store).
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedSnapshot {
    /// Snapshot version.
    pub version: u64,
    /// Verified tree size.
    pub tree_size: u64,
    /// Day of the newest checkpoint.
    pub checkpoint_day: Day,
    /// Tree size the consistency proof starts from; must equal the stored
    /// high-water mark (checked atomically with the install).
    pub consistent_from: u64,
    /// Signed CBOR body.
    pub body: Vec<u8>,
    /// Signatures.
    pub signatures: Vec<u8>,
}

impl fmt::Debug for VerifiedSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedSnapshot")
            .field("version", &self.version)
            .field("tree_size", &self.tree_size)
            .finish_non_exhaustive()
    }
}

/// The snapshot high-water mark (09 `intake_meta.kd_tree_size_hwm` and
/// `kd_checkpoint_day_hwm`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct KdHighWater {
    /// Largest verified tree size ever applied.
    pub tree_size: u64,
    /// Checkpoint day of that snapshot (`None` before the first install).
    pub checkpoint_day: Option<Day>,
    /// Last applied snapshot version.
    pub directory_version: u64,
}

/// Snapshot install outcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InstallOutcome {
    /// Installed and the high-water mark advanced (or stayed equal).
    Installed,
    /// The identical snapshot was already installed (idempotent re-push).
    AlreadyInstalled,
}

/// Monthly counter names (09 `counter_month.name`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum CounterName {
    /// Real envelopes received.
    SubmissionsReceived,
    /// Accounts created.
    AccountsCreated,
    /// Account deletions.
    AccountDeletions,
}

impl CounterName {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SubmissionsReceived => "submissions_received",
            Self::AccountsCreated => "accounts_created",
            Self::AccountDeletions => "account_deletions",
        }
    }

    pub(crate) fn parse(s: &str) -> Result<Self, StoreError> {
        match s {
            "submissions_received" => Ok(Self::SubmissionsReceived),
            "accounts_created" => Ok(Self::AccountsCreated),
            "account_deletions" => Ok(Self::AccountDeletions),
            _ => Err(StoreError::Integrity("unknown counter name")),
        }
    }
}

/// One monthly counter cell (aggregate; suppression is applied by the exporter).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CounterCell {
    /// Channel.
    pub channel_id: ChannelId,
    /// Name.
    pub name: CounterName,
    /// Value.
    pub value: u32,
}

/// A monthly counter increment flushed at an import slot (ADR-046(5)). Counters
/// are accumulated in process RAM and written only by
/// [`crate::IntakeStore::uniform_rewrite`], so no counter row is written next to
/// a real envelope (AUD-RM2-STO-01, ADR-047(3)).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CounterDelta {
    /// First day of the month.
    pub month: Day,
    /// Channel.
    pub channel_id: ChannelId,
    /// Name.
    pub name: CounterName,
    /// Increment.
    pub delta: u32,
}

impl fmt::Debug for CounterDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CounterDelta(<redacted>)")
    }
}

/// A fixed import slot (ADR-038(1)): the slot's UTC day and its index within the
/// day (`0..slots_per_day`). Slot times are public configuration.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ImportSlot {
    /// UTC day of the slot.
    pub day: Day,
    /// Index of the slot within the day.
    pub index: u8,
}

/// `intake_meta` contents carried in a backup snapshot (RL-10).
#[derive(Clone, PartialEq, Eq)]
pub struct MetaSnapshot {
    /// Tenant.
    pub tenant_id: TenantId,
    /// Per-deployment Argon2id salt (public).
    pub kdf_salt: [u8; 32],
    /// Relay anti-replay counter.
    pub relay_req_counter: u64,
    /// Last batch number.
    pub last_batch_no: u64,
    /// KD high-water mark.
    pub kd: KdHighWater,
    /// Last Z-CORE-signed deletion-list head the store verified (acknowledged
    /// through RL-11 or confirmed by RL-12). Carried in backups so that a
    /// restored node only accepts a pushed list that chains to it
    /// (AUD-RM2-STO-22).
    pub deletion_head: Option<crate::deletion::SignedDeletionHead>,
}

impl fmt::Debug for MetaSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MetaSnapshot(<redacted>)")
    }
}

/// RL-10 backup content: `source_account`, `deletion_list`, `intake_meta` only
/// (no envelopes, no replies). Encryption to the Backup Key is the caller's job.
#[derive(Clone, PartialEq, Eq)]
pub struct BackupSnapshot {
    /// Meta.
    pub meta: MetaSnapshot,
    /// Accounts.
    pub accounts: Vec<SourceAccount>,
    /// Deletion list (with relayed flags).
    pub deletion_list: Vec<crate::deletion::DeletionEntry>,
}

impl fmt::Debug for BackupSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BackupSnapshot(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_math() {
        // 2026-10-01 = day 20727; 2026-10-15 = 20741; 2026-11-01 = 20758.
        assert_eq!(Day(20741).month_start(), Day(20727));
        assert!(Day(20727).is_month_start());
        assert!(!Day(20741).is_month_start());
        assert_eq!(Day(20741).next_month_start(), Day(20758));
        // 2026-12-31 -> 2027-01-01
        assert_eq!(Day(20818).next_month_start(), Day(20819));
        assert_eq!(Day(0).month_start(), Day(0));
    }

    /// AUD-RM2-STO-19/20: the canonical REPLY lengths match candor-core's STREAM
    /// and HPKE_BASE stanza encodings, and length ↔ bucket is a bijection.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn reply_ct_len_matches_core() {
        use candor_core::stanza::{HpkeWrapContext, WrapStanza};
        use candor_core::{Suite, kem::KemKeyPair};
        let kp = KemKeyPair::derive(Suite::CandorStd1, &[7u8; 32]).unwrap();
        let ctx = HpkeWrapContext::Reply {
            tenant_id: [1; 16],
            channel_id: [2; 16],
            mailbox_id: [3; 32],
        };
        let st = WrapStanza::seal_hpke(Suite::CandorStd1, &kp.public, [0; 32], [9; 32], &ctx, &[5u8; 32])
            .unwrap();
        let stanza_len = st.encode().unwrap().len();
        for k in 1..=REPLY_BUCKETS {
            let pt = u64::from(k) * 4096;
            let payload = usize::try_from(candor_core::stream::ciphertext_len(pt).unwrap()).unwrap();
            let expect = candor_core::header::HEADER_LEN
                + candor_core::header::HEADER_MAC_LEN
                + payload
                + stanza_len;
            assert_eq!(reply_ct_len(k), Some(expect), "bucket {k}");
            assert!(expect <= MAX_REPLY_CT);
            assert_eq!(reply_bucket_of_len(expect), Some(k));
            assert_eq!(reply_bucket_of_len(expect + 1), None);
            assert_eq!(reply_bucket_of_len(expect - 1), None);
        }
        assert_eq!(reply_ct_len(0), None);
        assert_eq!(reply_ct_len(17), None);
        assert_eq!(reply_bucket_of_len(0), None);
        assert_eq!(reply_bucket_of_len(REPLY_CT_OVERHEAD_STD), None);
        assert_eq!(reply_bucket_of_len(usize::MAX), None);
    }

    #[test]
    fn debug_is_redacted() {
        let a = AccountId([0xab; 16]);
        assert_eq!(format!("{a:?}"), "AccountId(<redacted>)");
        let t = LookupTag([0xcd; 32]);
        assert!(!format!("{t:?}").contains("cd"));
    }
}

#[cfg(test)]
mod props {
    #![allow(clippy::arithmetic_side_effects)]
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Month arithmetic is total and consistent for every u32 day number.
        #[test]
        fn month_start_properties(d in 0u32..3_000_000) {
            let day = Day(d);
            let m = day.month_start();
            prop_assert!(m <= day);
            prop_assert!(m.is_month_start());
            prop_assert!(day.0 - m.0 < 31);
            let n = day.next_month_start();
            prop_assert!(n > day);
            prop_assert!(n.is_month_start());
            prop_assert!(n.0 - m.0 >= 28 && n.0 - m.0 <= 31);
        }
    }
}

impl fmt::Debug for PartRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PartRef(<redacted>)")
    }
}

impl fmt::Debug for ClaimedObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClaimedObject(<redacted>)")
    }
}

impl fmt::Debug for ClaimedBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClaimedBatch(<redacted>)")
    }
}

impl fmt::Debug for ObjectData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ObjectData(<redacted>)")
    }
}

impl fmt::Debug for AckResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AckResult(<redacted>)")
    }
}

impl fmt::Debug for CounterCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CounterCell(<redacted>)")
    }
}
