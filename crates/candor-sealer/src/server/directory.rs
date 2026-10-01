// SPDX-License-Identifier: AGPL-3.0-or-later
//! The sealer's view of a **verified** Key Directory snapshot (04 §12.1, §14).
//!
//! Parsing and verifying C-14 snapshots (checkpoint signatures, witness
//! cosignatures, consistency proofs, roster and COI_POLICY signatures) belongs to
//! the key-directory crate, which does not exist yet. The integrator verifies the
//! snapshot and hands the sealer this typed view; the sealer itself enforces the
//! high-water mark (ADR-036(6)), freshness (ADR-047(4)), suite, time locks
//! (`effective_day`), MEK validity windows and the Triage Set / COI rules.

use candor_core::Suite;

/// One roster member of a channel (latest active CHANNEL_ROSTER).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterMember {
    /// Staff user id.
    pub user_id: [u8; 16],
    /// Role-label id (the COI checklist and COI_POLICY refer to it).
    pub role_label: u16,
    /// Holds `read_intake` (Triage Set member, ADR-037(1)).
    pub read_intake: bool,
    /// First UTC day on which this entry is active (time-locked additions,
    /// ADR-036(2)); entries with `effective_day > today` are ignored.
    pub effective_day: u32,
}

/// A COI_POLICY entry (ADR-030/037).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoiPolicy {
    /// Directory entry hash (recorded in the Recipient List, §13.4 key 16.4).
    pub entry_hash: [u8; 32],
    /// First UTC day on which it is active (loosening is time-locked).
    pub effective_day: u32,
    /// `(category_id, excluded role-label ids)`.
    pub categories: Vec<(u16, Vec<u16>)>,
}

/// A MEMBER_EPOCH entry (04 §9.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberEpochKey {
    /// Owner.
    pub user_id: [u8; 16],
    /// Epoch number.
    pub epoch_id: u32,
    /// First valid UTC day (inclusive).
    pub valid_from_day: u32,
    /// End of validity (exclusive).
    pub valid_until_day: u32,
    /// Revoked.
    pub revoked: bool,
    /// X-Wing public key bytes.
    pub public_key: Vec<u8>,
}

/// One channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelView {
    /// Channel id.
    pub channel_id: [u8; 16],
    /// Intake enabled.
    pub enabled: bool,
    /// Hash of the roster entry the sealer used (§13.4 key 6).
    pub roster_entry_hash: [u8; 32],
    /// Roster version (kept in `prefs_ct`).
    pub roster_version: u64,
    /// Latest active roster.
    pub members: Vec<RosterMember>,
    /// COI_POLICY entries (latest active one applies).
    pub coi_policies: Vec<CoiPolicy>,
    /// Member Epoch Keys.
    pub meks: Vec<MemberEpochKey>,
    /// Alternative independent channel (`independent_route`, §14.2).
    pub independent_route: Option<[u8; 16]>,
}

/// A USER_KEYS entry, used to verify reply signatures (04 §13.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserKeyEntry {
    /// Entry hash (REPLY inner key 6).
    pub entry_hash: [u8; 32],
    /// User.
    pub user_id: [u8; 16],
    /// K08 Ed25519 public key.
    pub sig_pk: [u8; 32],
}

/// A verified directory snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectorySnapshot {
    /// Monotonic snapshot version (returned by `HELLO`).
    pub snapshot_version: u64,
    /// Newest verified checkpoint: tree size.
    pub tree_size: u64,
    /// Newest verified checkpoint: root hash.
    pub root_hash: [u8; 32],
    /// Newest verified checkpoint: issued hour (hours since the Unix epoch).
    pub issued_hour: u64,
    /// Suite of the tenant.
    pub suite: Suite,
    /// UTC day of epoch 0; epoch `n` starts at `epoch_origin_day + 7n` (04 §9.5).
    pub epoch_origin_day: u32,
    /// Identity Custodian Group public key K13 (X-Wing bytes).
    pub custodian_pk: Vec<u8>,
    /// Chaff Disposition public key K41 (X-Wing bytes).
    pub disposition_pk: Vec<u8>,
    /// Channels.
    pub channels: Vec<ChannelView>,
    /// User key entries.
    pub user_keys: Vec<UserKeyEntry>,
}

/// Epoch length in days (04 §9.5).
pub const EPOCH_DAYS: u32 = 7;
/// `KD_SNAPSHOT_MAX_AGE` in hours (ADR-047(4)): 7 days.
pub const KD_SNAPSHOT_MAX_AGE_HOURS: u64 = 7 * 24;

impl DirectorySnapshot {
    /// Channel by id.
    #[must_use]
    pub fn channel(&self, id: &[u8; 16]) -> Option<&ChannelView> {
        self.channels.iter().find(|c| &c.channel_id == id)
    }

    /// UTC day of the checkpoint.
    #[must_use]
    pub fn issued_day(&self) -> u64 {
        self.issued_hour.checked_div(24).unwrap_or(0)
    }

    /// Current epoch for `today`, if `today` is not before the origin.
    #[must_use]
    pub fn epoch_for_day(&self, today: u32) -> Option<u32> {
        today
            .checked_sub(self.epoch_origin_day)?
            .checked_div(EPOCH_DAYS)
    }

    /// Fresh enough to seal to at `today` (ADR-047(4)). Day resolution only
    /// (07 BE-031), so the check is conservative: the checkpoint's issue *day*
    /// plus 7 days must be after today's start, i.e. any checkpoint that may be
    /// older than 7 days is refused.
    #[must_use]
    pub fn is_fresh(&self, today: u32) -> bool {
        let issued_day = self.issued_day();
        let max_days = KD_SNAPSHOT_MAX_AGE_HOURS.checked_div(24).unwrap_or(0);
        match u64::from(today).checked_sub(issued_day) {
            // A checkpoint from the future (by our day) is accepted only within
            // one day of skew (07 BE-032).
            None => issued_day.saturating_sub(u64::from(today)) <= 1,
            Some(age) => age < max_days,
        }
    }

    /// User key entry by hash.
    #[must_use]
    pub fn user_key(&self, entry_hash: &[u8; 32]) -> Option<&UserKeyEntry> {
        self.user_keys
            .iter()
            .find(|u| candor_core::kdf::ct_eq(&u.entry_hash, entry_hash))
    }
}

/// Snapshot high-water mark (ADR-036(6)): `(tree_size, issued_hour)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HighWaterMark {
    /// Tree size.
    pub tree_size: u64,
    /// Checkpoint issued hour.
    pub issued_hour: u64,
}

impl HighWaterMark {
    /// Whether `s` is not below this mark (rollback otherwise).
    #[must_use]
    pub fn admits(&self, s: &DirectorySnapshot) -> bool {
        s.tree_size >= self.tree_size && s.issued_hour >= self.issued_hour
    }

    /// The mark after accepting `s`.
    #[must_use]
    pub fn after(&self, s: &DirectorySnapshot) -> Self {
        Self {
            tree_size: self.tree_size.max(s.tree_size),
            issued_hour: self.issued_hour.max(s.issued_hour),
        }
    }
}
