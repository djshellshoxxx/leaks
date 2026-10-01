// SPDX-License-Identifier: AGPL-3.0-or-later
//! The sealer's view of a **verified** Key Directory snapshot (04 §12.1, §14).
//!
//! The sealer only seals against a [`VerifiedSnapshot`] (ADR-052(6)), whose only
//! constructor [`VerifiedSnapshot::verify`] *derives* the view from the
//! directory log itself (AUD-RM2-SEA-19); there is no way to hand the sealer a
//! free-standing view. Against the pinned [`DirectoryTrust`] (VR-1) it checks:
//! * **content binding (VR-4, full-tree recomputation):** the bundle carries
//!   every SignedKDEntry of the log; their RFC 9162 Merkle root must equal the
//!   signed checkpoint's root. This proves the inclusion of every entry used
//!   *and* the absence of any other (a newer roster, a REVOCATION or an
//!   OBJECTION cannot be withheld), which inclusion proofs alone cannot;
//! * every entry's format, continuity and signatures (`kd`, §14.2/§14.4:
//!   member K08 signs MEKs, OVERSIGHT certifies role labels, the CIK signs
//!   rosters and COI policies, K01 the tenant keys), with time locks,
//!   objections and revocations;
//! * the checkpoint signature of the LOG_KEY entry (itself K01-signed) and the
//!   witness cosignature policy of the ORG_ROOT entry, never below the pinned
//!   floors (VR-2, 04 §14.3);
//! * continuity with the high-water mark: an RFC 9162 consistency proof from
//!   the mark's `(tree_size, root_hash)`, and an equal size only with an equal
//!   root (VR-3, ADR-036(6)).
//!
//! The sealer additionally enforces freshness (ADR-047(4)), suite, activation
//! days, role-label certificate validity, MEK validity windows and the Triage
//! Set / COI rules at selection time. The Recipient List's checkpoint field
//! (§13.4 key 16.5) and SUBMISSION key 7 carry the verified checkpoint's
//! `(tree_size, root_hash)`, which commits to every entry the selection used.

use super::kd;
use candor_core::Suite;
use candor_core::sig::verify_strict;

/// One member of a CHANNEL_ROSTER entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterMember {
    /// Staff user id.
    pub user_id: [u8; 16],
    /// Role-label id (the COI checklist and COI_POLICY refer to it).
    pub role_label: u16,
    /// Holds `read_intake` (Triage Set member, ADR-037(1)).
    pub read_intake: bool,
    /// Last day (inclusive) of the latest ROLE_LABEL_CERT for this label in the
    /// channel, if that certificate is *independent* (ADR-036(3), §14.4 rule 5).
    /// A Triage Set member is eligible only while this covers `today`.
    pub label_certified_until: Option<u32>,
}

/// One verified CHANNEL_ROSTER entry. The active roster at `today` is the
/// latest entry with `activation_day ≤ today` (tightening entries are active
/// on inclusion; loosening ones after their time lock, ADR-036(2)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterVersion {
    /// Entry hash (§13.4 key 6).
    pub entry_hash: [u8; 32],
    /// Roster version (kept in `prefs_ct`).
    pub roster_version: u64,
    /// Effective activation day (0 = active on inclusion).
    pub activation_day: u32,
    /// Alternative independent channel (`independent_route`, §14.2).
    pub independent_route: Option<[u8; 16]>,
    /// Members.
    pub members: Vec<RosterMember>,
}

/// A COI_POLICY entry (ADR-030/037).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoiPolicy {
    /// Directory entry hash (recorded in the Recipient List, §13.4 key 16.4).
    pub entry_hash: [u8; 32],
    /// Effective activation day (0 = active on inclusion; loosening is
    /// time-locked). The latest entry with `effective_day ≤ today` applies.
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
    /// Revoked, or no longer signed by the member's current K08.
    pub revoked: bool,
    /// X-Wing public key bytes.
    pub public_key: Vec<u8>,
}

/// One channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelView {
    /// Channel id.
    pub channel_id: [u8; 16],
    /// Intake enabled (the operator may disable a channel; it can never
    /// enable one the directory does not define).
    pub enabled: bool,
    /// Verified roster entries in log order.
    pub rosters: Vec<RosterVersion>,
    /// COI_POLICY entries in log order (latest active one applies).
    pub coi_policies: Vec<CoiPolicy>,
    /// Member Epoch Keys.
    pub meks: Vec<MemberEpochKey>,
}

impl ChannelView {
    /// The active roster at `today`.
    #[must_use]
    pub fn active_roster(&self, today: u32) -> Option<&RosterVersion> {
        self.rosters
            .iter()
            .rev()
            .find(|r| r.activation_day <= today)
    }

    /// The active COI_POLICY at `today`.
    #[must_use]
    pub fn active_coi(&self, today: u32) -> Option<&CoiPolicy> {
        self.coi_policies
            .iter()
            .rev()
            .find(|p| p.effective_day <= today)
    }

    /// `independent_route` of the active roster (else of the latest one).
    #[must_use]
    pub fn independent_route(&self, today: u32) -> Option<[u8; 16]> {
        self.active_roster(today)
            .or(self.rosters.last())
            .and_then(|r| r.independent_route)
    }
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

/// The view derived from a verified directory log. Only produced by
/// [`VerifiedSnapshot::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectorySnapshot {
    /// Snapshot counter from C-09 (returned by `HELLO`; informational).
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
    /// Identity Custodian Group public key K13 (X-Wing bytes; latest K01-signed
    /// CUSTODIAN_GROUP of the tenant suite, empty if none).
    pub custodian_pk: Vec<u8>,
    /// Chaff Disposition public key K41 (X-Wing bytes; latest DISPOSITION_KEY).
    pub disposition_pk: Vec<u8>,
    /// Channels.
    pub channels: Vec<ChannelView>,
    /// Unrevoked USER_KEYS entries (every version).
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

/// Snapshot high-water mark (ADR-036(6)): the newest accepted checkpoint.
/// Persist it **before** the snapshot is used ([`crate::server::Sealer::install_snapshot`]
/// calls the persistence hook first) and restore it at start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HighWaterMark {
    /// Tree size (0 = nothing accepted yet).
    pub tree_size: u64,
    /// Root hash at `tree_size`.
    pub root_hash: [u8; 32],
    /// Checkpoint issued hour.
    pub issued_hour: u64,
}

/// One pinned witness key (ORG_ROOT witness list, 04 §14.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessKey {
    /// K39 Ed25519 public key.
    pub pk: [u8; 32],
    /// Witness outside the operating organisation.
    pub external: bool,
}

/// Directory trust anchors pinned at install (VR-1). The LOG_KEY, the witness
/// keys and the tenant's cosignature policy come from the verified log
/// (LOG_KEY and ORG_ROOT entries); the pinned minimums are floors the log
/// cannot lower.
#[derive(Clone, PartialEq, Eq)]
pub struct DirectoryTrust {
    /// Tenant id (checkpoint origin line, entry tenant).
    pub tenant_id: [u8; 16],
    /// K01 (ORG_ROOT Ed25519 key) pinned at install. The log's ORG_ROOT chain
    /// must contain it; later roots must be rotation-signed (VR-1).
    pub org_root_pk: [u8; 32],
    /// UTC day of epoch 0; epoch `n` starts at `epoch_origin_day + 7n` (04 §9.5;
    /// not a directory field, see SPEC-NOTES item 12).
    pub epoch_origin_day: u32,
    /// Floor for `w_total` (EE/GOV/MANAGED: ≥ 2).
    pub min_cosignatures: usize,
    /// Floor for `w_external` (EE/GOV/MANAGED: ≥ 1).
    pub min_external: usize,
}

impl core::fmt::Debug for DirectoryTrust {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DirectoryTrust")
            .field("min_cosignatures", &self.min_cosignatures)
            .field("min_external", &self.min_external)
            .finish_non_exhaustive()
    }
}

/// A witness cosignature (C2SP tlog-cosignature v1 form, 04 §14.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cosignature {
    /// The witness's K39 public key.
    pub witness_pk: [u8; 32],
    /// Cosignature timestamp (seconds; part of the signed message).
    pub timestamp: u64,
    /// Ed25519 signature over [`cosignature_message`].
    pub sig: [u8; 64],
}

/// A signed checkpoint (04 §14.3), in structured form: the sealer rebuilds the
/// exact note text from the fields, so no text or base64 parsing of untrusted
/// input happens here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCheckpoint {
    /// Tree size.
    pub tree_size: u64,
    /// Root hash.
    pub root_hash: [u8; 32],
    /// Issued hour (hours since the Unix epoch; hour granularity, RVW-A-29).
    pub issued_hour: u64,
    /// LOG_KEY Ed25519 signature over [`SignedCheckpoint::note_body`].
    pub log_sig: [u8; 64],
    /// Witness cosignatures.
    pub cosignatures: Vec<Cosignature>,
}

/// What C-09 pushes with each snapshot (04 §14.3): the newest checkpoint, the
/// whole log and the consistency proof from the sealer's high-water mark.
#[derive(Clone, PartialEq, Eq)]
pub struct SnapshotBundle {
    /// C-09 snapshot counter (informational, `HELLO`).
    pub snapshot_version: u64,
    /// Newest checkpoint.
    pub checkpoint: SignedCheckpoint,
    /// RFC 9162 consistency proof from the high-water mark's tree size to
    /// `checkpoint.tree_size` (empty when the mark is 0 or the sizes are equal).
    pub consistency_proof: Vec<[u8; 32]>,
    /// Every SignedKDEntry of the log, in leaf order (`checkpoint.tree_size`
    /// entries; VR-4 full-tree recomputation, VR-12 bounds).
    pub entries: Vec<Vec<u8>>,
    /// Channels the operator has disabled for intake (can only remove).
    pub disabled_channels: Vec<[u8; 16]>,
}

impl core::fmt::Debug for SnapshotBundle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SnapshotBundle")
            .field("snapshot_version", &self.snapshot_version)
            .field("tree_size", &self.checkpoint.tree_size)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

/// Why a snapshot was refused (fail closed: nothing is installed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    /// Below the high-water mark (rollback, ADR-036(6)).
    Rollback,
    /// Suite mismatch.
    Suite,
    /// Checkpoint signature or cosignature policy failed (VR-2).
    Signature,
    /// Consistency with the high-water mark failed: fork or bad proof (VR-3).
    Fork,
    /// Structurally invalid bundle or log (sizes, missing ORG_ROOT, salt).
    Invalid,
    /// The entries do not recompute the checkpoint's root (content not bound
    /// to the checkpoint, an entry missing, added or altered; VR-4).
    Inclusion,
    /// An entry fails its format, continuity or signature rules (§14.2, §14.4).
    Entry,
    /// The high-water mark moved since verification; verify again.
    Stale,
    /// Persisting the new high-water mark failed.
    Persist,
}

impl core::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Rollback => "directory snapshot below high-water mark",
            Self::Suite => "directory snapshot suite mismatch",
            Self::Signature => "directory checkpoint signature or cosignature policy failed",
            Self::Fork => "directory checkpoint not consistent with high-water mark",
            Self::Invalid => "directory snapshot structurally invalid",
            Self::Inclusion => "directory entries do not match the checkpoint root",
            Self::Entry => "directory entry failed verification",
            Self::Stale => "high-water mark changed during verification",
            Self::Persist => "high-water mark could not be persisted",
        })
    }
}

impl std::error::Error for SnapshotError {}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (encode only; trusted 32-byte input).
fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3).saturating_mul(4));
    for chunk in input.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let sym = |shift: u32| -> char {
            let i = usize::try_from((n >> shift) & 0x3f).unwrap_or(0);
            B64.get(i).map_or('A', |c| char::from(*c))
        };
        out.push(sym(18));
        out.push(sym(12));
        out.push(if chunk.len() > 1 { sym(6) } else { '=' });
        out.push(if chunk.len() > 2 { sym(0) } else { '=' });
    }
    out
}

/// Civil date `(year, month, day)` of a day number since 1970-01-01
/// (H. Hinnant's `civil_from_days`, valid for the whole `u64` hour range used).
fn civil_from_days(days: u64) -> Option<(u64, u64, u64)> {
    let z = days.checked_add(719_468)?;
    let era = z.checked_div(146_097)?;
    let doe = z.checked_sub(era.checked_mul(146_097)?)?;
    let yoe = doe
        .checked_sub(doe.checked_div(1460)?)?
        .checked_add(doe.checked_div(36_524)?)?
        .checked_sub(doe.checked_div(146_096)?)?
        .checked_div(365)?;
    let y = yoe.checked_add(era.checked_mul(400)?)?;
    let doy = doe.checked_sub(
        yoe.checked_mul(365)?
            .checked_add(yoe.checked_div(4)?)?
            .checked_sub(yoe.checked_div(100)?)?,
    )?;
    let mp = doy.checked_mul(5)?.checked_add(2)?.checked_div(153)?;
    let d = doy
        .checked_sub(mp.checked_mul(153)?.checked_add(2)?.checked_div(5)?)?
        .checked_add(1)?;
    let m = if mp < 10 {
        mp.checked_add(3)?
    } else {
        mp.checked_sub(9)?
    };
    let y = if m <= 2 { y.checked_add(1)? } else { y };
    Some((y, m, d))
}

impl SignedCheckpoint {
    /// The signed-note body (04 §14.3):
    /// `candor-kd/<tenant hex>/v1\n<size>\n<base64 root>\nissued <YYYY-MM-DDTHH>Z\n`.
    #[must_use]
    pub fn note_body(&self, tenant_id: &[u8; 16]) -> Option<Vec<u8>> {
        use core::fmt::Write as _;
        let (y, mo, d) = civil_from_days(self.issued_hour.checked_div(24)?)?;
        let h = self.issued_hour.checked_rem(24)?;
        let mut s = String::with_capacity(160);
        s.push_str("candor-kd/");
        for b in tenant_id {
            write!(s, "{b:02x}").ok()?;
        }
        write!(
            s,
            "/v1\n{}\n{}\nissued {y:04}-{mo:02}-{d:02}T{h:02}Z\n",
            self.tree_size,
            base64_encode(&self.root_hash)
        )
        .ok()?;
        Some(s.into_bytes())
    }
}

/// The message a witness signs (C2SP tlog-cosignature v1):
/// `"cosignature/v1\ntime <timestamp>\n" ‖ note body`.
#[must_use]
pub fn cosignature_message(note_body: &[u8], timestamp: u64) -> Vec<u8> {
    let head = format!("cosignature/v1\ntime {timestamp}\n");
    let mut m = Vec::with_capacity(head.len().saturating_add(note_body.len()));
    m.extend_from_slice(head.as_bytes());
    m.extend_from_slice(note_body);
    m
}

pub use super::merkle;

/// A directory snapshot that passed [`VerifiedSnapshot::verify`]. The only form
/// in which the sealer uses a snapshot (ADR-052(6)). Not constructible otherwise.
#[derive(Debug)]
pub struct VerifiedSnapshot {
    view: DirectorySnapshot,
    /// The high-water mark the verification was relative to.
    base: HighWaterMark,
}

impl core::ops::Deref for VerifiedSnapshot {
    type Target = DirectorySnapshot;
    fn deref(&self) -> &DirectorySnapshot {
        &self.view
    }
}

impl VerifiedSnapshot {
    /// Verify `bundle` against the pinned trust, the tenant suite and
    /// deployment salt, and the current high-water mark, and derive the view.
    /// Cheap checks first; nothing is trusted until every check passed.
    pub fn verify(
        bundle: SnapshotBundle,
        trust: &DirectoryTrust,
        suite: Suite,
        deployment_salt: &[u8; 32],
        hwm: &HighWaterMark,
    ) -> Result<Self, SnapshotError> {
        let SnapshotBundle {
            snapshot_version,
            checkpoint: cp,
            consistency_proof,
            entries,
            disabled_channels,
        } = bundle;
        // VR-12 bounds; the entries must be exactly the checkpoint's tree.
        let n = u64::try_from(entries.len()).map_err(|_| SnapshotError::Invalid)?;
        if cp.tree_size == 0 || entries.len() > kd::MAX_LOG_ENTRIES {
            return Err(SnapshotError::Invalid);
        }
        let total = entries
            .iter()
            .try_fold(0usize, |a, e| a.checked_add(e.len()))
            .ok_or(SnapshotError::Invalid)?;
        if total > kd::MAX_LOG_BYTES || disabled_channels.len() > 4_096 {
            return Err(SnapshotError::Invalid);
        }
        if n != cp.tree_size {
            return Err(SnapshotError::Inclusion);
        }
        // ADR-036(6): never below the high-water mark.
        if hwm.tree_size != 0 && (cp.tree_size < hwm.tree_size || cp.issued_hour < hwm.issued_hour)
        {
            return Err(SnapshotError::Rollback);
        }
        if hwm.tree_size == 0 && !consistency_proof.is_empty() {
            return Err(SnapshotError::Invalid);
        }
        // VR-4: the log content is bound to the signed root.
        let root = merkle::root_of(entries.iter().map(|e| merkle::leaf_hash(e)));
        if !candor_core::kdf::ct_eq(&root, &cp.root_hash) {
            return Err(SnapshotError::Inclusion);
        }
        // §14.2/§14.4: every entry, in order.
        let ctx = kd::VerifyCtx {
            tenant_id: trust.tenant_id,
            suite,
            deployment_salt,
            pinned_k01: &trust.org_root_pk,
            hwm_tree_size: hwm.tree_size,
            hwm_issued_day: u32::try_from(hwm.issued_hour.checked_div(24).unwrap_or(0))
                .map_err(|_| SnapshotError::Invalid)?,
        };
        let log = kd::verify_log(&entries, &ctx)?;
        drop(entries);
        // VR-2: LOG_KEY signature and the cosignature policy (ORG_ROOT, never
        // below the pinned floors).
        let body = cp
            .note_body(&trust.tenant_id)
            .ok_or(SnapshotError::Invalid)?;
        if verify_strict(&log.log_key, &body, &cp.log_sig).is_err() {
            return Err(SnapshotError::Signature);
        }
        let need_total = log.w_total.max(trust.min_cosignatures);
        let need_external = log.w_external.max(trust.min_external);
        let mut counted: Vec<[u8; 32]> = Vec::with_capacity(cp.cosignatures.len());
        let mut external = 0usize;
        for c in &cp.cosignatures {
            let Some(w) = log.witnesses.iter().find(|w| w.pk == c.witness_pk) else {
                continue;
            };
            if counted.contains(&w.pk) {
                continue;
            }
            let msg = cosignature_message(&body, c.timestamp);
            if verify_strict(&w.pk, &msg, &c.sig).is_ok() {
                counted.push(w.pk);
                if w.external {
                    external = external.saturating_add(1);
                }
            }
        }
        if counted.len() < need_total || external < need_external {
            return Err(SnapshotError::Signature);
        }
        // VR-3 / ADR-036(6): continuity with the high-water mark.
        if hwm.tree_size != 0
            && !merkle::verify_consistency(
                hwm.tree_size,
                cp.tree_size,
                &hwm.root_hash,
                &cp.root_hash,
                &consistency_proof,
            )
        {
            return Err(SnapshotError::Fork);
        }
        let mut channels = log.channels;
        for ch in &mut channels {
            if disabled_channels.contains(&ch.channel_id) {
                ch.enabled = false;
            }
        }
        let view = DirectorySnapshot {
            snapshot_version,
            tree_size: cp.tree_size,
            root_hash: cp.root_hash,
            issued_hour: cp.issued_hour,
            suite,
            epoch_origin_day: trust.epoch_origin_day,
            custodian_pk: log.custodian_pk,
            disposition_pk: log.disposition_pk,
            channels,
            user_keys: log.user_keys,
        };
        Ok(Self { view, base: *hwm })
    }

    /// The high-water mark this snapshot was verified against.
    #[must_use]
    pub fn base(&self) -> HighWaterMark {
        self.base
    }

    /// The high-water mark after accepting this snapshot.
    #[must_use]
    pub fn mark(&self) -> HighWaterMark {
        HighWaterMark {
            tree_size: self.view.tree_size,
            root_hash: self.view.root_hash,
            issued_hour: self.view.issued_hour,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    /// RFC 4648 test vectors and a known civil date.
    #[test]
    fn note_helpers() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(civil_from_days(0), Some((1970, 1, 1)));
        assert_eq!(civil_from_days(20_362), Some((2025, 10, 1)));
        assert_eq!(civil_from_days(11_016), Some((2000, 2, 29)));
        let cp = SignedCheckpoint {
            tree_size: 7,
            root_hash: [0; 32],
            issued_hour: 20_362 * 24 + 5,
            log_sig: [0; 64],
            cosignatures: vec![],
        };
        let body = String::from_utf8(cp.note_body(&[0xab; 16]).unwrap()).unwrap();
        assert_eq!(
            body,
            "candor-kd/abababababababababababababababab/v1\n7\n\
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nissued 2025-10-01T05Z\n"
        );
    }
}
