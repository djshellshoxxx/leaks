// SPDX-License-Identifier: AGPL-3.0-or-later
//! The sealer's view of a **verified** Key Directory snapshot (04 §12.1, §14).
//!
//! [`DirectorySnapshot`] is the flattened view the C-14 verifier produces from the
//! directory entries. It is *not* usable by itself: the sealer only seals against
//! a [`VerifiedSnapshot`] (ADR-052(6), AUD-RM2-SEA-07), whose only constructor
//! [`VerifiedSnapshot::verify`] checks, against the pinned [`DirectoryTrust`]
//! (VR-1):
//! * the checkpoint signature of the LOG_KEY and the witness cosignature policy
//!   (VR-2, 04 §14.3);
//! * that the view is bound to that checkpoint (tree size, root hash, issued hour);
//! * continuity with the high-water mark: an RFC 9162 consistency proof from the
//!   mark's `(tree_size, root_hash)`, and an equal size only with an equal root
//!   (VR-3, ADR-036(6));
//! * structural invariants of the view (unique channels, ≤ 16 Triage Set persons
//!   per channel, ≤ 1 COI_POLICY per `effective_day`). MEKs of users outside the
//!   Triage Set are ignored at selection.
//!
//! Per-entry signatures and §14.4 continuity of the roster, COI_POLICY,
//! MEMBER_EPOCH and USER_KEYS entries, and their flattening into this view, stay
//! with the C-14 verifier (see SPEC-NOTES). The sealer additionally enforces
//! freshness (ADR-047(4)), suite, time locks (`effective_day`), MEK validity
//! windows and the Triage Set / COI rules at selection time.

use candor_core::Suite;
use candor_core::hash::sha256;
use candor_core::sig::verify_strict;

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

/// Directory trust anchors pinned at install (VR-1): the tenant, its LOG_KEY and
/// the witness cosignature policy of ORG_ROOT.
#[derive(Clone, PartialEq, Eq)]
pub struct DirectoryTrust {
    /// Tenant id (checkpoint origin line).
    pub tenant_id: [u8; 16],
    /// LOG_KEY Ed25519 public keys accepted for checkpoint signatures.
    pub log_keys: Vec<[u8; 32]>,
    /// Witness keys.
    pub witnesses: Vec<WitnessKey>,
    /// `w_total`: valid cosignatures required (EE/GOV/MANAGED: ≥ 2).
    pub min_cosignatures: usize,
    /// `w_external`: of which from external witnesses (EE/GOV/MANAGED: ≥ 1).
    pub min_external: usize,
}

impl core::fmt::Debug for DirectoryTrust {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DirectoryTrust")
            .field("log_keys", &self.log_keys.len())
            .field("witnesses", &self.witnesses.len())
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

/// What C-09 pushes with each snapshot: the flattened view, the newest
/// checkpoint and the consistency proof from the sealer's high-water mark.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotBundle {
    /// Flattened, entry-verified view (C-14 verifier output).
    pub view: DirectorySnapshot,
    /// Newest checkpoint.
    pub checkpoint: SignedCheckpoint,
    /// RFC 9162 consistency proof from the high-water mark's tree size to
    /// `checkpoint.tree_size` (empty when the mark is 0 or the sizes are equal).
    pub consistency_proof: Vec<[u8; 32]>,
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
    /// The view is not bound to the checkpoint or violates an invariant.
    Invalid,
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

/// RFC 6962 / RFC 9162 Merkle tree hashing over SHA-256 (`candor-core`).
pub mod merkle {
    use super::sha256;

    /// `HASH(0x00 ‖ leaf)`.
    #[must_use]
    pub fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
        sha256(&[&[0x00], leaf])
    }

    /// `HASH(0x01 ‖ left ‖ right)`.
    #[must_use]
    pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        sha256(&[&[0x01], left, right])
    }

    fn split(n: usize) -> usize {
        // Largest power of two strictly below n (n ≥ 2).
        let mut k = 1usize;
        while k.checked_mul(2).is_some_and(|d| d < n) {
            k = k.saturating_mul(2);
        }
        k
    }

    /// `MTH(D[n])` of leaf hashes (RFC 9162 §2.1.1). Tooling and tests only:
    /// recursion depth is `log2(n)`.
    #[must_use]
    pub fn root(leaves: &[[u8; 32]]) -> [u8; 32] {
        match leaves {
            [] => sha256(&[]),
            [one] => *one,
            _ => {
                let k = split(leaves.len());
                let (l, r) = leaves.split_at(k);
                node_hash(&root(l), &root(r))
            }
        }
    }

    fn subproof(m: usize, leaves: &[[u8; 32]], complete: bool, out: &mut Vec<[u8; 32]>) {
        let n = leaves.len();
        if m == n {
            if !complete {
                out.push(root(leaves));
            }
            return;
        }
        if n < 2 {
            return;
        }
        let k = split(n);
        let (l, r) = leaves.split_at(k);
        if m <= k {
            subproof(m, l, complete, out);
            out.push(root(r));
        } else {
            subproof(m.saturating_sub(k), r, false, out);
            out.push(root(l));
        }
    }

    /// `PROOF(m, D[n])` (RFC 9162 §2.1.4.1). Tooling and tests only.
    #[must_use]
    pub fn consistency_proof(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let mut out = Vec::new();
        if m == 0 || m > leaves.len() {
            return out;
        }
        subproof(m, leaves, true, &mut out);
        out
    }

    /// Verify a consistency proof (RFC 9162 §2.1.4.2). Iterative; the proof
    /// length is bounded by the caller (≤ 64 entries for `u64` tree sizes).
    #[must_use]
    pub fn verify_consistency(
        first: u64,
        second: u64,
        first_hash: &[u8; 32],
        second_hash: &[u8; 32],
        proof: &[[u8; 32]],
    ) -> bool {
        if proof.len() > 128 || first == 0 || first > second {
            return false;
        }
        if first == second {
            return proof.is_empty() && candor_core::kdf::ct_eq(first_hash, second_hash);
        }
        let mut path: Vec<[u8; 32]> = Vec::with_capacity(proof.len().saturating_add(1));
        if first.is_power_of_two() {
            path.push(*first_hash);
        }
        path.extend_from_slice(proof);
        let Some((start, rest)) = path.split_first() else {
            return false;
        };
        let (Some(mut fn_), Some(mut sn)) = (first.checked_sub(1), second.checked_sub(1)) else {
            return false;
        };
        while fn_ & 1 == 1 {
            fn_ >>= 1;
            sn >>= 1;
        }
        let mut fr = *start;
        let mut sr = *start;
        for c in rest {
            if sn == 0 {
                return false;
            }
            if fn_ & 1 == 1 || fn_ == sn {
                fr = node_hash(c, &fr);
                sr = node_hash(c, &sr);
                if fn_ & 1 == 0 {
                    while fn_ & 1 == 0 && fn_ != 0 {
                        fn_ >>= 1;
                        sn >>= 1;
                    }
                }
            } else {
                sr = node_hash(&sr, c);
            }
            fn_ >>= 1;
            sn >>= 1;
        }
        sn == 0
            && candor_core::kdf::ct_eq(&fr, first_hash)
            && candor_core::kdf::ct_eq(&sr, second_hash)
    }
}

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

fn check_invariants(v: &DirectorySnapshot) -> Result<(), SnapshotError> {
    for (i, ch) in v.channels.iter().enumerate() {
        if v.channels
            .get(..i)
            .is_some_and(|prev| prev.iter().any(|c| c.channel_id == ch.channel_id))
        {
            return Err(SnapshotError::Invalid);
        }
        let mut triage: Vec<[u8; 16]> = Vec::with_capacity(ch.members.len());
        for m in &ch.members {
            if m.read_intake && !triage.contains(&m.user_id) {
                triage.push(m.user_id);
            }
        }
        if triage.len() > candor_core::slots::SLOT_COUNT {
            return Err(SnapshotError::Invalid);
        }
        for (j, p) in ch.coi_policies.iter().enumerate() {
            if ch
                .coi_policies
                .get(..j)
                .is_some_and(|prev| prev.iter().any(|q| q.effective_day == p.effective_day))
            {
                return Err(SnapshotError::Invalid);
            }
        }
    }
    Ok(())
}

impl VerifiedSnapshot {
    /// Verify `bundle` against the pinned trust and the current high-water mark.
    pub fn verify(
        bundle: SnapshotBundle,
        trust: &DirectoryTrust,
        suite: Suite,
        hwm: &HighWaterMark,
    ) -> Result<Self, SnapshotError> {
        let SnapshotBundle {
            view,
            checkpoint: cp,
            consistency_proof,
        } = bundle;
        if view.suite != suite {
            return Err(SnapshotError::Suite);
        }
        // The view must be bound to the checkpoint it claims.
        if view.tree_size != cp.tree_size
            || view.root_hash != cp.root_hash
            || view.issued_hour != cp.issued_hour
            || cp.tree_size == 0
        {
            return Err(SnapshotError::Invalid);
        }
        // VR-2: LOG_KEY signature and the cosignature policy.
        let body = cp
            .note_body(&trust.tenant_id)
            .ok_or(SnapshotError::Invalid)?;
        if !trust
            .log_keys
            .iter()
            .any(|k| verify_strict(k, &body, &cp.log_sig).is_ok())
        {
            return Err(SnapshotError::Signature);
        }
        let mut counted: Vec<[u8; 32]> = Vec::with_capacity(cp.cosignatures.len());
        let mut external = 0usize;
        for c in &cp.cosignatures {
            let Some(w) = trust.witnesses.iter().find(|w| w.pk == c.witness_pk) else {
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
        if counted.len() < trust.min_cosignatures || external < trust.min_external {
            return Err(SnapshotError::Signature);
        }
        // VR-3 / ADR-036(6): continuity with the high-water mark.
        if hwm.tree_size != 0 {
            if cp.tree_size < hwm.tree_size || cp.issued_hour < hwm.issued_hour {
                return Err(SnapshotError::Rollback);
            }
            if !merkle::verify_consistency(
                hwm.tree_size,
                cp.tree_size,
                &hwm.root_hash,
                &cp.root_hash,
                &consistency_proof,
            ) {
                return Err(SnapshotError::Fork);
            }
        } else if !consistency_proof.is_empty() {
            return Err(SnapshotError::Invalid);
        }
        check_invariants(&view)?;
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
    use super::merkle::*;
    use super::*;

    fn leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| leaf_hash(&i.to_be_bytes())).collect()
    }

    /// RFC 9162 consistency proofs: every (m, n) up to 40 verifies; any tamper,
    /// wrong size or wrong root fails.
    #[test]
    fn consistency_proofs_round_trip_and_reject_tampering() {
        let all = leaves(40);
        for n in 1..=40usize {
            let rn = root(&all[..n]);
            for m in 1..=n {
                let rm = root(&all[..m]);
                let p = consistency_proof(m, &all[..n]);
                let (m64, n64) = (m as u64, n as u64);
                assert!(verify_consistency(m64, n64, &rm, &rn, &p), "{m} {n}");
                if m < n {
                    assert!(!verify_consistency(m64, n64, &rn, &rn, &p));
                    assert!(!verify_consistency(m64, n64, &rm, &rm, &p));
                    for i in 0..p.len() {
                        let mut bad = p.clone();
                        bad[i][0] ^= 1;
                        assert!(!verify_consistency(m64, n64, &rm, &rn, &bad));
                    }
                    let mut longer = p.clone();
                    longer.push([0; 32]);
                    assert!(!verify_consistency(m64, n64, &rm, &rn, &longer));
                }
            }
        }
        assert!(!verify_consistency(0, 1, &[0; 32], &[0; 32], &[]));
        assert!(!verify_consistency(3, 2, &[0; 32], &[0; 32], &[]));
    }

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
