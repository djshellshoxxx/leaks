// SPDX-License-Identifier: AGPL-3.0-or-later
//! Input validation and decision logic shared by both implementations, so that the
//! memory and PostgreSQL stores enforce byte-for-byte the same rules.

use crate::deletion::{DeletionEntry, verify_chain};
use crate::error::{Result, StoreError};
use crate::types::{
    AccountLink, ClaimLimits, CommitEnvelope, DISPOSITION_CT_LEN_STD, IncomingReply,
    InstallOutcome, KdHighWater, MAX_CLAIM_BYTES, MAX_CLAIM_OBJECTS, MAX_HEADER_CT,
    MAX_MANIFEST_CT, MAX_PART_PADDED_SIZE, MAX_PARTS, MAX_PREFS_CT, MAX_PUSHED_DELETION_LIST,
    MAX_RELEASE_OFFSET_DAYS, MAX_REPLY_CT, MAX_SNAPSHOT_BODY, MAX_SNAPSHOT_SIGNATURES, NewAccount,
    VerifiedSnapshot, XWING_PK_LEN,
};

pub(crate) fn has_duplicates<T: PartialEq>(v: &[T]) -> bool {
    v.iter()
        .enumerate()
        .any(|(i, a)| v.iter().skip(i.saturating_add(1)).any(|b| a == b))
}

/// Validate a `COMMIT_ENVELOPE` request.
pub(crate) fn commit(env: &CommitEnvelope) -> Result<()> {
    if env.header_ct.is_empty() || env.header_ct.len() > MAX_HEADER_CT {
        return Err(StoreError::InvalidInput("header_ct size"));
    }
    if env.manifest_ct.is_empty() || env.manifest_ct.len() > MAX_MANIFEST_CT {
        return Err(StoreError::InvalidInput("manifest_ct size"));
    }
    if env.disposition_ct.len() != DISPOSITION_CT_LEN_STD {
        return Err(StoreError::InvalidInput("disposition_ct size"));
    }
    if env.release_offset_days > MAX_RELEASE_OFFSET_DAYS {
        return Err(StoreError::InvalidInput("release offset"));
    }
    if env.parts.len() > MAX_PARTS {
        return Err(StoreError::InvalidInput("too many parts"));
    }
    for (i, p) in env.parts.iter().enumerate() {
        if p.padded_size == 0 || p.padded_size > MAX_PART_PADDED_SIZE {
            return Err(StoreError::InvalidInput("part size"));
        }
        if env
            .parts
            .iter()
            .skip(i.saturating_add(1))
            .any(|q| q.blob_id == p.blob_id)
        {
            return Err(StoreError::InvalidInput("duplicate blob id"));
        }
    }
    i32::try_from(env.epoch_index).map_err(|_| StoreError::InvalidInput("epoch index"))?;
    day_i32(env.received_date)?;
    day_i32(env.received_date.plus(u32::from(env.release_offset_days))?)?;
    if let AccountLink::New(a) = &env.account {
        new_account(a)?;
    }
    Ok(())
}

pub(crate) fn new_account(a: &NewAccount) -> Result<()> {
    if a.xwing_pk.len() != XWING_PK_LEN {
        return Err(StoreError::InvalidInput("xwing_pk size"));
    }
    if a.prefs_ct.is_empty() || a.prefs_ct.len() > MAX_PREFS_CT {
        return Err(StoreError::InvalidInput("prefs_ct size"));
    }
    Ok(())
}

/// Day as an i32 for PostgreSQL date arithmetic (bounded to avoid overflow).
pub(crate) fn day_i32(d: crate::types::Day) -> Result<i32> {
    // Keep well inside PostgreSQL's date range.
    if d.0 > 2_000_000 {
        return Err(StoreError::InvalidInput("day out of range"));
    }
    i32::try_from(d.0).map_err(|_| StoreError::InvalidInput("day out of range"))
}

pub(crate) fn claim_limits(l: ClaimLimits) -> Result<()> {
    if l.max_objects == 0 || l.max_objects > MAX_CLAIM_OBJECTS {
        return Err(StoreError::InvalidInput("max_objects"));
    }
    if l.max_bytes == 0 || l.max_bytes > MAX_CLAIM_BYTES {
        return Err(StoreError::InvalidInput("max_bytes"));
    }
    Ok(())
}

/// Bytes an object contributes to `max_bytes`.
pub(crate) fn object_bytes(header_len: u64, manifest_len: u64, parts: &[u64]) -> u64 {
    parts
        .iter()
        .fold(header_len.saturating_add(manifest_len), |a, p| {
            a.saturating_add(*p)
        })
}

/// Greedy batch fill: take objects in the given (random) order while within
/// limits. The first object is always taken so that an envelope larger than
/// `max_bytes` cannot block the queue forever (SPEC-NOTES).
pub(crate) fn fill_batch(sizes: &[u64], limits: ClaimLimits) -> Vec<usize> {
    let mut out = Vec::new();
    let mut bytes: u64 = 0;
    for (i, s) in sizes.iter().enumerate() {
        if out.len() >= usize::try_from(limits.max_objects).unwrap_or(usize::MAX) {
            break;
        }
        let next = bytes.saturating_add(*s);
        if !out.is_empty() && next > limits.max_bytes {
            continue;
        }
        bytes = next;
        out.push(i);
    }
    out
}

/// Structural check of a pushed reply (other than deletion-list drops).
pub(crate) fn reply(r: &IncomingReply) -> bool {
    !r.reply_ct.is_empty()
        && r.reply_ct.len() <= MAX_REPLY_CT
        && (1..=16).contains(&r.size_bucket)
        && (r.mailbox_id.is_some() || r.account.is_none())
}

/// What to do with a snapshot install.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SnapshotDecision {
    Install,
    AlreadyInstalled,
}

/// Rollback protection (ADR-036(6); 09 `kd_tree_size_hwm`; BE-060; RL-06).
pub(crate) fn snapshot(
    hwm: &KdHighWater,
    current_body: Option<&[u8]>,
    snap: &VerifiedSnapshot,
) -> Result<SnapshotDecision> {
    if snap.body.is_empty() || snap.body.len() > MAX_SNAPSHOT_BODY {
        return Err(StoreError::InvalidInput("snapshot body size"));
    }
    if snap.signatures.is_empty() || snap.signatures.len() > MAX_SNAPSHOT_SIGNATURES {
        return Err(StoreError::InvalidInput("snapshot signature size"));
    }
    if snap.version == 0 || i64::try_from(snap.version).is_err() {
        return Err(StoreError::InvalidInput("snapshot version"));
    }
    if i64::try_from(snap.tree_size).is_err() || snap.tree_size == 0 {
        return Err(StoreError::InvalidInput("tree size"));
    }
    day_i32(snap.checkpoint_day)?;
    if snap.tree_size < hwm.tree_size {
        return Err(StoreError::Rollback("tree size below high-water mark"));
    }
    if let Some(d) = hwm.checkpoint_day {
        if snap.checkpoint_day < d {
            return Err(StoreError::Rollback(
                "checkpoint older than high-water mark",
            ));
        }
    }
    if snap.version < hwm.directory_version {
        return Err(StoreError::Rollback("version below current"));
    }
    if snap.version == hwm.directory_version {
        return match current_body {
            Some(b) if b == snap.body.as_slice() && snap.tree_size == hwm.tree_size => {
                Ok(SnapshotDecision::AlreadyInstalled)
            }
            _ => Err(StoreError::Rollback("same version, different snapshot")),
        };
    }
    if snap.tree_size > hwm.tree_size && snap.consistent_from != hwm.tree_size {
        return Err(StoreError::Rollback(
            "not consistency-proven from high-water mark",
        ));
    }
    if snap.tree_size == hwm.tree_size && snap.consistent_from != hwm.tree_size {
        return Err(StoreError::Rollback(
            "not consistency-proven from high-water mark",
        ));
    }
    Ok(SnapshotDecision::Install)
}

impl From<SnapshotDecision> for InstallOutcome {
    fn from(d: SnapshotDecision) -> Self {
        match d {
            SnapshotDecision::Install => InstallOutcome::Installed,
            SnapshotDecision::AlreadyInstalled => InstallOutcome::AlreadyInstalled,
        }
    }
}

/// Merge a pushed deletion list into the local one (RL-12). `local` is sorted by
/// seq. Returns the pushed entries that are new locally (marked relayed).
pub(crate) fn merge_pushed(
    local: &[DeletionEntry],
    pushed: &[DeletionEntry],
    k31_pk: &[u8; 32],
) -> Result<Vec<DeletionEntry>> {
    if pushed.len() > MAX_PUSHED_DELETION_LIST {
        return Err(StoreError::InvalidInput("deletion list too long"));
    }
    let Some(first) = pushed.first() else {
        return Ok(Vec::new());
    };
    let anchor = first
        .seq
        .checked_sub(1)
        .and_then(|s| local.iter().find(|e| e.seq == s));
    verify_chain(pushed, k31_pk, anchor)?;
    let mut new = Vec::new();
    for p in pushed {
        match local.iter().find(|e| e.seq == p.seq) {
            Some(l) => {
                if !l.same_signed(p) {
                    return Err(StoreError::DeletionList("fork with local list"));
                }
            }
            None => {
                let mut e = *p;
                e.relayed = true;
                new.push(e);
            }
        }
    }
    // A pushed entry below the local head that is missing locally means the local
    // list has a hole that the pushed copy fills; if the local successor exists it
    // must link to it.
    for n in &new {
        if let Some(succ) = local.iter().find(|e| Some(e.seq) == n.seq.checked_add(1)) {
            verify_chain(std::slice::from_ref(succ), k31_pk, Some(n))?;
        }
    }
    Ok(new)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::types::Day;

    fn snap(version: u64, tree: u64, day: u32, from: u64) -> VerifiedSnapshot {
        VerifiedSnapshot {
            version,
            tree_size: tree,
            checkpoint_day: Day(day),
            consistent_from: from,
            body: vec![version as u8; 8],
            signatures: vec![1; 64],
        }
    }

    /// BE-060 / RVW-A-04: rollback rejection matrix.
    #[test]
    fn rollback_matrix() {
        let hwm = KdHighWater {
            tree_size: 100,
            checkpoint_day: Some(Day(50)),
            directory_version: 5,
        };
        let body = vec![5u8; 8];
        assert_eq!(
            snapshot(&hwm, Some(&body), &snap(6, 120, 51, 100)).unwrap(),
            SnapshotDecision::Install
        );
        assert!(matches!(
            snapshot(&hwm, Some(&body), &snap(6, 99, 51, 99)),
            Err(StoreError::Rollback(_))
        ));
        assert!(matches!(
            snapshot(&hwm, Some(&body), &snap(6, 120, 49, 100)),
            Err(StoreError::Rollback(_))
        ));
        assert!(matches!(
            snapshot(&hwm, Some(&body), &snap(4, 120, 51, 100)),
            Err(StoreError::Rollback(_))
        ));
        assert!(matches!(
            snapshot(&hwm, Some(&body), &snap(6, 120, 51, 90)),
            Err(StoreError::Rollback(_))
        ));
        assert_eq!(
            snapshot(&hwm, Some(&body), &snap(5, 100, 50, 100)).unwrap(),
            SnapshotDecision::AlreadyInstalled
        );
        let mut other = snap(5, 100, 50, 100);
        other.body = vec![9; 8];
        assert!(snapshot(&hwm, Some(&body), &other).is_err());
        // First install from an empty high-water mark.
        let zero = KdHighWater::default();
        assert_eq!(
            snapshot(&zero, None, &snap(1, 10, 1, 0)).unwrap(),
            SnapshotDecision::Install
        );
    }

    #[test]
    fn fill_batch_limits() {
        let l = ClaimLimits {
            max_objects: 2,
            max_bytes: 100,
        };
        assert_eq!(fill_batch(&[10, 10, 10], l), vec![0, 1]);
        let l = ClaimLimits {
            max_objects: 10,
            max_bytes: 25,
        };
        assert_eq!(fill_batch(&[10, 20, 10], l), vec![0, 2]);
        let l = ClaimLimits {
            max_objects: 10,
            max_bytes: 5,
        };
        assert_eq!(fill_batch(&[10, 20], l), vec![0]);
    }
}
