// SPDX-License-Identifier: AGPL-3.0-or-later
//! Input validation and decision logic shared by both implementations, so that the
//! memory and PostgreSQL stores enforce byte-for-byte the same rules.

use std::collections::{BTreeMap, HashSet};

use subtle::ConstantTimeEq;

use crate::deletion::{DeletionEntry, verify_chain};
use crate::error::{Result, StoreError};
use crate::types::{
    AccountLink, BackupSnapshot, ClaimLimits, CounterDelta, CommitEnvelope, DISPOSITION_CT_LEN_STD, IncomingReply,
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

/// A monthly counter delta flushed at an import slot.
pub(crate) fn counter_delta(c: &CounterDelta) -> Result<()> {
    if !c.month.is_month_start() {
        return Err(StoreError::InvalidInput("month"));
    }
    day_i32(c.month)?;
    i32::try_from(c.delta).map_err(|_| StoreError::InvalidInput("counter overflow"))?;
    Ok(())
}

/// Structural checks of an RL-10 backup before anything is restored, so that the
/// restore never relies on a database constraint violation (AUD-RM2-STO-02).
pub(crate) fn backup(b: &BackupSnapshot) -> Result<()> {
    let mut ids = HashSet::new();
    let mut tags = HashSet::new();
    for a in &b.accounts {
        new_account(&NewAccount {
            lookup_tag: a.lookup_tag,
            auth_pk: a.auth_pk,
            xwing_pk: a.xwing_pk.clone(),
            prefs_ct: a.prefs_ct.clone(),
        })?;
        if !a.activity_month.is_month_start() {
            return Err(StoreError::InvalidInput("activity month"));
        }
        day_i32(a.activity_month)?;
        if !ids.insert(a.account_id) || !tags.insert(a.lookup_tag) {
            return Err(StoreError::InvalidInput("duplicate account in backup"));
        }
    }
    if b
        .deletion_list
        .windows(2)
        .any(|w| matches!(w, [x, y] if y.seq <= x.seq))
    {
        return Err(StoreError::DeletionList("unordered backup list"));
    }
    for e in &b.deletion_list {
        if e.seq == 0 || i64::try_from(e.seq).is_err() {
            return Err(StoreError::DeletionList("seq out of range"));
        }
        day_i32(e.del_day)?;
    }
    if let Some(d) = b.meta.kd.checkpoint_day {
        day_i32(d)?;
    }
    for v in [
        b.meta.relay_req_counter,
        b.meta.last_batch_no,
        b.meta.kd.tree_size,
        b.meta.kd.directory_version,
    ] {
        i64::try_from(v).map_err(|_| StoreError::InvalidInput("value out of range"))?;
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
    if let Some(d) = hwm.checkpoint_day
        && snap.checkpoint_day < d
    {
        return Err(StoreError::Rollback(
            "checkpoint older than high-water mark",
        ));
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

/// RL-12 step 1 (outside any lock, AUD-RM2-STO-12): bound the size and verify
/// the pushed run's internal chain and every strict Ed25519 signature under K31.
pub(crate) fn verify_pushed(pushed: &[DeletionEntry], k31_pk: &[u8; 32]) -> Result<()> {
    if pushed.len() > MAX_PUSHED_DELETION_LIST {
        return Err(StoreError::InvalidInput("deletion list too long"));
    }
    verify_chain(pushed, k31_pk, None)
}

fn links(prev: &DeletionEntry, next: &DeletionEntry) -> bool {
    prev.seq.checked_add(1) == Some(next.seq)
        && bool::from(prev.next_prev_hash().ct_eq(&next.prev_hash))
}

/// RL-12 step 2 (under the row lock): merge an already signature-verified
/// pushed run into the local list (AUD-RM2-STO-04). `local` is sorted by seq;
/// `acked` is the highest seq the relay has acknowledged; `core_head` is the
/// Z-CORE head seq the relay asserts. Fails closed on:
/// - a non-empty push whose last seq is not `core_head` (truncation);
/// - an empty push when `core_head > 0` (missing list);
/// - `core_head < acked` (Z-CORE lost entries it acknowledged);
/// - a gap between the local head and the pushed run;
/// - a run that neither links to a local entry nor overlaps the local list
///   (unanchored), unless the local list is empty;
/// - any overlapping entry that differs (fork), a filled hole that does not link
///   to its local successor, or a merged list that is not contiguous.
///
/// Returns the pushed entries that are new locally (marked relayed).
pub(crate) fn merge_pushed(
    local: &[DeletionEntry],
    acked: u64,
    pushed: &[DeletionEntry],
    core_head: u64,
) -> Result<Vec<DeletionEntry>> {
    if pushed.len() > MAX_PUSHED_DELETION_LIST {
        return Err(StoreError::InvalidInput("deletion list too long"));
    }
    if core_head < acked {
        return Err(StoreError::DeletionList(
            "Z-CORE head behind acknowledged entries",
        ));
    }
    let Some(last) = pushed.last() else {
        return if core_head == 0 {
            Ok(Vec::new())
        } else {
            Err(StoreError::DeletionList("empty push for non-empty list"))
        };
    };
    if last.seq != core_head {
        return Err(StoreError::DeletionList("truncated push"));
    }
    // Internal contiguity again (cheap; signatures were verified before the lock).
    if pushed.windows(2).any(|w| match w {
        [a, b] => !links(a, b),
        _ => false,
    }) {
        return Err(StoreError::DeletionList("broken hash chain"));
    }
    let map: BTreeMap<u64, &DeletionEntry> = local.iter().map(|e| (e.seq, e)).collect();
    let first = pushed.first().ok_or(StoreError::DeletionList("empty"))?;
    if first.seq == 1 && first.prev_hash != [0u8; 32] {
        return Err(StoreError::DeletionList("bad genesis link"));
    }
    if let Some((&local_head, _)) = map.last_key_value() {
        if first.seq > local_head.saturating_add(1) {
            return Err(StoreError::DeletionList("gap after local head"));
        }
        let anchored = first
            .seq
            .checked_sub(1)
            .and_then(|s| map.get(&s))
            .is_some_and(|a| links(a, first));
        let overlaps = pushed.iter().any(|p| map.contains_key(&p.seq));
        if !anchored && !overlaps {
            return Err(StoreError::DeletionList("unanchored push"));
        }
        if let Some(a) = first.seq.checked_sub(1).and_then(|s| map.get(&s))
            && !links(a, first)
        {
            return Err(StoreError::DeletionList("broken anchor link"));
        }
    }
    let mut new = Vec::new();
    for p in pushed {
        match map.get(&p.seq) {
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
    // A filled hole must link to its local successor.
    for n in &new {
        if let Some(succ) = n.seq.checked_add(1).and_then(|s| map.get(&s))
            && !links(n, succ)
        {
            return Err(StoreError::DeletionList("broken link to local successor"));
        }
    }
    // The merged list must be contiguous from its lowest retained seq.
    let mut seqs: Vec<u64> = map.keys().copied().chain(new.iter().map(|e| e.seq)).collect();
    seqs.sort_unstable();
    if seqs
        .windows(2)
        .any(|w| matches!(w, [a, b] if a.checked_add(1) != Some(*b)))
    {
        return Err(StoreError::DeletionList("merged list not contiguous"));
    }
    Ok(new)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
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

    fn chain(n: usize) -> (Vec<DeletionEntry>, [u8; 32]) {
        use crate::deletion::{DeletionKind, Ed25519DeletionSigner, make_entry};
        let s = Ed25519DeletionSigner::new(candor_core::sig::SigningKey::from_seed(&[4u8; 32]));
        let mut v: Vec<DeletionEntry> = Vec::new();
        for i in 0..n {
            let e = make_entry(v.last(), DeletionKind::Account, [i as u8; 32], Day(9), &s).unwrap();
            v.push(e);
        }
        (v, s.verifying_key())
    }

    /// AUD-RM2-STO-04: gapped, truncated, empty, unanchored and forked pushes
    /// are rejected; a proper push merges.
    #[test]
    fn merge_rules() {
        let (all, pk) = chain(8);
        verify_pushed(&all, &pk).unwrap();
        let local = &all[..2];
        // Gap: local [1,2] + pushed [5..=6].
        assert_eq!(
            merge_pushed(local, 0, &all[4..6], 6),
            Err(StoreError::DeletionList("gap after local head"))
        );
        // Empty push while Z-CORE has entries.
        assert!(merge_pushed(local, 0, &[], 6).is_err());
        // Empty push when Z-CORE has none and nothing was acknowledged: fine.
        assert_eq!(merge_pushed(local, 0, &[], 0).unwrap().len(), 0);
        // Z-CORE behind what it acknowledged.
        assert!(merge_pushed(local, 2, &[], 0).is_err());
        // Truncated: the run ends before the asserted head.
        assert_eq!(
            merge_pushed(local, 0, &all[..5], 8),
            Err(StoreError::DeletionList("truncated push"))
        );
        // Proper: anchored at 2, through the head.
        let new = merge_pushed(local, 0, &all[2..], 8).unwrap();
        assert_eq!(new.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![3, 4, 5, 6, 7, 8]);
        assert!(new.iter().all(|e| e.relayed));
        // Overlapping full copy.
        assert_eq!(merge_pushed(local, 0, &all, 8).unwrap().len(), 6);
        // Local list empty: unanchored suffix accepted (only option).
        assert_eq!(merge_pushed(&[], 0, &all[3..], 8).unwrap().len(), 5);
        // Unanchored with a local list: other chain's suffix.
        let (other, _) = {
            use crate::deletion::{DeletionKind, Ed25519DeletionSigner, make_entry};
            let s = Ed25519DeletionSigner::new(candor_core::sig::SigningKey::from_seed(&[4u8; 32]));
            let mut v: Vec<DeletionEntry> = Vec::new();
            for i in 0..4 {
                v.push(make_entry(v.last(), DeletionKind::Reply, [i as u8; 32], Day(9), &s).unwrap());
            }
            (v, ())
        };
        assert!(merge_pushed(local, 0, &other[2..], 4).is_err());
        // Fork on overlap.
        assert_eq!(
            merge_pushed(&all[..3], 0, &other, 4),
            Err(StoreError::DeletionList("fork with local list"))
        );
        // Local head beyond Z-CORE (unrelayed local entries) is accepted.
        assert_eq!(merge_pushed(&all[..6], 0, &all[..4], 4).unwrap().len(), 0);
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
